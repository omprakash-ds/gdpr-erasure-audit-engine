import csv
import json
from pathlib import Path


POLICY_BY_PREFIX = {
    "account_": "DELETE",
    "search_": "DELETE",
    "cache_": "DELETE",
    "export_": "DELETE",
    "marketing_": "DELETE",
    "object_": "DELETE",
    "attachment_": "DELETE",
    "analytics_": "ANONYMIZE",
    "telemetry_": "ANONYMIZE",
    "support_": "REDACT",
    "email_log_": "REDACT",
    "tombstone_": "REDACT",
    "audit_record_": "RETAIN",
    "legal_hold_": "RETAIN",
    "data_flow_": "DISABLE_FLOW",
    "backup_": "BLOCK_RESTORE",
}

DEFAULT_POLICY_BY_CATEGORY = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "BLOCK_RESTORE",
    "ACCOUNT_TOMBSTONE": "REDACT",
}

SYSTEM_BY_PREFIX = {
    "account_": "account_service",
    "search_": "search_service",
    "cache_": "cache_service",
    "export_": "export_service",
    "marketing_": "marketing_platform",
    "object_": "object_storage",
    "attachment_": "object_storage",
    "analytics_": "analytics_platform",
    "telemetry_": "analytics_platform",
    "support_": "support_platform",
    "email_log_": "email_service",
    "tombstone_": "identity_service",
    "audit_record_": "security_service",
    "legal_hold_": "security_service",
    "data_flow_": "integration_service",
    "backup_": "backup_service",
}

OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}


def _normalize_rule_action(raw_action: str) -> str:
    a = (raw_action or "").strip().upper()
    if "BLOCK" in a and "RESTORE" in a:
        return "BLOCK_RESTORE"
    if "DISABLE" in a and "FLOW" in a:
        return "DISABLE_FLOW"
    if "ANONYM" in a:
        return "ANONYMIZE"
    if "REDACT" in a or "TOMBSTONE" in a:
        return "REDACT"
    if "RETAIN" in a or "KEEP" in a or "PRESERVE" in a:
        return "RETAIN"
    if "DELETE" in a or "REMOVE" in a or "ERASE" in a:
        return "DELETE"
    return a


def load_deletion_rules(rules_csv: str = "dataset/deletion_rules.csv") -> dict[str, str]:
    mapping = dict(DEFAULT_POLICY_BY_CATEGORY)
    path = Path(rules_csv)
    if not path.exists():
        return mapping
    with open(path, mode="r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cat = (
                row.get("data_category")
                or row.get("category")
                or row.get("record_type")
                or ""
            ).strip().upper()
            act = (
                row.get("required_action")
                or row.get("action")
                or row.get("treatment")
                or ""
            ).strip()
            if cat and act:
                mapping[cat] = _normalize_rule_action(act)
    return mapping


POLICY_BY_CATEGORY = load_deletion_rules()


def infer_policy_and_system(
    resource_id: str,
    system_id: str | None = None,
    category: str | None = None,
) -> tuple[str, str]:
    rid = resource_id.lower()
    action = "DELETE"
    sys_id = system_id or "account_service"
    for prefix, act in POLICY_BY_PREFIX.items():
        if rid.startswith(prefix):
            action = act
            sys_id = SYSTEM_BY_PREFIX[prefix]
            break
    if category and category.upper() in POLICY_BY_CATEGORY and not rid.startswith(("backup_", "data_flow_")):
        action = POLICY_BY_CATEGORY[category.upper()]
    return action, sys_id


def build_case_output(case_id: str, resource_states: list[dict], is_not_applicable: bool = False) -> dict:
    if is_not_applicable:
        return {
            "case_id": case_id,
            "deletion_status": "NOT_APPLICABLE",
            "steps_json": "[]",
        }

    findings = []
    remediations = []
    verifications = []
    has_violation = False

    def make_step(phase: str, system_id: str, resource_id: str, operation: str, state: str, evidence_id: str):
        return {
            "phase": phase,
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        }

    for item in resource_states:
        rid = item["resource_id"]
        obs = item["observed_state"].upper()
        if obs == "UNKNOWN":
            continue
        ev_id = item.get("evidence_id", "")
        action, sys_id = infer_policy_and_system(rid, item.get("system_id"), item.get("data_category"))
        if item.get("policy_override"):
            action = item["policy_override"]

        if action == "DELETE":
            if obs == "PRESENT":
                has_violation = True
                findings.append(make_step("FINDING", sys_id, rid, "REPORT_REMAINING_RECORD", "PRESENT", ev_id))
                remediations.append(make_step("REMEDIATION", sys_id, rid, "DELETE_RECORD", "ABSENT", ""))
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
            else:
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_ABSENT", "ABSENT", ev_id))

        elif action == "ANONYMIZE":
            if obs == "PRESENT":
                has_violation = True
                findings.append(make_step("FINDING", sys_id, rid, "REPORT_EXPOSED_PII", "PRESENT", ev_id))
                remediations.append(make_step("REMEDIATION", sys_id, rid, "ANONYMIZE_RECORD", "ANONYMIZED", ""))
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
            else:
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ev_id))

        elif action == "REDACT":
            if obs == "PRESENT":
                has_violation = True
                findings.append(make_step("FINDING", sys_id, rid, "REPORT_EXPOSED_PII", "PRESENT", ev_id))
                remediations.append(make_step("REMEDIATION", sys_id, rid, "REDACT_RECORD", "REDACTED", ""))
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
            else:
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_REDACTED", "REDACTED", ev_id))

        elif action == "RETAIN":
            verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RECORD_PRESENT", "PRESENT", ev_id))

        elif action == "DISABLE_FLOW":
            if obs == "ACTIVE":
                has_violation = True
                findings.append(make_step("FINDING", sys_id, rid, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", ev_id))
                remediations.append(make_step("REMEDIATION", sys_id, rid, "DISABLE_DATA_FLOW", "DISABLED", ""))
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
            else:
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ev_id))

        elif action == "BLOCK_RESTORE":
            if obs == "ACTIVE":
                has_violation = True
                findings.append(make_step("FINDING", sys_id, rid, "REPORT_RESTORE_RISK", "ACTIVE", ev_id))
                remediations.append(make_step("REMEDIATION", sys_id, rid, "BLOCK_RESTORE", "BLOCKED", ""))
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
            else:
                verifications.append(make_step("VERIFICATION", sys_id, rid, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ev_id))

    if has_violation:
        for v in verifications:
            v["evidence_id"] = ""

    step_sort_key = lambda s: (OP_ORDER.get(s["operation"], 99), s["system_id"], s["resource_id"])
    findings.sort(key=step_sort_key)
    remediations.sort(key=step_sort_key)
    verifications.sort(key=step_sort_key)

    ordered = findings + remediations + verifications
    steps = [{"step_no": i + 1, **s} for i, s in enumerate(ordered)]

    return {
        "case_id": case_id,
        "deletion_status": "INCOMPLETE" if has_violation else "COMPLETE",
        "steps_json": json.dumps(steps),
    }