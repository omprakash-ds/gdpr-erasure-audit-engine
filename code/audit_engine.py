import csv
from datetime import datetime
import json
import re
from collections import defaultdict
import duckdb
from identity_resolver import IdentityResolver


RESOURCE_RE = re.compile(
    r"\b((?:account|search|cache|support|analytics|telemetry|export|marketing|"
    r"email_log|audit_record|legal_hold|backup|data_flow|object|tombstone|attachment)_\d+)\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_ID_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
BARE_TRACE_RE = re.compile(r"\b(tr-\d+)\b", re.IGNORECASE)
LINK_ALIAS_RE = re.compile(r"linked\s+\w+\s+\(([^)]+)\)", re.IGNORECASE)
SQL_INSERT_RE = re.compile(r'INSERT INTO\s+"?([^"\s(]+)"?\s+VALUES\s*\((.+?)\);', re.IGNORECASE)
KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s|]+))')


def parse_utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))


def extract_identity_tokens(text: str) -> set[str]:
    tokens = set()
    for m in EMAIL_RE.findall(text):
        tokens.add(m.lower())
    for m in USER_ID_RE.findall(text):
        tokens.add(m.lower())
    for m in HASH_RE.findall(text):
        tokens.add(m.lower())
    return tokens


def parse_sql_values(vals_str: str) -> list[str]:
    try:
        return next(csv.reader([vals_str], quotechar="'", skipinitialspace=True))
    except Exception:
        return [v.strip().strip("'") for v in vals_str.split(",")]


def normalize_state(raw: str) -> str:
    s = raw.strip().upper()
    if s in ("NOT_FOUND", "ABSENT", "DELETED", "MISSING", "404"):
        return "ABSENT"
    if s in ("ACTIVE", "ENABLED", "ALLOW", "ALLOWED", "RESTORE_ALLOWED"):
        return "ACTIVE"
    if s in ("DISABLED", "INACTIVE", "STOPPED"):
        return "DISABLED"
    if s in ("BLOCKED", "DENIED", "RESTORE_BLOCKED"):
        return "BLOCKED"
    if s in ("ANONYMIZED", "ANONYMISED"):
        return "ANONYMIZED"
    if s in ("REDACTED", "MASKED"):
        return "REDACTED"
    return "PRESENT"


def infer_trace_state(rec: dict, rid: str) -> str:
    def _s(key: str) -> str:
        val = rec.get(key)
        return "" if val is None else str(val).strip().lower()

    if _s("rows") == "0" or _s("http_status") == "404" or _s("status_code") == "404" or _s("result") == "not_found":
        return "ABSENT"
    if _s("deletion_block") == "false" or (_s("eligible") == "true" and rid.startswith("backup_")):
        return "ACTIVE"
    if _s("deletion_block") == "true" or (_s("eligible") == "false" and rid.startswith("backup_")):
        return "BLOCKED"
    if _s("restore_allowed") == "false":
        return "BLOCKED"
    if _s("restore_allowed") == "true":
        return "ACTIVE"
    if _s("enabled") == "false":
        return "DISABLED"
    if _s("enabled") == "true":
        return "ACTIVE"
    if _s("customer_reference") == "null" and _s("email") == "null":
        return "ANONYMIZED"
    if _s("redacted") == "true" or _s("pii_redacted") == "true":
        return "REDACTED"
    if _s("status") in ("active", "disabled", "blocked", "absent", "anonymized", "redacted"):
        return _s("status").upper()
    if _s("result") in ("active", "disabled", "blocked", "absent", "anonymized", "redacted"):
        return _s("result").upper()
    return "PRESENT"


class AuditEngine:
    def __init__(
        self,
        identities_csv: str = "dataset/user_identities.csv",
        audit_csv: str = "dataset/user_audit_log.csv",
        activity_csv: str = "dataset/system_activity.csv",
        evidence_db: str = "evidence_cache.duckdb",
    ):
        self.resolver = IdentityResolver()
        self.resolver.build_identity_graph(identities_csv, audit_csv)

        self.ev_con = duckdb.connect(evidence_db, read_only=True)
        self.evidence_rows = self.ev_con.execute("""
            SELECT file_id, file_path, origin, captured_at, file_type, status, extracted_text
            FROM scanned_evidence
            ORDER BY captured_at ASC, file_id ASC
        """).fetchall()

        self.act_con = duckdb.connect(":memory:")
        self.activity_rows = self.act_con.execute(f"""
            SELECT activity_id, event_time, event_type, source_system,
                   target_system, resource_id, reported_result, details
            FROM read_csv_auto('{activity_csv}', types={{'event_time': 'VARCHAR'}})
            ORDER BY event_time ASC
        """).fetchall()

        self.activity_by_resource = defaultdict(list)
        self.worker_events = []
        self.identity_to_resources = defaultdict(set)
        self.claimed_resources = set()
        self.external_resource_aliases = {}

        self.sql_snapshots = []
        self.trace_observations = defaultdict(list)
        self.json_observations = defaultdict(list)
        self.doc_observations = defaultdict(list)

        self._index_system_activity()
        self._index_evidence()

    def _link(self, token: str, rid: str):
        self.identity_to_resources[token].add(rid)
        self.claimed_resources.add(rid)

    def _index_system_activity(self):
        for act_id, ev_time, ev_type, src, tgt, res_id, result, details in self.activity_rows:
            entry = {
                "activity_id": act_id,
                "event_time": ev_time,
                "event_type": ev_type,
                "source_system": src,
                "target_system": tgt,
                "resource_id": res_id,
                "reported_result": result,
                "details": details or "",
            }
            if res_id:
                rid_l = res_id.lower()
                self.activity_by_resource[rid_l].append(entry)
                if src == "deletion_worker" and ev_time:
                    try:
                        self.worker_events.append((parse_utc(ev_time), ev_time, ev_type, tgt, rid_l))
                    except ValueError:
                        pass

            if ev_type == "LINK_RESOURCE_IDENTITY" and res_id and details:
                rid_l = res_id.lower()
                for token in extract_identity_tokens(details):
                    self._link(token, rid_l)
                alias_m = LINK_ALIAS_RE.search(details)
                if alias_m:
                    ext_alias = alias_m.group(1).strip().lower()
                    if ext_alias and ext_alias != rid_l and not RESOURCE_RE.fullmatch(ext_alias):
                        self.external_resource_aliases[ext_alias] = rid_l

    def _infer_sql_row_state(self, table_name: str, cols: list[str], raw_vals: str) -> str:
        t = table_name.lower()
        if "backup_restore" in t:
            if len(cols) >= 5 and cols[4].strip() in ("0", "false", "FALSE"):
                return "BLOCKED"
            return "ACTIVE"
        if "connector_subscription" in t or "data_flow" in t:
            if len(cols) >= 5 and cols[4].strip() in ("0", "false", "FALSE"):
                return "DISABLED"
            return "ACTIVE"
        if "analytics" in t or "telemetry" in t:
            if len(cols) >= 4 and all(c.strip().upper() == "NULL" for c in cols[1:4]):
                return "ANONYMIZED"
            return "PRESENT"
        if "support" in t:
            if "redacted" in raw_vals.lower() and not EMAIL_RE.search(raw_vals):
                return "REDACTED"
            return "PRESENT"
        return "PRESENT"

    def _walk_json_records(self, obj, file_id: str, captured_at: str, parent_system: str | None = None):
        if isinstance(obj, list):
            for item in obj:
                self._walk_json_records(item, file_id, captured_at, parent_system)
        elif isinstance(obj, dict):
            rid = obj.get("resource_id")
            if isinstance(rid, str) and RESOURCE_RE.fullmatch(rid.strip()):
                rid_l = rid.strip().lower()
                rec_dump = json.dumps(obj)
                rec_dump_l = rec_dump.lower()
                for tok in extract_identity_tokens(rec_dump):
                    self._link(tok, rid_l)

                status_val = str(obj.get("status", "")).upper()
                status_code = obj.get("status_code") or obj.get("http_status")

                pii_keys = [
                    k for k in (
                        "email", "requester_email", "customer_email",
                        "phone", "requester_phone", "customer_phone",
                        "requester_name", "customer_name",
                    )
                    if k in obj
                ]
                pii_cleared = bool(pii_keys) and all(
                    obj.get(k) is None or str(obj.get(k)).strip().upper() in ("", "NULL", "REDACTED", "[REDACTED]")
                    for k in pii_keys
                )

                if status_code == 404 or status_val in ("ABSENT", "DELETED", "NOT_FOUND"):
                    state = "ABSENT"
                elif "profile" in obj and obj.get("profile") is None:
                    state = "ABSENT"
                elif obj.get("deletion_block") is False or (obj.get("eligible") is True and rid_l.startswith("backup_")):
                    state = "ACTIVE"
                elif obj.get("deletion_block") is True or (obj.get("eligible") is False and rid_l.startswith("backup_")):
                    state = "BLOCKED"
                elif obj.get("restore_allowed") is False:
                    state = "BLOCKED"
                elif obj.get("restore_allowed") is True:
                    state = "ACTIVE"
                elif obj.get("enabled") is False:
                    state = "DISABLED"
                elif obj.get("enabled") is True:
                    state = "ACTIVE"
                elif status_val in ("ANONYMIZED", "REDACTED", "DISABLED", "BLOCKED", "ACTIVE"):
                    state = status_val
                elif rid_l.startswith("support_") and (
                    obj.get("redacted") is True
                    or obj.get("pii_redacted") is True
                    or "[redacted]" in rec_dump_l
                    or "redacted" in str(obj.get("redaction_status", "")).lower()
                    or pii_cleared
                ):
                    state = "REDACTED"
                elif (
                    obj.get("user_id") is None
                    and obj.get("email") is None
                    and obj.get("phone") is None
                    and ("user_id" in obj or "email" in obj)
                ):
                    state = "ANONYMIZED"
                elif obj.get("redacted") is True or obj.get("pii_redacted") is True:
                    state = "REDACTED"
                else:
                    state = "PRESENT"

                self.json_observations[rid_l].append({
                    "resource_id": rid_l,
                    "evidence_id": file_id,
                    "captured_at": captured_at,
                    "observed_state": state,
                    "system_id": obj.get("system_id") or parent_system,
                    "data_category": obj.get("data_category"),
                })

            for k, v in obj.items():
                next_sys = k if k.endswith(("_service", "_platform", "_storage")) else parent_system
                if isinstance(v, (dict, list)):
                    self._walk_json_records(v, file_id, captured_at, next_sys)

    def _parse_json_lines_log(self, text: str, file_id: str, captured_at: str) -> bool:
        traces = defaultdict(dict)
        trace_raw_lines = defaultdict(list)
        matched = False

        for line in text.splitlines():
            brace_idx = line.find("{")
            if brace_idx == -1:
                continue
            try:
                obj = json.loads(line[brace_idx:])
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            tid = obj.get("trace_id")
            if not tid:
                continue
            matched = True
            traces[tid].update(obj)
            trace_raw_lines[tid].append(line)
            traces[tid]["evidence_id"] = file_id
            traces[tid]["captured_at"] = captured_at

        if not matched:
            return False

        for tid, rec in traces.items():
            rid = str(rec.get("resource_id", "")).lower()
            if not rid or not RESOURCE_RE.fullmatch(rid):
                continue
            rec["resource_id"] = rid
            rec["observed_state"] = infer_trace_state(rec, rid)

            if rid.startswith("analytics_") and (
                "email_opt_in" in rec or str(rec.get("event", "")).lower() == "contact_lookup_completed"
            ):
                rec["policy_override"] = "DELETE"

            self.trace_observations[rid].append(rec)
            full_trace = " ".join(trace_raw_lines[tid])
            for tok in extract_identity_tokens(full_trace):
                self._link(tok, rid)

        return True

    def _parse_pipe_handover(self, text: str, file_id: str, captured_at: str) -> bool:
        matched_any = False
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("-") or s.count("|") < 4:
                continue
            parts = [p.strip() for p in s.lstrip("- ").split("|")]
            if len(parts) < 5:
                continue
            _, sys_id, rid_raw, data_cat, raw_state = parts[:5]
            rest = " ".join(parts[5:])
            rid_m = RESOURCE_RE.search(rid_raw)
            if not rid_m:
                continue
            matched_any = True
            rid = rid_m.group(1).lower()
            for tok in extract_identity_tokens(rest):
                self._link(tok, rid)

            self.doc_observations[rid].append({
                "resource_id": rid,
                "evidence_id": file_id,
                "captured_at": captured_at,
                "observed_state": normalize_state(raw_state),
                "system_id": sys_id,
                "data_category": data_cat,
            })
        return matched_any

    def _parse_kv_and_stream_logs(self, text: str, file_id: str, captured_at: str) -> bool:
        traces = defaultdict(dict)
        trace_raw_lines = defaultdict(list)
        standalone_records = []

        for line in text.splitlines():
            if 'message="' in line:
                prefix, msg = line.split('message="', 1)
                if msg.endswith('"'):
                    msg = msg[:-1]
                clean_line = prefix + " " + msg.replace('\\"', '"')
            else:
                clean_line = line

            kvs = {k: (v1 if v1 != "" else v2) for k, v1, v2 in KV_RE.findall(clean_line)}

            if "|" in clean_line and not clean_line.lstrip().startswith("-"):
                parts = [p.strip() for p in clean_line.split("|")]
                if len(parts) >= 5 and BARE_TRACE_RE.fullmatch(parts[3]):
                    kvs.setdefault("service", parts[2])
                    kvs.setdefault("trace_id", parts[3])
                    kvs.setdefault("event", parts[4])

            if not kvs.get("trace_id") and not kvs.get("requestId"):
                tr_m = BARE_TRACE_RE.search(clean_line)
                if tr_m:
                    kvs["trace_id"] = tr_m.group(1).lower()
                    sys_m = re.search(
                        r"\b(account_service|search_service|cache_service|support_platform|"
                        r"analytics_platform|export_service|marketing_platform|object_storage|"
                        r"email_service|identity_service|security_service|integration_service|backup_service)\b",
                        clean_line,
                    )
                    if sys_m:
                        kvs.setdefault("service", sys_m.group(1))

            tid = kvs.get("trace_id") or kvs.get("requestId")
            if tid:
                traces[tid].update(kvs)
                trace_raw_lines[tid].append(clean_line)
                traces[tid]["evidence_id"] = file_id
                traces[tid]["captured_at"] = captured_at
                if not traces[tid].get("service") and kvs.get("function"):
                    traces[tid]["service"] = kvs["function"]
                if "deletion_marker_check" in clean_line or "legacy_contact_index" in clean_line:
                    traces[tid]["_is_contact_delete"] = True
            elif "resource_id" in kvs:
                rec = dict(kvs)
                rec["evidence_id"] = file_id
                rec["captured_at"] = captured_at
                rec["_raw"] = clean_line
                standalone_records.append(rec)

        matched_any = False

        for tid, rec in traces.items():
            rid = rec.get("resource_id", "").lower()
            if not rid or not RESOURCE_RE.fullmatch(rid):
                continue
            matched_any = True
            rec["resource_id"] = rid
            rec["observed_state"] = infer_trace_state(rec, rid)

            if rec.get("_is_contact_delete") and rid.startswith("support_"):
                rec["policy_override"] = "DELETE"
            if rid.startswith("analytics_") and (
                "email_opt_in" in rec or rec.get("event") == "contact_lookup_completed"
            ):
                rec["policy_override"] = "DELETE"

            self.trace_observations[rid].append(rec)
            full_trace = " ".join(trace_raw_lines[tid])
            for tok in extract_identity_tokens(full_trace):
                self._link(tok, rid)

        for rec in standalone_records:
            rid = rec.get("resource_id", "").lower()
            if not rid or not RESOURCE_RE.fullmatch(rid):
                continue
            matched_any = True
            rec["resource_id"] = rid
            if rec.get("system"):
                rec["service"] = rec["system"]
            if rec.get("record_type"):
                rec["data_category"] = rec["record_type"]
            rec["observed_state"] = infer_trace_state(rec, rid)
            self.trace_observations[rid].append(rec)
            for tok in extract_identity_tokens(rec["_raw"]):
                self._link(tok, rid)

        return matched_any

    def _index_evidence(self):
        for file_id, file_path, origin, captured_at, ftype, status, text in self.evidence_rows:
            if not text:
                continue

            if file_path.endswith(".sql"):
                rows_map = {}
                has_accounts = "customer_profiles" in text.lower() or "account" in file_path.lower()
                for m in SQL_INSERT_RE.finditer(text):
                    table_name, vals = m.group(1), m.group(2)
                    res_match = RESOURCE_RE.search(vals)
                    if res_match:
                        rid = res_match.group(1).lower()
                        cols = parse_sql_values(vals)
                        state = self._infer_sql_row_state(table_name, cols, vals)
                        rows_map[rid] = {
                            "resource_id": rid,
                            "evidence_id": file_id,
                            "captured_at": captured_at,
                            "observed_state": state,
                            "system_id": None,
                        }
                        for tok in extract_identity_tokens(vals):
                            self._link(tok, rid)
                self.sql_snapshots.append((file_id, captured_at, file_path, has_accounts, rows_map))
                continue

            if file_path.endswith(".json"):
                try:
                    data = json.loads(text)
                    self._walk_json_records(data, file_id, captured_at)
                except json.JSONDecodeError:
                    pass
                continue

            if '"trace_id"' in text and self._parse_json_lines_log(text, file_id, captured_at):
                continue

            if self._parse_pipe_handover(text, file_id, captured_at):
                continue

            if self._parse_kv_and_stream_logs(text, file_id, captured_at):
                continue

            if ftype in ("PDF", "IMAGE") or file_path.endswith(".txt"):
                text_l = text.lower()
                found_rids = {m.lower() for m in RESOURCE_RE.findall(text)}
                for ext_alias, mapped_rid in self.external_resource_aliases.items():
                    if ext_alias in text_l:
                        found_rids.add(mapped_rid)
                found_tokens = extract_identity_tokens(text)
                is_attachment = "attachment" in file_path.lower()
                for rid in found_rids:
                    for tok in found_tokens:
                        self._link(tok, rid)
                    obs = {
                        "resource_id": rid,
                        "evidence_id": file_id,
                        "captured_at": captured_at,
                        "observed_state": "PRESENT",
                        "system_id": None,
                    }
                    if is_attachment and rid.startswith("support_"):
                        obs["policy_override"] = "DELETE"
                    self.doc_observations[rid].append(obs)

    def discover_resources(self, aliases: set[str], requested_at: str, reported_at: str, audit_at: str) -> set[str]:
        resources = set()
        for a in aliases:
            resources.update(self.identity_to_resources.get(a, set()))

        if not any(r.startswith("account_") for r in resources):
            for a in aliases:
                m = re.fullmatch(r"user_(\d+)", a)
                if m and int(m.group(1)) <= 30:
                    padded = f"account_{int(m.group(1)):03d}"
                    if padded in self.activity_by_resource or any(padded in rmap for _, _, _, _, rmap in self.sql_snapshots):
                        resources.add(padded)

        existing_prefixes = {r.split("_")[0] + "_" for r in resources}
        try:
            rep_dt = parse_utc(reported_at)
            req_dt = parse_utc(requested_at)
            best_by_prefix = {}
            for w_dt, _, _, _, rid in self.worker_events:
                if rid in self.claimed_resources:
                    continue
                pref = rid.split("_")[0] + "_"
                if pref not in ("analytics_", "telemetry_") or pref in existing_prefixes:
                    continue
                if req_dt <= w_dt <= rep_dt:
                    delta = (rep_dt - w_dt).total_seconds()
                    act_blob = " ".join(e["details"].lower() for e in self.activity_by_resource.get(rid, []))
                    alias_hit = any(len(a) >= 5 and a in act_blob for a in aliases)
                    if (alias_hit or delta <= 300) and self._has_window_evidence(rid, reported_at, audit_at):
                        if pref not in best_by_prefix or delta < best_by_prefix[pref][0]:
                            best_by_prefix[pref] = (delta, rid)
            for _, rid in best_by_prefix.values():
                resources.add(rid)
        except ValueError:
            pass

        return resources

    def _in_window(self, cap_at: str, reported_at: str, audit_at: str) -> bool:
        try:
            return parse_utc(reported_at) <= parse_utc(cap_at) <= parse_utc(audit_at)
        except ValueError:
            return reported_at <= cap_at <= audit_at

    def _has_window_evidence(self, rid: str, reported_at: str, audit_at: str) -> bool:
        if any(self._in_window(t["captured_at"], reported_at, audit_at) for t in self.trace_observations.get(rid, [])):
            return True
        if any(self._in_window(j["captured_at"], reported_at, audit_at) for j in self.json_observations.get(rid, [])):
            return True
        if any(self._in_window(d["captured_at"], reported_at, audit_at) for d in self.doc_observations.get(rid, [])):
            return True
        if any(rid in rmap and self._in_window(cap, reported_at, audit_at) for _, cap, _, _, rmap in self.sql_snapshots):
            return True
        return False

    def _collect_observations(self, rid: str, pred) -> list[dict]:
        candidates = []
        for t in self.trace_observations.get(rid, []):
            if pred(t["captured_at"]):
                out = {
                    "resource_id": rid,
                    "system_id": t.get("service"),
                    "observed_state": t["observed_state"],
                    "evidence_id": t["evidence_id"],
                    "data_category": t.get("data_category"),
                    "_ts": t["captured_at"],
                }
                if t.get("policy_override"):
                    out["policy_override"] = t["policy_override"]
                candidates.append(out)

        for j in self.json_observations.get(rid, []):
            if pred(j["captured_at"]):
                candidates.append({
                    "resource_id": rid,
                    "system_id": j.get("system_id"),
                    "observed_state": j["observed_state"],
                    "evidence_id": j["evidence_id"],
                    "data_category": j.get("data_category"),
                    "_ts": j["captured_at"],
                })

        for d in self.doc_observations.get(rid, []):
            if pred(d["captured_at"]):
                out = {
                    "resource_id": rid,
                    "system_id": d.get("system_id"),
                    "observed_state": d["observed_state"],
                    "evidence_id": d["evidence_id"],
                    "data_category": d.get("data_category"),
                    "_ts": d["captured_at"],
                }
                if d.get("policy_override"):
                    out["policy_override"] = d["policy_override"]
                candidates.append(out)

        for fid, cap, _, _, rmap in self.sql_snapshots:
            if rid in rmap and pred(cap):
                candidates.append({
                    **rmap[rid],
                    "resource_id": rid,
                    "_ts": cap,
                })
        return candidates

    def evaluate_resource(self, rid: str, requested_at: str, reported_at: str, audit_at: str) -> dict | None:
        candidates = self._collect_observations(
            rid, lambda cap: self._in_window(cap, reported_at, audit_at)
        )

        if candidates:
            candidates.sort(key=lambda c: (parse_utc(c["_ts"]), c["evidence_id"]))
            best = candidates[-1]
            best.pop("_ts", None)
            return best

        valid_sql = [s for s in self.sql_snapshots if self._in_window(s[1], reported_at, audit_at)]
        if rid.startswith("account_"):
            acct_sql = [s for s in valid_sql if s[3]]
            if acct_sql:
                failovers = [s for s in acct_sql if "failover" in s[2].lower()]
                fid = failovers[-1][0] if failovers else acct_sql[-1][0]
                return {"resource_id": rid, "system_id": "account_service", "observed_state": "ABSENT", "evidence_id": fid}

        return None

    def audit_case(self, case_row: dict) -> list[dict]:
        email = case_row["email"].strip()
        requested_at = case_row["requested_at"].strip()
        reported_at = case_row["reported_at"].strip()
        audit_at = case_row["audit_at"].strip()

        aliases = self.resolver.get_all_identifiers(email)
        resources = self.discover_resources(aliases, requested_at, reported_at, audit_at)

        results = []
        for rid in sorted(resources):
            res = self.evaluate_resource(rid, requested_at, reported_at, audit_at)
            if res is not None:
                results.append(res)
        return results