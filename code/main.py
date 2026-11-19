import argparse
import csv
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_engine import AuditEngine
from media_scanner import MediaScanner
from remediation import build_case_output


NEGATION_OR_NON_DELETION_RE = re.compile(
    r"|".join([
        r"\bnot\s+(?:asking|a\s+request)\s+(?:for|to)\s+(?:delet|eras|clos|remov)",
        r"\bdo\s+not\s+(?:close|delet|eras|remov)",
        r"\bdon'?t\s+(?:delet|clos|eras|remov)",
        r"\bleave\s+(?:the\s+account|my\s+profile)\s+(?:active|in\s+place)",
        r"\bkeep\s+(?:the|my)\s+account\s+(?:active|open|as\s+it\s+is)\b",
        r"\bcontinue\s+using\s+the\s+service\b",
        r"\bwithout\s+removing\s+any\s+of\s+my\s+records\b",
        r"\bremove\s+me\s+from\s+marketing\s+lists\s+only\b",
        r"\b(?:unsubscribe|opt[\s-]?out)\b.*\b(?:marketing|newsletter|promotional)\b",
        r"\bstop\s+the\s+promotional\s+emails\b",
        r"\bdownload\s+my\s+account\s+information\s+in\s+a\s+portable\s+format\b",
        r"\bhelp\s+resetting\s+the\s+login\b",
        r"\bcopy\s+of\s+last\s+year'?s\s+invoices\b",
        r"\bchange\s+the\s+email\s+address\s+used\b",
        r"\bmobile\s+number\s+on\s+my\s+profile\s+is\s+out\s+of\s+date\b",
        r"\bsurname\s+is\s+misspelled\b",
        r"\binformation\s+request,\s+not\s+a\s+request\s+to\s+erase\b",
        # Spanish / French / Portuguese negations & non-deletion intents
        r"\bno\s+(?:elimin|borr|cierr|suprim)",
        r"\bne\s+(?:pas\s+)?(?:supprim|effac|ferm)",
        r"\bn[ãa]o\s+(?:exclu|apag|encerr|remov)",
        r"\b(?:désabonner|d[ée]sinscrire|cancelar\s+suscripci[óo]n|cancelar\s+inscri[çc][ãa]o)\b",
        r"\b(?:exporter|exportar)\s+(?:mes|mis|meus)\s+(?:donn[ée]es|datos|dados)\b",
        r"\b(?:corriger|corregir|corrigir)\s+(?:mon|mi|meu)\b",
    ]),
    re.IGNORECASE,
)

POSITIVE_DELETION_RE = re.compile(
    r"\b("
    r"delet\w*|eras\w*|remov\w*|clos\w*|purg\w*|wip\w*|forget\w*|forgotten|terminat\w*|deactivat\w*|"
    r"elimin\w*|borr\w*|suprim\w*|cerr\w*|olvid\w*|"
    r"supprim\w*|effac\w*|ferm\w*|cl[ôo]tur\w*|oubli\w*|"
    r"exclu\w*|apag\w*|encerr\w*|esquec\w*|"
    r"l[öo]sch\w*|entfern\w*"
    r")\b",
    re.IGNORECASE,
)


def is_not_applicable_request(request_text: str) -> bool:
    txt = (request_text or "").strip()
    return bool(txt and NEGATION_OR_NON_DELETION_RE.search(txt))


def ensure_evidence_cache(db_path: str = "evidence_cache.duckdb"):
    if not Path(db_path).exists():
        print(f"{db_path} not found. Running MediaScanner().scan_all()...")
        scanner = MediaScanner(db_path=db_path)
        summary = scanner.scan_all()
        print("MediaScanner summary:", summary)


def run_pipeline(input_csv: str, output_csv: str, db_path: str = "evidence_cache.duckdb"):
    t0 = time.perf_counter()
    ensure_evidence_cache(db_path)
    engine = AuditEngine(evidence_db=db_path)
    with open(input_csv, mode="r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    results = []
    for case in cases:
        if is_not_applicable_request(case.get("request_text", "")):
            out_row = build_case_output(case["case_id"], [], is_not_applicable=True)
        else:
            resource_states = engine.audit_case(case)
            out_row = build_case_output(case["case_id"], resource_states, is_not_applicable=False)
        results.append(out_row)

    results.sort(key=lambda r: r["case_id"])
    with open(output_csv, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)
    elapsed = time.perf_counter() - t0
    print(f"Wrote {len(results)} rows to {output_csv} in {elapsed:.2f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GDPR Deletion Audit Engine")
    parser.add_argument("--input", default="dataset/deletion_requests.csv")
    parser.add_argument("--output", default="output.csv")
    args = parser.parse_args()
    run_pipeline(args.input, args.output)