# Deterministic GDPR Right-to-Erasure Audit Engine

A deterministic compliance audit pipeline that verifies whether customer PII has been genuinely erased across distributed commerce systems (databases, read/failover replicas, JSON exports, cloud runtime logs, PDFs, and OCR screenshots) at a strict `audit_at` cutoff.

## Benchmark Performance
- **Case-Level Status Accuracy:** 32 / 32 (**100.0%**)
- **Step Precision:** **92.1%** | **Step Recall:** **80.4%**
- **Sequence Accuracy:** **84.4%** | **Field Accuracy:** **71.0%**
- **Throughput & Cost:** **518 multi-format cases audited in 0.64s** at **$0.00 inference cost** (100% local, zero external LLM API calls)

## Architecture
- `code/identity_resolver.py` — `NetworkX` + `DuckDB` identity graph linking current and historical emails, `user_id`s, and SHA-256 hashes from audit logs.
- `code/media_scanner.py` — Offline multimodal indexer (`pypdf` + `rapidocr-onnxruntime`) caching 94 artifacts (`79 TEXT`, `11 IMAGE`, `4 PDF`) into `evidence_cache.duckdb`.
- `code/audit_engine.py` — Multi-format parser (SQL snapshots, nested JSON, JSONL traces, escaped cloud runtime logs, pipe-delimited shift handovers, PDF/OCR docs) with strict UTC `[reported_at, audit_at]` windowing.
- `code/remediation.py` — Policy engine driven by `deletion_rules.csv`, enforcing canonical phase ordering (`FINDING` -> `REMEDIATION` -> `VERIFICATION`) and blocker-first remediation (`DISABLE_DATA_FLOW` / `BLOCK_RESTORE` before record mutations).
- `code/evaluation/` — Evaluation harness (`eval.py`), full benchmark & custom test cases (`evaluation_report.md`), and runtime/cost report (`usage_report.md`).

## Quick Start
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python code/main.py --input dataset/deletion_requests.csv --output output.csv
