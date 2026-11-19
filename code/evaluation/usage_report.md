# Model & Token Usage Report

## Final Full-Dataset Run Summary (`output.csv` — 518 Cases)
The production audit pipeline (`code/main.py`) is **100% deterministic and local**, using zero external LLM API calls.

| Provider | Model / Engine | Calls | Input Tokens | Output Tokens | Total Tokens | Avg Tokens / Request | Estimated Cost (USD) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| None (Deterministic Python) | Rule / Graph / Parser Engine | 0 | 0 | 0 | 0 | 0.0 | $0.00 |
| Local ONNX Runtime | `rapidocr-onnxruntime` (offline OCR, cached in DuckDB) | 11 images (cached) | 0 | 0 | 0 | 0.0 | $0.00 |
| **Overall Total** | — | **0 LLM calls** | **0** | **0** | **0** | **0.0** | **$0.00** |

## Runtime & Caching Efficiency
- **Evidence Cache:** All 94 evidence files (`79 TEXT`, `11 IMAGE`, `4 PDF`) pre-indexed into `evidence_cache.duckdb` (`SCANNED = 94/94`, `PENDING_VLM = 0`).
- **End-to-End Execution Time (518 cases):** `0.52s` on local Windows Python 3.12 (`.venv`).
- **Estimated Cost per Request:** `$0.00`.