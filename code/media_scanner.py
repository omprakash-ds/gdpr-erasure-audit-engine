import csv
from pathlib import Path
import duckdb
from pypdf import PdfReader
from rapidocr_onnxruntime import RapidOCR


TEXT_EXTENSIONS = {".log", ".txt", ".json", ".csv", ".md", ".sql"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


class MediaScanner:
    def __init__(self, db_path: str = "evidence_cache.duckdb", dataset_dir: str = "dataset"):
        self.db_path = db_path
        self.dataset_dir = Path(dataset_dir)
        self.con = duckdb.connect(self.db_path)
        self.ocr = RapidOCR()
        self._init_table()

    def _init_table(self):
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS scanned_evidence (
                file_id VARCHAR PRIMARY KEY,
                file_path VARCHAR,
                origin VARCHAR,
                captured_at VARCHAR,
                file_type VARCHAR,
                status VARCHAR,
                extracted_text VARCHAR
            )
        """)

    def _is_already_scanned(self, file_id: str) -> bool:
        res = self.con.execute(
            "SELECT status FROM scanned_evidence WHERE file_id = ?", [file_id]
        ).fetchone()
        return res is not None and res[0] == "SCANNED"

    def _extract_image_ocr(self, full_path: Path) -> tuple[str, str]:
        result, _ = self.ocr(str(full_path))
        text = "\n".join(line[1] for line in result) if result else ""
        return ("SCANNED", text.strip()) if text.strip() else ("PENDING_VLM", "")

    def scan_all(self, manifest_csv: str = "dataset/evidence_files.csv"):
        with open(manifest_csv, mode="r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        stats = {"TEXT_SCANNED": 0, "PDF_SCANNED": 0, "IMAGE_SCANNED": 0, "IMAGE_PENDING": 0, "SKIPPED_CACHED": 0, "MISSING": 0}

        for row in rows:
            file_id = row["file_id"].strip()
            rel_path = row["file_path"].strip()
            origin = row["origin"].strip()
            captured_at = row["captured_at"].strip()

            if self._is_already_scanned(file_id):
                stats["SKIPPED_CACHED"] += 1
                continue

            full_path = self.dataset_dir / rel_path
            if not full_path.exists():
                stats["MISSING"] += 1
                continue

            ext = full_path.suffix.lower()
            if ext in TEXT_EXTENSIONS:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                status, file_type = "SCANNED", "TEXT"
                stats["TEXT_SCANNED"] += 1
            elif ext == ".pdf":
                reader = PdfReader(str(full_path))
                content = "\n".join(page.extract_text() or "" for page in reader.pages)
                status, file_type = "SCANNED", "PDF"
                stats["PDF_SCANNED"] += 1
            elif ext in IMAGE_EXTENSIONS:
                status, content = self._extract_image_ocr(full_path)
                file_type = "IMAGE"
                stats["IMAGE_SCANNED" if status == "SCANNED" else "IMAGE_PENDING"] += 1
            else:
                content, status, file_type = "", "UNSUPPORTED", ext

            self.con.execute("""
                INSERT OR REPLACE INTO scanned_evidence
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [file_id, rel_path, origin, captured_at, file_type, status, content])

        return stats


if __name__ == "__main__":
    scanner = MediaScanner()
    summary = scanner.scan_all()
    print("Scan Summary:", summary)

    counts = scanner.con.execute(
        "SELECT file_type, status, COUNT(*) FROM scanned_evidence GROUP BY 1, 2 ORDER BY 1, 2"
    ).fetchall()
    print("\nBreakdown in evidence_cache.duckdb:")
    for ftype, status, cnt in counts:
        print(f"  - {ftype} | {status}: {cnt}")