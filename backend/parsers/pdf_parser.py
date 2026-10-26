"""
PDF Source Report Parser - Extracts text and structured lines from PDF incident reports,
security advisories, and forensic memos using PyMuPDF (fitz).
"""
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    import pymupdf as fitz
    PYMUPDF_AVAILABLE = True
except ImportError:
    try:
        import fitz
        PYMUPDF_AVAILABLE = True
    except ImportError:
        PYMUPDF_AVAILABLE = False


class PDFReportParser:
    @classmethod
    def is_available(cls) -> bool:
        return PYMUPDF_AVAILABLE

    @classmethod
    def parse_pdf_bytes(cls, pdf_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
        """
        Extracts textual content from a PDF file byte buffer and produces structured
        records with page numbers, line offsets, and cryptographic hashes.
        """
        if not PYMUPDF_AVAILABLE:
            raise RuntimeError("PyMuPDF (fitz) is not installed for PDF parsing.")

        records = []
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        for page_idx in range(len(doc)):
            page = doc[page_idx]
            text = page.get_text("text")
            lines = text.splitlines()

            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or len(clean_line) < 3:
                    continue

                raw_hash = hashlib.sha256(clean_line.encode("utf-8")).hexdigest()

                records.append({
                    "source_type": "pdf_report",
                    "source_file": filename,
                    "line_number": line_idx,
                    "byte_offset": page_idx + 1,  # Store page number in offset
                    "raw_record": clean_line,
                    "raw_hash": raw_hash,
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "endpoint": f"Page {page_idx + 1}",
                    "severity": "INFO",
                    "evidence_classification": "Publicly Reported Fact",
                    "extra_metadata": {
                        "page_number": page_idx + 1,
                        "line_in_page": line_idx,
                        "document_title": doc.metadata.get("title") or filename
                    }
                })

        return records
