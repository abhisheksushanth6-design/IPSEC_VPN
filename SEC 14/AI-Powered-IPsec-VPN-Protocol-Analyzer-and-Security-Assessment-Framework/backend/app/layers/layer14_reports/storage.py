"""Secure filesystem storage manager for generated PDF reports.

Ensures reports are stored strictly in the dedicated application reports
directory with path-traversal prevention and filename sanitization.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# Resolve storage directory: backend/data/reports
BACKEND_DIR = Path(__file__).resolve().parents[2]
REPORTS_DIR = BACKEND_DIR / "data" / "reports"
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def get_reports_dir() -> Path:
    """Ensure and return the reports storage directory."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def sanitize_filename(filename: str) -> str:
    """Strip path traversal elements and unsafe characters from filenames."""
    base = os.path.basename(filename)
    clean = _SAFE_FILENAME.sub("_", base)
    if not clean.endswith(".pdf"):
        clean += ".pdf"
    return clean


def resolve_report_path(filename: str) -> Path:
    """Resolve report path and ensure it does not escape the reports directory."""
    sanitized = sanitize_filename(filename)
    reports_dir = get_reports_dir().resolve()
    resolved = (reports_dir / sanitized).resolve()

    # Path traversal check
    if not str(resolved).startswith(str(reports_dir)):
        raise ValueError(f"Path traversal detected for filename: {filename}")

    return resolved


def save_report_file(filename: str, pdf_bytes: bytes) -> Path:
    """Save generated PDF bytes to the reports directory."""
    target_path = resolve_report_path(filename)
    target_path.write_bytes(pdf_bytes)
    return target_path


def delete_report_file(filename: str) -> bool:
    """Safely delete a report PDF file if it exists."""
    try:
        target_path = resolve_report_path(filename)
        if target_path.is_file():
            target_path.unlink()
            return True
    except Exception:
        pass
    return False
