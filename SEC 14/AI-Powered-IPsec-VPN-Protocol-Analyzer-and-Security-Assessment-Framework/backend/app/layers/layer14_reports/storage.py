"""Secure filesystem storage manager for generated PDF reports.

Ensures reports are stored strictly in the dedicated application reports
directory with path-traversal prevention and filename sanitization.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# Resolve storage directory: canonical is backend/data/reports; legacy is backend/app/data/reports
BACKEND_ROOT = Path(__file__).resolve().parents[3]
APP_DIR = Path(__file__).resolve().parents[2]
PRIMARY_REPORTS_DIR = BACKEND_ROOT / "data" / "reports"
LEGACY_REPORTS_DIR = APP_DIR / "data" / "reports"
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def get_reports_dir() -> Path:
    """Ensure and return the primary reports storage directory (backend/data/reports)."""
    PRIMARY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return PRIMARY_REPORTS_DIR


def sanitize_filename(filename: str) -> str:
    """Strip path traversal elements and unsafe characters from filenames."""
    base = os.path.basename(filename)
    clean = _SAFE_FILENAME.sub("_", base)
    if not clean.endswith(".pdf"):
        clean += ".pdf"
    return clean


def resolve_report_path(filename: str) -> Path:
    """Resolve report path across primary and legacy storage directories with traversal protection."""
    if not filename or "\x00" in filename:
        raise ValueError(f"Invalid filename: {filename!r}")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError(f"Path traversal detected for filename: {filename}")

    sanitized = sanitize_filename(filename)
    primary_dir = get_reports_dir().resolve()
    legacy_dir = (LEGACY_REPORTS_DIR).resolve()

    # If the file exists in the canonical reports dir, use it
    candidate_primary = (primary_dir / sanitized).resolve()
    if candidate_primary.is_file():
        _verify_confinement(candidate_primary, primary_dir, filename)
        return candidate_primary

    # Fallback to legacy reports dir if file exists there
    candidate_legacy = (legacy_dir / sanitized).resolve()
    if candidate_legacy.is_file():
        _verify_confinement(candidate_legacy, legacy_dir, filename)
        return candidate_legacy

    # Default to candidate in primary directory for new writes or checks
    _verify_confinement(candidate_primary, primary_dir, filename)
    return candidate_primary


def _verify_confinement(path: Path, parent_dir: Path, original_filename: str) -> None:
    """Verify that path is strictly confined within parent_dir."""
    try:
        if not path.is_relative_to(parent_dir):
            raise ValueError(f"Path traversal detected for filename: {original_filename}")
    except AttributeError:
        if not str(path).lower().startswith(str(parent_dir).lower()):
            raise ValueError(f"Path traversal detected for filename: {original_filename}")


def save_report_file(filename: str, pdf_bytes: bytes) -> Path:
    """Save generated PDF bytes to the primary reports directory."""
    sanitized = sanitize_filename(filename)
    primary_dir = get_reports_dir().resolve()
    target_path = (primary_dir / sanitized).resolve()
    _verify_confinement(target_path, primary_dir, filename)
    target_path.write_bytes(pdf_bytes)
    return target_path


def delete_report_file(filename: str) -> bool:
    """Safely delete a report PDF file from storage if it exists."""
    deleted = False
    try:
        sanitized = sanitize_filename(filename)
        for directory in [get_reports_dir().resolve(), LEGACY_REPORTS_DIR.resolve()]:
            target_path = (directory / sanitized).resolve()
            if target_path.is_file():
                _verify_confinement(target_path, directory, filename)
                target_path.unlink()
                deleted = True
    except Exception:
        pass
    return deleted
