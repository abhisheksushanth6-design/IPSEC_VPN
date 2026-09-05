"""Service layer for Layer 14 — Report Generation (PDF).

Coordinates data collection, PDF document rendering, safe filesystem storage,
and database lifecycle management for security assessment reports.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.layers.layer14_reports.collector import report_collector
from app.layers.layer14_reports.pdf_renderer import pdf_renderer
from app.layers.layer14_reports.schemas import (
    ReportGenerateRequest,
    ReportMetadataDTO,
)
from app.layers.layer14_reports.storage import (
    delete_report_file,
    resolve_report_path,
    save_report_file,
)
from app.models.report import ReportRow

logger = logging.getLogger(__name__)


class ReportService:
    """Core reporting facade for generating, querying, and downloading security assessment PDFs."""

    def generate_report(self, db: Session, request: ReportGenerateRequest) -> ReportMetadataDTO:
        """Collect analysis outputs, render professional PDF, and persist record."""
        # 1. Collect empirical data across layers 01-13
        report_data = report_collector.collect(db, request)
        report_id = report_data.metadata["report_id"]
        title = report_data.metadata["title"]

        # 2. Render PDF bytes using ReportLab
        try:
            pdf_bytes = pdf_renderer.render(report_data)
        except Exception as exc:
            logger.error("Failed to render PDF report %s: %s", report_id, exc, exc_info=True)
            raise RuntimeError(f"PDF rendering failed: {exc}") from exc

        # 3. Save PDF file safely
        filename = f"ipsec-assessment-{report_id.lower()}.pdf"
        file_path = save_report_file(filename, pdf_bytes)
        file_size = len(pdf_bytes)

        # Estimate page count (at least 2 pages: cover + body)
        page_count = max(2, file_size // 7000)

        # 4. Record report in SQLite
        row = ReportRow(
            id=report_id,
            report_type=request.report_type,
            title=title,
            filename=filename,
            file_path=str(file_path),
            file_size_bytes=file_size,
            page_count=page_count,
            status="COMPLETED",
            error_message=None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        return self._to_dto(row)

    def list_reports(self, db: Session) -> list[ReportMetadataDTO]:
        """List all generated assessment reports ordered by timestamp descending."""
        rows = db.scalars(select(ReportRow).order_by(ReportRow.generated_at.desc())).all()
        return [self._to_dto(r) for r in rows]

    def get_report(self, db: Session, report_id: str) -> Optional[ReportRow]:
        """Retrieve a specific report row by its identifier."""
        return db.scalar(select(ReportRow).where(ReportRow.id == report_id))

    def get_report_pdf_path(self, db: Session, report_id: str) -> Optional[Path]:
        """Resolve and verify existence of report PDF file on disk."""
        row = self.get_report(db, report_id)
        if not row:
            return None
        try:
            path = resolve_report_path(row.filename)
            if path.is_file():
                return path
        except ValueError:
            return None
        return None

    def delete_report(self, db: Session, report_id: str) -> bool:
        """Delete report record from database and remove file from disk."""
        row = self.get_report(db, report_id)
        if not row:
            return False

        # Remove physical file
        delete_report_file(row.filename)

        # Remove database record
        db.delete(row)
        db.commit()
        return True

    @staticmethod
    def _to_dto(row: ReportRow) -> ReportMetadataDTO:
        return ReportMetadataDTO(
            id=row.id,
            report_type=row.report_type,
            title=row.title,
            filename=row.filename,
            file_size_bytes=row.file_size_bytes,
            page_count=row.page_count,
            status=row.status,
            error_message=row.error_message,
            generated_at=row.generated_at.isoformat(),
            download_url=f"/api/reports/{row.id}/download",
        )


report_service = ReportService()
