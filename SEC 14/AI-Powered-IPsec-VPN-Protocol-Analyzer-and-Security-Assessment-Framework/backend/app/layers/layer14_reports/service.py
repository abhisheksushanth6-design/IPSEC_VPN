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

    def get_layer_status(self, db: Optional[Session] = None) -> str:
        """Return dynamic Layer 14 status based on PDF engine readiness and storage accessibility."""
        try:
            from app.layers.layer14_reports.pdf_renderer import pdf_renderer
            if pdf_renderer is None:
                return "NOT INITIALIZED"
            return "OPERATIONAL"
        except Exception as exc:
            logger.warning("Layer 14 Report service error: %s", exc)
            return "ERROR"

    def generate_report(self, db: Session, request: ReportGenerateRequest) -> ReportMetadataDTO:
        """Collect analysis outputs, render professional PDF, and persist record."""
        logger.info(
            "Initiating report generation: scope=%s, session_id=%s, custom_title=%r",
            request.report_type,
            request.session_id,
            request.title,
        )

        # 1. Collect empirical data across layers 01-13
        report_data = report_collector.collect(db, request)
        report_id = report_data.metadata["report_id"]
        title = report_data.metadata["title"]

        # 2. Render PDF bytes using ReportLab
        try:
            pdf_bytes, page_count = pdf_renderer.render_with_metadata(report_data)
        except Exception as exc:
            logger.error("Failed to render PDF report %s: %s", report_id, exc, exc_info=True)
            raise RuntimeError(f"PDF rendering failed: {exc}") from exc

        # 3. Save PDF file safely
        filename = f"ipsec-assessment-{report_id.lower()}.pdf"
        file_size = len(pdf_bytes)
        try:
            file_path = save_report_file(filename, pdf_bytes)
            abs_path = file_path.resolve()
            logger.info(
                "PDF report rendered & persisted: id=%s, filename=%s, path=%s, size=%d bytes, pages=%d",
                report_id,
                filename,
                str(abs_path),
                file_size,
                page_count,
            )
        except Exception as exc:
            logger.error("Failed to save PDF report file %s: %s", filename, exc, exc_info=True)
            raise RuntimeError(f"Failed to persist report file: {exc}") from exc

        # 4. Record report in SQLite
        row = ReportRow(
            id=report_id,
            report_type=request.report_type,
            title=title,
            filename=filename,
            file_path=str(file_path.resolve()),
            file_size_bytes=file_size,
            page_count=page_count,
            status="COMPLETED",
            error_message=None,
        )
        try:
            db.add(row)
            db.commit()
            db.refresh(row)
        except Exception as exc:
            db.rollback()
            delete_report_file(filename)
            logger.error("Database error saving report metadata: %s", exc, exc_info=True)
            raise RuntimeError(f"Failed to save report metadata to database: {exc}") from exc

        return self._to_dto(row)

    def list_reports(self, db: Session) -> list[ReportMetadataDTO]:
        """List all generated assessment reports ordered by timestamp descending."""
        rows = db.scalars(select(ReportRow).order_by(ReportRow.generated_at.desc())).all()
        return [self._to_dto(r) for r in rows]

    def get_report(self, db: Session, report_id: str) -> Optional[ReportRow]:
        """Retrieve a specific report row by its identifier."""
        return db.scalar(select(ReportRow).where(ReportRow.id == report_id))

    def get_report_pdf_path(
        self, db: Session, report_id: str, auto_regenerate: bool = True
    ) -> Optional[Path]:
        """Resolve and verify existence of report PDF file on disk, with resilient auto-regeneration."""
        row = self.get_report(db, report_id)
        if not row:
            logger.warning("Report record not found for id=%s", report_id)
            return None

        # 1. Check primary / legacy resolved path
        try:
            resolved = resolve_report_path(row.filename)
            if resolved.is_file():
                logger.debug(
                    "Found report PDF on disk: id=%s, path=%s, size=%d bytes",
                    report_id,
                    str(resolved),
                    resolved.stat().st_size,
                )
                return resolved
        except ValueError as val_err:
            logger.warning("Path resolution error for filename %s: %s", row.filename, val_err)

        # 2. Check row.file_path if stored directly
        if row.file_path:
            try:
                candidate = Path(row.file_path).resolve()
                if candidate.is_file():
                    logger.info("Found report PDF via row.file_path: id=%s, path=%s", report_id, str(candidate))
                    return candidate
            except Exception as exc:
                logger.warning("Error checking row.file_path %s: %s", row.file_path, exc)

        # 3. If file is missing from disk and auto-regeneration is allowed, re-render PDF
        if auto_regenerate:
            logger.warning(
                "PDF file %s for report %s is missing on disk. Auto-regenerating...",
                row.filename,
                report_id,
            )
            try:
                synth_req = ReportGenerateRequest(report_type=row.report_type)
                report_data = report_collector.collect(
                    db,
                    synth_req,
                    target_report_id=row.id,
                    override_title=row.title,
                    generated_at=row.generated_at,
                )
                pdf_bytes, page_count = pdf_renderer.render_with_metadata(report_data)
                new_path = save_report_file(row.filename, pdf_bytes)
                row.file_path = str(new_path.resolve())
                row.file_size_bytes = len(pdf_bytes)
                row.page_count = page_count
                db.commit()
                db.refresh(row)
                logger.info(
                    "Successfully auto-regenerated report PDF: id=%s, path=%s, size=%d bytes",
                    report_id,
                    str(new_path.resolve()),
                    len(pdf_bytes),
                )
                return new_path.resolve()
            except Exception as regen_err:
                logger.error(
                    "Auto-regeneration failed for report %s: %s",
                    report_id,
                    regen_err,
                    exc_info=True,
                )
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
