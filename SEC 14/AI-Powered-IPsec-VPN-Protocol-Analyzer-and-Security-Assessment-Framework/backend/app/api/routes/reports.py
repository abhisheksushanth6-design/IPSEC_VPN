"""Report Generation endpoints (Layer 14).

Provides endpoints to generate, list, inspect, download, and delete
auditable security assessment PDF reports.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer14_reports.schemas import (
    ReportGenerateRequest,
    ReportMetadataDTO,
)
from app.layers.layer14_reports.service import report_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate", response_model=ReportMetadataDTO, status_code=status.HTTP_201_CREATED, summary="Generate security assessment PDF")
def generate_report(
    request: ReportGenerateRequest,
    db: Session = Depends(get_db),
) -> ReportMetadataDTO:
    """Generate a structured, evidence-based cybersecurity assessment PDF report."""
    try:
        return report_service.generate_report(db, request)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        ) from exc


@router.get("", response_model=List[ReportMetadataDTO], summary="List generated assessment reports")
def list_reports(db: Session = Depends(get_db)) -> List[ReportMetadataDTO]:
    """List all previously generated security assessment reports."""
    return report_service.list_reports(db)


@router.get("/{report_id}", response_model=ReportMetadataDTO, summary="Get report metadata")
def get_report(report_id: str, db: Session = Depends(get_db)) -> ReportMetadataDTO:
    """Retrieve metadata for a specific generated assessment report."""
    row = report_service.get_report(db, report_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report_service._to_dto(row)


@router.get("/{report_id}/download", summary="Download report PDF file")
def download_report(report_id: str, db: Session = Depends(get_db)) -> FileResponse:
    """Download the generated report PDF file with safe disposition headers."""
    row = report_service.get_report(db, report_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report record not found")

    pdf_path = report_service.get_report_pdf_path(db, report_id)
    if not pdf_path or not pdf_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PDF file not found on disk or path invalid",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=row.filename,
    )


@router.delete("/{report_id}", summary="Delete report")
def delete_report(report_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Delete a report record and remove its generated PDF file from storage."""
    deleted = report_service.delete_report(db, report_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return {"deleted": True, "id": report_id}
