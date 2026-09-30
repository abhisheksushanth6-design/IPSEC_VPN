"""API router for Metadata Exposure Assessment (Layer 09)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer09_vulnerability_engine.metadata_exposure import MetadataExposureService
from app.models.ipsec_session import IPsecSession
from app.models.metadata_exposure import MetadataExposureRow
from app.schemas.metadata_exposure import (
    MetadataExposureSchema,
    MetadataExposureSummarySchema,
)

router = APIRouter(prefix="/metadata-exposure", tags=["Metadata Exposure"])


def _row_to_schema(r: MetadataExposureRow) -> MetadataExposureSchema:
    return MetadataExposureSchema(
        id=r.id,
        capture_id=r.capture_id,
        session_id=r.session_id,
        overall_score=r.overall_score,
        risk_level=r.risk_level,
        spi_leakage_score=r.spi_leakage_score,
        sequence_leakage_score=r.sequence_leakage_score,
        packet_length_leakage_score=r.packet_length_leakage_score,
        timing_leakage_score=r.timing_leakage_score,
        topology_leakage_score=r.topology_leakage_score,
        findings=json.loads(r.findings_json) if r.findings_json else [],
        recommendations=json.loads(r.recommendations_json) if r.recommendations_json else [],
        created_at=r.created_at.isoformat() if r.created_at else "",
    )


@router.get("/capture/{capture_id}", response_model=List[MetadataExposureSchema])
def get_capture_exposure(capture_id: str, db: Session = Depends(get_db)) -> List[MetadataExposureSchema]:
    """Retrieve all metadata exposure assessments for a capture."""
    svc = MetadataExposureService(db)
    rows = svc.get_by_capture(capture_id)
    return [_row_to_schema(r) for r in rows]


@router.get("/summary/{capture_id}", response_model=MetadataExposureSummarySchema)
def get_exposure_summary(capture_id: str, db: Session = Depends(get_db)) -> MetadataExposureSummarySchema:
    """Retrieve 5-vector exposure summary and dominant leakage indicator."""
    svc = MetadataExposureService(db)
    summary = svc.get_summary(capture_id)
    return MetadataExposureSummarySchema(**summary)


@router.get("/summary", response_model=MetadataExposureSummarySchema)
def get_global_exposure_summary(db: Session = Depends(get_db)) -> MetadataExposureSummarySchema:
    from app.services.packet_service import packet_service
    capture_id = packet_service.capture_id or "default"
    svc = MetadataExposureService(db)
    summary = svc.get_summary(capture_id)
    return MetadataExposureSummarySchema(**summary)



@router.post("/assess/{capture_id}", response_model=List[MetadataExposureSchema])
def trigger_exposure_assessment(capture_id: str, db: Session = Depends(get_db)) -> List[MetadataExposureSchema]:
    """Trigger 5-vector metadata exposure evaluation for all sessions in a capture."""
    svc = MetadataExposureService(db)
    rows = svc.assess_capture(capture_id)
    return [_row_to_schema(r) for r in rows]


@router.get("/session/{session_id}", response_model=MetadataExposureSchema)
def get_session_exposure(session_id: str, db: Session = Depends(get_db)) -> MetadataExposureSchema:
    """Retrieve metadata exposure assessment for a specific session."""
    session = db.get(IPsecSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    svc = MetadataExposureService(db)
    row = svc.assess_session(session)
    return _row_to_schema(row)
