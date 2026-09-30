"""API router for Standalone Threat Matrix (Layer 09 / 10)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer09_vulnerability_engine.threat_matrix import ThreatMatrixService
from app.models.threat_matrix import ThreatMatrixRow
from app.schemas.threat_matrix import (
    ThreatMatrixItemSchema,
    ThreatMatrixPageSchema,
    ThreatMatrixSummarySchema,
)

router = APIRouter(prefix="/threat-matrix", tags=["Threat Matrix"])


def _row_to_schema(r: ThreatMatrixRow) -> ThreatMatrixItemSchema:
    return ThreatMatrixItemSchema(
        id=r.id,
        capture_id=r.capture_id,
        session_id=r.session_id,
        matrix_id=r.matrix_id,
        name=r.name,
        category=r.category,
        severity=r.severity,
        mitre_technique_id=r.mitre_technique_id,
        mitre_tactic=r.mitre_tactic,
        nist_control=r.nist_control,
        rfc_reference=r.rfc_reference,
        status=r.status,
        evidence=json.loads(r.evidence_json) if r.evidence_json else [],
        remediation=r.remediation,
        created_at=r.created_at.isoformat() if r.created_at else "",
    )


@router.get("/capture/{capture_id}", response_model=List[ThreatMatrixItemSchema])
def get_threat_matrix(capture_id: str, db: Session = Depends(get_db)) -> List[ThreatMatrixItemSchema]:
    """Retrieve all 10 threat matrix evaluation items for the capture."""
    svc = ThreatMatrixService(db)
    rows = svc.get_by_capture(capture_id)
    return [_row_to_schema(r) for r in rows]


@router.get("/summary/{capture_id}", response_model=ThreatMatrixSummarySchema)
def get_threat_matrix_summary(capture_id: str, db: Session = Depends(get_db)) -> ThreatMatrixSummarySchema:
    """Retrieve summary status counts and RFC/NIST compliance score for the threat matrix."""
    svc = ThreatMatrixService(db)
    summary = svc.get_summary(capture_id)
    return ThreatMatrixSummarySchema(**summary)


@router.get("/threats", response_model=List[Dict[str, Any]])
def get_threat_catalog() -> List[Dict[str, Any]]:
    """Retrieve the authoritative 10-threat catalog with MITRE and NIST mappings."""
    from app.layers.layer09_vulnerability_engine.threat_matrix import THREAT_DEFINITIONS
    return THREAT_DEFINITIONS


@router.get("/summary", response_model=ThreatMatrixSummarySchema)
def get_global_threat_matrix_summary(db: Session = Depends(get_db)) -> ThreatMatrixSummarySchema:
    from app.services.packet_service import packet_service
    capture_id = packet_service.capture_id or "default"
    svc = ThreatMatrixService(db)
    summary = svc.get_summary(capture_id)
    return ThreatMatrixSummarySchema(**summary)


@router.get("/session/{session_id}", response_model=Dict[str, Any])
def get_session_threat_matrix(session_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve threat matrix evaluated for a specific session."""
    from app.models.ipsec_session import IPsecSession
    session = db.get(IPsecSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    svc = ThreatMatrixService(db)
    rows = svc.get_by_capture(session.capture_id)
    summary = svc.get_summary(session.capture_id)
    return {
        "session_id": session_id,
        "capture_id": session.capture_id,
        "overall_compliance_score": summary["compliance_score"],
        "threats": [_row_to_schema(r).model_dump() for r in rows],
    }

