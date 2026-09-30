"""FastAPI router for Layer 10 — Risk Assessment & Decision Engine."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer10_risk_engine import (
    RiskAssessmentResponse,
    RiskExportResponse,
    RiskSummaryResponse,
    get_risk_engine_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/risk", tags=["Risk Assessment & Decision Engine"])


@router.get(
    "/status",
    summary="Get Risk Assessment Engine status",
)
def get_risk_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Return live operational status and capability metrics for Layer 10."""
    svc = get_risk_engine_service()
    summary = svc.get_summary(db)
    detailed = svc.get_detailed_status(db)
    return {
        "layer_number": 10,
        "layer_name": "Risk Assessment & Decision Engine",
        "status": svc.get_layer_status(db),
        "total_assessed_sessions": summary.assessed_sessions_count,
        "critical_risk_count": summary.critical_risk_count,
        "high_risk_count": summary.high_risk_count,
        "medium_risk_count": summary.medium_risk_count,
        "low_risk_count": summary.low_risk_count,
        "checks": detailed.get("checks", {}),
        "is_advisory": True,
    }


@router.get(
    "/summary",
    response_model=RiskSummaryResponse,
    summary="Get overall risk summary and executive posture",
)
def get_risk_summary(db: Session = Depends(get_db)) -> RiskSummaryResponse:
    """Retrieve holistic security risk summary and posture metrics across all sessions."""
    svc = get_risk_engine_service()
    return svc.get_summary(db)


@router.get(
    "/export",
    response_model=RiskExportResponse,
    summary="Export risk assessments for SIEM/SOAR/compliance reporting",
)
def export_risk_assessments(
    session_id: Optional[str] = Query(None, description="Filter export by specific session ID"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum assessments to export"),
    db: Session = Depends(get_db),
) -> RiskExportResponse:
    """Export risk assessments and evidence in structured JSON format for compliance audit."""
    svc = get_risk_engine_service()
    return svc.export_assessments(db, session_id=session_id, limit=limit)


@router.get(
    "/assessments",
    response_model=List[RiskAssessmentResponse],
    summary="List all session risk assessments",
)
def list_assessments(
    limit: int = Query(50, ge=1, le=200, description="Maximum assessments to return"),
    db: Session = Depends(get_db),
) -> List[RiskAssessmentResponse]:
    """Retrieve recent session risk assessments ordered by recency."""
    svc = get_risk_engine_service()
    return svc.get_all_assessments(db, limit=limit)


@router.get(
    "/assessments/{assessment_id}",
    response_model=RiskAssessmentResponse,
    summary="Get risk assessment by its unique assessment ID",
)
def get_assessment_by_id(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> RiskAssessmentResponse:
    """Retrieve a specific persistent risk assessment record by assessment ID."""
    svc = get_risk_engine_service()
    assessment = svc.get_assessment_by_id(db, assessment_id)
    if assessment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment '{assessment_id}' not found.",
        )
    return assessment


@router.get(
    "/sessions/{session_id}",
    response_model=RiskAssessmentResponse,
    summary="Get or evaluate risk assessment for a specific session",
)
def get_session_risk(
    session_id: str,
    db: Session = Depends(get_db),
) -> RiskAssessmentResponse:
    """Retrieve existing risk assessment for session, or evaluate on-demand if not yet evaluated."""
    svc = get_risk_engine_service()
    try:
        assessment = svc.get_session_assessment(db, session_id)
        if assessment is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"IPsec session '{session_id}' not found.",
            )
        return assessment
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/evaluate/{session_id}",
    response_model=RiskAssessmentResponse,
    summary="Force refresh / re-evaluate risk for a session",
)
def evaluate_session_risk(
    session_id: str,
    db: Session = Depends(get_db),
) -> RiskAssessmentResponse:
    """Force deterministic re-evaluation of risk score and policy decision for an IPsec session."""
    svc = get_risk_engine_service()
    try:
        return svc.evaluate_session(db, session_id, force_refresh=True)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/evaluate-all",
    response_model=List[RiskAssessmentResponse],
    summary="Batch evaluate all discovered sessions",
)
def evaluate_all_sessions(
    capture_id: Optional[str] = Query(None, description="Optional target capture ID to evaluate"),
    db: Session = Depends(get_db),
) -> List[RiskAssessmentResponse]:
    """Execute risk evaluation across sessions present in the telemetry database."""
    svc = get_risk_engine_service()
    return svc.evaluate_all_sessions(db, capture_id=capture_id)
