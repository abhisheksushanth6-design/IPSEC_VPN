"""FastAPI endpoints for Layer 05 Security Assessment & Risk Engine."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Query

from app.api.routes.packets import ERROR_RESPONSES
from app.layers.layer05_feature_engineering.assessment_service import (
    get_security_assessment_service,
)
from app.schemas.security_assessment import (
    RiskAssessmentReportSchema,
    RiskScoreSummarySchema,
    SecurityFindingSchema,
)
from app.services.packet_service import packet_service

router = APIRouter(prefix="/security-assessment", tags=["security-assessment"])


def _get_or_run_assessment() -> RiskAssessmentReportSchema:
    svc = get_security_assessment_service()
    capture_id = packet_service.capture_id or "default"
    packets = packet_service.all_packets()
    report = svc.evaluate_capture(packets, capture_id=capture_id)
    return RiskAssessmentReportSchema(
        capture_id=report.capture_id,
        overall_risk_score=report.overall_risk_score,
        risk_level=report.risk_level,
        findings_count=report.findings_count,
        findings_by_severity=report.findings_by_severity,
        findings=[SecurityFindingSchema.model_validate(f) for f in report.findings],
        evaluated_sessions_count=report.evaluated_sessions_count,
        evaluated_tunnels_count=report.evaluated_tunnels_count,
        evaluated_packets_count=report.evaluated_packets_count,
        assessment_timestamp=report.assessment_timestamp,
        status=svc.get_layer_status(),
    )


@router.get("", response_model=RiskAssessmentReportSchema, responses=ERROR_RESPONSES, summary="Full Layer 05 security assessment and risk report")
def get_security_assessment() -> RiskAssessmentReportSchema:
    return _get_or_run_assessment()


@router.get("/findings", response_model=List[SecurityFindingSchema], responses=ERROR_RESPONSES, summary="List detected security findings with optional filters")
def get_findings(
    severity: Optional[str] = Query(None, pattern="^(?i)(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    category: Optional[str] = Query(None, max_length=32),
    session_id: Optional[str] = Query(None, max_length=128),
) -> List[SecurityFindingSchema]:
    report = _get_or_run_assessment()
    findings = report.findings

    if severity:
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    if category:
        findings = [f for f in findings if f.category.upper() == category.upper()]
    if session_id:
        findings = [f for f in findings if f.affected_session == session_id]

    return findings


@router.get("/risk-score", response_model=RiskScoreSummarySchema, responses=ERROR_RESPONSES, summary="Overall risk score and severity breakdown")
def get_risk_score() -> RiskScoreSummarySchema:
    report = _get_or_run_assessment()
    return RiskScoreSummarySchema(
        overall_risk_score=report.overall_risk_score,
        risk_level=report.risk_level,
        findings_count=report.findings_count,
        findings_by_severity=report.findings_by_severity,
        status=report.status,
    )


# ---------------------------------------------------------------------------
# SIH 26160 Comprehensive Security Assessment Engine Endpoints
# ---------------------------------------------------------------------------

from app.db.base import get_db
from app.layers.layer09_vulnerability_engine.security_assessment import (
    ComprehensiveSecurityAssessmentDTO,
    SecurityAssessmentEngine,
)
from app.models.ipsec_session import IPsecSession
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session


@router.get(
    "/comprehensive/{session_id}",
    response_model=ComprehensiveSecurityAssessmentDTO,
    responses=ERROR_RESPONSES,
    summary="Comprehensive SIH 26160 Security Assessment for a target session",
)
def get_comprehensive_security_assessment(
    session_id: str,
    db: Session = Depends(get_db),
) -> ComprehensiveSecurityAssessmentDTO:
    session = db.scalar(select(IPsecSession).where(IPsecSession.id == session_id))
    if not session:
        raise HTTPException(status_code=404, detail=f"IPsec session {session_id} not found")
    return SecurityAssessmentEngine.evaluate_session(db, session)


@router.get(
    "/session/{session_id}",
    response_model=ComprehensiveSecurityAssessmentDTO,
    responses=ERROR_RESPONSES,
    summary="Alias for comprehensive session security assessment",
)
def get_session_security_assessment(
    session_id: str,
    db: Session = Depends(get_db),
) -> ComprehensiveSecurityAssessmentDTO:
    return get_comprehensive_security_assessment(session_id, db=db)


@router.get(
    "/comprehensive-capture/{capture_id}",
    response_model=List[ComprehensiveSecurityAssessmentDTO],
    responses=ERROR_RESPONSES,
    summary="Comprehensive SIH 26160 Security Assessments for all sessions in a capture",
)
def get_capture_security_assessments(
    capture_id: str,
    db: Session = Depends(get_db),
) -> List[ComprehensiveSecurityAssessmentDTO]:
    sessions = db.scalars(select(IPsecSession).where(IPsecSession.capture_id == capture_id)).all()
    if not sessions:
        raise HTTPException(status_code=404, detail=f"No sessions found for capture {capture_id}")
    return [SecurityAssessmentEngine.evaluate_session(db, s) for s in sessions]

