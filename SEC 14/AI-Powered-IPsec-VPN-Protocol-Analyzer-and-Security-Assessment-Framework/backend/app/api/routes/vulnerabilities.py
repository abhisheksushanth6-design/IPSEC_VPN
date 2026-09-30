"""FastAPI router for Layer 09 — Security Rule & Vulnerability Engine."""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.base import get_db
from app.layers.layer09_vulnerability_engine import (
    FindingStatus,
    FindingStatusUpdateRequest,
    RuleCategory,
    RuleStatusUpdateRequest,
    SecurityRuleDTO,
    VulnerabilityAnalyzeRequest,
    VulnerabilityAnalyzeResponse,
    VulnerabilityEngineStatusDTO,
    VulnerabilityFindingDetailDTO,
    VulnerabilityFindingSummaryDTO,
    VulnerabilityStatsDTO,
    get_vulnerability_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Engine"])


@router.get(
    "/status",
    response_model=VulnerabilityEngineStatusDTO,
    summary="Get Vulnerability Engine Status",
)
def get_vulnerability_status(db: Session = Depends(get_db)) -> VulnerabilityEngineStatusDTO:
    """Retrieve operational status, rule counts, and summary metrics."""
    svc = get_vulnerability_service()
    return svc.get_status(db)


@router.get(
    "/rules",
    response_model=List[SecurityRuleDTO],
    summary="List Security Rules",
)
def list_rules(
    category: Optional[RuleCategory] = Query(None, description="Filter rules by category"),
    enabled_only: bool = Query(False, description="Filter only enabled rules"),
    db: Session = Depends(get_db),
) -> List[SecurityRuleDTO]:
    """List all registered security rules and their operational status."""
    svc = get_vulnerability_service()
    return svc.get_rules(db, category=category, enabled_only=enabled_only)


@router.get(
    "/rules/{rule_id}",
    response_model=SecurityRuleDTO,
    summary="Get Rule Detail",
)
def get_rule_detail(rule_id: str, db: Session = Depends(get_db)) -> SecurityRuleDTO:
    """Retrieve details and remediation guidance for a specific rule."""
    svc = get_vulnerability_service()
    rule = svc.get_rule(db, rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security rule '{rule_id}' not found in registry.",
        )
    return rule


@router.post(
    "/rules/{rule_id}/enable",
    response_model=SecurityRuleDTO,
    summary="Enable Security Rule",
)
def enable_rule(rule_id: str, db: Session = Depends(get_db)) -> SecurityRuleDTO:
    """Enable a security rule for automated evaluation."""
    svc = get_vulnerability_service()
    updated = svc.set_rule_enabled(db, rule_id, enabled=True)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security rule '{rule_id}' not found.",
        )
    return updated


@router.post(
    "/rules/{rule_id}/disable",
    response_model=SecurityRuleDTO,
    summary="Disable Security Rule",
)
def disable_rule(rule_id: str, db: Session = Depends(get_db)) -> SecurityRuleDTO:
    """Disable a security rule from automated evaluation."""
    svc = get_vulnerability_service()
    updated = svc.set_rule_enabled(db, rule_id, enabled=False)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security rule '{rule_id}' not found.",
        )
    return updated


@router.post(
    "/analyze",
    response_model=VulnerabilityAnalyzeResponse,
    summary="Run Vulnerability Analysis",
)
def run_vulnerability_analysis(
    req: VulnerabilityAnalyzeRequest,
    db: Session = Depends(get_db),
) -> VulnerabilityAnalyzeResponse:
    """Execute deterministic security rule evaluation across target session(s) or capture."""
    svc = get_vulnerability_service()

    if req.session_id:
        findings = svc.analyze_session(db, req.session_id, rule_ids=req.rule_ids)
        sessions_count = 1
    elif req.capture_id:
        findings = svc.analyze_capture(db, req.capture_id, rule_ids=req.rule_ids)
        sessions_count = len({f.affected_session_id for f in findings if f.affected_session_id}) or 1
    else:
        # Default: evaluate all available sessions
        from app.models.ipsec_session import IPsecSession
        from sqlalchemy import select

        sessions = db.scalars(select(IPsecSession.id)).all()
        findings = []
        for s_id in sessions:
            findings.extend(svc.analyze_session(db, s_id, rule_ids=req.rule_ids))
        sessions_count = len(sessions)

    rules = svc.registry.list_rules(enabled_only=True)
    if req.rule_ids:
        rules = [r for r in rules if r.rule_id in req.rule_ids]

    return VulnerabilityAnalyzeResponse(
        sessions_analyzed=sessions_count,
        rules_evaluated=len(rules),
        rules_matched=len(findings),
        findings_created=len(findings),
        findings_updated=0,
        findings=findings,
    )


@router.get(
    "/findings",
    response_model=List[VulnerabilityFindingSummaryDTO],
    summary="List Vulnerability Findings",
)
def list_findings(
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    category: Optional[str] = Query(None, description="Filter by rule category"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (OPEN, ACTIVE, RESOLVED, SUPPRESSED)"),
    session_id: Optional[str] = Query(None, description="Filter by affected session ID"),
    rule_id: Optional[str] = Query(None, description="Filter by triggering rule ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[VulnerabilityFindingSummaryDTO]:
    """Retrieve filtered list of vulnerability findings."""
    svc = get_vulnerability_service()
    findings, _ = svc.get_findings(
        db,
        severity=severity,
        category=category,
        status=status_filter,
        session_id=session_id,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )
    return findings


@router.get(
    "/findings/{finding_id}",
    response_model=VulnerabilityFindingDetailDTO,
    summary="Get Finding Detail",
)
def get_finding_detail(finding_id: str, db: Session = Depends(get_db)) -> VulnerabilityFindingDetailDTO:
    """Retrieve finding details with full factual evidence items and remediation guidance."""
    svc = get_vulnerability_service()
    finding = svc.get_finding_detail(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{finding_id}' not found.",
        )
    return finding


@router.patch(
    "/findings/{finding_id}/status",
    response_model=VulnerabilityFindingDetailDTO,
    summary="Update Finding Status",
)
def update_finding_status(
    finding_id: str,
    req: FindingStatusUpdateRequest,
    db: Session = Depends(get_db),
) -> VulnerabilityFindingDetailDTO:
    """Transition finding lifecycle status (e.g., OPEN -> RESOLVED or SUPPRESSED)."""
    svc = get_vulnerability_service()
    updated = svc.update_finding_status(db, finding_id, req.status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{finding_id}' not found.",
        )
    return updated


@router.get(
    "/stats",
    response_model=VulnerabilityStatsDTO,
    summary="Get Vulnerability Statistics",
)
def get_vulnerability_stats(db: Session = Depends(get_db)) -> VulnerabilityStatsDTO:
    """Retrieve aggregated vulnerability metrics grouped by severity, category, and lifecycle status."""
    svc = get_vulnerability_service()
    return svc.get_statistics(db)


@router.get(
    "/export",
    summary="Export Vulnerability Audit Report",
)
def export_vulnerability_findings(
    session_id: Optional[str] = Query(None, description="Filter export to specific session ID"),
    capture_id: Optional[str] = Query(None, description="Filter export to specific capture ID"),
    db: Session = Depends(get_db),
) -> dict:
    """Export complete security findings, technical evidence, and rule catalog as structured JSON."""
    svc = get_vulnerability_service()
    return svc.export_findings(db, session_id=session_id, capture_id=capture_id)

