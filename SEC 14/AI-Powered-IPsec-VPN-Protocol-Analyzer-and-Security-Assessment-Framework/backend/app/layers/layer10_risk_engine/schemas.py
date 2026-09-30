"""Pydantic schemas for Layer 10 — Risk Assessment & Decision Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyDecision(str, Enum):
    """Canonical policy decisions supported by the decision engine."""

    ALLOW = "ALLOW"
    INSPECT = "INSPECT"
    RESTRICT = "RESTRICT"
    TERMINATE = "TERMINATE"


class PolicyDecisionAlias(str, Enum):
    """Standard security decision aliases."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    ISOLATE = "ISOLATE"
    BLOCK = "BLOCK"


DECISION_TO_ALIAS: Dict[str, str] = {
    "ALLOW": "ALLOW",
    "INSPECT": "WARN",
    "RESTRICT": "ISOLATE",
    "TERMINATE": "BLOCK",
}

ALIAS_TO_DECISION: Dict[str, str] = {
    "ALLOW": "ALLOW",
    "WARN": "INSPECT",
    "ISOLATE": "RESTRICT",
    "BLOCK": "TERMINATE",
}


class ContributingSignal(BaseModel):
    """An individual signal contributing to the session's overall risk calculation."""

    source: str = Field(..., description="Originating layer (e.g. LAYER_04, LAYER_07, LAYER_08, LAYER_09)")
    contribution: float = Field(..., description="Exact numeric points contributed to the overall risk score")
    reason: str = Field(..., description="Factual explanatory rationale derived from actual database records")
    evidence_reference: Optional[str] = Field(None, description="Direct identifier linking to the upstream record")
    confidence: Optional[float] = Field(None, description="Finding confidence weighting factor (0.0 - 1.0)")
    finding_status: Optional[str] = Field(None, description="Status of the finding (OPEN, CONFIRMED, RESOLVED, SUPPRESSED, FALSE_POSITIVE)")
    recurrence_count: Optional[int] = Field(None, description="Number of observed recurrences")


class RiskEvidenceItem(BaseModel):
    """Specific verifiable evidence item linking back to upstream project data."""

    source_layer: str = Field(..., description="Layer providing the evidence")
    evidence_type: str = Field(..., description="Type of evidence (e.g. VULNERABILITY_FINDING, ML_ANOMALY, DRIFT_FEATURE, SA_LIFECYCLE)")
    identifier: str = Field(..., description="Upstream entity ID (e.g. finding_id, rule_id, model_id, drift_analysis_id, sa_id)")
    summary: str = Field(..., description="Concrete non-fabricated observation summary")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional structured parameters")


class RiskScoreBreakdown(BaseModel):
    """Sub-score components contributing to the total risk score."""

    vulnerability_score: float = Field(..., description="Vulnerability rule score (max 50.0)")
    ml_score: float = Field(..., description="AI/ML anomaly attack probability score (max 30.0)")
    drift_score: float = Field(..., description="Security drift deviation score (max 12.0)")
    state_score: float = Field(..., description="Security Association state and protocol score (max 8.0)")
    total_risk_score: float = Field(..., description="Final clamped total risk score [0.0, 100.0]")


class RiskAssessmentResponse(BaseModel):
    """Full deterministic risk assessment for an evaluated IPsec session."""

    id: str = Field(..., description="Unique assessment record identifier")
    session_id: str = Field(..., description="Target IPsec session identifier")
    risk_score: float = Field(..., description="Total risk score in [0.0, 100.0]")
    risk_level: str = Field(..., description="Discrete risk level: LOW, MEDIUM, HIGH, CRITICAL")
    decision: str = Field(..., description="Policy decision: ALLOW, INSPECT, RESTRICT, TERMINATE")
    decision_alias: str = Field("ALLOW", description="Standard security decision alias: ALLOW, WARN, ISOLATE, BLOCK")
    is_advisory: bool = Field(True, description="Advisory-only indicator (no disruptive blocking executed)")
    data_quality: str = Field(..., description="Signal completeness: COMPLETE (all 6 signals present) or PARTIAL")
    confidence_score: float = Field(..., description="Explainable signal coverage score (0.0 - 1.0)")
    breakdown: RiskScoreBreakdown = Field(..., description="Detailed component score breakdown")
    severity_summary: Dict[str, int] = Field(default_factory=dict, description="Counts of active findings by severity")
    contributing_signals: List[ContributingSignal] = Field(default_factory=list, description="All contributing risk signals")
    evidence: List[RiskEvidenceItem] = Field(default_factory=list, description="Factual evidence items pointing to actual data")
    recommended_actions: List[str] = Field(default_factory=list, description="Actionable remediations tied directly to findings")
    available_signals: List[str] = Field(default_factory=list, description="Layers with available data for this assessment")
    unavailable_signals: List[str] = Field(default_factory=list, description="Layers missing data for this session")
    evaluated_at: datetime = Field(..., description="Timestamp when assessment was performed")


class RiskSummaryResponse(BaseModel):
    """Aggregated risk overview across all observed sessions for SOC dashboard."""

    state: str = Field(..., description="Engine state: OPERATIONAL or NOT_ANALYZED")
    overall_risk_score: Optional[float] = Field(None, description="Latest or maximum assessed risk score")
    overall_risk_level: Optional[str] = Field(None, description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")
    decision: Optional[str] = Field(None, description="Recommended executive posture decision")
    decision_alias: Optional[str] = Field(None, description="Security decision alias: ALLOW, WARN, ISOLATE, BLOCK")
    is_advisory: bool = Field(True, description="Advisory-only indicator")
    data_quality: Optional[str] = Field(None, description="Data quality of latest assessment")
    assessed_sessions_count: int = Field(0, description="Total sessions evaluated by Layer 10")
    total_sessions_count: int = Field(0, description="Total sessions discovered in the system")
    critical_risk_count: int = Field(0, description="Sessions assessed at CRITICAL risk")
    high_risk_count: int = Field(0, description="Sessions assessed at HIGH risk")
    medium_risk_count: int = Field(0, description="Sessions assessed at MEDIUM risk")
    low_risk_count: int = Field(0, description="Sessions assessed at LOW risk")
    latest_assessment: Optional[RiskAssessmentResponse] = Field(None, description="Most recent session assessment")


class RiskExportResponse(BaseModel):
    """Structured export package of risk assessments for SIEM/SOAR/compliance."""

    export_version: str = Field("1.0.0", description="Schema version of export format")
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of export")
    total_assessments: int = Field(..., description="Count of exported assessments")
    assessments: List[RiskAssessmentResponse] = Field(default_factory=list, description="Exported risk assessment records")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Audit export metadata")
