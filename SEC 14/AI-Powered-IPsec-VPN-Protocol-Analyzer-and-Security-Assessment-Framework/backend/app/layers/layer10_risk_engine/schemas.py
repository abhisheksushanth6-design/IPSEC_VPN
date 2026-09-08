"""Pydantic schemas for Layer 10 — Risk Assessment & Decision Engine."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ContributingSignal(BaseModel):
    """An individual signal contributing to the session's overall risk calculation."""

    source: str = Field(..., description="Originating layer (e.g. LAYER_04, LAYER_07, LAYER_08, LAYER_09)")
    contribution: float = Field(..., description="Exact numeric points contributed to the overall risk score")
    reason: str = Field(..., description="Factual explanatory rationale derived from actual database records")
    evidence_reference: Optional[str] = Field(None, description="Direct identifier linking to the upstream record")


class RiskEvidenceItem(BaseModel):
    """Specific verifiable evidence item linking back to upstream project data."""

    source_layer: str = Field(..., description="Layer providing the evidence")
    evidence_type: str = Field(..., description="Type of evidence (e.g. VULNERABILITY_FINDING, ML_ANOMALY, DRIFT_FEATURE, SA_LIFECYCLE)")
    identifier: str = Field(..., description="Upstream entity ID (e.g. finding_id, rule_id, model_id, drift_analysis_id, sa_id)")
    summary: str = Field(..., description="Concrete non-fabricated observation summary")


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
    data_quality: str = Field(..., description="Signal completeness: COMPLETE (all 6 signals present) or PARTIAL")
    confidence_score: float = Field(..., description="Explainable signal coverage score (0.0 - 1.0)")
    breakdown: RiskScoreBreakdown = Field(..., description="Detailed component score breakdown")
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
    data_quality: Optional[str] = Field(None, description="Data quality of latest assessment")
    assessed_sessions_count: int = Field(0, description="Total sessions evaluated by Layer 10")
    total_sessions_count: int = Field(0, description="Total sessions discovered in the system")
    critical_risk_count: int = Field(0, description="Sessions assessed at CRITICAL risk")
    high_risk_count: int = Field(0, description="Sessions assessed at HIGH risk")
    medium_risk_count: int = Field(0, description="Sessions assessed at MEDIUM risk")
    low_risk_count: int = Field(0, description="Sessions assessed at LOW risk")
    latest_assessment: Optional[RiskAssessmentResponse] = Field(None, description="Most recent session assessment")
