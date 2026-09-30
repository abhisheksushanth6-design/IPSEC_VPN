"""Pydantic schemas for Layer 05 Security Assessment & Risk Engine API."""

from __future__ import annotations

from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SecurityFindingSchema(_Model):
    finding_id: str = Field(..., description="Unique finding identifier")
    rule_id: str = Field(..., description="Identifier of the triggered security rule")
    title: str = Field(..., description="Descriptive title of the security finding")
    category: str = Field(..., description="Category (CRYPTOGRAPHY, INTEGRITY, PROTOCOL_ANOMALY, DATA_LEAKAGE, TUNNEL_STATE, CONFIGURATION)")
    severity: str = Field(..., description="Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    confidence: float = Field(1.0, description="Confidence level between 0.0 and 1.0")
    explanation: str = Field(..., description="Technical explanation of the security risk")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Observed evidence supporting the finding")
    affected_session: Optional[str] = Field(None, description="Affected IPsec session ID if applicable")
    affected_tunnel: Optional[str] = Field(None, description="Affected tunnel endpoints if applicable")
    affected_packet_numbers: List[int] = Field(default_factory=list, description="Packet numbers cited as evidence")
    remediation: str = Field("", description="Actionable remediation recommendation")
    cve_references: List[str] = Field(default_factory=list, description="Associated CVE or RFC identifiers")
    compliance_mappings: List[str] = Field(default_factory=list, description="Standards compliance mappings")


class RiskScoreSummarySchema(BaseModel):
    overall_risk_score: float = Field(..., description="Normalized risk score between 0.0 and 100.0")
    risk_level: str = Field(..., description="Risk tier (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)")
    findings_count: int = Field(..., description="Total number of findings")
    findings_by_severity: dict[str, int] = Field(..., description="Count of findings per severity tier")
    status: str = Field("READY", description="Assessment engine status")


class RiskAssessmentReportSchema(BaseModel):
    capture_id: str = Field(..., description="Identifier of the assessed capture")
    overall_risk_score: float = Field(..., description="Overall risk score (0.0 - 100.0)")
    risk_level: str = Field(..., description="Overall risk classification")
    findings_count: int = Field(..., description="Total findings detected")
    findings_by_severity: dict[str, int] = Field(..., description="Breakdown of findings count by severity")
    findings: List[SecurityFindingSchema] = Field(default_factory=list, description="Detailed list of security findings")
    evaluated_sessions_count: int = Field(0, description="Total VPN sessions assessed")
    evaluated_tunnels_count: int = Field(0, description="Total VPN tunnels assessed")
    evaluated_packets_count: int = Field(0, description="Total packets evaluated")
    assessment_timestamp: str = Field(..., description="ISO 8601 timestamp of assessment")
    status: str = Field("READY", description="Engine readiness status")
