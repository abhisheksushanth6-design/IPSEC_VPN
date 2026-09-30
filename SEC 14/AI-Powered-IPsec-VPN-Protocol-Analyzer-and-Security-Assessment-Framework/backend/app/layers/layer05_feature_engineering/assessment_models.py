"""Data models for Layer 05 Security Assessment & Risk Engine.

Defines structured security findings, risk rating levels, remediation
recommendations, and the comprehensive risk assessment report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
FindingCategory = Literal[
    "CRYPTOGRAPHY",
    "INTEGRITY",
    "PROTOCOL_ANOMALY",
    "DATA_LEAKAGE",
    "TUNNEL_STATE",
    "CONFIGURATION",
]


@dataclass
class SecurityFinding:
    """A structured finding produced by evaluating security rules."""
    finding_id: str
    rule_id: str
    title: str
    category: FindingCategory
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    affected_session: Optional[str] = None
    affected_tunnel: Optional[str] = None
    affected_packet_numbers: list[int] = field(default_factory=list)
    remediation: str = ""
    cve_references: list[str] = field(default_factory=list)
    compliance_mappings: list[str] = field(default_factory=list)


@dataclass
class RiskAssessmentReport:
    """Comprehensive security posture assessment report and risk metrics."""
    capture_id: str
    overall_risk_score: float  # 0.0 to 100.0
    risk_level: RiskLevel
    findings_count: int
    findings_by_severity: dict[str, int]
    findings: list[SecurityFinding]
    evaluated_sessions_count: int
    evaluated_tunnels_count: int
    evaluated_packets_count: int
    assessment_timestamp: str
    status: str = "READY"
