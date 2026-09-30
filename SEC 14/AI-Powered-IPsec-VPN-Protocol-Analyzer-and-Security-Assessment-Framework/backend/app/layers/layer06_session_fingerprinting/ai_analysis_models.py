"""Data models for Layer 06 AI-Powered Security Analysis.

Defines structured security explanations, prioritized findings, attack implications,
phased remediation recommendations, executive summaries, and analyst-oriented
technical dossiers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

PriorityRank = Literal["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"]
UrgencyLevel = Literal["IMMEDIATE", "SCHEDULED", "DISCRETIONARY"]
RemediationPhase = Literal["PHASE_1_IMMEDIATE", "PHASE_2_HARDENING", "PHASE_3_ARCHITECTURAL"]
EffortLevel = Literal["LOW", "MEDIUM", "HIGH"]


@dataclass
class PrioritizedFinding:
    """A prioritized security finding enriched with contextual urgency and exploitability."""
    finding_id: str
    title: str
    original_severity: str
    priority_rank: PriorityRank
    urgency: UrgencyLevel
    justification: str
    exploitability_score: float  # 0.0 to 10.0 scale
    affected_session: Optional[str] = None
    affected_tunnel: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    cve_references: list[str] = field(default_factory=list)


@dataclass
class AttackImplication:
    """Threat modeling scenario detailing potential attack vectors and impact."""
    attack_id: str
    vector_name: str
    threat_actor_profile: str  # e.g., "Nation-State / Advanced Persistent Threat", "Opportunistic Network Adversary"
    exploit_scenario: str
    prerequisites: str
    impact_summary: str
    mitre_attack_technique: str  # e.g., "T1040 - Network Sniffing", "T1557 - Adversary-in-the-Middle"
    affected_findings: list[str] = field(default_factory=list)


@dataclass
class RemediationStep:
    """Actionable remediation item in a structured, phased hardening roadmap."""
    step_id: str
    phase: RemediationPhase
    component: str  # e.g., "strongSwan ipsec.conf", "Firewall / Routing", "Crypto Policy"
    action_title: str
    instructions: str
    config_snippet: str
    verification_command: str
    effort: EffortLevel = "MEDIUM"


@dataclass
class ExecutiveSummary:
    """High-level security briefing for CISOs and executive leadership."""
    overall_posture: str
    risk_score_summary: str
    business_impact: str
    compliance_overview: str
    strategic_recommendations: list[str] = field(default_factory=list)


@dataclass
class TechnicalSummary:
    """In-depth technical breakdown for SOC analysts and network engineers."""
    protocol_health: str
    cryptographic_assessment: str
    integrity_and_sequence_analysis: str
    leakage_and_exposure_analysis: str
    rfc_compliance_citations: list[str] = field(default_factory=list)


@dataclass
class AISecurityAnalysis:
    """Comprehensive AI-Powered Security Analysis report."""
    analysis_id: str
    capture_id: str
    timestamp: str
    provider_used: str  # "deterministic", "openai", "deterministic_fallback", etc.
    overall_risk_score: float
    risk_level: str
    executive_summary: ExecutiveSummary
    technical_summary: TechnicalSummary
    prioritized_findings: list[PrioritizedFinding] = field(default_factory=list)
    attack_implications: list[AttackImplication] = field(default_factory=list)
    remediation_steps: list[RemediationStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
