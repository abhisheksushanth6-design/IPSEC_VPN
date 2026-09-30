"""Pydantic schemas for Layer 06 AI-Powered Security Analysis API."""

from __future__ import annotations

from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PrioritizedFindingSchema(_Model):
    finding_id: str = Field(..., description="Original finding identifier")
    title: str = Field(..., description="Title of the security finding")
    original_severity: str = Field(..., description="Original rule-based severity")
    priority_rank: str = Field(..., description="Prioritized triage rank (P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW)")
    urgency: str = Field(..., description="Actionable urgency (IMMEDIATE, SCHEDULED, DISCRETIONARY)")
    justification: str = Field(..., description="AI contextual justification for the assigned rank")
    exploitability_score: float = Field(..., description="Exploitability rating between 0.0 and 10.0")
    affected_session: Optional[str] = Field(None, description="Affected session identifier")
    affected_tunnel: Optional[str] = Field(None, description="Affected tunnel endpoints")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Telemetry evidence")
    cve_references: List[str] = Field(default_factory=list, description="Associated CVEs")


class AttackImplicationSchema(_Model):
    attack_id: str = Field(..., description="Unique threat vector identifier")
    vector_name: str = Field(..., description="Descriptive attack vector name")
    threat_actor_profile: str = Field(..., description="Archetype of adversary capable of exploitation")
    exploit_scenario: str = Field(..., description="Detailed narrative of the threat exploitation flow")
    prerequisites: str = Field(..., description="Required adversary position or capabilities")
    impact_summary: str = Field(..., description="Consequences of successful exploitation")
    mitre_attack_technique: str = Field(..., description="MITRE ATT&CK technique reference")
    affected_findings: List[str] = Field(default_factory=list, description="Findings contributing to this vector")


class RemediationStepSchema(_Model):
    step_id: str = Field(..., description="Unique remediation action ID")
    phase: str = Field(..., description="Roadmap phase (PHASE_1_IMMEDIATE, PHASE_2_HARDENING, PHASE_3_ARCHITECTURAL)")
    component: str = Field(..., description="Target system component or configuration file")
    action_title: str = Field(..., description="Concise title of the remediation action")
    instructions: str = Field(..., description="Detailed instructions for implementing the fix")
    config_snippet: str = Field(..., description="Concrete configuration directive or rule")
    verification_command: str = Field(..., description="Terminal or management command to verify the fix")
    effort: str = Field("MEDIUM", description="Estimated operational effort (LOW, MEDIUM, HIGH)")


class ExecutiveSummarySchema(_Model):
    overall_posture: str = Field(..., description="Executive briefing on overall security posture")
    risk_score_summary: str = Field(..., description="Summary of risk score and evaluated volume")
    business_impact: str = Field(..., description="Business and compliance impact assessment")
    compliance_overview: str = Field(..., description="Standards compliance status (NIST, RFC 8221, PCI-DSS)")
    strategic_recommendations: List[str] = Field(default_factory=list, description="Strategic recommendations for leadership")


class TechnicalSummarySchema(_Model):
    protocol_health: str = Field(..., description="Protocol state and handshake health summary")
    cryptographic_assessment: str = Field(..., description="In-depth analysis of observed ciphers, hashes, and DH groups")
    integrity_and_sequence_analysis: str = Field(..., description="Evaluation of ESP sequence monotonically increasing invariants")
    leakage_and_exposure_analysis: str = Field(..., description="Evaluation of cleartext or perimeter leakage")
    rfc_compliance_citations: List[str] = Field(default_factory=list, description="Applicable RFC and standard citations")


class AISecurityAnalysisResponse(_Model):
    analysis_id: str = Field(..., description="Unique analysis identifier")
    capture_id: str = Field(..., description="Associated capture identifier")
    timestamp: str = Field(..., description="ISO 8601 generation timestamp")
    provider_used: str = Field(..., description="Provider utilized (deterministic, openai, etc.)")
    overall_risk_score: float = Field(..., description="Overall risk score (0.0 - 100.0)")
    risk_level: str = Field(..., description="Risk tier classification")
    executive_summary: ExecutiveSummarySchema = Field(..., description="Executive leadership summary")
    technical_summary: TechnicalSummarySchema = Field(..., description="SOC technical analyst dossier")
    prioritized_findings: List[PrioritizedFindingSchema] = Field(default_factory=list, description="Prioritized findings list")
    attack_implications: List[AttackImplicationSchema] = Field(default_factory=list, description="Threat attack implications")
    remediation_steps: List[RemediationStepSchema] = Field(default_factory=list, description="Phased remediation roadmap")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Execution and session metrics")


class AISecurityAnalysisRequest(BaseModel):
    provider: Optional[str] = Field(None, description="Optional provider preference ('deterministic' or 'real_llm')")
