/**
 * TypeScript definitions for Layer 06 — AI-Powered Security Analysis.
 */

export interface PrioritizedFinding {
  finding_id: string;
  title: string;
  original_severity: string;
  priority_rank: 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';
  urgency: 'IMMEDIATE' | 'SCHEDULED' | 'DISCRETIONARY';
  justification: string;
  exploitability_score: number;
  affected_session?: string | null;
  affected_tunnel?: string | null;
  evidence: Record<string, unknown>;
  cve_references: string[];
}

export interface AttackImplication {
  attack_id: string;
  vector_name: string;
  threat_actor_profile: string;
  exploit_scenario: string;
  prerequisites: string;
  impact_summary: string;
  mitre_attack_technique: string;
  affected_findings: string[];
}

export interface RemediationStep {
  step_id: string;
  phase: 'PHASE_1_IMMEDIATE' | 'PHASE_2_HARDENING' | 'PHASE_3_ARCHITECTURAL';
  component: string;
  action_title: string;
  instructions: string;
  config_snippet: string;
  verification_command: string;
  effort: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface ExecutiveSummary {
  overall_posture: string;
  risk_score_summary: string;
  business_impact: string;
  compliance_overview: string;
  strategic_recommendations: string[];
}

export interface TechnicalSummary {
  protocol_health: string;
  cryptographic_assessment: string;
  integrity_and_sequence_analysis: string;
  leakage_and_exposure_analysis: string;
  rfc_compliance_citations: string[];
}

export interface AISecurityAnalysis {
  analysis_id: string;
  capture_id: string;
  timestamp: string;
  provider_used: string;
  overall_risk_score: number;
  risk_level: string;
  executive_summary: ExecutiveSummary;
  technical_summary: TechnicalSummary;
  prioritized_findings: PrioritizedFinding[];
  attack_implications: AttackImplication[];
  remediation_steps: RemediationStep[];
  metadata: Record<string, unknown>;
}
