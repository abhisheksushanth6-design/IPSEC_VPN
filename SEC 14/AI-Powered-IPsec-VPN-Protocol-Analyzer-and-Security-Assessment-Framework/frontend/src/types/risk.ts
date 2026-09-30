/**
 * Type definitions for Layer 10 — Risk Assessment & Decision Engine.
 */

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type PolicyDecision = 'ALLOW' | 'INSPECT' | 'RESTRICT' | 'TERMINATE';
export type DataQuality = 'COMPLETE' | 'PARTIAL';

export interface ContributingSignal {
  source: string;
  contribution: number;
  reason: string;
  evidence_reference?: string | null;
}

export interface RiskEvidenceItem {
  source_layer: string;
  evidence_type: string;
  identifier: string;
  summary: string;
}

export interface RiskScoreBreakdown {
  vulnerability_score: number;
  ml_score: number;
  drift_score: number;
  state_score: number;
  total_risk_score: number;
}

export interface RiskAssessmentResponse {
  id: string;
  session_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  decision: PolicyDecision;
  decision_alias?: 'ALLOW' | 'WARN' | 'ISOLATE' | 'BLOCK';
  is_advisory?: boolean;
  data_quality: DataQuality;
  confidence_score: number;
  breakdown: RiskScoreBreakdown;
  severity_summary?: Record<string, number>;
  contributing_signals: ContributingSignal[];
  evidence: RiskEvidenceItem[];
  recommended_actions: string[];
  available_signals: string[];
  unavailable_signals: string[];
  evaluated_at: string;
}

export interface RiskSummaryResponse {
  state: 'OPERATIONAL' | 'READY' | 'NOT_ANALYZED';
  overall_risk_score?: number | null;
  overall_risk_level?: RiskLevel | null;
  decision?: PolicyDecision | null;
  decision_alias?: 'ALLOW' | 'WARN' | 'ISOLATE' | 'BLOCK' | null;
  is_advisory?: boolean;
  data_quality?: DataQuality | null;
  assessed_sessions_count: number;
  total_sessions_count: number;
  critical_risk_count: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  latest_assessment?: RiskAssessmentResponse | null;
}

export interface RiskExportResponse {
  export_version: string;
  exported_at: string;
  total_assessments: number;
  assessments: RiskAssessmentResponse[];
  metadata: Record<string, any>;
}
