/**
 * TypeScript definitions for Layer 05 — Security Assessment & Risk Engine.
 */

export interface SecurityFinding {
  finding_id: string;
  rule_id: string;
  title: string;
  category: 'CRYPTOGRAPHY' | 'INTEGRITY' | 'PROTOCOL_ANOMALY' | 'DATA_LEAKAGE' | 'TUNNEL_STATE' | 'CONFIGURATION';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number; // 0.0 to 1.0
  explanation: string;
  evidence: Record<string, unknown>;
  affected_session?: string | null;
  affected_tunnel?: string | null;
  affected_packet_numbers?: number[];
  remediation: string;
  cve_references: string[];
  compliance_mappings: string[];
}

export interface RiskScoreSummary {
  overall_risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  findings_count: number;
  findings_by_severity: Record<string, number>;
  status: string;
}

export interface RiskAssessmentReport {
  capture_id: string;
  overall_risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  findings_count: number;
  findings_by_severity: Record<string, number>;
  findings: SecurityFinding[];
  evaluated_sessions_count: number;
  evaluated_tunnels_count: number;
  evaluated_packets_count: number;
  assessment_timestamp: string;
  status: string;
}
