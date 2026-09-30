export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ThreatStatus = 'DETECTED' | 'VULNERABLE' | 'MITIGATED' | 'NOT_APPLICABLE';

export interface ThreatMatrixItem {
  id: string;
  capture_id: string;
  session_id?: string | null;
  matrix_id: string;
  name: string;
  category: string;
  severity: ThreatSeverity;
  mitre_technique_id?: string | null;
  mitre_tactic?: string | null;
  nist_control?: string | null;
  rfc_reference?: string | null;
  status: ThreatStatus;
  evidence: string[];
  remediation: string;
  created_at: string;
}

export interface ThreatMatrixSummary {
  capture_id: string;
  total_threats: number;
  detected_count: number;
  vulnerable_count: number;
  mitigated_count: number;
  not_applicable_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  compliance_score: number;
}
