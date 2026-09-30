/**
 * TypeScript definitions for the SIH 26160 Security Posture view:
 * Layer 07 protocol identification (provenance-tagged) and the Layer 08
 * comprehensive security assessment with the what-if remediation simulator.
 */

export type Provenance = 'OBSERVED' | 'INFERRED' | 'PREDICTED' | 'ASSUMED' | 'UNAVAILABLE' | 'WHAT_IF' | string;

export interface ProtocolIdentification {
  is_ipsec: boolean;
  protocol_type: string;
  confidence: number;
  provenance: Provenance;
  evidence: string[];
}

export interface IKEIdentification {
  detected: boolean;
  version: string;
  initiator_spi: string | null;
  responder_spi: string | null;
  exchanges: string[];
  confidence: number;
  provenance: Provenance;
  nat_traversal: boolean;
  notify_types: string[];
  auth_method: string | null;
  evidence: string[];
}

export interface VPNModeIdentification {
  mode: 'TUNNEL' | 'TRANSPORT' | string;
  confidence: number;
  evidence: string;
  provenance: Provenance;
}

export interface ESPInference {
  provenance: Provenance;
  cipher_family: string | null;
  framing_hypothesis: string | null;
  block_size: number | null;
  iv_length: number | null;
  icv_length_candidates: number[];
  integrity_candidates: string[];
  key_length_observable: boolean;
  confidence: number;
  packets_examined: number;
  distinct_lengths: number;
  hypothesis_consistency: Record<string, number>;
  payload_entropy_bits: number | null;
  entropy_sample_bytes: number;
  null_encryption_suspected: boolean;
  legacy_block_cipher_suspected: boolean;
  evidence: string[];
}

export interface PFSInference {
  status: 'ENABLED' | 'DISABLED' | 'UNKNOWN' | string;
  provenance: Provenance;
  confidence: number;
  rekey_exchanges_observed?: number;
  message_lengths?: number[];
  evidence: string[];
}

export interface CryptoConfiguration {
  cipher: string;
  key_size_bits: number | null;
  cipher_family: string;
  integrity: string;
  prf: string | null;
  dh_group: string;
  pfs_enabled: boolean | null;
  confidence: number;
  observable_source: string;
  provenance: Provenance;
  ike_sa: Record<string, unknown>;
  esp_inference: Partial<ESPInference>;
  pfs: Partial<PFSInference>;
  downgrade: { detected?: boolean; reason?: string; best_offered_label?: string; selected_label?: string } | null;
  weak_offered: string[];
  details: Record<string, unknown>;
  evidence: string[];
}

export interface SACharacteristics {
  ike_sas_count: number;
  child_sas_count: number;
  observed_spis: string[];
  rekey_count: number;
  sa_state: string;
  replay_protection_active: boolean;
  replay_verdict: string;
  replay_window_size: number;
  esn_enabled: boolean | null;
  esn_observable: boolean;
  lifetime_seconds: number | null;
  lifetime_provenance: Provenance;
  provenance: Provenance;
  evidence: string[];
}

export interface TrafficClassificationResult {
  predicted_type: string;
  confidence: number;
  probabilities: Record<string, number>;
  flow_features: Record<string, number | string | null>;
  explanations: Array<{ feature: string; value: unknown; influence: string; reason: string }>;
  provenance: Provenance;
  abstained: boolean;
  data_packets: number;
  model_version: string | null;
}

export interface AIComprehensiveAnalysis {
  session_id: string;
  capture_id: string;
  timestamp: string;
  protocol_identification: ProtocolIdentification;
  ike_identification: IKEIdentification;
  vpn_mode_identification: VPNModeIdentification;
  crypto_configuration: CryptoConfiguration;
  sa_characteristics: SACharacteristics;
  traffic_classification: TrafficClassificationResult;
  overall_ai_confidence: number;
  confidence_breakdown: Record<string, unknown>;
}

export interface ComplianceCheck {
  component: string;
  requirement: string;
  level: string;
  observed: string | null;
  status: 'PASS' | 'FAIL' | 'WARN' | 'NOT_ASSESSABLE' | string;
  reference: string;
  note: string;
}

export interface ComplianceProfile {
  profile_id: string;
  profile_name: string;
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIALLY_COMPLIANT' | 'NOT_ASSESSABLE' | string;
  score: number | null;
  checks_total: number;
  checks_assessable: number;
  checks_passed: number;
  checks_failed: number;
  checks_warned: number;
  coverage: number;
  checks: ComplianceCheck[];
  summary: string;
}

export interface ExplainableFinding {
  finding: string;
  evidence: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  reason: string;
  recommendation: string;
  provenance: Provenance;
  rule_id: string | null;
}

export interface AssessmentCoverage {
  components_total: number;
  components_assessed: number;
  assessed: string[];
  unassessable: Array<{ component: string; reason: string }>;
  weight_fraction: number;
  summary: string;
}

export interface ComprehensiveSecurityAssessment {
  session_id: string;
  capture_id: string;
  overall_security_score: number;
  overall_risk_score: number;
  security_posture: string;
  ai_confidence: number;
  coverage: AssessmentCoverage;
  traffic_prediction: { predicted_type: string; confidence: number; abstained: boolean; provenance: Provenance; data_packets: number; probabilities: Record<string, number> };
  protocol_identification: { protocol_type: string; ike_version: string; ipsec_mode: string; mode_provenance: Provenance; mode_confidence: number; nat_traversal: boolean };
  cryptographic_strength: {
    grade: string; score: number | null; status: string; cipher: string; key_length_bits: number | null; authenticated_encryption: boolean | null;
    integrity_algorithm: string; prf_algorithm: string | null; dh_group: string; security_bits: number | null; provenance: Provenance;
    observable_source: string; provisional: boolean; assessable: boolean; details: string[];
  };
  configuration_compliance: {
    compliance_status: string; compliance_score: number; rules_evaluated: number; rules_passed: number; rules_violated: number;
    violations: Array<{ rule_id: string; name: string; severity: string; category: string; remediation: string }>; profiles: ComplianceProfile[];
  };
  sa_parameters: { active_sas_count: number; ike_sa_state: string; child_sa_state: string; rekey_count: number; observed_spis: string[]; state_synchronization: string; status: string; provenance: Provenance; findings: string[] };
  key_lifetime: { observed_duration_seconds: number; configured_limit_seconds: number; observed_volume_bytes: number; configured_volume_limit_bytes: number; negotiated_lifetime_seconds: number | null; lifetime_provenance: Provenance; rekeys_observed: number; lifetime_status: string; rekey_recommended: boolean; assessable: boolean; details: string };
  replay_protection: { status: string; replay_window_size: number; esn_supported: boolean | null; esn_observable: boolean; duplicate_sequences_detected: boolean; duplicates_count: number; out_of_order_count: number; max_reorder_distance: number; sequence_gaps: number; streams_analysed: number; verdict: string; window_inference: string; assessable: boolean; details: string };
  forward_secrecy: { pfs_enabled: boolean | null; pfs_status: string; dh_group: string; strength_bits: number; security_level: string; provenance: Provenance; confidence: number; assessable: boolean; details: string };
  cipher_suite_strength: { cipher_suite: string; nist_sp800_77_compliant: boolean | null; quantum_readiness: string; security_bits: number | null; assessment_summary: string };
  metadata_exposure: {
    exposure_level: string; composite_score: number; spi_leakage_score: number; sequence_leakage_score: number; length_tfc_leakage_score: number;
    timing_leakage_score: number; topology_leakage_score: number; tfc_padding_detected: boolean; observable_vectors: string[];
    traffic_context: { applied?: boolean; traffic_type?: string | null; confidence?: number | null; attack_classes?: string[]; length_multiplier?: number; timing_multiplier?: number };
    findings: Array<{ vector: string; severity: string; finding: string; leakage: string }>; remediations: string[];
  };
  explainable_findings: ExplainableFinding[];
  component_scores: Record<string, number | null>;
  evaluated_at: string;
}

export interface WhatIfRequest {
  cipher?: string;
  key_length?: number;
  integrity?: string;
  prf?: string;
  dh_group?: number;
  pfs_enabled?: boolean;
  ike_version?: '1.0' | '2.0';
  ipsec_mode?: 'TUNNEL' | 'TRANSPORT';
  tfc_padding?: boolean;
}

export interface WhatIfSummary {
  overall_security_score: number;
  security_posture: string;
  crypto_grade: string;
  crypto_score: number | null;
  security_bits: number | null;
  pfs_status: string;
  compliance_score: number;
  metadata_exposure_score: number;
  profiles: Record<string, string>;
  violations: Array<{ rule_id: string; name: string; severity: string }>;
}

export interface WhatIfResponse {
  session_id: string;
  overrides_applied: Record<string, unknown>;
  baseline: WhatIfSummary;
  simulated: WhatIfSummary;
  delta: { overall_security_score: number; compliance_score: number; violations: number; metadata_exposure_score: number };
  simulated_assessment: Record<string, unknown>;
  note: string;
}

export interface TestbedGroundTruth {
  profile_id: string;
  profile_name: string;
  capture_id: string;
  ike_version: string | null;
  ike_exchange_mode: string | null;
  ipsec_protocol: string;
  mode: string;
  ip_version: number;
  nat_traversal: boolean;
  encryption: string;
  cipher_family: string;
  key_length: number | null;
  aead: boolean;
  integrity: string;
  dh_group: number;
  pfs_enabled: boolean;
  rekey_observed: boolean;
  tfc_padding: boolean;
  downgrade: boolean;
  traffic_type: string;
  traffic_parameters: Record<string, unknown>;
  duration_seconds: number;
  spis: string[];
  synthetic: boolean;
  note: string;
}
