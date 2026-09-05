/**
 * Dashboard data contracts.
 *
 * Every collection is nullable: `null` means the producing engine does not
 * exist yet, which the dashboard renders as NOT INITIALIZED or NO DATA
 * AVAILABLE. An empty array means the engine ran and found nothing. The two
 * are never conflated.
 */

import type { LucideIcon } from 'lucide-react';

import type { StatusKind } from './status';

/** Where a displayed value actually came from. */
export type DataSource = 'backend' | 'unavailable';

export interface DashboardMetric {
  id: string;
  label: string;
  /** Numeric value, or null when the producing engine is not initialised. */
  value: number | null;
  /** Secondary status shown beneath the value. */
  status?: StatusKind;
  statusLabel?: string;
  icon: LucideIcon;
  source: DataSource;
  /** Route to the module that owns this metric. */
  href?: string;
}

/** Fixed risk bands. Classification happens only once a real score exists. */
export type RiskClassification = 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface RiskBand {
  classification: RiskClassification;
  min: number;
  max: number;
}

export interface RiskSummary {
  /** 0–100, or null when Layer 10 is not initialised. */
  score: number | null;
  classification: RiskClassification | null;
  lastUpdated: string | null;
}

export interface TrafficPoint {
  timestamp: string;
  packets: number;
  bytes?: number;
}

export interface RiskHistoryPoint {
  timestamp: string;
  score: number;
}

export type ProtocolName = 'IKE' | 'ESP' | 'AH' | 'UDP' | 'IP';

export interface ProtocolDistribution {
  protocol: ProtocolName;
  count: number;
}

export interface AnomalyPoint {
  timestamp: string;
  anomalies: number;
}

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface VulnerabilitySeverity {
  severity: SeverityLevel;
  count: number;
}

export type SAChartState =
  | 'NEGOTIATING'
  | 'ESTABLISHED'
  | 'REKEYING'
  | 'EXPIRED'
  | 'FAILED'
  | 'TERMINATED';

export interface SAActivity {
  state: SAChartState;
  count: number;
}

export type SecurityEventType =
  | 'Packet Captured'
  | 'IKE Negotiation'
  | 'SA Established'
  | 'SA Rekey'
  | 'Security Drift Detected'
  | 'AI Anomaly Detected'
  | 'Vulnerability Detected'
  | 'Risk Score Changed';

export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: SecurityEventType;
  severity: EventSeverity;
  source: string;
  description: string;
}

/** Everything the overview needs, assembled by `useDashboardData`. */
export interface DashboardData {
  risk: RiskSummary;
  metrics: DashboardMetric[];
  traffic: TrafficPoint[] | null;
  riskHistory: RiskHistoryPoint[] | null;
  protocols: ProtocolDistribution[] | null;
  anomalies: AnomalyPoint[] | null;
  vulnerabilities: VulnerabilitySeverity[] | null;
  saActivity: SAActivity[] | null;
  events: SecurityEvent[] | null;
}

// ---------------------------------------------------------------------------
// Section 13 — Web Dashboard API Contracts
// ---------------------------------------------------------------------------

export interface DashboardMetricsPayload {
  overall_risk_score: number | null;
  overall_risk_status: string;
  active_vpn_sessions: number;
  active_sas: number;
  packets_analyzed: number;
  ai_anomalies: number;
  drift_events: number;
  vulnerabilities_total: number;
  vulnerabilities_critical: number;
  vulnerabilities_high: number;
  vulnerabilities_medium: number;
  vulnerabilities_low: number;
  vulnerabilities_active: number;
  capture_status: string;
}

export interface SystemPosture {
  backend_status: string;
  database_status: string;
  application_mode: string;
  layers_total: number;
  layers_initialized: number;
  last_refresh: string;
}

export interface SessionActivityItem {
  session_id: string;
  start_time: string | null;
  duration_seconds: number;
  peer_a: string;
  peer_b: string;
  ike_version: string | null;
  sa_count: number;
  packet_count: number;
  has_anomaly: boolean;
  anomaly_score: number | null;
  has_drift: boolean;
  drift_status: string | null;
  vulnerabilities_count: number;
  status: string;
}

export interface SecurityTimelineEvent {
  id: string;
  timestamp: string;
  layer: string;
  layer_number: number;
  event_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  source_id?: string | null;
  details?: Record<string, unknown>;
}

export interface ProtocolPosture {
  ike_versions: string[];
  observed_encryption_algorithms: string[];
  observed_integrity_algorithms: string[];
  observed_dh_groups: string[];
  observed_prf_algorithms: string[];
  pfs_enabled: boolean | null;
  protocol_counts: Record<string, number>;
}

export interface DashboardSummaryResponse {
  posture: SystemPosture;
  metrics: DashboardMetricsPayload;
  recent_sessions: SessionActivityItem[];
  recent_events: SecurityTimelineEvent[];
  protocol_posture: ProtocolPosture;
  vulnerability_breakdown: Record<string, number>;
  sa_state_breakdown: Record<string, number>;
  ml_engine_status: Record<string, unknown>;
  drift_engine_status: Record<string, unknown>;
}
