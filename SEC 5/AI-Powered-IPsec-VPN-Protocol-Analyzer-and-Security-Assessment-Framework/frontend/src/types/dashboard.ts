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

export type SAState =
  | 'NEGOTIATING'
  | 'ESTABLISHED'
  | 'REKEYING'
  | 'EXPIRED'
  | 'FAILED'
  | 'TERMINATED';

export interface SAActivity {
  state: SAState;
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
