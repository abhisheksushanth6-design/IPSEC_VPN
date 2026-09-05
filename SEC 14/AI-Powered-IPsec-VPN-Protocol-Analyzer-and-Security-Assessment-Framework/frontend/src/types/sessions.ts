/** Contracts for the IPsec sessions API. Mirror `backend/app/schemas/sessions.py`. */

import type { AnalyzedPacketSummary } from './packetAnalysis';

export type SessionState = 'DISCOVERED' | 'NEGOTIATING' | 'ESTABLISHED' | 'ACTIVE' | 'IDLE' | 'TERMINATED' | 'UNKNOWN';
export type SessionDirection = 'OUTBOUND' | 'INBOUND' | 'BIDIRECTIONAL' | 'UNKNOWN';
export type SessionCorrelation = 'DIRECT' | 'CORRELATED' | 'PARTIAL' | 'UNKNOWN';
export type SessionProtocol = 'IKE' | 'ESP' | 'AH';
export type SessionEngineState = 'NOT INITIALIZED' | 'READY' | 'ANALYZING' | 'AVAILABLE' | 'ERROR';
export type SessionSortKey = 'start_time' | 'end_time' | 'duration_seconds' | 'packet_count' | 'byte_count' | 'source' | 'destination' | 'state';

export interface SessionTimelineEvent {
  timestamp: string | null;
  packet_number: number;
  label: string;
  detail: string;
}

export interface SessionIKEInfo {
  version: string | null;
  initiator_spis: string[];
  responder_spis: string[];
  exchange_types: string[];
  message_ids: number[];
  payload_types: string[];
  packet_count: number;
  nat_traversal: boolean;
}

export interface SessionSPIInfo {
  spi: string;
  direction: string;
  packet_count: number;
  sequence_min: number;
  sequence_max: number;
  nat_traversal: boolean;
}

export interface SessionDataPlaneInfo {
  spis: SessionSPIInfo[];
  packet_count: number;
}

export interface SessionActivityPoint {
  timestamp: string;
  packets: number;
}

export interface IPsecSessionSummary {
  id: string;
  ordinal: number;
  source: string;
  destination: string;
  direction: SessionDirection;
  state: SessionState;
  correlation: SessionCorrelation;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number | null;
  packet_count: number;
  byte_count: number;
  ike_packets: number;
  esp_packets: number;
  ah_packets: number;
  ike_version: string | null;
  nat_traversal: boolean;
}

export interface IPsecSession extends IPsecSessionSummary {
  ike: SessionIKEInfo | null;
  esp: SessionDataPlaneInfo | null;
  ah: SessionDataPlaneInfo | null;
  timeline: SessionTimelineEvent[];
  activity: SessionActivityPoint[];
  evidence: string[];
  packets: AnalyzedPacketSummary[];
  packets_total: number;
  packets_available: boolean;
}

export interface SessionStatistics {
  total: number;
  active: number;
  established: number;
  negotiating: number;
  terminated: number;
  discovered: number;
  unknown: number;
}

export interface SessionEngineStatus {
  state: SessionEngineState;
  packets_available: boolean;
  capture_id: string | null;
  capture_filename: string | null;
  discovered_at: string | null;
  statistics: SessionStatistics | null;
  inactivity_gap_seconds: number;
  last_error: string | null;
}

export interface SessionPage {
  items: IPsecSessionSummary[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface SessionFilters {
  page: number;
  pageSize: number;
  state?: SessionState;
  protocol?: SessionProtocol;
  source?: string;
  destination?: string;
  ikeVersion?: string;
  search?: string;
  startAfter?: string;
  endBefore?: string;
  sort: SessionSortKey;
  order: 'asc' | 'desc';
}

export interface PacketSessionLink {
  packet_id: string;
  session_id: string | null;
  role: string | null;
}
