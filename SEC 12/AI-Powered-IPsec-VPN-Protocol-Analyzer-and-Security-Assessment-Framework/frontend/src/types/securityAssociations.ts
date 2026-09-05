/** Contracts for the SA lifecycle API. Mirror `backend/app/schemas/security_associations.py`. */

import type { AnalyzedPacketSummary } from './packetAnalysis';

export type SAType = 'IKE' | 'CHILD' | 'UNKNOWN';
export type SAState = 'UNKNOWN' | 'DETECTED' | 'NEGOTIATING' | 'ESTABLISHED' | 'ACTIVE' | 'REKEYING' | 'EXPIRED' | 'TERMINATED' | 'FAILED';
export type SAEngineState = 'NOT INITIALIZED' | 'READY' | 'ANALYZING' | 'ACTIVE' | 'ERROR';
export type SASortKey = 'start_time' | 'last_seen' | 'state' | 'type' | 'initiator' | 'responder' | 'packet_count';

export interface SALifecycleEvent {
  timestamp: string | null;
  event_type: string;
  previous_state: SAState | null;
  new_state: SAState | null;
  packet_number: number | null;
  message_id: number | null;
  spi: string | null;
  description: string;
}

export interface SAStateTransition {
  timestamp: string | null;
  state: SAState;
}

export interface SAFailure {
  exchange: string;
  message_id: number;
  notification: string;
  timestamp: string | null;
  packet_number: number;
}

export interface SecurityAssociationSummary {
  id: string;
  type: SAType;
  state: SAState;
  protocol: string;
  initiator: string;
  responder: string;
  ike_version: string | null;
  initiator_spi: string | null;
  responder_spi: string | null;
  spi: string | null;
  start_time: string | null;
  last_seen: string | null;
  duration_seconds: number | null;
  packet_count: number;
  byte_count: number;
  nat_traversal: boolean;
  parent_sa_id: string | null;
  association: string;
  rekey_count: number;
  session_id: string | null;
}

export interface ChildSA {
  id: string;
  protocol: string;
  spi: string;
  state: SAState;
  initiator: string;
  responder: string;
  packet_count: number;
  start_time: string | null;
  last_seen: string | null;
  association: string;
}

export interface SecurityAssociation extends SecurityAssociationSummary {
  exchange_types: string[];
  message_ids: number[];
  payload_types: string[];
  flags_seen: string[];
  child_sas: ChildSA[];
  parent: ChildSA | null;
  timeline: SALifecycleEvent[];
  state_history: SAStateTransition[];
  observations: string[];
  failure: SAFailure | null;
  capture_ended_in_state: boolean;
  security_parameters_available: boolean;
  traffic_selectors_available: boolean;
  packets: AnalyzedPacketSummary[];
  packets_total: number;
  packets_available: boolean;
}

export interface SAStatistics {
  total: number; ike: number; child: number; active: number; established: number; negotiating: number;
  rekeying: number; terminated: number; failed: number; detected: number; unknown: number;
}

export interface SAEngineStatus {
  state: SAEngineState;
  packets_available: boolean;
  sessions_available: boolean;
  capture_id: string | null;
  capture_filename: string | null;
  discovered_at: string | null;
  statistics: SAStatistics | null;
  last_error: string | null;
}

export interface SAPage {
  items: SecurityAssociationSummary[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface SAFilters {
  page: number;
  pageSize: number;
  type?: SAType;
  state?: SAState;
  ikeVersion?: string;
  source?: string;
  destination?: string;
  protocol?: 'IKE' | 'ESP' | 'AH';
  spi?: string;
  search?: string;
  sort: SASortKey;
  order: 'asc' | 'desc';
}

export interface SAReference {
  id: string;
  type: SAType;
  state: SAState;
  protocol: string;
  spi: string | null;
  initiator_spi: string | null;
}
