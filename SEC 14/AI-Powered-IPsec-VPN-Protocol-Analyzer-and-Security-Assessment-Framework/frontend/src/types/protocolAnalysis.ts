/**
 * TypeScript definitions for Layer 03 — Packet & Protocol Analysis.
 */

export interface IKEProposal {
  packet_number: number;
  proposal_number: number;
  protocol: string;
  spi: string | null;
  encryption: string[];
  integrity: string[];
  prf: string[];
  dh_groups: string[];
  esn: string | null;
}

export interface IKESummary {
  version: string | null;
  initiator_spi: string | null;
  responder_spi: string | null;
  exchange_type: string | null;
  exchange_name: string | null;
  is_response: boolean;
  proposals: IKEProposal[];
  payload_types: string[];
}

export interface IPsecStream {
  stream_id: string;
  protocol: string; // "ESP" | "AH"
  spi: string;
  source_ip: string;
  destination_ip: string;
  packet_count: number;
  total_bytes: number;
  first_seen: string;
  last_seen: string;
  sequence_numbers: number[];
  sequence_min: number;
  sequence_max: number;
  replay_count: number;
  zero_sequence_count: number;
  has_large_gap: boolean;
}

export interface TunnelEndpoint {
  source_ip: string;
  destination_ip: string;
  protocols: string[];
  spis: string[];
  packet_count: number;
  byte_count: number;
}

export interface ProtocolAnomaly {
  anomaly_id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  packet_number?: number | null;
  evidence: Record<string, unknown>;
}

export interface ProtocolAnalysisReport {
  capture_id: string;
  total_packets_analyzed: number;
  ipsec_packets: number;
  ike_summary: IKESummary;
  ipsec_streams: IPsecStream[];
  tunnel_endpoints: TunnelEndpoint[];
  anomalies: ProtocolAnomaly[];
  protocol_counts: Record<string, number>;
  analysis_timestamp: string;
  status: string;
}
