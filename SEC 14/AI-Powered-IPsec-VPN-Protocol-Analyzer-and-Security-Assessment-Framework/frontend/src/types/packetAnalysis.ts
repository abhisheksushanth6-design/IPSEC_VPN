/** Contracts for the packet-analysis API. Mirror `backend/app/schemas/packets.py`. */

export type ParseStatus = 'OK' | 'MALFORMED' | 'ERROR';
export type AnalysisState = 'NOT INITIALIZED' | 'READY' | 'ANALYZING' | 'COMPLETED' | 'ERROR';
export type DisplayProtocol = 'IKE' | 'ESP' | 'AH' | 'TCP' | 'UDP' | 'ICMP' | 'IP' | 'OTHER';
export type IPsecFilter = 'ALL' | 'IKE' | 'ESP' | 'AH' | 'NON-IPSEC';
export type PacketSortKey = 'number' | 'timestamp' | 'length' | 'source' | 'destination' | 'protocol';

export interface EthernetLayer {
  source_mac: string;
  destination_mac: string;
  ethertype: string;
  vlan_id: number | null;
}

export interface IPLayer {
  version: number;
  source: string;
  destination: string;
  protocol_number: number;
  protocol_name: string;
  total_length: number;
  ttl: number;
  header_length: number | null;
  identification: number | null;
  dont_fragment: boolean | null;
  more_fragments: boolean | null;
  fragment_offset: number | null;
  traffic_class: number | null;
  flow_label: number | null;
}

export interface TCPLayer {
  kind: 'TCP';
  source_port: number;
  destination_port: number;
  sequence_number: number;
  acknowledgment_number: number;
  flags: string[];
  window: number;
  header_length: number;
}

export interface UDPLayer {
  kind: 'UDP';
  source_port: number;
  destination_port: number;
  length: number;
  checksum: number;
}

export interface ICMPLayer {
  kind: 'ICMP';
  type: number;
  code: number;
  checksum: number;
  type_name: string;
}

export type TransportLayer = TCPLayer | UDPLayer | ICMPLayer;

export interface IKEPayload {
  type_number: number;
  name: string;
  length: number;
  critical: boolean;
}

export interface IKELayer {
  version: string;
  major_version: number;
  minor_version: number;
  exchange_type: number;
  exchange_name: string;
  initiator_spi: string;
  responder_spi: string;
  message_id: number;
  flags: string[];
  length: number;
  payloads: IKEPayload[];
  payload_count: number;
  encrypted_payload: boolean;
}

export interface ESPLayer {
  spi: string;
  sequence_number: number;
  payload_length: number;
  encrypted: boolean;
  authentication_data: string;
}

export interface AHLayer {
  next_header: number;
  next_header_name: string;
  payload_length: number;
  spi: string;
  sequence_number: number;
  authentication_data: string;
  icv_length: number;
}

export type IPsecAnalysis =
  | { type: 'IKE'; nat_traversal: boolean; nat_traversal_note: string | null; udp_port: number | null; ike: IKELayer; esp: null; ah: null }
  | { type: 'ESP'; nat_traversal: boolean; nat_traversal_note: string | null; udp_port: number | null; ike: null; esp: ESPLayer; ah: null }
  | { type: 'AH'; nat_traversal: boolean; nat_traversal_note: string | null; udp_port: number | null; ike: null; esp: null; ah: AHLayer };

export interface RawData {
  hex: string;
  ascii: string;
  length: number;
  truncated: boolean;
}

export interface SecurityFlags {
  encrypted: boolean;
  authenticated: boolean;
  fragmented: boolean;
  nat_t: boolean;
  malformed: boolean;
  incomplete: boolean;
}

export interface AnalyzedPacketSummary {
  id: string;
  number: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: DisplayProtocol;
  length: number;
  info: string;
  parse_status: ParseStatus;
  ipsec_type: 'IKE' | 'ESP' | 'AH' | null;
  nat_traversal: boolean;
  spi: string | null;
}

export interface PacketAnalysisResult {
  id: string;
  number: number;
  timestamp: string;
  captured_length: number;
  original_length: number;
  source: string;
  destination: string;
  protocol: DisplayProtocol;
  length: number;
  info: string;
  layers: string[];
  ethernet: EthernetLayer | null;
  ip: IPLayer | null;
  transport: TransportLayer | null;
  ipsec: IPsecAnalysis | null;
  raw: RawData | null;
  flags: SecurityFlags;
  parse_status: ParseStatus;
  parse_error: string | null;
  parse_affected_protocol: string | null;
}

export interface ProtocolCounts {
  IKE: number; ESP: number; AH: number; TCP: number; UDP: number; ICMP: number; OTHER: number;
}

export interface PacketStatistics {
  total_packets: number;
  ipsec_packets: number;
  ike_packets: number;
  esp_packets: number;
  ah_packets: number;
  malformed_packets: number;
}

export interface CaptureMetadata {
  format: string;
  link_type: number;
  link_type_name: string;
  packet_count: number;
  truncated: boolean;
  filename: string | null;
  loaded_at: string | null;
}

export interface AnalysisStatus {
  state: AnalysisState;
  analyzer_available: boolean;
  supported_formats: string[];
  max_upload_bytes: number;
  max_packets: number;
  capture: CaptureMetadata | null;
  statistics: PacketStatistics | null;
  protocol_counts: ProtocolCounts | null;
  last_error: string | null;
}

export interface PacketPage {
  items: AnalyzedPacketSummary[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface PacketQuery {
  page: number;
  pageSize: number;
  protocol?: DisplayProtocol;
  source?: string;
  destination?: string;
  port?: number;
  ipsec: IPsecFilter;
  search?: string;
  sort: PacketSortKey;
  order: 'asc' | 'desc';
}

export interface PacketApiError {
  error: string;
  message: string;
}
