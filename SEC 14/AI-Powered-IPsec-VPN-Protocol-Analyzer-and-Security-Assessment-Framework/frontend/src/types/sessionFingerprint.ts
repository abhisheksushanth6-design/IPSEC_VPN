/**
 * TypeScript definitions for Layer 04 — Session Fingerprinting & SA Lifecycle.
 */

export interface VPNSessionFingerprint {
  session_id: string;
  capture_id: string;
  fingerprint: string; // 64-character SHA-256 hash
  short_signature: string; // 16-character hex
  initiator_ip: string;
  responder_ip: string;
  endpoint_pair: [string, string];
  protocols: string[];
  state: string; // "ACTIVE" | "NEGOTIATING" | "TERMINATED"
  start_time: string;
  end_time: string;
  duration_seconds: number;
  total_packets: number;
  total_bytes: number;
  ike_packets: number;
  esp_packets: number;
  ah_packets: number;
  ike_version: string | null;
  initiator_spi: string | null;
  responder_spi: string | null;
  child_sa_spis: string[];
  encapsulation_mode: string; // "TUNNEL" | "TRANSPORT"
  nat_traversal: boolean;
  crypto_summary: {
    encryption?: string[];
    integrity?: string[];
    dh_groups?: string[];
    prf?: string[];
  };
  anomaly_indicators: string[];
  protocol_suite: string;
}

export interface SessionFingerprintReport {
  capture_id: string;
  total_sessions: number;
  sessions: VPNSessionFingerprint[];
  status: string;
}
