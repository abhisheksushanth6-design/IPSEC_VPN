/**
 * Live Monitor contracts.
 *
 * As with the dashboard, `null` means "the producing engine does not exist"
 * and `[]` means "the engine ran and observed nothing".
 */

import type { EventSeverity } from './dashboard';

export type PacketProtocol = 'IP' | 'TCP' | 'UDP' | 'IKE' | 'ESP' | 'AH' | 'ICMP';

export const PACKET_PROTOCOLS: readonly PacketProtocol[] = [
  'IP', 'TCP', 'UDP', 'IKE', 'ESP', 'AH', 'ICMP',
];

export type PacketStatus = 'OK' | 'MALFORMED' | 'FLAGGED';

export interface PacketSummary {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  protocol: PacketProtocol;
  length: number;
  info: string;
  status: PacketStatus;
}

/** Full packet detail, populated by Layer 03 in a later section. */
export interface Packet extends PacketSummary {
  network?: Record<string, string>;
  transport?: Record<string, string>;
  ipsec?: Record<string, string>;
  parsed?: Record<string, string>;
  raw?: string;
}

export type VPNSessionState = 'NEGOTIATING' | 'ESTABLISHED' | 'REKEYING' | 'CLOSING' | 'CLOSED';

export interface VPNSession {
  id: string;
  source: string;
  destination: string;
  state: VPNSessionState;
  startedAt: string;
  durationSeconds: number;
  protocol: PacketProtocol;
  ikeVersion?: string;
  cipher?: string;
  authentication?: string;
  saCount?: number;
  /** 0–100 once the risk engine exists. */
  risk?: number;
}

export type SADirection = 'INBOUND' | 'OUTBOUND';
export type SAProtocol = 'ESP' | 'AH';

export interface MonitorSecurityAssociation {
  id: string;
  spi: string;
  direction: SADirection;
  protocol: SAProtocol;
  encryption?: string;
  integrity?: string;
  authentication?: string;
  state: string;
  createdAt: string;
  expiresAt?: string;
  lifetimeSeconds?: number;
}

export type SystemActivityType =
  | 'Capture Started'
  | 'Capture Stopped'
  | 'Backend Connected'
  | 'Backend Disconnected'
  | 'Analyzer Started'
  | 'Analyzer Stopped'
  | 'Model Loaded'
  | 'Model Unloaded'
  | 'Realtime Connected'
  | 'Realtime Disconnected'
  | 'Realtime Error';

export interface SystemActivityEvent {
  id: string;
  timestamp: string;
  type: SystemActivityType;
  detail: string;
}

export type RealtimeConnectionState =
  | 'IDLE'
  | 'CONNECTING'
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'RECONNECTING'
  | 'ERROR';

export type CaptureState =
  | 'IDLE'
  | 'STARTING'
  | 'CAPTURING'
  | 'STOPPING'
  | 'INGESTING'
  | 'COMPLETED'
  | 'READY'
  | 'NOT INITIALIZED'
  | 'PAUSED'
  | 'STOPPED'
  | 'ERROR';

export interface NetworkInterface {
  name: string;
  description?: string;
}

export interface MonitorFilters {
  protocol?: PacketProtocol;
  source?: string;
  destination?: string;
  severity?: EventSeverity;
  eventType?: string;
  timeRange?: { from: string; to: string };
  search?: string;
}

/** Envelope for messages received on /ws/events. */
export interface RealtimeMessage<TPayload = unknown> {
  id?: string;
  timestamp?: string;
  type: string;
  severity?: EventSeverity;
  source?: string;
  payload?: TPayload;
  /** Present on the backend's handshake frame. */
  message?: string;
  project?: string;
}
