import { useMemo } from 'react';
import { Activity, BrainCircuit, Cable, KeyRound, Network, ShieldAlert } from 'lucide-react';

import type {
  CaptureState,
  DashboardMetric,
  NetworkInterface,
  Packet,
  SecurityAssociation,
  SecurityEvent,
  TrafficPoint,
  VPNSession,
} from '@/types';

export interface LiveMonitorData {
  captureState: CaptureState;
  interfaces: NetworkInterface[] | null;
  metrics: DashboardMetric[];
  packets: Packet[] | null;
  traffic: TrafficPoint[] | null;
  packetRate: number | null;
  bandwidth: number | null;
  ipsecBreakdown: Array<{ category: 'IKE' | 'ESP' | 'AH' | 'OTHER'; count: number }> | null;
  sessions: VPNSession[] | null;
  associations: SecurityAssociation[] | null;
  events: SecurityEvent[] | null;
}

/**
 * The monitor's data model. No capture, session, SA or analysis endpoint
 * exists yet, so every collection is `null` and every count is reported as
 * NOT INITIALIZED rather than as a measurement.
 */
export function useLiveMonitorData(): LiveMonitorData {
  return useMemo<LiveMonitorData>(() => {
    const metrics: DashboardMetric[] = [
      { id: 'packets', label: 'Packets Observed', value: 0, status: 'NOT INITIALIZED', icon: Network, source: 'unavailable' },
      { id: 'ipsec', label: 'IPsec Packets', value: 0, status: 'NOT INITIALIZED', icon: KeyRound, source: 'unavailable' },
      { id: 'sessions', label: 'Active VPN Sessions', value: 0, status: 'NOT INITIALIZED', icon: Cable, source: 'unavailable' },
      { id: 'sas', label: 'Active Security Associations', value: 0, status: 'NOT INITIALIZED', icon: Activity, source: 'unavailable' },
      { id: 'events', label: 'Security Events', value: 0, status: 'NOT INITIALIZED', icon: ShieldAlert, source: 'unavailable' },
      { id: 'anomalies', label: 'Anomalies', value: 0, status: 'NOT INITIALIZED', statusLabel: 'MODEL NOT INITIALIZED', icon: BrainCircuit, source: 'unavailable' },
    ];

    return {
      captureState: 'NOT INITIALIZED',
      interfaces: null,
      metrics,
      packets: null,
      traffic: null,
      packetRate: null,
      bandwidth: null,
      ipsecBreakdown: null,
      sessions: null,
      associations: null,
      events: null,
    };
  }, []);
}
