import { useCallback, useEffect, useState } from 'react';
import { Activity, BrainCircuit, Cable, KeyRound, Network, ShieldAlert } from 'lucide-react';

import {
  CaptureSourceInterface,
  fetchLiveCaptureInterfaces,
  fetchLiveCaptureStatus,
  LiveCaptureStatusResponse,
  startLiveCapture,
  stopLiveCapture,
  StopCaptureResponse,
} from '@/services/liveCaptureService';
import { dashboardService } from '@/services/dashboardService';
import { packetService } from '@/services/packetService';
import { sessionService } from '@/services/sessionService';
import { saService } from '@/services/saService';
import type {
  CaptureState,
  DashboardMetric,
  DashboardMetricsPayload,
  DashboardSummaryResponse,
  NetworkInterface,
  Packet,
  MonitorSecurityAssociation,
  PacketPage,
  SAPage,
  SecurityEvent,
  SecurityEventType,
  SessionPage,
  TrafficPoint,
  VPNSession,
  VPNSessionState,
} from '@/types';

export interface LiveMonitorData {
  captureState: CaptureState;
  interfaces: NetworkInterface[] | null;
  rawInterfaces: CaptureSourceInterface[];
  status: LiveCaptureStatusResponse | null;
  metrics: DashboardMetric[];
  packets: Packet[] | null;
  traffic: TrafficPoint[] | null;
  packetRate: number | null;
  bandwidth: number | null;
  ipsecBreakdown: Array<{ category: 'IKE' | 'ESP' | 'AH' | 'OTHER'; count: number }> | null;
  sessions: VPNSession[] | null;
  associations: MonitorSecurityAssociation[] | null;
  events: SecurityEvent[] | null;
  actionLoading: boolean;
  actionMessage: { type: 'success' | 'error'; text: string } | null;
  start: (vm: string, nic?: number) => Promise<void>;
  stop: () => Promise<StopCaptureResponse | null>;
  refresh: () => Promise<void>;
}

export function useLiveMonitorData(): LiveMonitorData {
  const [status, setStatus] = useState<LiveCaptureStatusResponse | null>(null);
  const [rawInterfaces, setRawInterfaces] = useState<CaptureSourceInterface[]>([]);
  const [dashboardMetrics, setDashboardMetrics] = useState<DashboardMetricsPayload | null>(null);
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummaryResponse | null>(null);
  const [packetPage, setPacketPage] = useState<PacketPage | null>(null);
  const [sessionPage, setSessionPage] = useState<SessionPage | null>(null);
  const [saPage, setSaPage] = useState<SAPage | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [st, ifaces, dMetrics, dSummary, pkts, sess, sas] = await Promise.all([
        fetchLiveCaptureStatus().catch(() => null),
        fetchLiveCaptureInterfaces().catch(() => null),
        dashboardService.getMetrics().catch(() => null),
        dashboardService.getSummary().catch(() => null),
        packetService.fetchPackets({ page: 1, pageSize: 50, sort: 'number', order: 'asc', ipsec: 'ALL' }).catch(() => null),
        sessionService.fetchSessions({ page: 1, pageSize: 20, sort: 'start_time', order: 'desc' }).catch(() => null),
        saService.fetchSAs({ page: 1, pageSize: 20, sort: 'start_time', order: 'desc' }).catch(() => null),
      ]);
      if (st) setStatus(st);
      if (ifaces && ifaces.interfaces) {
        setRawInterfaces(ifaces.interfaces);
      }
      if (dMetrics) {
        setDashboardMetrics(dMetrics);
      }
      if (dSummary) {
        setDashboardSummary(dSummary);
      }
      if (pkts) {
        setPacketPage(pkts);
      }
      if (sess) {
        setSessionPage(sess);
      }
      if (sas) {
        setSaPage(sas);
      }
    } catch {
      // Handled cleanly
    }
  }, []);

  useEffect(() => {
    loadData();
    // When capturing, poll frequently; otherwise poll gently
    const intervalMs = status?.state === 'CAPTURING' ? 1500 : 5000;
    const interval = setInterval(loadData, intervalMs);
    return () => clearInterval(interval);
  }, [loadData, status?.state]);

  const handleStart = async (vm: string, nic?: number) => {
    setActionLoading(true);
    setActionMessage(null);
    try {
      const res = await startLiveCapture(vm, nic);
      setStatus(res);
      setActionMessage({ type: 'success', text: `Live capture started on ${res.source_vm} NIC ${res.nic_number}` });
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to start live capture' });
      await loadData();
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async (): Promise<StopCaptureResponse | null> => {
    setActionLoading(true);
    setActionMessage(null);
    try {
      const res = await stopLiveCapture();
      setActionMessage({
        type: 'success',
        text: `Capture finalized. ${res.packet_count} packets ingested. Discovered ${res.sessions_discovered} session(s).`,
      });
      await loadData();
      return res;
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Failed to stop live capture' });
      await loadData();
      return null;
    } finally {
      setActionLoading(false);
    }
  };

  const captureState: CaptureState = (status?.state as CaptureState) || 'IDLE';
  const packetCount = status?.packet_count ?? 0;

  // Convert rawInterfaces to UI NetworkInterface objects
  const interfaces: NetworkInterface[] = rawInterfaces.map((iface) => ({
    name: `${iface.vm_name} (NIC ${iface.nic_number} · ${iface.nic_type})`,
    description: `${iface.role.toUpperCase()} · MAC: ${iface.mac_address || 'N/A'} · State: ${iface.vm_state.toUpperCase()}`,
  }));

  // Build live or ingested packets
  let displayPackets: Packet[] | null = null;
  if (captureState === 'CAPTURING' && status?.recent_packets && status.recent_packets.length > 0) {
    displayPackets = status.recent_packets.map((p) => ({
      id: `live-${p.packet_number}`,
      timestamp: new Date(p.timestamp * 1000).toISOString(),
      source: p.source_ip,
      destination: p.destination_ip,
      protocol: (['IKE', 'ESP', 'AH', 'TCP', 'UDP', 'ICMP'].includes(p.protocol)
        ? p.protocol
        : 'IP') as any,
      length: p.length,
      info: p.summary || `${p.protocol} ${p.source_ip} -> ${p.destination_ip}`,
      status: 'OK' as const,
    }));
  } else if (packetPage && packetPage.items && packetPage.items.length > 0) {
    displayPackets = packetPage.items.map((p) => ({
      id: p.id,
      timestamp: p.timestamp,
      source: p.source,
      destination: p.destination,
      protocol: (['IKE', 'ESP', 'AH', 'TCP', 'UDP', 'ICMP'].includes(p.protocol)
        ? p.protocol
        : 'IP') as any,
      length: p.length,
      info: p.info,
      status: (p.parse_status === 'MALFORMED' ? 'MALFORMED' : 'OK') as any,
    }));
  } else if (captureState === 'CAPTURING') {
    displayPackets = [];
  }

  // Build sessions
  let displaySessions: VPNSession[] | null = null;
  if (sessionPage && sessionPage.items && sessionPage.items.length > 0) {
    displaySessions = sessionPage.items.map((s) => {
      let vpnState: VPNSessionState = 'NEGOTIATING';
      if (s.state === 'ESTABLISHED' || s.state === 'ACTIVE') vpnState = 'ESTABLISHED';
      else if (s.state === 'TERMINATED') vpnState = 'CLOSED';

      return {
        id: s.id,
        source: s.source,
        destination: s.destination,
        state: vpnState,
        startedAt: s.start_time || new Date().toISOString(),
        durationSeconds: Math.round(s.duration_seconds ?? 0),
        protocol: (s.esp_packets > 0 ? 'ESP' : s.ah_packets > 0 ? 'AH' : 'IKE') as any,
        ikeVersion: s.ike_version || '2.0',
        saCount: (s.esp_packets > 0 ? 1 : 0) + (s.ike_packets > 0 ? 1 : 0),
      };
    });
  }

  // Build Security Associations
  let displayAssociations: MonitorSecurityAssociation[] | null = null;
  if (saPage && saPage.items && saPage.items.length > 0) {
    displayAssociations = saPage.items.map((sa) => ({
      id: sa.id,
      spi: sa.spi || sa.initiator_spi || '0x00000000',
      direction: 'INBOUND',
      protocol: sa.protocol === 'AH' ? 'AH' : 'ESP',
      state: sa.state,
      createdAt: sa.start_time || new Date().toISOString(),
    }));
  }

  // Build Security Events
  let displayEvents: SecurityEvent[] | null = null;
  if (dashboardSummary && dashboardSummary.recent_events && dashboardSummary.recent_events.length > 0) {
    displayEvents = dashboardSummary.recent_events.map((e) => {
      let eventType: SecurityEventType = 'Packet Captured';
      if (e.event_type.toLowerCase().includes('vulnerab')) eventType = 'Vulnerability Detected';
      else if (e.event_type.toLowerCase().includes('anomaly')) eventType = 'AI Anomaly Detected';
      else if (e.event_type.toLowerCase().includes('drift')) eventType = 'Security Drift Detected';
      else if (e.event_type.toLowerCase().includes('rekey') || e.event_type.toLowerCase().includes('re-key')) eventType = 'SA Rekey';
      else if (e.event_type.toLowerCase().includes('sa')) eventType = 'SA Established';
      else if (e.event_type.toLowerCase().includes('ike')) eventType = 'IKE Negotiation';

      return {
        id: e.id,
        timestamp: e.timestamp,
        type: eventType,
        severity: (['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(e.severity) ? e.severity : 'INFO') as any,
        source: e.source_id || 'Security Engine',
        description: e.description || e.title,
      };
    });
  }

  // Build Traffic Timeline
  let displayTraffic: TrafficPoint[] | null = null;
  if (displayPackets && displayPackets.length > 0) {
    const buckets: Record<string, { count: number; bytes: number }> = {};
    for (const p of displayPackets) {
      const timeStr = p.timestamp ? p.timestamp.substring(11, 19) : '00:00:00';
      if (!buckets[timeStr]) buckets[timeStr] = { count: 0, bytes: 0 };
      buckets[timeStr].count++;
      buckets[timeStr].bytes += p.length || 64;
    }
    displayTraffic = Object.entries(buckets).slice(-12).map(([timestamp, val]) => ({
      timestamp,
      packets: val.count,
      bytes: val.bytes,
    }));
  }

  // Build IPsec breakdown
  let ipsecBreakdown: Array<{ category: 'IKE' | 'ESP' | 'AH' | 'OTHER'; count: number }> | null = null;
  if (displayPackets && displayPackets.length > 0) {
    const counts = { IKE: 0, ESP: 0, AH: 0, OTHER: 0 };
    for (const p of displayPackets) {
      if (p.protocol === 'IKE') counts.IKE++;
      else if (p.protocol === 'ESP') counts.ESP++;
      else if (p.protocol === 'AH') counts.AH++;
      else counts.OTHER++;
    }
    ipsecBreakdown = [
      { category: 'IKE', count: counts.IKE },
      { category: 'ESP', count: counts.ESP },
      { category: 'AH', count: counts.AH },
      { category: 'OTHER', count: counts.OTHER },
    ];
  } else if (dashboardSummary?.protocol_posture?.protocol_counts) {
    const pc = dashboardSummary.protocol_posture.protocol_counts;
    ipsecBreakdown = [
      { category: 'IKE', count: pc.IKE || 0 },
      { category: 'ESP', count: pc.ESP || 0 },
      { category: 'AH', count: pc.AH || 0 },
      { category: 'OTHER', count: (pc.UDP || 0) + (pc.IP || 0) },
    ];
  }

  // Derive rates
  const elapsed = status?.elapsed_seconds || 1;
  const packetRate = captureState === 'CAPTURING' && elapsed > 0
    ? Math.round(((status?.packet_count || 0) / elapsed) * 10) / 10
    : displayPackets && displayPackets.length > 0
    ? Math.round((displayPackets.length / 10) * 10) / 10
    : null;

  const bandwidth = captureState === 'CAPTURING' && elapsed > 0
    ? Math.round((status?.file_size_bytes || 0) / elapsed)
    : displayPackets && displayPackets.length > 0
    ? Math.round(displayPackets.reduce((acc, p) => acc + p.length, 0) / 10)
    : null;

  const metrics: DashboardMetric[] = [
    {
      id: 'packets',
      label: 'Packets Captured',
      value: packetCount,
      status: captureState === 'CAPTURING' ? 'LIVE' : captureState === 'COMPLETED' ? 'READY' : 'INACTIVE',
      icon: Network,
      source: 'backend',
    },
    {
      id: 'duration',
      label: 'Elapsed Duration',
      value: Math.round(status?.elapsed_seconds ?? 0),
      statusLabel: `${status?.elapsed_seconds ?? 0}s`,
      status: captureState === 'CAPTURING' ? 'LIVE' : 'INACTIVE',
      icon: Activity,
      source: 'backend',
    },
    {
      id: 'size',
      label: 'PCAP Buffer Size',
      value: Math.round((status?.file_size_bytes ?? 0) / 1024),
      statusLabel: `${Math.round((status?.file_size_bytes ?? 0) / 1024)} KB`,
      status: (status?.file_size_bytes ?? 0) > 0 ? 'READY' : 'INACTIVE',
      icon: Cable,
      source: 'backend',
    },
    {
      id: 'source',
      label: 'Capture Target VM',
      value: status?.nic_number ?? 0,
      statusLabel: status?.source_vm ? `${status.source_vm} (NIC ${status.nic_number})` : 'None',
      status: status?.source_vm ? 'ONLINE' : 'INACTIVE',
      icon: KeyRound,
      source: 'backend',
    },
    {
      id: 'events',
      label: 'Security Events',
      value: dashboardMetrics ? (dashboardMetrics.vulnerabilities_total ?? 0) : 0,
      status: (dashboardMetrics?.vulnerabilities_total ?? 0) > 0 ? 'WARNING' : 'ONLINE',
      statusLabel: (dashboardMetrics?.vulnerabilities_total ?? 0) > 0 ? `${dashboardMetrics?.vulnerabilities_total} FINDINGS` : 'CLEAN',
      icon: ShieldAlert,
      source: 'backend',
      href: '/vulnerabilities',
    },
    {
      id: 'anomalies',
      label: 'Anomalies',
      value: dashboardMetrics ? (dashboardMetrics.ai_anomalies ?? 0) : 0,
      status: 'READY',
      statusLabel: (dashboardMetrics?.ai_anomalies ?? 0) > 0 ? 'ANOMALIES DETECTED' : 'MODEL READY',
      icon: BrainCircuit,
      source: 'backend',
      href: '/ai-anomalies',
    },
  ];

  return {
    captureState,
    interfaces: interfaces.length > 0 ? interfaces : null,
    rawInterfaces,
    status,
    metrics,
    packets: displayPackets,
    traffic: displayTraffic,
    packetRate,
    bandwidth,
    ipsecBreakdown,
    sessions: displaySessions,
    associations: displayAssociations,
    events: displayEvents,
    actionLoading,
    actionMessage,
    start: handleStart,
    stop: handleStop,
    refresh: loadData,
  };
}
