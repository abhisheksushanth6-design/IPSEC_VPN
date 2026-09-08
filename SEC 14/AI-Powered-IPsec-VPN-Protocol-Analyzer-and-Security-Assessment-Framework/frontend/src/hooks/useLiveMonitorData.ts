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
import type {
  CaptureState,
  DashboardMetric,
  NetworkInterface,
  Packet,
  MonitorSecurityAssociation,
  SecurityEvent,
  TrafficPoint,
  VPNSession,
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
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [st, ifaces] = await Promise.all([
        fetchLiveCaptureStatus().catch(() => null),
        fetchLiveCaptureInterfaces().catch(() => null),
      ]);
      if (st) setStatus(st);
      if (ifaces && ifaces.interfaces) {
        setRawInterfaces(ifaces.interfaces);
      }
    } catch {
      // Handled cleanly
    }
  }, []);

  useEffect(() => {
    loadData();
    // When capturing, poll frequently; otherwise poll gently
    const intervalMs = status?.state === 'CAPTURING' ? 1500 : 6000;
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
      value: null,
      status: 'NOT INITIALIZED',
      icon: ShieldAlert,
      source: 'unavailable',
    },
    {
      id: 'anomalies',
      label: 'Anomalies',
      value: null,
      status: 'NOT INITIALIZED',
      statusLabel: 'MODEL READY',
      icon: BrainCircuit,
      source: 'unavailable',
    },
  ];

  return {
    captureState,
    interfaces: interfaces.length > 0 ? interfaces : null,
    rawInterfaces,
    status,
    metrics,
    packets: null,
    traffic: null,
    packetRate: null,
    bandwidth: null,
    ipsecBreakdown: null,
    sessions: null,
    associations: null,
    events: null,
    actionLoading,
    actionMessage,
    start: handleStart,
    stop: handleStop,
    refresh: loadData,
  };
}
