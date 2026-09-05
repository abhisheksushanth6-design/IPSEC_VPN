import { useMemo } from 'react';
import {
  Activity,
  BrainCircuit,
  Cable,
  Gauge,
  GitCompare,
  KeyRound,
  Network,
  ShieldAlert,
} from 'lucide-react';

import { useSystemState } from '@/context/SystemStateContext';
import type { DashboardData, DashboardMetric } from '@/types';

/**
 * Assembles the overview data model.
 *
 * Only `/api/health` and `/api/system/status` exist. Every security metric is
 * therefore reported as unavailable — `null` — so the UI shows that the
 * producing engine is not initialised rather than a value it never measured.
 */
export function useDashboardData(): DashboardData {
  const { reachable } = useSystemState();

  return useMemo<DashboardData>(() => {
    const metrics: DashboardMetric[] = [
      {
        id: 'risk',
        label: 'Overall Risk Score',
        value: null,
        status: 'NOT INITIALIZED',
        icon: Gauge,
        source: 'unavailable',
        href: '/risk-assessment',
      },
      {
        id: 'sessions',
        label: 'Active VPN Sessions',
        value: 0,
        status: 'NOT INITIALIZED',
        statusLabel: 'SESSION ENGINE NOT INITIALIZED',
        icon: Cable,
        source: 'unavailable',
        href: '/ipsec-sessions',
      },
      {
        id: 'sas',
        label: 'Active Security Associations',
        value: 0,
        status: 'NOT INITIALIZED',
        statusLabel: 'SA ENGINE NOT INITIALIZED',
        icon: KeyRound,
        source: 'unavailable',
        href: '/sa-lifecycle',
      },
      {
        id: 'packets',
        label: 'Packets Analyzed',
        value: 0,
        status: 'NOT INITIALIZED',
        statusLabel: 'ANALYSIS NOT INITIALIZED',
        icon: Network,
        source: 'unavailable',
        href: '/packet-analysis',
      },
      {
        id: 'anomalies',
        label: 'AI Anomalies',
        value: 0,
        status: 'NOT INITIALIZED',
        statusLabel: 'MODEL NOT INITIALIZED',
        icon: BrainCircuit,
        source: 'unavailable',
        href: '/ai-anomalies',
      },
      {
        id: 'drift',
        label: 'Security Drift Events',
        value: 0,
        status: 'NOT INITIALIZED',
        icon: GitCompare,
        source: 'unavailable',
        href: '/security-drift',
      },
      {
        id: 'vulnerabilities',
        label: 'Critical Vulnerabilities',
        value: 0,
        status: 'NOT INITIALIZED',
        statusLabel: 'ENGINE NOT INITIALIZED',
        icon: ShieldAlert,
        source: 'unavailable',
        href: '/vulnerabilities',
      },
      {
        id: 'capture',
        label: 'Capture Status',
        value: null,
        status: 'NOT INITIALIZED',
        icon: Activity,
        source: 'unavailable',
        href: '/live-monitor',
      },
    ];

    return {
      risk: { score: null, classification: null, lastUpdated: null },
      metrics,
      traffic: null,
      riskHistory: null,
      protocols: null,
      anomalies: null,
      vulnerabilities: null,
      saActivity: null,
      events: null,
    };
    // `reachable` is included so the model re-evaluates when the backend
    // returns; nothing in it depends on the backend yet.
  }, [reachable]);
}
