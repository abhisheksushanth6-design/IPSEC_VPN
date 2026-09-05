import { useCallback, useEffect, useMemo, useState } from 'react';
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
import { dashboardService } from '@/services/dashboardService';
import type {
  DashboardData,
  DashboardMetric,
  DashboardSummaryResponse,
  EventSeverity,
  ProtocolDistribution,
  ProtocolName,
  SAActivity,
  SAChartState,
  SecurityEvent,
  SecurityEventType,
  SeverityLevel,
  VulnerabilitySeverity,
} from '@/types';

export interface UseDashboardResult extends DashboardData {
  summary: DashboardSummaryResponse | null;
  loading: boolean;
  refetch: () => Promise<void>;
}

/**
 * Assembles the operational overview data model by querying Layer 13 Web Dashboard API.
 * Aggregates real metrics, posture, timeline events, and protocol transforms.
 * Layer 10 Risk Assessment remains strictly NOT INITIALIZED.
 */
export function useDashboardData(): UseDashboardResult {
  const { reachable } = useSystemState();
  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchSummary = useCallback(async () => {
    if (!reachable) {
      setSummary(null);
      return;
    }
    try {
      setLoading(true);
      const res = await dashboardService.getSummary();
      setSummary(res);
    } catch {
      // Keep null on failure; UI handles empty/offline states cleanly
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }, [reachable]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  return useMemo<UseDashboardResult>(() => {
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
        value: summary ? summary.metrics.active_vpn_sessions : 0,
        status: summary ? (summary.metrics.active_vpn_sessions > 0 ? 'ONLINE' : 'ONLINE') : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.active_vpn_sessions} SESSIONS`
          : 'SESSION ENGINE NOT INITIALIZED',
        icon: Cable,
        source: summary ? 'backend' : 'unavailable',
        href: '/ipsec-sessions',
      },
      {
        id: 'sas',
        label: 'Active Security Associations',
        value: summary ? summary.metrics.active_sas : 0,
        status: summary ? (summary.metrics.active_sas > 0 ? 'ONLINE' : 'ONLINE') : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.active_sas} ACTIVE SAs`
          : 'SA ENGINE NOT INITIALIZED',
        icon: KeyRound,
        source: summary ? 'backend' : 'unavailable',
        href: '/sa-lifecycle',
      },
      {
        id: 'packets',
        label: 'Packets Analyzed',
        value: summary ? summary.metrics.packets_analyzed : 0,
        status: summary ? (summary.metrics.packets_analyzed > 0 ? 'ONLINE' : 'ONLINE') : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.packets_analyzed} TOTAL`
          : 'ANALYSIS NOT INITIALIZED',
        icon: Network,
        source: summary ? 'backend' : 'unavailable',
        href: '/packet-analysis',
      },
      {
        id: 'anomalies',
        label: 'AI Anomalies',
        value: summary ? summary.metrics.ai_anomalies : 0,
        status: summary ? (summary.metrics.ai_anomalies > 0 ? 'WARNING' : 'ONLINE') : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.ai_anomalies} FLAGGED`
          : 'MODEL NOT INITIALIZED',
        icon: BrainCircuit,
        source: summary ? 'backend' : 'unavailable',
        href: '/ai-anomalies',
      },
      {
        id: 'drift',
        label: 'Security Drift Events',
        value: summary ? summary.metrics.drift_events : 0,
        status: summary ? (summary.metrics.drift_events > 0 ? 'WARNING' : 'ONLINE') : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.drift_events} DRIFTING`
          : 'ENGINE NOT INITIALIZED',
        icon: GitCompare,
        source: summary ? 'backend' : 'unavailable',
        href: '/security-drift',
      },
      {
        id: 'vulnerabilities',
        label: 'Critical Vulnerabilities',
        value: summary ? summary.metrics.vulnerabilities_critical : 0,
        status: summary ? (summary.metrics.vulnerabilities_critical > 0 ? 'CRITICAL' : 'ONLINE') : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.vulnerabilities_critical} CRITICAL`
          : 'ENGINE NOT INITIALIZED',
        icon: ShieldAlert,
        source: summary ? 'backend' : 'unavailable',
        href: '/vulnerabilities',
      },
      {
        id: 'capture',
        label: 'Capture Status',
        value: null,
        status: summary ? (summary.metrics.capture_status === 'READY' ? 'ONLINE' : 'INACTIVE') : 'NOT INITIALIZED',
        statusLabel: summary ? summary.metrics.capture_status : undefined,
        icon: Activity,
        source: summary ? 'backend' : 'unavailable',
        href: '/live-monitor',
      },
    ];

    // Protocols
    let protocols: ProtocolDistribution[] | null = null;
    if (summary && summary.protocol_posture.protocol_counts) {
      const counts = summary.protocol_posture.protocol_counts;
      const entries = Object.entries(counts)
        .filter(([_, c]) => c > 0)
        .map(([proto, count]) => ({ protocol: proto as ProtocolName, count }));
      if (entries.length > 0) {
        protocols = entries;
      }
    }

    // Vulnerabilities
    let vulnerabilities: VulnerabilitySeverity[] | null = null;
    if (summary && summary.vulnerability_breakdown) {
      const breakdown = summary.vulnerability_breakdown;
      const entries = Object.entries(breakdown)
        .filter(([_, c]) => c > 0)
        .map(([sev, count]) => ({ severity: sev as SeverityLevel, count }));
      if (entries.length > 0) {
        vulnerabilities = entries;
      }
    }

    // SA Activity
    let saActivity: SAActivity[] | null = null;
    if (summary && summary.sa_state_breakdown) {
      const breakdown = summary.sa_state_breakdown;
      const entries = Object.entries(breakdown)
        .filter(([_, c]) => c > 0)
        .map(([st, count]) => ({ state: st as SAChartState, count }));
      if (entries.length > 0) {
        saActivity = entries;
      }
    }

    // Events
    let events: SecurityEvent[] | null = null;
    if (summary && summary.recent_events.length > 0) {
      events = summary.recent_events.map((e) => ({
        id: e.id,
        timestamp: e.timestamp,
        type: (e.event_type as SecurityEventType) || 'Packet Captured',
        severity: (e.severity as EventSeverity) || 'INFO',
        source: e.layer,
        description: e.title + (e.description ? `: ${e.description}` : ''),
      }));
    }

    return {
      risk: { score: null, classification: null, lastUpdated: null },
      metrics,
      traffic: null,
      riskHistory: null,
      protocols,
      anomalies: null,
      vulnerabilities,
      saActivity,
      events,
      summary,
      loading,
      refetch: fetchSummary,
    };
  }, [summary, loading, fetchSummary]);
}
