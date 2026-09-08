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
  RiskClassification,
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
  const { reachable, status } = useSystemState();
  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchSummary = useCallback(async () => {
    try {
      setLoading(true);
      const res = await dashboardService.getSummary();
      setSummary(res);
    } catch {
      if (!reachable) {
        setSummary(null);
      }
    } finally {
      setLoading(false);
    }
  }, [reachable]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  return useMemo<UseDashboardResult>(() => {
    const isLayerActive = (num: number) => {
      const l = status?.architecture_layers?.find((layer) => layer.number === num);
      return l ? l.status !== 'NOT INITIALIZED' : false;
    };

    const isLayer10Ready = isLayerActive(10);
    const isLayer04Ready = isLayerActive(4);
    const isLayer03Ready = isLayerActive(3);
    const isLayer07Ready = isLayerActive(7);
    const isLayer08Ready = isLayerActive(8);
    const isLayer09Ready = isLayerActive(9);

    const hasRiskScore =
      summary?.metrics?.overall_risk_score !== null &&
      summary?.metrics?.overall_risk_score !== undefined;

    const metrics: DashboardMetric[] = [
      {
        id: 'risk',
        label: 'Overall Risk Score',
        value: hasRiskScore ? summary!.metrics.overall_risk_score : null,
        status: hasRiskScore
          ? ((summary?.metrics?.overall_risk_status as any) || 'ONLINE')
          : isLayer10Ready
            ? 'READY'
            : 'NOT INITIALIZED',
        statusLabel: hasRiskScore
          ? `${summary!.metrics.overall_risk_score}/100`
          : isLayer10Ready
            ? 'AWAITING EVALUATION'
            : 'NOT INITIALIZED',
        icon: Gauge,
        source: hasRiskScore || isLayer10Ready ? 'backend' : 'unavailable',
        href: '/risk-assessment',
      },
      {
        id: 'sessions',
        label: 'Active VPN Sessions',
        value: summary ? summary.metrics.active_vpn_sessions : null,
        status: summary
          ? (summary.metrics.active_vpn_sessions > 0 ? 'ONLINE' : 'ONLINE')
          : isLayer04Ready
            ? 'ONLINE'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.active_vpn_sessions} SESSIONS`
          : isLayer04Ready
            ? '0 SESSIONS'
            : 'SESSION ENGINE NOT INITIALIZED',
        icon: Cable,
        source: summary || isLayer04Ready ? 'backend' : 'unavailable',
        href: '/ipsec-sessions',
      },
      {
        id: 'sas',
        label: 'Active Security Associations',
        value: summary ? summary.metrics.active_sas : null,
        status: summary
          ? (summary.metrics.active_sas > 0 ? 'ONLINE' : 'ONLINE')
          : isLayer04Ready
            ? 'ONLINE'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.active_sas} ACTIVE SAs`
          : isLayer04Ready
            ? '0 ACTIVE SAs'
            : 'SA ENGINE NOT INITIALIZED',
        icon: KeyRound,
        source: summary || isLayer04Ready ? 'backend' : 'unavailable',
        href: '/sa-lifecycle',
      },
      {
        id: 'packets',
        label: 'Packets Analyzed',
        value: summary ? summary.metrics.packets_analyzed : null,
        status: summary
          ? (summary.metrics.packets_analyzed > 0 ? 'ONLINE' : 'ONLINE')
          : isLayer03Ready
            ? 'ONLINE'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.packets_analyzed} TOTAL`
          : isLayer03Ready
            ? '0 TOTAL'
            : 'ANALYSIS NOT INITIALIZED',
        icon: Network,
        source: summary || isLayer03Ready ? 'backend' : 'unavailable',
        href: '/packet-analysis',
      },
      {
        id: 'anomalies',
        label: 'AI Anomalies',
        value: summary ? summary.metrics.ai_anomalies : null,
        status: summary
          ? (summary.metrics.ai_anomalies > 0 ? 'WARNING' : 'ONLINE')
          : isLayer08Ready
            ? 'ONLINE'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? (summary.metrics.ai_anomalies > 0
              ? `${summary.metrics.ai_anomalies} FLAGGED`
              : (summary.ml_engine_status?.active_model_id ? 'INFERENCE READY' : 'ONLINE'))
          : isLayer08Ready
            ? 'INFERENCE READY'
            : 'MODEL NOT INITIALIZED',
        icon: BrainCircuit,
        source: summary || isLayer08Ready ? 'backend' : 'unavailable',
        href: '/ai-anomalies',
      },
      {
        id: 'drift',
        label: 'Security Drift Events',
        value: summary ? summary.metrics.drift_events : null,
        status: summary
          ? (summary.metrics.drift_events > 0 ? 'WARNING' : 'ONLINE')
          : isLayer07Ready
            ? 'ONLINE'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.drift_events} DRIFTING`
          : isLayer07Ready
            ? '0 DRIFTING'
            : 'ENGINE NOT INITIALIZED',
        icon: GitCompare,
        source: summary || isLayer07Ready ? 'backend' : 'unavailable',
        href: '/security-drift',
      },
      {
        id: 'vulnerabilities',
        label: 'Critical Vulnerabilities',
        value: summary ? summary.metrics.vulnerabilities_critical : null,
        status: summary
          ? (summary.metrics.vulnerabilities_critical > 0 ? 'CRITICAL' : 'ONLINE')
          : isLayer09Ready
            ? 'ONLINE'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? `${summary.metrics.vulnerabilities_critical} CRITICAL`
          : isLayer09Ready
            ? '0 CRITICAL'
            : 'ENGINE NOT INITIALIZED',
        icon: ShieldAlert,
        source: summary || isLayer09Ready ? 'backend' : 'unavailable',
        href: '/vulnerabilities',
      },
      {
        id: 'capture',
        label: 'Capture Status',
        value: null,
        status: summary
          ? (summary.metrics.capture_status === 'READY' ? 'READY' : 'INACTIVE')
          : isLayer03Ready
            ? 'READY'
            : 'NOT INITIALIZED',
        statusLabel: summary
          ? (summary.metrics.capture_status === 'READY' ? 'PCAP UPLOAD READY' : summary.metrics.capture_status)
          : isLayer03Ready
            ? 'PCAP UPLOAD READY'
            : undefined,
        icon: Activity,
        source: summary || isLayer03Ready ? 'backend' : 'unavailable',
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
      risk: {
        score: summary?.metrics?.overall_risk_score ?? null,
        classification: (summary?.metrics?.overall_risk_status as RiskClassification) ?? null,
        lastUpdated: summary?.metrics?.overall_risk_score !== null && summary?.metrics?.overall_risk_score !== undefined
          ? (summary?.posture?.last_refresh ?? null)
          : null,
      },
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
  }, [summary, loading, fetchSummary, status]);
}
