import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Cable,
  Gauge,
  KeyRound,
  Network,
} from 'lucide-react';

import { useSystemState } from '@/context/SystemStateContext';
import { dashboardService } from '@/services/dashboardService';
import { trafficAnalysisService } from '@/services/trafficAnalysisService';
import { metadataExposureService } from '@/services/metadataExposureService';
import { baselineService } from '@/services/baselineService';
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
  TrafficClassificationSummary,
  MetadataExposureSummary,
  VulnerabilitySeverity,
} from '@/types';

export interface UseDashboardResult extends DashboardData {
  summary: DashboardSummaryResponse | null;
  trafficSummary: TrafficClassificationSummary | null;
  metadataSummary: MetadataExposureSummary | null;
  fingerprintCount: number;
  trafficClassification: { type: string; count: number }[] | null;
  loading: boolean;
  refetch: () => Promise<void>;
}

/**
 * Assembles the operational overview data model by querying Layer 10 Dashboard API,
 * Layer 07 AI Traffic Classification, Layer 08 Metadata Exposure & Security Assessment, and Layer 06 Fingerprints.
 */
export function useDashboardData(): UseDashboardResult {
  const { reachable, status } = useSystemState();
  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [trafficSummary, setTrafficSummary] = useState<TrafficClassificationSummary | null>(null);
  const [metadataSummary, setMetadataSummary] = useState<MetadataExposureSummary | null>(null);
  const [fingerprintCount, setFingerprintCount] = useState<number>(0);
  const [loading, setLoading] = useState(false);

  const fetchSummary = useCallback(async () => {
    try {
      setLoading(true);
      const [sumRes, trafRes, metaRes, fpsRes] = await Promise.allSettled([
        dashboardService.getSummary(),
        trafficAnalysisService.getDistribution(),
        metadataExposureService.getGlobalSummary(),
        baselineService.listFingerprints(),
      ]);

      if (sumRes.status === 'fulfilled') {
        setSummary(sumRes.value);
      } else if (!reachable) {
        setSummary(null);
      }

      if (trafRes.status === 'fulfilled' && trafRes.value) {
        setTrafficSummary(trafRes.value);
      }

      if (metaRes.status === 'fulfilled' && metaRes.value) {
        setMetadataSummary(metaRes.value);
      }

      if (fpsRes.status === 'fulfilled' && Array.isArray(fpsRes.value)) {
        setFingerprintCount(fpsRes.value.length);
      }
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

    // AI Traffic Classification Breakdown
    let trafficClassification: { type: string; count: number }[] | null = null;
    if (trafficSummary && trafficSummary.distribution && Object.keys(trafficSummary.distribution).length > 0) {
      trafficClassification = Object.entries(trafficSummary.distribution).map(([type, count]) => ({
        type,
        count,
      }));
    } else if (trafficSummary && trafficSummary.total_classified > 0) {
      trafficClassification = [
        { type: 'VOIP', count: trafficSummary.voip_count || 0 },
        { type: 'WHATSAPP', count: trafficSummary.whatsapp_count || 0 },
        { type: 'EMAIL', count: trafficSummary.email_count || 0 },
        { type: 'VIDEO', count: trafficSummary.video_streaming_count || 0 },
        { type: 'WEB', count: trafficSummary.web_browsing_count || 0 },
        { type: 'ICMP', count: trafficSummary.icmp_count || 0 },
        { type: 'OTHER', count: trafficSummary.other_count || trafficSummary.generic_count || 0 },
      ].filter((x) => x.count > 0);
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
      trafficSummary,
      metadataSummary,
      fingerprintCount,
      trafficClassification,
      loading,
      refetch: fetchSummary,
    };
  }, [summary, trafficSummary, metadataSummary, fingerprintCount, loading, fetchSummary, status]);
}
