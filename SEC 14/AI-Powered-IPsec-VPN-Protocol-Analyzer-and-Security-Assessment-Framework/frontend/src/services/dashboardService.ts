/**
 * API client service for Layer 13 — Web Dashboard.
 *
 * Interacts with /api/dashboard/* endpoints to fetch aggregated SOC metrics,
 * operational posture, chronological timeline events, protocol posture,
 * and correlated session activities across layers 01-09.
 */

import { requestJson } from './httpClient';
import type {
  DashboardMetricsPayload,
  DashboardSummaryResponse,
  ProtocolPosture,
  SecurityTimelineEvent,
  SessionActivityItem,
} from '@/types';

export const dashboardService = {
  /** Get full aggregated dashboard summary */
  getSummary: async (signal?: AbortSignal): Promise<DashboardSummaryResponse> => {
    const res = await requestJson<DashboardSummaryResponse>('/api/dashboard/summary', signal);
    if (res?.posture) {
      const p = res.posture as any;
      p.backendStatus = p.backendStatus ?? p.backend_status;
      p.databaseStatus = p.databaseStatus ?? p.database_status;
      p.applicationMode = p.applicationMode ?? p.application_mode;
      p.total_layers = p.total_layers ?? p.layers_total;
      p.totalLayers = p.totalLayers ?? p.layers_total;
      p.initialized_layers = p.initialized_layers ?? p.layers_initialized;
      p.initializedLayers = p.initializedLayers ?? p.layers_initialized;
    }
    return res;
  },

  /** Get core security and operational metrics */
  getMetrics: (signal?: AbortSignal): Promise<DashboardMetricsPayload> =>
    requestJson<DashboardMetricsPayload>('/api/dashboard/metrics', signal),

  /** Get chronological security events across layers */
  getTimeline: (limit = 50, signal?: AbortSignal): Promise<SecurityTimelineEvent[]> =>
    requestJson<SecurityTimelineEvent[]>(`/api/dashboard/timeline?limit=${limit}`, signal),

  /** Get observed cryptographic transforms and protocol posture */
  getProtocols: (signal?: AbortSignal): Promise<ProtocolPosture> =>
    requestJson<ProtocolPosture>('/api/dashboard/protocols', signal),

  /** Get recent sessions with correlated analytical flags */
  getSessions: (limit = 10, signal?: AbortSignal): Promise<SessionActivityItem[]> =>
    requestJson<SessionActivityItem[]>(`/api/dashboard/sessions?limit=${limit}`, signal),
};
