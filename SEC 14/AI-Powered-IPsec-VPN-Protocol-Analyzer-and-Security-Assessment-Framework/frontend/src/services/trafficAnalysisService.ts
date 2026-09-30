/**
 * API client service for Layer 08 — AI Traffic Classification inside ESP.
 */

import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type {
  TrafficClassificationItem,
  TrafficClassificationSummary,
} from '@/types';

export const trafficAnalysisService = {
  /** Get classifications for a capture ID */
  getCaptureClassifications: (captureId: string, signal?: AbortSignal) =>
    requestJson<TrafficClassificationItem[]>(`/api/traffic-analysis/capture/${encodeURIComponent(captureId)}`, signal),

  /** Get classification summary for a capture ID */
  getSummary: (captureId: string, signal?: AbortSignal) =>
    requestJson<TrafficClassificationSummary>(`/api/traffic-analysis/summary/${encodeURIComponent(captureId)}`, signal),

  /** Get global/current distribution summary */
  getDistribution: (signal?: AbortSignal) =>
    requestJson<TrafficClassificationSummary>('/api/traffic-analysis/distribution', signal),

  /** Get single session classification */
  getSessionClassification: (sessionId: string, signal?: AbortSignal) =>
    requestJson<TrafficClassificationItem>(`/api/traffic-analysis/session/${encodeURIComponent(sessionId)}`, signal),

  /** Trigger AI classification across all sessions in a capture */
  classifyCapture: async (captureId: string): Promise<TrafficClassificationItem[]> => {
    const res = await fetch(`${appConfig.apiBaseUrl}/api/traffic-analysis/classify/${encodeURIComponent(captureId)}`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to trigger classification: ${res.statusText}`);
    }
    return res.json();
  },
};
