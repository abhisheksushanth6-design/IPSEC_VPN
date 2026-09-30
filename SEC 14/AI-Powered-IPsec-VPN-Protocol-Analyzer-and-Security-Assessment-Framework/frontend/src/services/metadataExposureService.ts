/**
 * API client service for Layer 09 — Metadata Exposure & Side-Channel Assessment.
 */

import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type {
  MetadataExposureItem,
  MetadataExposureSummary,
} from '@/types';

export const metadataExposureService = {
  /** Get exposure assessments for a capture ID */
  getCaptureAssessments: (captureId: string, signal?: AbortSignal) =>
    requestJson<MetadataExposureItem[]>(`/api/metadata-exposure/capture/${encodeURIComponent(captureId)}`, signal),

  /** Get exposure assessment summary for a capture ID */
  getSummary: (captureId: string, signal?: AbortSignal) =>
    requestJson<MetadataExposureSummary>(`/api/metadata-exposure/summary/${encodeURIComponent(captureId)}`, signal),

  /** Get global/current capture exposure summary */
  getGlobalSummary: (signal?: AbortSignal) =>
    requestJson<MetadataExposureSummary>('/api/metadata-exposure/summary', signal),

  /** Get exposure assessment for a specific session */
  getSessionAssessment: (sessionId: string, signal?: AbortSignal) =>
    requestJson<MetadataExposureItem>(`/api/metadata-exposure/session/${encodeURIComponent(sessionId)}`, signal),

  /** Trigger metadata exposure assessment across a capture */
  evaluateCapture: async (captureId: string): Promise<MetadataExposureItem[]> => {
    const res = await fetch(`${appConfig.apiBaseUrl}/api/metadata-exposure/assess/${encodeURIComponent(captureId)}`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      let detail = res.statusText || `HTTP ${res.status}`;
      try {
        const body = await res.json();
        detail = body.detail || body.message || body.error || detail;
      } catch {
        // Fall back to status text
      }
      throw new Error(`Failed to evaluate metadata exposure: ${detail}`);
    }
    return res.json();
  },
};
