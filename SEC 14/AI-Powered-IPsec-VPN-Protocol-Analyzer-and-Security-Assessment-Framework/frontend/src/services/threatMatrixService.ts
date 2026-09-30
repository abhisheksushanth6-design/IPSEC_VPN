/**
 * API client service for Layer 09/10 — Standalone IPsec Threat Matrix.
 */

import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type {
  ThreatMatrixItem,
  ThreatMatrixSummary,
} from '@/types';

export const threatMatrixService = {
  /** Get all threat matrix records for a capture ID */
  getCaptureThreats: (captureId: string, signal?: AbortSignal) =>
    requestJson<ThreatMatrixItem[]>(`/api/threat-matrix/capture/${encodeURIComponent(captureId)}`, signal),

  /** Get 10 cataloged threat matrix definitions / current state */
  getThreats: (signal?: AbortSignal) =>
    requestJson<ThreatMatrixItem[]>('/api/threat-matrix/threats', signal),

  /** Get threat matrix summary for a capture ID */
  getSummary: (captureId: string, signal?: AbortSignal) =>
    requestJson<ThreatMatrixSummary>(`/api/threat-matrix/summary/${encodeURIComponent(captureId)}`, signal),

  /** Get global/current capture threat summary */
  getGlobalSummary: (signal?: AbortSignal) =>
    requestJson<ThreatMatrixSummary>('/api/threat-matrix/summary', signal),

  /** Get threat evaluation for a specific session */
  getSessionThreats: (sessionId: string, signal?: AbortSignal) =>
    requestJson<ThreatMatrixItem[]>(`/api/threat-matrix/session/${encodeURIComponent(sessionId)}`, signal),

  /** Trigger threat matrix evaluation across a capture */
  evaluateCapture: async (captureId: string): Promise<ThreatMatrixItem[]> => {
    const res = await fetch(`${appConfig.apiBaseUrl}/api/threat-matrix/evaluate/${encodeURIComponent(captureId)}`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to evaluate threat matrix: ${res.statusText}`);
    }
    return res.json();
  },
};
