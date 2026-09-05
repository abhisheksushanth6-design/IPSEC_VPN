/**
 * API client service for Layer 14 — Report Generation (PDF).
 *
 * Interacts with /api/reports/* endpoints to generate, list, inspect,
 * download, and delete structured cybersecurity assessment PDF reports.
 */

import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type { ReportGenerateRequest, ReportMetadata } from '@/types';

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`${appConfig.apiBaseUrl}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init.headers || {}),
    },
  });

  if (!response.ok) {
    let body: any = {};
    try {
      body = await response.json();
    } catch {
      // non-JSON response
    }
    const message = body.detail
      ? typeof body.detail === 'object'
        ? JSON.stringify(body.detail)
        : body.detail
      : body.message ?? response.statusText;
    throw new Error(message || `Request failed with status ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export const reportService = {
  /** List all generated security assessment reports */
  list: (signal?: AbortSignal): Promise<ReportMetadata[]> =>
    requestJson<ReportMetadata[]>('/api/reports', signal),

  /** Get metadata for a specific generated report */
  get: (reportId: string, signal?: AbortSignal): Promise<ReportMetadata> =>
    requestJson<ReportMetadata>(`/api/reports/${encodeURIComponent(reportId)}`, signal),

  /** Generate a new security assessment PDF report */
  generate: (payload: ReportGenerateRequest): Promise<ReportMetadata> =>
    mutate<ReportMetadata>('/api/reports/generate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** Get direct download URL for a report PDF */
  getDownloadUrl: (reportId: string): string =>
    `${appConfig.apiBaseUrl}/api/reports/${encodeURIComponent(reportId)}/download`,

  /** Delete a report record and remove its PDF file */
  delete: (reportId: string): Promise<{ deleted: boolean; id: string }> =>
    mutate<{ deleted: boolean; id: string }>(`/api/reports/${encodeURIComponent(reportId)}`, {
      method: 'DELETE',
    }),
};
