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

  /**
   * Programmatically fetch and download report PDF using binary blob handling.
   * Traps backend errors gracefully and triggers a reliable client-side file save.
   */
  downloadReportPdf: async (reportId: string, filename?: string): Promise<void> => {
    const downloadUrl = reportService.getDownloadUrl(reportId);
    const response = await fetch(downloadUrl, {
      method: 'GET',
      headers: {
        Accept: 'application/pdf, application/json, */*',
      },
    });

    if (!response.ok) {
      let errorMessage = `Download failed with HTTP status ${response.status}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorMessage =
            typeof errorJson.detail === 'object'
              ? JSON.stringify(errorJson.detail)
              : String(errorJson.detail);
        } else if (errorJson.error) {
          errorMessage = String(errorJson.error);
        }
      } catch {
        // Non-JSON response
      }
      throw new Error(errorMessage);
    }

    const blob = await response.blob();

    // Derive download filename: argument > Content-Disposition header > sensible default
    let targetFilename = filename?.trim();
    if (!targetFilename) {
      const disposition =
        response.headers.get('Content-Disposition') ||
        response.headers.get('content-disposition');
      if (disposition) {
        const filenameMatch = disposition.match(
          /filename\*?=(?:UTF-8'')?["']?([^"';]+)["']?/i,
        );
        if (filenameMatch && filenameMatch[1]) {
          targetFilename = decodeURIComponent(filenameMatch[1].trim());
        }
      }
    }
    if (!targetFilename) {
      targetFilename = `ipsec-assessment-${reportId.toLowerCase()}.pdf`;
    }
    if (!targetFilename.toLowerCase().endsWith('.pdf')) {
      targetFilename += '.pdf';
    }

    const objectUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = targetFilename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();

    // Revoke object URL after browser starts saving
    setTimeout(() => {
      window.URL.revokeObjectURL(objectUrl);
    }, 1500);
  },

  /** Delete a report record and remove its PDF file */
  delete: (reportId: string): Promise<{ deleted: boolean; id: string }> =>
    mutate<{ deleted: boolean; id: string }>(`/api/reports/${encodeURIComponent(reportId)}`, {
      method: 'DELETE',
    }),
};
