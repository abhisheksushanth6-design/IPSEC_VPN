/**
 * API client service for Layer 10 — Risk Assessment & Decision Engine.
 */

import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type { RiskAssessmentResponse, RiskSummaryResponse } from '@/types/risk';

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

export const riskService = {
  /** Retrieve overall security risk posture summary */
  async getSummary(): Promise<RiskSummaryResponse> {
    return requestJson<RiskSummaryResponse>('/api/risk/summary');
  },

  /** List recent session risk assessments */
  async getAssessments(limit: number = 50): Promise<RiskAssessmentResponse[]> {
    return requestJson<RiskAssessmentResponse[]>(`/api/risk/assessments?limit=${limit}`);
  },

  /** Retrieve or evaluate risk assessment for a specific session */
  async getSessionRisk(sessionId: string): Promise<RiskAssessmentResponse> {
    return requestJson<RiskAssessmentResponse>(`/api/risk/sessions/${encodeURIComponent(sessionId)}`);
  },

  /** Force re-evaluate risk assessment for a specific session */
  async evaluateSession(sessionId: string): Promise<RiskAssessmentResponse> {
    return mutate<RiskAssessmentResponse>(`/api/risk/evaluate/${encodeURIComponent(sessionId)}`, {
      method: 'POST',
    });
  },

  /** Batch evaluate all sessions present in telemetry */
  async evaluateAll(): Promise<RiskAssessmentResponse[]> {
    return mutate<RiskAssessmentResponse[]>('/api/risk/evaluate-all', {
      method: 'POST',
    });
  },

  /** Get operational status of Layer 10 */
  async getStatus(): Promise<any> {
    return requestJson<any>('/api/risk/status');
  },
};
