import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type {
  DriftAnalysis,
  DriftAnalysisSummary,
  DriftAnalyzeRequest,
  DriftEngineStatus,
  DriftThresholdConfig,
  FeatureDrift,
} from '@/types';

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`${appConfig.apiBaseUrl}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
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

export const driftService = {
  getStatus: (signal?: AbortSignal) =>
    requestJson<DriftEngineStatus>('/api/drift/status', signal),

  getConfig: (signal?: AbortSignal) =>
    requestJson<DriftThresholdConfig>('/api/drift/config', signal),

  analyze: (payload: DriftAnalyzeRequest) =>
    mutate<DriftAnalysis>('/api/drift/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listAnalyses: (
    params?: {
      sessionId?: string;
      baselineId?: string;
      status?: string;
      severity?: string;
      limit?: number;
      offset?: number;
    },
    signal?: AbortSignal
  ) => {
    const query = new URLSearchParams();
    if (params?.sessionId) query.set('session_id', params.sessionId);
    if (params?.baselineId) query.set('baseline_id', params.baselineId);
    if (params?.status) query.set('status', params.status);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));

    const qs = query.toString();
    return requestJson<DriftAnalysisSummary[]>(`/api/drift${qs ? `?${qs}` : ''}`, signal);
  },

  getAnalysis: (analysisId: string, signal?: AbortSignal) =>
    requestJson<DriftAnalysis>(`/api/drift/${encodeURIComponent(analysisId)}`, signal),

  getFeatures: (analysisId: string, signal?: AbortSignal) =>
    requestJson<FeatureDrift[]>(`/api/drift/${encodeURIComponent(analysisId)}/features`, signal),

  getSessionLatest: (sessionId: string, signal?: AbortSignal) =>
    requestJson<DriftAnalysis>(`/api/drift/session/${encodeURIComponent(sessionId)}`, signal),

  clear: () =>
    mutate<{ status: string }>('/api/drift', {
      method: 'DELETE',
    }),
};
