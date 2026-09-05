import { requestJson } from './httpClient';
import { PacketServiceError } from './packetService';
import { appConfig } from '@/utils/config';
import type {
  BaselineBuildRequest,
  BaselineComparison,
  BaselineEngineStatus,
  BaselineFeatureProfile,
  BaselineProfile,
  BaselineSessionItem,
  BaselineSummary,
  FingerprintComparison,
  PacketApiError,
  SessionFingerprint,
} from '@/types';

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`${appConfig.apiBaseUrl}${path}`, {
    ...init,
    headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
  });
  if (!response.ok) {
    let body: Partial<PacketApiError> = {};
    try {
      body = (await response.json()) as PacketApiError;
    } catch {
      /* non-JSON response */
    }
    throw new PacketServiceError(
      body.error ?? 'REQUEST_FAILED',
      body.message ?? `Request failed with status ${response.status}.`,
      response.status,
    );
  }
  return (await response.json()) as T;
}

/** Layer 06 Session Fingerprinting and Baseline Profiling service. */
export const baselineService = {
  fetchStatus: (signal?: AbortSignal) =>
    requestJson<BaselineEngineStatus>('/api/baselines/status', signal),

  listBaselines: (signal?: AbortSignal) =>
    requestJson<BaselineSummary[]>('/api/baselines', signal),

  getBaseline: (id: string, signal?: AbortSignal) =>
    requestJson<BaselineProfile>(`/api/baselines/${encodeURIComponent(id)}`, signal),

  buildBaseline: (payload: BaselineBuildRequest) =>
    mutate<BaselineProfile>('/api/baselines', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  activateBaseline: (id: string) =>
    mutate<BaselineSummary>(`/api/baselines/${encodeURIComponent(id)}/activate`, {
      method: 'POST',
    }),

  fetchBaselineFeatures: (id: string, signal?: AbortSignal) =>
    requestJson<BaselineFeatureProfile[]>(`/api/baselines/${encodeURIComponent(id)}/features`, signal),

  fetchBaselineSessions: (id: string, signal?: AbortSignal) =>
    requestJson<BaselineSessionItem[]>(`/api/baselines/${encodeURIComponent(id)}/sessions`, signal),

  compareWithFingerprint: (baselineId: string, fingerprintId: string, signal?: AbortSignal) =>
    requestJson<BaselineComparison>(
      `/api/baselines/${encodeURIComponent(baselineId)}/compare/${encodeURIComponent(fingerprintId)}`,
      signal,
    ),

  listFingerprints: (signal?: AbortSignal) =>
    requestJson<SessionFingerprint[]>('/api/fingerprints', signal),

  getFingerprint: (id: string, signal?: AbortSignal) =>
    requestJson<SessionFingerprint>(`/api/fingerprints/${encodeURIComponent(id)}`, signal),

  getSessionFingerprint: (sessionId: string, signal?: AbortSignal) =>
    requestJson<SessionFingerprint>(
      `/api/sessions/${encodeURIComponent(sessionId)}/fingerprint`,
      signal,
    ),

  compareFingerprints: (idA: string, idB: string, signal?: AbortSignal) =>
    requestJson<FingerprintComparison>(
      `/api/fingerprints/${encodeURIComponent(idA)}/compare/${encodeURIComponent(idB)}`,
      signal,
    ),
};
