/**
 * Client for the SIH 26160 Security Posture endpoints: provenance-tagged protocol
 * identification (Layer 07), the comprehensive security assessment and the what-if
 * remediation simulator (Layer 08), and testbed ground truth (Layer 01).
 */

import { appConfig } from '@/utils/config';
import { ApiError, NetworkError, requestJson } from './httpClient';
import type {
  AIComprehensiveAnalysis,
  ComprehensiveSecurityAssessment,
  TestbedGroundTruth,
  WhatIfRequest,
  WhatIfResponse,
} from '@/types/securityPosture';

async function postJson<T>(path: string, body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${appConfig.apiBaseUrl}${path}`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new NetworkError();
  }
  if (!response.ok) {
    let message = `The request failed with status ${response.status}.`;
    let code = 'REQUEST_FAILED';
    try {
      const err = (await response.json()) as { error?: string; message?: string; detail?: string };
      code = err.error ?? code;
      message = err.message ?? err.detail ?? err.error ?? message;
    } catch {
      // keep generic message
    }
    throw new ApiError(message, response.status, code);
  }
  return (await response.json()) as T;
}

export const securityPostureService = {
  /** Layer 08 comprehensive assessment for one session. */
  getAssessment: (sessionId: string, signal?: AbortSignal) =>
    requestJson<ComprehensiveSecurityAssessment>(
      `/api/security-assessment/comprehensive/${encodeURIComponent(sessionId)}`,
      signal,
    ),

  /** Layer 07 provenance-tagged protocol, mode, crypto, SA and traffic identification. */
  getAIAnalysis: (sessionId: string, signal?: AbortSignal) =>
    requestJson<AIComprehensiveAnalysis>(
      `/api/traffic-analysis/comprehensive/${encodeURIComponent(sessionId)}`,
      signal,
    ),

  /** Re-score a session under a hypothetical configuration. */
  whatIf: (sessionId: string, body: WhatIfRequest) =>
    postJson<WhatIfResponse>(`/api/security-assessment/what-if/${encodeURIComponent(sessionId)}`, body),

  /** Ground truth registered by the software testbed for a generated capture (404 when not a testbed capture). */
  getGroundTruth: async (captureId: string, signal?: AbortSignal): Promise<TestbedGroundTruth | null> => {
    try {
      return await requestJson<TestbedGroundTruth>(
        `/api/environment/ground-truth/${encodeURIComponent(captureId)}`,
        signal,
      );
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return null;
      throw err;
    }
  },
};
