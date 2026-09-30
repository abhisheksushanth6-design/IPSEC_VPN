/**
 * Client service for Layer 06 — AI-Powered Security Analysis.
 */

import { appConfig } from '@/utils/config';
import { ApiError, NetworkError, requestJson } from './httpClient';
import type {
  AISecurityAnalysis,
  ExecutiveSummary,
  RemediationStep,
  TechnicalSummary,
} from '@/types';

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${appConfig.apiBaseUrl}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(init.headers ?? {}),
      },
    });
  } catch {
    throw new NetworkError();
  }
  if (!response.ok) {
    throw new ApiError(`Request failed with status ${response.status}`, response.status);
  }
  return (await response.json()) as T;
}

export const aiAnalysisService = {
  /** Retrieve the complete AI-powered security analysis report */
  getAnalysis(provider?: string, signal?: AbortSignal): Promise<AISecurityAnalysis> {
    const qs = provider ? `?provider=${encodeURIComponent(provider)}` : '';
    return requestJson<AISecurityAnalysis>(`/api/ai-analysis${qs}`, signal);
  },

  /** Retrieve the CISO executive briefing */
  getExecutiveSummary(signal?: AbortSignal): Promise<ExecutiveSummary> {
    return requestJson<ExecutiveSummary>('/api/ai-analysis/executive-summary', signal);
  },

  /** Retrieve the phased remediation roadmap with optional phase filter */
  getRemediationRoadmap(phase?: string, signal?: AbortSignal): Promise<RemediationStep[]> {
    const qs = phase && phase !== 'ALL' ? `?phase=${encodeURIComponent(phase)}` : '';
    return requestJson<RemediationStep[]>(`/api/ai-analysis/remediation${qs}`, signal);
  },

  /** Retrieve the SOC analyst technical dossier */
  getTechnicalSummary(signal?: AbortSignal): Promise<TechnicalSummary> {
    return requestJson<TechnicalSummary>('/api/ai-analysis/technical-summary', signal);
  },

  /** Trigger on-demand AI analysis evaluation */
  triggerAnalysis(provider?: string): Promise<AISecurityAnalysis> {
    return mutate<AISecurityAnalysis>('/api/ai-analysis/analyze', {
      method: 'POST',
      body: JSON.stringify(provider ? { provider } : {}),
    });
  },
};
