/**
 * API client service for Layer 08 — AI / ML Anomaly Detection Engine.
 *
 * Interacts with /api/ml/* endpoints for training, model management,
 * anomaly inference, explainable evidence, and operational status.
 */

import { requestJson } from './httpClient';
import { appConfig } from '@/utils/config';
import type {
  AIAnomalyEngineStatus,
  AnomalyAnalysis,
  AnomalyAnalysisSummary,
  AnomalyInferenceRequest,
  MLModelDetail,
  MLModelSummary,
  MLModelTrainRequest,
  TrainingDatasetDetail,
  TrainingDatasetSummary,
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

export const aiAnomalyService = {
  /** Get operational status, health, and active model summary. */
  getStatus: (signal?: AbortSignal) =>
    requestJson<AIAnomalyEngineStatus>('/api/ml/status', signal),

  /** List all registered ML model versions. */
  listModels: (signal?: AbortSignal) =>
    requestJson<MLModelSummary[]>('/api/ml/models', signal),

  /** Get detailed model configuration, parameters, and diagnostics. */
  getModel: (modelId: string, signal?: AbortSignal) =>
    requestJson<MLModelDetail>(`/api/ml/models/${modelId}`, signal),

  /** Train a new model version on an established baseline profile. */
  trainModel: (payload: MLModelTrainRequest) =>
    mutate<MLModelDetail>('/api/ml/models/train', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** Activate a specific model version for inference. */
  activateModel: (modelId: string) =>
    mutate<MLModelDetail>(`/api/ml/models/${modelId}/activate`, {
      method: 'POST',
    }),

  /** List training dataset snapshots. */
  listDatasets: (signal?: AbortSignal) =>
    requestJson<TrainingDatasetSummary[]>('/api/ml/datasets', signal),

  /** Get specific training dataset inspection. */
  getDataset: (datasetId: string, signal?: AbortSignal) =>
    requestJson<TrainingDatasetDetail>(`/api/ml/datasets/${datasetId}`, signal),

  /** Run anomaly inference on an observed VPN session. */
  analyzeSession: (payload: AnomalyInferenceRequest) =>
    mutate<AnomalyAnalysis>('/api/ml/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** List historical anomaly analyses with optional filters. */
  listAnalyses: (
    params?: {
      sessionId?: string;
      classification?: string;
      modelId?: string;
      limit?: number;
      offset?: number;
    },
    signal?: AbortSignal
  ) => {
    const q = new URLSearchParams();
    if (params?.sessionId) q.set('session_id', params.sessionId);
    if (params?.classification && params.classification !== 'ALL') q.set('classification', params.classification);
    if (params?.modelId) q.set('model_id', params.modelId);
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.offset) q.set('offset', String(params.offset));

    const queryStr = q.toString() ? `?${q.toString()}` : '';
    return requestJson<AnomalyAnalysisSummary[]>(`/api/ml/anomalies${queryStr}`, signal);
  },

  /** Get complete anomaly analysis details including feature evidence. */
  getAnalysis: (analysisId: string, signal?: AbortSignal) =>
    requestJson<AnomalyAnalysis>(`/api/ml/anomalies/${analysisId}`, signal),

  /** Get the latest anomaly analysis for a given session. */
  getSessionLatest: (sessionId: string, signal?: AbortSignal) =>
    requestJson<AnomalyAnalysis>(`/api/ml/anomalies/session/${sessionId}/latest`, signal),
};
