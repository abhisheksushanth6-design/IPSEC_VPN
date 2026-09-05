import { requestJson } from './httpClient';
import { PacketServiceError } from './packetService';
import { appConfig } from '@/utils/config';
import type {
  FeatureDefinition,
  FeatureEngineStatus,
  FeatureEntityList,
  FeatureEntityType,
  FeatureExtractionResponse,
  FeatureVector,
  FeatureVectorPage,
  PacketApiError,
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
      /* non-JSON */
    }
    throw new PacketServiceError(
      body.error ?? 'REQUEST_FAILED',
      body.message ?? `Request failed with status ${response.status}.`,
      response.status,
    );
  }
  return (await response.json()) as T;
}

/** Layer 05 feature engineering API. */
export const featureService = {
  fetchStatus: (signal?: AbortSignal) =>
    requestJson<FeatureEngineStatus>('/api/features/status', signal),

  fetchDefinitions: (signal?: AbortSignal) =>
    requestJson<FeatureDefinition[]>('/api/features/definitions', signal),

  fetchEntities: (entityType: FeatureEntityType, signal?: AbortSignal) =>
    requestJson<FeatureEntityList>(`/api/features/entities?entity_type=${entityType}`, signal),

  fetchVectors: (entityType: FeatureEntityType | null, signal?: AbortSignal) =>
    requestJson<FeatureVectorPage>(
      `/api/features?page=1&page_size=200${entityType ? `&entity_type=${entityType}` : ''}`,
      signal,
    ),

  fetchForEntity: (entityType: FeatureEntityType, entityId: string, signal?: AbortSignal) =>
    requestJson<FeatureVector>(
      `/api/features/entity/${entityType}/${encodeURIComponent(entityId)}`,
      signal,
    ),

  extract: (entityType: FeatureEntityType, entityId: string) =>
    mutate<FeatureExtractionResponse>('/api/features/extract', {
      method: 'POST',
      body: JSON.stringify({ entity_type: entityType, entity_id: entityId }),
    }),

  clear: () => mutate<FeatureEngineStatus>('/api/features', { method: 'DELETE' }),

  /** Absolute URL for a download; export only ever serves stored data. */
  exportUrl: (format: 'json' | 'csv') =>
    `${appConfig.apiBaseUrl}/api/features/export?format=${format}`,
};
