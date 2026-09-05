import { requestJson } from './httpClient';
import type { HealthResponse } from '@/types';

/** Reads `GET /api/health`. */
export const healthService = {
  fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
    return requestJson<HealthResponse>('/api/health', signal);
  },
};
