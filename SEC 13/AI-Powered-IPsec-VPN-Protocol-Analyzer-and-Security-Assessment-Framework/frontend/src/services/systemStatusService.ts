import { requestJson } from './httpClient';
import type { SystemStatus } from '@/types';

/** Reads `GET /api/system/status`. */
export const systemStatusService = {
  fetchSystemStatus(signal?: AbortSignal): Promise<SystemStatus> {
    return requestJson<SystemStatus>('/api/system/status', signal);
  },
};
