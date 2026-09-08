import { requestJson } from './httpClient';
import type { SystemStatus } from '@/types';

/** Reads `GET /api/system/status` and explicitly normalizes properties. */
export const systemStatusService = {
  async fetchSystemStatus(signal?: AbortSignal): Promise<SystemStatus> {
    const raw = await requestJson<any>('/api/system/status', signal);
    const total_layers =
      raw.total_layers ??
      raw.totalLayers ??
      (Array.isArray(raw.architecture_layers) ? raw.architecture_layers.length : 14);

    const initialized_layers =
      raw.initialized_layers ??
      raw.initializedLayers ??
      (Array.isArray(raw.architecture_layers)
        ? raw.architecture_layers.filter((l: any) => l.status !== 'NOT INITIALIZED').length
        : total_layers);

    const backend_status = raw.backend_status ?? raw.backendStatus ?? 'operational';
    const database_status = raw.database_status ?? raw.databaseStatus ?? 'CONNECTED';
    const application_mode = raw.application_mode ?? raw.applicationMode ?? 'STANDALONE';

    return {
      project:
        raw.project ??
        'AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework',
      backend_status,
      database_status,
      application_mode,
      architecture_layers: raw.architecture_layers ?? [],
      total_layers,
      initialized_layers,
      backendStatus: backend_status,
      databaseStatus: database_status,
      applicationMode: application_mode,
      totalLayers: total_layers,
      initializedLayers: initialized_layers,
    };
  },
};
