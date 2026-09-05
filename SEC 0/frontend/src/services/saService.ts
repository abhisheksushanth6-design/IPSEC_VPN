import { requestJson } from './httpClient';
import { PacketServiceError } from './packetService';
import { appConfig } from '@/utils/config';
import type { PacketApiError, SAEngineStatus, SAFilters, SAPage, SAReference, SecurityAssociation } from '@/types';

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`${appConfig.apiBaseUrl}${path}`, { ...init, headers: { Accept: 'application/json' } });
  if (!response.ok) {
    let body: Partial<PacketApiError> = {};
    try { body = (await response.json()) as PacketApiError; } catch { /* non-JSON */ }
    throw new PacketServiceError(body.error ?? 'REQUEST_FAILED', body.message ?? `Request failed with status ${response.status}.`, response.status);
  }
  return (await response.json()) as T;
}

function buildQuery(f: SAFilters): string {
  const p = new URLSearchParams({ page: String(f.page), page_size: String(f.pageSize), sort: f.sort, order: f.order });
  if (f.type) p.set('type', f.type);
  if (f.state) p.set('state', f.state);
  if (f.ikeVersion) p.set('ike_version', f.ikeVersion);
  if (f.source) p.set('source', f.source);
  if (f.destination) p.set('destination', f.destination);
  if (f.protocol) p.set('protocol', f.protocol);
  if (f.spi) p.set('spi', f.spi);
  if (f.search) p.set('search', f.search);
  return p.toString();
}

/** Layer 04 SA lifecycle API. */
export const saService = {
  fetchStatus: (signal?: AbortSignal) => requestJson<SAEngineStatus>('/api/sas/status', signal),
  fetchSAs: (filters: SAFilters, signal?: AbortSignal) => requestJson<SAPage>(`/api/sas?${buildQuery(filters)}`, signal),
  fetchSA: (id: string, signal?: AbortSignal) => requestJson<SecurityAssociation>(`/api/sas/${encodeURIComponent(id)}`, signal),
  fetchForSession: (sessionId: string, signal?: AbortSignal) => requestJson<{ session_id: string; associations: SAReference[] }>(`/api/sas/for-session/${encodeURIComponent(sessionId)}`, signal),
  fetchForPacket: (packetId: string, signal?: AbortSignal) => requestJson<SAReference[]>(`/api/sas/for-packet/${encodeURIComponent(packetId)}`, signal),
  discover: () => mutate<SAEngineStatus>('/api/sas/discover', { method: 'POST' }),
  clear: () => mutate<SAEngineStatus>('/api/sas', { method: 'DELETE' }),
};
