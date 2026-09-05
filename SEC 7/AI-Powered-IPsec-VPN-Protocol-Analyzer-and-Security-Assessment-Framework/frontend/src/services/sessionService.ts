import { requestJson } from './httpClient';
import { PacketServiceError } from './packetService';
import { appConfig } from '@/utils/config';
import type { IPsecSession, PacketApiError, PacketSessionLink, SessionEngineStatus, SessionFilters, SessionPage } from '@/types';

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`${appConfig.apiBaseUrl}${path}`, { ...init, headers: { Accept: 'application/json' } });
  if (!response.ok) {
    let body: Partial<PacketApiError> = {};
    try { body = (await response.json()) as PacketApiError; } catch { /* non-JSON */ }
    throw new PacketServiceError(body.error ?? 'REQUEST_FAILED', body.message ?? `Request failed with status ${response.status}.`, response.status);
  }
  return (await response.json()) as T;
}

function buildQuery(f: SessionFilters): string {
  const params = new URLSearchParams({ page: String(f.page), page_size: String(f.pageSize), sort: f.sort, order: f.order });
  if (f.state) params.set('state', f.state);
  if (f.protocol) params.set('protocol', f.protocol);
  if (f.source) params.set('source', f.source);
  if (f.destination) params.set('destination', f.destination);
  if (f.ikeVersion) params.set('ike_version', f.ikeVersion);
  if (f.search) params.set('search', f.search);
  if (f.startAfter) params.set('start_after', f.startAfter);
  if (f.endBefore) params.set('end_before', f.endBefore);
  return params.toString();
}

/** IPsec session correlation API. */
export const sessionService = {
  fetchStatus(signal?: AbortSignal): Promise<SessionEngineStatus> {
    return requestJson<SessionEngineStatus>('/api/sessions/status', signal);
  },
  fetchSessions(filters: SessionFilters, signal?: AbortSignal): Promise<SessionPage> {
    return requestJson<SessionPage>(`/api/sessions?${buildQuery(filters)}`, signal);
  },
  fetchSession(id: string, signal?: AbortSignal): Promise<IPsecSession> {
    return requestJson<IPsecSession>(`/api/sessions/${encodeURIComponent(id)}`, signal);
  },
  fetchSessionForPacket(packetId: string, signal?: AbortSignal): Promise<PacketSessionLink> {
    return requestJson<PacketSessionLink>(`/api/sessions/for-packet/${encodeURIComponent(packetId)}`, signal);
  },
  discover(): Promise<SessionEngineStatus> {
    return mutate<SessionEngineStatus>('/api/sessions/discover', { method: 'POST' });
  },
  clear(): Promise<SessionEngineStatus> {
    return mutate<SessionEngineStatus>('/api/sessions', { method: 'DELETE' });
  },
};
