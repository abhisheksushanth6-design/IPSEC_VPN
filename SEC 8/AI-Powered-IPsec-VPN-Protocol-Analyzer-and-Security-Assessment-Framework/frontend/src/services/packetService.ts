import { appConfig } from '@/utils/config';
import { ApiError, NetworkError, requestJson } from './httpClient';
import type { AnalysisStatus, PacketAnalysisResult, PacketApiError, PacketPage, PacketQuery } from '@/types';

/** Error carrying the backend's structured code, e.g. CAPTURE_FORMAT_UNSUPPORTED. */
export class PacketServiceError extends ApiError {
  readonly code: string;

  constructor(code: string, message: string, status: number) {
    super(message, status);
    this.name = 'PacketServiceError';
    this.code = code;
  }
}

async function mutate<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${appConfig.apiBaseUrl}${path}`, { ...init, headers: { Accept: 'application/json', ...(init.headers ?? {}) } });
  } catch {
    throw new NetworkError();
  }
  if (!response.ok) {
    let body: Partial<PacketApiError> = {};
    try {
      body = (await response.json()) as PacketApiError;
    } catch {
      // non-JSON error body
    }
    throw new PacketServiceError(body.error ?? 'REQUEST_FAILED', body.message ?? `Request failed with status ${response.status}.`, response.status);
  }
  return (await response.json()) as T;
}

function buildQuery(query: PacketQuery): string {
  const params = new URLSearchParams();
  params.set('page', String(query.page));
  params.set('page_size', String(query.pageSize));
  params.set('sort', query.sort);
  params.set('order', query.order);
  if (query.protocol) params.set('protocol', query.protocol);
  if (query.source) params.set('source', query.source);
  if (query.destination) params.set('destination', query.destination);
  if (query.port !== undefined) params.set('port', String(query.port));
  if (query.ipsec !== 'ALL') params.set('ipsec', query.ipsec);
  if (query.search) params.set('search', query.search);
  return params.toString();
}

/** Layer 03 packet-analysis API. */
export const packetService = {
  fetchStatus(signal?: AbortSignal): Promise<AnalysisStatus> {
    return requestJson<AnalysisStatus>('/api/packets/status', signal);
  },
  fetchPackets(query: PacketQuery, signal?: AbortSignal): Promise<PacketPage> {
    return requestJson<PacketPage>(`/api/packets?${buildQuery(query)}`, signal);
  },
  fetchPacket(id: string, signal?: AbortSignal): Promise<PacketAnalysisResult> {
    return requestJson<PacketAnalysisResult>(`/api/packets/${encodeURIComponent(id)}`, signal);
  },
  uploadCapture(file: File): Promise<AnalysisStatus> {
    const form = new FormData();
    form.append('file', file, file.name);
    return mutate<AnalysisStatus>('/api/packets/upload', { method: 'POST', body: form });
  },
  analyze(): Promise<AnalysisStatus> {
    return mutate<AnalysisStatus>('/api/packets/analyze', { method: 'POST' });
  },
  clear(): Promise<AnalysisStatus> {
    return mutate<AnalysisStatus>('/api/packets', { method: 'DELETE' });
  },
};
