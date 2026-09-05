import { appConfig } from '@/utils/config';
import type { ApiErrorBody, HealthResponse, SystemStatus } from '@/types';

/** An error raised when the backend responds with a non-2xx status. */
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** An error raised when the backend cannot be reached at all. */
export class NetworkError extends Error {
  constructor(message = 'The backend is unreachable.') {
    super(message);
    this.name = 'NetworkError';
  }
}

async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;

  try {
    response = await fetch(`${appConfig.apiBaseUrl}${path}`, {
      headers: { Accept: 'application/json' },
      signal,
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') {
      throw cause;
    }
    throw new NetworkError();
  }

  if (!response.ok) {
    let message = `Request to ${path} failed with status ${response.status}.`;
    try {
      const body = (await response.json()) as ApiErrorBody;
      if (typeof body.error === 'string') {
        message = body.error;
      }
    } catch {
      // Body was not JSON; keep the generic message.
    }
    throw new ApiError(message, response.status);
  }

  return (await response.json()) as T;
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>('/api/health', signal);
}

export function fetchSystemStatus(signal?: AbortSignal): Promise<SystemStatus> {
  return request<SystemStatus>('/api/system/status', signal);
}

/** Build the URL for the future real-time event channel. */
export function eventStreamUrl(): string {
  return `${appConfig.wsBaseUrl}${appConfig.eventsPath}`;
}
