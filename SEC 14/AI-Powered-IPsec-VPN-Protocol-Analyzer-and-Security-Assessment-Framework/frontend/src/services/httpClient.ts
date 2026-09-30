import { appConfig } from '@/utils/config';
import type { ApiErrorBody } from '@/types';

/** An error raised when the backend responds with a non-2xx status. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(message: string, status: number, code: string = 'REQUEST_FAILED') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** An error raised when the backend cannot be reached at all. */
export class NetworkError extends Error {
  constructor(message = 'The backend service is currently unavailable.') {
    super(message);
    this.name = 'NetworkError';
  }
}

/**
 * Single place where network requests are made. Services build on this; UI
 * components never call `fetch` directly.
 */
export async function requestJson<T>(path: string, signal?: AbortSignal): Promise<T> {
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
    // The backend returns a safe envelope; internal detail is never surfaced.
    let message = `The request failed with status ${response.status}.`;
    let code = 'REQUEST_FAILED';
    try {
      const body = (await response.json()) as ApiErrorBody & { message?: string };
      if (typeof body.error === 'string') {
        code = body.error;
      }
      if (typeof body.message === 'string') {
        message = body.message;
      } else if (typeof body.error === 'string') {
        message = body.error;
      }
    } catch {
      // Body was not JSON; keep the generic message.
    }
    throw new ApiError(message, response.status, code);
  }

  return (await response.json()) as T;
}

/** Build the URL for the real-time event channel. */
export function eventStreamUrl(): string {
  if (appConfig.wsBaseUrl) {
    return `${appConfig.wsBaseUrl}${appConfig.eventsPath}`;
  }
  if (typeof window !== 'undefined' && window.location) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}${appConfig.eventsPath}`;
  }
  return `ws://127.0.0.1:8000${appConfig.eventsPath}`;
}
