import type { ApplicationConfiguration } from '@/types';

/**
 * Backend location comes from the environment, never from hard-coded values in
 * In development, requests to /api are proxied by Vite dev-server to http://127.0.0.1:8000.
 * In production, relative /api paths target the same origin serving the application.
 * If an explicit VITE_API_BASE_URL is provided in .env, it takes precedence.
 */
const DEFAULT_API_BASE_URL = '';
const DEFAULT_WS_BASE_URL = '';

function trimTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

export const appConfig: ApplicationConfiguration = {
  apiBaseUrl: trimTrailingSlash(
    import.meta.env.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL,
  ),
  wsBaseUrl: trimTrailingSlash(
    import.meta.env.VITE_WS_BASE_URL ?? DEFAULT_WS_BASE_URL,
  ),
  eventsPath: '/ws/events',
};
