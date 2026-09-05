import type { ApplicationConfiguration } from '@/types';

/**
 * Backend location comes from the environment, never from hard-coded values in
 * component code. Defaults target a local development backend.
 */
const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000';
const DEFAULT_WS_BASE_URL = 'ws://127.0.0.1:8000';

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
