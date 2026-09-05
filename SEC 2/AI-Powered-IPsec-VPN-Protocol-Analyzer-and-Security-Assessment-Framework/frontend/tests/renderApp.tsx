import { vi } from 'vitest';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { RenderResult } from '@testing-library/react';

import App from '@/App';

/** Render the whole application shell at a given route. */
export function renderAppAt(route: string): RenderResult {
  return render(
    <MemoryRouter
      initialEntries={[route]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <App />
    </MemoryRouter>,
  );
}

/** A backend response matching the real `/api/system/status` contract. */
export const SYSTEM_STATUS_FIXTURE = {
  project:
    'AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework',
  backend_status: 'operational',
  database_status: 'CONNECTED',
  application_mode: 'DEMO',
  architecture_layers: [],
  total_layers: 14,
  initialized_layers: 4,
};

export const HEALTH_FIXTURE = {
  project:
    'AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework',
  status: 'operational',
};

/** Stub a reachable backend. */
export function mockBackendOnline(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.includes('/api/health') ? HEALTH_FIXTURE : SYSTEM_STATUS_FIXTURE;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );
}

/** Stub a backend that cannot be reached at all. */
export function mockBackendOffline(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    }),
  );
}
