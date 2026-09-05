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

/**
 * The locked 14-layer architecture exactly as the backend serves it. Tests
 * compare rendered output against this list, so a rename or reorder in the
 * UI code fails loudly.
 */
export const LOCKED_LAYERS = [
  [1, 'IPsec VPN Test Environment', 'layer01_test_environment', 'NOT INITIALIZED'],
  [2, 'Packet Capture & Data Collection', 'layer02_packet_capture', 'NOT INITIALIZED'],
  [3, 'Packet & Protocol Analysis', 'layer03_protocol_analysis', 'IN DEVELOPMENT'],
  [4, 'Security State & SA Lifecycle Engine', 'layer04_sa_lifecycle', 'IN DEVELOPMENT'],
  [5, 'Feature Extraction & Engineering', 'layer05_feature_engineering', 'NOT INITIALIZED'],
  [6, 'Session Fingerprinting & Baseline Profiling', 'layer06_session_fingerprinting', 'NOT INITIALIZED'],
  [7, 'Security Drift Detection', 'layer07_drift_detection', 'NOT INITIALIZED'],
  [8, 'AI / ML Anomaly Detection Engine', 'layer08_ai_ml', 'NOT INITIALIZED'],
  [9, 'Security Rule & Vulnerability Engine', 'layer09_vulnerability_engine', 'NOT INITIALIZED'],
  [10, 'Risk Assessment & Decision Engine', 'layer10_risk_engine', 'NOT INITIALIZED'],
  [11, 'Security Databases (SQLite)', 'layer11_database', 'FOUNDATION CREATED'],
  [12, 'Backend & API (FastAPI)', 'layer12_api', 'FOUNDATION CREATED'],
  [13, 'Web Dashboard', 'layer13_dashboard', 'FOUNDATION CREATED'],
  [14, 'Report Generation (PDF)', 'layer14_reports', 'FOUNDATION READY'],
] as const;

export const ARCHITECTURE_LAYERS_FIXTURE = LOCKED_LAYERS.map(([number, name, pkg, status]) => ({
  number,
  name,
  package: pkg,
  status,
  description: `Description of ${name}.`,
}));

/** A backend response matching the real `/api/system/status` contract. */
export const SYSTEM_STATUS_FIXTURE = {
  project:
    'AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework',
  backend_status: 'operational',
  database_status: 'CONNECTED',
  application_mode: 'DEMO',
  architecture_layers: ARCHITECTURE_LAYERS_FIXTURE,
  total_layers: 14,
  initialized_layers: 6,
};

export const HEALTH_FIXTURE = {
  project:
    'AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework',
  status: 'operational',
};

/** Stub a reachable backend, optionally overriding the status payload. */
export function mockBackendOnline(statusOverride?: Partial<typeof SYSTEM_STATUS_FIXTURE>): void {
  const statusBody = { ...SYSTEM_STATUS_FIXTURE, ...statusOverride };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.includes('/api/health') ? HEALTH_FIXTURE : statusBody;
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
