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
 * The locked 10-layer architecture exactly as the backend serves it. Tests
 * compare rendered output against this list, so a rename or reorder in the
 * UI code fails loudly.
 */
export const LOCKED_LAYERS = [
  [1, 'IPsec VPN Test Environment', 'layer01_test_environment', 'READY'],
  [2, 'Packet Capture & Data Collection', 'layer02_packet_capture', 'OPERATIONAL'],
  [3, 'Packet & Protocol Analysis', 'layer03_protocol_analysis', 'OPERATIONAL'],
  [4, 'Security Association & Protocol State Analysis', 'layer04_sa_lifecycle', 'OPERATIONAL'],
  [5, 'Feature Extraction & Engineering', 'layer05_feature_engineering', 'OPERATIONAL'],
  [6, 'IPsec Session Fingerprinting', 'layer06_session_fingerprinting', 'OPERATIONAL'],
  [7, 'AI-Based Protocol & Traffic Classification', 'layer08_ai_ml', 'OPERATIONAL'],
  [8, 'Security Assessment Engine', 'layer09_vulnerability_engine', 'OPERATIONAL'],
  [9, 'Risk Assessment & Decision Engine', 'layer10_risk_engine', 'OPERATIONAL'],
  [10, 'Dashboard & Report Generation', 'layer14_reports', 'OPERATIONAL'],
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
  total_layers: 10,
  initialized_layers: 10,
};

export const HEALTH_FIXTURE = {
  project:
    'AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework',
  status: 'operational',
};

/** Layer 05 feature engine status, matching `/api/features/status`. */
export const FEATURE_STATUS_FIXTURE = {
  state: 'READY',
  feature_version: '1.0',
  packets_available: true,
  sessions_available: true,
  sas_available: true,
  capture_id: 'capture-1',
  capture_filename: 'sample.pcap',
  extracted_at: null,
  registered_features: 100,
  burst_window_seconds: 1,
  statistics: null,
  last_error: null,
};

/** Selectable entities, matching `/api/features/entities`. */
export const FEATURE_ENTITIES_FIXTURE = {
  entity_type: 'SESSION',
  items: [
    {
      entity_type: 'SESSION',
      entity_id: 'SESSION-1',
      label: '192.0.2.10 \u2194 198.51.100.20',
      detail: 'ACTIVE \u00b7 6 packets',
      extracted: false,
    },
  ],
  source_available: true,
  detail: '1 session(s) discovered.',
};

export const DASHBOARD_SUMMARY_FIXTURE = {
  posture: {
    backend_status: 'OPERATIONAL',
    database_status: 'CONNECTED',
    application_mode: 'DEMO',
    layers_total: 10,
    layers_initialized: 10,
    last_refresh: '2026-09-04T10:00:00Z',
  },
  metrics: {
    overall_risk_score: null,
    overall_risk_status: 'NOT INITIALIZED',
    active_vpn_sessions: 0,
    active_sas: 0,
    packets_analyzed: 0,
    ai_anomalies: 0,
    drift_events: 0,
    vulnerabilities_total: 0,
    vulnerabilities_critical: 0,
    vulnerabilities_high: 0,
    vulnerabilities_medium: 0,
    vulnerabilities_low: 0,
    vulnerabilities_active: 0,
    capture_status: 'IDLE',
  },
  recent_sessions: [],
  recent_events: [],
  protocol_posture: {
    ike_versions: [],
    observed_encryption_algorithms: [],
    observed_integrity_algorithms: [],
    observed_dh_groups: [],
    observed_prf_algorithms: [],
    pfs_enabled: null,
    protocol_counts: {},
  },
  vulnerability_breakdown: {},
  sa_state_breakdown: {},
  ml_engine_status: { total_models: 0, total_anomalies: 0 },
  drift_engine_status: { total_drift_analyses: 0, active_baselines_count: 0 },
};

/** Stub a reachable backend, optionally overriding the status payload. */
export function mockBackendOnline(statusOverride?: Partial<typeof SYSTEM_STATUS_FIXTURE>): void {
  const statusBody = { ...SYSTEM_STATUS_FIXTURE, ...statusOverride };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      let body: unknown = statusBody;
      if (url.includes('/api/auth/me')) {
        body = {
          id: 'test-user-id',
          name: 'Security Analyst',
          email: 'admin@ipsec-analyzer.local',
          username: 'analyst',
          role: 'admin',
          is_active: true,
          created_at: '2026-09-01T00:00:00Z',
          last_login: '2026-09-01T00:00:00Z',
        };
      } else if (url.includes('/api/health')) body = HEALTH_FIXTURE;
      else if (url.includes('/api/features/status')) body = FEATURE_STATUS_FIXTURE;
      else if (url.includes('/api/features/entities')) body = FEATURE_ENTITIES_FIXTURE;
      else if (url.includes('/api/features/entity/')) {
        return new Response(JSON.stringify({ error: 'FEATURE_VECTOR_NOT_FOUND' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      } else if (url.includes('/api/baselines/status')) {
        body = { state: 'READY', active_baseline_id: null, total_baselines: 0, baseline_version: '1.0' };
      } else if (url.includes('/api/baselines')) {
        body = [];
      } else if (url.includes('/api/fingerprints')) {
        body = [];
      } else if (url.includes('/api/drift/status')) {
        body = { state: 'READY', total_drift_analyses: 0 };
      } else if (url.includes('/api/drift')) {
        body = [];
      } else if (url.includes('/api/ml/status')) {
        body = {
          status: 'READY',
          active_model: null,
          total_models: 0,
          feature_version: '1.0',
          preprocessing_version: '1.0',
          models_dir_writable: true,
          available_baselines_count: 0,
          available_sessions_count: 0,
        };
      } else if (url.includes('/api/ml/models')) {
        body = [];
      } else if (url.includes('/api/ml/analyses')) {
        body = [];
      } else if (url.includes('/api/vulnerabilities/status')) {
        body = {
          layer_number: 9,
          layer_name: 'Security Rule & Vulnerability Engine',
          status: 'OPERATIONAL',
          total_rules: 16,
          enabled_rules: 16,
          total_findings: 0,
          open_findings: 0,
          categories: ['CRYPTO', 'IKE', 'AUTH', 'PROTOCOL', 'SA_LIFECYCLE', 'CONFIGURATION'],
        };
      } else if (url.includes('/api/vulnerabilities/stats')) {
        body = {
          total_rules: 16,
          enabled_rules: 16,
          total_findings: 0,
          open_findings: 0,
          confirmed_findings: 0,
          resolved_findings: 0,
          suppressed_findings: 0,
          false_positive_findings: 0,
          by_severity: {},
          by_category: {},
          by_affected_type: {},
        };
      } else if (url.includes('/api/vulnerabilities/findings')) {
        body = [];
      } else if (url.includes('/api/vulnerabilities/rules')) {
        body = [];
      } else if (url.includes('/api/dashboard/summary')) {
        body = DASHBOARD_SUMMARY_FIXTURE;
      } else if (url.includes('/api/dashboard/metrics')) {
        body = DASHBOARD_SUMMARY_FIXTURE.metrics;
      } else if (url.includes('/api/dashboard/timeline')) {
        body = [];
      } else if (url.includes('/api/dashboard/protocols')) {
        body = DASHBOARD_SUMMARY_FIXTURE.protocol_posture;
      } else if (url.includes('/api/dashboard/sessions')) {
        body = [];
      } else if (url.includes('/api/reports')) {
        body = [];
      } else if (url.includes('/api/sessions/fingerprints')) {
        body = { capture_id: 'default', total_sessions: 0, sessions: [], metadata: {} };
      } else if (url.includes('/api/sessions')) {
        body = { items: [], total: 0, page: 1, page_size: 50 };
      } else if (url.includes('/api/packets/protocol-analysis')) {
        body = {
          capture_id: 'default',
          total_packets_analyzed: 0,
          ike_summary: { total_ike_packets: 0, versions_detected: [], proposals: [], anomalies: [] },
          ipsec_streams: [],
          anomalies: [],
          endpoint_summary: [],
          generated_at: '2026-09-11T00:00:00Z',
        };
      } else if (url.includes('/api/packets/anomalies')) {
        body = [];
      } else if (url.includes('/api/security-assessment')) {
        body = {
          assessment_id: 'assess-1',
          capture_id: 'default',
          overall_risk_score: 0,
          risk_level: 'LOW',
          findings_by_severity: {},
          findings_by_category: {},
          findings: [],
          evaluated_sessions_count: 0,
          evaluated_tunnels_count: 0,
          evaluated_packets_count: 0,
          timestamp: '2026-09-11T00:00:00Z',
        };
      } else if (url.includes('/api/ai-analysis')) {
        body = {
          analysis_id: 'ai-1',
          capture_id: 'default',
          timestamp: '2026-09-11T00:00:00Z',
          provider_used: 'mock',
          overall_risk_score: 0,
          risk_level: 'LOW',
          executive_summary: {
            overall_posture: 'LOW_RISK',
            risk_score_summary: 'Clean baseline',
            business_impact: 'None',
            compliance_overview: 'Compliant',
            strategic_recommendations: [],
          },
          technical_summary: {
            protocol_health: 'Healthy',
            cryptographic_assessment: 'Strong',
            integrity_and_sequence_analysis: 'Valid',
            leakage_and_exposure_analysis: 'None',
            rfc_compliance_citations: [],
          },
          prioritized_findings: [],
          attack_implications: [],
          remediation_steps: [],
          metadata: {},
        };
      } else if (url.includes('/api/metadata-exposure/summary')) {
        body = { total_assessments: 0, total_sessions: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, average_exposure_score: 0 };
      } else if (url.includes('/api/metadata-exposure')) {
        body = [];
      } else if (url.includes('/api/threat-matrix/summary')) {
        body = { total_threats: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, active_vectors_count: 0 };
      } else if (url.includes('/api/threat-matrix')) {
        body = [];
      } else if (url.includes('/api/risk/summary')) {
        body = { state: 'OPERATIONAL', overall_risk_score: 0, overall_risk_level: 'LOW', decision: 'ALLOW', assessed_sessions_count: 0, total_sessions_count: 0 };
      } else if (url.includes('/api/risk/assessments')) {
        body = [];
      }
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
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/api/auth/me')) {
        return new Response(
          JSON.stringify({ id: '1', email: 'admin@ipsec-analyzer.local', name: 'Analyst', role: 'ADMIN' }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      throw new TypeError('Failed to fetch');
    }),
  );
}
