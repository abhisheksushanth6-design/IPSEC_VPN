import { describe, expect, it, beforeEach, vi } from 'vitest';
import { screen, waitFor, fireEvent } from '@testing-library/react';
import { renderAppAt, HEALTH_FIXTURE, SYSTEM_STATUS_FIXTURE } from './renderApp';

const MOCK_ASSESSMENT = {
  id: 'RISK-TEST-001',
  session_id: 'IPSEC-SESS-ALPHA',
  risk_score: 55.0,
  risk_level: 'HIGH',
  decision: 'RESTRICT',
  decision_alias: 'ISOLATE',
  is_advisory: true,
  data_quality: 'COMPLETE',
  confidence_score: 1.0,
  breakdown: {
    vulnerability_score: 35.0,
    ml_score: 12.0,
    drift_score: 4.0,
    state_score: 4.0,
    total_risk_score: 55.0,
  },
  severity_summary: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  contributing_signals: [
    {
      source: 'LAYER_09',
      contribution: 35.0,
      reason: 'Rule violation [RULE-CRYPTO-001] (CRITICAL): Deprecated 3DES cipher',
      evidence_reference: 'FINDING-001',
      confidence: 1.0,
      finding_status: 'OPEN',
      recurrence_count: 1,
    },
  ],
  evidence: [
    {
      source_layer: 'LAYER_09_VULNERABILITY_ENGINE',
      evidence_type: 'VULNERABILITY_FINDING',
      identifier: 'FINDING-001',
      summary: '[CRITICAL][OPEN] RULE-CRYPTO-001: Deprecated 3DES cipher',
      details: {},
    },
  ],
  recommended_actions: [
    'RESTRICTION ACTION: Limit tunnel throughput and enforce strict traffic rate-limiting pending investigation.',
    'Cryptographic Upgrade: Deprecate 3DES cipher suites; transition immediately to AES-256-GCM (RFC 4106).',
  ],
  available_signals: [
    'LAYER_04_SA_LIFECYCLE',
    'LAYER_05_FEATURE_EXTRACTION',
    'LAYER_06_BASELINE_PROFILING',
    'LAYER_07_DRIFT_DETECTION',
    'LAYER_08_AI_ML_ANOMALY',
    'LAYER_09_VULNERABILITY_ENGINE',
  ],
  unavailable_signals: [],
  evaluated_at: '2026-09-12T12:00:00Z',
};

const MOCK_SUMMARY = {
  state: 'OPERATIONAL',
  overall_risk_score: 55.0,
  overall_risk_level: 'HIGH',
  decision: 'RESTRICT',
  decision_alias: 'ISOLATE',
  is_advisory: true,
  data_quality: 'COMPLETE',
  assessed_sessions_count: 1,
  total_sessions_count: 1,
  critical_risk_count: 0,
  high_risk_count: 1,
  medium_risk_count: 0,
  low_risk_count: 0,
  latest_assessment: MOCK_ASSESSMENT,
};

const MOCK_STATUS = {
  layer_number: 10,
  layer_name: 'Risk Assessment & Decision Engine',
  status: 'OPERATIONAL',
  total_assessed_sessions: 1,
  critical_risk_count: 0,
  high_risk_count: 1,
  medium_risk_count: 0,
  low_risk_count: 0,
  is_advisory: true,
  checks: {
    evaluator_loaded: true,
    dry_run_passed: true,
    database_connected: true,
    tables_verified: true,
  },
};

function mockRiskBackend(options: {
  assessments?: any[];
  summary?: any;
  status?: any;
} = {}) {
  const assessments = options.assessments ?? [MOCK_ASSESSMENT];
  const summary = options.summary ?? MOCK_SUMMARY;
  const status = options.status ?? MOCK_STATUS;

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const json = (body: unknown, init?: ResponseInit) =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          ...init,
        });

      if (url.includes('/api/auth/me')) {
        return json({
          id: 'test-user-id',
          name: 'Security Analyst',
          email: 'admin@ipsec-analyzer.local',
          username: 'analyst',
          role: 'admin',
          is_active: true,
        });
      }
      if (url.includes('/api/health')) return json(HEALTH_FIXTURE);
      if (url.includes('/api/system/status')) return json(SYSTEM_STATUS_FIXTURE);
      if (url.includes('/api/risk/status')) return json(status);
      if (url.includes('/api/risk/summary')) return json(summary);
      if (url.includes('/api/risk/export')) {
        return json({
          export_version: '1.0.0',
          exported_at: '2026-09-12T12:00:00Z',
          total_assessments: assessments.length,
          assessments,
          metadata: { is_advisory: true },
        });
      }
      if (url.includes('/api/risk/evaluate-all')) return json(assessments);
      if (url.includes('/api/risk/evaluate/')) return json(assessments[0]);
      if (url.includes('/api/risk/sessions/')) return json(assessments[0]);
      if (url.includes('/api/risk/assessments/RISK-TEST-001')) return json(assessments[0]);
      if (url.includes('/api/risk/assessments')) return json(assessments);

      if (url.includes('/api/security-assessment')) return json({ findings: [] });
      if (url.includes('/api/ai-analysis')) return json({});

      // Default mock for any other layer API
      return json(SYSTEM_STATUS_FIXTURE);
    }),
  );
}

describe('Risk Assessment & Decision Engine (Layer 10)', () => {
  beforeEach(() => {
    mockRiskBackend();
  });

  it('renders the Risk Assessment page at /risk-assessment with title and header actions', async () => {
    renderAppAt('/risk-assessment');

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
        'Risk Assessment & Decision Engine',
      );
    });

    expect(screen.getAllByText('Refresh')[0]).toBeInTheDocument();
    expect(screen.getByText('Export JSON')).toBeInTheDocument();
    expect(screen.getByText('Evaluate All Sessions')).toBeInTheDocument();
  });

  it('displays the Layer 10 Decision Engine tab with advisory-only notice and KPIs', async () => {
    renderAppAt('/risk-assessment');

    // Layer 10 is default active tab
    await waitFor(() => {
      expect(screen.getByText('Advisory-Only Policy Decision Engine')).toBeInTheDocument();
      expect(
        screen.getByText(/The framework does not modify active firewall rules/i),
      ).toBeInTheDocument();
    });

    // Check KPI score cards after data loads
    await waitFor(() => {
      expect(screen.getByText('Overall Risk Posture')).toBeInTheDocument();
      expect(screen.getAllByText('55.0')[0]).toBeInTheDocument();
      expect(screen.getByText('Assessed Sessions')).toBeInTheDocument();
    });
  });

  it('renders the sessions assessment table and inspector breakdown', async () => {
    renderAppAt('/risk-assessment');

    await waitFor(() => {
      expect(screen.getAllByText('IPSEC-SESS-ALPHA')[0]).toBeInTheDocument();
    });

    // Verify sub-score breakdown display
    expect(screen.getByText('Sub-Score Contributions')).toBeInTheDocument();
    expect(screen.getByText('Vulnerabilities (L09)')).toBeInTheDocument();
    expect(screen.getByText('ML Anomaly (L08)')).toBeInTheDocument();
    expect(screen.getByText('Security Drift (L07)')).toBeInTheDocument();
    expect(screen.getByText('SA Lifecycle (L04)')).toBeInTheDocument();

    // Verify policy decision
    expect(screen.getByText('RESTRICT POLICY')).toBeInTheDocument();
  });

  it('triggers evaluate all action without throwing errors', async () => {
    renderAppAt('/risk-assessment');

    const btn = await screen.findByRole('button', { name: /evaluate all sessions/i });
    await waitFor(() => expect(btn).not.toBeDisabled());
    fireEvent.click(btn);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/risk/evaluate-all'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  it('triggers JSON export when Export JSON button is clicked', async () => {
    // Mock URL.createObjectURL and URL.revokeObjectURL
    global.URL.createObjectURL = vi.fn(() => 'blob:mock-url');
    global.URL.revokeObjectURL = vi.fn();

    renderAppAt('/risk-assessment');

    const btn = await screen.findByRole('button', { name: /export json/i });
    await waitFor(() => expect(btn).not.toBeDisabled());
    fireEvent.click(btn);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/risk/export'),
        expect.anything(),
      );
    });
  });
});
