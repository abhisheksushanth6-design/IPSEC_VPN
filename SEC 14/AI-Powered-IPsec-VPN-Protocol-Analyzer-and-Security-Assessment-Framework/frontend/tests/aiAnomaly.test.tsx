import { describe, expect, it, beforeEach, vi } from 'vitest';
import { screen, waitFor, fireEvent } from '@testing-library/react';
import { renderAppAt, HEALTH_FIXTURE, SYSTEM_STATUS_FIXTURE } from './renderApp';

const MOCK_MODEL = {
  id: 'model-mock-1',
  name: 'Production Isolation Forest',
  model_type: 'IsolationForest',
  model_version: '1.0',
  feature_version: '1.0',
  preprocessing_version: '1.0',
  training_samples: 25,
  feature_count: 27,
  status: 'READY',
  is_active: true,
  created_at: '2026-09-04T00:00:00Z',
  updated_at: '2026-09-04T00:00:00Z',
  configuration: { contamination: 0.05, n_estimators: 100 },
  feature_names: ['esp_burst_rate', 'ike_exchange_type'],
};

const MOCK_ANALYSIS = {
  id: 'analysis-mock-1',
  session_id: 'session-test-42',
  model_id: 'model-mock-1',
  model_version: '1.0',
  feature_version: '1.0',
  preprocessing_version: '1.0',
  classification: 'ANOMALOUS' as const,
  raw_score: -0.15,
  display_score: 81.8,
  features_analyzed: 27,
  features_anomalous: 3,
  explanation_summary: 'Observed session exhibits severe statistical deviation (+3.20σ on esp_burst_rate).',
  feature_contributions: [
    {
      feature_name: 'esp_burst_rate',
      display_name: 'ESP Packet Burst Rate',
      category: 'volumetric',
      data_type: 'float',
      observed_value: 145.2,
      reference_mean: 25.0,
      reference_std: 12.0,
      reference_median: 24.5,
      contribution_score: 0.35,
      deviation: 3.2,
      direction: 'ABOVE_REFERENCE' as const,
      evidence_description: 'Observed value 145.2 is significantly elevated (+3.20σ) relative to baseline mean 25.0.',
    },
  ],
  signal_comparison: {
    baseline_id: 'baseline-test-1',
    baseline_status: 'MATCHES_BASELINE',
    drift_analysis_id: null,
    drift_status: 'NO_DRIFT',
    ml_model_id: 'model-mock-1',
    ml_status: 'ANOMALOUS',
  },
  analyzed_at: '2026-09-04T00:00:00Z',
};

function mockAnomalyBackend(options: { models?: any[]; analyses?: any[]; activeModel?: any } = {}) {
  const models = options.models ?? [MOCK_MODEL];
  const analyses = options.analyses ?? [MOCK_ANALYSIS];
  const activeModel = options.activeModel ?? MOCK_MODEL;

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      // console.log('MOCK FETCH:', url);
      const json = (body: unknown, init?: ResponseInit) =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          ...init,
        });

      if (url.includes('/api/health')) return json(HEALTH_FIXTURE);
      if (url.includes('/api/system/status')) return json(SYSTEM_STATUS_FIXTURE);
      if (url.includes('/api/ml/status')) {
        return json({
          status: 'READY',
          active_model: activeModel,
          total_models: models.length,
          feature_version: '1.0',
          preprocessing_version: '1.0',
          models_dir_writable: true,
          available_baselines_count: 1,
          available_sessions_count: 1,
        });
      }
      if (url.includes('/api/ml/models/')) return json(models[0] ?? MOCK_MODEL);
      if (url.includes('/api/ml/models')) return json(models);
      if (url.includes('/api/ml/anomalies/')) return json(analyses[0] ?? MOCK_ANALYSIS);
      if (url.includes('/api/ml/anomalies')) return json(analyses);
      if (url.includes('/api/ml/analyze')) return json(analyses[0] ?? MOCK_ANALYSIS);
      if (url.includes('/api/baselines/status')) return json({ state: 'READY', active_baseline_id: null, total_baselines: 0 });
      if (url.includes('/api/baselines')) return json([]);
      if (url.includes('/api/fingerprints')) return json([]);
      if (url.includes('/api/sessions')) return json({ items: [{ id: 'session-test-42' }], total: 1, page: 1, page_size: 50 });
      return json(SYSTEM_STATUS_FIXTURE);
    }),
  );
}

describe('AI / ML Anomaly Detection Engine (Layer 08)', () => {
  beforeEach(() => {
    mockAnomalyBackend();
  });

  it('renders the AI / ML Anomaly Detection page at /ai-anomaly-detection', async () => {
    renderAppAt('/ai-anomaly-detection');

    await waitFor(() => {
      expect(
        screen.getByRole('heading', { name: /SUPPLEMENTARY ANOMALY DETECTION/i }),
      ).toBeInTheDocument();
    });

    // Check tab buttons
    expect(screen.getByRole('button', { name: /Anomaly Evaluation/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Inference History & Timeline/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Model Registry & Training/i })).toBeInTheDocument();
  });

  it('navigates across tabs properly', async () => {
    renderAppAt('/ai-anomaly-detection');

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Model Registry & Training/i })).toBeInTheDocument();
    });

    // Click Model Registry & Training tab
    fireEvent.click(screen.getByRole('button', { name: /Model Registry & Training/i }));

    await waitFor(() => {
      expect(screen.getByText(/MODEL TRAINING WORKFLOW/i)).toBeInTheDocument();
      expect(screen.getByText(/REGISTERED MODEL VERSIONS/i)).toBeInTheDocument();
    });

    // Click History & Timeline tab
    fireEvent.click(screen.getByRole('button', { name: /Inference History & Timeline/i }));

    await waitFor(() => {
      expect(screen.getByText(/Inference Timeline/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/Search by session ID/i)).toBeInTheDocument();
    });
  });

  it('renders the multi-layer pipeline lineage', async () => {
    renderAppAt('/ai-anomaly-detection');

    await waitFor(() => {
      expect(screen.getByText(/Multi-Layer End-to-End Pipeline Lineage/i)).toBeInTheDocument();
      expect(screen.getByText(/Packet Capture/i)).toBeInTheDocument();
      expect(screen.getByText(/Session Reassembly/i)).toBeInTheDocument();
      expect(screen.getAllByText(/SA & Protocol State/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/Feature Vector/i)).toBeInTheDocument();
      expect(screen.getByText(/Baseline Profile/i)).toBeInTheDocument();
      expect(screen.getByText(/Drift Analysis/i)).toBeInTheDocument();
    });
  });

  it('displays anomaly evaluation results when inference data is present', async () => {
    renderAppAt('/ai-anomaly-detection');

    await waitFor(
      () => {
        expect(screen.getByText('81.8')).toBeInTheDocument();
        expect(screen.getAllByText(/ANOMALOUS/i).length).toBeGreaterThan(0);
        expect(screen.getByText(/3-SIGNAL COMPARISON/i)).toBeInTheDocument();
        expect(screen.getAllByText(/ESP Packet Burst Rate/i).length).toBeGreaterThan(0);
        expect(screen.getByText(/WHY THIS SESSION WAS FLAGGED/i)).toBeInTheDocument();
      },
      { timeout: 3000 },
    );
  });
});
