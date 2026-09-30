import { describe, expect, it, vi, beforeEach } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { renderAppAt } from './renderApp';

/**
 * The page must never invent a value. These tests pin the two behaviours
 * that matter: a calculated zero renders as 0, and a feature that could not
 * be calculated renders as an em dash with its reason, never as a zero.
 */

const STATUS_READY = {
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

const STATUS_EMPTY = {
  ...STATUS_READY,
  state: 'NOT INITIALIZED',
  packets_available: false,
  sessions_available: false,
  sas_available: false,
  capture_id: null,
  capture_filename: null,
};

const ENTITIES = {
  entity_type: 'SESSION',
  items: [
    {
      entity_type: 'SESSION',
      entity_id: 'SESSION-1',
      label: '192.0.2.10 ↔ 198.51.100.20',
      detail: 'ACTIVE · 6 packets',
      extracted: true,
    },
  ],
  source_available: true,
  detail: '1 session(s) discovered.',
};

const EMPTY_ENTITIES = {
  entity_type: 'SESSION',
  items: [],
  source_available: false,
  detail: 'No capture is loaded. Load one in Packet Analysis first.',
};

function feature(overrides: Record<string, unknown>) {
  return {
    name: 'packet_count',
    display_name: 'Packet Count',
    description: 'Packets correlated into the session.',
    value: 6,
    data_type: 'INTEGER',
    category: 'TRAFFIC',
    level: 'SESSION',
    unit: 'packets',
    source: 'IPsec session record (Section 6)',
    detail: null,
    availability: 'AVAILABLE',
    quality: 'COMPLETE',
    formula: null,
    normalization_method: 'NONE',
    normalized_value: null,
    ...overrides,
  };
}

const VECTOR = {
  id: 'FV-1',
  entity_type: 'SESSION',
  entity_id: 'SESSION-1',
  entity_label: '192.0.2.10 ↔ 198.51.100.20',
  capture_id: 'capture-1',
  feature_version: '1.0',
  generated_at: '2026-01-01T00:00:00+00:00',
  feature_count: 4,
  available_count: 2,
  partial_count: 1,
  unavailable_count: 1,
  sources: [
    { name: 'Session record', available: true, detail: '6 packet(s), state ACTIVE.' },
    {
      name: 'Session packets',
      available: false,
      detail: 'The originating capture is not loaded.',
    },
  ],
  features: [
    feature({}),
    feature({
      name: 'ah_packet_count',
      display_name: 'AH Packet Count',
      value: 0,
      unit: 'packets',
    }),
    feature({
      name: 'rekey_count',
      display_name: 'Rekey Count',
      value: null,
      unit: 'rekeys',
      availability: 'UNAVAILABLE',
      quality: 'MISSING_SOURCE_DATA',
      category: 'SA_LIFECYCLE',
      detail: 'A child SA is keyed by its SPI, so a rekey produces a new child SA.',
    }),
    feature({
      name: 'ike_payload_count',
      display_name: 'IKE Payload Count',
      value: 10,
      unit: 'payloads',
      category: 'IKE',
      availability: 'PARTIAL',
      quality: 'PARTIAL',
      detail: 'Encrypted payloads are not decoded, so this count is a floor.',
    }),
  ],
};

function mockFeatureBackend(options: { status?: unknown; entities?: unknown; vector?: unknown } = {}) {
  const status = options.status ?? STATUS_READY;
  const entities = options.entities ?? ENTITIES;
  const vector = options.vector;

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

      if (url.includes('/api/features/status')) return json(status);
      if (url.includes('/api/features/entities')) return json(entities);
      if (url.includes('/api/features/entity/')) {
        if (!vector) {
          return json({ error: 'FEATURE_VECTOR_NOT_FOUND' }, { status: 404 });
        }
        return json(vector);
      }
      if (url.includes('/api/features/extract')) {
        return json({
          status: 'EXTRACTED',
          feature_version: '1.0',
          generated_at: '2026-01-01T00:00:00+00:00',
          feature_vector: VECTOR,
        });
      }
      return json({ project: 'test', architecture_layers: [], total_layers: 14 });
    }),
  );
}

describe('feature engineering page', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders the locked page title and engine state', async () => {
    mockFeatureBackend();
    renderAppAt('/feature-engineering');

    expect(
      await screen.findByRole('heading', { name: /Feature Extraction & Engineering/i }),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByText('READY').length).toBeGreaterThan(0);
    });
  });

  it('states that source data is unavailable rather than showing values', async () => {
    mockFeatureBackend({ status: STATUS_EMPTY, entities: EMPTY_ENTITIES });
    renderAppAt('/feature-engineering');

    expect(await screen.findByText('SOURCE DATA UNAVAILABLE')).toBeInTheDocument();
    expect(screen.queryByText('Feature Inspector')).not.toBeInTheDocument();
  });

  it('prompts for extraction when an entity has no stored vector', async () => {
    mockFeatureBackend();
    renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    expect(await screen.findByText('FEATURE EXTRACTION NOT RUN')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    const extractBtn = await screen.findByRole('button', { name: /Extract features/i });
    expect(extractBtn).toBeEnabled();
    await userEvent.click(extractBtn);

    expect(await screen.findByRole('region', { name: /Feature Summary/i })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows summary counts from the vector metadata', async () => {
    mockFeatureBackend({ vector: VECTOR });
    renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    const summary = await screen.findByRole('region', { name: /Feature Summary/i });
    expect(within(summary).getByText('Total features')).toBeInTheDocument();
    expect(within(summary).getByText('4')).toBeInTheDocument();
    expect(within(summary).getByText('Partial')).toBeInTheDocument();
  });

  it('distinguishes a calculated zero from an unavailable feature', async () => {
    mockFeatureBackend({ vector: VECTOR });
    renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    await screen.findByRole('region', { name: /Feature Summary/i });

    // A real zero is rendered as a number.
    const zeroRow = (await screen.findAllByText('ah_packet_count'))[0]!.closest('tr')!;
    expect(within(zeroRow).getByText('0')).toBeInTheDocument();
    expect(within(zeroRow).getAllByText('AVAILABLE').length).toBeGreaterThan(0);

    // A missing value is a dash carrying its reason, never a zero. The SA
    // lifecycle group is collapsed by default, so open it first.
    await userEvent.click(await screen.findByRole('button', { name: /SA Lifecycle Features/i }));
    const inspector = await screen.findByRole('region', { name: /SA Lifecycle Features/i });
    const missingRow = within(inspector).getByText('rekey_count').closest('tr')!;
    expect(within(missingRow).getByText('—')).toBeInTheDocument();
    expect(within(missingRow).queryByText('0')).not.toBeInTheDocument();
    expect(within(missingRow).getByText(/keyed by its SPI/)).toBeInTheDocument();
  });

  it('marks partially calculated features rather than hiding them', async () => {
    mockFeatureBackend({ vector: VECTOR });
    renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    const ike = await screen.findByRole('region', { name: /IKE Features/i });
    const row = within(ike).getByText('ike_payload_count').closest('tr')!;
    expect(within(row).getByText('10')).toBeInTheDocument();
    expect(within(row).getByText('PARTIAL')).toBeInTheDocument();
    expect(within(row).getByText(/floor/)).toBeInTheDocument();
  });

  it('reports source availability for lineage', async () => {
    mockFeatureBackend({ vector: VECTOR });
    renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    const panel = await screen.findByRole('region', { name: /Source Availability/i });
    expect(within(panel).getByText('Session record')).toBeInTheDocument();
    expect(within(panel).getByText(/capture is not loaded/)).toBeInTheDocument();
  });

  it('keeps the JSON view closed until it is requested', async () => {
    mockFeatureBackend({ vector: VECTOR });
    renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    const toggle = await screen.findByRole('button', { name: /View JSON/i });
    expect(screen.queryByText(/"feature_version": "1.0"/)).not.toBeInTheDocument();

    await userEvent.click(toggle);
    await waitFor(() => {
      expect(screen.getByText(/"feature_version": "1.0"/)).toBeInTheDocument();
    });
  });

  it('disables extraction until an entity is selected', async () => {
    mockFeatureBackend();
    renderAppAt('/feature-engineering');

    const button = await screen.findByRole('button', { name: /Extract features/i });
    expect(button).toBeDisabled();
  });

  it('shows no future intelligence anywhere on the page', async () => {
    mockFeatureBackend({ vector: VECTOR });
    const { container } = renderAppAt('/feature-engineering?entity_type=SESSION&entity_id=SESSION-1');

    await screen.findByRole('region', { name: /Feature Summary/i });
    const main = container.querySelector('#main-content')?.textContent?.toLowerCase() ?? '';
    for (const forbidden of ['anomaly score', 'risk score', 'drift score', 'baseline mean']) {
      expect(main).not.toContain(forbidden);
    }
  });
});
