import { describe, expect, it, beforeEach } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  analyzeLayerStatus,
  buildArchitectureLayers,
  normalizeLayerStatus,
  summarizeProgress,
} from '@/config/architecture';
import { NAVIGATION_ITEMS } from '@/config/navigation';
import { ARCHITECTURE_LAYERS_FIXTURE, LOCKED_LAYERS, mockBackendOffline, mockBackendOnline, renderAppAt } from './renderApp';

async function renderArchitecture() {
  renderAppAt('/architecture');
  await screen.findByRole('list', { name: /10-layer processing pipeline/i });
}

describe('architecture route and navigation', () => {
  beforeEach(() => mockBackendOnline());

  it('is reachable at /architecture with the correct header', async () => {
    await renderArchitecture();
    expect(screen.getByRole('heading', { level: 1, name: /10-layer system architecture/i })).toBeInTheDocument();
    expect(screen.getByText('ARCHITECTURE DEFINED')).toBeInTheDocument();
  });

  it('has a sidebar entry next to Overview', async () => {
    await renderArchitecture();
    const nav = screen.getByRole('navigation', { name: /main navigation/i });
    const link = within(nav).getByRole('link', { name: 'Architecture' });
    expect(link).toHaveAttribute('href', '/architecture');
    expect(link).toHaveAttribute('aria-current', 'page');

    const labels = NAVIGATION_ITEMS.map((i) => i.label);
    expect(labels.indexOf('Architecture')).toBe(labels.indexOf('Overview') + 1);
    expect(labels.filter((l) => l === 'Architecture')).toHaveLength(1);
  });

  it('links back to Overview', async () => {
    await renderArchitecture();
    expect(screen.getByRole('link', { name: /back to overview/i })).toHaveAttribute('href', '/overview');
  });
});

describe('exact 10-layer validation', () => {
  beforeEach(() => mockBackendOnline());

  it('renders exactly ten layer cards', async () => {
    await renderArchitecture();
    const cards = screen.getAllByRole('button', { name: /^Layer \d{2}: / });
    expect(cards).toHaveLength(10);
  });

  it('renders every layer with the exact name, number, order and status', async () => {
    await renderArchitecture();
    const cards = screen.getAllByRole('button', { name: /^Layer \d{2}: / });

    cards.forEach((card, index) => {
      const [number, name, , status] = LOCKED_LAYERS[index]!;
      const padded = String(number).padStart(2, '0');
      expect(card).toHaveAccessibleName(`Layer ${padded}: ${name}`);
      expect(within(card).getByText(name)).toBeInTheDocument();
      expect(within(card).getByText(padded)).toBeInTheDocument();
      expect(within(card).getByText(status)).toBeInTheDocument();
    });
  });

  it('has no duplicated or renamed layers', async () => {
    await renderArchitecture();
    const names = screen.getAllByRole('button', { name: /^Layer \d{2}: / }).map((c) => c.getAttribute('aria-labelledby'));
    expect(new Set(names).size).toBe(10);
    for (const [, name] of LOCKED_LAYERS) {
      expect(screen.getAllByText(name).length).toBeGreaterThanOrEqual(1);
    }
  });

  it('groups layers into the five categories without changing order', async () => {
    await renderArchitecture();
    for (const category of [
      'DATA GENERATION & COLLECTION',
      'PROTOCOL & SESSION ANALYSIS',
      'FEATURE & FINGERPRINTING',
      'AI CLASSIFICATION & ASSESSMENT',
      'PRESENTATION & REPORTING',
    ]) {
      expect(screen.getByRole('heading', { level: 3, name: category })).toBeInTheDocument();
    }
  });
});

describe('progress and legend', () => {
  beforeEach(() => mockBackendOnline());

  it('derives progress from metadata rather than hard-coding it', async () => {
    await renderArchitecture();
    const foundation = screen.getByRole('progressbar', { name: /foundation components available/i });
    expect(foundation).toHaveAttribute('aria-valuenow', '10');
    expect(foundation).toHaveAttribute('aria-valuemax', '10');

    const implemented = screen.getByRole('progressbar', { name: /fully implemented/i });
    expect(implemented).toHaveAttribute('aria-valuenow', '9');
  });

  it('summarizeProgress responds to metadata changes', () => {
    const layers = buildArchitectureLayers(ARCHITECTURE_LAYERS_FIXTURE)!;
    expect(summarizeProgress(layers)).toEqual({ foundation: 10, implemented: 9, total: 10 });

    const altered = buildArchitectureLayers(
      ARCHITECTURE_LAYERS_FIXTURE.map((l) => (l.number === 1 ? { ...l, status: 'OPERATIONAL' as const } : l)),
    )!;
    expect(summarizeProgress(altered)).toEqual({ foundation: 10, implemented: 10, total: 10 });
  });

  it('shows the legend with statuses', async () => {
    await renderArchitecture();
    const legend = screen.getByLabelText(/status legend/i);
    expect(within(legend).getByText('OPERATIONAL')).toBeInTheDocument();
  });
});

describe('layer detail interaction', () => {
  beforeEach(() => mockBackendOnline());

  it('opens a detail panel with purpose, inputs and outputs when a card is clicked', async () => {
    const user = userEvent.setup();
    await renderArchitecture();

    await user.click(screen.getByRole('button', { name: 'Layer 08: Security Assessment Engine' }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Security Assessment Engine' })).toBeInTheDocument();
    expect(within(dialog).getByText('OPERATIONAL')).toBeInTheDocument();
  });

  it('offers a module link only where a foundation and a route exist', async () => {
    const user = userEvent.setup();
    await renderArchitecture();

    await user.click(screen.getByRole('button', { name: 'Layer 10: Dashboard & Report Generation' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('link', { name: /view module/i })).toHaveAttribute('href', '/reports');
  });

  it('closes with Escape and the close button', async () => {
    const user = userEvent.setup();
    await renderArchitecture();

    await user.click(screen.getByRole('button', { name: 'Layer 03: Packet & Protocol Analysis' }));
    await screen.findByRole('dialog');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: 'Layer 03: Packet & Protocol Analysis' }));
    await user.click(await screen.findByRole('button', { name: /close layer detail/i }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('navigator selects a layer', async () => {
    const user = userEvent.setup();
    await renderArchitecture();

    const navigator = screen.getByRole('navigation', { name: /architecture navigator/i });
    expect(within(navigator).getAllByRole('link')).toHaveLength(10);

    await user.click(within(navigator).getByRole('link', { name: /^Layer 08:/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Security Assessment Engine' })).toBeInTheDocument();
  });
});

describe('unavailable and invalid architecture data', () => {
  it('shows ARCHITECTURE DATA UNAVAILABLE when the backend is offline', async () => {
    mockBackendOffline();
    renderAppAt('/architecture');
    expect(await screen.findByText('ARCHITECTURE DATA UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /architecture data unavailable/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: /10-layer processing pipeline/i })).not.toBeInTheDocument();
  });

  it('rejects a payload with the wrong number of layers', async () => {
    mockBackendOnline({ architecture_layers: ARCHITECTURE_LAYERS_FIXTURE.slice(0, 9) });
    renderAppAt('/architecture');
    expect(await screen.findByText('ARCHITECTURE DATA UNAVAILABLE')).toBeInTheDocument();
  });

  it('buildArchitectureLayers handles unknown statuses safely and rejects gaps and empties', () => {
    expect(buildArchitectureLayers(null)).toBeNull();
    expect(buildArchitectureLayers([])).toBeNull();
    // Unknown status is safely normalized to NOT INITIALIZED without dropping the list
    const withBogus = buildArchitectureLayers(
      ARCHITECTURE_LAYERS_FIXTURE.map((l) => (l.number === 5 ? { ...l, status: 'BOGUS' as never } : l)),
    );
    expect(withBogus).not.toBeNull();
    expect(withBogus?.find((l) => l.number === 5)?.status).toBe('NOT INITIALIZED');

    // Structural gap (invalid number) must be rejected
    expect(
      buildArchitectureLayers(ARCHITECTURE_LAYERS_FIXTURE.map((l) => (l.number === 5 ? { ...l, number: 99 } : l))),
    ).toBeNull();
  });
});

describe('no runtime security data', () => {
  it('page contains no counts, scores or events', async () => {
    mockBackendOnline();
    await renderArchitecture();
    const text = document.body.textContent ?? '';
    for (const claim of [/packets? analyzed/i, /risk score:?\s*\d/i, /anomal(y|ies) detected/i, /CAPTURING/, /\d+ sessions?/i]) {
      expect(text).not.toMatch(claim);
    }
  });
});

describe('authoritative status normalization and progress calculation (Requirements 1-8)', () => {
  // Requirement 1: All 10 layers operational → 10 / 10
  it('displays 10 / 10 when all 10 layers are operational in production', async () => {
    const allOperational = ARCHITECTURE_LAYERS_FIXTURE.map((layer) => ({
      ...layer,
      status: 'OPERATIONAL' as const,
      overall_status: 'FULLY_OPERATIONAL',
      foundation_available: true,
      implementation_available: true,
      runtime_verified: true,
    }));

    mockBackendOnline({
      architecture_layers: allOperational,
      application_mode: 'PRODUCTION',
    });

    await renderArchitecture();

    const foundation = screen.getByRole('progressbar', { name: /foundation components available/i });
    expect(foundation).toHaveAttribute('aria-valuenow', '10');
    expect(foundation).toHaveAttribute('aria-valuemax', '10');

    const implemented = screen.getByRole('progressbar', { name: /fully implemented/i });
    expect(implemented).toHaveAttribute('aria-valuenow', '10');
    expect(implemented).toHaveAttribute('aria-valuemax', '10');

    expect(screen.getAllByText('10 / 10').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Live Backend Data')).toBeInTheDocument();
  });

  // Requirement 2: Mixed operational and foundation-only statuses
  it('correctly calculates mixed operational and foundation-only statuses', () => {
    const mixedLayers = ARCHITECTURE_LAYERS_FIXTURE.map((l, idx) => {
      if (idx < 5) {
        return {
          ...l,
          status: 'OPERATIONAL' as const,
          overall_status: 'FULLY_OPERATIONAL',
          foundation_available: true,
          implementation_available: true,
        };
      }
      if (idx < 9) {
        return {
          ...l,
          status: 'FOUNDATION READY' as const,
          foundation_available: true,
          implementation_available: false,
        };
      }
      return {
        ...l,
        status: 'NOT INITIALIZED' as const,
        foundation_available: false,
        implementation_available: false,
      };
    });

    const parsed = buildArchitectureLayers(mixedLayers)!;
    expect(parsed).not.toBeNull();
    const progress = summarizeProgress(parsed);
    expect(progress).toEqual({ foundation: 9, implemented: 5, total: 10 });
  });

  // Requirement 3: NOT_INITIALIZED layers are excluded from the implemented count
  it('strictly excludes NOT_INITIALIZED layers from the implemented count', () => {
    const analysisWithFoundation = analyzeLayerStatus({
      status: 'NOT INITIALIZED',
      foundation_available: true,
      implementation_available: true,
    });
    expect(analysisWithFoundation.isFullyImplemented).toBe(false);
    expect(analysisWithFoundation.normalizedStatus).toBe('NOT INITIALIZED');
    expect(analysisWithFoundation.hasFoundation).toBe(true);

    const analysisSnakeCase = analyzeLayerStatus({
      status: 'NOT_INITIALIZED' as any,
    });
    expect(analysisSnakeCase.isFullyImplemented).toBe(false);
    expect(analysisSnakeCase.normalizedStatus).toBe('NOT INITIALIZED');
  });

  // Requirement 4: Unknown or missing statuses are handled safely
  it('safely handles unknown or missing statuses without crashing', () => {
    const unknownStatus = analyzeLayerStatus({ status: 'CORRUPTED_OR_UNKNOWN' as any });
    expect(unknownStatus.isFullyImplemented).toBe(false);
    expect(unknownStatus.normalizedStatus).toBe('NOT INITIALIZED');

    const missingStatus = analyzeLayerStatus({ status: undefined, overall_status: undefined });
    expect(missingStatus.isFullyImplemented).toBe(false);
    expect(missingStatus.normalizedStatus).toBe('NOT INITIALIZED');

    const withUnknown = buildArchitectureLayers(
      ARCHITECTURE_LAYERS_FIXTURE.map((l) => (l.number === 3 ? { ...l, status: 'UNKNOWN_CUSTOM' as any } : l)),
    );
    expect(withUnknown).not.toBeNull();
    expect(withUnknown?.length).toBe(10);
    expect(withUnknown?.find((l) => l.number === 3)?.status).toBe('NOT INITIALIZED');
  });

  // Requirement 5: Backend status values are normalized correctly
  it('normalizes various backend statuses correctly', () => {
    expect(analyzeLayerStatus({ status: 'OPERATIONAL' })).toMatchObject({
      normalizedStatus: 'OPERATIONAL',
      isFullyImplemented: true,
      hasFoundation: true,
    });

    expect(analyzeLayerStatus({ status: 'FULLY_OPERATIONAL' as any })).toMatchObject({
      normalizedStatus: 'OPERATIONAL',
      isFullyImplemented: true,
      hasFoundation: true,
    });

    expect(analyzeLayerStatus({ status: 'READY', implementation_available: true })).toMatchObject({
      normalizedStatus: 'OPERATIONAL',
      isFullyImplemented: true,
    });

    expect(analyzeLayerStatus({ status: 'READY', overall_status: 'FULLY_OPERATIONAL' })).toMatchObject({
      normalizedStatus: 'OPERATIONAL',
      isFullyImplemented: true,
    });

    expect(analyzeLayerStatus({ status: 'READY', implementation_available: false })).toMatchObject({
      normalizedStatus: 'READY',
      isFullyImplemented: false,
      hasFoundation: true,
    });

    expect(analyzeLayerStatus({ status: 'FOUNDATION_READY' as any })).toMatchObject({
      normalizedStatus: 'FOUNDATION READY',
      isFullyImplemented: false,
      hasFoundation: true,
    });

    expect(analyzeLayerStatus({ status: 'FOUNDATION_CREATED' as any })).toMatchObject({
      normalizedStatus: 'FOUNDATION CREATED',
      isFullyImplemented: false,
      hasFoundation: true,
    });

    expect(analyzeLayerStatus({ status: 'ERROR' as any })).toMatchObject({
      normalizedStatus: 'NOT INITIALIZED',
      isFullyImplemented: false,
      tone: 'danger',
    });
  });

  // Requirement 6: Architecture page counters match rendered layer-card statuses
  it('ensures layer cards and summary counters cannot disagree', async () => {
    const allOperational = ARCHITECTURE_LAYERS_FIXTURE.map((layer) => ({
      ...layer,
      status: 'OPERATIONAL' as const,
      overall_status: 'FULLY_OPERATIONAL',
      foundation_available: true,
      implementation_available: true,
    }));

    mockBackendOnline({
      architecture_layers: allOperational,
      application_mode: 'LIVE',
    });

    await renderArchitecture();

    const implementedProgress = screen.getByRole('progressbar', { name: /fully implemented/i });
    const implementedCount = Number(implementedProgress.getAttribute('aria-valuenow'));

    const cards = screen.getAllByRole('button', { name: /^Layer \d{2}: / });
    const operationalCards = cards.filter((card) => within(card).queryByText('OPERATIONAL') !== null);

    expect(operationalCards.length).toBe(implementedCount);
    expect(operationalCards.length).toBe(10);
  });

  // Requirement 7: Backend unavailable / error response
  it('renders a safe fallback error state when the backend is unavailable', async () => {
    mockBackendOffline();
    renderAppAt('/architecture');

    expect(await screen.findByText('ARCHITECTURE DATA UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText('Backend Offline')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /architecture data unavailable/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.queryByRole('progressbar', { name: /fully implemented/i })).not.toBeInTheDocument();
  });

  // Requirement 8: Fallback/mock data does not falsely claim production readiness
  it('shows demo / fallback data badge and does not falsely claim full readiness when in DEMO mode', async () => {
    mockBackendOnline();
    await renderArchitecture();

    expect(screen.getByText('Fallback / Demo Data')).toBeInTheDocument();
    const implemented = screen.getByRole('progressbar', { name: /fully implemented/i });
    expect(screen.getByText('9 / 10')).toBeInTheDocument();
    expect(screen.getAllByText('10 / 10')).toHaveLength(1);
  });
});
