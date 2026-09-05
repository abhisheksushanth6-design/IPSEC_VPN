import { describe, expect, it, beforeEach } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { buildArchitectureLayers, summarizeProgress } from '@/config/architecture';
import { NAVIGATION_ITEMS } from '@/config/navigation';
import { ARCHITECTURE_LAYERS_FIXTURE, LOCKED_LAYERS, mockBackendOffline, mockBackendOnline, renderAppAt } from './renderApp';

async function renderArchitecture() {
  renderAppAt('/architecture');
  await screen.findByRole('list', { name: /14-layer processing pipeline/i });
}

describe('architecture route and navigation', () => {
  beforeEach(() => mockBackendOnline());

  it('is reachable at /architecture with the correct header', async () => {
    await renderArchitecture();
    expect(screen.getByRole('heading', { level: 1, name: /14-layer system architecture/i })).toBeInTheDocument();
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

describe('exact 14-layer validation', () => {
  beforeEach(() => mockBackendOnline());

  it('renders exactly fourteen layer cards', async () => {
    await renderArchitecture();
    const cards = screen.getAllByRole('button', { name: /^Layer \d{2}: / });
    expect(cards).toHaveLength(14);
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
    expect(new Set(names).size).toBe(14);
    for (const [, name] of LOCKED_LAYERS) {
      expect(screen.getAllByText(name).length).toBeGreaterThanOrEqual(1);
    }
  });

  it('groups layers into the five categories without changing order', async () => {
    await renderArchitecture();
    for (const category of [
      'DATA GENERATION & COLLECTION',
      'PROTOCOL & SECURITY ANALYSIS',
      'INTELLIGENCE & DETECTION',
      'PLATFORM FOUNDATION',
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
    expect(foundation).toHaveAttribute('aria-valuenow', '6');
    expect(foundation).toHaveAttribute('aria-valuemax', '14');

    const implemented = screen.getByRole('progressbar', { name: /fully implemented/i });
    expect(implemented).toHaveAttribute('aria-valuenow', '0');
  });

  it('summarizeProgress responds to metadata changes', () => {
    const layers = buildArchitectureLayers(ARCHITECTURE_LAYERS_FIXTURE)!;
    expect(summarizeProgress(layers)).toEqual({ foundation: 6, implemented: 0, total: 14 });

    const altered = buildArchitectureLayers(
      ARCHITECTURE_LAYERS_FIXTURE.map((l) => (l.number === 12 ? { ...l, status: 'OPERATIONAL' as const } : l)),
    )!;
    expect(summarizeProgress(altered)).toEqual({ foundation: 6, implemented: 1, total: 14 });
  });

  it('shows the three-entry legend', async () => {
    await renderArchitecture();
    const legend = screen.getByLabelText(/status legend/i);
    expect(within(legend).getByText('NOT INITIALIZED')).toBeInTheDocument();
    expect(within(legend).getByText('FOUNDATION CREATED')).toBeInTheDocument();
    expect(within(legend).getByText('FOUNDATION READY')).toBeInTheDocument();
  });
});

describe('layer detail interaction', () => {
  beforeEach(() => mockBackendOnline());

  it('opens a detail panel with purpose, inputs and outputs when a card is clicked', async () => {
    const user = userEvent.setup();
    await renderArchitecture();

    await user.click(screen.getByRole('button', { name: 'Layer 08: AI / ML Anomaly Detection Engine' }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'AI / ML Anomaly Detection Engine' })).toBeInTheDocument();
    expect(within(dialog).getByText('NOT INITIALIZED')).toBeInTheDocument();
    expect(within(dialog).getByText('Feature vectors')).toBeInTheDocument();
    expect(within(dialog).getByText('Anomaly score')).toBeInTheDocument();
    expect(within(dialog).getByText('Module not implemented yet.')).toBeInTheDocument();
    expect(within(dialog).getByText('MODULE NOT INITIALIZED')).toBeInTheDocument();
    expect(within(dialog).queryByRole('link', { name: /view module/i })).not.toBeInTheDocument();
  });

  it('offers a module link only where a foundation and a route exist', async () => {
    const user = userEvent.setup();
    await renderArchitecture();

    await user.click(screen.getByRole('button', { name: 'Layer 14: Report Generation (PDF)' }));
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
    expect(within(navigator).getAllByRole('link')).toHaveLength(14);

    await user.click(within(navigator).getByRole('link', { name: /^Layer 11:/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Security Databases (SQLite)' })).toBeInTheDocument();
  });
});

describe('unavailable and invalid architecture data', () => {
  it('shows ARCHITECTURE DATA UNAVAILABLE when the backend is offline', async () => {
    mockBackendOffline();
    renderAppAt('/architecture');
    expect(await screen.findByText('ARCHITECTURE DATA UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /architecture data unavailable/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: /14-layer processing pipeline/i })).not.toBeInTheDocument();
  });

  it('rejects a payload with the wrong number of layers', async () => {
    mockBackendOnline({ architecture_layers: ARCHITECTURE_LAYERS_FIXTURE.slice(0, 13) });
    renderAppAt('/architecture');
    expect(await screen.findByText('ARCHITECTURE DATA UNAVAILABLE')).toBeInTheDocument();
  });

  it('buildArchitectureLayers rejects invalid statuses, gaps and empties', () => {
    expect(buildArchitectureLayers(null)).toBeNull();
    expect(buildArchitectureLayers([])).toBeNull();
    expect(
      buildArchitectureLayers(ARCHITECTURE_LAYERS_FIXTURE.map((l) => (l.number === 5 ? { ...l, status: 'BOGUS' as never } : l))),
    ).toBeNull();
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
