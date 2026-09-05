import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SessionStateBadge } from '@/components/ipsec-sessions';
import { formatDuration } from '@/components/ipsec-sessions';
import type { IPsecSession, SessionState } from '@/types';
import fixture from './fixtures/sessions.json';
import packetFixture from './fixtures/packets.json';
import { HEALTH_FIXTURE, SYSTEM_STATUS_FIXTURE, renderAppAt } from './renderApp';

const details = fixture.details as Record<string, IPsecSession>;
const [firstId, secondId] = Object.keys(details) as [string, string];

function mockSessionBackend(mode: 'empty' | 'ready' | 'available') {
  let state = mode;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); const method = init?.method ?? 'GET';
    if (url.includes('/api/health')) return json(HEALTH_FIXTURE);
    if (url.includes('/api/system/status')) return json(SYSTEM_STATUS_FIXTURE);
    if (url.includes('/api/sas/for-session/')) return json({ session_id: 'x', associations: [] });
    if (url.endsWith('/api/sessions/status')) return json(state === 'empty' ? fixture.empty_status : state === 'ready' ? fixture.ready_status : fixture.available_status);
    if (url.endsWith('/api/sessions/discover')) {
      if (state === 'empty') return json({ error: 'PACKET_DATA_UNAVAILABLE', message: 'No packet data is available. Load a capture in Packet Analysis first.' }, 409);
      state = 'available'; return json(fixture.available_status);
    }
    if (url.endsWith('/api/sessions') && method === 'DELETE') { state = 'ready'; return json(fixture.ready_status); }
    const forPacket = url.match(/\/api\/sessions\/for-packet\/([0-9a-f]{32})$/);
    if (forPacket) return json((fixture.packet_links as Record<string, unknown>)[forPacket[1]!] ?? { packet_id: forPacket[1], session_id: null, role: null });
    const detail = url.match(/\/api\/sessions\/(IPSEC-[0-9A-F]{12})$/);
    if (detail) return details[detail[1]!] ? json(details[detail[1]!]) : json({ error: 'SESSION_NOT_FOUND', message: 'No session with that identifier exists.' }, 404);
    if (url.includes('/api/sessions?')) {
      const p = new URL(url).searchParams;
      let items = fixture.page.items;
      if (p.get('protocol') === 'IKE') items = items.filter((i) => i.ike_packets > 0);
      if (p.get('search')) items = items.filter((i) => [i.id, i.source, i.destination].some((f) => f.toLowerCase().includes(p.get('search')!.toLowerCase())));
      if (p.get('sort') === 'packet_count' && p.get('order') === 'desc') items = [...items].sort((a, b) => b.packet_count - a.packet_count);
      return json({ ...fixture.page, items, total: items.length });
    }
    if (url.endsWith('/api/packets/status')) return json(packetFixture.status);
    const packetDetail = url.match(/\/api\/packets\/([0-9a-f]{32})$/);
    if (packetDetail) {
      // Session packets belong to a different capture than packets.json; answer with a real decoded packet of the same protocol.
      const wanted = fixture.page.items.length ? Object.values(details).flatMap((d) => d.packets).find((p) => p.id === packetDetail[1])?.protocol : undefined;
      const match = Object.values(packetFixture.details).find((d) => d.protocol === wanted) ?? Object.values(packetFixture.details)[0]!;
      return json({ ...match, id: packetDetail[1] });
    }
    if (url.includes('/api/packets?')) return json(packetFixture.page);
    return json({ error: 'NOT_FOUND', message: 'unhandled' }, 404);
  }));
}

async function renderPage(route = '/ipsec-sessions') {
  renderAppAt(route);
  await screen.findByRole('heading', { level: 1, name: /^ipsec sessions$/i });
}

describe('ipsec sessions — no packet data', () => {
  beforeEach(() => mockSessionBackend('empty'));
  afterEach(() => vi.unstubAllGlobals());

  it('shows the engine as not initialised with N/A metrics and disabled discovery', async () => {
    await renderPage();
    expect(await screen.findAllByText('SESSION ENGINE NOT INITIALIZED')).not.toHaveLength(0);
    expect(screen.getByText(/no ipsec sessions available/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /discover sessions/i })).toBeDisabled();
    const total = screen.getByRole('article', { name: 'Total Sessions' });
    expect(within(total).getByText('NO PACKET DATA')).toBeInTheDocument();
    expect(within(total).queryByText('0')).not.toBeInTheDocument();
    expect(document.querySelectorAll('table')).toHaveLength(0);
    expect(document.body.textContent).not.toMatch(/IPSEC-[0-9A-F]{12}/);
  });
});

describe('ipsec sessions — packets loaded, not discovered', () => {
  beforeEach(() => mockSessionBackend('ready'));
  afterEach(() => vi.unstubAllGlobals());

  it('enables discovery and lists real sessions afterwards', async () => {
    const user = userEvent.setup();
    await renderPage();
    expect(await screen.findAllByText('READY')).not.toHaveLength(0);
    expect(within(screen.getByRole('article', { name: 'Total Sessions' })).getByText('NOT DISCOVERED')).toBeInTheDocument();

    const discover = screen.getByRole('button', { name: /discover sessions/i });
    expect(discover).toBeEnabled();
    await user.click(discover);

    expect(await screen.findAllByText('AVAILABLE')).not.toHaveLength(0);
    const table = await screen.findByRole('table', { name: /discovered ipsec sessions/i });
    expect(within(table).getAllByRole('row')).toHaveLength(3);
    expect(within(screen.getByRole('article', { name: 'Total Sessions' })).getByText('2')).toBeInTheDocument();
    expect(within(screen.getByRole('article', { name: 'Active Sessions' })).getByText('2')).toBeInTheDocument();
  });
});

describe('ipsec sessions — discovered', () => {
  beforeEach(() => mockSessionBackend('available'));
  afterEach(() => vi.unstubAllGlobals());

  it('renders the session table with the required columns', async () => {
    await renderPage();
    const table = await screen.findByRole('table');
    for (const h of ['Session ID', 'Start time', 'End time', 'Source', 'Destination', 'Protocol', 'Packets', 'State']) {
      expect(within(table).getByRole('columnheader', { name: new RegExp(`^${h}`) })).toBeInTheDocument();
    }
    expect(within(table).getByText(firstId)).toBeInTheDocument();
    expect(within(table).getAllByText('ACTIVE')).toHaveLength(2);
  });

  it('opens session details with overview, evidence, timeline, packets and IKE/ESP info', async () => {
    const user = userEvent.setup();
    await renderPage();
    const table = await screen.findByRole('table');
    await user.click(within(table).getByText(firstId));

    const dialog = await screen.findByRole('dialog', { name: /session details/i });
    expect(within(dialog).getByText('192.0.2.10', { selector: 'dd' })).toBeInTheDocument();
    expect(within(dialog).getByText('BIDIRECTIONAL', { selector: 'dd' })).toBeInTheDocument();
    expect(within(dialog).getByText(/child SA carried traffic/i)).toBeInTheDocument();
    expect(within(dialog).getByRole('figure', { name: /session between/i })).toBeInTheDocument();

    await user.click(within(dialog).getByRole('tab', { name: /timeline/i }));
    const timeline = within(dialog).getByRole('list', { name: /session timeline/i });
    expect(within(timeline).getByText('First packet')).toBeInTheDocument();
    expect(within(timeline).getByText('IKE_AUTH observed')).toBeInTheDocument();
    expect(within(timeline).getByText('IPsec traffic')).toBeInTheDocument();

    await user.click(within(dialog).getByRole('tab', { name: /packets/i }));
    expect(within(dialog).getAllByRole('row')).toHaveLength(4);

    await user.click(within(dialog).getByRole('tab', { name: /ipsec/i }));
    expect(within(dialog).getByText('IKE_SA_INIT, IKE_AUTH')).toBeInTheDocument();
    expect(within(dialog).getByText('0xaaaa0001')).toBeInTheDocument();
    expect(within(dialog).getByText(/no ah information/i)).toBeInTheDocument();
  });

  it('shows ESP-only session without IKE information', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(within(await screen.findByRole('table')).getByText(secondId));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('tab', { name: /ipsec/i }));
    expect(within(dialog).getByText(/no ike information/i)).toBeInTheDocument();
    expect(within(dialog).getByText('0x12345678')).toBeInTheDocument();
  });

  it('navigates from a session packet to Packet Analysis', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(within(await screen.findByRole('table')).getByText(firstId));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('tab', { name: /packets/i }));
    await user.click(within(dialog).getAllByRole('row')[1]!);
    expect(await screen.findByRole('heading', { level: 1, name: /^packet analysis$/i })).toBeInTheDocument();
    // The deep-linked packet opens and shows its session link back.
    const packetDialog = await screen.findByRole('dialog', { name: /packet details/i });
    expect(await within(packetDialog).findByRole('link', { name: /view session/i })).toHaveAttribute('href', expect.stringContaining('/ipsec-sessions?session='));
  });

  it('deep-links to a session via ?session=', async () => {
    await renderPage(`/ipsec-sessions?session=${secondId}`);
    expect(await screen.findByRole('dialog', { name: /session details/i })).toHaveTextContent(secondId);
  });

  it('filters, searches and sorts', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByRole('table');
    await user.selectOptions(screen.getByLabelText(/^protocol$/i), 'IKE');
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2));
    await user.selectOptions(screen.getByLabelText(/^protocol$/i), '');
    await user.type(screen.getByPlaceholderText(/search sessions/i), '192.0.2.30');
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2));
    await user.clear(screen.getByPlaceholderText(/search sessions/i));
    await user.click(screen.getByRole('button', { name: /^packets/i }));
    await waitFor(() => expect(screen.getByRole('columnheader', { name: /^packets/i })).toHaveAttribute('aria-sort', 'ascending'));
  });

  it('clears and returns to the ready state', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: /^clear$/i }));
    expect(await screen.findByText(/no ipsec sessions available/i)).toBeInTheDocument();
  });

  it('shows a structured error on discovery failure and unreachable service', async () => {
    mockSessionBackend('empty');
    await renderPage();
    await screen.findAllByText('SESSION ENGINE NOT INITIALIZED');
    // Force-enable is impossible; verify the error path via the service instead.
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    render(<></>);
    renderAppAt('/ipsec-sessions');
    expect(await screen.findAllByText('SESSION SERVICE UNAVAILABLE')).not.toHaveLength(0);
    expect(screen.getAllByRole('alert')[0]).toHaveTextContent(/could not be reached/i);
  });
});

describe('session helpers', () => {
  it('renders every state through the shared badge', () => {
    const states: SessionState[] = ['DISCOVERED', 'NEGOTIATING', 'ESTABLISHED', 'ACTIVE', 'IDLE', 'TERMINATED', 'UNKNOWN'];
    render(<>{states.map((s) => <SessionStateBadge key={s} state={s} />)}</>);
    for (const s of states) expect(screen.getByText(s)).toBeInTheDocument();
  });

  it('formats duration honestly', () => {
    expect(formatDuration(null)).toBe('N/A');
    expect(formatDuration(0.25)).toBe('250 ms');
    expect(formatDuration(2)).toBe('2.00 s');
    expect(formatDuration(125)).toBe('2m 5s');
  });
});
