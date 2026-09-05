import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SAStateBadge } from '@/components/sa-lifecycle';
import type { SAState, SecurityAssociation } from '@/types';
import fixture from './fixtures/sas.json';
import packetFixture from './fixtures/packets.json';
import { HEALTH_FIXTURE, SYSTEM_STATUS_FIXTURE, renderAppAt } from './renderApp';

const details = fixture.details as Record<string, SecurityAssociation>;
const ike = Object.values(details).find((d) => d.type === 'IKE')!;
const child = Object.values(details).find((d) => d.type === 'CHILD' && d.timeline.some((e) => e.event_type === 'CREATED AFTER REKEY'))!;

function mockSABackend(mode: 'empty' | 'ready' | 'active') {
  let state = mode;
  const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'Content-Type': 'application/json' } });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); const method = init?.method ?? 'GET';
    if (url.includes('/api/health')) return json(HEALTH_FIXTURE);
    if (url.includes('/api/system/status')) return json(SYSTEM_STATUS_FIXTURE);
    if (url.endsWith('/api/sas/status')) return json(state === 'empty' ? fixture.empty_status : state === 'ready' ? fixture.ready_status : fixture.active_status);
    if (url.endsWith('/api/sas/discover')) { if (state === 'empty') return json({ error: 'PACKET_DATA_UNAVAILABLE', message: 'No packet data is available.' }, 409); state = 'active'; return json(fixture.active_status); }
    if (url.endsWith('/api/sas') && method === 'DELETE') { state = 'ready'; return json(fixture.ready_status); }
    const d = url.match(/\/api\/sas\/(SA-[0-9A-F]{12})$/);
    if (d) return details[d[1]!] ? json(details[d[1]!]) : json({ error: 'SA_NOT_FOUND', message: 'No Security Association with that identifier exists.' }, 404);
    if (url.includes('/api/sas?')) {
      const p = new URL(url).searchParams; let items = fixture.page.items;
      if (p.get('type')) items = items.filter((i) => i.type === p.get('type'));
      if (p.get('state')) items = items.filter((i) => i.state === p.get('state'));
      if (p.get('search')) items = items.filter((i) => [i.id, i.spi ?? '', i.initiator_spi ?? ''].some((f) => f.toLowerCase().includes(p.get('search')!.toLowerCase())));
      if (p.get('sort') === 'packet_count' && p.get('order') === 'desc') items = [...items].sort((a, b) => b.packet_count - a.packet_count);
      return json({ ...fixture.page, items, total: items.length });
    }
    if (url.endsWith('/api/packets/status')) return json(packetFixture.status);
    const pd = url.match(/\/api\/packets\/([0-9a-f]{32})$/);
    if (pd) { const m = Object.values(packetFixture.details)[0]!; return json({ ...m, id: pd[1] }); }
    if (url.includes('/api/packets?')) return json(packetFixture.page);
    if (url.includes('/api/sessions/for-packet/')) return json({ packet_id: 'x', session_id: null, role: null });
    if (url.includes('/api/sas/for-packet/')) return json([]);
    return json({ error: 'NOT_FOUND', message: 'unhandled' }, 404);
  }));
}

async function renderPage(route = '/sa-lifecycle') {
  renderAppAt(route);
  await screen.findByRole('heading', { level: 1, name: /security state & sa lifecycle/i });
}

describe('sa lifecycle — no packet data', () => {
  beforeEach(() => mockSABackend('empty'));
  afterEach(() => vi.unstubAllGlobals());
  it('shows NOT INITIALIZED, empty state, and no fabricated rows', async () => {
    await renderPage();
    expect((await screen.findAllByText('NOT INITIALIZED')).length).toBeGreaterThan(0);
    expect(screen.getByText(/no security associations available/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /discover sas/i })).toBeDisabled();
    expect(within(screen.getByRole('article', { name: 'Total SAs' })).getByText('NO PACKET DATA')).toBeInTheDocument();
    expect(document.querySelectorAll('table')).toHaveLength(0);
    expect(document.body.textContent).not.toMatch(/SA-[0-9A-F]{12}/);
  });
});

describe('sa lifecycle — ready then discovered', () => {
  beforeEach(() => mockSABackend('ready'));
  afterEach(() => vi.unstubAllGlobals());
  it('discovers and lists SAs with counts from the engine', async () => {
    const user = userEvent.setup();
    await renderPage();
    expect(await screen.findAllByText('READY')).not.toHaveLength(0);
    await user.click(screen.getByRole('button', { name: /discover sas/i }));
    const table = await screen.findByRole('table', { name: /discovered security associations/i });
    expect(within(table).getAllByRole('row')).toHaveLength(4);
    expect(within(screen.getByRole('article', { name: 'IKE SAs' })).getByText('1')).toBeInTheDocument();
    expect(within(screen.getByRole('article', { name: 'Child SAs' })).getByText('2')).toBeInTheDocument();
    expect(within(screen.getByRole('article', { name: 'Terminated' })).getByText('1')).toBeInTheDocument();
  });
});

describe('sa lifecycle — discovered', () => {
  beforeEach(() => mockSABackend('active'));
  afterEach(() => vi.unstubAllGlobals());

  it('renders the required columns', async () => {
    await renderPage();
    const table = await screen.findByRole('table');
    for (const h of ['SA ID', 'Type', 'Start time', 'Last seen', 'Initiator', 'Responder', 'Protocol', 'State']) expect(within(table).getByRole('columnheader', { name: new RegExp(`^${h}`) })).toBeInTheDocument();
    expect(within(table).getByText(ike.id)).toBeInTheDocument();
    expect(within(table).getByText('TERMINATED')).toBeInTheDocument();
  });

  it('shows the IKE SA state card, lifecycle path, history and evidence-cited timeline', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(within(await screen.findByRole('table')).getByText(ike.id));
    const dialog = await screen.findByRole('dialog', { name: /sa details/i });
    expect(within(dialog).getByText('Current state').nextElementSibling).toHaveTextContent('TERMINATED');
    const path = within(dialog).getByRole('figure', { name: /lifecycle path/i });
    expect(within(path).getByText('TERMINATED')).toHaveAttribute('aria-current', 'step');
    expect(within(dialog).getByText(/These are observations of protocol state, not a security assessment/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('tab', { name: /timeline/i }));
    const history = within(dialog).getByRole('list', { name: /state history/i });
    expect(within(history).getAllByRole('listitem').map((li) => li.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('DETECTED'), expect.stringContaining('REKEYING'), expect.stringContaining('TERMINATED')]));
    const timeline = within(dialog).getByRole('list', { name: /lifecycle timeline/i });
    for (const ev of ['SA DETECTED', 'NEGOTIATION START', 'SA ESTABLISHED', 'IPSEC TRAFFIC OBSERVED', 'REKEY START', 'REKEY COMPLETE', 'DELETE OBSERVED']) expect(within(timeline).getByText(ev)).toBeInTheDocument();
    expect(within(timeline).getAllByText(/packet #\d+/).length).toBeGreaterThan(5);
  });

  it('shows IKE information, child SAs and NOT AVAILABLE security parameters', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(within(await screen.findByRole('table')).getByText(ike.id));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('tab', { name: /ike/i }));
    expect(within(dialog).getByText('IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL')).toBeInTheDocument();
    expect(within(dialog).getByText('SK (Encrypted)')).toBeInTheDocument();
    expect(within(dialog).getByText(/child sas \(2\)/i)).toBeInTheDocument();
    expect(within(dialog).getAllByText('NOT AVAILABLE').length).toBeGreaterThanOrEqual(6);
    expect(dialog.textContent).not.toMatch(/AES|SHA|HMAC|MODP/);

    await user.click(within(dialog).getByRole('button', { name: new RegExp(child.spi!) }));
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent(child.id));
    expect(within(screen.getByRole('dialog')).getByRole('heading', { name: /parent ike sa/i })).toBeInTheDocument();
    await user.click(within(screen.getByRole('dialog')).getByRole('tab', { name: /timeline/i }));
    expect(within(screen.getByRole('dialog')).getByText('CREATED AFTER REKEY')).toBeInTheDocument();
  });

  it('shows associated packets with SPI and navigates to Packet Analysis', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(within(await screen.findByRole('table')).getByText(ike.id));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('tab', { name: /packets/i }));
    const rows = within(dialog).getAllByRole('row');
    expect(rows).toHaveLength(ike.packets.length + 1);
    expect(within(dialog).getAllByText('0101010101010101').length).toBeGreaterThan(0);
    await user.click(rows[1]!);
    expect(await screen.findByRole('heading', { level: 1, name: /^packet analysis$/i })).toBeInTheDocument();
  });

  it('links to the associated session', async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(within(await screen.findByRole('table')).getByText(ike.id));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('link', { name: /view session/i })).toHaveAttribute('href', expect.stringContaining('/ipsec-sessions?session='));
  });

  it('deep-links via ?sa=', async () => {
    await renderPage(`/sa-lifecycle?sa=${child.id}`);
    expect(await screen.findByRole('dialog', { name: /sa details/i })).toHaveTextContent(child.id);
  });

  it('filters, searches, sorts', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByRole('table');
    await user.selectOptions(screen.getByLabelText(/^type$/i), 'CHILD');
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(3));
    await user.selectOptions(screen.getByLabelText(/^type$/i), '');
    await user.type(screen.getByPlaceholderText(/search security associations/i), '0x000000a2');
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2));
    await user.clear(screen.getByPlaceholderText(/search security associations/i));
    await user.click(screen.getByRole('button', { name: /^packets/i }));
    await waitFor(() => expect(screen.getByRole('columnheader', { name: /^packets/i })).toHaveAttribute('aria-sort', 'ascending'));
  });

  it('shows structured errors and the unreachable state', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    await renderPage();
    expect(await screen.findAllByText('SA SERVICE UNAVAILABLE')).not.toHaveLength(0);
    expect(screen.getAllByRole('alert')[0]).toHaveTextContent(/could not be reached/i);
    expect(screen.getByText(/no security associations available/i)).toBeInTheDocument();
  });
});

describe('sa helpers', () => {
  it('renders every state through the shared badge', () => {
    const states: SAState[] = ['UNKNOWN', 'DETECTED', 'NEGOTIATING', 'ESTABLISHED', 'ACTIVE', 'REKEYING', 'EXPIRED', 'TERMINATED', 'FAILED'];
    render(<>{states.map((s) => <SAStateBadge key={s} state={s} />)}</>);
    for (const s of states) expect(screen.getByText(s)).toBeInTheDocument();
  });
  it('fixture never claims security', () => {
    const text = JSON.stringify(fixture).toLowerCase();
    for (const w of ['secure', 'insecure', 'malicious', 'high risk', 'vulnerab', 'anomal']) expect(text).not.toContain(w);
  });
});
