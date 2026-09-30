import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { buildTree, ProtocolTree } from '@/components/packet-analysis';
import type { PacketAnalysisResult } from '@/types';
import fixture from './fixtures/packets.json';
import { HEALTH_FIXTURE, SYSTEM_STATUS_FIXTURE, renderAppAt } from './renderApp';

type Fixture = typeof fixture;
const details = fixture.details as Record<string, PacketAnalysisResult>;
const byProtocol = (protocol: string) => Object.values(details).find((d) => d.protocol === protocol)!;

/** Route-aware fetch stub driven by the real decoder fixture. */
function mockPacketBackend(opts: { loaded: boolean; failUpload?: { status: number; body: unknown } } = { loaded: true }) {
  let loaded = opts.loaded;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    if (url.includes('/api/health')) return json(HEALTH_FIXTURE);
    if (url.includes('/api/system/status')) return json(SYSTEM_STATUS_FIXTURE);
    if (url.endsWith('/api/packets/status')) return json(loaded ? fixture.status : fixture.empty_status);
    if (url.endsWith('/api/packets/upload') && method === 'POST') {
      if (opts.failUpload) return json(opts.failUpload.body, opts.failUpload.status);
      loaded = true;
      return json(fixture.status, 201);
    }
    if (url.endsWith('/api/packets/analyze')) return json(loaded ? fixture.status : { error: 'NO_PACKET_SOURCE', message: 'No capture is loaded to analyze.' }, loaded ? 200 : 409);
    if (url.endsWith('/api/packets') && method === 'DELETE') { loaded = false; return json(fixture.empty_status); }
    const detailMatch = url.match(/\/api\/packets\/([0-9a-f]{32})$/);
    if (detailMatch) return details[detailMatch[1]!] ? json(details[detailMatch[1]!]) : json({ error: 'PACKET_NOT_FOUND', message: 'No packet with that identifier is loaded.' }, 404);
    if (url.includes('/api/packets/protocol-analysis')) {
      return json({
        capture_id: loaded ? 'fixture.pcap' : 'empty',
        total_packets_analyzed: loaded ? 7 : 0,
        ike_summary: { total_ike_packets: loaded ? 2 : 0, versions_detected: ['IKEv2'], proposals: [], anomalies: [] },
        ipsec_streams: [],
        anomalies: [],
        endpoint_summary: [],
        generated_at: '2026-09-11T00:00:00Z',
      });
    }
    if (url.includes('/api/packets/anomalies')) return json([]);
    if (url.includes('/api/packets/streams')) return json([]);
    if (url.includes('/api/packets?')) {
      const params = new URL(url, 'http://localhost').searchParams;
      let items = (fixture.page as Fixture['page']).items;
      const protocol = params.get('protocol'); const ipsec = params.get('ipsec'); const search = params.get('search');
      if (protocol) items = items.filter((i) => i.protocol === protocol.toUpperCase());
      if (ipsec === 'NON-IPSEC') items = items.filter((i) => !i.ipsec_type);
      else if (ipsec) items = items.filter((i) => i.ipsec_type === ipsec.toUpperCase());
      if (search) items = items.filter((i) => [String(i.number), i.source, i.info].some((f) => f.toLowerCase().includes(search.toLowerCase())));
      if (params.get('sort') === 'length' && params.get('order') === 'desc') items = [...items].sort((a, b) => b.length - a.length);
      return json({ ...fixture.page, items, total: items.length, total_pages: 1 });
    }
    return json({ error: 'NOT_FOUND', message: 'unhandled' }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

async function renderPage() {
  renderAppAt('/packet-analysis');
  await screen.findByRole('heading', { level: 1, name: /^packet analysis$/i });
}

describe('packet analysis — empty analyzer', () => {
  beforeEach(() => mockPacketBackend({ loaded: false }));
  afterEach(() => vi.unstubAllGlobals());

  it('loads with the analyzer-ready status and the empty state', async () => {
    await renderPage();
    expect(await screen.findAllByText('ANALYZER READY')).not.toHaveLength(0);
    expect(screen.getByText(/no packets available/i)).toBeInTheDocument();
    expect(screen.getByText(/capture or load packet data to begin analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/no packet selected/i)).toBeInTheDocument();
  });

  it('shows N/A statistics and disables Analyze and Clear until a capture exists', async () => {
    await renderPage();
    await screen.findAllByText('ANALYZER READY');
    const stats = screen.getByRole('region', { name: /packet statistics/i });
    expect(within(stats).getAllByText('N/A')).toHaveLength(6);
    expect(within(stats).queryByText('0')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^analyze$/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /^clear$/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /upload capture/i })).toBeEnabled();
    expect(screen.getByPlaceholderText(/search packets/i)).toBeDisabled();
    expect(screen.getByText('NO DATA')).toBeInTheDocument();
  });

  it('renders no table and no fabricated rows', async () => {
    await renderPage();
    await screen.findAllByText('ANALYZER READY');
    expect(document.querySelectorAll('table')).toHaveLength(0);
    expect(document.body.textContent).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
  });

  it('uploads a capture and shows the decoded packets', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findAllByText('ANALYZER READY');
    const file = new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'fixture.pcap');
    await user.upload(screen.getByLabelText(/upload capture file/i), file);
    expect(await screen.findAllByText('ANALYSIS COMPLETED')).not.toHaveLength(0);
    expect(await screen.findAllByRole('row')).toHaveLength(8); // header + 7
  });
});

describe('packet analysis — loaded capture', () => {
  beforeEach(() => mockPacketBackend({ loaded: true }));
  afterEach(() => vi.unstubAllGlobals());

  it('renders the packet table from decoder output with the right columns', async () => {
    await renderPage();
    const table = await screen.findByRole('table', { name: /analysed packets/i });
    for (const header of ['#', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']) {
      expect(within(table).getByRole('columnheader', { name: new RegExp(`^${header.replace('#', '\\#')}`) })).toBeInTheDocument();
    }
    expect(within(table).getAllByRole('row')).toHaveLength(8);
    expect(within(table).getAllByText('192.0.2.10').length).toBeGreaterThan(0);
  });

  it('shows real protocol counts and statistics', async () => {
    await renderPage();
    await screen.findByRole('table');
    const stats = screen.getByRole('region', { name: /packet statistics/i });
    expect(within(stats).getByText('Total packets').nextElementSibling).toHaveTextContent('7');
    expect(within(stats).getByText('IPsec packets').nextElementSibling).toHaveTextContent('4');
    expect(within(stats).getByText('Malformed packets').nextElementSibling).toHaveTextContent('1');
    const summary = screen.getByRole('region', { name: /protocol summary/i });
    expect(within(summary).getByText('IKE', { selector: 'dt' }).parentElement).toHaveTextContent('2');
  });

  it('selects an IKE packet and shows header, payloads and tree', async () => {
    const user = userEvent.setup();
    await renderPage();
    const table = await screen.findByRole('table');
    await user.click(within(table).getAllByRole('row')[1]!);

    const dialog = await screen.findByRole('dialog', { name: /packet details/i });
    expect(within(dialog).getByText('IKE_SA_INIT (34)')).toBeInTheDocument();
    expect(within(dialog).getByText('0101010101010101')).toBeInTheDocument();
    for (const name of ['SA', 'KE', 'Nonce']) expect(within(dialog).getByText(name)).toBeInTheDocument();
    expect(within(dialog).getByText(/No — UDP\/500/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('tab', { name: /protocol tree/i }));
    const tree = within(dialog).getByRole('tree', { name: /protocol tree/i });
    expect(within(tree).getByText('IKEv2')).toBeInTheDocument();
    await user.click(within(tree).getByRole('button', { name: /expand payloads/i }));
    expect(within(tree).getByText('Payload 1: SA')).toBeInTheDocument();

    await user.click(within(dialog).getByRole('tab', { name: /raw/i }));
    expect(within(dialog).getByText(/^0000\s+02 00 00 00 00 02/)).toBeInTheDocument();
  });

  it('shows ESP as encrypted and NAT-T IKE as traversal', async () => {
    const user = userEvent.setup();
    await renderPage();
    const table = await screen.findByRole('table');
    await user.click(within(table).getAllByRole('row')[2]!);
    let dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('0xc0ffee01')).toBeInTheDocument();
    expect(within(dialog).getByText(/encrypted payload/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/not available for plaintext inspection/i)).toBeInTheDocument();

    await user.click(within(table).getAllByRole('row')[5]!);
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent(/IKE_AUTH/));
    dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText(/Yes — UDP\/4500/)).toBeInTheDocument();
    expect(within(dialog).getByText('SK (Encrypted)')).toBeInTheDocument();
    expect(within(table).getAllByText('NAT-T')).toHaveLength(1);
  });

  it('shows AH authentication data and TCP flags', async () => {
    const user = userEvent.setup();
    await renderPage();
    const table = await screen.findByRole('table');
    await user.click(within(table).getAllByRole('row')[3]!);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('0xabcd0001')).toBeInTheDocument();
    expect(within(dialog).getByText('12 bytes')).toBeInTheDocument();
    expect(within(dialog).getByText('Authenticated')).toBeInTheDocument();

    await user.click(within(table).getAllByRole('row')[4]!);
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent(/Transport layer — TCP/));
    expect(within(screen.getByRole('dialog')).getByText('SYN')).toBeInTheDocument();
  });

  it('reports a malformed packet without hiding it or labelling it a threat', async () => {
    const user = userEvent.setup();
    await renderPage();
    const table = await screen.findByRole('table');
    await user.click(within(table).getAllByRole('row')[7]!);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/^malformed packet$/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/IPv4 header needs 20 bytes/)).toBeInTheDocument();
    expect(within(dialog).getByText('IPv4')).toBeInTheDocument();
    expect(dialog.textContent).not.toMatch(/threat|attack|malicious|vulnerab|risk/i);
  });

  it('filters by protocol and searches by SPI', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByRole('table');
    await user.selectOptions(screen.getByLabelText(/^protocol$/i), 'ESP');
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2));

    await user.selectOptions(screen.getByLabelText(/^protocol$/i), '');
    await user.selectOptions(screen.getByLabelText(/ipsec type/i), 'NON-IPSEC');
    await waitFor(() => expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(4));
  });

  it('sorts by clicking a column header', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: /^length/i }));
    await waitFor(() => expect(screen.getByRole('columnheader', { name: /^length/i })).toHaveAttribute('aria-sort', 'ascending'));
    await user.click(screen.getByRole('button', { name: /^length/i }));
    await waitFor(() => expect(screen.getByRole('columnheader', { name: /^length/i })).toHaveAttribute('aria-sort', 'descending'));
  });

  it('clears the capture and returns to the empty state', async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: /^clear$/i }));
    expect(await screen.findByText(/no packets available/i)).toBeInTheDocument();
    expect(screen.getAllByText('ANALYZER READY').length).toBeGreaterThan(0);
  });

  it('is keyboard operable', async () => {
    const user = userEvent.setup();
    await renderPage();
    const table = await screen.findByRole('table');
    within(table).getAllByRole('row')[2]!.focus();
    await user.keyboard('{Enter}');
    expect(await screen.findByRole('dialog')).toHaveTextContent(/ESP/);
  });
});

describe('packet analysis — errors', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('shows a structured error for an unsupported capture format', async () => {
    mockPacketBackend({ loaded: false, failUpload: { status: 415, body: { error: 'CAPTURE_FORMAT_UNSUPPORTED', message: 'Only .pcap, .pcapng and .cap files are supported.' } } });
    // applyAccept off: simulate a user overriding the picker filter.
    const user = userEvent.setup({ applyAccept: false });
    await renderPage();
    await screen.findAllByText('ANALYZER READY');
    await user.upload(screen.getByLabelText(/upload capture file/i), new File(['x'], 'notes.txt'));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/capture format unsupported/i);
    expect(alert).not.toHaveTextContent(/Traceback|at .*\.py/);
  });

  it('shows the analysis service as unavailable when the backend is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    await renderPage();
    expect(await screen.findAllByText('ANALYSIS SERVICE UNAVAILABLE')).not.toHaveLength(0);
    expect(screen.getByRole('alert')).toHaveTextContent(/could not be reached/i);
    expect(screen.getByText(/no packets available/i)).toBeInTheDocument();
  });
});

describe('protocol tree builder', () => {
  it('produces nodes only for decoded layers', () => {
    const ike = byProtocol('IKE');
    const labels = buildTree(ike).children!.map((c) => c.label);
    expect(labels).toEqual(['Ethernet', 'IPv4', 'UDP', 'IKEv2']);
    const other = byProtocol('OTHER');
    expect(buildTree(other).children!.map((c) => c.label)).toEqual(['Ethernet']);
  });

  it('renders as an accessible tree', () => {
    render(<ProtocolTree packet={byProtocol('ESP')} />);
    expect(screen.getByRole('tree')).toBeInTheDocument();
    expect(screen.getByText('ESP')).toBeInTheDocument();
  });
});
