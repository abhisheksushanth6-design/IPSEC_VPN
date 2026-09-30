import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { RealtimeService, parseRealtimeMessage } from '@/services';
import { REALTIME_RECONNECT } from '@/config/monitor';
import { appendBounded } from '@/utils/boundedBuffer';
import { installMockWebSocket, MockWebSocket } from './mockWebSocket';
import { mockBackendOffline, mockBackendOnline, renderAppAt } from './renderApp';

const METRIC_LABELS = [
  'Packets Captured',
  'Elapsed Duration',
  'PCAP Buffer Size',
  'Capture Target VM',
  'Security Events',
  'Anomalies',
];

async function renderMonitor() {
  renderAppAt('/live-monitor');
  await screen.findByRole('heading', { level: 1, name: /^live monitor$/i });
}

describe('live monitor page', () => {
  beforeEach(() => {
    mockBackendOnline();
    installMockWebSocket();
  });
  afterEach(() => vi.unstubAllGlobals());

  it('loads at /live-monitor with the correct header and banner', async () => {
    await renderMonitor();
    expect(screen.getByText('Live Capture Engine Ready')).toBeInTheDocument();
  });

  it('never claims live capture', async () => {
    await renderMonitor();
    const text = document.body.textContent ?? '';
    expect(text).not.toMatch(/CAPTURING ACTIVE/);
    expect(screen.queryByText(/^LIVE$/)).not.toBeInTheDocument();
  });

  it('renders the control bar with disabled capture controls and reasons', async () => {
    await renderMonitor();
    const group = screen.getByRole('group', { name: /monitor controls/i });
    const startBtn = within(group).getByRole('button', { name: /start capture/i });
    expect(startBtn).toBeDisabled();
    expect(within(group).getByRole('button', { name: /refresh/i })).toBeEnabled();
  });

  it('reports capture status, mode and an uninitialised interface selector', async () => {
    await renderMonitor();
    // Capture status readout sits next to its label in the control bar.
    const captureLabel = screen.getByText('Capture status');
    expect(within(captureLabel.parentElement as HTMLElement).getByText('IDLE')).toBeInTheDocument();
    expect(screen.getAllByText('DEMO').length).toBeGreaterThan(0);

    const select = screen.getByLabelText(/network interface/i);
    expect(select).toBeDisabled();
    expect(within(select).getAllByRole('option')).toHaveLength(1);
    expect(select).toHaveDisplayValue('NOT INITIALIZED');
  });

  it('renders the six metric cards as not initialised', async () => {
    await renderMonitor();
    for (const label of METRIC_LABELS) {
      const card = screen.getByRole('article', { name: label });
      expect(within(card).getByText('0')).toBeInTheDocument();
    }
  });

  it('renders every empty state and no fabricated rows', async () => {
    await renderMonitor();
    expect(screen.getByText(/no packets available/i)).toBeInTheDocument();
    expect(screen.getByText(/no packet frames currently in buffer/i)).toBeInTheDocument();
    expect(screen.getByText(/^no active sessions$/i)).toBeInTheDocument();
    expect(screen.getByText(/no active vpn sessions discovered/i)).toBeInTheDocument();
    expect(screen.getByText(/^no security associations$/i)).toBeInTheDocument();
    expect(screen.getByText(/no security associations observed/i)).toBeInTheDocument();
    expect(screen.getByText(/^no security events$/i)).toBeInTheDocument();
    expect(screen.getByText(/^no system activity$/i)).toBeInTheDocument();
    expect(screen.getAllByText('NO DATA AVAILABLE').length).toBeGreaterThan(0);

    expect(document.querySelectorAll('table')).toHaveLength(0);
    expect(document.querySelectorAll('.recharts-surface')).toHaveLength(0);
  });

  it('shows N/A for packet rate and bandwidth', async () => {
    await renderMonitor();
    const panel = screen.getByRole('region', { name: /ipsec traffic/i });
    expect(within(panel).getAllByText('N/A').length).toBeGreaterThanOrEqual(6);
    expect(within(panel).queryByText(/\d+ packets\/sec/)).not.toBeInTheDocument();
  });

  it('disables filters and search while no data exists', async () => {
    await renderMonitor();
    expect(screen.getByPlaceholderText(/search packets/i)).toBeDisabled();
    expect(screen.getByLabelText(/^protocol$/i)).toBeDisabled();
    expect(screen.getByText(/monitoring data unavailable/i)).toBeInTheDocument();
  });

  it('shows the three detail panels in their empty state', async () => {
    await renderMonitor();
    expect(screen.getByText(/no packet selected/i)).toBeInTheDocument();
    expect(screen.getByText(/no session selected/i)).toBeInTheDocument();
    expect(screen.getByText(/no security association selected/i)).toBeInTheDocument();
  });
});

describe('real-time connection on the live monitor', () => {
  beforeEach(() => {
    mockBackendOnline();
    installMockWebSocket();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('opens a socket to /ws/events and reports CONNECTING then CONNECTED', async () => {
    await renderMonitor();
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.latest().url).toMatch(/\/ws\/events$/);
    expect(await screen.findByText('CONNECTING')).toBeInTheDocument();

    act(() => MockWebSocket.latest().simulateOpen());
    expect(await screen.findByText('CONNECTED')).toBeInTheDocument();
    expect(screen.getByText(/no event sources publish yet/i)).toBeInTheDocument();
  });

  it('logs the real connection transition to system activity', async () => {
    await renderMonitor();
    act(() => MockWebSocket.latest().simulateOpen());
    const panel = await screen.findByRole('region', { name: /system activity/i });
    expect(within(panel).getByText('Realtime Connected')).toBeInTheDocument();
    expect(within(panel).getAllByRole('listitem')).toHaveLength(1);
  });

  it('moves to RECONNECTING when the server closes, then ERROR after the attempt cap', async () => {
    await renderMonitor();
    vi.useFakeTimers({ shouldAdvanceTime: true });

    act(() => MockWebSocket.latest().simulateOpen());
    await screen.findByText('CONNECTED');

    act(() => MockWebSocket.latest().simulateServerClose());
    expect(await screen.findByText('RECONNECTING')).toBeInTheDocument();

    for (let i = 0; i < REALTIME_RECONNECT.maxAttempts; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(REALTIME_RECONNECT.maxDelayMs);
      });
      act(() => MockWebSocket.latest().simulateServerClose());
    }

    expect(await screen.findByText('ERROR')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reconnect/i })).toBeInTheDocument();
    expect(MockWebSocket.instances.length).toBe(REALTIME_RECONNECT.maxAttempts + 1);
    vi.useRealTimers();
  });

  it('closes the socket when leaving the page', async () => {
    const user = userEvent.setup();
    await renderMonitor();
    const socket = MockWebSocket.latest();
    act(() => socket.simulateOpen());

    await user.click(screen.getByRole('link', { name: 'Overview' }));
    await waitFor(() => expect(socket.close).toHaveBeenCalled());
  });

  it('shows BACKEND OFFLINE in mode when the API is unreachable but still renders', async () => {
    mockBackendOffline();
    await renderMonitor();
    expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThan(0);
    expect(screen.getByText(/no packets available/i)).toBeInTheDocument();
  });
});

describe('realtime service unit behaviour', () => {
  beforeEach(() => installMockWebSocket());
  afterEach(() => vi.unstubAllGlobals());

  it('parses only typed JSON frames', () => {
    expect(parseRealtimeMessage('{"type":"x"}')).toEqual({ type: 'x' });
    expect(parseRealtimeMessage('{"noType":1}')).toBeNull();
    expect(parseRealtimeMessage('not json')).toBeNull();
  });

  it('delivers received frames to listeners and never invents any', () => {
    const service = new RealtimeService();
    const received: unknown[] = [];
    service.onMessage((m) => received.push(m));
    service.connect();
    const socket = MockWebSocket.latest();
    socket.simulateOpen();
    expect(received).toHaveLength(0);
    socket.simulateMessage({ type: 'connection.established', message: 'hello' });
    expect(received).toEqual([{ type: 'connection.established', message: 'hello' }]);
    service.disconnect();
    expect(service.getState()).toBe('DISCONNECTED');
  });

  it('appendBounded keeps buffers within the limit', () => {
    const out = appendBounded([1, 2, 3], [4, 5], 4);
    expect(out).toEqual([2, 3, 4, 5]);
    expect(appendBounded([1], [], 4)).toEqual([1]);
  });
});
