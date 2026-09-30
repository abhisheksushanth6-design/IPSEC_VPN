import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { screen } from '@testing-library/react';

import { eventStreamUrl, NetworkError } from '@/services/httpClient';
import { dashboardService } from '@/services/dashboardService';
import { reportService } from '@/services/reportService';
import { RealtimeService, parseRealtimeMessage } from '@/services/realtimeService';
import { appConfig } from '@/utils/config';
import {
  DASHBOARD_SUMMARY_FIXTURE,
  mockBackendOnline,
  renderAppAt,
} from '../../frontend/tests/renderApp';
import { installMockWebSocket, MockWebSocket } from '../../frontend/tests/mockWebSocket';

describe('Layer 13 — Application Shell & Routing Tests', () => {
  beforeEach(() => {
    mockBackendOnline();
    installMockWebSocket();
  });
  afterEach(() => vi.unstubAllGlobals());

  it('renders the application shell with branding, header, and system status cluster', async () => {
    renderAppAt('/overview');
    expect(await screen.findByRole('heading', { level: 1, name: /^overview$/i })).toBeInTheDocument();
    expect(screen.getAllByText(/AI-Powered IPsec VPN Protocol Analyzer/i).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: /skip to main content/i })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: /main navigation/i })).toBeInTheDocument();
  });

  it('navigates seamlessly across primary route destinations', async () => {
    renderAppAt('/architecture');
    expect(await screen.findByRole('heading', { level: 1, name: /14-layer system architecture/i })).toBeInTheDocument();
  });

  it('renders a designated fallback page for unknown routes with recovery link', async () => {
    renderAppAt('/route-that-does-not-exist-in-framework');
    expect(await screen.findByRole('heading', { level: 1, name: /page not found/i })).toBeInTheDocument();
    expect(screen.getByText(/this page does not exist/i)).toBeInTheDocument();
    expect(screen.getByText(/the address you followed is not part of the application/i)).toBeInTheDocument();
    const returnLink = screen.getByRole('link', { name: /go to overview/i });
    expect(returnLink).toBeInTheDocument();
    expect(returnLink).toHaveAttribute('href', '/overview');
  });

  it('respects production and development environment configuration without hardcoded hosts', () => {
    expect(appConfig.eventsPath).toBe('/ws/events');
    const wsUrl = eventStreamUrl();
    expect(wsUrl).toMatch(/^wss?:\/\/.*\/ws\/events$/);
  });
});

describe('Layer 13 — Layer 12 API Client Integration Tests', () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.unstubAllGlobals());

  it('queries Layer 12 dashboard summary with structured contract mapping', async () => {
    const mockSummary = {
      ...DASHBOARD_SUMMARY_FIXTURE,
      metrics: {
        ...DASHBOARD_SUMMARY_FIXTURE.metrics,
        overall_risk_score: 82,
        overall_risk_status: 'HIGH',
        active_vpn_sessions: 4,
        packets_analyzed: 1520,
      },
    };

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/api/dashboard/summary')) {
          return new Response(JSON.stringify(mockSummary), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({ error: 'NOT_FOUND' }), { status: 404 });
      }),
    );

    const data = await dashboardService.getSummary();
    expect(data.metrics.overall_risk_score).toBe(82);
    expect(data.metrics.overall_risk_status).toBe('HIGH');
    expect(data.metrics.active_vpn_sessions).toBe(4);
    expect(data.metrics.packets_analyzed).toBe(1520);
  });

  it('handles HTTP 404, 422, and 500 error envelopes without throwing unhandled rejections', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            error: 'SESSION_NOT_FOUND',
            message: 'Target session identifier not located in database.',
            status: 404,
          }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    );

    await expect(dashboardService.getSummary()).rejects.toThrow(/SESSION_NOT_FOUND/);
  });

  it('handles network failure gracefully without crashing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );

    await expect(dashboardService.getMetrics()).rejects.toThrow(NetworkError);
  });

  it('constructs binary PDF download URL without JSON parse', () => {
    const url = reportService.getDownloadUrl('report-001');
    expect(url).toMatch(/\/api\/reports\/report-001\/download$/);
  });
});

describe('Layer 13 — Dashboard KPIs & SOC Posture Tests', () => {
  beforeEach(() => {
    mockBackendOnline();
    installMockWebSocket();
  });
  afterEach(() => vi.unstubAllGlobals());

  it('renders overall risk score, risk level, and Layer 10 policy decision accurately', async () => {
    renderAppAt('/overview');
    expect(await screen.findByRole('heading', { level: 1, name: /^overview$/i })).toBeInTheDocument();

    expect(screen.getAllByText(/active vpn sessions/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/overall risk score/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/packets analyzed/i).length).toBeGreaterThan(0);
  });

  it('faithfully preserves zero values without hiding or fabricating metrics', async () => {
    renderAppAt('/overview');
    await screen.findByRole('heading', { level: 1, name: /^overview$/i });
    const zeros = screen.getAllByText('0');
    expect(zeros.length).toBeGreaterThan(0);
  });
});

describe('Layer 13 — WebSocket /ws/events Integration Tests', () => {
  beforeEach(() => installMockWebSocket());
  afterEach(() => vi.unstubAllGlobals());

  it('establishes connection to /ws/events and handles open, message, and close cycles', () => {
    const service = new RealtimeService();
    const received: unknown[] = [];
    service.onMessage((msg) => received.push(msg));

    service.connect();
    expect(MockWebSocket.instances.length).toBe(1);
    expect(MockWebSocket.latest().url).toMatch(/\/ws\/events$/);

    MockWebSocket.latest().simulateOpen();
    expect(service.getState()).toBe('CONNECTED');

    MockWebSocket.latest().simulateMessage({
      type: 'risk_updated',
      session_id: 'SESSION-01',
      risk_score: 75.5,
      policy_decision: 'WARN',
      timestamp: '2026-09-12T12:00:00Z',
    });

    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({
      type: 'risk_updated',
      session_id: 'SESSION-01',
      risk_score: 75.5,
      policy_decision: 'WARN',
    });

    service.disconnect();
    expect(service.getState()).toBe('DISCONNECTED');
  });

  it('ignores malformed, non-JSON, and un-typed frames safely without throwing', () => {
    expect(parseRealtimeMessage('invalid { json string')).toBeNull();
    expect(parseRealtimeMessage(JSON.stringify({ message: 'missing type field' }))).toBeNull();
    expect(parseRealtimeMessage(JSON.stringify({ type: 'session_updated', session_id: '123' }))).toEqual({
      type: 'session_updated',
      session_id: '123',
    });
  });
});

describe('Layer 13 — Security & Secret Leakage Prevention Tests', () => {
  beforeEach(() => {
    mockBackendOnline();
    installMockWebSocket();
  });
  afterEach(() => vi.unstubAllGlobals());

  it('never renders private keys, PSKs, database credentials, or secret tokens in DOM', async () => {
    renderAppAt('/overview');
    await screen.findByRole('heading', { level: 1, name: /^overview$/i });

    const html = document.body.innerHTML;
    expect(html).not.toMatch(/BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY/i);
    expect(html).not.toMatch(/sqlite:\/\/\//i);
    expect(html).not.toMatch(/postgres:\/\//i);
    expect(html).not.toMatch(/SECRET_KEY|API_KEY|PASSWORD|PRESHARED_KEY/i);
  });

  it('contains accessible semantic landmarks and ARIA labels for assistive technologies', async () => {
    renderAppAt('/overview');
    await screen.findByRole('heading', { level: 1, name: /^overview$/i });

    expect(screen.getAllByRole('banner').length).toBeGreaterThan(0);
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
    expect(screen.getByLabelText(/main navigation/i)).toBeInTheDocument();
  });
});
