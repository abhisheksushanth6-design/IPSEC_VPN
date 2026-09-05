import { describe, expect, it, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { RiskGauge } from '@/components/dashboard/RiskGauge';
import { SecurityEventRow } from '@/components/dashboard/SecurityEventRow';
import { TrafficTimelineChart } from '@/components/dashboard/charts';
import { classifyRiskScore } from '@/config/risk';
import { mockBackendOffline, mockBackendOnline, renderAppAt } from './renderApp';

const CARD_LABELS = [
  'Overall Risk Score',
  'Active VPN Sessions',
  'Active Security Associations',
  'Packets Analyzed',
  'AI Anomalies',
  'Security Drift Events',
  'Critical Vulnerabilities',
  'Capture Status',
];

const CHART_TITLES = [
  'Traffic Timeline',
  'Risk Trend',
  'Protocol Distribution',
  'AI Anomalies Over Time',
  'Vulnerability Severity',
  'SA Lifecycle Activity',
];

describe('overview dashboard', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it('renders all eight KPI cards', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');
    for (const label of CARD_LABELS) {
      expect(screen.getByRole('article', { name: label })).toBeInTheDocument();
    }
  });

  it('renders all six charts as empty states with no drawn data', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');
    for (const title of CHART_TITLES) {
      const card = screen.getByRole('region', { name: title });
      expect(within(card).getByRole('status')).toBeInTheDocument();
    }
    // Recharts renders an SVG with class "recharts-surface" only when it draws.
    expect(document.querySelector('.recharts-surface')).toBeNull();
  });

  it('shows the risk gauge as NOT INITIALIZED with no numeric score', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');
    const riskPanel = screen.getByRole('region', { name: /^overall risk$/i });
    const gauge = within(riskPanel).getByRole('img', { name: /risk gauge/i });
    expect(gauge).toHaveAccessibleName(/not initialised/i);
    // Score and last-updated are both N/A; neither is a number.
    expect(within(riskPanel).getAllByText('N/A')).toHaveLength(2);
    expect(within(riskPanel).queryByText(/\d+ \/ 100/)).not.toBeInTheDocument();
  });

  it('reads backend, database and mode from the API in the system status panel', async () => {
    renderAppAt('/overview');
    const panel = await screen.findByRole('region', { name: /system status/i });
    expect(within(panel).getByText('BACKEND ONLINE')).toBeInTheDocument();
    expect(within(panel).getAllByText('FOUNDATION READY').length).toBeGreaterThanOrEqual(2);
    expect(within(panel).getByText('DEMO')).toBeInTheDocument();
    expect(within(panel).getAllByText('NOT INITIALIZED')).toHaveLength(2);
  });

  it('refetches status when refresh is pressed', async () => {
    const user = userEvent.setup();
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');

    const before = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
    await user.click(screen.getByRole('button', { name: /refresh/i }));
    await screen.findAllByText('FOUNDATION ONLINE');
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(before);
  });

  it('shows the empty event stream with no fabricated events', async () => {
    renderAppAt('/overview');
    const stream = await screen.findByRole('region', { name: /live security event stream/i });
    expect(within(stream).getByText(/no security events/i)).toBeInTheDocument();
    expect(within(stream).queryByRole('time')).not.toBeInTheDocument();
  });

  it('exposes quick navigation to the real routes', async () => {
    renderAppAt('/overview');
    const nav = await screen.findByRole('navigation', { name: /quick navigation/i });
    expect(within(nav).getByRole('link', { name: /reports/i })).toHaveAttribute('href', '/reports');
    expect(within(nav).getAllByRole('link')).toHaveLength(7);
  });

  it('never makes an unearned security claim', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');
    const body = document.body.textContent ?? '';
    for (const claim of [
      /no attacks detected/i,
      /network is safe/i,
      /traffic is normal/i,
      /vpn is secure/i,
      /CAPTURING/,
      /MONITORING/,
    ]) {
      expect(body).not.toMatch(claim);
    }
  });
});

describe('overview dashboard with backend offline', () => {
  it('reports BACKEND OFFLINE and keeps the dashboard rendered', async () => {
    mockBackendOffline();
    renderAppAt('/overview');

    const panel = await screen.findByRole('region', { name: /system status/i });
    expect(within(panel).getByText('BACKEND OFFLINE')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/unable to connect/i);

    for (const label of CARD_LABELS) {
      expect(screen.getByRole('article', { name: label })).toBeInTheDocument();
    }
  });
});

describe('risk classification', () => {
  it('maps scores to the locked bands', () => {
    expect(classifyRiskScore(0)).toBe('SAFE');
    expect(classifyRiskScore(20)).toBe('SAFE');
    expect(classifyRiskScore(21)).toBe('LOW');
    expect(classifyRiskScore(40)).toBe('LOW');
    expect(classifyRiskScore(41)).toBe('MODERATE');
    expect(classifyRiskScore(60)).toBe('MODERATE');
    expect(classifyRiskScore(61)).toBe('HIGH');
    expect(classifyRiskScore(80)).toBe('HIGH');
    expect(classifyRiskScore(81)).toBe('CRITICAL');
    expect(classifyRiskScore(100)).toBe('CRITICAL');
  });

  it('rejects out-of-range scores', () => {
    expect(classifyRiskScore(-1)).toBeNull();
    expect(classifyRiskScore(101)).toBeNull();
    expect(classifyRiskScore(Number.NaN)).toBeNull();
  });
});

describe('dashboard components accept future data', () => {
  it('RiskGauge renders a supplied score and its classification', () => {
    render(<RiskGauge riskScore={73} />);
    expect(screen.getByRole('img')).toHaveAccessibleName(/73 of 100, classified HIGH/);
    expect(screen.getByText('73')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
  });

  it('SecurityEventRow renders only what it is given', () => {
    render(
      <MemoryRouter>
        <ul>
          <SecurityEventRow
            event={{
              id: 'evt-1',
              timestamp: '2026-01-01T00:00:00Z',
              type: 'SA Established',
              severity: 'INFO',
              source: 'test-fixture',
              description: 'fixture description',
            }}
          />
        </ul>
      </MemoryRouter>,
    );
    expect(screen.getByText('SA Established')).toBeInTheDocument();
    expect(screen.getByText('fixture description')).toBeInTheDocument();
    expect(screen.getByRole('time')).toHaveAttribute('dateTime', '2026-01-01T00:00:00Z');
  });

  it('charts distinguish "not initialised" from "ran and found nothing"', () => {
    const { rerender } = render(<TrafficTimelineChart data={null} />);
    expect(screen.getByRole('status')).toHaveTextContent('NO DATA AVAILABLE');

    rerender(<TrafficTimelineChart data={[]} />);
    expect(screen.getByRole('status')).toHaveTextContent('NO TRAFFIC RECORDED');
  });
});

describe('Section 13 Web Dashboard widgets and live posture', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it('renders the executive posture banner with strict Layer 10 uninitialized notice', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');

    const postureBanner = screen.getByRole('region', { name: /executive security posture/i });
    expect(postureBanner).toBeInTheDocument();
    expect(within(postureBanner).getByText(/framework security & analytical posture/i)).toBeInTheDocument();
    expect(within(postureBanner).getByText(/layer 10 \(risk assessment & decision engine\)/i)).toBeInTheDocument();
    expect(within(postureBanner).getByText(/not initialized/i)).toBeInTheDocument();
  });

  it('renders all four analytical layer summary cards', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');

    expect(screen.getByRole('article', { name: 'Security Vulnerabilities' })).toBeInTheDocument();
    expect(screen.getByRole('article', { name: 'AI / ML Anomalies' })).toBeInTheDocument();
    expect(screen.getByRole('article', { name: 'Security Drift' })).toBeInTheDocument();
    expect(screen.getByRole('article', { name: 'SA Lifecycles' })).toBeInTheDocument();
  });

  it('renders recent session activity table and protocol posture with clean empty states', async () => {
    renderAppAt('/overview');
    await screen.findAllByText('FOUNDATION ONLINE');

    const sessionSection = screen.getByRole('region', { name: /recent session activity/i });
    expect(within(sessionSection).getByText(/no ipsec sessions discovered yet/i)).toBeInTheDocument();

    const protoArticle = screen.getByRole('article', { name: /cryptographic & protocol posture/i });
    expect(within(protoArticle).getByText(/no cryptographic sessions recorded yet/i)).toBeInTheDocument();
  });
});
