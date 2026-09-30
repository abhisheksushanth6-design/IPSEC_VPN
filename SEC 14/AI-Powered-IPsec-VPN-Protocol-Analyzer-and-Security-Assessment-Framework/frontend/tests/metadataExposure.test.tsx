import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { MetadataExposurePage } from '@/pages/MetadataExposure/MetadataExposurePage';
import { metadataExposureService } from '@/services/metadataExposureService';
import { sessionService } from '@/services/sessionService';
import type { MetadataExposureItem, MetadataExposureSummary } from '@/types';

vi.mock('@/services/metadataExposureService', () => ({
  metadataExposureService: {
    getCaptureAssessments: vi.fn(),
    getSummary: vi.fn(),
    getGlobalSummary: vi.fn(),
    getSessionAssessment: vi.fn(),
    evaluateCapture: vi.fn(),
  },
}));

vi.mock('@/services/sessionService', () => ({
  sessionService: {
    fetchStatus: vi.fn(),
  },
}));

const mockAssessmentItem: MetadataExposureItem = {
  id: 'EXP-TEST-001',
  capture_id: 'cap-eval-123',
  session_id: 'IPSEC-TEST-SESS-99',
  overall_score: 68.5,
  risk_level: 'HIGH',
  spi_leakage_score: 50.0,
  sequence_leakage_score: 75.0,
  packet_length_leakage_score: 80.0,
  timing_leakage_score: 85.0,
  topology_leakage_score: 20.0,
  findings: [
    {
      vector: 'Packet Length Leakage',
      severity: 'HIGH',
      description: 'Variable unpadded frames without RFC 4303 TFC padding.',
    },
  ],
  recommendations: ['Enable RFC 4303 Traffic Flow Confidentiality (TFC) padding.'],
  created_at: '2026-09-25T12:00:00Z',
};

const mockSummary: MetadataExposureSummary = {
  capture_id: 'cap-eval-123',
  average_score: 68.5,
  highest_risk_level: 'HIGH',
  total_assessed: 1,
  critical_count: 0,
  high_count: 1,
  medium_count: 0,
  low_count: 0,
  dominant_leakage_vector: 'Packet Length (TFC)',
};

describe('Layer 08 Metadata Exposure Assessment UI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders "No capture/session data available" and dash placeholders when no sessions exist', async () => {
    vi.mocked(sessionService.fetchStatus).mockResolvedValue({
      state: 'READY',
      packets_available: false,
      capture_id: null,
      capture_filename: null,
      discovered_at: null,
      statistics: null,
      inactivity_gap_seconds: 300,
      last_error: null,
    });
    vi.mocked(metadataExposureService.getCaptureAssessments).mockResolvedValue([]);
    vi.mocked(metadataExposureService.getSummary).mockResolvedValue({
      capture_id: 'default',
      average_score: 0.0,
      highest_risk_level: 'LOW',
      total_assessed: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      dominant_leakage_vector: 'None',
    });

    render(
      <MemoryRouter>
        <MetadataExposurePage />
      </MemoryRouter>
    );

    // Verify empty state is displayed
    await waitFor(() => {
      expect(screen.getByText('No capture/session data available')).toBeInTheDocument();
    });

    // Verify misleading 0 values are not shown for scores, dash placeholders are shown instead
    const dashes = screen.getAllByText('—');
    expect(dashes.length).toBeGreaterThanOrEqual(5);

    // Verify button exists
    expect(screen.getByRole('button', { name: /evaluate capture exposure/i })).toBeInTheDocument();
  });

  it('successfully evaluates capture exposure and populates session table and KPI cards', async () => {
    const user = userEvent.setup();

    vi.mocked(sessionService.fetchStatus).mockResolvedValue({
      state: 'AVAILABLE',
      packets_available: true,
      capture_id: 'cap-eval-123',
      capture_filename: 'demo.pcap',
      discovered_at: '2026-09-25T12:00:00Z',
      statistics: null,
      inactivity_gap_seconds: 300,
      last_error: null,
    });
    vi.mocked(metadataExposureService.getCaptureAssessments).mockResolvedValue([]);
    vi.mocked(metadataExposureService.getSummary).mockResolvedValue(null);

    // When Evaluate is clicked
    vi.mocked(metadataExposureService.evaluateCapture).mockResolvedValue([mockAssessmentItem]);
    vi.mocked(metadataExposureService.getSummary).mockResolvedValue(mockSummary);

    render(
      <MemoryRouter>
        <MetadataExposurePage />
      </MemoryRouter>
    );

    // Wait for initial load to finish
    await waitFor(() => {
      expect(screen.getByText('No capture/session data available')).toBeInTheDocument();
    });

    const evalBtn = screen.getByRole('button', { name: /evaluate capture exposure/i });
    await user.click(evalBtn);

    // Verify evaluateCapture was called
    expect(metadataExposureService.evaluateCapture).toHaveBeenCalled();

    // Verify table populated with discovered session
    await waitFor(() => {
      expect(screen.getByText('IPSEC-TEST-SESS-99')).toBeInTheDocument();
      expect(screen.getAllByText('HIGH').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('68.5').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/1 findings recorded/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /inspect/i })).toBeInTheDocument();
    });
  });

  it('displays backend error and prevents showing stale 47.0 score on evaluation failure', async () => {
    const user = userEvent.setup();

    vi.mocked(sessionService.fetchStatus).mockResolvedValue({
      state: 'AVAILABLE',
      packets_available: true,
      capture_id: 'default',
      capture_filename: null,
      discovered_at: null,
      statistics: null,
      inactivity_gap_seconds: 300,
      last_error: null,
    });
    vi.mocked(metadataExposureService.getCaptureAssessments).mockResolvedValue([]);
    // Mock a stale summary from a previous capture (47.0)
    vi.mocked(metadataExposureService.getSummary).mockResolvedValue({
      capture_id: 'default',
      average_score: 47.0,
      highest_risk_level: 'MEDIUM',
      total_assessed: 1,
      critical_count: 0,
      high_count: 0,
      medium_count: 1,
      low_count: 0,
      dominant_leakage_vector: 'Timing Cadence',
    });

    // Mock evaluation failure with backend error message
    vi.mocked(metadataExposureService.evaluateCapture).mockRejectedValue(
      new Error('Failed to evaluate metadata exposure: Method Not Allowed')
    );

    render(
      <MemoryRouter>
        <MetadataExposurePage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /evaluate capture exposure/i })).toBeInTheDocument();
    });

    const evalBtn = screen.getByRole('button', { name: /evaluate capture exposure/i });
    await user.click(evalBtn);

    // Verify actual backend error is displayed
    await waitFor(() => {
      expect(screen.getByText('Failed to evaluate metadata exposure: Method Not Allowed')).toBeInTheDocument();
    });

    // Verify stale 47.0 is NOT shown as a valid result in the KPI score
    expect(screen.queryByText('47.0')).not.toBeInTheDocument();
  });
});
