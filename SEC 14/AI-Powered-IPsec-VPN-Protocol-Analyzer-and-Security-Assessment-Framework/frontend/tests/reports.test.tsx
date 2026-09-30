import { describe, expect, it, beforeEach, vi } from 'vitest';
import { screen, waitFor, fireEvent } from '@testing-library/react';

import { mockBackendOnline, renderAppAt } from './renderApp';
import type { ReportMetadata } from '@/types';

const MOCK_REPORTS: ReportMetadata[] = [
  {
    id: 'REPORT-20260904-001',
    report_type: 'FULL',
    title: 'Enterprise Gateway Comprehensive Assessment',
    filename: 'ipsec-assessment-report-20260904-001.pdf',
    file_size_bytes: 45000,
    page_count: 5,
    status: 'COMPLETED',
    error_message: null,
    generated_at: '2026-09-04T10:30:00Z',
    download_url: '/api/reports/REPORT-20260904-001/download',
  },
  {
    id: 'REPORT-20260904-002',
    report_type: 'VULNERABILITY',
    title: 'Cryptographic Vulnerability Audit',
    filename: 'ipsec-assessment-report-20260904-002.pdf',
    file_size_bytes: 18500,
    page_count: 3,
    status: 'COMPLETED',
    error_message: null,
    generated_at: '2026-09-04T11:00:00Z',
    download_url: '/api/reports/REPORT-20260904-002/download',
  },
];

describe('Reports Page (Layer 14)', () => {
  beforeEach(() => {
    mockBackendOnline();
  });

  it('renders page header with operational status and evidence-based notice', async () => {
    renderAppAt('/reports');

    expect(
      await screen.findByRole('heading', { name: /Security Assessment Reports/i, level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText(/LAYER 14 OPERATIONAL/i)).toBeInTheDocument();

    // Verify evidence-based audit traceability notice
    expect(
      screen.getByText(/Evidence-Based Audit Traceability \(Layers 01–10\)/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/composite risk evaluations/i),
    ).toBeInTheDocument();
  });

  it('renders report generator options and scope controls', async () => {
    renderAppAt('/reports');

    expect(
      await screen.findByRole('heading', { name: /Generate Security Assessment Report/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Full Assessment/i)).toBeInTheDocument();
    expect(screen.getByText(/Session Deep-Dive/i)).toBeInTheDocument();
    expect(screen.getByText(/Security Assessment & Hardening/i)).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Generate Assessment Report/i }),
    ).toBeInTheDocument();
  });

  it('renders report history table when reports are returned', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('/api/reports')) {
          return new Response(JSON.stringify(MOCK_REPORTS), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );

    renderAppAt('/reports');

    expect(
      await screen.findByText('Enterprise Gateway Comprehensive Assessment'),
    ).toBeInTheDocument();
    expect(screen.getByText('Cryptographic Vulnerability Audit')).toBeInTheDocument();
    expect(screen.getByText('REPORT-20260904-001')).toBeInTheDocument();
    expect(screen.getByText('5 pages')).toBeInTheDocument();

    // Verify download links exist
    const downloadLinks = screen.getAllByTitle('Download PDF');
    expect(downloadLinks.length).toBe(2);
  });

  it('displays clean empty state when no reports have been generated', async () => {
    renderAppAt('/reports');

    expect(
      await screen.findByText(/No assessment reports found/i),
    ).toBeInTheDocument();
  });
});
