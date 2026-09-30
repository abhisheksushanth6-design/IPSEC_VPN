import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import { formatSessionTime, formatTimeOnly, parseSessionDate } from '@/components/ipsec-sessions';
import { AISecurityAnalysisPanel } from '@/components/risk-assessment/AISecurityAnalysisPanel';
import { SARow } from '@/components/sa-lifecycle/SARow';
import type { AISecurityAnalysisReport, SecurityAssociationSummary } from '@/types';

describe('SA Lifecycle timestamp conversion', () => {
  it('converts relative PCAP timestamps so 1970-01-01 does not appear', () => {
    const pcapRelativeTs = '1970-01-01T01:18:57.612152+00:00';
    const formatted = formatSessionTime(pcapRelativeTs);
    expect(formatted).not.toContain('1970-01-01');
    expect(formatted).toBe('01:18:57.612 UTC');
  });

  it('converts another relative PCAP timestamp correctly', () => {
    const pcapRelativeTs = '1970-01-01T00:32:36.269765+00:00';
    const formatted = formatSessionTime(pcapRelativeTs);
    expect(formatted).not.toContain('1970-01-01');
    expect(formatted).toBe('00:32:36.269 UTC');
  });

  it('converts numeric epoch timestamps in seconds to real UTC date string', () => {
    // 1789068117 corresponds to 2026-09-10T19:21:57Z
    const formatted = formatSessionTime('1789068117');
    expect(formatted).not.toContain('1970');
    expect(formatted).toBe('2026-09-10 19:21:57.000 UTC');
  });

  it('preserves valid calendar dates for absolute timestamps', () => {
    const absoluteTs = '2023-11-14T22:13:20.000000+00:00';
    const formatted = formatSessionTime(absoluteTs);
    expect(formatted).toBe('2023-11-14 22:13:20.000 UTC');
  });

  it('handles null and empty timestamps gracefully', () => {
    expect(formatSessionTime(null)).toBe('—');
    expect(formatSessionTime('')).toBe('—');
    expect(formatTimeOnly(null)).toBe('—');
    expect(formatTimeOnly('')).toBe('—');
  });

  it('extracts time-only without date prefix for state history and packet list', () => {
    expect(formatTimeOnly('1970-01-01T01:18:57.612152+00:00')).toBe('01:18:57.612');
    expect(formatTimeOnly('2023-11-14T22:13:20.000000+00:00')).toBe('22:13:20.000');
  });

  it('renders SARow with relative PCAP timestamps without displaying 1970-01-01', () => {
    const mockSA: SecurityAssociationSummary = {
      id: 'SA-DE3CD93A8FFF',
      type: 'IKE',
      state: 'ACTIVE',
      protocol: 'IKE',
      initiator: '192.168.56.104',
      responder: '192.168.56.20',
      ike_version: '2.0',
      initiator_spi: '5a1d54c5e252bd81',
      responder_spi: '446b2ca427dfe396',
      spi: null,
      start_time: '1970-01-01T01:18:57.612152+00:00',
      last_seen: '1970-01-01T01:18:57.839518+00:00',
      duration_seconds: 0.227366,
      packet_count: 6,
      byte_count: 2860,
      nat_traversal: true,
      parent_sa_id: null,
      association: 'DIRECT',
      rekey_count: 0,
      session_id: 'IPSEC-F3B75BD79056',
    };

    render(
      <MemoryRouter>
        <table>
          <tbody>
            <SARow sa={mockSA} selected={false} onSelect={() => {}} />
          </tbody>
        </table>
      </MemoryRouter>
    );

    expect(screen.getByText('01:18:57.612 UTC')).toBeInTheDocument();
    expect(screen.getByText('01:18:57.839 UTC')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('1970-01-01');
  });
});

describe('AI finding score formatting', () => {
  const mockReport: AISecurityAnalysisReport = {
    analysis_id: 'AI-TEST-01',
    timestamp: '2026-09-12T10:00:00Z',
    status: 'READY',
    provider_used: 'MOCK_DETERMINISTIC',
    executive_summary: {
      overview: 'Test overview',
      risk_level: 'HIGH',
      key_strengths: [],
      critical_vulnerabilities: [],
      immediate_actions: [],
      business_impact: 'Low',
      risk_score_summary: '78/100',
    },
    prioritized_findings: [
      {
        finding_id: 'SEC-001',
        title: 'DES Cipher Suite Deprecated',
        original_severity: 'CRITICAL',
        priority_rank: 'P1_CRITICAL',
        urgency: 'IMMEDIATE',
        justification: 'Vulnerable to key recovery attacks.',
        exploitability_score: 9.2, // 9.2 on 0-10 scale -> 92/100
        affected_session: 'SESS-01',
        affected_tunnel: 'TUN-01',
        evidence: {},
        cve_references: ['CVE-2016-2183'],
      },
      {
        finding_id: 'SEC-002',
        title: 'Diffie-Hellman Group 2 Insecure',
        original_severity: 'MEDIUM',
        priority_rank: 'P3_MEDIUM',
        urgency: 'SCHEDULED',
        justification: 'Insufficient key length.',
        exploitability_score: 5.2, // 5.2 on 0-10 scale -> 52/100
        affected_session: 'SESS-02',
        affected_tunnel: 'TUN-02',
        evidence: {},
        cve_references: [],
      },
      {
        finding_id: 'SEC-003',
        title: 'Pre-scaled Finding Score Test',
        original_severity: 'HIGH',
        priority_rank: 'P2_HIGH',
        urgency: 'SCHEDULED',
        justification: 'Finding score already out of 100.',
        exploitability_score: 76, // 76 on 0-100 scale -> 76/100
        affected_session: null,
        affected_tunnel: null,
        evidence: {},
        cve_references: [],
      },
    ],
    attack_implications: [],
    remediation_roadmap: [],
    technical_summary: {
      protocol_posture: 'ADEQUATE',
      crypto_assessment: 'NEEDS_UPGRADE',
      session_integrity: 'SECURE',
      attack_surface_analysis: 'MINIMAL',
      recommendations_count: 3,
    },
    overall_risk_score: 78,
  };

  it('formats scores such as 92 and 52 as 92/100 and 52/100, never as 92/10 or 52/10', async () => {
    const { aiAnalysisService } = await import('@/services');
    vi.spyOn(aiAnalysisService, 'getAnalysis').mockResolvedValue(mockReport);

    render(<AISecurityAnalysisPanel />);

    // Wait for the Prioritized Findings tab button to render
    const tab = await screen.findByRole('button', { name: /prioritized findings/i });
    tab.click();

    // Verify correct /100 denominator and formatted scores
    expect(await screen.findByText('Score: 92/100')).toBeInTheDocument();
    expect(screen.getByText('Score: 52/100')).toBeInTheDocument();
    expect(screen.getByText('Score: 76/100')).toBeInTheDocument();

    // Verify broken /10 format is nowhere in the document
    expect(document.body.textContent).not.toMatch(/\b92\/10\b/);
    expect(document.body.textContent).not.toMatch(/\b52\/10\b/);
    expect(document.body.textContent).not.toMatch(/\b76\/10\b/);
  });
});
