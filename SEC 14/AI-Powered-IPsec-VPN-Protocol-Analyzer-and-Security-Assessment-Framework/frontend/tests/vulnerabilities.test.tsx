import { describe, expect, it, beforeEach, vi } from 'vitest';
import { screen, waitFor, fireEvent } from '@testing-library/react';
import { renderAppAt, HEALTH_FIXTURE, SYSTEM_STATUS_FIXTURE } from './renderApp';

const MOCK_RULE = {
  id: 'RULE-CRYPTO-001',
  category: 'CRYPTO' as const,
  name: 'Weak / Deprecated Encryption Algorithm',
  severity: 'CRITICAL' as const,
  confidence: 1.0,
  description: 'Detects deprecated ciphers like 3DES, DES, or Blowfish violating RFC 8221.',
  remediation: 'Migrate to AES-GCM-256 or ChaCha20-Poly1305.',
  cve_references: ['RFC 8221', 'NIST SP 800-77 Rev. 1'],
  enabled: true,
  version: '1.0.0',
  author: 'Framework Security Engine',
};

const MOCK_EVIDENCE = [
  {
    id: 1,
    finding_id: 1,
    evidence_source: 'SA' as const,
    source_id: 'sa-test-spi-001',
    field_name: 'encryption_algorithm',
    observed_value: '3DES-CBC',
    expected_value: 'AES-GCM-256 / ChaCha20-Poly1305',
    rule_criterion: 'RFC 8221 Section 4: 3DES is MUST NOT',
    timestamp: '2026-09-04T00:00:00Z',
  },
];

const MOCK_FINDING = {
  id: 1,
  rule_id: 'RULE-CRYPTO-001',
  category: 'CRYPTO' as const,
  severity: 'CRITICAL' as const,
  confidence: 1.0,
  title: 'Weak Encryption Cipher 3DES-CBC in Active SA',
  description: 'Security Association sa-test-spi-001 was negotiated with 3DES-CBC cipher.',
  affected_object_type: 'SecurityAssociation',
  affected_object_id: 'sa-test-spi-001',
  remediation: 'Update peer configuration to require AES-GCM-256.',
  cve_references: ['RFC 8221', 'CVE-2016-2183'],
  status: 'OPEN' as const,
  status_note: null,
  dedup_hash: 'dedup-hash-crypto-001-sa-001',
  recurrence_count: 3,
  first_detected_at: '2026-09-04T00:00:00Z',
  last_detected_at: '2026-09-04T01:00:00Z',
  resolved_at: null,
  evidence: MOCK_EVIDENCE,
};

const MOCK_STATS = {
  total_rules: 16,
  enabled_rules: 16,
  total_findings: 1,
  open_findings: 1,
  confirmed_findings: 0,
  resolved_findings: 0,
  suppressed_findings: 0,
  false_positive_findings: 0,
  by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 },
  by_category: { CRYPTO: 1, IKE: 0, AUTH: 0, PROTOCOL: 0, SA_LIFECYCLE: 0, CONFIGURATION: 0 },
  by_affected_type: { SecurityAssociation: 1 },
};

const MOCK_STATUS = {
  layer_number: 9,
  layer_name: 'Security Rule & Vulnerability Engine',
  status: 'OPERATIONAL',
  total_rules: 16,
  enabled_rules: 16,
  total_findings: 1,
  open_findings: 1,
  categories: ['CRYPTO', 'IKE', 'AUTH', 'PROTOCOL', 'SA_LIFECYCLE', 'CONFIGURATION'],
};

function mockVulnerabilityBackend(options: {
  findings?: any[];
  rules?: any[];
  stats?: any;
  status?: any;
} = {}) {
  const findings = options.findings ?? [MOCK_FINDING];
  const rules = options.rules ?? [MOCK_RULE];
  const stats = options.stats ?? MOCK_STATS;
  const status = options.status ?? MOCK_STATUS;

  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const json = (body: unknown, init?: ResponseInit) =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          ...init,
        });

      if (url.includes('/api/health')) return json(HEALTH_FIXTURE);
      if (url.includes('/api/system/status')) return json(SYSTEM_STATUS_FIXTURE);
      if (url.includes('/api/vulnerabilities/status')) return json(status);
      if (url.includes('/api/vulnerabilities/stats')) return json(stats);
      if (url.includes('/api/vulnerabilities/rules/RULE-CRYPTO-001/disable')) {
        return json({ ...MOCK_RULE, enabled: false });
      }
      if (url.includes('/api/vulnerabilities/rules/RULE-CRYPTO-001/enable')) {
        return json({ ...MOCK_RULE, enabled: true });
      }
      if (url.includes('/api/vulnerabilities/rules/')) return json(rules[0]);
      if (url.includes('/api/vulnerabilities/rules')) return json(rules);
      if (url.includes('/api/vulnerabilities/findings/1/status')) {
        return json({ ...MOCK_FINDING, status: 'CONFIRMED' });
      }
      if (url.includes('/api/vulnerabilities/findings/1')) return json(findings[0]);
      if (url.includes('/api/vulnerabilities/findings')) return json(findings);
      if (url.includes('/api/vulnerabilities/analyze')) {
        return json({
          evaluated_rules: 16,
          new_findings: 0,
          updated_findings: 1,
          total_active_findings: 1,
          duration_ms: 12.5,
          findings: findings,
        });
      }

      return json(SYSTEM_STATUS_FIXTURE);
    }),
  );
}

describe('Security Rule & Vulnerability Engine (Layer 09)', () => {
  beforeEach(() => {
    mockVulnerabilityBackend();
  });

  it('renders the Vulnerabilities page at /vulnerabilities with header and KPIs', async () => {
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(
        screen.getByRole('heading', { name: /Security Assessment Findings/i }),
      ).toBeInTheDocument();
    });

    // Check KPIs
    expect(screen.getByText(/Active Vulnerabilities/i)).toBeInTheDocument();
    expect(screen.getByText(/Active Rule Engine/i)).toBeInTheDocument();
    expect(screen.getByText(/Resolved & Suppressed/i)).toBeInTheDocument();
    expect(screen.getByText(/Deduplication Engine/i)).toBeInTheDocument();

    // Check Tab triggers
    expect(screen.getByRole('button', { name: /Security Assessment Findings/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Security Rule Catalog/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Architecture & Lineage/i })).toBeInTheDocument();
  });

  it('displays vulnerability findings in the table with recurrence and inspect button', async () => {
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(screen.getByText('RULE-CRYPTO-001')).toBeInTheDocument();
      expect(screen.getByText('Weak Encryption Cipher 3DES-CBC in Active SA')).toBeInTheDocument();
      expect(screen.getByText('3×')).toBeInTheDocument(); // Recurrence count
    });
  });

  it('opens FindingDetailModal when clicking Inspect', async () => {
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(screen.getByText('RULE-CRYPTO-001')).toBeInTheDocument();
    });

    const row = screen.getByText('Weak Encryption Cipher 3DES-CBC in Active SA');
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText(/Vulnerability Details/i)).toBeInTheDocument();
      expect(screen.getByText(/RFC & Security Standard Remediation/i)).toBeInTheDocument();
      expect(screen.getByText(/SOC Analyst Triage Workflow/i)).toBeInTheDocument();
    });
  });

  it('navigates to Security Rule Catalog and displays rules', async () => {
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Security Rule Catalog/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Security Rule Catalog/i }));

    await waitFor(() => {
      expect(screen.getByText(/Weak \/ Deprecated Encryption Algorithm/i)).toBeInTheDocument();
      expect(screen.getByText(/Rule Catalog \(1\/1\)/i)).toBeInTheDocument();
    });
  });

  it('navigates to Architecture & Lineage tab', async () => {
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Architecture & Lineage/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Architecture & Lineage/i }));

    await waitFor(() => {
      expect(screen.getByText(/Layer 08 Architecture & Upstream Pipeline Lineage/i)).toBeInTheDocument();
      expect(screen.getByText(/L08 • Security Assessment Engine/i)).toBeInTheDocument();
    });
  });

  it('renders clean empty state when no findings exist', async () => {
    mockVulnerabilityBackend({ findings: [], stats: { ...MOCK_STATS, total_findings: 0, open_findings: 0 } });
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(screen.getByText(/No Security Rule Violations Detected/i)).toBeInTheDocument();
      expect(screen.getByText(/Zero active security violations across monitored sessions/i)).toBeInTheDocument();
    });
  });

  it('renders the Export button and enables audit trail exports', async () => {
    renderAppAt('/vulnerabilities');

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Export/i })).toBeInTheDocument();
    });
  });
});
