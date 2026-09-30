import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { AIComprehensiveAnalysis, ComprehensiveSecurityAssessment, TestbedGroundTruth, WhatIfResponse } from '@/types';
import { mockBackendOnline, renderAppAt } from './renderApp';

const SESSION = {
  id: 'IPSEC-TEST0001',
  ordinal: 1,
  source: '10.10.0.1',
  destination: '10.20.0.1',
  direction: 'BIDIRECTIONAL',
  state: 'ACTIVE',
  correlation: 'DIRECT',
  start_time: '2026-09-30T08:00:00Z',
  end_time: '2026-09-30T08:00:30Z',
  duration_seconds: 30,
  packet_count: 420,
  byte_count: 61000,
  ike_packets: 6,
  esp_packets: 414,
  ah_packets: 0,
  ike_version: '2.0',
  nat_traversal: false,
};

const ANALYSIS: AIComprehensiveAnalysis = {
  session_id: SESSION.id,
  capture_id: 'cap-testbed-1',
  timestamp: '2026-09-30T08:01:00Z',
  protocol_identification: { is_ipsec: true, protocol_type: 'ESP+IKE', confidence: 0.99, provenance: 'OBSERVED', evidence: ['6 IKE and 414 ESP packets observed'] },
  ike_identification: {
    detected: true, version: '2.0', initiator_spi: '0x1122334455667788', responder_spi: '0x8877665544332211', exchanges: ['IKE_SA_INIT', 'IKE_AUTH'],
    confidence: 0.98, provenance: 'OBSERVED', nat_traversal: false, notify_types: [], auth_method: null, evidence: ['IKE_SA_INIT request/response in cleartext'],
  },
  vpn_mode_identification: { mode: 'TUNNEL', confidence: 0.55, evidence: 'ESP hides the inner header; TUNNEL is the documented default.', provenance: 'ASSUMED' },
  crypto_configuration: {
    cipher: 'AES-GCM', key_size_bits: 256, cipher_family: 'AES-GCM', integrity: 'AEAD', prf: 'HMAC-SHA2-256', dh_group: 'Group 19 (ECP-256)', pfs_enabled: null,
    confidence: 0.98, observable_source: 'IKE_SA_INIT SA payload', provenance: 'OBSERVED', ike_sa: {},
    esp_inference: { provenance: 'INFERRED', cipher_family: 'AES-GCM / ChaCha20-Poly1305', framing_hypothesis: 'AEAD-CTR', confidence: 0.72, payload_entropy_bits: 7.98, null_encryption_suspected: false, evidence: ['ESP payload lengths ≡ 4 (mod 8) with 8-byte IV'] },
    pfs: { status: 'UNKNOWN', provenance: 'UNAVAILABLE', confidence: 0, evidence: ['No CREATE_CHILD_SA exchange observed'] },
    downgrade: { detected: false, reason: '' }, weak_offered: [], details: {}, evidence: ['Responder selected proposal 1: AES-GCM-256 / PRF-HMAC-SHA2-256 / ECP-256'],
  },
  sa_characteristics: {
    ike_sas_count: 1, child_sas_count: 2, observed_spis: ['0x0a0b0c0d', '0x1a1b1c1d'], rekey_count: 0, sa_state: 'ESTABLISHED', replay_protection_active: true,
    replay_verdict: 'PROTECTED', replay_window_size: 64, esn_enabled: null, esn_observable: false, lifetime_seconds: null, lifetime_provenance: 'UNAVAILABLE', provenance: 'OBSERVED', evidence: [],
  },
  traffic_classification: {
    predicted_type: 'VOIP', confidence: 0.91, probabilities: { VOIP: 0.91, WHATSAPP: 0.03, EMAIL: 0.01, WEB_BROWSING: 0.02, ICMP: 0.02, VIDEO_STREAMING: 0.0, OTHER: 0.01 },
    flow_features: {}, explanations: [], provenance: 'PREDICTED', abstained: false, data_packets: 414, model_version: '2.0',
  },
  overall_ai_confidence: 0.86,
  confidence_breakdown: {},
};

const ASSESSMENT: ComprehensiveSecurityAssessment = {
  session_id: SESSION.id,
  capture_id: 'cap-testbed-1',
  overall_security_score: 85.7,
  overall_risk_score: 14.3,
  security_posture: 'ROBUST',
  ai_confidence: 0.86,
  coverage: { components_total: 6, components_assessed: 5, assessed: ['crypto', 'cipher_suite', 'replay', 'lifetime', 'metadata'], unassessable: [{ component: 'forward_secrecy', reason: 'no CREATE_CHILD_SA exchange in the capture' }], weight_fraction: 0.8, summary: '5 of 6 components assessed (80% of the weight)' },
  traffic_prediction: { predicted_type: 'VOIP', confidence: 0.91, abstained: false, provenance: 'PREDICTED', data_packets: 414, probabilities: {} },
  protocol_identification: { protocol_type: 'ESP+IKE', ike_version: '2.0', ipsec_mode: 'TUNNEL', mode_provenance: 'ASSUMED', mode_confidence: 0.55, nat_traversal: false },
  cryptographic_strength: {
    grade: 'A', score: 92, status: 'SECURE', cipher: 'AES-GCM', key_length_bits: 256, authenticated_encryption: true, integrity_algorithm: 'AEAD', prf_algorithm: 'HMAC-SHA2-256',
    dh_group: 'Group 19 (ECP-256)', security_bits: 128, provenance: 'OBSERVED', observable_source: 'IKE_SA_INIT', provisional: false, assessable: true,
    details: ['AES-256-GCM (AEAD) negotiated; 128-bit security strength from ECP-256'],
  },
  configuration_compliance: {
    compliance_status: 'PARTIALLY_COMPLIANT', compliance_score: 88, rules_evaluated: 24, rules_passed: 23, rules_violated: 1,
    violations: [{ rule_id: 'RULE-PROTO-006', name: 'Missing TFC padding', severity: 'MEDIUM', category: 'PROTOCOL_ANOMALY', remediation: 'Enable TFC padding' }],
    profiles: [
      { profile_id: 'IETF-BASELINE', profile_name: 'IETF RFC 8247 / RFC 8221 (2017–2024 algorithm requirements)', status: 'COMPLIANT', score: 100, checks_total: 6, checks_assessable: 5, checks_passed: 5, checks_failed: 0, checks_warned: 0, coverage: 0.83, checks: [{ component: 'encryption', requirement: 'AES-GCM or ChaCha20-Poly1305', level: 'MUST', observed: 'AES-GCM-256', status: 'PASS', reference: 'RFC 8221 §5', note: '' }], summary: 'All assessable checks pass' },
      { profile_id: 'NIST-SP800-77R1', profile_name: 'NIST SP 800-77 Rev. 1 / SP 800-131A', status: 'COMPLIANT', score: 100, checks_total: 6, checks_assessable: 5, checks_passed: 5, checks_failed: 0, checks_warned: 0, coverage: 0.83, checks: [], summary: 'All assessable checks pass' },
      { profile_id: 'CNSA-1.0', profile_name: 'CNSA 1.0 (NSA Commercial National Security Algorithm Suite)', status: 'NON_COMPLIANT', score: 50, checks_total: 4, checks_assessable: 4, checks_passed: 2, checks_failed: 2, checks_warned: 0, coverage: 1, checks: [{ component: 'dh_group', requirement: 'ECP-384 (group 20) or MODP-3072+', level: 'MUST', observed: 'Group 19 (ECP-256)', status: 'FAIL', reference: 'CNSA 1.0', note: '' }], summary: 'ECP-256 below CNSA minimum' },
    ],
  },
  sa_parameters: { active_sas_count: 2, ike_sa_state: 'ESTABLISHED', child_sa_state: 'ACTIVE', rekey_count: 0, observed_spis: ['0x0a0b0c0d'], state_synchronization: 'CONSISTENT', status: 'OPTIMAL', provenance: 'OBSERVED', findings: [] },
  key_lifetime: { observed_duration_seconds: 30, configured_limit_seconds: 3600, observed_volume_bytes: 61000, configured_volume_limit_bytes: 1073741824, negotiated_lifetime_seconds: null, lifetime_provenance: 'OBSERVED', rekeys_observed: 0, lifetime_status: 'COMPLIANT', rekey_recommended: false, assessable: true, details: 'Observed 30 s / 61 kB against the policy limits.' },
  replay_protection: { status: 'ENABLED', replay_window_size: 64, esn_supported: null, esn_observable: false, duplicate_sequences_detected: false, duplicates_count: 0, out_of_order_count: 0, max_reorder_distance: 0, sequence_gaps: 0, streams_analysed: 2, verdict: 'PROTECTED', window_inference: 'All reordering fits a 64-packet window.', assessable: true, details: 'Sequence numbers strictly increase per SPI.' },
  forward_secrecy: { pfs_enabled: null, pfs_status: 'UNKNOWN', dh_group: 'Group 19 (ECP-256)', strength_bits: 128, security_level: 'UNKNOWN', provenance: 'UNAVAILABLE', confidence: 0, assessable: false, details: 'No CREATE_CHILD_SA exchange observed; PFS cannot be determined from this capture.' },
  cipher_suite_strength: { cipher_suite: 'AES-256-GCM / ECP-256', nist_sp800_77_compliant: true, quantum_readiness: 'MEDIUM', security_bits: 128, assessment_summary: 'AEAD suite at 128-bit classical strength; symmetric side is quantum-tolerant, ECP-256 is not.' },
  metadata_exposure: {
    exposure_level: 'MEDIUM', composite_score: 48.5, spi_leakage_score: 60, sequence_leakage_score: 40, length_tfc_leakage_score: 55, timing_leakage_score: 62, topology_leakage_score: 30, tfc_padding_detected: false,
    observable_vectors: ['SPI', 'sequence numbers', 'packet lengths', 'timing', 'topology'],
    traffic_context: { applied: true, traffic_type: 'VOIP', confidence: 0.91, attack_classes: ['spoken-phrase identification (Wright et al. 2008)'], length_multiplier: 1.3, timing_multiplier: 1.4 },
    findings: [], remediations: ['Enable TFC padding'],
  },
  explainable_findings: [
    { finding: 'Traffic Flow Confidentiality (TFC) Inactive', evidence: '27 distinct ESP frame sizes across 414 frames', severity: 'MEDIUM', reason: 'Frame sizes track application message sizes', recommendation: 'Enable TFC padding on the gateway', provenance: 'OBSERVED', rule_id: 'RULE-PROTO-006' },
  ],
  component_scores: { crypto: 92, replay: 100, lifetime: 100 },
  evaluated_at: '2026-09-30T08:01:00Z',
};

const WHAT_IF: WhatIfResponse = {
  session_id: SESSION.id,
  overrides_applied: { dh_group: 20, tfc_padding: true },
  baseline: { overall_security_score: 85.7, security_posture: 'ROBUST', crypto_grade: 'A', crypto_score: 92, security_bits: 128, pfs_status: 'UNKNOWN', compliance_score: 88, metadata_exposure_score: 48.5, profiles: { 'IETF-BASELINE': 'COMPLIANT', 'NIST-SP800-77R1': 'COMPLIANT', 'CNSA-1.0': 'NON_COMPLIANT' }, violations: [{ rule_id: 'RULE-PROTO-006', name: 'Missing TFC padding', severity: 'MEDIUM' }] },
  simulated: { overall_security_score: 94.2, security_posture: 'ROBUST', crypto_grade: 'A+', crypto_score: 100, security_bits: 192, pfs_status: 'UNKNOWN', compliance_score: 100, metadata_exposure_score: 30.1, profiles: { 'IETF-BASELINE': 'COMPLIANT', 'NIST-SP800-77R1': 'COMPLIANT', 'CNSA-1.0': 'COMPLIANT' }, violations: [] },
  delta: { overall_security_score: 8.5, compliance_score: 12, violations: -1, metadata_exposure_score: -18.4 },
  simulated_assessment: {},
  note: 'Hypothetical re-evaluation; nothing was written.',
};

const GROUND_TRUTH: TestbedGroundTruth = {
  profile_id: 'PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4', profile_name: 'Standard Secure Gateway', capture_id: 'cap-testbed-1', ike_version: '2.0', ike_exchange_mode: 'IKE_SA_INIT/IKE_AUTH',
  ipsec_protocol: 'ESP', mode: 'TUNNEL', ip_version: 4, nat_traversal: false, encryption: 'AES-256-GCM', cipher_family: 'AES-GCM', key_length: 256, aead: true, integrity: 'AEAD', dh_group: 19,
  pfs_enabled: true, rekey_observed: false, tfc_padding: false, downgrade: false, traffic_type: 'VOIP', traffic_parameters: {}, duration_seconds: 30, spis: ['0x0a0b0c0d'], synthetic: true,
  note: 'Application traffic is model-generated; IPsec framing and encryption are real.',
};

function mockPostureBackend(options: { sessions?: unknown[]; groundTruth?: boolean } = {}): void {
  mockBackendOnline();
  const base = globalThis.fetch as unknown as (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/api/security-assessment/what-if/')) return json(WHAT_IF);
      if (url.includes('/api/security-assessment/comprehensive/')) return json(ASSESSMENT);
      if (url.includes('/api/traffic-analysis/comprehensive/')) return json(ANALYSIS);
      if (url.includes('/api/environment/ground-truth/')) {
        return options.groundTruth ? json(GROUND_TRUTH) : json({ error: 'NOT_FOUND', message: 'No testbed ground truth registered for this capture' }, 404);
      }
      if (url.includes('/api/sessions')) {
        const items = options.sessions ?? [SESSION];
        return json({ items, total: items.length, page: 1, page_size: 100, total_pages: 1 });
      }
      return base(input, init);
    }),
  );
}

describe('Security Posture page (SIH 26160 assessment)', () => {
  beforeEach(() => {
    mockPostureBackend();
  });

  it('renders the provenance-tagged posture for the first discovered session', async () => {
    renderAppAt('/security-posture');
    expect(await screen.findByRole('heading', { name: /Security Posture/i })).toBeInTheDocument();

    expect(await screen.findByText('ROBUST')).toBeInTheDocument();
    expect(screen.getByText(/5 of 6 components assessed/i)).toBeInTheDocument();
    expect(screen.getAllByText('OBSERVED').length).toBeGreaterThan(0);
    expect(screen.getAllByText('PREDICTED').length).toBeGreaterThan(0);
    expect(screen.getAllByText('UNAVAILABLE').length).toBeGreaterThan(0);
    expect(screen.getAllByText('ASSUMED').length).toBeGreaterThan(0);

    // Honest gap: PFS is unknown and listed as not assessable, never invented.
    expect(screen.getByText(/no CREATE_CHILD_SA exchange in the capture/i)).toBeInTheDocument();
    expect(screen.queryByText(/PFS ENABLED/)).not.toBeInTheDocument();

    // Compliance profiles and the explainable finding.
    expect(screen.getByRole('article', { name: /CNSA 1\.0/i })).toHaveTextContent(/NON COMPLIANT/);
    expect(screen.getByRole('article', { name: /IETF RFC 8247/i })).toHaveTextContent(/COMPLIANT/);
    expect(screen.getByText('Traffic Flow Confidentiality (TFC) Inactive')).toBeInTheDocument();
    expect(screen.getByText('RULE-PROTO-006')).toBeInTheDocument();
  });

  it('runs the what-if remediation simulator and shows baseline versus simulated scores', async () => {
    const user = userEvent.setup();
    renderAppAt('/security-posture');
    await screen.findByText('ROBUST');

    await user.click(screen.getByRole('button', { name: /simulate configuration/i }));
    const result = await screen.findByLabelText('what-if result');
    expect(within(result).getByText('85.7')).toBeInTheDocument();
    expect(within(result).getByText('94.2')).toBeInTheDocument();
    expect(within(result).getByText('+8.5')).toBeInTheDocument();
    expect(within(result).getByText(/No remaining rule violations/i)).toBeInTheDocument();

    const whatIfCalls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.filter(([input]) =>
      String(input).includes('/api/security-assessment/what-if/'),
    );
    expect(whatIfCalls).toHaveLength(1);
    expect(whatIfCalls[0]?.[1]?.method).toBe('POST');
  });

  it('compares the platform result with the testbed ground truth when it is registered', async () => {
    mockPostureBackend({ groundTruth: true });
    renderAppAt('/security-posture');
    await screen.findByText('ROBUST');

    expect(await screen.findByText(/Testbed ground truth vs\. inference/i)).toBeInTheDocument();
    expect(screen.getAllByText('match').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/not verifiable from capture/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText('mismatch')).not.toBeInTheDocument();
  });

  it('shows an honest empty state when no session has been discovered', async () => {
    mockPostureBackend({ sessions: [] });
    renderAppAt('/security-posture');
    await waitFor(() => {
      expect(screen.getByText(/No session selected/i)).toBeInTheDocument();
    });
    expect(screen.queryByText('ROBUST')).not.toBeInTheDocument();
  });
});
