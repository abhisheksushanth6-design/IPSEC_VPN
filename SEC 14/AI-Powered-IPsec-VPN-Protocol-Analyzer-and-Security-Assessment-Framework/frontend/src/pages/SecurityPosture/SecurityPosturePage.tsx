import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  FlaskConical,
  Gauge,
  KeyRound,
  Lock,
  RefreshCw,
  Repeat,
  ShieldCheck,
  Sparkles,
  Timer,
  Wand2,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { PageContainer } from '@/components/layout';
import { ErrorState, LoadingState } from '@/components/states';
import { PageHeader, Panel } from '@/components/ui';
import { securityPostureService } from '@/services/securityPostureService';
import { sessionService } from '@/services/sessionService';
import type {
  AIComprehensiveAnalysis,
  ComprehensiveSecurityAssessment,
  IPsecSessionSummary,
  Provenance,
  TestbedGroundTruth,
  WhatIfRequest,
  WhatIfResponse,
} from '@/types';

/* ------------------------------------------------------------------------- */
/* Small presentational helpers                                               */
/* ------------------------------------------------------------------------- */

const PROVENANCE_STYLE: Record<string, string> = {
  OBSERVED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  INFERRED: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
  PREDICTED: 'bg-violet-500/10 text-violet-400 border-violet-500/30',
  ASSUMED: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  UNAVAILABLE: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  WHAT_IF: 'bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30',
};

export function ProvenanceBadge({ value }: { value: Provenance | undefined }) {
  const key = (value || 'UNAVAILABLE').toUpperCase();
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider ${PROVENANCE_STYLE[key] ?? PROVENANCE_STYLE.UNAVAILABLE}`}
      title={
        {
          OBSERVED: 'Read directly from cleartext protocol fields in the capture',
          INFERRED: 'Derived from side channels (framing arithmetic, message sizes)',
          PREDICTED: 'Produced by the supervised traffic classifier',
          ASSUMED: 'Documented default the capture cannot confirm',
          UNAVAILABLE: 'Evidence absent or encrypted',
          WHAT_IF: 'Hypothetical value supplied to the simulator',
        }[key] ?? key
      }
    >
      {key}
    </span>
  );
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-rose-600/20 text-rose-300 border-rose-500/40',
  HIGH: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  LOW: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
  INFO: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
};

function SeverityBadge({ value }: { value: string }) {
  return (
    <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-semibold ${SEVERITY_STYLE[value] ?? SEVERITY_STYLE.INFO}`}>
      {value}
    </span>
  );
}

function statusTone(status: string): string {
  switch (status) {
    case 'COMPLIANT':
    case 'PASS':
    case 'PROTECTED':
    case 'ENABLED':
    case 'SECURE':
      return 'text-emerald-400';
    case 'PARTIALLY_COMPLIANT':
    case 'WARN':
    case 'DEGRADED':
    case 'ACCEPTABLE':
    case 'NEAR_EXPIRATION':
      return 'text-amber-400';
    case 'NON_COMPLIANT':
    case 'FAIL':
    case 'REPLAY_INDICATORS':
    case 'DISABLED':
    case 'INSECURE':
    case 'WEAK':
    case 'EXCEEDED':
      return 'text-rose-400';
    default:
      return 'text-slate-400';
  }
}

function scoreTone(score: number): string {
  if (score >= 85) return 'text-emerald-400';
  if (score >= 70) return 'text-amber-400';
  if (score >= 50) return 'text-orange-400';
  return 'text-rose-400';
}

function ScoreRing({ score, label }: { score: number; label: string }) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - Math.max(0, Math.min(100, score)) / 100);
  return (
    <div className="flex items-center gap-4">
      <svg width="112" height="112" viewBox="0 0 112 112" role="img" aria-label={`${label} ${score.toFixed(1)} out of 100`}>
        <circle cx="56" cy="56" r={radius} stroke="currentColor" strokeWidth="10" fill="none" className="text-slate-800" />
        <circle
          cx="56" cy="56" r={radius} stroke="currentColor" strokeWidth="10" fill="none"
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          transform="rotate(-90 56 56)" className={scoreTone(score)}
        />
        <text x="56" y="52" textAnchor="middle" className="fill-current text-primary" fontSize="22" fontWeight="700">
          {score.toFixed(0)}
        </text>
        <text x="56" y="70" textAnchor="middle" className="fill-current text-muted" fontSize="10">
          / 100
        </text>
      </svg>
    </div>
  );
}

function DimensionCard({
  icon, title, value, provenance, tone, detail, assessable = true,
}: {
  icon: React.ReactNode; title: string; value: string; provenance?: Provenance; tone?: string; detail: string; assessable?: boolean;
}) {
  return (
    <article aria-label={title} className={`rounded border border-border bg-surface p-4 ${assessable ? '' : 'opacity-75'}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted">
          {icon}
          {title}
        </div>
        {provenance ? <ProvenanceBadge value={provenance} /> : null}
      </div>
      <div className={`mt-2 text-lg font-bold ${tone ?? 'text-primary'}`}>{value}</div>
      <p className="mt-1 text-xs leading-relaxed text-secondary">{detail}</p>
    </article>
  );
}

/* ------------------------------------------------------------------------- */
/* Page                                                                       */
/* ------------------------------------------------------------------------- */

const CIPHER_OPTIONS = ['AES-GCM-256', 'AES-GCM-128', 'CHACHA20-POLY1305', 'AES-CBC-256', 'AES-CBC-128', '3DES', 'NULL'];
const INTEGRITY_OPTIONS = ['AEAD', 'HMAC-SHA2-256', 'HMAC-SHA2-384', 'HMAC-SHA2-512', 'HMAC-SHA1-96', 'HMAC-MD5-96'];
const PRF_OPTIONS = ['SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA1', 'MD5'];
const DH_OPTIONS: Array<[number, string]> = [
  [31, 'Curve25519 (31)'], [19, 'ECP-256 (19)'], [20, 'ECP-384 (20)'], [21, 'ECP-521 (21)'],
  [14, 'MODP-2048 (14)'], [15, 'MODP-3072 (15)'], [16, 'MODP-4096 (16)'], [5, 'MODP-1536 (5)'], [2, 'MODP-1024 (2)'],
];

export function SecurityPosturePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [sessions, setSessions] = useState<IPsecSessionSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string>(searchParams.get('session') ?? '');
  const [assessment, setAssessment] = useState<ComprehensiveSecurityAssessment | null>(null);
  const [analysis, setAnalysis] = useState<AIComprehensiveAnalysis | null>(null);
  const [groundTruth, setGroundTruth] = useState<TestbedGroundTruth | null>(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [whatIf, setWhatIf] = useState<WhatIfRequest>({ cipher: 'AES-GCM-256', dh_group: 19, pfs_enabled: true, ike_version: '2.0', tfc_padding: false });
  const [whatIfResult, setWhatIfResult] = useState<WhatIfResponse | null>(null);
  const [simulating, setSimulating] = useState(false);

  const loadSessions = useCallback(async () => {
    try {
      setError(null);
      const page = await sessionService.fetchSessions({ page: 1, pageSize: 100, sort: 'start_time', order: 'desc' });
      const items = page.items ?? [];
      setSessions(items);
      setSelectedId((current) => current || items[0]?.id || '');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sessions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const evaluate = useCallback(async (sessionId: string) => {
    if (!sessionId) {
      setAssessment(null);
      setAnalysis(null);
      return;
    }
    setEvaluating(true);
    setError(null);
    setWhatIfResult(null);
    try {
      const [a, ai] = await Promise.all([
        securityPostureService.getAssessment(sessionId),
        securityPostureService.getAIAnalysis(sessionId),
      ]);
      setAssessment(a);
      setAnalysis(ai);
      setGroundTruth(await securityPostureService.getGroundTruth(a.capture_id).catch(() => null));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to evaluate session');
    } finally {
      setEvaluating(false);
    }
  }, []);

  useEffect(() => {
    if (selectedId) {
      setSearchParams({ session: selectedId }, { replace: true });
      evaluate(selectedId);
    }
  }, [selectedId, evaluate, setSearchParams]);

  const runWhatIf = async () => {
    if (!selectedId) return;
    setSimulating(true);
    try {
      setWhatIfResult(await securityPostureService.whatIf(selectedId, whatIf));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'What-if simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  const crypto = analysis?.crypto_configuration;
  const esp = crypto?.esp_inference;
  const pfs = crypto?.pfs;

  const truthComparison = useMemo(() => {
    if (!groundTruth || !analysis || !assessment) return null;
    const ike = analysis.ike_identification;
    const rows: Array<{ dimension: string; truth: string; inferred: string; provenance: Provenance; match: boolean | null }> = [];
    rows.push({ dimension: 'IKE version', truth: groundTruth.ike_version ?? 'not in capture', inferred: ike.detected ? ike.version : 'NONE', provenance: ike.provenance,
      match: groundTruth.ike_version ? String(ike.version).startsWith(String(groundTruth.ike_version).split('.')[0] ?? '') : null });
    rows.push({ dimension: 'Mode', truth: groundTruth.mode, inferred: analysis.vpn_mode_identification.mode, provenance: analysis.vpn_mode_identification.provenance,
      match: analysis.vpn_mode_identification.provenance === 'ASSUMED' ? null : analysis.vpn_mode_identification.mode === groundTruth.mode });
    const truthCipher = `${groundTruth.encryption}`;
    rows.push({ dimension: 'Cipher', truth: truthCipher, inferred: crypto ? `${crypto.cipher}${crypto.key_size_bits ? `-${crypto.key_size_bits}` : ''}` : '—', provenance: crypto?.provenance ?? 'UNAVAILABLE',
      match: crypto?.provenance === 'OBSERVED' ? (groundTruth.ipsec_protocol === 'AH' ? null : truthCipher.replace('-CBC', '').replace('-GCM', '').includes(String(crypto.key_size_bits ?? '')) && crypto.cipher_family.split('-')[0] === groundTruth.cipher_family.split('-')[0]) : crypto?.provenance === 'INFERRED' ? (esp?.framing_hypothesis ? ({ 'CTR-OR-CBC-8': ['AES-GCM', 'CHACHA20', '3DES'], 'CBC-16': ['AES-CBC'] } as Record<string, string[]>)[esp.framing_hypothesis]?.includes(groundTruth.cipher_family) ?? null : null) : null });
    rows.push({ dimension: 'DH group', truth: `Group ${groundTruth.dh_group}`, inferred: crypto?.dh_group ?? '—', provenance: crypto?.provenance ?? 'UNAVAILABLE',
      match: crypto?.provenance === 'OBSERVED' ? (crypto.dh_group ?? '').includes(`Group ${groundTruth.dh_group}`) : null });
    rows.push({ dimension: 'PFS', truth: groundTruth.pfs_enabled ? 'ENABLED' : 'DISABLED', inferred: pfs?.status ?? 'UNKNOWN', provenance: (pfs?.provenance as Provenance) ?? 'UNAVAILABLE',
      match: pfs?.status && pfs.status !== 'UNKNOWN' ? pfs.status === (groundTruth.pfs_enabled ? 'ENABLED' : 'DISABLED') : null });
    rows.push({ dimension: 'Traffic inside ESP', truth: groundTruth.traffic_type, inferred: `${assessment.traffic_prediction.predicted_type} (${(assessment.traffic_prediction.confidence * 100).toFixed(0)}%)`, provenance: 'PREDICTED',
      match: assessment.traffic_prediction.abstained ? null : assessment.traffic_prediction.predicted_type === groundTruth.traffic_type });
    return rows;
  }, [groundTruth, analysis, assessment, crypto, esp, pfs]);

  if (loading) {
    return (
      <PageContainer>
        <LoadingState message="Loading discovered IPsec sessions..." />
      </PageContainer>
    );
  }

  return (
    <PageContainer>
      <PageHeader
        title="Security Posture — SIH 26160 Assessment"
        description="Per-session view of what the capture proved (OBSERVED), what the engine derived from side channels (INFERRED), what the AI predicted (PREDICTED) and what stays UNAVAILABLE — with published-profile compliance and a what-if remediation simulator."
        status={assessment ? 'OPERATIONAL' : 'READY'}
        breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Security Posture' }]}
        actions={
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted" htmlFor="posture-session">Session</label>
            <select
              id="posture-session"
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              className="rounded border border-border bg-surface px-2 py-1.5 text-xs text-primary"
            >
              {sessions.length === 0 ? <option value="">No sessions discovered</option> : null}
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id} · {s.source} ↔ {s.destination} · {s.packet_count} pkts
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => evaluate(selectedId)}
              disabled={!selectedId || evaluating}
              className="inline-flex items-center gap-2 rounded bg-info px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-info/90 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${evaluating ? 'animate-spin' : ''}`} />
              {evaluating ? 'Evaluating…' : 'Re-evaluate'}
            </button>
          </div>
        }
      />

      {error ? <ErrorState message={error} onRetry={() => (selectedId ? evaluate(selectedId) : loadSessions())} /> : null}

      {!selectedId && !error ? (
        <Panel title="No session selected" description="Load a capture in Packet Analysis (or generate one in Test Environment) and discover sessions to assess a security posture.">
          <p className="text-sm text-secondary">Nothing is fabricated here: without a session there is no assessment.</p>
        </Panel>
      ) : null}

      {assessment && analysis ? (
        <>
          {/* Headline */}
          <section aria-labelledby="posture-headline" className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Panel className="lg:col-span-1 p-5">
              <h2 id="posture-headline" className="sr-only">Overall posture</h2>
              <div className="flex items-center gap-5">
                <ScoreRing score={assessment.overall_security_score} label="Security score" />
                <div>
                  <div className="text-xs uppercase tracking-wider text-muted">Security score</div>
                  <div className={`text-2xl font-bold ${scoreTone(assessment.overall_security_score)}`}>{assessment.security_posture.replace('_', ' ')}</div>
                  <div className="mt-1 text-xs text-secondary">Risk score {assessment.overall_risk_score.toFixed(1)} · AI confidence {(assessment.ai_confidence * 100).toFixed(0)}%</div>
                  <div className="mt-2 text-xs text-muted">{assessment.coverage.summary}</div>
                </div>
              </div>
              {assessment.coverage.unassessable.length > 0 ? (
                <ul className="mt-3 space-y-1 text-xs text-secondary">
                  {assessment.coverage.unassessable.map((u) => (
                    <li key={u.component} className="flex items-start gap-1.5">
                      <Eye className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-slate-500" />
                      <span><span className="font-semibold uppercase text-muted">{u.component}</span> not assessable: {u.reason}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </Panel>

            <Panel title="Protocol identification" description="Layer 07 — what the capture shows about the IPsec deployment." className="lg:col-span-2">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs md:grid-cols-3">
                <div>
                  <dt className="text-muted">Protocol</dt>
                  <dd className="flex items-center gap-2 font-semibold text-primary">{analysis.protocol_identification.protocol_type} <ProvenanceBadge value={analysis.protocol_identification.provenance} /></dd>
                </div>
                <div>
                  <dt className="text-muted">IKE version</dt>
                  <dd className="flex items-center gap-2 font-semibold text-primary">{analysis.ike_identification.detected ? `IKEv${analysis.ike_identification.version}` : 'Not in capture'} <ProvenanceBadge value={analysis.ike_identification.provenance} /></dd>
                </div>
                <div>
                  <dt className="text-muted">Mode</dt>
                  <dd className="flex items-center gap-2 font-semibold text-primary">{analysis.vpn_mode_identification.mode} <ProvenanceBadge value={analysis.vpn_mode_identification.provenance} /> <span className="font-normal text-muted">{(analysis.vpn_mode_identification.confidence * 100).toFixed(0)}%</span></dd>
                </div>
                <div>
                  <dt className="text-muted">Cipher (IKE SA)</dt>
                  <dd className="flex flex-wrap items-center gap-2 font-semibold text-primary">
                    {crypto?.cipher}{crypto?.key_size_bits ? `-${crypto.key_size_bits}` : ''} <ProvenanceBadge value={crypto?.provenance} />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Integrity / PRF</dt>
                  <dd className="font-semibold text-primary">{crypto?.integrity}{crypto?.prf ? ` / ${crypto.prf}` : ''}</dd>
                </div>
                <div>
                  <dt className="text-muted">DH group</dt>
                  <dd className="font-semibold text-primary">{crypto?.dh_group}</dd>
                </div>
                <div>
                  <dt className="text-muted">ESP cipher family (framing)</dt>
                  <dd className="flex flex-wrap items-center gap-2 font-semibold text-primary">
                    {esp?.framing_hypothesis ? `${esp.framing_hypothesis} → ${esp.cipher_family}` : esp?.cipher_family ?? 'not inferable'} <ProvenanceBadge value={esp?.provenance} />
                    {esp?.confidence !== undefined ? <span className="font-normal text-muted">{(esp.confidence * 100).toFixed(0)}%</span> : null}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Perfect forward secrecy</dt>
                  <dd className="flex items-center gap-2 font-semibold text-primary">
                    <span className={statusTone(pfs?.status ?? 'UNKNOWN')}>{pfs?.status ?? 'UNKNOWN'}</span> <ProvenanceBadge value={pfs?.provenance} />
                    {pfs?.confidence ? <span className="font-normal text-muted">{(pfs.confidence * 100).toFixed(0)}%</span> : null}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted">Traffic inside ESP</dt>
                  <dd className="flex items-center gap-2 font-semibold text-primary">
                    {assessment.traffic_prediction.predicted_type}{assessment.traffic_prediction.abstained ? ' (abstained)' : ''} <ProvenanceBadge value="PREDICTED" />
                    <span className="font-normal text-muted">{(assessment.traffic_prediction.confidence * 100).toFixed(0)}% · {assessment.traffic_prediction.data_packets} pkts</span>
                  </dd>
                </div>
              </dl>
              {crypto?.downgrade?.detected ? (
                <div className="mt-3 flex items-start gap-2 rounded border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                  <span><span className="font-semibold">Negotiation downgrade:</span> {crypto.downgrade.reason}</span>
                </div>
              ) : null}
              {esp?.null_encryption_suspected ? (
                <div className="mt-3 flex items-start gap-2 rounded border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                  <span><span className="font-semibold">ESP-NULL suspected:</span> payload entropy {esp.payload_entropy_bits} bits/byte — the data plane does not look encrypted (RFC 5879).</span>
                </div>
              ) : null}
              <details className="mt-3 text-xs text-secondary">
                <summary className="cursor-pointer text-muted">Evidence trail</summary>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {[...analysis.ike_identification.evidence, ...(crypto?.evidence ?? []), ...(esp?.evidence ?? []), ...(pfs?.evidence ?? [])].map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </details>
            </Panel>
          </section>

          {/* Assessment dimensions */}
          <section aria-labelledby="dimensions-heading" className="space-y-3">
            <h2 id="dimensions-heading" className="text-base font-semibold text-primary">Assessment dimensions</h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
              <DimensionCard icon={<Lock className="h-4 w-4" />} title="Cryptographic strength"
                value={`Grade ${assessment.cryptographic_strength.grade}${assessment.cryptographic_strength.provisional ? ' (provisional)' : ''} · ${assessment.cryptographic_strength.status.replace('_', ' ')}`}
                tone={statusTone(assessment.cryptographic_strength.status)} provenance={assessment.cryptographic_strength.provenance}
                assessable={assessment.cryptographic_strength.assessable}
                detail={assessment.cryptographic_strength.details[0] ?? ''} />
              <DimensionCard icon={<KeyRound className="h-4 w-4" />} title="Forward secrecy"
                value={`${assessment.forward_secrecy.pfs_status} · ${assessment.forward_secrecy.security_level}`}
                tone={statusTone(assessment.forward_secrecy.pfs_status)} provenance={assessment.forward_secrecy.provenance}
                assessable={assessment.forward_secrecy.assessable} detail={assessment.forward_secrecy.details} />
              <DimensionCard icon={<Repeat className="h-4 w-4" />} title="Replay protection"
                value={`${assessment.replay_protection.verdict.replace('_', ' ')} · ${assessment.replay_protection.streams_analysed} SPI stream(s)`}
                tone={statusTone(assessment.replay_protection.verdict)} provenance={assessment.replay_protection.assessable ? 'OBSERVED' : 'UNAVAILABLE'}
                assessable={assessment.replay_protection.assessable}
                detail={`${assessment.replay_protection.duplicates_count} duplicate(s), ${assessment.replay_protection.out_of_order_count} reordered (max distance ${assessment.replay_protection.max_reorder_distance}). ${assessment.replay_protection.window_inference} ESN is not observable on the wire.`} />
              <DimensionCard icon={<Timer className="h-4 w-4" />} title="Key lifetime"
                value={assessment.key_lifetime.lifetime_status.replace('_', ' ')} tone={statusTone(assessment.key_lifetime.lifetime_status)}
                provenance={assessment.key_lifetime.lifetime_provenance as Provenance} assessable={assessment.key_lifetime.assessable}
                detail={assessment.key_lifetime.details} />
              <DimensionCard icon={<Eye className="h-4 w-4" />} title="Metadata exposure"
                value={`${assessment.metadata_exposure.exposure_level} · ${assessment.metadata_exposure.composite_score.toFixed(1)}/100`}
                tone={assessment.metadata_exposure.exposure_level === 'LOW' ? 'text-emerald-400' : assessment.metadata_exposure.exposure_level === 'MEDIUM' ? 'text-amber-400' : 'text-rose-400'}
                provenance={assessment.metadata_exposure.traffic_context?.applied ? 'PREDICTED' : 'OBSERVED'}
                detail={assessment.metadata_exposure.traffic_context?.applied
                  ? `Weighted for predicted ${assessment.metadata_exposure.traffic_context.traffic_type} traffic: ${(assessment.metadata_exposure.traffic_context.attack_classes ?? []).join('; ') || 'no specific attack class'}`
                  : assessment.metadata_exposure.observable_vectors.join(' · ')} />
              <DimensionCard icon={<Gauge className="h-4 w-4" />} title="Cipher suite & quantum readiness"
                value={`Quantum readiness ${assessment.cipher_suite_strength.quantum_readiness}`}
                tone={assessment.cipher_suite_strength.quantum_readiness === 'HIGH' ? 'text-emerald-400' : assessment.cipher_suite_strength.quantum_readiness === 'MEDIUM' ? 'text-amber-400' : 'text-slate-400'}
                provenance={assessment.cryptographic_strength.provenance} detail={assessment.cipher_suite_strength.assessment_summary} />
            </div>
          </section>

          {/* Compliance profiles */}
          <Panel title="Compliance profiles" description="The observed suite against three published algorithm policies. Coverage states how much of each profile the capture could verify.">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {assessment.configuration_compliance.profiles.map((p) => (
                <article key={p.profile_id} aria-label={p.profile_name} className="rounded border border-border bg-black/20 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold text-primary">{p.profile_name}</div>
                      <div className={`text-xs font-bold ${statusTone(p.status)}`}>{p.status.replace(/_/g, ' ')}{p.score !== null ? ` · ${p.score.toFixed(0)}/100` : ''}</div>
                    </div>
                    <div className="text-right text-2xs text-muted">coverage {(p.coverage * 100).toFixed(0)}%</div>
                  </div>
                  <ul className="mt-3 space-y-1.5 text-xs">
                    {p.checks.map((c) => (
                      <li key={c.component} className="flex items-start gap-2">
                        {c.status === 'PASS' ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-emerald-400" />
                          : c.status === 'FAIL' ? <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-rose-400" />
                          : c.status === 'WARN' ? <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-amber-400" />
                          : <Eye className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-slate-500" />}
                        <span className="text-secondary">
                          <span className="font-semibold text-primary">{c.component}:</span> {c.observed ?? 'not observable'}{' '}
                          <span className="text-muted">— {c.requirement} [{c.level}] · {c.reference}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          </Panel>

          {/* Findings */}
          <Panel title="Explainable findings" description="Finding → Evidence → Severity → Reason → Recommendation. Each row states whether it was observed, inferred or predicted.">
            {assessment.explainable_findings.length === 0 ? (
              <p className="text-sm text-secondary">No findings for this session under the current rule set and evidence.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-muted">
                    <tr>
                      <th className="py-2 pr-3">Finding</th>
                      <th className="py-2 pr-3">Severity</th>
                      <th className="py-2 pr-3">Evidence</th>
                      <th className="py-2 pr-3">Reason</th>
                      <th className="py-2">Recommendation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {assessment.explainable_findings.map((f, i) => (
                      <tr key={`${f.rule_id ?? f.finding}-${i}`} className="align-top">
                        <td className="py-2 pr-3 font-semibold text-primary">
                          {f.finding}
                          <div className="mt-1 flex items-center gap-1.5"><ProvenanceBadge value={f.provenance} />{f.rule_id ? <span className="font-mono text-2xs text-muted">{f.rule_id}</span> : null}</div>
                        </td>
                        <td className="py-2 pr-3"><SeverityBadge value={f.severity} /></td>
                        <td className="py-2 pr-3 text-secondary">{f.evidence}</td>
                        <td className="py-2 pr-3 text-secondary">{f.reason}</td>
                        <td className="py-2 text-secondary">{f.recommendation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {/* Ground truth comparison */}
          {truthComparison ? (
            <Panel title="Testbed ground truth vs. inference" description={`This capture was generated by the software testbed (${groundTruth?.profile_name}). The table compares the configuration that was actually used with what the platform identified from the packets alone.`}>
              <table className="w-full text-left text-xs">
                <thead className="text-muted">
                  <tr><th className="py-2 pr-3">Dimension</th><th className="py-2 pr-3">Ground truth</th><th className="py-2 pr-3">Platform result</th><th className="py-2 pr-3">Provenance</th><th className="py-2">Match</th></tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {truthComparison.map((r) => (
                    <tr key={r.dimension}>
                      <td className="py-2 pr-3 font-semibold text-primary">{r.dimension}</td>
                      <td className="py-2 pr-3 text-secondary">{r.truth}</td>
                      <td className="py-2 pr-3 text-secondary">{r.inferred}</td>
                      <td className="py-2 pr-3"><ProvenanceBadge value={r.provenance} /></td>
                      <td className="py-2">
                        {r.match === null ? <span className="text-muted">not verifiable from capture</span>
                          : r.match ? <span className="inline-flex items-center gap-1 text-emerald-400"><CheckCircle2 className="h-3.5 w-3.5" /> match</span>
                          : <span className="inline-flex items-center gap-1 text-rose-400"><AlertTriangle className="h-3.5 w-3.5" /> mismatch</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-2 text-2xs text-muted">{groundTruth?.note}</p>
            </Panel>
          ) : null}

          {/* What-if simulator */}
          <Panel title="What-if remediation simulator" description="Re-score this session under a hypothetical configuration. The rule set is re-run on the modified negotiation facts; observations that a configuration change cannot alter (replay, lifetime) are carried over.">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
              <label className="text-xs text-muted">Cipher
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.cipher ?? ''} onChange={(e) => setWhatIf({ ...whatIf, cipher: e.target.value || undefined })}>
                  <option value="">keep</option>{CIPHER_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </label>
              <label className="text-xs text-muted">Integrity
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.integrity ?? ''} onChange={(e) => setWhatIf({ ...whatIf, integrity: e.target.value || undefined })}>
                  <option value="">keep</option>{INTEGRITY_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </label>
              <label className="text-xs text-muted">PRF
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.prf ?? ''} onChange={(e) => setWhatIf({ ...whatIf, prf: e.target.value || undefined })}>
                  <option value="">keep</option>{PRF_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </label>
              <label className="text-xs text-muted">DH group
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.dh_group ?? ''} onChange={(e) => setWhatIf({ ...whatIf, dh_group: e.target.value ? Number(e.target.value) : undefined })}>
                  <option value="">keep</option>{DH_OPTIONS.map(([g, label]) => <option key={g} value={g}>{label}</option>)}
                </select>
              </label>
              <label className="text-xs text-muted">PFS
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.pfs_enabled === undefined ? '' : String(whatIf.pfs_enabled)} onChange={(e) => setWhatIf({ ...whatIf, pfs_enabled: e.target.value === '' ? undefined : e.target.value === 'true' })}>
                  <option value="">keep</option><option value="true">enabled</option><option value="false">disabled</option>
                </select>
              </label>
              <label className="text-xs text-muted">IKE version
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.ike_version ?? ''} onChange={(e) => setWhatIf({ ...whatIf, ike_version: (e.target.value || undefined) as WhatIfRequest['ike_version'] })}>
                  <option value="">keep</option><option value="2.0">IKEv2</option><option value="1.0">IKEv1</option>
                </select>
              </label>
              <label className="text-xs text-muted">Mode
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.ipsec_mode ?? ''} onChange={(e) => setWhatIf({ ...whatIf, ipsec_mode: (e.target.value || undefined) as WhatIfRequest['ipsec_mode'] })}>
                  <option value="">keep</option><option value="TUNNEL">TUNNEL</option><option value="TRANSPORT">TRANSPORT</option>
                </select>
              </label>
              <label className="text-xs text-muted">TFC padding
                <select className="mt-1 w-full rounded border border-border bg-surface px-2 py-1 text-xs text-primary" value={whatIf.tfc_padding === undefined ? '' : String(whatIf.tfc_padding)} onChange={(e) => setWhatIf({ ...whatIf, tfc_padding: e.target.value === '' ? undefined : e.target.value === 'true' })}>
                  <option value="">keep</option><option value="true">enabled</option><option value="false">disabled</option>
                </select>
              </label>
            </div>
            <div className="mt-3 flex items-center gap-3">
              <button
                type="button"
                onClick={runWhatIf}
                disabled={simulating || !selectedId}
                className="inline-flex items-center gap-2 rounded bg-info px-3 py-1.5 text-sm font-medium text-white hover:bg-info/90 disabled:opacity-50"
              >
                <Wand2 className={`h-4 w-4 ${simulating ? 'animate-pulse' : ''}`} />
                {simulating ? 'Simulating…' : 'Simulate configuration'}
              </button>
              <span className="text-2xs text-muted">Nothing is written to the gateway or the database.</span>
            </div>
            {whatIfResult ? (
              <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3" aria-label="what-if result">
                <div className="rounded border border-border bg-black/20 p-4">
                  <div className="text-xs uppercase tracking-wider text-muted">Baseline</div>
                  <div className={`text-2xl font-bold ${scoreTone(whatIfResult.baseline.overall_security_score)}`}>{whatIfResult.baseline.overall_security_score.toFixed(1)}</div>
                  <div className="text-xs text-secondary">Grade {whatIfResult.baseline.crypto_grade} · PFS {whatIfResult.baseline.pfs_status} · {whatIfResult.baseline.violations.length} violation(s)</div>
                  <div className="mt-1 text-2xs text-muted">{Object.entries(whatIfResult.baseline.profiles).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>
                </div>
                <div className="rounded border border-info/40 bg-info/5 p-4">
                  <div className="text-xs uppercase tracking-wider text-muted">Simulated</div>
                  <div className={`text-2xl font-bold ${scoreTone(whatIfResult.simulated.overall_security_score)}`}>
                    {whatIfResult.simulated.overall_security_score.toFixed(1)}
                    <span className={`ml-2 text-sm ${whatIfResult.delta.overall_security_score >= 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {whatIfResult.delta.overall_security_score >= 0 ? '+' : ''}{whatIfResult.delta.overall_security_score.toFixed(1)}
                    </span>
                  </div>
                  <div className="text-xs text-secondary">Grade {whatIfResult.simulated.crypto_grade} · PFS {whatIfResult.simulated.pfs_status} · {whatIfResult.simulated.violations.length} violation(s)</div>
                  <div className="mt-1 text-2xs text-muted">{Object.entries(whatIfResult.simulated.profiles).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>
                </div>
                <div className="rounded border border-border bg-black/20 p-4 text-xs text-secondary">
                  <div className="text-xs uppercase tracking-wider text-muted">Applied</div>
                  <ul className="mt-1 space-y-0.5">
                    {Object.entries(whatIfResult.overrides_applied).map(([k, v]) => <li key={k}><span className="font-mono text-primary">{k}</span> = {String(v)}</li>)}
                  </ul>
                  {whatIfResult.simulated.violations.length > 0 ? (
                    <div className="mt-2">Remaining: {whatIfResult.simulated.violations.map((v) => v.rule_id).join(', ')}</div>
                  ) : <div className="mt-2 text-emerald-400">No remaining rule violations.</div>}
                </div>
              </div>
            ) : null}
          </Panel>

          <p className="flex items-center gap-2 text-2xs text-muted">
            <FlaskConical className="h-3.5 w-3.5" /> Evaluated {new Date(assessment.evaluated_at).toLocaleString()} · Layer 07 model {analysis.traffic_classification.model_version ?? 'rules only'} · <ShieldCheck className="h-3.5 w-3.5" /> <Sparkles className="h-3.5 w-3.5" /> SIH 26160
          </p>
        </>
      ) : null}
    </PageContainer>
  );
}
