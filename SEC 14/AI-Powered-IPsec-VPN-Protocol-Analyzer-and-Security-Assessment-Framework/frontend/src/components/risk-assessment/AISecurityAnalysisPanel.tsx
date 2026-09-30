import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  BrainCircuit,
  Check,
  Copy,
  Cpu,
  Layers,
  RefreshCw,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Zap,
} from 'lucide-react';
import { aiAnalysisService } from '@/services';
import type {
  AISecurityAnalysis,
  AttackImplication,
  PrioritizedFinding,
  RemediationStep,
} from '@/types';

export function AISecurityAnalysisPanel() {
  const [analysis, setAnalysis] = useState<AISecurityAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [triggering, setTriggering] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Active section tab: 'executive' | 'prioritized' | 'threats' | 'remediation' | 'technical'
  const [activeSection, setActiveSection] = useState<string>('executive');

  // Remediation phase filter: 'ALL' | 'PHASE_1_IMMEDIATE' | 'PHASE_2_HARDENING' | 'PHASE_3_ARCHITECTURAL'
  const [remediationPhase, setRemediationPhase] = useState<string>('ALL');

  // Selected provider: 'mock' | 'deterministic' | 'llm'
  const [selectedProvider, setSelectedProvider] = useState<string>('deterministic');

  // Copied snippet trackers
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadData = async (provider?: string) => {
    try {
      setLoading(true);
      setError(null);
      const res = await aiAnalysisService.getAnalysis(provider);
      setAnalysis(res);
    } catch {
      setError('AI security analysis data not yet available or engine offline.');
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerAnalysis = async () => {
    try {
      setTriggering(true);
      setError(null);
      const res = await aiAnalysisService.triggerAnalysis(selectedProvider);
      setAnalysis(res);
    } catch {
      setError('Failed to execute AI re-analysis.');
    } finally {
      setTriggering(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  useEffect(() => {
    void loadData();
  }, []);

  if (loading && !analysis) {
    return (
      <div className="rounded border border-border bg-surface p-10 text-center text-xs text-secondary">
        <BrainCircuit className="mx-auto mb-3 h-8 w-8 animate-pulse text-indigo-400" />
        <p className="font-semibold text-primary">Synthesizing Layer 07 AI Security Analysis…</p>
        <p className="mt-1 text-muted">Correlating attack vectors, exploit chains, and remediation guidance</p>
      </div>
    );
  }

  if (error && !analysis) {
    return (
      <div className="flex items-center justify-between rounded border border-border bg-surface p-4 text-xs text-secondary">
        <span>{error}</span>
        <button
          type="button"
          onClick={() => void loadData()}
          className="inline-flex items-center gap-1 rounded border border-border px-2.5 py-1 text-primary hover:border-info"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Retry
        </button>
      </div>
    );
  }

  if (!analysis) return null;

  const execSummary = analysis.executive_summary ?? {
    overall_posture: 'UNKNOWN',
    risk_score_summary: '',
    business_impact: '',
    compliance_overview: '',
    strategic_recommendations: [],
  };
  const techSummary = analysis.technical_summary ?? {
    protocol_health: '',
    cryptographic_assessment: '',
    integrity_and_sequence_analysis: '',
    leakage_and_exposure_analysis: '',
    rfc_compliance_citations: [],
  };
  const prioritizedFindings = Array.isArray(analysis.prioritized_findings) ? analysis.prioritized_findings : [];
  const attackImplications = Array.isArray(analysis.attack_implications) ? analysis.attack_implications : [];
  const remediationSteps = Array.isArray(analysis.remediation_steps) ? analysis.remediation_steps : [];
  const strategicRecs = Array.isArray(execSummary.strategic_recommendations) ? execSummary.strategic_recommendations : [];
  const rfcCitations = Array.isArray(techSummary.rfc_compliance_citations) ? techSummary.rfc_compliance_citations : [];

  const getPriorityBadge = (p: string) => {
    switch (p) {
      case 'P1_CRITICAL':
        return 'bg-danger/20 text-danger border-danger/40';
      case 'P2_HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'P3_MEDIUM':
        return 'bg-warning/20 text-warning border-warning/40';
      case 'P4_LOW':
        return 'bg-info/20 text-info border-info/40';
      default:
        return 'bg-muted/20 text-muted border-border';
    }
  };

  const getUrgencyBadge = (u: string) => {
    switch (u) {
      case 'IMMEDIATE':
        return 'bg-danger/10 text-danger border-danger/30';
      case 'SCHEDULED':
        return 'bg-warning/10 text-warning border-warning/30';
      default:
        return 'bg-secondary/10 text-secondary border-border';
    }
  };

  const getPhaseColor = (phase: string) => {
    switch (phase) {
      case 'PHASE_1_IMMEDIATE':
        return 'border-l-4 border-l-danger bg-danger/5';
      case 'PHASE_2_HARDENING':
        return 'border-l-4 border-l-warning bg-warning/5';
      case 'PHASE_3_ARCHITECTURAL':
        return 'border-l-4 border-l-info bg-info/5';
      default:
        return 'border-l-4 border-l-border bg-surface';
    }
  };

  const filteredRemediation =
    remediationPhase === 'ALL'
      ? remediationSteps
      : remediationSteps.filter((s) => s.phase === remediationPhase);

  return (
    <div className="space-y-6">
      {/* Top Bar: Model / Engine Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-primary">Layer 07: AI Security Analysis</h2>
              <span className="rounded-full bg-indigo-500/15 px-2 py-0.5 text-[10px] font-semibold text-indigo-300 border border-indigo-500/30">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-secondary">
              Provider:{' '}
              <span className="font-mono text-primary">{analysis.provider_used}</span>
              {' · '}Analysis ID:{' '}
              <span className="font-mono text-muted">{analysis.analysis_id}</span>
              {' · '}Evaluated:{' '}
              <span className="text-muted">{new Date(analysis.timestamp).toLocaleTimeString()}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={selectedProvider}
            onChange={(e) => setSelectedProvider(e.target.value)}
            className="rounded border border-border bg-background px-2.5 py-1 text-xs text-primary focus:border-info focus:outline-none"
          >
            <option value="deterministic">Deterministic Engine</option>
            <option value="mock">Offline Mock Provider</option>
            <option value="gemini">Gemini / LLM Provider</option>
          </select>

          <button
            type="button"
            onClick={() => void handleTriggerAnalysis()}
            disabled={triggering}
            className="inline-flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50 transition-colors shadow-sm"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${triggering ? 'animate-spin' : ''}`} />
            {triggering ? 'Analyzing…' : 'Re-Analyze'}
          </button>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex flex-wrap gap-1 border-b border-border text-xs">
        {[
          { id: 'executive', label: 'Executive Briefing', icon: Shield },
          { id: 'prioritized', label: `Prioritized Findings (${prioritizedFindings.length})`, icon: ShieldAlert },
          { id: 'threats', label: `Threat Vectors & MITRE (${attackImplications.length})`, icon: Zap },
          { id: 'remediation', label: `Phased Roadmap (${remediationSteps.length})`, icon: Terminal },
          { id: 'technical', label: 'SOC Technical Dossier', icon: Cpu },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSection === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveSection(tab.id)}
              className={`inline-flex items-center gap-1.5 border-b-2 px-3.5 py-2 font-medium transition-colors ${
                isActive
                  ? 'border-indigo-500 text-indigo-400 font-semibold'
                  : 'border-transparent text-secondary hover:border-border hover:text-primary'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: Executive Briefing */}
      {activeSection === 'executive' && (
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-surface p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 pb-3">
              <div>
                <h3 className="text-sm font-semibold text-primary flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-indigo-400" />
                  CISO Executive Security Briefing
                </h3>
                <p className="text-xs text-secondary mt-0.5">
                  High-level strategic posture assessment and business exposure overview
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted">Posture Status:</span>
                <span className="rounded px-2.5 py-1 text-xs font-bold uppercase tracking-wider bg-danger/20 text-danger border border-danger/40">
                  {(execSummary.overall_posture || 'UNKNOWN').replace(/_/g, ' ')}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="rounded border border-border bg-background/50 p-3.5 space-y-1.5">
                <span className="font-semibold text-primary block">Risk Score Summary</span>
                <p className="text-secondary leading-relaxed">{execSummary.risk_score_summary}</p>
              </div>

              <div className="rounded border border-border bg-background/50 p-3.5 space-y-1.5">
                <span className="font-semibold text-primary block">Business Impact</span>
                <p className="text-secondary leading-relaxed">{execSummary.business_impact}</p>
              </div>
            </div>

            <div className="rounded border border-border bg-background/50 p-3.5 space-y-2 text-xs">
              <span className="font-semibold text-primary block">Compliance & Regulatory Exposure</span>
              <p className="text-secondary leading-relaxed">{execSummary.compliance_overview}</p>
            </div>

            <div className="rounded border border-border bg-background/50 p-3.5 space-y-2 text-xs">
              <span className="font-semibold text-primary block">Strategic Recommendations</span>
              <ul className="space-y-1.5 pl-4 list-disc text-secondary marker:text-indigo-400">
                {strategicRecs.map((rec, i) => (
                  <li key={i} className="leading-relaxed">
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Prioritized Findings */}
      {activeSection === 'prioritized' && (
        <div className="space-y-3">
          {prioritizedFindings.map((f: PrioritizedFinding) => (
            <div
              key={f.finding_id}
              className="rounded-lg border border-border bg-surface p-4 text-xs space-y-3 transition hover:border-border/80"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase ${getPriorityBadge(
                      f.priority_rank
                    )}`}
                  >
                    {f.priority_rank}
                  </span>
                  <span
                    className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${getUrgencyBadge(
                      f.urgency
                    )}`}
                  >
                    {f.urgency}
                  </span>
                  <span className="font-semibold text-primary text-sm">{f.title}</span>
                </div>

                <div className="flex items-center gap-2 font-mono text-[11px] text-muted">
                  <span>Score: {f.exploitability_score <= 10 ? Math.round(f.exploitability_score * 10) : Math.round(f.exploitability_score)}/100</span>
                  <span>·</span>
                  <span>{f.finding_id}</span>
                </div>
              </div>

              <div className="text-secondary leading-relaxed pl-1">
                <p>{f.justification}</p>
              </div>

              {/* Context & CVE Pills */}
              <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-border/40">
                {f.affected_session && (
                  <span className="rounded bg-background px-2 py-0.5 font-mono text-[10px] text-secondary border border-border">
                    Session: {f.affected_session}
                  </span>
                )}
                {f.cve_references.map((cve) => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 rounded bg-danger/10 px-2 py-0.5 font-mono text-[10px] font-medium text-danger border border-danger/30 hover:underline"
                  >
                    {cve}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 3: Threat Vectors & MITRE ATT&CK */}
      {activeSection === 'threats' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {attackImplications.map((att: AttackImplication) => (
            <div
              key={att.attack_id}
              className="flex flex-col justify-between rounded-lg border border-border bg-surface p-4 space-y-3"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="font-semibold text-primary text-sm">{att.vector_name}</span>
                  <span className="rounded bg-indigo-500/10 px-2 py-0.5 font-mono text-[10px] text-indigo-300 border border-indigo-500/30 shrink-0">
                    {att.mitre_attack_technique}
                  </span>
                </div>

                <div className="text-secondary space-y-1.5 leading-relaxed">
                  <p>
                    <strong className="text-primary font-medium">Actor Profile:</strong> {att.threat_actor_profile}
                  </p>
                  <p>
                    <strong className="text-primary font-medium">Prerequisites:</strong> {att.prerequisites}
                  </p>
                  <div className="rounded bg-background/60 p-2.5 border border-border text-[11px] font-mono text-muted">
                    {att.exploit_scenario}
                  </div>
                </div>
              </div>

              <div className="border-t border-border/50 pt-2 space-y-1">
                <span className="font-medium text-primary text-[11px]">Impact Summary:</span>
                <p className="text-secondary text-[11px]">{att.impact_summary}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 4: Phased Remediation Roadmap */}
      {activeSection === 'remediation' && (
        <div className="space-y-4">
          {/* Phase Filter Buttons */}
          <div className="flex flex-wrap gap-2 text-xs">
            {[
              { id: 'ALL', label: 'All Phases' },
              { id: 'PHASE_1_IMMEDIATE', label: 'Phase 1: Immediate Mitigations' },
              { id: 'PHASE_2_HARDENING', label: 'Phase 2: Cryptographic Hardening' },
              { id: 'PHASE_3_ARCHITECTURAL', label: 'Phase 3: Architectural Migration' },
            ].map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setRemediationPhase(p.id)}
                className={`rounded border px-2.5 py-1 transition-colors ${
                  remediationPhase === p.id
                    ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300 font-semibold'
                    : 'border-border bg-surface text-secondary hover:border-border/80'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="space-y-4">
            {filteredRemediation.map((step: RemediationStep) => (
              <div
                key={step.step_id}
                className={`rounded-lg border border-border p-4 text-xs space-y-3 ${getPhaseColor(step.phase)}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-background px-2 py-0.5 font-mono text-[10px] text-muted border border-border">
                      {step.phase.replace(/_/g, ' ')}
                    </span>
                    <span className="rounded bg-background px-2 py-0.5 text-[10px] font-semibold text-secondary border border-border">
                      Effort: {step.effort}
                    </span>
                    <span className="font-semibold text-primary text-sm">{step.action_title}</span>
                  </div>
                  <span className="font-mono text-[11px] text-muted">{step.component}</span>
                </div>

                <p className="text-secondary leading-relaxed">{step.instructions}</p>

                {/* Config Snippet */}
                {step.config_snippet && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-muted font-mono">
                      <span>Configuration Directive:</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(step.config_snippet, `${step.step_id}-cfg`)}
                        className="inline-flex items-center gap-1 text-primary hover:text-indigo-400"
                      >
                        {copiedId === `${step.step_id}-cfg` ? (
                          <Check className="h-3 w-3 text-success" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        {copiedId === `${step.step_id}-cfg` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <pre className="overflow-x-auto rounded bg-background p-2.5 font-mono text-[11px] text-primary border border-border">
                      {step.config_snippet}
                    </pre>
                  </div>
                )}

                {/* Verification Command */}
                {step.verification_command && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-muted font-mono">
                      <span>Verification Command:</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(step.verification_command, `${step.step_id}-cmd`)}
                        className="inline-flex items-center gap-1 text-primary hover:text-indigo-400"
                      >
                        {copiedId === `${step.step_id}-cmd` ? (
                          <Check className="h-3 w-3 text-success" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        {copiedId === `${step.step_id}-cmd` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <pre className="overflow-x-auto rounded bg-background p-2.5 font-mono text-[11px] text-indigo-300 border border-border">
                      $ {step.verification_command}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: SOC Technical Dossier */}
      {activeSection === 'technical' && (
        <div className="space-y-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-lg border border-border bg-surface p-4 space-y-2">
              <span className="font-semibold text-primary text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-info" />
                Protocol Health
              </span>
              <p className="text-secondary leading-relaxed">{techSummary.protocol_health}</p>
            </div>

            <div className="rounded-lg border border-border bg-surface p-4 space-y-2">
              <span className="font-semibold text-primary text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-warning" />
                Cryptographic Assessment
              </span>
              <p className="text-secondary leading-relaxed">{techSummary.cryptographic_assessment}</p>
            </div>

            <div className="rounded-lg border border-border bg-surface p-4 space-y-2">
              <span className="font-semibold text-primary text-sm flex items-center gap-2">
                <Cpu className="h-4 w-4 text-danger" />
                Integrity & Sequence Tracking
              </span>
              <p className="text-secondary leading-relaxed">{techSummary.integrity_and_sequence_analysis}</p>
            </div>

            <div className="rounded-lg border border-border bg-surface p-4 space-y-2">
              <span className="font-semibold text-primary text-sm flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
                Leakage & Exposure Analysis
              </span>
              <p className="text-secondary leading-relaxed">{techSummary.leakage_and_exposure_analysis}</p>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-surface p-4 space-y-2">
            <span className="font-semibold text-primary text-sm block">RFC Compliance References</span>
            <div className="flex flex-wrap gap-2 pt-1">
              {rfcCitations.map((rfc, i) => (
                <span
                  key={i}
                  className="rounded bg-background px-2.5 py-1 font-mono text-[11px] text-primary border border-border"
                >
                  {rfc}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
