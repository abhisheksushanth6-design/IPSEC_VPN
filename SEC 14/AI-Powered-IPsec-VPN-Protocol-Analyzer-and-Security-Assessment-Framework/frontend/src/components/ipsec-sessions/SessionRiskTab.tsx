import { AlertTriangle, CheckCircle2, HelpCircle, RefreshCw, Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { useEffect, useState } from 'react';

import { riskService } from '@/services/riskService';
import type { RiskAssessmentResponse, RiskLevel, PolicyDecision } from '@/types/risk';
import { cn } from '@/utils/cn';

interface SessionRiskTabProps {
  sessionId: string;
}

function getLevelBadgeStyle(level: RiskLevel): string {
  switch (level) {
    case 'CRITICAL':
      return 'border-rose-500/40 bg-rose-500/15 text-rose-400';
    case 'HIGH':
      return 'border-orange-500/40 bg-orange-500/15 text-orange-400';
    case 'MEDIUM':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-400';
    case 'LOW':
    default:
      return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-400';
  }
}

function getDecisionBadgeStyle(decision: PolicyDecision): string {
  switch (decision) {
    case 'TERMINATE':
      return 'border-rose-500/50 bg-rose-600/20 text-rose-300';
    case 'RESTRICT':
      return 'border-orange-500/50 bg-orange-600/20 text-orange-300';
    case 'INSPECT':
      return 'border-amber-500/50 bg-amber-600/20 text-amber-300';
    case 'ALLOW':
    default:
      return 'border-emerald-500/50 bg-emerald-600/20 text-emerald-300';
  }
}

function getDecisionIcon(decision: PolicyDecision) {
  switch (decision) {
    case 'TERMINATE':
      return <ShieldX className="h-4 w-4 text-rose-400" />;
    case 'RESTRICT':
      return <ShieldAlert className="h-4 w-4 text-orange-400" />;
    case 'INSPECT':
      return <AlertTriangle className="h-4 w-4 text-amber-400" />;
    case 'ALLOW':
    default:
      return <ShieldCheck className="h-4 w-4 text-emerald-400" />;
  }
}

export function SessionRiskTab({ sessionId }: SessionRiskTabProps) {
  const [assessment, setAssessment] = useState<RiskAssessmentResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchRisk = async (force: boolean = false) => {
    try {
      if (force) {
        setEvaluating(true);
        const data = await riskService.evaluateSession(sessionId);
        setAssessment(data);
      } else {
        setLoading(true);
        const data = await riskService.getSessionRisk(sessionId);
        setAssessment(data);
      }
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve session risk assessment.');
    } finally {
      setLoading(false);
      setEvaluating(false);
    }
  };

  useEffect(() => {
    fetchRisk(false);
  }, [sessionId]);

  if (loading) {
    return (
      <div className="flex h-48 items-center justify-center space-x-2 text-xs text-muted">
        <RefreshCw className="h-4 w-4 animate-spin text-info" />
        <span>Evaluating session telemetry across Layers 04-09…</span>
      </div>
    );
  }

  if (error || !assessment) {
    return (
      <div className="space-y-3 rounded border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300">
        <div className="flex items-center gap-2 font-medium">
          <AlertTriangle className="h-4 w-4" />
          <span>Risk Assessment Unavailable</span>
        </div>
        <p className="text-muted">{error || 'Session could not be evaluated.'}</p>
        <button
          type="button"
          onClick={() => fetchRisk(true)}
          className="inline-flex items-center gap-1.5 rounded bg-surface px-3 py-1 text-xs text-primary hover:bg-elevated"
        >
          <RefreshCw className="h-3 w-3" />
          Retry Evaluation
        </button>
      </div>
    );
  }

  const { breakdown, contributing_signals, evidence, recommended_actions, available_signals, unavailable_signals } = assessment;

  return (
    <div className="space-y-4 text-xs">
      {/* 1. Header Posture Banner */}
      <div className="rounded border border-border bg-elevated/40 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-info" />
              <span className="text-xs font-semibold uppercase tracking-wider text-muted">
                Layer 10 Holistic Assessment
              </span>
              <span className={cn('rounded border px-2 py-0.5 text-[11px] font-bold uppercase', getLevelBadgeStyle(assessment.risk_level))}>
                {assessment.risk_level} RISK
              </span>
              <span className={cn('inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-bold uppercase', getDecisionBadgeStyle(assessment.decision))}>
                {getDecisionIcon(assessment.decision)}
                {assessment.decision}
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold tracking-tight text-primary">
                {assessment.risk_score.toFixed(1)}
              </span>
              <span className="text-sm text-muted">/ 100</span>
              <span className="ml-3 text-[11px] text-muted">
                Confidence: <strong className="text-primary">{Math.round(assessment.confidence_score * 100)}%</strong> ({assessment.data_quality})
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => fetchRisk(true)}
            disabled={evaluating}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-primary shadow-sm hover:bg-elevated hover:text-info disabled:opacity-50"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', evaluating && 'animate-spin')} />
            {evaluating ? 'Evaluating…' : 'Re-evaluate'}
          </button>
        </div>
      </div>

      {/* 2. Sub-Score Breakdown Grid */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded border border-border/80 bg-surface p-2.5">
          <div className="text-[11px] text-muted">Security Assessment Findings</div>
          <div className="mt-1 text-base font-semibold text-primary">
            {breakdown.vulnerability_score.toFixed(1)} <span className="text-xs font-normal text-muted">/ 50</span>
          </div>
        </div>
        <div className="rounded border border-border/80 bg-surface p-2.5">
          <div className="text-[11px] text-muted">Supplementary ML Score</div>
          <div className="mt-1 text-base font-semibold text-primary">
            {breakdown.ml_score.toFixed(1)} <span className="text-xs font-normal text-muted">/ 30</span>
          </div>
        </div>
        <div className="rounded border border-border/80 bg-surface p-2.5">
          <div className="text-[11px] text-muted">Protocol Deviation Score</div>
          <div className="mt-1 text-base font-semibold text-primary">
            {breakdown.drift_score.toFixed(1)} <span className="text-xs font-normal text-muted">/ 12</span>
          </div>
        </div>
        <div className="rounded border border-border/80 bg-surface p-2.5">
          <div className="text-[11px] text-muted">SA &amp; Protocol State (L04)</div>
          <div className="mt-1 text-base font-semibold text-primary">
            {breakdown.state_score.toFixed(1)} <span className="text-xs font-normal text-muted">/ 8</span>
          </div>
        </div>
      </div>

      {/* 3. Signal Telemetry Coverage */}
      <div className="rounded border border-border bg-surface p-3">
        <div className="mb-2 font-medium text-primary">Telemetry Completeness (Explainable Coverage)</div>
        <div className="flex flex-wrap gap-2">
          {available_signals.map((sig) => (
            <span
              key={sig}
              className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-400 border border-emerald-500/30"
            >
              <CheckCircle2 className="h-3 w-3" />
              {sig.replace(/_/g, ' ')}
            </span>
          ))}
          {unavailable_signals.map((sig) => (
            <span
              key={sig}
              className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-400 border border-amber-500/30"
            >
              <HelpCircle className="h-3 w-3" />
              {sig.replace(/_/g, ' ')} (MISSING)
            </span>
          ))}
        </div>
      </div>

      {/* 4. Contributing Signals */}
      <div className="rounded border border-border bg-surface p-3">
        <div className="mb-2 font-medium text-primary">Contributing Risk Signals ({contributing_signals.length})</div>
        {contributing_signals.length === 0 ? (
          <p className="text-muted italic">No negative risk factors detected in available telemetry.</p>
        ) : (
          <div className="space-y-2">
            {contributing_signals.map((sig, idx) => (
              <div key={idx} className="flex items-start justify-between gap-3 rounded bg-elevated/40 p-2 border border-border/60">
                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-[10px] text-info uppercase font-bold">{sig.source}</span>
                    <span className="text-primary">{sig.reason}</span>
                  </div>
                  {sig.evidence_reference && (
                    <div className="mt-1 font-mono text-[10px] text-muted">
                      Ref: {sig.evidence_reference}
                    </div>
                  )}
                </div>
                <div className="shrink-0 font-mono font-bold text-rose-400">
                  +{sig.contribution.toFixed(1)} pts
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 5. Prioritized Recommended Actions */}
      <div className="rounded border border-border bg-surface p-3">
        <div className="mb-2 font-medium text-primary">Prioritized Remediations ({recommended_actions.length})</div>
        <ul className="space-y-1.5">
          {recommended_actions.map((rec, idx) => (
            <li key={idx} className="flex items-start gap-2 text-muted">
              <span className="text-info font-bold">•</span>
              <span className="text-secondary">{rec}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* 6. Verifiable Detection Evidence */}
      {evidence.length > 0 && (
        <div className="rounded border border-border bg-surface p-3">
          <div className="mb-2 font-medium text-primary">Verifiable Evidence Links ({evidence.length})</div>
          <div className="space-y-1">
            {evidence.map((ev, idx) => (
              <div key={idx} className="font-mono text-[11px] text-muted">
                [{ev.source_layer}] <span className="text-primary">{ev.evidence_type}</span> ({ev.identifier}): {ev.summary}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
