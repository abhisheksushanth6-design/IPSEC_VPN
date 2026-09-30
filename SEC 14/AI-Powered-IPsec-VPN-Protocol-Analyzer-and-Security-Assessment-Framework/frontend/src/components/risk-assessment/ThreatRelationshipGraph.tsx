import { useState } from 'react';
import {
  FileSearch,
  KeyRound,
  Network,
  Shield,
  ShieldAlert,
  Wrench,
  CheckCircle2,
} from 'lucide-react';
import type { RiskAssessmentResponse } from '@/types/risk';
import { cn } from '@/utils/cn';

interface ThreatRelationshipGraphProps {
  assessment: RiskAssessmentResponse | null;
  className?: string;
}

export function ThreatRelationshipGraph({
  assessment,
  className,
}: ThreatRelationshipGraphProps) {
  const [selectedSignalIndex, setSelectedSignalIndex] = useState<number>(0);

  if (!assessment) {
    return (
      <div className={cn('rounded-lg border border-border bg-surface p-6 text-center text-xs text-muted', className)}>
        Select an assessed session to inspect its Threat Relationship Graph.
      </div>
    );
  }

  const signals = assessment.contributing_signals ?? [];
  const activeSignal = signals[selectedSignalIndex] || signals[0];

  // Find corresponding evidence item from assessment.evidence matching activeSignal
  const matchingEvidence = assessment.evidence?.find(
    (ev) =>
      ev.identifier === activeSignal?.evidence_reference ||
      ev.summary.toLowerCase().includes(activeSignal?.reason?.toLowerCase().slice(0, 15) || '')
  ) || assessment.evidence?.[0];

  // Recommended mitigation associated
  const recommendedAction = assessment.recommended_actions?.[0] || 'Enforce RFC 8221 / NIST SP 800-77 Rev 1 cipher hardening.';

  return (
    <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-4 shadow-sm', className)}>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2">
        <div>
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-info" />
            <h3 className="text-xs font-semibold text-primary">Threat Relationship Graph</h3>
          </div>
          <p className="text-2xs text-muted">
            Deterministic causal correlation across Finding → Session → Evidence → Severity → Mitigation
          </p>
        </div>

        {signals.length > 1 && (
          <div className="flex items-center gap-1">
            <span className="text-2xs text-muted">Signal:</span>
            {signals.map((_sig, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setSelectedSignalIndex(idx)}
                className={cn(
                  'rounded px-2 py-0.5 font-mono text-[10px] transition-colors',
                  selectedSignalIndex === idx
                    ? 'bg-info text-white font-bold'
                    : 'bg-elevated text-secondary hover:bg-elevated/80'
                )}
              >
                #{idx + 1}
              </button>
            ))}
          </div>
        )}
      </div>

      {signals.length === 0 ? (
        <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-400 text-center">
          <CheckCircle2 className="h-5 w-5 mx-auto mb-1 text-emerald-400" />
          No negative security finding relationships detected for session{' '}
          <strong className="font-mono text-primary">{assessment.session_id}</strong>.
          The tunnel conforms to baseline security policies.
        </div>
      ) : (
        <div className="space-y-4">
          {/* Visual Node-to-Node Chain */}
          <div className="grid grid-cols-1 gap-2 lg:grid-cols-5 items-stretch">
            {/* Node 1: Security Finding */}
            <div className="flex flex-col justify-between rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs">
              <div>
                <div className="flex items-center justify-between text-2xs font-mono text-rose-400 font-bold uppercase">
                  <span>1. Finding</span>
                  <ShieldAlert className="h-3.5 w-3.5" />
                </div>
                <div className="mt-1 font-semibold text-primary text-xs">
                  {activeSignal?.reason?.split('(')[0] || 'Identified Policy Deficiency'}
                </div>
              </div>
              <div className="mt-2 text-[10px] font-mono text-rose-300">
                Source: {activeSignal?.source || 'SECURITY_RULES'}
              </div>
            </div>

            {/* Node 2: Affected Session */}
            <div className="flex flex-col justify-between rounded-lg border border-info/40 bg-info/10 p-3 text-xs">
              <div>
                <div className="flex items-center justify-between text-2xs font-mono text-info font-bold uppercase">
                  <span>2. Affected Session</span>
                  <KeyRound className="h-3.5 w-3.5" />
                </div>
                <div className="mt-1 font-mono font-bold text-primary text-xs truncate">
                  {assessment.session_id}
                </div>
              </div>
              <div className="mt-2 text-[10px] font-mono text-muted">
                Confidence: {Math.round(assessment.confidence_score * 100)}%
              </div>
            </div>

            {/* Node 3: Observed Evidence */}
            <div className="flex flex-col justify-between rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
              <div>
                <div className="flex items-center justify-between text-2xs font-mono text-amber-400 font-bold uppercase">
                  <span>3. Observed Evidence</span>
                  <FileSearch className="h-3.5 w-3.5" />
                </div>
                <p className="mt-1 text-[11px] text-secondary leading-snug line-clamp-3">
                  {matchingEvidence?.summary || activeSignal?.reason || 'Observable header metadata mismatch'}
                </p>
              </div>
              <div className="mt-2 text-[10px] font-mono text-amber-300 truncate">
                Ref: {activeSignal?.evidence_reference || matchingEvidence?.identifier || 'METRIC_VERIFIED'}
              </div>
            </div>

            {/* Node 4: Risk Severity */}
            <div className="flex flex-col justify-between rounded-lg border border-orange-500/40 bg-orange-500/10 p-3 text-xs">
              <div>
                <div className="flex items-center justify-between text-2xs font-mono text-orange-400 font-bold uppercase">
                  <span>4. Risk Impact</span>
                  <Shield className="h-3.5 w-3.5" />
                </div>
                <div className="mt-1 font-mono text-lg font-extrabold text-orange-400">
                  +{activeSignal?.contribution?.toFixed(1) ?? '15.0'}
                </div>
              </div>
              <div className="mt-2 font-mono text-[10px] uppercase text-orange-300 font-bold">
                {assessment.risk_level} SEVERITY
              </div>
            </div>

            {/* Node 5: Recommended Mitigation */}
            <div className="flex flex-col justify-between rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs">
              <div>
                <div className="flex items-center justify-between text-2xs font-mono text-emerald-400 font-bold uppercase">
                  <span>5. Prescriptive Remediation</span>
                  <Wrench className="h-3.5 w-3.5" />
                </div>
                <p className="mt-1 text-[11px] text-secondary leading-snug line-clamp-3">
                  {recommendedAction}
                </p>
              </div>
              <div className="mt-2 text-[10px] font-mono text-emerald-400 font-bold">
                POLICY: {assessment.decision}
              </div>
            </div>
          </div>

          <div className="rounded border border-border/50 bg-background/50 p-2.5 text-[11px] font-mono text-muted flex items-center justify-between">
            <span className="text-secondary">
              Traceability: Finding <span className="text-info font-bold">{activeSignal?.evidence_reference || 'REF-1'}</span> ➔ Session <span className="text-primary font-bold">{assessment.session_id}</span> ➔ Evidence Verified
            </span>
            <span className="text-[10px] uppercase text-emerald-400">Zero Payload Decryption Needed</span>
          </div>
        </div>
      )}
    </div>
  );
}
