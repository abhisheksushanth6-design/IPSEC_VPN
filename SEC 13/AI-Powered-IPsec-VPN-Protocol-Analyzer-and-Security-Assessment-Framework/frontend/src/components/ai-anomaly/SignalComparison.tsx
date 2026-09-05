import { Fingerprint, GitCompare, BrainCircuit, Info } from 'lucide-react';
import type { SignalComparisonSummary } from '@/types';

interface SignalComparisonProps {
  signals: SignalComparisonSummary;
}

export function SignalComparison({ signals }: SignalComparisonProps) {
  const isBaselineMember = signals.baseline_status === 'WITHIN_BASELINE';
  const isDrift = signals.drift_status === 'DRIFT_DETECTED';
  const isAnomaly = signals.ml_status === 'ANOMALOUS';

  return (
    <div className="rounded-lg border border-border bg-surface p-5 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-border/60">
        <div>
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">
            BEHAVIORAL ANALYSIS: 3-SIGNAL COMPARISON
          </h3>
          <p className="text-2xs text-muted mt-0.5">
            Integrated analytical signals from Section 9 (Baseline), Section 10 (Drift), and Section 11 (ML).
          </p>
        </div>
        <span className="text-3xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded font-semibold uppercase">
          Separate Signals
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Signal 1: Baseline Profiling */}
        <div className="rounded border border-border/80 bg-base p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-2xs font-semibold text-muted">
              <Fingerprint className="h-3.5 w-3.5 text-cyan-400" />
              <span>Layer 06: Baseline</span>
            </div>
            <span
              className={`text-3xs font-mono font-bold px-2 py-0.5 rounded border ${
                isBaselineMember
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {signals.baseline_status.replace(/_/g, ' ')}
            </span>
          </div>
          <div className="text-xs font-bold text-text-primary">
            Reference Profile Membership
          </div>
          <p className="text-3xs text-muted">
            {isBaselineMember
              ? 'Session is an active member included in the established behavioral baseline.'
              : 'Session was observed independently from reference training profile.'}
          </p>
        </div>

        {/* Signal 2: Statistical Drift Detection */}
        <div className="rounded border border-border/80 bg-base p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-2xs font-semibold text-muted">
              <GitCompare className="h-3.5 w-3.5 text-amber-400" />
              <span>Layer 07: Drift</span>
            </div>
            <span
              className={`text-3xs font-mono font-bold px-2 py-0.5 rounded border ${
                isDrift
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : signals.drift_status === 'NO_DRIFT'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {signals.drift_status.replace(/_/g, ' ')}
            </span>
          </div>
          <div className="text-xs font-bold text-text-primary">
            Statistical Threshold Drift
          </div>
          <p className="text-3xs text-muted">
            {isDrift
              ? 'Deterministic feature deviations exceed configured baseline standard deviations.'
              : signals.drift_status === 'NO_DRIFT'
              ? 'Deterministic feature comparisons remain within expected baseline bounds.'
              : 'No prior drift evaluation recorded for this specific session.'}
          </p>
        </div>

        {/* Signal 3: ML Anomaly Detection */}
        <div className="rounded border border-border/80 bg-base p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-2xs font-semibold text-muted">
              <BrainCircuit className="h-3.5 w-3.5 text-purple-400" />
              <span>Layer 08: ML Model</span>
            </div>
            <span
              className={`text-3xs font-mono font-bold px-2 py-0.5 rounded border ${
                isAnomaly
                  ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              }`}
            >
              {signals.ml_status}
            </span>
          </div>
          <div className="text-xs font-bold text-text-primary">
            Isolation Forest Outlier
          </div>
          <p className="text-3xs text-muted">
            {isAnomaly
              ? 'Unsupervised multi-dimensional partitioning isolated this session as an outlier.'
              : 'Unsupervised partitioning identified this session within normal high-density cluster.'}
          </p>
        </div>
      </div>

      {/* Strict Scope Disclaimer */}
      <div className="flex items-start gap-2 rounded bg-base/60 p-2.5 border border-border/60 text-3xs text-muted">
        <Info className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
        <span>
          <strong>No Risk Fusion:</strong> These three signals represent independent mathematical lenses (membership, univariate variance, and multivariate tree isolation). They are displayed for analyst visibility without artificial fusion into a composite risk or threat score.
        </span>
      </div>
    </div>
  );
}
