import { Info } from 'lucide-react';
import { DriftSeverityBadge, DriftStatusBadge } from './DriftStatusBadge';
import type { DriftAnalysis } from '@/types';

interface DriftStatusCardProps {
  analysis: DriftAnalysis;
}

export function DriftStatusCard({ analysis }: DriftStatusCardProps) {
  const isDrift = analysis.status === 'DRIFT DETECTED';

  return (
    <div
      className={`mx-6 mb-6 rounded-lg border p-5 transition ${
        isDrift
          ? 'border-amber-500/30 bg-gradient-to-r from-amber-500/5 via-surface to-surface'
          : 'border-emerald-500/30 bg-gradient-to-r from-emerald-500/5 via-surface to-surface'
      }`}
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2.5">
            <DriftStatusBadge status={analysis.status} />
            <div className="flex items-center gap-1.5">
              <span className="text-2xs font-medium text-muted">Overall Severity:</span>
              <DriftSeverityBadge severity={analysis.severity} />
            </div>
          </div>

          <div>
            <h2 className="text-base font-bold text-text-primary">
              {isDrift ? 'Behavioral Drift Detected' : 'Session Behavior Within Reference Baseline'}
            </h2>
            <p className="text-xs text-text-secondary mt-0.5 max-w-2xl">
              {isDrift
                ? `${analysis.features_drifting} of ${analysis.features_analyzed} observed session features diverge from established reference distributions by more than configured statistical thresholds.`
                : `All ${analysis.features_analyzed} extracted session features are statistically consistent with the active reference baseline profile.`}
            </p>
          </div>

          {/* Educational Note: Drift != Anomaly or Threat */}
          <div className="flex items-center gap-2 rounded border border-border/80 bg-base/60 px-3 py-1.5 text-2xs text-muted max-w-2xl">
            <Info className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
            <span>
              <strong>Note:</strong> Behavioral drift indicates statistical deviation from observed reference norms.
              It does not automatically imply malicious activity, security compromise, or system failure.
            </span>
          </div>
        </div>

        {/* Target Session & Baseline Lineage */}
        <div className="flex flex-col gap-1.5 text-2xs sm:text-right font-mono border-t sm:border-t-0 pt-3 sm:pt-0 border-border">
          <div>
            <span className="text-muted">Target Session: </span>
            <span className="font-semibold text-text-primary">{analysis.session_id}</span>
          </div>
          <div>
            <span className="text-muted">Baseline: </span>
            <span className="text-cyan-400 font-semibold">{analysis.baseline_id}</span>
            <span className="text-muted"> (v{analysis.baseline_version})</span>
          </div>
          <div className="text-muted">
            Analyzed: {new Date(analysis.analyzed_at).toLocaleString()}
          </div>
        </div>
      </div>
    </div>
  );
}
