import { Activity, AlertCircle, AlertTriangle, CheckCircle2, Database, Sliders } from 'lucide-react';
import type { DriftAnalysis } from '@/types';

interface DriftSummaryProps {
  analysis: DriftAnalysis | null;
  activeBaselineName?: string | null;
}

export function DriftSummary({ analysis, activeBaselineName }: DriftSummaryProps) {
  const analyzed = analysis?.features_analyzed ?? 0;
  const drifting = analysis?.features_drifting ?? 0;

  const lowCount =
    analysis?.feature_results.filter((f) => f.drift_detected && f.severity === 'LOW').length ?? 0;
  const modCount =
    analysis?.feature_results.filter((f) => f.drift_detected && f.severity === 'MODERATE').length ?? 0;
  const highCount =
    analysis?.feature_results.filter((f) => f.drift_detected && f.severity === 'HIGH').length ?? 0;

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6 p-6">
      {/* 1. Analyzed Features */}
      <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Features Analyzed
          </span>
          <Activity className="h-4 w-4 text-cyan-400" />
        </div>
        <div className="mt-2 font-mono text-xl font-bold text-text-primary">
          {analyzed}
        </div>
        <div className="mt-1 text-3xs text-muted">
          v{analysis?.feature_version ?? '1.0'} Schema
        </div>
      </div>

      {/* 2. Drifting Features */}
      <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Features with Drift
          </span>
          <AlertCircle
            className={`h-4 w-4 ${drifting > 0 ? 'text-amber-400' : 'text-emerald-400'}`}
          />
        </div>
        <div
          className={`mt-2 font-mono text-xl font-bold ${
            drifting > 0 ? 'text-amber-400' : 'text-emerald-400'
          }`}
        >
          {drifting}
        </div>
        <div className="mt-1 text-3xs text-muted">
          {analyzed > 0 ? `${Math.round((drifting / analyzed) * 100)}% of features` : '0%'}
        </div>
      </div>

      {/* 3. Low Deviations */}
      <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Low Severity
          </span>
          <CheckCircle2 className="h-4 w-4 text-sky-400" />
        </div>
        <div className="mt-2 font-mono text-xl font-bold text-sky-400">
          {lowCount}
        </div>
        <div className="mt-1 text-3xs text-muted">Mild statistical shift</div>
      </div>

      {/* 4. Moderate Deviations */}
      <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Moderate Severity
          </span>
          <AlertTriangle className="h-4 w-4 text-amber-400" />
        </div>
        <div className="mt-2 font-mono text-xl font-bold text-amber-400">
          {modCount}
        </div>
        <div className="mt-1 text-3xs text-muted">Measurable divergence</div>
      </div>

      {/* 5. High Deviations */}
      <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
            High Severity
          </span>
          <AlertCircle className="h-4 w-4 text-rose-400" />
        </div>
        <div className="mt-2 font-mono text-xl font-bold text-rose-400">
          {highCount}
        </div>
        <div className="mt-1 text-3xs text-muted">Major distribution shift</div>
      </div>

      {/* 6. Active Baseline */}
      <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Reference Baseline
          </span>
          <Database className="h-4 w-4 text-cyan-400" />
        </div>
        <div
          className="mt-2 font-mono text-sm font-bold text-text-primary truncate"
          title={activeBaselineName ?? analysis?.baseline_id ?? 'None'}
        >
          {activeBaselineName ?? (analysis ? `v${analysis.baseline_version}` : 'None')}
        </div>
        <div className="mt-1 text-3xs font-mono text-muted flex items-center gap-1">
          <Sliders className="h-2.5 w-2.5" />
          <span>Config v{analysis?.configuration_version ?? '1.0'}</span>
        </div>
      </div>
    </div>
  );
}
