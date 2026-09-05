import { ChevronRight, Info, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { DriftSeverityBadge, DriftStatusBadge } from './DriftStatusBadge';
import { DriftVisualization } from './DriftVisualization';
import type { FeatureDrift } from '@/types';

interface DriftDetailDrawerProps {
  feature: FeatureDrift;
  sessionId: string;
  baselineId: string;
  onClose: () => void;
}

export function DriftDetailDrawer({
  feature,
  sessionId,
  baselineId,
  onClose,
}: DriftDetailDrawerProps) {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full bg-surface border border-border rounded-lg shadow-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between border-b border-border p-5 bg-surface-muted/30">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="rounded bg-surface-muted px-2 py-0.5 font-mono text-2xs font-semibold text-text-secondary border border-border">
              {feature.category}
            </span>
            <span className="font-mono text-2xs text-muted">{feature.data_type}</span>
          </div>
          <h2 className="text-base font-bold text-text-primary">
            {feature.display_name}
          </h2>
          <div className="font-mono text-2xs text-muted">{feature.feature_name}</div>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-muted hover:bg-surface-muted hover:text-text-primary transition"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
        {/* Drift Status Banner */}
        <div
          className={`flex items-center justify-between rounded-lg border p-3 ${
            feature.drift_detected
              ? 'border-amber-500/30 bg-amber-500/10'
              : 'border-emerald-500/30 bg-emerald-500/10'
          }`}
        >
          <div className="flex items-center gap-2">
            <DriftStatusBadge status={feature.drift_detected ? 'DRIFT DETECTED' : 'WITHIN BASELINE'} />
            <span className="text-2xs text-muted">Severity:</span>
            <DriftSeverityBadge severity={feature.severity} />
          </div>
        </div>

        {/* Explainable Reason */}
        <div className="space-y-1.5 rounded-lg border border-border bg-base/50 p-3.5">
          <div className="flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wider text-muted">
            <Info className="h-3 w-3 text-cyan-400" />
            <span>Statistical Explanation</span>
          </div>
          <p className="text-xs text-text-primary leading-relaxed font-medium">
            {feature.reason}
          </p>
        </div>

        {/* Visual Distribution */}
        <div className="space-y-2">
          <div className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Distribution Comparison
          </div>
          <DriftVisualization feature={feature} />
        </div>

        {/* Measured Evidence Table */}
        <div className="space-y-2">
          <div className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Auditable Evidence
          </div>
          <div className="overflow-hidden rounded-lg border border-border bg-base/30">
            <table className="w-full text-left text-2xs border-collapse font-mono">
              <tbody className="divide-y divide-border">
                <tr>
                  <td className="py-2 px-3 text-muted">Observed Value</td>
                  <td className="py-2 px-3 text-right font-bold text-text-primary">
                    {feature.current_value !== null && feature.current_value !== undefined
                      ? String(feature.current_value)
                      : '—'}{' '}
                    {feature.unit ?? ''}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-muted">Baseline Mean (μ)</td>
                  <td className="py-2 px-3 text-right text-text-secondary">
                    {typeof feature.baseline_mean === 'number'
                      ? feature.baseline_mean.toFixed(2)
                      : '—'}{' '}
                    {feature.unit ?? ''}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-muted">Baseline Std Dev (σ)</td>
                  <td className="py-2 px-3 text-right text-text-secondary">
                    {typeof feature.baseline_std === 'number'
                      ? feature.baseline_std.toFixed(2)
                      : '—'}{' '}
                    {feature.unit ?? ''}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-muted">Baseline Median</td>
                  <td className="py-2 px-3 text-right text-text-secondary">
                    {typeof feature.baseline_median === 'number'
                      ? feature.baseline_median.toFixed(2)
                      : '—'}{' '}
                    {feature.unit ?? ''}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-muted">Deviation (x - μ)</td>
                  <td className="py-2 px-3 text-right font-bold text-cyan-400">
                    {typeof feature.deviation === 'number'
                      ? `${feature.deviation > 0 ? '+' : ''}${feature.deviation.toFixed(2)}`
                      : '—'}{' '}
                    {feature.unit ?? ''}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-muted">Z-Score</td>
                  <td className="py-2 px-3 text-right font-bold text-text-primary">
                    {typeof feature.z_score === 'number' ? feature.z_score.toFixed(2) : '—'}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-muted">Comparison Method</td>
                  <td className="py-2 px-3 text-right text-muted font-sans text-3xs">
                    {feature.comparison_method}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Lineage & Navigation Links */}
        <div className="space-y-2 pt-2 border-t border-border">
          <div className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Traceability & Lineage
          </div>
          <div className="flex flex-col gap-2">
            <button
              type="button"
              onClick={() => navigate(`/ipsec-sessions?session_id=${encodeURIComponent(sessionId)}`)}
              className="flex items-center justify-between rounded border border-border bg-surface px-3 py-2 text-2xs text-text-secondary hover:border-cyan-500 hover:text-cyan-400 transition"
            >
              <span>View Contributing Session ({sessionId})</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </button>

            <button
              type="button"
              onClick={() => navigate(`/features?session_id=${encodeURIComponent(sessionId)}`)}
              className="flex items-center justify-between rounded border border-border bg-surface px-3 py-2 text-2xs text-text-secondary hover:border-cyan-500 hover:text-cyan-400 transition"
            >
              <span>View Feature Vector (Layer 05)</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </button>

            <button
              type="button"
              onClick={() => navigate(`/baseline-profiling?baseline_id=${encodeURIComponent(baselineId)}`)}
              className="flex items-center justify-between rounded border border-border bg-surface px-3 py-2 text-2xs text-text-secondary hover:border-cyan-500 hover:text-cyan-400 transition"
            >
              <span>View Reference Baseline ({baselineId})</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
