import { Sliders } from 'lucide-react';
import type { DriftThresholdConfig } from '@/types';

interface DriftConfigurationProps {
  config: DriftThresholdConfig | null;
}

export function DriftConfiguration({ config }: DriftConfigurationProps) {
  if (!config) {
    return (
      <div className="p-8 text-center text-xs text-muted">
        Loading threshold configuration...
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 text-xs max-w-4xl">
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <Sliders className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-text-primary uppercase tracking-wide">
            Active Drift Threshold Configuration
          </h2>
          <span className="rounded bg-surface-muted px-2 py-0.5 font-mono text-3xs font-semibold text-cyan-400 border border-border">
            v{config.config_version}
          </span>
        </div>
        <p className="text-2xs text-muted">
          All statistical deviation rules, Gaussian Z-score cutoffs, and categorical handling parameters are centralized and auditable.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Numerical Gaussian Parameters */}
        <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
          <div className="font-semibold text-text-primary text-xs flex items-center justify-between border-b border-border pb-2">
            <span>Numerical Feature Thresholds</span>
            <span className="font-mono text-3xs text-muted">Gaussian &amp; IQR</span>
          </div>

          <div className="space-y-2 text-2xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-muted">Low Severity Z-Score (|z| ≥)</span>
              <span className="font-bold text-sky-400">{config.z_score_low.toFixed(1)} σ</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Moderate Severity Z-Score (|z| ≥)</span>
              <span className="font-bold text-amber-400">{config.z_score_moderate.toFixed(1)} σ</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">High Severity Z-Score (|z| ≥)</span>
              <span className="font-bold text-rose-400">{config.z_score_high.toFixed(1)} σ</span>
            </div>
            <div className="flex items-center justify-between pt-1 border-t border-border">
              <span className="text-muted">IQR Outlier Multiplier</span>
              <span className="text-text-primary">{config.iqr_multiplier.toFixed(1)} × IQR</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Percentile Bounds Check</span>
              <span className="text-emerald-400 font-semibold">
                {config.enable_percentile_check ? 'ENABLED' : 'DISABLED'}
              </span>
            </div>
          </div>
        </div>

        {/* Categorical & Boolean Parameters */}
        <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
          <div className="font-semibold text-text-primary text-xs flex items-center justify-between border-b border-border pb-2">
            <span>Discrete Feature Evaluation</span>
            <span className="font-mono text-3xs text-muted">Categories &amp; Booleans</span>
          </div>

          <div className="space-y-2 text-2xs font-mono">
            <div className="flex items-center justify-between">
              <span className="text-muted">Unseen Category Severity</span>
              <span className="font-bold text-amber-400">{config.unseen_category_severity}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Rare Category Threshold</span>
              <span className="text-text-primary">&lt; {(config.category_rare_threshold * 100).toFixed(0)}% frequency</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Boolean State Flip Severity</span>
              <span className="font-bold text-sky-400">{config.boolean_flip_severity}</span>
            </div>
            <div className="flex items-center justify-between pt-1 border-t border-border">
              <span className="text-muted">Minimum Baseline Sessions</span>
              <span className="text-text-primary">{config.minimum_baseline_samples} sessions</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Deterministic Reproducibility</span>
              <span className="text-emerald-400 font-semibold">100% Guaranteed</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
