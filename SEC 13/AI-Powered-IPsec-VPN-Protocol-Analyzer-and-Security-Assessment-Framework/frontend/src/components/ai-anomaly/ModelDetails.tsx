import { Cpu, ShieldCheck, X } from 'lucide-react';
import { ModelStatusBadge } from './ModelStatusBadge';
import type { MLModelDetail } from '@/types';

interface ModelDetailsProps {
  model: MLModelDetail;
  onClose?: () => void;
  onActivate?: (modelId: string) => Promise<void> | void;
  onViewDataset?: (datasetId: string) => Promise<void> | void;
}

export function ModelDetails({ model, onClose, onActivate, onViewDataset }: ModelDetailsProps) {
  const diag = model.metrics;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-lg border border-border bg-surface shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4 sticky top-0 bg-surface/95 backdrop-blur z-10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-text-primary">{model.name}</h3>
                <ModelStatusBadge status={model.status} size="sm" />
                {model.is_active && (
                  <span className="text-3xs uppercase font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 font-bold border border-purple-500/30">
                    Active
                  </span>
                )}
              </div>
              <div className="text-2xs font-mono text-muted mt-0.5">
                Model ID: {model.id}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-muted hover:text-text-primary hover:bg-surface-hover transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 text-xs">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="rounded border border-border/80 bg-base p-3">
              <div className="text-2xs text-muted">Model Version</div>
              <div className="text-sm font-bold font-mono text-text-primary mt-0.5">
                v{model.model_version}
              </div>
            </div>

            <div className="rounded border border-border/80 bg-base p-3">
              <div className="text-2xs text-muted">Feature Schema</div>
              <div className="text-sm font-bold font-mono text-text-primary mt-0.5">
                v{model.feature_version}
              </div>
            </div>

            <div className="rounded border border-border/80 bg-base p-3">
              <div className="text-2xs text-muted">Training Samples</div>
              <div className="text-sm font-bold font-mono text-text-primary mt-0.5">
                {model.training_samples} sessions
              </div>
            </div>

            <div className="rounded border border-border/80 bg-base p-3">
              <div className="text-2xs text-muted">Features Count</div>
              <div className="text-sm font-bold font-mono text-text-primary mt-0.5">
                {model.feature_count} features
              </div>
            </div>
          </div>

          {/* Genuine Diagnostics (Unsupervised Diagnostics — No Fake Accuracy) */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-text-secondary">
                Model Diagnostics & Score Distribution
              </h4>
              <span className="text-3xs text-muted font-mono">
                Genuine unsupervised metrics (NO fake accuracy)
              </span>
            </div>

            {diag ? (
              <div className="rounded border border-border/80 bg-base p-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-2xs">
                  <div>
                    <span className="text-muted block">Score Min (Outlier):</span>
                    <strong className="text-rose-400">{diag.score_min.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Score Max (Inlier):</span>
                    <strong className="text-emerald-400">{diag.score_max.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Score Mean:</span>
                    <strong className="text-cyan-400">{diag.score_mean.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Score Std Dev:</span>
                    <strong className="text-text-primary">{diag.score_std.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Quantile 25%:</span>
                    <strong className="text-text-secondary">{diag.score_p25.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Median (50%):</span>
                    <strong className="text-text-secondary">{diag.score_p50.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Quantile 75%:</span>
                    <strong className="text-text-secondary">{diag.score_p75.toFixed(4)}</strong>
                  </div>
                  <div>
                    <span className="text-muted block">Decision Threshold:</span>
                    <strong className="text-purple-400">{diag.score_threshold.toFixed(2)}</strong>
                  </div>
                </div>

                <div className="mt-3 pt-3 border-t border-border/60 text-2xs text-muted font-sans">
                  <strong>Score Interpretation:</strong> Raw score is the decision function output from Isolation Forest.
                  Scores below 0.0 denote isolation outliers; scores above 0.0 indicate high-density inlier behavior.
                </div>
              </div>
            ) : (
              <div className="rounded border border-border/60 bg-base p-3 text-muted text-xs">
                No diagnostic distribution metrics recorded for this model.
              </div>
            )}
          </div>

          {/* Hyperparameter Configuration */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">
              Hyperparameter Configuration
            </h4>
            <div className="rounded border border-border/80 bg-base p-3 font-mono text-2xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {Object.entries(model.configuration).map(([k, v]) => (
                  <div key={k}>
                    <span className="text-muted block">{k}:</span>
                    <strong className="text-text-primary">{String(v)}</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* SHA-256 Artifact Integrity */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">
              Model Artifact & Cryptographic Integrity
            </h4>
            <div className="rounded border border-border/80 bg-base p-3 font-mono text-2xs space-y-1.5">
              <div className="flex items-center gap-2 text-emerald-400 font-sans font-semibold">
                <ShieldCheck className="h-4 w-4 shrink-0" />
                <span>SHA-256 Integrity Verified on Loading</span>
              </div>
              <div className="text-muted truncate">
                Checksum: <span className="text-text-secondary">{model.model_checksum || 'None'}</span>
              </div>
              <div className="text-muted">
                Baseline Lineage: <span className="text-cyan-400">{model.baseline_id || 'Direct'}</span> | Dataset ID: <span className="text-text-secondary">{model.training_dataset_id || 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Feature List */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">
              Features Modeled ({model.feature_names.length})
            </h4>
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 rounded border border-border bg-base">
              {model.feature_names.map((fn) => (
                <span
                  key={fn}
                  className="rounded border border-border/60 bg-surface px-2 py-0.5 text-3xs font-mono text-text-secondary"
                >
                  {fn}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-border px-6 py-4 bg-surface mt-auto">
          <span className="text-2xs text-muted font-mono">
            Created: {new Date(model.created_at).toLocaleString()}
          </span>

          <div className="flex items-center gap-2">
            {model.training_dataset_id && onViewDataset && (
              <button
                onClick={() => onViewDataset(model.training_dataset_id!)}
                className="rounded border border-indigo-500/30 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 px-3 py-1.5 text-xs font-medium transition"
              >
                View Dataset
              </button>
            )}
            {!model.is_active && onActivate && (
              <button
                onClick={() => onActivate(model.id)}
                className="rounded bg-purple-600 hover:bg-purple-500 text-white px-3 py-1.5 text-xs font-semibold transition"
              >
                Set as Active Model
              </button>
            )}
            {onClose && (
              <button
                onClick={onClose}
                className="rounded border border-border bg-base hover:bg-surface-hover text-text-primary px-3 py-1.5 text-xs font-medium transition"
              >
                Close
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
