import { AlertTriangle, Cpu, Database, FileCheck, Layers } from 'lucide-react';
import type { MLModelSummary } from '@/types';

interface ModelStatusCardProps {
  activeModel?: MLModelSummary | null;
  onManageModels?: () => void;
  onTrainNew?: () => void;
  totalModels?: number;
  featureVersion?: string;
  preprocessingVersion?: string;
  onTrainClick?: () => void;
}

export function ModelStatusCard({
  activeModel,
  onManageModels,
  onTrainNew,
  totalModels: _totalModels,
  featureVersion: _featureVersion,
  preprocessingVersion: _preprocessingVersion,
  onTrainClick,
}: ModelStatusCardProps) {
  const handleTrain = onTrainNew || onTrainClick;
  if (!activeModel) {
    return (
      <div className="rounded-lg border border-amber-500/30 bg-gradient-to-r from-amber-500/5 via-surface to-surface p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="rounded-md bg-amber-500/10 p-2 border border-amber-500/20 text-amber-400 shrink-0">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-text-primary">NO ACTIVE MODEL LOADED</h3>
              <p className="text-xs text-text-secondary mt-0.5 max-w-xl">
                The AI anomaly detection engine requires a trained and validated Isolation Forest model
                fitted on reference baseline sessions to execute behavioral inference.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            {handleTrain && (
              <button
                onClick={handleTrain}
                className="rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs px-3 py-1.5 transition shadow-sm"
              >
                TRAIN MODEL
              </button>
            )}
            {onManageModels && (
              <button
                onClick={onManageModels}
                className="rounded border border-border bg-surface px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-surface-hover transition"
              >
                View Model Registry
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  const createdDate = new Date(activeModel.created_at).toLocaleString();

  return (
    <div className="rounded-lg border border-border bg-surface p-5 shadow-sm">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-4 border-b border-border/60">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 text-2xs font-semibold text-purple-400">
              ACTIVE BEHAVIORAL MODEL
            </span>
            <span className="font-mono text-xs font-bold text-text-primary">
              {activeModel.name}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-muted mt-1.5">
            <span>Model ID: <strong className="font-mono text-text-secondary">{activeModel.id}</strong></span>
            <span>Type: <strong className="font-mono text-cyan-400">{activeModel.model_type}</strong></span>
            <span>Trained: <strong className="font-mono text-text-secondary">{createdDate}</strong></span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {onTrainNew && (
            <button
              onClick={onTrainNew}
              className="rounded border border-border bg-surface-hover/60 hover:bg-surface-hover text-text-secondary hover:text-text-primary text-xs px-3 py-1.5 transition"
            >
              Train New Version
            </button>
          )}
          {onManageModels && (
            <button
              onClick={onManageModels}
              className="rounded border border-border bg-surface hover:bg-surface-hover text-text-secondary hover:text-text-primary text-xs px-3 py-1.5 transition"
            >
              Model Registry
            </button>
          )}
        </div>
      </div>

      {/* Grid of Key Properties */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-base border border-border/80 text-cyan-400">
            <Cpu className="h-4 w-4" />
          </div>
          <div>
            <div className="text-2xs text-muted">Model Version</div>
            <div className="font-mono text-sm font-bold text-text-primary">
              v{activeModel.model_version}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-base border border-border/80 text-emerald-400">
            <Layers className="h-4 w-4" />
          </div>
          <div>
            <div className="text-2xs text-muted">Feature Schema</div>
            <div className="font-mono text-sm font-bold text-text-primary">
              v{activeModel.feature_version} ({activeModel.feature_count} features)
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-base border border-border/80 text-purple-400">
            <Database className="h-4 w-4" />
          </div>
          <div>
            <div className="text-2xs text-muted">Training Samples</div>
            <div className="font-mono text-sm font-bold text-text-primary">
              {activeModel.training_samples} sessions
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-base border border-border/80 text-blue-400">
            <FileCheck className="h-4 w-4" />
          </div>
          <div>
            <div className="text-2xs text-muted">Pipeline Version</div>
            <div className="font-mono text-sm font-bold text-text-primary">
              v{activeModel.preprocessing_version} (Normalised)
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
