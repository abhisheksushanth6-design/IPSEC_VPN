import { useState } from 'react';
import { AlertCircle, CheckCircle2, Play, Sliders } from 'lucide-react';
import type { BaselineSummary, MLModelConfiguration, MLModelTrainRequest } from '@/types';

interface TrainingPanelProps {
  baselines: BaselineSummary[];
  onTrain: (payload: MLModelTrainRequest) => Promise<void>;
  training: boolean;
}

export function TrainingPanel({ baselines, onTrain, training }: TrainingPanelProps) {
  const [selectedBaselineId, setSelectedBaselineId] = useState<string>(
    baselines.find((b) => b.is_active)?.id || (baselines[0]?.id ?? '')
  );
  const [modelName, setModelName] = useState<string>('');
  const [minSamples, setMinSamples] = useState<number>(3);
  const [contamination, setContamination] = useState<number>(0.05);
  const [nEstimators, setNEstimators] = useState<number>(100);
  const [randomState, setRandomState] = useState<number>(42);
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const selectedBaseline = baselines.find((b) => b.id === selectedBaselineId);
  const sampleCount = selectedBaseline?.session_count ?? 0;
  const isSampleSufficient = sampleCount >= minSamples;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedBaselineId) {
      setErrorMsg('Please select a reference baseline profile.');
      return;
    }
    if (!isSampleSufficient) {
      setErrorMsg(
        `INSUFFICIENT TRAINING DATA: Selected baseline contains ${sampleCount} session(s), but at least ${minSamples} are required.`
      );
      return;
    }

    setErrorMsg(null);
    try {
      const config: MLModelConfiguration = {
        contamination,
        n_estimators: nEstimators,
        max_samples: 'auto',
        random_state: randomState,
      };

      await onTrain({
        baseline_id: selectedBaselineId,
        name: modelName.trim() || undefined,
        model_type: 'IsolationForest',
        minimum_training_samples: minSamples,
        configuration: config,
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'Model training failed');
    }
  };

  return (
    <div className="rounded-lg border border-border bg-surface p-5">
      <div className="flex items-center justify-between pb-4 border-b border-border/60">
        <div>
          <h3 className="text-sm font-bold text-text-primary">MODEL TRAINING WORKFLOW</h3>
          <p className="text-xs text-text-secondary mt-0.5">
            Train an unsupervised Isolation Forest model using real reference sessions from an established baseline.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-1 text-2xs text-muted hover:text-text-primary px-2.5 py-1 rounded border border-border bg-base transition"
        >
          <Sliders className="h-3 w-3" />
          <span>{showAdvanced ? 'Hide Hyperparameters' : 'Hyperparameters'}</span>
        </button>
      </div>

      <form onSubmit={handleSubmit} className="mt-4 space-y-4">
        {/* Baseline Selection */}
        <div>
          <label className="block text-xs font-semibold text-text-primary mb-1">
            Reference Baseline Profile <span className="text-rose-400">*</span>
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <select
              value={selectedBaselineId}
              onChange={(e) => setSelectedBaselineId(e.target.value)}
              className="w-full rounded border border-border bg-base px-3 py-2 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none"
              disabled={training || baselines.length === 0}
            >
              {baselines.length === 0 ? (
                <option value="">No Baselines Available (Build in Layer 06)</option>
              ) : (
                baselines.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name} ({b.session_count} sessions, v{b.version})
                  </option>
                ))
              )}
            </select>

            <input
              type="text"
              placeholder="Model name (e.g. Isolation Forest v1.0)"
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
              className="w-full rounded border border-border bg-base px-3 py-2 text-xs text-text-primary placeholder:text-muted focus:border-cyan-500 focus:outline-none"
              disabled={training}
            />
          </div>
        </div>

        {/* Training Data Validation Indicator */}
        <div className="rounded border border-border/80 bg-base/50 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2">
              {isSampleSufficient ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="h-4 w-4 text-amber-400 shrink-0" />
              )}
              <span className="text-text-primary font-medium">
                Training Sample Validation:
              </span>
              <span className="font-mono text-muted">
                {sampleCount} of {minSamples} minimum sessions available
              </span>
            </div>

            {!isSampleSufficient && (
              <span className="text-2xs font-mono uppercase px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
                INSUFFICIENT TRAINING DATA
              </span>
            )}
          </div>

          {!isSampleSufficient && (
            <p className="text-2xs text-amber-400/90 mt-1.5">
              Additional real session observations are required before a behavioral ML model can be trained reliably.
              Do not fabricate synthetic sessions.
            </p>
          )}
        </div>

        {/* Hyperparameters Drawer */}
        {showAdvanced && (
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 p-3.5 rounded border border-border/80 bg-base/80">
            <div>
              <label className="block text-2xs font-semibold text-muted mb-1">
                Contamination
              </label>
              <input
                type="number"
                step="0.01"
                min="0.001"
                max="0.5"
                value={contamination}
                onChange={(e) => setContamination(parseFloat(e.target.value) || 0.05)}
                className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs font-mono text-text-primary"
                disabled={training}
              />
              <span className="text-3xs text-muted block mt-0.5">Expected outlier proportion</span>
            </div>

            <div>
              <label className="block text-2xs font-semibold text-muted mb-1">
                Estimators (Trees)
              </label>
              <input
                type="number"
                min="10"
                max="500"
                value={nEstimators}
                onChange={(e) => setNEstimators(parseInt(e.target.value) || 100)}
                className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs font-mono text-text-primary"
                disabled={training}
              />
              <span className="text-3xs text-muted block mt-0.5">Ensemble tree count</span>
            </div>

            <div>
              <label className="block text-2xs font-semibold text-muted mb-1">
                Random State (Seed)
              </label>
              <input
                type="number"
                value={randomState}
                onChange={(e) => setRandomState(parseInt(e.target.value) || 42)}
                className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs font-mono text-text-primary"
                disabled={training}
              />
              <span className="text-3xs text-muted block mt-0.5">Controlled seed for determinism</span>
            </div>

            <div>
              <label className="block text-2xs font-semibold text-muted mb-1">
                Min Required Sessions
              </label>
              <input
                type="number"
                min="2"
                max="100"
                value={minSamples}
                onChange={(e) => setMinSamples(parseInt(e.target.value) || 3)}
                className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs font-mono text-text-primary"
                disabled={training}
              />
              <span className="text-3xs text-muted block mt-0.5">Configurable sample threshold</span>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {errorMsg && (
          <div className="flex items-center gap-2 rounded border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Submit */}
        <div className="flex items-center justify-between pt-2">
          <div className="text-2xs text-muted">
            Algorithm: <strong className="text-cyan-400 font-mono">Isolation Forest (Unsupervised)</strong> | Feature Schema: <strong className="font-mono text-text-primary">v1.0</strong>
          </div>

          <button
            type="submit"
            disabled={training || !selectedBaselineId || !isSampleSufficient}
            className="flex items-center gap-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:bg-surface-hover disabled:text-muted disabled:border-border text-white px-4 py-2 text-xs font-bold transition shadow-sm"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>{training ? 'TRAINING MODEL...' : 'TRAIN MODEL'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
