import React from 'react';
import { Loader2, CheckCircle2, ShieldAlert } from 'lucide-react';

interface TrainingProgressProps {
  isTraining: boolean;
  statusMessage?: string;
  error?: string | null;
}

export const TrainingProgress: React.FC<TrainingProgressProps> = ({
  isTraining,
  statusMessage,
  error,
}) => {
  if (!isTraining && !error) return null;

  const trainingSteps = [
    'Validating baseline sample count & feature version (v1.0)',
    'Preprocessing: Median imputation & deterministic StandardScaling',
    'Fitting IsolationForest ensemble (n_estimators=100, contamination=0.05)',
    'Evaluating empirical score distribution & quantiles (p25, p50, p75)',
    'Serializing model artifact to disk & computing SHA-256 checksum',
  ];

  return (
    <div className="bg-slate-900 border border-indigo-500/50 rounded-xl p-5 shadow-2xl animate-in fade-in duration-200">
      <div className="flex items-center space-x-3 mb-4">
        {isTraining ? (
          <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
        ) : error ? (
          <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        ) : (
          <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        )}

        <div>
          <h4 className="font-semibold text-white text-sm">
            {isTraining
              ? 'Fitting Isolation Forest Model'
              : error
              ? 'Model Training Failed'
              : 'Model Training Complete'}
          </h4>
          <p className="text-xs text-slate-400">
            {statusMessage || (isTraining ? 'Constructing decision trees from baseline sessions...' : '')}
          </p>
        </div>
      </div>

      {error ? (
        <div className="p-3 bg-rose-950/40 border border-rose-800 rounded-lg text-xs text-rose-300 font-mono">
          {error}
        </div>
      ) : (
        <div className="space-y-2 text-xs text-slate-300">
          {trainingSteps.map((step, idx) => (
            <div key={idx} className="flex items-center space-x-2">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
              <span className="text-slate-400 font-mono text-[11px]">{step}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
