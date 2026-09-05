import React from 'react';
import { Cpu, Play, Search, Sparkles } from 'lucide-react';

interface EmptyAnomalyStateProps {
  type: 'no-models' | 'no-inference' | 'no-results';
  onAction?: () => void;
  actionText?: string;
}

export const EmptyAnomalyState: React.FC<EmptyAnomalyStateProps> = ({
  type,
  onAction,
  actionText,
}) => {
  if (type === 'no-models') {
    return (
      <div className="bg-slate-900 border border-dashed border-slate-700 rounded-2xl p-10 text-center max-w-xl mx-auto shadow-xl">
        <div className="w-14 h-14 mx-auto rounded-2xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 mb-4">
          <Cpu className="w-7 h-7" />
        </div>
        <h3 className="text-lg font-bold text-white mb-2">
          No Trained Isolation Forest Model
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed mb-6">
          The AI / ML Anomaly Detection Engine requires a fitted scikit-learn IsolationForest model.
          Train a model using baseline session features to establish unsupervised anomaly boundaries.
        </p>
        {onAction && (
          <button
            onClick={onAction}
            className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-500/20 transition transform hover:-translate-y-0.5"
          >
            <Sparkles className="w-4 h-4" />
            <span>{actionText || 'Train Isolation Forest Model'}</span>
          </button>
        )}
      </div>
    );
  }

  if (type === 'no-inference') {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-10 text-center max-w-xl mx-auto shadow-md">
        <div className="w-14 h-14 mx-auto rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-4">
          <Play className="w-7 h-7" />
        </div>
        <h3 className="text-lg font-bold text-white mb-2">
          Ready for Anomaly Evaluation
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed mb-6">
          An active ML model is ready. Select an active or historical IPsec session to run real-time
          feature extraction, anomaly scoring, and explainable AI deviation analysis.
        </p>
        {onAction && (
          <button
            onClick={onAction}
            className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg transition"
          >
            <Play className="w-4 h-4" />
            <span>{actionText || 'Select Session & Evaluate'}</span>
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center max-w-md mx-auto">
      <Search className="w-10 h-10 mx-auto text-slate-600 mb-3" />
      <h4 className="text-sm font-semibold text-white mb-1">No Matching Inferences</h4>
      <p className="text-xs text-slate-400 mb-4">
        No anomaly evaluations match the active filter criteria.
      </p>
      {onAction && (
        <button
          onClick={onAction}
          className="text-xs text-indigo-400 hover:text-indigo-300 font-medium underline"
        >
          {actionText || 'Reset Filters'}
        </button>
      )}
    </div>
  );
};
