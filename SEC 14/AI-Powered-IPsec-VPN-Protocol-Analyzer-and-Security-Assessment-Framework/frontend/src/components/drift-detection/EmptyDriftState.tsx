import { ArrowRight, Database, GitCompare, Network, Play } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { DriftEngineState } from '@/types';

interface EmptyDriftStateProps {
  state?: DriftEngineState;
  onTriggerAnalyze: () => void;
  canAnalyze: boolean;
}

export function EmptyDriftState({ state, onTriggerAnalyze, canAnalyze }: EmptyDriftStateProps) {
  if (state === 'NOT INITIALIZED') {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-border bg-surface m-6">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-surface-muted border border-border text-muted mb-3">
          <Database className="h-6 w-6" />
        </div>
        <h2 className="text-base font-bold text-text-primary">No Active Baseline Profile</h2>
        <p className="text-xs text-muted max-w-md mt-1 mb-5">
          Security drift detection evaluates observed VPN sessions against an established behavioral baseline.
          Build and activate a baseline profile to begin detecting drift.
        </p>
        <Link to="/baseline-profiling">
          <span className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition">
            <span>Go to Baseline Profiling</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </span>
        </Link>
      </div>
    );
  }

  if (state === 'INSUFFICIENT DATA') {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-border bg-surface m-6">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 mb-3">
          <Network className="h-6 w-6" />
        </div>
        <h2 className="text-base font-bold text-text-primary">Insufficient Baseline Observations</h2>
        <p className="text-xs text-muted max-w-md mt-1 mb-5">
          The active reference baseline has insufficient sessions for statistically valid Gaussian comparison (minimum 3 sessions required).
        </p>
        <Link to="/baseline-profiling">
          <span className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition">
            <span>Inspect Baseline Coverage</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </span>
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-border bg-surface m-6">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 mb-3">
        <GitCompare className="h-6 w-6" />
      </div>
      <h2 className="text-base font-bold text-text-primary">Ready for Drift Evaluation</h2>
      <p className="text-xs text-muted max-w-md mt-1 mb-5">
        Observed session feature vectors and active reference baseline distributions are loaded.
        Select a target session and trigger drift analysis.
      </p>
      <button
        type="button"
        onClick={onTriggerAnalyze}
        disabled={!canAnalyze}
        className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition disabled:opacity-50"
      >
        <Play className="h-3.5 w-3.5" />
        <span>Analyze Target Session Drift</span>
      </button>
    </div>
  );
}
