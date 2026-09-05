import { AlertCircle, Play } from 'lucide-react';
import { SessionSelector } from './SessionSelector';
import type { MLModelSummary, VPNSession } from '@/types';

interface InferencePanelProps {
  sessions: VPNSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  activeModel?: MLModelSummary | null;
  onRunInference: () => Promise<void>;
  analyzing: boolean;
}

export function InferencePanel({
  sessions,
  selectedSessionId,
  onSelectSession,
  activeModel,
  onRunInference,
  analyzing,
}: InferencePanelProps) {
  const canAnalyze = Boolean(selectedSessionId && activeModel && activeModel.status === 'READY');

  return (
    <div className="rounded-lg border border-border bg-surface p-5">
      <div className="flex items-center justify-between pb-4 border-b border-border/60">
        <div>
          <h3 className="text-sm font-bold text-text-primary">BEHAVIORAL ANOMALY INFERENCE</h3>
          <p className="text-xs text-text-secondary mt-0.5">
            Evaluate an observed session vector against the active Isolation Forest model to detect behavioral outliers.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-2xs text-muted font-mono">
            Active Model: <strong className="text-purple-400">{activeModel ? activeModel.name : 'None'}</strong>
          </span>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4 items-end">
        <div className="sm:col-span-2">
          <SessionSelector
            sessions={sessions}
            selectedSessionId={selectedSessionId}
            onSelectSession={onSelectSession}
            disabled={analyzing}
          />
        </div>

        <div>
          <button
            onClick={onRunInference}
            disabled={!canAnalyze || analyzing}
            className="w-full flex items-center justify-center gap-2 rounded bg-purple-600 hover:bg-purple-500 disabled:bg-surface-hover disabled:text-muted text-white font-bold text-xs py-2.5 px-4 transition shadow-sm"
          >
            <Play className={`h-3.5 w-3.5 fill-current ${analyzing ? 'animate-spin' : ''}`} />
            <span>{analyzing ? 'RUNNING INFERENCE...' : 'RUN ANOMALY ANALYSIS'}</span>
          </button>
        </div>
      </div>

      {!activeModel && (
        <div className="mt-3 flex items-center gap-2 rounded border border-amber-500/20 bg-amber-500/5 p-2.5 text-2xs text-amber-300">
          <AlertCircle className="h-3.5 w-3.5 shrink-0 text-amber-400" />
          <span>Please train or activate an ML model before running anomaly inference.</span>
        </div>
      )}
    </div>
  );
}
