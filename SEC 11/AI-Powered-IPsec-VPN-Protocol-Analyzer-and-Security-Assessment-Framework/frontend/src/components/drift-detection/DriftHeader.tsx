import { GitCompare, Play, RefreshCw } from 'lucide-react';
import { DriftEngineBadge } from './DriftStatusBadge';
import type { DriftEngineStatus } from '@/types';

interface DriftHeaderProps {
  status?: DriftEngineStatus;
  loading: boolean;
  onRefresh: () => void;
  onTriggerAnalyze: () => void;
  canAnalyze: boolean;
}

export function DriftHeader({
  status,
  loading,
  onRefresh,
  onTriggerAnalyze,
  canAnalyze,
}: DriftHeaderProps) {
  return (
    <div className="flex flex-col gap-4 border-b border-border bg-surface px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <GitCompare className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-bold uppercase tracking-wide text-text-primary">
                SECURITY DRIFT DETECTION
              </h1>
              <DriftEngineBadge state={status?.state} />
            </div>
            <p className="text-xs text-muted">
              Identify measurable changes in observed IPsec VPN behavior relative to an established behavioral baseline.
            </p>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2.5">
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-surface-muted hover:text-text-primary transition disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh</span>
        </button>

        <button
          type="button"
          onClick={onTriggerAnalyze}
          disabled={!canAnalyze || loading}
          className="inline-flex items-center gap-1.5 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition disabled:opacity-50"
        >
          <Play className="h-3.5 w-3.5" />
          <span>Analyze Drift</span>
        </button>
      </div>
    </div>
  );
}
