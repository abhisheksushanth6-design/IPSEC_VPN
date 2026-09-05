import { Fingerprint, Plus, RefreshCw } from 'lucide-react';
import { BaselineEngineBadge } from './BaselineStatusBadge';
import type { BaselineEngineState } from '@/types';

interface BaselineHeaderProps {
  state?: BaselineEngineState;
  reachable?: boolean;
  loading?: boolean;
  onRefresh: () => void;
  onOpenBuildModal: () => void;
}

export function BaselineHeader({
  state,
  reachable = true,
  loading = false,
  onRefresh,
  onOpenBuildModal,
}: BaselineHeaderProps) {
  return (
    <div className="flex flex-col gap-4 border-b border-border bg-surface/80 px-6 py-5 backdrop-blur-sm lg:flex-row lg:items-center lg:justify-between">
      <div className="space-y-1">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Fingerprint className="h-5 w-5" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            SESSION FINGERPRINTING & BASELINE PROFILING
          </h1>
          <BaselineEngineBadge state={state} reachable={reachable} />
        </div>
        <p className="text-xs text-muted max-w-3xl">
          Establish behavioral fingerprints and reference baselines from observed IPsec VPN session features.
          Purely descriptive statistical models representing observed normal behaviors.
        </p>
      </div>

      <div className="flex items-center gap-2.5">
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-text-primary shadow-sm hover:bg-surface-muted transition disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
        <button
          type="button"
          onClick={onOpenBuildModal}
          disabled={!reachable || state === 'NOT INITIALIZED' || state === 'BUILDING'}
          className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm shadow-cyan-950 hover:bg-cyan-500 transition disabled:opacity-50"
        >
          <Plus className="h-3.5 w-3.5" />
          Build New Baseline
        </button>
      </div>
    </div>
  );
}
