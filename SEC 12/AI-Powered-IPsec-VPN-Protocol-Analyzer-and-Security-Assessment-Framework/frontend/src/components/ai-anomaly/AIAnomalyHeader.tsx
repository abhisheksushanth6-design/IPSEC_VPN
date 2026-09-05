import { BrainCircuit, RefreshCw } from 'lucide-react';
import { ModelStatusBadge } from './ModelStatusBadge';
import type { MLModelStatus } from '@/types';

interface AIAnomalyHeaderProps {
  status: MLModelStatus;
  activeModelName?: string | null;
  onRefresh: () => void;
  loading?: boolean;
}

export function AIAnomalyHeader({
  status,
  activeModelName,
  onRefresh,
  loading = false,
}: AIAnomalyHeaderProps) {
  return (
    <div className="border-b border-border bg-surface px-6 py-5">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="rounded-md bg-purple-500/10 p-2 border border-purple-500/20">
                <BrainCircuit className="h-5 w-5 text-purple-400" />
              </div>
              <h1 className="text-xl font-bold tracking-tight text-text-primary">
                AI / ML ANOMALY DETECTION ENGINE
              </h1>
            </div>
            <ModelStatusBadge status={status} />
          </div>

          <p className="text-xs text-text-secondary max-w-3xl">
            Use learned behavioral models to identify unusual IPsec VPN session patterns and
            provide explainable evidence.
            {activeModelName && (
              <span className="ml-2 font-mono text-cyan-400">
                Active model: <strong>{activeModelName}</strong>
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-surface-hover hover:text-text-primary transition disabled:opacity-50"
            title="Refresh engine status and model state"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>
    </div>
  );
}
