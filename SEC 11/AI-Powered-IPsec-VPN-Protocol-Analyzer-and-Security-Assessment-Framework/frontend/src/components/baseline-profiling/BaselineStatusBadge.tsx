import { StatusBadge } from '@/components/status';
import type { BaselineEngineState, StatusKind } from '@/types';

const ENGINE_STATES: Record<BaselineEngineState, { status: StatusKind; label: string }> = {
  'NOT INITIALIZED': { status: 'NOT INITIALIZED', label: 'NOT INITIALIZED' },
  COLLECTING: { status: 'INITIALIZING', label: 'COLLECTING SESSIONS' },
  READY: { status: 'INACTIVE', label: 'READY TO BUILD' },
  BUILDING: { status: 'INITIALIZING', label: 'BUILDING BASELINE' },
  AVAILABLE: { status: 'ONLINE', label: 'BASELINE AVAILABLE' },
  ERROR: { status: 'CRITICAL', label: 'ENGINE ERROR' },
};

export function BaselineEngineBadge({
  state,
  reachable = true,
}: {
  state?: BaselineEngineState;
  reachable?: boolean;
}) {
  if (!reachable) {
    return <StatusBadge status="OFFLINE" label="BASELINE SERVICE UNAVAILABLE" size="sm" />;
  }
  const entry = ENGINE_STATES[state ?? 'NOT INITIALIZED'] ?? ENGINE_STATES['NOT INITIALIZED'];
  return <StatusBadge status={entry.status} label={entry.label} size="sm" />;
}

export function BaselineQualityBadge({ rating }: { rating: 'HIGH' | 'SUFFICIENT' | 'INSUFFICIENT' }) {
  if (rating === 'HIGH') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded bg-emerald-500/10 px-2 py-0.5 text-2xs font-medium uppercase tracking-wider text-emerald-400 border border-emerald-500/20">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
        High Quality
      </span>
    );
  }
  if (rating === 'SUFFICIENT') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded bg-amber-500/10 px-2 py-0.5 text-2xs font-medium uppercase tracking-wider text-amber-400 border border-amber-500/20">
        <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
        Sufficient
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded bg-rose-500/10 px-2 py-0.5 text-2xs font-medium uppercase tracking-wider text-rose-400 border border-rose-500/20">
      <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
      Insufficient
    </span>
  );
}

export function BaselineActiveBadge({ isActive }: { isActive: boolean }) {
  if (isActive) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded bg-cyan-500/15 px-2 py-0.5 text-2xs font-semibold uppercase tracking-wider text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10">
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
        Active Reference
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded bg-surface-muted px-2 py-0.5 text-2xs font-medium uppercase tracking-wider text-muted border border-border">
      Standby
    </span>
  );
}
