import { RefreshCw, Route, Trash2 } from 'lucide-react';
import { Link } from 'react-router-dom';

import { StatusBadge } from '@/components/status';
import type { SessionController } from '@/hooks';
import type { StatusKind } from '@/types';

const ENGINE_BADGE: Record<string, { status: StatusKind; label: string }> = {
  'NOT INITIALIZED': { status: 'NOT INITIALIZED', label: 'SESSION ENGINE NOT INITIALIZED' },
  READY: { status: 'INACTIVE', label: 'READY' },
  ANALYZING: { status: 'INITIALIZING', label: 'ANALYZING' },
  AVAILABLE: { status: 'ONLINE', label: 'AVAILABLE' },
  ERROR: { status: 'CRITICAL', label: 'ERROR' },
};

export function engineBadge(state: string | undefined, reachable: boolean): { status: StatusKind; label: string } {
  if (!reachable) return { status: 'OFFLINE', label: 'SESSION SERVICE UNAVAILABLE' };
  return ENGINE_BADGE[state ?? 'NOT INITIALIZED'] ?? ENGINE_BADGE['NOT INITIALIZED']!;
}

const button = 'inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-border disabled:hover:text-secondary';

export function SessionToolbar({ controller }: { controller: SessionController }) {
  const { status, statusLoading, busy, discover, clear, refresh } = controller;
  const badge = engineBadge(status?.state, status !== null);
  const packetsAvailable = status?.packets_available ?? false;
  const hasSessions = status?.state === 'AVAILABLE';

  return (
    <div className="flex flex-col gap-3 rounded border border-border bg-surface p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge status={statusLoading ? 'INITIALIZING' : badge.status} label={statusLoading ? 'LOADING' : badge.label} />
        {status?.capture_filename ? (
          <span className="font-mono text-2xs text-muted">
            {status.capture_filename}{status.discovered_at ? ` · discovered ${status.discovered_at}` : ' · not yet discovered'}
          </span>
        ) : status ? (
          <span className="text-2xs text-muted">
            No packet data available. <Link to="/packet-analysis" className="text-info hover:underline">Load a capture in Packet Analysis</Link>.
          </span>
        ) : null}
      </div>

      <div role="group" aria-label="Session controls" className="flex flex-wrap items-center gap-2">
        <button type="button" className={button} disabled={!packetsAvailable || busy !== null} onClick={() => void discover()} title={packetsAvailable ? 'Correlate loaded packets into sessions' : 'No packet data available'}>
          <Route aria-hidden className="h-3.5 w-3.5" />
          {busy === 'discover' ? 'Correlating packets…' : 'Discover sessions'}
        </button>
        <button type="button" className={button} disabled={!hasSessions || busy !== null} onClick={() => void clear()}>
          <Trash2 aria-hidden className="h-3.5 w-3.5" />
          Clear
        </button>
        <button type="button" className={button} disabled={busy !== null || statusLoading} onClick={refresh}>
          <RefreshCw aria-hidden className={statusLoading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
          Refresh
        </button>
      </div>
    </div>
  );
}
