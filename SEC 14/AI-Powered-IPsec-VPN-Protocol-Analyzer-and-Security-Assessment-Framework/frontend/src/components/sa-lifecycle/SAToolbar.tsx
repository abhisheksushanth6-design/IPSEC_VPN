import { KeyRound, RefreshCw, Trash2 } from 'lucide-react';
import { Link } from 'react-router-dom';

import { StatusBadge } from '@/components/status';
import type { SAController } from '@/hooks';
import type { StatusKind } from '@/types';

const ENGINE: Record<string, { status: StatusKind; label: string }> = {
  'NOT INITIALIZED': { status: 'NOT INITIALIZED', label: 'NOT INITIALIZED' }, READY: { status: 'INACTIVE', label: 'READY' },
  ANALYZING: { status: 'INITIALIZING', label: 'ANALYZING' }, ACTIVE: { status: 'ONLINE', label: 'ACTIVE' }, ERROR: { status: 'CRITICAL', label: 'ERROR' },
};

export function engineBadge(state: string | undefined, reachable: boolean) {
  if (!reachable) return { status: 'OFFLINE' as StatusKind, label: 'SA SERVICE UNAVAILABLE' };
  return ENGINE[state ?? 'NOT INITIALIZED'] ?? ENGINE['NOT INITIALIZED']!;
}

const button = 'inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-border disabled:hover:text-secondary';

export function SAToolbar({ controller }: { controller: SAController }) {
  const { status, statusLoading, busy, discover, clear, refresh } = controller;
  const badge = engineBadge(status?.state, status !== null);
  const packets = status?.packets_available ?? false;
  return (
    <div className="flex flex-col gap-3 rounded border border-border bg-surface p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge status={statusLoading ? 'INITIALIZING' : badge.status} label={statusLoading ? 'LOADING' : badge.label} />
        {status?.capture_filename ? (
          <span className="font-mono text-2xs text-muted">
            {status.capture_filename}{status.discovered_at ? ` · analyzed ${status.discovered_at}` : ' · not yet analyzed'}
            {!status.sessions_available ? ' · sessions not discovered (SA→session links unavailable)' : ''}
          </span>
        ) : status ? <span className="text-2xs text-muted">No packet data available. <Link to="/packet-analysis" className="text-info hover:underline">Load a capture in Packet Analysis</Link>.</span> : null}
      </div>
      <div role="group" aria-label="SA controls" className="flex flex-wrap items-center gap-2">
        <button type="button" className={button} disabled={!packets || busy !== null} onClick={() => void discover()} title={packets ? 'Run SA & protocol state analysis on the loaded capture' : 'No packet data available'}>
          <KeyRound aria-hidden className="h-3.5 w-3.5" />{busy === 'discover' ? 'Analyzing SA & protocol state…' : 'Discover SAs'}
        </button>
        <button type="button" className={button} disabled={status?.state !== 'ACTIVE' || busy !== null} onClick={() => void clear()}><Trash2 aria-hidden className="h-3.5 w-3.5" />Clear</button>
        <button type="button" className={button} disabled={busy !== null || statusLoading} onClick={refresh}><RefreshCw aria-hidden className={statusLoading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />Refresh</button>
      </div>
    </div>
  );
}
