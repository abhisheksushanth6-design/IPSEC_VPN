import { RefreshCw } from 'lucide-react';

import { StatusBadge } from '@/components/status';
import type { RealtimeConnectionState, StatusKind } from '@/types';

interface RealtimeStatusProps {
  state: RealtimeConnectionState;
  detail: string | null;
  onRetry: () => void;
}

const TO_STATUS: Record<RealtimeConnectionState, StatusKind> = {
  IDLE: 'NOT INITIALIZED',
  CONNECTING: 'INITIALIZING',
  CONNECTED: 'ONLINE',
  DISCONNECTED: 'OFFLINE',
  RECONNECTING: 'INITIALIZING',
  ERROR: 'CRITICAL',
};

const DESCRIPTION: Record<RealtimeConnectionState, string> = {
  IDLE: 'Real-time stream is not initialized.',
  CONNECTING: 'Connecting to monitoring service…',
  CONNECTED: 'Connected to /ws/events. No event sources publish yet.',
  DISCONNECTED: 'The real-time channel is closed.',
  RECONNECTING: 'Connection lost; retrying with backoff.',
  ERROR: 'The real-time monitoring service could not be reached.',
};

/** Reports the actual socket state; CONNECTED appears only on a real open socket. */
export function RealtimeStatus({ state, detail, onRetry }: RealtimeStatusProps) {
  return (
    <div className="flex items-center justify-between gap-4 rounded border border-border bg-surface px-4 py-3">
      <div className="min-w-0">
        <p className="text-2xs text-muted">Real-time connection</p>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <StatusBadge status={TO_STATUS[state]} label={state} size="sm" />
          <span className="text-xs text-secondary">{DESCRIPTION[state]}</span>
        </div>
        {detail ? <p className="mt-1 font-mono text-2xs text-muted">{detail}</p> : null}
      </div>
      {state === 'ERROR' || state === 'DISCONNECTED' ? (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex shrink-0 items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info"
        >
          <RefreshCw aria-hidden className="h-3.5 w-3.5" />
          Reconnect
        </button>
      ) : null}
    </div>
  );
}
