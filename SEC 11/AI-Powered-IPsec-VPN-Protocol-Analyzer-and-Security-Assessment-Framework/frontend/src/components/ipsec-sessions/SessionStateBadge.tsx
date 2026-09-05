import { StatusBadge } from '@/components/status';
import type { SessionState, StatusKind } from '@/types';

const MAP: Record<SessionState, StatusKind> = {
  DISCOVERED: 'NOT INITIALIZED',
  NEGOTIATING: 'INITIALIZING',
  ESTABLISHED: 'ONLINE',
  ACTIVE: 'ACTIVE',
  IDLE: 'INACTIVE',
  TERMINATED: 'OFFLINE',
  UNKNOWN: 'NOT INITIALIZED',
};

/** Session state rendered through the shared badge so icon + text carry meaning. */
export function SessionStateBadge({ state, size = 'sm' }: { state: SessionState; size?: 'sm' | 'md' }) {
  return <StatusBadge status={MAP[state]} label={state} size={size} />;
}
