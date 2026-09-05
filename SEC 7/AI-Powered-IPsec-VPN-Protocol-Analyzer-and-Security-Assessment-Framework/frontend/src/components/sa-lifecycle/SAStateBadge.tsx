import { StatusBadge } from '@/components/status';
import type { SAState, StatusKind } from '@/types';

const MAP: Record<SAState, StatusKind> = {
  UNKNOWN: 'NOT INITIALIZED', DETECTED: 'NOT INITIALIZED', NEGOTIATING: 'INITIALIZING', ESTABLISHED: 'ONLINE', ACTIVE: 'ACTIVE',
  REKEYING: 'WARNING', EXPIRED: 'INACTIVE', TERMINATED: 'OFFLINE', FAILED: 'CRITICAL',
};

export function SAStateBadge({ state, size = 'sm' }: { state: SAState; size?: 'sm' | 'md' }) {
  return <StatusBadge status={MAP[state]} label={state} size={size} />;
}
