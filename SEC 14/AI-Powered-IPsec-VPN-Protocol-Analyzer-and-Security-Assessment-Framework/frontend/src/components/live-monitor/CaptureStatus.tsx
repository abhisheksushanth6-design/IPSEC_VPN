import { StatusReadout } from '@/components/status';
import type { CaptureState, StatusKind } from '@/types';

const TO_STATUS: Record<CaptureState, StatusKind> = {
  IDLE: 'INACTIVE',
  STARTING: 'INITIALIZING',
  CAPTURING: 'LIVE',
  STOPPING: 'WARNING',
  INGESTING: 'INITIALIZING',
  COMPLETED: 'READY',
  READY: 'READY',
  'NOT INITIALIZED': 'NOT INITIALIZED',
  PAUSED: 'WARNING',
  STOPPED: 'INACTIVE',
  ERROR: 'CRITICAL',
};

export function CaptureStatus({ state }: { state: CaptureState }) {
  const statusKind = TO_STATUS[state] || 'NOT INITIALIZED';
  return <StatusReadout label="Capture status" status={statusKind} displayValue={state} />;
}
