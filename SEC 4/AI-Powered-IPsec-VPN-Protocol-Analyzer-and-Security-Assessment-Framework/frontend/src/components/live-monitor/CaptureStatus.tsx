import { StatusReadout } from '@/components/status';
import type { CaptureState, StatusKind } from '@/types';

const TO_STATUS: Record<CaptureState, StatusKind> = {
  'NOT INITIALIZED': 'NOT INITIALIZED',
  READY: 'INACTIVE',
  CAPTURING: 'ACTIVE',
  PAUSED: 'WARNING',
  STOPPED: 'INACTIVE',
  ERROR: 'CRITICAL',
};

export function CaptureStatus({ state }: { state: CaptureState }) {
  return <StatusReadout label="Capture status" status={TO_STATUS[state]} displayValue={state} />;
}
