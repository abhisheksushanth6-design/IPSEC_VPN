import { useSystemState } from '@/context/SystemStateContext';
import { StatusReadout } from '@/components/status';
import type { StatusKind } from '@/types';

/**
 * The header's live readouts. Every value is derived from what the backend
 * actually reported. Nothing is asserted while the backend is unreachable.
 */
export function useSystemReadouts() {
  const { state, reachable, status } = useSystemState();

  const systemStatus: StatusKind = !reachable
    ? state === 'loading'
      ? 'INITIALIZING'
      : 'BACKEND OFFLINE'
    : 'FOUNDATION ONLINE';

  // Application mode comes from the database via the backend, never guessed.
  const applicationMode: StatusKind =
    reachable && status ? (status.application_mode === 'LIVE' ? 'LIVE' : 'DEMO') : 'NOT INITIALIZED';

  const applicationModeLabel =
    reachable && status ? status.application_mode : 'UNKNOWN';

  return {
    systemStatus,
    applicationMode,
    applicationModeLabel,
    // Layers 02 and 08 are not implemented, so these cannot report otherwise.
    captureStatus: 'NOT INITIALIZED' as StatusKind,
    aiModelStatus: 'NOT INITIALIZED' as StatusKind,
  };
}

export function SystemStatusCluster() {
  const readouts = useSystemReadouts();

  return (
    <div className="hidden items-center gap-5 xl:flex">
      <StatusReadout label="System" status={readouts.systemStatus} />
      <StatusReadout
        label="Mode"
        status={readouts.applicationMode}
        displayValue={readouts.applicationModeLabel}
      />
      <StatusReadout label="Capture" status={readouts.captureStatus} />
      <StatusReadout label="AI model" status={readouts.aiModelStatus} />
    </div>
  );
}

/** Compact stack of the same readouts, shown below the header on narrow screens. */
export function SystemStatusStrip() {
  const readouts = useSystemReadouts();

  return (
    <div className="scrollbar-slim flex items-center gap-4 overflow-x-auto border-b border-border bg-surface px-4 py-2 xl:hidden">
      <StatusReadout label="System" status={readouts.systemStatus} />
      <StatusReadout
        label="Mode"
        status={readouts.applicationMode}
        displayValue={readouts.applicationModeLabel}
      />
      <StatusReadout label="Capture" status={readouts.captureStatus} />
      <StatusReadout label="AI model" status={readouts.aiModelStatus} />
    </div>
  );
}
