import { useSystemState } from '@/context/SystemStateContext';
import { StatusReadout } from '@/components/status';
import type { StatusKind } from '@/types';

/**
 * The header's live readouts. Every value is derived from what the backend
 * actually reported. Nothing is asserted while the backend is unreachable.
 */
export function useSystemReadouts() {
  const { state, reachable, status, mlStatus, packetStatus } = useSystemState();

  const systemStatus: StatusKind = !reachable
    ? state === 'loading'
      ? 'INITIALIZING'
      : 'BACKEND OFFLINE'
    : 'FOUNDATION ONLINE';

  const mode = status?.application_mode ?? (status as any)?.applicationMode;
  const applicationMode: StatusKind =
    reachable && status
      ? mode === 'LIVE' || mode === 'PRODUCTION'
        ? 'LIVE'
        : mode === 'STANDALONE'
        ? 'STANDALONE'
        : mode === 'DEMO'
        ? 'DEMO'
        : 'ONLINE'
      : 'NOT INITIALIZED';

  const applicationModeLabel =
    reachable && status ? mode ?? 'UNKNOWN' : 'UNKNOWN';

  // AI Model Status derived dynamically from /api/ml/status
  let aiModelStatus: StatusKind = 'NOT INITIALIZED';
  let aiModelStatusLabel = 'NOT INITIALIZED';

  if (!reachable) {
    aiModelStatus = state === 'loading' ? 'INITIALIZING' : 'NOT INITIALIZED';
    aiModelStatusLabel = state === 'loading' ? 'INITIALIZING' : 'NOT INITIALIZED';
  } else if (mlStatus?.active_model) {
    const activeStatus = mlStatus.active_model.status;
    const isModelReady = activeStatus === 'READY' || activeStatus === 'INFERENCE READY' || activeStatus === 'TRAINED';
    if (isModelReady) {
      aiModelStatus = 'READY';
      aiModelStatusLabel = 'READY';
    } else if (activeStatus === 'ERROR' || mlStatus.status === 'ERROR') {
      aiModelStatus = 'ERROR';
      aiModelStatusLabel = 'ERROR';
    } else {
      aiModelStatus = 'IN DEVELOPMENT';
      aiModelStatusLabel = activeStatus;
    }
  } else if (mlStatus && mlStatus.total_models === 0) {
    aiModelStatus = 'NOT INITIALIZED';
    aiModelStatusLabel = 'NOT INITIALIZED';
  } else if (mlStatus && mlStatus.status === 'ERROR') {
    aiModelStatus = 'ERROR';
    aiModelStatusLabel = 'ERROR';
  }

  // Capture Status derived from Layer 03 packet analyzer
  let captureStatus: StatusKind = 'NOT INITIALIZED';
  let captureStatusLabel = 'NOT INITIALIZED';

  if (!reachable) {
    captureStatus = state === 'loading' ? 'INITIALIZING' : 'NOT INITIALIZED';
    captureStatusLabel = state === 'loading' ? 'INITIALIZING' : 'NOT INITIALIZED';
  } else if (packetStatus?.analyzer_available) {
    captureStatus = 'READY';
    captureStatusLabel = 'PCAP UPLOAD READY';
  }

  return {
    systemStatus,
    applicationMode,
    applicationModeLabel,
    captureStatus,
    captureStatusLabel,
    aiModelStatus,
    aiModelStatusLabel,
    activeModel: mlStatus?.active_model ?? null,
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
      <StatusReadout
        label="Capture"
        status={readouts.captureStatus}
        displayValue={readouts.captureStatusLabel}
      />
      <StatusReadout
        label="AI model"
        status={readouts.aiModelStatus}
        displayValue={readouts.aiModelStatusLabel}
      />
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
      <StatusReadout
        label="Capture"
        status={readouts.captureStatus}
        displayValue={readouts.captureStatusLabel}
      />
      <StatusReadout
        label="AI model"
        status={readouts.aiModelStatus}
        displayValue={readouts.aiModelStatusLabel}
      />
    </div>
  );
}
