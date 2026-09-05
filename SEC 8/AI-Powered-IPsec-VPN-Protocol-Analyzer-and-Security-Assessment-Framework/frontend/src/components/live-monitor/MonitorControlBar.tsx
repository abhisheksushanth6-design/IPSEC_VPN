import { Download, Pause, Play, RefreshCw, Square, Trash2 } from 'lucide-react';

import { StatusReadout } from '@/components/status';
import { CaptureStatus } from './CaptureStatus';
import { DisabledAction } from './DisabledAction';
import { InterfaceSelector } from './InterfaceSelector';
import type { CaptureState, NetworkInterface } from '@/types';

interface MonitorControlBarProps {
  interfaces: NetworkInterface[] | null;
  captureState: CaptureState;
  applicationMode: string | null;
  refreshing: boolean;
  onRefresh: () => void;
}

const NOT_READY = 'Packet capture engine is not initialized.';
const NO_STREAM = 'No stream data exists.';

export function MonitorControlBar({
  interfaces,
  captureState,
  applicationMode,
  refreshing,
  onRefresh,
}: MonitorControlBarProps) {
  const modeKnown = applicationMode !== null;

  return (
    <div className="flex flex-col gap-4 rounded border border-border bg-surface p-4 lg:flex-row lg:items-end lg:justify-between">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:gap-6">
        <InterfaceSelector interfaces={interfaces} />
        <CaptureStatus state={captureState} />
        <StatusReadout
          label="Monitor mode"
          status={applicationMode === 'LIVE' ? 'LIVE' : modeKnown ? 'DEMO' : 'NOT INITIALIZED'}
          displayValue={applicationMode ?? 'UNKNOWN'}
        />
      </div>

      <div role="group" aria-label="Monitor controls" className="flex flex-wrap items-center gap-2">
        <DisabledAction icon={Play} label="Start capture" reason={NOT_READY} />
        <DisabledAction icon={Square} label="Stop capture" reason={NOT_READY} />
        <DisabledAction icon={Pause} label="Pause stream" reason={NO_STREAM} />
        <DisabledAction icon={Trash2} label="Clear stream" reason={NO_STREAM} />
        <DisabledAction icon={Download} label="Export" reason="Export not available. No monitoring data is available." />
        <button
          type="button"
          onClick={onRefresh}
          disabled={refreshing}
          className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:opacity-50"
        >
          <RefreshCw aria-hidden className={refreshing ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
          Refresh
        </button>
      </div>
    </div>
  );
}
