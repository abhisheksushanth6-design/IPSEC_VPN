import { Play, RefreshCw, Square } from 'lucide-react';

import { StatusReadout } from '@/components/status';
import { CaptureStatus } from './CaptureStatus';
import { InterfaceSelector } from './InterfaceSelector';
import type { CaptureState, NetworkInterface } from '@/types';

interface MonitorControlBarProps {
  interfaces: NetworkInterface[] | null;
  selectedInterface?: string;
  onSelectInterface?: (name: string) => void;
  captureState: CaptureState;
  applicationMode: string | null;
  refreshing: boolean;
  actionLoading?: boolean;
  onStartCapture?: () => void;
  onStopCapture?: () => void;
  onRefresh: () => void;
}

export function MonitorControlBar({
  interfaces,
  selectedInterface,
  onSelectInterface,
  captureState,
  applicationMode,
  refreshing,
  actionLoading = false,
  onStartCapture,
  onStopCapture,
  onRefresh,
}: MonitorControlBarProps) {
  const modeKnown = applicationMode !== null;
  const isCapturing = captureState === 'CAPTURING';

  return (
    <div className="flex flex-col gap-4 rounded border border-border bg-surface p-4 lg:flex-row lg:items-end lg:justify-between">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:gap-6">
        <InterfaceSelector
          interfaces={interfaces}
          selected={selectedInterface}
          onChange={onSelectInterface}
        />
        <CaptureStatus state={captureState} />
        <StatusReadout
          label="Monitor mode"
          status={
            applicationMode === 'LIVE' || applicationMode === 'STANDALONE' || applicationMode === 'PRODUCTION'
              ? 'LIVE'
              : applicationMode === 'DEMO'
              ? 'DEMO'
              : modeKnown
              ? 'LIVE'
              : 'NOT INITIALIZED'
          }
          displayValue={applicationMode ?? 'UNKNOWN'}
        />
      </div>

      <div role="group" aria-label="Monitor controls" className="flex flex-wrap items-center gap-2">
        {isCapturing ? (
          <button
            type="button"
            onClick={onStopCapture}
            disabled={actionLoading}
            className="inline-flex items-center gap-1.5 rounded bg-danger px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-danger/90 disabled:opacity-50"
          >
            <Square className="h-3.5 w-3.5 fill-current" />
            {actionLoading ? 'Stopping & Ingesting...' : 'STOP CAPTURE'}
          </button>
        ) : (
          <button
            type="button"
            onClick={onStartCapture}
            disabled={actionLoading || !interfaces || interfaces.length === 0}
            className="inline-flex items-center gap-1.5 rounded bg-info px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-info/90 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            {actionLoading ? 'Starting Trace...' : 'START CAPTURE'}
          </button>
        )}

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
