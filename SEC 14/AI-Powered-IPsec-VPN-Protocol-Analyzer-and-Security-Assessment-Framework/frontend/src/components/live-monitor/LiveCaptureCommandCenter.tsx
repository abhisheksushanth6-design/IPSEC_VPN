import {
  Activity,
  Play,
  RefreshCw,
  Square,
  Network,
  Clock,
  HardDrive,
  Radio,
  Layers,
  Zap,
} from 'lucide-react';
import { InterfaceSelector } from './InterfaceSelector';
import { CaptureStatus } from './CaptureStatus';
import { StatusReadout } from '@/components/status';
import type { CaptureState, NetworkInterface } from '@/types';
import { cn } from '@/utils/cn';

interface LiveCaptureCommandCenterProps {
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
  // Live capture telemetry stats
  durationSeconds?: number;
  packetCount?: number;
  byteCount?: number;
  packetRate?: number | null;
  bandwidth?: number | null;
  activeSessionsCount?: number;
  outputFile?: string | null;
  sourceVM?: string | null;
  nicNumber?: number | null;
}

export function LiveCaptureCommandCenter({
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
  durationSeconds = 0,
  packetCount = 0,
  byteCount = 0,
  packetRate,
  bandwidth,
  activeSessionsCount = 0,
  outputFile,
  sourceVM,
  nicNumber,
}: LiveCaptureCommandCenterProps) {
  const modeKnown = applicationMode !== null;
  const isCapturing = captureState === 'CAPTURING';

  const formatDuration = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = Math.floor(sec % 60);
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  return (
    <div className="relative overflow-hidden rounded-lg border border-border bg-surface shadow-sm">
      {/* Subtle telemetry top accent stripe */}
      <div
        className={cn(
          'h-1 w-full transition-colors',
          isCapturing ? 'bg-emerald-500 animate-pulse' : 'bg-border'
        )}
      />

      <div className="p-4 sm:p-5 space-y-4">
        {/* Row 1: Header status, Interface selector, and Control actions */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap items-center gap-4 sm:gap-6">
            <div className="flex items-center gap-3">
              <div
                className={cn(
                  'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border',
                  isCapturing
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                    : 'border-border bg-elevated text-muted'
                )}
              >
                <Radio className={cn('h-5 w-5', isCapturing && 'animate-spin')} />
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-2xs font-semibold uppercase tracking-wider text-muted">
                    Engine State
                  </span>
                  {isCapturing && (
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      'text-sm font-bold tracking-tight',
                      isCapturing
                        ? 'text-emerald-400'
                        : captureState === 'ERROR'
                        ? 'text-danger'
                        : 'text-primary'
                    )}
                  >
                    {isCapturing ? 'LIVE CAPTURE ACTIVE' : captureState}
                  </span>
                </div>
              </div>
            </div>

            <div className="h-8 w-px bg-border hidden sm:block" />

            {/* Preserves CaptureStatus and InterfaceSelector for exact accessibility and test contract */}
            <div className="flex flex-wrap items-end gap-3">
              <InterfaceSelector
                interfaces={interfaces}
                selected={selectedInterface}
                onChange={onSelectInterface}
              />
              <CaptureStatus state={captureState} />
              <StatusReadout
                label="Monitor mode"
                status={
                  applicationMode === 'LIVE' ||
                  applicationMode === 'STANDALONE' ||
                  applicationMode === 'PRODUCTION'
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
          </div>

          {/* Action buttons (Preserved with exact group and accessibility roles) */}
          <div
            role="group"
            aria-label="Monitor controls"
            className="flex flex-wrap items-center gap-2"
          >
            {isCapturing ? (
              <button
                type="button"
                onClick={onStopCapture}
                disabled={actionLoading}
                className="inline-flex items-center gap-1.5 rounded-md bg-danger px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-danger/90 disabled:opacity-50"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
                {actionLoading ? 'Finalizing Trace...' : 'STOP CAPTURE'}
              </button>
            ) : (
              <button
                type="button"
                onClick={onStartCapture}
                disabled={actionLoading || !interfaces || interfaces.length === 0}
                className="inline-flex items-center gap-1.5 rounded-md bg-info px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-info/90 disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                {actionLoading ? 'Engaging Live Tap...' : 'START CAPTURE'}
              </button>
            )}

            <button
              type="button"
              onClick={onRefresh}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:opacity-50"
            >
              <RefreshCw
                aria-hidden
                className={refreshing ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'}
              />
              Refresh
            </button>
          </div>
        </div>

        {/* Row 2: Live Telemetry Telemetry Gauges Grid */}
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6 pt-2 border-t border-border/70">
          {/* Metric 1: Elapsed Duration */}
          <div className="rounded border border-border/80 bg-background/50 p-2.5">
            <div className="flex items-center justify-between text-2xs text-muted">
              <span>Capture Duration</span>
              <Clock className="h-3.5 w-3.5 text-muted" />
            </div>
            <div className="mt-1 font-mono text-base font-bold text-primary">
              {formatDuration(durationSeconds)}
            </div>
            <span className="text-[10px] text-muted">
              {isCapturing ? 'Continuous timer' : 'Stopped duration'}
            </span>
          </div>

          {/* Metric 2: Total Packets */}
          <div className="rounded border border-border/80 bg-background/50 p-2.5">
            <div className="flex items-center justify-between text-2xs text-muted">
              <span>Total Packets</span>
              <Network className="h-3.5 w-3.5 text-info" />
            </div>
            <div className="mt-1 font-mono text-base font-bold text-primary">
              {packetCount.toLocaleString()}
            </div>
            <span className="text-[10px] text-muted">Observable frames</span>
          </div>

          {/* Metric 3: Total Bytes / Buffer */}
          <div className="rounded border border-border/80 bg-background/50 p-2.5">
            <div className="flex items-center justify-between text-2xs text-muted">
              <span>Buffer Volume</span>
              <HardDrive className="h-3.5 w-3.5 text-muted" />
            </div>
            <div className="mt-1 font-mono text-base font-bold text-primary">
              {formatBytes(byteCount)}
            </div>
            <span className="text-[10px] text-muted">PCAP trace size</span>
          </div>

          {/* Metric 4: Packet Rate */}
          <div className="rounded border border-border/80 bg-background/50 p-2.5">
            <div className="flex items-center justify-between text-2xs text-muted">
              <span>Packet Rate</span>
              <Activity className="h-3.5 w-3.5 text-emerald-400" />
            </div>
            <div className="mt-1 font-mono text-base font-bold text-primary">
              {packetRate !== null && packetRate !== undefined ? `${packetRate}` : '0.0'}{' '}
              <span className="text-2xs text-muted font-normal">pkts/s</span>
            </div>
            <span className="text-[10px] text-muted">Observed pulse</span>
          </div>

          {/* Metric 5: Throughput Bandwidth */}
          <div className="rounded border border-border/80 bg-background/50 p-2.5">
            <div className="flex items-center justify-between text-2xs text-muted">
              <span>Throughput</span>
              <Zap className="h-3.5 w-3.5 text-amber-400" />
            </div>
            <div className="mt-1 font-mono text-base font-bold text-primary">
              {bandwidth !== null && bandwidth !== undefined
                ? bandwidth >= 1024
                  ? `${(bandwidth / 1024).toFixed(1)} KB/s`
                  : `${bandwidth} B/s`
                : '0 B/s'}
            </div>
            <span className="text-[10px] text-muted">Payload rate</span>
          </div>

          {/* Metric 6: Active Sessions */}
          <div className="rounded border border-border/80 bg-background/50 p-2.5">
            <div className="flex items-center justify-between text-2xs text-muted">
              <span>Monitored Sessions</span>
              <Layers className="h-3.5 w-3.5 text-info" />
            </div>
            <div className="mt-1 font-mono text-base font-bold text-primary">
              {activeSessionsCount}
            </div>
            <span className="text-[10px] text-muted">Correlated tunnels</span>
          </div>
        </div>

        {/* Optional Active PCAP Buffer Readout */}
        {outputFile && (
          <div className="flex items-center justify-between rounded border border-border/60 bg-elevated/40 px-3 py-2 text-2xs font-mono text-secondary">
            <div className="flex items-center gap-2 truncate">
              <span className="text-muted uppercase">Active Target:</span>
              <span className="text-primary font-bold">
                {sourceVM ?? 'Host'} {nicNumber ? `(NIC ${nicNumber})` : ''}
              </span>
              <span className="text-border">|</span>
              <span className="text-muted truncate">{outputFile}</span>
            </div>
            <div className="shrink-0 text-info font-bold">
              {isCapturing ? 'RECORDING BUFFER' : 'INSPECTION READY'}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
