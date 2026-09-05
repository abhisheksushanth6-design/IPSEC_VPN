import { Play, RefreshCw, Trash2, Upload } from 'lucide-react';
import { useRef } from 'react';

import { StatusBadge } from '@/components/status';
import type { PacketAnalysisController } from '@/hooks';
import type { StatusKind } from '@/types';

const STATE_BADGE: Record<string, { status: StatusKind; label: string }> = {
  'NOT INITIALIZED': { status: 'NOT INITIALIZED', label: 'ANALYZER READY' },
  READY: { status: 'INACTIVE', label: 'ANALYZER READY' },
  ANALYZING: { status: 'INITIALIZING', label: 'ANALYZING' },
  COMPLETED: { status: 'ONLINE', label: 'ANALYSIS COMPLETED' },
  ERROR: { status: 'CRITICAL', label: 'ANALYSIS ERROR' },
};

export function analyzerBadge(state: string | undefined, reachable: boolean): { status: StatusKind; label: string } {
  if (!reachable) return { status: 'OFFLINE', label: 'ANALYSIS SERVICE UNAVAILABLE' };
  return STATE_BADGE[state ?? 'NOT INITIALIZED'] ?? STATE_BADGE['NOT INITIALIZED']!;
}

const button =
  'inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-border disabled:hover:text-secondary';

export function PacketAnalysisToolbar({ controller }: { controller: PacketAnalysisController }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const { status, statusLoading, busy, upload, analyze, clear, refresh } = controller;
  const hasCapture = status?.state === 'COMPLETED';
  const badge = analyzerBadge(status?.state, status !== null);
  const accept = (status?.supported_formats ?? ['pcap', 'pcapng']).map((f) => `.${f}`).concat('.cap').join(',');

  return (
    <div className="flex flex-col gap-3 rounded border border-border bg-surface p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge status={statusLoading ? 'INITIALIZING' : badge.status} label={statusLoading ? 'LOADING' : badge.label} />
        {status?.capture ? (
          <span className="font-mono text-2xs text-muted">
            {status.capture.filename} · {status.capture.format} · {status.capture.link_type_name} · {status.capture.packet_count.toLocaleString()} packets
            {status.capture.truncated ? ` (first ${status.max_packets.toLocaleString()} only)` : ''}
          </span>
        ) : (
          <span className="text-2xs text-muted">Sources: capture file upload. Live capture arrives with Layer 02.</span>
        )}
      </div>

      <div role="group" aria-label="Analysis controls" className="flex flex-wrap items-center gap-2">
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="sr-only"
          aria-label="Upload capture file"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void upload(file);
            e.target.value = '';
          }}
        />
        <button type="button" className={button} disabled={busy !== null || status === null} onClick={() => inputRef.current?.click()}>
          <Upload aria-hidden className={busy === 'upload' ? 'h-3.5 w-3.5 animate-pulse' : 'h-3.5 w-3.5'} />
          {busy === 'upload' ? 'Parsing capture…' : 'Upload capture'}
        </button>
        <button type="button" className={button} disabled={!hasCapture || busy !== null} onClick={() => void analyze()} title={hasCapture ? 'Re-run analysis on the loaded capture' : 'Load a capture first'}>
          <Play aria-hidden className="h-3.5 w-3.5" />
          {busy === 'analyze' ? 'Analyzing…' : 'Analyze'}
        </button>
        <button type="button" className={button} disabled={!hasCapture || busy !== null} onClick={() => void clear()}>
          <Trash2 aria-hidden className="h-3.5 w-3.5" />
          Clear
        </button>
        <button type="button" className={button} disabled={busy !== null || statusLoading} onClick={refresh}>
          <RefreshCw aria-hidden className={statusLoading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
          Refresh
        </button>
      </div>
    </div>
  );
}
