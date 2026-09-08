import { RefreshCw } from 'lucide-react';

import { Panel } from '@/components/ui';
import { StatusBadge } from '@/components/status';
import { SkeletonCard } from '@/components/states';
import { useSystemState } from '@/context/SystemStateContext';
import type { StatusKind } from '@/types';

import { useSystemReadouts } from '@/components/layout/SystemStatusCluster';

interface StatusLine {
  label: string;
  status: StatusKind;
  displayValue?: string;
  note?: string;
}

/**
 * Live operational state. Backend, database, mode, capture readiness,
 * and AI/ML model status are dynamically derived from real backend APIs.
 */
export function SystemStatusPanel() {
  const { state, reachable, status, refresh } = useSystemState();
  const readouts = useSystemReadouts();

  const lines: StatusLine[] = [
    {
      label: 'Backend',
      status: reachable ? 'ONLINE' : 'OFFLINE',
      displayValue: reachable ? 'BACKEND ONLINE' : 'BACKEND OFFLINE',
      note: reachable ? 'GET /api/health' : 'No response from /api/health',
    },
    {
      label: 'Database',
      status: reachable ? 'ONLINE' : 'NOT INITIALIZED',
      displayValue: reachable ? 'FOUNDATION READY' : 'UNKNOWN',
      note: status ? `Reported ${status.database_status ?? (status as any).databaseStatus}` : undefined,
    },
    {
      label: 'Application mode',
      status: ((status?.application_mode ?? (status as any)?.applicationMode) === 'LIVE' ||
      (status?.application_mode ?? (status as any)?.applicationMode) === 'PRODUCTION'
        ? 'LIVE'
        : (status?.application_mode ?? (status as any)?.applicationMode) === 'STANDALONE'
        ? 'STANDALONE'
        : (status?.application_mode ?? (status as any)?.applicationMode) === 'DEMO'
        ? 'DEMO'
        : 'ONLINE') as StatusKind,
      displayValue: (status?.application_mode ?? (status as any)?.applicationMode) ?? 'UNKNOWN',
      note: 'From backend configuration',
    },
    {
      label: 'Capture engine',
      status: readouts.captureStatus,
      displayValue: readouts.captureStatusLabel,
      note: 'Layer 03 PCAP/PCAPNG upload ready',
    },
    {
      label: 'AI model',
      status: readouts.aiModelStatus,
      displayValue: readouts.aiModelStatusLabel,
      note: readouts.activeModel
        ? `${readouts.activeModel.id} (${readouts.activeModel.model_type}) · ${readouts.activeModel.status}`
        : 'Layer 08 not initialized',
    },
    {
      label: 'WebSocket',
      status: 'ONLINE',
      displayValue: 'FOUNDATION READY',
      note: '/ws/events accepts connections; no event sources',
    },
  ];

  return (
    <Panel
      title="System Status"
      description="Operational state of the framework."
      actions={
        <button
          type="button"
          onClick={refresh}
          disabled={state === 'loading'}
          className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:opacity-50"
        >
          <RefreshCw
            aria-hidden
            className={state === 'loading' ? 'h-3 w-3 animate-spin' : 'h-3 w-3'}
          />
          Refresh
        </button>
      }
    >
      {state === 'loading' ? (
        <div role="status" aria-label="Loading system status">
          <SkeletonCard lines={6} />
        </div>
      ) : (
        <dl>
          {lines.map((line) => (
            <div
              key={line.label}
              className="flex items-center justify-between gap-4 border-b border-border py-2.5 last:border-b-0"
            >
              <div className="min-w-0">
                <dt className="text-xs text-secondary">{line.label}</dt>
                {line.note ? (
                  <p className="truncate font-mono text-2xs text-muted">{line.note}</p>
                ) : null}
              </div>
              <dd className="shrink-0">
                <StatusBadge status={line.status} label={line.displayValue} size="sm" />
              </dd>
            </div>
          ))}
        </dl>
      )}
    </Panel>
  );
}
