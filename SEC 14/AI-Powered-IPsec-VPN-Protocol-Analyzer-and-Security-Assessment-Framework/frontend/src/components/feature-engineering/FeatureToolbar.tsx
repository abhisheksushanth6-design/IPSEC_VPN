import { Download, Layers3, RefreshCw, Trash2 } from 'lucide-react';
import { Link } from 'react-router-dom';

import { StatusBadge } from '@/components/status';
import type { FeatureController } from '@/hooks';
import { featureService } from '@/services';
import { featureEngineBadge } from './FeatureStatusBadge';

const button =
  'inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-border disabled:hover:text-secondary';

/**
 * Extraction controls. Extract is enabled only when a real entity is
 * selected, and export only when stored feature data actually exists.
 */
export function FeatureToolbar({ controller }: { controller: FeatureController }) {
  const { status, statusLoading, busy, selectedId, extract, clear, refresh } = controller;
  const badge = featureEngineBadge(status?.state, status !== null);
  const hasVectors = (status?.statistics?.vectors ?? 0) > 0;
  const canExtract = Boolean(selectedId) && busy === null;

  return (
    <div className="flex flex-col gap-3 rounded border border-border bg-surface p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap items-center gap-3">
        <StatusBadge
          status={statusLoading ? 'INITIALIZING' : badge.status}
          label={statusLoading ? 'LOADING' : badge.label}
        />
        {status?.capture_filename ? (
          <span className="font-mono text-2xs text-muted">
            {status.capture_filename}
            {status.extracted_at ? ` · extracted ${status.extracted_at}` : ' · no features extracted yet'}
            {` · schema v${status.feature_version}`}
          </span>
        ) : status ? (
          <span className="text-2xs text-muted">
            No packet data available.{' '}
            <Link to="/packet-analysis" className="text-info hover:underline">
              Load a capture in Packet Analysis
            </Link>
            .
          </span>
        ) : null}
      </div>

      <div role="group" aria-label="Feature extraction controls" className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className={button}
          disabled={!canExtract}
          onClick={() => void extract()}
          title={selectedId ? 'Extract features for the selected entity' : 'Select an entity first'}
        >
          <Layers3 aria-hidden className="h-3.5 w-3.5" />
          {busy === 'extract' ? 'Extracting features…' : 'Extract features'}
        </button>

        <a
          href={hasVectors ? featureService.exportUrl('json') : undefined}
          className={hasVectors ? button : `${button} pointer-events-none opacity-50`}
          aria-disabled={!hasVectors}
          title={hasVectors ? 'Export stored feature vectors as JSON' : 'No feature data available'}
          download
        >
          <Download aria-hidden className="h-3.5 w-3.5" />
          JSON
        </a>
        <a
          href={hasVectors ? featureService.exportUrl('csv') : undefined}
          className={hasVectors ? button : `${button} pointer-events-none opacity-50`}
          aria-disabled={!hasVectors}
          title={hasVectors ? 'Export stored feature vectors as CSV' : 'No feature data available'}
          download
        >
          <Download aria-hidden className="h-3.5 w-3.5" />
          CSV
        </a>

        <button
          type="button"
          className={button}
          disabled={!hasVectors || busy !== null}
          onClick={() => void clear()}
        >
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
