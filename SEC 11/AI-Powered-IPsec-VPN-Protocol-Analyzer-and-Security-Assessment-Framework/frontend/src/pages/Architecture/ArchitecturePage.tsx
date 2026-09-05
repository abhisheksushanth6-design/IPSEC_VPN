import { ArrowLeft, Layers, RefreshCw } from 'lucide-react';
import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import {
  ArchitectureLayerDetail,
  ArchitectureLegend,
  ArchitectureMiniMap,
  ArchitecturePipeline,
  ArchitectureProgress,
} from '@/components/architecture';
import { PageContainer } from '@/components/layout';
import { EmptyState, SkeletonCard } from '@/components/states';
import { PageHeader, Panel } from '@/components/ui';
import { buildArchitectureLayers } from '@/config/architecture';
import { PROJECT_NAME } from '@/config/branding';
import { useSystemState } from '@/context/SystemStateContext';
import type { ArchitectureLayerDetail as LayerDetail } from '@/types';

/**
 * 14-layer architecture visualization. Layer names, statuses and descriptions
 * come from `/api/system/status`; the page attaches presentation metadata
 * and never invents runtime figures.
 */
export function ArchitecturePage() {
  const { state, status, refresh } = useSystemState();
  const [selectedNumber, setSelectedNumber] = useState<number | null>(null);

  const layers = useMemo(
    () => (state === 'ready' ? buildArchitectureLayers(status?.architecture_layers) : null),
    [state, status],
  );

  const selected = layers?.find((l) => l.number === selectedNumber) ?? null;
  const onSelect = useCallback(
    (layer: LayerDetail) => setSelectedNumber((current) => (current === layer.number ? null : layer.number)),
    [],
  );
  const onClose = useCallback(() => setSelectedNumber(null), []);

  return (
    <PageContainer>
      <PageHeader
        title="14-Layer System Architecture"
        description={`Technical architecture of the ${PROJECT_NAME}.`}
        status={layers ? 'ARCHITECTURE DEFINED' : state === 'loading' ? 'INITIALIZING' : 'NOT INITIALIZED'}
        statusLabel={layers ? undefined : state === 'loading' ? undefined : 'ARCHITECTURE DATA UNAVAILABLE'}
        breadcrumbs={[{ label: 'System' }, { label: 'Architecture' }]}
        actions={
          <Link
            to="/overview"
            className="inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 text-sm text-secondary transition-colors hover:border-info hover:text-info"
          >
            <ArrowLeft aria-hidden className="h-3.5 w-3.5" />
            Back to Overview
          </Link>
        }
      />

      <Panel>
        <p className="max-w-reading text-sm leading-relaxed text-secondary">
          The framework is designed to process IPsec VPN activity through a layered
          security-analysis pipeline: from test-environment generation and packet
          collection, through protocol analysis and behavioural detection, to risk
          assessment, dashboard visualization and security reporting. This page
          describes the intended architecture; the analysis layers are not yet
          running.
        </p>
      </Panel>

      {state === 'loading' ? (
        <div role="status" aria-label="Loading architecture" className="grid gap-3 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <div className="space-y-3">
            <SkeletonCard lines={3} />
            <SkeletonCard lines={3} />
            <SkeletonCard lines={3} />
          </div>
          <SkeletonCard lines={6} />
        </div>
      ) : null}

      {state !== 'loading' && !layers ? (
        <EmptyState
          icon={Layers}
          title="Architecture data unavailable"
          description={
            state === 'error'
              ? 'The backend could not be reached, so the architecture metadata it serves is unavailable. The layer definitions are not stored in the browser.'
              : 'The backend returned architecture metadata that does not describe the locked 14-layer architecture.'
          }
          status="NOT INITIALIZED"
          action={
            <button
              type="button"
              onClick={refresh}
              className="inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 text-sm text-primary transition-colors hover:border-info hover:text-info"
            >
              <RefreshCw aria-hidden className="h-3.5 w-3.5" />
              Retry
            </button>
          }
        />
      ) : null}

      {layers ? (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] lg:items-start">
          <div className="space-y-4">
            <ArchitectureLegend />
            <ArchitecturePipeline layers={layers} selectedNumber={selectedNumber} onSelect={onSelect} />
          </div>

          <div className="space-y-4 lg:sticky lg:top-[calc(var(--header-height)+1.5rem)]">
            {selected ? (
              <ArchitectureLayerDetail layer={selected} onClose={onClose} />
            ) : (
              <>
                <ArchitectureProgress layers={layers} />
                <ArchitectureMiniMap layers={layers} selectedNumber={selectedNumber} onSelect={onSelect} />
                <p className="px-1 text-xs text-muted">Select a layer to see its purpose, inputs and outputs.</p>
              </>
            )}
          </div>
        </div>
      ) : null}
    </PageContainer>
  );
}
