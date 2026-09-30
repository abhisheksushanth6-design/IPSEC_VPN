import { AlertTriangle, X } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import { PageContainer } from '@/components/layout';
import { SADetails, SAFilters, SAMetrics, SATable, SAToolbar, saEngineBadge } from '@/components/sa-lifecycle';
import { PageHeader } from '@/components/ui';
import { useSALifecycle } from '@/hooks';

const ERROR_TITLES: Record<string, string> = {
  SA_SERVICE_UNAVAILABLE: 'SA service unavailable', SA_NOT_FOUND: 'SA not found', LIFECYCLE_ANALYSIS_ERROR: 'Lifecycle analysis error',
  PACKET_DATA_UNAVAILABLE: 'Packet data unavailable', SESSION_DATA_UNAVAILABLE: 'Session data unavailable', DATABASE_ERROR: 'Database error',
};

/** Layer 04 — SA & Protocol State Analysis. All state and parameters come from the backend engine. */
export function SALifecyclePage() {
  const [params] = useSearchParams();
  const controller = useSALifecycle(params.get('sa'));
  const badge = saEngineBadge(controller.status?.state, controller.status !== null || controller.statusLoading);
  return (
    <PageContainer>
      <PageHeader title="SA & Protocol State Analysis" description="Inspect Security Association (SA) characteristics, encryption and authentication parameters, and protocol state transitions."
        status={controller.statusLoading ? 'INITIALIZING' : badge.status} statusLabel={controller.statusLoading ? 'LOADING' : badge.label} breadcrumbs={[{ label: 'Security Analysis' }, { label: 'SA & Protocol State' }]} />
      <SAToolbar controller={controller} />
      {controller.error ? (
        <div role="alert" className="flex items-start justify-between gap-3 rounded border border-danger/30 bg-danger/5 px-4 py-3">
          <div className="flex items-start gap-3"><AlertTriangle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-danger" /><div><p className="text-sm font-medium text-primary">{ERROR_TITLES[controller.error.code] ?? 'Request failed'}</p><p className="mt-0.5 text-xs text-secondary">{controller.error.message}</p></div></div>
          <button type="button" onClick={controller.dismissError} aria-label="Dismiss error" className="rounded p-1 text-muted hover:text-primary"><X aria-hidden className="h-4 w-4" /></button>
        </div>
      ) : null}
      <SAMetrics status={controller.status} />
      <SAFilters controller={controller} />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start"><SATable controller={controller} /><SADetails controller={controller} /></div>
    </PageContainer>
  );
}
