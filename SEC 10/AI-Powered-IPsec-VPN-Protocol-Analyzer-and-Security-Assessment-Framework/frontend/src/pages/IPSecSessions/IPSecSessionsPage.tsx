import { AlertTriangle, X } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import { SessionDetails, SessionFilters, SessionMetrics, SessionTable, SessionToolbar, engineBadge } from '@/components/ipsec-sessions';
import { PageContainer } from '@/components/layout';
import { PageHeader } from '@/components/ui';
import { useIPsecSessions } from '@/hooks';

const ERROR_TITLES: Record<string, string> = {
  SESSION_SERVICE_UNAVAILABLE: 'Session service unavailable',
  SESSION_NOT_FOUND: 'Session not found',
  CORRELATION_ERROR: 'Correlation error',
  PACKET_DATA_UNAVAILABLE: 'Packet data unavailable',
  DATABASE_ERROR: 'Database error',
};

/**
 * IPsec Sessions — a supporting analysis module over Layer 03 output.
 * Every session is derived by the backend from decoded packets.
 */
export function IPSecSessionsPage() {
  const [params] = useSearchParams();
  const controller = useIPsecSessions(params.get('session'));
  const badge = engineBadge(controller.status?.state, controller.status !== null || controller.statusLoading);

  return (
    <PageContainer>
      <PageHeader
        title="IPsec Sessions"
        description="Discover, correlate, and inspect logical IPsec VPN sessions from analyzed network traffic."
        status={controller.statusLoading ? 'INITIALIZING' : badge.status}
        statusLabel={controller.statusLoading ? 'LOADING' : badge.label}
        breadcrumbs={[{ label: 'Monitoring' }, { label: 'IPsec Sessions' }]}
      />

      <SessionToolbar controller={controller} />

      {controller.error ? (
        <div role="alert" className="flex items-start justify-between gap-3 rounded border border-danger/30 bg-danger/5 px-4 py-3">
          <div className="flex items-start gap-3">
            <AlertTriangle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <div><p className="text-sm font-medium text-primary">{ERROR_TITLES[controller.error.code] ?? 'Request failed'}</p><p className="mt-0.5 text-xs text-secondary">{controller.error.message}</p></div>
          </div>
          <button type="button" onClick={controller.dismissError} aria-label="Dismiss error" className="rounded p-1 text-muted hover:text-primary"><X aria-hidden className="h-4 w-4" /></button>
        </div>
      ) : null}

      <SessionMetrics status={controller.status} />
      <SessionFilters controller={controller} />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <SessionTable controller={controller} />
        <SessionDetails controller={controller} />
      </div>
    </PageContainer>
  );
}
