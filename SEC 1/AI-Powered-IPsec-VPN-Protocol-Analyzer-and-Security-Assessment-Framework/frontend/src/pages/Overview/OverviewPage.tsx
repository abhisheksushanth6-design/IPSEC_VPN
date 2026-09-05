import { Database, Layers, RefreshCw, Server } from 'lucide-react';

import { PageContainer } from '@/components/layout';
import { DataRow, PageHeader, Panel } from '@/components/ui';
import { ErrorState, LoadingState } from '@/components/states';
import { StatusBadge } from '@/components/status';
import { PROJECT_NAME } from '@/config/branding';
import { useSystemState } from '@/context/SystemStateContext';

const FOUNDATION_ITEMS = [
  {
    icon: Server,
    label: 'Backend and API',
    detail: 'FastAPI serving health and system status.',
  },
  {
    icon: Database,
    label: 'Database',
    detail: 'SQLite holding application configuration only.',
  },
  {
    icon: Layers,
    label: 'Web shell',
    detail: 'Navigation, routing and shared page components.',
  },
];

/**
 * Overview reports the real state of the foundation. The operational
 * dashboard belongs to a later section; nothing here is fabricated.
 */
export function OverviewPage() {
  const { state, reachable, status, errorMessage, refresh } = useSystemState();

  return (
    <PageContainer>
      <PageHeader
        title="Overview"
        description={PROJECT_NAME}
        status={
          state === 'loading'
            ? 'INITIALIZING'
            : reachable
              ? 'FOUNDATION ONLINE'
              : 'BACKEND OFFLINE'
        }
        breadcrumbs={[{ label: 'Overview' }]}
        actions={
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 text-sm text-secondary transition-colors hover:border-info hover:text-info"
          >
            <RefreshCw aria-hidden className="h-3.5 w-3.5" />
            Refresh
          </button>
        }
      />

      {state === 'loading' ? <LoadingState message="Contacting the backend" /> : null}

      {state === 'error' ? (
        <ErrorState message={errorMessage ?? undefined} onRetry={refresh} />
      ) : null}

      {state === 'ready' && status ? (
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel title="Backend" description="Reported by the running API.">
            <dl>
              <DataRow label="Service">
                <StatusBadge status="ONLINE" label={status.backend_status} size="sm" />
              </DataRow>
              <DataRow label="Database">
                <StatusBadge
                  status={
                    status.database_status === 'CONNECTED' ? 'ONLINE' : 'NOT INITIALIZED'
                  }
                  label={status.database_status}
                  size="sm"
                />
              </DataRow>
              <DataRow label="Application mode">
                <StatusBadge
                  status={status.application_mode === 'LIVE' ? 'LIVE' : 'DEMO'}
                  label={status.application_mode}
                  size="sm"
                />
              </DataRow>
            </dl>
          </Panel>

          <Panel title="Architecture" description="Progress across the fourteen layers.">
            <dl>
              <DataRow label="Layers defined">{status.total_layers}</DataRow>
              <DataRow label="Layers with a foundation">
                {status.initialized_layers}
              </DataRow>
              <DataRow label="Analysis layers implemented">0</DataRow>
            </dl>
            <p className="mt-4 text-xs text-muted">
              A per-layer breakdown arrives with the architecture view in a later
              section.
            </p>
          </Panel>

          <Panel className="lg:col-span-2" title="What exists so far">
            <ul className="grid gap-4 sm:grid-cols-3">
              {FOUNDATION_ITEMS.map((entry) => (
                <li
                  key={entry.label}
                  className="rounded border border-border bg-elevated/40 p-4"
                >
                  <entry.icon aria-hidden className="h-4 w-4 text-info" />
                  <p className="mt-3 text-sm font-medium text-primary">{entry.label}</p>
                  <p className="mt-1 text-xs text-muted">{entry.detail}</p>
                </li>
              ))}
            </ul>

            <p className="mt-5 max-w-reading text-sm text-muted">
              No packet capture, protocol analysis, anomaly detection, vulnerability
              evaluation, risk scoring or report generation is running. Those modules
              are implemented in later stages.
            </p>
          </Panel>
        </div>
      ) : null}
    </PageContainer>
  );
}
