import { Settings2 } from 'lucide-react';

import { PageContainer } from '@/components/layout';
import { DataRow, PageHeader, Panel } from '@/components/ui';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { StatusBadge } from '@/components/status';
import { useSystemState } from '@/context/SystemStateContext';
import type { StatusKind } from '@/types';

/**
 * Settings currently displays the configuration the backend actually reports.
 * Editing configuration is implemented in a later section.
 */
export function SettingsPage() {
  const { state, status, errorMessage, refresh } = useSystemState();

  return (
    <PageContainer>
      <PageHeader
        title="System Settings"
        description="Application configuration reported by the backend. Values are read-only at this stage."
        status={state === 'ready' ? 'ONLINE' : state === 'loading' ? 'INITIALIZING' : 'BACKEND OFFLINE'}
        breadcrumbs={[{ label: 'System' }, { label: 'System Settings' }]}
      />

      {state === 'loading' ? <LoadingState message="Reading configuration" /> : null}

      {state === 'error' ? (
        <ErrorState message={errorMessage ?? undefined} onRetry={refresh} />
      ) : null}

      {state === 'ready' && status ? (
        <>
          <Panel title="Configuration" description="Read from the backend at runtime.">
            <dl>
              <DataRow label="Application mode">
                <StatusBadge
                  status={
                    (status.application_mode === 'LIVE' || status.application_mode === 'PRODUCTION'
                      ? 'LIVE'
                      : status.application_mode === 'STANDALONE'
                      ? 'STANDALONE'
                      : status.application_mode === 'DEMO'
                      ? 'DEMO'
                      : 'ONLINE') as StatusKind
                  }
                  label={status.application_mode}
                  size="sm"
                />
              </DataRow>
              <DataRow label="Database">{status.database_status}</DataRow>
              <DataRow label="Backend">{status.backend_status}</DataRow>
            </dl>
          </Panel>

          <EmptyState
            icon={Settings2}
            title="No editable settings yet"
            description="Configuration is managed through environment variables. An in-application settings editor is implemented in a later development stage."
            status="NOT INITIALIZED"
          />
        </>
      ) : null}
    </PageContainer>
  );
}
