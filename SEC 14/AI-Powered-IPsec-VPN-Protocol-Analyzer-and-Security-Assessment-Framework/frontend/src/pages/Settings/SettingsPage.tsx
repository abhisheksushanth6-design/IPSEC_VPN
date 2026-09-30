import { Moon, Settings2, Sun } from 'lucide-react';

import { PageContainer } from '@/components/layout';
import { DataRow, PageHeader, Panel } from '@/components/ui';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { StatusBadge } from '@/components/status';
import { useSystemState } from '@/context/SystemStateContext';
import { useTheme } from '@/context/ThemeContext';
import type { StatusKind } from '@/types';

/**
 * Settings displays system configuration and provides user theme customization.
 */
export function SettingsPage() {
  const { state, status, errorMessage, refresh } = useSystemState();
  const { theme, setTheme } = useTheme();

  return (
    <PageContainer>
      <PageHeader
        title="System Settings"
        description="Application configuration reported by the backend and local interface appearance preferences."
        status={state === 'ready' ? 'ONLINE' : state === 'loading' ? 'INITIALIZING' : 'BACKEND OFFLINE'}
        breadcrumbs={[{ label: 'System' }, { label: 'System Settings' }]}
      />

      {state === 'loading' ? <LoadingState message="Reading configuration" /> : null}

      {state === 'error' ? (
        <ErrorState message={errorMessage ?? undefined} onRetry={refresh} />
      ) : null}

      <div className="space-y-6">
        <Panel title="Appearance & Theme" description="Select your preferred color theme. Preference is persisted across browser refreshes.">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-lg">
            <button
              type="button"
              data-testid="settings-theme-light"
              onClick={() => setTheme('light')}
              aria-pressed={theme === 'light'}
              className={`flex items-center gap-3.5 p-3.5 rounded-lg border text-left transition-all ${
                theme === 'light'
                  ? 'border-info bg-info/10 text-primary shadow-sm ring-1 ring-info'
                  : 'border-border bg-surface text-secondary hover:bg-elevated hover:text-primary'
              }`}
            >
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 text-amber-500 border border-amber-500/20">
                <Sun className="h-5 w-5" />
              </div>
              <div>
                <p className="text-sm font-medium">Light Mode</p>
                <p className="text-2xs text-muted">Clean high-contrast daytime interface</p>
              </div>
            </button>

            <button
              type="button"
              data-testid="settings-theme-dark"
              onClick={() => setTheme('dark')}
              aria-pressed={theme === 'dark'}
              className={`flex items-center gap-3.5 p-3.5 rounded-lg border text-left transition-all ${
                theme === 'dark'
                  ? 'border-info bg-info/10 text-primary shadow-sm ring-1 ring-info'
                  : 'border-border bg-surface text-secondary hover:bg-elevated hover:text-primary'
              }`}
            >
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
                <Moon className="h-5 w-5" />
              </div>
              <div>
                <p className="text-sm font-medium">Dark Mode</p>
                <p className="text-2xs text-muted">Deep navy cybersecurity operations center</p>
              </div>
            </button>
          </div>
        </Panel>

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
              title="No editable backend settings yet"
              description="Backend configuration is managed through environment variables. An in-application settings editor is implemented in a later development stage."
              status="NOT INITIALIZED"
            />
          </>
        ) : null}
      </div>
    </PageContainer>
  );
}
