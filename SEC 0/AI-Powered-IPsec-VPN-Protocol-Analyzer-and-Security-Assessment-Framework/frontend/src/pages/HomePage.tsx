import { ErrorState, LoadingState, StatusIndicator } from '@/components';
import { useSystemStatus } from '@/hooks/useSystemStatus';

/**
 * Boot screen for the foundation. It reports what the backend actually says
 * about itself and nothing more.
 */
export function HomePage() {
  const { state, status, errorMessage, retry } = useSystemStatus();

  return (
    <div className="space-y-10">
      <section>
        <h1 className="max-w-reading text-3xl font-medium leading-snug tracking-tight sm:text-4xl">
          AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
        </h1>
        <p className="mt-4 max-w-reading text-muted">
          The foundation is in place: a FastAPI backend, a SQLite store, a WebSocket
          channel and this React shell. The fourteen analysis layers are defined but not
          yet built.
        </p>
      </section>

      <section className="rounded border border-line bg-surface p-6">
        <h2 className="mb-2 text-lg font-medium">Backend connection</h2>

        {state === 'loading' ? <LoadingState /> : null}

        {state === 'error' ? (
          <ErrorState
            message={errorMessage ?? 'Could not load system status.'}
            onRetry={retry}
          />
        ) : null}

        {state === 'ready' && status ? (
          <div className="mt-4">
            <StatusIndicator label="Backend" value={status.backend_status} tone="signal" />
            <StatusIndicator
              label="Database"
              value={status.database_status}
              tone={status.database_status === 'CONNECTED' ? 'signal' : 'fault'}
            />
            <StatusIndicator label="Application mode" value={status.application_mode} />
            <StatusIndicator
              label="Architecture layers"
              value={`${status.initialized_layers} of ${status.total_layers} have a foundation`}
            />
          </div>
        ) : null}
      </section>
    </div>
  );
}
