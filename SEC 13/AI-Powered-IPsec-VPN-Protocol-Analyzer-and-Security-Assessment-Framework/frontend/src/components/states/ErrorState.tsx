import { PlugZap, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
}

/**
 * Shown when the backend cannot be reached. The message describes what
 * happened and what to do; internal detail is never surfaced.
 */
export function ErrorState({
  title = 'Unable to connect',
  message = 'The backend service is currently unavailable.',
  onRetry,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded border border-danger/30 bg-danger/5 px-5 py-5 animate-fade-in"
    >
      <div className="flex items-start gap-3">
        <PlugZap aria-hidden className="mt-0.5 h-5 w-5 shrink-0 text-danger" />

        <div className="max-w-reading">
          <h3 className="text-base font-medium text-primary">{title}</h3>
          <p className="mt-1 text-sm text-secondary">{message}</p>
          <p className="mt-2 text-sm text-muted">
            Start the backend with{' '}
            <code className="rounded bg-elevated px-1 py-0.5 font-mono text-xs text-secondary">
              uvicorn app.main:app --reload
            </code>{' '}
            from the backend directory. Navigation continues to work while the
            backend is offline.
          </p>

          {onRetry ? (
            <button
              type="button"
              onClick={onRetry}
              className="mt-4 inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 text-sm text-primary transition-colors hover:border-info hover:text-info"
            >
              <RefreshCw aria-hidden className="h-3.5 w-3.5" />
              Retry
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
