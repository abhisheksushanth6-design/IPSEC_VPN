import { PlugZap } from 'lucide-react';

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
}

/** Shown when the backend cannot be reached or returns an error. */
export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded border border-line bg-surface px-4 py-4 text-sm"
    >
      <div className="flex items-start gap-3">
        <PlugZap aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-caution" />
        <div className="max-w-reading">
          <p className="text-text">{message}</p>
          <p className="mt-1 text-muted">
            Start the backend with <span className="font-mono">uvicorn app.main:app</span> from
            the <span className="font-mono">backend</span> directory, then try again.
          </p>
          {onRetry ? (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 rounded border border-line px-3 py-1.5 text-text transition-colors hover:border-signal hover:text-signal"
            >
              Try again
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
