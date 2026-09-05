import { Loader2 } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
}

/** Shown while a backend request is in flight. */
export function LoadingState({ message = 'Contacting the backend.' }: LoadingStateProps) {
  return (
    <div
      role="status"
      className="flex items-center gap-3 rounded border border-line bg-surface px-4 py-3 text-sm text-muted"
    >
      <Loader2 aria-hidden className="h-4 w-4 animate-spin text-signal" />
      <span>{message}</span>
    </div>
  );
}
