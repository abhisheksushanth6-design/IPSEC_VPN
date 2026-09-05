import { Loader2 } from 'lucide-react';

import { cn } from '@/utils/cn';

export function Spinner({ className }: { className?: string }) {
  return (
    <Loader2 aria-hidden className={cn('h-4 w-4 animate-spin text-info', className)} />
  );
}

/** Inline loading row for a panel that is fetching. */
export function LoadingState({ message = 'Loading' }: { message?: string }) {
  return (
    <div role="status" className="flex items-center gap-3 py-6 text-sm text-muted">
      <Spinner />
      <span>{message}</span>
    </div>
  );
}

/** Full-page loading state used while a route resolves. */
export function PageLoadingState({ message = 'Loading' }: { message?: string }) {
  return (
    <div
      role="status"
      className="flex min-h-64 flex-col items-center justify-center gap-3 text-sm text-muted"
    >
      <Spinner className="h-5 w-5" />
      <span>{message}</span>
    </div>
  );
}

/** Placeholder block matching the shape of a card while it loads. */
export function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div
      aria-hidden
      className="rounded border border-border bg-surface p-4 animate-pulse-slow"
    >
      <div className="h-3 w-28 rounded bg-border" />
      <div className="mt-4 space-y-2">
        {Array.from({ length: lines }).map((_, index) => (
          <div
            key={index}
            className="h-2.5 rounded bg-border"
            style={{ width: `${90 - index * 15}%` }}
          />
        ))}
      </div>
    </div>
  );
}

/** Placeholder rows matching the shape of a data table while it loads. */
export function SkeletonTable({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div
      aria-hidden
      className="overflow-hidden rounded border border-border animate-pulse-slow"
    >
      <div className="flex gap-4 border-b border-border bg-elevated px-4 py-3">
        {Array.from({ length: columns }).map((_, index) => (
          <div key={index} className="h-2.5 flex-1 rounded bg-border" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div
          key={rowIndex}
          className="flex gap-4 border-b border-border px-4 py-3 last:border-b-0"
        >
          {Array.from({ length: columns }).map((_, colIndex) => (
            <div key={colIndex} className="h-2.5 flex-1 rounded bg-border/60" />
          ))}
        </div>
      ))}
    </div>
  );
}
