import type { ReactNode } from 'react';

import { cn } from '@/utils/cn';

interface ChartCardProps {
  title: string;
  description?: string;
  /** Owning layer, shown as metadata. */
  source?: string;
  children: ReactNode;
  className?: string;
}

/** Container shared by every dashboard chart. */
export function ChartCard({ title, description, source, children, className }: ChartCardProps) {
  return (
    <section
      aria-label={title}
      className={cn('flex flex-col rounded border border-border bg-surface', className)}
    >
      <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-primary">{title}</h3>
          {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
        </div>
        {source ? (
          <span className="shrink-0 font-mono text-2xs text-muted">{source}</span>
        ) : null}
      </div>
      <div className="flex-1 p-4">{children}</div>
    </section>
  );
}
