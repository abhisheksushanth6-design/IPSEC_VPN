import type { ReactNode } from 'react';

import { cn } from '@/utils/cn';

interface PanelProps {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** A bordered content region. The standard container for page sections. */
export function Panel({ title, description, actions, children, className }: PanelProps) {
  return (
    <section className={cn('rounded border border-border bg-surface', className)}>
      {title ? (
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
          <div>
            <h2 className="text-sm font-medium text-primary">{title}</h2>
            {description ? (
              <p className="mt-1 text-xs text-muted">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="shrink-0">{actions}</div> : null}
        </div>
      ) : null}

      <div className="p-5">{children}</div>
    </section>
  );
}
