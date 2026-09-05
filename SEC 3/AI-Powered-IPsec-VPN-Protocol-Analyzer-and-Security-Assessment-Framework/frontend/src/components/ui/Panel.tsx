import { useId } from 'react';
import type { ReactNode } from 'react';

import { cn } from '@/utils/cn';

interface PanelProps {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

/**
 * A bordered content region. When titled, the section is labelled by its
 * heading so assistive technology exposes it as a named landmark.
 */
export function Panel({ title, description, actions, children, className }: PanelProps) {
  const headingId = useId();

  return (
    <section
      aria-labelledby={title ? headingId : undefined}
      className={cn('rounded border border-border bg-surface', className)}
    >
      {title ? (
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
          <div>
            <h2 id={headingId} className="text-sm font-medium text-primary">
              {title}
            </h2>
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
