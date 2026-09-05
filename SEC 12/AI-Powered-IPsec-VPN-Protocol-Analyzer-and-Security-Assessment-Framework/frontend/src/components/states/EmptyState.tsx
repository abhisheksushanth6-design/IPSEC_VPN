import { Inbox } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

import { StatusBadge } from '@/components/status';
import type { StatusKind } from '@/types';

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  status?: StatusKind;
  action?: ReactNode;
}

/**
 * Shown when a view has nothing to display. An empty screen states what is
 * absent and what would fill it, rather than apologising.
 */
export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  status,
  action,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center rounded border border-dashed border-border bg-surface px-6 py-12 text-center">
      <span className="rounded-full border border-border bg-elevated p-3">
        <Icon aria-hidden className="h-5 w-5 text-muted" />
      </span>

      <h3 className="mt-4 text-base font-medium text-primary">{title}</h3>

      {description ? (
        <p className="mt-2 max-w-reading text-sm text-muted">{description}</p>
      ) : null}

      {status ? <StatusBadge status={status} className="mt-4" size="sm" /> : null}

      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}
