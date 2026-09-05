import { ChevronRight } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { StatusBadge } from '@/components/status';
import type { StatusKind } from '@/types';

export interface Breadcrumb {
  label: string;
  /** Omit for the current page, which is rendered as plain text. */
  to?: string;
}

interface PageHeaderProps {
  title: string;
  description?: string;
  status?: StatusKind;
  statusLabel?: string;
  breadcrumbs?: Breadcrumb[];
  actions?: ReactNode;
}

/** Standard header used at the top of every page. */
export function PageHeader({
  title,
  description,
  status,
  statusLabel,
  breadcrumbs,
  actions,
}: PageHeaderProps) {
  return (
    <header className="border-b border-border pb-5">
      {breadcrumbs && breadcrumbs.length > 0 ? (
        <nav aria-label="Breadcrumb" className="mb-3">
          <ol className="flex flex-wrap items-center gap-1 text-2xs text-muted">
            {breadcrumbs.map((crumb, index) => (
              <li key={`${crumb.label}-${index}`} className="flex items-center gap-1">
                {index > 0 ? (
                  <ChevronRight aria-hidden className="h-3 w-3 text-border" />
                ) : null}
                {crumb.to ? (
                  <Link
                    to={crumb.to}
                    className="rounded transition-colors hover:text-secondary"
                  >
                    {crumb.label}
                  </Link>
                ) : (
                  <span aria-current="page" className="text-secondary">
                    {crumb.label}
                  </span>
                )}
              </li>
            ))}
          </ol>
        </nav>
      ) : null}

      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">{title}</h1>
            {status ? <StatusBadge status={status} label={statusLabel} size="sm" /> : null}
          </div>

          {description ? (
            <p className="mt-2 max-w-reading text-sm leading-relaxed text-muted">
              {description}
            </p>
          ) : null}
        </div>

        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}
