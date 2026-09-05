import { ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';

import { StatusBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import type { DashboardMetric } from '@/types';

interface MetricCardProps {
  metric: DashboardMetric;
  className?: string;
}

const numberFormatter = new Intl.NumberFormat('en-US');

/**
 * A single KPI. The number is only shown when the metric carries one; when
 * the engine is not initialised the status stands in for it, so a bare zero
 * never reads as a measurement.
 */
export function MetricCard({ metric, className }: MetricCardProps) {
  const Icon = metric.icon;
  const hasValue = metric.value !== null;
  const unavailable = metric.source === 'unavailable';

  return (
    <article
      aria-labelledby={`metric-${metric.id}-label`}
      className={cn(
        'relative flex flex-col rounded border border-border bg-surface p-4',
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <p id={`metric-${metric.id}-label`} className="text-xs text-muted">
          {metric.label}
        </p>
        <Icon aria-hidden className="h-4 w-4 shrink-0 text-muted" />
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        {hasValue ? (
          <span
            className={cn(
              'font-mono text-2xl font-medium tabular-nums',
              unavailable ? 'text-secondary' : 'text-primary',
            )}
          >
            {numberFormatter.format(metric.value as number)}
          </span>
        ) : (
          <span className="text-sm font-medium text-secondary">
            {metric.status ?? 'NOT INITIALIZED'}
          </span>
        )}
      </div>

      <div className="mt-3 flex items-center justify-between gap-2">
        {metric.status && hasValue ? (
          <StatusBadge status={metric.status} label={metric.statusLabel} size="sm" />
        ) : (
          <span className="text-2xs text-muted">
            {unavailable ? 'Engine not implemented' : 'Reported by backend'}
          </span>
        )}

        {metric.href ? (
          <Link
            to={metric.href}
            aria-label={`Open ${metric.label}`}
            className="rounded p-1 text-muted transition-colors hover:bg-elevated hover:text-primary"
          >
            <ArrowUpRight aria-hidden className="h-3.5 w-3.5" />
          </Link>
        ) : null}
      </div>
    </article>
  );
}
