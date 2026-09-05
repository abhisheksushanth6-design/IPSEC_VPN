import { ChartNoAxesColumn } from 'lucide-react';

interface EmptyChartStateProps {
  message?: string;
  detail?: string;
  height?: number;
}

/** Stands in for a chart when its data source does not exist yet. */
export function EmptyChartState({
  message = 'NO DATA AVAILABLE',
  detail,
  height = 200,
}: EmptyChartStateProps) {
  return (
    <div
      role="status"
      style={{ minHeight: height }}
      className="flex h-full flex-col items-center justify-center rounded border border-dashed border-border text-center"
    >
      <ChartNoAxesColumn aria-hidden className="h-5 w-5 text-muted" />
      <p className="mt-3 text-xs font-medium text-secondary">{message}</p>
      {detail ? <p className="mt-1 max-w-xs px-4 text-2xs text-muted">{detail}</p> : null}
    </div>
  );
}
