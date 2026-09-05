import { cn } from '@/utils/cn';
import type { StatusKind } from '@/types';
import { StatusBadge } from './StatusBadge';

interface StatusReadoutProps {
  label: string;
  status: StatusKind;
  displayValue?: string;
  className?: string;
}

/** A labelled status used in the header cluster and on summary panels. */
export function StatusReadout({
  label,
  status,
  displayValue,
  className,
}: StatusReadoutProps) {
  return (
    <div className={cn('flex flex-col gap-1', className)}>
      <span className="text-2xs text-muted">{label}</span>
      <StatusBadge status={status} label={displayValue} size="sm" />
    </div>
  );
}
