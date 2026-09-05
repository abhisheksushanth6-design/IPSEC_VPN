import { cn } from '@/utils/cn';
import type { ReactNode } from 'react';

interface DataRowProps {
  label: string;
  children: ReactNode;
  className?: string;
}

/** A labelled value in a definition-style list. */
export function DataRow({ label, children, className }: DataRowProps) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-3 border-b border-border py-2.5 last:border-b-0',
        className,
      )}
    >
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="text-sm text-primary">{children}</dd>
    </div>
  );
}
