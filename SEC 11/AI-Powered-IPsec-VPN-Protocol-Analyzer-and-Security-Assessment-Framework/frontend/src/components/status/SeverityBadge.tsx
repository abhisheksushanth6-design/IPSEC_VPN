import { AlertTriangle, Info, OctagonAlert, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { cn } from '@/utils/cn';
import type { EventSeverity } from '@/types';

const SEVERITY: Record<EventSeverity, { icon: LucideIcon; classes: string }> = {
  INFO: { icon: Info, classes: 'text-info border-info/35 bg-info/10' },
  LOW: { icon: ShieldCheck, classes: 'text-success border-success/35 bg-success/10' },
  MEDIUM: { icon: AlertTriangle, classes: 'text-warning border-warning/35 bg-warning/10' },
  HIGH: { icon: ShieldAlert, classes: 'text-warning border-warning/35 bg-warning/10' },
  CRITICAL: { icon: OctagonAlert, classes: 'text-danger border-danger/35 bg-danger/10' },
};

export function SeverityBadge({ severity, className }: { severity: EventSeverity; className?: string }) {
  const Icon = SEVERITY[severity].icon;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-px text-2xs font-medium',
        SEVERITY[severity].classes,
        className,
      )}
    >
      <Icon aria-hidden className="h-3 w-3" />
      {severity}
    </span>
  );
}
