import {
  AlertTriangle,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleSlash,
  Hammer,
  Layers,
  Loader2,
  OctagonAlert,
  Radio,
  ShieldCheck,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { cn } from '@/utils/cn';
import type { StatusKind, StatusTone } from '@/types';

interface StatusDescriptor {
  tone: StatusTone;
  icon: LucideIcon;
}

/**
 * Status is never carried by colour alone: each entry pairs a tone with a
 * distinct icon and keeps its text label visible.
 */
const STATUS_MAP: Record<StatusKind, StatusDescriptor> = {
  ONLINE: { tone: 'success', icon: ShieldCheck },
  READY: { tone: 'success', icon: CircleCheck },
  ERROR: { tone: 'danger', icon: OctagonAlert },
  'FOUNDATION ONLINE': { tone: 'success', icon: ShieldCheck },
  LIVE: { tone: 'success', icon: Radio },
  STANDALONE: { tone: 'success', icon: ShieldCheck },
  ACTIVE: { tone: 'success', icon: Radio },
  DEMO: { tone: 'info', icon: CircleDashed },
  INITIALIZING: { tone: 'info', icon: Loader2 },
  'NOT INITIALIZED': { tone: 'neutral', icon: CircleDashed },
  INACTIVE: { tone: 'neutral', icon: CircleSlash },
  WARNING: { tone: 'warning', icon: AlertTriangle },
  OFFLINE: { tone: 'danger', icon: CircleSlash },
  'BACKEND OFFLINE': { tone: 'danger', icon: CircleSlash },
  CRITICAL: { tone: 'danger', icon: OctagonAlert },
  'FOUNDATION CREATED': { tone: 'info', icon: CircleDot },
  'FOUNDATION READY': { tone: 'info', icon: CircleCheck },
  'IN DEVELOPMENT': { tone: 'warning', icon: Hammer },
  OPERATIONAL: { tone: 'success', icon: CircleCheck },
  IMPLEMENTED: { tone: 'success', icon: CircleCheck },
  'ARCHITECTURE DEFINED': { tone: 'info', icon: Layers },
};

const TONE_CLASSES: Record<StatusTone, string> = {
  success: 'border-success/35 bg-success/10 text-success',
  warning: 'border-warning/35 bg-warning/10 text-warning',
  danger: 'border-danger/35 bg-danger/10 text-danger',
  info: 'border-info/35 bg-info/10 text-info',
  neutral: 'border-border bg-elevated text-muted',
};

interface StatusBadgeProps {
  status: StatusKind;
  /** Overrides the visible text while keeping the status semantics. */
  label?: string;
  size?: 'sm' | 'md';
  className?: string;
}

export function StatusBadge({
  status,
  label,
  size = 'md',
  className,
}: StatusBadgeProps) {
  const descriptor = STATUS_MAP[status] ?? STATUS_MAP['NOT INITIALIZED'];
  const Icon = descriptor.icon;
  const spins = status === 'INITIALIZING';

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border font-medium',
        TONE_CLASSES[descriptor.tone],
        size === 'sm' ? 'px-1.5 py-0.5 text-2xs' : 'px-2 py-1 text-xs',
        className,
      )}
    >
      <Icon
        aria-hidden
        className={cn(size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5', spins && 'animate-spin')}
      />
      <span>{label ?? status}</span>
    </span>
  );
}

/** Resolve the semantic tone of a status, for callers that need the colour. */
export function statusTone(status: StatusKind): StatusTone {
  return (STATUS_MAP[status] ?? STATUS_MAP['NOT INITIALIZED']).tone;
}
