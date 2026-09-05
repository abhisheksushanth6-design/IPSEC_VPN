import {
  AlertTriangle,
  BrainCircuit,
  Gauge,
  GitCompare,
  KeyRound,
  Network,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { cn } from '@/utils/cn';
import type { EventSeverity, SecurityEvent, SecurityEventType } from '@/types';

const EVENT_ICON: Record<SecurityEventType, LucideIcon> = {
  'Packet Captured': Network,
  'IKE Negotiation': KeyRound,
  'SA Established': KeyRound,
  'SA Rekey': RefreshCw,
  'Security Drift Detected': GitCompare,
  'AI Anomaly Detected': BrainCircuit,
  'Vulnerability Detected': ShieldAlert,
  'Risk Score Changed': Gauge,
};

const SEVERITY_TONE: Record<EventSeverity, string> = {
  INFO: 'text-info border-info/35 bg-info/10',
  LOW: 'text-success border-success/35 bg-success/10',
  MEDIUM: 'text-warning border-warning/35 bg-warning/10',
  HIGH: 'text-warning border-warning/35 bg-warning/10',
  CRITICAL: 'text-danger border-danger/35 bg-danger/10',
};

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** One row of the event stream. Renders only data it is given. */
export function SecurityEventRow({ event }: { event: SecurityEvent }) {
  const Icon = EVENT_ICON[event.type] ?? AlertTriangle;

  return (
    <li className="flex items-start gap-3 border-b border-border py-2.5 last:border-b-0">
      <time
        dateTime={event.timestamp}
        className="w-16 shrink-0 pt-0.5 font-mono text-2xs tabular-nums text-muted"
      >
        {formatTimestamp(event.timestamp)}
      </time>

      <Icon aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0 text-secondary" />

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-primary">{event.type}</span>
          <span
            className={cn(
              'rounded border px-1 py-px text-2xs font-medium',
              SEVERITY_TONE[event.severity],
            )}
          >
            {event.severity}
          </span>
        </div>
        <p className="mt-0.5 truncate text-xs text-secondary">{event.description}</p>
        <p className="font-mono text-2xs text-muted">{event.source}</p>
      </div>
    </li>
  );
}
