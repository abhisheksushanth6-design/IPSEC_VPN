import { Clock, ServerCog } from 'lucide-react';

import { Panel } from '@/components/ui';
import { EmptyState } from '@/components/states';
import type { SystemActivityEvent } from '@/types';

interface SystemActivityProps {
  /** Real lifecycle entries only, newest last. */
  activity: SystemActivityEvent[];
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}

/**
 * Operational log. At this stage the only source is the real-time channel's
 * own connect/disconnect transitions, each stamped when it actually happened.
 */
export function SystemActivity({ activity }: SystemActivityProps) {
  return (
    <Panel title="System Activity" description="Capture, analyzer, model and connection lifecycle.">
      {activity.length === 0 ? (
        <EmptyState icon={ServerCog} title="No system activity" description="No capture, analyzer or model lifecycle events have occurred." />
      ) : (
        <ol className="scrollbar-slim max-h-64 overflow-y-auto">
          {[...activity].reverse().map((entry) => (
            <li key={entry.id} className="flex items-start gap-3 border-b border-border py-2 last:border-b-0">
              <Clock aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-muted" />
              <time dateTime={entry.timestamp} className="w-16 shrink-0 font-mono text-2xs tabular-nums text-muted">{formatTime(entry.timestamp)}</time>
              <div className="min-w-0">
                <p className="text-xs font-medium text-primary">{entry.type}</p>
                <p className="truncate font-mono text-2xs text-muted">{entry.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
