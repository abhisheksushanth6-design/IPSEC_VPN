import { Radio } from 'lucide-react';

import { Panel } from '@/components/ui';
import { EmptyState } from '@/components/states';
import { StatusBadge } from '@/components/status';
import { SecurityEventRow } from './SecurityEventRow';
import type { SecurityEvent } from '@/types';

interface SecurityEventStreamProps {
  /** `null` while no event source exists; `[]` when connected but quiet. */
  events: SecurityEvent[] | null;
  title?: string;
  description?: string;
}

/** Live event list. Fed by /ws/events in a later section. */
export function SecurityEventStream({
  events,
  title = 'Live Security Event Stream',
  description = 'Events published on /ws/events.',
}: SecurityEventStreamProps) {
  return (
    <Panel
      title={title}
      description={description}
      actions={<StatusBadge status="READY" label="EVENT STREAM READY" size="sm" />}
      className="flex flex-col"
    >
      {events === null ? (
        <EmptyState
          icon={Radio}
          title="No security events"
          description="Real-time stream active. Security events, negotiation changes, drift alerts, and anomaly detections will appear as traffic is analyzed."
          status="READY"
        />
      ) : events.length === 0 ? (
        <EmptyState icon={Radio} title="No security events" description="Connected. Waiting for events." />
      ) : (
        <ul className="scrollbar-slim max-h-96 overflow-y-auto">
          {events.map((event) => (
            <SecurityEventRow key={event.id} event={event} />
          ))}
        </ul>
      )}
    </Panel>
  );
}
