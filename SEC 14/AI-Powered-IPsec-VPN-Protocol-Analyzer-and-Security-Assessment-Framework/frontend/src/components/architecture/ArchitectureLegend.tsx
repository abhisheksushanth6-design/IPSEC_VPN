import { StatusBadge } from '@/components/status';
import type { ArchitectureStatus } from '@/types';

const LEGEND: Array<{ status: ArchitectureStatus; meaning: string }> = [
  { status: 'OPERATIONAL', meaning: 'Layer operational and verified' },
  { status: 'FOUNDATION READY', meaning: 'Structure ready for implementation' },
  { status: 'FOUNDATION CREATED', meaning: 'Technical foundation exists' },
  { status: 'NOT INITIALIZED', meaning: 'Functionality not yet available' },
];

export function ArchitectureLegend() {
  return (
    <dl aria-label="Status legend" className="flex flex-wrap gap-x-6 gap-y-2">
      {LEGEND.map((entry) => (
        <div key={entry.status} className="flex items-center gap-2">
          <dt>
            <StatusBadge status={entry.status} size="sm" />
          </dt>
          <dd className="text-xs text-muted">{entry.meaning}</dd>
        </div>
      ))}
    </dl>
  );
}
