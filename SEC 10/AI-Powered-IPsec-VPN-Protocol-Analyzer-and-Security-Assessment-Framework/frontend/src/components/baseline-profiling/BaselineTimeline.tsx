import { Calendar, Clock, History, Timer } from 'lucide-react';
import type { BaselineProfile } from '@/types';

interface BaselineTimelineProps {
  profile: BaselineProfile;
}

export function BaselineTimeline({ profile }: BaselineTimelineProps) {
  const first = profile.first_observation ? new Date(profile.first_observation) : null;
  const last = profile.last_observation ? new Date(profile.last_observation) : null;

  let durationStr = 'Unknown';
  if (first && last) {
    const diffMs = Math.max(0, last.getTime() - first.getTime());
    const secs = Math.floor(diffMs / 1000);
    const mins = Math.floor(secs / 60);
    const hours = Math.floor(mins / 60);
    if (hours > 0) {
      durationStr = `${hours}h ${mins % 60}m`;
    } else if (mins > 0) {
      durationStr = `${mins}m ${secs % 60}s`;
    } else {
      durationStr = `${secs}s`;
    }
  }

  return (
    <div className="rounded-lg border border-border bg-surface p-5 space-y-3 shadow-sm">
      <div className="flex items-center gap-2 border-b border-border pb-2.5">
        <History className="h-4 w-4 text-cyan-400" />
        <h3 className="text-sm font-bold text-text-primary">Observation Timeline Window</h3>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
        <div className="rounded border border-border bg-base p-3 space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <Calendar className="h-3 w-3 text-cyan-400" />
            First Observed Session
          </span>
          <div className="font-mono text-xs font-semibold text-text-primary">
            {first ? first.toLocaleString() : 'No timestamp available'}
          </div>
        </div>

        <div className="rounded border border-border bg-base p-3 space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <Clock className="h-3 w-3 text-cyan-400" />
            Last Observed Session
          </span>
          <div className="font-mono text-xs font-semibold text-text-primary">
            {last ? last.toLocaleString() : 'No timestamp available'}
          </div>
        </div>

        <div className="rounded border border-border bg-base p-3 space-y-1">
          <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
            <Timer className="h-3 w-3 text-cyan-400" />
            Observation Horizon
          </span>
          <div className="font-mono text-xs font-semibold text-cyan-400">
            {durationStr}
          </div>
        </div>
      </div>
    </div>
  );
}
