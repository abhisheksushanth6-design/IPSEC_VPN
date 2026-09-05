import { Cable, ChevronDown } from 'lucide-react';
import type { VPNSession } from '@/types';

interface SessionSelectorProps {
  sessions: VPNSession[];
  selectedSessionId: string | null;
  onSelect: (sessionId: string) => void;
  disabled?: boolean;
}

export function SessionSelector({
  sessions,
  selectedSessionId,
  onSelect,
  disabled,
}: SessionSelectorProps) {
  if (sessions.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-border bg-surface-muted/40 px-3 py-1.5 text-xs text-muted">
        <Cable className="h-3.5 w-3.5" />
        <span>No observed sessions available</span>
      </div>
    );
  }

  return (
    <div className="relative inline-flex items-center">
      <Cable className="absolute left-2.5 h-3.5 w-3.5 text-cyan-400 pointer-events-none" />
      <select
        value={selectedSessionId ?? ''}
        onChange={(e) => onSelect(e.target.value)}
        disabled={disabled}
        className="appearance-none rounded-md border border-border bg-surface pl-8 pr-8 py-1.5 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none transition cursor-pointer disabled:opacity-50"
      >
        <option value="" disabled>
          Select Target Session...
        </option>
        {sessions.map((s) => (
          <option key={s.id} value={s.id}>
            {s.id} ({s.source ?? '—'} → {s.destination ?? '—'})
          </option>
        ))}
      </select>
      <ChevronDown className="absolute right-2.5 h-3.5 w-3.5 text-muted pointer-events-none" />
    </div>
  );
}
