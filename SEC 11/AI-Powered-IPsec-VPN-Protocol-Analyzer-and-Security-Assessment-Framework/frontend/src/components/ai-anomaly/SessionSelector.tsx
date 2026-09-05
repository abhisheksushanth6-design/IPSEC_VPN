import type { VPNSession } from '@/types';

interface SessionSelectorProps {
  sessions: VPNSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  disabled?: boolean;
}

export function SessionSelector({
  sessions,
  selectedSessionId,
  onSelectSession,
  disabled = false,
}: SessionSelectorProps) {
  return (
    <div>
      <label className="block text-xs font-semibold text-text-primary mb-1">
        Target IPsec Session <span className="text-rose-400">*</span>
      </label>
      <select
        value={selectedSessionId || ''}
        onChange={(e) => onSelectSession(e.target.value)}
        disabled={disabled || sessions.length === 0}
        className="w-full rounded border border-border bg-base px-3 py-2 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none"
      >
        {sessions.length === 0 ? (
          <option value="">No Observed Sessions Available (Capture in Layer 02/03)</option>
        ) : (
          sessions.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id} ({s.source} ↔ {s.destination}, {(s as any).packet_count ?? (s as any).total_packets ?? 0} pkts, {s.state})
            </option>
          ))
        )}
      </select>
    </div>
  );
}
