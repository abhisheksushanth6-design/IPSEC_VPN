import { ArrowRight, Cable, ExternalLink, Fingerprint } from 'lucide-react';
import type { BaselineSessionItem } from '@/types';

interface BaselineSessionTableProps {
  sessions: BaselineSessionItem[];
  onSelectFingerprint?: (fingerprintId: string) => void;
}

export function BaselineSessionTable({
  sessions,
  onSelectFingerprint,
}: BaselineSessionTableProps) {
  if (sessions.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-muted">
        No sessions are linked to this baseline profile.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-muted/50 text-2xs uppercase tracking-wider text-muted">
            <th className="py-2.5 px-4">Session ID</th>
            <th className="py-2.5 px-4">Fingerprint ID</th>
            <th className="py-2.5 px-4">Peers (Source → Destination)</th>
            <th className="py-2.5 px-4 text-center">IKE</th>
            <th className="py-2.5 px-4 text-right">Duration</th>
            <th className="py-2.5 px-4 text-right">Packets</th>
            <th className="py-2.5 px-4 text-right">Bytes</th>
            <th className="py-2.5 px-4 text-center">State</th>
            <th className="py-2.5 px-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {sessions.map((s) => (
            <tr key={s.session_id} className="hover:bg-surface-muted/40 transition">
              <td className="py-3 px-4 font-mono font-semibold text-text-primary">
                <span className="inline-flex items-center gap-1.5">
                  <Cable className="h-3.5 w-3.5 text-cyan-400" />
                  {s.session_id}
                </span>
              </td>

              <td className="py-3 px-4 font-mono text-2xs text-muted">
                <span className="inline-flex items-center gap-1">
                  <Fingerprint className="h-3 w-3 text-sky-400" />
                  {s.fingerprint_id.slice(0, 16)}...
                </span>
              </td>

              <td className="py-3 px-4 font-mono text-2xs text-text-secondary">
                <span className="inline-flex items-center gap-1">
                  {s.source ?? '—'}
                  <ArrowRight className="h-2.5 w-2.5 text-muted" />
                  {s.destination ?? '—'}
                </span>
              </td>

              <td className="py-3 px-4 text-center font-mono text-2xs text-muted">
                {s.ike_version ?? '—'}
              </td>

              <td className="py-3 px-4 text-right font-mono text-2xs text-muted">
                {s.duration !== null ? `${s.duration.toFixed(2)}s` : '—'}
              </td>

              <td className="py-3 px-4 text-right font-mono text-2xs text-text-secondary">
                {s.packets?.toLocaleString() ?? '—'}
              </td>

              <td className="py-3 px-4 text-right font-mono text-2xs text-text-secondary">
                {s.bytes?.toLocaleString() ?? '—'}
              </td>

              <td className="py-3 px-4 text-center">
                <span className="rounded bg-surface-muted px-2 py-0.5 font-mono text-2xs font-semibold text-text-secondary border border-border">
                  {s.state ?? 'UNKNOWN'}
                </span>
              </td>

              <td className="py-3 px-4 text-right">
                {onSelectFingerprint && (
                  <button
                    type="button"
                    onClick={() => onSelectFingerprint(s.fingerprint_id)}
                    className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2 py-1 text-2xs font-medium text-text-secondary hover:text-cyan-400 hover:border-cyan-500 transition"
                  >
                    <span>View FP</span>
                    <ExternalLink className="h-2.5 w-2.5" />
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
