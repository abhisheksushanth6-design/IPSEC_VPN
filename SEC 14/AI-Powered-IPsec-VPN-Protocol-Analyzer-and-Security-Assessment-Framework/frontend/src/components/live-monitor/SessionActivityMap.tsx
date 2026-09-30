import { ArrowRight, Cable, Clock, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { VPNSession } from '@/types';
import { cn } from '@/utils/cn';

interface SessionActivityMapProps {
  sessions: VPNSession[] | null;
  selectedId: string | null;
  onSelect: (session: VPNSession) => void;
  className?: string;
}

export function SessionActivityMap({
  sessions,
  selectedId,
  onSelect,
  className,
}: SessionActivityMapProps) {
  if (!sessions || sessions.length === 0) {
    return null; // Empty state handled by VPNSessionPanel
  }

  return (
    <div className={cn('rounded border border-border bg-surface p-4 space-y-3', className)}>
      <div className="flex items-center justify-between border-b border-border/70 pb-2">
        <div className="flex items-center gap-2">
          <Cable className="h-4 w-4 text-info" />
          <h3 className="text-xs font-semibold text-primary">Session Activity Flow Map</h3>
          <span className="rounded bg-info/10 px-1.5 py-0.5 font-mono text-[10px] text-info border border-info/30">
            {sessions.length} Flow{sessions.length === 1 ? '' : 's'}
          </span>
        </div>
        <span className="text-[10px] text-muted font-mono">Observable Endpoints &amp; SA State</span>
      </div>

      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
        {sessions.map((sess) => {
          const isSelected = selectedId === sess.id;
          const isEstablished = sess.state === 'ESTABLISHED' || (sess.state as any) === 'ACTIVE';

          return (
            <div
              key={sess.id}
              onClick={() => onSelect(sess)}
              className={cn(
                'group cursor-pointer rounded-md border p-3 transition-all',
                isSelected
                  ? 'border-info bg-info/10 shadow-sm ring-1 ring-info/30'
                  : 'border-border/70 bg-background/50 hover:border-info/50 hover:bg-elevated/40'
              )}
            >
              {/* Card Header: Session ID + State */}
              <div className="flex items-center justify-between gap-2 border-b border-border/50 pb-2">
                <span className="font-mono text-xs font-bold text-primary truncate max-w-[180px]">
                  {sess.id}
                </span>
                <span
                  className={cn(
                    'rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase',
                    isEstablished
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                      : sess.state === 'CLOSED'
                      ? 'border-slate-500/40 bg-slate-500/10 text-slate-400'
                      : 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                  )}
                >
                  {sess.state}
                </span>
              </div>

              {/* Endpoints Flow Visualization */}
              <div className="mt-2.5 flex items-center justify-between gap-1.5 font-mono text-2xs">
                <div className="min-w-0 flex-1 rounded bg-elevated/80 p-1.5 border border-border/50">
                  <div className="text-[9px] text-muted uppercase">Initiator</div>
                  <div className="font-bold text-primary truncate" title={sess.source}>
                    {sess.source}
                  </div>
                </div>

                <div className="flex flex-col items-center shrink-0 px-1 text-muted">
                  <span className="font-mono text-[9px] font-bold text-info">{sess.protocol}</span>
                  <ArrowRight className="h-3.5 w-3.5 text-info animate-pulse" />
                </div>

                <div className="min-w-0 flex-1 rounded bg-elevated/80 p-1.5 border border-border/50">
                  <div className="text-[9px] text-muted uppercase">Responder</div>
                  <div className="font-bold text-primary truncate" title={sess.destination}>
                    {sess.destination}
                  </div>
                </div>
              </div>

              {/* Metadata Badges */}
              <div className="mt-2.5 flex items-center justify-between text-[10px] text-muted font-mono">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {sess.durationSeconds}s duration
                </span>
                {sess.ikeVersion && (
                  <span className="rounded bg-elevated px-1 py-0.5 border border-border">
                    IKE v{sess.ikeVersion}
                  </span>
                )}
              </div>

              {/* Cross-Module Quick Actions */}
              <div
                className="mt-2.5 flex items-center justify-end gap-1.5 border-t border-border/50 pt-2"
                onClick={(e) => e.stopPropagation()}
              >
                <Link
                  to={`/packet-analysis?source=${encodeURIComponent(sess.source)}`}
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-muted hover:text-info hover:bg-elevated"
                  title="Inspect packets for this session"
                >
                  Packets
                  <ExternalLink className="h-2.5 w-2.5" />
                </Link>
                <Link
                  to={`/risk-assessment`}
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium text-muted hover:text-info hover:bg-elevated"
                  title="Evaluate risk posture"
                >
                  Risk Engine
                  <ExternalLink className="h-2.5 w-2.5" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
