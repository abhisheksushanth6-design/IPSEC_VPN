import { ArrowLeftRight, ArrowRight, ArrowLeft, CircleHelp } from 'lucide-react';

import { ProtocolBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import { SessionStateBadge } from './SessionStateBadge';
import { formatDuration, formatSessionTime } from './sessionFormat';
import type { IPsecSessionSummary, SessionDirection } from '@/types';

interface SessionRowProps {
  session: IPsecSessionSummary;
  selected: boolean;
  onSelect: (id: string) => void;
}

const DIRECTION_ICON: Record<SessionDirection, typeof ArrowRight> = {
  OUTBOUND: ArrowRight, INBOUND: ArrowLeft, BIDIRECTIONAL: ArrowLeftRight, UNKNOWN: CircleHelp,
};

export function SessionRow({ session, selected, onSelect }: SessionRowProps) {
  const Direction = DIRECTION_ICON[session.direction];
  const protocols = (['IKE', 'ESP', 'AH'] as const).filter((p) => session[`${p.toLowerCase()}_packets` as 'ike_packets' | 'esp_packets' | 'ah_packets'] > 0);
  return (
    <tr
      tabIndex={0}
      aria-selected={selected}
      onClick={() => onSelect(session.id)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(session.id); } }}
      className={cn('cursor-pointer border-b border-border text-xs transition-colors last:border-b-0', selected ? 'bg-elevated' : 'hover:bg-elevated/60')}
    >
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-primary">{session.id}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono tabular-nums text-muted">{formatSessionTime(session.start_time)}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono tabular-nums text-muted">{formatSessionTime(session.end_time)}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{session.source}</td>
      <td className="whitespace-nowrap px-3 py-1.5">
        <span className="inline-flex items-center gap-1.5 font-mono text-secondary">
          <Direction aria-label={session.direction} className="h-3 w-3 text-muted" />
          {session.destination}
        </span>
      </td>
      <td className="whitespace-nowrap px-3 py-1.5">
        <span className="inline-flex items-center gap-1">
          {protocols.map((p) => <ProtocolBadge key={p} protocol={p} />)}
          {session.nat_traversal ? <span className="rounded border border-info/35 px-1 font-mono text-2xs text-info">NAT-T</span> : null}
        </span>
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono tabular-nums text-secondary">{session.packet_count}</td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono tabular-nums text-muted">{formatDuration(session.duration_seconds)}</td>
      <td className="whitespace-nowrap px-3 py-1.5"><SessionStateBadge state={session.state} /></td>
    </tr>
  );
}
