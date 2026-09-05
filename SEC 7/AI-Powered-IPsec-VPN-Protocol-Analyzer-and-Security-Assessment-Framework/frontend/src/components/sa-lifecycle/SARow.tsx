import { ProtocolBadge } from '@/components/status';
import { formatSessionTime } from '@/components/ipsec-sessions';
import { cn } from '@/utils/cn';
import { SAStateBadge } from './SAStateBadge';
import type { SecurityAssociationSummary } from '@/types';

export function SARow({ sa, selected, onSelect }: { sa: SecurityAssociationSummary; selected: boolean; onSelect: (id: string) => void }) {
  return (
    <tr tabIndex={0} aria-selected={selected} onClick={() => onSelect(sa.id)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(sa.id); } }}
      className={cn('cursor-pointer border-b border-border text-xs transition-colors last:border-b-0', selected ? 'bg-elevated' : 'hover:bg-elevated/60')}>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-primary">{sa.id}</td>
      <td className="whitespace-nowrap px-3 py-1.5"><span className={cn('rounded border px-1.5 py-px text-2xs font-medium', sa.type === 'IKE' ? 'border-info/35 bg-info/10 text-info' : sa.type === 'CHILD' ? 'border-success/35 bg-success/10 text-success' : 'border-border text-muted')}>{sa.type}</span></td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono tabular-nums text-muted">{formatSessionTime(sa.start_time)}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono tabular-nums text-muted">{formatSessionTime(sa.last_seen)}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{sa.initiator}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{sa.responder}</td>
      <td className="whitespace-nowrap px-3 py-1.5"><span className="inline-flex items-center gap-1.5"><ProtocolBadge protocol={sa.protocol as 'IKE' | 'ESP' | 'AH'} />{sa.nat_traversal ? <span className="rounded border border-info/35 px-1 font-mono text-2xs text-info">NAT-T</span> : null}</span></td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted">{sa.spi ?? sa.initiator_spi ?? '—'}</td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono tabular-nums text-secondary">{sa.packet_count}</td>
      <td className="whitespace-nowrap px-3 py-1.5"><SAStateBadge state={sa.state} /></td>
    </tr>
  );
}
