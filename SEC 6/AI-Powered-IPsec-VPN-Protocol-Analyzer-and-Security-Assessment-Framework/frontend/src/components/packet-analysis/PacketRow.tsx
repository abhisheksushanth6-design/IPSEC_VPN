import { AlertTriangle } from 'lucide-react';

import { ProtocolBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import type { AnalyzedPacketSummary } from '@/types';

interface PacketRowProps {
  packet: AnalyzedPacketSummary;
  selected: boolean;
  onSelect: (id: string) => void;
}

export function formatPacketTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const ms = String(d.getUTCMilliseconds()).padStart(3, '0');
  return `${d.toISOString().slice(11, 19)}.${ms}`;
}

/** One analysed packet. Everything shown was decoded from the frame bytes. */
export function PacketRow({ packet, selected, onSelect }: PacketRowProps) {
  const malformed = packet.parse_status !== 'OK';
  return (
    <tr
      tabIndex={0}
      aria-selected={selected}
      data-packet-number={packet.number}
      onClick={() => onSelect(packet.id)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(packet.id); } }}
      className={cn('cursor-pointer border-b border-border text-xs transition-colors last:border-b-0', selected ? 'bg-elevated' : 'hover:bg-elevated/60')}
    >
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono tabular-nums text-muted">{packet.number}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono tabular-nums text-muted">{formatPacketTime(packet.timestamp)}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{packet.source}</td>
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{packet.destination}</td>
      <td className="whitespace-nowrap px-3 py-1.5">
        <span className="inline-flex items-center gap-1.5">
          <ProtocolBadge protocol={packet.protocol === 'IP' || packet.protocol === 'OTHER' ? 'IP' : packet.protocol} />
          {packet.nat_traversal ? <span className="rounded border border-info/35 px-1 font-mono text-2xs text-info">NAT-T</span> : null}
        </span>
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono tabular-nums text-secondary">{packet.length}</td>
      <td className="max-w-md truncate px-3 py-1.5 text-secondary" title={packet.info}>
        {malformed ? <AlertTriangle aria-label="Malformed packet" className="mr-1 inline h-3 w-3 text-warning" /> : null}
        {packet.info}
      </td>
    </tr>
  );
}
