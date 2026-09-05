import { ProtocolBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import type { PacketSummary } from '@/types';

interface PacketRowProps {
  packet: PacketSummary;
  selected: boolean;
  onSelect: (packet: PacketSummary) => void;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}

const STATUS_CLASS: Record<PacketSummary['status'], string> = {
  OK: 'text-muted',
  MALFORMED: 'text-warning',
  FLAGGED: 'text-danger',
};

/** One packet. Renders only the data it is handed. */
export function PacketRow({ packet, selected, onSelect }: PacketRowProps) {
  return (
    <tr
      tabIndex={0}
      aria-selected={selected}
      onClick={() => onSelect(packet)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(packet);
        }
      }}
      className={cn(
        'cursor-pointer border-b border-border text-xs transition-colors last:border-b-0',
        selected ? 'bg-elevated' : 'hover:bg-elevated/60',
      )}
    >
      <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-muted">
        <time dateTime={packet.timestamp}>{formatTime(packet.timestamp)}</time>
      </td>
      <td className="whitespace-nowrap px-3 py-2 font-mono text-secondary">{packet.source}</td>
      <td className="whitespace-nowrap px-3 py-2 font-mono text-secondary">{packet.destination}</td>
      <td className="px-3 py-2"><ProtocolBadge protocol={packet.protocol} /></td>
      <td className="whitespace-nowrap px-3 py-2 text-right font-mono tabular-nums text-secondary">{packet.length}</td>
      <td className="max-w-xs truncate px-3 py-2 text-secondary">{packet.info}</td>
      <td className={cn('whitespace-nowrap px-3 py-2 font-mono', STATUS_CLASS[packet.status])}>{packet.status}</td>
    </tr>
  );
}
