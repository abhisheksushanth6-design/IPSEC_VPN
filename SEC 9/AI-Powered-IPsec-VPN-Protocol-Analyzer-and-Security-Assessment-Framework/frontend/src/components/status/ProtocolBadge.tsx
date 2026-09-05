import { cn } from '@/utils/cn';
import type { PacketProtocol } from '@/types';

/** IPsec protocols are emphasised; carriers stay neutral. */
const IPSEC: readonly PacketProtocol[] = ['IKE', 'ESP', 'AH'];

export function ProtocolBadge({ protocol, className }: { protocol: PacketProtocol; className?: string }) {
  const emphasised = IPSEC.includes(protocol);
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-px font-mono text-2xs font-medium',
        emphasised ? 'border-info/35 bg-info/10 text-info' : 'border-border bg-elevated text-secondary',
        className,
      )}
    >
      {protocol}
    </span>
  );
}
