import { PackageSearch } from 'lucide-react';

import { ProtocolBadge } from '@/components/status';
import { DetailPanel, DetailSection } from './DetailPanel';
import type { Packet } from '@/types';

interface PacketDetailsProps {
  packet: Packet | null;
  onClose: () => void;
}

const toEntries = (record?: Record<string, string>): Array<[string, string]> =>
  record ? Object.entries(record) : [];

export function PacketDetails({ packet, onClose }: PacketDetailsProps) {
  return (
    <DetailPanel
      title="Packet details"
      icon={PackageSearch}
      emptyTitle="No packet selected"
      emptyDescription="Select a row in the packet stream to inspect its headers and IPsec fields."
      onClose={onClose}
      subject={
        packet ? (
          <>
            <DetailSection
              title="Packet summary"
              entries={[
                ['Timestamp', packet.timestamp],
                ['Source', packet.source],
                ['Destination', packet.destination],
                ['Protocol', <ProtocolBadge key="p" protocol={packet.protocol} />],
                ['Length', `${packet.length} bytes`],
                ['Status', packet.status],
              ]}
            />
            <DetailSection title="Network headers" entries={toEntries(packet.network)} />
            <DetailSection title="Transport information" entries={toEntries(packet.transport)} />
            <DetailSection title="IPsec information (IKE / ESP / AH)" entries={toEntries(packet.ipsec)} />
            <DetailSection title="Parsed information" entries={toEntries(packet.parsed)} />
            {packet.raw ? (
              <section className="border-t border-border py-3">
                <h3 className="text-2xs font-medium text-muted">Raw</h3>
                <pre className="scrollbar-slim mt-2 max-h-40 overflow-auto rounded bg-background p-2 font-mono text-2xs text-secondary">{packet.raw}</pre>
              </section>
            ) : null}
          </>
        ) : null
      }
    />
  );
}
