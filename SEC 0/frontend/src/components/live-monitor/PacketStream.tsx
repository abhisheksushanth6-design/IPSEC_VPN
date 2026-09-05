import { Network } from 'lucide-react';

import { EmptyState } from '@/components/states';
import { StatusBadge } from '@/components/status';
import { PacketRow } from './PacketRow';
import type { PacketSummary } from '@/types';

interface PacketStreamProps {
  packets: PacketSummary[] | null;
  selectedId: string | null;
  onSelect: (packet: PacketSummary) => void;
}

const COLUMNS = ['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Status'];

/**
 * The main packet table. Horizontal scrolling is confined to the table's own
 * container so the page never widens.
 */
export function PacketStream({ packets, selectedId, onSelect }: PacketStreamProps) {
  return (
    <section
      aria-labelledby="packet-stream-title"
      className="flex flex-col rounded border border-border bg-surface"
    >
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 id="packet-stream-title" className="text-sm font-medium text-primary">Live Packet Stream</h2>
          <p className="mt-0.5 text-xs text-muted">Packets as observed by the capture engine.</p>
        </div>
        <StatusBadge status="NOT INITIALIZED" label="NO CAPTURE SOURCE" size="sm" />
      </div>

      {packets === null ? (
        <div className="p-4">
          <EmptyState
            icon={Network}
            title="No packets available"
            description="Packet capture has not been initialized. Rows appear here once Layer 02 publishes captured packets."
            status="NOT INITIALIZED"
          />
        </div>
      ) : packets.length === 0 ? (
        <div className="p-4">
          <EmptyState icon={Network} title="No packets observed" description="Capture is active but nothing has been seen yet." />
        </div>
      ) : (
        <div className="scrollbar-slim max-h-[28rem] overflow-auto">
          <table className="w-full min-w-[56rem] border-collapse text-left">
            <caption className="sr-only">Captured packets</caption>
            <thead className="sticky top-0 z-10 bg-elevated">
              <tr>
                {COLUMNS.map((column) => (
                  <th
                    key={column}
                    scope="col"
                    className={`whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted ${column === 'Length' ? 'text-right' : ''}`}
                  >
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {packets.map((packet) => (
                <PacketRow key={packet.id} packet={packet} selected={packet.id === selectedId} onSelect={onSelect} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
