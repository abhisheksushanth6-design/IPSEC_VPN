import React, { useMemo, useState } from 'react';
import { Network, Search, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';
import { EmptyState } from '@/components/states';
import { StatusBadge, ProtocolBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import type { CaptureState, PacketSummary } from '@/types';

interface PacketStreamProps {
  packets: PacketSummary[] | null;
  selectedId: string | null;
  onSelect: (packet: PacketSummary) => void;
  captureState?: CaptureState;
}

const COLUMNS = ['Time', 'Source', 'Destination', 'Protocol', 'Length', 'SPI / Info', 'Status'];

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}

const STATUS_CLASS: Record<PacketSummary['status'], string> = {
  OK: 'text-muted',
  MALFORMED: 'text-warning font-bold',
  FLAGGED: 'text-danger font-bold',
};

/**
 * Enhanced Live Packet Inspector & Stream.
 * Features inline filtering, search, SPI extraction, and expandable quick details.
 */
export function PacketStream({ packets, selectedId, onSelect, captureState }: PacketStreamProps) {
  const isCapturing = captureState === 'CAPTURING';

  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [expandedRowId, setExpandedRowId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredPackets = useMemo(() => {
    if (!packets) return null;
    return packets.filter((p) => {
      if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          p.source.toLowerCase().includes(q) ||
          p.destination.toLowerCase().includes(q) ||
          p.protocol.toLowerCase().includes(q) ||
          (p.info && p.info.toLowerCase().includes(q)) ||
          p.id.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [packets, protocolFilter, search]);

  const copyToClipboard = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  // Helper to extract SPI from summary or info
  const extractSPI = (p: PacketSummary) => {
    if (!p.info) return '—';
    const spiMatch = p.info.match(/SPI[:=]\s*(0x[0-9a-fA-F]+|\d+)/i);
    if (spiMatch) return spiMatch[1];
    if (p.info.includes('0x')) {
      const hexMatch = p.info.match(/0x[0-9a-fA-F]{4,8}/);
      if (hexMatch) return hexMatch[0];
    }
    return null;
  };

  return (
    <section
      aria-labelledby="packet-stream-title"
      className="flex flex-col rounded border border-border bg-surface shadow-sm"
    >
      <div className="flex flex-col gap-3 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 id="packet-stream-title" className="text-sm font-semibold text-primary">
              Live Packet Inspector
            </h2>
            {filteredPackets && (
              <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-2xs text-muted border border-border">
                {filteredPackets.length} frames
              </span>
            )}
          </div>
          <p className="mt-0.5 text-xs text-muted">Real-time wire frame telemetry observed by Layer 02 tap.</p>
        </div>

        <div className="flex items-center gap-2">
          <StatusBadge
            status={isCapturing ? 'LIVE' : 'READY'}
            label={isCapturing ? 'STREAMING' : 'CAPTURE READY'}
            size="sm"
          />
        </div>
      </div>

      {packets !== null && packets.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/70 bg-background/40 p-2.5 text-xs">
          <div className="relative min-w-[180px] flex-1">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted" />
            <input
              type="text"
              placeholder="Filter by IP, SPI, info…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded border border-border bg-surface py-1 pl-8 pr-3 text-2xs text-primary placeholder:text-muted focus:border-info focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1">
            {(['ALL', 'ESP', 'IKE', 'AH', 'OTHER'] as const).map((proto) => (
              <button
                key={proto}
                type="button"
                onClick={() => setProtocolFilter(proto)}
                className={cn(
                  'rounded px-2 py-0.5 font-mono text-[10px] font-medium transition-colors',
                  protocolFilter === proto
                    ? 'bg-info text-white font-bold'
                    : 'bg-elevated text-secondary hover:bg-elevated/80'
                )}
              >
                {proto}
              </button>
            ))}
          </div>
        </div>
      )}

      {packets === null ? (
        <div className="p-4">
          <EmptyState
            icon={Network}
            title="No packets available"
            description="No packet frames currently in buffer. Start a live capture above or inspect ingested packets in Packet Analysis."
            status="READY"
          />
        </div>
      ) : packets.length === 0 ? (
        <div className="p-4">
          <EmptyState
            icon={Network}
            title="No packets observed"
            description="Capture is active but nothing has been seen yet."
          />
        </div>
      ) : filteredPackets && filteredPackets.length === 0 ? (
        <div className="p-8 text-center text-xs text-muted">
          No packets match the current search or protocol filters.
        </div>
      ) : (
        <div className="scrollbar-slim max-h-[30rem] overflow-auto">
          <table className="w-full min-w-[56rem] border-collapse text-left">
            <caption className="sr-only">Captured packets</caption>
            <thead className="sticky top-0 z-10 bg-elevated text-2xs font-semibold text-muted uppercase tracking-wider">
              <tr>
                <th className="w-6 px-2 py-2" />
                {COLUMNS.map((column) => (
                  <th
                    key={column}
                    scope="col"
                    className={`whitespace-nowrap px-3 py-2 ${
                      column === 'Length' ? 'text-right' : ''
                    }`}
                  >
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredPackets?.map((packet) => {
                const isSelected = packet.id === selectedId;
                const isExpanded = expandedRowId === packet.id;
                const spi = extractSPI(packet);

                return (
                  <React.Fragment key={packet.id}>
                    <tr
                      tabIndex={0}
                      aria-selected={isSelected}
                      onClick={() => onSelect(packet)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onSelect(packet);
                        }
                      }}
                      className={cn(
                        'cursor-pointer border-b border-border text-xs transition-colors',
                        isSelected ? 'bg-info/10' : 'hover:bg-elevated/60'
                      )}
                    >
                      <td
                        className="px-2 py-2 text-center text-muted hover:text-primary"
                        onClick={(e) => {
                          e.stopPropagation();
                          setExpandedRowId((prev) => (prev === packet.id ? null : packet.id));
                        }}
                      >
                        {isExpanded ? (
                          <ChevronDown className="h-3.5 w-3.5 inline" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5 inline" />
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-muted">
                        <time dateTime={packet.timestamp}>{formatTime(packet.timestamp)}</time>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-primary font-medium">
                        {packet.source}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-primary font-medium">
                        {packet.destination}
                      </td>
                      <td className="px-3 py-2">
                        <ProtocolBadge protocol={packet.protocol} />
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-right font-mono tabular-nums text-secondary">
                        {packet.length} B
                      </td>
                      <td className="max-w-xs truncate px-3 py-2 font-mono text-2xs text-secondary">
                        {spi ? (
                          <span className="rounded bg-elevated px-1.5 py-0.5 text-info border border-border mr-1.5 font-bold">
                            SPI: {spi}
                          </span>
                        ) : null}
                        <span>{packet.info}</span>
                      </td>
                      <td
                        className={cn(
                          'whitespace-nowrap px-3 py-2 font-mono text-2xs',
                          STATUS_CLASS[packet.status]
                        )}
                      >
                        {packet.status}
                      </td>
                    </tr>

                    {/* Expandable Technical Drawer */}
                    {isExpanded && (
                      <tr className="border-b border-border bg-elevated/40 text-2xs font-mono text-secondary">
                        <td colSpan={8} className="p-3 pl-8">
                          <div className="flex flex-col gap-2 rounded border border-border/70 bg-background/80 p-2.5">
                            <div className="flex items-center justify-between border-b border-border/50 pb-1.5">
                              <span className="font-bold text-info uppercase">
                                Packet Frame #{packet.id} Technical Details
                              </span>
                              <button
                                type="button"
                                onClick={(e) =>
                                  copyToClipboard(JSON.stringify(packet, null, 2), packet.id, e)
                                }
                                className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-muted hover:text-primary hover:bg-elevated"
                              >
                                {copiedId === packet.id ? (
                                  <>
                                    <Check className="h-3 w-3 text-emerald-400" />
                                    <span>Copied</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="h-3 w-3" />
                                    <span>Copy JSON</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 pt-1">
                              <div>
                                <span className="text-muted">Protocol: </span>
                                <span className="text-primary font-bold">{packet.protocol}</span>
                              </div>
                              <div>
                                <span className="text-muted">Wire Length: </span>
                                <span className="text-primary font-bold">{packet.length} bytes</span>
                              </div>
                              <div>
                                <span className="text-muted">Parse Status: </span>
                                <span className="text-primary font-bold">{packet.status}</span>
                              </div>
                              <div>
                                <span className="text-muted">Timestamp: </span>
                                <span className="text-primary font-bold">{packet.timestamp}</span>
                              </div>
                            </div>
                            <div className="mt-1">
                              <span className="text-muted">Summary Info: </span>
                              <span className="text-primary">{packet.info}</span>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
