import { ArrowDown, Clock, KeyRound, Lock, Server, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

import { ChartCard, EmptyChartState, TrafficTimelineChart } from '@/components/dashboard';
import { DetailSection } from '@/components/live-monitor';
import { PacketRow } from '@/components/packet-analysis';
import { EmptyState } from '@/components/states';
import { ProtocolBadge } from '@/components/status';
import { SessionStateBadge } from './SessionStateBadge';
import { formatBytes, formatDuration, formatSessionTime } from './sessionFormat';
import type { IPsecSession, SessionDataPlaneInfo } from '@/types';

/* ----- Overview ----- */

export function SessionOverview({ session }: { session: IPsecSession }) {
  return (
    <>
      <DetailSection title="Session overview" entries={[
        ['Session ID', session.id], ['Start time', formatSessionTime(session.start_time)], ['End time', formatSessionTime(session.end_time)],
        ['Duration', formatDuration(session.duration_seconds)], ['Source', session.source], ['Destination', session.destination],
        ['Direction', session.direction], ['Current state', <SessionStateBadge key="s" state={session.state} />],
        ['Correlation', session.correlation], ['Packet count', String(session.packet_count)], ['Byte count', `${formatBytes(session.byte_count)} (${session.byte_count} B, original lengths)`],
      ]} />
      <section className="border-t border-border py-3">
        <h3 className="text-2xs font-medium text-muted">State evidence</h3>
        <ul className="mt-2 space-y-1 text-xs text-secondary">{session.evidence.map((e) => <li key={e} className="flex gap-2"><span aria-hidden className="text-border">—</span>{e}</li>)}</ul>
      </section>
    </>
  );
}

/* ----- Endpoint graph ----- */

export function SessionGraph({ session }: { session: IPsecSession }) {
  return (
    <figure aria-label={`Session between ${session.source} and ${session.destination}`} className="flex flex-col items-center gap-1 rounded border border-border bg-background/60 px-4 py-4">
      <span className="inline-flex items-center gap-2 font-mono text-xs text-primary"><Server aria-hidden className="h-3.5 w-3.5 text-muted" />{session.source}</span>
      <ArrowDown aria-hidden className="h-4 w-4 text-border" />
      <span className="inline-flex items-center gap-2 rounded border border-info/35 bg-info/10 px-2 py-1 text-2xs font-medium text-info"><Lock aria-hidden className="h-3 w-3" />IPsec session · {session.direction}</span>
      <ArrowDown aria-hidden className="h-4 w-4 text-border" />
      <span className="inline-flex items-center gap-2 font-mono text-xs text-primary"><Server aria-hidden className="h-3.5 w-3.5 text-muted" />{session.destination}</span>
    </figure>
  );
}

/* ----- Timeline ----- */

export function SessionTimeline({ session }: { session: IPsecSession }) {
  if (session.timeline.length === 0) return <EmptyState icon={Clock} title="No timeline data" />;
  return (
    <ol aria-label="Session timeline" className="relative ml-2 border-l border-border pl-4">
      {session.timeline.map((e, i) => (
        <li key={`${e.label}-${i}`} className="relative pb-3 last:pb-0">
          <span aria-hidden className="absolute -left-[1.3rem] top-1 h-2 w-2 rounded-full border border-info bg-surface" />
          <p className="text-xs font-medium text-primary">{e.label}</p>
          <p className="font-mono text-2xs text-muted">{e.timestamp ? formatSessionTime(e.timestamp) : 'no timestamp'} · packet #{e.packet_number}</p>
          <p className="truncate text-2xs text-secondary" title={e.detail}>{e.detail}</p>
        </li>
      ))}
    </ol>
  );
}

/* ----- Protocol summary ----- */

export function SessionProtocolSummary({ session }: { session: IPsecSession }) {
  return (
    <DetailSection title="IPsec protocol summary" entries={[
      ['IKE packets', String(session.ike_packets)], ['ESP packets', String(session.esp_packets)], ['AH packets', String(session.ah_packets)],
      ['NAT traversal', session.nat_traversal ? 'UDP/4500 observed' : 'Not observed'],
    ]} />
  );
}

/* ----- IKE / ESP / AH ----- */

export function IKEInformation({ session }: { session: IPsecSession }) {
  const ike = session.ike;
  if (!ike) return <section className="border-t border-border py-3"><h3 className="text-2xs font-medium text-muted">IKE information</h3><p className="mt-2 text-xs text-muted">No IKE information. No IKE packets belong to this session.</p></section>;
  return (
    <DetailSection title={`IKE information (${ike.packet_count} packets)`} entries={[
      ['IKE version', ike.version ?? '—'], ['Initiator SPIs', ike.initiator_spis.join(', ')], ['Responder SPIs', ike.responder_spis.join(', ') || '— (none seen)'],
      ['Exchange types', ike.exchange_types.join(', ')], ['Message IDs', ike.message_ids.join(', ')], ['Payload types', ike.payload_types.join(', ') || '—'],
      ['NAT-T', ike.nat_traversal ? 'Yes' : 'No'],
    ]} />
  );
}

function DataPlane({ title, kind, info }: { title: string; kind: 'ESP' | 'AH'; info: SessionDataPlaneInfo | null }) {
  if (!info) return <section className="border-t border-border py-3"><h3 className="text-2xs font-medium text-muted">{title}</h3><p className="mt-2 text-xs text-muted">No {kind} information. No {kind} packets belong to this session.</p></section>;
  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">{title} ({info.packet_count} packets)</h3>
      <ul className="mt-2 space-y-1.5">
        {info.spis.map((s) => (
          <li key={s.spi} className="rounded border border-border bg-background/60 px-2 py-1.5 text-xs">
            <div className="flex items-center justify-between gap-2"><span className="inline-flex items-center gap-2"><ProtocolBadge protocol={kind} /><span className="font-mono text-primary">{s.spi}</span>{s.nat_traversal ? <span className="rounded border border-info/35 px-1 font-mono text-2xs text-info">NAT-T</span> : null}</span><span className="font-mono text-muted">{s.packet_count} pkt</span></div>
            <p className="mt-0.5 font-mono text-2xs text-muted">{s.direction} · seq {s.sequence_min}–{s.sequence_max}</p>
          </li>
        ))}
      </ul>
      {kind === 'ESP' ? <p className="mt-2 flex items-center gap-1 text-2xs text-muted"><Lock aria-hidden className="h-3 w-3" />Payloads are encrypted; only headers are observed.</p> : <p className="mt-2 flex items-center gap-1 text-2xs text-muted"><ShieldCheck aria-hidden className="h-3 w-3" />Authenticated headers observed.</p>}
    </section>
  );
}

export const ESPInformation = ({ session }: { session: IPsecSession }) => <DataPlane title="ESP information" kind="ESP" info={session.esp} />;
export const AHInformation = ({ session }: { session: IPsecSession }) => <DataPlane title="AH information" kind="AH" info={session.ah} />;

/* ----- Activity ----- */

export function SessionActivity({ session }: { session: IPsecSession }) {
  return (
    <ChartCard title="Packet activity" description="Packets per interval across the session.">
      {session.activity.length === 0 ? <EmptyChartState message="NO ACTIVITY DATA" detail="Packets in this session carry no timestamps." height={140} /> : <TrafficTimelineChart data={session.activity} />}
    </ChartCard>
  );
}

/* ----- Packets ----- */

export function SessionPacketList({ session, onSelectPacket }: { session: IPsecSession; onSelectPacket: (id: string) => void }) {
  if (!session.packets_available) return <EmptyState icon={KeyRound} title="Packet data unavailable" description="The capture these sessions were derived from is no longer loaded. Reload it in Packet Analysis to inspect packets." />;
  if (session.packets.length === 0) return <EmptyState icon={KeyRound} title="No session packets" />;
  return (
    <div>
      <div className="scrollbar-slim max-h-72 overflow-auto rounded border border-border">
        <table className="w-full min-w-[56rem] border-collapse text-left">
          <caption className="sr-only">Packets in session {session.id}</caption>
          <thead className="sticky top-0 z-10 bg-elevated"><tr>{['#', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].map((h) => <th key={h} scope="col" className={`whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted ${h === '#' || h === 'Length' ? 'text-right' : ''}`}>{h}</th>)}</tr></thead>
          <tbody>{session.packets.map((p) => <PacketRow key={p.id} packet={p} selected={false} onSelect={onSelectPacket} />)}</tbody>
        </table>
      </div>
      <p className="mt-1.5 text-2xs text-muted">
        {session.packets_total > session.packets.length ? `Showing first ${session.packets.length} of ${session.packets_total} packets. ` : `${session.packets_total} packets. `}
        Select a packet to open it in <Link to="/packet-analysis" className="text-info hover:underline">Packet Analysis</Link>.
      </p>
    </div>
  );
}
