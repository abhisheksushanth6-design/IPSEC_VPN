import { ArrowDown, ArrowUpRight, Cable, Clock, KeyRound, Lock } from 'lucide-react';
import { Link } from 'react-router-dom';

import { ChartCard, EmptyChartState, TrafficTimelineChart } from '@/components/dashboard';
import { formatBytes, formatDuration, formatSessionTime } from '@/components/ipsec-sessions';
import { DetailSection } from '@/components/live-monitor';
import { EmptyState } from '@/components/states';
import { ProtocolBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import { SAStateBadge } from './SAStateBadge';
import type { SAState, SecurityAssociation, TrafficPoint } from '@/types';

const LIFECYCLE_PATH: SAState[] = ['DETECTED', 'NEGOTIATING', 'ESTABLISHED', 'ACTIVE', 'REKEYING', 'TERMINATED'];

/* ----- State card + lifecycle graph ----- */

export function SAStateCard({ sa }: { sa: SecurityAssociation }) {
  return (
    <div className="rounded border border-border bg-background/60 p-4">
      <p className="text-2xs text-muted">Current state</p>
      <div className="mt-1.5 flex flex-wrap items-center gap-3"><SAStateBadge state={sa.state} size="md" /><span className="font-mono text-2xs text-muted">{sa.type} SA · {sa.protocol}</span></div>
      {sa.capture_ended_in_state ? <p className="mt-2 text-2xs text-muted">Capture ended in this state; no termination or expiry was observed.</p> : null}
      {sa.failure ? <p className="mt-2 text-2xs text-secondary">Negotiation failure evidence: {sa.failure.exchange} msg {sa.failure.message_id} — {sa.failure.notification} (packet #{sa.failure.packet_number}).</p> : null}
    </div>
  );
}

export function SALifecycleGraph({ sa }: { sa: SecurityAssociation }) {
  const visited = new Set(sa.state_history.map((h) => h.state));
  const unknown = sa.state === 'UNKNOWN' || sa.state === 'FAILED' || sa.state === 'EXPIRED';
  return (
    <figure aria-label="SA lifecycle path" className="rounded border border-border bg-background/60 p-3">
      {unknown ? <p className="text-xs text-muted">{sa.state === 'UNKNOWN' ? 'Unknown state — the lifecycle path cannot be drawn from the available evidence.' : `Path ended in ${sa.state}.`}</p> : null}
      <ol className="flex flex-wrap items-center gap-1">
        {LIFECYCLE_PATH.map((step, i) => {
          const current = step === sa.state; const seen = visited.has(step);
          return (
            <li key={step} className="flex items-center gap-1">
              <span aria-current={current ? 'step' : undefined} className={cn('rounded border px-1.5 py-0.5 font-mono text-2xs', current ? 'border-info bg-info/15 text-info' : seen ? 'border-border bg-elevated text-secondary' : 'border-border/50 text-muted/60')}>{step}</span>
              {i < LIFECYCLE_PATH.length - 1 ? <ArrowDown aria-hidden className="h-3 w-3 -rotate-90 text-border" /> : null}
            </li>
          );
        })}
      </ol>
      {sa.rekey_count > 1 ? <p className="mt-2 text-2xs text-muted">{sa.rekey_count} rekeys observed (REKEYING → ACTIVE repeated).</p> : null}
    </figure>
  );
}

/* ----- Overview / identifiers ----- */

export function SAOverview({ sa }: { sa: SecurityAssociation }) {
  return (
    <>
      <DetailSection title="SA overview" entries={[
        ['SA ID', sa.id], ['Type', sa.type], ['State', <SAStateBadge key="s" state={sa.state} />], ['Start time', formatSessionTime(sa.start_time)],
        ['Last seen', formatSessionTime(sa.last_seen)], ['Initiator', sa.initiator], ['Responder', sa.responder], ['Duration', formatDuration(sa.duration_seconds)],
        ['Packet count', String(sa.packet_count)], ['Byte count', `${formatBytes(sa.byte_count)} (original lengths)`], ['Rekeys observed', String(sa.rekey_count)],
      ]} />
      <section className="border-t border-border py-3">
        <h3 className="text-2xs font-medium text-muted">Observed security state</h3>
        <ul className="mt-2 space-y-1 text-xs text-secondary">{sa.observations.map((o) => <li key={o} className="flex gap-2"><span aria-hidden className="text-border">—</span>{o}</li>)}</ul>
        <p className="mt-2 text-2xs text-muted">These are observations of protocol state, not a security assessment.</p>
      </section>
    </>
  );
}

export function SAIdentifiers({ sa }: { sa: SecurityAssociation }) {
  return (
    <DetailSection title="Identifiers" entries={[
      ['IKE version', sa.ike_version ?? '—'], ['Initiator SPI', sa.initiator_spi ?? '—'], ['Responder SPI', sa.responder_spi ?? '— (none seen)'],
      ['Data-plane SPI', sa.spi ?? '—'], ['NAT-T', sa.nat_traversal ? 'Observed' : 'Not observed'], ['Association', sa.association],
    ]} />
  );
}

/* ----- State history & timeline ----- */

export function SAStateHistory({ sa }: { sa: SecurityAssociation }) {
  if (sa.state_history.length === 0) return <EmptyState icon={Clock} title="No state history" />;
  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">State history</h3>
      <ol aria-label="State history" className="mt-2 space-y-1">
        {sa.state_history.map((h, i) => <li key={i} className="flex items-center gap-3 text-xs"><span className="w-28 shrink-0 font-mono tabular-nums text-muted">{h.timestamp ? formatSessionTime(h.timestamp).slice(11, 23) : 'no timestamp'}</span><SAStateBadge state={h.state} /></li>)}
      </ol>
    </section>
  );
}

export function SALifecycleTimeline({ sa }: { sa: SecurityAssociation }) {
  if (sa.timeline.length === 0) return <EmptyState icon={Clock} title="No lifecycle events" />;
  return (
    <ol aria-label="SA lifecycle timeline" className="relative ml-2 border-l border-border pl-4">
      {sa.timeline.map((e, i) => {
        const transition = e.previous_state !== e.new_state;
        return (
          <li key={i} className="relative pb-3 last:pb-0">
            <span aria-hidden className={cn('absolute -left-[1.3rem] top-1 h-2 w-2 rounded-full border bg-surface', transition ? 'border-info' : 'border-border')} />
            <p className="flex flex-wrap items-center gap-2 text-xs font-medium text-primary">{e.event_type}{transition && e.new_state ? <span className="font-mono text-2xs text-muted">{e.previous_state ?? '—'} → {e.new_state}</span> : null}</p>
            <p className="font-mono text-2xs text-muted">{e.timestamp ? formatSessionTime(e.timestamp) : 'no timestamp'}{e.packet_number !== null ? ` · packet #${e.packet_number}` : ''}{e.message_id !== null ? ` · msg ${e.message_id}` : ''}</p>
            <p className="text-2xs text-secondary">{e.description}</p>
          </li>
        );
      })}
    </ol>
  );
}

/* ----- IKE / child / parameters ----- */

export function IKEInformation({ sa }: { sa: SecurityAssociation }) {
  if (sa.type !== 'IKE') return <section className="border-t border-border py-3"><h3 className="text-2xs font-medium text-muted">IKE information</h3><p className="mt-2 text-xs text-muted">No IKE data. This is a {sa.protocol} child SA{sa.parent ? '; see its parent IKE SA' : ''}.</p></section>;
  return (
    <>
      <DetailSection title="IKE information" entries={[
        ['IKE version', sa.ike_version ?? '—'], ['Exchange types', sa.exchange_types.join(', ') || '—'], ['Message IDs', sa.message_ids.join(', ') || '—'],
        ['Initiator SPI', sa.initiator_spi ?? '—'], ['Responder SPI', sa.responder_spi ?? '— (none seen)'], ['Flags seen', sa.flags_seen.join(', ') || '—'],
      ]} />
      <section className="border-t border-border py-3">
        <h3 className="text-2xs font-medium text-muted">IKE payloads observed</h3>
        {sa.payload_types.length === 0 ? <p className="mt-2 text-xs text-muted">No payload types decoded.</p> : <ul className="mt-2 flex flex-wrap gap-1.5">{sa.payload_types.map((p) => <li key={p} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-1.5 py-px font-mono text-2xs text-secondary">{p.includes('Encrypted') ? <Lock aria-hidden className="h-3 w-3 text-info" /> : null}{p}</li>)}</ul>}
      </section>
    </>
  );
}

export function SecurityParameters({ sa }: { sa: SecurityAssociation }) {
  return (
    <DetailSection title="Security parameters" entries={[
      ['Encryption algorithm', sa.security_parameters_available ? '—' : 'NOT AVAILABLE'], ['Integrity algorithm', 'NOT AVAILABLE'], ['PRF', 'NOT AVAILABLE'],
      ['DH group', 'NOT AVAILABLE'], ['Authentication method', 'NOT AVAILABLE'], ['Traffic selectors', sa.traffic_selectors_available ? '—' : 'NOT AVAILABLE'],
    ]} />
  );
}

export function ChildSAInformation({ sa, onSelect }: { sa: SecurityAssociation; onSelect: (id: string) => void }) {
  if (sa.type === 'CHILD') {
    return (
      <section className="border-t border-border py-3">
        <h3 className="text-2xs font-medium text-muted">Parent IKE SA</h3>
        {sa.parent ? (
          <button type="button" onClick={() => onSelect(sa.parent!.id)} className="mt-2 flex w-full items-center justify-between gap-2 rounded border border-border bg-background/60 px-2 py-1.5 text-left text-xs hover:border-info">
            <span className="inline-flex items-center gap-2"><KeyRound aria-hidden className="h-3.5 w-3.5 text-info" /><span className="font-mono text-primary">{sa.parent.id}</span><SAStateBadge state={sa.parent.state} /></span><span className="font-mono text-2xs text-muted">{sa.association}</span>
          </button>
        ) : <p className="mt-2 text-xs text-muted">Association unknown — no IKE SA was observed between these endpoints in the capture.</p>}
      </section>
    );
  }
  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">Child SAs ({sa.child_sas.length})</h3>
      {sa.child_sas.length === 0 ? <p className="mt-2 text-xs text-muted">No child SAs. No ESP or AH traffic was observed under this IKE SA.</p> : (
        <ul className="mt-2 space-y-1.5">
          {sa.child_sas.map((c) => (
            <li key={c.id}>
              <button type="button" onClick={() => onSelect(c.id)} className="flex w-full items-center justify-between gap-2 rounded border border-border bg-background/60 px-2 py-1.5 text-left text-xs hover:border-info">
                <span className="inline-flex items-center gap-2"><ProtocolBadge protocol={c.protocol as 'ESP' | 'AH'} /><span className="font-mono text-primary">{c.spi}</span><SAStateBadge state={c.state} /></span>
                <span className="font-mono text-2xs text-muted">{c.initiator} → {c.responder} · {c.packet_count} pkt</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-2xs text-muted">Child SAs are correlated to this IKE SA by endpoint pair; the binding SPI is negotiated inside payloads not decoded.</p>
    </section>
  );
}

/* ----- Traffic / packets / activity / session ----- */

export function SAActivity({ sa }: { sa: SecurityAssociation }) {
  const points: TrafficPoint[] = [];
  if (sa.packets.length > 0 && sa.start_time && sa.last_seen) {
    const s = Date.parse(sa.start_time); const e = Math.max(Date.parse(sa.last_seen), s + 1);
    const buckets = 24; const width = (e - s) / buckets; const counts = new Array<number>(buckets).fill(0);
    for (const p of sa.packets) { const t = Date.parse(p.timestamp); if (!Number.isNaN(t)) counts[Math.min(Math.floor((t - s) / width), buckets - 1)]! += 1; }
    counts.forEach((c, i) => points.push({ timestamp: new Date(s + i * width).toISOString(), packets: c }));
  }
  return (
    <ChartCard title="SA activity" description="Packets per interval across the SA's lifetime.">
      {points.length === 0 ? <EmptyChartState message="NO ACTIVITY DATA" detail="No timestamped packets are available for this SA." height={140} /> : <TrafficTimelineChart data={points} />}
    </ChartCard>
  );
}

export function SAPacketList({ sa, onSelectPacket }: { sa: SecurityAssociation; onSelectPacket: (id: string) => void }) {
  if (!sa.packets_available) return <EmptyState icon={KeyRound} title="Packet data unavailable" description="The capture these SAs came from is no longer loaded." />;
  if (sa.packets.length === 0) return <EmptyState icon={KeyRound} title="No associated packets" />;
  return (
    <div>
      <div className="scrollbar-slim max-h-72 overflow-auto rounded border border-border">
        <table className="w-full min-w-[52rem] border-collapse text-left">
          <caption className="sr-only">Packets associated with {sa.id}</caption>
          <thead className="sticky top-0 z-10 bg-elevated"><tr>{['Time', 'Protocol', 'Source', 'Destination', 'SPI', 'Info'].map((h) => <th key={h} scope="col" className="whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted">{h}</th>)}</tr></thead>
          <tbody>
            {sa.packets.map((p) => (
              <tr key={p.id} tabIndex={0} onClick={() => onSelectPacket(p.id)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelectPacket(p.id); } }} className="cursor-pointer border-b border-border text-xs last:border-b-0 hover:bg-elevated/60">
                <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted">{p.timestamp ? formatSessionTime(p.timestamp).slice(11, 23) : '—'}</td>
                <td className="px-3 py-1.5"><ProtocolBadge protocol={p.protocol === 'IP' || p.protocol === 'OTHER' ? 'IP' : p.protocol} /></td>
                <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{p.source}</td>
                <td className="whitespace-nowrap px-3 py-1.5 font-mono text-secondary">{p.destination}</td>
                <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted">{p.spi ?? '—'}</td>
                <td className="max-w-md truncate px-3 py-1.5 text-secondary" title={p.info}>{p.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-1.5 text-2xs text-muted">{sa.packets_total > sa.packets.length ? `Showing first ${sa.packets.length} of ${sa.packets_total}. ` : `${sa.packets_total} packets. `}Select a packet to open it in Packet Analysis.</p>
    </div>
  );
}

export function SASessionLink({ sa }: { sa: SecurityAssociation }) {
  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">IPsec session</h3>
      {sa.session_id ? (
        <Link to={`/ipsec-sessions?session=${encodeURIComponent(sa.session_id)}`} className="mt-2 inline-flex items-center gap-2 rounded border border-border px-2.5 py-1.5 text-xs text-primary transition-colors hover:border-info hover:text-info"><Cable aria-hidden className="h-3.5 w-3.5" />View session <span className="font-mono">{sa.session_id}</span><ArrowUpRight aria-hidden className="h-3 w-3" /></Link>
      ) : <p className="mt-2 text-xs text-muted">No session associated. Discover sessions in IPsec Sessions, then re-run SA analysis to link them.</p>}
    </section>
  );
}
