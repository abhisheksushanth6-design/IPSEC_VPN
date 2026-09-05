import { AlertTriangle, Lock, ShieldCheck } from 'lucide-react';

import { DetailSection } from '@/components/live-monitor';
import { EmptyState } from '@/components/states';
import { ProtocolBadge } from '@/components/status';
import type { IPsecAnalysis, IPLayer, PacketAnalysisResult, SecurityFlags, TransportLayer } from '@/types';
import { formatPacketTime } from './PacketRow';

/* ---------- Summary ---------- */

export function PacketSummary({ packet }: { packet: PacketAnalysisResult }) {
  return (
    <DetailSection
      title="Packet summary"
      entries={[
        ['Packet number', String(packet.number)],
        ['Timestamp', packet.timestamp ? `${formatPacketTime(packet.timestamp)} UTC` : 'Not recorded'],
        ['Captured length', `${packet.captured_length} bytes`],
        ['Original length', `${packet.original_length} bytes`],
        ['Source', packet.source],
        ['Destination', packet.destination],
        ['Protocol', <ProtocolBadge key="p" protocol={packet.protocol === 'IP' || packet.protocol === 'OTHER' ? 'IP' : packet.protocol} />],
        ['Layers', packet.layers.join(' › ') || '—'],
      ]}
    />
  );
}

/* ---------- Network ---------- */

export function NetworkDetails({ ip }: { ip: IPLayer | null }) {
  if (!ip) return <DetailSection title="Network layer" entries={[['IP header', 'Not decoded']]} />;
  const v4 = ip.version === 4;
  const entries: Array<[string, string]> = [
    ['IP version', String(ip.version)],
    ['Source IP', ip.source],
    ['Destination IP', ip.destination],
    [v4 ? 'TTL' : 'Hop limit', String(ip.ttl)],
    ['Protocol', `${ip.protocol_name} (${ip.protocol_number})`],
    ['Packet length', `${ip.total_length} bytes`],
  ];
  if (ip.header_length !== null) entries.push(['Header length', `${ip.header_length} bytes`]);
  if (v4 && ip.identification !== null) entries.push(['Identification', `0x${ip.identification.toString(16).padStart(4, '0')}`]);
  if (v4) entries.push(['Fragmentation', `${ip.dont_fragment ? 'DF ' : ''}${ip.more_fragments ? 'MF ' : ''}offset ${ip.fragment_offset ?? 0}`.trim()]);
  if (!v4 && ip.flow_label !== null) entries.push(['Flow label', `0x${ip.flow_label.toString(16)}`]);
  return <DetailSection title="Network layer" entries={entries} />;
}

/* ---------- Transport ---------- */

export function TransportDetails({ transport }: { transport: TransportLayer | null }) {
  if (!transport) return <DetailSection title="Transport layer" entries={[['Transport header', 'Not present']]} />;
  if (transport.kind === 'TCP') {
    return <DetailSection title="Transport layer — TCP" entries={[
      ['Source port', String(transport.source_port)], ['Destination port', String(transport.destination_port)],
      ['Sequence number', String(transport.sequence_number)], ['Acknowledgment number', String(transport.acknowledgment_number)],
      ['Flags', transport.flags.join(', ') || 'none'], ['Window', String(transport.window)], ['Header length', `${transport.header_length} bytes`],
    ]} />;
  }
  if (transport.kind === 'UDP') {
    return <DetailSection title="Transport layer — UDP" entries={[
      ['Source port', String(transport.source_port)], ['Destination port', String(transport.destination_port)],
      ['Length', `${transport.length} bytes`], ['Checksum', `0x${transport.checksum.toString(16).padStart(4, '0')}`],
    ]} />;
  }
  return <DetailSection title="Transport layer — ICMP" entries={[
    ['Type', `${transport.type_name} (${transport.type})`], ['Code', String(transport.code)], ['Checksum', `0x${transport.checksum.toString(16).padStart(4, '0')}`],
  ]} />;
}

/* ---------- IPsec ---------- */

export function IPsecDetails({ ipsec }: { ipsec: IPsecAnalysis | null }) {
  if (!ipsec) {
    return (
      <section className="border-t border-border py-3">
        <h3 className="text-2xs font-medium text-muted">IPsec information</h3>
        <p className="mt-2 text-xs text-muted">No IPsec data. This packet carries no IKE, ESP or AH structure.</p>
      </section>
    );
  }
  return (
    <>
      <DetailSection title="IPsec information" entries={[
        ['Type', <ProtocolBadge key="t" protocol={ipsec.type} />],
        ['NAT traversal', ipsec.nat_traversal ? `Yes — UDP/${ipsec.udp_port}` : ipsec.udp_port ? `No — UDP/${ipsec.udp_port}` : 'No — native IP protocol'],
        ...(ipsec.nat_traversal_note ? [['Note', ipsec.nat_traversal_note] as [string, string]] : []),
      ]} />
      {ipsec.type === 'IKE' ? <IKEDetails ike={ipsec.ike} /> : null}
      {ipsec.type === 'ESP' ? <ESPDetails esp={ipsec.esp} /> : null}
      {ipsec.type === 'AH' ? <AHDetails ah={ipsec.ah} /> : null}
    </>
  );
}

export function IKEDetails({ ike }: { ike: IPsecAnalysis extends { ike: infer T } ? NonNullable<T> : never }) {
  return (
    <>
      <DetailSection title={`IKE header — IKEv${ike.major_version}`} entries={[
        ['IKE version', ike.version], ['Exchange type', `${ike.exchange_name} (${ike.exchange_type})`],
        ['Initiator SPI', ike.initiator_spi], ['Responder SPI', ike.responder_spi],
        ['Message ID', String(ike.message_id)], ['Flags', ike.flags.join(', ') || 'none'],
        ['Length', `${ike.length} bytes`], ['Payload count', String(ike.payload_count)],
      ]} />
      <section className="border-t border-border py-3">
        <h3 className="text-2xs font-medium text-muted">IKE payloads</h3>
        {ike.payloads.length === 0 ? <p className="mt-2 text-xs text-muted">No IKE payloads decoded.</p> : (
          <ol className="mt-2 space-y-1">
            {ike.payloads.map((p, i) => (
              <li key={i} className="flex items-center justify-between gap-3 rounded border border-border bg-background/60 px-2 py-1.5 text-xs">
                <span className="flex items-center gap-2">
                  <span className="font-mono text-muted">{i + 1}</span>
                  <span className="text-primary">{p.name}</span>
                  {p.type_number === 46 || p.type_number === 53 ? <Lock aria-label="Encrypted" className="h-3 w-3 text-info" /> : null}
                </span>
                <span className="font-mono text-muted">type {p.type_number} · {p.length} B{p.critical ? ' · critical' : ''}</span>
              </li>
            ))}
          </ol>
        )}
        {ike.encrypted_payload ? <p className="mt-2 text-2xs text-muted">Payloads following SK are encrypted and cannot be inspected in plaintext.</p> : null}
      </section>
    </>
  );
}

export function ESPDetails({ esp }: { esp: NonNullable<Extract<IPsecAnalysis, { type: 'ESP' }>['esp']> }) {
  return (
    <>
      <DetailSection title="ESP" entries={[
        ['SPI', esp.spi], ['Sequence number', String(esp.sequence_number)], ['Payload length', `${esp.payload_length} bytes`], ['Authentication data', esp.authentication_data],
      ]} />
      <div className="mt-1 flex items-start gap-2 rounded border border-info/30 bg-info/5 px-3 py-2">
        <Lock aria-hidden className="mt-0.5 h-3.5 w-3.5 text-info" />
        <div>
          <p className="text-xs font-medium text-primary">Encrypted payload</p>
          <p className="text-2xs text-muted">Payload contents are not available for plaintext inspection.</p>
        </div>
      </div>
    </>
  );
}

export function AHDetails({ ah }: { ah: NonNullable<Extract<IPsecAnalysis, { type: 'AH' }>['ah']> }) {
  return (
    <DetailSection title="AH" entries={[
      ['Next header', `${ah.next_header_name} (${ah.next_header})`], ['Payload length', `${ah.payload_length} (32-bit words − 2)`],
      ['SPI', ah.spi], ['Sequence number', String(ah.sequence_number)],
      ['Authentication data', <span key="a" className="break-all">{ah.authentication_data}</span>], ['ICV length', `${ah.icv_length} bytes`],
    ]} />
  );
}

/* ---------- Flags & parser ---------- */

const FLAG_LABELS: Array<[keyof SecurityFlags, string]> = [
  ['encrypted', 'Encrypted'], ['authenticated', 'Authenticated'], ['fragmented', 'Fragmented'],
  ['nat_t', 'NAT-T'], ['malformed', 'Malformed'], ['incomplete', 'Incomplete'],
];

export function SecurityFlagBadges({ flags }: { flags: SecurityFlags }) {
  const active = FLAG_LABELS.filter(([k]) => flags[k]);
  if (active.length === 0) return <span className="text-2xs text-muted">No protocol flags observed.</span>;
  return (
    <ul aria-label="Protocol flags" className="flex flex-wrap gap-1.5">
      {active.map(([key, label]) => (
        <li key={key} className={`inline-flex items-center gap-1 rounded border px-1.5 py-px text-2xs font-medium ${key === 'malformed' || key === 'incomplete' ? 'border-warning/35 bg-warning/10 text-warning' : 'border-info/35 bg-info/10 text-info'}`}>
          {key === 'encrypted' ? <Lock aria-hidden className="h-3 w-3" /> : key === 'authenticated' ? <ShieldCheck aria-hidden className="h-3 w-3" /> : key === 'malformed' ? <AlertTriangle aria-hidden className="h-3 w-3" /> : null}
          {label}
        </li>
      ))}
    </ul>
  );
}

export function ParserStatus({ packet }: { packet: PacketAnalysisResult }) {
  if (packet.parse_status === 'OK') return null;
  return (
    <div role="status" className="rounded border border-warning/30 bg-warning/5 px-3 py-2">
      <p className="flex items-center gap-2 text-xs font-medium text-primary">
        <AlertTriangle aria-hidden className="h-3.5 w-3.5 text-warning" />
        {packet.parse_status === 'MALFORMED' ? 'Malformed packet' : 'Packet parse error'}
      </p>
      <p className="mt-1 text-2xs text-secondary">The packet could not be fully decoded. Layers before the failure are shown.</p>
      <dl className="mt-2 space-y-0.5 text-2xs">
        <div className="flex gap-2"><dt className="text-muted">Parser message</dt><dd className="font-mono text-secondary">{packet.parse_error}</dd></div>
        <div className="flex gap-2"><dt className="text-muted">Packet number</dt><dd className="font-mono text-secondary">{packet.number}</dd></div>
        <div className="flex gap-2"><dt className="text-muted">Affected protocol</dt><dd className="font-mono text-secondary">{packet.parse_affected_protocol ?? 'unknown'}</dd></div>
      </dl>
    </div>
  );
}

export function RawPacketViewer({ raw }: { raw: PacketAnalysisResult['raw'] }) {
  if (!raw) return <EmptyState title="Raw data not available" />;
  const lines: string[] = [];
  for (let offset = 0; offset < raw.hex.length; offset += 32) {
    const chunk = raw.hex.slice(offset, offset + 32);
    const bytes = chunk.match(/.{1,2}/g) ?? [];
    const ascii = raw.ascii.slice(offset / 2, offset / 2 + 16);
    lines.push(`${(offset / 2).toString(16).padStart(4, '0')}  ${bytes.join(' ').padEnd(47)}  ${ascii}`);
  }
  return (
    <section className="border-t border-border py-3">
      <h3 className="text-2xs font-medium text-muted">Raw packet — hex and ASCII</h3>
      <pre className="scrollbar-slim mt-2 max-h-64 overflow-auto rounded bg-background p-2 font-mono text-2xs leading-relaxed text-secondary">{lines.join('\n')}</pre>
      <p className="mt-1 text-2xs text-muted">{raw.length} bytes captured{raw.truncated ? '; first 2048 shown' : ''}.</p>
    </section>
  );
}
