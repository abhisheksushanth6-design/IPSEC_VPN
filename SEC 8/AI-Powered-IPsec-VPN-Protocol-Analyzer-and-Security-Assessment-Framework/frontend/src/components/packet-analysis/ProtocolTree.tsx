import { ChevronDown, ChevronRight } from 'lucide-react';
import { useState } from 'react';

import type { PacketAnalysisResult } from '@/types';

export interface TreeNode {
  label: string;
  value?: string;
  children?: TreeNode[];
}

/** Build the tree purely from decoded layers; absent layers produce no nodes. */
export function buildTree(packet: PacketAnalysisResult): TreeNode {
  const children: TreeNode[] = [];
  if (packet.ethernet) {
    children.push({ label: 'Ethernet', children: [
      { label: 'Source', value: packet.ethernet.source_mac },
      { label: 'Destination', value: packet.ethernet.destination_mac },
      { label: 'Type', value: packet.ethernet.ethertype },
      ...(packet.ethernet.vlan_id !== null ? [{ label: 'VLAN', value: String(packet.ethernet.vlan_id) }] : []),
    ] });
  }
  if (packet.ip) {
    children.push({ label: `IPv${packet.ip.version}`, children: [
      { label: 'Source', value: packet.ip.source },
      { label: 'Destination', value: packet.ip.destination },
      { label: 'Protocol', value: `${packet.ip.protocol_name} (${packet.ip.protocol_number})` },
      { label: packet.ip.version === 4 ? 'TTL' : 'Hop limit', value: String(packet.ip.ttl) },
    ] });
  }
  const t = packet.transport;
  if (t?.kind === 'TCP') children.push({ label: 'TCP', children: [
    { label: 'Source port', value: String(t.source_port) }, { label: 'Destination port', value: String(t.destination_port) },
    { label: 'Flags', value: t.flags.join(', ') || 'none' }, { label: 'Sequence', value: String(t.sequence_number) },
  ] });
  if (t?.kind === 'UDP') children.push({ label: 'UDP', children: [
    { label: 'Source port', value: String(t.source_port) }, { label: 'Destination port', value: String(t.destination_port) }, { label: 'Length', value: String(t.length) },
  ] });
  if (t?.kind === 'ICMP') children.push({ label: 'ICMP', children: [
    { label: 'Type', value: `${t.type_name} (${t.type})` }, { label: 'Code', value: String(t.code) },
  ] });
  const s = packet.ipsec;
  if (s?.type === 'IKE') children.push({ label: `IKEv${s.ike.major_version}`, children: [
    { label: 'Header', children: [
      { label: 'Exchange', value: s.ike.exchange_name }, { label: 'Initiator SPI', value: s.ike.initiator_spi },
      { label: 'Responder SPI', value: s.ike.responder_spi }, { label: 'Message ID', value: String(s.ike.message_id) },
    ] },
    { label: `Payloads (${s.ike.payload_count})`, children: s.ike.payloads.map((p, i) => ({ label: `Payload ${i + 1}: ${p.name}`, value: `${p.length} bytes${p.critical ? ', critical' : ''}` })) },
  ] });
  if (s?.type === 'ESP') children.push({ label: 'ESP', children: [
    { label: 'SPI', value: s.esp.spi }, { label: 'Sequence', value: String(s.esp.sequence_number) }, { label: 'Payload', value: `${s.esp.payload_length} bytes, encrypted` },
  ] });
  if (s?.type === 'AH') children.push({ label: 'AH', children: [
    { label: 'SPI', value: s.ah.spi }, { label: 'Sequence', value: String(s.ah.sequence_number) }, { label: 'Next header', value: s.ah.next_header_name }, { label: 'ICV', value: `${s.ah.icv_length} bytes` },
  ] });
  return { label: `Packet ${packet.number}`, children };
}

function Node({ node, depth, defaultOpen }: { node: TreeNode; depth: number; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const hasChildren = Boolean(node.children?.length);
  return (
    <li role="treeitem" aria-expanded={hasChildren ? open : undefined} className="text-xs">
      <div className="flex items-baseline gap-1.5" style={{ paddingLeft: depth * 14 }}>
        {hasChildren ? (
          <button type="button" onClick={() => setOpen((v) => !v)} aria-label={`${open ? 'Collapse' : 'Expand'} ${node.label}`} className="rounded p-0.5 text-muted hover:text-primary">
            {open ? <ChevronDown aria-hidden className="h-3 w-3" /> : <ChevronRight aria-hidden className="h-3 w-3" />}
          </button>
        ) : <span aria-hidden className="inline-block w-4 text-center text-border">·</span>}
        <span className={hasChildren ? 'font-medium text-primary' : 'text-muted'}>{node.label}</span>
        {node.value !== undefined ? <span className="font-mono text-secondary">{node.value}</span> : null}
      </div>
      {hasChildren && open ? (
        <ul role="group">{node.children!.map((child, i) => <Node key={`${child.label}-${i}`} node={child} depth={depth + 1} defaultOpen={depth < 1} />)}</ul>
      ) : null}
    </li>
  );
}

export function ProtocolTree({ packet }: { packet: PacketAnalysisResult }) {
  const tree = buildTree(packet);
  return (
    <ul role="tree" aria-label="Protocol tree" className="space-y-0.5">
      <Node node={tree} depth={0} defaultOpen />
    </ul>
  );
}
