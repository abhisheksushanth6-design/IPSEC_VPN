import { Panel, DataRow } from '@/components/ui';
import { ProtocolBadge, StatusBadge } from '@/components/status';
import type { AnalysisStatus, PacketProtocol } from '@/types';

const ORDER: Array<keyof NonNullable<AnalysisStatus['protocol_counts']>> = ['IKE', 'ESP', 'AH', 'TCP', 'UDP', 'ICMP', 'OTHER'];

/** Counts derived from the loaded capture only. */
export function ProtocolSummary({ status }: { status: AnalysisStatus | null }) {
  const counts = status?.protocol_counts ?? null;
  return (
    <Panel title="Protocol Summary" description="Packets by decoded protocol." actions={counts ? undefined : <StatusBadge status="NOT INITIALIZED" label="NO DATA" size="sm" />}>
      <dl>
        {ORDER.map((key) => (
          <DataRow key={key} label={key === 'OTHER' ? 'Other' : key}>
            <span className="inline-flex items-center gap-2">
              {key !== 'OTHER' ? <ProtocolBadge protocol={key as PacketProtocol} /> : null}
              <span className="font-mono tabular-nums">{counts ? counts[key].toLocaleString() : '—'}</span>
            </span>
          </DataRow>
        ))}
      </dl>
    </Panel>
  );
}
