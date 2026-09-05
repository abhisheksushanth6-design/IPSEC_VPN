import { Panel, DataRow } from '@/components/ui';
import type { AnalysisStatus } from '@/types';

const ROWS: Array<[keyof NonNullable<AnalysisStatus['statistics']>, string]> = [
  ['total_packets', 'Total packets'], ['ipsec_packets', 'IPsec packets'], ['ike_packets', 'IKE packets'],
  ['esp_packets', 'ESP packets'], ['ah_packets', 'AH packets'], ['malformed_packets', 'Malformed packets'],
];

/** N/A until analysis has run; zero only when analysis ran and found none. */
export function PacketStatistics({ status }: { status: AnalysisStatus | null }) {
  const stats = status?.statistics ?? null;
  return (
    <Panel title="Packet Statistics" description={stats ? `From ${status?.capture?.filename ?? 'the loaded capture'}.` : 'No analysis has run.'}>
      <dl>
        {ROWS.map(([key, label]) => (
          <DataRow key={key} label={label}><span className="font-mono tabular-nums">{stats ? stats[key].toLocaleString() : 'N/A'}</span></DataRow>
        ))}
      </dl>
    </Panel>
  );
}
