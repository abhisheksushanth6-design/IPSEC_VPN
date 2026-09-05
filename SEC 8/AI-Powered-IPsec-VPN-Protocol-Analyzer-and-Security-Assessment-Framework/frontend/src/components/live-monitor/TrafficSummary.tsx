import { Panel, DataRow } from '@/components/ui';
import { EmptyChartState } from '@/components/dashboard';
import type { LiveMonitorData } from '@/hooks';

interface TrafficSummaryProps {
  ipsecBreakdown: LiveMonitorData['ipsecBreakdown'];
  packetRate: number | null;
  bandwidth: number | null;
}

const CATEGORIES = ['IKE', 'ESP', 'AH', 'OTHER'] as const;

/** IPsec traffic split plus rate and bandwidth. Units shown; values withheld. */
export function TrafficSummary({ ipsecBreakdown, packetRate, bandwidth }: TrafficSummaryProps) {
  return (
    <Panel title="IPsec Traffic" description="Share of IKE, ESP, AH and other traffic.">
      {ipsecBreakdown === null ? (
        <>
          <ul aria-label="IPsec categories" className="grid grid-cols-4 gap-2">
            {CATEGORIES.map((c) => (
              <li key={c} className="rounded border border-border bg-background/60 px-2 py-2 text-center">
                <p className="font-mono text-xs text-secondary">{c}</p>
                <p className="mt-1 text-2xs text-muted">N/A</p>
              </li>
            ))}
          </ul>
          <div className="mt-3"><EmptyChartState height={64} detail="Protocol split appears once packet analysis runs." /></div>
        </>
      ) : (
        <ul className="grid grid-cols-4 gap-2">
          {CATEGORIES.map((c) => {
            const entry = ipsecBreakdown.find((b) => b.category === c);
            return (
              <li key={c} className="rounded border border-border bg-background/60 px-2 py-2 text-center">
                <p className="font-mono text-xs text-secondary">{c}</p>
                <p className="mt-1 font-mono text-sm tabular-nums text-primary">{entry?.count ?? 0}</p>
              </li>
            );
          })}
        </ul>
      )}

      <dl className="mt-4">
        <DataRow label="Packet rate">
          <span className="font-mono tabular-nums">{packetRate === null ? 'N/A' : `${packetRate} packets/sec`}</span>
        </DataRow>
        <DataRow label="Bandwidth">
          <span className="font-mono tabular-nums">{bandwidth === null ? 'N/A' : `${bandwidth} bytes/sec`}</span>
        </DataRow>
      </dl>
    </Panel>
  );
}
