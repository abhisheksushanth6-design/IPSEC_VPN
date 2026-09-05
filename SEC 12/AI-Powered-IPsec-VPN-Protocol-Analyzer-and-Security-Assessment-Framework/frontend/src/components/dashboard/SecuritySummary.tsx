import { Panel, DataRow } from '@/components/ui';
import { StatusBadge } from '@/components/status';
import type { DashboardData } from '@/types';

interface SecuritySummaryProps {
  data: DashboardData;
}

function metricValue(data: DashboardData, id: string): number | null {
  return data.metrics.find((m) => m.id === id)?.value ?? null;
}

/** Condensed readout of the posture figures, all of which are unavailable. */
export function SecuritySummary({ data }: SecuritySummaryProps) {
  const rows: Array<{ label: string; id: string }> = [
    { label: 'VPN sessions', id: 'sessions' },
    { label: 'Security Associations', id: 'sas' },
    { label: 'AI anomalies', id: 'anomalies' },
    { label: 'Drift events', id: 'drift' },
    { label: 'Vulnerabilities', id: 'vulnerabilities' },
  ];

  return (
    <Panel title="Security Summary" description="Posture figures from each engine.">
      <dl>
        <DataRow label="Overall risk">
          {data.risk.classification ? (
            <span className="font-medium">{data.risk.classification}</span>
          ) : (
            <StatusBadge status="NOT INITIALIZED" size="sm" />
          )}
        </DataRow>

        {rows.map((row) => {
          const metric = data.metrics.find((m) => m.id === row.id);
          const value = metricValue(data, row.id);
          return (
            <DataRow key={row.id} label={row.label}>
              <span className="inline-flex items-center gap-2">
                <span className="font-mono tabular-nums">{value ?? 'N/A'}</span>
                {metric?.source === 'unavailable' ? (
                  <StatusBadge status="NOT INITIALIZED" size="sm" />
                ) : null}
              </span>
            </DataRow>
          );
        })}
      </dl>

      <p className="mt-4 text-2xs text-muted">
        Zero indicates no engine has produced a figure, not that a scan found nothing.
      </p>
    </Panel>
  );
}
