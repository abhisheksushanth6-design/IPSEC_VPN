import { Panel, DataRow } from '@/components/ui';
import { StatusBadge } from '@/components/status';
import { RISK_BANDS } from '@/config/risk';
import { RiskGauge } from './RiskGauge';
import type { RiskSummary } from '@/types';

interface RiskCardProps {
  risk: RiskSummary;
}

/** The overall risk panel: gauge, details, and the fixed band legend. */
export function RiskCard({ risk }: RiskCardProps) {
  const hasScore = risk.score !== null;

  return (
    <Panel
      title="Overall Risk"
      description="Produced by the Risk Assessment & Decision Engine."
      className="flex flex-col"
    >
      <div className="grid gap-6 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] sm:items-center">
        <RiskGauge
          riskScore={risk.score ?? undefined}
          riskLabel={risk.classification ?? undefined}
          status="NOT INITIALIZED"
        />

        <dl>
          <DataRow label="Risk score">
            <span className="font-mono tabular-nums">
              {hasScore ? `${risk.score} / 100` : 'N/A'}
            </span>
          </DataRow>
          <DataRow label="Classification">
            {risk.classification ? (
              <span className="font-medium">{risk.classification}</span>
            ) : (
              <StatusBadge status="NOT INITIALIZED" size="sm" />
            )}
          </DataRow>
          <DataRow label="Last updated">
            <span className="font-mono text-xs">{risk.lastUpdated ?? 'N/A'}</span>
          </DataRow>
        </dl>
      </div>

      <ul
        aria-label="Risk classification bands"
        className="mt-5 grid grid-cols-5 gap-1 border-t border-border pt-4 text-center"
      >
        {RISK_BANDS.map((band) => (
          <li key={band.classification} className="min-w-0">
            <p className="truncate text-2xs font-medium text-secondary">
              {band.classification}
            </p>
            <p className="font-mono text-2xs tabular-nums text-muted">
              {band.min}–{band.max}
            </p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
