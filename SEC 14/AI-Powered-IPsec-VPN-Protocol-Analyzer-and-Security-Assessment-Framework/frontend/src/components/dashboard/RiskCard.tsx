import { Panel, DataRow } from '@/components/ui';
import { StatusBadge } from '@/components/status';
import { RISK_BANDS } from '@/config/risk';
import { RiskGauge } from './RiskGauge';
import { useSystemState } from '@/context/SystemStateContext';
import type { RiskSummary, StatusKind } from '@/types';

interface RiskCardProps {
  risk: RiskSummary;
}

/** The overall risk panel: gauge, details, and the fixed band legend. */
export function RiskCard({ risk }: RiskCardProps) {
  const { status } = useSystemState();
  const layer10 = status?.architecture_layers?.find((l) => l.number === 10);
  const isLayer10Ready = layer10
    ? layer10.status === 'OPERATIONAL' || layer10.status === 'READY' || layer10.status === 'IMPLEMENTED'
    : false;

  const fallbackStatus: StatusKind = isLayer10Ready ? 'READY' : 'NOT INITIALIZED';
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
          riskLabel={risk.classification ?? (isLayer10Ready && !hasScore ? 'AWAITING EVALUATION' : undefined)}
          status={fallbackStatus}
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
              <StatusBadge
                status={fallbackStatus}
                label={isLayer10Ready ? 'AWAITING EVALUATION' : 'NOT INITIALIZED'}
                size="sm"
              />
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
