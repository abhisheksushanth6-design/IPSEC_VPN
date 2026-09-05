
interface SeverityDistributionBarProps {
  distribution: Record<string, number>;
  total: number;
}

export function SeverityDistributionBar({ distribution, total }: SeverityDistributionBarProps) {
  const critical = distribution['CRITICAL'] || 0;
  const high = distribution['HIGH'] || 0;
  const medium = distribution['MEDIUM'] || 0;
  const low = distribution['LOW'] || 0;
  const info = distribution['INFORMATIONAL'] || 0;

  if (total === 0) {
    return (
      <div className="space-y-1.5">
        <div className="h-2.5 w-full rounded-full bg-surface-subtle overflow-hidden border border-border flex">
          <div className="h-full w-full bg-slate-800/40" />
        </div>
        <p className="text-[11px] text-text-muted">No findings recorded in current evaluation state.</p>
      </div>
    );
  }

  const critPct = (critical / total) * 100;
  const highPct = (high / total) * 100;
  const medPct = (medium / total) * 100;
  const lowPct = (low / total) * 100;
  const infoPct = (info / total) * 100;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-text-secondary">
        <span className="font-medium">Severity Distribution</span>
        <span className="font-mono text-text-primary">{total} Total Findings</span>
      </div>

      <div className="h-3 w-full rounded-full bg-surface-subtle overflow-hidden border border-border flex">
        {critPct > 0 && (
          <div
            style={{ width: `${critPct}%` }}
            className="h-full bg-rose-600 transition-all duration-300"
            title={`Critical: ${critical} (${Math.round(critPct)}%)`}
          />
        )}
        {highPct > 0 && (
          <div
            style={{ width: `${highPct}%` }}
            className="h-full bg-orange-500 transition-all duration-300"
            title={`High: ${high}% (${Math.round(highPct)}%)`}
          />
        )}
        {medPct > 0 && (
          <div
            style={{ width: `${medPct}%` }}
            className="h-full bg-amber-500 transition-all duration-300"
            title={`Medium: ${medium} (${Math.round(medPct)}%)`}
          />
        )}
        {lowPct > 0 && (
          <div
            style={{ width: `${lowPct}%` }}
            className="h-full bg-blue-500 transition-all duration-300"
            title={`Low: ${low} (${Math.round(lowPct)}%)`}
          />
        )}
        {infoPct > 0 && (
          <div
            style={{ width: `${infoPct}%` }}
            className="h-full bg-slate-500 transition-all duration-300"
            title={`Info: ${info} (${Math.round(infoPct)}%)`}
          />
        )}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-rose-600" />
          <span className="text-text-secondary">Critical:</span>
          <span className="font-mono font-medium text-rose-300">{critical}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-orange-500" />
          <span className="text-text-secondary">High:</span>
          <span className="font-mono font-medium text-orange-300">{high}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-amber-500" />
          <span className="text-text-secondary">Medium:</span>
          <span className="font-mono font-medium text-amber-300">{medium}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-blue-500" />
          <span className="text-text-secondary">Low:</span>
          <span className="font-mono font-medium text-blue-300">{low}</span>
        </div>
      </div>
    </div>
  );
}
