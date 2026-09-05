import type { FeatureDrift } from '@/types';

interface DriftVisualizationProps {
  feature: FeatureDrift;
}

export function DriftVisualization({ feature }: DriftVisualizationProps) {
  if (feature.data_type === 'NUMERIC' && feature.current_value !== null && typeof feature.baseline_mean === 'number') {
    const curr = Number(feature.current_value);
    const mean: number = feature.baseline_mean;
    const std: number = typeof feature.baseline_std === 'number' ? feature.baseline_std : 0;
    const p25: number = typeof feature.baseline_distribution?.p25 === 'number' ? feature.baseline_distribution.p25 : (mean - std);
    const med: number = typeof feature.baseline_median === 'number' ? feature.baseline_median : mean;
    const p75: number = typeof feature.baseline_distribution?.p75 === 'number' ? feature.baseline_distribution.p75 : (mean + std);

    // Calculate domain for chart
    const minVal = Math.min(curr, mean - 2.5 * Math.max(std, 1), p25);
    const maxVal = Math.max(curr, mean + 2.5 * Math.max(std, 1), p75);
    const range = maxVal - minVal || 1;

    const getPos = (val: number) => {
      const pct = ((val - minVal) / range) * 100;
      return Math.max(2, Math.min(98, pct));
    };

    const currPos = getPos(curr);
    const meanPos = getPos(mean);
    const medPos = getPos(med);
    const p25Pos = getPos(p25);
    const p75Pos = getPos(p75);

    return (
      <div className="space-y-2 rounded-md border border-border bg-base/50 p-3 text-2xs">
        <div className="flex items-center justify-between font-mono text-3xs text-muted">
          <span>Range: {minVal.toFixed(1)}</span>
          <span className="text-text-primary font-semibold">
            Baseline Reference vs Observed: {curr.toFixed(2)} {feature.unit ?? ''}
          </span>
          <span>{maxVal.toFixed(1)}</span>
        </div>

        {/* Visual Track */}
        <div className="relative h-7 w-full rounded bg-surface-muted/60 border border-border flex items-center overflow-hidden">
          {/* Baseline Interquartile Range Band (P25 - P75) */}
          <div
            className="absolute h-full bg-cyan-500/15 border-l border-r border-cyan-500/40"
            style={{
              left: `${Math.min(p25Pos, p75Pos)}%`,
              width: `${Math.abs(p75Pos - p25Pos)}%`,
            }}
            title={`Baseline IQR: [${p25.toFixed(1)}, ${p75.toFixed(1)}]`}
          />

          {/* Median Line */}
          <div
            className="absolute top-0 bottom-0 w-0.5 bg-cyan-400 z-10"
            style={{ left: `${medPos}%` }}
            title={`Baseline Median: ${med.toFixed(1)}`}
          />

          {/* Mean Line (Dashed) */}
          <div
            className="absolute top-0 bottom-0 w-0.5 border-l border-dashed border-sky-300 z-10"
            style={{ left: `${meanPos}%` }}
            title={`Baseline Mean: ${mean.toFixed(1)}`}
          />

          {/* Current Observed Marker */}
          <div
            className="absolute top-1/2 -translate-y-1/2 z-20 flex flex-col items-center"
            style={{ left: `${currPos}%`, transform: 'translate(-50%, -50%)' }}
            title={`Observed Value: ${curr.toFixed(2)}`}
          >
            <div
              className={`h-4 w-4 rounded-full border-2 shadow-sm ${
                feature.drift_detected
                  ? 'border-amber-400 bg-amber-500/40'
                  : 'border-emerald-400 bg-emerald-500/40'
              }`}
            />
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-between text-3xs text-muted font-mono pt-1">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-sm bg-cyan-500/20 border border-cyan-500/40" />
              <span>IQR (P25–P75)</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block h-3 w-0.5 bg-cyan-400" />
              <span>Median</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block h-3 w-0.5 border-l border-dashed border-sky-300" />
              <span>Mean</span>
            </span>
          </div>
          <div className="flex items-center gap-1">
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                feature.drift_detected ? 'bg-amber-400' : 'bg-emerald-400'
              }`}
            />
            <span className="font-semibold text-text-primary">
              Observed Value ({curr.toFixed(2)})
            </span>
          </div>
        </div>
      </div>
    );
  }

  if (feature.data_type === 'CATEGORICAL') {
    const dist = feature.baseline_distribution?.frequencies ?? {};
    const total = feature.baseline_distribution?.total_samples ?? 0;
    const entries = Object.entries(dist);

    return (
      <div className="space-y-2 rounded-md border border-border bg-base/50 p-3 text-2xs">
        <div className="flex items-center justify-between font-mono text-3xs text-muted">
          <span>Baseline Category Frequencies</span>
          <span className="text-text-primary font-semibold">
            Observed: &quot;{String(feature.current_value)}&quot;
          </span>
        </div>

        {entries.length === 0 ? (
          <div className="text-3xs text-muted py-1">No baseline frequency distribution available.</div>
        ) : (
          <div className="space-y-1.5">
            {entries.map(([cat, count]) => {
              const numCount = Number(count);
              const pct = total > 0 ? Math.round((numCount / total) * 100) : 0;
              const isMatch = String(feature.current_value) === cat;

              return (
                <div key={cat} className="space-y-0.5">
                  <div className="flex items-center justify-between text-3xs font-mono">
                    <span className={isMatch ? 'text-cyan-400 font-bold' : 'text-text-secondary'}>
                      {cat} {isMatch ? '★ (CURRENT)' : ''}
                    </span>
                    <span className="text-muted">
                      {pct}% ({numCount}/{total})
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-surface-muted overflow-hidden border border-border">
                    <div
                      className={`h-full rounded-full ${isMatch ? 'bg-cyan-400' : 'bg-muted'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  if (feature.data_type === 'BOOLEAN') {
    const trueRatio = feature.baseline_distribution?.true_ratio ?? 0;
    const truePct = Math.round(trueRatio * 100);
    const falsePct = 100 - truePct;

    return (
      <div className="space-y-2 rounded-md border border-border bg-base/50 p-3 text-2xs">
        <div className="flex items-center justify-between font-mono text-3xs text-muted">
          <span>Baseline Boolean Ratio</span>
          <span className="text-text-primary font-semibold">
            Observed: {feature.current_value ? 'TRUE' : 'FALSE'}
          </span>
        </div>

        <div className="h-4 w-full rounded overflow-hidden flex border border-border font-mono text-3xs font-bold text-center">
          <div
            className="bg-emerald-500/30 text-emerald-300 flex items-center justify-center transition"
            style={{ width: `${truePct}%` }}
          >
            {truePct > 15 ? `TRUE ${truePct}%` : ''}
          </div>
          <div
            className="bg-surface-muted text-muted flex items-center justify-center transition"
            style={{ width: `${falsePct}%` }}
          >
            {falsePct > 15 ? `FALSE ${falsePct}%` : ''}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded border border-border bg-base/50 p-2.5 text-3xs text-muted">
      Visual distribution representation unavailable for this data type.
    </div>
  );
}
