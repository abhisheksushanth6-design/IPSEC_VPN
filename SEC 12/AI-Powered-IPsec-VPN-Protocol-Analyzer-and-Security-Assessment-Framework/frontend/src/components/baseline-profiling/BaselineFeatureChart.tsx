import { BarChart3, Binary, Layers } from 'lucide-react';
import type { BaselineFeatureProfile } from '@/types';

interface BaselineFeatureChartProps {
  feature: BaselineFeatureProfile;
}

export function BaselineFeatureChart({ feature }: BaselineFeatureChartProps) {
  const num = feature.numeric_stats;
  const cat = feature.categorical_stats;
  const bool = feature.boolean_stats;

  if (num) {
    const range = num.max - num.min;
    const getPct = (val: number) => {
      if (range <= 0) return 50;
      return Math.min(100, Math.max(0, ((val - num.min) / range) * 100));
    };

    const p25Pct = getPct(num.p25);
    const p50Pct = getPct(num.median);
    const p75Pct = getPct(num.p75);
    const meanPct = getPct(num.mean);

    return (
      <div className="rounded-lg border border-border bg-base p-4 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            <span className="text-xs font-semibold text-text-primary">
              Descriptive Distribution: {feature.display_name}
            </span>
          </div>
          <span className="text-2xs font-mono text-muted">
            {num.count} observations · Sample Std Dev: {num.std_dev.toLocaleString(undefined, { maximumFractionDigits: 3 })}
          </span>
        </div>

        {/* Five-Number Summary & Percentile Cards */}
        <div className="grid grid-cols-4 gap-2 sm:grid-cols-8">
          {[
            { label: 'Min', val: num.min },
            { label: 'P25', val: num.p25 },
            { label: 'Median (P50)', val: num.median },
            { label: 'Mean (μ)', val: num.mean, isMean: true },
            { label: 'P75', val: num.p75 },
            { label: 'P95', val: num.p95 },
            { label: 'Max', val: num.max },
            { label: 'Std Dev (σ)', val: num.std_dev },
          ].map((item) => (
            <div key={item.label} className="rounded border border-border bg-surface p-2 text-center">
              <div className="text-3xs uppercase tracking-wider text-muted truncate">
                {item.label}
              </div>
              <div
                className={`mt-1 font-mono text-xs font-semibold truncate ${
                  item.isMean ? 'text-cyan-400' : 'text-text-primary'
                }`}
                title={String(item.val)}
              >
                {item.val.toLocaleString(undefined, { maximumFractionDigits: 2 })}
              </div>
            </div>
          ))}
        </div>

        {/* Five-number summary graphic / distribution range bar */}
        <div className="pt-2">
          <div className="flex justify-between text-3xs font-mono text-muted mb-1">
            <span>Min: {num.min.toLocaleString(undefined, { maximumFractionDigits: 1 })}</span>
            <span>Median: {num.median.toLocaleString(undefined, { maximumFractionDigits: 1 })}</span>
            <span>Max: {num.max.toLocaleString(undefined, { maximumFractionDigits: 1 })}</span>
          </div>
          <div className="relative h-6 w-full rounded-md bg-surface-muted border border-border flex items-center px-2">
            {/* Range track */}
            <div className="absolute left-2 right-2 h-1.5 bg-border rounded-full" />

            {/* Interquartile Range (IQR) block: P25 to P75 */}
            <div
              className="absolute h-4 rounded bg-cyan-500/30 border border-cyan-500/50"
              style={{
                left: `calc(8px + ${p25Pct}% * (100% - 16px) / 100)`,
                width: `calc((${p75Pct - p25Pct}%) * (100% - 16px) / 100)`,
              }}
              title={`IQR: P25 (${num.p25}) to P75 (${num.p75})`}
            />

            {/* Median tick (P50) */}
            <div
              className="absolute h-5 w-1 rounded-full bg-cyan-400 shadow-sm"
              style={{
                left: `calc(8px + ${p50Pct}% * (100% - 16px) / 100)`,
              }}
              title={`Median: ${num.median}`}
            />

            {/* Mean marker */}
            <div
              className="absolute h-2.5 w-2.5 rounded-full bg-indigo-400 border border-indigo-200"
              style={{
                left: `calc(7px + ${meanPct}% * (100% - 16px) / 100)`,
              }}
              title={`Mean: ${num.mean}`}
            />
          </div>
          <div className="flex items-center justify-between text-3xs text-muted mt-1.5">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded bg-cyan-500/30 border border-cyan-500/50" />
              Interquartile Range (IQR: P25–P75)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-1 rounded-full bg-cyan-400" />
              Median (P50)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-indigo-400" />
              Mean (μ)
            </span>
          </div>
        </div>
      </div>
    );
  }

  if (cat) {
    return (
      <div className="rounded-lg border border-border bg-base p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-purple-400" />
            <span className="text-xs font-semibold text-text-primary">
              Categorical Distribution: {feature.display_name}
            </span>
          </div>
          <span className="text-2xs font-mono text-muted">
            Mode: <strong className="text-purple-400">{cat.mode ?? 'N/A'}</strong> · {cat.unique_count} distinct categories
          </span>
        </div>

        <div className="space-y-2">
          {Object.entries(cat.frequencies).map(([category, count]) => {
            const relFreq = cat.relative_frequencies[category] ?? 0;
            const pct = Math.round(relFreq * 100);
            return (
              <div key={category} className="space-y-1">
                <div className="flex justify-between text-2xs">
                  <span className="font-mono font-medium text-text-secondary">{category}</span>
                  <span className="font-mono text-muted">
                    {count} ({pct}%)
                  </span>
                </div>
                <div className="h-2 w-full rounded-full bg-surface-muted overflow-hidden border border-border">
                  <div
                    className="h-full rounded-full bg-purple-500/70"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  if (bool) {
    const truePct = Math.round(bool.true_ratio * 100);
    const falsePct = Math.round(bool.false_ratio * 100);

    return (
      <div className="rounded-lg border border-border bg-base p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2">
            <Binary className="h-4 w-4 text-emerald-400" />
            <span className="text-xs font-semibold text-text-primary">
              Boolean State Ratio: {feature.display_name}
            </span>
          </div>
          <span className="text-2xs font-mono text-muted">
            {bool.count} observed values
          </span>
        </div>

        <div className="space-y-1.5">
          <div className="flex justify-between text-2xs">
            <span className="font-mono font-semibold text-emerald-400">
              TRUE: {bool.true_count} ({truePct}%)
            </span>
            <span className="font-mono font-semibold text-muted">
              FALSE: {bool.false_count} ({falsePct}%)
            </span>
          </div>
          <div className="h-3 w-full rounded-md bg-surface-muted overflow-hidden border border-border flex">
            <div className="h-full bg-emerald-500/70" style={{ width: `${truePct}%` }} />
            <div className="h-full bg-surface-muted" style={{ width: `${falsePct}%` }} />
          </div>
        </div>
      </div>
    );
  }

  return null;
}
