import { useState, useEffect } from 'react';
import { Database, Fingerprint, Layers } from 'lucide-react';
import { baselineService } from '@/services/baselineService';
import type {
  BaselineComparison as BaselineComparisonType,
  BaselineSummary,
  SessionFingerprint,
} from '@/types';

interface BaselineComparisonProps {
  baselines: BaselineSummary[];
  fingerprints: SessionFingerprint[];
  initialBaselineId?: string;
  initialFingerprintId?: string;
}

export function BaselineComparison({
  baselines,
  fingerprints,
  initialBaselineId,
  initialFingerprintId,
}: BaselineComparisonProps) {
  const [baselineId, setBaselineId] = useState<string>(
    initialBaselineId ?? baselines.find((b) => b.is_active)?.id ?? baselines[0]?.id ?? ''
  );
  const [fingerprintId, setFingerprintId] = useState<string>(
    initialFingerprintId ?? fingerprints[0]?.id ?? ''
  );
  const [data, setData] = useState<BaselineComparisonType | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!baselineId || !fingerprintId) return;
    let active = true;
    setLoading(true);
    setError(null);

    baselineService
      .compareWithFingerprint(baselineId, fingerprintId)
      .then((res) => {
        if (active) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err.message ?? 'Failed to perform comparison');
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [baselineId, fingerprintId]);

  if (baselines.length === 0 || fingerprints.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-muted border border-border rounded-lg bg-surface m-6">
        <Layers className="h-8 w-8 text-muted mx-auto mb-2 opacity-50" />
        <h3 className="text-sm font-semibold text-text-primary">Baseline and Fingerprints Required</h3>
        <p className="text-xs text-muted max-w-sm mx-auto mt-1">
          Requires at least one baseline profile and one observed session fingerprint.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Selectors */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="space-y-1.5">
          <label className="text-2xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
            <Database className="h-3 w-3 text-cyan-400" />
            Reference Baseline Profile
          </label>
          <select
            value={baselineId}
            onChange={(e) => setBaselineId(e.target.value)}
            className="w-full rounded-md border border-border bg-base px-3 py-2 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none"
          >
            {baselines.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name} (v{b.version}) {b.is_active ? '— [Active Reference]' : ''}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-1.5">
          <label className="text-2xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
            <Fingerprint className="h-3 w-3 text-sky-400" />
            Observed Session Fingerprint
          </label>
          <select
            value={fingerprintId}
            onChange={(e) => setFingerprintId(e.target.value)}
            className="w-full rounded-md border border-border bg-base px-3 py-2 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none"
          >
            {fingerprints.map((fp) => (
              <option key={fp.id} value={fp.id}>
                {fp.session_id} ({fp.id.slice(0, 14)}...)
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading && (
        <div className="p-8 text-center text-xs text-muted">
          Loading descriptive baseline comparison...
        </div>
      )}

      {error && (
        <div className="p-4 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-lg">
          {error}
        </div>
      )}

      {data && !loading && (
        <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
          <div className="flex items-center justify-between border-b border-border bg-surface-muted/50 p-4">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-text-primary">
                Descriptive Comparison: {data.session_id} vs {data.baseline_name} (v{data.baseline_version})
              </h3>
            </div>
            <span className="text-2xs font-mono text-muted">
              {data.features.length} features inspected
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border text-2xs uppercase tracking-wider text-muted bg-surface-muted/20">
                  <th className="py-2.5 px-4">Feature</th>
                  <th className="py-2.5 px-4">Category</th>
                  <th className="py-2.5 px-4 text-right">Observed Value</th>
                  <th className="py-2.5 px-4 text-right">Baseline Mean</th>
                  <th className="py-2.5 px-4 text-right">Baseline Median</th>
                  <th className="py-2.5 px-4 text-right">Baseline Range [Min .. Max]</th>
                  <th className="py-2.5 px-4 text-right">Baseline Std Dev</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.features.map((f) => {
                  const formatObserved = (v: any) => {
                    if (v === null || v === undefined) return '—';
                    if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
                    if (typeof v === 'number') return v.toLocaleString();
                    return String(v);
                  };

                  return (
                    <tr key={f.feature_name} className="hover:bg-surface-muted/40 transition">
                      <td className="py-2.5 px-4">
                        <div className="font-semibold text-text-primary">{f.display_name}</div>
                        <div className="font-mono text-3xs text-muted">{f.feature_name}</div>
                      </td>

                      <td className="py-2.5 px-4">
                        <span className="rounded bg-surface-muted px-2 py-0.5 text-2xs font-mono font-medium text-text-secondary border border-border">
                          {f.category}
                        </span>
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-xs font-semibold text-cyan-400">
                        {formatObserved(f.observed_value)} {f.unit ?? ''}
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-2xs text-text-secondary">
                        {f.baseline_mean !== null
                          ? `${f.baseline_mean.toLocaleString(undefined, { maximumFractionDigits: 2 })} ${f.unit ?? ''}`
                          : (f.baseline_mode ? `Mode: ${f.baseline_mode}` : '—')}
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-2xs text-text-secondary">
                        {f.baseline_median !== null
                          ? `${f.baseline_median.toLocaleString(undefined, { maximumFractionDigits: 2 })} ${f.unit ?? ''}`
                          : '—'}
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-2xs text-muted">
                        {f.baseline_min !== null && f.baseline_max !== null
                          ? `[${f.baseline_min.toLocaleString(undefined, { maximumFractionDigits: 1 })} .. ${f.baseline_max.toLocaleString(undefined, { maximumFractionDigits: 1 })}]`
                          : '—'}
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-2xs text-muted">
                        {f.baseline_std_dev !== null
                          ? `σ = ${f.baseline_std_dev.toLocaleString(undefined, { maximumFractionDigits: 2 })}`
                          : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
