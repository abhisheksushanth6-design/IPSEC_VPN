import { useState, useEffect } from 'react';
import { CheckCircle2, GitCompare, Minus } from 'lucide-react';
import { baselineService } from '@/services/baselineService';
import type { FingerprintComparison as FingerprintComparisonType, SessionFingerprint } from '@/types';

interface FingerprintComparisonProps {
  fingerprints: SessionFingerprint[];
  initialIdA?: string;
  initialIdB?: string;
}

export function FingerprintComparison({
  fingerprints,
  initialIdA,
  initialIdB,
}: FingerprintComparisonProps) {
  const [idA, setIdA] = useState<string>(initialIdA ?? fingerprints[0]?.id ?? '');
  const [idB, setIdB] = useState<string>(
    initialIdB ?? (fingerprints[1]?.id ?? fingerprints[0]?.id ?? '')
  );
  const [comparison, setComparison] = useState<FingerprintComparisonType | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!idA || !idB) return;
    let active = true;
    setLoading(true);
    setError(null);

    baselineService
      .compareFingerprints(idA, idB)
      .then((data) => {
        if (active) {
          setComparison(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err.message ?? 'Failed to compare fingerprints');
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [idA, idB]);

  if (fingerprints.length < 2) {
    return (
      <div className="p-8 text-center text-xs text-muted border border-border rounded-lg bg-surface m-6">
        <GitCompare className="h-8 w-8 text-muted mx-auto mb-2 opacity-50" />
        <h3 className="text-sm font-semibold text-text-primary">At Least 2 Fingerprints Required</h3>
        <p className="text-xs text-muted max-w-sm mx-auto mt-1">
          Comparison requires two observed session fingerprints to evaluate feature values side-by-side.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Selectors Card */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 rounded-lg border border-border bg-surface p-4 shadow-sm">
        <div className="space-y-1.5">
          <label className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Fingerprint A (Reference)
          </label>
          <select
            value={idA}
            onChange={(e) => setIdA(e.target.value)}
            className="w-full rounded-md border border-border bg-base px-3 py-2 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none"
          >
            {fingerprints.map((fp) => (
              <option key={fp.id} value={fp.id}>
                {fp.session_id} ({fp.id.slice(0, 14)}...)
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-1.5">
          <label className="text-2xs font-semibold uppercase tracking-wider text-muted">
            Fingerprint B (Target)
          </label>
          <select
            value={idB}
            onChange={(e) => setIdB(e.target.value)}
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
          Loading comparison data...
        </div>
      )}

      {error && (
        <div className="p-4 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-lg">
          {error}
        </div>
      )}

      {comparison && !loading && (
        <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
          <div className="flex items-center justify-between border-b border-border bg-surface-muted/50 p-4">
            <div className="flex items-center gap-2">
              <GitCompare className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-text-primary">
                Factual Feature Comparison: {comparison.fingerprint_a.session_id} vs {comparison.fingerprint_b.session_id}
              </h3>
            </div>
            <span className="text-2xs font-mono text-muted">
              {comparison.features.length} features evaluated
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border text-2xs uppercase tracking-wider text-muted bg-surface-muted/20">
                  <th className="py-2.5 px-4">Feature</th>
                  <th className="py-2.5 px-4">Category</th>
                  <th className="py-2.5 px-4 text-right">Fingerprint A</th>
                  <th className="py-2.5 px-4 text-right">Fingerprint B</th>
                  <th className="py-2.5 px-4 text-center">Identity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {comparison.features.map((item) => {
                  const formatVal = (v: any) => {
                    if (v === null || v === undefined) return '—';
                    if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
                    if (typeof v === 'number') return v.toLocaleString();
                    return String(v);
                  };

                  const isMatch = item.value_a === item.value_b;

                  return (
                    <tr key={item.feature_name} className="hover:bg-surface-muted/40 transition">
                      <td className="py-2.5 px-4">
                        <div className="font-semibold text-text-primary">{item.display_name}</div>
                        <div className="font-mono text-3xs text-muted">{item.feature_name}</div>
                      </td>

                      <td className="py-2.5 px-4">
                        <span className="rounded bg-surface-muted px-2 py-0.5 text-2xs font-mono font-medium text-text-secondary border border-border">
                          {item.category}
                        </span>
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-xs text-text-primary font-semibold">
                        {formatVal(item.value_a)} {item.unit ?? ''}
                      </td>

                      <td className="py-2.5 px-4 text-right font-mono text-xs text-text-primary font-semibold">
                        {formatVal(item.value_b)} {item.unit ?? ''}
                      </td>

                      <td className="py-2.5 px-4 text-center">
                        {isMatch ? (
                          <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-2xs font-mono text-emerald-400 border border-emerald-500/20">
                            <CheckCircle2 className="h-3 w-3" />
                            Match
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-2xs font-mono text-amber-400 border border-amber-500/20">
                            <Minus className="h-3 w-3" />
                            Differs
                          </span>
                        )}
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
