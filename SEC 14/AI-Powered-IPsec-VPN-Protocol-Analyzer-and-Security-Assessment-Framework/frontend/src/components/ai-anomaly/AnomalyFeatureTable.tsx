import { useState } from 'react';
import { ArrowDown, ArrowUp, Minus, Search } from 'lucide-react';
import type { AnomalyFeatureContribution } from '@/types';

interface AnomalyFeatureTableProps {
  contributions: AnomalyFeatureContribution[];
  onSelectFeature?: (feature: AnomalyFeatureContribution) => void;
}

export function AnomalyFeatureTable({
  contributions,
  onSelectFeature,
}: AnomalyFeatureTableProps) {
  const [search, setSearch] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [directionFilter, setDirectionFilter] = useState<string>('ALL');

  // Categories
  const categories = Array.from(new Set(contributions.map((c) => c.category))).sort();

  // Filtering
  const filtered = contributions.filter((c) => {
    const matchesSearch =
      c.display_name.toLowerCase().includes(search.toLowerCase()) ||
      c.feature_name.toLowerCase().includes(search.toLowerCase()) ||
      c.evidence_description.toLowerCase().includes(search.toLowerCase());

    const matchesCat = categoryFilter === 'ALL' || c.category === categoryFilter;
    const matchesDir = directionFilter === 'ALL' || c.direction === directionFilter;

    return matchesSearch && matchesCat && matchesDir;
  });

  return (
    <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
      {/* Header & Filter Toolbar */}
      <div className="p-4 border-b border-border/80 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 bg-surface">
        <div>
          <h3 className="text-sm font-bold text-text-primary">
            FEATURE CONTRIBUTION & DEVIATION EVIDENCE
          </h3>
          <p className="text-2xs text-muted mt-0.5">
            Model-derived feature deviations relative to baseline reference distribution.
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              placeholder="Search features..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1 rounded border border-border bg-base text-xs text-text-primary placeholder:text-muted focus:border-cyan-500 focus:outline-none w-44"
            />
          </div>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded border border-border bg-base px-2.5 py-1 text-xs text-text-primary focus:border-cyan-500 focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>

          {/* Direction Filter */}
          <select
            value={directionFilter}
            onChange={(e) => setDirectionFilter(e.target.value)}
            className="rounded border border-border bg-base px-2.5 py-1 text-xs text-text-primary focus:border-cyan-500 focus:outline-none"
          >
            <option value="ALL">All Deviations</option>
            <option value="ABOVE_REFERENCE">Above (+)</option>
            <option value="BELOW_REFERENCE">Below (-)</option>
            <option value="WITHIN_RANGE">Within Normal</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-border/80 bg-base/60 text-2xs font-semibold text-muted uppercase tracking-wider">
              <th className="py-2.5 px-4">Feature Name</th>
              <th className="py-2.5 px-4">Category</th>
              <th className="py-2.5 px-4 text-right">Observed Value</th>
              <th className="py-2.5 px-4 text-right">Reference Mean (Std)</th>
              <th className="py-2.5 px-4 text-center">Deviation (z-score)</th>
              <th className="py-2.5 px-4 text-right">Contribution</th>
              <th className="py-2.5 px-4">Evidence Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40 font-mono text-2xs">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-muted font-sans">
                  No feature contributions match current filters.
                </td>
              </tr>
            ) : (
              filtered.map((c) => {
                const isAbove = c.direction === 'ABOVE_REFERENCE';
                const isBelow = c.direction === 'BELOW_REFERENCE';
                const isNormal = c.direction === 'WITHIN_RANGE';

                return (
                  <tr
                    key={c.feature_name}
                    onClick={() => onSelectFeature && onSelectFeature(c)}
                    className={`hover:bg-surface-hover/60 transition ${
                      onSelectFeature ? 'cursor-pointer' : ''
                    } ${!isNormal ? 'bg-rose-500/[0.02]' : ''}`}
                  >
                    {/* Feature Name */}
                    <td className="py-2.5 px-4 font-sans font-medium text-text-primary">
                      <div>{c.display_name}</div>
                      <div className="text-3xs font-mono text-muted">{c.feature_name}</div>
                    </td>

                    {/* Category */}
                    <td className="py-2.5 px-4">
                      <span className="text-3xs uppercase font-mono px-2 py-0.5 rounded bg-base border border-border text-muted">
                        {c.category}
                      </span>
                    </td>

                    {/* Observed Value */}
                    <td className="py-2.5 px-4 text-right font-bold text-text-primary">
                      {typeof c.observed_value === 'number'
                        ? c.observed_value.toLocaleString(undefined, { maximumFractionDigits: 2 })
                        : String(c.observed_value)}
                    </td>

                    {/* Reference Mean & Std */}
                    <td className="py-2.5 px-4 text-right text-muted">
                      {c.reference_mean !== null && c.reference_mean !== undefined ? (
                        <>
                          <span className="text-text-secondary">{c.reference_mean.toFixed(2)}</span>
                          <span className="text-3xs text-muted block">
                            (±{c.reference_std !== null && c.reference_std !== undefined ? c.reference_std.toFixed(2) : '1.0'})
                          </span>
                        </>
                      ) : (
                        '—'
                      )}
                    </td>

                    {/* Deviation (z-score) & Direction Badge */}
                    <td className="py-2.5 px-4 text-center">
                      <div className="inline-flex items-center gap-1">
                        {isAbove && <ArrowUp className="h-3 w-3 text-rose-400" />}
                        {isBelow && <ArrowDown className="h-3 w-3 text-cyan-400" />}
                        {isNormal && <Minus className="h-3 w-3 text-muted" />}

                        <span
                          className={`px-1.5 py-0.5 rounded text-3xs font-bold ${
                            isAbove
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : isBelow
                              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                              : 'bg-surface text-muted border border-border'
                          }`}
                        >
                          {c.deviation !== null && c.deviation !== undefined
                            ? `${c.deviation > 0 ? '+' : ''}${c.deviation.toFixed(2)}σ`
                            : '0.00σ'}
                        </span>
                      </div>
                    </td>

                    {/* Contribution Score */}
                    <td className="py-2.5 px-4 text-right font-bold">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-12 h-1.5 bg-base rounded-full overflow-hidden border border-border">
                          <div
                            className={`h-full ${
                              !isNormal ? 'bg-rose-400' : 'bg-slate-500'
                            }`}
                            style={{ width: `${Math.min(100, c.contribution_score * 2)}%` }}
                          />
                        </div>
                        <span className={!isNormal ? 'text-rose-400' : 'text-muted'}>
                          {c.contribution_score.toFixed(1)}%
                        </span>
                      </div>
                    </td>

                    {/* Evidence Description */}
                    <td className="py-2.5 px-4 font-sans text-2xs text-text-secondary max-w-xs truncate">
                      {c.evidence_description}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
