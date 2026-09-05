import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { BaselineFeatureChart } from './BaselineFeatureChart';
import type { BaselineFeatureProfile } from '@/types';

interface BaselineFeatureTableProps {
  features: BaselineFeatureProfile[];
  searchQuery?: string;
}

export function BaselineFeatureTable({ features, searchQuery = '' }: BaselineFeatureTableProps) {
  const [expandedFeature, setExpandedFeature] = useState<string | null>(null);

  const filtered = features.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.name.toLowerCase().includes(q) ||
      f.display_name.toLowerCase().includes(q) ||
      f.category.toLowerCase().includes(q)
    );
  });

  const toggleExpand = (name: string) => {
    setExpandedFeature((prev: string | null) => (prev === name ? null : name));
  };

  if (features.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-muted">
        No feature statistics available for this profile.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-muted/50 text-2xs uppercase tracking-wider text-muted">
            <th className="py-2.5 px-4 w-8"></th>
            <th className="py-2.5 px-4">Feature Name</th>
            <th className="py-2.5 px-4">Category</th>
            <th className="py-2.5 px-4 text-center">Data Type</th>
            <th className="py-2.5 px-4 text-right">Completeness</th>
            <th className="py-2.5 px-4 text-right">Central Tendency</th>
            <th className="py-2.5 px-4 text-right">Dispersion / Range</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {filtered.map((feature) => {
            const isExpanded = expandedFeature === feature.name;
            const completenessPct = Math.round(feature.completeness_ratio * 100);

            let centralTendency = '—';
            let dispersion = '—';

            if (feature.numeric_stats) {
              const num = feature.numeric_stats;
              centralTendency = `Mean: ${num.mean.toLocaleString(undefined, { maximumFractionDigits: 2 })} ${feature.unit ?? ''}`;
              dispersion = `σ: ${num.std_dev.toLocaleString(undefined, { maximumFractionDigits: 2 })} [${num.min.toLocaleString(undefined, { maximumFractionDigits: 1 })} .. ${num.max.toLocaleString(undefined, { maximumFractionDigits: 1 })}]`;
            } else if (feature.categorical_stats) {
              const cat = feature.categorical_stats;
              centralTendency = `Mode: ${cat.mode ?? 'N/A'}`;
              dispersion = `${cat.unique_count} distinct categories`;
            } else if (feature.boolean_stats) {
              const bool = feature.boolean_stats;
              centralTendency = `TRUE: ${Math.round(bool.true_ratio * 100)}%`;
              dispersion = `FALSE: ${Math.round(bool.false_ratio * 100)}%`;
            }

            return (
              <tr key={feature.name} className="group">
                <td colSpan={7} className="p-0">
                  <div
                    onClick={() => toggleExpand(feature.name)}
                    className={`flex items-center cursor-pointer transition hover:bg-surface-muted/50 py-2.5 px-4 ${
                      isExpanded ? 'bg-surface-muted/40' : ''
                    }`}
                  >
                    <div className="w-8 text-muted">
                      {isExpanded ? (
                        <ChevronDown className="h-3.5 w-3.5 text-cyan-400" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5" />
                      )}
                    </div>

                    <div className="flex-1 min-w-[180px]">
                      <div className="font-semibold text-text-primary group-hover:text-cyan-400 transition">
                        {feature.display_name}
                      </div>
                      <div className="font-mono text-2xs text-muted">{feature.name}</div>
                    </div>

                    <div className="w-32">
                      <span className="rounded bg-surface-muted px-2 py-0.5 text-2xs font-mono font-medium text-text-secondary border border-border">
                        {feature.category}
                      </span>
                    </div>

                    <div className="w-24 text-center font-mono text-2xs text-muted">
                      {feature.data_type}
                    </div>

                    <div className="w-36 text-right">
                      <div className="inline-flex flex-col items-end gap-1">
                        <span className="font-mono text-2xs text-text-secondary">
                          {completenessPct}% ({feature.available_samples}/{feature.total_samples})
                        </span>
                        <div className="h-1.5 w-16 rounded-full bg-surface-muted overflow-hidden border border-border">
                          <div
                            className={`h-full rounded-full ${
                              completenessPct >= 90
                                ? 'bg-emerald-400'
                                : completenessPct >= 50
                                ? 'bg-amber-400'
                                : 'bg-rose-400'
                            }`}
                            style={{ width: `${completenessPct}%` }}
                          />
                        </div>
                      </div>
                    </div>

                    <div className="w-48 text-right font-mono text-2xs text-text-primary">
                      {centralTendency}
                    </div>

                    <div className="w-48 text-right font-mono text-2xs text-muted truncate" title={dispersion}>
                      {dispersion}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-4 border-b border-border bg-surface-muted/20">
                      <BaselineFeatureChart feature={feature} />
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
