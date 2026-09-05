import { FeatureDriftRow } from './FeatureDriftRow';
import type { FeatureDrift } from '@/types';

interface FeatureDriftTableProps {
  features: FeatureDrift[];
  selectedFeature: FeatureDrift | null;
  onSelectFeature: (feature: FeatureDrift) => void;
  searchQuery: string;
  categoryFilter: string;
  driftFilter: string;
  severityFilter: string;
}

export function FeatureDriftTable({
  features,
  selectedFeature,
  onSelectFeature,
  searchQuery,
  categoryFilter,
  driftFilter,
  severityFilter,
}: FeatureDriftTableProps) {
  const filtered = features.filter((f) => {
    // Search
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const match =
        f.feature_name.toLowerCase().includes(q) ||
        f.display_name.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q);
      if (!match) return false;
    }

    // Category
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) {
      return false;
    }

    // Drift filter
    if (driftFilter === 'DRIFTING' && !f.drift_detected) {
      return false;
    }
    if (driftFilter === 'NO_DRIFT' && f.drift_detected) {
      return false;
    }

    // Severity filter
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) {
      return false;
    }

    return true;
  });

  if (filtered.length === 0) {
    return (
      <div className="p-12 text-center text-xs text-muted">
        No feature comparisons match the selected filter criteria.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-muted/50 text-2xs uppercase tracking-wider text-muted">
            <th className="py-2.5 px-4">Feature Name</th>
            <th className="py-2.5 px-4">Category</th>
            <th className="py-2.5 px-4 text-right">Observed Value</th>
            <th className="py-2.5 px-4 text-right">Baseline Reference</th>
            <th className="py-2.5 px-4 text-right">Deviation</th>
            <th className="py-2.5 px-4 text-center">Method</th>
            <th className="py-2.5 px-4 text-center">Result</th>
            <th className="py-2.5 px-4 text-center">Severity</th>
            <th className="py-2.5 px-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {filtered.map((feature) => (
            <FeatureDriftRow
              key={feature.feature_name}
              feature={feature}
              isSelected={selectedFeature?.feature_name === feature.feature_name}
              onSelect={onSelectFeature}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}
