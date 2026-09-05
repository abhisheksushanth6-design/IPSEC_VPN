import { CategoryBadge } from './FindingStatusBadge';
import type { RuleCategory } from '@/types';

interface CategoryDistributionChartProps {
  distribution: Record<string, number>;
  total: number;
}

const ALL_CATEGORIES: RuleCategory[] = [
  'CRYPTO',
  'IKE',
  'AUTH',
  'PROTOCOL',
  'SA_LIFECYCLE',
  'CONFIGURATION',
];

export function CategoryDistributionChart({
  distribution,
  total,
}: CategoryDistributionChartProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs text-text-secondary">
        <span className="font-medium">Findings by Security Category</span>
        <span className="font-mono text-text-primary">6 Categories</span>
      </div>

      <div className="space-y-2.5">
        {ALL_CATEGORIES.map((category) => {
          const count = distribution[category] || 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;

          return (
            <div key={category} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <CategoryBadge category={category} className="py-0 px-1.5 text-[10px]" />
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-text-primary font-medium">{count}</span>
                  <span className="text-text-muted text-[11px]">({pct}%)</span>
                </div>
              </div>

              <div className="h-1.5 w-full rounded-full bg-surface-subtle overflow-hidden border border-border/40">
                <div
                  style={{ width: `${pct}%` }}
                  className="h-full bg-rose-500/80 transition-all duration-300"
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
