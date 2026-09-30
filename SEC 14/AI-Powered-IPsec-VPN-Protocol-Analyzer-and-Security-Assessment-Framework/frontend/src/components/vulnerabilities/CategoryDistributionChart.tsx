import { CategoryBadge } from './FindingStatusBadge';
import type { RuleCategory } from '@/types';

interface CategoryDistributionChartProps {
  distribution: Record<string, number>;
  total: number;
}

const CATEGORY_DEFINITIONS: { key: RuleCategory; label: string; aliases: string[] }[] = [
  { key: 'CRYPTO', label: 'Cryptography', aliases: ['CRYPTO', 'CRYPTOGRAPHIC'] },
  { key: 'IKE', label: 'IKE Negotiation', aliases: ['IKE'] },
  { key: 'AUTH', label: 'Authentication', aliases: ['AUTH', 'AUTHENTICATION'] },
  { key: 'PROTOCOL', label: 'Protocol Integrity', aliases: ['PROTOCOL', 'IPSEC_PROTOCOL', 'PROTOCOL_ANOMALY'] },
  { key: 'SA_LIFECYCLE', label: 'SA & Protocol State', aliases: ['SA_LIFECYCLE'] },
  { key: 'CONFIGURATION', label: 'Configuration', aliases: ['CONFIGURATION'] },
  { key: 'TRAFFIC_ANALYSIS', label: 'Traffic Analysis', aliases: ['TRAFFIC_ANALYSIS', 'BEHAVIORAL'] },
];

export function CategoryDistributionChart({
  distribution,
  total,
}: CategoryDistributionChartProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs text-text-secondary">
        <span className="font-medium">Findings by Security Category</span>
        <span className="font-mono text-text-primary">{CATEGORY_DEFINITIONS.length} Categories</span>
      </div>

      <div className="space-y-2.5">
        {CATEGORY_DEFINITIONS.map(({ key, aliases }) => {
          const count = aliases.reduce((sum, alias) => sum + (distribution[alias] || 0), 0);
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;

          return (
            <div key={key} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <CategoryBadge category={key} className="py-0 px-1.5 text-[10px]" />
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
