import { useMemo } from 'react';
import { Grid } from 'lucide-react';
import { cn } from '@/utils/cn';
import type { RiskAssessmentResponse, RiskLevel } from '@/types/risk';

interface RiskDistributionMatrixProps {
  assessments: RiskAssessmentResponse[];
  onSelectCategory?: (category: string) => void;
  className?: string;
}

const CATEGORIES = [
  'CRYPTOGRAPHY',
  'INTEGRITY',
  'PROTOCOL_ANOMALY',
  'DATA_LEAKAGE',
  'TUNNEL_STATE',
] as const;

type FindingCategory = (typeof CATEGORIES)[number];

const SEVERITIES: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function RiskDistributionMatrix({
  assessments,
  onSelectCategory,
  className,
}: RiskDistributionMatrixProps) {
  // Aggregate finding occurrences across categories and severities from real evidence / contributing signals
  const matrix = useMemo(() => {
    const grid: Record<FindingCategory, Record<RiskLevel, number>> = {
      CRYPTOGRAPHY: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      INTEGRITY: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      PROTOCOL_ANOMALY: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      DATA_LEAKAGE: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      TUNNEL_STATE: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    };

    for (const a of assessments) {
      const level = a.risk_level;
      for (const sig of a.contributing_signals ?? []) {
        const reason = sig.reason.toUpperCase();
        let matchedCat: FindingCategory = 'PROTOCOL_ANOMALY';
        if (reason.includes('CRYPTO') || reason.includes('CIPHER') || reason.includes('3DES') || reason.includes('DES')) {
          matchedCat = 'CRYPTOGRAPHY';
        } else if (reason.includes('INTEGRITY') || reason.includes('HMAC') || reason.includes('HASH')) {
          matchedCat = 'INTEGRITY';
        } else if (reason.includes('LEAK') || reason.includes('METADATA') || reason.includes('PADDING')) {
          matchedCat = 'DATA_LEAKAGE';
        } else if (reason.includes('STATE') || reason.includes('REKEY') || reason.includes('LIFETIME')) {
          matchedCat = 'TUNNEL_STATE';
        }
        grid[matchedCat][level]++;
      }
    }
    return grid;
  }, [assessments]);

  const getCellColor = (count: number, level: RiskLevel) => {
    if (count === 0) return 'bg-background/40 text-muted border-border/40';
    if (level === 'CRITICAL') return 'bg-rose-500/25 text-rose-300 border-rose-500/50 font-bold';
    if (level === 'HIGH') return 'bg-orange-500/25 text-orange-300 border-orange-500/50 font-bold';
    if (level === 'MEDIUM') return 'bg-amber-500/25 text-amber-300 border-amber-500/50 font-bold';
    return 'bg-emerald-500/25 text-emerald-300 border-emerald-500/50 font-bold';
  };

  return (
    <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-3 shadow-sm', className)}>
      <div className="flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-2">
          <Grid className="h-4 w-4 text-info" />
          <h3 className="text-xs font-semibold text-primary">Risk Distribution Matrix</h3>
        </div>
        <span className="text-2xs font-mono text-muted">Category × Severity Breakdown</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-border/60 text-[10px] text-muted uppercase">
              <th className="py-1.5 px-2">Finding Domain</th>
              {SEVERITIES.map((sev) => (
                <th key={sev} className="py-1.5 px-2 text-center">
                  {sev}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40 text-2xs">
            {CATEGORIES.map((cat) => (
              <tr
                key={cat}
                onClick={() => onSelectCategory && onSelectCategory(cat)}
                className="cursor-pointer hover:bg-elevated/40 transition-colors"
              >
                <td className="py-2 px-2 font-medium text-primary flex items-center gap-1.5 truncate">
                  <span className="h-1.5 w-1.5 rounded-full bg-info" />
                  {cat.replace(/_/g, ' ')}
                </td>
                {SEVERITIES.map((sev) => {
                  const count = matrix[cat][sev] ?? 0;
                  return (
                    <td key={sev} className="py-1 px-2 text-center">
                      <span
                        className={cn(
                          'inline-block min-w-[28px] rounded border px-1.5 py-0.5 text-center transition-all',
                          getCellColor(count, sev)
                        )}
                      >
                        {count}
                      </span>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-[10px] text-muted font-mono pt-1">
        <span>Click any row to filter findings</span>
        <span>Aggregated across {assessments.length} evaluated sessions</span>
      </div>
    </div>
  );
}
