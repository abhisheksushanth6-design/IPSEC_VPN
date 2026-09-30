import { Sparkles } from 'lucide-react';
import { cn } from '@/utils/cn';

interface ThreatSeverityConstellationProps {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  className?: string;
  onSelectSeverity?: (severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'ALL') => void;
  selectedSeverity?: string;
}

export function ThreatSeverityConstellation({
  criticalCount,
  highCount,
  mediumCount,
  lowCount,
  className,
  onSelectSeverity,
  selectedSeverity = 'ALL',
}: ThreatSeverityConstellationProps) {
  const total = criticalCount + highCount + mediumCount + lowCount;

  const bands = [
    {
      key: 'CRITICAL' as const,
      label: 'Critical',
      count: criticalCount,
      color: '#F43F5E',
      barColor: 'bg-rose-500',
      badge: 'border-rose-500/40 bg-rose-500/10 text-rose-400',
      description: 'Immediate compromise risk (deprecated ciphers, disabled integrity, open replay)',
    },
    {
      key: 'HIGH' as const,
      label: 'High',
      count: highCount,
      color: '#FB923C',
      barColor: 'bg-orange-500',
      badge: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
      description: 'Priority remediation (weak DH group, excessive SA lifetime, metadata exposure)',
    },
    {
      key: 'MEDIUM' as const,
      label: 'Medium',
      count: mediumCount,
      color: '#FBBF24',
      barColor: 'bg-amber-500',
      badge: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
      description: 'Hardening required (flow burst leakage, packet padding variance, rekey delays)',
    },
    {
      key: 'LOW' as const,
      label: 'Low',
      count: lowCount,
      color: '#10B981',
      barColor: 'bg-emerald-500',
      badge: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
      description: 'Minor deviation or informational security notice',
    },
  ];

  return (
    <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-3 shadow-sm', className)}>
      <div className="flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-info" />
          <h3 className="text-xs font-semibold text-primary">Threat Severity Constellation</h3>
        </div>
        <span className="font-mono text-2xs text-muted">
          {total} Total Finding{total === 1 ? '' : 's'}
        </span>
      </div>

      {/* Segmented Constellation Bar */}
      <div className="space-y-1.5">
        <div className="flex h-3.5 w-full overflow-hidden rounded-full bg-border/40 p-0.5">
          {total === 0 ? (
            <div className="h-full w-full rounded-full bg-emerald-500/30" />
          ) : (
            bands.map((b) => {
              if (b.count === 0) return null;
              const widthPct = Math.max(6, (b.count / total) * 100);
              return (
                <div
                  key={b.key}
                  style={{ width: `${widthPct}%` }}
                  className={cn(
                    'h-full transition-all duration-300 first:rounded-l-full last:rounded-r-full',
                    b.barColor,
                    selectedSeverity === b.key ? 'ring-2 ring-white ring-offset-1' : 'opacity-90 hover:opacity-100'
                  )}
                  title={`${b.label}: ${b.count} (${((b.count / total) * 100).toFixed(0)}%)`}
                />
              );
            })
          )}
        </div>
        <div className="flex justify-between text-[10px] font-mono text-muted">
          <span>CRITICAL DEFICIENCIES</span>
          <span>HARDENED BASELINE</span>
        </div>
      </div>

      {/* Interactive Severity Cards Grid */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 pt-1">
        {bands.map((band) => {
          const isSelected = selectedSeverity === band.key;
          return (
            <div
              key={band.key}
              onClick={() => onSelectSeverity && onSelectSeverity(isSelected ? 'ALL' : band.key)}
              className={cn(
                'cursor-pointer rounded-md border p-2.5 transition-all',
                band.badge,
                isSelected ? 'ring-1 ring-current font-bold' : 'hover:bg-elevated/40'
              )}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase font-bold">{band.label}</span>
                <span className="font-mono text-base font-extrabold">{band.count}</span>
              </div>
              <p className="mt-1 text-[9px] text-secondary line-clamp-2 leading-tight">
                {band.description}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
