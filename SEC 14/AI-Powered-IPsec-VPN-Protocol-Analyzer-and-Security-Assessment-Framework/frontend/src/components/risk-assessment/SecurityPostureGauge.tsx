import { Shield, ShieldAlert, ShieldCheck, ShieldX, AlertTriangle, Clock } from 'lucide-react';
import type { PolicyDecision, RiskLevel } from '@/types/risk';
import { cn } from '@/utils/cn';

interface SecurityPostureGaugeProps {
  score: number | null | undefined;
  level: RiskLevel | null | undefined;
  decision?: PolicyDecision | null;
  assessedSessionsCount: number;
  totalSessionsCount: number;
  findingsCount?: number;
  confidenceScore?: number;
  dataQuality?: string | null;
  timestamp?: string;
  className?: string;
}

export function SecurityPostureGauge({
  score,
  level,
  decision,
  assessedSessionsCount,
  totalSessionsCount,
  findingsCount = 0,
  confidenceScore = 1.0,
  dataQuality = 'COMPLETE',
  timestamp,
  className,
}: SecurityPostureGaugeProps) {
  const numScore = score != null ? Math.max(0, Math.min(100, score)) : null;

  // Colors based on risk level
  const getColors = () => {
    if (numScore == null) return { stroke: '#64748B', fill: 'text-muted', badge: 'bg-muted/10 text-muted border-border' };
    if (numScore >= 70)
      return { stroke: '#F43F5E', fill: 'text-rose-500', badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30' };
    if (numScore >= 50)
      return { stroke: '#FB923C', fill: 'text-orange-400', badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30' };
    if (numScore >= 25)
      return { stroke: '#FBBF24', fill: 'text-amber-400', badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30' };
    return { stroke: '#10B981', fill: 'text-emerald-400', badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' };
  };

  const colors = getColors();

  // SVG Gauge calculations (radius = 54, strokeWidth = 8, circumference = 2 * PI * r)
  const radius = 54;
  const strokeWidth = 8;
  const circumference = 2 * Math.PI * radius;
  // Use a 270 degree arc (3/4 of a circle)
  const arcLength = circumference * 0.75;
  const strokeDashoffset = numScore != null ? arcLength - (arcLength * numScore) / 100 : arcLength;

  return (
    <div className={cn('relative flex flex-col items-center justify-between rounded-lg border border-border bg-surface p-5 shadow-sm', className)}>
      {/* Gauge Title */}
      <div className="w-full flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-1.5">
          <Shield className="h-4 w-4 text-info" />
          <span className="text-xs font-semibold text-primary">IPsec Security Posture</span>
        </div>
        <span className="font-mono text-2xs text-muted">Layer 09 Engine</span>
      </div>

      {/* Circular Gauge Canvas */}
      <div className="relative my-3 flex items-center justify-center">
        <svg width="150" height="150" className="transform -rotate-135">
          {/* Background Track Arc */}
          <circle
            cx="75"
            cy="75"
            r={radius}
            fill="transparent"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            className="text-border/60"
            strokeLinecap="round"
          />
          {/* Active Value Arc */}
          {numScore != null && (
            <circle
              cx="75"
              cy="75"
              r={radius}
              fill="transparent"
              stroke={colors.stroke}
              strokeWidth={strokeWidth}
              strokeDasharray={`${arcLength} ${circumference}`}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              className="transition-all duration-700 ease-out"
            />
          )}
        </svg>

        {/* Center Score Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={cn('font-mono text-3xl font-extrabold tracking-tight', numScore != null ? colors.fill : 'text-muted')}>
            {numScore != null ? numScore.toFixed(1) : '—'}
          </span>
          <span className="font-mono text-[10px] text-muted uppercase">Risk Score / 100</span>
          {level && (
            <span className={cn('mt-1 rounded border px-2 py-0.5 font-mono text-[9px] font-bold uppercase', colors.badge)}>
              {level} RISK
            </span>
          )}
        </div>
      </div>

      {/* Decision & Findings Readouts */}
      <div className="w-full space-y-2.5 pt-2 border-t border-border/60">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted">Policy Decision:</span>
          {decision ? (
            <span
              className={cn(
                'inline-flex items-center gap-1 rounded border px-2 py-0.5 text-2xs font-mono font-bold uppercase',
                decision === 'TERMINATE'
                  ? 'border-rose-500/40 bg-rose-500/10 text-rose-400'
                  : decision === 'RESTRICT'
                  ? 'border-orange-500/40 bg-orange-500/10 text-orange-400'
                  : decision === 'INSPECT'
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-400'
                  : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
              )}
            >
              {decision === 'TERMINATE' ? (
                <ShieldX className="h-3 w-3" />
              ) : decision === 'RESTRICT' ? (
                <ShieldAlert className="h-3 w-3" />
              ) : decision === 'INSPECT' ? (
                <AlertTriangle className="h-3 w-3" />
              ) : (
                <ShieldCheck className="h-3 w-3" />
              )}
              {decision}
            </span>
          ) : (
            <span className="text-muted font-mono text-2xs">READY</span>
          )}
        </div>

        <div className="flex items-center justify-between text-2xs font-mono text-muted">
          <span>Coverage &amp; Quality:</span>
          <span className="text-primary font-bold">
            {assessedSessionsCount} / {totalSessionsCount} • {dataQuality} ({Math.round(confidenceScore * 100)}%)
          </span>
        </div>

        {findingsCount > 0 && (
          <div className="flex items-center justify-between text-2xs font-mono text-muted">
            <span>Findings Evaluated:</span>
            <span className="text-info font-bold">{findingsCount} items</span>
          </div>
        )}

        {timestamp && (
          <div className="flex items-center justify-between text-[10px] font-mono text-muted border-t border-border/40 pt-1.5">
            <span className="flex items-center gap-1">
              <Clock className="h-2.5 w-2.5" /> Evaluated
            </span>
            <span className="truncate max-w-[130px]">{new Date(timestamp).toLocaleTimeString()}</span>
          </div>
        )}
      </div>
    </div>
  );
}
