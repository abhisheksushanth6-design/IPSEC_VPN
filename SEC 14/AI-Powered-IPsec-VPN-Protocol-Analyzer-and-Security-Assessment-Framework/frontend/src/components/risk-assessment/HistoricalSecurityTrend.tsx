import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { History } from 'lucide-react';
import { EmptyChartState } from '@/components/dashboard/EmptyChartState';
import {
  axisProps,
  chartColors,
  formatTime,
} from '@/components/dashboard/charts/chartTheme';
import type { RiskAssessmentResponse } from '@/types/risk';
import { cn } from '@/utils/cn';

interface HistoricalSecurityTrendProps {
  assessments: RiskAssessmentResponse[];
  className?: string;
}

export function HistoricalSecurityTrend({
  assessments,
  className,
}: HistoricalSecurityTrendProps) {
  const colors = chartColors();

  // If assessments has more than 1 point, sort by evaluated_at and plot trend
  const hasHistory = Array.isArray(assessments) && assessments.length > 1;

  if (!hasHistory) {
    return (
      <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-3 shadow-sm', className)}>
        <div className="flex items-center justify-between border-b border-border/60 pb-2">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-info" />
            <h3 className="text-xs font-semibold text-primary">Historical Security Posture Trend</h3>
          </div>
          <span className="font-mono text-2xs text-muted">Audited Over Time</span>
        </div>
        <EmptyChartState
          message="NO HISTORICAL AUDIT TIMELINE YET"
          detail="Historical posture trend graphs will visualize multi-session risk fluctuations as repetitive captures and automated re-evaluations occur."
        />
      </div>
    );
  }

  // Format real assessment timeline data
  const data = assessments
    .slice()
    .sort((a, b) => new Date(a.evaluated_at).getTime() - new Date(b.evaluated_at).getTime())
    .map((a) => ({
      timestamp: a.evaluated_at,
      score: a.risk_score,
      session: a.session_id,
      level: a.risk_level,
    }));

  const customTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const p = payload[0].payload;
      return (
        <div className="rounded border border-border bg-elevated/95 p-2.5 shadow-xl text-xs font-mono space-y-1">
          <div className="text-muted border-b border-border pb-1">
            TIMESTAMP: {formatTime(p.timestamp)}
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-secondary">Session:</span>
            <span className="font-bold text-primary">{p.session}</span>
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-secondary">Risk Score:</span>
            <span className="font-bold text-rose-400">{p.score.toFixed(1)} / 100</span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-3 shadow-sm', className)}>
      <div className="flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-info" />
          <h3 className="text-xs font-semibold text-primary">Historical Security Posture Trend</h3>
        </div>
        <span className="font-mono text-2xs text-muted">
          {data.length} Audit Points Captured
        </span>
      </div>

      <div className="h-44 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <defs>
              <linearGradient id="riskHistoryGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#F43F5E" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke={colors.grid} strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke={colors.axis} {...axisProps} />
            <YAxis stroke={colors.axis} {...axisProps} domain={[0, 100]} />
            <Tooltip content={customTooltip} />
            <Area
              type="monotone"
              dataKey="score"
              name="Risk Score"
              stroke="#F43F5E"
              fill="url(#riskHistoryGradient)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
