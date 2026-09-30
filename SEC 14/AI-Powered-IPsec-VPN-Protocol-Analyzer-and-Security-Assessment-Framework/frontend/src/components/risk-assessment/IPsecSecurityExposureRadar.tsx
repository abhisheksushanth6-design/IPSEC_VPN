import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { ShieldAlert, Compass } from 'lucide-react';
import { chartColors } from '@/components/dashboard/charts/chartTheme';
import type { RiskAssessmentResponse } from '@/types/risk';
import { cn } from '@/utils/cn';

interface IPsecSecurityExposureRadarProps {
  assessment: RiskAssessmentResponse | null;
  className?: string;
}

export function IPsecSecurityExposureRadar({
  assessment,
  className,
}: IPsecSecurityExposureRadarProps) {
  const colors = chartColors();

  if (!assessment || !assessment.breakdown) {
    return (
      <div className={cn('rounded-lg border border-border bg-surface p-4 text-xs text-muted flex flex-col items-center justify-center min-h-[260px]', className)}>
        <Compass className="h-8 w-8 text-muted mb-2 animate-pulse" />
        <span className="font-semibold text-primary">No Active Session Selected</span>
        <p className="text-2xs text-muted text-center mt-1 max-w-xs">
          Select a session from the table below to inspect its multi-dimensional IPsec exposure radar.
        </p>
      </div>
    );
  }

  // Derive scores strictly from backend breakdown fields
  // Breakdown: vulnerability_score (max 50), ml_score (max 30), drift_score (max 12), state_score (max 8)
  const b = assessment.breakdown;
  const cryptoRisk = Math.min(100, Math.round((b.vulnerability_score / 50) * 100));
  const mlTimingRisk = Math.min(100, Math.round((b.ml_score / 30) * 100));
  const driftRisk = Math.min(100, Math.round((b.drift_score / 12) * 100));
  const saStateRisk = Math.min(100, Math.round((b.state_score / 8) * 100));
  const compositeRisk = Math.round(assessment.risk_score);

  // Check replay & metadata signals from contributing signals
  const hasReplaySignal = assessment.contributing_signals?.some((s) =>
    s.reason.toLowerCase().includes('replay') || s.reason.toLowerCase().includes('sequence')
  );
  const replayRisk = hasReplaySignal ? 80 : 15;

  const radarData = [
    {
      dimension: 'Cryptographic Rules',
      exposure: cryptoRisk,
      fullMark: 100,
      detail: `${b.vulnerability_score.toFixed(1)} / 50 sub-score`,
    },
    {
      dimension: 'SA State Security',
      exposure: saStateRisk,
      fullMark: 100,
      detail: `${b.state_score.toFixed(1)} / 8 sub-score`,
    },
    {
      dimension: 'Replay & Seq Integrity',
      exposure: replayRisk,
      fullMark: 100,
      detail: hasReplaySignal ? 'Replay anomalies detected' : 'Normal sequence progression',
    },
    {
      dimension: 'Traffic Flow & Timing',
      exposure: mlTimingRisk,
      fullMark: 100,
      detail: `${b.ml_score.toFixed(1)} / 30 ML anomaly`,
    },
    {
      dimension: 'Protocol Deviation',
      exposure: driftRisk,
      fullMark: 100,
      detail: `${b.drift_score.toFixed(1)} / 12 drift score`,
    },
    {
      dimension: 'Overall Composite Risk',
      exposure: compositeRisk,
      fullMark: 100,
      detail: `${compositeRisk} / 100 composite`,
    },
  ];

  const customTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const p = payload[0].payload;
      return (
        <div className="rounded border border-border bg-elevated/95 p-2.5 shadow-xl text-xs font-mono space-y-1">
          <div className="font-bold text-info border-b border-border pb-1">
            {p.dimension}
          </div>
          <div className="text-primary font-bold">
            Exposure Level: {p.exposure} / 100
          </div>
          <div className="text-2xs text-muted">Evidence: {p.detail}</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-3 shadow-sm', className)}>
      <div className="flex items-center justify-between border-b border-border/60 pb-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-info" />
          <h3 className="text-xs font-semibold text-primary">IPsec Security Exposure Radar</h3>
        </div>
        <span className="font-mono text-2xs text-muted truncate max-w-[140px]">
          {assessment.session_id}
        </span>
      </div>

      <div className="h-56 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radarData}>
            <PolarGrid stroke={colors.grid} strokeDasharray="2 4" />
            <PolarAngleAxis
              dataKey="dimension"
              tick={{ fill: colors.text, fontSize: 10 }}
            />
            <PolarRadiusAxis
              angle={30}
              domain={[0, 100]}
              tick={{ fill: colors.axis, fontSize: 8 }}
              stroke={colors.axis}
            />
            <Radar
              name="Exposure"
              dataKey="exposure"
              stroke="#0EA5E9"
              fill="#0EA5E9"
              fillOpacity={0.25}
              strokeWidth={2}
            />
            <Tooltip content={customTooltip} />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center justify-between rounded border border-border/50 bg-background/50 px-3 py-1.5 text-2xs font-mono text-muted">
        <span>Evaluated from Empirical Signals:</span>
        <span className="text-primary font-bold">{assessment.available_signals?.length ?? 0} Layers</span>
      </div>
    </div>
  );
}
