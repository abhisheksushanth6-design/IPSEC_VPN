import { RISK_BANDS, RISK_SCORE_MAX } from '@/config/risk';
import { classifyRiskScore } from '@/config/risk';
import { cn } from '@/utils/cn';
import type { RiskClassification, StatusKind } from '@/types';

interface RiskGaugeProps {
  /** 0–100. When undefined the gauge renders in its uninitialised state. */
  riskScore?: number;
  /** Overrides the derived classification label. */
  riskLabel?: string;
  /** Status to show when there is no score. */
  status?: StatusKind;
  size?: number;
  className?: string;
}

const BAND_TONE: Record<RiskClassification, string> = {
  SAFE: 'text-success',
  LOW: 'text-info',
  MODERATE: 'text-warning',
  HIGH: 'text-warning',
  CRITICAL: 'text-danger',
};

// Semicircle from 180° to 360° (left to right over the top).
const START_ANGLE = 180;
const SWEEP = 180;

function polar(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = (angleDeg * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(cx: number, cy: number, r: number, from: number, to: number) {
  const a = polar(cx, cy, r, from);
  const b = polar(cx, cy, r, to);
  const large = to - from > 180 ? 1 : 0;
  return `M ${a.x} ${a.y} A ${r} ${r} 0 ${large} 1 ${b.x} ${b.y}`;
}

/**
 * Semicircular risk meter. The five classification bands are drawn as a
 * quiet track; a needle and value appear only when a real score is supplied.
 */
export function RiskGauge({
  riskScore,
  riskLabel,
  status = 'NOT INITIALIZED',
  size = 240,
  className,
}: RiskGaugeProps) {
  const hasScore = typeof riskScore === 'number' && Number.isFinite(riskScore);
  const classification = hasScore ? classifyRiskScore(riskScore) : null;
  const label = riskLabel ?? classification ?? status;

  const width = size;
  const height = size * 0.58;
  const cx = width / 2;
  const cy = height - 8;
  const radius = width / 2 - 14;
  const stroke = 10;

  const needleAngle = hasScore
    ? START_ANGLE + (Math.min(Math.max(riskScore, 0), RISK_SCORE_MAX) / RISK_SCORE_MAX) * SWEEP
    : null;
  const needleTip = needleAngle !== null ? polar(cx, cy, radius - 6, needleAngle) : null;

  const description = hasScore
    ? `Overall risk score ${riskScore} of 100, classified ${classification ?? 'unknown'}.`
    : 'Overall risk gauge. No score is available because the risk engine is not initialised.';

  return (
    <figure className={cn('flex flex-col items-center', className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        style={{ maxWidth: width }}
        role="img"
        aria-label={description}
      >
        {/* Band track, subdivided so the classification scale is legible. */}
        {RISK_BANDS.map((band) => {
          const from = START_ANGLE + (band.min / RISK_SCORE_MAX) * SWEEP;
          const to = START_ANGLE + ((band.max + 1) / RISK_SCORE_MAX) * SWEEP;
          return (
            <path
              key={band.classification}
              d={arcPath(cx, cy, radius, from + 0.6, Math.min(to, 360) - 0.6)}
              fill="none"
              strokeWidth={stroke}
              strokeLinecap="butt"
              className={cn(
                'stroke-current transition-opacity',
                hasScore ? BAND_TONE[band.classification] : 'text-border',
              )}
              opacity={hasScore && classification === band.classification ? 1 : 0.35}
            />
          );
        })}

        {needleTip ? (
          <>
            <line
              x1={cx}
              y1={cy}
              x2={needleTip.x}
              y2={needleTip.y}
              strokeWidth={2}
              strokeLinecap="round"
              className="stroke-current text-primary"
            />
            <circle cx={cx} cy={cy} r={4} className="fill-current text-primary" />
          </>
        ) : (
          <circle
            cx={cx}
            cy={cy}
            r={4}
            className="fill-current text-border"
          />
        )}
      </svg>

      <figcaption className="-mt-1 flex flex-col items-center">
        <span
          className={cn(
            'font-mono text-3xl font-medium tabular-nums',
            hasScore ? 'text-primary' : 'text-muted',
          )}
        >
          {hasScore ? riskScore : '—'}
        </span>
        <span
          className={cn(
            'mt-1 text-xs font-medium',
            classification ? BAND_TONE[classification] : 'text-muted',
          )}
        >
          {label}
        </span>
      </figcaption>
    </figure>
  );
}
