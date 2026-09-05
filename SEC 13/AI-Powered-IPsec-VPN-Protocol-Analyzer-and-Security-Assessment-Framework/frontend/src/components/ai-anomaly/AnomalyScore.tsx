import { Info } from 'lucide-react';

interface AnomalyScoreProps {
  score: number;
  rawScore: number;
  threshold?: number;
}

export function AnomalyScore({ score, rawScore, threshold = 50.0 }: AnomalyScoreProps) {
  // Determine meter color
  let barColor = 'bg-emerald-500';
  let textColor = 'text-emerald-400';
  if (score >= 75) {
    barColor = 'bg-rose-500';
    textColor = 'text-rose-400';
  } else if (score >= 50) {
    barColor = 'bg-amber-500';
    textColor = 'text-amber-400';
  } else if (score >= 30) {
    barColor = 'bg-cyan-500';
    textColor = 'text-cyan-400';
  }

  return (
    <div className="rounded-lg border border-border bg-base p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-bold text-text-primary uppercase tracking-wider">
            Normalized Anomaly Score
          </span>
          <span className="text-2xs text-muted font-mono">(0 – 100)</span>
        </div>
        <div className="font-mono text-xl font-black">
          <span className={textColor}>{score.toFixed(1)}</span>
          <span className="text-xs text-muted font-normal"> / 100</span>
        </div>
      </div>

      {/* Visual Meter Bar */}
      <div className="relative h-3 w-full rounded-full bg-surface-hover/80 overflow-hidden border border-border/60">
        {/* Threshold indicator at 50% */}
        <div
          className="absolute top-0 bottom-0 w-0.5 bg-rose-500/60 z-10"
          style={{ left: '50%' }}
          title="Anomaly Threshold (50.0)"
        />
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>

      <div className="flex items-center justify-between text-3xs font-mono text-muted mt-1.5">
        <span>0 (Deep Inlier)</span>
        <span className="text-rose-400 font-semibold">Threshold: {threshold.toFixed(1)}</span>
        <span>100 (Extreme Outlier)</span>
      </div>

      {/* Mathematical Derivation & Semantics Box */}
      <div className="mt-3.5 pt-3 border-t border-border/60 space-y-1.5 text-2xs text-muted">
        <div className="flex items-center justify-between font-mono">
          <span>Raw Model Decision Score:</span>
          <strong className={rawScore < 0 ? 'text-rose-400' : 'text-emerald-400'}>
            {rawScore > 0 ? `+${rawScore.toFixed(4)}` : rawScore.toFixed(4)}
          </strong>
        </div>

        <div className="flex items-start gap-1.5 rounded bg-surface p-2 border border-border/60 text-3xs leading-relaxed">
          <Info className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <strong>Mathematical Derivation:</strong> Normalized via logistic transformation:{' '}
            <code className="text-cyan-300 font-mono">score = 100 / (1 + exp(10 × raw_score))</code>.
            Higher score = more anomalous relative to learned profile.
            <div className="text-amber-400/90 font-medium mt-0.5">
              Note: This score represents statistical distance from the reference distribution; it does NOT represent attack probability.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
