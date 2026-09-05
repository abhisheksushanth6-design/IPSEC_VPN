import { FileText, ShieldCheck } from 'lucide-react';
import type { AnomalyFeatureContribution } from '@/types';

interface AnomalyExplanationProps {
  summary: string;
  contributions: AnomalyFeatureContribution[];
  isAnomalous?: boolean;
}

export function AnomalyExplanation({
  summary,
  contributions,
}: AnomalyExplanationProps) {
  const topDeviations = contributions.filter((c) => c.direction !== 'WITHIN_RANGE');

  return (
    <div className="rounded-lg border border-border bg-surface p-5 space-y-4">
      <div className="flex items-center gap-2 pb-3 border-b border-border/60">
        <div className="p-1.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
          <FileText className="h-4 w-4" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider">
            WHY THIS SESSION WAS FLAGGED
          </h3>
          <span className="text-3xs text-muted font-mono">
            Model-based feature deviation evidence
          </span>
        </div>
      </div>

      {/* Summary Narrative */}
      <div className="rounded border border-border/80 bg-base p-3.5 text-xs text-text-primary leading-relaxed">
        {summary}
      </div>

      {/* Top Evidence Cards */}
      {topDeviations.length > 0 ? (
        <div>
          <h4 className="text-2xs font-bold uppercase tracking-wider text-muted mb-2 font-mono">
            Primary Contributing Evidence ({topDeviations.length})
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {topDeviations.slice(0, 4).map((c) => (
              <div
                key={c.feature_name}
                className="rounded border border-border/80 bg-base/80 p-3 flex flex-col justify-between space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-xs font-bold text-text-primary block">
                      {c.display_name}
                    </span>
                    <span className="text-3xs font-mono text-muted uppercase">
                      Category: {c.category}
                    </span>
                  </div>
                  <span
                    className={`text-3xs font-mono font-bold px-2 py-0.5 rounded border ${
                      c.direction === 'ABOVE_REFERENCE'
                        ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    }`}
                  >
                    {c.direction === 'ABOVE_REFERENCE' ? 'ELEVATED (+)' : 'DEPRESSED (-)'}
                  </span>
                </div>

                <p className="text-2xs text-text-secondary leading-normal">
                  {c.evidence_description}
                </p>

                <div className="flex items-center justify-between text-3xs text-muted pt-2 border-t border-border/40 font-mono">
                  <span>Deviation: <strong className="text-text-primary">{c.deviation !== null && c.deviation !== undefined ? `${c.deviation > 0 ? '+' : ''}${c.deviation.toFixed(2)}σ` : '—'}</strong></span>
                  <span>Contribution: <strong className="text-rose-400">{c.contribution_score.toFixed(1)}%</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-2 rounded border border-emerald-500/20 bg-emerald-500/5 p-3 text-xs text-emerald-300">
          <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>
            No individual features exceed the statistical deviation threshold (&gt;1.5σ) relative to the learned reference population.
          </span>
        </div>
      )}
    </div>
  );
}
