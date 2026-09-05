import { AlertOctagon, CheckCircle2, ShieldAlert } from 'lucide-react';
import { AnomalyClassificationBadge } from './ModelStatusBadge';
import type { AnomalyClassification as AnomalyClassificationType } from '@/types';

interface AnomalyClassificationBannerProps {
  classification: AnomalyClassificationType;
  featuresAnomalous: number;
  featuresAnalyzed: number;
}

export function AnomalyClassificationBanner({
  classification,
  featuresAnomalous,
  featuresAnalyzed,
}: AnomalyClassificationBannerProps) {
  const isAnomalous = classification === 'ANOMALOUS';

  return (
    <div
      className={`rounded-lg border p-5 transition ${
        isAnomalous
          ? 'border-rose-500/40 bg-gradient-to-r from-rose-500/10 via-surface to-surface'
          : 'border-emerald-500/30 bg-gradient-to-r from-emerald-500/10 via-surface to-surface'
      }`}
    >
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <div
            className={`p-2.5 rounded-md border shrink-0 ${
              isAnomalous
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-400'
                : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
            }`}
          >
            {isAnomalous ? (
              <AlertOctagon className="h-6 w-6 animate-pulse" />
            ) : (
              <CheckCircle2 className="h-6 w-6" />
            )}
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <AnomalyClassificationBadge classification={classification} size="lg" />
              <span className="text-2xs text-muted font-mono">
                ({featuresAnomalous} of {featuresAnalyzed} features divergent)
              </span>
            </div>

            <h3 className="text-base font-bold text-text-primary">
              {isAnomalous
                ? 'MODEL ANOMALY DETECTED'
                : 'SESSION WITHIN LEARNED MODEL PROFILE'}
            </h3>

            <p className="text-xs text-text-secondary max-w-2xl leading-relaxed">
              {isAnomalous
                ? 'The observed behavioral feature vector deviates substantially from the learned reference cluster. Isolation Forest isolated this observation in significantly fewer partitioning steps.'
                : 'The observed behavioral feature vector conforms closely to the high-density distribution of the learned reference cluster.'}
            </p>
          </div>
        </div>
      </div>

      {/* Critical Distinction Notice (Section 38 & 64) */}
      <div className="mt-4 pt-3 border-t border-border/60 flex items-start gap-2 rounded bg-base/70 px-3 py-2 text-2xs text-muted border border-border/80">
        <ShieldAlert className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-text-primary">CRITICAL ANALYTICAL DISTINCTION: </strong>
          <span className="text-text-secondary">
            {isAnomalous
              ? 'ANOMALOUS signifies that observed behavioral metrics differ unusually from reference patterns. It does NOT automatically denote an attack, malware, compromised tunnel, or security vulnerability. Formal security scoring belongs to downstream layers.'
              : 'NORMAL signifies that observed behavioral metrics match learned reference clusters. It is an unsupervised statistical assessment and does not prove the absence of encrypted threats.'}
          </span>
        </div>
      </div>
    </div>
  );
}

export const AnomalyClassification = AnomalyClassificationBanner;

