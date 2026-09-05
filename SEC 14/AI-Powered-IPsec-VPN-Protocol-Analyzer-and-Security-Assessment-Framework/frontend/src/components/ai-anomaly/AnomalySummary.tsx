import { AnomalyScore } from './AnomalyScore';
import { AnomalyClassificationBanner } from './AnomalyClassification';
import type { AnomalyAnalysis } from '@/types';

interface AnomalySummaryProps {
  analysis: AnomalyAnalysis;
}

export function AnomalySummary({ analysis }: AnomalySummaryProps) {
  const analyzedDate = new Date(analysis.analyzed_at).toLocaleString();

  return (
    <div className="space-y-4">
      {/* Classification Banner */}
      <AnomalyClassificationBanner
        classification={analysis.classification}
        featuresAnomalous={analysis.features_anomalous}
        featuresAnalyzed={analysis.features_analyzed}
      />

      {/* Grid: Anomaly Score & Metadata Lineage */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <AnomalyScore
            score={analysis.display_score}
            rawScore={analysis.raw_score}
          />
        </div>

        <div className="rounded-lg border border-border bg-base p-4 flex flex-col justify-between space-y-3 text-xs font-mono">
          <div>
            <span className="text-2xs uppercase tracking-wider text-muted font-bold block mb-2 font-sans">
              ANALYSIS METADATA
            </span>

            <div className="space-y-2 text-2xs">
              <div>
                <span className="text-muted block">Target Session:</span>
                <strong className="text-text-primary text-xs">{analysis.session_id}</strong>
              </div>
              <div>
                <span className="text-muted block">Model Evaluated:</span>
                <span className="text-cyan-400 font-bold">{analysis.model_id}</span>
                <span className="text-muted"> (v{analysis.model_version})</span>
              </div>
              <div>
                <span className="text-muted block">Feature Schema:</span>
                <span className="text-text-secondary">v{analysis.feature_version} ({analysis.features_analyzed} features)</span>
              </div>
              <div>
                <span className="text-muted block">Analyzed Timestamp:</span>
                <span className="text-text-secondary font-sans">{analyzedDate}</span>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-border/60 text-3xs text-muted font-sans">
            Analysis Run ID: <span className="font-mono text-text-secondary">{analysis.id}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
