import React from 'react';
import { X, TrendingUp, TrendingDown, Minus, Info } from 'lucide-react';
import { AnomalyFeatureContribution } from '../../types/mlAnomaly';

interface AnomalyEvidenceProps {
  feature: AnomalyFeatureContribution | null;
  isOpen: boolean;
  onClose: () => void;
}

export const AnomalyEvidence: React.FC<AnomalyEvidenceProps> = ({
  feature,
  isOpen,
  onClose,
}) => {
  if (!isOpen || !feature) return null;

  const zScore = feature.deviation ?? 0;
  const isElevated = feature.direction === 'ABOVE_REFERENCE';
  const isSuppressed = feature.direction === 'BELOW_REFERENCE';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full overflow-hidden shadow-2xl">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-indigo-500/10 text-indigo-400">
              <Info className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">Statistical Feature Evidence</h3>
              <p className="text-xs text-slate-400 font-mono">{feature.feature_name}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 space-y-5 text-sm">
          {/* Top Banner: Status & Contribution */}
          <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-950 border border-slate-800">
            <div>
              <div className="text-xs text-slate-400 font-medium">Deviation Status</div>
              <div className="flex items-center space-x-1.5 mt-0.5">
                {isElevated ? (
                  <>
                    <TrendingUp className="w-4 h-4 text-rose-400" />
                    <span className="text-rose-400 font-semibold font-mono text-xs">
                      Significantly Elevated (+{zScore.toFixed(2)}σ)
                    </span>
                  </>
                ) : isSuppressed ? (
                  <>
                    <TrendingDown className="w-4 h-4 text-amber-400" />
                    <span className="text-amber-400 font-semibold font-mono text-xs">
                      Significantly Suppressed ({zScore.toFixed(2)}σ)
                    </span>
                  </>
                ) : (
                  <>
                    <Minus className="w-4 h-4 text-emerald-400" />
                    <span className="text-emerald-400 font-semibold font-mono text-xs">
                      Within Normal Tolerance ({zScore.toFixed(2)}σ)
                    </span>
                  </>
                )}
              </div>
            </div>

            <div className="text-right">
              <div className="text-xs text-slate-400 font-medium">Anomaly Contribution</div>
              <div className="text-sm font-bold font-mono text-indigo-400 mt-0.5">
                {(feature.contribution_score * 100).toFixed(1)}%
              </div>
            </div>
          </div>

          {/* Factual Evidence Explanation */}
          <div>
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Explainable AI Finding
            </h4>
            <div className="p-3.5 rounded-xl bg-indigo-950/20 border border-indigo-900/40 text-slate-200 text-xs leading-relaxed font-sans">
              {feature.evidence_description}
            </div>
          </div>

          {/* Metric Comparison Grid */}
          <div>
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Distribution Diagnostics
            </h4>
            <div className="grid grid-cols-2 gap-2.5 font-mono text-xs">
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Observed Value</span>
                <span className="text-white font-bold text-sm">
                  {typeof feature.observed_value === 'number'
                    ? feature.observed_value.toLocaleString(undefined, { maximumFractionDigits: 3 })
                    : String(feature.observed_value)}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Baseline Mean (μ)</span>
                <span className="text-slate-300 font-medium text-sm">
                  {feature.reference_mean !== null && feature.reference_mean !== undefined
                    ? feature.reference_mean.toLocaleString(undefined, { maximumFractionDigits: 3 })
                    : 'N/A'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Baseline StdDev (σ)</span>
                <span className="text-slate-300 font-medium text-sm">
                  {feature.reference_std !== null && feature.reference_std !== undefined
                    ? feature.reference_std.toLocaleString(undefined, { maximumFractionDigits: 3 })
                    : 'N/A'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Standardized Z-Score</span>
                <span
                  className={`font-bold text-sm ${
                    Math.abs(zScore) >= 2.0
                      ? 'text-rose-400'
                      : Math.abs(zScore) >= 1.0
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {zScore > 0 ? `+${zScore.toFixed(2)}` : zScore.toFixed(2)}
                </span>
              </div>
            </div>
          </div>

          {/* Statistical Bounds Context */}
          <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] text-slate-400 space-y-1.5">
            <div className="flex items-center justify-between">
              <span>Category</span>
              <span className="font-mono text-slate-200">{feature.category}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Feature Type</span>
              <span className="font-mono text-slate-200">{feature.data_type}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Statistical Significance</span>
              <span className="font-mono text-slate-200">
                {Math.abs(zScore) >= 3.0
                  ? 'Extreme (> 3.0σ)'
                  : Math.abs(zScore) >= 2.0
                  ? 'High (> 2.0σ)'
                  : Math.abs(zScore) >= 1.0
                  ? 'Moderate (> 1.0σ)'
                  : 'Normal (< 1.0σ)'}
              </span>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/70 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
