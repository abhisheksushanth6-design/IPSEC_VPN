import { ChevronRight } from 'lucide-react';
import { DriftSeverityBadge } from './DriftStatusBadge';
import type { FeatureDrift } from '@/types';

interface FeatureDriftRowProps {
  feature: FeatureDrift;
  isSelected: boolean;
  onSelect: (feature: FeatureDrift) => void;
}

export function FeatureDriftRow({ feature, isSelected, onSelect }: FeatureDriftRowProps) {
  let displayCurrent = '—';
  if (feature.current_value !== null) {
    if (typeof feature.current_value === 'boolean') {
      displayCurrent = feature.current_value ? 'TRUE' : 'FALSE';
    } else if (typeof feature.current_value === 'number') {
      displayCurrent = Number.isInteger(feature.current_value)
        ? feature.current_value.toLocaleString()
        : feature.current_value.toFixed(2);
    } else {
      displayCurrent = String(feature.current_value);
    }
  }

  let baselineSummary = '—';
  if (feature.data_type === 'NUMERIC') {
    if (typeof feature.baseline_mean === 'number') {
      const meanStr = feature.baseline_mean.toFixed(1);
      const stdStr = typeof feature.baseline_std === 'number' ? `±${feature.baseline_std.toFixed(1)}` : '';
      baselineSummary = `μ = ${meanStr} ${stdStr}`;
    }
  } else if (feature.data_type === 'CATEGORICAL') {
    baselineSummary = 'Distribution';
  } else if (feature.data_type === 'BOOLEAN') {
    const trueRatio = feature.baseline_distribution?.true_ratio;
    baselineSummary = trueRatio !== undefined ? `${Math.round(trueRatio * 100)}% TRUE` : 'Ratio';
  }

  let devStr = '—';
  if (typeof feature.deviation === 'number') {
    devStr = `${feature.deviation > 0 ? '+' : ''}${feature.deviation.toFixed(2)}`;
    if (typeof feature.z_score === 'number') {
      devStr += ` (z: ${feature.z_score.toFixed(1)})`;
    }
  }

  return (
    <tr
      onClick={() => onSelect(feature)}
      className={`group cursor-pointer transition ${
        isSelected
          ? 'bg-cyan-500/10 hover:bg-cyan-500/15'
          : feature.drift_detected
          ? 'bg-amber-500/5 hover:bg-surface-muted/50'
          : 'hover:bg-surface-muted/40'
      }`}
    >
      {/* Feature Name */}
      <td className="py-2.5 px-4">
        <div className="font-semibold text-text-primary group-hover:text-cyan-400 transition">
          {feature.display_name}
        </div>
        <div className="font-mono text-3xs text-muted">{feature.feature_name}</div>
      </td>

      {/* Category */}
      <td className="py-2.5 px-4">
        <span className="rounded bg-surface-muted px-2 py-0.5 text-2xs font-mono font-medium text-text-secondary border border-border">
          {feature.category}
        </span>
      </td>

      {/* Current Observed Value */}
      <td className="py-2.5 px-4 text-right font-mono text-text-primary font-semibold">
        {displayCurrent} {feature.unit ?? ''}
      </td>

      {/* Baseline Reference */}
      <td className="py-2.5 px-4 text-right font-mono text-2xs text-muted">
        {baselineSummary}
      </td>

      {/* Deviation */}
      <td
        className={`py-2.5 px-4 text-right font-mono text-2xs ${
          feature.drift_detected ? 'text-amber-400 font-bold' : 'text-muted'
        }`}
      >
        {devStr}
      </td>

      {/* Comparison Method */}
      <td className="py-2.5 px-4 text-center font-mono text-3xs text-muted">
        {feature.comparison_method.split(' ')[0]}
      </td>

      {/* Drift Flag */}
      <td className="py-2.5 px-4 text-center">
        <span
          className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-3xs font-mono font-bold ${
            feature.drift_detected
              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
          }`}
        >
          {feature.drift_detected ? 'DRIFT' : 'BASELINE'}
        </span>
      </td>

      {/* Severity */}
      <td className="py-2.5 px-4 text-center">
        <DriftSeverityBadge severity={feature.severity} />
      </td>

      {/* Action */}
      <td className="py-2.5 px-4 text-right">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onSelect(feature);
          }}
          className={`inline-flex items-center gap-1 rounded px-2 py-1 text-2xs font-medium transition ${
            isSelected
              ? 'bg-cyan-600 text-white'
              : 'border border-border bg-surface text-text-secondary hover:bg-surface-muted hover:text-cyan-400'
          }`}
        >
          <span>Inspect</span>
          <ChevronRight className="h-3 w-3" />
        </button>
      </td>
    </tr>
  );
}
