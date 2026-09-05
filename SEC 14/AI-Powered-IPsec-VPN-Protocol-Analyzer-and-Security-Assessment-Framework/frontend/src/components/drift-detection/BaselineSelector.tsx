import { ChevronDown, Database } from 'lucide-react';
import type { BaselineSummary } from '@/types';

interface BaselineSelectorProps {
  baselines: BaselineSummary[];
  selectedBaselineId: string | null;
  onSelect: (baselineId: string) => void;
  disabled?: boolean;
}

export function BaselineSelector({
  baselines,
  selectedBaselineId,
  onSelect,
  disabled,
}: BaselineSelectorProps) {
  if (baselines.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-border bg-surface-muted/40 px-3 py-1.5 text-xs text-muted">
        <Database className="h-3.5 w-3.5" />
        <span>No reference baselines available</span>
      </div>
    );
  }

  return (
    <div className="relative inline-flex items-center">
      <Database className="absolute left-2.5 h-3.5 w-3.5 text-cyan-400 pointer-events-none" />
      <select
        value={selectedBaselineId ?? ''}
        onChange={(e) => onSelect(e.target.value)}
        disabled={disabled}
        className="appearance-none rounded-md border border-border bg-surface pl-8 pr-8 py-1.5 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none transition cursor-pointer disabled:opacity-50"
      >
        <option value="" disabled>
          Select Reference Baseline...
        </option>
        {baselines.map((b) => (
          <option key={b.id} value={b.id}>
            {b.name} (v{b.version}) {b.is_active ? '★ ACTIVE' : ''}
          </option>
        ))}
      </select>
      <ChevronDown className="absolute right-2.5 h-3.5 w-3.5 text-muted pointer-events-none" />
    </div>
  );
}
