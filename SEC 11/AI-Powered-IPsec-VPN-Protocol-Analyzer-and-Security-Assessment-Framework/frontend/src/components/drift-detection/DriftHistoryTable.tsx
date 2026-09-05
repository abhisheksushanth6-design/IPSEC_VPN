import { ChevronRight, History } from 'lucide-react';
import { DriftSeverityBadge, DriftStatusBadge } from './DriftStatusBadge';
import type { DriftAnalysisSummary } from '@/types';

interface DriftHistoryTableProps {
  history: DriftAnalysisSummary[];
  selectedId: string | null;
  onSelect: (analysisId: string) => void;
}

export function DriftHistoryTable({ history, selectedId, onSelect }: DriftHistoryTableProps) {
  if (history.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center">
        <History className="h-8 w-8 text-muted mb-2 opacity-50" />
        <h3 className="text-sm font-semibold text-text-primary">No Drift History Available</h3>
        <p className="text-xs text-muted max-w-sm mt-1">
          No historical drift evaluations recorded yet. Run drift analysis on observed sessions to build audit history.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-muted/50 text-2xs uppercase tracking-wider text-muted">
            <th className="py-2.5 px-4">Analysis Time</th>
            <th className="py-2.5 px-4">Analysis ID</th>
            <th className="py-2.5 px-4">Target Session</th>
            <th className="py-2.5 px-4">Reference Baseline</th>
            <th className="py-2.5 px-4 text-center">Features Drifting</th>
            <th className="py-2.5 px-4 text-center">Overall Status</th>
            <th className="py-2.5 px-4 text-center">Severity</th>
            <th className="py-2.5 px-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {history.map((item) => {
            const isSelected = selectedId === item.id;
            return (
              <tr
                key={item.id}
                onClick={() => onSelect(item.id)}
                className={`group cursor-pointer transition ${
                  isSelected ? 'bg-cyan-500/10 hover:bg-cyan-500/15' : 'hover:bg-surface-muted/40'
                }`}
              >
                <td className="py-3 px-4 text-muted text-2xs whitespace-nowrap">
                  {new Date(item.analyzed_at).toLocaleString()}
                </td>

                <td className="py-3 px-4 font-mono font-semibold text-text-primary group-hover:text-cyan-400 transition">
                  {item.id}
                </td>

                <td className="py-3 px-4 font-mono text-text-secondary">
                  {item.session_id}
                </td>

                <td className="py-3 px-4 font-mono text-2xs text-muted">
                  {item.baseline_id} (v{item.baseline_version})
                </td>

                <td className="py-3 px-4 text-center font-mono text-2xs">
                  <span
                    className={`font-semibold ${
                      item.features_drifting > 0 ? 'text-amber-400' : 'text-emerald-400'
                    }`}
                  >
                    {item.features_drifting}
                  </span>
                  <span className="text-muted"> / {item.features_analyzed}</span>
                </td>

                <td className="py-3 px-4 text-center">
                  <DriftStatusBadge status={item.status} />
                </td>

                <td className="py-3 px-4 text-center">
                  <DriftSeverityBadge severity={item.severity} />
                </td>

                <td className="py-3 px-4 text-right">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect(item.id);
                    }}
                    className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-2xs font-medium transition ${
                      isSelected
                        ? 'bg-cyan-600 text-white'
                        : 'border border-border bg-surface text-text-secondary hover:bg-surface-muted hover:text-cyan-400'
                    }`}
                  >
                    <span>Load</span>
                    <ChevronRight className="h-3 w-3" />
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
