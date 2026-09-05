import { CheckCircle2, ChevronRight, Clock, Layers, Users } from 'lucide-react';
import { BaselineActiveBadge } from './BaselineStatusBadge';
import type { BaselineSummary } from '@/types';

interface BaselineTableProps {
  baselines: BaselineSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onActivate: (id: string) => void;
  activatingId?: string | null;
}

export function BaselineTable({
  baselines,
  selectedId,
  onSelect,
  onActivate,
  activatingId,
}: BaselineTableProps) {
  if (baselines.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center border-b border-border">
        <Layers className="h-8 w-8 text-muted mb-2 opacity-50" />
        <h3 className="text-sm font-semibold text-text-primary">No Baseline Profiles Generated</h3>
        <p className="text-xs text-muted max-w-sm mt-1">
          No baseline reference profiles have been built yet. Load packet observations and build a baseline to establish normal operational parameters.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-muted/50 text-2xs uppercase tracking-wider text-muted">
            <th className="py-2.5 px-4">Profile Name & ID</th>
            <th className="py-2.5 px-4">Status</th>
            <th className="py-2.5 px-4 text-center">Version</th>
            <th className="py-2.5 px-4 text-right">Sessions</th>
            <th className="py-2.5 px-4 text-right">Features</th>
            <th className="py-2.5 px-4">Created</th>
            <th className="py-2.5 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {baselines.map((baseline) => {
            const isSelected = selectedId === baseline.id;
            const isActivating = activatingId === baseline.id;

            return (
              <tr
                key={baseline.id}
                onClick={() => onSelect(baseline.id)}
                className={`group cursor-pointer transition ${
                  isSelected
                    ? 'bg-cyan-500/10 hover:bg-cyan-500/15'
                    : 'hover:bg-surface-muted/40'
                }`}
              >
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-text-primary group-hover:text-cyan-400 transition">
                      {baseline.name}
                    </span>
                    <BaselineActiveBadge isActive={baseline.is_active} />
                  </div>
                  <div className="mt-0.5 font-mono text-2xs text-muted">
                    {baseline.id}
                  </div>
                  {baseline.description && (
                    <div className="mt-0.5 text-2xs text-muted truncate max-w-md">
                      {baseline.description}
                    </div>
                  )}
                </td>

                <td className="py-3 px-4">
                  <span
                    className={`inline-flex items-center rounded px-2 py-0.5 text-2xs font-medium uppercase tracking-wider ${
                      baseline.status === 'READY'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}
                  >
                    {baseline.status}
                  </span>
                </td>

                <td className="py-3 px-4 text-center">
                  <span className="rounded bg-surface-muted px-2 py-0.5 font-mono text-2xs font-semibold text-text-secondary border border-border">
                    v{baseline.version}
                  </span>
                </td>

                <td className="py-3 px-4 text-right font-mono text-xs text-text-secondary">
                  <span className="inline-flex items-center gap-1">
                    <Users className="h-3 w-3 text-muted" />
                    {baseline.session_count}
                  </span>
                </td>

                <td className="py-3 px-4 text-right font-mono text-xs text-text-secondary">
                  <span className="inline-flex items-center gap-1">
                    <Layers className="h-3 w-3 text-muted" />
                    {baseline.feature_count}
                  </span>
                </td>

                <td className="py-3 px-4 text-muted text-2xs whitespace-nowrap">
                  <span className="inline-flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(baseline.created_at).toLocaleString()}
                  </span>
                </td>

                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                    {!baseline.is_active && (
                      <button
                        type="button"
                        onClick={() => onActivate(baseline.id)}
                        disabled={isActivating}
                        className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2.5 py-1 text-2xs font-medium text-text-secondary hover:border-cyan-500 hover:text-cyan-400 transition disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-3 w-3" />
                        {isActivating ? 'Activating...' : 'Set Active'}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onSelect(baseline.id)}
                      className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-2xs font-medium transition ${
                        isSelected
                          ? 'bg-cyan-600 text-white hover:bg-cyan-500'
                          : 'border border-border bg-surface text-text-secondary hover:bg-surface-muted'
                      }`}
                    >
                      <span>Inspect</span>
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
