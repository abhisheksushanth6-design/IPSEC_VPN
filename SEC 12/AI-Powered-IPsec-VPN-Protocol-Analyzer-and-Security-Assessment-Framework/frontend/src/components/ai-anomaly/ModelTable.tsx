import { Cpu, Eye, Radio } from 'lucide-react';
import { ModelStatusBadge } from './ModelStatusBadge';
import type { MLModelSummary } from '@/types';

interface ModelTableProps {
  models: MLModelSummary[];
  selectedModelId?: string | null;
  onSelectModel: (modelId: string) => void | Promise<void>;
  onActivateModel: (modelId: string) => Promise<void>;
  activatingId?: string | null;
}

export function ModelTable({
  models,
  selectedModelId: _selectedModelId,
  onSelectModel,
  onActivateModel,
  activatingId,
}: ModelTableProps) {
  if (models.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-surface p-8 text-center">
        <Cpu className="h-8 w-8 text-muted mx-auto mb-2 opacity-50" />
        <h4 className="text-sm font-semibold text-text-primary">No Trained Models Registered</h4>
        <p className="text-xs text-text-secondary mt-1 max-w-sm mx-auto">
          Train a new model version using real session observations from an established baseline.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
      <div className="px-5 py-4 border-b border-border/80 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-text-primary">REGISTERED MODEL VERSIONS</h3>
          <p className="text-2xs text-muted mt-0.5">
            Historical trained models preserved with checksums and parameter lineages.
          </p>
        </div>
        <span className="text-xs font-mono font-medium text-muted">
          {models.length} {models.length === 1 ? 'version' : 'versions'}
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-border/80 bg-base/60 text-2xs font-semibold text-muted uppercase tracking-wider">
              <th className="py-2.5 px-4">Status</th>
              <th className="py-2.5 px-4">Model Name</th>
              <th className="py-2.5 px-4">Version</th>
              <th className="py-2.5 px-4">Algorithm</th>
              <th className="py-2.5 px-4">Samples</th>
              <th className="py-2.5 px-4">Features</th>
              <th className="py-2.5 px-4">Trained Date</th>
              <th className="py-2.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40 font-mono text-2xs">
            {models.map((m) => {
              const isActivating = activatingId === m.id;
              return (
                <tr
                  key={m.id}
                  className={`hover:bg-surface-hover/50 transition ${
                    m.is_active ? 'bg-purple-500/5' : ''
                  }`}
                >
                  <td className="py-3 px-4">
                    <ModelStatusBadge status={m.status} size="sm" />
                  </td>
                  <td className="py-3 px-4 font-sans font-medium text-text-primary">
                    <div className="flex items-center gap-2">
                      <span>{m.name}</span>
                      {m.is_active && (
                        <span className="text-3xs uppercase font-mono px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 font-bold border border-purple-500/30">
                          Active
                        </span>
                      )}
                    </div>
                    <div className="text-3xs text-muted font-mono">{m.id}</div>
                  </td>
                  <td className="py-3 px-4 text-text-secondary font-bold">
                    v{m.model_version}
                  </td>
                  <td className="py-3 px-4 text-cyan-400">
                    {m.model_type}
                  </td>
                  <td className="py-3 px-4 text-text-primary">
                    {m.training_samples} sessions
                  </td>
                  <td className="py-3 px-4 text-muted">
                    {m.feature_count} features (schema {m.feature_version})
                  </td>
                  <td className="py-3 px-4 text-muted font-sans">
                    {new Date(m.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-2 font-sans">
                      <button
                        onClick={() => onSelectModel(m.id)}
                        className="flex items-center gap-1 rounded border border-border px-2 py-1 text-2xs text-text-secondary hover:text-text-primary hover:bg-surface-hover transition"
                      >
                        <Eye className="h-3 w-3" />
                        <span>Inspect</span>
                      </button>

                      {!m.is_active && (
                        <button
                          onClick={() => onActivateModel(m.id)}
                          disabled={isActivating}
                          className="flex items-center gap-1 rounded bg-purple-600/80 hover:bg-purple-600 text-white px-2 py-1 text-2xs font-medium transition disabled:opacity-50"
                        >
                          <Radio className="h-3 w-3" />
                          <span>{isActivating ? 'Activating...' : 'Activate'}</span>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
