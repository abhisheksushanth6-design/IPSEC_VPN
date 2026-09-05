import { useState } from 'react';
import { Database, Plus, X } from 'lucide-react';
import type { BaselineBuildRequest } from '@/types';

interface BuildBaselineModalProps {
  isOpen: boolean;
  onClose: () => void;
  onBuild: (payload: BaselineBuildRequest) => Promise<void>;
  isBuilding: boolean;
  availableSessionCount?: number;
}

export function BuildBaselineModal({
  isOpen,
  onClose,
  onBuild,
  isBuilding,
  availableSessionCount = 0,
}: BuildBaselineModalProps) {
  const [name, setName] = useState<string>('Observed Traffic Baseline');
  const [description, setDescription] = useState<string>(
    'Reference baseline profile compiled from observed session traffic features.'
  );
  const [minimumSessions, setMinimumSessions] = useState<number>(3);
  const [activate, setActivate] = useState<boolean>(true);
  const [formError, setFormError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setFormError('Baseline name is required.');
      return;
    }
    setFormError(null);
    try {
      await onBuild({
        name: name.trim(),
        description: description.trim() || null,
        minimum_sessions: minimumSessions,
        activate,
      });
      onClose();
    } catch (err: any) {
      setFormError(err.message ?? 'Failed to build baseline profile');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-lg border border-border bg-surface shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-4 bg-surface-muted/30">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Database className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-text-primary">
                Build Baseline Profile
              </h2>
              <p className="text-2xs text-muted">
                Compile descriptive statistics over observed sessions
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={isBuilding}
            className="rounded p-1 text-muted hover:bg-surface-muted hover:text-text-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {formError && (
            <div className="rounded border border-rose-500/20 bg-rose-500/10 p-2.5 text-2xs text-rose-400">
              {formError}
            </div>
          )}

          <div className="space-y-1">
            <label className="text-2xs font-semibold uppercase tracking-wider text-muted">
              Profile Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Production Core Baseline"
              disabled={isBuilding}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-xs text-text-primary placeholder:text-muted focus:border-cyan-500 focus:outline-none"
              required
            />
          </div>

          <div className="space-y-1">
            <label className="text-2xs font-semibold uppercase tracking-wider text-muted">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe observation scope or parameters..."
              rows={3}
              disabled={isBuilding}
              className="w-full rounded-md border border-border bg-base px-3 py-2 text-xs text-text-primary placeholder:text-muted focus:border-cyan-500 focus:outline-none resize-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-2xs font-semibold uppercase tracking-wider text-muted">
                Minimum Sessions
              </label>
              <input
                type="number"
                min={1}
                max={100}
                value={minimumSessions}
                onChange={(e) => setMinimumSessions(parseInt(e.target.value, 10) || 1)}
                disabled={isBuilding}
                className="w-full rounded-md border border-border bg-base px-3 py-2 text-xs font-mono text-text-primary focus:border-cyan-500 focus:outline-none"
              />
              <p className="text-3xs text-muted">Threshold for READY status</p>
            </div>

            <div className="space-y-1 flex flex-col justify-end">
              <label className="flex items-center gap-2 cursor-pointer pb-2">
                <input
                  type="checkbox"
                  checked={activate}
                  onChange={(e) => setActivate(e.target.checked)}
                  disabled={isBuilding}
                  className="rounded border-border bg-base text-cyan-500 focus:ring-cyan-500 h-4 w-4"
                />
                <span className="text-2xs font-medium text-text-primary">
                  Set as Active Reference
                </span>
              </label>
              <p className="text-3xs text-muted">Marks this profile for active comparisons</p>
            </div>
          </div>

          <div className="rounded border border-border bg-base/50 p-2.5 text-2xs text-muted space-y-1">
            <div className="flex justify-between">
              <span>Available Session Observations:</span>
              <span className="font-mono font-semibold text-text-primary">
                {availableSessionCount}
              </span>
            </div>
            <p className="text-3xs text-muted">
              Observed features will be deterministically fingerprinted and statistically aggregated.
            </p>
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              disabled={isBuilding}
              className="rounded border border-border bg-surface px-3 py-1.5 text-xs text-text-secondary hover:bg-surface-muted transition disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isBuilding}
              className="inline-flex items-center gap-1.5 rounded bg-cyan-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>{isBuilding ? 'Building Baseline...' : 'Compile Baseline'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
