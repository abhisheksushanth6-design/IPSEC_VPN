import { summarizeProgress } from '@/config/architecture';
import type { ArchitectureLayerDetail } from '@/types';

interface ArchitectureProgressProps {
  layers: ArchitectureLayerDetail[];
}

/** Derived from the metadata; nothing here is typed in by hand. */
export function ArchitectureProgress({ layers }: ArchitectureProgressProps) {
  const { foundation, implemented, total } = summarizeProgress(layers);
  const foundationPct = total ? Math.round((foundation / total) * 100) : 0;
  const implementedPct = total ? Math.round((implemented / total) * 100) : 0;

  return (
    <div className="rounded border border-border bg-surface p-4">
      <h3 className="text-xs font-medium text-secondary">Implementation progress</h3>

      <div className="mt-4 space-y-4">
        <div>
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-xs text-muted">Foundation components available</span>
            <span className="font-mono text-sm tabular-nums text-primary">
              {foundation} / {total}
            </span>
          </div>
          <div
            role="progressbar"
            aria-label="Foundation components available"
            aria-valuemin={0}
            aria-valuemax={total}
            aria-valuenow={foundation}
            className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-border"
          >
            <div className="h-full rounded-full bg-info" style={{ width: `${foundationPct}%` }} />
          </div>
        </div>

        <div>
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-xs text-muted">Fully implemented</span>
            <span className="font-mono text-sm tabular-nums text-primary">
              {implemented} / {total}
            </span>
          </div>
          <div
            role="progressbar"
            aria-label="Fully implemented layers"
            aria-valuemin={0}
            aria-valuemax={total}
            aria-valuenow={implemented}
            className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-border"
          >
            <div className="h-full rounded-full bg-success" style={{ width: `${implementedPct}%` }} />
          </div>
        </div>
      </div>

      <p className="mt-4 text-2xs text-muted">
        A foundation means scaffolding exists for the layer, not that it performs its function.
      </p>
    </div>
  );
}
