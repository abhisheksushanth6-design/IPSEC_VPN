import { ChevronRight } from 'lucide-react';

import { StatusBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import type { ArchitectureLayerDetail } from '@/types';

interface ArchitectureLayerCardProps {
  layer: ArchitectureLayerDetail;
  selected: boolean;
  onSelect: (layer: ArchitectureLayerDetail) => void;
}

const LABEL_ID = (n: number) => `arch-layer-${n}-name`;

/** One layer in the pipeline. A button, so it is keyboard-operable. */
export function ArchitectureLayerCard({ layer, selected, onSelect }: ArchitectureLayerCardProps) {
  const Icon = layer.icon;
  const number = String(layer.number).padStart(2, '0');

  return (
    <button
      type="button"
      id={layer.id}
      onClick={() => onSelect(layer)}
      aria-pressed={selected}
      aria-labelledby={LABEL_ID(layer.number)}
      aria-describedby={`${layer.id}-desc`}
      className={cn(
        'group w-full scroll-mt-24 rounded border bg-surface text-left transition-colors duration-150',
        selected
          ? 'border-info bg-elevated'
          : 'border-border hover:border-secondary/40 hover:bg-elevated/60',
      )}
    >
      <div className="flex items-start gap-4 p-4">
        <span
          aria-hidden
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded border border-border bg-background font-mono text-sm text-secondary"
        >
          {number}
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Icon aria-hidden className="h-4 w-4 shrink-0 text-muted" />
            <h4 id={LABEL_ID(layer.number)} className="text-sm font-medium text-primary">
              <span className="sr-only">Layer {number}: </span>
              {layer.name}
            </h4>
          </div>
          <p id={`${layer.id}-desc`} className="mt-1.5 max-w-reading text-xs leading-relaxed text-muted">
            {layer.description}
          </p>
          <div className="mt-3">
            <StatusBadge status={layer.status} size="sm" />
          </div>
        </div>

        <ChevronRight
          aria-hidden
          className={cn(
            'mt-3 h-4 w-4 shrink-0 text-muted transition-transform duration-150',
            selected ? 'translate-x-0.5 text-info' : 'group-hover:translate-x-0.5',
          )}
        />
      </div>
    </button>
  );
}
