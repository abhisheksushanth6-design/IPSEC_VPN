import { cn } from '@/utils/cn';
import type { ArchitectureLayerDetail } from '@/types';

interface ArchitectureMiniMapProps {
  layers: ArchitectureLayerDetail[];
  selectedNumber: number | null;
  onSelect: (layer: ArchitectureLayerDetail) => void;
}

const TONE: Record<string, string> = {
  'NOT INITIALIZED': 'border-border text-muted',
  'FOUNDATION CREATED': 'border-info/40 text-info',
  'FOUNDATION READY': 'border-info/40 text-info',
  'IN DEVELOPMENT': 'border-warning/40 text-warning',
  READY: 'border-success/40 text-success',
  OPERATIONAL: 'border-success/40 text-success',
  IMPLEMENTED: 'border-success/40 text-success',
  ERROR: 'border-danger/40 text-danger',
  UNKNOWN: 'border-border text-muted',
};

/** Compact navigator: two rows of seven, each a jump to its card. */
export function ArchitectureMiniMap({ layers, selectedNumber, onSelect }: ArchitectureMiniMapProps) {
  const rows = [layers.slice(0, 7), layers.slice(7, 14)];

  return (
    <nav aria-label="Architecture navigator" className="rounded border border-border bg-surface p-4">
      <h3 className="text-xs font-medium text-secondary">Navigator</h3>
      <div className="mt-3 space-y-2">
        {rows.map((row, rowIndex) => (
          <ol key={rowIndex} className="grid grid-cols-7 gap-1.5">
            {row.map((layer) => {
              const number = String(layer.number).padStart(2, '0');
              return (
                <li key={layer.id}>
                  <a
                    href={`#${layer.id}`}
                    onClick={(event) => {
                      event.preventDefault();
                      onSelect(layer);
                      document.getElementById(layer.id)?.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
                    }}
                    aria-label={`Layer ${number}: ${layer.name} — ${layer.status}`}
                    aria-current={selectedNumber === layer.number ? 'true' : undefined}
                    className={cn(
                      'flex h-8 items-center justify-center rounded border font-mono text-xs transition-colors',
                      TONE[layer.status] ?? TONE['NOT INITIALIZED'],
                      selectedNumber === layer.number ? 'bg-elevated ring-1 ring-info' : 'hover:bg-elevated/60',
                    )}
                  >
                    {number}
                  </a>
                </li>
              );
            })}
          </ol>
        ))}
      </div>
    </nav>
  );
}
