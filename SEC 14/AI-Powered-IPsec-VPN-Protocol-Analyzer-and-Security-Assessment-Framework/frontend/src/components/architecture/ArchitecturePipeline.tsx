import { Fragment } from 'react';

import { ARCHITECTURE_CATEGORIES } from '@/config/architecture';
import { ArchitectureConnector } from './ArchitectureConnector';
import { ArchitectureLayerCard } from './ArchitectureLayerCard';
import type { ArchitectureLayerDetail } from '@/types';

interface ArchitecturePipelineProps {
  layers: ArchitectureLayerDetail[];
  selectedNumber: number | null;
  onSelect: (layer: ArchitectureLayerDetail) => void;
}

/**
 * The vertical 01 → 14 pipeline, grouped visually into five categories.
 * Grouping is presentation only; the layer order is never altered.
 */
export function ArchitecturePipeline({ layers, selectedNumber, onSelect }: ArchitecturePipelineProps) {
  return (
    <ol aria-label="10-layer processing pipeline" className="space-y-1">
      {ARCHITECTURE_CATEGORIES.map((group, groupIndex) => {
        const members = layers.filter((l) => l.number >= group.from && l.number <= group.to);
        const isLast = groupIndex === ARCHITECTURE_CATEGORIES.length - 1;

        return (
          <li key={group.category} className="list-none">
            <section
              aria-labelledby={`arch-group-${groupIndex}`}
              className="rounded border border-border/60 bg-background/40 p-3 sm:p-4"
            >
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h3 id={`arch-group-${groupIndex}`} className="text-xs font-medium text-secondary">
                  {group.category}
                </h3>
                <span className="font-mono text-2xs text-muted">
                  Layers {String(group.from).padStart(2, '0')}–{String(group.to).padStart(2, '0')}
                </span>
              </div>

              <ol className="list-none">
                {members.map((layer, index) => (
                  <Fragment key={layer.id}>
                    <li>
                      <ArchitectureLayerCard
                        layer={layer}
                        selected={selectedNumber === layer.number}
                        onSelect={onSelect}
                      />
                    </li>
                    {index < members.length - 1 ? (
                      <li aria-hidden>
                        <ArchitectureConnector />
                      </li>
                    ) : null}
                  </Fragment>
                ))}
              </ol>
            </section>

            {!isLast ? <ArchitectureConnector label="DATA FLOW" /> : null}
          </li>
        );
      })}
    </ol>
  );
}
