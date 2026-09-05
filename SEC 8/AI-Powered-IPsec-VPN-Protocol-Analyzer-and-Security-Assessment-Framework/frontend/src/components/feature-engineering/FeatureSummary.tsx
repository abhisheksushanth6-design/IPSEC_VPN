import { Panel } from '@/components/ui';
import type { FeatureVector } from '@/types';

interface Card {
  label: string;
  value: number;
  tone: string;
  hint: string;
}

/**
 * Counts taken straight from the vector's own metadata. No percentages are
 * invented and no distribution is drawn from a single observation.
 */
export function FeatureSummary({ vector }: { vector: FeatureVector | null }) {
  if (!vector) return null;

  const cards: Card[] = [
    {
      label: 'Total features',
      value: vector.feature_count,
      tone: 'text-primary',
      hint: `Schema v${vector.feature_version}`,
    },
    {
      label: 'Available',
      value: vector.available_count,
      tone: 'text-success',
      hint: 'Calculated from complete source data',
    },
    {
      label: 'Partial',
      value: vector.partial_count,
      tone: 'text-warning',
      hint: 'Calculated over partially visible evidence',
    },
    {
      label: 'Unavailable',
      value: vector.unavailable_count,
      tone: 'text-muted',
      hint: 'Source data did not support calculation',
    },
  ];

  return (
    <Panel
      title="Feature Summary"
      description={`${vector.entity_type} · ${vector.entity_label} · generated ${vector.generated_at}`}
    >
      <dl className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {cards.map((card) => (
          <div key={card.label} className="rounded border border-border bg-base p-3">
            <dt className="text-2xs uppercase tracking-wide text-muted">{card.label}</dt>
            <dd className={`mt-1 font-mono text-xl ${card.tone}`}>{card.value}</dd>
            <p className="mt-1 text-2xs text-muted">{card.hint}</p>
          </div>
        ))}
      </dl>
    </Panel>
  );
}
