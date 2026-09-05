import { ChevronDown, ChevronRight } from 'lucide-react';
import { useState } from 'react';

import { Panel } from '@/components/ui';
import { FEATURE_CATEGORY_LABELS, FEATURE_CATEGORY_ORDER } from '@/types';
import type { FeatureCategory, FeatureValue, FeatureVector } from '@/types';
import { FeatureStatusBadge, formatFeatureValue } from './FeatureStatusBadge';

/** One feature. Unavailable rows show a dash and carry the reason as a note. */
export function FeatureRow({ feature }: { feature: FeatureValue }) {
  const unavailable = feature.availability === 'UNAVAILABLE';
  return (
    <tr className="border-b border-border/60 last:border-0 align-top">
      <th scope="row" className="px-3 py-2 text-left font-normal">
        <span className="font-mono text-xs text-primary">{feature.name}</span>
        <span className="block text-2xs text-muted">{feature.display_name}</span>
      </th>
      <td className="px-3 py-2 text-right">
        <span className={`font-mono text-xs ${unavailable ? 'text-muted' : 'text-primary'}`}>
          {formatFeatureValue(feature)}
        </span>
        {feature.detail ? (
          <span className="mt-0.5 block max-w-prose text-2xs leading-snug text-muted">
            {feature.detail}
          </span>
        ) : null}
      </td>
      <td className="px-3 py-2 text-2xs text-muted">{feature.data_type}</td>
      <td className="px-3 py-2 text-2xs text-muted">{feature.unit ?? '—'}</td>
      <td className="hidden px-3 py-2 text-2xs text-muted lg:table-cell">{feature.source}</td>
      <td className="px-3 py-2">
        <FeatureStatusBadge availability={feature.availability} />
      </td>
    </tr>
  );
}

/** A collapsible group of features sharing one display category. */
export function FeatureCategorySection({
  category,
  features,
  defaultOpen,
}: {
  category: FeatureCategory;
  features: FeatureValue[];
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const available = features.filter((f) => f.availability !== 'UNAVAILABLE').length;
  const headingId = `feature-category-${category.toLowerCase()}`;

  return (
    <div className="rounded border border-border">
      <h3>
        <button
          type="button"
          id={headingId}
          aria-expanded={open}
          aria-controls={`${headingId}-panel`}
          onClick={() => setOpen((value) => !value)}
          className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left transition-colors hover:bg-base focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-info"
        >
          <span className="flex items-center gap-2">
            {open ? (
              <ChevronDown aria-hidden className="h-3.5 w-3.5 text-muted" />
            ) : (
              <ChevronRight aria-hidden className="h-3.5 w-3.5 text-muted" />
            )}
            <span className="text-xs font-medium uppercase tracking-wide text-primary">
              {FEATURE_CATEGORY_LABELS[category]}
            </span>
          </span>
          <span className="font-mono text-2xs text-muted">
            {available}/{features.length} calculated
          </span>
        </button>
      </h3>

      {open ? (
        <div id={`${headingId}-panel`} role="region" aria-labelledby={headingId} className="overflow-x-auto">
          <table className="w-full min-w-[40rem] border-t border-border text-xs">
            <caption className="sr-only">{FEATURE_CATEGORY_LABELS[category]}</caption>
            <thead>
              <tr className="border-b border-border text-2xs uppercase tracking-wide text-muted">
                <th scope="col" className="px-3 py-2 text-left font-normal">Feature</th>
                <th scope="col" className="px-3 py-2 text-right font-normal">Value</th>
                <th scope="col" className="px-3 py-2 text-left font-normal">Type</th>
                <th scope="col" className="px-3 py-2 text-left font-normal">Unit</th>
                <th scope="col" className="hidden px-3 py-2 text-left font-normal lg:table-cell">Source</th>
                <th scope="col" className="px-3 py-2 text-left font-normal">Status</th>
              </tr>
            </thead>
            <tbody>
              {features.map((feature) => (
                <FeatureRow key={feature.name} feature={feature} />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

/** The full inspector, grouped into display categories. */
export function FeatureInspector({ vector }: { vector: FeatureVector }) {
  const grouped = FEATURE_CATEGORY_ORDER.map((category) => ({
    category,
    features: vector.features.filter((feature) => feature.category === category),
  })).filter((group) => group.features.length > 0);

  return (
    <Panel
      title="Feature Inspector"
      description="Every feature in the vector, grouped for readability. Categories are a display grouping only."
    >
      <div className="space-y-3">
        {grouped.map((group, index) => (
          <FeatureCategorySection
            key={group.category}
            category={group.category}
            features={group.features}
            defaultOpen={index < 2}
          />
        ))}
      </div>
    </Panel>
  );
}
