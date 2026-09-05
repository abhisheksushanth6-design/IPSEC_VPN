import { Check, Minus } from 'lucide-react';
import { useState } from 'react';

import { EmptyState } from '@/components/states';
import { DataRow, Panel } from '@/components/ui';
import type { FeatureValue, FeatureVector } from '@/types';
import { formatFeatureValue } from './FeatureStatusBadge';

/**
 * A readable digest of the vector rather than a raw JSON dump. The full
 * structure is available behind the JSON view for technical inspection.
 */
export function FeatureVectorPreview({ vector }: { vector: FeatureVector }) {
  const calculated = vector.features.filter((f) => f.availability !== 'UNAVAILABLE');
  const highlights = calculated.slice(0, 8);

  return (
    <Panel title="Feature Vector Preview" description="Structured view of the extracted vector.">
      <dl className="space-y-1">
        <DataRow label="Entity">{`${vector.entity_type} · ${vector.entity_label}`}</DataRow>
        <DataRow label="Entity ID">
          <span className="font-mono text-xs">{vector.entity_id}</span>
        </DataRow>
        <DataRow label="Feature version">
          <span className="font-mono text-xs">{vector.feature_version}</span>
        </DataRow>
        <DataRow label="Generated at">
          <span className="font-mono text-xs">{vector.generated_at}</span>
        </DataRow>
        <DataRow label="Features calculated">{`${calculated.length} of ${vector.feature_count}`}</DataRow>
      </dl>

      {highlights.length > 0 ? (
        <ul className="mt-4 grid gap-2 sm:grid-cols-2">
          {highlights.map((feature) => (
            <li key={feature.name} className="rounded border border-border bg-base px-3 py-2">
              <span className="block font-mono text-2xs text-muted">{feature.name}</span>
              <span className="font-mono text-sm text-primary">
                {formatFeatureValue(feature)}
                {feature.unit ? <span className="ml-1 text-2xs text-muted">{feature.unit}</span> : null}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </Panel>
  );
}

/** Source availability, which is what the vector's quality rests on. */
export function FeatureMetadataPanel({ vector }: { vector: FeatureVector }) {
  return (
    <Panel
      title="Source Availability"
      description="What source data this extraction actually had to work with."
    >
      <ul className="space-y-2">
        {vector.sources.map((source) => (
          <li key={source.name} className="flex items-start gap-2.5">
            {source.available ? (
              <Check aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" />
            ) : (
              <Minus aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
            )}
            <div>
              <span className="text-xs text-primary">{source.name}</span>
              <span className="sr-only">{source.available ? ' available' : ' unavailable'}</span>
              <p className="text-2xs leading-snug text-muted">{source.detail}</p>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/**
 * Feature lineage: where a value came from and how it was calculated. This is
 * explainability of the *data*, not of any model — there is no model here.
 */
export function FeatureLineage({ vector }: { vector: FeatureVector }) {
  const [name, setName] = useState<string>(vector.features[0]?.name ?? '');
  const feature: FeatureValue | undefined =
    vector.features.find((f) => f.name === name) ?? vector.features[0];

  if (!feature) return null;

  return (
    <Panel title="Feature Lineage" description="Trace a feature back to the observation behind it.">
      <label htmlFor="lineage-select" className="text-2xs uppercase tracking-wide text-muted">
        Feature
      </label>
      <select
        id="lineage-select"
        className="mt-2 w-full rounded border border-border bg-base px-3 py-2 text-xs text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-info"
        value={feature.name}
        onChange={(event) => setName(event.target.value)}
      >
        {vector.features.map((item) => (
          <option key={item.name} value={item.name}>
            {item.name}
          </option>
        ))}
      </select>

      <dl className="mt-4 space-y-1">
        <DataRow label="Feature">
          <span>{feature.display_name}</span>
        </DataRow>
        <DataRow label="Value">
          <span className="font-mono text-xs">{formatFeatureValue(feature)}</span>
        </DataRow>
        <DataRow label="Unit">
          <span>{feature.unit ?? 'not applicable'}</span>
        </DataRow>
        <DataRow label="Source entity">{`${vector.entity_type} · ${vector.entity_label}`}</DataRow>
        <DataRow label="Source data">
          <span>{feature.source}</span>
        </DataRow>
        <DataRow label="Formula">
          <span className="font-mono text-xs">{feature.formula ?? 'read directly from the source'}</span>
        </DataRow>
        <DataRow label="Availability">
          <span>{feature.availability}</span>
        </DataRow>
        <DataRow label="Quality">
          <span>{feature.quality}</span>
        </DataRow>
        <DataRow label="Normalization">
          <span>{feature.normalization_method}</span>
        </DataRow>
      </dl>

      <p className="mt-3 text-2xs leading-relaxed text-muted">{feature.description}</p>
      {feature.detail ? (
        <p className="mt-2 rounded border border-border bg-base px-3 py-2 text-2xs leading-relaxed text-secondary">
          {feature.detail}
        </p>
      ) : null}
    </Panel>
  );
}

/** Raw structured data, shown only on request. */
export function FeatureJsonView({ vector }: { vector: FeatureVector }) {
  const [open, setOpen] = useState(false);
  return (
    <Panel
      title="JSON View"
      description="The stored structure, for technical inspection."
      actions={
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          className="rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info"
        >
          {open ? 'Hide JSON' : 'View JSON'}
        </button>
      }
    >
      {open ? (
        <pre className="max-h-96 overflow-auto rounded border border-border bg-base p-3 font-mono text-2xs leading-relaxed text-secondary">
          {JSON.stringify(vector, null, 2)}
        </pre>
      ) : (
        <p className="text-xs text-muted">
          The full vector is {vector.feature_count} features. Open it only when you need the raw
          structure.
        </p>
      )}
    </Panel>
  );
}

/** Empty states, each naming the actual reason nothing is shown. */
export function EmptyFeatureState({
  entitySelected,
  sourceAvailable,
  extracting,
}: {
  entitySelected: boolean;
  sourceAvailable: boolean;
  extracting: boolean;
}) {
  if (extracting) {
    return (
      <Panel>
        <p className="py-8 text-center text-xs text-muted">EXTRACTING FEATURES…</p>
      </Panel>
    );
  }
  if (!sourceAvailable) {
    return (
      <EmptyState
        title="SOURCE DATA UNAVAILABLE"
        description="Load a capture in Packet Analysis, then discover sessions or Security Associations to create entities to extract from."
      />
    );
  }
  if (!entitySelected) {
    return (
      <EmptyState
        title="NO ENTITY SELECTED"
        description="Choose an entity above to view or extract its feature vector."
      />
    );
  }
  return (
    <EmptyState
      title="FEATURE EXTRACTION NOT RUN"
      description="No features have been extracted for this entity yet. Use Extract features to calculate them."
    />
  );
}
