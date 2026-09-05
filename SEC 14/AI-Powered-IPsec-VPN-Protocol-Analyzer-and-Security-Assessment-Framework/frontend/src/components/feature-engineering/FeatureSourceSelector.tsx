import { Panel } from '@/components/ui';
import type { FeatureController } from '@/hooks';
import { FEATURE_ENTITY_LABELS } from '@/types';
import type { FeatureEntityType } from '@/types';

const TYPES: FeatureEntityType[] = ['PACKET', 'SESSION', 'SA'];

const tab =
  'rounded border px-3 py-1.5 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-info';

/**
 * Source selection: entity type, then a real entity of that type. Options
 * come from the backend, so an empty list is an honest statement that no
 * such source data exists yet.
 */
export function FeatureSourceSelector({ controller }: { controller: FeatureController }) {
  const { entityType, entities, entitiesLoading, selectedId, setEntityType, select } = controller;
  // Defensive: never assume a payload shape the backend might not have sent.
  const options = entities?.items ?? [];

  return (
    <Panel title="Feature Source" description="Choose the observed entity to extract features from.">
      <div className="space-y-4">
        <div>
          <span id="entity-type-label" className="text-2xs uppercase tracking-wide text-muted">
            Entity type
          </span>
          <div
            role="group"
            aria-labelledby="entity-type-label"
            className="mt-2 flex flex-wrap gap-2"
          >
            {TYPES.map((type) => {
              const active = type === entityType;
              return (
                <button
                  key={type}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setEntityType(type)}
                  className={`${tab} ${
                    active
                      ? 'border-info bg-info/10 text-info'
                      : 'border-border text-secondary hover:border-info hover:text-info'
                  }`}
                >
                  {FEATURE_ENTITY_LABELS[type]}
                </button>
              );
            })}
          </div>
        </div>

        <div>
          <label htmlFor="entity-select" className="text-2xs uppercase tracking-wide text-muted">
            Select {FEATURE_ENTITY_LABELS[entityType].toLowerCase()}
          </label>
          {entitiesLoading ? (
            <p className="mt-2 text-xs text-muted">Loading entities…</p>
          ) : options.length > 0 ? (
            <>
              <select
                id="entity-select"
                className="mt-2 w-full rounded border border-border bg-base px-3 py-2 text-xs text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-info"
                value={selectedId ?? ''}
                onChange={(event) => select(event.target.value || null)}
              >
                <option value="">— none selected —</option>
                {options.map((entity) => (
                  <option key={entity.entity_id} value={entity.entity_id}>
                    {entity.label} · {entity.detail}
                    {entity.extracted ? ' · extracted' : ''}
                  </option>
                ))}
              </select>
              <p className="mt-2 text-2xs text-muted">{entities?.detail}</p>
            </>
          ) : (
            <p className="mt-2 rounded border border-dashed border-border px-3 py-4 text-center text-xs text-muted">
              {entities?.detail ?? `NO ${FEATURE_ENTITY_LABELS[entityType].toUpperCase()} DATA AVAILABLE`}
            </p>
          )}
        </div>
      </div>
    </Panel>
  );
}
