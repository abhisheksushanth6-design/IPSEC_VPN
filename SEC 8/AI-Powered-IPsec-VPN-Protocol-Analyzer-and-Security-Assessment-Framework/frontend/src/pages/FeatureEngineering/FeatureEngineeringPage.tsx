import { AlertTriangle, X } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import {
  EmptyFeatureState,
  FeatureInspector,
  FeatureJsonView,
  FeatureLineage,
  FeatureMetadataPanel,
  FeatureSourceSelector,
  FeatureSummary,
  FeatureToolbar,
  FeatureVectorPreview,
  featureEngineBadge,
} from '@/components/feature-engineering';
import { PageContainer } from '@/components/layout';
import { PageHeader } from '@/components/ui';
import { useFeatureEngineering } from '@/hooks';
import type { FeatureEntityType } from '@/types';

const ERROR_TITLES: Record<string, string> = {
  FEATURE_SERVICE_UNAVAILABLE: 'Feature service unavailable',
  ENTITY_NOT_FOUND: 'Entity not found',
  FEATURE_VECTOR_NOT_FOUND: 'Feature vector not found',
  SOURCE_DATA_INCOMPLETE: 'Source data incomplete',
  FEATURE_EXTRACTION_FAILED: 'Feature extraction failed',
  FEATURE_VALIDATION_FAILED: 'Feature validation failed',
  PACKET_DATA_UNAVAILABLE: 'Packet data unavailable',
  NO_FEATURE_DATA_AVAILABLE: 'No feature data available',
  DATABASE_ERROR: 'Database error',
};

const ENTITY_TYPES: FeatureEntityType[] = ['PACKET', 'SESSION', 'SA'];

function initialEntityType(value: string | null): FeatureEntityType {
  return ENTITY_TYPES.includes(value as FeatureEntityType)
    ? (value as FeatureEntityType)
    : 'SESSION';
}

/**
 * Layer 05 — Feature Extraction & Engineering. Every value shown here is
 * calculated by the backend from observed packets, sessions and SAs.
 */
export function FeatureEngineeringPage() {
  const [params] = useSearchParams();
  const controller = useFeatureEngineering(
    initialEntityType(params.get('entity_type')),
    params.get('entity_id'),
  );
  const badge = featureEngineBadge(
    controller.status?.state,
    controller.status !== null || controller.statusLoading,
  );
  const sourceAvailable = controller.entities?.source_available ?? false;

  return (
    <PageContainer>
      <PageHeader
        title="Feature Extraction & Engineering"
        description="Transform observed IPsec VPN packet, session, and SA behavior into structured security-analysis features."
        status={controller.statusLoading ? 'INITIALIZING' : badge.status}
        statusLabel={controller.statusLoading ? 'LOADING' : badge.label}
        breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Feature Extraction' }]}
      />

      <FeatureToolbar controller={controller} />

      {controller.error ? (
        <div
          role="alert"
          className="flex items-start justify-between gap-3 rounded border border-danger/30 bg-danger/5 px-4 py-3"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <div>
              <p className="text-sm font-medium text-primary">
                {ERROR_TITLES[controller.error.code] ?? 'Request failed'}
              </p>
              <p className="mt-0.5 text-xs text-secondary">{controller.error.message}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={controller.dismissError}
            aria-label="Dismiss error"
            className="rounded p-1 text-muted hover:text-primary"
          >
            <X aria-hidden className="h-4 w-4" />
          </button>
        </div>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] xl:items-start">
        <FeatureSourceSelector controller={controller} />
        {controller.vector ? (
          <FeatureSummary vector={controller.vector} />
        ) : (
          <EmptyFeatureState
            entitySelected={Boolean(controller.selectedId)}
            sourceAvailable={sourceAvailable}
            extracting={controller.busy === 'extract' || controller.vectorLoading}
          />
        )}
      </div>

      {controller.vector ? (
        <>
          <FeatureInspector vector={controller.vector} />
          <div className="grid gap-6 xl:grid-cols-2 xl:items-start">
            <FeatureVectorPreview vector={controller.vector} />
            <FeatureMetadataPanel vector={controller.vector} />
          </div>
          <div className="grid gap-6 xl:grid-cols-2 xl:items-start">
            <FeatureLineage vector={controller.vector} />
            <FeatureJsonView vector={controller.vector} />
          </div>
        </>
      ) : null}
    </PageContainer>
  );
}
