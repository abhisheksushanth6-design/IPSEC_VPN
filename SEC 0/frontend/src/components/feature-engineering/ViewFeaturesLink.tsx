import { ArrowUpRight, Layers3 } from 'lucide-react';
import { Link } from 'react-router-dom';

import type { FeatureEntityType } from '@/types';

/**
 * Navigates to the feature workspace for one entity. Feature values are
 * calculated in one place only, so this links to Layer 05 rather than
 * recalculating anything here.
 */
export function ViewFeaturesLink({
  entityType,
  entityId,
  label = 'View features',
}: {
  entityType: FeatureEntityType;
  entityId: string;
  label?: string;
}) {
  return (
    <Link
      to={`/feature-engineering?entity_type=${entityType}&entity_id=${encodeURIComponent(entityId)}`}
      className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info"
    >
      <Layers3 aria-hidden className="h-3.5 w-3.5" />
      {label}
      <ArrowUpRight aria-hidden className="h-3 w-3" />
    </Link>
  );
}
