import { StatusBadge } from '@/components/status';
import type {
  FeatureAvailability,
  FeatureEngineState,
  FeatureValue,
  StatusKind,
} from '@/types';

const ENGINE: Record<FeatureEngineState, { status: StatusKind; label: string }> = {
  'NOT INITIALIZED': { status: 'NOT INITIALIZED', label: 'NOT INITIALIZED' },
  READY: { status: 'INACTIVE', label: 'READY' },
  PROCESSING: { status: 'INITIALIZING', label: 'PROCESSING' },
  AVAILABLE: { status: 'ONLINE', label: 'AVAILABLE' },
  ERROR: { status: 'CRITICAL', label: 'ERROR' },
};

/** Engine state, or an explicit offline badge when the backend is unreachable. */
export function featureEngineBadge(state: FeatureEngineState | undefined, reachable: boolean) {
  if (!reachable) {
    return { status: 'OFFLINE' as StatusKind, label: 'FEATURE SERVICE UNAVAILABLE' };
  }
  return ENGINE[state ?? 'NOT INITIALIZED'] ?? ENGINE['NOT INITIALIZED'];
}

const AVAILABILITY: Record<FeatureAvailability, { status: StatusKind; label: string }> = {
  AVAILABLE: { status: 'ONLINE', label: 'AVAILABLE' },
  PARTIAL: { status: 'WARNING', label: 'PARTIAL' },
  UNAVAILABLE: { status: 'INACTIVE', label: 'UNAVAILABLE' },
};

export function FeatureStatusBadge({ availability }: { availability: FeatureAvailability }) {
  const entry = AVAILABILITY[availability];
  return <StatusBadge status={entry.status} label={entry.label} size="sm" />;
}

/**
 * Format a value for display without losing the distinction between a
 * calculated zero and a value that was never calculated. Raw precision is
 * preserved in the data; only the rendering is shortened.
 */
export function formatFeatureValue(feature: FeatureValue): string {
  if (feature.value === null) return '—';
  if (typeof feature.value === 'boolean') return feature.value ? 'TRUE' : 'FALSE';
  if (typeof feature.value === 'number') {
    if (Number.isInteger(feature.value)) return feature.value.toLocaleString();
    const magnitude = Math.abs(feature.value);
    const digits = magnitude >= 100 ? 2 : magnitude >= 1 ? 3 : 6;
    return feature.value.toLocaleString(undefined, { maximumFractionDigits: digits });
  }
  return feature.value;
}

/** Short unit suffix, omitted for unitless categorical and boolean features. */
export function formatFeatureUnit(feature: FeatureValue): string {
  if (feature.value === null || !feature.unit) return '';
  return feature.unit;
}
