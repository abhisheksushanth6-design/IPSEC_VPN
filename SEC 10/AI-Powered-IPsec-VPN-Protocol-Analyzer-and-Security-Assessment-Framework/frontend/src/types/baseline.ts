/**
 * Layer 06 — Session Fingerprinting & Baseline Profiling TypeScript Definitions.
 *
 * Grounded in observed protocol features. Strictly descriptive — no drift scores or anomaly labels.
 */

export type BaselineEngineState =
  | 'NOT INITIALIZED'
  | 'COLLECTING'
  | 'READY'
  | 'BUILDING'
  | 'AVAILABLE'
  | 'ERROR';

export interface BaselineEngineStatus {
  state: BaselineEngineState;
  feature_version: string;
  active_baseline_id: string | null;
  active_baseline_name: string | null;
  total_baselines: number;
  total_fingerprints: number;
  total_sessions_profiled: number;
  total_features_profiled: number;
  last_error: string | null;
}

export interface FingerprintFeature {
  name: string;
  display_name: string;
  category: string;
  data_type: string;
  unit: string | null;
  value: string | number | boolean | null;
  availability: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE';
  quality: 'COMPLETE' | 'PARTIAL' | 'MISSING_SOURCE_DATA';
  source: string;
}

export interface SessionFingerprint {
  id: string;
  session_id: string;
  capture_id: string;
  feature_version: string;
  signature: string;
  created_at: string;
  feature_count: number;
  features: FingerprintFeature[];
}

export interface FingerprintSummary {
  id: string;
  session_id: string;
  capture_id: string;
  feature_version: string;
  signature: string;
  created_at: string;
  feature_count: number;
}

export interface NumericStatistics {
  count: number;
  mean: number;
  median: number;
  min: number;
  max: number;
  std_dev: number;
  p25: number;
  p50: number;
  p75: number;
  p95: number;
}

export interface CategoricalStatistics {
  count: number;
  unique_count: number;
  frequencies: Record<string, number>;
  relative_frequencies: Record<string, number>;
  mode: string | null;
}

export interface BooleanStatistics {
  count: number;
  true_count: number;
  false_count: number;
  true_ratio: number;
  false_ratio: number;
}

export interface BaselineFeatureProfile {
  name: string;
  display_name: string;
  category: string;
  data_type: string;
  unit: string | null;
  numeric_stats?: NumericStatistics | null;
  categorical_stats?: CategoricalStatistics | null;
  boolean_stats?: BooleanStatistics | null;
  total_samples: number;
  available_samples: number;
  missing_samples: number;
  completeness_ratio: number;
}

export interface BaselineCoverage {
  sessions_included: string[];
  total_sessions: number;
  features_profiled: number;
  features_available: number;
  features_missing: number;
  feature_completeness: number;
  first_observation: string | null;
  last_observation: string | null;
}

export interface BaselineDataQuality {
  complete_sessions: number;
  partial_sessions: number;
  missing_data_features: number;
  invalid_records: number;
  quality_rating: 'HIGH' | 'SUFFICIENT' | 'INSUFFICIENT';
}

export interface BaselineSummary {
  id: string;
  name: string;
  description: string | null;
  version: number;
  feature_version: string;
  status: string;
  is_active: boolean;
  session_count: number;
  feature_count: number;
  minimum_sessions: number;
  first_observation: string | null;
  last_observation: string | null;
  created_at: string;
  updated_at: string;
}

export interface BaselineProfile extends BaselineSummary {
  coverage: BaselineCoverage;
  data_quality: BaselineDataQuality;
  features: BaselineFeatureProfile[];
}

export interface BaselineSessionItem {
  session_id: string;
  fingerprint_id: string;
  start_time: string | null;
  end_time: string | null;
  duration: number | null;
  packets: number | null;
  bytes: number | null;
  source: string | null;
  destination: string | null;
  state: string | null;
  ike_version: string | null;
}

export interface FingerprintComparisonItem {
  feature_name: string;
  display_name: string;
  category: string;
  data_type: string;
  unit: string | null;
  value_a: string | number | boolean | null;
  value_b: string | number | boolean | null;
  availability_a: string;
  availability_b: string;
}

export interface FingerprintComparison {
  fingerprint_a: FingerprintSummary;
  fingerprint_b: FingerprintSummary;
  features: FingerprintComparisonItem[];
}

export interface BaselineComparisonItem {
  feature_name: string;
  display_name: string;
  category: string;
  data_type: string;
  unit: string | null;
  observed_value: string | number | boolean | null;
  baseline_mean: number | null;
  baseline_median: number | null;
  baseline_min: number | null;
  baseline_max: number | null;
  baseline_std_dev: number | null;
  baseline_mode: string | null;
  availability: string;
}

export interface BaselineComparison {
  fingerprint_id: string;
  session_id: string;
  baseline_id: string;
  baseline_name: string;
  baseline_version: number;
  features: BaselineComparisonItem[];
}

export interface BaselineBuildRequest {
  name: string;
  description?: string | null;
  session_ids?: string[] | null;
  minimum_sessions?: number;
  activate?: boolean;
}
