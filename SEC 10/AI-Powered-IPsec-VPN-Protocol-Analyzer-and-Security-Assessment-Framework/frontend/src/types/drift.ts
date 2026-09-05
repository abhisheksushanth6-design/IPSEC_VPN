/**
 * Layer 07 — Security Drift Detection TypeScript definitions.
 *
 * Types for deterministic behavioral drift evaluation, feature deviations,
 * threshold configuration, and historical records.
 */

export type DriftEngineState =
  | 'NOT INITIALIZED'
  | 'READY'
  | 'ANALYZING'
  | 'AVAILABLE'
  | 'ERROR'
  | 'INSUFFICIENT DATA';

export type DriftSeverity = 'NONE' | 'LOW' | 'MODERATE' | 'HIGH';

export type DriftStatus =
  | 'WITHIN BASELINE'
  | 'DRIFT DETECTED'
  | 'ANALYSIS UNAVAILABLE'
  | 'INSUFFICIENT DATA'
  | 'ERROR';

export type ComparisonMethod =
  | 'Z-Score (Gaussian Standard Deviation)'
  | 'Zero-Variance Exact Match'
  | 'Interquartile Percentile Range (IQR)'
  | 'Categorical Distribution Frequency'
  | 'Boolean State Probability'
  | 'Baseline Reference Unavailable'
  | 'Feature Observation Unavailable';

export interface DriftEngineStatus {
  state: DriftEngineState;
  active_baseline_id: string | null;
  active_baseline_name: string | null;
  total_analyses: number;
  sessions_evaluated: number;
  drifting_sessions_count: number;
  feature_schema_version: string;
  configuration_version: string;
}

export interface DriftThresholdConfig {
  config_version: string;
  z_score_low: number;
  z_score_moderate: number;
  z_score_high: number;
  enable_percentile_check: boolean;
  iqr_multiplier: number;
  unseen_category_severity: string;
  boolean_flip_severity: string;
  category_rare_threshold: number;
  minimum_baseline_samples: number;
}

export interface DriftAnalyzeRequest {
  session_id: string;
  baseline_id?: string | null;
  config_override?: Partial<DriftThresholdConfig> | null;
}

export interface FeatureDrift {
  feature_name: string;
  display_name: string;
  category: string;
  data_type: string;
  unit?: string | null;
  current_value: any;
  baseline_mean?: number | null;
  baseline_std?: number | null;
  baseline_median?: number | null;
  baseline_distribution?: Record<string, any> | null;
  deviation?: number | null;
  z_score?: number | null;
  comparison_method: string;
  drift_detected: boolean;
  severity: DriftSeverity;
  reason: string;
}

export interface DriftAnalysisSummary {
  id: string;
  session_id: string;
  baseline_id: string;
  baseline_version: number;
  feature_version: string;
  configuration_version: string;
  status: DriftStatus;
  severity: DriftSeverity;
  features_analyzed: number;
  features_drifting: number;
  analyzed_at: string;
}

export interface DriftAnalysis extends DriftAnalysisSummary {
  feature_results: FeatureDrift[];
  thresholds_used: Record<string, any>;
}

export interface DriftFilterOptions {
  status?: string;
  severity?: string;
  category?: string;
  searchQuery?: string;
}
