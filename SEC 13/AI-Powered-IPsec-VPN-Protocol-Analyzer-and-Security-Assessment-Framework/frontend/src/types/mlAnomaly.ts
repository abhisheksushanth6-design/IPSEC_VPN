/**
 * TypeScript type definitions for Layer 08 — AI / ML Anomaly Detection Engine.
 *
 * Strictly typed contracts for models, training datasets, anomaly inference runs,
 * feature contributions, and 3-signal comparison.
 */

export type MLModelStatus =
  | 'NOT INITIALIZED'
  | 'NOT_INITIALIZED'
  | 'READY'
  | 'TRAINING'
  | 'TRAINED'
  | 'INFERENCE READY'
  | 'ERROR'
  | 'INSUFFICIENT DATA'
  | 'FAILED'
  | 'STALE';

export type AnomalyClassification = 'NORMAL' | 'ANOMALOUS';

export type FeatureDeviationDirection = 'ABOVE_REFERENCE' | 'BELOW_REFERENCE' | 'WITHIN_RANGE';

export interface MLModelConfiguration {
  contamination: number;
  n_estimators: number;
  max_samples: string | number;
  random_state: number;
}

export interface MLModelDiagnostics {
  sample_count: number;
  feature_count: number;
  contamination: number;
  score_min: number;
  score_max: number;
  score_mean: number;
  score_std: number;
  score_p25: number;
  score_p50: number;
  score_p75: number;
  score_threshold: number;
}

export interface MLModelSummary {
  id: string;
  name: string;
  model_type: string;
  model_version: string;
  feature_version: string;
  preprocessing_version: string;
  training_samples: number;
  feature_count: number;
  status: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface MLModelDetail extends MLModelSummary {
  configuration: Record<string, any>;
  metrics?: MLModelDiagnostics | null;
  feature_names: string[];
  model_checksum?: string | null;
  training_dataset_id?: string | null;
  baseline_id?: string | null;
}

export interface MLModelTrainRequest {
  baseline_id: string;
  name?: string;
  model_type?: string;
  minimum_training_samples?: number;
  configuration?: Partial<MLModelConfiguration>;
}

export interface TrainingDatasetSummary {
  id: string;
  baseline_id: string;
  dataset_version: string;
  feature_version: string;
  sample_count: number;
  feature_count: number;
  session_ids: string[];
  created_at: string;
}

export interface TrainingDatasetDetail extends TrainingDatasetSummary {
  feature_names: string[];
  missing_data_summary: Record<string, number>;
}

export interface AnomalyInferenceRequest {
  session_id: string;
  model_id?: string;
}

export interface AnomalyFeatureContribution {
  feature_name: string;
  display_name: string;
  category: string;
  data_type: string;
  observed_value: any;
  reference_mean?: number | null;
  reference_std?: number | null;
  reference_median?: number | null;
  contribution_score: number;
  deviation?: number | null;
  direction: FeatureDeviationDirection;
  evidence_description: string;
}

export interface SignalComparisonSummary {
  baseline_id?: string | null;
  baseline_status: string;
  drift_analysis_id?: string | null;
  drift_status: string;
  ml_model_id: string;
  ml_status: string;
}

export interface AnomalyAnalysis {
  id: string;
  session_id: string;
  model_id: string;
  model_version: string;
  feature_version: string;
  preprocessing_version: string;
  classification: AnomalyClassification;
  raw_score: number;
  display_score: number;
  features_analyzed: number;
  features_anomalous: number;
  explanation_summary: string;
  feature_contributions: AnomalyFeatureContribution[];
  signal_comparison: SignalComparisonSummary;
  analyzed_at: string;
}

export interface AnomalyAnalysisSummary {
  id: string;
  session_id: string;
  model_id: string;
  model_version: string;
  feature_version: string;
  classification: AnomalyClassification;
  raw_score: number;
  display_score: number;
  features_analyzed: number;
  features_anomalous: number;
  explanation_summary: string;
  analyzed_at: string;
}

export interface AIAnomalyEngineStatus {
  status: MLModelStatus;
  active_model?: MLModelSummary | null;
  total_models: number;
  feature_version: string;
  preprocessing_version: string;
  models_dir_writable: boolean;
  available_baselines_count: number;
  available_sessions_count: number;
}

export interface AnomalyFilterOptions {
  classification: 'ALL' | 'NORMAL' | 'ANOMALOUS';
  modelVersion: string;
  search: string;
}
