/**
 * Layer 05 — Feature Extraction & Engineering.
 *
 * These mirror the backend schemas exactly. `value` is deliberately nullable:
 * null means the feature could not be calculated, which is a different fact
 * from a calculated zero, and the UI must keep the two apart.
 */

export type FeatureEntityType = 'PACKET' | 'SESSION' | 'SA';
export type FeatureLevel = FeatureEntityType;

export type FeatureType =
  | 'INTEGER'
  | 'FLOAT'
  | 'BOOLEAN'
  | 'CATEGORICAL'
  | 'TIMESTAMP';

export type FeatureCategory =
  | 'TRAFFIC'
  | 'TIMING'
  | 'PROTOCOL'
  | 'IPSEC'
  | 'IKE'
  | 'SA_LIFECYCLE'
  | 'DIRECTIONAL'
  | 'STATISTICAL';

export type FeatureAvailability = 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE';
export type FeatureQuality = 'COMPLETE' | 'PARTIAL' | 'MISSING_SOURCE_DATA';

export type NormalizationMethod =
  | 'NONE'
  | 'MIN_MAX'
  | 'STANDARD'
  | 'ROBUST'
  | 'CATEGORICAL_ENCODING';

export type FeatureEngineState =
  | 'NOT INITIALIZED'
  | 'READY'
  | 'PROCESSING'
  | 'AVAILABLE'
  | 'ERROR';

export type FeatureScalar = boolean | number | string | null;

export interface FeatureDefinition {
  name: string;
  display_name: string;
  description: string;
  level: FeatureLevel;
  category: FeatureCategory;
  data_type: FeatureType;
  unit: string | null;
  source: string;
  nullable: boolean;
  formula: string | null;
  normalization_method: NormalizationMethod;
  minimum_expected_value: number | null;
  maximum_expected_value: number | null;
}

export interface FeatureValue {
  name: string;
  display_name: string;
  description: string;
  value: FeatureScalar;
  data_type: FeatureType;
  category: FeatureCategory;
  level: FeatureLevel;
  unit: string | null;
  source: string;
  detail: string | null;
  availability: FeatureAvailability;
  quality: FeatureQuality;
  formula: string | null;
  normalization_method: NormalizationMethod;
  /** Reserved for a later section; always null while no parameters are fitted. */
  normalized_value: number | null;
}

export interface FeatureSourceAvailability {
  name: string;
  available: boolean;
  detail: string;
}

export interface FeatureVector {
  id: string;
  entity_type: FeatureEntityType;
  entity_id: string;
  entity_label: string;
  capture_id: string;
  feature_version: string;
  generated_at: string;
  feature_count: number;
  available_count: number;
  partial_count: number;
  unavailable_count: number;
  sources: FeatureSourceAvailability[];
  features: FeatureValue[];
}

export interface FeatureVectorSummary {
  id: string;
  entity_type: FeatureEntityType;
  entity_id: string;
  entity_label: string;
  feature_version: string;
  generated_at: string;
  feature_count: number;
  available_count: number;
  partial_count: number;
  unavailable_count: number;
}

export interface FeatureVectorPage {
  items: FeatureVectorSummary[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface FeatureEntity {
  entity_type: FeatureEntityType;
  entity_id: string;
  label: string;
  detail: string;
  extracted: boolean;
}

export interface FeatureEntityList {
  entity_type: FeatureEntityType;
  items: FeatureEntity[];
  source_available: boolean;
  detail: string;
}

export interface FeatureStatistics {
  vectors: number;
  packet_vectors: number;
  session_vectors: number;
  sa_vectors: number;
  total_features: number;
  available_features: number;
  partial_features: number;
  unavailable_features: number;
}

export interface FeatureEngineStatus {
  state: FeatureEngineState;
  feature_version: string;
  packets_available: boolean;
  sessions_available: boolean;
  sas_available: boolean;
  capture_id: string | null;
  capture_filename: string | null;
  extracted_at: string | null;
  registered_features: number;
  burst_window_seconds: number;
  statistics: FeatureStatistics | null;
  last_error: string | null;
}

export interface FeatureExtractionResponse {
  status: 'EXTRACTED';
  feature_version: string;
  generated_at: string;
  feature_vector: FeatureVector;
}

/** Display order and labels for the inspector's category sections. */
export const FEATURE_CATEGORY_ORDER: readonly FeatureCategory[] = [
  'TRAFFIC',
  'TIMING',
  'PROTOCOL',
  'IPSEC',
  'IKE',
  'SA_LIFECYCLE',
  'DIRECTIONAL',
  'STATISTICAL',
];

export const FEATURE_CATEGORY_LABELS: Record<FeatureCategory, string> = {
  TRAFFIC: 'Traffic Features',
  TIMING: 'Timing Features',
  PROTOCOL: 'Protocol Features',
  IPSEC: 'IPsec Features',
  IKE: 'IKE Features',
  SA_LIFECYCLE: 'SA Lifecycle Features',
  DIRECTIONAL: 'Directional Features',
  STATISTICAL: 'Statistical Features',
};

export const FEATURE_ENTITY_LABELS: Record<FeatureEntityType, string> = {
  PACKET: 'Packet',
  SESSION: 'Session',
  SA: 'Security Association',
};
