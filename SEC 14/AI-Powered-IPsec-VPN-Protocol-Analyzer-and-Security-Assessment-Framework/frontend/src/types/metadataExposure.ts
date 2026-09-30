export type ExposureRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface MetadataExposureItem {
  id: string;
  capture_id: string;
  session_id?: string | null;
  overall_score: number;
  risk_level: ExposureRiskLevel;
  spi_leakage_score: number;
  sequence_leakage_score: number;
  packet_length_leakage_score: number;
  timing_leakage_score: number;
  topology_leakage_score: number;
  findings: Array<{
    vector: string;
    description: string;
    evidence: string;
  }>;
  recommendations: string[];
  created_at: string;
}

export interface MetadataExposureSummary {
  capture_id: string;
  average_score: number;
  highest_risk_level: ExposureRiskLevel;
  total_assessed: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  dominant_leakage_vector: string;
}
