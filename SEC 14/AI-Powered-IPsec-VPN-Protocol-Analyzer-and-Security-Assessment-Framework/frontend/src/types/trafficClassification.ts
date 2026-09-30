export type TrafficType =
  | 'VOIP'
  | 'WHATSAPP'
  | 'EMAIL'
  | 'VIDEO_STREAMING'
  | 'WEB_BROWSING'
  | 'ICMP'
  | 'GENERIC'
  | 'OTHER';

export interface TrafficExplainabilityItem {
  feature?: string;
  signal?: string;
  value?: string | number;
  importance?: number;
  description?: string;
}

export interface TrafficClassificationItem {
  id: string;
  capture_id: string;
  session_id?: string | null;
  flow_id: string;
  traffic_type: TrafficType;
  confidence: number;
  probabilities: Record<string, number>;
  features: Record<string, any>;
  explainability: TrafficExplainabilityItem[];
  created_at: string;
}

export interface TrafficClassificationSummary {
  capture_id: string;
  total_classified: number;
  distribution: Record<string, number>;
  voip_count: number;
  whatsapp_count: number;
  email_count: number;
  video_streaming_count: number;
  generic_count: number;
  web_browsing_count?: number;
  icmp_count?: number;
  other_count?: number;
  average_confidence: number;
}
