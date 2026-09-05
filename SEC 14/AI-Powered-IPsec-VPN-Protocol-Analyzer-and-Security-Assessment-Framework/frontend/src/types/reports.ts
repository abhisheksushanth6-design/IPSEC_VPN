/**
 * Type definitions for Layer 14 — Report Generation (PDF).
 */

export type ReportType = 'FULL' | 'SESSION' | 'VULNERABILITY';
export type ReportStatus = 'PENDING' | 'COMPLETED' | 'FAILED';

export interface ReportGenerateRequest {
  report_type: ReportType;
  session_id?: string | null;
  title?: string | null;
}

export interface ReportMetadata {
  id: string;
  report_type: ReportType;
  title: string;
  filename: string;
  file_size_bytes: number;
  page_count: number;
  status: ReportStatus;
  error_message?: string | null;
  generated_at: string;
  download_url: string;
}
