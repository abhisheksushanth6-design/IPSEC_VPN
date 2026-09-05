/** Shapes returned by the backend API. Mirrors `backend/app/schemas`. */

export interface HealthResponse {
  project: string;
  status: string;
}

/** Status values a layer can report. Matches `LayerStatus` in the backend. */
export type LayerStatusValue =
  | 'NOT INITIALIZED'
  | 'FOUNDATION CREATED'
  | 'FOUNDATION READY'
  | 'IMPLEMENTED';

export interface ArchitectureLayer {
  number: number;
  name: string;
  package: string;
  status: LayerStatusValue;
  description: string;
}

export interface SystemStatus {
  project: string;
  backend_status: string;
  database_status: string;
  application_mode: string;
  architecture_layers: ArchitectureLayer[];
  total_layers: number;
  initialized_layers: number;
}

/** Error envelope produced by the backend exception handlers. */
export interface ApiErrorBody {
  error: string;
  detail?: unknown;
}
