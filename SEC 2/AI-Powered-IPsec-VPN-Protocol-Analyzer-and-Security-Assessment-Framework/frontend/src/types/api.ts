/** Shapes returned by the backend API. Mirrors `backend/app/schemas`. */

import type { ModuleStatus } from './status';

export interface HealthResponse {
  project: string;
  status: string;
}

/** Status values a layer can report. Matches `LayerStatus` in the backend. */
export type LayerStatusValue = ModuleStatus;

export interface ArchitectureLayer {
  number: number;
  name: string;
  package: string;
  status: LayerStatusValue;
  description: string;
}

/** Operating mode reported by the backend. */
export type ApplicationMode = 'DEMO' | 'DEVELOPMENT' | 'PRODUCTION' | 'LIVE';

export interface SystemStatus {
  project: string;
  backend_status: string;
  database_status: string;
  application_mode: string;
  architecture_layers: ArchitectureLayer[];
  total_layers: number;
  initialized_layers: number;
}

/**
 * Combined view of the backend used by the header and the overview page.
 * `reachable` is the single fact the UI needs before it claims anything.
 */
export interface SystemHealth {
  reachable: boolean;
  health: HealthResponse | null;
  status: SystemStatus | null;
}

/** Error envelope produced by the backend exception handlers. */
export interface ApiErrorBody {
  error: string;
  detail?: unknown;
}
