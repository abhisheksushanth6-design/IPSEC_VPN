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
  foundation_available?: boolean;
  implementation_available?: boolean;
  runtime_verified?: boolean;
  unit_tests_passed?: boolean;
  integration_tests_passed?: boolean;
  end_to_end_verified?: boolean;
  last_verified?: string | null;
  verification_errors?: string[];
  limitations?: string[];
  overall_status?: string;
  evidence_files?: string[];
}

/** Operating mode reported by the backend. */
export type ApplicationMode = 'DEMO' | 'DEVELOPMENT' | 'PRODUCTION' | 'LIVE' | 'STANDALONE';

export interface SystemStatus {
  project: string;
  backend_status: string;
  database_status: string;
  application_mode: string;
  architecture_layers: ArchitectureLayer[];
  total_layers: number;
  initialized_layers: number;
  // camelCase interoperability aliases
  backendStatus?: string;
  databaseStatus?: string;
  applicationMode?: string;
  totalLayers?: number;
  initializedLayers?: number;
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
