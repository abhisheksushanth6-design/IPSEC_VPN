import type { LucideIcon } from 'lucide-react';

import type { ArchitectureLayer } from './api';
import type { ModuleStatus } from './status';

/** Status a layer may report. Section 3 uses only the first three. */
export type ArchitectureStatus = ModuleStatus;

/** Visual grouping only. Never replaces the fourteen official layers. */
export type ArchitectureCategory =
  | 'DATA GENERATION & COLLECTION'
  | 'PROTOCOL & SESSION ANALYSIS'
  | 'FEATURE & FINGERPRINTING'
  | 'AI CLASSIFICATION & ASSESSMENT'
  | 'PRESENTATION & REPORTING';

export interface ArchitectureCategoryDefinition {
  category: ArchitectureCategory;
  /** Inclusive layer range. */
  from: number;
  to: number;
}

/**
 * Presentation metadata the frontend attaches to a layer. Keyed by number;
 * names, statuses and descriptions always come from the backend.
 */
export interface ArchitectureLayerPresentation {
  icon: LucideIcon;
  category: ArchitectureCategory;
  purpose: string;
  futureInputs: string[];
  futureOutputs: string[];
  /** Existing dashboard route for this layer's module, if one exists. */
  route?: string;
}

/** A backend layer merged with its presentation metadata. */
export interface ArchitectureLayerDetail extends ArchitectureLayer, ArchitectureLayerPresentation {
  id: string;
  status: ArchitectureStatus;
}
