import {
  Activity,
  BrainCircuit,
  Database,
  FileText,
  Fingerprint,
  Gauge,
  GitCompare,
  KeyRound,
  LayoutDashboard,
  Network,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  TestTube2,
} from 'lucide-react';

import type {
  ArchitectureCategoryDefinition,
  ArchitectureLayer,
  ArchitectureLayerDetail,
  ArchitectureLayerPresentation,
  ArchitectureStatus,
} from '@/types';

/** The five visual groupings, in pipeline order. */
export const ARCHITECTURE_CATEGORIES: readonly ArchitectureCategoryDefinition[] = [
  { category: 'DATA GENERATION & COLLECTION', from: 1, to: 2 },
  { category: 'PROTOCOL & SECURITY ANALYSIS', from: 3, to: 7 },
  { category: 'INTELLIGENCE & DETECTION', from: 8, to: 10 },
  { category: 'PLATFORM FOUNDATION', from: 11, to: 12 },
  { category: 'PRESENTATION & REPORTING', from: 13, to: 14 },
];

export const EXPECTED_LAYER_COUNT = 14;

const VALID_STATUSES: readonly ArchitectureStatus[] = [
  'NOT INITIALIZED',
  'FOUNDATION CREATED',
  'FOUNDATION READY',
  'IN DEVELOPMENT',
  'OPERATIONAL',
  'IMPLEMENTED',
];

/**
 * Presentation-only metadata, keyed by layer number. Layer names and statuses
 * are deliberately absent: the backend is the sole authority for those.
 */
export const LAYER_PRESENTATION: Record<number, ArchitectureLayerPresentation> = {
  1: {
    icon: TestTube2,
    category: 'DATA GENERATION & COLLECTION',
    purpose: 'Generate, test and validate IPsec VPN behaviour in a controlled environment.',
    futureInputs: ['Tunnel configuration', 'Test scenarios'],
    futureOutputs: ['Live IPsec traffic', 'Tunnel state'],
  },
  2: {
    icon: Activity,
    category: 'DATA GENERATION & COLLECTION',
    purpose: 'Collect network traffic and IPsec-related packets for downstream analysis.',
    futureInputs: ['Network interfaces', 'Capture filters'],
    futureOutputs: ['Raw packet records', 'Capture metadata'],
    route: '/live-monitor',
  },
  3: {
    icon: Network,
    category: 'PROTOCOL & SECURITY ANALYSIS',
    purpose: 'Examine packet structures, headers, IKE exchanges and IPsec protocol information.',
    futureInputs: ['Raw packet records'],
    futureOutputs: ['Decoded protocol fields', 'IKE exchange records', 'ESP / AH records'],
    route: '/packet-analysis',
  },
  4: {
    icon: KeyRound,
    category: 'PROTOCOL & SECURITY ANALYSIS',
    purpose: 'Track Security Associations and their lifecycle states across VPN sessions.',
    futureInputs: ['IKE exchange records', 'ESP / AH records'],
    futureOutputs: ['SA state transitions', 'Session records'],
    route: '/sa-lifecycle',
  },
  5: {
    icon: SlidersHorizontal,
    category: 'PROTOCOL & SECURITY ANALYSIS',
    purpose: 'Transform protocol and session observations into structured features.',
    futureInputs: ['Decoded protocol fields', 'Session records'],
    futureOutputs: ['Feature vectors'],
  },
  6: {
    icon: Fingerprint,
    category: 'PROTOCOL & SECURITY ANALYSIS',
    purpose: 'Build behavioural profiles of expected VPN session and protocol characteristics.',
    futureInputs: ['Feature vectors'],
    futureOutputs: ['Session fingerprints', 'Baseline profiles'],
    route: '/baseline-profiles',
  },
  7: {
    icon: GitCompare,
    category: 'PROTOCOL & SECURITY ANALYSIS',
    purpose: 'Identify deviations between observed behaviour and established baselines.',
    futureInputs: ['Feature vectors', 'Baseline profiles'],
    futureOutputs: ['Drift events', 'Drift magnitude'],
    route: '/security-drift',
  },
  8: {
    icon: BrainCircuit,
    category: 'INTELLIGENCE & DETECTION',
    purpose: 'Identify potentially abnormal VPN behaviour using machine-learning-based analysis.',
    futureInputs: ['Feature vectors', 'Session profiles', 'Baseline information'],
    futureOutputs: ['Anomaly score', 'Anomaly classification', 'Explainability information'],
    route: '/ai-anomalies',
  },
  9: {
    icon: ShieldAlert,
    category: 'INTELLIGENCE & DETECTION',
    purpose: 'Evaluate observations against security rules and vulnerability-detection logic.',
    futureInputs: ['Decoded protocol fields', 'SA state transitions'],
    futureOutputs: ['Vulnerability findings', 'Rule matches'],
    route: '/vulnerabilities',
  },
  10: {
    icon: Gauge,
    category: 'INTELLIGENCE & DETECTION',
    purpose: 'Combine security findings into an overall risk assessment and decision context.',
    futureInputs: ['Drift events', 'Anomaly scores', 'Vulnerability findings'],
    futureOutputs: ['Risk score', 'Risk classification', 'Recommendations'],
    route: '/risk-assessment',
  },
  11: {
    icon: Database,
    category: 'PLATFORM FOUNDATION',
    purpose: 'Store configuration, analysis results, security findings and system information.',
    futureInputs: ['Records from every analysis layer'],
    futureOutputs: ['Persisted state', 'Query results'],
  },
  12: {
    icon: Server,
    category: 'PLATFORM FOUNDATION',
    purpose: 'Provide the application backend, API services, business logic and integration layer.',
    futureInputs: ['Client requests', 'Persisted state'],
    futureOutputs: ['REST responses', 'WebSocket events'],
  },
  13: {
    icon: LayoutDashboard,
    category: 'PRESENTATION & REPORTING',
    purpose: 'Present the analyst-facing interface for monitoring, analysis and assessment.',
    futureInputs: ['REST responses', 'WebSocket events'],
    futureOutputs: ['Interactive views', 'Analyst actions'],
    route: '/overview',
  },
  14: {
    icon: FileText,
    category: 'PRESENTATION & REPORTING',
    purpose: 'Generate structured security assessment reports for analysis results and findings.',
    futureInputs: ['Risk assessment', 'Findings', 'Session records'],
    futureOutputs: ['PDF reports', 'Report history'],
    route: '/reports',
  },
};

function isValidStatus(value: string): value is ArchitectureStatus {
  return (VALID_STATUSES as readonly string[]).includes(value);
}

/**
 * Merge backend layers with presentation metadata. Returns null when the
 * payload does not describe the locked architecture, so callers can show an
 * explicit unavailable state rather than a partial diagram.
 */
export function buildArchitectureLayers(
  layers: ArchitectureLayer[] | null | undefined,
): ArchitectureLayerDetail[] | null {
  if (!layers || layers.length !== EXPECTED_LAYER_COUNT) return null;

  const merged: ArchitectureLayerDetail[] = [];
  for (const layer of layers) {
    const presentation = LAYER_PRESENTATION[layer.number];
    if (!presentation || !isValidStatus(layer.status) || !layer.name.trim()) return null;
    merged.push({ ...layer, ...presentation, id: `layer-${String(layer.number).padStart(2, '0')}` });
  }

  const ordered = [...merged].sort((a, b) => a.number - b.number);
  const contiguous = ordered.every((layer, index) => layer.number === index + 1);
  return contiguous ? ordered : null;
}

/** Count layers with any foundation in place, and those fully implemented. */
export function summarizeProgress(layers: ArchitectureLayerDetail[]) {
  const foundation = layers.filter((l) => l.status !== 'NOT INITIALIZED').length;
  const implemented = layers.filter(
    (l) => l.status === 'OPERATIONAL' || l.status === 'IMPLEMENTED',
  ).length;
  return { foundation, implemented, total: layers.length };
}
