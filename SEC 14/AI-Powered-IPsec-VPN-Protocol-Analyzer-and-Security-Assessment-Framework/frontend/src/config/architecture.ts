import {
  Activity,
  BrainCircuit,
  FileText,
  Fingerprint,
  Gauge,
  KeyRound,
  Network,
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
  { category: 'PROTOCOL & SESSION ANALYSIS', from: 3, to: 4 },
  { category: 'FEATURE & FINGERPRINTING', from: 5, to: 6 },
  { category: 'AI CLASSIFICATION & ASSESSMENT', from: 7, to: 9 },
  { category: 'PRESENTATION & REPORTING', from: 10, to: 10 },
];

export const EXPECTED_LAYER_COUNT = 10;

/**
 * Presentation-only metadata, keyed by layer number. Layer names and statuses
 * are deliberately absent: the backend is the sole authority for those.
 */
export const LAYER_PRESENTATION: Record<number, ArchitectureLayerPresentation> = {
  1: {
    icon: TestTube2,
    category: 'DATA GENERATION & COLLECTION',
    purpose: 'Controlled environment for generating, testing, and validating IPsec VPN behavior across Tunnel/Transport modes, AES ciphers, DH groups, PFS, and traffic profiles.',
    futureInputs: ['Tunnel configuration', 'Testbed profiles'],
    futureOutputs: ['Live IPsec traffic', 'Tunnel state'],
    route: '/environment',
  },
  2: {
    icon: Activity,
    category: 'DATA GENERATION & COLLECTION',
    purpose: 'Collect raw network traffic, PCAP captures, and live streams across IKE negotiation, ESP, and AH.',
    futureInputs: ['Network interfaces', 'Capture filters', 'PCAP files'],
    futureOutputs: ['Raw packet records', 'Capture metadata'],
    route: '/live-monitor',
  },
  3: {
    icon: Network,
    category: 'PROTOCOL & SESSION ANALYSIS',
    purpose: 'Decode and parse packet structures, IKE versions, ESP/AH headers, Tunnel/Transport mode, and IPv4/IPv6.',
    futureInputs: ['Raw packet records'],
    futureOutputs: ['Decoded protocol fields', 'IKE exchange records', 'ESP / AH records'],
    route: '/packet-analysis',
  },
  4: {
    icon: KeyRound,
    category: 'PROTOCOL & SESSION ANALYSIS',
    purpose: 'Analyze Security Association parameters, protocol states, lifetime limits, and negotiated crypto transforms.',
    futureInputs: ['IKE exchange records', 'ESP / AH records'],
    futureOutputs: ['SA state transitions', 'Session records', 'Key lifetime metrics'],
    route: '/sa-lifecycle',
  },
  5: {
    icon: SlidersHorizontal,
    category: 'FEATURE & FINGERPRINTING',
    purpose: 'Extract compact packet size, timing, burst frequency, directionality, and metadata features.',
    futureInputs: ['Decoded packets', 'Session records', 'SA characteristics'],
    futureOutputs: ['Statistical feature vectors'],
    route: '/feature-engineering',
  },
  6: {
    icon: Fingerprint,
    category: 'FEATURE & FINGERPRINTING',
    purpose: 'Generate compact behavioral session fingerprints from observable flow characteristics to empower traffic classification.',
    futureInputs: ['Feature vectors', 'Flow metrics'],
    futureOutputs: ['Session fingerprints', 'Behavioral flow signatures'],
    route: '/baseline-profiling',
  },
  7: {
    icon: BrainCircuit,
    category: 'AI CLASSIFICATION & ASSESSMENT',
    purpose: 'Predict encapsulated traffic types (VoIP, Web, Email, Video, ICMP), VPN modes, and crypto configurations with calibrated AI confidence.',
    futureInputs: ['Feature vectors', 'Session fingerprints', 'Observable metadata'],
    futureOutputs: ['Traffic category prediction', 'AI confidence score', 'Protocol classification'],
    route: '/traffic-analysis',
  },
  8: {
    icon: ShieldAlert,
    category: 'AI CLASSIFICATION & ASSESSMENT',
    purpose: 'Evaluate cryptographic strength, configuration compliance, key lifetime, replay protection, PFS, and 5-vector metadata exposure.',
    futureInputs: ['Crypto configurations', 'Security rules', 'Observable metadata vectors'],
    futureOutputs: ['Cryptographic strength grade', 'Rule compliance findings', 'Metadata exposure score'],
    route: '/vulnerabilities',
  },
  9: {
    icon: Gauge,
    category: 'AI CLASSIFICATION & ASSESSMENT',
    purpose: 'Generate explainable overall security scores, risk scores, threat matrices, and actionable recommendations (Finding -> Evidence -> Severity -> Reason -> Recommendation).',
    futureInputs: ['Security assessment findings', 'AI predictions', 'Threat matrix'],
    futureOutputs: ['Security score (0-100)', 'Risk score (0-100)', 'Threat matrix', 'Actionable recommendations'],
    route: '/risk-assessment',
  },
  10: {
    icon: FileText,
    category: 'PRESENTATION & REPORTING',
    purpose: 'Interactive SOC dashboard and auditable Executive & Technical PDF reports distinguishing Observed, Inferred, Predicted, and Unavailable data.',
    futureInputs: ['All pipeline layers telemetry', 'Security findings', 'Traffic predictions'],
    futureOutputs: ['Interactive dashboard visualization', 'Executive PDF report', 'Technical PDF report'],
    route: '/reports',
  },
};

export interface LayerStatusAnalysis {
  /** The canonical status string for display and filtering */
  normalizedStatus: ArchitectureStatus;
  /** Whether the layer's technical foundation exists */
  hasFoundation: boolean;
  /** Whether the layer is genuinely fully operational / implemented */
  isFullyImplemented: boolean;
  /** Visual tone for UI indicators */
  tone: 'success' | 'warning' | 'danger' | 'info' | 'neutral';
}

/**
 * Centralized, authoritative status analysis and normalization function.
 * Evaluates backend layer contract attributes: status, overall_status,
 * foundation_available, implementation_available, and runtime_verified.
 *
 * Rules:
 * - "Foundation components available" counts layers whose foundation exists.
 * - "Fully implemented" counts layers that are genuinely operational or fully operational.
 * - "READY" must not automatically be treated as fully implemented unless the official
 *   layer contract confirms that meaning (via implementation_available === true or overall_status === 'FULLY_OPERATIONAL' / 'OPERATIONAL').
 * - "NOT_INITIALIZED" must never count as implemented.
 * - Missing, malformed, or unknown statuses are handled safely and visibly without crashing.
 */
export function analyzeLayerStatus(layer: Partial<ArchitectureLayer>): LayerStatusAnalysis {
  const rawStatus = String(layer.status ?? '').trim().toUpperCase().replace(/_/g, ' ');
  const rawOverall = String(layer.overall_status ?? '').trim().toUpperCase().replace(/_/g, ' ');

  const hasExplicitFoundation = layer.foundation_available === true;
  const foundationExplicitlyFalse = layer.foundation_available === false;
  const hasExplicitImplementation = layer.implementation_available === true;
  const isRuntimeVerified = layer.runtime_verified === true;

  // 1. Strict Exclusion: NOT INITIALIZED must never count as implemented
  if (rawStatus === 'NOT INITIALIZED' || rawOverall === 'NOT INITIALIZED' || (!rawStatus && !rawOverall)) {
    return {
      normalizedStatus: 'NOT INITIALIZED',
      hasFoundation: hasExplicitFoundation,
      isFullyImplemented: false,
      tone: 'neutral',
    };
  }

  // 2. Strict Exclusion: Failures / Errors
  if (rawStatus === 'ERROR' || rawStatus === 'FAILED' || rawOverall === 'FAILED') {
    return {
      normalizedStatus: 'NOT INITIALIZED',
      hasFoundation: hasExplicitFoundation || (!foundationExplicitlyFalse && rawStatus !== 'ERROR'),
      isFullyImplemented: false,
      tone: 'danger',
    };
  }

  // 3. Operational / Implemented statuses
  const isDirectlyOperational =
    rawStatus === 'OPERATIONAL' ||
    rawStatus === 'FULLY OPERATIONAL' ||
    rawStatus === 'IMPLEMENTED' ||
    rawOverall === 'FULLY OPERATIONAL' ||
    rawOverall === 'OPERATIONAL';

  if (isDirectlyOperational) {
    return {
      normalizedStatus: 'OPERATIONAL',
      hasFoundation: !foundationExplicitlyFalse,
      isFullyImplemented: true,
      tone: 'success',
    };
  }

  // 4. READY status:
  // "READY" must not automatically be treated as fully implemented unless
  // the official layer contract confirms that meaning.
  if (rawStatus === 'READY') {
    const isConfirmedByContract =
      hasExplicitImplementation ||
      rawOverall === 'FULLY OPERATIONAL' ||
      rawOverall === 'OPERATIONAL' ||
      isRuntimeVerified;

    if (isConfirmedByContract) {
      return {
        normalizedStatus: 'OPERATIONAL',
        hasFoundation: true,
        isFullyImplemented: true,
        tone: 'success',
      };
    }

    // Scaffolding or mock fixture without confirmed implementation
    return {
      normalizedStatus: 'READY',
      hasFoundation: true,
      isFullyImplemented: false,
      tone: 'info',
    };
  }

  // 5. Explicit Foundation States
  if (rawStatus === 'FOUNDATION READY') {
    return {
      normalizedStatus: 'FOUNDATION READY',
      hasFoundation: true,
      isFullyImplemented: false,
      tone: 'info',
    };
  }

  if (rawStatus === 'FOUNDATION CREATED') {
    return {
      normalizedStatus: 'FOUNDATION CREATED',
      hasFoundation: true,
      isFullyImplemented: false,
      tone: 'info',
    };
  }

  if (rawStatus === 'IN DEVELOPMENT') {
    return {
      normalizedStatus: 'IN DEVELOPMENT',
      hasFoundation: true,
      isFullyImplemented: false,
      tone: 'warning',
    };
  }

  // 6. Safe fallback for malformed or unknown statuses
  return {
    normalizedStatus: 'NOT INITIALIZED',
    hasFoundation: hasExplicitFoundation,
    isFullyImplemented: false,
    tone: 'neutral',
  };
}

/** Convenience wrapper returning just the normalized status string. */
export function normalizeLayerStatus(layer: Partial<ArchitectureLayer>): ArchitectureStatus {
  return analyzeLayerStatus(layer).normalizedStatus;
}

/**
 * Merge backend layers with presentation metadata and canonical status normalization.
 * Returns null when the payload does not describe the locked 14-layer architecture.
 */
export function buildArchitectureLayers(
  layers: ArchitectureLayer[] | null | undefined,
): ArchitectureLayerDetail[] | null {
  if (!layers || layers.length !== EXPECTED_LAYER_COUNT) return null;

  const merged: ArchitectureLayerDetail[] = [];
  for (const layer of layers) {
    const presentation = LAYER_PRESENTATION[layer.number];
    if (!presentation || !layer.name?.trim()) return null;

    const analysis = analyzeLayerStatus(layer);

    merged.push({
      ...layer,
      ...presentation,
      status: analysis.normalizedStatus,
      id: `layer-${String(layer.number).padStart(2, '0')}`,
    });
  }

  const ordered = [...merged].sort((a, b) => a.number - b.number);
  const contiguous = ordered.every((layer, index) => layer.number === index + 1);
  return contiguous ? ordered : null;
}

/**
 * Count layers with technical foundation in place, and those genuinely fully implemented.
 * Total is strictly derived from the actual layer list.
 */
export function summarizeProgress(layers: ArchitectureLayerDetail[]) {
  let foundation = 0;
  let implemented = 0;

  for (const layer of layers) {
    const analysis = analyzeLayerStatus(layer);
    if (analysis.hasFoundation) foundation++;
    if (analysis.isFullyImplemented) implemented++;
  }

  return { foundation, implemented, total: layers.length };
}

