import {
  Activity,
  BrainCircuit,
  Cable,
  FileText,
  Fingerprint,
  FlaskConical,
  Gauge,
  KeyRound,
  LayoutDashboard,
  Layers,
  Network,
  Server,
  Settings,
  ShieldAlert,
  Sparkles,
  EyeOff,
} from 'lucide-react';

import type { NavigationGroup, NavigationItem } from '@/types';

/**
 * The only definition of the application's navigation. Routes in `App.tsx`
 * and the sidebar are both generated from this list, so the two cannot drift.
 */
export const NAVIGATION: NavigationGroup[] = [
  {
    items: [
      {
        label: 'Overview',
        path: '/overview',
        icon: LayoutDashboard,
        description: 'System-wide summary of the framework and its layers.',
      },
      {
        label: 'Architecture',
        path: '/architecture',
        icon: Layers,
        description: 'The 10-layer functional processing pipeline and its implementation status.',
      },
      {
        label: 'Test Environment',
        path: '/environment',
        icon: Server,
        description: 'Layer 01 VirtualBox testbed profiles, management, and verification.',
      },
    ],
  },
  {
    title: 'Monitoring',
    items: [
      {
        label: 'Live Monitor',
        path: '/live-monitor',
        icon: Activity,
        description: 'Real-time view of tunnel activity as it is observed.',
      },
      {
        label: 'Packet Analysis',
        path: '/packet-analysis',
        icon: Network,
        description: 'Decoded packet records and protocol-level inspection.',
      },
      {
        label: 'IPsec Sessions',
        path: '/ipsec-sessions',
        icon: Cable,
        description: 'Tunnel sessions observed between negotiating peers.',
      },
    ],
  },
  {
    title: 'Security Analysis',
    items: [
      {
        label: 'SA & Protocol State',
        path: '/sa-lifecycle',
        icon: KeyRound,
        description: 'Security Association parameters, state transitions, and lifetime metrics.',
      },
      {
        label: 'Feature Extraction',
        path: '/feature-engineering',
        icon: FlaskConical,
        description: 'Structured features derived from observed packets, sessions and SAs.',
      },
      {
        label: 'IPsec Session Fingerprinting',
        path: '/baseline-profiling',
        icon: Fingerprint,
        description: 'Compact behavioral session fingerprints derived from observable IPsec flow characteristics.',
      },
      {
        label: 'AI Traffic Classification',
        path: '/traffic-analysis',
        icon: Sparkles,
        description: 'AI-driven classification of encapsulated payload types (VoIP, Web, Email, Video, ICMP) inside ESP tunnels.',
      },
      {
        label: 'Metadata Exposure',
        path: '/metadata-exposure',
        icon: EyeOff,
        description: '5-vector side-channel exposure and leakage assessment (SPI, Monotonicity, Length/TFC, Timing, Topology).',
      },
      {
        label: 'Security Assessment',
        path: '/vulnerabilities',
        icon: ShieldAlert,
        description: 'Comprehensive cryptographic strength, compliance, replay protection, and security evaluation.',
      },
      {
        label: 'Risk & Threat Analysis',
        path: '/risk-assessment',
        icon: Gauge,
        description: 'Explainable risk scoring, threat matrix, and actionable recommendations.',
      },
    ],
  },
  {
    title: 'Reporting',
    items: [
      {
        label: 'Reports',
        path: '/reports',
        icon: FileText,
        description: 'Generated assessment reports and export history.',
      },
    ],
  },
  {
    title: 'Supplementary Analysis',
    items: [
      {
        label: 'Supplementary Anomaly Detection',
        path: '/ai-anomaly-detection',
        icon: BrainCircuit,
        description: 'Optional supplementary behavioral anomaly detection.',
      },
    ],
  },
  {
    title: 'System',
    items: [
      {
        label: 'System Settings',
        path: '/settings',
        icon: Settings,
        description: 'Application configuration and operating mode.',
      },
    ],
  },
];

/** Flat list of every navigable item, in sidebar order. */
export const NAVIGATION_ITEMS: NavigationItem[] = NAVIGATION.flatMap(
  (group) => group.items,
);

/** Look up an item by pathname; used for breadcrumbs and document titles. */
export function findNavigationItem(pathname: string): NavigationItem | undefined {
  return NAVIGATION_ITEMS.find((item) => item.path === pathname);
}

/** Find the group title containing a path, for breadcrumbs. */
export function findGroupTitle(pathname: string): string | undefined {
  return NAVIGATION.find((group) =>
    group.items.some((item) => item.path === pathname),
  )?.title;
}
