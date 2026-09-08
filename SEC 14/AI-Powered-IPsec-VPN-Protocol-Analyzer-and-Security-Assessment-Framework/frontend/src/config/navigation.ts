import {
  Activity,
  BrainCircuit,
  Cable,
  FileText,
  Fingerprint,
  FlaskConical,
  Gauge,
  GitCompare,
  KeyRound,
  LayoutDashboard,
  Layers,
  Network,
  Server,
  Settings,
  ShieldAlert,
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
        description: 'The 14-layer processing pipeline and its implementation status.',
      },
      {
        label: 'Test Environment',
        path: '/environment',
        icon: Server,
        description: 'Layer 01 VirtualBox test environment management and verification.',
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
        label: 'SA Lifecycle',
        path: '/sa-lifecycle',
        icon: KeyRound,
        description: 'Security Association negotiation, rekey and teardown.',
      },
      {
        label: 'Feature Extraction',
        path: '/feature-engineering',
        icon: FlaskConical,
        description: 'Structured features derived from observed packets, sessions and SAs.',
      },
      {
        label: 'Baseline Profiling',
        path: '/baseline-profiling',
        icon: Fingerprint,
        description: 'Establish behavioral fingerprints and reference baselines from observed IPsec VPN session features.',
      },
      {
        label: 'Drift Detection',
        path: '/drift-detection',
        icon: GitCompare,
        description: 'Identify measurable changes in observed IPsec VPN behavior relative to an established behavioral baseline.',
      },
      {
        label: 'AI / ML Anomaly',
        path: '/ai-anomaly-detection',
        icon: BrainCircuit,
        description: 'Machine learning isolation forest anomaly detection and factual explainability for IPsec VPN sessions.',
      },
      {
        label: 'Vulnerabilities',
        path: '/vulnerabilities',
        icon: ShieldAlert,
        description: 'Weaknesses identified by the security rule engine.',
      },
      {
        label: 'Risk Assessment',
        path: '/risk-assessment',
        icon: Gauge,
        description: 'Prioritised risk derived from all detection sources.',
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
