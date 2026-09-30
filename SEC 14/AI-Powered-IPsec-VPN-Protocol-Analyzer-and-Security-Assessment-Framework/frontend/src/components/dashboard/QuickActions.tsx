import { Link } from 'react-router-dom';

import { NAVIGATION_ITEMS } from '@/config/navigation';

const QUICK_ACTION_PATHS = [
  '/live-monitor',
  '/packet-analysis',
  '/ipsec-sessions',
  '/baseline-profiling',
  '/traffic-analysis',
  '/vulnerabilities',
  '/risk-assessment',
  '/reports',
];

/** Shortcuts to the main modules. Pure navigation; nothing is executed. */
export function QuickActions() {
  const items = QUICK_ACTION_PATHS.map((path) =>
    NAVIGATION_ITEMS.find((item) => item.path === path),
  ).filter((item): item is NonNullable<typeof item> => item !== undefined);

  return (
    <nav aria-label="Quick navigation" className="flex flex-wrap gap-2">
      {items.map((item) => (
        <Link
          key={item.path}
          to={item.path}
          className="inline-flex items-center gap-2 rounded border border-border bg-surface px-3 py-1.5 text-xs text-secondary transition-colors hover:border-info hover:text-info"
        >
          <item.icon aria-hidden className="h-3.5 w-3.5" />
          {item.label}
        </Link>
      ))}
    </nav>
  );
}
