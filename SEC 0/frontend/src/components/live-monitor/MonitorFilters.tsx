import { Filter, Search } from 'lucide-react';

import { PACKET_PROTOCOLS } from '@/types';

interface MonitorFiltersProps {
  /** True once any monitoring data exists to filter. */
  dataAvailable: boolean;
}

const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

/**
 * Filter and search controls. Disabled while no data exists, so they never
 * appear to be operating over something that isn't there.
 */
export function MonitorFilters({ dataAvailable }: MonitorFiltersProps) {
  const disabled = !dataAvailable;
  const field =
    'rounded border border-border bg-background px-2.5 py-1.5 text-xs text-secondary disabled:cursor-not-allowed disabled:opacity-60';

  return (
    <div className="rounded border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-xs font-medium text-secondary">
          <Filter aria-hidden className="h-3.5 w-3.5 text-muted" />
          Filters
        </h3>
        {disabled ? <span className="text-2xs text-muted">Monitoring data unavailable</span> : null}
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <label className="relative sm:col-span-2 lg:col-span-4">
          <span className="sr-only">Search</span>
          <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            type="search"
            disabled={disabled}
            placeholder="Search packets, sessions, or events…"
            className={`${field} w-full pl-8`}
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Protocol</span>
          <select disabled={disabled} defaultValue="" className={field}>
            <option value="">Any</option>
            {PACKET_PROTOCOLS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Source</span>
          <input type="text" disabled={disabled} placeholder="Any" className={field} />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Destination</span>
          <input type="text" disabled={disabled} placeholder="Any" className={field} />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Severity</span>
          <select disabled={disabled} defaultValue="" className={field}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
      </div>
    </div>
  );
}
