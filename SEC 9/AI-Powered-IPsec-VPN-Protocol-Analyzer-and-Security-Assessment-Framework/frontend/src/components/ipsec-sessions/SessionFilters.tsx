import { Filter, Search, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import type { SessionController } from '@/hooks';
import type { SessionProtocol, SessionState } from '@/types';

const STATES: SessionState[] = ['DISCOVERED', 'NEGOTIATING', 'ESTABLISHED', 'ACTIVE', 'IDLE', 'TERMINATED', 'UNKNOWN'];
const PROTOCOLS: SessionProtocol[] = ['IKE', 'ESP', 'AH'];
const field = 'w-full rounded border border-border bg-background px-2.5 py-1.5 text-xs text-secondary disabled:cursor-not-allowed disabled:opacity-60';

export function SessionFilters({ controller }: { controller: SessionController }) {
  const { filters, setFilters, status } = controller;
  const disabled = status?.state !== 'AVAILABLE';
  const [search, setSearch] = useState(filters.search ?? '');
  const [source, setSource] = useState(filters.source ?? '');
  const [destination, setDestination] = useState(filters.destination ?? '');
  const [ikeVersion, setIkeVersion] = useState(filters.ikeVersion ?? '');
  const [startAfter, setStartAfter] = useState('');
  const [endBefore, setEndBefore] = useState('');

  // The debounce must not fire on mount: it would re-issue identical filters and refetch the list.
  const mounted = useRef(false);
  useEffect(() => {
    if (!mounted.current) { mounted.current = true; return; }
    const handle = setTimeout(() => setFilters({
      search: search.trim() || undefined, source: source.trim() || undefined, destination: destination.trim() || undefined,
      ikeVersion: ikeVersion.trim() || undefined,
      startAfter: startAfter ? new Date(startAfter).toISOString() : undefined,
      endBefore: endBefore ? new Date(endBefore).toISOString() : undefined,
    }), 250);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, source, destination, ikeVersion, startAfter, endBefore]);

  const active = Boolean(filters.state || filters.protocol || filters.search || filters.source || filters.destination || filters.ikeVersion || filters.startAfter || filters.endBefore);
  const reset = () => {
    setSearch(''); setSource(''); setDestination(''); setIkeVersion(''); setStartAfter(''); setEndBefore('');
    setFilters({ state: undefined, protocol: undefined, search: undefined, source: undefined, destination: undefined, ikeVersion: undefined, startAfter: undefined, endBefore: undefined });
  };

  return (
    <div className="rounded border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-xs font-medium text-secondary"><Filter aria-hidden className="h-3.5 w-3.5 text-muted" />Filters</h3>
        <div className="flex items-center gap-3">
          {disabled ? <span className="text-2xs text-muted">No sessions discovered</span> : null}
          {active ? <button type="button" onClick={reset} className="inline-flex items-center gap-1 text-2xs text-muted hover:text-primary"><X aria-hidden className="h-3 w-3" /> Reset</button> : null}
        </div>
      </div>
      <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
        <label className="relative sm:col-span-2 lg:col-span-4 xl:col-span-7">
          <span className="sr-only">Search sessions</span>
          <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input type="search" value={search} disabled={disabled} onChange={(e) => setSearch(e.target.value)} placeholder="Search sessions… (session ID, source, destination, SPI, protocol)" className={`${field} pl-8`} />
        </label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">State</span>
          <select value={filters.state ?? ''} disabled={disabled} onChange={(e) => setFilters({ state: (e.target.value || undefined) as SessionState | undefined })} className={field}>
            <option value="">Any</option>{STATES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Protocol</span>
          <select value={filters.protocol ?? ''} disabled={disabled} onChange={(e) => setFilters({ protocol: (e.target.value || undefined) as SessionProtocol | undefined })} className={field}>
            <option value="">Any</option>{PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Source</span><input type="text" value={source} disabled={disabled} onChange={(e) => setSource(e.target.value)} placeholder="Any" className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Destination</span><input type="text" value={destination} disabled={disabled} onChange={(e) => setDestination(e.target.value)} placeholder="Any" className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">IKE version</span><input type="text" value={ikeVersion} disabled={disabled} onChange={(e) => setIkeVersion(e.target.value)} placeholder="e.g. 2.0" className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Start after</span><input type="datetime-local" value={startAfter} disabled={disabled} onChange={(e) => setStartAfter(e.target.value)} className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">End before</span><input type="datetime-local" value={endBefore} disabled={disabled} onChange={(e) => setEndBefore(e.target.value)} className={field} /></label>
      </div>
    </div>
  );
}
