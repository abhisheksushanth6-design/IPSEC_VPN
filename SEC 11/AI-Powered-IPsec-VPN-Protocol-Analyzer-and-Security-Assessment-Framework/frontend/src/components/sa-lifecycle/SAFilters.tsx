import { Filter, Search, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import type { SAController } from '@/hooks';
import type { SAState, SAType } from '@/types';

const TYPES: SAType[] = ['IKE', 'CHILD', 'UNKNOWN'];
const STATES: SAState[] = ['UNKNOWN', 'DETECTED', 'NEGOTIATING', 'ESTABLISHED', 'ACTIVE', 'REKEYING', 'EXPIRED', 'TERMINATED', 'FAILED'];
const field = 'w-full rounded border border-border bg-background px-2.5 py-1.5 text-xs text-secondary disabled:cursor-not-allowed disabled:opacity-60';

export function SAFilters({ controller }: { controller: SAController }) {
  const { filters, setFilters, status } = controller;
  const disabled = status?.state !== 'ACTIVE';
  const [search, setSearch] = useState(''); const [source, setSource] = useState(''); const [destination, setDestination] = useState('');
  const [ikeVersion, setIkeVersion] = useState(''); const [spi, setSpi] = useState('');

  // The debounce must not fire on mount: it would re-issue identical filters and refetch the list.
  const mounted = useRef(false);
  useEffect(() => {
    if (!mounted.current) { mounted.current = true; return; }
    const h = setTimeout(() => setFilters({ search: search.trim() || undefined, source: source.trim() || undefined, destination: destination.trim() || undefined, ikeVersion: ikeVersion.trim() || undefined, spi: spi.trim() || undefined }), 250);
    return () => clearTimeout(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, source, destination, ikeVersion, spi]);

  const active = Boolean(filters.type || filters.state || filters.protocol || filters.search || filters.source || filters.destination || filters.ikeVersion || filters.spi);
  const reset = () => { setSearch(''); setSource(''); setDestination(''); setIkeVersion(''); setSpi(''); setFilters({ type: undefined, state: undefined, protocol: undefined, search: undefined, source: undefined, destination: undefined, ikeVersion: undefined, spi: undefined }); };

  return (
    <div className="rounded border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-xs font-medium text-secondary"><Filter aria-hidden className="h-3.5 w-3.5 text-muted" />Filters</h3>
        <div className="flex items-center gap-3">{disabled ? <span className="text-2xs text-muted">No SAs analyzed</span> : null}{active ? <button type="button" onClick={reset} className="inline-flex items-center gap-1 text-2xs text-muted hover:text-primary"><X aria-hidden className="h-3 w-3" /> Reset</button> : null}</div>
      </div>
      <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
        <label className="relative sm:col-span-2 lg:col-span-4 xl:col-span-7"><span className="sr-only">Search Security Associations</span><Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" /><input type="search" value={search} disabled={disabled} onChange={(e) => setSearch(e.target.value)} placeholder="Search Security Associations… (SA ID, SPI, source, destination, state, IKE version)" className={`${field} pl-8`} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Type</span><select value={filters.type ?? ''} disabled={disabled} onChange={(e) => setFilters({ type: (e.target.value || undefined) as SAType | undefined })} className={field}><option value="">Any</option>{TYPES.map((t) => <option key={t} value={t}>{t}</option>)}</select></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">State</span><select value={filters.state ?? ''} disabled={disabled} onChange={(e) => setFilters({ state: (e.target.value || undefined) as SAState | undefined })} className={field}><option value="">Any</option>{STATES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Protocol</span><select value={filters.protocol ?? ''} disabled={disabled} onChange={(e) => setFilters({ protocol: (e.target.value || undefined) as 'IKE' | 'ESP' | 'AH' | undefined })} className={field}><option value="">Any</option>{['IKE', 'ESP', 'AH'].map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">IKE version</span><input type="text" value={ikeVersion} disabled={disabled} onChange={(e) => setIkeVersion(e.target.value)} placeholder="e.g. 2.0" className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Source</span><input type="text" value={source} disabled={disabled} onChange={(e) => setSource(e.target.value)} placeholder="Any" className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">Destination</span><input type="text" value={destination} disabled={disabled} onChange={(e) => setDestination(e.target.value)} placeholder="Any" className={field} /></label>
        <label className="flex flex-col gap-1"><span className="text-2xs text-muted">SPI</span><input type="text" value={spi} disabled={disabled} onChange={(e) => setSpi(e.target.value)} placeholder="Any" className={field} /></label>
      </div>
    </div>
  );
}
