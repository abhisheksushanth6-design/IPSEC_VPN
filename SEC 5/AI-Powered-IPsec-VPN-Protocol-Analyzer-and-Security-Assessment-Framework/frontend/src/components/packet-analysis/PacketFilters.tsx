import { Filter, Search, X } from 'lucide-react';
import { useEffect, useState } from 'react';

import type { PacketAnalysisController } from '@/hooks';
import type { DisplayProtocol, IPsecFilter } from '@/types';

const PROTOCOLS: DisplayProtocol[] = ['IKE', 'ESP', 'AH', 'TCP', 'UDP', 'ICMP', 'IP', 'OTHER'];
const IPSEC: IPsecFilter[] = ['ALL', 'IKE', 'ESP', 'AH', 'NON-IPSEC'];

const field = 'w-full rounded border border-border bg-background px-2.5 py-1.5 text-xs text-secondary disabled:cursor-not-allowed disabled:opacity-60';

/** Filters and search over the loaded capture. Debounced so typing doesn't hammer the API. */
export function PacketFilters({ controller }: { controller: PacketAnalysisController }) {
  const { query, setQuery, status } = controller;
  const disabled = status?.state !== 'COMPLETED';
  const [search, setSearch] = useState(query.search ?? '');
  const [source, setSource] = useState(query.source ?? '');
  const [destination, setDestination] = useState(query.destination ?? '');
  const [port, setPort] = useState(query.port?.toString() ?? '');

  useEffect(() => {
    const handle = setTimeout(() => {
      const parsedPort = port.trim() === '' ? undefined : Number(port);
      setQuery({
        search: search.trim() || undefined,
        source: source.trim() || undefined,
        destination: destination.trim() || undefined,
        port: parsedPort !== undefined && Number.isInteger(parsedPort) && parsedPort >= 0 && parsedPort <= 65535 ? parsedPort : undefined,
      });
    }, 250);
    return () => clearTimeout(handle);
    // setQuery is stable; only user input should re-trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, source, destination, port]);

  const reset = () => {
    setSearch(''); setSource(''); setDestination(''); setPort('');
    setQuery({ protocol: undefined, ipsec: 'ALL', search: undefined, source: undefined, destination: undefined, port: undefined });
  };

  const active = Boolean(query.protocol || query.ipsec !== 'ALL' || query.search || query.source || query.destination || query.port !== undefined);

  return (
    <div className="rounded border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-xs font-medium text-secondary">
          <Filter aria-hidden className="h-3.5 w-3.5 text-muted" />
          Filters
        </h3>
        <div className="flex items-center gap-3">
          {disabled ? <span className="text-2xs text-muted">No packets loaded</span> : null}
          {active ? (
            <button type="button" onClick={reset} className="inline-flex items-center gap-1 text-2xs text-muted hover:text-primary">
              <X aria-hidden className="h-3 w-3" /> Reset
            </button>
          ) : null}
        </div>
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
        <label className="relative sm:col-span-2 lg:col-span-6">
          <span className="sr-only">Search packets</span>
          <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input type="search" value={search} disabled={disabled} onChange={(e) => setSearch(e.target.value)} placeholder="Search packets… (IP, protocol, SPI, packet number, info)" className={`${field} pl-8`} />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Protocol</span>
          <select value={query.protocol ?? ''} disabled={disabled} onChange={(e) => setQuery({ protocol: (e.target.value || undefined) as DisplayProtocol | undefined })} className={field}>
            <option value="">Any</option>
            {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">IPsec type</span>
          <select value={query.ipsec} disabled={disabled} onChange={(e) => setQuery({ ipsec: e.target.value as IPsecFilter })} className={field}>
            {IPSEC.map((v) => <option key={v} value={v}>{v === 'ALL' ? 'All' : v === 'NON-IPSEC' ? 'Non-IPsec' : v}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Source</span>
          <input type="text" value={source} disabled={disabled} onChange={(e) => setSource(e.target.value)} placeholder="Any" className={field} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-2xs text-muted">Destination</span>
          <input type="text" value={destination} disabled={disabled} onChange={(e) => setDestination(e.target.value)} placeholder="Any" className={field} />
        </label>
        <label className="flex flex-col gap-1 lg:col-span-2">
          <span className="text-2xs text-muted">Port</span>
          <input type="number" inputMode="numeric" min={0} max={65535} value={port} disabled={disabled} onChange={(e) => setPort(e.target.value)} placeholder="Any" className={field} />
        </label>
      </div>
    </div>
  );
}
