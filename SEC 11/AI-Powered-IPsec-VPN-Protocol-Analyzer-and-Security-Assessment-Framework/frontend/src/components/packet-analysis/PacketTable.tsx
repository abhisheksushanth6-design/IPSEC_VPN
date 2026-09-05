import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Network } from 'lucide-react';

import { EmptyState, LoadingState } from '@/components/states';
import { cn } from '@/utils/cn';
import { PacketRow } from './PacketRow';
import type { PacketAnalysisController } from '@/hooks';
import type { PacketSortKey } from '@/types';

const COLUMNS: Array<{ key: PacketSortKey | 'info'; header: string; align?: 'right' }> = [
  { key: 'number', header: '#', align: 'right' },
  { key: 'timestamp', header: 'Time' },
  { key: 'source', header: 'Source' },
  { key: 'destination', header: 'Destination' },
  { key: 'protocol', header: 'Protocol' },
  { key: 'length', header: 'Length', align: 'right' },
  { key: 'info', header: 'Info' },
];

/** Paginated packet list. Only one page lives in the DOM at a time. */
export function PacketTable({ controller }: { controller: PacketAnalysisController }) {
  const { status, page, listLoading, query, setQuery, setSort, selectedId, select } = controller;
  const loaded = status?.state === 'COMPLETED';

  return (
    <section aria-labelledby="packet-table-title" className="flex min-w-0 flex-col rounded border border-border bg-surface">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 id="packet-table-title" className="text-sm font-medium text-primary">Packets</h2>
          <p className="mt-0.5 text-xs text-muted">
            {page ? `${page.total.toLocaleString()} matching · page ${page.page} of ${page.total_pages}` : 'Decoded from the loaded capture.'}
          </p>
        </div>
        {page && page.total_pages > 1 ? (
          <nav aria-label="Packet pages" className="flex items-center gap-1">
            <button type="button" aria-label="Previous page" disabled={page.page <= 1} onClick={() => setQuery({ page: page.page - 1 })} className="rounded border border-border p-1 text-muted disabled:opacity-40 hover:text-primary">
              <ChevronLeft aria-hidden className="h-3.5 w-3.5" />
            </button>
            <span className="px-1 font-mono text-2xs text-muted">{page.page} / {page.total_pages}</span>
            <button type="button" aria-label="Next page" disabled={page.page >= page.total_pages} onClick={() => setQuery({ page: page.page + 1 })} className="rounded border border-border p-1 text-muted disabled:opacity-40 hover:text-primary">
              <ChevronRight aria-hidden className="h-3.5 w-3.5" />
            </button>
          </nav>
        ) : null}
      </div>

      {!loaded ? (
        <div className="p-4">
          <EmptyState icon={Network} title="No packets available" description="Capture or load packet data to begin analysis. Upload a .pcap or .pcapng file using the toolbar." status="NOT INITIALIZED" />
        </div>
      ) : listLoading && !page ? (
        <div className="px-4"><LoadingState message="Loading packets…" /></div>
      ) : page && page.items.length === 0 ? (
        <div className="p-4"><EmptyState icon={Network} title="No packets match" description="No packets in the capture match the current filters." /></div>
      ) : page ? (
        <div className="scrollbar-slim max-h-[36rem] overflow-auto">
          <table className="w-full min-w-[60rem] border-collapse text-left">
            <caption className="sr-only">Analysed packets</caption>
            <thead className="sticky top-0 z-10 bg-elevated">
              <tr>
                {COLUMNS.map((c) => {
                  const sortable = c.key !== 'info';
                  const active = query.sort === c.key;
                  const Icon = !active ? ArrowUpDown : query.order === 'asc' ? ArrowUp : ArrowDown;
                  return (
                    <th key={c.key} scope="col" aria-sort={active ? (query.order === 'asc' ? 'ascending' : 'descending') : undefined} className={cn('whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted', c.align === 'right' && 'text-right')}>
                      {sortable ? (
                        <button type="button" onClick={() => setSort(c.key as PacketSortKey)} className={cn('inline-flex items-center gap-1 rounded hover:text-primary', active && 'text-primary')}>
                          {c.header}<Icon aria-hidden className="h-3 w-3" />
                        </button>
                      ) : c.header}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {page.items.map((p) => <PacketRow key={p.id} packet={p} selected={p.id === selectedId} onSelect={select} />)}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
