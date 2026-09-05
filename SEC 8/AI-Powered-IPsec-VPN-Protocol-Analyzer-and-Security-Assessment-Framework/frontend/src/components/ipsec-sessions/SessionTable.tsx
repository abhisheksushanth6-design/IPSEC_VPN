import { ArrowDown, ArrowUp, ArrowUpDown, Cable, ChevronLeft, ChevronRight } from 'lucide-react';

import { EmptyState, LoadingState } from '@/components/states';
import { cn } from '@/utils/cn';
import { SessionRow } from './SessionRow';
import type { SessionController } from '@/hooks';
import type { SessionSortKey } from '@/types';

const COLUMNS: Array<{ key: SessionSortKey | 'id' | 'protocol'; header: string; align?: 'right' }> = [
  { key: 'id', header: 'Session ID' }, { key: 'start_time', header: 'Start time' }, { key: 'end_time', header: 'End time' },
  { key: 'source', header: 'Source' }, { key: 'destination', header: 'Destination' }, { key: 'protocol', header: 'Protocol' },
  { key: 'packet_count', header: 'Packets', align: 'right' }, { key: 'duration_seconds', header: 'Duration', align: 'right' }, { key: 'state', header: 'State' },
];

export function SessionTable({ controller }: { controller: SessionController }) {
  const { status, page, listLoading, filters, setFilters, setSort, selectedId, select } = controller;
  const available = status?.state === 'AVAILABLE';

  return (
    <section aria-labelledby="session-table-title" className="flex min-w-0 flex-col rounded border border-border bg-surface">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 id="session-table-title" className="text-sm font-medium text-primary">IPsec Sessions</h2>
          <p className="mt-0.5 text-xs text-muted">{page ? `${page.total} matching · page ${page.page} of ${page.total_pages}` : 'Correlated from analysed IPsec packets.'}</p>
        </div>
        {page && page.total_pages > 1 ? (
          <nav aria-label="Session pages" className="flex items-center gap-1">
            <button type="button" aria-label="Previous page" disabled={page.page <= 1} onClick={() => setFilters({ page: page.page - 1 })} className="rounded border border-border p-1 text-muted disabled:opacity-40 hover:text-primary"><ChevronLeft aria-hidden className="h-3.5 w-3.5" /></button>
            <span className="px-1 font-mono text-2xs text-muted">{page.page} / {page.total_pages}</span>
            <button type="button" aria-label="Next page" disabled={page.page >= page.total_pages} onClick={() => setFilters({ page: page.page + 1 })} className="rounded border border-border p-1 text-muted disabled:opacity-40 hover:text-primary"><ChevronRight aria-hidden className="h-3.5 w-3.5" /></button>
          </nav>
        ) : null}
      </div>

      {!available ? (
        <div className="p-4"><EmptyState icon={Cable} title="No IPsec sessions available" description={status?.packets_available ? 'Analyze IPsec packet data to discover VPN sessions. Use Discover sessions in the toolbar.' : 'Analyze IPsec packet data to discover VPN sessions. Load a capture in Packet Analysis first.'} status="NOT INITIALIZED" /></div>
      ) : listLoading && !page ? (
        <div className="px-4"><LoadingState message="Loading sessions…" /></div>
      ) : page && page.items.length === 0 ? (
        <div className="p-4"><EmptyState icon={Cable} title="No sessions match" description="No discovered sessions match the current filters." /></div>
      ) : page ? (
        <div className="scrollbar-slim max-h-[32rem] overflow-auto">
          <table className="w-full min-w-[72rem] border-collapse text-left">
            <caption className="sr-only">Discovered IPsec sessions</caption>
            <thead className="sticky top-0 z-10 bg-elevated"><tr>
              {COLUMNS.map((c) => {
                const sortable = c.key !== 'id' && c.key !== 'protocol';
                const active = filters.sort === c.key;
                const Icon = !active ? ArrowUpDown : filters.order === 'asc' ? ArrowUp : ArrowDown;
                return (
                  <th key={c.key} scope="col" aria-sort={active ? (filters.order === 'asc' ? 'ascending' : 'descending') : undefined} className={cn('whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted', c.align === 'right' && 'text-right')}>
                    {sortable ? <button type="button" onClick={() => setSort(c.key as SessionSortKey)} className={cn('inline-flex items-center gap-1 rounded hover:text-primary', active && 'text-primary')}>{c.header}<Icon aria-hidden className="h-3 w-3" /></button> : c.header}
                  </th>
                );
              })}
            </tr></thead>
            <tbody>{page.items.map((s) => <SessionRow key={s.id} session={s} selected={s.id === selectedId} onSelect={select} />)}</tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
