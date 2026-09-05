import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, KeyRound } from 'lucide-react';

import { EmptyState, LoadingState } from '@/components/states';
import { cn } from '@/utils/cn';
import { SARow } from './SARow';
import type { SAController } from '@/hooks';
import type { SASortKey } from '@/types';

const COLUMNS: Array<{ key: SASortKey | 'id' | 'protocol' | 'spi'; header: string; align?: 'right' }> = [
  { key: 'id', header: 'SA ID' }, { key: 'type', header: 'Type' }, { key: 'start_time', header: 'Start time' }, { key: 'last_seen', header: 'Last seen' },
  { key: 'initiator', header: 'Initiator' }, { key: 'responder', header: 'Responder' }, { key: 'protocol', header: 'Protocol' }, { key: 'spi', header: 'SPI' },
  { key: 'packet_count', header: 'Packets', align: 'right' }, { key: 'state', header: 'State' },
];

export function SATable({ controller }: { controller: SAController }) {
  const { status, page, listLoading, filters, setFilters, setSort, selectedId, select } = controller;
  const active = status?.state === 'ACTIVE';
  return (
    <section aria-labelledby="sa-table-title" className="flex min-w-0 flex-col rounded border border-border bg-surface">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div><h2 id="sa-table-title" className="text-sm font-medium text-primary">Security Associations</h2><p className="mt-0.5 text-xs text-muted">{page ? `${page.total} matching · page ${page.page} of ${page.total_pages}` : 'IKE and child SAs derived from decoded packets.'}</p></div>
        {page && page.total_pages > 1 ? (
          <nav aria-label="SA pages" className="flex items-center gap-1">
            <button type="button" aria-label="Previous page" disabled={page.page <= 1} onClick={() => setFilters({ page: page.page - 1 })} className="rounded border border-border p-1 text-muted disabled:opacity-40 hover:text-primary"><ChevronLeft aria-hidden className="h-3.5 w-3.5" /></button>
            <span className="px-1 font-mono text-2xs text-muted">{page.page} / {page.total_pages}</span>
            <button type="button" aria-label="Next page" disabled={page.page >= page.total_pages} onClick={() => setFilters({ page: page.page + 1 })} className="rounded border border-border p-1 text-muted disabled:opacity-40 hover:text-primary"><ChevronRight aria-hidden className="h-3.5 w-3.5" /></button>
          </nav>
        ) : null}
      </div>
      {!active ? (
        <div className="p-4"><EmptyState icon={KeyRound} title="No Security Associations available" description={status?.packets_available ? 'Analyze IPsec/IKE traffic to discover Security Associations. Use Discover SAs in the toolbar.' : 'Analyze IPsec/IKE traffic to discover Security Associations. Load a capture in Packet Analysis first.'} status="NOT INITIALIZED" /></div>
      ) : listLoading && !page ? <div className="px-4"><LoadingState message="Discovering Security Associations…" /></div>
      : page && page.items.length === 0 ? <div className="p-4"><EmptyState icon={KeyRound} title="No Security Associations match" description="No SAs match the current filters." /></div>
      : page ? (
        <div className="scrollbar-slim max-h-[32rem] overflow-auto">
          <table className="w-full min-w-[80rem] border-collapse text-left">
            <caption className="sr-only">Discovered Security Associations</caption>
            <thead className="sticky top-0 z-10 bg-elevated"><tr>
              {COLUMNS.map((c) => { const sortable = !['id', 'protocol', 'spi'].includes(c.key); const on = filters.sort === c.key; const Icon = !on ? ArrowUpDown : filters.order === 'asc' ? ArrowUp : ArrowDown;
                return <th key={c.key} scope="col" aria-sort={on ? (filters.order === 'asc' ? 'ascending' : 'descending') : undefined} className={cn('whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted', c.align === 'right' && 'text-right')}>{sortable ? <button type="button" onClick={() => setSort(c.key as SASortKey)} className={cn('inline-flex items-center gap-1 rounded hover:text-primary', on && 'text-primary')}>{c.header}<Icon aria-hidden className="h-3 w-3" /></button> : c.header}</th>; })}
            </tr></thead>
            <tbody>{page.items.map((sa) => <SARow key={sa.id} sa={sa} selected={sa.id === selectedId} onSelect={select} />)}</tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
