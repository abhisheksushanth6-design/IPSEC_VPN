import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

import { EmptyState } from '@/components/states';
import { StatusBadge } from '@/components/status';
import { cn } from '@/utils/cn';

interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  align?: 'left' | 'right';
}

interface EntityTableProps<T extends { id: string }> {
  title: string;
  description: string;
  icon: LucideIcon;
  columns: Column<T>[];
  rows: T[] | null;
  selectedId: string | null;
  onSelect: (row: T) => void;
  emptyTitle: string;
  emptyDescription: string;
  /** Shown when rows is [] — the engine exists but observed nothing. */
  quietTitle: string;
  minWidth?: string;
}

/**
 * Generic selectable table shared by the session and SA panels. Same
 * null-vs-empty semantics as everywhere else.
 */
export function EntityTable<T extends { id: string }>({
  title, description, icon, columns, rows, selectedId, onSelect,
  emptyTitle, emptyDescription, quietTitle, minWidth = '48rem',
}: EntityTableProps<T>) {
  const headingId = `${title.replace(/\s+/g, '-').toLowerCase()}-title`;

  return (
    <section aria-labelledby={headingId} className="flex flex-col rounded border border-border bg-surface">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 id={headingId} className="text-sm font-medium text-primary">{title}</h2>
          <p className="mt-0.5 text-xs text-muted">{description}</p>
        </div>
        {rows === null ? <StatusBadge status="NOT INITIALIZED" size="sm" /> : null}
      </div>

      {rows === null ? (
        <div className="p-4"><EmptyState icon={icon} title={emptyTitle} description={emptyDescription} status="NOT INITIALIZED" /></div>
      ) : rows.length === 0 ? (
        <div className="p-4"><EmptyState icon={icon} title={quietTitle} /></div>
      ) : (
        <div className="scrollbar-slim max-h-80 overflow-auto">
          <table className="w-full border-collapse text-left" style={{ minWidth }}>
            <caption className="sr-only">{title}</caption>
            <thead className="sticky top-0 z-10 bg-elevated">
              <tr>
                {columns.map((c) => (
                  <th key={c.key} scope="col" className={cn('whitespace-nowrap px-3 py-2 text-2xs font-medium text-muted', c.align === 'right' && 'text-right')}>
                    {c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  tabIndex={0}
                  aria-selected={row.id === selectedId}
                  onClick={() => onSelect(row)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(row); } }}
                  className={cn('cursor-pointer border-b border-border text-xs last:border-b-0', row.id === selectedId ? 'bg-elevated' : 'hover:bg-elevated/60')}
                >
                  {columns.map((c) => (
                    <td key={c.key} className={cn('whitespace-nowrap px-3 py-2 text-secondary', c.align === 'right' && 'text-right')}>
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
