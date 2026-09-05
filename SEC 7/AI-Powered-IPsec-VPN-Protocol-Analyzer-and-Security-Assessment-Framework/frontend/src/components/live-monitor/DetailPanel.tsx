import { X } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

import { EmptyState } from '@/components/states';

interface DetailPanelProps {
  title: string;
  emptyTitle: string;
  emptyDescription: string;
  icon: LucideIcon;
  /** When null the panel shows its empty state. */
  subject: ReactNode | null;
  onClose?: () => void;
}

/** Shared frame for packet, session and SA detail views. */
export function DetailPanel({ title, emptyTitle, emptyDescription, icon, subject, onClose }: DetailPanelProps) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (subject) closeRef.current?.focus();
  }, [subject]);

  return (
    <aside
      role={subject ? 'dialog' : 'region'}
      aria-label={title}
      className="flex flex-col rounded border border-border bg-surface"
    >
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="text-sm font-medium text-primary">{title}</h2>
        {subject && onClose ? (
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label={`Close ${title.toLowerCase()}`}
            className="rounded p-1 text-muted transition-colors hover:bg-elevated hover:text-primary"
          >
            <X aria-hidden className="h-4 w-4" />
          </button>
        ) : null}
      </div>
      <div className="p-4">
        {subject ?? <EmptyState icon={icon} title={emptyTitle} description={emptyDescription} />}
      </div>
    </aside>
  );
}

/** A titled group of label/value pairs inside a detail panel. */
export function DetailSection({ title, entries }: { title: string; entries: Array<[string, ReactNode]> }) {
  return (
    <section className="border-t border-border py-3 first:border-t-0 first:pt-0">
      <h3 className="text-2xs font-medium text-muted">{title}</h3>
      <dl className="mt-2 space-y-1">
        {entries.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-4 text-xs">
            <dt className="text-muted">{label}</dt>
            <dd className="text-right font-mono text-secondary">{value ?? '—'}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
