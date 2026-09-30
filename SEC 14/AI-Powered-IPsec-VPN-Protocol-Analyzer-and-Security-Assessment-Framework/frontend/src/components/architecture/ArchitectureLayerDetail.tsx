import { ArrowUpRight, X } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';

import { StatusBadge } from '@/components/status';
import { cn } from '@/utils/cn';
import type { ArchitectureLayerDetail as LayerDetail } from '@/types';

interface ArchitectureLayerDetailProps {
  layer: LayerDetail | null;
  onClose: () => void;
}

function currentStateText(status: LayerDetail['status']): string {
  switch (status) {
    case 'NOT INITIALIZED':
      return 'Module not implemented yet.';
    case 'FOUNDATION CREATED':
      return 'Technical foundation exists. Functional logic is not implemented.';
    case 'FOUNDATION READY':
      return 'Application structure is ready for implementation. No functionality exists.';
    case 'IN DEVELOPMENT':
      return 'Implementation in progress.';
    default:
      return 'Implemented.';
  }
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-border py-4 first:border-t-0 first:pt-0">
      <h3 className="text-2xs font-medium text-muted">{title}</h3>
      <div className="mt-2">{children}</div>
    </section>
  );
}

/**
 * Side panel describing a layer. Describes intended role, inputs and outputs
 * only; it exposes no runtime data because none exists.
 */
export function ArchitectureLayerDetail({ layer, onClose }: ArchitectureLayerDetailProps) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const open = layer !== null;

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!layer) return null;

  const Icon = layer.icon;
  const number = String(layer.number).padStart(2, '0');
  const moduleAvailable = layer.status !== 'NOT INITIALIZED' && layer.route;

  return (
    <aside
      role="dialog"
      aria-modal="false"
      aria-labelledby="arch-detail-title"
      className={cn(
        'flex flex-col rounded border border-border bg-surface animate-fade-up',
        'lg:sticky lg:top-[calc(var(--header-height)+1.5rem)] lg:max-h-[calc(100vh-var(--header-height)-3rem)]',
      )}
    >
      <div className="flex items-start justify-between gap-3 border-b border-border p-4">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded border border-border bg-background font-mono text-sm text-secondary">
            {number}
          </span>
          <div className="min-w-0">
            <p className="text-2xs text-muted">Layer {number}</p>
            <h2 id="arch-detail-title" className="text-base font-medium leading-snug text-primary">
              {layer.name}
            </h2>
          </div>
        </div>
        <button
          ref={closeRef}
          type="button"
          onClick={onClose}
          aria-label="Close layer detail"
          className="rounded p-1.5 text-muted transition-colors hover:bg-elevated hover:text-primary"
        >
          <X aria-hidden className="h-4 w-4" />
        </button>
      </div>

      <div className="scrollbar-slim flex-1 overflow-y-auto p-4">
        <Section title="Status">
          <div className="flex items-center gap-3">
            <StatusBadge status={layer.status} />
            <Icon aria-hidden className="h-4 w-4 text-muted" />
          </div>
        </Section>

        <Section title="Purpose">
          <p className="text-sm leading-relaxed text-secondary">{layer.purpose}</p>
        </Section>

        <Section title="Current state">
          <p className="text-sm text-secondary">{currentStateText(layer.status)}</p>
        </Section>

        <Section title="Layer inputs">
          <ul className="space-y-1 text-sm text-secondary">
            {layer.futureInputs.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden className="text-border">—</span>
                {item}
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Layer outputs">
          <ul className="space-y-1 text-sm text-secondary">
            {layer.futureOutputs.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden className="text-border">—</span>
                {item}
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Implementation status">
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-muted">Category</dt>
              <dd className="text-right text-secondary">{layer.category}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-muted">Backend package</dt>
              <dd className="font-mono text-xs text-secondary">{layer.package}</dd>
            </div>
          </dl>
        </Section>

        <Section title="Runtime Verification & Capability">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="flex items-center gap-1.5 p-2 rounded border border-border bg-background">
              <span className={cn("h-2 w-2 rounded-full", layer.foundation_available !== false ? "bg-emerald-500" : "bg-muted")} />
              <span className="text-secondary">Foundation:</span>
              <span className="font-medium text-primary ml-auto">{layer.foundation_available !== false ? "Ready" : "Missing"}</span>
            </div>
            <div className="flex items-center gap-1.5 p-2 rounded border border-border bg-background">
              <span className={cn("h-2 w-2 rounded-full", layer.implementation_available ? "bg-emerald-500" : "bg-amber-500")} />
              <span className="text-secondary">Logic:</span>
              <span className="font-medium text-primary ml-auto">{layer.implementation_available ? "Implemented" : "Pending"}</span>
            </div>
            <div className="flex items-center gap-1.5 p-2 rounded border border-border bg-background">
              <span className={cn("h-2 w-2 rounded-full", layer.runtime_verified ? "bg-emerald-500" : "bg-rose-500")} />
              <span className="text-secondary">Runtime:</span>
              <span className="font-medium text-primary ml-auto">{layer.runtime_verified ? "Verified" : "Unverified"}</span>
            </div>
            <div className="flex items-center gap-1.5 p-2 rounded border border-border bg-background">
              <span className={cn("h-2 w-2 rounded-full", layer.unit_tests_passed !== false ? "bg-emerald-500" : "bg-rose-500")} />
              <span className="text-secondary">Unit Tests:</span>
              <span className="font-medium text-primary ml-auto">{layer.unit_tests_passed !== false ? "Passing" : "Failing"}</span>
            </div>
          </div>
          {layer.last_verified && (
            <p className="mt-2 text-2xs text-muted">
              Last verified: {new Date(layer.last_verified).toLocaleTimeString()}
            </p>
          )}
          {layer.verification_errors && layer.verification_errors.length > 0 && (
            <div className="mt-2 p-2 rounded border border-rose-500/30 bg-rose-500/10 text-xs text-rose-400">
              <p className="font-medium">Verification Errors:</p>
              <ul className="list-disc list-inside mt-1 space-y-0.5">
                {layer.verification_errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}
          {layer.limitations && layer.limitations.length > 0 && (
            <div className="mt-2 p-2 rounded border border-amber-500/30 bg-amber-500/10 text-xs text-amber-400">
              <p className="font-medium">Operational Constraints:</p>
              <ul className="list-disc list-inside mt-1 space-y-0.5">
                {layer.limitations.map((lim, i) => (
                  <li key={i}>{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </Section>
      </div>

      <div className="border-t border-border p-4">
        {moduleAvailable ? (
          <Link
            to={layer.route as string}
            className="inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 text-sm text-primary transition-colors hover:border-info hover:text-info"
          >
            View module
            <ArrowUpRight aria-hidden className="h-3.5 w-3.5" />
          </Link>
        ) : (
          <StatusBadge status="NOT INITIALIZED" label="MODULE NOT INITIALIZED" size="sm" />
        )}
      </div>
    </aside>
  );
}
