import type { LucideIcon } from 'lucide-react';

interface DisabledActionProps {
  icon: LucideIcon;
  label: string;
  reason: string;
}

/**
 * A control whose functionality does not yet exist. It is disabled in the
 * DOM, says why in a tooltip, and exposes the reason to assistive tech.
 */
export function DisabledAction({ icon: Icon, label, reason }: DisabledActionProps) {
  return (
    <span className="group relative inline-flex">
      <button
        type="button"
        disabled
        aria-disabled="true"
        aria-describedby={`${label.replace(/\s+/g, '-').toLowerCase()}-reason`}
        title={reason}
        className="inline-flex cursor-not-allowed items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs text-muted opacity-60"
      >
        <Icon aria-hidden className="h-3.5 w-3.5" />
        {label}
      </button>
      <span
        id={`${label.replace(/\s+/g, '-').toLowerCase()}-reason`}
        role="tooltip"
        className="pointer-events-none absolute left-1/2 top-full z-30 mt-1.5 -translate-x-1/2 whitespace-nowrap rounded border border-border bg-elevated px-2 py-1 text-2xs text-secondary opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-within:opacity-100"
      >
        {reason}
      </span>
    </span>
  );
}
