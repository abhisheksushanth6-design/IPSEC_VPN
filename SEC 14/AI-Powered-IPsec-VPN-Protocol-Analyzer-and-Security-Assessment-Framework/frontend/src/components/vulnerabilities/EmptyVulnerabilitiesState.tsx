import { ShieldCheck, SearchX } from 'lucide-react';

interface EmptyVulnerabilitiesStateProps {
  isFiltered?: boolean;
  onClearFilters?: () => void;
}

export function EmptyVulnerabilitiesState({
  isFiltered = false,
  onClearFilters,
}: EmptyVulnerabilitiesStateProps) {
  if (isFiltered) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-surface p-12 text-center">
        <div className="rounded-full bg-surface-subtle p-3 text-text-muted mb-3">
          <SearchX className="h-8 w-8" />
        </div>
        <h3 className="text-base font-medium text-text-primary">No Matching Findings</h3>
        <p className="mt-1 text-xs text-text-secondary max-w-sm">
          No security rule violations match your current search and filter criteria.
        </p>
        {onClearFilters && (
          <button
            onClick={onClearFilters}
            className="mt-4 rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-surface-hover transition"
          >
            Clear Filters
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-surface p-12 text-center">
      <div className="rounded-full bg-emerald-500/10 border border-emerald-500/20 p-3 text-emerald-400 mb-3">
        <ShieldCheck className="h-8 w-8" />
      </div>
      <h3 className="text-base font-semibold text-text-primary">No Security Rule Violations Detected</h3>
      <p className="mt-1 text-xs text-text-secondary max-w-md">
        All evaluated IPsec VPN protocol states, cryptographic suites, SA &amp; protocol states, and configuration parameters comply with active security rules and RFC standards.
      </p>
      <div className="mt-4 inline-flex items-center gap-2 rounded bg-surface-subtle px-3 py-1.5 text-xs font-mono text-emerald-400 border border-emerald-500/20">
        <span className="h-2 w-2 rounded-full bg-emerald-500" />
        Zero active security violations across monitored sessions
      </div>
    </div>
  );
}
