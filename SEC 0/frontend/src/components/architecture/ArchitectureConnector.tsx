import { ArrowDown } from 'lucide-react';

interface ArchitectureConnectorProps {
  /** Shown beside the arrow, e.g. "DATA FLOW". */
  label?: string;
}

/** Static connector between two layers. Indicates intended flow, not live data. */
export function ArchitectureConnector({ label }: ArchitectureConnectorProps) {
  return (
    <div aria-hidden className="flex items-center gap-2 py-1 pl-[1.6rem]">
      <span className="flex h-6 w-3 flex-col items-center">
        <span className="h-3 w-px bg-border" />
        <ArrowDown className="h-3 w-3 -translate-y-px text-border" />
      </span>
      {label ? <span className="text-2xs text-muted">{label}</span> : null}
    </div>
  );
}
