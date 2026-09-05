import { Radio } from 'lucide-react';

/** Persistent notice so the interface is never mistaken for a running capture. */
export function MonitorBanner() {
  return (
    <div
      role="status"
      className="flex items-start gap-3 rounded border border-warning/30 bg-warning/5 px-4 py-3"
    >
      <Radio aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
      <div>
        <p className="text-sm font-medium text-primary">Monitoring not initialized</p>
        <p className="mt-0.5 text-xs text-secondary">
          The packet capture and real-time analysis engines are not currently active. This
          interface is prepared to receive their output once Layers 02 and 03 are implemented.
        </p>
      </div>
    </div>
  );
}
