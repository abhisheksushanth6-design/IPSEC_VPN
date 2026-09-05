import { Wifi } from 'lucide-react';

import type { NetworkInterface } from '@/types';

interface InterfaceSelectorProps {
  interfaces: NetworkInterface[] | null;
  selected?: string;
  onChange?: (name: string) => void;
}

/**
 * Chooses the capture interface. Options come only from the backend; until
 * an interface-discovery endpoint exists there is nothing to list.
 */
export function InterfaceSelector({ interfaces, selected, onChange }: InterfaceSelectorProps) {
  const unavailable = interfaces === null;
  const empty = interfaces !== null && interfaces.length === 0;

  return (
    <div className="flex flex-col gap-1">
      <label htmlFor="monitor-interface" className="text-2xs text-muted">
        Network interface
      </label>
      <div className="relative">
        <Wifi aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
        <select
          id="monitor-interface"
          disabled={unavailable || empty}
          value={selected ?? ''}
          onChange={(e) => onChange?.(e.target.value)}
          aria-describedby="monitor-interface-note"
          className="w-full min-w-48 appearance-none rounded border border-border bg-surface py-1.5 pl-8 pr-3 text-xs text-secondary disabled:cursor-not-allowed disabled:opacity-60"
        >
          <option value="">
            {unavailable ? 'NOT INITIALIZED' : empty ? 'No interfaces found' : 'No interface selected'}
          </option>
          {interfaces?.map((iface) => (
            <option key={iface.name} value={iface.name}>
              {iface.name}
              {iface.description ? ` — ${iface.description}` : ''}
            </option>
          ))}
        </select>
      </div>
      <span id="monitor-interface-note" className="text-2xs text-muted">
        {unavailable ? 'Interface discovery requires the capture engine.' : ''}
      </span>
    </div>
  );
}
