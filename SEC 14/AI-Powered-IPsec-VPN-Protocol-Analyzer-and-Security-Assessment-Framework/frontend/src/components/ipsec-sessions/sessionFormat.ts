export function formatDuration(seconds: number | null): string {
  if (seconds === null) return 'N/A';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(2)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${s}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

export function parseSessionDate(iso: string | null): Date | null {
  if (!iso) return null;
  const trimmed = iso.trim();
  if (!trimmed) return null;

  // Handle numeric string or timestamp
  const num = Number(trimmed);
  if (!Number.isNaN(num) && !trimmed.includes('-') && !trimmed.includes('T') && !trimmed.includes(':')) {
    if (num > 1e8 && num < 1e11) {
      return new Date(num * 1000);
    }
    if (num >= 1e11) {
      return new Date(num);
    }
    return new Date(num * 1000);
  }

  const d = new Date(trimmed);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatSessionTime(iso: string | null): string {
  if (!iso) return '—';
  const d = parseSessionDate(iso);
  if (!d) return iso;
  // Valid PCAP timestamps with relative capture time or epoch offset have year 1970.
  // Display time-of-day / elapsed time without the 1970-01-01 epoch artifact.
  if (d.getUTCFullYear() === 1970) {
    return d.toISOString().slice(11, 23) + ' UTC';
  }
  return d.toISOString().replace('T', ' ').slice(0, 23) + ' UTC';
}

export function formatTimeOnly(iso: string | null): string {
  if (!iso) return '—';
  const d = parseSessionDate(iso);
  if (!d) return iso;
  return d.toISOString().slice(11, 23);
}

