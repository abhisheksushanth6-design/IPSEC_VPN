import type { DriftEngineState, DriftSeverity, DriftStatus } from '@/types';

export function DriftEngineBadge({ state }: { state?: DriftEngineState }) {
  const s = state ?? 'NOT INITIALIZED';

  const styles: Record<DriftEngineState, { bg: string; dot: string }> = {
    'NOT INITIALIZED': {
      bg: 'bg-muted/10 border-border text-muted',
      dot: 'bg-muted',
    },
    'READY': {
      bg: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
      dot: 'bg-cyan-400',
    },
    'ANALYZING': {
      bg: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
      dot: 'bg-sky-400 animate-ping',
    },
    'AVAILABLE': {
      bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
      dot: 'bg-emerald-400',
    },
    'ERROR': {
      bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
      dot: 'bg-rose-400',
    },
    'INSUFFICIENT DATA': {
      bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
      dot: 'bg-amber-400',
    },
  };

  const style = styles[s] || styles['NOT INITIALIZED'];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-2xs font-mono font-semibold tracking-wider uppercase ${style.bg}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      <span>{s}</span>
    </span>
  );
}

export function DriftStatusBadge({ status }: { status: DriftStatus }) {
  if (status === 'WITHIN BASELINE') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-2xs font-mono font-semibold text-emerald-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
        <span>WITHIN BASELINE</span>
      </span>
    );
  }

  if (status === 'DRIFT DETECTED') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-2xs font-mono font-semibold text-amber-400">
        <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
        <span>DRIFT DETECTED</span>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-border bg-surface-muted px-2.5 py-0.5 text-2xs font-mono font-medium text-muted">
      <span>{status}</span>
    </span>
  );
}

export function DriftSeverityBadge({ severity }: { severity: DriftSeverity }) {
  const styles: Record<DriftSeverity, { bg: string; text: string }> = {
    NONE: {
      bg: 'bg-surface-muted text-muted border-border',
      text: 'NONE',
    },
    LOW: {
      bg: 'bg-sky-500/10 text-sky-400 border-sky-500/20',
      text: 'LOW',
    },
    MODERATE: {
      bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      text: 'MODERATE',
    },
    HIGH: {
      bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      text: 'HIGH',
    },
  };

  const style = styles[severity] || styles.NONE;

  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-3xs font-mono font-bold uppercase tracking-wider ${style.bg}`}
    >
      {style.text}
    </span>
  );
}
