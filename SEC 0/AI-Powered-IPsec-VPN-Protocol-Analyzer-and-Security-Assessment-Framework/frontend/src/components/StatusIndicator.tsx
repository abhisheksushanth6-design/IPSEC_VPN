interface StatusIndicatorProps {
  label: string;
  value: string;
  tone?: 'signal' | 'muted' | 'fault';
}

const toneClasses: Record<NonNullable<StatusIndicatorProps['tone']>, string> = {
  signal: 'text-signal',
  muted: 'text-muted',
  fault: 'text-fault',
};

/** A single labelled piece of backend state. */
export function StatusIndicator({ label, value, tone = 'muted' }: StatusIndicatorProps) {
  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-line py-3 last:border-b-0">
      <span className="text-sm text-muted">{label}</span>
      <span className={`font-mono text-sm ${toneClasses[tone]}`}>{value}</span>
    </div>
  );
}
