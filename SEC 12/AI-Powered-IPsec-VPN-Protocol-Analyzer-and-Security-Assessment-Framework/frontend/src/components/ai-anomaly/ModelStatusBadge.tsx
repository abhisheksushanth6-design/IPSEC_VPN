import type { MLModelStatus, AnomalyClassification } from '@/types';

interface ModelStatusBadgeProps {
  status: MLModelStatus | string;
  size?: 'sm' | 'md';
}

export function ModelStatusBadge({ status, size = 'md' }: ModelStatusBadgeProps) {
  const norm = status.toUpperCase().replace(/_/g, ' ');
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-2xs' : 'px-2.5 py-1 text-xs';

  let colorClasses = 'border-slate-700/60 bg-slate-800/40 text-slate-400';
  let dotColor = 'bg-slate-400';

  if (norm === 'READY' || norm === 'INFERENCE READY' || norm === 'TRAINED') {
    colorClasses = 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400';
    dotColor = 'bg-emerald-400';
  } else if (norm === 'TRAINING') {
    colorClasses = 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400 animate-pulse';
    dotColor = 'bg-cyan-400';
  } else if (norm === 'INSUFFICIENT DATA') {
    colorClasses = 'border-amber-500/30 bg-amber-500/10 text-amber-400';
    dotColor = 'bg-amber-400';
  } else if (norm === 'ERROR' || norm === 'FAILED') {
    colorClasses = 'border-rose-500/30 bg-rose-500/10 text-rose-400';
    dotColor = 'bg-rose-400';
  } else if (norm === 'NOT INITIALIZED') {
    colorClasses = 'border-slate-700/60 bg-slate-800/40 text-slate-400';
    dotColor = 'bg-slate-500';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-mono font-semibold tracking-wider border ${sizeClasses} ${colorClasses}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />
      {norm}
    </span>
  );
}

interface AnomalyClassificationBadgeProps {
  classification: AnomalyClassification;
  size?: 'sm' | 'md' | 'lg';
}

export function AnomalyClassificationBadge({
  classification,
  size = 'md',
}: AnomalyClassificationBadgeProps) {
  const isAnomalous = classification === 'ANOMALOUS';
  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-2xs'
      : size === 'lg'
      ? 'px-3.5 py-1.5 text-sm'
      : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-mono font-bold tracking-wider border ${sizeClasses} ${
        isAnomalous
          ? 'border-rose-500/40 bg-rose-500/15 text-rose-400 shadow-sm shadow-rose-950/30'
          : 'border-emerald-500/40 bg-emerald-500/15 text-emerald-400 shadow-sm shadow-emerald-950/30'
      }`}
    >
      <span className={`h-2 w-2 rounded-full ${isAnomalous ? 'bg-rose-400 animate-ping' : 'bg-emerald-400'}`} />
      {classification}
    </span>
  );
}
