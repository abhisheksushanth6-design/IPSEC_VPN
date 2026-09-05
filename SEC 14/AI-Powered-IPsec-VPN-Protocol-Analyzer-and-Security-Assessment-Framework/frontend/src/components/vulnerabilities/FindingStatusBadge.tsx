import type { FindingStatus, RuleSeverity, RuleCategory } from '@/types';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, CheckCircle2 } from 'lucide-react';

interface FindingStatusBadgeProps {
  status: FindingStatus;
  className?: string;
}

export function FindingStatusBadge({ status, className = '' }: FindingStatusBadgeProps) {
  switch (status) {
    case 'OPEN':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30 ${className}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" />
          OPEN
        </span>
      );
    case 'CONFIRMED':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/30 ${className}`}
        >
          <AlertCircle className="h-3 w-3" />
          CONFIRMED
        </span>
      );
    case 'RESOLVED':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 ${className}`}
        >
          <CheckCircle2 className="h-3 w-3" />
          RESOLVED
        </span>
      );
    case 'SUPPRESSED':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30 ${className}`}
        >
          SUPPRESSED
        </span>
      );
    case 'FALSE_POSITIVE':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 ${className}`}
        >
          FALSE POSITIVE
        </span>
      );
    default:
      return (
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700 ${className}`}
        >
          {status}
        </span>
      );
  }
}

interface SeverityBadgeProps {
  severity: RuleSeverity;
  className?: string;
  showIcon?: boolean;
}

export function SeverityBadge({ severity, className = '', showIcon = true }: SeverityBadgeProps) {
  switch (severity) {
    case 'CRITICAL':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-bold bg-rose-950/60 text-rose-300 border border-rose-600/50 shadow-sm shadow-rose-900/20 ${className}`}
        >
          {showIcon && <ShieldAlert className="h-3 w-3 text-rose-400" />}
          CRITICAL
        </span>
      );
    case 'HIGH':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold bg-orange-950/60 text-orange-300 border border-orange-600/50 shadow-sm shadow-orange-900/20 ${className}`}
        >
          {showIcon && <AlertTriangle className="h-3 w-3 text-orange-400" />}
          HIGH
        </span>
      );
    case 'MEDIUM':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium bg-amber-950/50 text-amber-300 border border-amber-600/40 ${className}`}
        >
          {showIcon && <AlertCircle className="h-3 w-3 text-amber-400" />}
          MEDIUM
        </span>
      );
    case 'LOW':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium bg-blue-950/50 text-blue-300 border border-blue-600/40 ${className}`}
        >
          {showIcon && <Info className="h-3 w-3 text-blue-400" />}
          LOW
        </span>
      );
    case 'INFORMATIONAL':
      return (
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium bg-slate-900 text-slate-300 border border-slate-700 ${className}`}
        >
          {showIcon && <Info className="h-3 w-3 text-slate-400" />}
          INFO
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-surface-subtle text-text-secondary ${className}`}>
          {severity}
        </span>
      );
  }
}

interface CategoryBadgeProps {
  category: RuleCategory;
  className?: string;
}

export function CategoryBadge({ category, className = '' }: CategoryBadgeProps) {
  const styles: Record<RuleCategory, string> = {
    CRYPTO: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
    IKE: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
    AUTH: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    PROTOCOL: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30',
    SA_LIFECYCLE: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    CONFIGURATION: 'bg-blue-500/10 text-blue-300 border-blue-500/30',
  };

  const labels: Record<RuleCategory, string> = {
    CRYPTO: 'Cryptography',
    IKE: 'IKE Negotiation',
    AUTH: 'Authentication',
    PROTOCOL: 'Protocol Integrity',
    SA_LIFECYCLE: 'SA Lifecycle',
    CONFIGURATION: 'Configuration',
  };

  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium border ${
        styles[category] || 'bg-slate-800 text-slate-300 border-slate-700'
      } ${className}`}
    >
      {labels[category] || category}
    </span>
  );
}
