import { X, ExternalLink, CheckCircle2, XCircle } from 'lucide-react';
import { SeverityBadge, CategoryBadge } from './FindingStatusBadge';
import type { SecurityRule } from '@/types';

interface RuleDetailModalProps {
  rule: SecurityRule | null;
  onClose: () => void;
  onToggleRule: (ruleId: string, enabled: boolean) => Promise<void>;
}

export function RuleDetailModal({
  rule,
  onClose,
  onToggleRule,
}: RuleDetailModalProps) {
  if (!rule) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="relative w-full max-w-2xl rounded-xl border border-border bg-surface p-6 shadow-2xl space-y-5 my-8 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-border/60 pb-4">
          <div className="space-y-1 pr-4">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-rose-400 bg-rose-500/10 px-2.5 py-0.5 rounded border border-rose-500/20">
                {rule.id}
              </span>
              <SeverityBadge severity={rule.severity} />
              <CategoryBadge category={rule.category} />
            </div>
            <h2 className="text-base font-bold text-text-primary mt-1">{rule.name}</h2>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-surface-hover hover:text-text-primary transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Rule Metadata */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 rounded-lg bg-surface-subtle p-3 border border-border/60 text-xs">
          <div>
            <span className="text-text-secondary block mb-0.5">Status</span>
            <span
              className={`font-semibold inline-flex items-center gap-1 ${
                rule.enabled ? 'text-emerald-400' : 'text-slate-400'
              }`}
            >
              {rule.enabled ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" /> Enabled
                </>
              ) : (
                <>
                  <XCircle className="h-3.5 w-3.5" /> Disabled
                </>
              )}
            </span>
          </div>

          <div>
            <span className="text-text-secondary block mb-0.5">Confidence</span>
            <span className="font-mono text-text-primary">{Math.round(rule.confidence * 100)}%</span>
          </div>

          <div>
            <span className="text-text-secondary block mb-0.5">Version</span>
            <span className="font-mono text-text-primary">{rule.version}</span>
          </div>

          <div>
            <span className="text-text-secondary block mb-0.5">Author</span>
            <span className="font-mono text-text-primary">{rule.author}</span>
          </div>
        </div>

        {/* Description */}
        <div className="space-y-1">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
            Rule Description & Rationale
          </h4>
          <p className="text-xs text-text-primary leading-relaxed rounded-lg bg-surface-subtle p-3.5 border border-border/60">
            {rule.description}
          </p>
        </div>

        {/* Remediation Guide */}
        <div className="space-y-1">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-400">
            Remediation Directive & Standards
          </h4>
          <p className="text-xs text-amber-200/90 leading-relaxed rounded-lg bg-amber-950/20 p-3.5 border border-amber-500/20">
            {rule.remediation}
          </p>
        </div>

        {/* CVEs / RFCs */}
        {rule.cve_references && rule.cve_references.length > 0 && (
          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Authoritative Citations & RFCs
            </h4>
            <div className="flex flex-wrap gap-2">
              {rule.cve_references.map((ref) => (
                <span
                  key={ref}
                  className="inline-flex items-center gap-1 rounded bg-surface-subtle px-2.5 py-1 text-xs font-mono text-cyan-300 border border-border"
                >
                  <ExternalLink className="h-3 w-3" />
                  {ref}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-border/60 pt-4">
          <button
            onClick={() => onToggleRule(rule.id, !rule.enabled)}
            className={`rounded px-3.5 py-1.5 text-xs font-semibold transition ${
              rule.enabled
                ? 'bg-slate-700 hover:bg-slate-600 text-slate-200'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white'
            }`}
          >
            {rule.enabled ? 'Disable This Rule' : 'Enable This Rule'}
          </button>

          <button
            onClick={onClose}
            className="rounded border border-border bg-surface px-4 py-1.5 text-xs font-medium text-text-secondary hover:bg-surface-hover hover:text-text-primary transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
