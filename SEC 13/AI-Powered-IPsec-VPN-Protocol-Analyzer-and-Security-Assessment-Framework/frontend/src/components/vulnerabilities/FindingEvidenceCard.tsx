import { Database, Clock, Layers, FileCode, Check, X } from 'lucide-react';
import type { FindingEvidence } from '@/types';

interface FindingEvidenceCardProps {
  evidence: FindingEvidence[];
}

export function FindingEvidenceCard({ evidence }: FindingEvidenceCardProps) {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="rounded border border-border/60 bg-surface-subtle p-4 text-xs text-text-muted">
        No specific technical evidence records attached to this finding.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary flex items-center gap-1.5">
          <Database className="h-3.5 w-3.5 text-rose-400" />
          Technical Evidence Chain ({evidence.length} artifact{evidence.length !== 1 ? 's' : ''})
        </h4>
        <span className="text-[11px] font-mono text-text-muted">RFC Audit Trail</span>
      </div>

      <div className="space-y-2.5">
        {evidence.map((item, idx) => (
          <div
            key={item.id ?? idx}
            className="rounded-lg border border-border bg-surface-subtle p-3.5 text-xs space-y-2.5"
          >
            {/* Header / Source */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/40 pb-2">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300 border border-cyan-500/20">
                  <Layers className="h-3 w-3" />
                  {item.evidence_source}
                </span>
                <span className="font-mono text-text-primary font-medium">
                  ID: {item.source_id}
                </span>
              </div>

              <div className="flex items-center gap-1.5 text-text-muted text-[11px] font-mono">
                <Clock className="h-3 w-3" />
                {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'N/A'}
              </div>
            </div>

            {/* Observed vs Expected Grid */}
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <div className="rounded bg-rose-950/20 border border-rose-900/30 p-2">
                <div className="flex items-center justify-between text-[11px] text-rose-300 mb-1">
                  <span className="font-medium flex items-center gap-1">
                    <X className="h-3 w-3 text-rose-400" /> Observed Value
                  </span>
                  <span className="font-mono text-[10px] text-text-muted">{item.field_name}</span>
                </div>
                <div className="font-mono text-xs font-semibold text-rose-200 break-all">
                  {item.observed_value}
                </div>
              </div>

              <div className="rounded bg-emerald-950/20 border border-emerald-900/30 p-2">
                <div className="flex items-center justify-between text-[11px] text-emerald-300 mb-1">
                  <span className="font-medium flex items-center gap-1">
                    <Check className="h-3 w-3 text-emerald-400" /> Expected / Secure
                  </span>
                  <span className="font-mono text-[10px] text-text-muted">Standard</span>
                </div>
                <div className="font-mono text-xs font-semibold text-emerald-200 break-all">
                  {item.expected_value || 'Compliant cryptographic parameter / state'}
                </div>
              </div>
            </div>

            {/* Criterion */}
            <div className="rounded bg-surface/60 border border-border/50 p-2 text-text-secondary flex items-start gap-2">
              <FileCode className="h-3.5 w-3.5 text-amber-400 mt-0.5 shrink-0" />
              <div>
                <span className="text-[11px] font-medium text-text-primary">Evaluation Criterion: </span>
                <span className="text-[11px] font-mono text-text-secondary">{item.rule_criterion}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
