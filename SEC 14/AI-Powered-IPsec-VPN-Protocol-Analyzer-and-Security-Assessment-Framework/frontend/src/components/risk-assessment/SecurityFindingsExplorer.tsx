import { useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Search,
  ShieldAlert,
  Copy,
  Check,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import type { RiskAssessmentResponse } from '@/types/risk';
import { cn } from '@/utils/cn';

interface SecurityFindingsExplorerProps {
  assessments: RiskAssessmentResponse[];
  selectedAssessment: RiskAssessmentResponse | null;
  onSelectAssessment: (assessment: RiskAssessmentResponse) => void;
  className?: string;
}

export function SecurityFindingsExplorer({
  assessments,
  selectedAssessment,
  onSelectAssessment,
  className,
}: SecurityFindingsExplorerProps) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Flatten findings across assessments with session associations
  const allFindings = useMemo(() => {
    const list: Array<{
      id: string;
      session_id: string;
      title: string;
      severity: string;
      reason: string;
      contribution: number;
      evidence_ref?: string | null;
      source: string;
      assessment: RiskAssessmentResponse;
      mitigation?: string;
    }> = [];

    for (const a of assessments) {
      for (const sig of a.contributing_signals ?? []) {
        const reasonText = sig?.reason ?? 'Identified security deficiency';
        list.push({
          id: `${a.session_id}-${sig.evidence_reference || reasonText.slice(0, 10)}`,
          session_id: a.session_id,
          title: (reasonText.split('(')[0] ?? reasonText).trim(),
          severity: a.risk_level,
          reason: reasonText,
          contribution: sig.contribution,
          evidence_ref: sig.evidence_reference,
          source: sig.source,
          assessment: a,
          mitigation: a.recommended_actions?.[0] || 'Enforce hardened cipher suite and anti-replay protection.',
        });
      }
    }
    return list;
  }, [assessments]);

  const filteredFindings = useMemo(() => {
    return allFindings.filter((f) => {
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          f.session_id.toLowerCase().includes(q) ||
          f.reason.toLowerCase().includes(q) ||
          (f.evidence_ref && f.evidence_ref.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [allFindings, severityFilter, search]);

  const copyToClipboard = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'border-rose-500/40 bg-rose-500/10 text-rose-400';
      case 'HIGH':
        return 'border-orange-500/40 bg-orange-500/10 text-orange-400';
      case 'MEDIUM':
        return 'border-amber-500/40 bg-amber-500/10 text-amber-400';
      default:
        return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
    }
  };

  return (
    <div className={cn('rounded-lg border border-border bg-surface p-4 space-y-4 shadow-sm', className)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border/60 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-info" />
            <h3 className="text-xs font-semibold text-primary">Security Findings Explorer</h3>
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-2xs text-muted border border-border">
              {filteredFindings.length} Active Finding{filteredFindings.length === 1 ? '' : 's'}
            </span>
          </div>
          <p className="mt-0.5 text-2xs text-muted">
            Traceable vulnerability deficiencies linked to observed empirical session telemetry.
          </p>
        </div>

        {/* Filters and search */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[170px]">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted" />
            <input
              type="text"
              placeholder="Search findings, sessions…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded border border-border bg-elevated/40 py-1 pl-8 pr-3 text-2xs text-primary placeholder:text-muted focus:border-info focus:outline-none"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded border border-border bg-elevated px-2 py-1 text-2xs font-mono text-primary focus:border-info focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {filteredFindings.length === 0 ? (
        <div className="rounded border border-border bg-surface p-8 text-center text-xs text-muted">
          {allFindings.length === 0
            ? 'No security findings detected! The analyzed IPsec traffic meets hardened configuration criteria.'
            : 'No findings match the selected filters.'}
        </div>
      ) : (
        <div className="space-y-2.5">
          {filteredFindings.map((f, idx) => {
            const isExpanded = expandedIndex === idx;
            const isSelected = selectedAssessment?.session_id === f.session_id;

            return (
              <div
                key={f.id}
                onClick={() => onSelectAssessment(f.assessment)}
                className={cn(
                  'cursor-pointer rounded-lg border p-3 text-xs transition-all',
                  isSelected
                    ? 'border-info bg-info/5 ring-1 ring-info/30'
                    : 'border-border/80 bg-surface hover:border-info/40 hover:bg-elevated/30'
                )}
              >
                {/* Header Row */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        'rounded border px-2 py-0.5 font-mono text-[9px] font-bold uppercase',
                        getSeverityBadge(f.severity)
                      )}
                    >
                      {f.severity}
                    </span>
                    <h4 className="font-semibold text-primary">{f.title}</h4>
                    <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-muted border border-border">
                      {f.source}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-2xs">
                    <span className="text-muted">Target Session:</span>
                    <span className="font-bold text-primary">{f.session_id}</span>
                    <span className="text-rose-400 font-bold">+{f.contribution.toFixed(1)}</span>
                  </div>
                </div>

                {/* Technical Explanation */}
                <p className="mt-1.5 text-secondary text-2xs leading-relaxed">{f.reason}</p>

                {/* Evidence & Remediation Quick Preview */}
                <div className="mt-2.5 grid grid-cols-1 sm:grid-cols-2 gap-2 text-2xs font-mono">
                  <div className="rounded border border-border/60 bg-background/50 p-2">
                    <span className="text-muted uppercase text-[9px] block">Observed Evidence</span>
                    <span className="text-primary truncate block">{f.evidence_ref || 'Telemetry Rule Match'}</span>
                  </div>
                  <div className="rounded border border-emerald-500/30 bg-emerald-500/5 p-2">
                    <span className="text-emerald-400 uppercase text-[9px] block">Prescriptive Mitigation</span>
                    <span className="text-secondary truncate block">{f.mitigation}</span>
                  </div>
                </div>

                {/* Expand Toggle */}
                <div className="mt-2 flex items-center justify-between pt-1 border-t border-border/50 text-[10px] text-muted">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setExpandedIndex((prev) => (prev === idx ? null : idx));
                    }}
                    className="inline-flex items-center gap-1 text-info hover:underline"
                  >
                    {isExpanded ? (
                      <>
                        <ChevronDown className="h-3 w-3" /> Hide Technical Audit Trail
                      </>
                    ) : (
                      <>
                        <ChevronRight className="h-3 w-3" /> Inspect Technical Audit Trail
                      </>
                    )}
                  </button>

                  <div className="flex items-center gap-2">
                    <Link
                      to={`/ipsec-sessions`}
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex items-center gap-1 text-muted hover:text-info"
                    >
                      <span>Session Flow</span>
                      <ExternalLink className="h-2.5 w-2.5" />
                    </Link>
                  </div>
                </div>

                {/* Expanded Technical Details Drawer */}
                {isExpanded && (
                  <div
                    className="mt-3 rounded border border-border/80 bg-elevated/60 p-3 font-mono text-2xs text-secondary space-y-2"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex items-center justify-between border-b border-border/60 pb-1.5">
                      <span className="font-bold text-info uppercase">Technical Evidence Snapshot</span>
                      <button
                        type="button"
                        onClick={(e) => copyToClipboard(JSON.stringify(f, null, 2), f.id, e)}
                        className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-muted hover:text-primary hover:bg-elevated"
                      >
                        {copiedId === f.id ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-400" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" />
                            <span>Copy Audit JSON</span>
                          </>
                        )}
                      </button>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-muted">Policy Decision: </span>
                        <span className="text-primary font-bold">{f.assessment.decision}</span>
                      </div>
                      <div>
                        <span className="text-muted">Assessment Confidence: </span>
                        <span className="text-primary font-bold">
                          {Math.round(f.assessment.confidence_score * 100)}%
                        </span>
                      </div>
                      <div>
                        <span className="text-muted">Evaluated Layer: </span>
                        <span className="text-primary font-bold">{f.source}</span>
                      </div>
                      <div>
                        <span className="text-muted">Evaluated At: </span>
                        <span className="text-primary">{new Date(f.assessment.evaluated_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
