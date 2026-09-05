import { Eye } from 'lucide-react';
import { FindingStatusBadge, SeverityBadge, CategoryBadge } from './FindingStatusBadge';
import type { VulnerabilityFinding } from '@/types';

interface FindingsTableProps {
  findings: VulnerabilityFinding[];
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  loading?: boolean;
}

export function FindingsTable({
  findings,
  onSelectFinding,
  loading = false,
}: FindingsTableProps) {
  if (loading) {
    return (
      <div className="overflow-hidden rounded-lg border border-border bg-surface p-8 text-center text-xs text-text-secondary">
        <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-rose-500 border-t-transparent mb-2" />
        <p>Loading security findings...</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-surface shadow-sm">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-subtle text-[11px] font-semibold uppercase tracking-wider text-text-secondary">
            <th className="py-3 px-4">Rule & Finding</th>
            <th className="py-3 px-4">Category</th>
            <th className="py-3 px-4">Severity</th>
            <th className="py-3 px-4">Affected Object</th>
            <th className="py-3 px-4 text-center">Recurrence</th>
            <th className="py-3 px-4">Status</th>
            <th className="py-3 px-4">Last Detected</th>
            <th className="py-3 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/60 text-xs">
          {findings.map((finding) => (
            <tr
              key={finding.id}
              className="hover:bg-surface-hover/60 transition cursor-pointer"
              onClick={() => onSelectFinding(finding)}
            >
              {/* Rule & Finding Title */}
              <td className="py-3 px-4 max-w-xs">
                <div className="space-y-0.5">
                  <span className="font-mono text-[11px] font-semibold text-rose-400">
                    {finding.rule_id}
                  </span>
                  <div className="font-medium text-text-primary line-clamp-1" title={finding.title}>
                    {finding.title}
                  </div>
                </div>
              </td>

              {/* Category */}
              <td className="py-3 px-4 whitespace-nowrap">
                <CategoryBadge category={finding.category} />
              </td>

              {/* Severity */}
              <td className="py-3 px-4 whitespace-nowrap">
                <SeverityBadge severity={finding.severity} />
              </td>

              {/* Affected Object */}
              <td className="py-3 px-4 max-w-[180px]">
                <div className="font-mono text-xs text-text-primary truncate" title={`${finding.affected_object_type}: ${finding.affected_object_id}`}>
                  <span className="text-text-muted text-[11px] block">{finding.affected_object_type}</span>
                  {finding.affected_object_id}
                </div>
              </td>

              {/* Recurrence Counter */}
              <td className="py-3 px-4 text-center whitespace-nowrap">
                <span
                  className={`inline-block font-mono text-xs font-semibold px-2 py-0.5 rounded ${
                    finding.recurrence_count > 1
                      ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      : 'bg-surface-subtle text-text-muted'
                  }`}
                >
                  {finding.recurrence_count}×
                </span>
              </td>

              {/* Status */}
              <td className="py-3 px-4 whitespace-nowrap">
                <FindingStatusBadge status={finding.status} />
              </td>

              {/* Last Detected */}
              <td className="py-3 px-4 whitespace-nowrap text-text-secondary font-mono text-[11px]">
                {finding.last_detected_at ? new Date(finding.last_detected_at).toLocaleTimeString() : 'N/A'}
              </td>

              {/* Actions */}
              <td className="py-3 px-4 text-right whitespace-nowrap">
                <button
                  onClick={() => onSelectFinding(finding)}
                  className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2.5 py-1 text-xs font-medium text-text-secondary hover:bg-surface-hover hover:text-text-primary transition"
                  title="Inspect Technical Evidence & Triage"
                >
                  <Eye className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Inspect</span>
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
