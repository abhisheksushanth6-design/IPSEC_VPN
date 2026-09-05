import { useState } from 'react';
import { X, ExternalLink, Calendar, Hash, CheckCircle2, Wrench } from 'lucide-react';
import { FindingStatusBadge, SeverityBadge, CategoryBadge } from './FindingStatusBadge';
import { FindingEvidenceCard } from './FindingEvidenceCard';
import type { VulnerabilityFinding, FindingStatus } from '@/types';

interface FindingDetailModalProps {
  finding: VulnerabilityFinding | null;
  onClose: () => void;
  onUpdateStatus: (findingId: number, status: FindingStatus, note?: string) => Promise<void>;
}

export function FindingDetailModal({
  finding,
  onClose,
  onUpdateStatus,
}: FindingDetailModalProps) {
  const [selectedStatus, setSelectedStatus] = useState<FindingStatus>(finding?.status || 'OPEN');
  const [note, setNote] = useState<string>(finding?.status_note || '');
  const [saving, setSaving] = useState<boolean>(false);

  if (!finding) return null;

  const handleSaveStatus = async () => {
    try {
      setSaving(true);
      await onUpdateStatus(finding.id, selectedStatus, note);
      onClose();
    } catch (err) {
      console.error('Failed to update status', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl rounded-xl border border-border bg-surface p-6 shadow-2xl space-y-6 my-8 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-border/60 pb-4">
          <div className="space-y-1.5 pr-6">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-semibold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                {finding.rule_id}
              </span>
              <SeverityBadge severity={finding.severity} />
              <CategoryBadge category={finding.category} />
              <FindingStatusBadge status={finding.status} />
              {finding.recurrence_count > 1 && (
                <span className="font-mono text-xs font-semibold text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                  Seen {finding.recurrence_count}×
                </span>
              )}
            </div>
            <h2 className="text-lg font-bold text-text-primary mt-1">{finding.title}</h2>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-surface-hover hover:text-text-primary transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Overview Grid */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 rounded-lg bg-surface-subtle p-3.5 border border-border/60 text-xs">
          <div>
            <span className="text-text-secondary block mb-0.5">Affected Object</span>
            <div className="font-mono font-medium text-text-primary break-all">
              <span className="text-rose-300 font-semibold">{finding.affected_object_type}</span>: {finding.affected_object_id}
            </div>
          </div>

          <div>
            <span className="text-text-secondary block mb-0.5">Rule Confidence</span>
            <div className="font-mono font-medium text-emerald-400">
              {Math.round(finding.confidence * 100)}% Deterministic
            </div>
          </div>

          <div>
            <span className="text-text-secondary block mb-0.5">First Observed</span>
            <div className="font-mono text-text-primary flex items-center gap-1">
              <Calendar className="h-3 w-3 text-text-muted" />
              {new Date(finding.first_detected_at).toLocaleString()}
            </div>
          </div>

          <div>
            <span className="text-text-secondary block mb-0.5">Last Observed</span>
            <div className="font-mono text-text-primary flex items-center gap-1">
              <Calendar className="h-3 w-3 text-text-muted" />
              {new Date(finding.last_detected_at).toLocaleString()}
            </div>
          </div>
        </div>

        {/* Deduplication Hash Tag */}
        <div className="flex items-center gap-2 text-xs font-mono text-text-muted bg-surface-subtle/50 px-3 py-1.5 rounded border border-border/40">
          <Hash className="h-3.5 w-3.5 text-purple-400" />
          <span>Deduplication Hash:</span>
          <span className="text-text-secondary truncate">{finding.dedup_hash}</span>
        </div>

        {/* Technical Description */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
            Vulnerability Details
          </h4>
          <p className="text-xs text-text-primary leading-relaxed rounded-lg bg-surface-subtle p-3.5 border border-border/60">
            {finding.description}
          </p>
        </div>

        {/* Technical Evidence Chain */}
        <FindingEvidenceCard evidence={finding.evidence} />

        {/* Authoritative Remediation & Standards */}
        <div className="space-y-2 rounded-lg border border-amber-500/20 bg-amber-950/10 p-4">
          <div className="flex items-center gap-2 text-amber-400">
            <Wrench className="h-4 w-4" />
            <h4 className="text-xs font-bold uppercase tracking-wider">
              RFC & Security Standard Remediation
            </h4>
          </div>
          <p className="text-xs text-amber-200/90 leading-relaxed">
            {finding.remediation}
          </p>

          {finding.cve_references && finding.cve_references.length > 0 && (
            <div className="mt-3 pt-3 border-t border-amber-500/20 flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-amber-300">Authoritative References:</span>
              {finding.cve_references.map((cve) => (
                <span
                  key={cve}
                  className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-xs font-mono text-amber-300 border border-amber-500/30"
                >
                  <ExternalLink className="h-3 w-3" />
                  {cve}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* SOC Analyst Triage Controls */}
        <div className="rounded-lg border border-border bg-surface-subtle p-4 space-y-3">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-secondary flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400" />
            SOC Analyst Triage Workflow
          </h4>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="block text-xs text-text-secondary mb-1">Update Status</label>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value as FindingStatus)}
                className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs text-text-primary focus:border-rose-500 focus:outline-none"
              >
                <option value="OPEN">OPEN (Active Violation)</option>
                <option value="CONFIRMED">CONFIRMED (Validated by Analyst)</option>
                <option value="RESOLVED">RESOLVED (Remediation Verified)</option>
                <option value="SUPPRESSED">SUPPRESSED (Accepted Operational Risk)</option>
                <option value="FALSE_POSITIVE">FALSE POSITIVE (Excluded)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-text-secondary mb-1">Triage Notes</label>
              <input
                type="text"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add resolution details or risk acceptance notes..."
                className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-rose-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={onClose}
              className="rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-surface-hover transition"
            >
              Cancel
            </button>
            <button
              onClick={handleSaveStatus}
              disabled={saving}
              className="rounded bg-rose-600 hover:bg-rose-500 text-white px-3.5 py-1.5 text-xs font-semibold shadow transition disabled:opacity-50"
            >
              {saving ? 'Updating...' : 'Save Triage Status'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
