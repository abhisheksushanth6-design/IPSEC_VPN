import { useState } from 'react';
import { Check, ChevronRight, Copy, Fingerprint, GitCompare } from 'lucide-react';
import type { SessionFingerprint } from '@/types';

interface FingerprintTableProps {
  fingerprints: SessionFingerprint[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onCompareWith?: (id: string) => void;
}

export function FingerprintTable({
  fingerprints,
  selectedId,
  onSelect,
  onCompareWith,
}: FingerprintTableProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  if (fingerprints.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center border-b border-border">
        <Fingerprint className="h-8 w-8 text-muted mb-2 opacity-50" />
        <h3 className="text-sm font-semibold text-text-primary">No Session Fingerprints</h3>
        <p className="text-xs text-muted max-w-sm mt-1">
          No session fingerprints have been generated yet. When sessions are observed or analyzed, deterministic fingerprints are calculated.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-muted/50 text-2xs uppercase tracking-wider text-muted">
            <th className="py-2.5 px-4">Fingerprint Identifier</th>
            <th className="py-2.5 px-4">Session ID</th>
            <th className="py-2.5 px-4">Behavioral Signature (SHA-256)</th>
            <th className="py-2.5 px-4 text-center">Version</th>
            <th className="py-2.5 px-4 text-right">Features</th>
            <th className="py-2.5 px-4">Created</th>
            <th className="py-2.5 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {fingerprints.map((fp) => {
            const isSelected = selectedId === fp.id;
            return (
              <tr
                key={fp.id}
                onClick={() => onSelect(fp.id)}
                className={`group cursor-pointer transition ${
                  isSelected ? 'bg-cyan-500/10 hover:bg-cyan-500/15' : 'hover:bg-surface-muted/40'
                }`}
              >
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-semibold text-text-primary group-hover:text-cyan-400 transition">
                      {fp.id}
                    </span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(fp.id, `id-${fp.id}`);
                      }}
                      className="text-muted hover:text-text-primary"
                      title="Copy Fingerprint ID"
                    >
                      {copiedId === `id-${fp.id}` ? (
                        <Check className="h-3 w-3 text-emerald-400" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                    </button>
                  </div>
                  <div className="mt-0.5 font-mono text-2xs text-muted">
                    Capture: {fp.capture_id}
                  </div>
                </td>

                <td className="py-3 px-4 font-mono text-text-secondary">
                  {fp.session_id}
                </td>

                <td className="py-3 px-4">
                  <div className="flex items-center gap-1.5 font-mono text-2xs text-text-secondary">
                    <span className="truncate max-w-[200px]" title={fp.signature}>
                      {fp.signature.slice(0, 16)}...{fp.signature.slice(-8)}
                    </span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(fp.signature, `sig-${fp.id}`);
                      }}
                      className="text-muted hover:text-text-primary"
                      title="Copy Full SHA-256 Signature"
                    >
                      {copiedId === `sig-${fp.id}` ? (
                        <Check className="h-3 w-3 text-emerald-400" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                    </button>
                  </div>
                </td>

                <td className="py-3 px-4 text-center">
                  <span className="rounded bg-surface-muted px-2 py-0.5 font-mono text-2xs font-semibold text-text-secondary border border-border">
                    v{fp.feature_version}
                  </span>
                </td>

                <td className="py-3 px-4 text-right font-mono text-xs text-text-secondary">
                  {fp.feature_count}
                </td>

                <td className="py-3 px-4 text-muted text-2xs whitespace-nowrap">
                  {new Date(fp.created_at).toLocaleString()}
                </td>

                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                    {onCompareWith && (
                      <button
                        type="button"
                        onClick={() => onCompareWith(fp.id)}
                        className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2.5 py-1 text-2xs font-medium text-text-secondary hover:border-cyan-500 hover:text-cyan-400 transition"
                      >
                        <GitCompare className="h-3 w-3" />
                        <span>Compare</span>
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onSelect(fp.id)}
                      className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-2xs font-medium transition ${
                        isSelected
                          ? 'bg-cyan-600 text-white hover:bg-cyan-500'
                          : 'border border-border bg-surface text-text-secondary hover:bg-surface-muted'
                      }`}
                    >
                      <span>Inspect</span>
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
