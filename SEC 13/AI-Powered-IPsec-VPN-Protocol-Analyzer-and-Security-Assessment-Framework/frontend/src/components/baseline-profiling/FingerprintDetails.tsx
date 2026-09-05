import { useState } from 'react';
import { Check, Copy, Fingerprint, X } from 'lucide-react';
import type { SessionFingerprint } from '@/types';

interface FingerprintDetailsProps {
  fingerprint: SessionFingerprint;
  onClose: () => void;
  onCompare?: (id: string) => void;
}

export function FingerprintDetails({
  fingerprint,
  onClose,
  onCompare,
}: FingerprintDetailsProps) {
  const [copied, setCopied] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const copySignature = () => {
    navigator.clipboard.writeText(fingerprint.signature);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const categories = ['ALL', ...Array.from(new Set(fingerprint.features.map((f) => f.category)))];

  const filteredFeatures = fingerprint.features.filter((f) => {
    if (selectedCategory === 'ALL') return true;
    return f.category === selectedCategory;
  });

  return (
    <div className="flex flex-col h-full bg-surface border border-border rounded-lg shadow-sm">
      {/* Drawer / Panel Header */}
      <div className="flex items-start justify-between border-b border-border p-5 bg-surface-muted/30">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Fingerprint className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-text-primary">
                Session Fingerprint Identity
              </h2>
              <p className="font-mono text-2xs text-muted">
                {fingerprint.id} · Session: {fingerprint.session_id}
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {onCompare && (
            <button
              type="button"
              onClick={() => onCompare(fingerprint.id)}
              className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2.5 py-1 text-2xs font-medium text-text-secondary hover:text-cyan-400 hover:border-cyan-500 transition"
            >
              Compare
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-muted hover:bg-surface-muted hover:text-text-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Signature & Key Metadata */}
      <div className="p-5 border-b border-border space-y-3 bg-base/50">
        <div className="space-y-1">
          <div className="flex items-center justify-between text-2xs text-muted">
            <span className="font-semibold uppercase tracking-wider">
              Deterministic SHA-256 Signature
            </span>
            <button
              type="button"
              onClick={copySignature}
              className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition"
            >
              {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <div className="rounded border border-border bg-surface p-2.5 font-mono text-2xs text-cyan-300 break-all select-all">
            {fingerprint.signature}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 text-2xs">
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-muted">Feature Schema</span>
            <div className="font-mono font-semibold text-text-primary mt-0.5">
              v{fingerprint.feature_version}
            </div>
          </div>
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-muted">Features Profiled</span>
            <div className="font-mono font-semibold text-text-primary mt-0.5">
              {fingerprint.feature_count}
            </div>
          </div>
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-muted">Capture ID</span>
            <div className="font-mono font-semibold text-text-primary mt-0.5 truncate" title={fingerprint.capture_id}>
              {fingerprint.capture_id}
            </div>
          </div>
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-muted">Generated At</span>
            <div className="font-mono font-semibold text-text-primary mt-0.5">
              {new Date(fingerprint.created_at).toLocaleTimeString()}
            </div>
          </div>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex items-center gap-1 overflow-x-auto border-b border-border px-5 py-2 bg-surface">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`rounded px-2.5 py-1 text-2xs font-mono font-semibold uppercase tracking-wider transition ${
              selectedCategory === cat
                ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                : 'text-muted hover:bg-surface-muted hover:text-text-primary border border-transparent'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Features List */}
      <div className="flex-1 overflow-y-auto p-5">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-border text-2xs uppercase tracking-wider text-muted">
              <th className="py-2 px-3">Feature</th>
              <th className="py-2 px-3 text-right">Observed Value</th>
              <th className="py-2 px-3 text-center">Availability</th>
              <th className="py-2 px-3 text-center">Quality</th>
              <th className="py-2 px-3">Origin Lineage</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filteredFeatures.map((feat) => {
              let displayVal = '—';
              if (feat.value !== null) {
                if (typeof feat.value === 'boolean') {
                  displayVal = feat.value ? 'TRUE' : 'FALSE';
                } else if (typeof feat.value === 'number') {
                  displayVal = feat.value.toLocaleString();
                } else {
                  displayVal = String(feat.value);
                }
              }

              return (
                <tr key={feat.name} className="hover:bg-surface-muted/40 transition">
                  <td className="py-2 px-3">
                    <div className="font-medium text-text-primary">{feat.display_name}</div>
                    <div className="font-mono text-3xs text-muted">{feat.name}</div>
                  </td>

                  <td className="py-2 px-3 text-right font-mono text-text-primary font-semibold">
                    {displayVal} {feat.unit ?? ''}
                  </td>

                  <td className="py-2 px-3 text-center">
                    <span
                      className={`inline-flex rounded px-1.5 py-0.5 text-3xs font-mono font-medium ${
                        feat.availability === 'AVAILABLE'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-muted/10 text-muted border border-border'
                      }`}
                    >
                      {feat.availability}
                    </span>
                  </td>

                  <td className="py-2 px-3 text-center">
                    <span
                      className={`inline-flex rounded px-1.5 py-0.5 text-3xs font-mono font-medium ${
                        feat.quality === 'COMPLETE'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      {feat.quality}
                    </span>
                  </td>

                  <td className="py-2 px-3 text-3xs text-muted truncate max-w-[140px]" title={feat.source}>
                    {feat.source}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
