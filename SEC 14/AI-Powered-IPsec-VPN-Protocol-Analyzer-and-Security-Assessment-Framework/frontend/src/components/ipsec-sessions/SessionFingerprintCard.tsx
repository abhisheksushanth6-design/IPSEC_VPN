import { useEffect, useState } from 'react';
import { Check, Copy, Fingerprint, Key, RefreshCw } from 'lucide-react';
import { sessionService } from '@/services';
import type { SessionFingerprintReport } from '@/types';

export function SessionFingerprintCard() {
  const [report, setReport] = useState<SessionFingerprintReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await sessionService.fetchFingerprints();
      setReport(res);
    } catch {
      // Session fingerprints not yet available
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const sessions = Array.isArray(report?.sessions) ? report.sessions : [];

  if (!report || sessions.length === 0) {
    return (
      <div className="rounded border border-border bg-surface p-4 text-xs text-secondary">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-info" />
            <span className="font-medium text-primary">Layer 04: Session Fingerprinting</span>
          </div>
          <button
            type="button"
            onClick={() => void loadData()}
            disabled={loading}
            className="inline-flex items-center gap-1 text-2xs text-muted hover:text-info"
          >
            <RefreshCw className={loading ? 'h-3 w-3 animate-spin' : 'h-3 w-3'} /> Refresh
          </button>
        </div>
        <p className="mt-1 text-2xs text-muted">
          No correlated session fingerprints for the current capture. Upload an IPsec capture to generate stable fingerprints.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded border border-border bg-surface p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-3">
        <div className="flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-info" />
          <h3 className="text-sm font-semibold text-primary">Layer 04: Deterministic Session Fingerprints</h3>
          <span className="rounded bg-info/10 px-2 py-0.5 text-2xs font-medium text-info">
            {report.total_sessions} Correlated Session{report.total_sessions !== 1 ? 's' : ''}
          </span>
        </div>
        <button
          type="button"
          onClick={() => void loadData()}
          disabled={loading}
          className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1 text-2xs text-secondary hover:border-info hover:text-info"
        >
          <RefreshCw className={loading ? 'h-3 w-3 animate-spin' : 'h-3 w-3'} />
          Refresh
        </button>
      </div>

      {/* Sessions List */}
      <div className="space-y-3">
        {sessions.map((sess) => {
          const encList = sess?.crypto_summary?.encryption ?? [];
          const has3DES = encList.some((c) => c?.toUpperCase().includes('3DES'));
          return (
            <div
              key={sess.session_id}
              className={`rounded border p-4 text-xs ${
                has3DES ? 'border-danger/30 bg-danger/5' : 'border-border bg-surface-elevated'
              }`}
            >
              {/* Row 1: Fingerprint hash & Endpoints */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-elevated px-2 py-1 font-mono text-xs font-bold text-info border border-border">
                    FP: {sess.short_signature}
                  </span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(sess.fingerprint, sess.session_id)}
                    title={`Full SHA-256: ${sess.fingerprint}`}
                    className="inline-flex items-center gap-1 rounded p-1 text-muted hover:text-primary"
                  >
                    {copiedId === sess.session_id ? (
                      <Check className="h-3 w-3 text-success" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                  </button>
                  <span className="font-semibold text-primary">
                    {sess.initiator_ip} &harr; {sess.responder_ip}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-2xs">
                  <span className="rounded bg-surface px-2 py-0.5 font-medium text-secondary border border-border">
                    {sess.encapsulation_mode} Mode
                  </span>
                  {sess.nat_traversal && (
                    <span className="rounded bg-warning/20 px-2 py-0.5 font-medium text-warning">NAT-T Active</span>
                  )}
                  <span className="rounded bg-info/20 px-2 py-0.5 font-medium text-info">{sess.state}</span>
                </div>
              </div>

              {/* Row 2: SPIs */}
              <div className="mt-2.5 flex flex-wrap items-center gap-3 font-mono text-2xs text-secondary border-t border-border/60 pt-2">
                <div>
                  <span className="text-muted">Init SPI: </span>
                  <span className="text-primary">{sess.initiator_spi || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-muted">Resp SPI: </span>
                  <span className="text-primary">{sess.responder_spi || 'N/A'}</span>
                </div>
                {sess.child_sa_spis.length > 0 && (
                  <div>
                    <span className="text-muted">Child SAs: </span>
                    <span className="text-info">{sess.child_sa_spis.join(', ')}</span>
                  </div>
                )}
                <div>
                  <span className="text-muted">Traffic: </span>
                  <span className="text-primary">
                    {sess.total_packets} pkts ({sess.ike_packets} IKE / {sess.esp_packets} ESP) · {sess.total_bytes} bytes
                  </span>
                </div>
              </div>

              {/* Row 3: Cryptographic Profile */}
              <div className="mt-2.5 rounded border border-border/80 bg-surface p-2.5">
                <div className="flex items-center gap-1 text-2xs font-semibold text-primary mb-1.5">
                  <Key className="h-3 w-3 text-info" />
                  <span>Negotiated Cryptographic Suite</span>
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4 text-2xs">
                  <div>
                    <span className="text-muted">Ciphers:</span>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {(sess.crypto_summary.encryption ?? []).slice(0, 4).map((c, i) => (
                        <span
                          key={i}
                          className={`rounded px-1 py-0.5 font-mono ${
                            c.toUpperCase().includes('3DES')
                              ? 'bg-danger/20 text-danger font-bold'
                              : 'bg-surface-elevated text-secondary'
                          }`}
                        >
                          {c}
                        </span>
                      ))}
                      {(sess.crypto_summary.encryption ?? []).length > 4 && (
                        <span className="text-muted">+{ (sess.crypto_summary.encryption ?? []).length - 4} more</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <span className="text-muted">Integrity:</span>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {(sess.crypto_summary.integrity ?? []).slice(0, 3).map((h, i) => (
                        <span key={i} className="rounded bg-surface-elevated px-1 py-0.5 font-mono text-secondary">
                          {h}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <span className="text-muted">DH Groups:</span>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {(sess.crypto_summary.dh_groups ?? []).slice(0, 3).map((dh, i) => (
                        <span key={i} className="rounded bg-surface-elevated px-1 py-0.5 font-mono text-secondary">
                          {dh}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <span className="text-muted">PRF:</span>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {(sess.crypto_summary.prf ?? []).slice(0, 2).map((p, i) => (
                        <span key={i} className="rounded bg-surface-elevated px-1 py-0.5 font-mono text-secondary">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
