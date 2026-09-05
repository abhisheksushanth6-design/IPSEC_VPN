import { KeyRound, Shield, CheckCircle2, XCircle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { ProtocolPosture } from '@/types';

interface ProtocolPostureCardProps {
  posture: ProtocolPosture | null;
}

export function ProtocolPostureCard({ posture }: ProtocolPostureCardProps) {
  const hasData =
    posture &&
    (posture.ike_versions.length > 0 ||
      posture.observed_encryption_algorithms.length > 0 ||
      posture.observed_dh_groups.length > 0);

  return (
    <article
      aria-labelledby="protocol-posture-title"
      className="flex flex-col justify-between rounded border border-border bg-surface p-5"
    >
      <div>
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-info" aria-hidden />
            <h3 id="protocol-posture-title" className="text-sm font-medium text-primary">
              Cryptographic & Protocol Posture
            </h3>
          </div>
          <Link
            to="/vulnerabilities"
            className="inline-flex items-center gap-1 text-xs text-secondary hover:text-info transition-colors"
          >
            Rules <ArrowRight className="h-3 w-3" aria-hidden />
          </Link>
        </div>

        <p className="mt-1 text-xs text-secondary">
          Observed cryptographic algorithms and key exchange transforms across IPsec sessions.
        </p>

        {!hasData ? (
          <div className="my-6 rounded border border-border/50 bg-elevated/40 p-4 text-center">
            <p className="text-xs text-muted">No cryptographic sessions recorded yet.</p>
            <p className="mt-1 text-2xs text-muted">Upload a PCAP or run session discovery to observe transforms.</p>
          </div>
        ) : (
          <div className="mt-4 space-y-3">
            {/* IKE Versions */}
            <div>
              <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
                Observed IKE Versions
              </span>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {posture.ike_versions.map((ver) => (
                  <span
                    key={ver}
                    className="rounded bg-elevated px-2 py-0.5 font-mono text-xs font-medium text-primary border border-border"
                  >
                    {ver}
                  </span>
                ))}
              </div>
            </div>

            {/* Encryption Algorithms */}
            <div>
              <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
                Encryption Ciphers
              </span>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {posture.observed_encryption_algorithms.length > 0 ? (
                  posture.observed_encryption_algorithms.map((enc) => (
                    <span
                      key={enc}
                      className="rounded bg-elevated px-2 py-0.5 font-mono text-xs text-secondary border border-border"
                    >
                      {enc}
                    </span>
                  ))
                ) : (
                  <span className="text-2xs text-muted">None detected</span>
                )}
              </div>
            </div>

            {/* DH Groups */}
            <div>
              <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
                Diffie-Hellman Groups
              </span>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {posture.observed_dh_groups.length > 0 ? (
                  posture.observed_dh_groups.map((dh) => (
                    <span
                      key={dh}
                      className="rounded bg-elevated px-2 py-0.5 font-mono text-xs text-secondary border border-border"
                    >
                      Group {dh}
                    </span>
                  ))
                ) : (
                  <span className="text-2xs text-muted">None detected</span>
                )}
              </div>
            </div>

            {/* PFS Enabled */}
            <div className="flex items-center justify-between border-t border-border pt-2.5 text-xs">
              <span className="text-secondary">Perfect Forward Secrecy (PFS):</span>
              {posture.pfs_enabled === true ? (
                <span className="inline-flex items-center gap-1 font-medium text-success">
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> ACTIVE
                </span>
              ) : posture.pfs_enabled === false ? (
                <span className="inline-flex items-center gap-1 font-medium text-warning">
                  <XCircle className="h-3.5 w-3.5" aria-hidden /> DISABLED
                </span>
              ) : (
                <span className="text-muted">UNDETERMINED</span>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="mt-4 border-t border-border pt-3 flex items-center justify-between text-2xs text-muted">
        <span>Source: Layer 03 &amp; 04 Analytics</span>
        <KeyRound className="h-3.5 w-3.5 text-muted" aria-hidden />
      </div>
    </article>
  );
}
