import { ArrowRight, Cable, AlertTriangle, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { SessionActivityItem } from '@/types';

interface SessionActivityTableProps {
  sessions: SessionActivityItem[] | null;
}

export function SessionActivityTable({ sessions }: SessionActivityTableProps) {
  const hasSessions = sessions && sessions.length > 0;

  return (
    <section
      role="region"
      aria-label="Recent Session Activity"
      className="rounded border border-border bg-surface p-5"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Cable className="h-4 w-4 text-info" aria-hidden />
          <h3 className="text-sm font-medium text-primary">Recent IPsec VPN Sessions</h3>
        </div>
        <Link
          to="/ipsec-sessions"
          className="inline-flex items-center gap-1 text-xs text-secondary hover:text-info transition-colors"
        >
          View all <ArrowRight className="h-3 w-3" aria-hidden />
        </Link>
      </div>
      <p className="mt-1 text-xs text-secondary">
        Correlated session streams with AI traffic classification, protocol state, and security assessment findings.
      </p>

      {!hasSessions ? (
        <div className="my-6 rounded border border-border/50 bg-elevated/40 p-6 text-center">
          <p className="text-xs text-muted">No IPsec sessions discovered yet.</p>
          <p className="mt-1 text-2xs text-muted">Upload a PCAP capture in Packet Analysis to discover sessions.</p>
        </div>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border text-2xs uppercase tracking-wider text-muted">
                <th className="pb-2 font-medium">Session ID</th>
                <th className="pb-2 font-medium">Peers</th>
                <th className="pb-2 font-medium">Protocol</th>
                <th className="pb-2 font-medium">Packets</th>
                <th className="pb-2 font-medium">Findings</th>
                <th className="pb-2 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {sessions.map((sess) => (
                <tr key={sess.session_id} className="hover:bg-elevated/40 transition-colors">
                  <td className="py-2.5 font-mono text-xs font-medium text-primary">
                    {sess.session_id}
                  </td>
                  <td className="py-2.5 font-mono text-2xs text-secondary">
                    {sess.peer_a} &harr; {sess.peer_b}
                  </td>
                  <td className="py-2.5">
                    <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-2xs border border-border text-secondary">
                      {sess.ike_version ?? 'IPsec'}
                    </span>
                  </td>
                  <td className="py-2.5 font-mono text-xs tabular-nums text-secondary">
                    {sess.packet_count.toLocaleString()}
                  </td>
                  <td className="py-2.5">
                    <div className="flex items-center gap-2">
                      {sess.vulnerabilities_count > 0 && (
                        <span
                          title={`${sess.vulnerabilities_count} security assessment findings`}
                          className="inline-flex items-center gap-0.5 rounded bg-error/10 px-1.5 py-0.5 text-2xs font-medium text-error"
                        >
                          <ShieldAlert className="h-3 w-3" aria-hidden /> {sess.vulnerabilities_count} Findings
                        </span>
                      )}
                      {sess.has_anomaly && (
                        <span
                          title={`Supplementary Anomaly Score: ${sess.anomaly_score?.toFixed(1) ?? 'N/A'}`}
                          className="inline-flex items-center gap-0.5 rounded bg-warning/10 px-1.5 py-0.5 text-2xs font-medium text-warning"
                        >
                          <AlertTriangle className="h-3 w-3" aria-hidden /> Flagged
                        </span>
                      )}
                      {!sess.has_anomaly && sess.vulnerabilities_count === 0 && (
                        <span className="text-2xs text-muted">&mdash;</span>
                      )}
                    </div>
                  </td>
                  <td className="py-2.5 text-right">
                    <Link
                      to={`/ipsec-sessions?id=${sess.session_id}`}
                      className="text-xs font-medium text-info hover:underline"
                    >
                      Inspect
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
