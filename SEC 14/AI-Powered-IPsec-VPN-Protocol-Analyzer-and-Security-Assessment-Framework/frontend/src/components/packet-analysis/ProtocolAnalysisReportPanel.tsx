import { useEffect, useState } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { packetService } from '@/services';
import type { ProtocolAnalysisReport } from '@/types';

export function ProtocolAnalysisReportPanel() {
  const [report, setReport] = useState<ProtocolAnalysisReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedSection, setExpandedSection] = useState<'proposals' | 'streams' | 'anomalies'>('proposals');

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await packetService.fetchProtocolAnalysis();
      setReport(res);
    } catch (err) {
      setError('Protocol analysis report not yet generated or service offline.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  if (loading && !report) {
    return (
      <div className="rounded border border-border bg-surface p-6 text-center text-xs text-secondary">
        <RefreshCw className="mx-auto mb-2 h-5 w-5 animate-spin text-info" />
        Loading Layer 03 Protocol Analysis report…
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex items-center justify-between rounded border border-border bg-surface p-4 text-xs text-secondary">
        <span>Layer 03 Protocol Analysis: {error || 'No report available. Load a capture to inspect.'}</span>
        <button
          type="button"
          onClick={() => void loadData()}
          className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-primary hover:border-info"
        >
          <RefreshCw className="h-3 w-3" /> Retry
        </button>
      </div>
    );
  }

  const proposals = report.ike_summary?.proposals ?? [];
  const streams = report.ipsec_streams ?? [];
  const anomalies = report.anomalies ?? [];

  return (
    <div className="space-y-4 rounded border border-border bg-surface p-5 shadow-sm">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-primary">Layer 03: Protocol Analysis & Cryptographic Telemetry</h3>
            <span className="rounded bg-info/10 px-2 py-0.5 text-2xs font-medium text-info">READY</span>
          </div>
          <p className="mt-0.5 text-2xs text-muted">
            Decoded IKE proposals, active ESP/AH streams, and protocol anomaly detections for capture{' '}
            <span className="font-mono text-primary">{report.capture_id}</span>
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadData()}
          disabled={loading}
          className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1 text-xs text-secondary hover:border-info hover:text-info"
        >
          <RefreshCw className={loading ? 'h-3.5 w-3.5 animate-spin' : 'h-3.5 w-3.5'} />
          Refresh
        </button>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded border border-border bg-surface-elevated p-3">
          <span className="text-2xs text-muted">Total Packets</span>
          <p className="text-lg font-bold text-primary">{report.total_packets_analyzed}</p>
        </div>
        <div className="rounded border border-border bg-surface-elevated p-3">
          <span className="text-2xs text-muted">IKE Proposals</span>
          <p className="text-lg font-bold text-primary">{proposals.length}</p>
        </div>
        <div className="rounded border border-border bg-surface-elevated p-3">
          <span className="text-2xs text-muted">IPsec Streams</span>
          <p className="text-lg font-bold text-primary">{streams.length}</p>
        </div>
        <div className="rounded border border-border bg-surface-elevated p-3">
          <span className="text-2xs text-muted">Detected Anomalies</span>
          <p className={`text-lg font-bold ${anomalies.length > 0 ? 'text-warning' : 'text-success'}`}>
            {anomalies.length}
          </p>
        </div>
      </div>

      {/* Accordion Tabs */}
      <div className="flex gap-2 border-b border-border text-xs">
        <button
          type="button"
          onClick={() => setExpandedSection('proposals')}
          className={`border-b-2 px-3 py-1.5 font-medium transition-colors ${
            expandedSection === 'proposals'
              ? 'border-info text-info'
              : 'border-transparent text-secondary hover:text-primary'
          }`}
        >
          Decoded IKE Proposals ({proposals.length})
        </button>
        <button
          type="button"
          onClick={() => setExpandedSection('streams')}
          className={`border-b-2 px-3 py-1.5 font-medium transition-colors ${
            expandedSection === 'streams'
              ? 'border-info text-info'
              : 'border-transparent text-secondary hover:text-primary'
          }`}
        >
          Active ESP/AH Streams ({streams.length})
        </button>
        <button
          type="button"
          onClick={() => setExpandedSection('anomalies')}
          className={`border-b-2 px-3 py-1.5 font-medium transition-colors ${
            expandedSection === 'anomalies'
              ? 'border-warning text-warning'
              : 'border-transparent text-secondary hover:text-primary'
          }`}
        >
          Protocol Anomalies ({anomalies.length})
        </button>
      </div>

      {/* Tab 1: Decoded IKE Proposals */}
      {expandedSection === 'proposals' && (
        <div className="space-y-3">
          {proposals.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted">No IKE proposals detected in capture.</p>
          ) : (
            <div className="space-y-2">
              {proposals.map((prop, idx) => {
                const has3DES = prop.encryption.some((c) => c.toUpperCase().includes('3DES'));
                return (
                  <div
                    key={idx}
                    className={`rounded border p-3 text-xs ${
                      has3DES ? 'border-danger/40 bg-danger/5' : 'border-border bg-surface-elevated'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-primary">
                        Proposal #{prop.proposal_number} (Packet #{prop.packet_number})
                      </span>
                      {has3DES && (
                        <span className="rounded bg-danger/20 px-2 py-0.5 text-2xs font-semibold text-danger">
                          INSECURE: 3DES OFFERED
                        </span>
                      )}
                    </div>
                    <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
                      <div>
                        <span className="text-2xs text-muted">Encryption:</span>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {prop.encryption.map((c, i) => (
                            <span
                              key={i}
                              className={`rounded px-1.5 py-0.5 font-mono text-2xs ${
                                c.toUpperCase().includes('3DES')
                                  ? 'bg-danger/20 text-danger font-bold'
                                  : 'bg-surface text-secondary border border-border'
                              }`}
                            >
                              {c}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-2xs text-muted">Integrity:</span>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {prop.integrity.map((h, i) => (
                            <span key={i} className="rounded bg-surface px-1.5 py-0.5 font-mono text-2xs text-secondary border border-border">
                              {h}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-2xs text-muted">Diffie-Hellman Groups:</span>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {prop.dh_groups.map((dh, i) => (
                            <span key={i} className="rounded bg-surface px-1.5 py-0.5 font-mono text-2xs text-secondary border border-border">
                              {dh}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-2xs text-muted">PRF:</span>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {prop.prf.map((p, i) => (
                            <span key={i} className="rounded bg-surface px-1.5 py-0.5 font-mono text-2xs text-secondary border border-border">
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Active IPsec Streams */}
      {expandedSection === 'streams' && (
        <div className="overflow-x-auto">
          {streams.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted">No active ESP or AH streams observed.</p>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-surface-elevated text-2xs uppercase text-muted">
                <tr>
                  <th className="px-3 py-2">Protocol</th>
                  <th className="px-3 py-2">SPI</th>
                  <th className="px-3 py-2">Endpoints</th>
                  <th className="px-3 py-2">Packets</th>
                  <th className="px-3 py-2">Sequence Range</th>
                  <th className="px-3 py-2">Replays</th>
                  <th className="px-3 py-2">Seq 0</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {streams.map((stream, idx) => (
                  <tr key={idx} className="hover:bg-surface-elevated">
                    <td className="px-3 py-2 font-semibold text-primary">{stream.protocol}</td>
                    <td className="px-3 py-2 font-mono text-info">{stream.spi}</td>
                    <td className="px-3 py-2 font-mono text-secondary">
                      {stream.source_ip} &rarr; {stream.destination_ip}
                    </td>
                    <td className="px-3 py-2 text-primary">{stream.packet_count}</td>
                    <td className="px-3 py-2 font-mono text-secondary">
                      {stream.sequence_min} &ndash; {stream.sequence_max}
                    </td>
                    <td className="px-3 py-2 font-bold text-primary">
                      {stream.replay_count > 0 ? (
                        <span className="text-danger">{stream.replay_count}</span>
                      ) : (
                        <span className="text-muted">0</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-bold text-primary">
                      {stream.zero_sequence_count > 0 ? (
                        <span className="text-warning">{stream.zero_sequence_count}</span>
                      ) : (
                        <span className="text-muted">0</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Tab 3: Protocol Anomalies */}
      {expandedSection === 'anomalies' && (
        <div className="space-y-2">
          {anomalies.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted">Zero protocol anomalies detected in capture.</p>
          ) : (
            anomalies.map((ano, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 rounded border border-warning/30 bg-warning/5 p-3 text-xs"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-primary">{ano.type || 'Protocol Anomaly'}</span>
                    <span className="rounded bg-warning/20 px-1.5 py-0.5 text-2xs font-semibold text-warning">
                      {ano.severity}
                    </span>
                    {ano.packet_number && (
                      <span className="text-2xs text-muted">Packet #{ano.packet_number}</span>
                    )}
                  </div>
                  <p className="mt-1 text-secondary">{ano.description}</p>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
