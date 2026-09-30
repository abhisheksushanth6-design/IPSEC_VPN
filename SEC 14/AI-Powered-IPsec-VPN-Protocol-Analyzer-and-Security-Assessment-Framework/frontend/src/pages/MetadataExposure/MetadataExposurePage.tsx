import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ShieldAlert,
  EyeOff,
  Layers,
  RefreshCw,
  Search,
  AlertTriangle,
  Info,
  ChevronRight,
  CheckCircle2,
  X,
  Gauge,
  Lock,
  Network,
  FileCode,
} from 'lucide-react';
import { metadataExposureService } from '@/services/metadataExposureService';
import { sessionService } from '@/services/sessionService';
import type {
  MetadataExposureItem,
  MetadataExposureSummary,
  ExposureRiskLevel,
} from '@/types';

export const MetadataExposurePage: React.FC = () => {
  const [captureId, setCaptureId] = useState<string>('default');
  const [assessments, setAssessments] = useState<MetadataExposureItem[]>([]);
  const [summary, setSummary] = useState<MetadataExposureSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRisk, setSelectedRisk] = useState<string>('ALL');
  const [selectedItem, setSelectedItem] = useState<MetadataExposureItem | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      setError(null);

      let currentId = 'default';
      try {
        const sessStatus = await sessionService.fetchStatus();
        if (sessStatus?.capture_id) {
          currentId = sessStatus.capture_id;
        }
      } catch {
        // Fall back to default
      }
      setCaptureId(currentId);

      const [sumRes, itemsRes] = await Promise.all([
        metadataExposureService.getSummary(currentId).catch(() => null),
        metadataExposureService.getCaptureAssessments(currentId).catch(() => []),
      ]);

      const items = Array.isArray(itemsRes) ? itemsRes : [];
      setAssessments(items);
      if (items.length > 0 && sumRes) {
        setSummary(sumRes);
      } else {
        setSummary(null);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load metadata exposure telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleEvaluate = async () => {
    try {
      setEvaluating(true);
      setError(null);
      const targetId = captureId || 'default';
      const updated = await metadataExposureService.evaluateCapture(targetId);
      const items = Array.isArray(updated) ? updated : [];
      if (items.length > 0) {
        setAssessments(items);
        const resolvedId = items[0]?.capture_id || targetId;
        setCaptureId(resolvedId);
        const newSum = await metadataExposureService.getSummary(resolvedId).catch(() => null);
        if (newSum) {
          setSummary(newSum);
        }
      } else {
        if (assessments.length === 0) {
          setAssessments([]);
          setSummary(null);
        }
        setError('No capture/session data available for evaluation. Please load a capture and discover sessions.');
      }
    } catch (err: any) {
      if (assessments.length === 0) {
        setSummary(null);
      }
      setError(err.message || 'Failed to evaluate metadata exposure');
    } finally {
      setEvaluating(false);
    }
  };

  const filteredItems = useMemo(() => {
    return (Array.isArray(assessments) ? assessments : []).filter((item) => {
      const matchesSearch =
        !searchQuery ||
        item.session_id?.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesRisk = selectedRisk === 'ALL' || item.risk_level === selectedRisk;
      return matchesSearch && matchesRisk;
    });
  }, [assessments, searchQuery, selectedRisk]);

  const getRiskBadge = (level: ExposureRiskLevel) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400';
    if (score >= 50) return 'text-amber-400';
    if (score >= 25) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/20">
              Layer 08 &middot; Security Assessment Engine
            </span>
            <span className="text-xs text-slate-400">RFC 4301 / RFC 4303 Metadata Leakage &amp; TFC Audit</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <EyeOff className="w-7 h-7 text-rose-400" />
            Metadata Exposure Assessment
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Quantitative 5-vector evaluation of side-channel information leakage (SPI tracking, sequence monotonicity,
            packet length/TFC padding, timing cadence, and topology exposure) exposed to network eavesdroppers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchData()}
            disabled={loading}
            className="px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleEvaluate}
            disabled={evaluating}
            className="px-4 py-2 text-xs font-semibold text-white bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 rounded-lg shadow-lg shadow-rose-900/20 flex items-center gap-2 transition-all disabled:opacity-50"
          >
            <ShieldAlert className={`w-4 h-4 ${evaluating ? 'animate-pulse' : ''}`} />
            {evaluating ? 'Evaluating Exposure...' : 'Evaluate Capture Exposure'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      {/* 5 Vector KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Overall Posture */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Overall Leakage Score</span>
            <Gauge className="w-4 h-4 text-rose-400" />
          </div>
          <div className={`text-2xl font-bold mb-1 ${assessments.length > 0 ? getScoreColor(summary?.average_score || 0) : 'text-slate-400'}`}>
            {assessments.length > 0 && summary?.average_score !== undefined
              ? summary.average_score.toFixed(1)
              : '—'}
            {assessments.length > 0 && <span className="text-xs text-slate-500 font-normal"> / 100</span>}
          </div>
          <div className="text-xs text-slate-400">
            Peak Risk:{' '}
            <span className={`font-semibold ${assessments.length === 0 ? 'text-slate-500' : summary?.highest_risk_level === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'}`}>
              {assessments.length > 0 ? (summary?.highest_risk_level || 'LOW') : '—'}
            </span>
          </div>
        </div>

        {/* Vector 1: SPI Leakage */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-semibold text-slate-300">1. SPI Leakage</span>
            <Lock className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-xl font-bold text-slate-100 mb-1">
            {assessments.length > 0
              ? (assessments.reduce((acc, a) => acc + a.spi_leakage_score, 0) / assessments.length).toFixed(1)
              : '—'}
            {assessments.length > 0 && <span className="text-xs text-slate-500 font-normal"> / 100</span>}
          </div>
          <div className="text-xs text-slate-400">Static SPI linkability</div>
        </div>

        {/* Vector 2: Sequence Monotonicity */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-semibold text-slate-300">2. Sequence Monot.</span>
            <FileCode className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-xl font-bold text-slate-100 mb-1">
            {assessments.length > 0
              ? (assessments.reduce((acc, a) => acc + a.sequence_leakage_score, 0) / assessments.length).toFixed(1)
              : '—'}
            {assessments.length > 0 && <span className="text-xs text-slate-500 font-normal"> / 100</span>}
          </div>
          <div className="text-xs text-slate-400">Cleartext seq predictability</div>
        </div>

        {/* Vector 3: Packet Length / TFC */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-semibold text-slate-300">3. Length / TFC</span>
            <Layers className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-slate-100 mb-1">
            {assessments.length > 0
              ? (assessments.reduce((acc, a) => acc + a.packet_length_leakage_score, 0) / assessments.length).toFixed(1)
              : '—'}
            {assessments.length > 0 && <span className="text-xs text-slate-500 font-normal"> / 100</span>}
          </div>
          <div className="text-xs text-slate-400">RFC 4303 TFC padding check</div>
        </div>

        {/* Vector 4: Timing & Vector 5: Topology */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-semibold text-slate-300">4-5. Timing &amp; Topo</span>
            <Network className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-xl font-bold text-slate-100 mb-1">
            {assessments.length > 0
              ? (
                  (assessments.reduce((acc, a) => acc + a.timing_leakage_score + a.topology_leakage_score, 0) /
                    (assessments.length * 2))
                ).toFixed(1)
              : '—'}
            {assessments.length > 0 && <span className="text-xs text-slate-500 font-normal"> / 100</span>}
          </div>
          <div className="text-xs text-slate-400">Cadence &amp; Transport Mode</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by session ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((r) => (
            <button
              key={r}
              onClick={() => setSelectedRisk(r)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                selectedRisk === r
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 bg-slate-800/40 border border-transparent'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Exposure Assessment Table */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">Session</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Overall Score</th>
                <th className="px-4 py-3">5 Leakage Vectors</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {loading && assessments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-slate-500">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-rose-400" />
                    Loading metadata exposure telemetry...
                  </td>
                </tr>
              ) : assessments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-slate-400">
                    <Info className="w-6 h-6 mx-auto mb-2 text-slate-400" />
                    <p className="text-sm font-semibold text-slate-200">No capture/session data available</p>
                    <p className="text-xs text-slate-500 mt-1">Please load a PCAP capture in Packet Analysis and discover sessions to evaluate metadata exposure.</p>
                  </td>
                </tr>
              ) : filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-slate-500">
                    <Info className="w-6 h-6 mx-auto mb-2 text-slate-400" />
                    No session metadata assessments match the current filters.
                  </td>
                </tr>
              ) : (
                filteredItems.map((item) => (
                  <tr
                    key={item.id}
                    className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                    onClick={() => setSelectedItem(item)}
                  >
                    <td className="px-4 py-3 font-mono text-slate-300 font-semibold">
                      {item.session_id || 'Session'}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${getRiskBadge(
                          item.risk_level
                        )}`}
                      >
                        {item.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-mono font-bold text-sm ${getScoreColor(item.overall_score)}`}>
                        {item.overall_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3 text-[11px] font-mono">
                        <span title="SPI Leakage">
                          SPI: <span className="text-slate-200">{item.spi_leakage_score.toFixed(0)}</span>
                        </span>
                        <span title="Sequence Monotonicity">
                          Seq: <span className="text-slate-200">{item.sequence_leakage_score.toFixed(0)}</span>
                        </span>
                        <span title="Packet Length / TFC">
                          Len: <span className="text-slate-200">{item.packet_length_leakage_score.toFixed(0)}</span>
                        </span>
                        <span title="Timing Cadence">
                          Time: <span className="text-slate-200">{item.timing_leakage_score.toFixed(0)}</span>
                        </span>
                        <span title="Topology Exposure">
                          Topo: <span className="text-slate-200">{item.topology_leakage_score.toFixed(0)}</span>
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-slate-300">
                        {item.findings?.length || 0} findings recorded
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedItem(item);
                        }}
                        className="px-2.5 py-1 rounded text-xs font-medium text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 transition-all flex items-center gap-1 ml-auto"
                      >
                        Inspect
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Findings & Remediation Drawer */}
      {selectedItem && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-6 h-6 text-rose-400" />
                <div>
                  <h3 className="text-lg font-bold text-white">Metadata Exposure Audit</h3>
                  <p className="text-xs text-slate-400 font-mono">{selectedItem.session_id}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedItem(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Score Verdict */}
            <div className="p-4 rounded-xl border border-rose-500/30 bg-gradient-to-br from-rose-950/40 to-slate-900">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs uppercase font-bold text-slate-300">Side-Channel Vulnerability</span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getRiskBadge(selectedItem.risk_level)}`}>
                  {selectedItem.risk_level} RISK
                </span>
              </div>
              <div className="text-3xl font-bold text-white mb-2">
                {selectedItem.overall_score.toFixed(1)} / 100
              </div>
              <p className="text-xs text-slate-300">
                Measures the degree to which an external passive adversary can infer payload semantics, endpoints, or timing
                patterns from unpadded or unmasked ESP packet structures.
              </p>
            </div>

            {/* Vector Breakdown Progress */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                5-Vector Exposure Breakdown
              </h4>
              {[
                { name: 'Vector 1: SPI Leakage (Linkability)', val: selectedItem.spi_leakage_score },
                { name: 'Vector 2: Sequence Monotonicity', val: selectedItem.sequence_leakage_score },
                { name: 'Vector 3: Packet Length / Missing TFC', val: selectedItem.packet_length_leakage_score },
                { name: 'Vector 4: Timing Cadence & Burstiness', val: selectedItem.timing_leakage_score },
                { name: 'Vector 5: Network Topology Exposure', val: selectedItem.topology_leakage_score },
              ].map((v) => (
                <div key={v.name} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-300">{v.name}</span>
                    <span className="font-mono text-slate-400">{v.val.toFixed(1)}/100</span>
                  </div>
                  <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      style={{ width: `${v.val}%` }}
                      className={`h-full ${
                        v.val >= 75 ? 'bg-rose-500' : v.val >= 50 ? 'bg-amber-500' : v.val >= 25 ? 'bg-yellow-500' : 'bg-emerald-500'
                      }`}
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* Empirical Findings */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Empirical Exposure Findings
              </h4>
              <div className="space-y-2">
                {selectedItem.findings?.map((f: any, idx: number) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800/80">
                    <div className="text-xs font-semibold text-rose-300 mb-1">{f.vector || f.evidence_key || 'Leakage Finding'}</div>
                    <p className="text-xs text-slate-300">{f.description}</p>
                    {f.evidence && (
                      <div className="mt-1 text-[11px] font-mono text-slate-400 bg-slate-950 p-1.5 rounded border border-slate-800">
                        Evidence: {String(f.evidence)}
                      </div>
                    )}
                  </div>
                ))}
                {(!selectedItem.findings || selectedItem.findings.length === 0) && (
                  <p className="text-xs text-slate-500">No active side-channel leakage anomalies flagged.</p>
                )}
              </div>
            </div>

            {/* Actionable Recommendations */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Actionable Remediation Recommendations
              </h4>
              <div className="space-y-2">
                {selectedItem.recommendations?.map((rec: string, idx: number) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                    <p className="text-xs text-slate-300">{rec}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
