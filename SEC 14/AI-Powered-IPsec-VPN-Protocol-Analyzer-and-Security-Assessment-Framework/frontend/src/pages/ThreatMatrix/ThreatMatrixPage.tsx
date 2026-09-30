import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Search,
  AlertTriangle,
  Info,
  ChevronRight,
  CheckCircle2,
  X,
  Grid,
  Award,
} from 'lucide-react';
import { threatMatrixService } from '@/services/threatMatrixService';
import { PipelineProgressionRibbon } from '@/components/common/PipelineProgressionRibbon';
import type {
  ThreatMatrixItem,
  ThreatMatrixSummary,
  ThreatSeverity,
  ThreatStatus,
} from '@/types';

export const ThreatMatrixPage: React.FC = () => {
  const [threats, setThreats] = useState<ThreatMatrixItem[]>([]);
  const [summary, setSummary] = useState<ThreatMatrixSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedThreat, setSelectedThreat] = useState<ThreatMatrixItem | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      setError(null);
      const [sumRes, threatsRes] = await Promise.all([
        threatMatrixService.getGlobalSummary().catch(() => null),
        threatMatrixService.getCaptureThreats('default').catch(() => []),
      ]);

      if (sumRes) {
        setSummary(sumRes);
      }
      setThreats(Array.isArray(threatsRes) ? threatsRes : []);
    } catch (err: any) {
      setError(err.message || 'Failed to load threat matrix telemetry');
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
      const updated = await threatMatrixService.evaluateCapture('default');
      setThreats(updated);
      const newSum = await threatMatrixService.getGlobalSummary();
      setSummary(newSum);
    } catch (err: any) {
      setError(err.message || 'Failed to evaluate threat matrix');
    } finally {
      setEvaluating(false);
    }
  };

  const filteredThreats = useMemo(() => {
    return (Array.isArray(threats) ? threats : []).filter((t) => {
      const matchesSearch =
        !searchQuery ||
        t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.matrix_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (t.mitre_technique_id && t.mitre_technique_id.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (t.nist_control && t.nist_control.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesSeverity = selectedSeverity === 'ALL' || t.severity === selectedSeverity;
      const matchesStatus = selectedStatus === 'ALL' || t.status === selectedStatus;
      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [threats, searchQuery, selectedSeverity, selectedStatus]);

  const getSeverityBadge = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    }
  };

  const getStatusBadge = (st: ThreatStatus) => {
    switch (st) {
      case 'DETECTED':
      case 'VULNERABLE':
        return {
          badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          dot: 'bg-rose-500',
          text: 'DETECTED',
        };
      case 'MITIGATED':
        return {
          badge: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
          dot: 'bg-blue-500',
          text: 'MITIGATED',
        };
      default:
        return {
          badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          dot: 'bg-emerald-500',
          text: 'NOT DETECTED',
        };
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Observatory Pipeline Navigation Ribbon */}
      <PipelineProgressionRibbon />

      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Layer 09 &middot; Threat Intelligence Matrix
            </span>
            <span className="text-xs text-slate-400">MITRE ATT&amp;CK &amp; NIST SP 800-77 Rev. 1 Mapping</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <Grid className="w-7 h-7 text-indigo-400" />
            Standalone IPsec Threat Matrix
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            10 cataloged IPsec vulnerabilities and side-channel threats mapped to authoritative standards
            (MITRE ATT&amp;CK Enterprise, NIST SP 800-77 Rev. 1, and IETF RFCs) with deterministic evidence evaluation.
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
            className="px-4 py-2 text-xs font-semibold text-white bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 rounded-lg shadow-lg shadow-indigo-900/20 flex items-center gap-2 transition-all disabled:opacity-50"
          >
            <ShieldAlert className={`w-4 h-4 ${evaluating ? 'animate-pulse' : ''}`} />
            {evaluating ? 'Evaluating Matrix...' : 'Evaluate Threat Matrix'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Compliance Score */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Framework Compliance</span>
            <Award className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.compliance_score ? `${summary.compliance_score.toFixed(1)}%` : '100.0%'}
          </div>
          <div className="text-xs text-slate-400">NIST SP 800-77 &amp; MITRE standard</div>
        </div>

        {/* Total Cataloged */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Evaluated Threat Vectors</span>
            <Grid className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.total_threats ?? threats.length}
          </div>
          <div className="text-xs text-slate-400">TM-IPSEC-001 through 010</div>
        </div>

        {/* Active Detections */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Active Detections</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div
            className={`text-2xl font-bold mb-1 ${
              (summary?.detected_count ?? 0) > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {summary?.detected_count ?? threats.filter((t) => t.status === 'DETECTED' || t.status === 'VULNERABLE').length}
          </div>
          <div className="text-xs text-slate-400">Threats actively matched in capture</div>
        </div>

        {/* Mitigated / Safe */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Mitigated / Safe</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 mb-1">
            {threats.filter((t) => t.status === 'NOT_APPLICABLE' || t.status === 'MITIGATED').length}
          </div>
          <div className="text-xs text-slate-400">Clean controls or not triggered</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by threat, MITRE ID, or NIST control..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <div className="flex items-center gap-1.5 overflow-x-auto">
            <span className="text-xs text-slate-400 font-medium">Status:</span>
            {['ALL', 'DETECTED', 'MITIGATED', 'NOT_APPLICABLE'].map((st) => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all ${
                  selectedStatus === st
                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-800/40 border border-transparent'
                }`}
              >
                {st === 'NOT_APPLICABLE' ? 'CLEAN' : st}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto ml-0 sm:ml-2">
            <span className="text-xs text-slate-400 font-medium">Severity:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all ${
                  selectedSeverity === sev
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-800/40 border border-transparent'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Threat Matrix Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading && threats.length === 0 ? (
          <div className="col-span-2 p-12 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-indigo-400" />
            Loading threat matrix framework...
          </div>
        ) : filteredThreats.length === 0 ? (
          <div className="col-span-2 p-12 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
            <Info className="w-6 h-6 mx-auto mb-2 text-slate-400" />
            No threats match the current filters.
          </div>
        ) : (
          filteredThreats.map((t) => {
            const stBadge = getStatusBadge(t.status);
            return (
              <div
                key={t.matrix_id}
                className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer group flex flex-col justify-between"
                onClick={() => setSelectedThreat(t)}
              >
                <div>
                  {/* Top Bar: Matrix ID, Severity, Status */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                        {t.matrix_id}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(t.severity)}`}>
                        {t.severity}
                      </span>
                    </div>

                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${stBadge.badge}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${stBadge.dot}`} />
                      {stBadge.text}
                    </span>
                  </div>

                  {/* Threat Title */}
                  <h3 className="text-sm font-bold text-slate-100 group-hover:text-indigo-300 transition-colors mb-2">
                    {t.name}
                  </h3>

                  {/* Framework Mapping Tags */}
                  <div className="flex flex-wrap items-center gap-2 mb-3 text-[11px]">
                    {t.mitre_technique_id && (
                      <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60">
                        <span className="text-slate-400 font-semibold">MITRE:</span> {t.mitre_technique_id}
                      </span>
                    )}
                    {t.nist_control && (
                      <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60">
                        <span className="text-slate-400 font-semibold">NIST:</span> {t.nist_control}
                      </span>
                    )}
                    {t.rfc_reference && (
                      <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60">
                        <span className="text-slate-400 font-semibold">RFC:</span> {t.rfc_reference}
                      </span>
                    )}
                  </div>

                  {/* Evidence / Summary snippet */}
                  {t.evidence && t.evidence.length > 0 ? (
                    <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-rose-300 mb-3">
                      <span className="font-semibold text-rose-400">Observed Evidence:</span> {t.evidence[0]}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-400 mb-3 line-clamp-2">
                      {t.remediation}
                    </p>
                  )}
                </div>

                {/* Card Footer */}
                <div className="flex items-center justify-between border-t border-slate-800/60 pt-3 mt-2 text-xs text-slate-400">
                  <span className="capitalize">{t.category.toLowerCase().replace('_', ' ')}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedThreat(t);
                    }}
                    className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
                  >
                    View Dossier
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Threat Detail Dossier Drawer */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <Grid className="w-6 h-6 text-indigo-400" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                      {selectedThreat.matrix_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(selectedThreat.severity)}`}>
                      {selectedThreat.severity}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1">{selectedThreat.name}</h3>
                </div>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Status Banner */}
            <div
              className={`p-4 rounded-xl border ${
                selectedThreat.status === 'DETECTED' || selectedThreat.status === 'VULNERABLE'
                  ? 'bg-rose-950/30 border-rose-500/30'
                  : 'bg-emerald-950/30 border-emerald-500/30'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs uppercase font-bold text-slate-300">Detection Status</span>
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getStatusBadge(
                    selectedThreat.status
                  ).badge}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${getStatusBadge(selectedThreat.status).dot}`} />
                  {getStatusBadge(selectedThreat.status).text}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-2">
                Evaluated against deterministic session and packet attributes observed across the IPsec tunnel.
              </p>
            </div>

            {/* Standards Traceability */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Authoritative Standards Mapping
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-slate-400 text-[11px] mb-1 font-semibold">MITRE ATT&amp;CK Enterprise</div>
                  <div className="font-mono text-indigo-300 font-bold">
                    {selectedThreat.mitre_technique_id || 'N/A'}
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Tactic: {selectedThreat.mitre_tactic || 'Credential Access / Discovery'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-slate-400 text-[11px] mb-1 font-semibold">NIST SP 800-77 Rev. 1</div>
                  <div className="font-mono text-indigo-300 font-bold">
                    {selectedThreat.nist_control || 'N/A'}
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Ref: {selectedThreat.rfc_reference || 'N/A'}
                  </div>
                </div>
              </div>
            </div>

            {/* Empirical Evidence */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Empirical Evaluation Evidence
              </h4>
              <div className="space-y-2">
                {selectedThreat.evidence?.map((ev, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 text-xs text-slate-300 font-mono">
                    {ev}
                  </div>
                ))}
                {(!selectedThreat.evidence || selectedThreat.evidence.length === 0) && (
                  <p className="text-xs text-slate-500">No vulnerable empirical indicators detected for this threat.</p>
                )}
              </div>
            </div>

            {/* Actionable Remediation */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Prescriptive Remediation &amp; Mitigation
              </h4>
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800/80 flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-slate-200 leading-relaxed">{selectedThreat.remediation}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
