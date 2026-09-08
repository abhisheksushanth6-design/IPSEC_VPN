import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  HelpCircle,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { PageHeader } from '@/components/ui';
import { riskService } from '@/services/riskService';
import type { PolicyDecision, RiskAssessmentResponse, RiskLevel, RiskSummaryResponse } from '@/types/risk';
import { cn } from '@/utils/cn';

function getLevelBadgeStyle(level: RiskLevel): string {
  switch (level) {
    case 'CRITICAL':
      return 'border-rose-500/40 bg-rose-500/15 text-rose-400';
    case 'HIGH':
      return 'border-orange-500/40 bg-orange-500/15 text-orange-400';
    case 'MEDIUM':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-400';
    case 'LOW':
    default:
      return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-400';
  }
}

function getDecisionBadgeStyle(decision: PolicyDecision): string {
  switch (decision) {
    case 'TERMINATE':
      return 'border-rose-500/50 bg-rose-600/20 text-rose-300';
    case 'RESTRICT':
      return 'border-orange-500/50 bg-orange-600/20 text-orange-300';
    case 'INSPECT':
      return 'border-amber-500/50 bg-amber-600/20 text-amber-300';
    case 'ALLOW':
    default:
      return 'border-emerald-500/50 bg-emerald-600/20 text-emerald-300';
  }
}

function getDecisionIcon(decision: PolicyDecision) {
  switch (decision) {
    case 'TERMINATE':
      return <ShieldX className="h-3.5 w-3.5 text-rose-400" />;
    case 'RESTRICT':
      return <ShieldAlert className="h-3.5 w-3.5 text-orange-400" />;
    case 'INSPECT':
      return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />;
    case 'ALLOW':
    default:
      return <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />;
  }
}

export function RiskAssessmentPage() {
  const [summary, setSummary] = useState<RiskSummaryResponse | null>(null);
  const [assessments, setAssessments] = useState<RiskAssessmentResponse[]>([]);
  const [selectedAssessment, setSelectedAssessment] = useState<RiskAssessmentResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [evaluatingAll, setEvaluatingAll] = useState<boolean>(false);
  const [evaluatingSessionId, setEvaluatingSessionId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedLevel, setSelectedLevel] = useState<string>('ALL');
  const [selectedDecision, setSelectedDecision] = useState<string>('ALL');

  const loadData = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      setErrorMessage(null);

      const [sum, list] = await Promise.all([
        riskService.getSummary(),
        riskService.getAssessments(100),
      ]);

      setSummary(sum);
      setAssessments(Array.isArray(list) ? list : []);

      // Auto-select latest assessment if none selected
      if (Array.isArray(list) && list.length > 0) {
        setSelectedAssessment((prev) => (prev ? list.find((a) => a.id === prev.id) || list[0] || null : list[0] || null));
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to load risk engine assessment data.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadData(true);
  };

  const handleEvaluateAll = async () => {
    try {
      setEvaluatingAll(true);
      setErrorMessage(null);
      await riskService.evaluateAll();
      await loadData(true);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to run batch risk evaluation.');
    } finally {
      setEvaluatingAll(false);
    }
  };

  const handleEvaluateSingle = async (sessionId: string) => {
    try {
      setEvaluatingSessionId(sessionId);
      const updated = await riskService.evaluateSession(sessionId);
      setAssessments((prev) => [updated, ...(Array.isArray(prev) ? prev.filter((a) => a.session_id !== sessionId) : [])]);
      if (selectedAssessment?.session_id === sessionId) {
        setSelectedAssessment(updated);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || `Failed to evaluate session ${sessionId}.`);
    } finally {
      setEvaluatingSessionId(null);
    }
  };

  const filteredAssessments = useMemo(() => {
    if (!Array.isArray(assessments)) return [];
    return assessments.filter((item) => {
      if (searchQuery && !item.session_id.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false;
      }
      if (selectedLevel !== 'ALL' && item.risk_level !== selectedLevel) {
        return false;
      }
      if (selectedDecision !== 'ALL' && item.decision !== selectedDecision) {
        return false;
      }
      return true;
    });
  }, [assessments, searchQuery, selectedLevel, selectedDecision]);

  return (
    <div className="space-y-6">
      {/* 1. Page Header */}
      <PageHeader
        title="Risk Assessment & Decision Engine"
        description="Layer 10: Deterministic composite risk evaluation across vulnerabilities, AI anomalies, drift, and SA lifecycle."
        breadcrumbs={[{ label: 'Security Analysis' }, { label: 'Risk Assessment' }]}
        status={summary?.state === 'OPERATIONAL' ? 'OPERATIONAL' : 'READY'}
        statusLabel={summary?.state === 'OPERATIONAL' ? 'Layer 10: OPERATIONAL' : 'Layer 10: READY'}
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleRefresh}
              disabled={refreshing || loading}
              className="inline-flex items-center gap-1.5 rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-primary shadow-sm hover:bg-elevated hover:text-info disabled:opacity-50"
            >
              <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} />
              Refresh
            </button>
            <button
              type="button"
              onClick={handleEvaluateAll}
              disabled={evaluatingAll || loading}
              className="inline-flex items-center gap-1.5 rounded border border-info/40 bg-info/10 px-3 py-1.5 text-xs font-medium text-info shadow-sm hover:bg-info/20 disabled:opacity-50"
            >
              <Play className={cn('h-3.5 w-3.5', evaluatingAll && 'animate-spin')} />
              {evaluatingAll ? 'Evaluating All Sessions…' : 'Evaluate All Sessions'}
            </button>
          </div>
        }
      />

      {/* Error Alert */}
      {errorMessage && (
        <div className="flex items-center justify-between rounded border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setErrorMessage(null)}
            className="rounded p-1 hover:bg-rose-500/20"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* 2. KPI Summary Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Card 1: Overall Posture Risk */}
        <div className="rounded border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Overall Risk Posture</span>
            <Shield className="h-4 w-4 text-info" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-primary">
              {summary?.overall_risk_score != null ? summary.overall_risk_score.toFixed(1) : '—'}
            </span>
            <span className="text-xs text-muted">/ 100</span>
          </div>
          <div className="mt-2 flex items-center gap-2">
            {summary?.overall_risk_level && (
              <span className={cn('rounded border px-2 py-0.5 text-[10px] font-bold uppercase', getLevelBadgeStyle(summary.overall_risk_level))}>
                {summary.overall_risk_level}
              </span>
            )}
            {summary?.decision && (
              <span className={cn('inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-bold uppercase', getDecisionBadgeStyle(summary.decision))}>
                {getDecisionIcon(summary.decision)}
                {summary.decision}
              </span>
            )}
          </div>
        </div>

        {/* Card 2: Assessed Sessions */}
        <div className="rounded border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Assessed Sessions</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-primary">
              {summary?.assessed_sessions_count ?? 0}
            </span>
            <span className="text-xs text-muted">
              / {summary?.total_sessions_count ?? 0} discovered
            </span>
          </div>
          <div className="mt-2 text-xs text-muted">
            {summary?.assessed_sessions_count === summary?.total_sessions_count && (summary?.total_sessions_count ?? 0) > 0
              ? '100% telemetry coverage'
              : 'Telemetry ingestion active'}
          </div>
        </div>

        {/* Card 3: Severity Breakdown */}
        <div className="rounded border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Risk Severity Bands</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs font-semibold">
            <span className="rounded bg-rose-500/20 px-2 py-0.5 text-rose-400">
              {summary?.critical_risk_count ?? 0} Crit
            </span>
            <span className="rounded bg-orange-500/20 px-2 py-0.5 text-orange-400">
              {summary?.high_risk_count ?? 0} High
            </span>
            <span className="rounded bg-amber-500/20 px-2 py-0.5 text-amber-400">
              {summary?.medium_risk_count ?? 0} Med
            </span>
            <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-emerald-400">
              {summary?.low_risk_count ?? 0} Low
            </span>
          </div>
          <div className="mt-2 text-xs text-muted">
            Aggregated across all evaluated VPN sessions
          </div>
        </div>

        {/* Card 4: Quality & Confidence */}
        <div className="rounded border border-border bg-surface p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Telemetry Quality</span>
            <HelpCircle className="h-4 w-4 text-secondary" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-primary">
              {summary?.latest_assessment ? `${Math.round(summary.latest_assessment.confidence_score * 100)}%` : '—'}
            </span>
            <span className="text-xs text-muted">Confidence</span>
          </div>
          <div className="mt-2 text-xs text-muted">
            Data Quality:{' '}
            <strong className="text-primary">
              {summary?.data_quality ?? 'READY'}
            </strong>
          </div>
        </div>
      </div>

      {/* 3. Main Workspace: Table + Detail Inspector Drawer */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Left 2 Cols: Table & Filter Controls */}
        <div className="space-y-4 xl:col-span-2">
          {/* Filters Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-border bg-surface p-3 text-xs">
            <div className="relative min-w-[200px] flex-1">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by session ID…"
                className="w-full rounded border border-border bg-elevated/50 py-1.5 pl-8 pr-3 text-xs text-primary placeholder:text-muted focus:border-info focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-2">
              <label className="text-muted">Level:</label>
              <select
                value={selectedLevel}
                onChange={(e) => setSelectedLevel(e.target.value)}
                className="rounded border border-border bg-elevated px-2 py-1 text-xs text-primary focus:border-info focus:outline-none"
              >
                <option value="ALL">All Levels</option>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>

              <label className="ml-2 text-muted">Decision:</label>
              <select
                value={selectedDecision}
                onChange={(e) => setSelectedDecision(e.target.value)}
                className="rounded border border-border bg-elevated px-2 py-1 text-xs text-primary focus:border-info focus:outline-none"
              >
                <option value="ALL">All Decisions</option>
                <option value="ALLOW">Allow</option>
                <option value="INSPECT">Inspect</option>
                <option value="RESTRICT">Restrict</option>
                <option value="TERMINATE">Terminate</option>
              </select>
            </div>
          </div>

          {/* Assessments Table */}
          <div className="overflow-hidden rounded border border-border bg-surface shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border bg-elevated/40 text-[11px] font-semibold text-muted uppercase tracking-wider">
                  <tr>
                    <th className="px-4 py-3">Session ID</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Level</th>
                    <th className="px-4 py-3">Policy Decision</th>
                    <th className="px-4 py-3">Breakdown (V / M / D / S)</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {loading ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-muted">
                        <RefreshCw className="mx-auto mb-2 h-5 w-5 animate-spin text-info" />
                        Loading risk evaluations…
                      </td>
                    </tr>
                  ) : filteredAssessments.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-muted">
                        No evaluated sessions found. Click &quot;Evaluate All Sessions&quot; to run assessment.
                      </td>
                    </tr>
                  ) : (
                    filteredAssessments.map((row) => {
                      const isSelected = selectedAssessment?.id === row.id;
                      const isEvaluating = evaluatingSessionId === row.session_id;

                      return (
                        <tr
                          key={row.id}
                          onClick={() => setSelectedAssessment(row)}
                          className={cn(
                            'cursor-pointer transition-colors hover:bg-elevated/50',
                            isSelected && 'bg-elevated/80'
                          )}
                        >
                          <td className="px-4 py-3 font-mono font-medium text-primary">
                            <div className="flex items-center gap-1.5">
                              <span>{row.session_id}</span>
                              <Link
                                to={`/sessions?session=${encodeURIComponent(row.session_id)}`}
                                onClick={(e) => e.stopPropagation()}
                                title="Open in IPsec Sessions"
                                className="text-muted hover:text-info"
                              >
                                <ExternalLink className="h-3 w-3" />
                              </Link>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-bold text-primary">
                                {row.risk_score.toFixed(1)}
                              </span>
                              <div className="h-1.5 w-16 overflow-hidden rounded-full bg-border">
                                <div
                                  className={cn(
                                    'h-full',
                                    row.risk_level === 'CRITICAL' && 'bg-rose-500',
                                    row.risk_level === 'HIGH' && 'bg-orange-500',
                                    row.risk_level === 'MEDIUM' && 'bg-amber-500',
                                    row.risk_level === 'LOW' && 'bg-emerald-500'
                                  )}
                                  style={{ width: `${Math.min(100, Math.max(5, row.risk_score))}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span className={cn('rounded border px-2 py-0.5 text-[10px] font-bold uppercase', getLevelBadgeStyle(row.risk_level))}>
                              {row.risk_level}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={cn('inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-bold uppercase', getDecisionBadgeStyle(row.decision))}>
                              {getDecisionIcon(row.decision)}
                              {row.decision}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-[11px] text-muted">
                            <span title="Vulnerability Score (max 50)" className="text-primary font-medium">{row.breakdown.vulnerability_score.toFixed(0)}</span>
                            {' / '}
                            <span title="ML Anomaly Score (max 30)">{row.breakdown.ml_score.toFixed(0)}</span>
                            {' / '}
                            <span title="Drift Score (max 12)">{row.breakdown.drift_score.toFixed(0)}</span>
                            {' / '}
                            <span title="SA State Score (max 8)">{row.breakdown.state_score.toFixed(0)}</span>
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleEvaluateSingle(row.session_id);
                              }}
                              disabled={isEvaluating}
                              className="rounded border border-border bg-surface px-2 py-1 text-[11px] text-muted hover:bg-elevated hover:text-primary disabled:opacity-50"
                            >
                              <RefreshCw className={cn('h-3 w-3 inline mr-1', isEvaluating && 'animate-spin')} />
                              {isEvaluating ? '…' : 'Re-evaluate'}
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Selected Assessment Details Inspector */}
        <div className="space-y-4">
          {selectedAssessment ? (
            <div className="rounded border border-border bg-surface p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div>
                  <div className="text-xs text-muted">Detailed Inspection</div>
                  <div className="font-mono text-sm font-bold text-primary">
                    {selectedAssessment.session_id}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xl font-bold text-primary">
                    {selectedAssessment.risk_score.toFixed(1)} <span className="text-xs text-muted">/ 100</span>
                  </div>
                  <span className={cn('rounded border px-2 py-0.5 text-[10px] font-bold uppercase', getLevelBadgeStyle(selectedAssessment.risk_level))}>
                    {selectedAssessment.risk_level}
                  </span>
                </div>
              </div>

              {/* Policy Decision & Confidence */}
              <div className="flex items-center justify-between rounded bg-elevated/40 p-2.5 border border-border/60">
                <div className="flex items-center gap-1.5">
                  {getDecisionIcon(selectedAssessment.decision)}
                  <span className="font-semibold text-primary">{selectedAssessment.decision} POLICY</span>
                </div>
                <div className="text-xs text-muted">
                  Confidence: <strong className="text-primary">{Math.round(selectedAssessment.confidence_score * 100)}%</strong>
                </div>
              </div>

              {/* Sub-Score Breakdown */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-primary">Sub-Score Contributions</div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded border border-border/80 bg-elevated/20 p-2">
                    <div className="text-[10px] text-muted">Vulnerabilities (L09)</div>
                    <div className="text-sm font-bold text-primary">
                      {selectedAssessment.breakdown.vulnerability_score.toFixed(1)} <span className="text-[10px] text-muted">/ 50</span>
                    </div>
                  </div>
                  <div className="rounded border border-border/80 bg-elevated/20 p-2">
                    <div className="text-[10px] text-muted">ML Anomaly (L08)</div>
                    <div className="text-sm font-bold text-primary">
                      {selectedAssessment.breakdown.ml_score.toFixed(1)} <span className="text-[10px] text-muted">/ 30</span>
                    </div>
                  </div>
                  <div className="rounded border border-border/80 bg-elevated/20 p-2">
                    <div className="text-[10px] text-muted">Security Drift (L07)</div>
                    <div className="text-sm font-bold text-primary">
                      {selectedAssessment.breakdown.drift_score.toFixed(1)} <span className="text-[10px] text-muted">/ 12</span>
                    </div>
                  </div>
                  <div className="rounded border border-border/80 bg-elevated/20 p-2">
                    <div className="text-[10px] text-muted">SA Lifecycle (L04)</div>
                    <div className="text-sm font-bold text-primary">
                      {selectedAssessment.breakdown.state_score.toFixed(1)} <span className="text-[10px] text-muted">/ 8</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Telemetry Availability */}
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-primary">Telemetry Signals</div>
                <div className="flex flex-wrap gap-1.5">
                  {selectedAssessment.available_signals.map((sig) => (
                    <span key={sig} className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-400 border border-emerald-500/30">
                      <CheckCircle2 className="h-3 w-3" />
                      {sig.replace(/_/g, ' ')}
                    </span>
                  ))}
                  {selectedAssessment.unavailable_signals.map((sig) => (
                    <span key={sig} className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-400 border border-amber-500/30">
                      <HelpCircle className="h-3 w-3" />
                      {sig.replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>
              </div>

              {/* Contributing Factors */}
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-primary">Contributing Risk Signals</div>
                {selectedAssessment.contributing_signals.length === 0 ? (
                  <p className="text-xs text-muted italic">No negative risk factors detected.</p>
                ) : (
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {selectedAssessment.contributing_signals.map((sig, idx) => (
                      <div key={idx} className="rounded bg-elevated/30 p-2 border border-border/50 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] text-info uppercase font-bold">{sig.source}</span>
                          <span className="font-mono text-rose-400 font-bold">+{sig.contribution.toFixed(1)}</span>
                        </div>
                        <div className="text-primary mt-0.5">{sig.reason}</div>
                        {sig.evidence_reference && (
                          <div className="text-[10px] font-mono text-muted mt-0.5">
                            Ref: {sig.evidence_reference}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Remediations */}
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-primary">Recommended Actions</div>
                <ul className="space-y-1 text-xs text-muted">
                  {selectedAssessment.recommended_actions.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-info mt-0.5" />
                      <span className="text-secondary">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Evaluated timestamp */}
              <div className="text-[11px] text-muted border-t border-border pt-2">
                Evaluated: {new Date(selectedAssessment.evaluated_at).toLocaleString()}
              </div>
            </div>
          ) : (
            <div className="rounded border border-border bg-surface p-8 text-center text-xs text-muted">
              Select a session from the table to view detailed risk decomposition and evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
