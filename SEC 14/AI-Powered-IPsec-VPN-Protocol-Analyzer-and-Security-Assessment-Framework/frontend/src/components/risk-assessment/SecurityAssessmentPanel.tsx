import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Search } from 'lucide-react';
import { securityAssessmentService } from '@/services';
import type { RiskAssessmentReport } from '@/types';

export function SecurityAssessmentPanel() {
  const [report, setReport] = useState<RiskAssessmentReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await securityAssessmentService.getAssessment();
      setReport(res);
    } catch {
      setError('Security assessment data not yet available or engine offline.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const findings = Array.isArray(report?.findings) ? report.findings : [];

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
      if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          f.title?.toLowerCase().includes(q) ||
          f.finding_id?.toLowerCase().includes(q) ||
          f.rule_id?.toLowerCase().includes(q) ||
          f.explanation?.toLowerCase().includes(q) ||
          (Array.isArray(f.cve_references) && f.cve_references.some((cve) => cve?.toLowerCase().includes(q)))
        );
      }
      return true;
    });
  }, [findings, selectedSeverity, selectedCategory, searchQuery]);

  if (loading && !report) {
    return (
      <div className="rounded border border-border bg-surface p-8 text-center text-xs text-secondary">
        <RefreshCw className="mx-auto mb-2 h-6 w-6 animate-spin text-info" />
        Evaluating Layer 08 Security Assessment rules & risk metrics…
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex items-center justify-between rounded border border-border bg-surface p-4 text-xs text-secondary">
        <span>{error || 'No assessment report generated. Upload an IPsec capture first.'}</span>
        <button
          type="button"
          onClick={() => void loadData()}
          className="inline-flex items-center gap-1 rounded border border-border px-2.5 py-1 text-primary hover:border-info"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Retry
        </button>
      </div>
    );
  }

  const overallScore = report.overall_risk_score ?? 0;
  const riskLevel = report.risk_level ?? 'LOW';
  const bySeverity = report.findings_by_severity ?? {};

  const getScoreColor = (score: number) => {
    if (score >= 70) return 'text-danger border-danger/40 bg-danger/10';
    if (score >= 50) return 'text-warning border-warning/40 bg-warning/10';
    if (score >= 25) return 'text-amber-400 border-amber-500/40 bg-amber-500/10';
    return 'text-success border-success/40 bg-success/10';
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-danger/20 text-danger border-danger/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-warning/20 text-warning border-warning/40';
      case 'LOW':
        return 'bg-info/20 text-info border-info/40';
      default:
        return 'bg-muted/20 text-muted border-border';
    }
  };

  return (
    <div className="space-y-5">
      {/* 1. Posture & Risk Score KPI Header */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {/* Risk Score Gauge */}
        <div className="rounded border border-border bg-surface p-4 sm:col-span-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Overall IPsec Risk Score</span>
            <span className={`rounded border px-2 py-0.5 text-2xs font-bold ${getScoreColor(overallScore)}`}>
              {riskLevel}
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold text-primary">{overallScore.toFixed(1)}</span>
            <span className="text-xs text-muted">/ 100.0</span>
          </div>
          <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-surface-elevated">
            <div
              className={`h-full transition-all duration-500 ${
                overallScore >= 70
                  ? 'bg-danger'
                  : overallScore >= 50
                    ? 'bg-warning'
                    : 'bg-success'
              }`}
              style={{ width: `${Math.min(100, overallScore)}%` }}
            />
          </div>
          <p className="mt-2 text-2xs text-muted">
            Evaluated {report.evaluated_sessions_count ?? 0} session(s), {report.evaluated_tunnels_count ?? 0} tunnel(s), and{' '}
            {report.evaluated_packets_count ?? 0} packet(s).
          </p>
        </div>

        {/* Critical Findings */}
        <div className="rounded border border-border bg-surface p-4">
          <span className="text-2xs text-muted">Critical Severity</span>
          <p className="mt-1 text-2xl font-bold text-danger">{bySeverity.CRITICAL ?? 0}</p>
          <span className="text-2xs text-muted">Immediate action required</span>
        </div>

        {/* High Severity */}
        <div className="rounded border border-border bg-surface p-4">
          <span className="text-2xs text-muted">High Severity</span>
          <p className="mt-1 text-2xl font-bold text-orange-400">{bySeverity.HIGH ?? 0}</p>
          <span className="text-2xs text-muted">Priority remediation</span>
        </div>

        {/* Medium / Low */}
        <div className="rounded border border-border bg-surface p-4">
          <span className="text-2xs text-muted">Medium & Low</span>
          <p className="mt-1 text-2xl font-bold text-warning">
            {(bySeverity.MEDIUM ?? 0) + (bySeverity.LOW ?? 0)}
          </p>
          <span className="text-2xs text-muted">Scheduled hardening</span>
        </div>
      </div>

      {/* 2. Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-border bg-surface p-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted" />
            <input
              type="text"
              placeholder="Search findings, CVEs, rules…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded border border-border bg-surface-elevated py-1.5 pl-8 pr-3 text-xs text-primary placeholder:text-muted focus:border-info focus:outline-none"
            />
          </div>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="rounded border border-border bg-surface-elevated px-2.5 py-1.5 text-xs text-primary focus:border-info focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="rounded border border-border bg-surface-elevated px-2.5 py-1.5 text-xs text-primary focus:border-info focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            <option value="CRYPTOGRAPHY">Cryptography</option>
            <option value="INTEGRITY">Integrity</option>
            <option value="DATA_LEAKAGE">Data Leakage</option>
            <option value="PROTOCOL_ANOMALY">Protocol Anomaly</option>
            <option value="TUNNEL_STATE">Tunnel State</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-2xs text-muted">
            Showing {filteredFindings.length} of {findings.length} finding(s)
          </span>
          <button
            type="button"
            onClick={() => void loadData()}
            disabled={loading}
            className="inline-flex items-center gap-1 rounded border border-border px-2.5 py-1 text-2xs text-secondary hover:border-info hover:text-info"
          >
            <RefreshCw className={loading ? 'h-3 w-3 animate-spin' : 'h-3 w-3'} /> Refresh
          </button>
        </div>
      </div>

      {/* 3. Findings Cards List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="rounded border border-border bg-surface p-8 text-center text-xs text-muted">
            {findings.length === 0
              ? 'Zero security findings detected! The analyzed traffic conforms to hardened IPsec specifications.'
              : 'No findings match the selected filters.'}
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <div
              key={finding.finding_id}
              className={`rounded border p-4 text-xs transition-colors ${
                finding.severity === 'CRITICAL'
                  ? 'border-danger/30 bg-danger/5'
                  : finding.severity === 'HIGH'
                    ? 'border-orange-500/30 bg-orange-500/5'
                    : 'border-border bg-surface'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded border px-2 py-0.5 text-2xs font-bold ${getSeverityBadge(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className="font-mono text-2xs text-muted">{finding.finding_id}</span>
                  <span className="rounded bg-elevated px-1.5 py-0.5 font-mono text-2xs text-info border border-border">
                    {finding.rule_id}
                  </span>
                  <h4 className="font-semibold text-primary">{finding.title}</h4>
                </div>
                <div className="flex items-center gap-2 text-2xs text-muted">
                  <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                  <span className="rounded bg-surface px-1.5 py-0.5 border border-border">{finding.category}</span>
                </div>
              </div>

              {/* Explanation */}
              <p className="mt-2 text-xs text-secondary leading-relaxed">{finding.explanation}</p>

              {/* CVE and Standards */}
              {finding.cve_references.length > 0 && (
                <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                  <span className="text-2xs font-medium text-muted">Vulnerability References:</span>
                  {finding.cve_references.map((cve, i) => (
                    <span
                      key={i}
                      className="rounded bg-danger/15 px-1.5 py-0.5 font-mono text-2xs font-semibold text-danger border border-danger/30"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              )}

              {/* Remediation Action */}
              {finding.remediation && (
                <div className="mt-3 rounded border border-info/30 bg-info/5 p-2.5 text-2xs text-info">
                  <span className="font-bold uppercase tracking-wider">Recommended Remediation:</span>
                  <p className="mt-0.5 text-primary">{finding.remediation}</p>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
