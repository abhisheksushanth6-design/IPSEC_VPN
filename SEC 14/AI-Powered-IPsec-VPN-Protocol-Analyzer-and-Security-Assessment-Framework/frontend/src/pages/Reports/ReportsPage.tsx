import { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Download,
  Trash2,
  RefreshCw,
  PlusCircle,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Shield,
  Layers,
} from 'lucide-react';

import { PageHeader, Panel } from '@/components/ui';
import { reportService, sessionService } from '@/services';
import type { ReportMetadata, ReportType, IPsecSessionSummary } from '@/types';

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatDate(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return isoString;
  }
}

export function ReportsPage() {
  // Report Generation State
  const [reportType, setReportType] = useState<ReportType>('FULL');
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [customTitle, setCustomTitle] = useState<string>('');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [generationSuccess, setGenerationSuccess] = useState<ReportMetadata | null>(null);
  const [generationError, setGenerationError] = useState<string | null>(null);

  // Available Sessions for selection
  const [availableSessions, setAvailableSessions] = useState<IPsecSessionSummary[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState<boolean>(false);

  // Reports History State
  const [reports, setReports] = useState<ReportMetadata[]>([]);
  const [isLoadingReports, setIsLoadingReports] = useState<boolean>(true);
  const [typeFilter, setTypeFilter] = useState<'ALL' | ReportType>('ALL');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Fetch reports list
  const loadReports = useCallback(async () => {
    setIsLoadingReports(true);
    try {
      const data = await reportService.list();
      setReports(data);
    } catch {
      // ignore abort or log error
    } finally {
      setIsLoadingReports(false);
    }
  }, []);

  // Fetch sessions for dropdown
  const loadSessions = useCallback(async () => {
    setSessionsLoading(true);
    try {
      const data = await sessionService.fetchSessions({
        page: 1,
        pageSize: 50,
        sort: 'start_time',
        order: 'desc',
      });
      const items = data.items || [];
      setAvailableSessions(items);
      if (items.length > 0 && items[0]?.id && !selectedSessionId) {
        setSelectedSessionId(items[0].id);
      }
    } catch {
      // fallback
    } finally {
      setSessionsLoading(false);
    }
  }, [selectedSessionId]);

  useEffect(() => {
    loadReports();
    loadSessions();
  }, [loadReports, loadSessions]);

  // Handle Generate
  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsGenerating(true);
    setGenerationError(null);
    setGenerationSuccess(null);

    try {
      const payload = {
        report_type: reportType,
        session_id: reportType === 'SESSION' ? selectedSessionId || null : null,
        title: customTitle.trim() || null,
      };
      const created = await reportService.generate(payload);
      setGenerationSuccess(created);
      setCustomTitle('');
      await loadReports();
    } catch (err: any) {
      setGenerationError(err.message || 'Report generation failed');
    } finally {
      setIsGenerating(false);
    }
  };

  // Handle Delete
  const handleDelete = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this report?')) return;
    setDeletingId(id);
    try {
      await reportService.delete(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
      if (generationSuccess?.id === id) {
        setGenerationSuccess(null);
      }
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  // Filtered reports
  const filteredReports = reports.filter((r) => {
    if (typeFilter === 'ALL') return true;
    return r.report_type === typeFilter;
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Assessment Reports"
        description="Generate, review and export evidence-based IPsec VPN security assessment PDF reports."
        status="OPERATIONAL"
        statusLabel="LAYER 14 OPERATIONAL"
        breadcrumbs={[{ label: 'Reporting' }, { label: 'Reports' }]}
        actions={
          <button
            onClick={() => {
              loadReports();
              loadSessions();
            }}
            disabled={isLoadingReports}
            className="inline-flex items-center gap-2 rounded border border-border bg-surface px-3 py-1.5 text-xs font-medium text-secondary hover:bg-subtle hover:text-primary transition-colors disabled:opacity-50"
            title="Refresh Reports"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoadingReports ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Scope & Traceability Advisory */}
      <div className="rounded-lg border border-border/80 bg-surface/50 p-4 text-xs text-muted flex items-start gap-3">
        <Shield className="h-5 w-5 text-indigo-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-medium text-primary">
            Evidence-Based Audit Traceability (Layers 01–14)
          </p>
          <p>
            Generated PDF reports compile empirical protocol state, cryptographic Security Associations,
            behavioral baselines, deterministic drift detections, unsupervised ML anomalies, security rule
            evaluations, and composite Layer 10 risk assessments with zero synthetic scores.
          </p>
        </div>
      </div>

      {/* Generator Section */}
      <Panel
        title="Generate Security Assessment Report"
        description="Select assessment scope and parameters to build a publication-grade PDF report."
      >
        <form onSubmit={handleGenerate} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Full Report Option */}
            <label
              className={`cursor-pointer rounded border p-3 flex flex-col justify-between transition-colors ${
                reportType === 'FULL'
                  ? 'border-indigo-500/70 bg-indigo-500/10 text-primary'
                  : 'border-border bg-surface text-muted hover:border-border-hover'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-sm text-primary flex items-center gap-2">
                  <Layers className="h-4 w-4 text-indigo-400" />
                  Full Assessment
                </span>
                <input
                  type="radio"
                  name="reportType"
                  value="FULL"
                  checked={reportType === 'FULL'}
                  onChange={() => setReportType('FULL')}
                  className="accent-indigo-500"
                />
              </div>
              <p className="text-2xs leading-relaxed text-muted">
                Comprehensive security audit covering all layers: Packets, Sessions, SAs, Features, Baselines, Drift, ML Anomalies, and Rule Findings.
              </p>
            </label>

            {/* Session Report Option */}
            <label
              className={`cursor-pointer rounded border p-3 flex flex-col justify-between transition-colors ${
                reportType === 'SESSION'
                  ? 'border-cyan-500/70 bg-cyan-500/10 text-primary'
                  : 'border-border bg-surface text-muted hover:border-border-hover'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-sm text-primary flex items-center gap-2">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  Session Deep-Dive
                </span>
                <input
                  type="radio"
                  name="reportType"
                  value="SESSION"
                  checked={reportType === 'SESSION'}
                  onChange={() => setReportType('SESSION')}
                  className="accent-cyan-500"
                />
              </div>
              <p className="text-2xs leading-relaxed text-muted">
                Focused forensic report on a specific IPsec session, including its IKE/ESP parameters, active SAs, drift deviations, and specific findings.
              </p>
            </label>

            {/* Vulnerability Report Option */}
            <label
              className={`cursor-pointer rounded border p-3 flex flex-col justify-between transition-colors ${
                reportType === 'VULNERABILITY'
                  ? 'border-amber-500/70 bg-amber-500/10 text-primary'
                  : 'border-border bg-surface text-muted hover:border-border-hover'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-sm text-primary flex items-center gap-2">
                  <Shield className="h-4 w-4 text-amber-400" />
                  Vulnerability &amp; Hardening
                </span>
                <input
                  type="radio"
                  name="reportType"
                  value="VULNERABILITY"
                  checked={reportType === 'VULNERABILITY'}
                  onChange={() => setReportType('VULNERABILITY')}
                  className="accent-amber-500"
                />
              </div>
              <p className="text-2xs leading-relaxed text-muted">
                Security finding summary prioritized by severity (Critical/High/Medium/Low) with actionable remediation guidance.
              </p>
            </label>
          </div>

          {/* Session Selector (when SESSION type chosen) */}
          {reportType === 'SESSION' && (
            <div className="rounded border border-border bg-subtle/30 p-3.5 space-y-2">
              <label htmlFor="session-select" className="block text-xs font-medium text-secondary">
                Target IPsec Session <span className="text-red-400">*</span>
              </label>
              {sessionsLoading ? (
                <div className="text-xs text-muted flex items-center gap-2">
                  <RefreshCw className="h-3 w-3 animate-spin" /> Loading available sessions...
                </div>
              ) : availableSessions.length > 0 ? (
                <select
                  id="session-select"
                  value={selectedSessionId}
                  onChange={(e) => setSelectedSessionId(e.target.value)}
                  className="w-full rounded border border-border bg-surface px-3 py-2 text-xs text-primary focus:border-cyan-500 focus:outline-none"
                  required
                >
                  {availableSessions.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id} | {s.source} &rarr; {s.destination} ({s.ike_version || 'IKE'}, {s.packet_count} pkts, {s.state})
                    </option>
                  ))}
                </select>
              ) : (
                <div className="flex gap-2 items-center">
                  <input
                    type="text"
                    placeholder="Enter Session ID (e.g. sess-01)"
                    value={selectedSessionId}
                    onChange={(e) => setSelectedSessionId(e.target.value)}
                    className="flex-1 rounded border border-border bg-surface px-3 py-1.5 text-xs text-primary focus:border-cyan-500 focus:outline-none"
                    required
                  />
                  <span className="text-2xs text-muted">No sessions loaded automatically</span>
                </div>
              )}
            </div>
          )}

          {/* Custom Title Input */}
          <div>
            <label htmlFor="report-title" className="block text-xs font-medium text-secondary mb-1">
              Custom Report Title (Optional)
            </label>
            <input
              id="report-title"
              type="text"
              value={customTitle}
              onChange={(e) => setCustomTitle(e.target.value)}
              placeholder="e.g., Enterprise Gateway IPsec Security Audit — Q3 2026"
              className="w-full rounded border border-border bg-surface px-3 py-2 text-xs text-primary placeholder:text-muted/60 focus:border-indigo-500 focus:outline-none"
            />
          </div>

          {/* Action Row */}
          <div className="flex items-center justify-between pt-2">
            <button
              type="submit"
              disabled={isGenerating || (reportType === 'SESSION' && !selectedSessionId)}
              className="inline-flex items-center gap-2 rounded bg-indigo-600 px-4 py-2 text-xs font-medium text-white hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
            >
              {isGenerating ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  <span>Generating PDF Report...</span>
                </>
              ) : (
                <>
                  <PlusCircle className="h-4 w-4" />
                  <span>Generate Assessment Report</span>
                </>
              )}
            </button>
          </div>

          {/* Success Banner */}
          {generationSuccess && (
            <div className="mt-3 rounded border border-green-500/30 bg-green-500/10 p-3 text-xs flex items-center justify-between text-green-300">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" />
                <span>
                  Report generated successfully: <strong>{generationSuccess.title}</strong> ({generationSuccess.page_count} pages, {formatBytes(generationSuccess.file_size_bytes)})
                </span>
              </div>
              <a
                href={reportService.getDownloadUrl(generationSuccess.id)}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 rounded bg-green-600 px-3 py-1 text-2xs font-semibold text-white hover:bg-green-500 transition-colors"
              >
                <Download className="h-3 w-3" />
                <span>Download PDF</span>
              </a>
            </div>
          )}

          {/* Error Banner */}
          {generationError && (
            <div className="mt-3 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs flex items-center gap-2 text-red-300">
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              <span>{generationError}</span>
            </div>
          )}
        </form>
      </Panel>

      {/* Reports History Section */}
      <Panel
        title={`Generated Assessment Reports (${filteredReports.length})`}
        description="Historical assessment reports stored in backend storage ready for download and compliance review."
        actions={
          <div className="flex items-center gap-1 bg-subtle/60 p-0.5 rounded border border-border text-2xs">
            {(['ALL', 'FULL', 'SESSION', 'VULNERABILITY'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setTypeFilter(tab)}
                className={`px-2.5 py-1 rounded font-medium transition-colors ${
                  typeFilter === tab
                    ? 'bg-surface text-primary shadow-sm'
                    : 'text-muted hover:text-secondary'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        }
      >
        {isLoadingReports && reports.length === 0 ? (
          <div className="py-8 text-center text-xs text-muted flex flex-col items-center justify-center gap-2">
            <RefreshCw className="h-5 w-5 animate-spin text-muted" />
            <span>Loading assessment reports...</span>
          </div>
        ) : filteredReports.length === 0 ? (
          <div className="py-12 text-center text-xs text-muted flex flex-col items-center justify-center gap-2">
            <FileText className="h-8 w-8 text-border" />
            <p className="font-medium text-secondary">No assessment reports found</p>
            <p className="text-2xs text-muted max-w-sm">
              {typeFilter === 'ALL'
                ? 'Generate your first cybersecurity assessment PDF report using the generator above.'
                : `No reports match the ${typeFilter} filter.`}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border text-2xs uppercase tracking-wider text-muted">
                <tr>
                  <th className="pb-2.5 font-medium">Report ID</th>
                  <th className="pb-2.5 font-medium">Scope</th>
                  <th className="pb-2.5 font-medium">Title</th>
                  <th className="pb-2.5 font-medium">Generated</th>
                  <th className="pb-2.5 font-medium">Pages</th>
                  <th className="pb-2.5 font-medium">Size</th>
                  <th className="pb-2.5 font-medium">Status</th>
                  <th className="pb-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredReports.map((report) => {
                  const typeBadgeClass =
                    report.report_type === 'FULL'
                      ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-400'
                      : report.report_type === 'SESSION'
                      ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400'
                      : 'border-amber-500/30 bg-amber-500/10 text-amber-400';

                  return (
                    <tr key={report.id} className="hover:bg-subtle/40 transition-colors">
                      <td className="py-3 font-mono text-2xs text-secondary font-medium">
                        {report.id}
                      </td>
                      <td className="py-3">
                        <span
                          className={`inline-block rounded border px-1.5 py-0.5 font-mono text-3xs font-semibold uppercase ${typeBadgeClass}`}
                        >
                          {report.report_type}
                        </span>
                      </td>
                      <td className="py-3 max-w-[280px] truncate text-primary font-medium" title={report.title}>
                        {report.title}
                      </td>
                      <td className="py-3 text-muted text-2xs whitespace-nowrap">
                        <span className="inline-flex items-center gap-1">
                          <Clock className="h-3 w-3 text-muted" />
                          {formatDate(report.generated_at)}
                        </span>
                      </td>
                      <td className="py-3 text-secondary text-2xs">
                        {report.page_count} {report.page_count === 1 ? 'page' : 'pages'}
                      </td>
                      <td className="py-3 text-muted text-2xs">
                        {formatBytes(report.file_size_bytes)}
                      </td>
                      <td className="py-3">
                        <span className="inline-flex items-center gap-1 rounded bg-green-500/10 px-1.5 py-0.5 text-3xs font-medium text-green-400 border border-green-500/20">
                          <CheckCircle2 className="h-2.5 w-2.5" />
                          {report.status}
                        </span>
                      </td>
                      <td className="py-3 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-2">
                          <a
                            href={reportService.getDownloadUrl(report.id)}
                            download={report.filename}
                            className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2.5 py-1 text-2xs font-medium text-secondary hover:bg-subtle hover:text-primary transition-colors"
                            title="Download PDF"
                          >
                            <Download className="h-3 w-3 text-indigo-400" />
                            <span>PDF</span>
                          </a>
                          <button
                            onClick={() => handleDelete(report.id)}
                            disabled={deletingId === report.id}
                            className="inline-flex items-center p-1 text-muted hover:text-red-400 transition-colors rounded hover:bg-red-500/10 disabled:opacity-50"
                            title="Delete Report"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
