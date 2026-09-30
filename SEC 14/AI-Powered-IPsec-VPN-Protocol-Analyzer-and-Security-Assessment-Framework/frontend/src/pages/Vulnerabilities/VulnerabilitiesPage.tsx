import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ShieldAlert,
  BookOpen,
  GitCommit,
  AlertCircle,
} from 'lucide-react';
import {
  VulnerabilityHeader,
  VulnerabilityKPIs,
  SeverityDistributionBar,
  CategoryDistributionChart,
  VulnerabilityFilters,
  EmptyVulnerabilitiesState,
  FindingsTable,
  FindingDetailModal,
  RuleExplorer,
  RuleDetailModal,
  ScanControlsPanel,
  VulnerabilityLineage,
} from '@/components/vulnerabilities';
import { vulnerabilityService } from '@/services/vulnerabilityService';
import type {
  VulnerabilityEngineStatus,
  VulnerabilityStats,
  VulnerabilityFinding,
  SecurityRule,
  FindingFilters,
  FindingStatus,
  AnalyzeResponse,
} from '@/types';

export function VulnerabilitiesPage() {
  // Navigation & View State
  const [activeTab, setActiveTab] = useState<'findings' | 'rules' | 'lineage'>('findings');

  // Engine Status & Data States
  const [status, setStatus] = useState<VulnerabilityEngineStatus | null>(null);
  const [stats, setStats] = useState<VulnerabilityStats | null>(null);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [rules, setRules] = useState<SecurityRule[]>([]);

  // Loading & Action States
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [scanning, setScanning] = useState<boolean>(false);
  const [lastScanResult, setLastScanResult] = useState<AnalyzeResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Filter State
  const [filters, setFilters] = useState<FindingFilters>({
    category: 'ALL',
    severity: 'ALL',
    status: 'ALL',
    searchQuery: '',
  });

  // Modal States
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [selectedRule, setSelectedRule] = useState<SecurityRule | null>(null);

  // Fetch all initial data
  const fetchData = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      setErrorMessage(null);

      const [statusRes, statsRes, findingsRes, rulesRes] = await Promise.all([
        vulnerabilityService.getStatus().catch(() => null),
        vulnerabilityService.getStats().catch(() => null),
        vulnerabilityService.listFindings().catch(() => []),
        vulnerabilityService.listRules().catch(() => []),
      ]);

      if (statusRes) setStatus(statusRes);
      if (statsRes) setStats(statsRes);
      setFindings(Array.isArray(findingsRes) ? findingsRes : []);
      setRules(Array.isArray(rulesRes) ? rulesRes : []);
    } catch (err: any) {
      console.error('Failed to load vulnerability engine data:', err);
      setErrorMessage(err?.message || 'Failed to connect to Security Rule & Vulnerability Engine');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchData(true);
  };

  const handleRunScan = async (force: boolean) => {
    try {
      setScanning(true);
      setErrorMessage(null);
      const result = await vulnerabilityService.runAnalysis({
        force_reevaluation: force,
      });
      setLastScanResult(result);
      await fetchData(true);
      return result;
    } catch (err: any) {
      console.error('Vulnerability scan failed:', err);
      setErrorMessage(err?.message || 'Vulnerability scan execution failed');
      return null;
    } finally {
      setScanning(false);
    }
  };

  const handleExportFindings = async () => {
    try {
      const data = await vulnerabilityService.exportFindings();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `vulnerability_findings_report_${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Failed to export findings:', err);
      setErrorMessage(err?.message || 'Failed to export findings report');
    }
  };

  const handleUpdateFindingStatus = async (
    findingId: string | number,
    newStatus: FindingStatus,
    note?: string
  ) => {
    try {
      const updated = await vulnerabilityService.updateFindingStatus(findingId, {
        status: newStatus,
        status_note: note,
      });

      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? updated : f))
      );

      // Refresh stats
      const newStats = await vulnerabilityService.getStats().catch(() => null);
      if (newStats) setStats(newStats);
    } catch (err: any) {
      console.error('Failed to update finding status:', err);
      setErrorMessage(err?.message || 'Failed to update finding status');
      throw err;
    }
  };

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      if (enabled) {
        await vulnerabilityService.enableRule(ruleId);
      } else {
        await vulnerabilityService.disableRule(ruleId);
      }

      setRules((prev) =>
        prev.map((r) => (r.id === ruleId ? { ...r, enabled } : r))
      );

      // Refresh status & stats
      const [newStatus, newStats] = await Promise.all([
        vulnerabilityService.getStatus().catch(() => null),
        vulnerabilityService.getStats().catch(() => null),
      ]);
      if (newStatus) setStatus(newStatus);
      if (newStats) setStats(newStats);
    } catch (err: any) {
      console.error('Failed to toggle rule:', err);
      setErrorMessage(err?.message || 'Failed to toggle rule state');
      throw err;
    }
  };

  // Filtered Findings
  const filteredFindings = useMemo(() => {
    if (!Array.isArray(findings)) return [];
    return findings.filter((f) => {
      if (filters.category && filters.category !== 'ALL' && f.category !== filters.category) {
        return false;
      }
      if (filters.severity && filters.severity !== 'ALL' && f.severity !== filters.severity) {
        return false;
      }
      if (filters.status && filters.status !== 'ALL' && f.status !== filters.status) {
        return false;
      }
      if (filters.searchQuery) {
        const q = filters.searchQuery.toLowerCase();
        const matchesRule = f.rule_id.toLowerCase().includes(q);
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesObj = f.affected_object_id.toLowerCase().includes(q);
        const matchesDesc = f.description.toLowerCase().includes(q);
        return matchesRule || matchesTitle || matchesObj || matchesDesc;
      }
      return true;
    });
  }, [findings, filters]);

  const isFiltered =
    (filters.category && filters.category !== 'ALL') ||
    (filters.severity && filters.severity !== 'ALL') ||
    (filters.status && filters.status !== 'ALL') ||
    Boolean(filters.searchQuery);

  return (
    <div className="flex-1 space-y-6 pb-12 bg-background min-h-screen">
      {/* Top Header */}
      <VulnerabilityHeader
        status={status}
        onRefresh={handleRefresh}
        onRunScan={() => handleRunScan(false)}
        onExport={handleExportFindings}
        refreshing={refreshing}
        scanning={scanning}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
        {/* Error Notification */}
        {errorMessage && (
          <div className="flex items-center justify-between rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="font-medium hover:underline text-red-400"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* KPIs */}
        <VulnerabilityKPIs stats={stats} loading={loading} />

        {/* Scan Controls Panel */}
        <ScanControlsPanel
          onRunScan={handleRunScan}
          scanning={scanning}
          lastScanResult={lastScanResult}
        />

        {/* Distribution Charts */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
            <SeverityDistributionBar
              distribution={stats?.by_severity ?? {}}
              total={stats?.total_findings ?? 0}
            />
          </div>

          <div className="rounded-lg border border-border bg-surface p-4 shadow-sm">
            <CategoryDistributionChart
              distribution={stats?.by_category ?? {}}
              total={stats?.total_findings ?? 0}
            />
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="border-b border-border">
          <nav className="flex space-x-6" aria-label="Tabs">
            <button
              onClick={() => setActiveTab('findings')}
              className={`flex items-center gap-2 border-b-2 py-3 text-xs font-semibold transition ${
                activeTab === 'findings'
                  ? 'border-rose-500 text-rose-400'
                  : 'border-transparent text-text-secondary hover:border-border hover:text-text-primary'
              }`}
            >
              <ShieldAlert className="h-4 w-4" />
              <span>Security Assessment Findings</span>
              <span className="rounded-full bg-surface-subtle px-2 py-0.5 text-[11px] font-mono text-text-secondary">
                {findings.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`flex items-center gap-2 border-b-2 py-3 text-xs font-semibold transition ${
                activeTab === 'rules'
                  ? 'border-rose-500 text-rose-400'
                  : 'border-transparent text-text-secondary hover:border-border hover:text-text-primary'
              }`}
            >
              <BookOpen className="h-4 w-4" />
              <span>Security Rule Catalog</span>
              <span className="rounded-full bg-surface-subtle px-2 py-0.5 text-[11px] font-mono text-text-secondary">
                {rules.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('lineage')}
              className={`flex items-center gap-2 border-b-2 py-3 text-xs font-semibold transition ${
                activeTab === 'lineage'
                  ? 'border-rose-500 text-rose-400'
                  : 'border-transparent text-text-secondary hover:border-border hover:text-text-primary'
              }`}
            >
              <GitCommit className="h-4 w-4" />
              <span>Architecture & Lineage</span>
            </button>
          </nav>
        </div>

        {/* Tab 1: Findings Table */}
        {activeTab === 'findings' && (
          <div className="space-y-4">
            <VulnerabilityFilters
              filters={filters}
              onChange={setFilters}
              totalResults={filteredFindings.length}
            />

            {filteredFindings.length === 0 ? (
              <EmptyVulnerabilitiesState
                isFiltered={isFiltered}
                onClearFilters={() =>
                  setFilters({
                    category: 'ALL',
                    severity: 'ALL',
                    status: 'ALL',
                    searchQuery: '',
                  })
                }
              />
            ) : (
              <FindingsTable
                findings={filteredFindings}
                onSelectFinding={setSelectedFinding}
                loading={loading}
              />
            )}
          </div>
        )}

        {/* Tab 2: Rule Explorer */}
        {activeTab === 'rules' && (
          <RuleExplorer
            rules={rules}
            onSelectRule={setSelectedRule}
            onToggleRule={handleToggleRule}
            loading={loading}
          />
        )}

        {/* Tab 3: Lineage */}
        {activeTab === 'lineage' && <VulnerabilityLineage />}
      </div>

      {/* Modals */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onUpdateStatus={handleUpdateFindingStatus}
        />
      )}

      {selectedRule && (
        <RuleDetailModal
          rule={selectedRule}
          onClose={() => setSelectedRule(null)}
          onToggleRule={handleToggleRule}
        />
      )}
    </div>
  );
}
