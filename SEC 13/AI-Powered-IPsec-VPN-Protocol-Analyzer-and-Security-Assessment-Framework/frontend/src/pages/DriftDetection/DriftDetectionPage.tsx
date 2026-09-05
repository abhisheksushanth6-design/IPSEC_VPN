import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  BaselineSelector,
  DriftConfiguration,
  DriftDetailDrawer,
  DriftHeader,
  DriftHistoryTable,
  DriftStatusCard,
  DriftSummary,
  DriftTabKey,
  DriftToolbar,
  EmptyDriftState,
  FeatureDriftTable,
  SessionSelector,
} from '@/components/drift-detection';
import { baselineService } from '@/services/baselineService';
import { driftService } from '@/services/driftService';
import { sessionService } from '@/services/sessionService';
import type {
  BaselineSummary,
  DriftAnalysis,
  DriftAnalysisSummary,
  DriftEngineStatus,
  DriftThresholdConfig,
  FeatureDrift,
  VPNSession,
} from '@/types';

export function DriftDetectionPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  const [engineStatus, setEngineStatus] = useState<DriftEngineStatus | null>(null);
  const [config, setConfig] = useState<DriftThresholdConfig | null>(null);
  const [baselines, setBaselines] = useState<BaselineSummary[]>([]);
  const [sessions, setSessions] = useState<VPNSession[]>([]);

  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    searchParams.get('session_id')
  );
  const [selectedBaselineId, setSelectedBaselineId] = useState<string | null>(
    searchParams.get('baseline_id')
  );

  const [currentAnalysis, setCurrentAnalysis] = useState<DriftAnalysis | null>(null);
  const [history, setHistory] = useState<DriftAnalysisSummary[]>([]);
  const [selectedFeature, setSelectedFeature] = useState<FeatureDrift | null>(null);

  const [activeTab, setActiveTab] = useState<DriftTabKey>('features');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [driftFilter, setDriftFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const [loading, setLoading] = useState<boolean>(true);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Load initial data
  const loadInitialData = useCallback(async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const [statusRes, configRes, baselinesRes, sessionsPage, historyRes] = await Promise.all([
        driftService.getStatus().catch(() => null),
        driftService.getConfig().catch(() => null),
        baselineService.listBaselines().catch(() => []),
        sessionService.fetchSessions({ page: 1, pageSize: 100, sort: 'start_time', order: 'desc' }).catch(() => ({ items: [] })),
        driftService.listAnalyses({ limit: 50 }).catch(() => []),
      ]);

      setEngineStatus(statusRes);
      setConfig(configRes);
      setBaselines(Array.isArray(baselinesRes) ? baselinesRes : []);
      const sessionItems = Array.isArray(sessionsPage?.items) ? (sessionsPage.items as VPNSession[]) : [];
      setSessions(sessionItems);
      setHistory(Array.isArray(historyRes) ? historyRes : []);

      // Select active baseline if none specified
      let activeBaseId = selectedBaselineId;
      if (!activeBaseId && Array.isArray(baselinesRes) && baselinesRes.length > 0) {
        const active = baselinesRes.find((b) => b.is_active);
        activeBaseId = active ? active.id : (baselinesRes[0]?.id ?? null);
        setSelectedBaselineId(activeBaseId);
      }

      // Select first session if none specified
      let targetSessionId = selectedSessionId;
      if (!targetSessionId && sessionItems.length > 0) {
        targetSessionId = sessionItems[0]?.id ?? null;
        setSelectedSessionId(targetSessionId);
      }

      // If we have a target session, attempt to load its latest drift analysis
      if (targetSessionId) {
        try {
          const latest = await driftService.getSessionLatest(targetSessionId);
          if (latest) {
            setCurrentAnalysis(latest);
          }
        } catch {
          // No analysis yet for this session
        }
      } else if (historyRes.length > 0 && historyRes[0]) {
        // Load the most recent historical analysis
        try {
          const latestHist = await driftService.getAnalysis(historyRes[0].id);
          setCurrentAnalysis(latestHist);
          setSelectedSessionId(latestHist.session_id);
          setSelectedBaselineId(latestHist.baseline_id);
        } catch {
          // Ignore
        }
      }
    } catch (err: any) {
      setErrorMessage(err.message ?? 'Failed to initialize drift detection dashboard.');
    } finally {
      setLoading(false);
    }
  }, [selectedSessionId, selectedBaselineId]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Execute Drift Analysis
  const handleAnalyzeDrift = async () => {
    if (!selectedSessionId) return;
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const result = await driftService.analyze({
        session_id: selectedSessionId,
        baseline_id: selectedBaselineId,
      });
      setCurrentAnalysis(result);
      setSelectedFeature(null);
      setActiveTab('features');

      // Refresh engine status & history
      const [updatedStatus, updatedHistory] = await Promise.all([
        driftService.getStatus().catch(() => null),
        driftService.listAnalyses({ limit: 50 }).catch(() => []),
      ]);
      if (updatedStatus) setEngineStatus(updatedStatus);
      setHistory(updatedHistory);
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      const msg = typeof detail === 'object' ? detail.message : (detail ?? err.message);
      setErrorMessage(msg || 'Failed to execute drift analysis');
    } finally {
      setAnalyzing(false);
    }
  };

  // Load a historical analysis
  const handleSelectHistoryAnalysis = async (analysisId: string) => {
    setLoading(true);
    try {
      const full = await driftService.getAnalysis(analysisId);
      setCurrentAnalysis(full);
      setSelectedSessionId(full.session_id);
      setSelectedBaselineId(full.baseline_id);
      setSelectedFeature(null);
      setActiveTab('features');
    } catch (err: any) {
      setErrorMessage(err.message ?? 'Failed to load analysis');
    } finally {
      setLoading(false);
    }
  };

  // Extract distinct categories from current analysis features
  const categories = Array.from(
    new Set(currentAnalysis?.feature_results.map((f) => f.category) ?? [])
  ).sort();

  const activeBaseline = Array.isArray(baselines)
    ? baselines.find((b) => b.id === selectedBaselineId)
    : undefined;
  const canAnalyze = Boolean(selectedSessionId && (selectedBaselineId || engineStatus?.active_baseline_id));

  return (
    <div className="flex flex-col min-h-screen bg-base">
      {/* 1. Header */}
      <DriftHeader
        status={engineStatus ?? undefined}
        loading={loading || analyzing}
        onRefresh={loadInitialData}
        onTriggerAnalyze={handleAnalyzeDrift}
        canAnalyze={canAnalyze}
      />

      {/* 2. Target Context Selection Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface-muted/30 px-6 py-2.5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
              Target Session:
            </span>
            <SessionSelector
              sessions={sessions}
              selectedSessionId={selectedSessionId}
              onSelect={(sid) => {
                setSelectedSessionId(sid);
                setSearchParams({ session_id: sid });
                // Check if session has previous analysis
                driftService
                  .getSessionLatest(sid)
                  .then((a) => setCurrentAnalysis(a))
                  .catch(() => setCurrentAnalysis(null));
              }}
              disabled={analyzing}
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
              Reference Baseline:
            </span>
            <BaselineSelector
              baselines={baselines}
              selectedBaselineId={selectedBaselineId}
              onSelect={(bid) => setSelectedBaselineId(bid)}
              disabled={analyzing}
            />
          </div>
        </div>

        {currentAnalysis && (
          <div className="font-mono text-2xs text-muted">
            Analysis ID: <span className="text-text-primary font-semibold">{currentAnalysis.id}</span>
          </div>
        )}
      </div>

      {/* 3. Error Banner */}
      {errorMessage && (
        <div className="mx-6 mt-4 rounded-md border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-400">
          <strong>Analysis Error:</strong> {errorMessage}
        </div>
      )}

      {/* 4. Empty / Ready State check */}
      {!currentAnalysis && (
        <EmptyDriftState
          state={engineStatus?.state}
          onTriggerAnalyze={handleAnalyzeDrift}
          canAnalyze={canAnalyze}
        />
      )}

      {/* 5. Main Analysis View */}
      {currentAnalysis && (
        <>
          {/* KPI Summary Cards */}
          <DriftSummary
            analysis={currentAnalysis}
            activeBaselineName={activeBaseline?.name}
          />

          {/* Prominent Overall Drift Status Card */}
          <DriftStatusCard analysis={currentAnalysis} />

          {/* Toolbar & Tabs */}
          <DriftToolbar
            activeTab={activeTab}
            onTabChange={setActiveTab}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            categoryFilter={categoryFilter}
            onCategoryChange={setCategoryFilter}
            driftFilter={driftFilter}
            onDriftFilterChange={setDriftFilter}
            severityFilter={severityFilter}
            onSeverityFilterChange={setSeverityFilter}
            categories={categories}
          />

          {/* Tab Content */}
          <div className="flex-1 p-6">
            {activeTab === 'features' && (
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                {/* Feature Drift Table */}
                <div
                  className={`rounded-lg border border-border bg-surface shadow-sm overflow-hidden ${
                    selectedFeature ? 'lg:col-span-7' : 'lg:col-span-12'
                  }`}
                >
                  <FeatureDriftTable
                    features={currentAnalysis.feature_results}
                    selectedFeature={selectedFeature}
                    onSelectFeature={(feat) => setSelectedFeature(feat)}
                    searchQuery={searchQuery}
                    categoryFilter={categoryFilter}
                    driftFilter={driftFilter}
                    severityFilter={severityFilter}
                  />
                </div>

                {/* Inspection Detail Drawer */}
                {selectedFeature && (
                  <div className="lg:col-span-5 min-h-[500px]">
                    <DriftDetailDrawer
                      feature={selectedFeature}
                      sessionId={currentAnalysis.session_id}
                      baselineId={currentAnalysis.baseline_id}
                      onClose={() => setSelectedFeature(null)}
                    />
                  </div>
                )}
              </div>
            )}

            {activeTab === 'history' && (
              <div className="rounded-lg border border-border bg-surface shadow-sm overflow-hidden">
                <DriftHistoryTable
                  history={history}
                  selectedId={currentAnalysis.id}
                  onSelect={handleSelectHistoryAnalysis}
                />
              </div>
            )}

            {activeTab === 'config' && (
              <div className="rounded-lg border border-border bg-surface shadow-sm overflow-hidden">
                <DriftConfiguration config={config} />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
