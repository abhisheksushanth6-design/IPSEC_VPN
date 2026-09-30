import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  BaselineComparison,
  BaselineDataQuality,
  BaselineFeatureTable,
  BaselineHeader,
  BaselineMetadata,
  BaselineSessionTable,
  BaselineSummary as BaselineSummaryCards,
  BaselineTable,
  BaselineTimeline,
  BaselineToolbar,
  BaselineVersionHistory,
  BuildBaselineModal,
  EmptyBaselineState,
  FingerprintComparison,
  FingerprintDetails,
  FingerprintTable,
  type BaselineTabKey,
} from '@/components/baseline-profiling';
import { baselineService } from '@/services/baselineService';
import { sessionService } from '@/services/sessionService';
import type {
  BaselineBuildRequest,
  BaselineEngineStatus,
  BaselineProfile,
  BaselineSessionItem,
  BaselineSummary,
  SessionFingerprint,
} from '@/types';

export function BaselineProfilesPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Navigation tab & query states
  const initialTab = (searchParams.get('tab') as BaselineTabKey) || 'fingerprints';
  const initialSessionId = searchParams.get('session_id');
  const initialBaselineId = searchParams.get('baseline_id');

  const [activeTab, setActiveTab] = useState<BaselineTabKey>(initialTab);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Data states
  const [engineStatus, setEngineStatus] = useState<BaselineEngineStatus | null>(null);
  const [baselines, setBaselines] = useState<BaselineSummary[]>([]);
  const [selectedBaselineId, setSelectedBaselineId] = useState<string | null>(initialBaselineId);
  const [selectedProfile, setSelectedProfile] = useState<BaselineProfile | null>(null);
  const [profileSessions, setProfileSessions] = useState<BaselineSessionItem[]>([]);
  const [profileSubTab, setProfileSubTab] = useState<'features' | 'sessions' | 'history'>('features');

  const [fingerprints, setFingerprints] = useState<SessionFingerprint[]>([]);
  const [selectedFingerprintId, setSelectedFingerprintId] = useState<string | null>(null);

  const [availableSessionCount, setAvailableSessionCount] = useState<number>(0);

  // Status & loading states
  const [loading, setLoading] = useState<boolean>(true);
  const [reachable, setReachable] = useState<boolean>(true);
  const [isBuildModalOpen, setIsBuildModalOpen] = useState<boolean>(false);
  const [isBuilding, setIsBuilding] = useState<boolean>(false);
  const [activatingId, setActivatingId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Refresh all primary data
  const loadData = useCallback(async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const [statusRes, baselinesRes, fpsRes] = await Promise.all([
        baselineService.fetchStatus().catch(() => null),
        baselineService.listBaselines().catch(() => []),
        baselineService.listFingerprints().catch(() => []),
      ]);

      if (statusRes) {
        setEngineStatus(statusRes);
        setReachable(true);
      } else {
        setReachable(false);
      }

      setBaselines(Array.isArray(baselinesRes) ? baselinesRes : []);
      setFingerprints(Array.isArray(fpsRes) ? fpsRes : []);

      // Select active baseline by default if none selected
      if (!selectedBaselineId && Array.isArray(baselinesRes) && baselinesRes.length > 0) {
        const active = baselinesRes.find((b) => b.is_active);
        setSelectedBaselineId(active ? active.id : (baselinesRes[0]?.id ?? null));
      }

      // Fetch available sessions from session service
      sessionService
        .fetchSessions({ page: 1, pageSize: 100, sort: 'start_time', order: 'desc' })
        .then((page) => setAvailableSessionCount(page.total))
        .catch(() => setAvailableSessionCount(0));
    } catch (err: any) {
      setErrorMessage(err.message ?? 'Error fetching session fingerprinting data');
    } finally {
      setLoading(false);
    }
  }, [selectedBaselineId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Load detailed profile whenever selectedBaselineId changes
  useEffect(() => {
    if (!selectedBaselineId) {
      setSelectedProfile(null);
      setProfileSessions([]);
      return;
    }

    let active = true;
    Promise.all([
      baselineService.getBaseline(selectedBaselineId),
      baselineService.fetchBaselineSessions(selectedBaselineId).catch(() => []),
    ])
      .then(([prof, sess]) => {
        if (active) {
          setSelectedProfile(prof);
          setProfileSessions(sess);
        }
      })
      .catch((err) => {
        if (active) {
          setErrorMessage(err.message ?? 'Failed to load baseline profile details');
        }
      });

    return () => {
      active = false;
    };
  }, [selectedBaselineId]);

  // Handle URL session_id parameter linking
  useEffect(() => {
    if (initialSessionId) {
      setActiveTab('fingerprints');
      // If fingerprint for this session is already in the list, select it
      const existing = fingerprints.find((f) => f.session_id === initialSessionId);
      if (existing) {
        setSelectedFingerprintId(existing.id);
      } else {
        // Fetch or create fingerprint for this session
        baselineService
          .getSessionFingerprint(initialSessionId)
          .then((fp) => {
            setSelectedFingerprintId(fp.id);
            setFingerprints((prev) => (prev.some((f) => f.id === fp.id) ? prev : [fp, ...prev]));
          })
          .catch(() => {
            /* ignore if session not available */
          });
      }
    }
  }, [initialSessionId, fingerprints]);

  const handleActivateBaseline = async (id: string) => {
    setActivatingId(id);
    try {
      await baselineService.activateBaseline(id);
      await loadData();
    } catch (err: any) {
      setErrorMessage(err.message ?? 'Failed to activate baseline profile');
    } finally {
      setActivatingId(null);
    }
  };

  const handleBuildBaseline = async (payload: BaselineBuildRequest) => {
    setIsBuilding(true);
    try {
      const newProfile = await baselineService.buildBaseline(payload);
      setSelectedBaselineId(newProfile.id);
      await loadData();
    } finally {
      setIsBuilding(false);
    }
  };

  const selectedFingerprint = Array.isArray(fingerprints)
    ? (fingerprints.find((f) => f.id === selectedFingerprintId) ?? null)
    : null;

  return (
    <div className="flex flex-col min-h-screen bg-base text-text-primary">
      {/* Header */}
      <BaselineHeader
        state={engineStatus?.state}
        reachable={reachable}
        loading={loading}
        onRefresh={loadData}
        onOpenBuildModal={() => setIsBuildModalOpen(true)}
      />

      {/* Error Banner */}
      {errorMessage && (
        <div className="mx-6 mt-4 flex items-center justify-between rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-xs text-rose-400">
          <span>{errorMessage}</span>
          <button
            type="button"
            onClick={() => setErrorMessage(null)}
            className="text-muted hover:text-rose-300 ml-4 font-bold"
          >
            ✕
          </button>
        </div>
      )}

      {/* Summary KPI Cards */}
      <BaselineSummaryCards status={engineStatus} />

      {/* Empty State Check */}
      {baselines.length === 0 && fingerprints.length === 0 && !loading && (
        <EmptyBaselineState
          state={engineStatus?.state}
          onOpenBuildModal={() => setIsBuildModalOpen(true)}
        />
      )}

      {/* Main Tabbed Interface (when data or partial observations exist) */}
      {(baselines.length > 0 || fingerprints.length > 0 || engineStatus?.state === 'READY') && (
        <div className="flex-1 flex flex-col">
          <BaselineToolbar
            activeTab={activeTab}
            onTabChange={(tab) => {
              setActiveTab(tab);
              setSearchParams({ tab });
            }}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            baselinesCount={baselines.length}
            fingerprintsCount={fingerprints.length}
          />

          <div className="flex-1">
            {/* TAB 1: Baseline Profiles */}
            {activeTab === 'baselines' && (
              <div className="space-y-6 p-6">
                {/* Profiles Table */}
                <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
                  <div className="flex items-center justify-between border-b border-border bg-surface-muted/50 px-4 py-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted">
                      Configured Baseline Reference Models
                    </h3>
                    <span className="text-2xs font-mono text-muted">
                      {baselines.length} total profiles
                    </span>
                  </div>
                  <BaselineTable
                    baselines={baselines}
                    selectedId={selectedBaselineId}
                    onSelect={(id) => setSelectedBaselineId(id)}
                    onActivate={handleActivateBaseline}
                    activatingId={activatingId}
                  />
                </div>

                {/* Selected Baseline Inspector */}
                {selectedProfile && (
                  <div className="space-y-6 pt-2">
                    <BaselineMetadata profile={selectedProfile} />
                    <BaselineDataQuality profile={selectedProfile} />
                    <BaselineTimeline profile={selectedProfile} />

                    {/* Sub-tabs: Features vs Sessions vs History */}
                    <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
                      <div className="flex items-center justify-between border-b border-border bg-surface-muted/50 px-4 py-2">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setProfileSubTab('features')}
                            className={`rounded px-3 py-1 text-xs font-semibold transition ${
                              profileSubTab === 'features'
                                ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                                : 'text-muted hover:text-text-primary'
                            }`}
                          >
                            Feature Profiles ({selectedProfile.features.length})
                          </button>
                          <button
                            type="button"
                            onClick={() => setProfileSubTab('sessions')}
                            className={`rounded px-3 py-1 text-xs font-semibold transition ${
                              profileSubTab === 'sessions'
                                ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                                : 'text-muted hover:text-text-primary'
                            }`}
                          >
                            Profiled Sessions ({profileSessions.length})
                          </button>
                          <button
                            type="button"
                            onClick={() => setProfileSubTab('history')}
                            className={`rounded px-3 py-1 text-xs font-semibold transition ${
                              profileSubTab === 'history'
                                ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                                : 'text-muted hover:text-text-primary'
                            }`}
                          >
                            Version Lineage
                          </button>
                        </div>
                      </div>

                      <div className="p-0">
                        {profileSubTab === 'features' && (
                          <BaselineFeatureTable
                            features={selectedProfile.features}
                            searchQuery={searchQuery}
                          />
                        )}
                        {profileSubTab === 'sessions' && (
                          <BaselineSessionTable
                            sessions={profileSessions}
                            onSelectFingerprint={(fpId) => {
                              setSelectedFingerprintId(fpId);
                              setActiveTab('fingerprints');
                            }}
                          />
                        )}
                        {profileSubTab === 'history' && (
                          <div className="p-5">
                            <BaselineVersionHistory
                              currentBaseline={selectedProfile}
                              allBaselines={baselines}
                              onSelectVersion={(verId) => setSelectedBaselineId(verId)}
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: Session Fingerprints */}
            {activeTab === 'fingerprints' && (
              <div className="p-6">
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  <div className={`${selectedFingerprint ? 'lg:col-span-7' : 'lg:col-span-12'}`}>
                    <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-sm">
                      <div className="flex items-center justify-between border-b border-border bg-surface-muted/50 px-4 py-3">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-muted">
                          Generated Behavioral Session Fingerprints
                        </h3>
                        <span className="text-2xs font-mono text-muted">
                          {fingerprints.length} total fingerprints
                        </span>
                      </div>
                      <FingerprintTable
                        fingerprints={fingerprints}
                        selectedId={selectedFingerprintId}
                        onSelect={(id) => setSelectedFingerprintId(id)}
                        onCompareWith={(id) => {
                          setSelectedFingerprintId(id);
                          setActiveTab('compare_fingerprints');
                        }}
                      />
                    </div>
                  </div>

                  {/* Fingerprint Details Panel */}
                  {selectedFingerprint && (
                    <div className="lg:col-span-5 min-h-[500px]">
                      <FingerprintDetails
                        fingerprint={selectedFingerprint}
                        onClose={() => setSelectedFingerprintId(null)}
                        onCompare={() => {
                          setActiveTab('compare_fingerprints');
                        }}
                      />
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 3: Baseline vs Observed */}
            {activeTab === 'compare_baseline' && (
              <BaselineComparison
                baselines={baselines}
                fingerprints={fingerprints}
                initialBaselineId={selectedBaselineId ?? undefined}
                initialFingerprintId={selectedFingerprintId ?? undefined}
              />
            )}

            {/* TAB 4: Compare Fingerprints */}
            {activeTab === 'compare_fingerprints' && (
              <FingerprintComparison
                fingerprints={fingerprints}
                initialIdA={selectedFingerprintId ?? undefined}
              />
            )}
          </div>
        </div>
      )}

      {/* Build Baseline Dialog Modal */}
      <BuildBaselineModal
        isOpen={isBuildModalOpen}
        onClose={() => setIsBuildModalOpen(false)}
        onBuild={handleBuildBaseline}
        isBuilding={isBuilding}
        availableSessionCount={availableSessionCount}
      />
    </div>
  );
}
