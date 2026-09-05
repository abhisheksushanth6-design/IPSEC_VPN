import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity,
  Cpu,
  History,
  AlertTriangle,
} from 'lucide-react';
import {
  AIAnomalyHeader,
  ModelStatusCard,
  TrainingPanel,
  ModelTable,
  ModelDetails,
  InferencePanel,
  AnomalySummary,
  AnomalyFeatureTable,
  AnomalyExplanation,
  SignalComparison,
  AnomalyHistory,
  AnomalyTimeline,
  AnomalyFilters,
  AnomalyEvidence,
  AnomalyLineage,
  EmptyAnomalyState,
  TrainingProgress,
  TrainingDataset,
} from '../../components/ai-anomaly';
import { aiAnomalyService } from '../../services/aiAnomalyService';
import { baselineService } from '../../services/baselineService';
import { sessionService } from '../../services/sessionService';
import {
  AIAnomalyEngineStatus,
  MLModelSummary,
  MLModelDetail,
  AnomalyAnalysis,
  AnomalyAnalysisSummary,
  AnomalyFeatureContribution,
  TrainingDatasetDetail,
  AnomalyFilterOptions,
} from '../../types/mlAnomaly';
import { BaselineSummary } from '../../types';

export const AIAnomaliesPage: React.FC = () => {
  // Navigation & View State
  const [activeTab, setActiveTab] = useState<'inference' | 'history' | 'models'>('inference');

  // Engine Status & Data States
  const [engineStatus, setEngineStatus] = useState<AIAnomalyEngineStatus | null>(null);
  const [models, setModels] = useState<MLModelSummary[]>([]);
  const [selectedModel, setSelectedModel] = useState<MLModelDetail | null>(null);
  const [baselines, setBaselines] = useState<BaselineSummary[]>([]);
  const [sessions, setSessions] = useState<any[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [sessionIds, setSessionIds] = useState<string[]>([]);

  // Inference States
  const [currentAnalysis, setCurrentAnalysis] = useState<AnomalyAnalysis | null>(null);
  const [analyses, setAnalyses] = useState<AnomalyAnalysisSummary[]>([]);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | undefined>(undefined);

  // Modals & Evidence States
  const [selectedFeatureEvidence, setSelectedFeatureEvidence] = useState<AnomalyFeatureContribution | null>(null);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState<boolean>(false);
  const [trainingDatasetDetail, setTrainingDatasetDetail] = useState<TrainingDatasetDetail | null>(null);
  const [isDatasetModalOpen, setIsDatasetModalOpen] = useState<boolean>(false);

  // Filters State
  const [filters, setFilters] = useState<AnomalyFilterOptions>({
    classification: 'ALL',
    modelVersion: '',
    search: '',
  });

  // UI Loaders & Errors
  const [loading, setLoading] = useState<boolean>(true);
  const [inferenceLoading, setInferenceLoading] = useState<boolean>(false);
  const [trainingLoading, setTrainingLoading] = useState<boolean>(false);
  const [trainingError, setTrainingError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Fetch all initial data
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [statusRes, modelsRes, baselinesRes, sessionsRes, analysesRes] = await Promise.all([
        aiAnomalyService.getStatus().catch(() => null),
        aiAnomalyService.listModels().catch(() => []),
        baselineService.listBaselines().catch(() => []),
        sessionService.fetchSessions({ page: 1, pageSize: 50, sort: 'start_time', order: 'desc' }).catch(() => ({ items: [] })),
        aiAnomalyService.listAnalyses({ limit: 50 }).catch(() => []),
      ]);

      if (statusRes) {
        setEngineStatus(statusRes);
      }
      setModels(Array.isArray(modelsRes) ? modelsRes : []);
      setBaselines(Array.isArray(baselinesRes) ? baselinesRes : []);

      const sessionList = Array.isArray(sessionsRes?.items) ? sessionsRes.items : [];
      setSessions(sessionList);
      const sIds = sessionList.map((s: any) => s.id);
      setSessionIds(sIds);
      if (sessionList.length > 0 && sessionList[0]?.id) {
        setSelectedSessionId((prev) => prev || sessionList[0]!.id);
      }

      const aList = Array.isArray(analysesRes) ? analysesRes : [];
      setAnalyses(aList);

      const activeM = Array.isArray(modelsRes)
        ? modelsRes.find((m) => m.is_active) || modelsRes[0]
        : null;

      // Concurrently load details of active model and most recent analysis
      const [modelDetail, latestDetail] = await Promise.all([
        activeM ? aiAnomalyService.getModel(activeM.id).catch(() => null) : Promise.resolve(null),
        aList.length > 0 && aList[0]?.id
          ? aiAnomalyService.getAnalysis(aList[0]!.id).catch(() => null)
          : Promise.resolve(null),
      ]);

      if (modelDetail) setSelectedModel(modelDetail);
      if (latestDetail) {
        setCurrentAnalysis(latestDetail);
        setSelectedAnalysisId(latestDetail.id);
      }
    } catch (err: any) {
      console.error('Failed to load AI / ML engine data:', err);
      setError(err?.message || 'Failed to communicate with Layer 08 AI / ML Anomaly Service.');
    } finally {
      setLoading(false);
    }
  }, [currentAnalysis]);

  useEffect(() => {
    fetchData();
  }, []);

  // Handle Model Training
  const handleTrainModel = async (params: {
    baseline_id: string;
    name?: string;
    contamination?: number;
    minimum_training_samples?: number;
  }) => {
    try {
      setTrainingLoading(true);
      setTrainingError(null);

      const newModel = await aiAnomalyService.trainModel({
        baseline_id: params.baseline_id,
        name: params.name,
        minimum_training_samples: params.minimum_training_samples,
        configuration: params.contamination ? { contamination: params.contamination } : undefined,
      });

      setSelectedModel(newModel);
      // Refresh models & status
      const [statusRes, modelsRes] = await Promise.all([
        aiAnomalyService.getStatus().catch(() => null),
        aiAnomalyService.listModels().catch(() => []),
      ]);

      if (statusRes) setEngineStatus(statusRes);
      setModels(modelsRes);
      setActiveTab('inference');
    } catch (err: any) {
      console.error('Training failed:', err);
      setTrainingError(err?.message || 'Model training failed.');
    } finally {
      setTrainingLoading(false);
    }
  };

  // Handle Model Activation
  const handleActivateModel = async (modelId: string) => {
    try {
      await aiAnomalyService.activateModel(modelId);
      const [statusRes, modelsRes] = await Promise.all([
        aiAnomalyService.getStatus().catch(() => null),
        aiAnomalyService.listModels().catch(() => []),
      ]);
      if (statusRes) setEngineStatus(statusRes);
      setModels(modelsRes);

      const detail = await aiAnomalyService.getModel(modelId).catch(() => null);
      setSelectedModel(detail);
    } catch (err: any) {
      console.error('Failed to activate model:', err);
      setError(err?.message || 'Failed to activate model.');
    }
  };

  // Handle Anomaly Inference Run
  const handleRunInference = async (sessionId: string, modelId?: string) => {
    try {
      setInferenceLoading(true);
      setError(null);

      const result = await aiAnomalyService.analyzeSession({
        session_id: sessionId,
        model_id: modelId,
      });

      setCurrentAnalysis(result);
      setSelectedAnalysisId(result.id);

      // Refresh analyses list
      const analysesRes = await aiAnomalyService.listAnalyses({ limit: 50 }).catch(() => []);
      setAnalyses(analysesRes);
    } catch (err: any) {
      console.error('Inference run failed:', err);
      setError(err?.message || 'Anomaly inference failed for the specified session.');
    } finally {
      setInferenceLoading(false);
    }
  };

  // Handle Selecting Past Analysis
  const handleSelectAnalysis = async (analysisId: string) => {
    try {
      setSelectedAnalysisId(analysisId);
      const detail = await aiAnomalyService.getAnalysis(analysisId);
      setCurrentAnalysis(detail);
      setActiveTab('inference');
    } catch (err: any) {
      console.error('Failed to load analysis detail:', err);
    }
  };

  // Handle Inspect Feature Evidence
  const handleInspectFeature = (feature: AnomalyFeatureContribution) => {
    setSelectedFeatureEvidence(feature);
    setIsEvidenceModalOpen(true);
  };

  // Handle View Dataset
  const handleViewDataset = async (datasetId: string) => {
    try {
      const detail = await aiAnomalyService.getDataset(datasetId);
      setTrainingDatasetDetail(detail);
      setIsDatasetModalOpen(true);
    } catch (err: any) {
      console.error('Failed to fetch dataset details:', err);
    }
  };

  // Model Versions list for filters
  const modelVersions = useMemo(() => {
    const set = new Set<string>();
    analyses.forEach((a) => {
      if (a.model_version) set.add(a.model_version);
    });
    return Array.from(set);
  }, [analyses]);

  // Filtered Analyses
  const filteredAnalyses = useMemo(() => {
    return analyses.filter((item) => {
      if (filters.classification !== 'ALL' && item.classification !== filters.classification) {
        return false;
      }
      if (filters.modelVersion && item.model_version !== filters.modelVersion) {
        return false;
      }
      if (filters.search) {
        const query = filters.search.toLowerCase();
        const matchesSession = item.session_id.toLowerCase().includes(query);
        const matchesId = item.id.toLowerCase().includes(query);
        if (!matchesSession && !matchesId) return false;
      }
      return true;
    });
  }, [analyses, filters]);

  const activeModelSummary = engineStatus?.active_model || models.find((m) => m.is_active) || null;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 md:p-8 space-y-6">
      {/* Header Banner */}
      <AIAnomalyHeader
        status={engineStatus?.status || 'NOT INITIALIZED'}
        onRefresh={fetchData}
        loading={loading}
      />

      {/* Global Error Banner */}
      {error && (
        <div className="bg-rose-950/50 border border-rose-800 text-rose-300 px-4 py-3 rounded-xl flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-rose-400 hover:text-white text-xs underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Active Model Status Card */}
      <ModelStatusCard
        activeModel={activeModelSummary}
        totalModels={models.length}
        featureVersion={engineStatus?.feature_version || '1.0'}
        preprocessingVersion={engineStatus?.preprocessing_version || '1.0'}
        onTrainClick={() => setActiveTab('models')}
      />

      {/* Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('inference')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'inference'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Anomaly Evaluation</span>
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'history'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <History className="w-4 h-4" />
          <span>Inference History & Timeline</span>
          {analyses.length > 0 && (
            <span className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded-full text-[10px] font-mono">
              {analyses.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('models')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'models'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/20'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Model Registry & Training</span>
          {models.length > 0 && (
            <span className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded-full text-[10px] font-mono">
              {models.length}
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Inference & Evaluation */}
      {activeTab === 'inference' && (
        <div className="space-y-6">
          {/* Multi-Layer Pipeline Lineage */}
          <AnomalyLineage
            sessionId={currentAnalysis?.session_id}
            baselineId={currentAnalysis?.signal_comparison?.baseline_id || selectedModel?.baseline_id || undefined}
            driftAnalysisId={currentAnalysis?.signal_comparison?.drift_analysis_id || undefined}
            modelId={currentAnalysis?.model_id || activeModelSummary?.id}
          />

          {/* Inference Control Bar */}
          {activeModelSummary ? (
            <InferencePanel
              sessions={sessions}
              selectedSessionId={selectedSessionId}
              onSelectSession={setSelectedSessionId}
              activeModel={activeModelSummary}
              onRunInference={() => handleRunInference(selectedSessionId || '', activeModelSummary?.id)}
              analyzing={inferenceLoading}
            />
          ) : (
            <EmptyAnomalyState
              type="no-models"
              onAction={() => setActiveTab('models')}
              actionText="Go to Model Registry & Train"
            />
          )}

          {/* Active Analysis Results */}
          {currentAnalysis ? (
            <div className="space-y-6 animate-in fade-in duration-200">
              {/* Top Overview: Classification Banner, Score & Diagnostic Metadata */}
              <AnomalySummary analysis={currentAnalysis} />

              {/* 3-Signal Behavioral Comparison Panel */}
              <SignalComparison signals={currentAnalysis.signal_comparison} />

              {/* Explainable AI Finding Summary */}
              <AnomalyExplanation
                summary={currentAnalysis.explanation_summary}
                contributions={currentAnalysis.feature_contributions}
                isAnomalous={currentAnalysis.classification === 'ANOMALOUS'}
              />

              {/* Feature Contributions Table */}
              <AnomalyFeatureTable
                contributions={currentAnalysis.feature_contributions}
                onSelectFeature={handleInspectFeature}
              />
            </div>
          ) : activeModelSummary ? (
            <EmptyAnomalyState
              type="no-inference"
              onAction={() => {
                const targetSession = sessionIds[0];
                if (targetSession) {
                  handleRunInference(targetSession, activeModelSummary.id);
                }
              }}
              actionText={
                sessionIds.length > 0 && sessionIds[0]
                  ? `Run Inference on Session (${sessionIds[0].slice(0, 8)}...)`
                  : 'Awaiting Active IPsec Sessions'
              }
            />
          ) : null}
        </div>
      )}

      {/* Tab 2: Inference History & Timeline */}
      {activeTab === 'history' && (
        <div className="space-y-6">
          {/* Visual Timeline Strip */}
          <AnomalyTimeline
            analyses={analyses}
            selectedId={selectedAnalysisId}
            onSelect={handleSelectAnalysis}
          />

          {/* Filtering Bar */}
          <AnomalyFilters
            filters={filters}
            onChange={setFilters}
            modelVersions={modelVersions}
            totalCount={analyses.length}
            filteredCount={filteredAnalyses.length}
            onReset={() => setFilters({ classification: 'ALL', modelVersion: '', search: '' })}
          />

          {/* Tabular History */}
          {filteredAnalyses.length > 0 ? (
            <AnomalyHistory
              analyses={filteredAnalyses}
              selectedId={selectedAnalysisId}
              onSelect={handleSelectAnalysis}
              onRefresh={fetchData}
              loading={loading}
            />
          ) : (
            <EmptyAnomalyState
              type="no-results"
              onAction={() => setFilters({ classification: 'ALL', modelVersion: '', search: '' })}
              actionText="Clear Filter Filters"
            />
          )}
        </div>
      )}

      {/* Tab 3: Model Registry & Training */}
      {activeTab === 'models' && (
        <div className="space-y-6">
          {/* Training Progress Banner */}
          <TrainingProgress
            isTraining={trainingLoading}
            error={trainingError}
          />

          {/* Training Panel */}
          <TrainingPanel
            baselines={baselines}
            onTrain={handleTrainModel}
            training={trainingLoading}
          />

          {/* Model Registry Table */}
          <ModelTable
            models={models}
            selectedModelId={selectedModel?.id}
            onSelectModel={async (modelId) => {
              const detail = await aiAnomalyService.getModel(modelId).catch(() => null);
              setSelectedModel(detail);
            }}
            onActivateModel={handleActivateModel}
          />

          {/* Selected Model Details Inspector */}
          {selectedModel && (
            <ModelDetails
              model={selectedModel}
              onActivate={handleActivateModel}
              onViewDataset={handleViewDataset}
            />
          )}
        </div>
      )}

      {/* Statistical Feature Evidence Modal */}
      <AnomalyEvidence
        feature={selectedFeatureEvidence}
        isOpen={isEvidenceModalOpen}
        onClose={() => {
          setIsEvidenceModalOpen(false);
          setSelectedFeatureEvidence(null);
        }}
      />

      {/* Training Dataset Metadata Modal */}
      <TrainingDataset
        dataset={trainingDatasetDetail}
        isOpen={isDatasetModalOpen}
        onClose={() => {
          setIsDatasetModalOpen(false);
          setTrainingDatasetDetail(null);
        }}
      />
    </div>
  );
};

export default AIAnomaliesPage;
