import React from 'react';
import { History, ShieldAlert, ShieldCheck, Clock, Cpu, ArrowRight, RefreshCw } from 'lucide-react';
import { AnomalyAnalysisSummary } from '../../types/mlAnomaly';

interface AnomalyHistoryProps {
  analyses: AnomalyAnalysisSummary[];
  selectedId?: string;
  onSelect: (analysisId: string) => void;
  loading?: boolean;
  onRefresh?: () => void;
}

export const AnomalyHistory: React.FC<AnomalyHistoryProps> = ({
  analyses,
  selectedId,
  onSelect,
  loading = false,
  onRefresh,
}) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <History className="w-5 h-5 text-indigo-400" />
          <h3 className="font-semibold text-white text-base">Inference History</h3>
          <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full font-mono">
            {analyses.length}
          </span>
        </div>
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={loading}
            className="text-xs text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 transition flex items-center space-x-1"
            title="Refresh history"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        )}
      </div>

      {analyses.length === 0 ? (
        <div className="p-8 text-center text-slate-500">
          <Clock className="w-8 h-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No anomaly analyses recorded yet.</p>
          <p className="text-xs text-slate-600 mt-1">
            Run an anomaly evaluation on an active session to view history.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto max-h-[360px] overflow-y-auto divide-y divide-slate-800/60 scrollbar-thin scrollbar-thumb-slate-700">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider sticky top-0 z-10 backdrop-blur-sm border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4 font-medium">Session ID</th>
                <th className="py-2.5 px-4 font-medium">Classification</th>
                <th className="py-2.5 px-4 font-medium">Anomaly Score</th>
                <th className="py-2.5 px-4 font-medium">Features (Flagged / Total)</th>
                <th className="py-2.5 px-4 font-medium">Model / Version</th>
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40 font-mono">
              {analyses.map((analysis) => {
                const isSelected = selectedId === analysis.id;
                const isAnomalous = analysis.classification === 'ANOMALOUS';

                return (
                  <tr
                    key={analysis.id}
                    onClick={() => onSelect(analysis.id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-indigo-950/40 hover:bg-indigo-950/60 border-l-2 border-indigo-500'
                        : 'hover:bg-slate-800/50'
                    }`}
                  >
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      <div className="truncate max-w-[140px]" title={analysis.session_id}>
                        {analysis.session_id}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      {isAnomalous ? (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-sans font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                          <ShieldAlert className="w-3 h-3" />
                          <span>ANOMALOUS</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-sans font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          <ShieldCheck className="w-3 h-3" />
                          <span>NORMAL</span>
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`text-xs font-bold ${
                            analysis.display_score >= 70
                              ? 'text-rose-400'
                              : analysis.display_score >= 45
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {analysis.display_score.toFixed(1)}
                        </span>
                        <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              analysis.display_score >= 70
                                ? 'bg-rose-500'
                                : analysis.display_score >= 45
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(0, analysis.display_score))}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-slate-300">
                      <span className={analysis.features_anomalous > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                        {analysis.features_anomalous}
                      </span>
                      <span className="text-slate-500"> / {analysis.features_analyzed}</span>
                    </td>

                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      <div className="flex items-center space-x-1">
                        <Cpu className="w-3 h-3 text-slate-500" />
                        <span>v{analysis.model_version}</span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-slate-400 text-[11px] font-sans">
                      {new Date(analysis.analyzed_at).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelect(analysis.id);
                        }}
                        className={`text-[11px] px-2 py-1 rounded inline-flex items-center space-x-1 transition ${
                          isSelected
                            ? 'bg-indigo-600 text-white font-medium'
                            : 'bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white'
                        }`}
                      >
                        <span>Details</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
