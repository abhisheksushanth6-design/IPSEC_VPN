import React from 'react';
import { Activity, ShieldAlert, ShieldCheck, Clock } from 'lucide-react';
import { AnomalyAnalysisSummary } from '../../types/mlAnomaly';

interface AnomalyTimelineProps {
  analyses: AnomalyAnalysisSummary[];
  selectedId?: string;
  onSelect: (analysisId: string) => void;
}

export const AnomalyTimeline: React.FC<AnomalyTimelineProps> = ({
  analyses,
  selectedId,
  onSelect,
}) => {
  // Sort chronologically ascending for timeline
  const sortedAnalyses = [...analyses].sort(
    (a, b) => new Date(a.analyzed_at).getTime() - new Date(b.analyzed_at).getTime()
  );

  const total = analyses.length;
  const anomalousCount = analyses.filter((a) => a.classification === 'ANOMALOUS').length;
  const normalCount = total - anomalousCount;
  const anomalyRate = total > 0 ? ((anomalousCount / total) * 100).toFixed(1) : '0.0';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-indigo-400" />
          <h3 className="font-semibold text-white text-base">Inference Timeline</h3>
        </div>

        <div className="flex items-center space-x-4 text-xs font-mono">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
            <span className="text-slate-400">Normal:</span>
            <span className="text-emerald-400 font-bold">{normalCount}</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
            <span className="text-slate-400">Anomalous:</span>
            <span className="text-rose-400 font-bold">{anomalousCount}</span>
          </div>
          <div className="flex items-center space-x-1.5 border-l border-slate-800 pl-3">
            <span className="text-slate-400">Anomaly Rate:</span>
            <span className={`font-bold ${anomalousCount > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
              {anomalyRate}%
            </span>
          </div>
        </div>
      </div>

      {sortedAnalyses.length === 0 ? (
        <div className="py-8 text-center text-slate-500 text-xs">
          No sequential anomaly events recorded yet.
        </div>
      ) : (
        <div>
          {/* Scrollable timeline strip */}
          <div className="relative pt-2 pb-4 overflow-x-auto scrollbar-thin scrollbar-thumb-slate-700">
            {/* Horizontal timeline connector bar */}
            <div className="absolute left-4 right-4 top-7 h-0.5 bg-slate-800 -z-0" />

            <div className="flex items-center space-x-6 min-w-max px-2 relative z-10">
              {sortedAnalyses.map((analysis) => {
                const isSelected = selectedId === analysis.id;
                const isAnomalous = analysis.classification === 'ANOMALOUS';
                const timeStr = new Date(analysis.analyzed_at).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                });

                return (
                  <div
                    key={analysis.id}
                    onClick={() => onSelect(analysis.id)}
                    className={`flex flex-col items-center cursor-pointer group transition-all transform hover:-translate-y-0.5 ${
                      isSelected ? 'scale-105' : ''
                    }`}
                  >
                    {/* Timestamp label */}
                    <div className="flex items-center space-x-1 text-[10px] text-slate-500 font-mono mb-1.5 group-hover:text-slate-300">
                      <Clock className="w-2.5 h-2.5" />
                      <span>{timeStr}</span>
                    </div>

                    {/* Node marker */}
                    <div
                      className={`w-9 h-9 rounded-full flex items-center justify-center transition shadow-md ${
                        isAnomalous
                          ? isSelected
                            ? 'bg-rose-500 text-white ring-4 ring-rose-500/30'
                            : 'bg-rose-950/80 border border-rose-500 text-rose-400 hover:bg-rose-900/60'
                          : isSelected
                          ? 'bg-emerald-500 text-white ring-4 ring-emerald-500/30'
                          : 'bg-emerald-950/80 border border-emerald-500 text-emerald-400 hover:bg-emerald-900/60'
                      }`}
                      title={`Session: ${analysis.session_id} | Score: ${analysis.display_score.toFixed(1)}`}
                    >
                      {isAnomalous ? (
                        <ShieldAlert className="w-4 h-4" />
                      ) : (
                        <ShieldCheck className="w-4 h-4" />
                      )}
                    </div>

                    {/* Score badge */}
                    <div className="mt-1.5 text-center">
                      <span
                        className={`text-[11px] font-mono font-bold px-1.5 py-0.5 rounded ${
                          isAnomalous
                            ? 'bg-rose-500/20 text-rose-300'
                            : 'bg-emerald-500/20 text-emerald-300'
                        }`}
                      >
                        {analysis.display_score.toFixed(0)}
                      </span>
                    </div>

                    {/* Truncated session ID */}
                    <div className="mt-1 text-[10px] text-slate-400 font-mono truncate max-w-[80px]">
                      {analysis.session_id.substring(0, 10)}...
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
