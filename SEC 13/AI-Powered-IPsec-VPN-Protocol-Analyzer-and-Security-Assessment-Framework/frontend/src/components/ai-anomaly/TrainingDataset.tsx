import React from 'react';
import { X, Database, ListFilter, Hash, Cpu } from 'lucide-react';
import { TrainingDatasetDetail } from '../../types/mlAnomaly';

interface TrainingDatasetProps {
  dataset: TrainingDatasetDetail | null;
  isOpen: boolean;
  onClose: () => void;
}

export const TrainingDataset: React.FC<TrainingDatasetProps> = ({
  dataset,
  isOpen,
  onClose,
}) => {
  if (!isOpen || !dataset) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">Training Dataset Metadata</h3>
              <p className="text-xs text-slate-400 font-mono">Dataset ID: {dataset.id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300 scrollbar-thin scrollbar-thumb-slate-700">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Samples</span>
              <span className="text-white font-bold text-base">{dataset.sample_count}</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Features</span>
              <span className="text-white font-bold text-base">{dataset.feature_count}</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Feature Version</span>
              <span className="text-indigo-400 font-bold text-base">v{dataset.feature_version}</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Dataset Version</span>
              <span className="text-emerald-400 font-bold text-base">v{dataset.dataset_version}</span>
            </div>
          </div>

          {/* Baseline Reference */}
          <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
            <div>
              <div className="text-[11px] text-slate-400">Linked Baseline Profile</div>
              <div className="font-mono text-white text-xs font-semibold mt-0.5">
                {dataset.baseline_id}
              </div>
            </div>
            <div className="text-right">
              <div className="text-[11px] text-slate-400">Created At</div>
              <div className="font-mono text-slate-300 text-xs mt-0.5">
                {new Date(dataset.created_at).toLocaleString()}
              </div>
            </div>
          </div>

          {/* Included Sessions */}
          <div>
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center space-x-1.5">
              <ListFilter className="w-3.5 h-3.5 text-indigo-400" />
              <span>Training Sessions ({dataset.session_ids.length})</span>
            </h4>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 max-h-36 overflow-y-auto flex flex-wrap gap-1.5 font-mono text-[11px]">
              {dataset.session_ids.map((sId) => (
                <span
                  key={sId}
                  className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
                >
                  {sId}
                </span>
              ))}
            </div>
          </div>

          {/* Feature Names */}
          <div>
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center space-x-1.5">
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span>Feature Columns ({dataset.feature_names.length})</span>
            </h4>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 max-h-40 overflow-y-auto flex flex-wrap gap-1.5 font-mono text-[11px]">
              {dataset.feature_names.map((name) => (
                <span
                  key={name}
                  className="px-2 py-0.5 rounded bg-indigo-950/40 border border-indigo-900/50 text-indigo-300"
                >
                  {name}
                </span>
              ))}
            </div>
          </div>

          {/* Missing Data Summary */}
          {dataset.missing_data_summary && Object.keys(dataset.missing_data_summary).length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2 flex items-center space-x-1.5">
                <Hash className="w-3.5 h-3.5 text-amber-400" />
                <span>Imputed Missing Values (Median Strategy)</span>
              </h4>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 max-h-32 overflow-y-auto divide-y divide-slate-900 font-mono text-[11px]">
                {Object.entries(dataset.missing_data_summary).map(([fName, missingCount]) => (
                  <div key={fName} className="py-1 flex justify-between">
                    <span className="text-slate-400">{fName}</span>
                    <span className="text-amber-400 font-bold">{missingCount} imputed</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
