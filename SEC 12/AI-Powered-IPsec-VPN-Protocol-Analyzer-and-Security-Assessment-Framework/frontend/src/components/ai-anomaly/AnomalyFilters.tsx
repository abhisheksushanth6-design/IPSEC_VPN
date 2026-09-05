import React from 'react';
import { Search, Filter, RotateCcw, ShieldCheck, ShieldAlert, Cpu } from 'lucide-react';
import { AnomalyFilterOptions } from '../../types/mlAnomaly';

interface AnomalyFiltersProps {
  filters: AnomalyFilterOptions;
  onChange: (filters: AnomalyFilterOptions) => void;
  modelVersions: string[];
  totalCount: number;
  filteredCount: number;
  onReset?: () => void;
}

export const AnomalyFilters: React.FC<AnomalyFiltersProps> = ({
  filters,
  onChange,
  modelVersions,
  totalCount,
  filteredCount,
  onReset,
}) => {
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange({ ...filters, search: e.target.value });
  };

  const handleClassificationChange = (classification: 'ALL' | 'NORMAL' | 'ANOMALOUS') => {
    onChange({ ...filters, classification });
  };

  const handleModelVersionChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onChange({ ...filters, modelVersion: e.target.value });
  };

  const isFiltered =
    filters.search !== '' ||
    filters.classification !== 'ALL' ||
    filters.modelVersion !== '';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Left: Search input */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={filters.search}
            onChange={handleSearchChange}
            placeholder="Search by session ID or analysis ID..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
          />
        </div>

        {/* Middle: Classification filter buttons */}
        <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          <button
            onClick={() => handleClassificationChange('ALL')}
            className={`px-3 py-1.5 rounded font-medium transition ${
              filters.classification === 'ALL'
                ? 'bg-indigo-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Inferences
          </button>
          <button
            onClick={() => handleClassificationChange('NORMAL')}
            className={`px-3 py-1.5 rounded font-medium transition flex items-center space-x-1 ${
              filters.classification === 'NORMAL'
                ? 'bg-emerald-600 text-white'
                : 'text-slate-400 hover:text-emerald-400'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Normal</span>
          </button>
          <button
            onClick={() => handleClassificationChange('ANOMALOUS')}
            className={`px-3 py-1.5 rounded font-medium transition flex items-center space-x-1 ${
              filters.classification === 'ANOMALOUS'
                ? 'bg-rose-600 text-white'
                : 'text-slate-400 hover:text-rose-400'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Anomalous</span>
          </button>
        </div>

        {/* Right: Model version filter */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1.5 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={filters.modelVersion}
              onChange={handleModelVersionChange}
              className="bg-transparent border-none focus:outline-none text-xs text-slate-300 font-mono cursor-pointer"
            >
              <option value="" className="bg-slate-900 text-white">
                All Model Versions
              </option>
              {modelVersions.map((v) => (
                <option key={v} value={v} className="bg-slate-900 text-white">
                  v{v}
                </option>
              ))}
            </select>
          </div>

          {/* Reset button if filtered */}
          {isFiltered && onReset && (
            <button
              onClick={onReset}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded-lg transition"
              title="Reset filters"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Filter status row */}
      <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500">
        <div className="flex items-center space-x-1.5">
          <Filter className="w-3 h-3" />
          <span>
            Showing <strong className="text-slate-300 font-mono">{filteredCount}</strong> of{' '}
            <strong className="text-slate-300 font-mono">{totalCount}</strong> inferences
          </span>
        </div>
        {isFiltered && (
          <span className="text-indigo-400 italic">Filter active</span>
        )}
      </div>
    </div>
  );
};
