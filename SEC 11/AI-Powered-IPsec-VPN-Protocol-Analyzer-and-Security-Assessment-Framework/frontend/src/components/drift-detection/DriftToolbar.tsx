import { Filter, History, Layers, Search, Sliders } from 'lucide-react';

export type DriftTabKey = 'features' | 'history' | 'config';

interface DriftToolbarProps {
  activeTab: DriftTabKey;
  onTabChange: (tab: DriftTabKey) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  categoryFilter: string;
  onCategoryChange: (cat: string) => void;
  driftFilter: string;
  onDriftFilterChange: (df: string) => void;
  severityFilter: string;
  onSeverityFilterChange: (sev: string) => void;
  categories: string[];
}

export function DriftToolbar({
  activeTab,
  onTabChange,
  searchQuery,
  onSearchChange,
  categoryFilter,
  onCategoryChange,
  driftFilter,
  onDriftFilterChange,
  severityFilter,
  onSeverityFilterChange,
  categories,
}: DriftToolbarProps) {
  return (
    <div className="flex flex-col gap-3 border-b border-border bg-surface px-6 py-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto">
          <button
            type="button"
            onClick={() => onTabChange('features')}
            className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === 'features'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-muted hover:bg-surface-muted hover:text-text-primary'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>Feature Drift Analysis</span>
          </button>

          <button
            type="button"
            onClick={() => onTabChange('history')}
            className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === 'history'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-muted hover:bg-surface-muted hover:text-text-primary'
            }`}
          >
            <History className="h-3.5 w-3.5" />
            <span>Drift History</span>
          </button>

          <button
            type="button"
            onClick={() => onTabChange('config')}
            className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === 'config'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-muted hover:bg-surface-muted hover:text-text-primary'
            }`}
          >
            <Sliders className="h-3.5 w-3.5" />
            <span>Threshold Config</span>
          </button>
        </div>

        {/* Search Bar */}
        {activeTab === 'features' && (
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search features or category..."
              className="w-full rounded-md border border-border bg-base pl-8 pr-3 py-1.5 text-xs text-text-primary placeholder:text-muted focus:border-cyan-500 focus:outline-none"
            />
          </div>
        )}
      </div>

      {/* Filter Row for Features Tab */}
      {activeTab === 'features' && (
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-border/40 text-2xs">
          <div className="flex items-center gap-1 text-muted">
            <Filter className="h-3 w-3" />
            <span>Filters:</span>
          </div>

          {/* Drift Status Filter */}
          <select
            value={driftFilter}
            onChange={(e) => onDriftFilterChange(e.target.value)}
            className="rounded border border-border bg-surface px-2 py-1 font-mono text-text-primary focus:border-cyan-500 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Drift States</option>
            <option value="DRIFTING">Drifting Only</option>
            <option value="NO_DRIFT">Within Baseline Only</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => onCategoryChange(e.target.value)}
            className="rounded border border-border bg-surface px-2 py-1 font-mono text-text-primary focus:border-cyan-500 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => onSeverityFilterChange(e.target.value)}
            className="rounded border border-border bg-surface px-2 py-1 font-mono text-text-primary focus:border-cyan-500 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="NONE">None</option>
            <option value="LOW">Low</option>
            <option value="MODERATE">Moderate</option>
            <option value="HIGH">High</option>
          </select>
        </div>
      )}
    </div>
  );
}
