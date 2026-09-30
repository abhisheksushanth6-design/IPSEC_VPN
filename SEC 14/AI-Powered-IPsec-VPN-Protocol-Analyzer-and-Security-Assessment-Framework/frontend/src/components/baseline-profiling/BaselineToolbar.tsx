import { Database, Fingerprint, GitCompare, Layers, Search } from 'lucide-react';

export type BaselineTabKey =
  | 'baselines'
  | 'fingerprints'
  | 'compare_fingerprints'
  | 'compare_baseline';

interface BaselineToolbarProps {
  activeTab: BaselineTabKey;
  onTabChange: (tab: BaselineTabKey) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  baselinesCount: number;
  fingerprintsCount: number;
}

export function BaselineToolbar({
  activeTab,
  onTabChange,
  searchQuery,
  onSearchChange,
  baselinesCount,
  fingerprintsCount,
}: BaselineToolbarProps) {
  const tabs = [
    {
      key: 'fingerprints' as BaselineTabKey,
      label: 'Session Fingerprints',
      count: fingerprintsCount,
      icon: Fingerprint,
    },
    {
      key: 'compare_fingerprints' as BaselineTabKey,
      label: 'Compare Fingerprints',
      icon: GitCompare,
    },
    {
      key: 'baselines' as BaselineTabKey,
      label: 'Statistical Profiles',
      count: baselinesCount,
      icon: Database,
    },
    {
      key: 'compare_baseline' as BaselineTabKey,
      label: 'Profile vs Observed',
      icon: Layers,
    },
  ];

  return (
    <div className="flex flex-col gap-3 border-b border-border bg-surface px-6 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex flex-wrap items-center gap-1.5">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => onTabChange(tab.key)}
              className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium transition ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-muted hover:bg-surface-muted hover:text-text-primary border border-transparent'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span
                  className={`rounded-full px-1.5 py-0.2 text-2xs font-mono ${
                    isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-surface-muted text-muted'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="relative min-w-[220px] max-w-xs">
        <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter features or IDs..."
          className="w-full rounded-md border border-border bg-base pl-8 pr-3 py-1.5 text-xs text-text-primary placeholder:text-muted focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
        />
      </div>
    </div>
  );
}
