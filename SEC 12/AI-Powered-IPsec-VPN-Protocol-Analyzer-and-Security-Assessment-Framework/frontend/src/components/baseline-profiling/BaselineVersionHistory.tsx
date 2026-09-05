import { GitCommit, History } from 'lucide-react';
import { BaselineActiveBadge } from './BaselineStatusBadge';
import type { BaselineSummary } from '@/types';

interface BaselineVersionHistoryProps {
  currentBaseline: BaselineSummary;
  allBaselines: BaselineSummary[];
  onSelectVersion: (id: string) => void;
}

export function BaselineVersionHistory({
  currentBaseline,
  allBaselines,
  onSelectVersion,
}: BaselineVersionHistoryProps) {
  // Find all baselines matching the same name lineage
  const versions = allBaselines
    .filter((b) => b.name === currentBaseline.name)
    .sort((a, b) => b.version - a.version);

  return (
    <div className="rounded-lg border border-border bg-surface p-5 space-y-3 shadow-sm">
      <div className="flex items-center gap-2 border-b border-border pb-2.5">
        <History className="h-4 w-4 text-cyan-400" />
        <h3 className="text-sm font-bold text-text-primary">
          Version Iteration Lineage ({versions.length} versions)
        </h3>
      </div>

      <div className="divide-y divide-border">
        {versions.map((ver) => {
          const isCurrent = ver.id === currentBaseline.id;
          return (
            <div
              key={ver.id}
              onClick={() => onSelectVersion(ver.id)}
              className={`flex items-center justify-between py-2.5 px-3 rounded cursor-pointer transition ${
                isCurrent ? 'bg-cyan-500/10 border border-cyan-500/30' : 'hover:bg-surface-muted/40'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <GitCommit className={`h-4 w-4 ${isCurrent ? 'text-cyan-400' : 'text-muted'}`} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-text-primary">
                      Version {ver.version}
                    </span>
                    <BaselineActiveBadge isActive={ver.is_active} />
                    {isCurrent && (
                      <span className="text-3xs rounded bg-surface-muted px-1.5 py-0.5 text-muted">
                        Inspecting
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-2xs text-muted">
                    {ver.id} · {ver.session_count} sessions · {ver.feature_count} features
                  </div>
                </div>
              </div>

              <div className="text-right font-mono text-2xs text-muted">
                {new Date(ver.created_at).toLocaleDateString()}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
