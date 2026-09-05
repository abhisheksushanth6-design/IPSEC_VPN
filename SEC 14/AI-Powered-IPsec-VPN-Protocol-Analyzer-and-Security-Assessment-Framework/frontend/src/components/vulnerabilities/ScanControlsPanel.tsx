import { useState } from 'react';
import { Play, Zap, CheckCircle2, Clock } from 'lucide-react';
import type { AnalyzeResponse } from '@/types';

interface ScanControlsPanelProps {
  onRunScan: (force: boolean) => Promise<AnalyzeResponse | null>;
  scanning?: boolean;
  lastScanResult?: AnalyzeResponse | null;
}

export function ScanControlsPanel({
  onRunScan,
  scanning = false,
  lastScanResult,
}: ScanControlsPanelProps) {
  const [forceReevaluation, setForceReevaluation] = useState<boolean>(false);

  const handleScanClick = async () => {
    await onRunScan(forceReevaluation);
  };

  return (
    <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-text-secondary flex items-center gap-1.5">
            <Zap className="h-3.5 w-3.5 text-rose-400" />
            Security Rule Evaluation Engine
          </h3>
          <p className="text-xs text-text-muted mt-0.5">
            Trigger deterministic rule evaluation over all captured protocol artifacts and active states.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={forceReevaluation}
              onChange={(e) => setForceReevaluation(e.target.checked)}
              className="rounded border-border text-rose-600 focus:ring-rose-500"
            />
            <span>Force Re-evaluation</span>
          </label>

          <button
            onClick={handleScanClick}
            disabled={scanning}
            className="flex items-center gap-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white px-3 py-1.5 text-xs font-semibold shadow transition disabled:opacity-50"
          >
            <Play className={`h-3.5 w-3.5 ${scanning ? 'animate-pulse' : ''}`} />
            <span>{scanning ? 'Running Evaluation...' : 'Evaluate Rules'}</span>
          </button>
        </div>
      </div>

      {lastScanResult && (
        <div className="flex flex-wrap items-center gap-4 rounded bg-surface-subtle p-2.5 border border-border/60 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>Evaluation Complete</span>
          </div>

          <div className="text-text-secondary">
            Rules: <span className="text-text-primary font-semibold">{lastScanResult.evaluated_rules}</span>
          </div>

          <div className="text-text-secondary">
            New: <span className="text-rose-400 font-semibold">{lastScanResult.new_findings}</span>
          </div>

          <div className="text-text-secondary">
            Updated: <span className="text-amber-400 font-semibold">{lastScanResult.updated_findings}</span>
          </div>

          <div className="text-text-secondary">
            Active Total: <span className="text-cyan-400 font-semibold">{lastScanResult.total_active_findings}</span>
          </div>

          <div className="flex items-center gap-1 text-text-muted ml-auto">
            <Clock className="h-3 w-3" />
            <span>{lastScanResult.duration_ms.toFixed(1)}ms</span>
          </div>
        </div>
      )}
    </div>
  );
}
