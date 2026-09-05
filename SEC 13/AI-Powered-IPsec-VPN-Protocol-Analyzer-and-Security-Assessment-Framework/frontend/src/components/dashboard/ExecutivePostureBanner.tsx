import { ShieldAlert, Info, Database, Server, Cpu } from 'lucide-react';
import type { SystemPosture } from '@/types';

interface ExecutivePostureBannerProps {
  posture: SystemPosture | null;
}

export function ExecutivePostureBanner({ posture }: ExecutivePostureBannerProps) {
  return (
    <div
      role="region"
      aria-label="Executive Security Posture"
      className="relative overflow-hidden rounded border border-border bg-surface/80 p-5 backdrop-blur-sm"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-start gap-3.5">
          <div className="rounded-lg bg-info/10 p-2.5 text-info">
            <Cpu className="h-5 w-5" aria-hidden />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold tracking-tight text-primary">
                Framework Security & Analytical Posture
              </h2>
              <span className="rounded bg-info/10 px-2 py-0.5 text-2xs font-medium text-info">
                Layer 13 Operations
              </span>
            </div>
            <p className="mt-1 text-xs text-secondary">
              Unified telemetry across protocol analysis, SA lifecycles, ML anomalies, and deterministic security rules.
            </p>
          </div>
        </div>

        {/* Operational status badges */}
        <div className="flex flex-wrap items-center gap-2.5 text-2xs">
          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Server className="h-3.5 w-3.5 text-success" aria-hidden />
            <span>Backend: <strong className="font-mono text-primary">{posture?.backend_status ?? 'OPERATIONAL'}</strong></span>
          </div>

          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Database className="h-3.5 w-3.5 text-info" aria-hidden />
            <span>SQLite: <strong className="font-mono text-primary">{posture?.database_status ?? 'CONNECTED'}</strong></span>
          </div>

          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Info className="h-3.5 w-3.5 text-warning" aria-hidden />
            <span>Initialized: <strong className="font-mono text-primary">{posture?.layers_initialized ?? 11}/14 Layers</strong></span>
          </div>
        </div>
      </div>

      {/* Layer 10 Strict Scope Notice */}
      <div className="mt-4 flex items-center gap-2 rounded border border-warning/20 bg-warning/5 px-3 py-2 text-xs text-warning">
        <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden />
        <span>
          <strong>Layer 10 (Risk Assessment & Decision Engine)</strong> is strictly{' '}
          <span className="font-mono font-semibold">NOT INITIALIZED</span>. Risk assessment is unavailable until Layer 10 is implemented. No artificial or calculated scores are displayed.
        </span>
      </div>
    </div>
  );
}
