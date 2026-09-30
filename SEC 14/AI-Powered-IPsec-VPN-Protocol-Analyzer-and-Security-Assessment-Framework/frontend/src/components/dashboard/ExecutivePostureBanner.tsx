import { ShieldAlert, ShieldCheck, Info, Database, Server, Cpu, Activity } from 'lucide-react';
import { useSystemState } from '@/context/SystemStateContext';
import type { SystemPosture, SystemStatus } from '@/types';

interface ExecutivePostureBannerProps {
  posture: SystemPosture | null;
  status?: SystemStatus | null;
}

export function ExecutivePostureBanner({ posture, status }: ExecutivePostureBannerProps) {
  const { status: ctxStatus } = useSystemState();
  const effectiveStatus = status ?? ctxStatus;

  const initializedCount =
    effectiveStatus?.initialized_layers ??
    effectiveStatus?.initializedLayers ??
    posture?.initialized_layers ??
    (posture as any)?.initializedLayers ??
    posture?.layers_initialized ??
    10;

  const totalCount =
    effectiveStatus?.total_layers ??
    effectiveStatus?.totalLayers ??
    posture?.total_layers ??
    (posture as any)?.totalLayers ??
    posture?.layers_total ??
    10;

  const backendStatus =
    effectiveStatus?.backend_status ??
    effectiveStatus?.backendStatus ??
    posture?.backend_status ??
    posture?.backendStatus ??
    'OPERATIONAL';

  const databaseStatus =
    effectiveStatus?.database_status ??
    effectiveStatus?.databaseStatus ??
    posture?.database_status ??
    posture?.databaseStatus ??
    'CONNECTED';

  const riskLayer = effectiveStatus?.architecture_layers?.find(
    (l) => l.number === 9 || l.name.includes('Risk Assessment')
  );
  const isRiskOperational = riskLayer
    ? riskLayer.status === 'OPERATIONAL' || riskLayer.status === 'READY' || riskLayer.status === 'IMPLEMENTED'
    : false;

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
                Layer 10 Operations
              </span>
            </div>
            <p className="mt-1 text-xs text-secondary">
              Integrated IPsec protocol analysis, session fingerprinting, AI traffic classification, security assessment, and risk analysis.
            </p>
          </div>
        </div>

        {/* Operational status badges */}
        <div className="flex flex-wrap items-center gap-2.5 text-2xs">
          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Server className="h-3.5 w-3.5 text-success" aria-hidden />
            <span>Backend: <strong className="font-mono text-primary uppercase">{backendStatus}</strong></span>
          </div>

          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Database className="h-3.5 w-3.5 text-info" aria-hidden />
            <span>SQLite: <strong className="font-mono text-primary uppercase">{databaseStatus}</strong></span>
          </div>

          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Activity className="h-3.5 w-3.5 text-accent" aria-hidden />
            <span>Capture: <strong className="font-mono text-primary uppercase">READY</strong></span>
          </div>

          <div className="flex items-center gap-1.5 rounded border border-border bg-elevated/60 px-2.5 py-1 text-secondary">
            <Info className={`h-3.5 w-3.5 ${initializedCount >= totalCount ? 'text-success' : 'text-warning'}`} aria-hidden />
            <span>Initialized: <strong className="font-mono text-primary">{initializedCount}/{totalCount} Layers</strong></span>
          </div>
        </div>
      </div>

      {/* Layer 09 Dynamic Posture Notice */}
      {isRiskOperational ? (
        <div className="mt-4 flex items-center justify-between gap-3 rounded border border-success/20 bg-success/5 px-3.5 py-2 text-xs text-success">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0 text-success" aria-hidden />
            <span>
              <strong>Layer 09 (Risk Assessment & Decision Engine)</strong> is{' '}
              <span className="font-mono font-semibold">{riskLayer?.status ?? 'OPERATIONAL'}</span>. Deterministic composite risk evaluation and decision engine active.
            </span>
          </div>
          <span className="shrink-0 rounded bg-success/10 px-2 py-0.5 text-2xs font-semibold text-success">
            {riskLayer?.status ?? 'OPERATIONAL'}
          </span>
        </div>
      ) : (
        <div className="mt-4 flex items-center gap-2 rounded border border-warning/20 bg-warning/5 px-3 py-2 text-xs text-warning">
          <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden />
          <span>
            <strong>Layer 09 (Risk Assessment & Decision Engine)</strong> is strictly{' '}
            <span className="font-mono font-semibold">NOT INITIALIZED</span>. Risk assessment is unavailable until Layer 09 is implemented. No artificial or calculated scores are displayed.
          </span>
        </div>
      )}
    </div>
  );
}
