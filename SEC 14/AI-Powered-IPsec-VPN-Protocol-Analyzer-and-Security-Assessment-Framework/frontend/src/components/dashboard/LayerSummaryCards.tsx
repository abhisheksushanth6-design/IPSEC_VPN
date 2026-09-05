import { BrainCircuit, GitCompare, KeyRound, ShieldAlert, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { DashboardSummaryResponse } from '@/types';

interface LayerSummaryCardsProps {
  summary: DashboardSummaryResponse | null;
}

export function LayerSummaryCards({ summary }: LayerSummaryCardsProps) {
  const metrics = summary?.metrics;
  const mlStatus = summary?.ml_engine_status;
  const driftStatus = summary?.drift_engine_status;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {/* 1. Vulnerabilities (Layer 09) */}
      <article
        aria-labelledby="card-vuln-heading"
        className="flex flex-col justify-between rounded border border-border bg-surface p-4 transition-colors hover:border-border/80"
      >
        <div>
          <div className="flex items-start justify-between gap-3">
            <h3 id="card-vuln-heading" className="text-xs font-semibold text-primary">
              Security Vulnerabilities
            </h3>
            <ShieldAlert className="h-4 w-4 text-error shrink-0" aria-hidden />
          </div>
          <p className="mt-0.5 text-2xs text-muted">Layer 09 &middot; Deterministic Rules</p>

          <div className="mt-3 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-primary">
              {metrics ? metrics.vulnerabilities_total : 0}
            </span>
            <span className="text-2xs text-secondary">total findings</span>
          </div>

          <div className="mt-2.5 flex items-center gap-2 text-2xs">
            <span className="rounded bg-error/10 px-1.5 py-0.5 font-medium text-error">
              {metrics ? metrics.vulnerabilities_critical : 0} Critical
            </span>
            <span className="rounded bg-warning/10 px-1.5 py-0.5 font-medium text-warning">
              {metrics ? metrics.vulnerabilities_high : 0} High
            </span>
            <span className="rounded bg-info/10 px-1.5 py-0.5 font-medium text-info">
              {metrics ? metrics.vulnerabilities_medium : 0} Medium
            </span>
          </div>
        </div>

        <div className="mt-4 border-t border-border pt-2.5">
          <Link
            to="/vulnerabilities"
            className="inline-flex items-center gap-1 text-xs font-medium text-info hover:underline"
          >
            Review findings <ArrowRight className="h-3 w-3" aria-hidden />
          </Link>
        </div>
      </article>

      {/* 2. AI/ML Anomalies (Layer 08) */}
      <article
        aria-labelledby="card-ml-heading"
        className="flex flex-col justify-between rounded border border-border bg-surface p-4 transition-colors hover:border-border/80"
      >
        <div>
          <div className="flex items-start justify-between gap-3">
            <h3 id="card-ml-heading" className="text-xs font-semibold text-primary">
              AI / ML Anomalies
            </h3>
            <BrainCircuit className="h-4 w-4 text-warning shrink-0" aria-hidden />
          </div>
          <p className="mt-0.5 text-2xs text-muted">Layer 08 &middot; Unsupervised Model</p>

          <div className="mt-3 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-primary">
              {metrics ? metrics.ai_anomalies : 0}
            </span>
            <span className="text-2xs text-secondary">flagged sessions</span>
          </div>

          <p className="mt-2.5 text-2xs text-secondary">
            Model:{' '}
            <strong className="font-mono text-primary">
              {typeof mlStatus?.active_model_name === 'string'
                ? mlStatus.active_model_name
                : 'IsolationForest'}
            </strong>
          </p>
        </div>

        <div className="mt-4 border-t border-border pt-2.5">
          <Link
            to="/ai-anomalies"
            className="inline-flex items-center gap-1 text-xs font-medium text-info hover:underline"
          >
            Inspect anomalies <ArrowRight className="h-3 w-3" aria-hidden />
          </Link>
        </div>
      </article>

      {/* 3. Security Drift (Layer 07) */}
      <article
        aria-labelledby="card-drift-heading"
        className="flex flex-col justify-between rounded border border-border bg-surface p-4 transition-colors hover:border-border/80"
      >
        <div>
          <div className="flex items-start justify-between gap-3">
            <h3 id="card-drift-heading" className="text-xs font-semibold text-primary">
              Security Drift
            </h3>
            <GitCompare className="h-4 w-4 text-info shrink-0" aria-hidden />
          </div>
          <p className="mt-0.5 text-2xs text-muted">Layer 07 &middot; Baseline Comparison</p>

          <div className="mt-3 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-primary">
              {metrics ? metrics.drift_events : 0}
            </span>
            <span className="text-2xs text-secondary">drift events</span>
          </div>

          <p className="mt-2.5 text-2xs text-secondary">
            Analyses:{' '}
            <strong className="font-mono text-primary">
              {typeof driftStatus?.total_drift_analyses === 'number'
                ? driftStatus.total_drift_analyses
                : 0}
            </strong>
          </p>
        </div>

        <div className="mt-4 border-t border-border pt-2.5">
          <Link
            to="/security-drift"
            className="inline-flex items-center gap-1 text-xs font-medium text-info hover:underline"
          >
            Compare baselines <ArrowRight className="h-3 w-3" aria-hidden />
          </Link>
        </div>
      </article>

      {/* 4. Security Associations (Layer 04) */}
      <article
        aria-labelledby="card-sa-heading"
        className="flex flex-col justify-between rounded border border-border bg-surface p-4 transition-colors hover:border-border/80"
      >
        <div>
          <div className="flex items-start justify-between gap-3">
            <h3 id="card-sa-heading" className="text-xs font-semibold text-primary">
              SA Lifecycles
            </h3>
            <KeyRound className="h-4 w-4 text-success shrink-0" aria-hidden />
          </div>
          <p className="mt-0.5 text-2xs text-muted">Layer 04 &middot; State Machine</p>

          <div className="mt-3 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-primary">
              {metrics ? metrics.active_sas : 0}
            </span>
            <span className="text-2xs text-secondary">active SAs</span>
          </div>

          <p className="mt-2.5 text-2xs text-secondary">
            State:{' '}
            <strong className="font-mono text-primary">
              {metrics && metrics.active_sas > 0 ? 'ESTABLISHED' : 'NO SAs'}
            </strong>
          </p>
        </div>

        <div className="mt-4 border-t border-border pt-2.5">
          <Link
            to="/sa-lifecycle"
            className="inline-flex items-center gap-1 text-xs font-medium text-info hover:underline"
          >
            Track lifecycles <ArrowRight className="h-3 w-3" aria-hidden />
          </Link>
        </div>
      </article>
    </div>
  );
}
