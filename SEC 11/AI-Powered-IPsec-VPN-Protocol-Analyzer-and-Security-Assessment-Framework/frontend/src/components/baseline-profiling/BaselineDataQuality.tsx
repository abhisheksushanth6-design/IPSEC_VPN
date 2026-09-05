import { AlertTriangle, CheckCircle, FileCheck, Shield } from 'lucide-react';
import { BaselineQualityBadge } from './BaselineStatusBadge';
import type { BaselineProfile } from '@/types';

interface BaselineDataQualityProps {
  profile: BaselineProfile;
}

export function BaselineDataQuality({ profile }: BaselineDataQualityProps) {
  const dq = profile.data_quality;
  const cov = profile.coverage;

  const completenessPct = Math.round((cov?.feature_completeness ?? 0) * 100);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Data Quality Card */}
      <div className="rounded-lg border border-border bg-surface p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-text-primary">Data Quality Audit</h3>
          </div>
          {dq && <BaselineQualityBadge rating={dq.quality_rating} />}
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="rounded border border-border bg-base p-3">
            <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
              <CheckCircle className="h-3 w-3 text-emerald-400" />
              Complete Sessions
            </span>
            <div className="font-mono text-lg font-bold text-emerald-400 mt-1">
              {dq?.complete_sessions ?? 0}
            </div>
            <p className="text-3xs text-muted mt-0.5">All features observable</p>
          </div>

          <div className="rounded border border-border bg-base p-3">
            <span className="text-2xs uppercase tracking-wider text-muted flex items-center gap-1">
              <AlertTriangle className="h-3 w-3 text-amber-400" />
              Partial Sessions
            </span>
            <div className="font-mono text-lg font-bold text-amber-400 mt-1">
              {dq?.partial_sessions ?? 0}
            </div>
            <p className="text-3xs text-muted mt-0.5">Missing some protocol fields</p>
          </div>

          <div className="rounded border border-border bg-base p-3">
            <span className="text-2xs uppercase tracking-wider text-muted">
              Missing Data Features
            </span>
            <div className="font-mono text-lg font-bold text-text-primary mt-1">
              {dq?.missing_data_features ?? 0}
            </div>
            <p className="text-3xs text-muted mt-0.5">Features lacking full data</p>
          </div>

          <div className="rounded border border-border bg-base p-3">
            <span className="text-2xs uppercase tracking-wider text-muted">
              Invalid Records
            </span>
            <div className="font-mono text-lg font-bold text-text-primary mt-1">
              {dq?.invalid_records ?? 0}
            </div>
            <p className="text-3xs text-muted mt-0.5">Malformed or dropped rows</p>
          </div>
        </div>
      </div>

      {/* Coverage & Completeness Card */}
      <div className="rounded-lg border border-border bg-surface p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2">
            <FileCheck className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-text-primary">Feature Coverage & Completeness</h3>
          </div>
          <span className="font-mono text-xs font-semibold text-cyan-400">
            {completenessPct}% Overall
          </span>
        </div>

        <div className="space-y-3 text-xs">
          <div className="space-y-1.5">
            <div className="flex justify-between text-2xs">
              <span className="text-muted">Profile Feature Completeness</span>
              <span className="font-mono font-semibold text-text-primary">{completenessPct}%</span>
            </div>
            <div className="h-2 w-full rounded-full bg-surface-muted overflow-hidden border border-border">
              <div
                className={`h-full rounded-full transition-all ${
                  completenessPct >= 90
                    ? 'bg-emerald-400'
                    : completenessPct >= 60
                    ? 'bg-amber-400'
                    : 'bg-rose-400'
                }`}
                style={{ width: `${completenessPct}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-2 text-center">
            <div className="rounded border border-border bg-base p-2">
              <div className="text-3xs uppercase tracking-wider text-muted">Profiled</div>
              <div className="font-mono text-sm font-bold text-text-primary mt-0.5">
                {cov?.features_profiled ?? 0}
              </div>
            </div>

            <div className="rounded border border-border bg-base p-2">
              <div className="text-3xs uppercase tracking-wider text-muted">Available</div>
              <div className="font-mono text-sm font-bold text-emerald-400 mt-0.5">
                {cov?.features_available ?? 0}
              </div>
            </div>

            <div className="rounded border border-border bg-base p-2">
              <div className="text-3xs uppercase tracking-wider text-muted">Missing</div>
              <div className="font-mono text-sm font-bold text-muted mt-0.5">
                {cov?.features_missing ?? 0}
              </div>
            </div>
          </div>

          <div className="text-2xs text-muted pt-2 border-t border-border">
            Contributing observation window: {cov?.sessions_included.length ?? 0} session(s)
          </div>
        </div>
      </div>
    </div>
  );
}
