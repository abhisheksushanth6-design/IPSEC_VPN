import { Database, Fingerprint, Layers, ShieldCheck, Tag, Users } from 'lucide-react';
import type { BaselineEngineStatus } from '@/types';

interface BaselineSummaryProps {
  status: BaselineEngineStatus | null;
}

export function BaselineSummary({ status }: BaselineSummaryProps) {
  if (!status) return null;

  const cards = [
    {
      label: 'Stored Baselines',
      value: status.total_baselines,
      subtext: status.total_baselines === 1 ? '1 profile configured' : `${status.total_baselines} profiles configured`,
      icon: Database,
      tone: 'text-cyan-400',
      bgTone: 'bg-cyan-500/10 border-cyan-500/20',
    },
    {
      label: 'Active Reference',
      value: status.active_baseline_name ?? 'None Active',
      subtext: status.active_baseline_id ? `ID: ${status.active_baseline_id}` : 'No active reference profile',
      icon: ShieldCheck,
      tone: status.active_baseline_id ? 'text-emerald-400' : 'text-muted',
      bgTone: status.active_baseline_id ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-surface-muted border-border',
      isText: true,
    },
    {
      label: 'Profiled Sessions',
      value: status.total_sessions_profiled,
      subtext: 'Distinct VPN sessions contributing',
      icon: Users,
      tone: 'text-indigo-400',
      bgTone: 'bg-indigo-500/10 border-indigo-500/20',
    },
    {
      label: 'Stored Fingerprints',
      value: status.total_fingerprints,
      subtext: 'Deterministic SHA-256 session identities',
      icon: Fingerprint,
      tone: 'text-sky-400',
      bgTone: 'bg-sky-500/10 border-sky-500/20',
    },
    {
      label: 'Profiled Features',
      value: status.total_features_profiled,
      subtext: 'Across traffic, timing, protocol & SA',
      icon: Layers,
      tone: 'text-teal-400',
      bgTone: 'bg-teal-500/10 border-teal-500/20',
    },
    {
      label: 'Feature Version',
      value: `v${status.feature_version}`,
      subtext: 'Strict schema specification',
      icon: Tag,
      tone: 'text-purple-400',
      bgTone: 'bg-purple-500/10 border-purple-500/20',
      isText: true,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 p-6 sm:grid-cols-3 xl:grid-cols-6">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className="flex flex-col justify-between rounded-lg border border-border bg-surface p-3.5 shadow-sm transition hover:border-border-strong"
          >
            <div className="flex items-center justify-between">
              <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
                {card.label}
              </span>
              <div className={`flex h-7 w-7 items-center justify-center rounded-md border ${card.bgTone}`}>
                <Icon className={`h-3.5 w-3.5 ${card.tone}`} />
              </div>
            </div>
            <div className="mt-2.5">
              <div
                className={`font-mono font-bold tracking-tight ${card.tone} ${
                  card.isText ? 'truncate text-sm' : 'text-xl'
                }`}
                title={card.isText ? String(card.value) : undefined}
              >
                {card.value}
              </div>
              <p className="mt-1 truncate text-2xs text-muted" title={card.subtext}>
                {card.subtext}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
