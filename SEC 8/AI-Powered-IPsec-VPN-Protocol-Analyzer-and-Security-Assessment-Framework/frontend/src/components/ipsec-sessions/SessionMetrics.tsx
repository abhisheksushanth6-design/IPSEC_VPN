import { Activity, Cable, CircleDashed, CircleHelp, KeyRound, PowerOff } from 'lucide-react';

import { MetricCard } from '@/components/dashboard';
import type { DashboardMetric, SessionEngineStatus } from '@/types';

/** Counts come from the discovered set; without discovery they are unavailable, not zero. */
export function SessionMetrics({ status }: { status: SessionEngineStatus | null }) {
  const stats = status?.statistics ?? null;
  const source: DashboardMetric['source'] = stats ? 'backend' : 'unavailable';
  const metric = (id: string, label: string, value: number | null, icon: DashboardMetric['icon']): DashboardMetric => ({
    id, label, value, icon, source,
    status: stats ? undefined : 'NOT INITIALIZED',
    statusLabel: stats ? undefined : status?.packets_available ? 'NOT DISCOVERED' : 'NO PACKET DATA',
  });

  const metrics = [
    metric('total', 'Total Sessions', stats?.total ?? null, Cable),
    metric('active', 'Active Sessions', stats?.active ?? null, Activity),
    metric('established', 'Established Sessions', stats?.established ?? null, KeyRound),
    metric('negotiating', 'Negotiating Sessions', stats?.negotiating ?? null, CircleDashed),
    metric('terminated', 'Terminated Sessions', stats?.terminated ?? null, PowerOff),
    metric('unknown', 'Unknown Sessions', stats ? stats.unknown + stats.discovered : null, CircleHelp),
  ];

  return (
    <section aria-labelledby="session-metrics-heading">
      <h2 id="session-metrics-heading" className="sr-only">Session statistics</h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        {metrics.map((m) => <MetricCard key={m.id} metric={m} />)}
      </div>
    </section>
  );
}
