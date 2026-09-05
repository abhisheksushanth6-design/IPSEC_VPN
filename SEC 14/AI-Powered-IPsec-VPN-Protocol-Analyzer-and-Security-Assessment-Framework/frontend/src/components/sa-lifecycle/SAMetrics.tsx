import { Activity, CircleDashed, KeyRound, Layers, PowerOff, ShieldCheck, XCircle } from 'lucide-react';

import { MetricCard } from '@/components/dashboard';
import type { DashboardMetric, SAEngineStatus } from '@/types';

export function SAMetrics({ status }: { status: SAEngineStatus | null }) {
  const s = status?.statistics ?? null;
  const m = (id: string, label: string, value: number | null, icon: DashboardMetric['icon']): DashboardMetric => ({
    id, label, value, icon, source: s ? 'backend' : 'unavailable', status: s ? undefined : 'NOT INITIALIZED',
    statusLabel: s ? undefined : status?.packets_available ? 'NOT ANALYZED' : 'NO PACKET DATA',
  });
  const metrics = [
    m('total', 'Total SAs', s?.total ?? null, Layers), m('ike', 'IKE SAs', s?.ike ?? null, KeyRound), m('child', 'Child SAs', s?.child ?? null, ShieldCheck),
    m('active', 'Active', s?.active ?? null, Activity), m('negotiating', 'Negotiating', s?.negotiating ?? null, CircleDashed),
    m('terminated', 'Terminated', s?.terminated ?? null, PowerOff), m('failed', 'Failed', s?.failed ?? null, XCircle),
  ];
  return (
    <section aria-labelledby="sa-metrics-heading">
      <h2 id="sa-metrics-heading" className="sr-only">SA statistics</h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">{metrics.map((x) => <MetricCard key={x.id} metric={x} />)}</div>
    </section>
  );
}
