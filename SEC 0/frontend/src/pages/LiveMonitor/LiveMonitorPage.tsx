import { useCallback, useState } from 'react';

import { ChartCard, MetricCard, SecurityEventStream, TrafficTimelineChart } from '@/components/dashboard';
import { PageContainer } from '@/components/layout';
import {
  MonitorBanner,
  MonitorControlBar,
  MonitorFilters,
  PacketDetails,
  PacketStream,
  RealtimeStatus,
  SADetails,
  SecurityAssociationPanel,
  SessionDetails,
  SystemActivity,
  TrafficSummary,
  VPNSessionPanel,
} from '@/components/live-monitor';
import { PageHeader } from '@/components/ui';
import { useSystemState } from '@/context/SystemStateContext';
import { useLiveMonitorData, useRealtime } from '@/hooks';
import type { Packet, PacketSummary, MonitorSecurityAssociation, VPNSession } from '@/types';

/**
 * Live Monitor. Connects to the real /ws/events channel and reports its true
 * state; every capture, session and analysis figure is NOT INITIALIZED
 * because the engines that produce them do not exist yet.
 */
export function LiveMonitorPage() {
  const { state, status, refresh } = useSystemState();
  const data = useLiveMonitorData();
  const realtime = useRealtime();

  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [selectedSession, setSelectedSession] = useState<VPNSession | null>(null);
  const [selectedSA, setSelectedSA] = useState<MonitorSecurityAssociation | null>(null);

  const selectPacket = useCallback(
    (packet: PacketSummary) => setSelectedPacket((c) => (c?.id === packet.id ? null : (packet as Packet))),
    [],
  );
  const selectSession = useCallback(
    (session: VPNSession) => setSelectedSession((c) => (c?.id === session.id ? null : session)),
    [],
  );
  const selectSA = useCallback(
    (sa: MonitorSecurityAssociation) => setSelectedSA((c) => (c?.id === sa.id ? null : sa)),
    [],
  );

  const dataAvailable =
    data.packets !== null || data.sessions !== null || data.associations !== null || data.events !== null;

  return (
    <PageContainer>
      <PageHeader
        title="Live Monitor"
        description="Real-time visibility into IPsec VPN traffic, sessions, security events, and system activity."
        status="NOT INITIALIZED"
        statusLabel="MONITORING NOT INITIALIZED"
        breadcrumbs={[{ label: 'Monitoring' }, { label: 'Live Monitor' }]}
      />

      <MonitorBanner />

      <MonitorControlBar
        interfaces={data.interfaces}
        captureState={data.captureState}
        applicationMode={state === 'ready' ? status?.application_mode ?? null : null}
        refreshing={state === 'loading'}
        onRefresh={refresh}
      />

      <RealtimeStatus
        state={realtime.connectionState}
        detail={realtime.connectionDetail}
        onRetry={realtime.retry}
      />

      <section aria-labelledby="monitor-metrics-heading">
        <h2 id="monitor-metrics-heading" className="sr-only">Monitoring metrics</h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {data.metrics.map((metric) => (
            <MetricCard key={metric.id} metric={metric} />
          ))}
        </div>
      </section>

      <MonitorFilters dataAvailable={dataAvailable} />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <PacketStream packets={data.packets} selectedId={selectedPacket?.id ?? null} onSelect={selectPacket} />
        <PacketDetails packet={selectedPacket} onClose={() => setSelectedPacket(null)} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <ChartCard title="Traffic Timeline" description="Packets observed per interval." source="Layer 02 · 03">
          <TrafficTimelineChart data={data.traffic} />
        </ChartCard>
        <TrafficSummary ipsecBreakdown={data.ipsecBreakdown} packetRate={data.packetRate} bandwidth={data.bandwidth} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <VPNSessionPanel sessions={data.sessions} selectedId={selectedSession?.id ?? null} onSelect={selectSession} />
        <SessionDetails session={selectedSession} onClose={() => setSelectedSession(null)} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <SecurityAssociationPanel associations={data.associations} selectedId={selectedSA?.id ?? null} onSelect={selectSA} />
        <SADetails association={selectedSA} onClose={() => setSelectedSA(null)} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <SecurityEventStream
          events={data.events}
          title="Security Event Stream"
          description="Session, negotiation, drift, anomaly, vulnerability and risk events."
        />
        <SystemActivity activity={realtime.activity} />
      </div>
    </PageContainer>
  );
}
