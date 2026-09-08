import { CheckCircle2, ArrowRight, AlertCircle } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';

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
import { PageHeader, Panel } from '@/components/ui';
import { useSystemState } from '@/context/SystemStateContext';
import { useLiveMonitorData, useRealtime } from '@/hooks';
import type { Packet, PacketSummary, MonitorSecurityAssociation, VPNSession, StatusKind } from '@/types';

/**
 * Live Monitor. Connects to real Layer 02 Live Capture engine and /ws/events.
 * Provides real start/stop capture controls, genuine duration and packet counts,
 * and passes finalized captures directly to Layer 03.
 */
export function LiveMonitorPage() {
  const { state, status, refresh } = useSystemState();
  const data = useLiveMonitorData();
  const realtime = useRealtime();

  const [selectedInterface, setSelectedInterface] = useState<string>('');
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

  // Derive target VM and NIC from selectedInterface string
  const handleStart = () => {
    let targetVM = 'IPsec-Server';
    let targetNIC = 2;

    if (selectedInterface && data.rawInterfaces.length > 0) {
      const match = data.rawInterfaces.find((i) =>
        selectedInterface.startsWith(i.vm_name)
      );
      if (match) {
        targetVM = match.vm_name;
        targetNIC = match.nic_number;
      }
    } else if (data.rawInterfaces.length > 0) {
      const rec = data.rawInterfaces.find((i) => i.is_recommended) || data.rawInterfaces[0];
      if (rec) {
        targetVM = rec.vm_name;
        targetNIC = rec.nic_number;
      }
    }

    data.start(targetVM, targetNIC);
  };

  // Header status derivation
  let headerStatus: StatusKind = 'READY';
  let headerLabel = 'CAPTURE READY';
  if (data.captureState === 'CAPTURING') {
    headerStatus = 'LIVE';
    headerLabel = 'CAPTURING ACTIVE';
  } else if (data.captureState === 'STOPPING' || data.captureState === 'INGESTING') {
    headerStatus = 'INITIALIZING';
    headerLabel = data.captureState;
  } else if (data.captureState === 'ERROR') {
    headerStatus = 'ERROR';
    headerLabel = 'CAPTURE ERROR';
  } else if (data.captureState === 'NOT INITIALIZED') {
    headerStatus = 'NOT INITIALIZED';
    headerLabel = 'NOT INITIALIZED';
  }

  return (
    <PageContainer>
      <PageHeader
        title="Live Monitor"
        description="Real-time visibility into IPsec VPN traffic, sessions, security events, and live packet capture."
        status={headerStatus}
        statusLabel={headerLabel}
        breadcrumbs={[{ label: 'Monitoring' }, { label: 'Live Monitor' }]}
      />

      {data.actionMessage ? (
        <div
          className={`flex items-center justify-between gap-3 rounded border px-4 py-3 text-sm ${
            data.actionMessage.type === 'success'
              ? 'border-success/30 bg-success/10 text-success'
              : 'border-danger/30 bg-danger/10 text-danger'
          }`}
        >
          <div className="flex items-center gap-2">
            {data.actionMessage.type === 'success' ? (
              <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
            ) : (
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
            )}
            <span>{data.actionMessage.text}</span>
          </div>
          {data.captureState === 'COMPLETED' ? (
            <div className="flex items-center gap-2">
              <Link
                to="/packet-analysis"
                className="inline-flex items-center gap-1 rounded bg-info px-2.5 py-1 text-xs font-medium text-white hover:bg-info/90"
              >
                Inspect Packets
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
              <Link
                to="/ipsec-sessions"
                className="inline-flex items-center gap-1 rounded border border-border px-2.5 py-1 text-xs font-medium text-primary hover:border-info"
              >
                View Sessions
              </Link>
            </div>
          ) : null}
        </div>
      ) : null}

      <MonitorBanner
        captureState={data.captureState}
        sourceVM={data.status?.source_vm}
        nicNumber={data.status?.nic_number}
      />

      <MonitorControlBar
        interfaces={data.interfaces}
        selectedInterface={selectedInterface}
        onSelectInterface={setSelectedInterface}
        captureState={data.captureState}
        applicationMode={state === 'ready' ? status?.application_mode ?? null : null}
        refreshing={state === 'loading'}
        actionLoading={data.actionLoading}
        onStartCapture={handleStart}
        onStopCapture={data.stop}
        onRefresh={refresh}
      />

      {/* Live capture active session readout */}
      {data.status?.output_file ? (
        <Panel className="p-4 bg-elevated/40">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between text-xs">
            <div className="space-y-1">
              <span className="font-semibold uppercase tracking-wider text-muted">Active PCAP Buffer</span>
              <p className="font-mono text-2xs text-secondary truncate max-w-xl">{data.status.output_file}</p>
            </div>
            <div className="flex items-center gap-4 font-mono text-2xs">
              <div>
                <span className="text-muted">Target: </span>
                <span className="text-primary font-bold">{data.status.source_vm} (NIC {data.status.nic_number})</span>
              </div>
              <div>
                <span className="text-muted">Packets: </span>
                <span className="text-success font-bold">{data.status.packet_count}</span>
              </div>
              <div>
                <span className="text-muted">Size: </span>
                <span className="text-info font-bold">{Math.round(data.status.file_size_bytes / 1024)} KB</span>
              </div>
            </div>
          </div>
        </Panel>
      ) : null}

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
        <PacketStream
          packets={data.packets}
          selectedId={selectedPacket?.id ?? null}
          onSelect={selectPacket}
          captureState={data.captureState}
        />
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
