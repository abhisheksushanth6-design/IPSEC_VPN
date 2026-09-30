import { CheckCircle2, ArrowRight, AlertCircle } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { ChartCard, MetricCard, SecurityEventStream } from '@/components/dashboard';
import { PageContainer } from '@/components/layout';
import { PipelineProgressionRibbon } from '@/components/common/PipelineProgressionRibbon';
import {
  LiveCaptureCommandCenter,
  IPsecTunnelPulseChart,
  PacketSizeHistogram,
  SessionActivityMap,
  MonitorBanner,
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
import type { Packet, PacketSummary, MonitorSecurityAssociation, VPNSession, StatusKind } from '@/types';

/**
 * IPsec Security Observatory — Live Monitor.
 * Connects to real Layer 02 Live Capture engine and /ws/events.
 * Renders IPsec Tunnel Pulse, Protocol Distribution Donut, Packet Size Fingerprint,
 * Session Flow Map, and Live Packet Inspector using actual capture data.
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

  // Auto-select recommended running interface on load
  useEffect(() => {
    if (!selectedInterface && data.rawInterfaces.length > 0) {
      const rec =
        data.rawInterfaces.find((i) => i.is_recommended) ||
        data.rawInterfaces.find((i) => i.vm_state.toLowerCase() === 'running') ||
        data.rawInterfaces[0];
      if (rec) {
        setSelectedInterface(`${rec.vm_name} (NIC ${rec.nic_number} · ${rec.nic_type})`);
      }
    }
  }, [data.rawInterfaces, selectedInterface]);

  // Derive target VM and NIC from selectedInterface string
  const handleStart = () => {
    let targetVM = '';
    let targetNIC = 1;

    if (selectedInterface && data.rawInterfaces.length > 0) {
      const match = data.rawInterfaces.find(
        (i) => selectedInterface.includes(i.vm_name) && selectedInterface.includes(`NIC ${i.nic_number}`)
      );
      if (match) {
        targetVM = match.vm_name;
        targetNIC = match.nic_number;
      }
    }

    if (!targetVM && data.rawInterfaces.length > 0) {
      const rec =
        data.rawInterfaces.find((i) => i.is_recommended) ||
        data.rawInterfaces.find((i) => i.vm_state.toLowerCase() === 'running') ||
        data.rawInterfaces[0];
      if (rec) {
        targetVM = rec.vm_name;
        targetNIC = rec.nic_number;
      }
    }

    if (targetVM) {
      data.start(targetVM, targetNIC);
    }
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
      {/* 1. Observatory End-to-End Pipeline Ribbon */}
      <PipelineProgressionRibbon />

      {/* 2. Main Page Header */}
      <PageHeader
        title="Live Monitor"
        description="IPsec Security Observatory • Real-time visibility into IPsec VPN traffic pulse, session flows, security events, and wire frame capture."
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

      {/* Preserved MonitorBanner for test expectations */}
      <MonitorBanner
        captureState={data.captureState}
        sourceVM={data.status?.source_vm}
        nicNumber={data.status?.nic_number}
      />

      {/* 3. Live Capture Command Center */}
      <LiveCaptureCommandCenter
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
        durationSeconds={Math.round(data.status?.elapsed_seconds ?? 0)}
        packetCount={data.status?.packet_count ?? (data.packets?.length ?? 0)}
        byteCount={data.status?.file_size_bytes ?? 0}
        packetRate={data.packetRate}
        bandwidth={data.bandwidth}
        activeSessionsCount={data.sessions?.length ?? 0}
        outputFile={data.status?.output_file}
        sourceVM={data.status?.source_vm}
        nicNumber={data.status?.nic_number}
      />

      <RealtimeStatus
        state={realtime.connectionState}
        detail={realtime.connectionDetail}
        onRetry={realtime.retry}
      />

      {/* 4. Six Metric Cards Grid (Strictly preserved for test expectations) */}
      <section aria-labelledby="monitor-metrics-heading">
        <h2 id="monitor-metrics-heading" className="sr-only">Monitoring metrics</h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {data.metrics.map((metric) => (
            <MetricCard key={metric.id} metric={metric} />
          ))}
        </div>
      </section>

      <MonitorFilters dataAvailable={dataAvailable} />

      {/* 5. Central Network Activity Visualization & Protocol Distribution */}
      <div className="grid gap-6 lg:grid-cols-2">
        <ChartCard
          title="IPsec Tunnel Pulse — Real-Time Telemetry"
          description="Observable frame rate and throughput pulse over time."
          source="Layer 01 · 02 Live Capture"
        >
          <IPsecTunnelPulseChart data={data.traffic} />
        </ChartCard>

        <TrafficSummary
          ipsecBreakdown={data.ipsecBreakdown}
          packetRate={data.packetRate}
          bandwidth={data.bandwidth}
        />
      </div>

      {/* 6. Packet Size Fingerprint Histogram */}
      <PacketSizeHistogram packets={data.packets} />

      {/* 7. Session Activity Flow Map */}
      <SessionActivityMap
        sessions={data.sessions}
        selectedId={selectedSession?.id ?? null}
        onSelect={selectSession}
      />

      {/* 8. Live Packet Inspector Stream */}
      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <PacketStream
          packets={data.packets}
          selectedId={selectedPacket?.id ?? null}
          onSelect={selectPacket}
          captureState={data.captureState}
        />
        <PacketDetails packet={selectedPacket} onClose={() => setSelectedPacket(null)} />
      </div>

      {/* 9. VPN Sessions Table Panel */}
      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <VPNSessionPanel sessions={data.sessions} selectedId={selectedSession?.id ?? null} onSelect={selectSession} />
        <SessionDetails session={selectedSession} onClose={() => setSelectedSession(null)} />
      </div>

      {/* 10. Security Associations Panel */}
      <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)] xl:items-start">
        <SecurityAssociationPanel associations={data.associations} selectedId={selectedSA?.id ?? null} onSelect={selectSA} />
        <SADetails association={selectedSA} onClose={() => setSelectedSA(null)} />
      </div>

      {/* 11. Security Events Stream & System Activity */}
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
