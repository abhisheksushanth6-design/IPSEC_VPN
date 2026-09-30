import { PageContainer } from '@/components/layout';
import { PageHeader } from '@/components/ui';
import { ErrorState } from '@/components/states';
import {
  AITrafficDistributionChart,
  ChartCard,
  MetricCard,
  ProtocolDistributionChart,
  ProtocolPostureCard,
  QuickActions,
  RiskCard,
  RiskTrendChart,
  SAActivityChart,
  SecurityEventStream,
  SecuritySummary,
  SessionActivityTable,
  SystemStatusPanel,
  TrafficTimelineChart,
  VulnerabilitySeverityChart,
  ExecutivePostureBanner,
  LayerSummaryCards,
} from '@/components/dashboard';
import { useSystemState } from '@/context/SystemStateContext';
import { useDashboardData } from '@/hooks';

/**
 * Overview dashboard. Every figure comes from `useDashboardData`, which
 * aggregates real metrics, posture, timeline events, and protocol transforms.
 */
export function OverviewPage() {
  const { state, reachable, status, errorMessage, refresh } = useSystemState();
  const data = useDashboardData();

  return (
    <PageContainer>
      <PageHeader
        title="Overview"
        description="Integrated IPsec protocol analysis, session fingerprinting, AI traffic classification, security assessment, and risk analysis."
        status={
          state === 'loading'
            ? 'INITIALIZING'
            : reachable
              ? 'FOUNDATION ONLINE'
              : 'BACKEND OFFLINE'
        }
        breadcrumbs={[{ label: 'Overview' }]}
      />

      <QuickActions />

      {state === 'error' ? (
        <ErrorState message={errorMessage ?? undefined} onRetry={refresh} />
      ) : null}

      <ExecutivePostureBanner posture={data.summary?.posture ?? null} status={status} />

      <section aria-labelledby="kpi-heading">
        <h2 id="kpi-heading" className="sr-only">
          Key indicators
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {data.metrics.map((metric) => (
            <MetricCard key={metric.id} metric={metric} />
          ))}
        </div>
      </section>

      <LayerSummaryCards
        summary={data.summary}
        trafficSummary={data.trafficSummary}
        metadataSummary={data.metadataSummary}
        fingerprintCount={data.fingerprintCount}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <RiskCard risk={data.risk} />
        <SystemStatusPanel />
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <SessionActivityTable sessions={data.summary?.recent_sessions ?? null} />
        <ProtocolPostureCard posture={data.summary?.protocol_posture ?? null} />
      </div>

      <section aria-labelledby="analytics-heading">
        <h2 id="analytics-heading" className="sr-only">
          Analytics
        </h2>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <ChartCard title="Traffic Timeline" description="Packets observed per interval." source="Layer 02 · 03">
            <TrafficTimelineChart data={data.traffic} />
          </ChartCard>
          <ChartCard title="Risk Trend" description="Overall risk score over time." source="Layer 09">
            <RiskTrendChart data={data.riskHistory} />
          </ChartCard>
          <ChartCard title="Protocol Distribution" description="Share of IKE, ESP, AH, UDP and IP." source="Layer 03">
            <ProtocolDistributionChart data={data.protocols} />
          </ChartCard>
          <ChartCard title="AI Traffic Classification" description="Encrypted ESP payload distribution." source="Layer 07">
            <AITrafficDistributionChart data={data.trafficClassification} />
          </ChartCard>
          <ChartCard title="Security Assessment Findings" description="Findings by severity." source="Layer 08">
            <VulnerabilitySeverityChart data={data.vulnerabilities} />
          </ChartCard>
          <ChartCard title="SA & Protocol State Activity" description="Security Associations by state." source="Layer 04">
            <SAActivityChart data={data.saActivity} />
          </ChartCard>
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <SecurityEventStream events={data.events} />
        <SecuritySummary data={data} />
      </div>
    </PageContainer>
  );
}
