import { PageContainer } from '@/components/layout';
import { PageHeader } from '@/components/ui';
import { ErrorState } from '@/components/states';
import {
  AnomalyTimelineChart,
  ChartCard,
  MetricCard,
  ProtocolDistributionChart,
  QuickActions,
  RiskCard,
  RiskTrendChart,
  SAActivityChart,
  SecurityEventStream,
  SecuritySummary,
  SystemStatusPanel,
  TrafficTimelineChart,
  VulnerabilitySeverityChart,
} from '@/components/dashboard';
import { PROJECT_NAME } from '@/config/branding';
import { useSystemState } from '@/context/SystemStateContext';
import { useDashboardData } from '@/hooks';

/**
 * Overview dashboard. Every figure comes from `useDashboardData`, which
 * reports each security metric as unavailable until its engine exists.
 */
export function OverviewPage() {
  const { state, reachable, errorMessage, refresh } = useSystemState();
  const data = useDashboardData();

  return (
    <PageContainer>
      <PageHeader
        title="Overview"
        description={`Security posture and operational overview of the ${PROJECT_NAME}.`}
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

      <div className="grid gap-6 lg:grid-cols-2">
        <RiskCard risk={data.risk} />
        <SystemStatusPanel />
      </div>

      <section aria-labelledby="analytics-heading">
        <h2 id="analytics-heading" className="sr-only">
          Analytics
        </h2>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <ChartCard title="Traffic Timeline" description="Packets observed per interval." source="Layer 02 · 03">
            <TrafficTimelineChart data={data.traffic} />
          </ChartCard>
          <ChartCard title="Risk Trend" description="Overall risk score over time." source="Layer 10">
            <RiskTrendChart data={data.riskHistory} />
          </ChartCard>
          <ChartCard title="Protocol Distribution" description="Share of IKE, ESP, AH, UDP and IP." source="Layer 03">
            <ProtocolDistributionChart data={data.protocols} />
          </ChartCard>
          <ChartCard title="AI Anomalies Over Time" description="Sessions flagged per interval." source="Layer 08">
            <AnomalyTimelineChart data={data.anomalies} />
          </ChartCard>
          <ChartCard title="Vulnerability Severity" description="Findings by severity." source="Layer 09">
            <VulnerabilitySeverityChart data={data.vulnerabilities} />
          </ChartCard>
          <ChartCard title="SA Lifecycle Activity" description="Security Associations by state." source="Layer 04">
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
