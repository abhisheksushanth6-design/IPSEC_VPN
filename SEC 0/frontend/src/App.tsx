import { Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from '@/components/layout';
import { SystemStateProvider } from '@/context/SystemStateContext';
import {
  AIAnomaliesPage,
  ArchitecturePage,
  BaselineProfilesPage,
  FeatureEngineeringPage,
  IPSecSessionsPage,
  LiveMonitorPage,
  NotFoundPage,
  OverviewPage,
  PacketAnalysisPage,
  ReportsPage,
  RiskAssessmentPage,
  SALifecyclePage,
  SecurityDriftPage,
  SettingsPage,
  VulnerabilitiesPage,
} from '@/pages';

/**
 * Application routes. Every sidebar destination resolves to a real page
 * component; none are left unrouted.
 */
export default function App() {
  return (
    <SystemStateProvider>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/architecture" element={<ArchitecturePage />} />

          <Route path="/live-monitor" element={<LiveMonitorPage />} />
          <Route path="/packet-analysis" element={<PacketAnalysisPage />} />
          <Route path="/ipsec-sessions" element={<IPSecSessionsPage />} />

          <Route path="/sa-lifecycle" element={<SALifecyclePage />} />
          <Route path="/feature-engineering" element={<FeatureEngineeringPage />} />
          <Route path="/baseline-profiles" element={<BaselineProfilesPage />} />
          <Route path="/security-drift" element={<SecurityDriftPage />} />
          <Route path="/ai-anomalies" element={<AIAnomaliesPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/risk-assessment" element={<RiskAssessmentPage />} />

          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />

          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </SystemStateProvider>
  );
}
