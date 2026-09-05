import { Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from '@/components/layout';
import { SystemStateProvider } from '@/context/SystemStateContext';
import {
  AIAnomaliesPage,
  ArchitecturePage,
  BaselineProfilesPage,
  DriftDetectionPage,
  FeatureEngineeringPage,
  IPSecSessionsPage,
  LiveMonitorPage,
  NotFoundPage,
  OverviewPage,
  PacketAnalysisPage,
  ReportsPage,
  RiskAssessmentPage,
  SALifecyclePage,
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
          <Route path="/baseline-profiling" element={<BaselineProfilesPage />} />
          <Route path="/baseline-profiles" element={<Navigate to="/baseline-profiling" replace />} />
          <Route path="/drift-detection" element={<DriftDetectionPage />} />
          <Route path="/security-drift" element={<Navigate to="/drift-detection" replace />} />
          <Route path="/ai-anomaly-detection" element={<AIAnomaliesPage />} />
          <Route path="/ai-anomalies" element={<Navigate to="/ai-anomaly-detection" replace />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/vulnerability-engine" element={<Navigate to="/vulnerabilities" replace />} />
          <Route path="/security-rules" element={<Navigate to="/vulnerabilities" replace />} />
          <Route path="/risk-assessment" element={<RiskAssessmentPage />} />

          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />

          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </SystemStateProvider>
  );
}
