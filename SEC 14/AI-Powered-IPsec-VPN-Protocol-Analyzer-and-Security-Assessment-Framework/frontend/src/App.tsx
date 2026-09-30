import { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from '@/components/layout';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { AuthProvider } from '@/context/AuthContext';
import { SystemStateProvider } from '@/context/SystemStateContext';
import { ThemeProvider } from '@/context/ThemeContext';

// Authentication Pages
import {
  LoginPage,
  RegisterPage,
  ForgotPasswordPage,
  ResetPasswordPage,
} from '@/pages/Auth';

// Route-level dynamic code splitting: each page loads on-demand as a discrete chunk
import { OverviewPage } from '@/pages/Overview';
const ArchitecturePage = lazy(() =>
  import('@/pages/Architecture').then((m) => ({ default: m.ArchitecturePage }))
);
const EnvironmentPage = lazy(() =>
  import('@/pages/Environment/EnvironmentPage').then((m) => ({ default: m.EnvironmentPage }))
);
import { LiveMonitorPage } from '@/pages/LiveMonitor';
const PacketAnalysisPage = lazy(() =>
  import('@/pages/PacketAnalysis').then((m) => ({ default: m.PacketAnalysisPage }))
);
const IPSecSessionsPage = lazy(() =>
  import('@/pages/IPSecSessions').then((m) => ({ default: m.IPSecSessionsPage }))
);
const SALifecyclePage = lazy(() =>
  import('@/pages/SALifecycle').then((m) => ({ default: m.SALifecyclePage }))
);
const FeatureEngineeringPage = lazy(() =>
  import('@/pages/FeatureEngineering').then((m) => ({ default: m.FeatureEngineeringPage }))
);
const BaselineProfilesPage = lazy(() =>
  import('@/pages/BaselineProfiles').then((m) => ({ default: m.BaselineProfilesPage }))
);
const DriftDetectionPage = lazy(() =>
  import('@/pages/DriftDetection').then((m) => ({ default: m.DriftDetectionPage }))
);
const AIAnomaliesPage = lazy(() =>
  import('@/pages/AIAnomalies').then((m) => ({ default: m.AIAnomaliesPage }))
);
const TrafficAnalysisPage = lazy(() =>
  import('@/pages/TrafficAnalysis').then((m) => ({ default: m.TrafficAnalysisPage }))
);
const MetadataExposurePage = lazy(() =>
  import('@/pages/MetadataExposure').then((m) => ({ default: m.MetadataExposurePage }))
);
const ThreatMatrixPage = lazy(() =>
  import('@/pages/ThreatMatrix').then((m) => ({ default: m.ThreatMatrixPage }))
);
const VulnerabilitiesPage = lazy(() =>
  import('@/pages/Vulnerabilities').then((m) => ({ default: m.VulnerabilitiesPage }))
);
const SecurityPosturePage = lazy(() =>
  import('@/pages/SecurityPosture').then((m) => ({ default: m.SecurityPosturePage }))
);
import { RiskAssessmentPage } from '@/pages/RiskAssessment';
const ReportsPage = lazy(() =>
  import('@/pages/Reports').then((m) => ({ default: m.ReportsPage }))
);
const SettingsPage = lazy(() =>
  import('@/pages/Settings').then((m) => ({ default: m.SettingsPage }))
);
const NotFoundPage = lazy(() =>
  import('@/pages/NotFound').then((m) => ({ default: m.NotFoundPage }))
);

/**
 * Application routes.
 * Public routes: /login, /register, /forgot-password, /reset-password
 * Protected routes: all IPsec analyzer pages protected by ProtectedRoute
 */
export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <SystemStateProvider>
          <Routes>
            {/* Public Authentication Pages */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />

            {/* Protected Application Routes */}
            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                <Route index element={<Navigate to="/overview" replace />} />
                <Route path="/overview" element={<OverviewPage />} />
                <Route path="/architecture" element={<ArchitecturePage />} />
                <Route path="/environment" element={<EnvironmentPage />} />

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
                <Route path="/traffic-analysis" element={<TrafficAnalysisPage />} />
                <Route path="/ai-classification" element={<Navigate to="/traffic-analysis" replace />} />
                <Route path="/metadata-exposure" element={<MetadataExposurePage />} />
                <Route path="/threat-matrix" element={<ThreatMatrixPage />} />
                <Route path="/security-posture" element={<SecurityPosturePage />} />
                <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
                <Route path="/vulnerability-engine" element={<Navigate to="/vulnerabilities" replace />} />
                <Route path="/security-rules" element={<Navigate to="/vulnerabilities" replace />} />
                <Route path="/risk-assessment" element={<RiskAssessmentPage />} />

                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/settings" element={<SettingsPage />} />

                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Route>
          </Routes>
        </SystemStateProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
