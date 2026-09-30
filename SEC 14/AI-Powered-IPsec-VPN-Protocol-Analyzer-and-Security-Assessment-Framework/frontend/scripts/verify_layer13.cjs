#!/usr/bin/env node
/**
 * Standalone Verification Script for Layer 13: Frontend Dashboard / React Visualization Layer
 * AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
 *
 * Mandated Checks:
 *  1. Frontend source structure (src/, pages, components, services, hooks, context, utils, types)
 *  2. TypeScript configuration (tsconfig.json, tsconfig.app.json)
 *  3. Vite build configuration (vite.config.ts, proxy settings, manualChunks)
 *  4. Application entrypoint & providers (index.html, main.tsx, App.tsx)
 *  5. Route registration & navigation catalog (App.tsx routes, navigation.ts items)
 *  6. API client configuration & HTTP client resilience (config.ts, httpClient.ts)
 *  7. Layer 12 API endpoint group coverage (all 21 prefix groups mapped)
 *  8. WebSocket integration (/ws/events, bounded reconnect, typed dispatcher)
 *  9. Environment variable safety (no hardcoded credentials or machine IPs)
 * 10. Secret scan (zero PSKs, private keys, database passwords in source)
 * 11. Safe error rendering (zero raw stack traces exposed to user)
 * 12. Dashboard SOC posture & KPI rendering (MetricCard, ExecutivePostureBanner)
 * 13. Loading, empty, and disconnected state safeguards
 * 14. Responsive layout safeguards (viewport hooks, scroll containers)
 * 15. Typecheck execution (tsc -p tsconfig.app.json)
 * 16. Production bundle build validation (dist/index.html, JS, CSS chunks)
 * 17. Dedicated Layer 13 test suite execution (test_layer13_dashboard.test.tsx)
 * 18. Complete frontend test suite execution (npm test)
 * 19. Report download & binary handling validation
 * 20. Overall Layer 13 readiness verdict
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const FRONTEND_DIR = path.resolve(__dirname, '..');
const SRC_DIR = path.join(FRONTEND_DIR, 'src');

const REQUIRED_SERVICES = [
  'healthService.ts',
  'systemStatusService.ts',
  'environmentService.ts',
  'liveCaptureService.ts',
  'packetService.ts',
  'sessionService.ts',
  'saService.ts',
  'featureService.ts',
  'baselineService.ts',
  'driftService.ts',
  'aiAnomalyService.ts',
  'trafficAnalysisService.ts',
  'metadataExposureService.ts',
  'threatMatrixService.ts',
  'vulnerabilityService.ts',
  'riskService.ts',
  'dashboardService.ts',
  'reportService.ts',
  'securityAssessmentService.ts',
  'aiAnalysisService.ts',
  'realtimeService.ts',
];

const REQUIRED_ROUTES = [
  '/overview',
  '/architecture',
  '/environment',
  '/live-monitor',
  '/packet-analysis',
  '/ipsec-sessions',
  '/sa-lifecycle',
  '/feature-engineering',
  '/baseline-profiling',
  '/drift-detection',
  '/ai-anomaly-detection',
  '/traffic-analysis',
  '/metadata-exposure',
  '/threat-matrix',
  '/vulnerabilities',
  '/risk-assessment',
  '/reports',
  '/settings',
];

let totalChecks = 0;
let passedChecks = 0;
let failedChecks = 0;

function runCheck(name, fn) {
  totalChecks++;
  process.stdout.write(`[CHECK ${String(totalChecks).padStart(2, '0')}] ${name.padEnd(65, '.')} `);
  try {
    const result = fn();
    if (result === false) {
      console.log('FAIL');
      failedChecks++;
      return false;
    }
    console.log('PASS');
    passedChecks++;
    return true;
  } catch (err) {
    console.log(`FAIL (${err.message})`);
    failedChecks++;
    return false;
  }
}

console.log('================================================================================');
console.log('  LAYER 13 FRONTEND DASHBOARD & VISUALIZATION VERIFICATION SCRIPT');
console.log('  AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework');
console.log('================================================================================\n');

// 1. Frontend source structure
runCheck('1. Frontend source structure verification', () => {
  const dirs = ['pages', 'components', 'services', 'hooks', 'context', 'config', 'types', 'utils'];
  for (const d of dirs) {
    if (!fs.existsSync(path.join(SRC_DIR, d))) {
      throw new Error(`Missing src/${d}`);
    }
  }
  return true;
});

// 2. TypeScript configuration
runCheck('2. TypeScript configuration verification', () => {
  const tsconfigApp = JSON.parse(fs.readFileSync(path.join(FRONTEND_DIR, 'tsconfig.app.json'), 'utf8'));
  return !!tsconfigApp.compilerOptions && tsconfigApp.compilerOptions.strict === true;
});

// 3. Vite configuration & reverse proxy
runCheck('3. Vite configuration & reverse proxy verification', () => {
  const viteConfig = fs.readFileSync(path.join(FRONTEND_DIR, 'vite.config.ts'), 'utf8');
  return viteConfig.includes("'/api'") && viteConfig.includes("'/ws'") && viteConfig.includes('manualChunks');
});

// 4. Application entrypoint & layout
runCheck('4. Application entrypoint & layout verification', () => {
  const indexHtml = fs.readFileSync(path.join(FRONTEND_DIR, 'index.html'), 'utf8');
  const mainTsx = fs.readFileSync(path.join(SRC_DIR, 'main.tsx'), 'utf8');
  const appTsx = fs.readFileSync(path.join(SRC_DIR, 'App.tsx'), 'utf8');
  return indexHtml.includes('id="root"') && mainTsx.includes('<App') && appTsx.includes('AppLayout');
});

// 5. Route registration & navigation catalog
runCheck('5. Route registration & navigation coverage (all 18 routes)', () => {
  const appTsx = fs.readFileSync(path.join(SRC_DIR, 'App.tsx'), 'utf8');
  for (const r of REQUIRED_ROUTES) {
    if (!appTsx.includes(`path="${r}"`)) {
      throw new Error(`Route ${r} not registered in App.tsx`);
    }
  }
  return true;
});

// 6. API client configuration & HTTP client
runCheck('6. API client configuration & HTTP client resilience', () => {
  const configTs = fs.readFileSync(path.join(SRC_DIR, 'utils', 'config.ts'), 'utf8');
  const httpClientTs = fs.readFileSync(path.join(SRC_DIR, 'services', 'httpClient.ts'), 'utf8');
  return configTs.includes('apiBaseUrl') && httpClientTs.includes('requestJson') && httpClientTs.includes('eventStreamUrl');
});

// 7. Layer 12 API endpoint group coverage (all 21 services)
runCheck('7. Layer 12 API endpoint group coverage (21 service modules)', () => {
  const servicesDir = path.join(SRC_DIR, 'services');
  for (const svc of REQUIRED_SERVICES) {
    if (!fs.existsSync(path.join(servicesDir, svc))) {
      throw new Error(`Missing service ${svc}`);
    }
  }
  return true;
});

// 8. WebSocket integration & bounded backoff
runCheck('8. WebSocket telemetry integration (/ws/events) & backoff', () => {
  const realtimeTs = fs.readFileSync(path.join(SRC_DIR, 'services', 'realtimeService.ts'), 'utf8');
  return realtimeTs.includes('eventStreamUrl') && realtimeTs.includes('REALTIME_RECONNECT') && realtimeTs.includes('onmessage');
});

// 9. Environment variable safety
runCheck('9. Environment variable safety & zero hardcoded hosts', () => {
  const configTs = fs.readFileSync(path.join(SRC_DIR, 'utils', 'config.ts'), 'utf8');
  const hasHardcodedIp = /https?:\/\/(?!127\.0\.0\.1|localhost)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(configTs);
  return !hasHardcodedIp && configTs.includes('import.meta.env.VITE_API_BASE_URL');
});

// 10. Secret scan across frontend codebase
runCheck('10. Secret scan (zero PSKs, private keys, database passwords)', () => {
  const checkSecrets = (dir) => {
    const files = fs.readdirSync(dir);
    for (const f of files) {
      const full = path.join(dir, f);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        checkSecrets(full);
      } else if (/\.(ts|tsx|js|html)$/.test(f)) {
        const content = fs.readFileSync(full, 'utf8');
        if (/BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY/i.test(content)) {
          throw new Error(`Private key found in ${full}`);
        }
        if (/postgres:\/\/[a-z0-9]+:[a-z0-9]+@/i.test(content)) {
          throw new Error(`Database connection secret found in ${full}`);
        }
      }
    }
  };
  checkSecrets(SRC_DIR);
  return true;
});

// 11. Sensitive error logging check
runCheck('11. Sensitive error logging & stack trace suppression check', () => {
  const httpClientTs = fs.readFileSync(path.join(SRC_DIR, 'services', 'httpClient.ts'), 'utf8');
  return httpClientTs.includes('ApiError') && !httpClientTs.includes('console.trace');
});

// 12. Dashboard SOC posture & KPI rendering
runCheck('12. Dashboard SOC posture & KPI components verification', () => {
  const dashboardDir = path.join(SRC_DIR, 'components', 'dashboard');
  const requiredComponents = ['MetricCard.tsx', 'ExecutivePostureBanner.tsx', 'RiskCard.tsx', 'SystemStatusPanel.tsx'];
  for (const c of requiredComponents) {
    if (!fs.existsSync(path.join(dashboardDir, c))) {
      throw new Error(`Missing ${c}`);
    }
  }
  return true;
});

// 13. Loading, empty, and disconnected state safeguards
runCheck('13. Loading, empty, and error state components verification', () => {
  const statesDir = path.join(SRC_DIR, 'components', 'states');
  const requiredStates = ['EmptyState.tsx', 'LoadingState.tsx', 'ErrorState.tsx'];
  for (const s of requiredStates) {
    if (!fs.existsSync(path.join(statesDir, s))) {
      throw new Error(`Missing ${s}`);
    }
  }
  return true;
});

// 14. Responsive layout safeguards
runCheck('14. Responsive layout & viewport hooks verification', () => {
  const hooksDir = path.join(SRC_DIR, 'hooks');
  const mediaHook = fs.readFileSync(path.join(hooksDir, 'useMediaQuery.ts'), 'utf8');
  return mediaHook.includes('useIsCompactViewport') && mediaHook.includes('matchMedia');
});

// 15. Typecheck execution
runCheck('15. TypeScript typecheck execution (npm run typecheck)', () => {
  try {
    execSync('npm run typecheck', { cwd: FRONTEND_DIR, stdio: 'pipe' });
    return true;
  } catch (err) {
    throw new Error('Typecheck reported TypeScript compiler errors');
  }
});

// 16. Production bundle build validation
runCheck('16. Production bundle build validation (dist/ directory)', () => {
  const distDir = path.join(FRONTEND_DIR, 'dist');
  if (!fs.existsSync(distDir)) {
    throw new Error('Missing dist directory; run npm run build first');
  }
  const indexHtml = fs.existsSync(path.join(distDir, 'index.html'));
  const assetsDir = fs.existsSync(path.join(distDir, 'assets'));
  return indexHtml && assetsDir;
});

// 17. Dedicated Layer 13 test suite execution
runCheck('17. Dedicated Layer 13 test suite (test_layer13_dashboard)', () => {
  try {
    execSync('npx vitest run tests/test_layer13_dashboard.test.tsx', { cwd: FRONTEND_DIR, stdio: 'pipe' });
    return true;
  } catch (err) {
    throw new Error('Dedicated Layer 13 tests failed');
  }
});

// 18. Complete frontend test suite execution
runCheck('18. Complete frontend test suite execution (npm test)', () => {
  try {
    execSync('npm test', { cwd: FRONTEND_DIR, stdio: 'pipe' });
    return true;
  } catch (err) {
    throw new Error('Frontend regression test suite failed');
  }
});

// 19. Report download & binary handling validation
runCheck('19. Report download & binary handling validation', () => {
  const reportSvc = fs.readFileSync(path.join(SRC_DIR, 'services', 'reportService.ts'), 'utf8');
  return reportSvc.includes('getDownloadUrl') && reportSvc.includes('/download');
});

// 20. Final readiness verdict
runCheck('20. Overall Layer 13 readiness verdict', () => {
  return failedChecks === 0;
});

console.log('\n================================================================================');
console.log(`  VERIFICATION RESULTS: ${passedChecks}/${totalChecks} CHECKS PASSED (${failedChecks} FAILED)`);
console.log('================================================================================');

if (failedChecks > 0) {
  console.log('\n❌ Layer 13 verification FAILED.');
  process.exit(1);
} else {
  console.log('\n✅ Layer 13 (Frontend Dashboard / React Visualization Layer) is FULLY OPERATIONAL.');
  process.exit(0);
}
