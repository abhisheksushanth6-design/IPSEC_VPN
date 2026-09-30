#!/usr/bin/env node
/**
 * SIH 26160 demo walkthrough.
 *
 * Loads two software-testbed captures through the real pipeline (a modern AES-256-GCM / ECP-256 / PFS
 * gateway and a legacy IKEv1 3DES / MD5 / MODP-1024 baseline), warms every analysis endpoint, downloads
 * the technical and executive PDF reports, then drives the dashboard in Chromium and records
 * screenshots plus a video into docs/demo/.
 *
 * Prerequisites: backend on http://127.0.0.1:8000, frontend dev server on http://127.0.0.1:5173
 * (`npm run dev` at the repository root starts both) and Playwright (`npm i -g playwright && npx
 * playwright install chromium`, or a local install).
 *
 * Usage:  NODE_PATH="$(npm root -g)" node scripts/demo_walkthrough.cjs
 * Env:    DEMO_BASE_URL, DEMO_API_URL, DEMO_OUT_DIR, DEMO_USER, DEMO_PASSWORD, DEMO_NO_VIDEO=1
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const BASE = process.env.DEMO_BASE_URL || 'http://127.0.0.1:5173';
const API = process.env.DEMO_API_URL || 'http://127.0.0.1:8000';
const OUT = process.env.DEMO_OUT_DIR || path.resolve(__dirname, '..', 'docs', 'demo');
const USER = process.env.DEMO_USER || 'analyst';
const PASS = process.env.DEMO_PASSWORD || 'Analyst@2026!';
const STRONG = 'PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4';
const LEGACY = 'PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4';

async function api(method, url, body) {
  const res = await fetch(API + url, {
    method,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${url} -> HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

async function download(url, file) {
  const res = await fetch(API + url);
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
}

async function prepareData() {
  const loaded = [];
  for (const profile of [STRONG, LEGACY]) {
    const r = await api('POST', `/api/environment/simulate-profile/${profile}?seed=2026&duration=30`);
    loaded.push(r);
    console.log(`loaded ${r.profile_name}: capture ${r.capture_id}, ${r.packets_loaded} packets, ${r.sessions_discovered} session(s)`);
    const sessions = await api('GET', '/api/sessions?page=1&page_size=50&sort=start_time&order=desc');
    for (const s of sessions.items.filter((x) => x.id)) {
      for (const ep of [
        `/api/traffic-analysis/comprehensive/${s.id}`,
        `/api/security-assessment/comprehensive/${s.id}`,
        `/api/metadata-exposure/session/${s.id}`,
        `/api/threat-matrix/session/${s.id}`,
      ]) {
        await api('GET', ep).catch((e) => console.warn(`warm ${ep} failed: ${e.message}`));
      }
    }
  }
  for (const [type, file] of [['TECHNICAL', 'sample-technical-report.pdf'], ['EXECUTIVE', 'sample-executive-report.pdf']]) {
    const report = await api('POST', '/api/reports/generate', { report_type: type });
    await download(`/api/reports/${report.id}/download`, path.join(OUT, file));
    console.log(`${type} report: ${report.page_count} pages -> ${file}`);
  }
  return loaded;
}

async function walkthrough() {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    recordVideo: process.env.DEMO_NO_VIDEO ? undefined : { dir: OUT, size: { width: 1440, height: 900 } },
  });
  const page = await context.newPage();
  let n = 0;
  const shot = async (name) => {
    n += 1;
    await page.waitForTimeout(1200);
    const file = path.join(OUT, `${String(n).padStart(2, '0')}-${name}.png`);
    await page.screenshot({ path: file, fullPage: true });
    console.log(`screenshot ${path.basename(file)}`);
  };
  const visit = async (route, readySelector, name) => {
    try {
      await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle' });
      if (readySelector) await page.waitForSelector(readySelector, { timeout: 20000 });
      await shot(name);
    } catch (err) {
      console.warn(`page ${route} did not settle: ${err.message}`);
      await shot(`${name}-partial`);
    }
  };

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('#identifier', USER);
  await page.fill('#password', PASS);
  await shot('login');
  await page.click('button[type="submit"]');
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 30000 }).catch(() => {});

  await visit('/overview', 'text=Security Summary', 'overview');
  await visit('/environment', 'text=Software Testbed', 'software-testbed');
  await visit('/security-posture', 'text=Assessment dimensions', 'security-posture-legacy-3des');
  try {
    await page.click('button:has-text("Simulate configuration")');
    await page.waitForSelector('[aria-label="what-if result"]', { timeout: 20000 });
    await shot('what-if-remediation');
  } catch (err) {
    console.warn(`what-if step failed: ${err.message}`);
  }
  try {
    const select = page.locator('#posture-session');
    const values = await select.locator('option').evaluateAll((opts) => opts.map((o) => o.value).filter(Boolean));
    if (values.length > 1) {
      await select.selectOption(values[values.length - 1]);
      await page.waitForSelector('text=Assessment dimensions', { timeout: 20000 });
      await shot('security-posture-modern-aes-gcm');
    }
  } catch (err) {
    console.warn(`second session step failed: ${err.message}`);
  }
  await visit('/traffic-analysis', 'text=AI Traffic Classification', 'ai-traffic-classification');
  await visit('/metadata-exposure', null, 'metadata-exposure');
  await visit('/threat-matrix', 'text=Threat Matrix', 'threat-matrix');
  await visit('/vulnerabilities', 'text=Security Assessment Findings', 'security-assessment-findings');
  await visit('/sa-lifecycle', null, 'sa-protocol-state');
  await visit('/reports', 'text=Generate Security Assessment Report', 'reports');

  const video = page.video();
  await context.close();
  if (video) {
    const tmp = await video.path();
    const target = path.join(OUT, 'walkthrough.webm');
    fs.renameSync(tmp, target);
    console.log(`video -> ${path.basename(target)}`);
  }
  await browser.close();
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  await prepareData();
  await walkthrough();
  console.log(`done: ${OUT}`);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
