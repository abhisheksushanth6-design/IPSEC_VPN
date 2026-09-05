#!/usr/bin/env node
/**
 * Unified Full-Stack Runner for
 * AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
 *
 * Runs or builds both Frontend and Backend with a single command.
 */

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const frontendDir = path.join(projectRoot, 'frontend');
const backendDir = path.join(projectRoot, 'backend');
const reqFile = path.join(backendDir, 'requirements.txt');

function findUvExecutable() {
  const candidates = [
    'uv',
    path.join(process.env.LOCALAPPDATA || '', 'Microsoft/WinGet/Packages/astral-sh.uv_Microsoft.Winget.Source_8wekyb3d8bbwe/uv.exe'),
    'C:\\Users\\abhis\\AppData\\Local\\Microsoft\\WinGet\\Packages\\astral-sh.uv_Microsoft.Winget.Source_8wekyb3d8bbwe\\uv.exe',
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return 'uv';
}

const uvPath = findUvExecutable();
const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const mode = process.argv[2] || 'build-and-run';

console.log('\n================================================================');
console.log('  AI-Powered IPsec VPN Protocol Analyzer & Security Framework');
console.log('================================================================\n');

if (mode === 'build' || mode === 'build-and-run') {
  console.log('>>> [1/2] Building Frontend production bundle (Vite & TypeScript)...');
  const buildResult = spawnSync(npmCmd, ['run', 'build'], {
    cwd: frontendDir,
    stdio: 'inherit',
    shell: true,
  });

  if (buildResult.status !== 0) {
    console.error('\n[ERROR] Frontend build failed.');
    process.exit(buildResult.status || 1);
  }

  console.log('\n>>> [2/2] Launching Full-Stack Application on FastAPI...');
  console.log('>>> Both Backend API and Frontend UI are served simultaneously at:');
  console.log('>>>   --> http://127.0.0.1:8000\n');
  console.log('Press Ctrl+C to terminate.\n');

  const backendProc = spawn(
    uvPath,
    [
      'run',
      '--python',
      '3.12',
      '--with-requirements',
      reqFile,
      'uvicorn',
      'app.main:app',
      '--host',
      '127.0.0.1',
      '--port',
      '8000',
    ],
    {
      cwd: backendDir,
      stdio: 'inherit',
      shell: false,
    }
  );

  backendProc.on('exit', (code) => {
    process.exit(code || 0);
  });
} else if (mode === 'dev') {
  console.log('>>> Starting Backend (Port 8000) & Frontend Dev Server (Port 5173)...\n');
  console.log('>>> Backend API: http://127.0.0.1:8000');
  console.log('>>> Frontend UI (HMR): http://localhost:5173\n');

  const backendProc = spawn(
    uvPath,
    [
      'run',
      '--python',
      '3.12',
      '--with-requirements',
      reqFile,
      'uvicorn',
      'app.main:app',
      '--reload',
      '--host',
      '127.0.0.1',
      '--port',
      '8000',
    ],
    {
      cwd: backendDir,
      stdio: 'inherit',
      shell: false,
    }
  );

  const frontendProc = spawn(npmCmd, ['run', 'dev'], {
    cwd: frontendDir,
    stdio: 'inherit',
    shell: true,
  });

  const cleanup = () => {
    console.log('\nShutting down backend and frontend...');
    try { backendProc.kill(); } catch {}
    try { frontendProc.kill(); } catch {}
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
} else {
  console.log(`Unknown mode "${mode}". Usage: node runner.js [build-and-run|dev|build]`);
}
