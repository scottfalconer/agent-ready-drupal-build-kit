#!/usr/bin/env node

import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function captureModuleCandidates() {
  return [
    new URL('../bin/global-chrome.mjs', import.meta.url),
    new URL('./global-chrome.mjs', import.meta.url)
  ];
}

async function loadCaptureModule() {
  const candidate = captureModuleCandidates().find((url) => existsSync(fileURLToPath(url)));
  if (!candidate) {
    throw new Error('The canonical global-chrome capture module is missing beside the browser runtime smoke.');
  }
  return import(candidate.href);
}

function assertPng(base64, label) {
  const bytes = Buffer.from(String(base64 || ''), 'base64');
  if (bytes.length <= PNG_SIGNATURE.length || !bytes.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    throw new Error(`${label} did not produce a nonempty PNG screenshot.`);
  }
  return bytes.length;
}

export function validateBrowserRuntimeSmoke({ globalCapture, networkCapture, targetUrl }) {
  const target = new URL(targetUrl);
  if (globalCapture?.status !== 'captured' || globalCapture?.authoritative !== true) {
    throw new Error(`Verifier-owned CDP/axe/screenshot capture failed: ${(globalCapture?.errors || []).join(' ') || 'no authoritative capture'}`);
  }
  if (globalCapture?.runtime?.backend !== 'selenium-grid-cdp' || globalCapture?.runtime?.ready !== true) {
    throw new Error('Global capture did not report a ready Selenium Grid CDP runtime.');
  }
  if (!Array.isArray(globalCapture.routes) || globalCapture.routes.length === 0) {
    throw new Error('Global capture returned no route/viewports.');
  }

  let screenshotBytes = 0;
  for (const route of globalCapture.routes) {
    if (route?.axe?.status !== 'executed' || !Array.isArray(route?.axe?.report?.violations)) {
      throw new Error(`Pinned axe-core did not return a structural result for ${route?.path || 'the target route'}.`);
    }
    screenshotBytes += assertPng(route?.screenshot?.base64, `${route?.path || '/'} ${route?.viewport?.name || 'viewport'}`);
    const finalHost = new URL(route?.signals?.finalUrl || targetUrl).hostname;
    if (finalHost !== target.hostname) {
      throw new Error(`Global capture reached ${finalHost} instead of the DDEV target host ${target.hostname}.`);
    }
  }

  if (networkCapture?.status !== 'captured' || networkCapture?.authoritative !== true) {
    throw new Error(`Verifier-owned CDP network capture failed: ${(networkCapture?.errors || []).join(' ') || 'no authoritative capture'}`);
  }
  if (networkCapture?.runtime?.backend !== 'selenium-grid-cdp' || networkCapture?.runtime?.ready !== true) {
    throw new Error('Network capture did not report a ready Selenium Grid CDP runtime.');
  }
  const requests = (networkCapture.routes || []).flatMap((route) => route?.requests || []);
  const targetRequests = requests.filter((request) => {
    try { return new URL(request.url).hostname === target.hostname; }
    catch { return false; }
  });
  if (targetRequests.length === 0) {
    throw new Error(`CDP Network events contained no request for the DDEV target host ${target.hostname}.`);
  }
  if (!(networkCapture.routes || []).every((route) => route?.isolation?.browserContextFresh === true)) {
    throw new Error('Network capture did not use a fresh verifier-owned browser context.');
  }

  return {
    axeRouteViewportCount: globalCapture.routes.length,
    browserVersion: globalCapture.browser?.product || null,
    executionBoundary: 'ddev-add-on-sidecar',
    networkRequestCount: requests.length,
    screenshotBytes,
    targetHost: target.hostname
  };
}

export async function runBrowserRuntimeSmoke({
  gridUrl = process.env.AGENT_READY_BROWSER_GRID_URL || 'http://selenium-chrome:4444',
  targetUrl = process.env.AGENT_READY_BROWSER_SMOKE_TARGET || process.env.DDEV_PRIMARY_URL,
  timeoutMs = Number.parseInt(process.env.AGENT_READY_BROWSER_SMOKE_TIMEOUT_MS || '90000', 10)
} = {}) {
  if (!targetUrl) {
    throw new Error('DDEV_PRIMARY_URL is missing; the smoke must run from the DDEV web container.');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 5000 || timeoutMs > 120000) {
    throw new Error('AGENT_READY_BROWSER_SMOKE_TIMEOUT_MS must be an integer from 5000 through 120000.');
  }
  const grid = new URL(gridUrl);
  if (grid.protocol !== 'http:' || grid.hostname !== 'selenium-chrome' || grid.port !== '4444' || grid.pathname !== '/') {
    throw new Error('The supported Grid boundary is exactly http://selenium-chrome:4444.');
  }

  const { captureBeforeConsentNetwork, captureGlobalChrome } = await loadCaptureModule();
  const deadline = Date.now() + timeoutMs;
  const remaining = () => {
    const value = deadline - Date.now();
    if (value < 1000) throw new Error(`Browser runtime smoke exceeded its ${timeoutMs} ms deadline.`);
    return value;
  };

  const globalCapture = await captureGlobalChrome({
    baseUrl: targetUrl,
    browserBackend: 'remote',
    gridUrl: grid.origin,
    limits: { deadlineMs: remaining(), maxRoutes: 1 },
    primaryRoutes: ['/']
  });
  const networkCapture = await captureBeforeConsentNetwork({
    baseUrl: targetUrl,
    browserBackend: 'remote',
    gridUrl: grid.origin,
    limits: { deadlineMs: remaining(), maxRoutes: 1 },
    primaryRoutes: ['/']
  });
  return validateBrowserRuntimeSmoke({ globalCapture, networkCapture, targetUrl });
}

function invokedDirectly() {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (invokedDirectly()) {
  try {
    const result = await runBrowserRuntimeSmoke();
    process.stdout.write(`${JSON.stringify({ ...result, ready: true })}\n`);
  } catch (error) {
    process.stderr.write(`Browser runtime smoke failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
