import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  BEFORE_CONSENT_NETWORK_SCHEMA,
  BROWSER_CAPTURE_LIMITS,
  COMPUTED_STYLE_EVIDENCE_SCHEMA,
  COMPUTED_STYLE_LIMITS,
  COMPUTED_STYLE_SHADOW_SCHEMA,
  DEFAULT_SELENIUM_GRID_URL,
  PUBLIC_FORM_CONTROL_LIMITS,
  SELENIUM_ADD_ON_RELEASE,
  SELENIUM_CHROMIUM_IMAGE,
  VERIFIER_AXE_SCHEMA,
  VERIFIER_AXE_SOURCE_SHA256,
  VERIFIER_AXE_TAGS,
  VERIFIER_AXE_VERSION,
  VERIFIER_WEBSOCKET_BUNDLE_SHA256,
  VERIFIER_WEBSOCKET_SOURCE_SHA256,
  VERIFIER_WEBSOCKET_VERSION,
  captureBeforeConsentNetwork,
  captureGlobalChrome,
  captureSummary,
  canonicalizeSeleniumCdpUrl,
  cleanupBrowserProfile,
  compareComputedStyleShadow,
  compareGlobalChromeCaptures,
  compareVerifierOwnedVisualFloor,
  createBrowserCaptureBudget,
  finalizeBeforeConsentNetworkCapture,
  finalizeGlobalChromeCapture,
  findBrowserExecutable,
  globalChromeImpact,
  normalizeComputedStyleEvidence,
  normalizeGlobalChromeContract,
  openSeleniumCdpBackend,
  validateBeforeConsentNetworkCapture,
  validateGlobalChromeCapture,
  validateScreenshotArtifacts,
  verifierAxeCompletionErrors
} from '../bin/global-chrome.mjs';
import {
  buildReviewedBuilderVisualFallback,
  consentNetworkCaptureRequired,
  sharedBeforeConsentNetworkCapture,
  sharedGlobalChromeCapture,
  verifierOwnedManagedBrowserRoutes,
  verifierOwnedPublicFormRoutes,
  visualParityCompletionSupport,
  verifyConsentReconciliation
} from '../bin/verify.mjs';
import { sha256 } from '../bin/state-fingerprint.mjs';

const { WebSocketServer } = await import('../vendor/ws/8.21.0/ws.mjs');

const state = (seed) => `sha256:${seed.repeat(64)}`;

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

class FixtureWebSocket extends EventEmitter {
  constructor(respond) {
    super();
    this.respond = respond;
    this.closed = false;
    this.terminated = false;
  }

  send(value) {
    const message = JSON.parse(value);
    queueMicrotask(() => this.respond(message, (response) => {
      this.emit('message', JSON.stringify(response), false);
    }, this));
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    queueMicrotask(() => this.emit('close'));
  }

  terminate() {
    this.terminated = true;
    this.close();
  }
}

function beforeConsentCaptureFixture({
  requests = [],
  stateFingerprint = state('e'),
  targetOrigin = 'https://fixture.ddev.site'
} = {}) {
  const primaryRoutes = ['/'];
  const budget = createBrowserCaptureBudget({
    label: 'Before-consent fixture',
    routeCount: primaryRoutes.length,
    viewportCount: 1
  });
  const capture = {
    schemaVersion: BEFORE_CONSENT_NETWORK_SCHEMA,
    checkedAt: '2026-07-12T00:00:00Z',
    status: 'captured',
    authoritative: true,
    captureMode: 'verifier-owned-cdp-network',
    targetOrigin,
    browser: { executable: 'fixture-chromium', product: 'Fixture Chromium' },
    primaryRoutes,
    routes: [{
      path: '/',
      requestedUrl: `${targetOrigin}/`,
      finalUrl: `${targetOrigin}/`,
      isolation: {
        browserContextFresh: true,
        cacheDisabled: true,
        consentInteractionPerformed: false,
        method: 'new-incognito-browser-context',
        storageCleared: true
      },
      observation: {
        floorMs: 2000,
        maximumMs: 8000,
        networkQuietMs: 500,
        settled: true
      },
      requests
    }],
    budget: budget.metrics({ attempted: true, capturedCount: primaryRoutes.length }),
    warnings: [],
    errors: []
  };
  return finalizeBeforeConsentNetworkCapture({ capture, stateFingerprint, targetOrigin });
}

test('browser capture budget enforces an absolute route ceiling and aggregate deadline', () => {
  let clock = 1_000;
  const routeBudget = createBrowserCaptureBudget({
    label: 'Fixture capture',
    limits: { maxRoutes: BROWSER_CAPTURE_LIMITS.maxRoutes + 10 },
    now: () => clock,
    routeCount: BROWSER_CAPTURE_LIMITS.maxRoutes + 1,
    viewportCount: 2
  });
  assert.throws(
    () => routeBudget.assertRouteLimit(),
    new RegExp(`exceeding the ${BROWSER_CAPTURE_LIMITS.maxRoutes} route limit`, 'i')
  );
  assert.equal(routeBudget.metrics().scheduledRouteViewportCount, (BROWSER_CAPTURE_LIMITS.maxRoutes + 1) * 2);

  const deadlineBudget = createBrowserCaptureBudget({
    label: 'Fixture capture',
    limits: { deadlineMs: 50 },
    now: () => clock,
    routeCount: 1,
    viewportCount: 2
  });
  clock += 40;
  assert.deepEqual(deadlineBudget.operationTiming(), { deadlineLimited: true, timeoutMs: 10 });
  clock += 10;
  assert.throws(() => deadlineBudget.assertWithinDeadline(), /50 ms total wall-clock deadline/i);
  assert.equal(deadlineBudget.metrics().deadlineExceeded, true);
});

test('Selenium se:cdp canonicalization keeps only the session path and trusted Grid origin', () => {
  assert.equal(
    canonicalizeSeleniumCdpUrl(
      'ws://192.168.97.32:4444/session/session-123/se/cdp',
      'session-123',
      DEFAULT_SELENIUM_GRID_URL
    ),
    'ws://selenium-chrome:4444/session/session-123/se/cdp'
  );
  assert.equal(
    canonicalizeSeleniumCdpUrl(
      'wss://untrusted.example/session/session-123/se/cdp',
      'session-123',
      'https://grid.internal:4444'
    ),
    'wss://grid.internal:4444/session/session-123/se/cdp'
  );
  for (const advertised of [
    'ws://bridge:4444/session/other/se/cdp',
    'ws://bridge:4444/session/session-123/se/cdp?token=secret',
    'ws://user:password@bridge:4444/session/session-123/se/cdp',
    'ws://bridge:4444/devtools/browser/session-123'
  ]) {
    assert.throws(
      () => canonicalizeSeleniumCdpUrl(advertised, 'session-123'),
      /exact session-scoped path/i
    );
  }
  assert.throws(
    () => canonicalizeSeleniumCdpUrl('ws://bridge:4444/session/session-123/se/cdp', '../session'),
    /invalid session ID/i
  );
});

test('vendored ws client matches its pinned upstream source and generated-bundle integrity record', () => {
  const vendorRoot = fileURLToPath(new URL(`../vendor/ws/${VERIFIER_WEBSOCKET_VERSION}/`, import.meta.url));
  const integrity = JSON.parse(readFileSync(join(vendorRoot, 'INTEGRITY.json'), 'utf8'));
  const bundle = readFileSync(join(vendorRoot, 'ws.mjs'));
  assert.equal(integrity.package, 'ws');
  assert.equal(integrity.version, VERIFIER_WEBSOCKET_VERSION);
  assert.equal(`sha256:${integrity.sourceSha256}`, VERIFIER_WEBSOCKET_SOURCE_SHA256);
  assert.equal(sha256(bundle), VERIFIER_WEBSOCKET_BUNDLE_SHA256);
  assert.equal(`sha256:${integrity.bundle.sha256}`, VERIFIER_WEBSOCKET_BUNDLE_SHA256);
  assert.match(readFileSync(join(vendorRoot, 'LICENSE'), 'utf8'), /Permission is hereby granted, free of charge/);
});

test('global chrome disables project-resolved ws native addons before loading the pinned client', () => {
  const project = mkdtempSync(join(tmpdir(), 'global-chrome-ws-boundary-'));
  const skillRoot = join(project, '.agents', 'skills', 'agent-ready-drupal-build-kit');
  mkdirSync(join(skillRoot, 'scripts'), { recursive: true });
  mkdirSync(join(skillRoot, 'assets', 'vendor'), { recursive: true });
  mkdirSync(join(skillRoot, 'vendor'), { recursive: true });
  cpSync(fileURLToPath(new URL('../bin/global-chrome.mjs', import.meta.url)), join(skillRoot, 'scripts', 'global-chrome.mjs'));
  cpSync(fileURLToPath(new URL('../bin/state-fingerprint.mjs', import.meta.url)), join(skillRoot, 'scripts', 'state-fingerprint.mjs'));
  cpSync(fileURLToPath(new URL('../assets/vendor/axe-core', import.meta.url)), join(skillRoot, 'assets', 'vendor', 'axe-core'), { recursive: true });
  cpSync(fileURLToPath(new URL('../vendor/ws', import.meta.url)), join(skillRoot, 'vendor', 'ws'), { recursive: true });

  for (const packageName of ['bufferutil', 'utf-8-validate']) {
    const packageRoot = join(project, 'node_modules', packageName);
    mkdirSync(packageRoot, { recursive: true });
    writeFileSync(join(packageRoot, 'package.json'), JSON.stringify({ name: packageName, main: 'index.js' }));
    writeFileSync(
      join(packageRoot, 'index.js'),
      `process.env.AGENT_READY_UNTRUSTED_WS_ADDON = ${JSON.stringify(packageName)}; module.exports = {};\n`
    );
  }

  const moduleUrl = pathToFileURL(join(skillRoot, 'scripts', 'global-chrome.mjs')).href;
  const child = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    delete process.env.WS_NO_BUFFER_UTIL;
    delete process.env.WS_NO_UTF_8_VALIDATE;
    await import(${JSON.stringify(moduleUrl)});
    if (process.env.AGENT_READY_UNTRUSTED_WS_ADDON) throw new Error('project addon loaded: ' + process.env.AGENT_READY_UNTRUSTED_WS_ADDON);
    if (process.env.WS_NO_BUFFER_UTIL || process.env.WS_NO_UTF_8_VALIDATE) throw new Error('ws guard environment was not restored');
  `], { cwd: project, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);

  const bundlePath = join(skillRoot, 'vendor', 'ws', VERIFIER_WEBSOCKET_VERSION, 'ws.mjs');
  writeFileSync(bundlePath, `${readFileSync(bundlePath, 'utf8')}\n// tampered after installation\n`);
  const tampered = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    await import(${JSON.stringify(moduleUrl)});
  `], { cwd: project, encoding: 'utf8' });
  assert.notEqual(tampered.status, 0);
  assert.match(tampered.stderr, /WebSocket transport failed its runtime integrity check/);
});

test('vendored ws client imports and carries real CDP request/response frames over an HTTP upgrade', async () => {
  const server = createServer();
  const webSocketServer = new WebSocketServer({ server, perMessageDeflate: false });
  webSocketServer.on('connection', (socket) => {
    socket.on('message', (data, binary) => {
      assert.equal(binary, false);
      const message = JSON.parse(data.toString('utf8'));
      socket.send(JSON.stringify({
        id: message.id,
        result: { product: 'Chrome/149.0', protocolVersion: '1.3' }
      }));
    });
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const gridUrl = `http://127.0.0.1:${server.address().port}`;
  const budget = createBrowserCaptureBudget({ label: 'Real ws fixture', routeCount: 1, viewportCount: 1 });
  let backend;
  try {
    backend = await openSeleniumCdpBackend({
      budget,
      gridUrl,
      async fetchImpl(_url, init) {
        if (init.method === 'POST') {
          return jsonResponse({
            value: {
              sessionId: 'fixture-session',
              capabilities: { 'se:cdp': 'ws://untrusted/session/fixture-session/se/cdp' }
            }
          });
        }
        return jsonResponse({ value: null });
      }
    });
    assert.deepEqual(await backend.cdp.send('Browser.getVersion'), {
      product: 'Chrome/149.0',
      protocolVersion: '1.3'
    });
    assert.deepEqual(await backend.close(), { errors: [], warnings: [] });
  } finally {
    if (backend) await backend.close();
    for (const client of webSocketServer.clients) client.terminate();
    await new Promise((resolveClose) => webSocketServer.close(resolveClose));
    await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  }
});

test('remote Selenium backend bounds WebDriver lifecycle, routes CDP messages, and always deletes its known session', async () => {
  const requests = [];
  let connectedUrl = '';
  const socket = new FixtureWebSocket((message, reply) => {
    reply({ id: message.id, result: { product: 'Chrome/149.0', protocolVersion: '1.3' } });
  });
  const fetchImpl = async (url, init) => {
    requests.push({
      url,
      method: init.method,
      redirect: init.redirect,
      body: init.body ? JSON.parse(init.body) : null
    });
    if (init.method === 'POST') {
      return jsonResponse({
        value: {
          sessionId: 'fixture-session',
          capabilities: { 'se:cdp': 'ws://172.20.0.9:4444/session/fixture-session/se/cdp' }
        }
      });
    }
    return jsonResponse({ value: null });
  };
  const budget = createBrowserCaptureBudget({ label: 'Remote fixture', routeCount: 1, viewportCount: 1 });
  const backend = await openSeleniumCdpBackend({
    budget,
    fetchImpl,
    async webSocketConnector(url, { signal }) {
      assert.equal(signal.aborted, false);
      connectedUrl = url;
      return socket;
    }
  });
  assert.deepEqual(await backend.cdp.send('Browser.getVersion'), { product: 'Chrome/149.0', protocolVersion: '1.3' });
  const firstClose = backend.close();
  assert.strictEqual(backend.close(), firstClose);
  assert.deepEqual(await firstClose, { errors: [], warnings: [] });
  assert.equal(socket.terminated, true, 'remote CDP transport should close immediately before WebDriver session deletion');
  assert.equal(connectedUrl, 'ws://selenium-chrome:4444/session/fixture-session/se/cdp');
  assert.deepEqual(requests.map(({ method, url }) => `${method} ${url}`), [
    'POST http://selenium-chrome:4444/session',
    'DELETE http://selenium-chrome:4444/session/fixture-session'
  ]);
  assert.deepEqual(requests.map(({ redirect }) => redirect), ['error', 'error']);
  assert.deepEqual(requests[0].body.capabilities.alwaysMatch, {
    browserName: 'chrome',
    acceptInsecureCerts: true,
    'goog:chromeOptions': {
      args: ['--headless=new', '--disable-gpu', '--no-sandbox', '--window-size=1280,800']
    }
  });
});

test('remote Selenium backend deletes a created session when se:cdp validation fails', async () => {
  const methods = [];
  const budget = createBrowserCaptureBudget({ label: 'Remote invalid fixture', routeCount: 1, viewportCount: 1 });
  await assert.rejects(
    () => openSeleniumCdpBackend({
      budget,
      async fetchImpl(url, init) {
        methods.push(`${init.method} ${new URL(url).pathname}`);
        if (init.method === 'POST') {
          return jsonResponse({
            value: {
              sessionId: 'fixture-session',
              capabilities: { 'se:cdp': 'ws://bridge:4444/session/a-different-session/se/cdp' }
            }
          });
        }
        return jsonResponse({ value: null });
      },
      async webSocketConnector() {
        assert.fail('A rejected se:cdp path must not be connected.');
      }
    }),
    /Verifier Selenium runtime is unavailable.*exact session-scoped path/i
  );
  assert.deepEqual(methods, ['POST /session', 'DELETE /session/fixture-session']);
});

test('DDEV container mode uses the remote Grid, owns its global context, and reports runtime readiness', async () => {
  const commands = [];
  const httpMethods = [];
  const targetUrl = 'https://fixture.ddev.site/';
  const axeReport = {
    testEngine: { name: 'axe-core', version: VERIFIER_AXE_VERSION },
    testRunner: { name: 'axe' },
    testEnvironment: {},
    timestamp: '2026-07-13T00:00:00.000Z',
    url: targetUrl,
    toolOptions: {},
    passes: [],
    incomplete: [],
    inapplicable: [],
    violations: []
  };
  const socket = new FixtureWebSocket((message, reply, fixtureSocket) => {
    commands.push(message);
    let result = {};
    if (message.method === 'Browser.getVersion') result = { product: 'Chrome/149.0', protocolVersion: '1.3' };
    if (message.method === 'Browser.getBrowserCommandLine') result = { arguments: ['/usr/bin/chromium', '--headless=new'] };
    if (message.method === 'Target.createBrowserContext') result = { browserContextId: 'owned-context' };
    if (message.method === 'Target.createTarget') result = { targetId: 'owned-target' };
    if (message.method === 'Target.attachToTarget') result = { sessionId: 'page-session' };
    if (message.method === 'Runtime.evaluate') {
      if (message.params.expression.includes('agent-ready-axe-core-4.10.3-preflight.js')) {
        result = { result: { value: VERIFIER_AXE_VERSION } };
      } else if (message.params.expression.includes('globalThis.axe')) result = { result: { value: axeReport } };
      else if (message.params.expression.includes('document.fonts')) result = { result: { value: true } };
      else {
        result = {
          result: {
            value: {
              title: 'Fixture',
              finalUrl: targetUrl,
              maskViolations: [],
              maskedRegionCount: 0,
              roles: {},
              meaningfulHrefs: [],
              placeholderHrefs: [],
              mobileMenu: {},
              layout: {}
            }
          }
        };
      }
    }
    if (message.method === 'Page.getLayoutMetrics') result = { cssContentSize: { width: 800, height: 600 } };
    if (message.method === 'Page.captureScreenshot') result = { data: Buffer.from('fixture-png').toString('base64') };
    reply({ id: message.id, result });
    if (message.method === 'Page.navigate') {
      queueMicrotask(() => fixtureSocket.emit('message', JSON.stringify({
        method: 'Page.loadEventFired',
        sessionId: message.sessionId,
        params: { timestamp: 1 }
      }), false));
    }
  });
  const raw = await captureGlobalChrome({
    baseUrl: targetUrl,
    primaryRoutes: ['/'],
    environment: { IS_DDEV_PROJECT: 'true', CHROME_PATH: '/bin/true' },
    async fetchImpl(url, init) {
      httpMethods.push(`${init.method} ${new URL(url).pathname}`);
      if (init.method === 'POST') {
        return jsonResponse({
          value: {
            sessionId: 'fixture-session',
            capabilities: { 'se:cdp': 'ws://bridge:4444/session/fixture-session/se/cdp' }
          }
        });
      }
      return jsonResponse({ value: null });
    },
    async webSocketConnector() { return socket; }
  });
  assert.equal(raw.status, 'captured', raw.errors.join('\n'));
  assert.equal(raw.runtime.ready, true);
  assert.equal(raw.routes[0].signals.computedStyleEvidence.schemaVersion, COMPUTED_STYLE_EVIDENCE_SCHEMA);
  assert.deepEqual(raw.routes[0].signals.computedStyleEvidence.samples, []);
  assert.deepEqual(raw.runtime, {
    backend: 'selenium-grid-cdp',
    executionBoundary: 'ddev-add-on-sidecar',
    service: 'selenium-chrome',
    addOnRelease: SELENIUM_ADD_ON_RELEASE,
    image: SELENIUM_CHROMIUM_IMAGE,
    executable: '/usr/bin/chromium',
    product: 'Chrome/149.0',
    protocolVersion: '1.3',
    ready: true
  });
  assert.deepEqual(captureSummary(raw).runtime, raw.runtime);
  assert.equal(commands.filter(({ method }) => method === 'Target.createBrowserContext').length, 1);
  assert.deepEqual(commands.find(({ method }) => method === 'Target.createTarget').params, {
    url: 'about:blank',
    browserContextId: 'owned-context'
  });
  assert.ok(commands.some(({ method, params }) => method === 'Target.disposeBrowserContext' && params.browserContextId === 'owned-context'));
  assert.ok(commands.some(({ method }) => method === 'Network.enable'));
  assert.ok(commands.some(({ method }) => method === 'Page.captureScreenshot'));
  assert.deepEqual(httpMethods, ['POST /session', 'DELETE /session/fixture-session']);
});

test('DDEV remote runtime failure never falls back to an ambient local executable', async () => {
  const unavailable = await captureBeforeConsentNetwork({
    baseUrl: 'https://fixture.ddev.site',
    primaryRoutes: ['/'],
    environment: { IS_DDEV_PROJECT: 'true', CHROME_PATH: '/bin/true' },
    async fetchImpl() { throw new Error('fixture Grid refusal'); }
  });
  assert.equal(unavailable.status, 'unavailable');
  assert.equal(unavailable.runtime.backend, 'selenium-grid-cdp');
  assert.equal(unavailable.runtime.ready, false);
  assert.match(unavailable.errors.join('\n'), /fixture Grid refusal/i);
});

test('DDEV remote runtime fails preflight when the observed browser major drifts from the pinned image', async () => {
  const commands = [];
  const socket = new FixtureWebSocket((message, reply) => {
    commands.push(message.method);
    const result = message.method === 'Browser.getVersion'
      ? { product: 'Chrome/148.0.0.0', protocolVersion: '1.3' }
      : {};
    reply({ id: message.id, result });
  });
  const capture = await captureGlobalChrome({
    baseUrl: 'https://fixture.ddev.site',
    primaryRoutes: ['/'],
    environment: { IS_DDEV_PROJECT: 'true' },
    async fetchImpl(_url, init) {
      if (init.method === 'POST') {
        return jsonResponse({
          value: {
            sessionId: 'fixture-session',
            capabilities: { 'se:cdp': 'ws://bridge:4444/session/fixture-session/se/cdp' }
          }
        });
      }
      return jsonResponse({ value: null });
    },
    async webSocketConnector() { return socket; }
  });
  assert.equal(capture.status, 'blocked');
  assert.equal(capture.runtime.ready, false);
  assert.equal(capture.runtime.product, 'Chrome/148.0.0.0');
  assert.match(capture.errors.join('\n'), /does not match pinned Chromium major 149/i);
  assert.deepEqual(commands, ['Browser.getVersion']);
});

test('global chrome capture fails closed before browser launch when route or wall-clock bounds are exceeded', async () => {
  const tooManyRoutes = await captureGlobalChrome({
    baseUrl: 'http://127.0.0.1',
    primaryRoutes: Array.from({ length: BROWSER_CAPTURE_LIMITS.maxRoutes + 1 }, (_, index) => `/route-${index}`)
  });
  assert.equal(tooManyRoutes.status, 'blocked');
  assert.equal(tooManyRoutes.authoritative, false);
  assert.equal(tooManyRoutes.budget.attempted, false);
  assert.equal(tooManyRoutes.budget.routeCount, BROWSER_CAPTURE_LIMITS.maxRoutes + 1);
  assert.match(tooManyRoutes.errors.join('\n'), /route limit; no browser checks were run/i);

  const clockValues = [0, 11, 11];
  const expired = await captureGlobalChrome({
    baseUrl: 'http://127.0.0.1',
    primaryRoutes: ['/'],
    limits: { deadlineMs: 10 },
    now: () => clockValues.shift() ?? 11
  });
  assert.equal(expired.status, 'blocked');
  assert.equal(expired.authoritative, false);
  assert.equal(expired.budget.deadlineExceeded, true);
  assert.equal(expired.budget.deadlineMs, 10);
  assert.match(expired.errors.join('\n'), /10 ms total wall-clock deadline/i);
});

test('managed public-form route closure deduplicates capture identities but never slices overflow', () => {
  const primaryRoutes = [{ sourcePath: '/', targetPath: '/' }];
  const publicFormRoutes = [
    ...Array.from({ length: BROWSER_CAPTURE_LIMITS.maxRoutes }, (_value, index) => ({
      sourcePath: `/form-${index}`,
      targetPath: `/form-${index}`,
      routeRole: 'form'
    })),
    { sourcePath: '/legacy-form', targetPath: '/form-0', routeRole: 'form' }
  ];
  const targetRoutes = verifierOwnedManagedBrowserRoutes({ primaryRoutes, publicFormRoutes });
  const sourceRoutes = verifierOwnedManagedBrowserRoutes({
    captureSide: 'source',
    primaryRoutes,
    publicFormRoutes
  });
  assert.equal(targetRoutes.length, BROWSER_CAPTURE_LIMITS.maxRoutes + 1);
  assert.equal(sourceRoutes.length, BROWSER_CAPTURE_LIMITS.maxRoutes + 2);
  assert.equal(targetRoutes.filter((route) => route.targetPath === '/form-0').length, 1);
  assert.equal(sourceRoutes.at(-1).targetPath, '/legacy-form');
  const budget = createBrowserCaptureBudget({
    label: 'Verifier-owned public-form capture',
    routeCount: targetRoutes.length,
    viewportCount: 2
  });
  assert.throws(
    () => budget.assertRouteLimit(),
    /requires 65 routes, exceeding the 64 route limit; no browser checks were run/i
  );
  assert.equal(budget.metrics().attempted, false);
  const blockedComparison = compareVerifierOwnedVisualFloor({
    sourceCapture: {},
    targetCapture: {},
    primaryRoutes: [],
    publicFormControlRoutes: publicFormRoutes,
    stateFingerprint: state('f')
  });
  assert.equal(blockedComparison.status, 'blocked');
  assert.match(blockedComparison.errors.join('\n'), /65 exact source\/target route pairs.*64 route-pair limit/i);
  assert.equal(blockedComparison.publicFormControlFindings.length, 0);
});

test('before-consent capture reuses the browser route ceiling and aggregate deadline', async () => {
  const tooManyRoutes = await captureBeforeConsentNetwork({
    baseUrl: 'http://127.0.0.1',
    primaryRoutes: Array.from({ length: BROWSER_CAPTURE_LIMITS.maxRoutes + 1 }, (_, index) => `/route-${index}`),
    browserExecutable: '/definitely/not/a/browser'
  });
  assert.equal(tooManyRoutes.status, 'blocked');
  assert.equal(tooManyRoutes.authoritative, false);
  assert.equal(tooManyRoutes.budget.attempted, false);
  assert.equal(tooManyRoutes.budget.routeCount, BROWSER_CAPTURE_LIMITS.maxRoutes + 1);
  assert.equal(tooManyRoutes.budget.viewportCount, 1);
  assert.match(tooManyRoutes.errors.join('\n'), /route limit; no browser checks were run/i);

  const clockValues = [0, 11, 11];
  const expired = await captureBeforeConsentNetwork({
    baseUrl: 'http://127.0.0.1',
    primaryRoutes: ['/'],
    browserExecutable: '/definitely/not/a/browser',
    limits: { deadlineMs: 10 },
    now: () => clockValues.shift() ?? 11
  });
  assert.equal(expired.status, 'blocked');
  assert.equal(expired.authoritative, false);
  assert.equal(expired.budget.deadlineExceeded, true);
  assert.equal(expired.budget.deadlineMs, 10);
  assert.match(expired.errors.join('\n'), /10 ms total wall-clock deadline/i);
});

test('every declared controlled consent app requires verifier-owned capture', () => {
  const declaration = (kind, { enabled = true, required = false } = {}) => ({
    discoveryStatus: 'installed',
    managers: [{ id: 'klaro', module: 'klaro', configNames: [`klaro.application.${kind}`] }],
    applications: [{
      id: kind,
      managerId: 'klaro',
      configName: `klaro.application.${kind}`,
      enabled,
      required,
      controlledResources: [{ kind, pattern: kind === 'selector' ? '#external-media' : 'remote_video' }]
    }]
  });
  assert.equal(consentNetworkCaptureRequired(declaration('selector')), true);
  assert.equal(consentNetworkCaptureRequired(declaration('attachment', { enabled: false, required: false })), true);
  assert.equal(consentNetworkCaptureRequired(declaration('selector', { enabled: true, required: true })), true);

  for (const kind of ['selector', 'attachment']) {
    const record = declaration(kind, { enabled: kind === 'selector', required: false });
    const application = record.applications[0];
    const reconciliation = verifyConsentReconciliation(record, {
      confirmed: true,
      detected: true,
      managerModules: ['klaro'],
      configNames: [application.configName],
      applications: [{
        id: application.id,
        configName: application.configName,
        enabled: application.enabled,
        required: application.required,
        resources: application.controlledResources
      }]
    }, [{ renderedResourceUrls: [] }], null, {
      targetOrigin: 'https://fixture.ddev.site',
      primaryRoutes: ['/'],
      stateFingerprint: state('e')
    });
    assert.equal(reconciliation.passed, false, `${kind} capture unexpectedly passed`);
    assert.match(reconciliation.errors.join('\n'), /requires verifier-owned fresh browser\/network capture/i);
    assert.equal(reconciliation.authoritativeBeforeConsentCapture, false);
  }
});

test('all-enabled required analytics and marketing apps cannot bypass pre-consent capture', () => {
  const applications = [
    {
      id: 'analytics',
      managerId: 'klaro',
      configName: 'klaro.application.analytics',
      enabled: true,
      required: true,
      controlledResources: [{ kind: 'script', pattern: 'analytics.example/collect.js' }]
    },
    {
      id: 'marketing',
      managerId: 'klaro',
      configName: 'klaro.application.marketing',
      enabled: true,
      required: true,
      controlledResources: [{ kind: 'script', pattern: 'marketing.example/pixel.js' }]
    }
  ];
  const declaration = {
    discoveryStatus: 'installed',
    managers: [{
      id: 'klaro',
      module: 'klaro',
      configNames: applications.map((application) => application.configName)
    }],
    applications
  };
  const runtime = {
    confirmed: true,
    detected: true,
    managerModules: ['klaro'],
    configNames: applications.map((application) => application.configName),
    applications: applications.map((application) => ({
      id: application.id,
      configName: application.configName,
      enabled: application.enabled,
      required: application.required,
      resources: application.controlledResources
    }))
  };
  const context = {
    targetOrigin: 'https://fixture.ddev.site',
    primaryRoutes: ['/'],
    stateFingerprint: state('e')
  };

  assert.equal(consentNetworkCaptureRequired(declaration), true);
  const missingCapture = verifyConsentReconciliation(
    declaration,
    runtime,
    [{ renderedResourceUrls: [] }],
    null,
    context
  );
  assert.equal(missingCapture.passed, false);
  assert.match(missingCapture.errors.join('\n'), /requires verifier-owned fresh browser\/network capture/i);

  const noRequests = verifyConsentReconciliation(
    declaration,
    runtime,
    [{ renderedResourceUrls: [] }],
    beforeConsentCaptureFixture(),
    context
  );
  assert.equal(noRequests.authoritativeBeforeConsentCapture, true);
  assert.equal(noRequests.passed, false);
  assert.match(noRequests.errors.join('\n'), /required consent application analytics lacks.*essential-without-consent/i);

  const essentialDeclaration = structuredClone(declaration);
  for (const application of essentialDeclaration.applications) {
    application.essentialWithoutConsent = true;
    application.essentialServiceRationale = 'Fixture-only essential service classification.';
    application.essentialServiceEvidence = ['evidence/essential-service.json'];
  }
  const justifiedNoRequests = verifyConsentReconciliation(
    essentialDeclaration,
    runtime,
    [{ renderedResourceUrls: [] }],
    beforeConsentCaptureFixture(),
    context
  );
  assert.equal(justifiedNoRequests.authoritativeBeforeConsentCapture, true);
  assert.equal(justifiedNoRequests.passed, true, justifiedNoRequests.errors.join('\n'));

  const capture = beforeConsentCaptureFixture({
    requests: [{
      method: 'GET',
      resourceType: 'Script',
      url: 'https://analytics.example/collect.js'
    }]
  });
  const observedRequest = verifyConsentReconciliation(
    declaration,
    runtime,
    [{ renderedResourceUrls: [] }],
    capture,
    context
  );
  assert.equal(observedRequest.authoritativeBeforeConsentCapture, true);
  assert.equal(observedRequest.passed, false);
  assert.match(
    observedRequest.errors.join('\n'),
    /analytics lacks.*essential-without-consent.*analytics loaded before consent.*lacks an evidence-backed essential-service classification.*analytics\.example\/collect\.js/is
  );
});

test('profile cleanup uses bounded retries and reports a deferred warning without leaking its path', () => {
  let options;
  const result = cleanupBrowserProfile('/sensitive/local/profile', {
    remove(_profile, receivedOptions) {
      options = receivedOptions;
      const error = new Error('directory still changing: /sensitive/local/profile');
      error.code = 'ENOTEMPTY';
      throw error;
    }
  });
  assert.equal(result.deferred, true);
  assert.deepEqual(result.warnings, ['Browser profile cleanup was deferred after bounded retries (ENOTEMPTY).']);
  assert.equal(result.warnings.join('\n').includes('/sensitive/local/profile'), false);
  assert.equal(options.maxRetries, 5);
  assert.equal(options.retryDelay, 50);
});

function captureFixture(stateFingerprint, mutate = () => {}) {
  const contract = normalizeGlobalChromeContract({ dynamicRegionSelectors: ['[data-dynamic]'] });
  const routes = ['desktop', 'mobile'].map((viewport) => ({
    path: '/',
    viewport: { name: viewport, width: viewport === 'desktop' ? 1280 : 390, height: viewport === 'desktop' ? 800 : 844 },
    signals: {
      finalUrl: 'https://fixture.ddev.site/',
      maskViolations: [],
      roles: {
        brand: { present: true, visible: true, identity: { href: '/', image: '/logo.svg', alt: 'Fixture', text: '' } },
        header: { present: true, visible: true },
        navigation: { present: true, visible: true },
        footer: { present: true, visible: true }
      },
      meaningfulHrefs: [
        { scope: 'navigation', href: '/about', label: 'About' },
        { scope: 'footer', href: '/legal', label: 'Legal' }
      ],
      placeholderHrefs: [],
      mobileMenu: {
        triggerVisible: viewport === 'mobile',
        activationWorks: viewport === 'mobile'
      },
      layout: { normalizedPageHeight: 1200, mainBox: { top: 80 } }
    },
    screenshot: {
      path: `evidence/${viewport}.png`,
      sha256: state(viewport === 'desktop' ? 'a' : 'b'),
      size: 1200,
      width: viewport === 'desktop' ? 1280 : 390,
      height: 1200,
      clipped: false
    }
  }));
  const core = {
    schemaVersion: 'public-kit.global-chrome-capture.1',
    checkedAt: '2026-07-11T20:00:00Z',
    status: 'captured',
    authoritative: true,
    captureMode: 'verifier-owned-browser',
    targetOrigin: 'https://fixture.ddev.site',
    resultStateFingerprint: stateFingerprint,
    contract,
    browser: { executable: 'fixture', product: 'Fixture' },
    primaryRoutes: ['/'],
    routes,
    errors: []
  };
  mutate(core);
  return { ...core, captureFingerprint: sha256(core) };
}

test('computed global chrome comparison catches missing chrome, links, mobile behavior, and material collapse', () => {
  const anchor = captureFixture(state('1'));
  const current = captureFixture(state('2'), (capture) => {
    for (const route of capture.routes) {
      route.signals.roles.brand.visible = false;
      route.signals.meaningfulHrefs = [];
      route.signals.layout.normalizedPageHeight = 400;
      if (route.viewport.name === 'mobile') route.signals.mobileMenu.activationWorks = false;
    }
  });
  const comparison = compareGlobalChromeCaptures({ anchor, current, primaryRoutes: ['/'] });
  assert.equal(comparison.passed, false);
  assert.match(comparison.errors.join('\n'), /brand disappeared/i);
  assert.match(comparison.errors.join('\n'), /meaningful global hrefs disappeared/i);
  assert.match(comparison.errors.join('\n'), /mobile menu trigger no longer exposes navigation/i);
  assert.match(comparison.errors.join('\n'), /material normalized page-height change/i);
});

function publicFormControlEvidence(controls = [], formCount = controls.length > 0 ? 1 : 0) {
  const nextControlOrdinal = new Map();
  const structurallyBoundControls = controls.map((control) => {
    const formOrdinal = Number.isSafeInteger(control.formOrdinal) ? control.formOrdinal : 1;
    const controlOrdinal = Number.isSafeInteger(control.controlOrdinal)
      ? control.controlOrdinal
      : (nextControlOrdinal.get(formOrdinal) || 0) + 1;
    nextControlOrdinal.set(formOrdinal, controlOrdinal);
    return { ...control, formOrdinal, controlOrdinal };
  });
  return {
    schemaVersion: 'public-kit.public-form-controls.1',
    limits: PUBLIC_FORM_CONTROL_LIMITS,
    formCount,
    controlCount: structurallyBoundControls.length,
    controls: structurallyBoundControls,
    overflow: { controls: 0, labels: 0, optionControls: 0 }
  };
}

function visualFloorCapture({
  origin,
  hashSeed,
  structure,
  protectedSource = false,
  path = '/',
  publicFormControls = publicFormControlEvidence()
}) {
  const routes = ['desktop', 'mobile'].map((viewport, index) => ({
    path,
    viewport: {
      name: viewport,
      width: viewport === 'desktop' ? 1280 : 390,
      height: viewport === 'desktop' ? 800 : 844
    },
    signals: {
      finalUrl: `${origin}${path}`,
      roles: {
        header: { present: true, visible: true },
        navigation: { present: true, visible: true },
        main: { present: true, visible: true },
        footer: { present: true, visible: true }
      },
      mobileMenu: {
        triggerVisible: viewport === 'mobile',
        activationWorks: viewport === 'mobile'
      },
      layout: { normalizedPageHeight: 2400 },
      structure,
      publicFormControls: structuredClone(publicFormControls),
      protection: {
        detected: protectedSource,
        responseStatus: protectedSource ? 403 : 200,
        reasonCodes: protectedSource ? ['http-status-403'] : []
      }
    },
    screenshot: {
      path: `evidence/${hashSeed}-${viewport}.png`,
      sha256: state(index === 0 ? hashSeed : (hashSeed === 'a' ? 'c' : 'd')),
      size: 4096,
      width: viewport === 'desktop' ? 1280 : 390,
      height: 2400,
      clipped: false
    }
  }));
  return {
    schemaVersion: 'public-kit.global-chrome-capture.1',
    checkedAt: '2026-07-22T12:00:00Z',
    status: 'captured',
    authoritative: true,
    captureMode: 'verifier-owned-browser',
    targetOrigin: origin,
    resultStateFingerprint: state('f'),
    contract: normalizeGlobalChromeContract(),
    primaryRoutes: [path],
    routes,
    captureFingerprint: state(hashSeed),
    errors: []
  };
}

function combinedVisualFloorCapture(captures, fingerprintSeed) {
  const combined = structuredClone(captures[0]);
  combined.primaryRoutes = captures.flatMap((capture) => capture.primaryRoutes);
  combined.routes = captures.flatMap((capture) => capture.routes);
  combined.captureFingerprint = state(fingerprintSeed);
  return combined;
}

function primaryNavigation(entries, overrides = {}) {
  return {
    present: true,
    visible: true,
    entryCount: entries.length,
    capturedEntryCount: entries.length,
    entriesTruncated: false,
    labelTruncatedCount: 0,
    depthTruncatedCount: 0,
    entries: entries.map((entry, position) => ({
      position,
      depth: 0,
      depthTruncated: false,
      parentPosition: null,
      kind: 'link',
      labelTruncated: false,
      ...entry
    })),
    ...overrides
  };
}

function setPrimaryNavigation(capture, entries, overrides = {}) {
  for (const route of capture.routes) {
    route.signals.primaryNavigation = primaryNavigation(entries, overrides);
  }
  return capture;
}

const composedStructure = {
  headingOrder: ['Build faster', 'Why it matters', 'Capabilities', 'Start today'],
  headingCount: 4,
  layoutBandCount: 4,
  mediaCount: 3,
  actionCount: 4,
  prominentActionCount: 2
};

function observedControl({
  accessibleIdentity,
  occurrence = 1,
  kind = 'input_text',
  visibleLabel = accessibleIdentity,
  visibleLabelSource = visibleLabel ? (accessibleIdentity ? 'associated_label' : 'placeholder') : 'none',
  required = false,
  disabled = false,
  selected = null,
  defaultSelected = null,
  optionEvidence = 'not_applicable',
  options = []
}) {
  return {
    accessibleIdentity,
    occurrence,
    kind,
    visibleLabel,
    visibleLabelSource,
    required,
    disabled,
    selected,
    defaultSelected,
    optionEvidence,
    optionCount: options.length,
    options
  };
}

const publicContactControls = [
  observedControl({
    accessibleIdentity: 'email address',
    kind: 'input_email',
    visibleLabel: 'Email address',
    required: true
  }),
  observedControl({
    accessibleIdentity: 'topic',
    kind: 'select_single',
    visibleLabel: 'Topic',
    optionEvidence: 'observed',
    options: [
      { label: 'General', selected: true, defaultSelected: true, disabled: false },
      { label: 'Admissions', selected: false, defaultSelected: false, disabled: false },
      { label: 'Archived', selected: false, defaultSelected: false, disabled: true }
    ]
  }),
  observedControl({
    accessibleIdentity: 'send me a copy',
    kind: 'input_checkbox',
    visibleLabel: 'Send me a copy',
    selected: true,
    defaultSelected: true
  }),
  observedControl({ accessibleIdentity: 'send', kind: 'button_submit', visibleLabel: 'Send' })
];
const styleSelectionMethods = {
  body: 'document-body',
  heading_1: 'first-visible-h1',
  heading_2: 'first-visible-h2',
  primary_navigation_link: 'first-visible-primary-navigation-link',
  primary_action: 'first-visible-prominent-main-action',
  form_control: 'first-visible-main-form-control',
  card_or_listing_surface: 'first-visible-card-class'
};

function completeComputedStyleEvidence({
  family = 'Raleway',
  loadedFontFamilies = [family],
  roleStyles = {}
} = {}) {
  const sizes = {
    body: '16px',
    heading_1: '48px',
    heading_2: '32px',
    primary_navigation_link: '16px',
    primary_action: '16px',
    form_control: '16px',
    card_or_listing_surface: '16px'
  };
  return normalizeComputedStyleEvidence({
    loadedFontFamilies,
    samples: Object.entries(styleSelectionMethods).map(([semanticRole, selectionMethod]) => ({
      semanticRole,
      selectionMethod,
      styles: {
        fontFamily: `"${family}", sans-serif`,
        fontSize: sizes[semanticRole],
        fontWeight: semanticRole.startsWith('heading_') ? '700' : '400',
        lineHeight: '24px',
        letterSpacing: 'normal',
        color: 'rgb(20, 20, 20)',
        backgroundColor: 'rgba(0, 0, 0, 0)',
        borderColor: 'rgb(20, 20, 20)',
        borderRadius: '0px',
        ...(roleStyles[semanticRole] ?? {})
      }
    }))
  });
}

function attachComputedStyles(capture, evidenceForViewport) {
  for (const route of capture.routes) {
    route.signals.computedStyleEvidence = evidenceForViewport(route.viewport.name);
  }
  return capture;
}

test('computed-style shadow diagnoses font replacement and control-token drift without changing completion', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => completeComputedStyleEvidence({
      family: 'Raleway',
      roleStyles: {
        primary_action: {
          color: 'rgb(255, 255, 255)',
          backgroundColor: 'rgb(0, 85, 170)',
          borderColor: 'rgb(0, 85, 170)',
          borderRadius: '4px'
        },
        form_control: {
          backgroundColor: 'rgb(255, 255, 255)',
          borderColor: 'rgb(80, 80, 80)',
          borderRadius: '4px'
        }
      }
    })
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => completeComputedStyleEvidence({
      family: 'Inter',
      roleStyles: {
        primary_action: {
          color: 'rgb(0, 0, 0)',
          backgroundColor: 'rgb(245, 210, 80)',
          borderColor: 'rgb(0, 0, 0)',
          borderRadius: '24px'
        },
        form_control: {
          backgroundColor: 'rgb(240, 240, 240)',
          borderColor: 'rgb(0, 0, 0)',
          borderRadius: '12px'
        }
      }
    })
  );
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.equal(floor.completionSupported, true);
  assert.equal(visualParityCompletionSupport(floor), true);
  assert.equal(floor.computedStyleShadow.schemaVersion, COMPUTED_STYLE_SHADOW_SCHEMA);
  assert.equal(floor.computedStyleShadow.authority, 'none');
  assert.equal(floor.computedStyleShadow.completionEffect, 'none');
  assert.equal(floor.computedStyleShadow.completionStatusAffected, false);
  assert.equal(floor.computedStyleShadow.status, 'diagnostics');
  const diagnostics = floor.computedStyleShadow.comparisons.flatMap((comparison) => comparison.diagnostics);
  assert.ok(diagnostics.some((diagnostic) =>
    diagnostic.code === 'font-family-replaced' &&
    diagnostic.sourceFamily === 'raleway' &&
    diagnostic.targetFamily === 'inter'
  ));
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === 'control-token-mismatch'));
});

test('computed-style shadow keeps a desktop-only oversized H1 scoped to that viewport', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => completeComputedStyleEvidence()
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    (viewport) => completeComputedStyleEvidence({
      roleStyles: viewport === 'desktop' ? { heading_1: { fontSize: '80px' } } : {}
    })
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }],
    stateFingerprint: state('f')
  });
  const desktop = shadow.comparisons.find((comparison) => comparison.viewport.name === 'desktop');
  const mobile = shadow.comparisons.find((comparison) => comparison.viewport.name === 'mobile');

  assert.ok(desktop.diagnostics.some((diagnostic) =>
    diagnostic.code === 'extreme-font-size-ratio' && diagnostic.semanticRole === 'heading_1'
  ));
  assert.ok(!mobile.diagnostics.some((diagnostic) => diagnostic.code === 'extreme-font-size-ratio'));
});

test('computed-style shadow reports a source web font that is computed but unloaded on target', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => completeComputedStyleEvidence({ family: 'Raleway', loadedFontFamilies: ['Raleway'] })
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => completeComputedStyleEvidence({ family: 'Raleway', loadedFontFamilies: [] })
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
  });

  assert.ok(shadow.comparisons.flatMap((comparison) => comparison.diagnostics).some((diagnostic) =>
    diagnostic.code === 'font-family-not-loaded' && diagnostic.fontFamily === 'raleway'
  ));
});

test('computed-style shadow does not infer an unloaded font from a truncated target family list', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => completeComputedStyleEvidence({ family: 'Raleway', loadedFontFamilies: ['Raleway'] })
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => ({
      ...completeComputedStyleEvidence({ family: 'Raleway', loadedFontFamilies: [] }),
      truncated: true
    })
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
  });

  assert.ok(!shadow.comparisons.flatMap((comparison) => comparison.diagnostics).some((diagnostic) =>
    diagnostic.code === 'font-family-not-loaded'
  ));
});

test('computed-style shadow ignores invisible border tokens on controls', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => completeComputedStyleEvidence({
      roleStyles: {
        form_control: {
          color: 'rgb(20, 20, 20)',
          backgroundColor: 'transparent',
          borderColor: 'rgb(0, 85, 170)',
          borderStyle: 'none',
          borderWidth: '0px',
          borderRadius: '4px'
        }
      }
    })
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => completeComputedStyleEvidence({
      roleStyles: {
        form_control: {
          color: 'rgb(40, 40, 40)',
          backgroundColor: 'transparent',
          borderColor: 'rgb(170, 0, 0)',
          borderStyle: 'none',
          borderWidth: '0px',
          borderRadius: '24px'
        }
      }
    })
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
  });

  assert.ok(!shadow.comparisons.flatMap((comparison) => comparison.diagnostics).some((diagnostic) =>
    diagnostic.code === 'control-token-mismatch' && diagnostic.semanticRole === 'form_control'
  ));
});

test('computed-style shadow calls missing semantic anchors insufficient evidence and never pass', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => completeComputedStyleEvidence()
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => {
      const evidence = completeComputedStyleEvidence();
      return { ...evidence, samples: evidence.samples.filter((sample) => sample.semanticRole !== 'form_control') };
    }
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
  });

  assert.equal(shadow.status, 'insufficient_evidence');
  assert.ok(shadow.comparisons.every((comparison) => comparison.disposition === 'insufficient_evidence'));
  assert.ok(shadow.comparisons.every((comparison) => comparison.missingAnchors.some((anchor) =>
    anchor.side === 'target' && anchor.semanticRole === 'form_control'
  )));
  assert.equal(Object.hasOwn(shadow, 'passed'), false);
  assert.ok(shadow.comparisons.every((comparison) => comparison.disposition !== 'passed'));
});

test('computed-style shadow treats source-absent semantic anchors as not applicable', () => {
  const withoutOptionalAnchors = () => {
    const evidence = completeComputedStyleEvidence();
    return {
      ...evidence,
      samples: evidence.samples.filter((sample) =>
        !['heading_2', 'form_control', 'card_or_listing_surface'].includes(sample.semanticRole)
      )
    };
  };
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    withoutOptionalAnchors
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    withoutOptionalAnchors
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
  });

  assert.equal(shadow.status, 'observed');
  assert.equal(shadow.insufficientEvidenceCount, 0);
  assert.ok(shadow.comparisons.every((comparison) => comparison.missingAnchors.length === 0));
  assert.ok(shadow.comparisons.every((comparison) =>
    comparison.notApplicableAnchors.map((anchor) => anchor.semanticRole).join(',') ===
      'heading_2,form_control,card_or_listing_surface'
  ));
});

test('computed-style shadow keeps missing evidence and the mandatory body anchor insufficient', () => {
  const missingEvidenceSource = visualFloorCapture({
    origin: 'https://source.example',
    hashSeed: 'a',
    structure: composedStructure
  });
  const missingBodySource = attachComputedStyles(
    visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: composedStructure }),
    () => {
      const evidence = completeComputedStyleEvidence();
      return { ...evidence, samples: evidence.samples.filter((sample) => sample.semanticRole !== 'body') };
    }
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => completeComputedStyleEvidence()
  );

  for (const sourceCapture of [missingEvidenceSource, missingBodySource]) {
    const shadow = compareComputedStyleShadow({
      sourceCapture,
      targetCapture,
      primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
    });
    assert.equal(shadow.status, 'insufficient_evidence');
    assert.ok(shadow.comparisons.every((comparison) => comparison.missingAnchors.some((anchor) =>
      anchor.side === 'source' && anchor.semanticRole === 'body'
    )));
  }
});

test('computed-style shadow suppresses style diagnostics for a protected source surface', () => {
  const sourceCapture = attachComputedStyles(
    visualFloorCapture({
      origin: 'https://source.example',
      hashSeed: 'a',
      structure: composedStructure,
      protectedSource: true
    }),
    () => completeComputedStyleEvidence({ family: 'Challenge Sans' })
  );
  const targetCapture = attachComputedStyles(
    visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: composedStructure }),
    () => completeComputedStyleEvidence({ family: 'Inter' })
  );
  const shadow = compareComputedStyleShadow({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }]
  });

  assert.equal(shadow.status, 'insufficient_evidence');
  assert.equal(shadow.diagnosticCount, 0);
  assert.ok(shadow.comparisons.every((comparison) => comparison.sourceProtected === true));
});

test('computed-style evidence strips page text and URLs while enforcing fixed output bounds', () => {
  const seed = completeComputedStyleEvidence();
  const evidence = normalizeComputedStyleEvidence({
    loadedFontFamilies: [
      'url(https://private.example/font.woff2)',
      ...Array.from({ length: 60 }, (_, index) => `Fixture Family ${index}`)
    ],
    samples: Array.from({ length: 20 }, (_, index) => {
      const sample = seed.samples[index % seed.samples.length];
      return {
        ...sample,
        textContent: 'private page copy',
        href: 'https://private.example/account?token=secret',
        styles: {
          ...sample.styles,
          backgroundColor: index === 0 ? 'url(https://private.example/image.png)' : sample.styles.backgroundColor
        }
      };
    })
  });
  const serialized = JSON.stringify(evidence);

  assert.equal(evidence.schemaVersion, COMPUTED_STYLE_EVIDENCE_SCHEMA);
  assert.ok(evidence.samples.length <= COMPUTED_STYLE_LIMITS.maxSamples);
  assert.ok(evidence.loadedFontFamilies.length <= COMPUTED_STYLE_LIMITS.maxLoadedFontFamilies);
  assert.equal(evidence.truncated, true);
  assert.deepEqual(normalizeComputedStyleEvidence(evidence), evidence);
  assert.doesNotMatch(serialized, /private page copy|private\.example|token=secret/i);
  assert.equal(evidence.samples[0].styles.backgroundColor, '');
  assert.deepEqual(evidence.privacy, { includesElementText: false, includesUrls: false });
});

test('verifier-owned visual floor passes comparable composed routes at identical desktop/mobile viewports', () => {
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example',
      hashSeed: 'a',
      structure: composedStructure
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example',
      hashSeed: 'b',
      structure: {
        headingOrder: ['Build faster', 'Why it matters', 'Capabilities', 'Start today'],
        headingCount: 4,
        layoutBandCount: 4,
        mediaCount: 2,
        actionCount: 4,
        prominentActionCount: 2
      }
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.equal(floor.completionSupported, true);
  assert.equal(visualParityCompletionSupport(floor), true);
  assert.equal(floor.verifierOwned, true);
  assert.equal(floor.findings.length, 2);
  assert.ok(floor.findings.every((finding) => finding.composedSource && finding.imageIdentityDistinct));
  assert.ok(floor.findings.every((finding) => finding.designLedComposition));
});

test('verifier-owned source and target form controls pass with exact accessible identity and native option state', () => {
  const evidence = publicFormControlEvidence(publicContactControls);
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: evidence
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: evidence
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.ok(floor.findings.every((finding) => finding.publicFormControlParity.matchedControlCount === 4));
  assert.ok(floor.findings.every((finding) => finding.publicFormControlParity.source.controlCount === 4));
  assert.ok(floor.findings.every((finding) => finding.publicFormControlParity.source.fingerprint.startsWith('sha256:')));
});

test('accepted non-primary form and search routes cannot escape verifier-owned control parity', () => {
  const searchPath = '/course-search?kind=summer';
  const primaryRoutes = [{ sourcePath: '/contact', targetPath: '/contact', routeRole: 'form' }];
  const publicFormRoutes = verifierOwnedPublicFormRoutes({
    routeMatrix: {
      primaryRoutes,
      routes: [
        { sourcePath: '/contact', targetPath: '/contact', routeRole: 'form', accepted: true },
        { sourcePath: searchPath, targetPath: searchPath, routeRole: 'search', accepted: true },
        { sourcePath: '/draft-form', targetPath: '/draft-form', routeRole: 'form', accepted: false }
      ]
    },
    patternMap: {
      forms: [{
        formKey: 'contact-main',
        sourceRoute: '/contact',
        targetRoute: '/contact',
        accepted: true
      }]
    },
    sourceAudit: {
      formsAndIntegrations: [
        {
          formKey: 'contact-main',
          kind: 'public_submission_form',
          sourceRoute: '/contact',
          anonymousPublicUse: true
        },
        { formKey: 'course-search', kind: 'search', sourceRoute: searchPath }
      ]
    }
  });
  assert.deepEqual(
    publicFormRoutes.map(({ sourcePath, targetPath }) => ({ sourcePath, targetPath })),
    [
      { sourcePath: '/contact', targetPath: '/contact' },
      { sourcePath: searchPath, targetPath: searchPath }
    ]
  );
  assert.deepEqual(
    verifierOwnedManagedBrowserRoutes({ primaryRoutes, publicFormRoutes })
      .map((route) => route.targetPath),
    ['/contact', searchPath]
  );
  assert.deepEqual(
    verifierOwnedManagedBrowserRoutes({ captureSide: 'source', primaryRoutes, publicFormRoutes })
      .map((route) => route.targetPath),
    ['/contact', searchPath]
  );

  const searchControls = [observedControl({
    accessibleIdentity: 'course type',
    kind: 'select_single',
    visibleLabel: 'Course type',
    optionEvidence: 'observed',
    options: [
      { label: 'All courses', selected: true, defaultSelected: true, disabled: false },
      { label: 'Summer courses', selected: false, defaultSelected: false, disabled: false }
    ]
  })];
  const targetSearchControls = structuredClone(searchControls);
  targetSearchControls[0].options.pop();
  targetSearchControls[0].optionCount = 1;

  const sourceCapture = combinedVisualFloorCapture([
    visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      path: '/contact', publicFormControls: publicFormControlEvidence(publicContactControls)
    }),
    visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      path: searchPath, publicFormControls: publicFormControlEvidence(searchControls)
    })
  ], 'e');
  const targetCapture = combinedVisualFloorCapture([
    visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      path: '/contact', publicFormControls: publicFormControlEvidence(publicContactControls)
    }),
    visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      path: searchPath, publicFormControls: publicFormControlEvidence(targetSearchControls)
    })
  ], 'f');
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture,
    targetCapture,
    primaryRoutes,
    publicFormControlRoutes: publicFormRoutes,
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.ok(floor.findings.filter((finding) => finding.targetPath === '/contact')
    .every((finding) => finding.passed));
  const nonPrimaryFindings = floor.publicFormControlFindings
    .filter((finding) => finding.targetPath === searchPath);
  assert.equal(nonPrimaryFindings.length, 2);
  assert.ok(nonPrimaryFindings.every((finding) => !finding.passed));
  assert.match(
    nonPrimaryFindings.flatMap((finding) => finding.errors).join('\n'),
    /ordered option labels or selected, default, and disabled option state/i
  );
});

test('an audited form route cannot claim parity from empty source and target control evidence', () => {
  const path = '/empty-contact';
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      path
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      path
    }),
    primaryRoutes: [],
    publicFormControlRoutes: [{ sourcePath: path, targetPath: path, routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.equal(floor.publicFormControlFindings.length, 2);
  assert.match(
    floor.publicFormControlFindings.flatMap((finding) => finding.errors).join('\n'),
    /empty source and target evidence cannot establish form parity/i
  );
});

test('an inaccessible source control may gain only the identity of its existing visible label', () => {
  const sourceControls = [observedControl({
    accessibleIdentity: '',
    visibleLabel: 'Email',
    visibleLabelSource: 'placeholder',
    kind: 'input_email',
    required: true
  })];
  const targetControls = [observedControl({
    accessibleIdentity: 'email',
    visibleLabel: 'Email',
    kind: 'input_email',
    required: true
  })];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(targetControls)
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.ok(floor.findings.every((finding) => finding.publicFormControlParity.matchedControlCount === 1));
  assert.ok(floor.findings.every((finding) => (
    finding.publicFormControlParity.accessibilityImprovements[0]?.type ===
      'accessible-identity-added-from-existing-visible-label'
  )));

  const stillUnlabeled = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });
  assert.equal(stillUnlabeled.status, 'failed');
  assert.match(stillUnlabeled.errors.join('\n'), /target public-form control 1 lacks a bounded accessible identity/i);

  const invented = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([observedControl({
        accessibleIdentity: 'email address',
        visibleLabel: 'Email address',
        kind: 'input_email',
        required: true
      })])
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });
  assert.equal(invented.status, 'failed');
  assert.match(invented.errors.join('\n'), /not bound to the source's existing visible label/i);
});

test('a truly unlabeled source control may gain only matching durable visible text and identity', () => {
  const sourceControl = observedControl({
    accessibleIdentity: '',
    visibleLabel: '',
    visibleLabelSource: 'none',
    kind: 'input_email',
    required: true
  });
  for (const visibleLabelSource of ['associated_label', 'visible_aria_labelledby']) {
    const floor = compareVerifierOwnedVisualFloor({
      sourceCapture: visualFloorCapture({
        origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
        publicFormControls: publicFormControlEvidence([sourceControl])
      }),
      targetCapture: visualFloorCapture({
        origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
        publicFormControls: publicFormControlEvidence([observedControl({
          accessibleIdentity: 'email address',
          visibleLabel: 'Email address',
          visibleLabelSource,
          kind: 'input_email',
          required: true
        })])
      }),
      primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
      stateFingerprint: state('f')
    });

    assert.equal(floor.status, 'passed', floor.errors.join('\n'));
    assert.ok(floor.findings.every((finding) => (
      finding.publicFormControlParity.accessibilityImprovements[0]?.type ===
        'matching-visible-label-and-accessible-identity-added'
    )));
  }

  for (const invalidTarget of [
    observedControl({
      accessibleIdentity: 'email address', visibleLabel: '', visibleLabelSource: 'none', kind: 'input_email', required: true
    }),
    observedControl({
      accessibleIdentity: 'email address', visibleLabel: 'Email address', visibleLabelSource: 'placeholder', kind: 'input_email', required: true
    }),
    observedControl({
      accessibleIdentity: 'contact email', visibleLabel: 'Email address', visibleLabelSource: 'associated_label', kind: 'input_email', required: true
    })
  ]) {
    const invalid = compareVerifierOwnedVisualFloor({
      sourceCapture: visualFloorCapture({
        origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
        publicFormControls: publicFormControlEvidence([sourceControl])
      }),
      targetCapture: visualFloorCapture({
        origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
        publicFormControls: publicFormControlEvidence([invalidTarget])
      }),
      primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
      stateFingerprint: state('f')
    });
    assert.equal(invalid.status, 'failed');
    assert.match(invalid.errors.join('\n'), /does not add matching durable visible text/i);
  }
});

test('an accessibly named source control may gain the same visible associated label only', () => {
  const sourceControl = observedControl({
    accessibleIdentity: 'email address',
    visibleLabel: '',
    visibleLabelSource: 'none',
    kind: 'input_email',
    required: true
  });
  const matchingVisibleLabel = observedControl({
    accessibleIdentity: 'email address',
    visibleLabel: 'Email address',
    visibleLabelSource: 'associated_label',
    kind: 'input_email',
    required: true
  });
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([sourceControl])
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([matchingVisibleLabel])
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.ok(floor.findings.every((finding) => (
    finding.publicFormControlParity.accessibilityImprovements[0]?.type ===
      'matching-durable-visible-label-added'
  )));

  for (const invalidTarget of [
    { ...matchingVisibleLabel, visibleLabel: 'Contact email' },
    { ...matchingVisibleLabel, visibleLabelSource: 'placeholder' }
  ]) {
    const invalid = compareVerifierOwnedVisualFloor({
      sourceCapture: visualFloorCapture({
        origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
        publicFormControls: publicFormControlEvidence([sourceControl])
      }),
      targetCapture: visualFloorCapture({
        origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
        publicFormControls: publicFormControlEvidence([invalidTarget])
      }),
      primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
      stateFingerprint: state('f')
    });
    assert.equal(invalid.status, 'failed');
    assert.match(invalid.errors.join('\n'), /differs in visibleLabel/i);
  }
});

test('equivalent public labels do not require the same target markup mechanism', () => {
  const sourceControl = observedControl({
    accessibleIdentity: 'email address',
    visibleLabel: 'Email address',
    visibleLabelSource: 'associated_label',
    kind: 'input_email'
  });
  const targetControl = {
    ...sourceControl,
    visibleLabelSource: 'visible_aria_labelledby'
  };
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([sourceControl])
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([targetControl])
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
});

test('structural fallback still blocks a missing unlabeled source control and option drift', () => {
  const sourceControls = [
    observedControl({ accessibleIdentity: '', visibleLabel: 'Email', kind: 'input_email', required: true }),
    observedControl({
      accessibleIdentity: '',
      occurrence: 2,
      visibleLabel: 'Campus',
      kind: 'select_single',
      optionEvidence: 'observed',
      options: [
        { label: 'Budapest', selected: true, defaultSelected: true, disabled: false },
        { label: 'Online', selected: false, defaultSelected: false, disabled: false }
      ]
    })
  ];
  const labeledEmail = observedControl({
    accessibleIdentity: 'email', visibleLabel: 'Email', kind: 'input_email', required: true
  });
  const missing = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([labeledEmail])
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });
  assert.equal(missing.status, 'failed');
  assert.match(missing.errors.join('\n'), /missing public-form control at form 1 control 2/i);

  const changedSelect = structuredClone(sourceControls[1]);
  changedSelect.accessibleIdentity = 'campus';
  changedSelect.occurrence = 1;
  changedSelect.visibleLabel = 'Campus';
  changedSelect.options[1].disabled = true;
  const optionsDifferent = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence([labeledEmail, changedSelect])
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });
  assert.equal(optionsDifferent.status, 'failed');
  assert.match(optionsDifferent.errors.join('\n'), /ordered option labels.*selected, default, and disabled option state/i);
});

test('structural fallback rejects reordered formerly unlabeled controls', () => {
  const sourceControls = [
    observedControl({ accessibleIdentity: '', visibleLabel: 'Email', kind: 'input_email' }),
    observedControl({
      accessibleIdentity: '', occurrence: 2, visibleLabel: 'Campus', kind: 'select_single',
      optionEvidence: 'observed',
      options: [{ label: 'Budapest', selected: true, defaultSelected: true, disabled: false }]
    })
  ];
  const targetControls = [
    observedControl({
      accessibleIdentity: 'campus', visibleLabel: 'Campus', kind: 'select_single',
      optionEvidence: 'observed',
      options: [{ label: 'Budapest', selected: true, defaultSelected: true, disabled: false }]
    }),
    observedControl({ accessibleIdentity: 'email', visibleLabel: 'Email', kind: 'input_email' })
  ];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(sourceControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(targetControls)
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /form 1 control [12].*differs in kind/i);
});

test('verifier-owned form parity blocks kind, label, required, selection, and ordered-option drift', () => {
  const targetControls = structuredClone(publicContactControls);
  targetControls[0].kind = 'input_text';
  targetControls[0].required = false;
  targetControls[1].options.reverse();
  targetControls[2].selected = false;
  targetControls[3].visibleLabel = 'Submit';
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(publicContactControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(targetControls)
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /differs in kind/i);
  assert.match(floor.errors.join('\n'), /differs in required/i);
  assert.match(floor.errors.join('\n'), /differs in selected/i);
  assert.match(floor.errors.join('\n'), /differs in visibleLabel/i);
  assert.match(floor.errors.join('\n'), /ordered option labels.*selected, default, and disabled option state/i);
});

test('verifier-owned form parity rejects target-only controls and forms', () => {
  const targetControls = [
    ...structuredClone(publicContactControls),
    observedControl({ accessibleIdentity: 'phone', visibleLabel: 'Phone', kind: 'input_tel' })
  ];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(publicContactControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(targetControls)
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /unexpected public-form control at form 1 control 5/i);

  const extraFormControls = structuredClone(publicContactControls);
  extraFormControls.push({
    ...observedControl({ accessibleIdentity: 'search', visibleLabel: 'Search', kind: 'input_search' }),
    formOrdinal: 2,
    controlOrdinal: 1
  });
  const extraForm = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(publicContactControls)
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: publicFormControlEvidence(extraFormControls, 2)
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(extraForm.status, 'failed');
  assert.match(extraForm.errors.join('\n'), /public-form count differs: target 2, source 1/i);
  assert.match(extraForm.errors.join('\n'), /unexpected public-form control at form 2 control 1/i);
});

test('empty or truncated select evidence cannot pass as a dynamic-options wildcard', () => {
  const emptySelect = observedControl({
    accessibleIdentity: 'campus',
    kind: 'select_single',
    visibleLabel: 'Campus',
    optionEvidence: 'unobserved_empty'
  });
  const evidence = publicFormControlEvidence([emptySelect]);
  evidence.overflow.optionControls = 1;
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: evidence
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: evidence
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /dynamic options must be populated.*empty list cannot act as a wildcard/i);
  assert.match(floor.errors.join('\n'), /truncated evidence cannot establish parity/i);
});

test('malformed form evidence is bounded before it reaches comparison findings', () => {
  const oversizedOptions = Array.from(
    { length: PUBLIC_FORM_CONTROL_LIMITS.maxOptionsPerControl + 10 },
    (_value, index) => ({
      label: `Option ${index + 1}`,
      selected: index === 0,
      defaultSelected: index === 0,
      disabled: false
    })
  );
  const oversizedControls = Array.from(
    { length: PUBLIC_FORM_CONTROL_LIMITS.maxControls + 10 },
    (_value, index) => observedControl({
      accessibleIdentity: `control ${index + 1}`,
      visibleLabel: `Control ${index + 1}`,
      kind: index === 0 ? 'select_single' : 'input_text',
      optionEvidence: index === 0 ? 'observed' : 'not_applicable',
      options: index === 0 ? oversizedOptions : []
    })
  );
  const evidence = publicFormControlEvidence(oversizedControls);
  evidence.overflow.controls = 10;
  evidence.overflow.optionControls = 1;
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: evidence
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: evidence
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  for (const finding of floor.findings) {
    assert.equal(finding.publicFormControlParity.source.controls.length, PUBLIC_FORM_CONTROL_LIMITS.maxControls);
    assert.equal(
      finding.publicFormControlParity.source.controls[0].options.length,
      PUBLIC_FORM_CONTROL_LIMITS.maxOptionsPerControl
    );
  }
});

test('noncanonical labels, unstable occurrences, and impossible native state fail closed', () => {
  const malformedControls = [
    observedControl({
      accessibleIdentity: 'ｅmail',
      occurrence: 2,
      visibleLabel: 'Ｅmail',
      kind: 'input_email',
      selected: true,
      defaultSelected: true
    }),
    observedControl({
      accessibleIdentity: 'choice',
      kind: 'input_checkbox',
      visibleLabel: 'Choice',
      selected: null,
      defaultSelected: null
    }),
    observedControl({
      accessibleIdentity: 'campus',
      kind: 'select_single',
      visibleLabel: 'Campus',
      optionEvidence: 'observed',
      options: [{ label: 'Ｏnline', selected: true, defaultSelected: true, disabled: false }]
    })
  ];
  const evidence = publicFormControlEvidence(malformedControls);
  delete evidence.controls[1].options;
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure,
      publicFormControls: evidence
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure,
      publicFormControls: evidence
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'form' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /unstable accessible identity/i);
  assert.match(floor.errors.join('\n'), /unbounded visible label/i);
  assert.match(floor.errors.join('\n'), /unstable identity occurrence/i);
  assert.match(floor.errors.join('\n'), /invalid option list/i);
  assert.match(floor.errors.join('\n'), /non-checkable.*unexpected current or default selected state/i);
  assert.match(floor.errors.join('\n'), /checkable.*lacks boolean current and default state/i);
  assert.match(floor.errors.join('\n'), /invalid bounded option evidence/i);
});

test('verifier-owned primary-navigation parity preserves accepted route mappings, order, labels, and hierarchy', () => {
  const sourceEntries = [
    { href: '/', label: 'Home' },
    { href: '/programs?audience=adult', label: 'Programs' },
    { href: '/programs/advanced', label: 'Advanced', depth: 1, parentPosition: 1 }
  ];
  const targetEntries = [
    { href: '/', label: 'Home' },
    { href: '/courses?audience=adult', label: 'Programs' },
    { href: '/courses/advanced', label: 'Advanced', depth: 1, parentPosition: 1 }
  ];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
    }), sourceEntries),
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), targetEntries),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    routeMappings: [
      { sourcePath: '/', targetPath: '/', accepted: true },
      { sourcePath: '/programs?audience=adult', targetPath: '/courses?audience=adult', accepted: true },
      { sourcePath: '/programs/advanced', targetPath: '/courses/advanced', accepted: true }
    ],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.equal(floor.primaryNavigationSemanticParity.status, 'passed');
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.passed));
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.differenceKinds.length === 0));
});

test('primary navigation prefers a unique canonical final route over an earlier incomplete primary mapping', () => {
  const sourceEntries = [{ href: '/legacy-programs', label: 'Programs' }];
  const targetEntries = [{ href: '/programs', label: 'Programs' }];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
    }), sourceEntries),
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), targetEntries),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    routeMappings: [
      { sourcePath: '/legacy-programs', targetPath: '/legacy-programs', accepted: true },
      {
        sourcePath: '/legacy-programs',
        targetPath: '/legacy-programs',
        targetFinalPath: '/programs',
        accepted: true
      }
    ],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.routeMappingConflictCount === 0));
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.passed));
});

test('conflicting canonical navigation mappings fail closed even when the observed trees otherwise match', () => {
  const entries = [{ href: '/legacy-programs', label: 'Programs' }];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
    }), entries),
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), entries),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    routeMappings: [
      {
        sourcePath: '/legacy-programs',
        targetPath: '/legacy-programs',
        targetFinalPath: '/programs-a',
        accepted: true
      },
      {
        sourcePath: '/legacy-programs',
        targetPath: '/legacy-programs',
        targetFinalPath: '/programs-b',
        accepted: true
      }
    ],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.equal(floor.primaryNavigationSemanticParity.status, 'failed');
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.routeMappingConflictCount === 1));
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.disposition.applied === false));
  assert.match(floor.errors.join('\n'), /ambiguous canonical route mapping/i);
});

test('verifier-owned primary-navigation parity fails when an otherwise exact target tree is hidden', () => {
  const entries = [
    { href: '/', label: 'Home' },
    { href: '/programs', label: 'Programs' }
  ];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
    }), entries),
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), entries, { visible: false }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.equal(floor.primaryNavigationSemanticParity.status, 'failed');
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.differenceKinds.includes('omission')));
  assert.ok(floor.findings.every((finding) =>
    finding.primaryNavigation.expectedSourceTreeFingerprint !== finding.primaryNavigation.targetTreeFingerprint
  ));
});

test('verifier-owned primary-navigation parity binds duplicate entries to exact hierarchy occurrences', () => {
  const entries = [
    { href: '/', label: 'Home' },
    { href: '/programs', label: 'Programs' },
    { href: '/programs/all', label: 'All programs', depth: 1, parentPosition: 1 },
    { href: '/programs', label: 'Programs' },
    { href: '/programs/all', label: 'All programs', depth: 1, parentPosition: 3 }
  ];
  const input = {
    sourceCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
    }), entries),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  };
  const exact = compareVerifierOwnedVisualFloor({
    ...input,
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), entries)
  });
  assert.equal(exact.status, 'passed', exact.errors.join('\n'));

  const reparented = entries.map((entry, index) => index === 4 ? { ...entry, parentPosition: 1 } : entry);
  const mismatched = compareVerifierOwnedVisualFloor({
    ...input,
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), reparented)
  });
  assert.equal(mismatched.status, 'failed');
  assert.ok(mismatched.findings.every((finding) => finding.primaryNavigation.differenceKinds.includes('hierarchy')));
});

test('verifier-owned primary-navigation parity catches swapped labels, wrong order, lost hierarchy, wrong hrefs, and additions', () => {
  const sourceEntries = [
    { href: '/', label: 'Home' },
    { href: '/programs', label: 'Programs' },
    { href: '/programs/advanced', label: 'Advanced', depth: 1, parentPosition: 1 }
  ];
  const cases = [
    {
      name: 'swapped labels',
      expectedKinds: ['addition', 'label', 'omission'],
      entries: [
        { href: '/', label: 'Programs' },
        { href: '/programs', label: 'Home' },
        { href: '/programs/advanced', label: 'Advanced', depth: 1, parentPosition: 1 }
      ]
    },
    {
      name: 'wrong order',
      expectedKinds: ['order'],
      entries: [
        { href: '/programs', label: 'Programs' },
        { href: '/', label: 'Home' },
        { href: '/programs/advanced', label: 'Advanced', depth: 1, parentPosition: 0 }
      ]
    },
    {
      name: 'lost hierarchy',
      expectedKinds: ['hierarchy'],
      entries: [
        { href: '/', label: 'Home' },
        { href: '/programs', label: 'Programs' },
        { href: '/programs/advanced', label: 'Advanced' }
      ]
    },
    {
      name: 'wrong href',
      expectedKinds: ['addition', 'href', 'omission'],
      entries: [
        { href: '/', label: 'Home' },
        { href: '/classes', label: 'Programs' },
        { href: '/programs/advanced', label: 'Advanced', depth: 1, parentPosition: 1 }
      ]
    },
    {
      name: 'invented entry',
      expectedKinds: ['addition', 'href'],
      entries: [
        ...sourceEntries,
        { href: '/invented', label: 'Invented' }
      ]
    }
  ];

  for (const fixture of cases) {
    const floor = compareVerifierOwnedVisualFloor({
      sourceCapture: setPrimaryNavigation(visualFloorCapture({
        origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
      }), sourceEntries),
      targetCapture: setPrimaryNavigation(visualFloorCapture({
        origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
      }), fixture.entries),
      primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
      stateFingerprint: state('f')
    });
    assert.equal(floor.status, 'failed', fixture.name);
    assert.equal(floor.primaryNavigationSemanticParity.status, 'failed', fixture.name);
    for (const expectedKind of fixture.expectedKinds) {
      assert.ok(
        floor.findings.every((finding) => finding.primaryNavigation.differenceKinds.includes(expectedKind)),
        `${fixture.name}: ${expectedKind}`
      );
    }
    assert.match(floor.errors.join('\n'), /primary navigation semantic mismatch/i, fixture.name);
  }
});

test('navigation mismatch dispositions bind exact tree fingerprints, viewport, and difference kinds', () => {
  const sourceEntries = [
    { href: '/', label: 'Home' },
    { href: '/programs', label: 'Programs' }
  ];
  const targetEntries = [
    { href: '/', label: 'Start' },
    { href: '/programs', label: 'Programs' }
  ];
  const input = {
    sourceCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
    }), sourceEntries),
    targetCapture: setPrimaryNavigation(visualFloorCapture({
      origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
    }), targetEntries),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  };
  const failed = compareVerifierOwnedVisualFloor(input);
  const dispositions = failed.findings.map((finding) => ({
    schemaVersion: 'public-kit.navigation-parity-disposition.1',
    viewport: finding.viewport.name,
    expectedSourceTreeFingerprint: finding.primaryNavigation.expectedSourceTreeFingerprint,
    targetTreeFingerprint: finding.primaryNavigation.targetTreeFingerprint,
    differenceKinds: finding.primaryNavigation.differenceKinds,
    acceptedBy: 'Site owner',
    rationale: 'The revised home label is an approved editorial change.',
    evidence: 'evidence/navigation-label-decision.txt',
    accepted: true
  }));
  const dispositioned = compareVerifierOwnedVisualFloor({
    ...input,
    navigationParityDispositions: dispositions
  });
  assert.equal(dispositioned.status, 'passed', dispositioned.errors.join('\n'));
  assert.equal(dispositioned.primaryNavigationSemanticParity.status, 'dispositioned');
  assert.ok(dispositioned.findings.every((finding) => finding.primaryNavigation.disposition.applied));

  dispositions[0].differenceKinds = ['href'];
  const mismatchedDisposition = compareVerifierOwnedVisualFloor({
    ...input,
    navigationParityDispositions: dispositions
  });
  assert.equal(mismatchedDisposition.status, 'failed');
  assert.equal(mismatchedDisposition.primaryNavigationSemanticParity.staleDispositionCount, 1);
  assert.equal(mismatchedDisposition.findings[0].primaryNavigation.disposition.applied, false);
});

test('truncated primary-navigation evidence fails closed and cannot be dispositioned', () => {
  const entries = [{ href: '/', label: 'Home' }];
  const sourceCapture = setPrimaryNavigation(visualFloorCapture({
    origin: 'https://source.example', hashSeed: 'a', structure: composedStructure
  }), entries, { entryCount: 129, entriesTruncated: true });
  const targetCapture = setPrimaryNavigation(visualFloorCapture({
    origin: 'https://target.example', hashSeed: 'b', structure: composedStructure
  }), entries, { entryCount: 129, entriesTruncated: true });
  const input = {
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  };
  const failed = compareVerifierOwnedVisualFloor(input);
  const desktop = failed.findings.find((finding) => finding.viewport.name === 'desktop').primaryNavigation;
  const disposition = {
    schemaVersion: 'public-kit.navigation-parity-disposition.1',
    viewport: 'desktop',
    expectedSourceTreeFingerprint: desktop.expectedSourceTreeFingerprint,
    targetTreeFingerprint: desktop.targetTreeFingerprint,
    differenceKinds: desktop.differenceKinds,
    acceptedBy: 'Site owner',
    rationale: 'The large navigation is intentional.',
    evidence: 'evidence/navigation.txt',
    accepted: true
  };
  const stillFailed = compareVerifierOwnedVisualFloor({
    ...input,
    navigationParityDispositions: [disposition]
  });

  assert.equal(stillFailed.status, 'failed');
  assert.match(stillFailed.errors.join('\n'), /exceeded verifier bounds/i);
  assert.ok(stillFailed.findings.every((finding) => !finding.primaryNavigation.disposition.applied));
});

test('long article structure does not become a design-led Canvas candidate from headings alone', () => {
  const articleStructure = {
    headingOrder: ['Article title', 'Context', 'Evidence', 'Analysis', 'Conclusion'],
    headingCount: 5,
    layoutBandCount: 5,
    mediaCount: 1,
    actionCount: 8,
    prominentActionCount: 0
  };
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({ origin: 'https://source.example', hashSeed: 'a', structure: articleStructure, path: '/article/example' }),
    targetCapture: visualFloorCapture({ origin: 'https://target.example', hashSeed: 'b', structure: articleStructure, path: '/article/example' }),
    primaryRoutes: [{ sourcePath: '/article/example', targetPath: '/article/example', routeRole: 'other' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.ok(floor.findings.every((finding) => finding.composedSource));
  assert.ok(floor.findings.every((finding) => finding.designLedComposition === false));
});

test('verifier-owned visual floor blocks gross composed-route omissions without a pixel threshold', () => {
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example',
      hashSeed: 'a',
      structure: composedStructure
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example',
      hashSeed: 'b',
      structure: {
        headingOrder: ['Build faster'],
        headingCount: 1,
        layoutBandCount: 1,
        mediaCount: 0,
        actionCount: 0
      }
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.equal(floor.completionSupported, false);
  assert.match(floor.errors.join('\n'), /headings.*layout bands.*media.*actions/is);
  assert.doesNotMatch(floor.errors.join('\n'), /pixel|diff score/i);
});

test('verifier-owned visual floor blocks missing source landmarks and inert mobile navigation', () => {
  const targetCapture = visualFloorCapture({
    origin: 'https://target.example',
    hashSeed: 'b',
    structure: composedStructure
  });
  for (const route of targetCapture.routes) route.signals.roles.footer.visible = false;
  targetCapture.routes.find((route) => route.viewport.name === 'mobile').signals.mobileMenu.activationWorks = false;
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example',
      hashSeed: 'a',
      structure: composedStructure
    }),
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /footer landmark/i);
  assert.match(floor.errors.join('\n'), /mobile navigation/i);
});

test('verifier-owned visual floor treats complete loss of material media as a decisive omission', () => {
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example',
      hashSeed: 'a',
      structure: {
        headingOrder: ['Build faster', 'Start today'],
        headingCount: 2,
        layoutBandCount: 2,
        mediaCount: 5,
        actionCount: 2
      }
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example',
      hashSeed: 'b',
      structure: {
        headingOrder: ['Build faster', 'Start today'],
        headingCount: 2,
        layoutBandCount: 2,
        mediaCount: 0,
        actionCount: 2
      }
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'landing' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /media 0\/5/i);
  assert.ok(floor.findings.every((finding) => finding.decisiveDeficits.includes('all material media omitted')));
});

test('verifier-owned visual floor rejects reused source and target image identities', () => {
  const sourceCapture = visualFloorCapture({
    origin: 'https://source.example',
    hashSeed: 'a',
    structure: composedStructure
  });
  const targetCapture = visualFloorCapture({
    origin: 'https://target.example',
    hashSeed: 'b',
    structure: composedStructure
  });
  for (let index = 0; index < targetCapture.routes.length; index += 1) {
    targetCapture.routes[index].screenshot.sha256 = sourceCapture.routes[index].screenshot.sha256;
  }
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'failed');
  assert.match(floor.errors.join('\n'), /distinct source and target screenshot identities/i);
});

test('positive source protection is review-required and never described as verifier-owned completion', () => {
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture: visualFloorCapture({
      origin: 'https://source.example',
      hashSeed: 'a',
      structure: { headingOrder: [], headingCount: 0, layoutBandCount: 0, mediaCount: 0, actionCount: 0 },
      protectedSource: true
    }),
    targetCapture: visualFloorCapture({
      origin: 'https://target.example',
      hashSeed: 'b',
      structure: composedStructure
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'review_required');
  assert.equal(floor.completionSupported, false);
  assert.equal(floor.reviewFallbackEligible, false);
  assert.equal(floor.diagnosticReviewEligible, true);
  assert.match(floor.errors.join('\n'), /verifier-owned source access is restored/i);
});

test('ordinary source capture failure stays blocked and cannot use the protected-source review fallback', () => {
  const sourceCapture = visualFloorCapture({
    origin: 'https://source.example',
    hashSeed: 'a',
    structure: composedStructure
  });
  sourceCapture.status = 'blocked';
  sourceCapture.authoritative = false;
  sourceCapture.errors = ['DNS lookup failed'];
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture,
    targetCapture: visualFloorCapture({
      origin: 'https://target.example',
      hashSeed: 'b',
      structure: composedStructure
    }),
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'blocked');
  assert.equal(floor.completionSupported, false);
  assert.notEqual(floor.reviewFallbackEligible, true);
  assert.match(floor.errors.join('\n'), /DNS lookup failed/i);
});

test('protected-source builder captures remain diagnostic even after strict handoff review', () => {
  const browserEvidence = {
    publicRouteChecks: ['desktop', 'mobile'].map((viewport) => ({
      sourceUrl: 'https://source.example/',
      targetUrl: 'https://target.example/',
      viewport: {
        name: viewport,
        width: viewport === 'desktop' ? 1280 : 390,
        height: viewport === 'desktop' ? 800 : 844
      },
      sourceScreenshot: `evidence/browser/source-${viewport}.png`,
      targetScreenshot: `evidence/browser/target-${viewport}.png`,
      visualComparison: { method: 'agent_review', status: 'pass' },
      captureState: {
        evidenceBindings: {
          sourceScreenshotSha256: state(viewport === 'desktop' ? '1' : '2'),
          targetScreenshotSha256: state(viewport === 'desktop' ? '3' : '4')
        }
      }
    }))
  };
  const blindReview = {
    reviewer: {
      freshContextUsed: true,
      sameContextAsBuilder: false,
      didNotBuildTarget: true,
      inputsRestrictedToBriefTargetAndSourceTruth: true,
      implementationFilesReadBeforePublicReview: false,
      reviewPacketReadBeforePublicReview: false,
      priorBuildConversationRead: false,
      builderSummaryExcluded: true
    },
    summary: { verdict: 'good', completionState: 'parity_reviewed' },
    routeViewportReviews: ['desktop', 'mobile'].map((viewport) => ({
      route: '/',
      viewport,
      sourceScreenshot: `evidence/browser/source-${viewport}.png`,
      targetScreenshot: `evidence/browser/target-${viewport}.png`,
      verdict: 'good',
      checks: {
        actualRequestedOutcome: 'pass',
        firstFoldVisualParity: 'pass',
        navigationBehavior: 'pass',
        contentHierarchyCompleteness: 'pass',
        mediaArtworkFidelity: 'pass',
        interactionParity: 'pass'
      }
    }))
  };
  const files = browserEvidence.publicRouteChecks.flatMap((check) => [
    {
      path: `review-packet/${check.sourceScreenshot}`,
      sha256: check.captureState.evidenceBindings.sourceScreenshotSha256,
      size: 4096
    },
    {
      path: `review-packet/${check.targetScreenshot}`,
      sha256: check.captureState.evidenceBindings.targetScreenshotSha256,
      size: 4096
    }
  ]);
  const input = {
    browserEvidence,
    blindReview,
    independentVerification: {
      completionClaims: [{ gate: 'visual', status: 'pass' }],
      summary: { verdict: 'pass' }
    },
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    reviewHandoff: {
      binding: { packetPath: 'review-packet' },
      handoffDigest: state('9')
    },
    reviewHandoffIndependent: { allowedInputs: { files } },
    reviewHandoffStateValid: true,
    blindReviewSupportsCompletion: true,
    independentVerificationSupportsCompletion: true
  };
  const fallback = buildReviewedBuilderVisualFallback(input);
  assert.equal(fallback.status, 'passed', fallback.errors.join('\n'));
  assert.equal(fallback.verifierOwned, false);
  assert.equal(fallback.authority, 'handoff-reviewed-builder-captures');
  assert.equal(fallback.findings.length, 2);
  assert.equal(visualParityCompletionSupport({
    schemaVersion: 'public-kit.visual-parity-floor.1',
    status: 'passed_with_handoff_review',
    authority: 'handoff-reviewed-builder-captures',
    verifierOwned: false,
    completionSupported: true,
    sourceProtectionDegradation: true,
    verifierCapture: { status: 'review_required', completionSupported: false },
    reviewedBuilderFallback: fallback
  }), false);

  const agentReviewOnly = buildReviewedBuilderVisualFallback({
    ...input,
    blindReview: { ...blindReview, routeViewportReviews: [] }
  });
  assert.equal(agentReviewOnly.status, 'blocked');
  assert.match(agentReviewOnly.errors.join('\n'), /fresh blind reviewer/i);
  assert.equal(visualParityCompletionSupport({
    status: 'passed',
    authority: 'builder-agent-review',
    verifierOwned: false,
    completionSupported: true
  }), false);

  const unbound = structuredClone(input);
  unbound.reviewHandoffIndependent.allowedInputs.files = files.filter(({ path }) => !path.includes('source-mobile'));
  const unboundFallback = buildReviewedBuilderVisualFallback(unbound);
  assert.equal(unboundFallback.status, 'blocked');
  assert.match(unboundFallback.errors.join('\n'), /handoff-bound/i);
});

test('actual config, theme, shared display, navigation, and menu-link changes trigger executable chrome coverage', () => {
  const base = {
    configManifest: { entries: [{ path: 'config/sync/system.site.yml', sha256: state('1'), size: 10 }] },
    codeManifest: { entries: [{ path: 'composer.lock', sha256: state('2'), size: 10 }] },
    entityInventory: { types: { menu_link_content: { fingerprint: state('3') } } }
  };
  const result = {
    configManifest: { entries: [
      ...base.configManifest.entries,
      { path: 'config/sync/canvas.page_region.mercury.header.yml', sha256: state('4'), size: 10 },
      { path: 'config/sync/block.block.public_header.yml', sha256: state('5'), size: 10 },
      { path: 'config/sync/system.menu.main.yml', sha256: state('6'), size: 10 },
      { path: 'config/sync/navigation.settings.yml', sha256: state('7'), size: 10 },
      { path: 'config/sync/core.entity_view_display.node.page.full.yml', sha256: state('8'), size: 10 }
    ] },
    codeManifest: { entries: [
      ...base.codeManifest.entries,
      { path: 'docroot/themes/custom/site/templates/page.html.twig', sha256: state('9'), size: 10 },
      { path: 'themes/custom/root_theme/root_theme.info.yml', sha256: state('b'), size: 10 },
      { path: 'web/themes/contrib/contrib_theme/contrib_theme.info.yml', sha256: state('c'), size: 10 },
      { path: 'web/themes/custom/site/templates/page.html.twig', sha256: state('d'), size: 10 }
    ] },
    entityInventory: { types: { menu_link_content: { fingerprint: state('a') } } }
  };
  const impact = globalChromeImpact(base, result);
  assert.equal(impact.triggered, true);
  assert.equal(impact.triggerConfigPaths.length, 5);
  assert.deepEqual(impact.triggerCodePaths, [
    'docroot/themes/custom/site/templates/page.html.twig',
    'themes/custom/root_theme/root_theme.info.yml',
    'web/themes/contrib/contrib_theme/contrib_theme.info.yml',
    'web/themes/custom/site/templates/page.html.twig'
  ]);
  assert.deepEqual(impact.triggerDependencyPaths, []);
  assert.equal(impact.menuLinkContentChanged, true);
  assert.equal(globalChromeImpact(
    { configManifest: { entries: [] }, codeManifest: { entries: [] }, entityInventory: { types: {} } },
    { configManifest: { entries: [] }, codeManifest: { entries: [] }, entityInventory: result.entityInventory }
  ).menuLinkContentChanged, true);

  const dependencyImpact = globalChromeImpact(base, {
    ...base,
    codeManifest: { entries: [{ path: 'composer.lock', sha256: state('e'), size: 11 }] }
  });
  assert.equal(dependencyImpact.triggered, true);
  assert.deepEqual(dependencyImpact.triggerDependencyPaths, ['composer.lock']);
});

function rawCaptureFixture() {
  const finalized = captureFixture(state('f'));
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.alloc(128)]).toString('base64');
  const raw = { ...finalized };
  delete raw.captureFingerprint;
  delete raw.resultStateFingerprint;
  raw.routes = raw.routes.map((route) => ({
    ...route,
    axe: {
      schemaVersion: VERIFIER_AXE_SCHEMA,
      status: 'executed',
      source: { version: VERIFIER_AXE_VERSION, sha256: VERIFIER_AXE_SOURCE_SHA256 },
      ruleScope: { type: 'tag', values: [...VERIFIER_AXE_TAGS] },
      report: {
        testEngine: { name: 'axe-core', version: VERIFIER_AXE_VERSION },
        testEnvironment: { userAgent: 'Fixture Browser', windowWidth: route.viewport.width, windowHeight: route.viewport.height },
        testRunner: { name: 'axe' },
        toolOptions: { runOnly: { type: 'tag', values: [...VERIFIER_AXE_TAGS] } },
        timestamp: '2026-07-11T20:00:00Z',
        url: route.signals.finalUrl,
        passes: [{ id: 'document-title', tags: ['wcag2a'], nodes: [{}] }],
        incomplete: [],
        inapplicable: [],
        violations: []
      },
      summary: {
        passRuleCount: 1,
        incompleteRuleCount: 0,
        inapplicableRuleCount: 0,
        violationRuleCount: 0,
        violationNodeCount: 0,
        violationRuleIds: []
      },
      errors: []
    },
    screenshot: {
      base64: png,
      width: route.screenshot.width,
      height: route.screenshot.height,
      clipped: false
    }
  }));
  return raw;
}

test('finalized exact-query form captures compare by their privacy-preserving route identity', () => {
  const route = '/course-search?kind=summer&campus=budapest';
  const sourceControls = [observedControl({
    accessibleIdentity: 'campus',
    kind: 'select_single',
    visibleLabel: 'Campus',
    optionEvidence: 'observed',
    options: [
      { label: 'All campuses', selected: true, defaultSelected: true, disabled: false },
      { label: 'Budapest', selected: false, defaultSelected: false, disabled: false }
    ]
  })];
  const targetControls = structuredClone(sourceControls);
  targetControls[0].options.pop();
  targetControls[0].optionCount = 1;
  const rawCapture = (origin, controls, byteSeed) => {
    const raw = rawCaptureFixture();
    raw.targetOrigin = origin;
    raw.primaryRoutes = [route];
    raw.routes = raw.routes.map((entry) => ({
      ...entry,
      path: route,
      signals: {
        ...entry.signals,
        finalUrl: `${origin}${route}`,
        publicFormControls: publicFormControlEvidence(controls),
        protection: { detected: false, responseStatus: 200, reasonCodes: [] }
      },
      axe: {
        ...entry.axe,
        report: { ...entry.axe.report, url: `${origin}${route}` }
      },
      screenshot: {
        ...entry.screenshot,
        base64: Buffer.concat([
          Buffer.from('89504e470d0a1a0a', 'hex'),
          Buffer.alloc(128, byteSeed)
        ]).toString('base64')
      }
    }));
    return raw;
  };
  const sourceRoot = mkdtempSync(join(tmpdir(), 'global-chrome-query-source-'));
  const targetRoot = mkdtempSync(join(tmpdir(), 'global-chrome-query-target-'));
  const sourcePacket = join(sourceRoot, 'review-packet');
  const targetPacket = join(targetRoot, 'review-packet');
  mkdirSync(sourcePacket, { recursive: true });
  mkdirSync(targetPacket, { recursive: true });
  const sourceCapture = finalizeGlobalChromeCapture({
    capture: rawCapture('https://source.example', sourceControls, 1),
    packetDir: sourcePacket,
    stateFingerprint: state('f')
  });
  const targetCapture = finalizeGlobalChromeCapture({
    capture: rawCapture('https://target.example', targetControls, 2),
    packetDir: targetPacket,
    stateFingerprint: state('f')
  });

  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture,
    targetCapture,
    primaryRoutes: [],
    publicFormControlRoutes: [{ sourcePath: route, targetPath: route, routeRole: 'search' }],
    stateFingerprint: state('f')
  });
  const expectedRoute = `/course-search?query-sha256=${sha256('?kind=summer&campus=budapest').slice('sha256:'.length)}`;
  assert.equal(floor.status, 'failed');
  assert.equal(floor.publicFormControlFindings.length, 2);
  assert.ok(floor.publicFormControlFindings.every((finding) => finding.targetPath === expectedRoute));
  assert.doesNotMatch(floor.errors.join('\n'), /missing (?:source|target) managed-browser capture/i);
  assert.match(
    floor.publicFormControlFindings.flatMap((finding) => finding.errors).join('\n'),
    /ordered option labels or selected, default, and disabled option state/i
  );
});

function finalizedNavigationCapture({ packetDir, origin, entries, screenshotSeed }) {
  const raw = rawCaptureFixture();
  raw.targetOrigin = origin;
  const png = Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'),
    Buffer.alloc(128, screenshotSeed)
  ]).toString('base64');
  raw.routes = raw.routes.map((route) => ({
    ...route,
    signals: {
      ...route.signals,
      finalUrl: `${origin}/`,
      publicFormControls: publicFormControlEvidence(),
      primaryNavigation: primaryNavigation(entries)
    },
    axe: {
      ...route.axe,
      report: { ...route.axe.report, url: `${origin}/` }
    },
    screenshot: { ...route.screenshot, base64: png }
  }));
  mkdirSync(packetDir, { recursive: true });
  return finalizeGlobalChromeCapture({ capture: raw, packetDir, stateFingerprint: state('f') });
}

test('navigation route mapping remains exact after labels and query values are privacy-bound', () => {
  const root = mkdtempSync(join(tmpdir(), 'navigation-finalized-mapping-'));
  const sourceCapture = finalizedNavigationCapture({
    packetDir: join(root, 'source-packet'),
    origin: 'https://source.example',
    entries: [{ href: '/programs?audience=adult', label: 'Programs' }],
    screenshotSeed: 1
  });
  const targetCapture = finalizedNavigationCapture({
    packetDir: join(root, 'target-packet'),
    origin: 'https://target.example',
    entries: [{ href: '/courses?audience=adult', label: 'Programs' }],
    screenshotSeed: 2
  });
  const floor = compareVerifierOwnedVisualFloor({
    sourceCapture,
    targetCapture,
    primaryRoutes: [{ sourcePath: '/', targetPath: '/', routeRole: 'homepage' }],
    routeMappings: [{
      sourcePath: '/programs?audience=adult',
      targetPath: '/courses?audience=adult',
      accepted: true
    }],
    stateFingerprint: state('f')
  });

  assert.equal(floor.status, 'passed', floor.errors.join('\n'));
  assert.ok(floor.findings.every((finding) => finding.primaryNavigation.passed));
  assert.doesNotMatch(JSON.stringify(sourceCapture), /audience=adult|"label":"Programs"/);
});

test('finalization fails before writing for incomplete captures and symlinked evidence ancestors', () => {
  const incompleteRoot = mkdtempSync(join(tmpdir(), 'global-chrome-incomplete-'));
  const incompletePacket = join(incompleteRoot, 'review-packet');
  mkdirSync(incompletePacket, { recursive: true });
  const incomplete = rawCaptureFixture();
  incomplete.routes = incomplete.routes.filter((route) => route.viewport.name === 'desktop');
  assert.throws(
    () => finalizeGlobalChromeCapture({ capture: incomplete, packetDir: incompletePacket, stateFingerprint: state('f') }),
    /incomplete.*mobile/i
  );
  assert.equal(existsSync(join(incompletePacket, 'evidence')), false);

  const missingAxeRoot = mkdtempSync(join(tmpdir(), 'global-chrome-missing-axe-'));
  const missingAxePacket = join(missingAxeRoot, 'review-packet');
  mkdirSync(missingAxePacket, { recursive: true });
  const missingAxe = rawCaptureFixture();
  delete missingAxe.routes[0].axe;
  assert.throws(
    () => finalizeGlobalChromeCapture({ capture: missingAxe, packetDir: missingAxePacket, stateFingerprint: state('f') }),
    /lacks a successful verifier-owned axe-core result/i
  );
  assert.equal(existsSync(join(missingAxePacket, 'evidence')), false);

  const symlinkRoot = mkdtempSync(join(tmpdir(), 'global-chrome-symlink-'));
  const symlinkPacket = join(symlinkRoot, 'review-packet');
  const outside = join(symlinkRoot, 'outside');
  mkdirSync(symlinkPacket, { recursive: true });
  mkdirSync(outside, { recursive: true });
  symlinkSync(outside, join(symlinkPacket, 'evidence'));
  assert.throws(
    () => finalizeGlobalChromeCapture({ capture: rawCaptureFixture(), packetDir: symlinkPacket, stateFingerprint: state('f') }),
    /symbolic link/i
  );
  assert.equal(existsSync(join(outside, 'lifecycle')), false);
});

test('state-bound verifier-owned axe results preserve and block WCAG violations', () => {
  const root = mkdtempSync(join(tmpdir(), 'global-chrome-axe-violation-'));
  const packetDir = join(root, 'review-packet');
  mkdirSync(packetDir, { recursive: true });
  const raw = rawCaptureFixture();
  const desktop = raw.routes.find((route) => route.viewport.name === 'desktop');
  desktop.axe.report.violations = [{
    id: 'color-contrast',
    impact: 'serious',
    tags: ['wcag2aa', 'wcag143'],
    nodes: [{ target: ['.notice'], html: '<p class="notice">Notice</p>', failureSummary: 'Insufficient contrast.' }]
  }];
  desktop.axe.summary = {
    ...desktop.axe.summary,
    violationRuleCount: 1,
    violationNodeCount: 1,
    violationRuleIds: ['color-contrast']
  };

  const finalized = finalizeGlobalChromeCapture({ capture: raw, packetDir, stateFingerprint: state('f') });
  const errors = verifierAxeCompletionErrors(finalized);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /unresolved WCAG 2\.2 A\/AA.*color-contrast/i);
  assert.equal(validateScreenshotArtifacts(packetDir, finalized), true);
});

test('CDP pipe captures lazy controlled ARIA navigation, standalone menuitems, controls, and hierarchy', {
  skip: findBrowserExecutable() ? false : 'Chrome/Chromium is not installed in this runtime.'
}, async () => {
  const server = createServer((request, response) => {
    const missingBrand = request.url?.startsWith('/missing-brand');
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html lang="en"><head><title>Global chrome fixture</title><meta name="viewport" content="width=device-width"><style>
      body{margin:0} header,footer{padding:20px} main{min-height:700px}a,button,[role="menuitem"]{display:inline-flex;min-width:24px;min-height:24px;padding:4px;margin:2px}input,select{min-height:24px}.menu-toggle,#mobile-menu-region{display:none}.honeypot{position:absolute;left:-10000px;width:10px;height:10px}.visually-hidden{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
      @media(max-width:600px){.menu-toggle{display:block}.desktop-primary{display:none}#mobile-menu-region.open{display:block}}
    </style></head><body>
      <header><div class="hf-branding">${missingBrand ? '' : '<a class="site-branding" href="/">Fixture Brand</a>'}</div>
      <button class="menu-toggle" aria-label="Menu" aria-controls="mobile-menu-region" aria-expanded="false"
        onclick="toggleFixtureMenu(this)">Menu</button>
      <div class="desktop-primary" role="menubar" aria-label="Primary navigation"><ul role="none"><li role="none"><a role="menuitem" href="/">Home</a></li><li role="none"><a role="menuitem" href="/about">About</a><ul role="menu"><li role="none"><a role="menuitem" href="/team">Team</a></li></ul></li><li role="none"><button role="menuitem">Programs</button></li></ul><div role="menuitem" tabindex="0" aria-label="Services">Services<div role="menu"><a role="menuitem" href="/consulting">Consulting</a></div></div><a role="menuitem" href="#">More</a></div>
      <div id="mobile-menu-region"><nav class="utility-navigation" aria-label="Account"><a class="account-link" href="/account">Account</a></nav></div>
      <script>function toggleFixtureMenu(button){const region=document.getElementById('mobile-menu-region');if(!region.querySelector('[role="menubar"]')){const menu=document.querySelector('.desktop-primary').cloneNode(true);menu.className='mobile-primary';region.append(menu)}const opening=button.getAttribute('aria-expanded')!=='true';button.setAttribute('aria-expanded',String(opening));region.classList.toggle('open',opening)}</script></header>
      <main><h1>Fixture</h1><p data-dynamic>Dynamic timestamp</p>
        <form id="fixture-form"><input type="hidden" name="form_token" value="csrf-secret">
          <label for="fixture-email">Email&nbsp;&#xFF21;ddress</label><input id="fixture-email" name="email_internal" type="email" required value="visitor-secret">
          <label for="fixture-topic">Topic</label><select id="fixture-topic" name="topic_internal">
            <option value="general-internal" selected>&#xFF27;eneral</option><option value="admissions-internal">Admissions</option><option value="archived-internal" disabled>Archived</option><option value="blank-internal" label="">Private fallback text</option>
          </select>
          <label><input type="checkbox" name="copy_internal" checked>Send me a copy</label>
          <input class="honeypot" aria-hidden="true" tabindex="-1" name="website_honeypot" value="honeypot-secret">
          <div inert><label>Inert secret<input name="inert_internal" value="inert-secret"></label></div>
          <div style="opacity:0"><label>Transparent secret<input name="transparent_internal" value="transparent-secret"></label></div>
          <div hidden><label>Hidden secret<input name="hidden_internal" value="hidden-secret"></label></div>
          <button type="submit" name="operation_internal" value="send-internal">Send</button>
          <button type="button"><span class="visually-hidden">Screen reader action</span><svg aria-hidden="true" width="16" height="16"><circle cx="8" cy="8" r="6"></circle></svg></button>
        </form>
        <span id="external-reference-label">Reference</span>
        <input id="external-reference" form="fixture-form" aria-labelledby="external-reference-label" name="reference_internal" value="external-secret">
      </main>
      <footer><a href="/legal">Legal</a><a href="mailto:team@example.com?subject=browser-private">Email</a></footer>
    </body></html>`);
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const raw = await captureGlobalChrome({
      baseUrl,
      primaryRoutes: ['/', '/missing-brand'],
      contract: { dynamicRegionSelectors: ['[data-dynamic]'] },
      profileCleanup(profile) {
        const cleanup = cleanupBrowserProfile(profile);
        return { ...cleanup, warnings: [...cleanup.warnings, 'Fixture deferred cleanup warning.'] };
      }
    });
    assert.equal(raw.status, 'captured', raw.errors.join('\n'));
    assert.equal(raw.authoritative, true);
    assert.ok(raw.warnings.includes('Fixture deferred cleanup warning.'));
    assert.deepEqual(raw.routes.map((route) => `${route.path}:${route.viewport.name}`), [
      '/:desktop', '/:mobile', '/missing-brand:desktop', '/missing-brand:mobile'
    ]);
    assert.ok(raw.routes.every((route) => route.signals.roles.header.visible));
    assert.ok(raw.routes.filter((route) => route.path === '/').every((route) => route.signals.roles.brand.visible));
    assert.ok(raw.routes.filter((route) => route.path === '/missing-brand').every((route) => !route.signals.roles.brand.visible));
    assert.ok(raw.routes.every((route) => route.signals.maskedRegionCount === 1));
    assert.ok(raw.routes.every((route) => route.signals.placeholderHrefs.some((link) => link.raw === '#')));
    assert.ok(raw.routes.every((route) => route.signals.meaningfulHrefs.some((link) => link.href === 'mailto:team@example.com?subject=browser-private')));
    assert.ok(raw.routes.every((route) => route.signals.publicFormControls.formCount === 1));
    assert.ok(raw.routes.every((route) => route.signals.publicFormControls.controlCount === 6));
    const publicControls = raw.routes[0].signals.publicFormControls.controls;
    assert.deepEqual(publicControls.map((control) => [control.formOrdinal, control.controlOrdinal]), [
      [1, 1], [1, 2], [1, 3], [1, 4], [1, 5], [1, 6]
    ]);
    assert.deepEqual(publicControls.map((control) => control.accessibleIdentity), [
      'email address', 'topic', 'send me a copy', 'send', 'screen reader action', 'reference'
    ]);
    assert.deepEqual(publicControls.map((control) => control.visibleLabel), [
      'Email Address', 'Topic', 'Send me a copy', 'Send', '', 'Reference'
    ]);
    assert.deepEqual(publicControls.map((control) => control.visibleLabelSource), [
      'associated_label', 'associated_label', 'associated_label', 'button_text', 'none', 'visible_aria_labelledby'
    ]);
    assert.deepEqual(publicControls[1].options, [
      { label: 'General', selected: true, defaultSelected: true, disabled: false },
      { label: 'Admissions', selected: false, defaultSelected: false, disabled: false },
      { label: 'Archived', selected: false, defaultSelected: false, disabled: true },
      { label: '', selected: false, defaultSelected: false, disabled: false }
    ]);
    assert.doesNotMatch(
      JSON.stringify(raw.routes.map((route) => route.signals.publicFormControls)),
      /form_token|csrf-secret|email_internal|visitor-secret|general-internal|blank-internal|Private fallback text|website_honeypot|honeypot-secret|inert_internal|inert-secret|transparent_internal|transparent-secret|hidden_internal|hidden-secret|operation_internal|send-internal|reference_internal|external-secret/
    );
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entryCount === 7));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries.map((entry) => entry.label).join('|') === 'Home|About|Team|Programs|Services|Consulting|More'));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[2].depth === 1));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[2].parentPosition === 1));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[3].kind === 'control'));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[4].kind === 'control'));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[5].depth === 1));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[5].parentPosition === 4));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[6].kind === 'control'));
    assert.ok(raw.routes.every((route) => route.signals.primaryNavigation.entries[6].href === ''));
    assert.ok(raw.routes.filter((route) => route.viewport.name === 'mobile').every((route) =>
      route.signals.primaryNavigation.entries.every((entry) => entry.href !== '/account')
    ));
    assert.ok(raw.routes.every((route) => route.axe.status === 'executed'));
    assert.ok(raw.routes.every((route) => route.axe.source.sha256 === VERIFIER_AXE_SOURCE_SHA256));
    assert.equal(raw.routes.find((route) => route.path === '/' && route.viewport.name === 'mobile').signals.mobileMenu.activationWorks, true);
    const project = mkdtempSync(join(tmpdir(), 'global-chrome-cdp-'));
    const packetDir = join(project, 'review-packet');
    mkdirSync(join(packetDir, 'evidence'), { recursive: true });
    const finalized = finalizeGlobalChromeCapture({ capture: raw, packetDir, stateFingerprint: state('f') });
    assert.equal(finalized.resultStateFingerprint, state('f'));
    assert.equal(finalized.routes.length, 4);
    assert.ok(finalized.routes.every((route) => route.axe.report.path.endsWith('.json')));
    assert.ok(finalized.routes.every((route) => route.axe.report.sha256.startsWith('sha256:')));
    assert.ok(finalized.routes.every((route) => route.signals.primaryNavigation.entries.every((entry) => !('label' in entry))));
    assert.doesNotMatch(JSON.stringify(finalized), /browser-private/);
    assert.deepEqual(verifierAxeCompletionErrors(finalized), []);
    assert.equal(validateScreenshotArtifacts(packetDir, finalized), true);
  } finally {
    await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  }
});

test('verifier-owned consent capture catches delayed JS requests and proves no-load routes in fresh contexts', {
  skip: findBrowserExecutable() ? false : 'Chrome/Chromium is not installed in this runtime.'
}, async () => {
  const server = createServer((request, response) => {
    if (request.url === '/controlled-map.js') {
      response.writeHead(200, { 'content-type': 'application/javascript' });
      response.end('globalThis.controlledMapLoaded = true;');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html><head><title>Consent fixture</title></head><body><h1>Fixture</h1>
      ${request.url === '/' ? `<script>setTimeout(() => { const script = document.createElement('script'); script.src = '/controlled-map.js'; document.head.append(script); }, 1200);</script>` : ''}
    </body></html>`);
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const raw = await captureBeforeConsentNetwork({ baseUrl, primaryRoutes: ['/', '/clean'] });
    assert.equal(raw.status, 'captured', raw.errors.join('\n'));
    assert.deepEqual(
      {
        attempted: raw.budget.attempted,
        captured: raw.budget.capturedRouteViewportCount,
        deadlineExceeded: raw.budget.deadlineExceeded,
        routeCount: raw.budget.routeCount,
        scheduled: raw.budget.scheduledRouteViewportCount,
        viewportCount: raw.budget.viewportCount
      },
      { attempted: true, captured: 2, deadlineExceeded: false, routeCount: 2, scheduled: 2, viewportCount: 1 }
    );
    assert.ok(raw.routes.every((route) => route.isolation.browserContextFresh));
    assert.ok(raw.routes.every((route) => route.isolation.consentInteractionPerformed === false));
    assert.ok(raw.routes.every((route) => route.observation.floorMs >= 2000 && route.observation.settled));
    assert.ok(raw.routes.find((route) => route.path === '/').requests.some((request) =>
      request.url === `${baseUrl}/controlled-map.js` && request.resourceType === 'Script'
    ));
    assert.equal(raw.routes.find((route) => route.path === '/clean').requests.some((request) =>
      request.url.includes('controlled-map.js')
    ), false);

    const finalized = finalizeBeforeConsentNetworkCapture({
      capture: raw,
      stateFingerprint: state('c'),
      targetOrigin: baseUrl
    });
    validateBeforeConsentNetworkCapture(finalized, {
      stateFingerprint: state('c'),
      targetOrigin: baseUrl,
      primaryRoutes: ['/', '/clean']
    });

    const queryRoutes = ['/?state=keep', '/clean?state=drop'];
    const queryBound = structuredClone(finalized);
    queryBound.primaryRoutes = queryRoutes;
    queryBound.routes = queryBound.routes.map((route) => {
      const path = route.path === '/' ? queryRoutes[0] : queryRoutes[1];
      const url = new URL(path, baseUrl).href;
      return { ...route, path, requestedUrl: url, finalUrl: url };
    });
    delete queryBound.captureFingerprint;
    queryBound.captureFingerprint = sha256(queryBound);
    const reportCapture = sharedBeforeConsentNetworkCapture(queryBound, '/private/review-packet');
    assert.doesNotMatch(JSON.stringify(reportCapture), /state=(?:drop|keep)/);
    assert.ok(reportCapture.primaryRoutes.every((route) => /query-sha256=[a-f0-9]{64}/.test(route)));
    assert.notEqual(reportCapture.captureFingerprint, queryBound.captureFingerprint);
    validateBeforeConsentNetworkCapture(reportCapture, {
      stateFingerprint: state('c'),
      targetOrigin: baseUrl,
      primaryRoutes: queryRoutes
    });

    const declaration = (pattern) => ({
      discoveryStatus: 'installed',
      managers: [{ id: 'klaro', module: 'klaro', configNames: ['klaro.application.maps'] }],
      applications: [{
        id: 'maps', managerId: 'klaro', configName: 'klaro.application.maps', enabled: true, required: false,
        controlledResources: [{ kind: 'script', pattern }]
      }],
      beforeConsentChecks: [{
        route: '/', observedResourceUrls: ['https://packet-authored.example/diagnostic.js'], blockedApplicationIds: ['maps']
      }]
    });
    const runtime = (pattern) => ({
      confirmed: true,
      detected: true,
      managerModules: ['klaro'],
      configNames: ['klaro.application.maps'],
      applications: [{
        id: 'maps', configName: 'klaro.application.maps', enabled: true, required: false,
        resources: [{ kind: 'script', pattern }]
      }]
    });
    const context = {
      targetOrigin: baseUrl,
      primaryRoutes: ['/', '/clean'],
      stateFingerprint: state('c')
    };
    const violation = verifyConsentReconciliation(
      declaration('controlled-map.js'), runtime('controlled-map.js'),
      [{ renderedResourceUrls: [] }], finalized, context
    );
    assert.equal(violation.passed, false);
    assert.match(violation.errors.join('\n'), /loaded before consent.*controlled-map\.js/i);
    assert.equal(violation.authoritativeBeforeConsentCapture, true);
    assert.ok(violation.browserObservedRequests.some((request) => request.resourceType === 'Script'));
    assert.deepEqual(violation.authoredBrowserObservedUrls, ['https://packet-authored.example/diagnostic.js']);
    assert.equal(violation.browserObservedUrls.includes('https://packet-authored.example/diagnostic.js'), false);

    const noLoad = verifyConsentReconciliation(
      declaration('maps.example.invalid'), runtime('maps.example.invalid'),
      [{ renderedResourceUrls: [] }], finalized, context
    );
    assert.equal(noLoad.passed, true, noLoad.errors.join('\n'));
    assert.equal(noLoad.authoritativeBeforeConsentCapture, true);

    const disabledDeclaration = declaration('maps.example.invalid');
    const disabledRuntime = runtime('maps.example.invalid');
    disabledDeclaration.applications[0].enabled = false;
    disabledRuntime.applications[0].enabled = false;
    const disabledNoLoad = verifyConsentReconciliation(
      disabledDeclaration, disabledRuntime, [{ renderedResourceUrls: [] }], finalized, context
    );
    assert.equal(disabledNoLoad.passed, true, disabledNoLoad.errors.join('\n'));

    assert.throws(() => validateBeforeConsentNetworkCapture(finalized, {
      stateFingerprint: state('d'), targetOrigin: baseUrl, primaryRoutes: ['/', '/clean']
    }), /exact live result-state fingerprint/i);
    assert.throws(() => validateBeforeConsentNetworkCapture(finalized, {
      stateFingerprint: state('c'), targetOrigin: baseUrl, primaryRoutes: ['/other']
    }), /routes do not match/i);
    assert.throws(() => validateBeforeConsentNetworkCapture(finalized, {
      stateFingerprint: state('c'), targetOrigin: 'https://other.example', primaryRoutes: ['/', '/clean']
    }), /target origin/i);
  } finally {
    await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  }
});

test('shared global chrome evidence redacts every query with provenance-bound identities', () => {
  const root = mkdtempSync(join(tmpdir(), 'global-chrome-shared-query-'));
  const packetDir = join(root, 'review-packet');
  mkdirSync(packetDir, { recursive: true });
  const literalDigest = 'a'.repeat(64);
  const privateRoute = '/search?preview=private-value';
  const digestLikeRoute = `/search?query-sha256=${literalDigest}`;
  const raw = rawCaptureFixture();
  raw.primaryRoutes = [privateRoute];
  raw.routes = raw.routes.map((route) => ({
    ...route,
    path: privateRoute,
    signals: {
      ...route.signals,
      finalUrl: `https://fixture.ddev.site${privateRoute}`,
      meaningfulHrefs: [
        { href: '/next?token=header-private', scope: 'navigation' },
        { href: digestLikeRoute, scope: 'footer' },
        { href: 'mailto:team@example.com?subject=email-private', scope: 'footer' },
        { href: 'tel:+441234?body=phone-private', scope: 'footer' }
      ],
      primaryNavigation: primaryNavigation([
        { href: '/next?token=header-private', label: 'Visitor private-value' },
        { href: 'mailto:team@example.com?subject=email-private', label: 'Email' }
      ])
    },
    axe: {
      ...route.axe,
      report: {
        ...route.axe.report,
        url: `https://fixture.ddev.site${privateRoute}`
      }
    }
  }));
  const capture = finalizeGlobalChromeCapture({ capture: raw, packetDir, stateFingerprint: state('f') });
  const rawRouteComparison = compareGlobalChromeCaptures({
    anchor: capture,
    current: capture,
    primaryRoutes: [privateRoute]
  });
  const finalizedRouteComparison = compareGlobalChromeCaptures({
    anchor: capture,
    current: capture,
    primaryRoutes: capture.primaryRoutes
  });
  assert.equal(rawRouteComparison.passed, true, rawRouteComparison.errors.join('\n'));
  assert.equal(finalizedRouteComparison.passed, true, finalizedRouteComparison.errors.join('\n'));
  assert.deepEqual(finalizedRouteComparison.routes, rawRouteComparison.routes);
  const captureWithLocalPath = {
    ...capture,
    warnings: [`Capture artifacts were finalized under ${packetDir}.`]
  };
  delete captureWithLocalPath.captureFingerprint;
  captureWithLocalPath.captureFingerprint = sha256(captureWithLocalPath);

  const shared = sharedGlobalChromeCapture(captureWithLocalPath, packetDir);
  const expectedPrivateIdentity = sha256('?preview=private-value').slice('sha256:'.length);
  const expectedLiteralIdentity = sha256(`?query-sha256=${literalDigest}`).slice('sha256:'.length);
  const expectedHeaderIdentity = sha256('?token=header-private').slice('sha256:'.length);
  const expectedEmailIdentity = sha256('?subject=email-private').slice('sha256:'.length);
  const expectedPhoneIdentity = sha256('?body=phone-private').slice('sha256:'.length);
  const serialized = JSON.stringify(shared);

  assert.doesNotMatch(serialized, /Visitor private-value|header-private|email-private|phone-private/);
  assert.equal(shared.primaryRoutes[0], `/search?query-sha256=${expectedPrivateIdentity}`);
  assert.equal(shared.routes[0].signals.meaningfulHrefs[1].href, `/search?query-sha256=${expectedLiteralIdentity}`);
  assert.notEqual(
    shared.routes[0].signals.meaningfulHrefs[1].href,
    digestLikeRoute,
    'raw digest-like queries must not impersonate redaction output'
  );
  assert.equal(shared.routes[0].signals.meaningfulHrefs[0].href, `/next?query-sha256=${expectedHeaderIdentity}`);
  assert.equal(
    shared.routes[0].signals.meaningfulHrefs[2].href,
    `mailto:team@example.com?query-sha256=${expectedEmailIdentity}`
  );
  assert.equal(
    shared.routes[0].signals.meaningfulHrefs[3].href,
    `tel:+441234?query-sha256=${expectedPhoneIdentity}`
  );
  assert.equal(
    shared.routes[0].signals.primaryNavigation.entries[0].labelSha256,
    sha256('visitor private-value')
  );
  assert.equal(
    shared.routes[0].signals.primaryNavigation.entries[0].href,
    `/next?query-sha256=${expectedHeaderIdentity}`
  );
  assert.equal(
    shared.routes[0].signals.primaryNavigation.entries[1].href,
    `mailto:team@example.com?query-sha256=${expectedEmailIdentity}`
  );
  assert.equal('label' in shared.routes[0].signals.primaryNavigation.entries[0], false);
  assert.doesNotMatch(shared.warnings.join('\n'), new RegExp(packetDir));
  const storedAxeReport = JSON.parse(readFileSync(join(packetDir, shared.routes[0].axe.report.path), 'utf8'));
  assert.equal(storedAxeReport.url, `https://fixture.ddev.site/search?query-sha256=${expectedPrivateIdentity}`);
  assert.doesNotMatch(JSON.stringify(storedAxeReport), /private-value|header-private|email-private|phone-private/);
  const fingerprintInput = { ...shared };
  delete fingerprintInput.captureFingerprint;
  assert.equal(shared.captureFingerprint, sha256(fingerprintInput));
  assert.notEqual(shared.captureFingerprint, captureWithLocalPath.captureFingerprint);
  assert.equal(
    validateGlobalChromeCapture(shared, { stateFingerprint: state('f'), requireAuthoritative: false }),
    shared
  );
  assert.equal(validateScreenshotArtifacts(packetDir, shared), true);
});

test('applicable consent capture fails closed when Chrome is unavailable', async () => {
  const unavailable = await captureBeforeConsentNetwork({
    baseUrl: 'https://fixture.ddev.site',
    primaryRoutes: ['/'],
    browserExecutable: '/definitely/not/a/browser'
  });
  assert.equal(unavailable.status, 'unavailable');
  assert.equal(unavailable.authoritative, false);
  assert.throws(() => finalizeBeforeConsentNetworkCapture({
    capture: unavailable,
    stateFingerprint: state('e'),
    targetOrigin: 'https://fixture.ddev.site'
  }), /capture is unavailable/i);
  const reconciliation = verifyConsentReconciliation({
    discoveryStatus: 'installed',
    managers: [{ id: 'klaro', module: 'klaro', configNames: ['klaro.application.maps'] }],
    applications: [{
      id: 'maps', configName: 'klaro.application.maps', enabled: false, required: false,
      controlledResources: [{ kind: 'script', pattern: 'maps.example' }]
    }]
  }, {
    confirmed: true,
    detected: true,
    managerModules: ['klaro'],
    configNames: ['klaro.application.maps'],
    applications: [{
      id: 'maps', configName: 'klaro.application.maps', enabled: false, required: false,
      resources: [{ kind: 'script', pattern: 'maps.example' }]
    }]
  }, [{ renderedResourceUrls: [] }], unavailable, {
    targetOrigin: 'https://fixture.ddev.site', primaryRoutes: ['/'], stateFingerprint: state('e')
  });
  assert.equal(reconciliation.passed, false);
  assert.match(reconciliation.errors.join('\n'), /requires verifier-owned fresh browser\/network capture/i);
});
