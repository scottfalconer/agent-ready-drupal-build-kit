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
  DEFAULT_SELENIUM_GRID_URL,
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
  compareGlobalChromeCaptures,
  createBrowserCaptureBudget,
  finalizeBeforeConsentNetworkCapture,
  finalizeGlobalChromeCapture,
  findBrowserExecutable,
  globalChromeImpact,
  normalizeGlobalChromeContract,
  openSeleniumCdpBackend,
  validateBeforeConsentNetworkCapture,
  validateScreenshotArtifacts,
  verifierAxeCompletionErrors
} from '../bin/global-chrome.mjs';
import {
  consentNetworkCaptureRequired,
  sharedBeforeConsentNetworkCapture,
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

test('CDP pipe captures desktop/mobile screenshots and computed signals without a browser-driver dependency', {
  skip: findBrowserExecutable() ? false : 'Chrome/Chromium is not installed in this runtime.'
}, async () => {
  const server = createServer((request, response) => {
    const missingBrand = request.url?.startsWith('/missing-brand');
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html lang="en"><head><title>Global chrome fixture</title><meta name="viewport" content="width=device-width"><style>
      body{margin:0} header,footer{padding:20px} main{min-height:700px}a,button{display:inline-flex;min-width:24px;min-height:24px;padding:4px;margin:2px}.menu-toggle{display:none}
      @media(max-width:600px){.menu-toggle{display:block}#main-nav{display:none}#main-nav.open{display:block}}
    </style></head><body>
      <header><div class="hf-branding">${missingBrand ? '' : '<a class="site-branding" href="/">Fixture Brand</a>'}</div>
      <button class="menu-toggle" aria-label="Menu" aria-controls="main-nav" aria-expanded="false"
        onclick="this.setAttribute('aria-expanded','true');document.getElementById('main-nav').classList.add('open')">Menu</button>
      <nav id="main-nav"><a href="/">Home</a><a href="/about">About</a></nav></header>
      <main><h1>Fixture</h1><p data-dynamic>Dynamic timestamp</p></main>
      <footer><a href="/legal">Legal</a><a href="mailto:team@example.com">Email</a></footer>
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
    assert.ok(raw.routes.every((route) => route.signals.placeholderHrefs.length === 0));
    assert.ok(raw.routes.every((route) => route.signals.meaningfulHrefs.some((link) => link.href === 'mailto:team@example.com')));
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
