import { spawn } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, sha256 } from './state-fingerprint.mjs';

const PINNED_WEBSOCKET_VERSION = '8.21.0';
const PINNED_WEBSOCKET_BUNDLE_SHA256 = 'sha256:6eaf56d9fa8443aeaa354c74d0e6ca2eef8f8194c25ba47ab8c0d92f3037191b';

async function loadPinnedWebSocket() {
  const bundleUrl = new URL(`../vendor/ws/${PINNED_WEBSOCKET_VERSION}/ws.mjs`, import.meta.url);
  if (sha256(readFileSync(bundleUrl)) !== PINNED_WEBSOCKET_BUNDLE_SHA256) {
    throw new Error('Pinned WebSocket transport failed its runtime integrity check. Reinstall the build-kit skill.');
  }
  const keys = ['WS_NO_BUFFER_UTIL', 'WS_NO_UTF_8_VALIDATE'];
  const previous = new Map(keys.map((key) => [key, process.env[key]]));
  for (const key of keys) process.env[key] = '1';
  try {
    return (await import(bundleUrl.href)).default;
  } finally {
    for (const key of keys) {
      const value = previous.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

const WebSocket = await loadPinnedWebSocket();

export const GLOBAL_CHROME_CAPTURE_SCHEMA = 'public-kit.global-chrome-capture.1';
export const GLOBAL_CHROME_CONTRACT_SCHEMA = 'public-kit.global-chrome-contract.1';
export const GLOBAL_CHROME_COMPARISON_SCHEMA = 'public-kit.global-chrome-comparison.1';
export const VISUAL_PARITY_FLOOR_SCHEMA = 'public-kit.visual-parity-floor.1';
export const BEFORE_CONSENT_NETWORK_SCHEMA = 'public-kit.before-consent-network-capture.1';
export const VERIFIER_AXE_SCHEMA = 'public-kit.verifier-axe.1';
export const VERIFIER_AXE_VERSION = '4.10.3';
export const DEFAULT_SELENIUM_GRID_URL = 'http://selenium-chrome:4444';
export const SELENIUM_ADD_ON_RELEASE = '2.2.1';
export const SELENIUM_CHROMIUM_IMAGE = 'selenium/standalone-chromium:149.0@sha256:9b10a9ccf68e3a18153a68a0705577157e20665d88d00bd4393a42e5839aa3d3';
export const SELENIUM_CHROMIUM_MAJOR = '149';
export const VERIFIER_WEBSOCKET_VERSION = PINNED_WEBSOCKET_VERSION;
export const VERIFIER_WEBSOCKET_SOURCE_SHA256 = 'sha256:d08b726b3aae3a0fed5218a0d9a4b2ac8d75d4ad453a9271db55fe38e94eb4cf';
export const VERIFIER_WEBSOCKET_BUNDLE_SHA256 = PINNED_WEBSOCKET_BUNDLE_SHA256;
export const VERIFIER_AXE_TAGS = Object.freeze([
  'wcag2a',
  'wcag2aa',
  'wcag21a',
  'wcag21aa',
  'wcag22a',
  'wcag22aa'
]);
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const VERIFIER_AXE_SOURCE_PATH = join(
  SCRIPT_DIRECTORY,
  '..',
  'assets',
  'vendor',
  'axe-core',
  VERIFIER_AXE_VERSION,
  'axe.min.js'
);
const VERIFIER_AXE_SOURCE = readFileSync(VERIFIER_AXE_SOURCE_PATH, 'utf8');
export const VERIFIER_AXE_SOURCE_SHA256 = sha256(VERIFIER_AXE_SOURCE);
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const AXE_WCAG_TAG_RE = /^wcag(?:2|21|22)(?:a|aa)$/i;
const VIEWPORTS = Object.freeze([
  Object.freeze({ name: 'desktop', width: 1280, height: 800, mobile: false }),
  Object.freeze({ name: 'mobile', width: 390, height: 844, mobile: true })
]);
export const BROWSER_CAPTURE_LIMITS = Object.freeze({
  deadlineMs: 120_000,
  maxRoutes: 64,
  operationTimeoutMs: 20_000
});
const FIXED_THRESHOLDS = Object.freeze({
  maximumMainTopShiftPx: 160,
  maximumPageHeightRatio: 1.6,
  minimumPageHeightRatio: 0.65
});
const VISUAL_FLOOR_THRESHOLDS = Object.freeze({
  minimumActionRatio: 0.5,
  minimumHeadingRatio: 0.5,
  minimumHeadingOrderRatio: 0.5,
  minimumLayoutBandRatio: 0.5,
  minimumMediaRatio: 0.4,
  minimumPageHeightRatio: 0.45
});
const CONFIG_GLOBAL_RE = /(?:^|\/)(?:canvas\.(?:page_region|brand_kit|asset_library\.global)|block\.block\.|system\.(?:menu\.|theme(?:\.|$))|navigation\.|core\.menu\.static_menu_link_overrides|core\.entity_view_display\.|canvas\.content_template\.)/i;
const CODE_GLOBAL_RE = /(?:^|\/)(?:(?:web|docroot)\/)?themes\/(?:custom|contrib)\//i;
const DEPENDENCY_GLOBAL_RE = /(?:^|\/)composer\.lock$/i;
const QUERY_IN_TEXT_RE = /((?:https?:\/\/[^\s"'<>?]+|\/[^\s"'<>?]*))\?([^\s"'<>]+)/g;

function connectWebSocket(value, { signal } = {}) {
  if (signal?.aborted) return Promise.reject(signal.reason ?? new Error('WebSocket connection aborted.'));
  return new Promise((resolvePromise, rejectPromise) => {
    let socket;
    let settled = false;
    const cleanup = () => {
      signal?.removeEventListener('abort', abort);
      socket?.removeListener('open', opened);
      socket?.removeListener('error', failed);
    };
    const reject = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectPromise(error instanceof Error ? error : new Error(String(error)));
    };
    const abort = () => {
      try { socket?.terminate(); } catch {}
      reject(signal?.reason ?? new Error('WebSocket connection aborted.'));
    };
    const failed = (error) => reject(error);
    const opened = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolvePromise(socket);
    };
    try {
      socket = new WebSocket(value, {
        followRedirects: false,
        maxPayload: 64 * 1024 * 1024,
        perMessageDeflate: false
      });
    } catch (error) {
      reject(error);
      return;
    }
    signal?.addEventListener('abort', abort, { once: true });
    socket.once('open', opened);
    socket.once('error', failed);
  });
}

function boundedPositiveLimit(value, ceiling, label) {
  if (value === undefined) return ceiling;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer.`);
  }
  return Math.min(value, ceiling);
}

export function createBrowserCaptureBudget({
  label = 'Browser capture',
  limits = {},
  now = Date.now,
  routeCount = 0,
  viewportCount = 1
} = {}) {
  if (!Number.isSafeInteger(routeCount) || routeCount < 0) {
    throw new Error(`${label} routeCount must be a non-negative safe integer.`);
  }
  if (!Number.isSafeInteger(viewportCount) || viewportCount <= 0) {
    throw new Error(`${label} viewportCount must be a positive safe integer.`);
  }
  if (typeof now !== 'function') throw new Error(`${label} clock must be a function.`);
  const boundedLimits = Object.freeze({
    deadlineMs: boundedPositiveLimit(limits.deadlineMs, BROWSER_CAPTURE_LIMITS.deadlineMs, `${label} deadlineMs`),
    maxRoutes: boundedPositiveLimit(limits.maxRoutes, BROWSER_CAPTURE_LIMITS.maxRoutes, `${label} maxRoutes`),
    operationTimeoutMs: boundedPositiveLimit(
      limits.operationTimeoutMs,
      BROWSER_CAPTURE_LIMITS.operationTimeoutMs,
      `${label} operationTimeoutMs`
    )
  });
  const startedAt = now();
  if (!Number.isFinite(startedAt)) throw new Error(`${label} clock must return a finite timestamp.`);
  let deadlineExceeded = false;
  const deadlineMessage = () => `${label} exceeded its ${boundedLimits.deadlineMs} ms total wall-clock deadline.`;
  const deadlineError = () => {
    deadlineExceeded = true;
    return new Error(deadlineMessage());
  };
  const elapsedMs = () => Math.max(0, Math.floor(now() - startedAt));
  const remainingMs = () => {
    const remaining = boundedLimits.deadlineMs - elapsedMs();
    if (remaining <= 0) throw deadlineError();
    return remaining;
  };
  return Object.freeze({
    label,
    limits: boundedLimits,
    assertRouteLimit() {
      if (routeCount > boundedLimits.maxRoutes) {
        throw new Error(
          `${label} requires ${routeCount} routes, exceeding the ${boundedLimits.maxRoutes} route limit; no browser checks were run.`
        );
      }
    },
    assertWithinDeadline() {
      remainingMs();
    },
    deadlineError,
    hasExceededDeadline() {
      return deadlineExceeded;
    },
    operationTiming() {
      const remaining = remainingMs();
      return {
        deadlineLimited: remaining <= boundedLimits.operationTimeoutMs,
        timeoutMs: Math.max(1, Math.min(remaining, boundedLimits.operationTimeoutMs))
      };
    },
    metrics({ attempted = false, capturedCount = 0 } = {}) {
      return {
        attempted,
        capturedRouteViewportCount: capturedCount,
        deadlineExceeded,
        deadlineMs: boundedLimits.deadlineMs,
        elapsedMs: elapsedMs(),
        maxRoutes: boundedLimits.maxRoutes,
        operationTimeoutMs: boundedLimits.operationTimeoutMs,
        routeCount,
        scheduledRouteViewportCount: routeCount * viewportCount,
        viewportCount
      };
    }
  });
}

export function cleanupBrowserProfile(profile, {
  maxRetries = 5,
  remove = rmSync,
  retryDelayMs = 50
} = {}) {
  try {
    remove(profile, {
      recursive: true,
      force: true,
      maxRetries: boundedPositiveLimit(maxRetries, 10, 'Browser profile cleanup maxRetries'),
      retryDelay: boundedPositiveLimit(retryDelayMs, 250, 'Browser profile cleanup retryDelayMs')
    });
    return { deferred: false, warnings: [] };
  } catch (error) {
    const code = String(error?.code ?? 'unknown-error').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40) || 'unknown-error';
    return {
      deferred: true,
      warnings: [`Browser profile cleanup was deferred after bounded retries (${code}).`]
    };
  }
}

function normalizeRoute(value) {
  const text = String(value ?? '').trim();
  if (!text.startsWith('/') || text.startsWith('//')) throw new Error(`Global chrome route must be root-relative: ${text}`);
  const url = new URL(text, 'https://global-chrome.invalid');
  return `${url.pathname || '/'}${url.search}`;
}

function privacyPreservingQuery(value) {
  const query = String(value ?? '');
  if (!query) return '';
  const normalized = query.startsWith('?') ? query : `?${query}`;
  return `?query-sha256=${sha256(normalized).slice('sha256:'.length)}`;
}

function privacyPreservingText(value) {
  return String(value).replace(
    QUERY_IN_TEXT_RE,
    (_match, prefix, rawQueryWithPunctuation) => {
      const [, rawQuery, punctuation = ''] = rawQueryWithPunctuation.match(/^(.*?)([),.;:]*)$/) ?? [];
      return rawQuery
        ? `${prefix}${privacyPreservingQuery(rawQuery)}${punctuation}`
        : _match;
    }
  );
}

function privacyPreservingValue(value) {
  if (typeof value === 'string') return privacyPreservingText(value);
  if (Array.isArray(value)) return value.map(privacyPreservingValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, privacyPreservingValue(entry)])
    );
  }
  return value;
}

function privacyPreservingRoute(value) {
  const route = normalizeRoute(value);
  const url = new URL(route, 'https://before-consent.invalid');
  return `${url.pathname || '/'}${privacyPreservingQuery(url.search)}`;
}

function inside(parent, child) {
  const fromParent = relative(parent, child);
  return fromParent === '' || (
    fromParent !== '..' &&
    !fromParent.startsWith(`..${sep}`) &&
    !isAbsolute(fromParent)
  );
}

function assertSafeDirectoryChain(root, target, label) {
  const requestedRoot = resolve(root);
  const requestedTarget = resolve(target);
  if (!existsSync(requestedRoot) || lstatSync(requestedRoot).isSymbolicLink() || !lstatSync(requestedRoot).isDirectory()) {
    throw new Error(`${label} root must be a real directory, not a file or symbolic link.`);
  }
  if (!inside(requestedRoot, requestedTarget)) {
    throw new Error(`${label} must remain inside the review packet.`);
  }
  const realRoot = realpathSync(requestedRoot);
  let current = requestedRoot;
  for (const segment of relative(requestedRoot, requestedTarget).split(sep).filter(Boolean)) {
    current = join(current, segment);
    if (!existsSync(current)) continue;
    const metadata = lstatSync(current);
    if (metadata.isSymbolicLink() || !metadata.isDirectory() || !inside(realRoot, realpathSync(current))) {
      throw new Error(`${label} must not traverse a file or symbolic link: ${current}`);
    }
  }
}

function ensureSafeDirectory(root, target, label) {
  assertSafeDirectoryChain(root, target, label);
  mkdirSync(target, { recursive: true });
  assertSafeDirectoryChain(root, target, label);
}

function normalizedSelectors(value) {
  const selectors = Array.isArray(value) ? value : [];
  if (selectors.length > 32) throw new Error('Global chrome dynamicRegionSelectors is limited to 32 selectors.');
  const normalized = [...new Set(selectors.map((selector) => String(selector).trim()).filter(Boolean))].sort();
  for (const selector of normalized) {
    if (selector.length > 240 || /[\r\n\0]/.test(selector)) {
      throw new Error('Global chrome dynamic-region selectors must be single-line CSS selectors of at most 240 characters.');
    }
  }
  return normalized;
}

export function normalizeGlobalChromeContract(value = {}) {
  const contract = {
    schemaVersion: GLOBAL_CHROME_CONTRACT_SCHEMA,
    selectorHeuristicsVersion: 2,
    dynamicRegionSelectors: normalizedSelectors(value?.dynamicRegionSelectors),
    thresholds: FIXED_THRESHOLDS,
    viewports: VIEWPORTS.map(({ name, width, height }) => ({ name, width, height }))
  };
  return { ...contract, fingerprint: sha256(contract) };
}

export function findBrowserExecutable(environment = process.env) {
  const candidates = [
    environment.CHROME_PATH,
    environment.CHROMIUM_PATH,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/microsoft-edge'
  ].map((value) => String(value ?? '').trim()).filter(Boolean);
  return candidates.find((path) => existsSync(path)) ?? '';
}

class CdpConnection {
  constructor(write, budget = null, timeoutMs = BROWSER_CAPTURE_LIMITS.operationTimeoutMs) {
    this.write = write;
    this.budget = budget;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.waiters = [];
    this.listeners = new Set();
    this.failure = null;
  }

  receive(raw, { binary = false } = {}) {
    if (this.failure) return;
    if (binary) {
      this.failAll(new Error('CDP WebSocket returned an unsupported binary message.'));
      return;
    }
    let message;
    try {
      message = JSON.parse(Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw));
    } catch {
      this.failAll(new Error('CDP transport returned malformed JSON.'));
      return;
    }
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      this.failAll(new Error('CDP transport returned a non-object message.'));
      return;
    }
    if (Number.isSafeInteger(message.id)) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timeout);
      if (message.error) {
        const detail = String(message.error?.message ?? message.error?.code ?? 'unknown CDP error');
        pending.reject(new Error(`${pending.method}: ${detail}`));
      } else {
        pending.resolve(message.result ?? {});
      }
      return;
    }
    if (typeof message.method !== 'string' || !message.method) return;
    for (const listener of this.listeners) {
      if (listener.method === message.method && (!listener.sessionId || listener.sessionId === message.sessionId)) {
        listener.callback(message.params ?? {});
      }
    }
    const waiterIndex = this.waiters.findIndex((waiter) =>
      waiter.method === message.method && (!waiter.sessionId || waiter.sessionId === message.sessionId)
    );
    if (waiterIndex !== -1) {
      const [waiter] = this.waiters.splice(waiterIndex, 1);
      clearTimeout(waiter.timeout);
      waiter.resolve(message.params ?? {});
    } else {
      this.events.push(message);
      if (this.events.length > 200) this.events.shift();
    }
  }

  failAll(error) {
    if (this.failure) return;
    this.failure = error instanceof Error ? error : new Error(String(error));
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(this.failure);
    }
    this.pending.clear();
    for (const waiter of this.waiters) {
      clearTimeout(waiter.timeout);
      waiter.reject(this.failure);
    }
    this.waiters = [];
  }

  send(method, params = {}, sessionId = '') {
    if (this.failure) return Promise.reject(this.failure);
    let timing = { deadlineLimited: false, timeoutMs: this.timeoutMs };
    try {
      if (this.budget) timing = this.budget.operationTiming();
    } catch (error) {
      return Promise.reject(error);
    }
    return this.sendWithTiming(method, params, sessionId, timing);
  }

  sendForCleanup(method, params = {}, sessionId = '') {
    if (this.failure) return Promise.reject(this.failure);
    return this.sendWithTiming(method, params, sessionId, {
      deadlineLimited: false,
      timeoutMs: Math.min(this.timeoutMs, 5_000)
    });
  }

  sendWithTiming(method, params, sessionId, timing) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolvePromise, rejectPromise) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        rejectPromise(timing.deadlineLimited
          ? this.budget.deadlineError()
          : new Error(`${method} timed out after ${timing.timeoutMs} ms.`));
      }, timing.timeoutMs);
      this.pending.set(id, { method, resolve: resolvePromise, reject: rejectPromise, timeout });
      try {
        this.write(message);
      } catch (error) {
        clearTimeout(timeout);
        this.pending.delete(id);
        rejectPromise(error);
      }
    });
  }

  waitFor(method, sessionId = '') {
    if (this.failure) return Promise.reject(this.failure);
    let timing = { deadlineLimited: false, timeoutMs: this.timeoutMs };
    try {
      if (this.budget) timing = this.budget.operationTiming();
    } catch (error) {
      return Promise.reject(error);
    }
    const queuedIndex = this.events.findIndex((event) =>
      event.method === method && (!sessionId || event.sessionId === sessionId)
    );
    if (queuedIndex !== -1) return Promise.resolve(this.events.splice(queuedIndex, 1)[0].params ?? {});
    return new Promise((resolvePromise, rejectPromise) => {
      const waiter = { method, sessionId, resolve: resolvePromise, reject: rejectPromise };
      waiter.timeout = setTimeout(() => {
        this.waiters = this.waiters.filter((candidate) => candidate !== waiter);
        rejectPromise(timing.deadlineLimited
          ? this.budget.deadlineError()
          : new Error(`${method} event timed out after ${timing.timeoutMs} ms.`));
      }, timing.timeoutMs);
      this.waiters.push(waiter);
    });
  }

  subscribe(method, sessionId, callback) {
    const listener = { method, sessionId, callback };
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

class CdpPipe extends CdpConnection {
  constructor(child, budget = null, timeoutMs = BROWSER_CAPTURE_LIMITS.operationTimeoutMs) {
    const input = child.stdio[3];
    super((message) => input.write(`${JSON.stringify(message)}\0`), budget, timeoutMs);
    this.buffer = Buffer.alloc(0);
    child.stdio[4].on('data', (chunk) => this.onData(chunk));
    child.once('exit', (code, signal) => this.failAll(new Error(`Headless browser exited (${code ?? signal ?? 'unknown'}).`)));
    child.once('error', (error) => this.failAll(error));
  }

  onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const boundary = this.buffer.indexOf(0);
      if (boundary === -1) break;
      const bytes = this.buffer.subarray(0, boundary);
      this.buffer = this.buffer.subarray(boundary + 1);
      if (bytes.length > 0) this.receive(bytes);
    }
  }
}

class CdpWebSocket extends CdpConnection {
  constructor(socket, budget = null, timeoutMs = BROWSER_CAPTURE_LIMITS.operationTimeoutMs) {
    super((message) => socket.send(JSON.stringify(message)), budget, timeoutMs);
    this.socket = socket;
    socket.on('message', (data, binary = false) => this.receive(data, { binary }));
    socket.once('error', (error) => this.failAll(error));
    socket.once('close', () => this.failAll(new Error('CDP WebSocket closed.')));
  }

  close() {
    this.failAll(new Error('CDP WebSocket was closed by the verifier.'));
    try {
      if (typeof this.socket.terminate === 'function') this.socket.terminate();
      else this.socket.close();
    } catch {}
  }
}

function seleniumGridOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Selenium Grid URL must be an HTTP(S) origin without credentials, path, query, or fragment.');
  }
  return url.origin;
}

export function canonicalizeSeleniumCdpUrl(advertisedValue, sessionId, gridUrl = DEFAULT_SELENIUM_GRID_URL) {
  const id = String(sessionId ?? '').trim();
  if (!/^[A-Za-z0-9._-]{1,200}$/.test(id)) throw new Error('WebDriver returned an invalid session ID.');
  let advertised;
  try { advertised = new URL(advertisedValue); }
  catch { throw new Error('WebDriver did not return a valid se:cdp WebSocket URL.'); }
  const expectedPath = `/session/${id}/se/cdp`;
  if (
    !['ws:', 'wss:'].includes(advertised.protocol) ||
    advertised.username || advertised.password || advertised.pathname !== expectedPath || advertised.search || advertised.hash
  ) {
    throw new Error(`WebDriver se:cdp must use the exact session-scoped path ${expectedPath}.`);
  }
  const trusted = new URL(seleniumGridOrigin(gridUrl));
  trusted.protocol = trusted.protocol === 'https:' ? 'wss:' : 'ws:';
  trusted.pathname = advertised.pathname;
  return trusted.href;
}

async function boundedWebDriverRequest({
  gridOrigin,
  path,
  method,
  body,
  budget,
  fetchImpl,
  phase,
  timeoutMs
}) {
  const timing = timeoutMs === undefined
    ? budget.operationTiming()
    : { deadlineLimited: false, timeoutMs };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`${phase} timed out after ${timing.timeoutMs} ms.`)), timing.timeoutMs);
  try {
    const response = await fetchImpl(`${gridOrigin}${path}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: controller.signal
    });
    const text = await response.text();
    let payload = null;
    if (text) {
      try { payload = JSON.parse(text); }
      catch { throw new Error(`${phase} returned malformed JSON.`); }
    }
    const webdriverError = payload?.value?.error;
    if (!response.ok || webdriverError) {
      const detail = String(payload?.value?.message ?? webdriverError ?? `HTTP ${response.status}`).replace(/\s+/g, ' ').slice(0, 500);
      throw new Error(`${phase} failed: ${detail}`);
    }
    return payload;
  } catch (error) {
    if (controller.signal.aborted) {
      if (timing.deadlineLimited) throw budget.deadlineError();
      throw controller.signal.reason instanceof Error ? controller.signal.reason : new Error(`${phase} timed out.`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function remoteChromeCapabilities() {
  return {
    capabilities: {
      alwaysMatch: {
        browserName: 'chrome',
        acceptInsecureCerts: true,
        'goog:chromeOptions': {
          args: ['--headless=new', '--disable-gpu', '--no-sandbox', '--window-size=1280,800']
        }
      }
    }
  };
}

async function observedBrowserExecutable(cdp, backend, product) {
  if (backend !== 'remote') return '';
  const match = String(product).match(/^(?:HeadlessChrome|Chrome|Chromium)\/(\d+)(?:\.|$)/);
  if (match?.[1] !== SELENIUM_CHROMIUM_MAJOR) {
    throw new Error(
      `Selenium runtime browser identity ${product || 'missing'} does not match pinned Chromium major ${SELENIUM_CHROMIUM_MAJOR}.`
    );
  }
  const commandLine = await cdp.send('Browser.getBrowserCommandLine');
  const executable = String(commandLine?.arguments?.[0] ?? '').trim();
  if (!executable || executable.startsWith('-') || !/(?:chrome|chromium)/i.test(executable)) {
    throw new Error('Selenium runtime did not report its selected Chrome/Chromium executable.');
  }
  return executable.slice(0, 1024);
}

export async function openSeleniumCdpBackend({
  budget,
  gridUrl = DEFAULT_SELENIUM_GRID_URL,
  fetchImpl = globalThis.fetch,
  webSocketConnector = connectWebSocket
} = {}) {
  if (!budget || typeof budget.operationTiming !== 'function') throw new Error('Remote browser backend requires a capture budget.');
  if (typeof fetchImpl !== 'function') throw new Error('Remote browser backend requires fetch support.');
  if (typeof webSocketConnector !== 'function') throw new Error('Remote browser backend requires a WebSocket connector.');
  const gridOrigin = seleniumGridOrigin(gridUrl);
  let sessionId = '';
  let cdp = null;
  let socket = null;
  let closePromise = null;
  const deleteSession = async () => {
    if (!sessionId) return;
    const deleting = sessionId;
    sessionId = '';
    await boundedWebDriverRequest({
      gridOrigin,
      path: `/session/${encodeURIComponent(deleting)}`,
      method: 'DELETE',
      budget,
      fetchImpl,
      phase: 'WebDriver session delete',
      timeoutMs: BROWSER_CAPTURE_LIMITS.operationTimeoutMs
    });
  };
  try {
    const created = await boundedWebDriverRequest({
      gridOrigin,
      path: '/session',
      method: 'POST',
      body: remoteChromeCapabilities(),
      budget,
      fetchImpl,
      phase: 'WebDriver session create'
    });
    const createdSessionId = String(created?.value?.sessionId ?? '').trim();
    if (!/^[A-Za-z0-9._-]{1,200}$/.test(createdSessionId)) {
      throw new Error('WebDriver returned an invalid session ID.');
    }
    sessionId = createdSessionId;
    const cdpUrl = canonicalizeSeleniumCdpUrl(created?.value?.capabilities?.['se:cdp'], sessionId, gridOrigin);
    const timing = budget.operationTiming();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(new Error(`CDP WebSocket connect timed out after ${timing.timeoutMs} ms.`)), timing.timeoutMs);
    try {
      socket = await webSocketConnector(cdpUrl, { signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) {
        if (timing.deadlineLimited) throw budget.deadlineError();
        throw controller.signal.reason instanceof Error ? controller.signal.reason : error;
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    cdp = new CdpWebSocket(socket, budget);
  } catch (error) {
    try { cdp?.close(); } catch {}
    try { socket?.close(); } catch {}
    let cleanupError = '';
    try { await deleteSession(); } catch (cleanup) { cleanupError = ` WebDriver cleanup also failed: ${cleanup.message}`; }
    throw new Error(`Verifier Selenium runtime is unavailable: ${error.message}${cleanupError}`);
  }
  return {
    cdp,
    executable: 'selenium-chrome',
    gridOrigin,
    close() {
      if (closePromise) return closePromise;
      closePromise = (async () => {
        const errors = [];
        cdp.close();
        try { await deleteSession(); } catch (error) { errors.push(error.message); }
        return { errors, warnings: [] };
      })();
      return closePromise;
    }
  };
}

function signalBrowserProcessGroup(child, signal) {
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    // The process group already exited.
  }
}

async function shutdownBrowser(child) {
  if (!child) return '';
  if (
    child.exitCode !== null &&
    child.stdio.every((stream) => !stream || stream.destroyed)
  ) return '';
  let closed = false;
  const closedPromise = new Promise((resolvePromise) => child.once('close', () => {
    closed = true;
    resolvePromise();
  }));
  try {
    signalBrowserProcessGroup(child, 'SIGTERM');
    await Promise.race([closedPromise, new Promise((resolvePromise) => setTimeout(resolvePromise, 1_000))]);
    // The Chrome parent may exit before profile-writing descendants. Always
    // signal the isolated process group before removing its ephemeral profile.
    signalBrowserProcessGroup(child, 'SIGKILL');
    if (!closed) {
      await Promise.race([closedPromise, new Promise((resolvePromise) => setTimeout(resolvePromise, 500))]);
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  } catch (error) {
    return `Browser shutdown failed: ${error.message}`;
  }
  return closed || child.stdio.every((stream) => !stream || stream.destroyed)
    ? ''
    : 'Browser shutdown failed: the headless browser did not close after bounded SIGTERM and SIGKILL.';
}

function openLocalCdpBackend({
  budget,
  executable,
  hideScrollbars = false,
  profileCleanup,
  profilePrefix
}) {
  const profile = join(tmpdir(), `${profilePrefix}-${process.pid}-${Date.now()}`);
  mkdirSync(profile, { recursive: true });
  const args = [
    '--headless=new', '--remote-debugging-pipe', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--disable-extensions',
    '--disable-sync', '--mute-audio', `--user-data-dir=${profile}`, 'about:blank'
  ];
  if (hideScrollbars) args.splice(args.length - 2, 0, '--hide-scrollbars');
  // The verifier is restricted to the current local DDEV target; local routers may use a custom TLD and development CA.
  args.unshift('--ignore-certificate-errors');
  if (typeof process.getuid === 'function' && process.getuid() === 0) args.unshift('--no-sandbox');
  const child = spawn(executable, args, {
    detached: process.platform !== 'win32',
    stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe']
  });
  const stderr = [];
  child.stderr.on('data', (chunk) => {
    if (stderr.join('').length < 8000) stderr.push(chunk.toString('utf8'));
  });
  const cdp = new CdpPipe(child, budget);
  let closePromise = null;
  return {
    cdp,
    executable: basename(executable),
    diagnostics() {
      return stderr.join('').replace(/\s+/g, ' ').trim().slice(0, 800);
    },
    close() {
      if (closePromise) return closePromise;
      closePromise = (async () => {
        const errors = [];
        const warnings = [];
        const shutdownError = await shutdownBrowser(child);
        if (shutdownError) {
          errors.push(shutdownError);
          warnings.push('Browser profile cleanup was deferred because browser shutdown was not confirmed.');
        } else {
          try {
            const cleanup = profileCleanup(profile);
            warnings.push(...(Array.isArray(cleanup?.warnings) ? cleanup.warnings : []));
          } catch (error) {
            const code = String(error?.code ?? 'unknown-error').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40) || 'unknown-error';
            warnings.push(`Browser profile cleanup was deferred after bounded retries (${code}).`);
          }
        }
        return { errors, warnings };
      })();
      return closePromise;
    }
  };
}

function ddevContainerMode(environment) {
  return /^(?:1|true|yes)$/i.test(String(environment?.IS_DDEV_PROJECT ?? '').trim());
}

function browserBackendKind(browserBackend, browserExecutable, environment = process.env) {
  const selected = browserBackend === undefined
    ? (browserExecutable !== undefined || !ddevContainerMode(environment) ? 'local' : 'remote')
    : String(browserBackend).trim();
  if (!['remote', 'local'].includes(selected)) {
    throw new Error('Browser backend must be remote or local.');
  }
  return selected;
}

function browserRuntimeEvidence({ backend, executable = '', product = '', protocolVersion = '', ready = false } = {}) {
  const remote = backend === 'remote';
  return {
    backend: remote ? 'selenium-grid-cdp' : 'local-executable-cdp-pipe',
    executionBoundary: remote ? 'ddev-add-on-sidecar' : 'maintainer-local-process',
    service: remote ? 'selenium-chrome' : '',
    addOnRelease: remote ? SELENIUM_ADD_ON_RELEASE : '',
    image: remote ? SELENIUM_CHROMIUM_IMAGE : '',
    executable,
    product,
    protocolVersion,
    ready: ready === true
  };
}

async function openCaptureBrowserBackend({
  browserBackend,
  browserExecutable,
  budget,
  environment,
  fetchImpl,
  gridUrl,
  hideScrollbars,
  profileCleanup,
  profilePrefix,
  webSocketConnector
}) {
  const kind = browserBackendKind(browserBackend, browserExecutable, environment);
  if (kind === 'remote') {
    return openSeleniumCdpBackend({ budget, gridUrl, fetchImpl, webSocketConnector });
  }
  const executable = browserExecutable === undefined
    ? findBrowserExecutable(environment)
    : String(browserExecutable ?? '').trim();
  if (!executable || !existsSync(executable)) {
    throw new Error('No Chrome/Chromium executable was found for the explicit local maintainer backend.');
  }
  return openLocalCdpBackend({ budget, executable, hideScrollbars, profileCleanup, profilePrefix });
}

function collectorExpression(contract, mobile) {
  const source = async ({ dynamicRegionSelectors, mobileViewport }) => {
    const visible = (element) => {
      if (!(element instanceof Element)) return false;
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return box.width > 1 && box.height > 1 && style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity) > 0;
    };
    const box = (element) => {
      if (!(element instanceof Element)) return null;
      const value = element.getBoundingClientRect();
      return {
        top: Math.round(value.top), left: Math.round(value.left), width: Math.round(value.width), height: Math.round(value.height)
      };
    };
    const first = (selectors, preferVisible = true) => {
      const elements = [];
      for (const selector of selectors) {
        try { elements.push(...document.querySelectorAll(selector)); } catch {}
      }
      return (preferVisible ? elements.find(visible) : null) || elements[0] || null;
    };
    const chromeSelector = 'header,nav,footer,[role="banner"],[role="navigation"],[role="contentinfo"],.site-branding,[class*="site-brand"],[id*="site-brand"]';
    const header = first(['header', '[role="banner"]', '#header', '.site-header']);
    const navigation = first([
      'header nav', '[role="banner"] nav', 'nav[aria-label*="primary" i]', '#navigation',
      '.main-navigation', '.primary-navigation'
    ], false) || first(['nav', '[role="navigation"]']);
    const footer = first(['footer', '[role="contentinfo"]', '#footer', '.site-footer']);
    const brand = first([
      'header a[rel="home"] img', 'header a[class*="brand" i] img', 'header a[class*="logo" i] img',
      '[role="banner"] a[rel="home"] img', '.block-system-branding-block img', '.site-branding img',
      '[class*="site-brand" i] img', '[id*="site-brand" i] img',
      'header a[rel="home"] svg', 'header a[class*="brand" i] svg', 'header a[class*="logo" i] svg',
      '.block-system-branding-block', '[data-block-plugin-id="system_branding_block"]',
      '[class*="site-brand" i]', '[id*="site-brand" i]', '[class*="branding" i]', '[id*="branding" i]',
      'header a[rel="home"]', '.site-branding'
    ]);
    const maskViolations = [];
    const masked = [];
    for (const selector of dynamicRegionSelectors) {
      let matches;
      try { matches = [...document.querySelectorAll(selector)]; }
      catch { maskViolations.push(`Invalid dynamic selector: ${selector}`); continue; }
      for (const element of matches) {
        const intersectsDetectedChrome = [header, navigation, footer, brand].some((chromeElement) =>
          chromeElement && (element === chromeElement || element.contains(chromeElement) || chromeElement.contains(element))
        );
        if (intersectsDetectedChrome || element.matches(chromeSelector) || element.closest(chromeSelector) || element.querySelector(chromeSelector)) {
          maskViolations.push(`Dynamic selector intersects global chrome: ${selector}`);
          continue;
        }
        element.setAttribute('data-agent-ready-dynamic-mask', '');
        masked.push(element);
      }
    }
    const style = document.createElement('style');
    style.setAttribute('data-agent-ready-global-chrome', '');
    style.textContent = `
      *, *::before, *::after { animation: none !important; transition: none !important; caret-color: transparent !important; }
      [data-agent-ready-dynamic-mask] { color: transparent !important; background: #d8d8d8 !important; box-shadow: none !important; text-shadow: none !important; }
      [data-agent-ready-dynamic-mask] img, [data-agent-ready-dynamic-mask] video, [data-agent-ready-dynamic-mask] iframe, [data-agent-ready-dynamic-mask] svg { visibility: hidden !important; }
    `;
    document.head.append(style);
    const normalizeHref = (href) => {
      try {
        const raw = String(href || '').trim();
        if (!raw) return '';
        const url = new URL(raw, location.href);
        if (['mailto:', 'tel:', 'sms:'].includes(url.protocol)) return url.href;
        if (!['http:', 'https:'].includes(url.protocol)) return '';
        url.hash = '';
        return url.origin === location.origin ? `${url.pathname}${url.search}` : url.href;
      } catch { return ''; }
    };
    const links = [];
    const placeholders = [];
    for (const [scope, root] of [['header', header], ['navigation', navigation], ['footer', footer]]) {
      if (!(root instanceof Element)) continue;
      for (const link of root.querySelectorAll('a')) {
        if (!visible(link)) continue;
        const raw = String(link.getAttribute('href') ?? '').trim();
        const label = String(link.getAttribute('aria-label') || link.textContent || link.querySelector('img')?.alt || '').replace(/\s+/g, ' ').trim();
        const href = normalizeHref(raw);
        if (!raw || raw === '#' || /^javascript:/i.test(raw) || !href) placeholders.push({ scope, raw, label });
        else links.push({ scope, href, label });
      }
    }
    links.sort((left, right) => `${left.scope}\0${left.href}\0${left.label}`.localeCompare(`${right.scope}\0${right.href}\0${right.label}`));
    const brandImage = brand?.matches('img') ? brand : brand?.querySelector('img');
    const brandSvg = brand?.matches('svg') ? brand : brand?.querySelector('svg');
    const brandLink = brand?.closest('a') || brand?.querySelector('a');
    const brandStyle = brand instanceof Element ? getComputedStyle(brand) : null;
    const brandBeforeStyle = brand instanceof Element ? getComputedStyle(brand, '::before') : null;
    const brandAfterStyle = brand instanceof Element ? getComputedStyle(brand, '::after') : null;
    const visualStyle = (computed) => computed ? {
      backgroundImage: computed.backgroundImage === 'none' ? '' : computed.backgroundImage,
      content: ['none', 'normal'].includes(computed.content) ? '' : computed.content
    } : { backgroundImage: '', content: '' };
    const brandIdentity = brand ? {
      href: normalizeHref(brandLink?.getAttribute('href') || ''),
      image: normalizeHref(brandImage?.currentSrc || brandImage?.getAttribute('src') || ''),
      alt: String(brandImage?.getAttribute('alt') || '').trim(),
      text: String(brand.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160),
      svg: brandSvg ? String(brandSvg.outerHTML || '').replace(/\s+/g, ' ').trim().slice(0, 1000) : '',
      style: visualStyle(brandStyle),
      beforeStyle: visualStyle(brandBeforeStyle),
      afterStyle: visualStyle(brandAfterStyle)
    } : null;
    const trigger = first([
      'button[aria-controls*="menu" i]', 'button[aria-label*="menu" i]', 'button[class*="menu" i]',
      'button[id*="menu" i]', '.menu-toggle', '.navbar-toggler', '[data-drupal-selector*="menu"] button'
    ]);
    let mobileMenu = {
      triggerPresent: Boolean(trigger), triggerVisible: visible(trigger), activationWorks: false,
      expandedBefore: String(trigger?.getAttribute('aria-expanded') || ''), expandedAfter: '', controlledMenuVisible: false
    };
    if (mobileViewport && visible(trigger)) {
      const beforeNavVisible = visible(navigation);
      trigger.click();
      await new Promise((resolve) => setTimeout(resolve, 120));
      const controlledId = String(trigger.getAttribute('aria-controls') || '').trim();
      const controlled = controlledId ? document.getElementById(controlledId) : null;
      mobileMenu.expandedAfter = String(trigger.getAttribute('aria-expanded') || '');
      mobileMenu.controlledMenuVisible = visible(controlled);
      mobileMenu.activationWorks = mobileMenu.expandedAfter === 'true' || mobileMenu.controlledMenuVisible || (!beforeNavVisible && visible(navigation));
      if (mobileMenu.expandedBefore !== mobileMenu.expandedAfter) trigger.click();
    }
    const topLevelMasked = masked.filter((element) => !masked.some((candidate) => candidate !== element && candidate.contains(element)));
    const maskedHeight = topLevelMasked.reduce((sum, element) => sum + Math.max(0, element.getBoundingClientRect().height), 0);
    const main = first(['main', '[role="main"]', '#main-content', '.main-content'], false);
    const documentHeight = Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0);
    const roleSignal = (element) => ({ present: Boolean(element), visible: visible(element), box: box(element) });
    const normalizeText = (value, limit = 160) => String(value || '').replace(/\s+/g, ' ').trim().slice(0, limit);
    const contentRoot = main || document.body;
    const headings = contentRoot instanceof Element
      ? [...contentRoot.querySelectorAll('h1,h2,h3')].filter(visible).slice(0, 64)
      : [];
    const headingOrder = headings.map((heading) => normalizeText(heading.textContent)).filter(Boolean);
    const media = contentRoot instanceof Element
      ? [...contentRoot.querySelectorAll('img,picture,video,iframe,svg')].filter((element) => {
          if (!visible(element)) return false;
          const value = element.getBoundingClientRect();
          return value.width >= 80 && value.height >= 50;
        })
      : [];
    const actions = contentRoot instanceof Element
      ? [...contentRoot.querySelectorAll('a[href],button,[role="button"]')].filter((element) => {
          if (!visible(element)) return false;
          const label = normalizeText(element.getAttribute('aria-label') || element.textContent || element.getAttribute('title'));
          if (!label) return false;
          if (element.matches('a')) {
            const raw = String(element.getAttribute('href') || '').trim();
            if (!raw || raw === '#' || /^javascript:/i.test(raw)) return false;
          }
          return true;
        })
      : [];
    let bandCandidates = contentRoot instanceof Element
      ? [...contentRoot.querySelectorAll('section,[role="region"]')].filter((element) => {
          if (!visible(element)) return false;
          const value = element.getBoundingClientRect();
          return value.height >= 80 && value.width >= Math.max(200, innerWidth * 0.35);
        })
      : [];
    bandCandidates = bandCandidates.filter((element) =>
      !bandCandidates.some((candidate) => candidate !== element && candidate.contains(element))
    );
    if (bandCandidates.length < 2 && contentRoot instanceof Element) {
      bandCandidates = [...contentRoot.children].filter((element) => {
        if (!visible(element) || ['SCRIPT', 'STYLE', 'LINK'].includes(element.tagName)) return false;
        const value = element.getBoundingClientRect();
        return value.height >= 80 && value.width >= Math.max(200, innerWidth * 0.35);
      });
    }
    const layoutBands = bandCandidates.slice(0, 64).map((element) => {
      const value = element.getBoundingClientRect();
      const heading = element.matches('h1,h2,h3') ? element : element.querySelector('h1,h2,h3');
      return {
        heading: normalizeText(heading?.textContent),
        top: Math.round(value.top + scrollY),
        height: Math.round(value.height)
      };
    });
    const navigationEntry = performance.getEntriesByType('navigation')?.[0];
    const responseStatus = Number(navigationEntry?.responseStatus || 0);
    const pageText = normalizeText(document.body?.innerText, 5000).toLowerCase();
    const pageTitle = normalizeText(document.title).toLowerCase();
    const challengePresent = Boolean(document.querySelector(
      'iframe[src*="captcha" i],iframe[src*="challenges.cloudflare" i],#cf-challenge-running,.cf-challenge,[id*="captcha" i],input[name*="captcha" i]'
    ));
    const challengeTitle = /just a moment|attention required|access denied|security check|verify (?:you are|that you are) human/.test(pageTitle);
    const challengeCopy = /cloudflare ray id|checking your browser|enable javascript and cookies to continue|complete the captcha|verify (?:you are|that you are) human/.test(pageText);
    const sparseChallengeSurface = headingOrder.length <= 2 && layoutBands.length <= 2 && actions.length <= 3;
    const reasonCodes = [];
    if ([401, 403, 429].includes(responseStatus)) reasonCodes.push(`http-status-${responseStatus}`);
    if (sparseChallengeSurface && challengeTitle) reasonCodes.push('challenge-title');
    if (sparseChallengeSurface && challengeCopy) reasonCodes.push('challenge-copy');
    if (sparseChallengeSurface && challengePresent && (challengeTitle || challengeCopy)) reasonCodes.push('challenge-element');
    return {
      title: document.title,
      finalUrl: location.href,
      maskViolations: [...new Set(maskViolations)].sort(),
      maskedRegionCount: topLevelMasked.length,
      roles: {
        brand: { ...roleSignal(brand), identity: brandIdentity },
        footer: roleSignal(footer),
        header: roleSignal(header),
        main: roleSignal(main),
        navigation: roleSignal(navigation)
      },
      meaningfulHrefs: links,
      placeholderHrefs: placeholders,
      mobileMenu,
      protection: {
        detected: reasonCodes.length > 0,
        responseStatus,
        reasonCodes: [...new Set(reasonCodes)].sort()
      },
      structure: {
        headingCount: headingOrder.length,
        headingOrder,
        layoutBandCount: layoutBands.length,
        layoutBands,
        mediaCount: media.length,
        actionCount: actions.length
      },
      layout: {
        viewportWidth: innerWidth,
        viewportHeight: innerHeight,
        documentHeight: Math.round(documentHeight),
        normalizedPageHeight: Math.round(Math.max(innerHeight, documentHeight - maskedHeight)),
        mainBox: box(main),
        headerBox: box(header),
        footerBox: box(footer)
      }
    };
  };
  return `(${source})(${JSON.stringify({
    dynamicRegionSelectors: contract.dynamicRegionSelectors,
    mobileViewport: mobile
  })})`;
}

function sameHttpDocument(left, right) {
  try {
    const leftUrl = new URL(left);
    const rightUrl = new URL(right);
    return leftUrl.origin === rightUrl.origin &&
      leftUrl.pathname === rightUrl.pathname &&
      leftUrl.search === rightUrl.search;
  } catch {
    return false;
  }
}

function verifierAxeSummary(report) {
  const wcagViolations = (Array.isArray(report?.violations) ? report.violations : []).filter((violation) =>
    (Array.isArray(violation?.tags) ? violation.tags : []).some((tag) => AXE_WCAG_TAG_RE.test(String(tag))) &&
    Array.isArray(violation?.nodes) && violation.nodes.length > 0
  );
  return {
    passRuleCount: Array.isArray(report?.passes) ? report.passes.length : 0,
    incompleteRuleCount: Array.isArray(report?.incomplete) ? report.incomplete.length : 0,
    inapplicableRuleCount: Array.isArray(report?.inapplicable) ? report.inapplicable.length : 0,
    violationRuleCount: wcagViolations.length,
    violationNodeCount: wcagViolations.reduce((count, violation) => count + violation.nodes.length, 0),
    violationRuleIds: wcagViolations.map((violation) => String(violation?.id ?? 'unknown-rule')).sort()
  };
}

function rawVerifierAxeRecord(report, finalUrl) {
  const errors = [];
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    errors.push('axe-core returned no structured result.');
  } else {
    if (String(report?.testEngine?.name ?? '').toLowerCase() !== 'axe-core' ||
        String(report?.testEngine?.version ?? '') !== VERIFIER_AXE_VERSION) {
      errors.push(`axe-core result did not report the pinned ${VERIFIER_AXE_VERSION} engine.`);
    }
    if (!sameHttpDocument(report?.url, finalUrl)) {
      errors.push('axe-core result URL does not match the browser route that was inspected.');
    }
    if (!Number.isFinite(Date.parse(String(report?.timestamp ?? '')))) {
      errors.push('axe-core result does not contain a valid execution timestamp.');
    }
    for (const resultType of ['passes', 'incomplete', 'inapplicable', 'violations']) {
      if (!Array.isArray(report?.[resultType])) {
        errors.push(`axe-core result is missing its ${resultType} array.`);
      }
    }
  }
  return {
    schemaVersion: VERIFIER_AXE_SCHEMA,
    status: errors.length === 0 ? 'executed' : 'failed',
    source: {
      version: VERIFIER_AXE_VERSION,
      sha256: VERIFIER_AXE_SOURCE_SHA256
    },
    ruleScope: {
      type: 'tag',
      values: [...VERIFIER_AXE_TAGS]
    },
    report,
    summary: verifierAxeSummary(report),
    errors
  };
}

function verifierAxeExpression() {
  return `(async () => {
    if (!globalThis.axe || typeof globalThis.axe.run !== 'function') {
      throw new Error('Pinned axe-core source was not installed in the page.');
    }
    return globalThis.axe.run(document, {
      runOnly: { type: 'tag', values: ${JSON.stringify(VERIFIER_AXE_TAGS)} },
      resultTypes: ['passes', 'incomplete', 'inapplicable', 'violations']
    });
  })()`;
}

async function preflightVerifierAxe(cdp, sessionId) {
  const installed = await cdp.send('Runtime.evaluate', {
    expression: `${VERIFIER_AXE_SOURCE}\n//# sourceURL=agent-ready-axe-core-${VERIFIER_AXE_VERSION}-preflight.js\n;globalThis.axe?.version`,
    returnByValue: true
  }, sessionId);
  if (installed.exceptionDetails || installed.result?.value !== VERIFIER_AXE_VERSION) {
    throw new Error(`Pinned axe-core ${VERIFIER_AXE_VERSION} could not be installed during browser runtime preflight.`);
  }
  const evaluated = await cdp.send('Runtime.evaluate', {
    expression: verifierAxeExpression(),
    awaitPromise: true,
    returnByValue: true
  }, sessionId);
  const report = evaluated.result?.value;
  if (
    evaluated.exceptionDetails ||
    String(report?.testEngine?.name ?? '').toLowerCase() !== 'axe-core' ||
    String(report?.testEngine?.version ?? '') !== VERIFIER_AXE_VERSION ||
    !['passes', 'incomplete', 'inapplicable', 'violations'].every((key) => Array.isArray(report?.[key]))
  ) {
    throw new Error(`Pinned axe-core ${VERIFIER_AXE_VERSION} did not execute during browser runtime preflight.`);
  }
}

async function captureRoute(cdp, sessionId, baseUrl, path, viewport, contract) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: viewport.width,
    height: viewport.height,
    deviceScaleFactor: 1,
    mobile: viewport.mobile,
    screenWidth: viewport.width,
    screenHeight: viewport.height
  }, sessionId);
  await cdp.send(
    'Emulation.setTouchEmulationEnabled',
    viewport.mobile ? { enabled: true, maxTouchPoints: 5 } : { enabled: false },
    sessionId
  );
  const url = new URL(path.replace(/^\//, ''), new URL('/', baseUrl)).href;
  const loaded = cdp.waitFor('Page.loadEventFired', sessionId);
  const navigation = await cdp.send('Page.navigate', { url }, sessionId).catch((error) => {
    void loaded.catch(() => {});
    throw error;
  });
  if (navigation.errorText) throw new Error(`${path} navigation failed: ${navigation.errorText}`);
  await loaded;
  await cdp.send('Runtime.evaluate', {
    expression: 'document.fonts && document.fonts.ready ? document.fonts.ready.then(() => true) : true',
    awaitPromise: true,
    returnByValue: true
  }, sessionId);
  const axeEvaluation = await cdp.send('Runtime.evaluate', {
    expression: verifierAxeExpression(),
    awaitPromise: true,
    returnByValue: true
  }, sessionId);
  if (axeEvaluation.exceptionDetails || !axeEvaluation.result?.value) {
    throw new Error(`${path} ${viewport.name} verifier-owned axe-core execution failed.`);
  }
  const evaluated = await cdp.send('Runtime.evaluate', {
    expression: collectorExpression(contract, viewport.mobile),
    awaitPromise: true,
    returnByValue: true
  }, sessionId);
  if (evaluated.exceptionDetails || !evaluated.result?.value) {
    throw new Error(`${path} ${viewport.name} signal collection failed.`);
  }
  const signals = evaluated.result.value;
  const axe = rawVerifierAxeRecord(axeEvaluation.result.value, signals.finalUrl);
  if (axe.status !== 'executed') {
    throw new Error(`${path} ${viewport.name} verifier-owned axe-core result failed validation: ${axe.errors.join(' ')}`);
  }
  const metrics = await cdp.send('Page.getLayoutMetrics', {}, sessionId);
  const content = metrics.cssContentSize || metrics.contentSize || { width: viewport.width, height: viewport.height };
  const screenshotWidth = Math.max(viewport.width, Math.min(4000, Math.ceil(content.width || viewport.width)));
  const screenshotHeight = Math.max(viewport.height, Math.min(12_000, Math.ceil(content.height || viewport.height)));
  const screenshot = await cdp.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: true,
    fromSurface: true,
    clip: { x: 0, y: 0, width: screenshotWidth, height: screenshotHeight, scale: 1 }
  }, sessionId);
  return {
    path,
    viewport: { name: viewport.name, width: viewport.width, height: viewport.height },
    axe,
    signals,
    screenshot: {
      base64: screenshot.data,
      width: screenshotWidth,
      height: screenshotHeight,
      clipped: Math.ceil(content.height || viewport.height) > screenshotHeight
    }
  };
}

export async function captureGlobalChrome({
  baseUrl,
  primaryRoutes,
  contract = {},
  environment = process.env,
  browserExecutable,
  browserBackend,
  gridUrl = DEFAULT_SELENIUM_GRID_URL,
  fetchImpl = globalThis.fetch,
  webSocketConnector = connectWebSocket,
  limits = {},
  now = Date.now,
  profileCleanup = cleanupBrowserProfile
} = {}) {
  const normalizedContract = normalizeGlobalChromeContract(contract);
  const checkedAt = new Date().toISOString();
  const routeInputs = Array.isArray(primaryRoutes) ? primaryRoutes : [];
  const budget = createBrowserCaptureBudget({
    label: 'Global chrome capture',
    limits,
    now,
    routeCount: routeInputs.length,
    viewportCount: VIEWPORTS.length
  });
  const base = new URL(baseUrl);
  let selectedBackend;
  try { selectedBackend = browserBackendKind(browserBackend, browserExecutable, environment); }
  catch (error) {
    return {
      schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
      checkedAt,
      status: 'blocked',
      authoritative: false,
      captureMode: 'verifier-owned-browser',
      targetOrigin: base.origin,
      contract: normalizedContract,
      browser: { executable: '', product: '' },
      runtime: browserRuntimeEvidence({ backend: 'local' }),
      primaryRoutes: [],
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  const browserLabel = selectedBackend === 'remote'
    ? ''
    : basename(String(browserExecutable === undefined ? findBrowserExecutable(environment) : browserExecutable));
  const runtimeEvidence = (overrides = {}) => browserRuntimeEvidence({
    backend: selectedBackend,
    executable: browserLabel,
    ...overrides
  });
  let routes = [];
  try {
    budget.assertRouteLimit();
    budget.assertWithinDeadline();
    routes = [...new Set(routeInputs.map((route) => normalizeRoute(route?.targetPath ?? route)))].sort();
  } catch (error) {
    return {
      schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
      checkedAt,
      status: 'blocked',
      authoritative: false,
      captureMode: 'verifier-owned-browser',
      targetOrigin: base.origin,
      contract: normalizedContract,
      browser: { executable: '', product: '' },
      runtime: runtimeEvidence(),
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  if (routes.length === 0) {
    return {
      schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
      checkedAt,
      status: 'blocked',
      authoritative: false,
      captureMode: 'verifier-owned-browser',
      targetOrigin: base.origin,
      contract: normalizedContract,
      browser: { executable: browserLabel, product: '' },
      runtime: runtimeEvidence(),
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: ['No primary routes were available for global chrome capture.']
    };
  }
  try {
    budget.assertWithinDeadline();
  } catch (error) {
    return {
      schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
      checkedAt,
      status: 'blocked',
      authoritative: false,
      captureMode: 'verifier-owned-browser',
      targetOrigin: base.origin,
      contract: normalizedContract,
      browser: { executable: browserLabel, product: '' },
      runtime: runtimeEvidence(),
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  let backend;
  try {
    backend = await openCaptureBrowserBackend({
      browserBackend: selectedBackend,
      browserExecutable,
      budget,
      environment,
      fetchImpl,
      gridUrl,
      hideScrollbars: true,
      profileCleanup,
      profilePrefix: 'agent-ready-chrome',
      webSocketConnector
    });
  } catch (error) {
    return {
      schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
      checkedAt,
      status: 'unavailable',
      authoritative: false,
      captureMode: 'verifier-owned-browser',
      targetOrigin: base.origin,
      contract: normalizedContract,
      browser: { executable: browserLabel, product: '' },
      runtime: runtimeEvidence(),
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics({ attempted: true }),
      warnings: [],
      errors: [error.message]
    };
  }
  const cdp = backend.cdp;
  const captured = [];
  const errors = [];
  const warnings = [];
  let product = '';
  let protocolVersion = '';
  let executable = browserLabel;
  let runtimeReady = false;
  let browserContextId = '';
  let targetId = '';
  try {
    const version = await cdp.send('Browser.getVersion');
    product = String(version.product ?? '');
    protocolVersion = String(version.protocolVersion ?? '');
    if (selectedBackend === 'remote') {
      executable = await observedBrowserExecutable(cdp, selectedBackend, product);
    }
    ({ browserContextId } = await cdp.send('Target.createBrowserContext', { disposeOnDetach: true }));
    ({ targetId } = await cdp.send('Target.createTarget', { url: 'about:blank', browserContextId }));
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Network.enable', {}, sessionId);
    await cdp.send('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `${VERIFIER_AXE_SOURCE}\n//# sourceURL=agent-ready-axe-core-${VERIFIER_AXE_VERSION}.js`
    }, sessionId);
    await preflightVerifierAxe(cdp, sessionId);
    runtimeReady = true;
    captureLoop:
    for (const path of routes) {
      for (const viewport of VIEWPORTS) {
        try {
          budget.assertWithinDeadline();
          const capture = await captureRoute(cdp, sessionId, base, path, viewport, normalizedContract);
          captured.push(capture);
          for (const violation of capture.signals.maskViolations ?? []) errors.push(`${path} ${viewport.name}: ${violation}`);
        } catch (error) {
          errors.push(`${path} ${viewport.name}: ${error.message}`);
          if (budget.hasExceededDeadline()) break captureLoop;
        }
      }
    }
  } catch (error) {
    errors.push(error.message);
  } finally {
    if (targetId) {
      try { await cdp.sendForCleanup('Target.closeTarget', { targetId }); }
      catch (error) { warnings.push(`Browser target cleanup failed: ${error.message}`); }
    }
    if (browserContextId) {
      try { await cdp.sendForCleanup('Target.disposeBrowserContext', { browserContextId }); }
      catch (error) { warnings.push(`Browser context cleanup failed: ${error.message}`); }
    }
    const closed = await backend.close();
    runtimeReady = runtimeReady && closed.errors.length === 0;
    errors.push(...closed.errors);
    warnings.push(...closed.warnings);
  }
  const diagnostics = backend.diagnostics?.() ?? '';
  if (captured.length !== routes.length * VIEWPORTS.length && diagnostics) {
    errors.push(`Browser diagnostics: ${diagnostics}`);
  }
  return {
    schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
    checkedAt,
    status: errors.length === 0 ? 'captured' : 'blocked',
    authoritative: errors.length === 0,
    captureMode: 'verifier-owned-browser',
    targetOrigin: base.origin,
    contract: normalizedContract,
    browser: { executable: executable || backend.executable, product },
    runtime: runtimeEvidence({
      executable: executable || backend.executable,
      product,
      protocolVersion,
      ready: runtimeReady
    }),
    primaryRoutes: routes,
    routes: captured,
    budget: budget.metrics({ attempted: true, capturedCount: captured.length }),
    warnings,
    errors
  };
}

function screenshotSha256(route) {
  const declared = String(route?.screenshot?.sha256 ?? '').trim();
  if (HASH_RE.test(declared)) return declared;
  const encoded = String(route?.screenshot?.base64 ?? '');
  if (!encoded) return '';
  try {
    return sha256(Buffer.from(encoded, 'base64'));
  } catch {
    return '';
  }
}

function normalizedHeading(value) {
  return String(value ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function headingSimilarity(left, right) {
  const leftWords = new Set(normalizedHeading(left).split(/\s+/).filter(Boolean));
  const rightWords = new Set(normalizedHeading(right).split(/\s+/).filter(Boolean));
  if (leftWords.size === 0 || rightWords.size === 0) return false;
  let intersection = 0;
  for (const word of leftWords) if (rightWords.has(word)) intersection += 1;
  return intersection / Math.min(leftWords.size, rightWords.size) >= 0.6;
}

function orderedHeadingMatchCount(sourceOrder, targetOrder) {
  const source = Array.isArray(sourceOrder) ? sourceOrder : [];
  const target = Array.isArray(targetOrder) ? targetOrder : [];
  let targetIndex = 0;
  let matches = 0;
  for (const sourceHeading of source) {
    while (targetIndex < target.length && !headingSimilarity(sourceHeading, target[targetIndex])) targetIndex += 1;
    if (targetIndex < target.length) {
      matches += 1;
      targetIndex += 1;
    }
  }
  return matches;
}

function visualStructureSummary(signals) {
  const structure = signals?.structure ?? {};
  const nonNegative = (value) => {
    const number = Number(value ?? 0);
    return Number.isFinite(number) ? Math.max(0, number) : 0;
  };
  return {
    headingCount: nonNegative(structure.headingCount),
    headingOrder: (Array.isArray(structure.headingOrder) ? structure.headingOrder : [])
      .map((heading) => String(heading).replace(/\s+/g, ' ').trim().slice(0, 160))
      .filter(Boolean)
      .slice(0, 64),
    layoutBandCount: nonNegative(structure.layoutBandCount),
    mediaCount: nonNegative(structure.mediaCount),
    actionCount: nonNegative(structure.actionCount),
    normalizedPageHeight: nonNegative(signals?.layout?.normalizedPageHeight)
  };
}

function composedSourceRoute(routeRole, structure) {
  if (!['homepage', 'landing'].includes(String(routeRole ?? '').trim())) return false;
  return structure.layoutBandCount >= 3 ||
    structure.headingCount >= 3 ||
    (structure.headingCount >= 2 && (structure.mediaCount >= 1 || structure.actionCount >= 2)) ||
    (structure.mediaCount >= 3 && structure.actionCount >= 2) ||
    (structure.actionCount >= 4 && structure.normalizedPageHeight >= 1600);
}

function captureRouteIndex(capture) {
  return new Map((Array.isArray(capture?.routes) ? capture.routes : []).map((route) => [
    `${normalizeRoute(route?.path)}\0${String(route?.viewport?.name ?? '')}`,
    route
  ]));
}

function visualFloorResult(value) {
  const record = { schemaVersion: VISUAL_PARITY_FLOOR_SCHEMA, ...value };
  return { ...record, fingerprint: sha256(record) };
}

export function compareVerifierOwnedVisualFloor({
  sourceCapture,
  targetCapture,
  primaryRoutes = [],
  stateFingerprint = ''
} = {}) {
  const checkedAt = String(targetCapture?.checkedAt || sourceCapture?.checkedAt || new Date().toISOString());
  const base = {
    checkedAt,
    authority: 'verifier-owned-managed-browser-structural-floor',
    verifierOwned: true,
    completionSupported: false,
    sourceOrigin: String(sourceCapture?.targetOrigin ?? ''),
    targetOrigin: String(targetCapture?.targetOrigin ?? ''),
    resultStateFingerprint: String(stateFingerprint || targetCapture?.resultStateFingerprint || ''),
    sourceCaptureFingerprint: String(sourceCapture?.captureFingerprint ?? ''),
    targetCaptureFingerprint: String(targetCapture?.captureFingerprint ?? ''),
    thresholds: VISUAL_FLOOR_THRESHOLDS,
    findings: [],
    errors: []
  };
  const captureErrors = [];
  if (sourceCapture?.status !== 'captured' || sourceCapture?.authoritative !== true) {
    captureErrors.push(`Source managed-browser capture is unavailable: ${(sourceCapture?.errors ?? []).join(' ') || sourceCapture?.status || 'missing'}.`);
  }
  if (targetCapture?.status !== 'captured' || targetCapture?.authoritative !== true) {
    captureErrors.push(`Target managed-browser capture is unavailable: ${(targetCapture?.errors ?? []).join(' ') || targetCapture?.status || 'missing'}.`);
  }
  if (!base.sourceOrigin || !base.targetOrigin || base.sourceOrigin === base.targetOrigin) {
    captureErrors.push('Verifier-owned visual comparison requires distinct source and target origins.');
  }
  if (!HASH_RE.test(base.sourceCaptureFingerprint) || !HASH_RE.test(base.targetCaptureFingerprint)) {
    captureErrors.push('Verifier-owned visual comparison requires fingerprint-bound source and target captures.');
  }
  if (
    base.resultStateFingerprint &&
    (
      sourceCapture?.resultStateFingerprint !== base.resultStateFingerprint ||
      targetCapture?.resultStateFingerprint !== base.resultStateFingerprint
    )
  ) {
    captureErrors.push('Verifier-owned visual comparison captures do not match the exact result-state fingerprint.');
  }
  if (captureErrors.length > 0) {
    return visualFloorResult({ ...base, status: 'blocked', errors: captureErrors });
  }

  const sourceIndex = captureRouteIndex(sourceCapture);
  const targetIndex = captureRouteIndex(targetCapture);
  const findings = [];
  const errors = [];
  let protectedFindingCount = 0;
  for (const route of Array.isArray(primaryRoutes) ? primaryRoutes : []) {
    const sourcePath = normalizeRoute(route?.sourcePath ?? route?.targetPath ?? route);
    const targetPath = normalizeRoute(route?.targetPath ?? route?.sourcePath ?? route);
    for (const viewport of VIEWPORTS) {
      const source = sourceIndex.get(`${sourcePath}\0${viewport.name}`);
      const target = targetIndex.get(`${targetPath}\0${viewport.name}`);
      const routeErrors = [];
      const deficits = [];
      const decisiveDeficits = [];
      const sourceStructure = visualStructureSummary(source?.signals);
      const targetStructure = visualStructureSummary(target?.signals);
      const composedSource = composedSourceRoute(route?.routeRole, sourceStructure);
      const sourceProtection = source?.signals?.protection ?? {};
      const protectedSource = sourceProtection.detected === true;
      if (!source || !target) {
        routeErrors.push(`missing ${!source ? 'source' : 'target'} managed-browser capture`);
      } else {
        const sameViewport = source.viewport?.width === target.viewport?.width &&
          source.viewport?.height === target.viewport?.height &&
          source.viewport?.width === viewport.width &&
          source.viewport?.height === viewport.height;
        if (!sameViewport) routeErrors.push('source and target were not captured at the identical required viewport');
        try {
          if (new URL(target.signals?.finalUrl ?? 'about:blank').origin !== base.targetOrigin) {
            routeErrors.push('target capture left the inspected target origin');
          }
          if (!protectedSource && new URL(source.signals?.finalUrl ?? 'about:blank').origin !== base.sourceOrigin) {
            routeErrors.push('source capture left the declared source origin');
          }
        } catch {
          routeErrors.push('source or target capture lacks a valid final URL identity');
        }
        const sourceHash = screenshotSha256(source);
        const targetHash = screenshotSha256(target);
        if (!HASH_RE.test(sourceHash) || !HASH_RE.test(targetHash)) {
          routeErrors.push('source or target screenshot lacks a computed sha256 identity');
        } else if (sourceHash === targetHash) {
          routeErrors.push('source and target must use distinct source and target screenshot identities');
        }
        if (!protectedSource) {
          for (const role of ['header', 'navigation', 'main', 'footer']) {
            if (source.signals?.roles?.[role]?.visible === true && target.signals?.roles?.[role]?.visible !== true) {
              routeErrors.push(`${role} landmark visible on the source is missing from the target`);
            }
          }
          if (
            viewport.mobile &&
            source.signals?.mobileMenu?.triggerVisible === true &&
            source.signals?.mobileMenu?.activationWorks === true &&
            (
              target.signals?.mobileMenu?.triggerVisible !== true ||
              target.signals?.mobileMenu?.activationWorks !== true
            )
          ) {
            routeErrors.push('working source mobile navigation is missing or inert on the target');
          }
          if (composedSource) {
            if (
              sourceStructure.headingCount >= 3 &&
              targetStructure.headingCount < Math.ceil(sourceStructure.headingCount * VISUAL_FLOOR_THRESHOLDS.minimumHeadingRatio)
            ) {
              deficits.push(`headings ${targetStructure.headingCount}/${sourceStructure.headingCount}`);
              if (sourceStructure.headingCount >= 4 && targetStructure.headingCount === 0) decisiveDeficits.push('all material headings omitted');
            }
            if (
              sourceStructure.layoutBandCount >= 3 &&
              targetStructure.layoutBandCount < Math.ceil(sourceStructure.layoutBandCount * VISUAL_FLOOR_THRESHOLDS.minimumLayoutBandRatio)
            ) {
              deficits.push(`layout bands ${targetStructure.layoutBandCount}/${sourceStructure.layoutBandCount}`);
              if (sourceStructure.layoutBandCount >= 4 && targetStructure.layoutBandCount === 0) decisiveDeficits.push('all material layout bands omitted');
            }
            if (
              sourceStructure.mediaCount >= 2 &&
              targetStructure.mediaCount < Math.ceil(sourceStructure.mediaCount * VISUAL_FLOOR_THRESHOLDS.minimumMediaRatio)
            ) {
              deficits.push(`media ${targetStructure.mediaCount}/${sourceStructure.mediaCount}`);
              if (sourceStructure.mediaCount >= 3 && targetStructure.mediaCount === 0) decisiveDeficits.push('all material media omitted');
            }
            if (
              sourceStructure.actionCount >= 2 &&
              targetStructure.actionCount < Math.ceil(sourceStructure.actionCount * VISUAL_FLOOR_THRESHOLDS.minimumActionRatio)
            ) {
              deficits.push(`actions ${targetStructure.actionCount}/${sourceStructure.actionCount}`);
              if (sourceStructure.actionCount >= 4 && targetStructure.actionCount === 0) decisiveDeficits.push('all material actions omitted');
            }
            if (sourceStructure.headingOrder.length >= 3) {
              const orderedMatches = orderedHeadingMatchCount(sourceStructure.headingOrder, targetStructure.headingOrder);
              if (orderedMatches < Math.ceil(sourceStructure.headingOrder.length * VISUAL_FLOOR_THRESHOLDS.minimumHeadingOrderRatio)) {
                deficits.push(`heading/section order ${orderedMatches}/${sourceStructure.headingOrder.length}`);
              }
            }
            const heightRatio = sourceStructure.normalizedPageHeight > 0
              ? targetStructure.normalizedPageHeight / sourceStructure.normalizedPageHeight
              : 1;
            if (!Number.isFinite(heightRatio) || heightRatio < VISUAL_FLOOR_THRESHOLDS.minimumPageHeightRatio) {
              deficits.push(`page-height ratio ${Number.isFinite(heightRatio) ? heightRatio.toFixed(3) : 'invalid'}`);
              if (!Number.isFinite(heightRatio) || heightRatio < 0.25) decisiveDeficits.push('target page collapsed below one quarter of source height');
            }
            if (decisiveDeficits.length > 0 || deficits.length >= 2) {
              routeErrors.push(`gross structural omissions detected: ${deficits.join('; ')}`);
            }
          }
        }
      }
      if (protectedSource) protectedFindingCount += 1;
      const finding = {
        sourcePath,
        targetPath,
        routeRole: String(route?.routeRole ?? ''),
        viewport: { name: viewport.name, width: viewport.width, height: viewport.height },
        composedSource,
        protectedSource,
        protectionReasonCodes: Array.isArray(sourceProtection.reasonCodes) ? sourceProtection.reasonCodes : [],
        sourceScreenshotSha256: screenshotSha256(source),
        targetScreenshotSha256: screenshotSha256(target),
        imageIdentityDistinct: Boolean(
          HASH_RE.test(screenshotSha256(source)) &&
          HASH_RE.test(screenshotSha256(target)) &&
          screenshotSha256(source) !== screenshotSha256(target)
        ),
        sourceStructure,
        targetStructure,
        deficits,
        decisiveDeficits,
        passed: routeErrors.length === 0 && !protectedSource,
        errors: routeErrors
      };
      findings.push(finding);
      errors.push(...routeErrors.map((message) => `${targetPath} ${viewport.name}: ${message}.`));
    }
  }
  if (findings.length !== primaryRoutes.length * VIEWPORTS.length) {
    errors.push('Visual floor did not cover every primary route at desktop and mobile viewports.');
  }
  const status = errors.length > 0 ? 'failed' : protectedFindingCount > 0 ? 'review_required' : 'passed';
  return visualFloorResult({
    ...base,
    status,
    completionSupported: status === 'passed',
    protectedFindingCount,
    reviewFallbackEligible: status === 'review_required' && protectedFindingCount > 0,
    findings,
    errors: status === 'review_required'
      ? ['Source protection prevented verifier-owned structural comparison; a fresh handoff reviewer must adjudicate the exact bound builder captures.']
      : errors
  });
}

function networkRequestValue(params) {
  const url = String(params?.request?.url ?? '').trim();
  if (!url) return null;
  return {
    method: String(params?.request?.method ?? 'GET').trim().toUpperCase(),
    resourceType: String(params?.type ?? 'Other').trim() || 'Other',
    url: url.slice(0, 4096)
  };
}

async function waitWithinBrowserCaptureBudget(budget, durationMs) {
  const timing = budget.operationTiming();
  if (timing.deadlineLimited && timing.timeoutMs <= durationMs) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, timing.timeoutMs));
    throw budget.deadlineError();
  }
  await new Promise((resolvePromise) => setTimeout(resolvePromise, durationMs));
  budget.assertWithinDeadline();
}

async function captureBeforeConsentRoute(cdp, baseUrl, path, budget) {
  let browserContextId = '';
  let targetId = '';
  const unsubscribers = [];
  try {
    ({ browserContextId } = await cdp.send('Target.createBrowserContext', { disposeOnDetach: true }));
    ({ targetId } = await cdp.send('Target.createTarget', { url: 'about:blank', browserContextId }));
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Network.enable', {}, sessionId);
    await cdp.send('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
    await cdp.send('Network.clearBrowserCookies', {}, sessionId);
    const requests = [];
    const inFlight = new Set();
    let requestCount = 0;
    unsubscribers.push(cdp.subscribe('Network.requestWillBeSent', sessionId, (params) => {
      requestCount += 1;
      if (params?.requestId) inFlight.add(params.requestId);
      if (requests.length >= 2000) return;
      const value = networkRequestValue(params);
      if (value) requests.push(value);
    }));
    unsubscribers.push(cdp.subscribe('Network.loadingFinished', sessionId, (params) => {
      if (params?.requestId) inFlight.delete(params.requestId);
    }));
    unsubscribers.push(cdp.subscribe('Network.loadingFailed', sessionId, (params) => {
      if (params?.requestId) inFlight.delete(params.requestId);
    }));
    const requestedUrl = new URL(path.replace(/^\//, ''), new URL('/', baseUrl)).href;
    const loaded = cdp.waitFor('Page.loadEventFired', sessionId);
    const navigation = await cdp.send('Page.navigate', { url: requestedUrl }, sessionId);
    if (navigation.errorText) throw new Error(`${path} navigation failed: ${navigation.errorText}`);
    await loaded;
    // Observe long enough to catch common delayed embed bootstraps, then require
    // a bounded quiet period. A route that never settles fails closed rather
    // than turning a truncated transcript into proof of absence.
    const observationStarted = Date.now();
    const observationFloorMs = 2000;
    const networkQuietMs = 500;
    const maximumObservationMs = 8000;
    await waitWithinBrowserCaptureBudget(budget, observationFloorMs);
    let quietSince = inFlight.size === 0 ? Date.now() : 0;
    while (Date.now() - observationStarted < maximumObservationMs) {
      budget.assertWithinDeadline();
      if (inFlight.size === 0) {
        if (!quietSince) quietSince = Date.now();
        if (Date.now() - quietSince >= networkQuietMs) break;
      } else {
        quietSince = 0;
      }
      await waitWithinBrowserCaptureBudget(budget, 100);
    }
    if (!quietSince || Date.now() - quietSince < networkQuietMs || inFlight.size > 0) {
      throw new Error(`${path} network did not settle within ${maximumObservationMs} ms; before-consent absence cannot be proven.`);
    }
    const location = await cdp.send('Runtime.evaluate', {
      expression: 'location.href',
      returnByValue: true
    }, sessionId);
    if (requestCount > 2000) {
      throw new Error(`${path} emitted more than 2000 network requests before consent; capture is bounded and cannot be authoritative.`);
    }
    const unique = [...new Map(requests.map((request) => [
      `${request.method}\0${request.resourceType}\0${request.url}`,
      request
    ])).values()].sort((left, right) =>
      `${left.url}\0${left.resourceType}\0${left.method}`.localeCompare(`${right.url}\0${right.resourceType}\0${right.method}`)
    );
    return {
      path,
      requestedUrl,
      finalUrl: String(location?.result?.value ?? requestedUrl),
      isolation: {
        browserContextFresh: true,
        cacheDisabled: true,
        consentInteractionPerformed: false,
        method: 'new-incognito-browser-context',
        storageCleared: true
      },
      observation: {
        floorMs: observationFloorMs,
        maximumMs: maximumObservationMs,
        networkQuietMs,
        settled: true
      },
      requests: unique
    };
  } finally {
    for (const unsubscribe of unsubscribers) unsubscribe();
    if (targetId) {
      try { await cdp.sendForCleanup('Target.closeTarget', { targetId }); } catch {}
    }
    if (browserContextId) {
      try { await cdp.sendForCleanup('Target.disposeBrowserContext', { browserContextId }); } catch {}
    }
  }
}

export async function captureBeforeConsentNetwork({
  baseUrl,
  primaryRoutes,
  environment = process.env,
  browserExecutable,
  browserBackend,
  gridUrl = DEFAULT_SELENIUM_GRID_URL,
  fetchImpl = globalThis.fetch,
  webSocketConnector = connectWebSocket,
  limits = {},
  now = Date.now,
  profileCleanup = cleanupBrowserProfile
} = {}) {
  const checkedAt = new Date().toISOString();
  const base = new URL(baseUrl);
  const routeInputs = Array.isArray(primaryRoutes) ? primaryRoutes : [];
  const budget = createBrowserCaptureBudget({
    label: 'Before-consent network capture',
    limits,
    now,
    routeCount: routeInputs.length,
    viewportCount: 1
  });
  let selectedBackend;
  try { selectedBackend = browserBackendKind(browserBackend, browserExecutable, environment); }
  catch (error) {
    return {
      schemaVersion: BEFORE_CONSENT_NETWORK_SCHEMA,
      checkedAt,
      status: 'blocked',
      authoritative: false,
      captureMode: 'verifier-owned-cdp-network',
      targetOrigin: base.origin,
      browser: { executable: '', product: '' },
      runtime: browserRuntimeEvidence({ backend: 'local' }),
      primaryRoutes: [],
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  const browserLabel = selectedBackend === 'remote'
    ? ''
    : basename(String(browserExecutable === undefined ? findBrowserExecutable(environment) : browserExecutable));
  const runtimeEvidence = (overrides = {}) => browserRuntimeEvidence({
    backend: selectedBackend,
    executable: browserLabel,
    ...overrides
  });
  let routes = [];
  try {
    budget.assertRouteLimit();
    budget.assertWithinDeadline();
    routes = [...new Set(routeInputs.map((route) => normalizeRoute(route?.targetPath ?? route)))].sort();
  } catch (error) {
    return {
      schemaVersion: BEFORE_CONSENT_NETWORK_SCHEMA,
      checkedAt,
      status: 'blocked',
      authoritative: false,
      captureMode: 'verifier-owned-cdp-network',
      targetOrigin: base.origin,
      browser: { executable: '', product: '' },
      runtime: runtimeEvidence(),
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  const unavailable = (message, status = 'unavailable', attempted = false) => ({
    schemaVersion: BEFORE_CONSENT_NETWORK_SCHEMA,
    checkedAt,
    status,
    authoritative: false,
    captureMode: 'verifier-owned-cdp-network',
    targetOrigin: base.origin,
    browser: { executable: browserLabel, product: '' },
    runtime: runtimeEvidence(),
    primaryRoutes: routes,
    routes: [],
    budget: budget.metrics({ attempted }),
    warnings: [],
    errors: [message]
  });
  if (routes.length === 0) {
    return unavailable('No primary routes were available for before-consent network capture.', 'blocked');
  }
  try {
    budget.assertWithinDeadline();
  } catch (error) {
    return unavailable(error.message, 'blocked');
  }
  let backend;
  try {
    backend = await openCaptureBrowserBackend({
      browserBackend: selectedBackend,
      browserExecutable,
      budget,
      environment,
      fetchImpl,
      gridUrl,
      hideScrollbars: false,
      profileCleanup,
      profilePrefix: 'agent-ready-consent-chrome',
      webSocketConnector
    });
  } catch (error) {
    return unavailable(error.message, 'unavailable', true);
  }
  const cdp = backend.cdp;
  const captured = [];
  const errors = [];
  const warnings = [];
  let product = '';
  let protocolVersion = '';
  let executable = browserLabel;
  let cleanupSucceeded = true;
  try {
    const version = await cdp.send('Browser.getVersion');
    product = String(version.product ?? '');
    protocolVersion = String(version.protocolVersion ?? '');
    if (selectedBackend === 'remote') {
      executable = await observedBrowserExecutable(cdp, selectedBackend, product);
    }
    captureLoop:
    for (const path of routes) {
      try {
        budget.assertWithinDeadline();
        captured.push(await captureBeforeConsentRoute(cdp, base, path, budget));
      } catch (error) {
        errors.push(`${path}: ${error.message}`);
        if (budget.hasExceededDeadline()) break captureLoop;
      }
    }
    budget.assertWithinDeadline();
  } catch (error) {
    errors.push(error.message);
  } finally {
    const closed = await backend.close();
    cleanupSucceeded = closed.errors.length === 0;
    errors.push(...closed.errors);
    warnings.push(...closed.warnings);
  }
  const diagnostics = backend.diagnostics?.() ?? '';
  if (captured.length !== routes.length && diagnostics) {
    errors.push(`Browser diagnostics: ${diagnostics}`);
  }
  return {
    schemaVersion: BEFORE_CONSENT_NETWORK_SCHEMA,
    checkedAt,
    status: errors.length === 0 ? 'captured' : 'blocked',
    authoritative: errors.length === 0,
    captureMode: 'verifier-owned-cdp-network',
    targetOrigin: base.origin,
    browser: { executable: executable || backend.executable, product },
    runtime: runtimeEvidence({
      executable: executable || backend.executable,
      product,
      protocolVersion,
      ready: captured.length > 0 && cleanupSucceeded
    }),
    primaryRoutes: routes,
    routes: captured,
    budget: budget.metrics({ attempted: true, capturedCount: captured.length }),
    warnings,
    errors
  };
}

function beforeConsentCoverage(capture, targetOrigin = '') {
  const expectedRoutes = [...new Set((capture?.primaryRoutes ?? []).map(normalizeRoute))].sort();
  if (expectedRoutes.length === 0) throw new Error('Before-consent capture must identify every primary route.');
  const budget = capture?.budget;
  if (
    budget?.attempted !== true ||
    budget?.deadlineExceeded !== false ||
    budget?.routeCount !== expectedRoutes.length ||
    budget?.viewportCount !== 1 ||
    budget?.scheduledRouteViewportCount !== expectedRoutes.length ||
    budget?.capturedRouteViewportCount !== expectedRoutes.length ||
    !Number.isSafeInteger(budget?.deadlineMs) || budget.deadlineMs <= 0 || budget.deadlineMs > BROWSER_CAPTURE_LIMITS.deadlineMs ||
    !Number.isSafeInteger(budget?.maxRoutes) || budget.maxRoutes <= 0 || budget.maxRoutes > BROWSER_CAPTURE_LIMITS.maxRoutes ||
    !Number.isSafeInteger(budget?.operationTimeoutMs) || budget.operationTimeoutMs <= 0 ||
      budget.operationTimeoutMs > BROWSER_CAPTURE_LIMITS.operationTimeoutMs ||
    !Number.isSafeInteger(budget?.elapsedMs) || budget.elapsedMs < 0
  ) {
    throw new Error('Before-consent capture lacks valid verifier-owned route, deadline, and completion budget metrics.');
  }
  if (targetOrigin && capture?.targetOrigin !== targetOrigin) {
    throw new Error('Before-consent capture target origin does not match the inspected target.');
  }
  const observed = new Set();
  for (const route of capture?.routes ?? []) {
    const path = normalizeRoute(route?.path);
    if (observed.has(path)) throw new Error(`Before-consent capture duplicates ${path}.`);
    if (!expectedRoutes.includes(path)) throw new Error(`Before-consent capture contains unexpected route ${path}.`);
    observed.add(path);
    const requested = new URL(route?.requestedUrl ?? 'about:blank');
    if (requested.origin !== capture.targetOrigin || normalizeRoute(`${requested.pathname}${requested.search}`) !== path) {
      throw new Error(`Before-consent capture ${path} is not bound to the inspected target route.`);
    }
    if (
      route?.isolation?.browserContextFresh !== true ||
      route?.isolation?.storageCleared !== true ||
      route?.isolation?.cacheDisabled !== true ||
      route?.isolation?.consentInteractionPerformed !== false ||
      route?.isolation?.method !== 'new-incognito-browser-context'
    ) {
      throw new Error(`Before-consent capture ${path} did not use a fresh isolated browser context without consent interaction.`);
    }
    if (
      route?.observation?.settled !== true ||
      Number(route?.observation?.floorMs ?? 0) < 2000 ||
      Number(route?.observation?.networkQuietMs ?? 0) < 500
    ) {
      throw new Error(`Before-consent capture ${path} did not complete the bounded observation and network-idle contract.`);
    }
    const finalUrl = new URL(route?.finalUrl ?? 'about:blank');
    if (finalUrl.origin !== capture.targetOrigin) {
      throw new Error(`Before-consent capture ${path} left the inspected target origin.`);
    }
    if (!Array.isArray(route.requests)) throw new Error(`Before-consent capture ${path} has no request list.`);
  }
  const missing = expectedRoutes.filter((path) => !observed.has(path));
  if (missing.length) throw new Error(`Before-consent capture is incomplete; missing ${missing.join(', ')}.`);
  return true;
}

export function finalizeBeforeConsentNetworkCapture({ capture, stateFingerprint, targetOrigin = '' } = {}) {
  const state = String(stateFingerprint ?? '');
  if (!HASH_RE.test(state)) throw new Error('Before-consent capture requires the exact result-state fingerprint.');
  if (
    capture?.schemaVersion !== BEFORE_CONSENT_NETWORK_SCHEMA ||
    capture?.captureMode !== 'verifier-owned-cdp-network' ||
    capture?.status !== 'captured' ||
    capture?.authoritative !== true
  ) {
    throw new Error(`Verifier-owned before-consent browser/network capture is unavailable: ${(capture?.errors ?? []).join(' ') || capture?.status || 'missing'}`);
  }
  if (!Number.isFinite(Date.parse(String(capture.checkedAt ?? '')))) {
    throw new Error('Before-consent capture must record a valid verification time.');
  }
  beforeConsentCoverage(capture, targetOrigin);
  const finalized = { ...capture, resultStateFingerprint: state };
  return { ...finalized, captureFingerprint: captureFingerprintValue(finalized) };
}

export function validateBeforeConsentNetworkCapture(capture, {
  stateFingerprint = '',
  targetOrigin = '',
  primaryRoutes = []
} = {}) {
  if (
    capture?.schemaVersion !== BEFORE_CONSENT_NETWORK_SCHEMA ||
    capture?.captureMode !== 'verifier-owned-cdp-network' ||
    capture?.status !== 'captured' ||
    capture?.authoritative !== true
  ) {
    throw new Error(`Verifier-owned before-consent browser/network capture is unavailable: ${(capture?.errors ?? []).join(' ') || capture?.status || 'missing'}`);
  }
  if (!Number.isFinite(Date.parse(String(capture.checkedAt ?? '')))) {
    throw new Error('Before-consent capture must record a valid verification time.');
  }
  beforeConsentCoverage(capture, targetOrigin);
  if (stateFingerprint && capture.resultStateFingerprint !== stateFingerprint) {
    throw new Error('Before-consent capture does not match the exact live result-state fingerprint.');
  }
  const expected = [...new Set(primaryRoutes.map((route) => normalizeRoute(route?.targetPath ?? route)))].sort();
  const privacyPreservingExpected = [...new Set(expected.map(privacyPreservingRoute))].sort();
  const capturedRoutes = [...capture.primaryRoutes].sort();
  if (
    expected.length &&
    canonicalJson(expected) !== canonicalJson(capturedRoutes) &&
    canonicalJson(privacyPreservingExpected) !== canonicalJson(capturedRoutes)
  ) {
    throw new Error('Before-consent capture primary routes do not match the current route matrix.');
  }
  if (!HASH_RE.test(capture.captureFingerprint) || captureFingerprintValue(capture) !== capture.captureFingerprint) {
    throw new Error('Before-consent capture fingerprint is invalid.');
  }
  return capture;
}

function captureFingerprintValue(capture) {
  const value = { ...capture };
  delete value.captureFingerprint;
  return sha256(value);
}

function captureCoverage(capture) {
  const primaryRoutes = [...new Set((Array.isArray(capture?.primaryRoutes) ? capture.primaryRoutes : [])
    .map(normalizeRoute))].sort();
  if (primaryRoutes.length === 0) {
    throw new Error('Global chrome capture must identify every expected primary route.');
  }
  const contract = normalizeGlobalChromeContract(capture?.contract);
  if (contract.fingerprint !== capture?.contract?.fingerprint) {
    throw new Error('Global chrome capture contract fingerprint is invalid.');
  }
  const expected = new Set();
  for (const path of primaryRoutes) {
    for (const viewport of contract.viewports) expected.add(`${path}\0${viewport.name}`);
  }
  const observed = new Set();
  for (const route of Array.isArray(capture?.routes) ? capture.routes : []) {
    const path = normalizeRoute(route?.path);
    const viewport = String(route?.viewport?.name ?? '');
    if (!contract.viewports.some((candidate) => candidate.name === viewport)) {
      throw new Error(`Global chrome ${path} has an unsupported viewport.`);
    }
    const key = `${path}\0${viewport}`;
    if (observed.has(key)) throw new Error(`Global chrome capture duplicates ${path} ${viewport}.`);
    if (!expected.has(key)) throw new Error(`Global chrome capture contains unexpected ${path} ${viewport}.`);
    observed.add(key);
  }
  const missing = [...expected].filter((key) => !observed.has(key));
  if (missing.length > 0) {
    throw new Error(`Global chrome capture is incomplete; missing ${missing.map((key) => key.replace('\0', ' ')).join(', ')}.`);
  }
  return { contract, primaryRoutes, expected, observed };
}

export function finalizeGlobalChromeCapture({ capture, packetDir, stateFingerprint } = {}) {
  const packet = resolve(packetDir);
  const state = String(stateFingerprint ?? '').trim();
  if (!HASH_RE.test(state)) throw new Error('Global chrome capture requires the exact result-state fingerprint.');
  if (capture?.status !== 'captured' || capture?.authoritative !== true) {
    throw new Error(`Executable global chrome capture is unavailable: ${(capture?.errors ?? []).join(' ') || capture?.status || 'missing'}`);
  }
  captureCoverage(capture);
  const plans = [];
  for (const route of Array.isArray(capture?.routes) ? capture.routes : []) {
    const encoded = String(route?.screenshot?.base64 ?? '');
    if (!encoded) {
      throw new Error(`Global chrome ${route.path} ${route.viewport?.name} lacks screenshot bytes.`);
    }
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.length < 100 || bytes.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') {
      throw new Error(`Global chrome ${route.path} ${route.viewport?.name} capture is not a PNG screenshot.`);
    }
    const digest = sha256(bytes);
    const routeKey = sha256(`${route.path}\0${route.viewport?.name}`).slice(7, 23);
    const directory = join(packet, 'evidence', 'lifecycle', 'chrome', 'runs', state.slice(7, 23));
    const path = join(directory, `${route.viewport.name}-${routeKey}-${digest.slice(7, 23)}.png`);
    const rawAxe = route?.axe;
    if (
      rawAxe?.schemaVersion !== VERIFIER_AXE_SCHEMA ||
      rawAxe?.status !== 'executed' ||
      rawAxe?.source?.version !== VERIFIER_AXE_VERSION ||
      rawAxe?.source?.sha256 !== VERIFIER_AXE_SOURCE_SHA256 ||
      !rawAxe?.report ||
      (Array.isArray(rawAxe?.errors) && rawAxe.errors.length > 0)
    ) {
      throw new Error(`Global chrome ${route.path} ${route.viewport?.name} lacks a successful verifier-owned axe-core result.`);
    }
    const validatedAxe = rawVerifierAxeRecord(rawAxe.report, route?.signals?.finalUrl);
    if (validatedAxe.status !== 'executed') {
      throw new Error(`Global chrome ${route.path} ${route.viewport?.name} axe-core result is invalid: ${validatedAxe.errors.join(' ')}`);
    }
    if (
      canonicalJson(rawAxe.ruleScope) !== canonicalJson(validatedAxe.ruleScope) ||
      canonicalJson(rawAxe.summary) !== canonicalJson(validatedAxe.summary)
    ) {
      throw new Error(`Global chrome ${route.path} ${route.viewport?.name} axe-core scope or summary was modified.`);
    }
    const sharedRoute = privacyPreservingValue(route);
    const axeBytes = Buffer.from(`${JSON.stringify(sharedRoute.axe.report, null, 2)}\n`, 'utf8');
    const axeDigest = sha256(axeBytes);
    const axePath = join(directory, `axe-${route.viewport.name}-${routeKey}-${axeDigest.slice(7, 23)}.json`);
    plans.push({ axeBytes, axeDigest, axePath, bytes, digest, directory, path, route: sharedRoute });
  }
  const finalizedRoutes = [];
  for (const plan of plans) {
    ensureSafeDirectory(packet, plan.directory, 'Global chrome screenshot directory');
    const { axeBytes, axeDigest, axePath, bytes, digest, path, route } = plan;
    if (existsSync(path)) {
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink() || !metadata.isFile() || !inside(realpathSync(packet), realpathSync(path))) {
        throw new Error(`Existing global chrome screenshot must be a packet-local regular file: ${path}`);
      }
      if (!readFileSync(path).equals(bytes)) throw new Error(`Existing global chrome screenshot bytes differ: ${path}`);
    } else {
      writeFileSync(path, bytes, { flag: 'wx' });
    }
    if (existsSync(axePath)) {
      const metadata = lstatSync(axePath);
      if (metadata.isSymbolicLink() || !metadata.isFile() || !inside(realpathSync(packet), realpathSync(axePath))) {
        throw new Error(`Existing verifier-owned axe report must be a packet-local regular file: ${axePath}`);
      }
      if (!readFileSync(axePath).equals(axeBytes)) {
        throw new Error(`Existing verifier-owned axe report bytes differ: ${axePath}`);
      }
    } else {
      writeFileSync(axePath, axeBytes, { flag: 'wx' });
    }
    const portablePath = relative(packet, path).split(sep).join('/');
    const portableAxePath = relative(packet, axePath).split(sep).join('/');
    finalizedRoutes.push({
      ...route,
      axe: {
        ...route.axe,
        report: {
          path: portableAxePath,
          sha256: axeDigest,
          size: axeBytes.length
        }
      },
      screenshot: {
        path: portablePath,
        sha256: digest,
        size: bytes.length,
        width: route.screenshot.width,
        height: route.screenshot.height,
        clipped: route.screenshot.clipped === true
      }
    });
  }
  const { routes: _rawRoutes, ...captureMetadata } = capture;
  const finalized = {
    ...privacyPreservingValue(captureMetadata),
    queryPrivacy: {
      schemaVersion: 'public-kit.query-privacy.1',
      method: 'sha256',
      authoritative: true
    },
    resultStateFingerprint: state,
    routes: finalizedRoutes.sort((left, right) => `${left.path}\0${left.viewport.name}`.localeCompare(`${right.path}\0${right.viewport.name}`))
  };
  const value = { ...finalized, captureFingerprint: captureFingerprintValue(finalized) };
  return validateGlobalChromeCapture(value, { stateFingerprint: state, requireAuthoritative: false });
}

export function validateGlobalChromeCapture(capture, { stateFingerprint = '', requireAuthoritative = true } = {}) {
  if (!capture || capture.schemaVersion !== GLOBAL_CHROME_CAPTURE_SCHEMA || capture.captureMode !== 'verifier-owned-browser') {
    throw new Error(`Global chrome capture must use schemaVersion ${GLOBAL_CHROME_CAPTURE_SCHEMA} and verifier-owned-browser mode.`);
  }
  if (!['captured', 'blocked', 'unavailable'].includes(capture.status) || typeof capture.authoritative !== 'boolean') {
    throw new Error('Global chrome capture has an invalid status or authority disposition.');
  }
  if (requireAuthoritative && (capture.status !== 'captured' || capture.authoritative !== true)) {
    throw new Error(`Executable global chrome capture is unavailable: ${(capture.errors ?? []).join(' ') || capture.status}`);
  }
  if (stateFingerprint && capture.resultStateFingerprint !== stateFingerprint) {
    throw new Error('Global chrome capture does not match the exact result-state fingerprint.');
  }
  if (capture.status === 'captured') {
    captureCoverage(capture);
    for (const route of capture.routes ?? []) {
      const path = normalizeRoute(route.path);
      if (!route.signals || !HASH_RE.test(route.screenshot?.sha256) || !String(route.screenshot?.path ?? '').trim() ||
          !Number.isSafeInteger(route.screenshot?.size) || route.screenshot.size <= 0) {
        throw new Error(`Global chrome ${path} ${route.viewport.name} lacks computed signals or screenshot evidence.`);
      }
      const axe = route?.axe;
      if (axe !== undefined && (
        axe?.schemaVersion !== VERIFIER_AXE_SCHEMA ||
        axe?.status !== 'executed' ||
        axe?.source?.version !== VERIFIER_AXE_VERSION ||
        axe?.source?.sha256 !== VERIFIER_AXE_SOURCE_SHA256 ||
        canonicalJson(axe?.ruleScope) !== canonicalJson({ type: 'tag', values: [...VERIFIER_AXE_TAGS] }) ||
        !String(axe?.report?.path ?? '').trim() ||
        !HASH_RE.test(String(axe?.report?.sha256 ?? '')) ||
        !Number.isSafeInteger(axe?.report?.size) ||
        axe.report.size <= 0 ||
        !Number.isSafeInteger(axe?.summary?.violationRuleCount) ||
        !Number.isSafeInteger(axe?.summary?.violationNodeCount) ||
        !Array.isArray(axe?.summary?.violationRuleIds) ||
        !Array.isArray(axe?.errors) ||
        axe.errors.length > 0
      )) {
        throw new Error(`Global chrome ${path} ${route.viewport.name} lacks state-bound verifier-owned axe-core evidence.`);
      }
    }
  }
  if (!HASH_RE.test(capture.captureFingerprint) || captureFingerprintValue(capture) !== capture.captureFingerprint) {
    throw new Error('Global chrome capture fingerprint is invalid.');
  }
  return capture;
}

export function verifierAxeCompletionErrors(capture) {
  const errors = [];
  if (
    capture?.schemaVersion !== GLOBAL_CHROME_CAPTURE_SCHEMA ||
    capture?.status !== 'captured' ||
    capture?.authoritative !== true
  ) {
    return [`Verifier-owned axe-core coverage is unavailable: ${(capture?.errors ?? []).join(' ') || capture?.status || 'missing'}`];
  }
  try {
    captureCoverage(capture);
  } catch (error) {
    return [`Verifier-owned axe-core route/viewport coverage is incomplete: ${error.message}`];
  }
  for (const route of capture.routes ?? []) {
    const label = `${normalizeRoute(route.path)} ${route.viewport?.name ?? 'unknown-viewport'}`;
    const axe = route?.axe;
    if (
      axe?.schemaVersion !== VERIFIER_AXE_SCHEMA ||
      axe?.status !== 'executed' ||
      axe?.source?.version !== VERIFIER_AXE_VERSION ||
      axe?.source?.sha256 !== VERIFIER_AXE_SOURCE_SHA256 ||
      !HASH_RE.test(String(axe?.report?.sha256 ?? '')) ||
      !String(axe?.report?.path ?? '').trim()
    ) {
      errors.push(`${label} is missing a successful state-bound verifier-owned axe-core result.`);
      continue;
    }
    if (Number(axe?.summary?.violationNodeCount ?? 0) > 0) {
      const ids = Array.isArray(axe?.summary?.violationRuleIds) && axe.summary.violationRuleIds.length > 0
        ? axe.summary.violationRuleIds.join(', ')
        : 'unknown-rule';
      errors.push(
        `${label} has ${axe.summary.violationNodeCount} unresolved WCAG 2.2 A/AA axe-core violation node(s) across: ${ids}.`
      );
    }
  }
  return errors;
}

function routeIndex(capture) {
  return new Map((capture.routes ?? []).map((route) => [`${normalizeRoute(route.path)}\0${route.viewport.name}`, route]));
}

function identityFingerprint(identity) {
  if (!identity) return '';
  const meaningful = canonicalJson(identity).replace(/(?:"(?:backgroundImage|content)":""|[{}:,])/g, '').trim();
  return meaningful ? sha256(identity) : '';
}

export function compareGlobalChromeCaptures({ anchor, current, primaryRoutes = [] } = {}) {
  validateGlobalChromeCapture(anchor, { stateFingerprint: anchor?.resultStateFingerprint, requireAuthoritative: true });
  validateGlobalChromeCapture(current, { stateFingerprint: current?.resultStateFingerprint, requireAuthoritative: true });
  const errors = [];
  if (anchor.contract?.fingerprint !== current.contract?.fingerprint) {
    errors.push('Current capture did not use the latest verified anchor mask/selector contract.');
  }
  if (anchor.targetOrigin !== current.targetOrigin) {
    errors.push('Current capture target origin differs from the latest verified anchor.');
  }
  const anchorRoutes = routeIndex(anchor);
  const currentRoutes = routeIndex(current);
  const routes = [...new Set((primaryRoutes.length ? primaryRoutes : anchor.routes.map((route) => route.path)).map(normalizeRoute))].sort();
  const findings = [];
  for (const path of routes) {
    for (const viewport of ['desktop', 'mobile']) {
      const key = `${path}\0${viewport}`;
      const before = anchorRoutes.get(key);
      const after = currentRoutes.get(key);
      const routeErrors = [];
      if (!before || !after) {
        routeErrors.push(`Missing ${!before ? 'anchor' : 'current'} ${viewport} capture.`);
      } else {
        for (const role of ['header', 'navigation', 'footer', 'brand']) {
          if (before.signals?.roles?.[role]?.visible === true && after.signals?.roles?.[role]?.visible !== true) {
            routeErrors.push(`${role} disappeared or became non-visible.`);
          }
        }
        const beforeBrand = before.signals?.roles?.brand?.visible === true
          ? identityFingerprint(before.signals?.roles?.brand?.identity)
          : '';
        const afterBrand = identityFingerprint(after.signals?.roles?.brand?.identity);
        if (beforeBrand && beforeBrand !== afterBrand) routeErrors.push('brand mark/link identity changed.');
        const beforeHrefs = new Set((before.signals?.meaningfulHrefs ?? []).map((link) => `${link.scope}\0${link.href}`));
        const afterHrefs = new Set((after.signals?.meaningfulHrefs ?? []).map((link) => `${link.scope}\0${link.href}`));
        const missingHrefs = [...beforeHrefs].filter((href) => !afterHrefs.has(href));
        if (missingHrefs.length) routeErrors.push(`meaningful global hrefs disappeared: ${missingHrefs.join(', ')}`);
        if ((after.signals?.placeholderHrefs ?? []).length > 0) routeErrors.push('global chrome contains empty, fragment-only, or javascript hrefs.');
        if (viewport === 'mobile' && before.signals?.mobileMenu?.triggerVisible === true) {
          if (after.signals?.mobileMenu?.triggerVisible !== true) routeErrors.push('mobile menu trigger disappeared.');
          else if (after.signals?.mobileMenu?.activationWorks !== true) routeErrors.push('mobile menu trigger no longer exposes navigation.');
        }
        const beforeHeight = Number(before.signals?.layout?.normalizedPageHeight);
        const afterHeight = Number(after.signals?.layout?.normalizedPageHeight);
        const ratio = beforeHeight > 0 ? afterHeight / beforeHeight : 1;
        if (!Number.isFinite(ratio) || ratio < FIXED_THRESHOLDS.minimumPageHeightRatio || ratio > FIXED_THRESHOLDS.maximumPageHeightRatio) {
          routeErrors.push(`material normalized page-height change (${Number.isFinite(ratio) ? ratio.toFixed(3) : 'invalid'}x).`);
        }
        const beforeMainTop = Number(before.signals?.layout?.mainBox?.top);
        const afterMainTop = Number(after.signals?.layout?.mainBox?.top);
        if (Number.isFinite(beforeMainTop) && Number.isFinite(afterMainTop) &&
            Math.abs(afterMainTop - beforeMainTop) > FIXED_THRESHOLDS.maximumMainTopShiftPx) {
          routeErrors.push(`main layout shifted ${Math.abs(afterMainTop - beforeMainTop)}px.`);
        }
        if ((after.signals?.maskViolations ?? []).length > 0) routeErrors.push('dynamic masks intersected global chrome.');
      }
      errors.push(...routeErrors.map((message) => `${path} ${viewport}: ${message}`));
      findings.push({ path, viewport, passed: routeErrors.length === 0, errors: routeErrors });
    }
  }
  const comparison = {
    schemaVersion: GLOBAL_CHROME_COMPARISON_SCHEMA,
    checkedAt: current.checkedAt,
    anchorStateFingerprint: anchor.resultStateFingerprint,
    resultStateFingerprint: current.resultStateFingerprint,
    anchorCaptureFingerprint: anchor.captureFingerprint,
    resultCaptureFingerprint: current.captureFingerprint,
    contractFingerprint: anchor.contract.fingerprint,
    routes,
    findings,
    passed: errors.length === 0,
    errors
  };
  return { ...comparison, comparisonFingerprint: sha256(comparison) };
}

function manifestChanges(baseManifest, resultManifest) {
  const index = (manifest) => new Map((manifest?.entries ?? []).map((entry) => [entry.path, `${entry.sha256}\0${entry.size}`]));
  const base = index(baseManifest);
  const result = index(resultManifest);
  return [...new Set([...base.keys(), ...result.keys()])].filter((path) => base.get(path) !== result.get(path)).sort();
}

export function globalChromeImpact(baseBuildState, resultBuildState) {
  const changedConfigPaths = manifestChanges(baseBuildState?.configManifest, resultBuildState?.configManifest);
  const changedCodePaths = manifestChanges(baseBuildState?.codeManifest, resultBuildState?.codeManifest);
  const menuBefore = baseBuildState?.entityInventory?.types?.menu_link_content?.fingerprint ?? '';
  const menuAfter = resultBuildState?.entityInventory?.types?.menu_link_content?.fingerprint ?? '';
  const triggerConfigPaths = changedConfigPaths.filter((path) => CONFIG_GLOBAL_RE.test(path));
  const triggerCodePaths = changedCodePaths.filter((path) => CODE_GLOBAL_RE.test(path));
  const triggerDependencyPaths = changedCodePaths.filter((path) => DEPENDENCY_GLOBAL_RE.test(path));
  const menuLinkContentChanged = menuBefore !== menuAfter;
  const reasons = [
    ...triggerConfigPaths.map((path) => `config:${path}`),
    ...triggerCodePaths.map((path) => `theme-code:${path}`),
    ...triggerDependencyPaths.map((path) => `theme-dependency-conservative:${path}`),
    ...(menuLinkContentChanged ? ['entity:menu_link_content'] : [])
  ];
  return {
    triggered: reasons.length > 0,
    changedConfigPaths,
    changedCodePaths,
    triggerConfigPaths,
    triggerCodePaths,
    triggerDependencyPaths,
    menuLinkContentChanged,
    reasons
  };
}

export function validateScreenshotArtifacts(packetDir, capture) {
  const packet = resolve(packetDir);
  const realPacket = realpathSync(packet);
  for (const route of capture?.routes ?? []) {
    const path = resolve(packet, String(route.screenshot?.path ?? ''));
    if (!inside(packet, path) || !existsSync(path) || lstatSync(path).isSymbolicLink() || !statSync(path).isFile() ||
        !inside(realPacket, realpathSync(path))) {
      throw new Error(`Global chrome screenshot is missing or outside the packet: ${route.screenshot?.path ?? ''}`);
    }
    const bytes = readFileSync(path);
    if (bytes.length !== route.screenshot.size || sha256(bytes) !== route.screenshot.sha256) {
      throw new Error(`Global chrome screenshot bytes do not match their manifest: ${route.screenshot.path}`);
    }
    // Historical global-chrome anchors created before verifier-owned axe remain
    // readable for visual regression. A fresh completion run separately
    // requires axe on every route/viewport through verifierAxeCompletionErrors().
    if (!route.axe) {
      continue;
    }
    const axePath = resolve(packet, String(route.axe?.report?.path ?? ''));
    if (!inside(packet, axePath) || !existsSync(axePath) || lstatSync(axePath).isSymbolicLink() || !statSync(axePath).isFile() ||
        !inside(realPacket, realpathSync(axePath))) {
      throw new Error(`Verifier-owned axe report is missing or outside the packet: ${route.axe?.report?.path ?? ''}`);
    }
    const axeBytes = readFileSync(axePath);
    if (axeBytes.length !== route.axe.report.size || sha256(axeBytes) !== route.axe.report.sha256) {
      throw new Error(`Verifier-owned axe report bytes do not match their manifest: ${route.axe.report.path}`);
    }
    let axeReport;
    try {
      axeReport = JSON.parse(axeBytes.toString('utf8'));
    } catch {
      throw new Error(`Verifier-owned axe report is not valid JSON: ${route.axe.report.path}`);
    }
    const validatedAxe = rawVerifierAxeRecord(axeReport, route?.signals?.finalUrl);
    if (
      validatedAxe.status !== 'executed' ||
      canonicalJson(validatedAxe.summary) !== canonicalJson(route.axe.summary) ||
      canonicalJson(validatedAxe.ruleScope) !== canonicalJson(route.axe.ruleScope)
    ) {
      throw new Error(`Verifier-owned axe report does not match its route manifest: ${route.axe.report.path}`);
    }
  }
  return true;
}

export function captureSummary(capture) {
  const axeErrors = verifierAxeCompletionErrors(capture);
  return {
    status: capture?.status ?? 'missing',
    authoritative: capture?.authoritative === true,
    stateFingerprint: capture?.resultStateFingerprint ?? '',
    captureFingerprint: capture?.captureFingerprint ?? '',
    runtime: capture?.runtime ?? null,
    routeViewportCount: Array.isArray(capture?.routes) ? capture.routes.length : 0,
    verifierAxe: {
      sourceVersion: VERIFIER_AXE_VERSION,
      sourceSha256: VERIFIER_AXE_SOURCE_SHA256,
      routeViewportCount: Array.isArray(capture?.routes)
        ? capture.routes.filter((route) => route?.axe?.status === 'executed').length
        : 0,
      violationNodeCount: Array.isArray(capture?.routes)
        ? capture.routes.reduce((count, route) => count + Number(route?.axe?.summary?.violationNodeCount ?? 0), 0)
        : 0,
      passed: axeErrors.length === 0,
      errors: axeErrors
    },
    budget: capture?.budget ?? null,
    warnings: Array.isArray(capture?.warnings) ? capture.warnings : [],
    errors: Array.isArray(capture?.errors) ? capture.errors : []
  };
}
