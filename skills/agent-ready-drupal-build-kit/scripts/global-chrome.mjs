import { spawn } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';

import { canonicalJson, sha256 } from './state-fingerprint.mjs';

export const GLOBAL_CHROME_CAPTURE_SCHEMA = 'public-kit.global-chrome-capture.1';
export const GLOBAL_CHROME_CONTRACT_SCHEMA = 'public-kit.global-chrome-contract.1';
export const GLOBAL_CHROME_COMPARISON_SCHEMA = 'public-kit.global-chrome-comparison.1';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
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
const CONFIG_GLOBAL_RE = /(?:^|\/)(?:canvas\.(?:page_region|brand_kit|asset_library\.global)|block\.block\.|system\.(?:menu\.|theme(?:\.|$))|navigation\.|core\.menu\.static_menu_link_overrides|core\.entity_view_display\.|canvas\.content_template\.)/i;
const CODE_GLOBAL_RE = /(?:^|\/)(?:(?:web|docroot)\/)?themes\/(?:custom|contrib)\//i;
const DEPENDENCY_GLOBAL_RE = /(?:^|\/)composer\.lock$/i;

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

function browserRunning(child) {
  return child.exitCode === null && child.signalCode === null;
}

function waitForBrowserExit(child, timeoutMs) {
  if (!browserRunning(child)) return Promise.resolve(true);
  return new Promise((resolvePromise) => {
    const onExit = () => {
      clearTimeout(timeout);
      resolvePromise(true);
    };
    const timeout = setTimeout(() => {
      child.off('exit', onExit);
      resolvePromise(!browserRunning(child));
    }, timeoutMs);
    child.once('exit', onExit);
  });
}

async function shutdownBrowser(child) {
  if (!browserRunning(child)) return '';
  try {
    child.kill('SIGTERM');
    await waitForBrowserExit(child, 1_000);
    if (browserRunning(child)) {
      child.kill('SIGKILL');
      await waitForBrowserExit(child, 500);
    }
  } catch (error) {
    return `Browser shutdown failed: ${error.message}`;
  }
  return browserRunning(child)
    ? 'Browser shutdown failed: the headless browser did not exit after SIGTERM and SIGKILL.'
    : '';
}

function normalizeRoute(value) {
  const text = String(value ?? '').trim();
  if (!text.startsWith('/') || text.startsWith('//')) throw new Error(`Global chrome route must be root-relative: ${text}`);
  const url = new URL(text, 'https://global-chrome.invalid');
  return `${url.pathname || '/'}${url.search}`;
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
    selectorHeuristicsVersion: 1,
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

class CdpPipe {
  constructor(child, budget = null, timeoutMs = BROWSER_CAPTURE_LIMITS.operationTimeoutMs) {
    this.child = child;
    this.input = child.stdio[3];
    this.output = child.stdio[4];
    this.budget = budget;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.waiters = [];
    this.buffer = Buffer.alloc(0);
    this.output.on('data', (chunk) => this.onData(chunk));
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
      if (bytes.length === 0) continue;
      let message;
      try {
        message = JSON.parse(bytes.toString('utf8'));
      } catch {
        continue;
      }
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        this.pending.delete(message.id);
        clearTimeout(pending.timeout);
        if (message.error) pending.reject(new Error(`${pending.method}: ${message.error.message}`));
        else pending.resolve(message.result ?? {});
        continue;
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
  }

  failAll(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.pending.clear();
    for (const waiter of this.waiters) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
    this.waiters = [];
  }

  send(method, params = {}, sessionId = '') {
    let timing = { deadlineLimited: false, timeoutMs: this.timeoutMs };
    try {
      if (this.budget) timing = this.budget.operationTiming();
    } catch (error) {
      return Promise.reject(error);
    }
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
      this.input.write(`${JSON.stringify(message)}\0`);
    });
  }

  waitFor(method, sessionId = '') {
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
    return {
      title: document.title,
      finalUrl: location.href,
      maskViolations: [...new Set(maskViolations)].sort(),
      maskedRegionCount: topLevelMasked.length,
      roles: {
        brand: { ...roleSignal(brand), identity: brandIdentity },
        footer: roleSignal(footer),
        header: roleSignal(header),
        navigation: roleSignal(navigation)
      },
      meaningfulHrefs: links,
      placeholderHrefs: placeholders,
      mobileMenu,
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
  const evaluated = await cdp.send('Runtime.evaluate', {
    expression: collectorExpression(contract, viewport.mobile),
    awaitPromise: true,
    returnByValue: true
  }, sessionId);
  if (evaluated.exceptionDetails || !evaluated.result?.value) {
    throw new Error(`${path} ${viewport.name} signal collection failed.`);
  }
  const signals = evaluated.result.value;
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
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  const executable = findBrowserExecutable(environment);
  if (!executable) {
    return {
      schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
      checkedAt,
      status: 'unavailable',
      authoritative: false,
      captureMode: 'verifier-owned-browser',
      targetOrigin: base.origin,
      contract: normalizedContract,
      browser: { executable: '', product: '' },
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: ['No Chrome/Chromium executable was found. Set CHROME_PATH or install Chrome/Chromium.']
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
      browser: { executable: basename(executable), product: '' },
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
      browser: { executable: basename(executable), product: '' },
      primaryRoutes: routes,
      routes: [],
      budget: budget.metrics(),
      warnings: [],
      errors: [error.message]
    };
  }
  const profile = join(tmpdir(), `agent-ready-chrome-${process.pid}-${Date.now()}`);
  mkdirSync(profile, { recursive: true });
  const args = [
    '--headless=new', '--remote-debugging-pipe', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--disable-extensions',
    '--disable-sync', '--hide-scrollbars', '--mute-audio', `--user-data-dir=${profile}`, 'about:blank'
  ];
  // The verifier is restricted to the current local DDEV target; local routers may use a custom TLD and development CA.
  args.unshift('--ignore-certificate-errors');
  if (typeof process.getuid === 'function' && process.getuid() === 0) args.unshift('--no-sandbox');
  const child = spawn(executable, args, { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  const stderr = [];
  child.stderr.on('data', (chunk) => {
    if (stderr.join('').length < 8000) stderr.push(chunk.toString('utf8'));
  });
  const cdp = new CdpPipe(child, budget);
  const captured = [];
  const errors = [];
  const warnings = [];
  let product = '';
  try {
    const version = await cdp.send('Browser.getVersion');
    product = String(version.product ?? '');
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Network.enable', {}, sessionId);
    await cdp.send('Network.setCacheDisabled', { cacheDisabled: true }, sessionId);
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
    if (!budget.hasExceededDeadline()) await cdp.send('Target.closeTarget', { targetId });
  } catch (error) {
    errors.push(error.message);
  } finally {
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
  }
  if (captured.length !== routes.length * VIEWPORTS.length && stderr.length) {
    errors.push(`Browser diagnostics: ${stderr.join('').replace(/\s+/g, ' ').trim().slice(0, 800)}`);
  }
  return {
    schemaVersion: GLOBAL_CHROME_CAPTURE_SCHEMA,
    checkedAt,
    status: errors.length === 0 ? 'captured' : 'blocked',
    authoritative: errors.length === 0,
    captureMode: 'verifier-owned-browser',
    targetOrigin: base.origin,
    contract: normalizedContract,
    browser: { executable: basename(executable), product },
    primaryRoutes: routes,
    routes: captured,
    budget: budget.metrics({ attempted: true, capturedCount: captured.length }),
    warnings,
    errors
  };
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
    plans.push({ bytes, digest, directory, path, route });
  }
  const finalizedRoutes = [];
  for (const plan of plans) {
    ensureSafeDirectory(packet, plan.directory, 'Global chrome screenshot directory');
    const { bytes, digest, path, route } = plan;
    if (existsSync(path)) {
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink() || !metadata.isFile() || !inside(realpathSync(packet), realpathSync(path))) {
        throw new Error(`Existing global chrome screenshot must be a packet-local regular file: ${path}`);
      }
      if (!readFileSync(path).equals(bytes)) throw new Error(`Existing global chrome screenshot bytes differ: ${path}`);
    } else {
      writeFileSync(path, bytes, { flag: 'wx' });
    }
    const portablePath = relative(packet, path).split(sep).join('/');
    finalizedRoutes.push({
      ...route,
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
  const finalized = {
    ...capture,
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
    }
  }
  if (!HASH_RE.test(capture.captureFingerprint) || captureFingerprintValue(capture) !== capture.captureFingerprint) {
    throw new Error('Global chrome capture fingerprint is invalid.');
  }
  return capture;
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
  }
  return true;
}

export function captureSummary(capture) {
  return {
    status: capture?.status ?? 'missing',
    authoritative: capture?.authoritative === true,
    stateFingerprint: capture?.resultStateFingerprint ?? '',
    captureFingerprint: capture?.captureFingerprint ?? '',
    routeViewportCount: Array.isArray(capture?.routes) ? capture.routes.length : 0,
    budget: capture?.budget ?? null,
    warnings: Array.isArray(capture?.warnings) ? capture.warnings : [],
    errors: Array.isArray(capture?.errors) ? capture.errors : []
  };
}
