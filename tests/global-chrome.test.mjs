import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  BROWSER_CAPTURE_LIMITS,
  captureGlobalChrome,
  compareGlobalChromeCaptures,
  createBrowserCaptureBudget,
  finalizeGlobalChromeCapture,
  findBrowserExecutable,
  globalChromeImpact,
  normalizeGlobalChromeContract,
  validateScreenshotArtifacts
} from '../bin/global-chrome.mjs';
import { sha256 } from '../bin/state-fingerprint.mjs';

const state = (seed) => `sha256:${seed.repeat(64)}`;

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

function captureFixture(stateFingerprint, mutate = () => {}) {
  const contract = normalizeGlobalChromeContract({ dynamicRegionSelectors: ['[data-dynamic]'] });
  const routes = ['desktop', 'mobile'].map((viewport) => ({
    path: '/',
    viewport: { name: viewport, width: viewport === 'desktop' ? 1280 : 390, height: viewport === 'desktop' ? 800 : 844 },
    signals: {
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

test('CDP pipe captures desktop/mobile screenshots and computed signals without a browser-driver dependency', {
  skip: findBrowserExecutable() ? false : 'Chrome/Chromium is not installed in this runtime.'
}, async () => {
  const server = createServer((request, response) => {
    const missingBrand = request.url?.startsWith('/missing-brand');
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html><head><meta name="viewport" content="width=device-width"><style>
      body{margin:0} header,footer{padding:20px} main{min-height:700px}.menu-toggle{display:none}
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
      contract: { dynamicRegionSelectors: ['[data-dynamic]'] }
    });
    assert.equal(raw.status, 'captured', raw.errors.join('\n'));
    assert.deepEqual(raw.routes.map((route) => `${route.path}:${route.viewport.name}`), [
      '/:desktop', '/:mobile', '/missing-brand:desktop', '/missing-brand:mobile'
    ]);
    assert.ok(raw.routes.every((route) => route.signals.roles.header.visible));
    assert.ok(raw.routes.filter((route) => route.path === '/').every((route) => route.signals.roles.brand.visible));
    assert.ok(raw.routes.filter((route) => route.path === '/missing-brand').every((route) => !route.signals.roles.brand.visible));
    assert.ok(raw.routes.every((route) => route.signals.maskedRegionCount === 1));
    assert.ok(raw.routes.every((route) => route.signals.placeholderHrefs.length === 0));
    assert.ok(raw.routes.every((route) => route.signals.meaningfulHrefs.some((link) => link.href === 'mailto:team@example.com')));
    assert.equal(raw.routes.find((route) => route.path === '/' && route.viewport.name === 'mobile').signals.mobileMenu.activationWorks, true);
    const project = mkdtempSync(join(tmpdir(), 'global-chrome-cdp-'));
    const packetDir = join(project, 'review-packet');
    mkdirSync(join(packetDir, 'evidence'), { recursive: true });
    const finalized = finalizeGlobalChromeCapture({ capture: raw, packetDir, stateFingerprint: state('f') });
    assert.equal(finalized.resultStateFingerprint, state('f'));
    assert.equal(finalized.routes.length, 4);
    assert.equal(validateScreenshotArtifacts(packetDir, finalized), true);
  } finally {
    await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  }
});
