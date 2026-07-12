import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  BEFORE_CONSENT_NETWORK_SCHEMA,
  BROWSER_CAPTURE_LIMITS,
  captureBeforeConsentNetwork,
  captureGlobalChrome,
  cleanupBrowserProfile,
  compareGlobalChromeCaptures,
  createBrowserCaptureBudget,
  finalizeBeforeConsentNetworkCapture,
  finalizeGlobalChromeCapture,
  findBrowserExecutable,
  globalChromeImpact,
  normalizeGlobalChromeContract,
  validateBeforeConsentNetworkCapture,
  validateScreenshotArtifacts
} from '../bin/global-chrome.mjs';
import {
  consentNetworkCaptureRequired,
  sharedBeforeConsentNetworkCapture,
  verifyConsentReconciliation
} from '../bin/verify.mjs';
import { sha256 } from '../bin/state-fingerprint.mjs';

const state = (seed) => `sha256:${seed.repeat(64)}`;

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
