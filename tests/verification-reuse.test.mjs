import assert from 'node:assert/strict';
import fs, {
  existsSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  symlinkSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { hostname, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

import { sha256 } from '../bin/state-fingerprint.mjs';
import {
  finalizeGlobalChromeCapture,
  normalizeGlobalChromeContract,
  VERIFIER_AXE_SCHEMA,
  VERIFIER_AXE_SOURCE_SHA256,
  VERIFIER_AXE_TAGS,
  VERIFIER_AXE_VERSION
} from '../bin/global-chrome.mjs';
import {
  GLOBAL_CHROME_SHADOW_AUTHORITY,
  GLOBAL_CHROME_SHADOW_LIMITS,
  buildGlobalChromePreflightKey,
  buildGlobalChromeShadowObservation,
  captureGlobalChromeWithShadowPrediction,
  lookupGlobalChromeShadowReuse,
  lookupGlobalChromeShadowReuseSafely,
  projectGlobalChromeArtifacts,
  projectGlobalChromeOutcome,
  recordGlobalChromeShadowObservation,
  recordGlobalChromeShadowObservationSafely,
  summarizeGlobalChromeShadowReuse
} from '../bin/verification-reuse.mjs';
import {
  buildVerifierGlobalChromePreflight,
  recordGlobalChromeShadowSessionSafely,
  retainGlobalChromeShadowSessionForFinalCodeState
} from '../bin/verify.mjs';

const digest = (value) => sha256(`fixture:${value}`);
const fixtureContract = normalizeGlobalChromeContract();

function preflight(overrides = {}) {
  return buildGlobalChromePreflightKey({
    drupalPreflightFingerprint: digest('drupal-preflight'),
    runtimeEnvironmentFingerprint: digest('drupal-runtime'),
    browserRuntimeFingerprint: digest('browser-runtime'),
    captureImplementationFingerprint: digest('capture-implementation'),
    contractFingerprint: fixtureContract.fingerprint,
    targetOrigin: 'https://fixture.ddev.site',
    primaryRoutes: ['/about?view=full', '/'],
    additionalDependencyFingerprints: {
      fonts: digest('fonts')
    },
    ...overrides
  });
}

function axe(route) {
  return {
    schemaVersion: 'public-kit.verifier-axe.1',
    status: 'executed',
    source: { version: VERIFIER_AXE_VERSION, sha256: VERIFIER_AXE_SOURCE_SHA256 },
    ruleScope: { type: 'tag', values: [...VERIFIER_AXE_TAGS] },
    summary: {
      passRuleCount: 10,
      incompleteRuleCount: 1,
      inapplicableRuleCount: 2,
      violationRuleCount: 0,
      violationNodeCount: 0,
      violationRuleIds: []
    },
    report: {
      path: `evidence/${route}-axe.json`,
      sha256: digest(`${route}-axe-report-at-12:00`),
      size: 412,
      rawSecret: `raw-axe-payload-${route}`
    },
    errors: []
  };
}

function captured(overrides = {}) {
  const route = (path, name, width, height, suffix) => ({
    path,
    viewport: { name, width, height },
    signals: {
      finalUrl: `https://fixture.ddev.site${path}`,
      title: `Fixture ${path}`,
      roles: { header: { present: true, visible: true } }
    },
    axe: axe(suffix),
    screenshot: {
      path: `evidence/${suffix}.png`,
      sha256: digest(`${suffix}-screenshot`),
      size: 1024,
      width,
      height: height + 300,
      clipped: false,
      base64: `raw-screenshot-payload-${suffix}`
    }
  });
  const primaryRoutes = ['/about?view=full', '/'];
  const value = {
    schemaVersion: 'public-kit.global-chrome-capture.1',
    checkedAt: '2026-07-15T12:00:00.000Z',
    status: 'captured',
    authoritative: true,
    captureMode: 'verifier-owned-browser',
    targetOrigin: 'https://fixture.ddev.site',
    resultStateFingerprint: digest('site-state'),
    contract: fixtureContract,
    browser: { executable: '/private/tmp/chrome-123', product: 'Chrome/149.0.1' },
    runtime: {
      backend: 'remote',
      executionBoundary: 'ddev-add-on-sidecar',
      service: 'selenium-chrome',
      addOnRelease: '2.2.1',
      image: 'selenium/standalone-chromium:149',
      executable: '',
      product: 'Chrome/149.0.1',
      protocolVersion: '1.3',
      ready: true
    },
    primaryRoutes,
    routes: primaryRoutes.flatMap((path) => fixtureContract.viewports.map((viewport) => route(
      path,
      viewport.name,
      viewport.width,
      viewport.height,
      `${path === '/' ? 'home' : 'about'}-${viewport.name}`
    ))),
    budget: {
      attempted: true,
      capturedRouteViewportCount: primaryRoutes.length * fixtureContract.viewports.length,
      deadlineExceeded: false,
      deadlineMs: 120000,
      elapsedMs: 4271,
      maxRoutes: 64,
      operationTimeoutMs: 20000,
      routeCount: 2,
      scheduledRouteViewportCount: primaryRoutes.length * fixtureContract.viewports.length,
      viewportCount: fixtureContract.viewports.length
    },
    warnings: [],
    errors: [],
    ...overrides
  };
  value.captureFingerprint = sha256(value);
  return value;
}

function finalizedCapturedWithQueries(packetDir) {
  const raw = captured();
  delete raw.captureFingerprint;
  delete raw.resultStateFingerprint;
  const png = Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'),
    Buffer.alloc(128)
  ]).toString('base64');
  raw.routes = raw.routes.map((route) => ({
    ...route,
    axe: {
      schemaVersion: VERIFIER_AXE_SCHEMA,
      status: 'executed',
      source: { version: VERIFIER_AXE_VERSION, sha256: VERIFIER_AXE_SOURCE_SHA256 },
      ruleScope: { type: 'tag', values: [...VERIFIER_AXE_TAGS] },
      report: {
        testEngine: { name: 'axe-core', version: VERIFIER_AXE_VERSION },
        testEnvironment: {
          userAgent: 'Fixture Browser',
          windowWidth: route.viewport.width,
          windowHeight: route.viewport.height
        },
        testRunner: { name: 'axe' },
        toolOptions: { runOnly: { type: 'tag', values: [...VERIFIER_AXE_TAGS] } },
        timestamp: '2026-07-15T12:00:00.000Z',
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
  return finalizeGlobalChromeCapture({
    capture: raw,
    packetDir,
    stateFingerprint: digest('site-state')
  });
}

function refingerprint(captureValue) {
  delete captureValue.captureFingerprint;
  captureValue.captureFingerprint = sha256(captureValue);
  return captureValue;
}

function projectRoot(label) {
  return mkdtempSync(join(tmpdir(), `global-chrome-shadow-${label}-`));
}

function stateDirectory(root) {
  return join(root, '.agent-ready-drupal', 'global-chrome-shadow-reuse');
}

function onlyStatePath(root) {
  const files = readdirSync(stateDirectory(root)).filter((name) => name.endsWith('.json'));
  assert.equal(files.length, 1);
  return join(stateDirectory(root), files[0]);
}

function persistedLiveReport(captureValue, buildFingerprint = captureValue.resultStateFingerprint) {
  return {
    schemaVersion: 'public-kit.live-verification.2',
    buildState: {
      complete: true,
      fingerprint: buildFingerprint
    },
    globalChromeCapture: captureValue
  };
}

function observabilityRecord(root, runId, captureValue = captured(), {
  persist = true,
  reportName = 'live-verification.json',
  reportCapture = captureValue,
  reportBuildFingerprint = reportCapture.resultStateFingerprint,
  recordOverrides = {}
} = {}) {
  const reportPath = join(root, 'review-packet', 'evidence', reportName);
  const reportText = `${JSON.stringify(
    persistedLiveReport(reportCapture, reportBuildFingerprint),
    null,
    2
  )}\n`;
  mkdirSync(join(root, 'review-packet', 'evidence'), { recursive: true });
  writeFileSync(reportPath, reportText);
  const base = {
    schemaVersion: 'public-kit.verification-observability.1',
    authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
    runId,
    command: { status: 'completed', failureClass: '' },
    observedReport: {
      available: true,
      persisted: true,
      sha256: sha256(reportText),
      bytes: Buffer.byteLength(reportText),
      path: `review-packet/evidence/${reportName}`
    },
    timing: {
      schemaVersion: 'public-kit.verification-phase-timing.1',
      status: 'completed',
      phases: [{
        id: 'global-chrome',
        startOffsetMs: 10,
        endOffsetMs: 52.5,
        durationMs: 42.5,
        status: 'completed',
        details: { attempted: true }
      }]
    }
  };
  const record = { ...base, ...recordOverrides };
  if (persist) {
    const stateRoot = join(root, '.agent-ready-drupal');
    const runDirectory = join(stateRoot, 'verification-metrics', 'runs');
    mkdirSync(runDirectory, { recursive: true });
    writeFileSync(
      join(stateRoot, '.agent-ready-drupal-build-kit-owner'),
      'agent-ready-drupal-build-kit verification state v1\n'
    );
    writeFileSync(join(stateRoot, '.gitignore'), '*\n');
    writeFileSync(join(runDirectory, `${runId}.json`), `${JSON.stringify(record, null, 2)}\n`);
  }
  return record;
}

async function observe(root, key, capture, runId, overrides = {}) {
  const record = observabilityRecord(root, runId, capture);
  const preCapturePrediction = await lookupGlobalChromeShadowReuse({
    projectRoot: root,
    preflightKey: key
  });
  return recordGlobalChromeShadowObservation({
    projectRoot: root,
    preflightKey: key,
    capture,
    fresh: true,
    freshRunId: runId,
    observabilityRecord: record,
    preCapturePrediction,
    now: new Date(`2026-07-15T12:00:0${runId.slice(-1)}.000Z`),
    ...overrides
  });
}

test('preflight keys are canonical and every dependency participates', () => {
  const left = preflight();
  const right = preflight({
    primaryRoutes: ['/', '/about?view=full', '/'],
    additionalDependencyFingerprints: { fonts: digest('fonts') }
  });
  assert.equal(left.eligible, true);
  assert.equal(left.actualReuseEligible, false);
  assert.equal(left.actualReuseBlockers.length, 4);
  assert.equal(left.fingerprint, right.fingerprint);
  assert.deepEqual(left.authority, GLOBAL_CHROME_SHADOW_AUTHORITY);
  assert.equal(left.manifest.primaryRoutes[0], '/');
  assert.match(left.manifest.primaryRoutes[1], /^\/about\?query-sha256=[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(left).includes('fixture.ddev.site'), false);
  assert.equal(JSON.stringify(left).includes('view=full'), false);

  for (const [field, value] of [
    ['drupalPreflightFingerprint', digest('other-preflight')],
    ['runtimeEnvironmentFingerprint', digest('other-drupal-runtime')],
    ['browserRuntimeFingerprint', digest('other-browser-runtime')],
    ['captureImplementationFingerprint', digest('other-implementation')],
    ['contractFingerprint', digest('other-contract')],
    ['targetOrigin', 'https://other.ddev.site'],
    ['primaryRoutes', ['/']],
    ['additionalDependencyFingerprints', { fonts: digest('other-fonts') }]
  ]) {
    assert.notEqual(preflight({ [field]: value }).fingerprint, left.fingerprint, field);
  }
});

test('verifier preflight maps Drupal, route, contract, environment, and remote-browser dependencies', () => {
  const runtime = {
    siteUuid: '123e4567-e89b-42d3-a456-426614174000',
    frontPage: '/home',
    configSyncDirectory: 'config/sync',
    configStatusClean: true,
    configSyncMatchesHead: true,
    configSyncTracked: true,
    configManifest: { entryCount: 12, fingerprint: digest('config') },
    entityInventory: { confirmed: true, fingerprint: digest('entities') },
    liveSurfaceInventory: { confirmed: true, fingerprint: digest('live-surface') },
    runtimeFacts: {
      confirmed: true,
      fingerprint: digest('runtime-facts'),
      coreVersion: '11.2.2',
      activeConfigEntryCount: 42,
      effectiveActiveConfigSha256: digest('active-config'),
      systemSchemaEntryCount: 8,
      systemSchemaSha256: digest('system-schema'),
      databaseUpdateStatusConfirmed: true,
      pendingDatabaseUpdateCount: 0,
      databaseUpdatesPending: false,
      phpVersion: '8.3.20',
      databaseDriver: 'mysql',
      effectiveSettingsEntryCount: 7,
      effectiveSettingsHmacSha256: digest('settings'),
      configSplitDirectories: []
    }
  };
  const input = (overrides = {}) => buildVerifierGlobalChromePreflight({
    browserBackend: overrides.browserBackend ?? 'remote',
    briefMode: overrides.briefMode ?? true,
    chromeContract: overrides.chromeContract ?? fixtureContract,
    codeManifest: overrides.codeManifest ?? {
      fingerprint: digest('code'),
      environmentBinding: { fingerprint: digest('code-environment') }
    },
    inspectedDrupalRuntime: {
      ...runtime,
      ...(overrides.inspectedDrupalRuntime ?? {}),
      runtimeFacts: {
        ...runtime.runtimeFacts,
        ...(overrides.runtimeFacts ?? {})
      }
    },
    primaryRoutes: overrides.primaryRoutes ?? ['/'],
    routeMatrixText: overrides.routeMatrixText ?? '{"primaryRoutes":["/"]}',
    targetOrigin: overrides.targetOrigin ?? 'https://fixture.ddev.site'
  });
  const base = input();
  assert.equal(base.eligible, true);
  assert.equal(input({ browserBackend: 'local' }), null);
  for (const candidate of [
    input({ briefMode: false }),
    input({ codeManifest: {
      fingerprint: digest('other-code'),
      environmentBinding: { fingerprint: digest('code-environment') }
    } }),
    input({ codeManifest: {
      fingerprint: digest('code'),
      environmentBinding: { fingerprint: digest('other-code-environment') }
    } }),
    input({ inspectedDrupalRuntime: { configManifest: { entryCount: 12, fingerprint: digest('other-config') } } }),
    input({ inspectedDrupalRuntime: { entityInventory: { confirmed: true, fingerprint: digest('other-entities') } } }),
    input({ inspectedDrupalRuntime: { liveSurfaceInventory: { confirmed: true, fingerprint: digest('other-live') } } }),
    input({ runtimeFacts: { phpVersion: '8.4.1', fingerprint: digest('other-runtime') } }),
    input({ chromeContract: normalizeGlobalChromeContract({ dynamicRegionSelectors: ['.clock'] }) }),
    input({ primaryRoutes: ['/', '/about'] }),
    input({ routeMatrixText: '{"primaryRoutes":["/"],"changed":true}' }),
    input({ targetOrigin: 'https://other.ddev.site' })
  ]) {
    assert.notEqual(candidate.fingerprint, base.fingerprint);
  }
});

test('shadow training is discarded when the late authoritative code state differs', () => {
  const shadowSession = { prediction: { status: 'missing' } };
  const early = {
    fingerprint: digest('code-a'),
    environmentBinding: { fingerprint: digest('environment-a') }
  };
  assert.equal(retainGlobalChromeShadowSessionForFinalCodeState({
    shadowSession,
    shadowCodeManifest: early,
    authoritativeCodeManifest: {
      fingerprint: digest('code-a'),
      environmentBinding: { fingerprint: digest('environment-a') }
    }
  }), shadowSession);
  assert.equal(retainGlobalChromeShadowSessionForFinalCodeState({
    shadowSession,
    shadowCodeManifest: early,
    authoritativeCodeManifest: {
      fingerprint: digest('code-b'),
      environmentBinding: { fingerprint: digest('environment-a') }
    }
  }), null);
  assert.equal(retainGlobalChromeShadowSessionForFinalCodeState({
    shadowSession,
    shadowCodeManifest: early,
    authoritativeCodeManifest: {
      fingerprint: digest('code-a'),
      environmentBinding: { fingerprint: digest('environment-b') }
    }
  }), null);
  assert.equal(retainGlobalChromeShadowSessionForFinalCodeState({
    shadowSession,
    shadowCodeManifest: null,
    authoritativeCodeManifest: {
      fingerprint: digest('code-a'),
      environmentBinding: { fingerprint: digest('environment-a') }
    }
  }), null);
});

test('incomplete and unsafe preflight inputs are explicitly ineligible', () => {
  const missing = preflight({ drupalPreflightFingerprint: '', primaryRoutes: [] });
  assert.equal(missing.eligible, false);
  assert.equal(missing.fingerprint, '');
  assert.equal(missing.manifest, null);
  assert.match(missing.errors.join(' '), /drupalPreflightFingerprint/);
  assert.match(missing.errors.join(' '), /primaryRoutes/);

  const unsafe = preflight({
    targetOrigin: 'https://user:secret@fixture.ddev.site/path?token=secret',
    primaryRoutes: ['//other.example/']
  });
  assert.equal(unsafe.eligible, false);
  assert.match(unsafe.errors.join(' '), /without credentials/);
  assert.match(unsafe.errors.join(' '), /root-relative/);

  const unknownExtension = preflight({
    additionalDependencyFingerprints: { '../escape': digest('escape') }
  });
  assert.equal(unknownExtension.eligible, false);
});

test('projections discard volatility while retaining completion and screenshot drift', () => {
  const base = captured();
  const volatile = structuredClone(base);
  volatile.checkedAt = '2026-07-15T13:00:00.000Z';
  volatile.captureFingerprint = digest('another-volatile-capture');
  volatile.budget.elapsedMs = 99999;
  volatile.browser.executable = '/another/private/profile/chrome';
  volatile.routes[0].screenshot.path = 'evidence/a-renamed-screenshot.png';
  volatile.routes[0].screenshot.base64 = 'different-raw-screenshot-payload';
  volatile.routes[0].axe.report.path = 'evidence/a-renamed-axe.json';
  volatile.routes[0].axe.report.sha256 = digest('timestamp-sensitive-axe-report');
  volatile.routes[0].axe.report.size = 999;
  volatile.routes[0].axe.report.rawSecret = 'different-raw-axe-payload';
  assert.deepEqual(projectGlobalChromeOutcome(volatile), projectGlobalChromeOutcome(base));
  assert.deepEqual(projectGlobalChromeArtifacts(volatile), projectGlobalChromeArtifacts(base));

  const completionDrift = structuredClone(base);
  completionDrift.routes[0].axe.summary.violationNodeCount = 1;
  completionDrift.routes[0].axe.summary.violationRuleCount = 1;
  completionDrift.routes[0].axe.summary.violationRuleIds = ['color-contrast'];
  assert.notDeepEqual(projectGlobalChromeOutcome(completionDrift), projectGlobalChromeOutcome(base));

  const aliasDrift = structuredClone(base);
  aliasDrift.resultStateFingerprint = digest('aliased-state');
  assert.notDeepEqual(projectGlobalChromeOutcome(aliasDrift), projectGlobalChromeOutcome(base));

  const artifactDrift = structuredClone(base);
  artifactDrift.routes[0].screenshot.sha256 = digest('new-screenshot-bytes');
  assert.notDeepEqual(projectGlobalChromeArtifacts(artifactDrift), projectGlobalChromeArtifacts(base));
  assert.deepEqual(projectGlobalChromeOutcome(artifactDrift), projectGlobalChromeOutcome(base));
});

test('finalized query routes keep one privacy identity through shadow observation', () => {
  const root = projectRoot('finalized-query');
  const packetDir = join(root, 'review-packet');
  mkdirSync(packetDir, { recursive: true });
  const key = preflight();
  const finalized = finalizedCapturedWithQueries(packetDir);
  const expectedQueryRoute = key.manifest.primaryRoutes.find((route) => route.startsWith('/about?'));

  assert.deepEqual(finalized.queryPrivacy, {
    schemaVersion: 'public-kit.query-privacy.1',
    method: 'sha256',
    authoritative: true
  });
  assert.ok(finalized.primaryRoutes.includes(expectedQueryRoute));
  const observation = buildGlobalChromeShadowObservation({
    preflightKey: key,
    capture: finalized
  });
  assert.equal(observation.eligible, true, observation.errors?.join(' '));
  assert.ok(observation.artifactManifest.routes.some((route) => route.path === expectedQueryRoute));

  const forgedPrivacyMarker = captured({
    queryPrivacy: {
      schemaVersion: 'public-kit.query-privacy.1',
      method: 'sha256',
      authoritative: true
    }
  });
  refingerprint(forgedPrivacyMarker);
  const forgedObservation = buildGlobalChromeShadowObservation({
    preflightKey: key,
    capture: forgedPrivacyMarker
  });
  assert.equal(forgedObservation.eligible, false);
  assert.match(forgedObservation.errors.join(' '), /canonical query identity/i);
});

test('only final, exact-key-bound captures form eligible observations', () => {
  const key = preflight();
  const good = buildGlobalChromeShadowObservation({ preflightKey: key, capture: captured() });
  assert.equal(good.eligible, true);
  assert.match(good.outcomeFingerprint, /^sha256:/);
  assert.match(good.artifactFingerprint, /^sha256:/);

  for (const capture of [
    captured({ authoritative: false }),
    captured({ status: 'blocked' }),
    captured({ targetOrigin: 'https://other.ddev.site' }),
    captured({ contract: { fingerprint: digest('other-contract') } }),
    captured({ primaryRoutes: ['/'] }),
    captured({ routes: [] })
  ]) {
    assert.equal(buildGlobalChromeShadowObservation({ preflightKey: key, capture }).eligible, false);
  }
  const missingFingerprint = captured();
  delete missingFingerprint.captureFingerprint;
  assert.equal(
    buildGlobalChromeShadowObservation({ preflightKey: key, capture: missingFingerprint }).eligible,
    false
  );
  const missingAxe = captured();
  delete missingAxe.routes[0].axe;
  refingerprint(missingAxe);
  assert.equal(
    buildGlobalChromeShadowObservation({ preflightKey: key, capture: missingAxe }).eligible,
    false
  );
  assert.equal(
    buildGlobalChromeShadowObservation({
      preflightKey: preflight({ drupalPreflightFingerprint: '' }),
      capture: captured()
    }).eligible,
    false
  );
});

test('seed plus two distinct fresh exact matches qualifies only shadow prediction', async () => {
  const root = projectRoot('qualify');
  const key = preflight();
  const capture = captured();
  const seed = await observe(root, key, capture, 'fresh-1');
  assert.equal(seed.status, 'seeded');
  assert.equal(seed.exactMatchCount, 0);
  assert.equal(seed.shadowQualified, false);
  assert.deepEqual(seed.authority, GLOBAL_CHROME_SHADOW_AUTHORITY);

  const duplicate = await observe(root, key, capture, 'fresh-1');
  assert.equal(duplicate.status, 'duplicate-observation');
  assert.equal(duplicate.exactMatchCount, 0);

  const first = await observe(root, key, capture, 'fresh-2');
  assert.equal(first.status, 'exact-match');
  assert.equal(first.exactMatchCount, 1);
  assert.equal(first.shadowQualified, false);

  const second = await observe(root, key, capture, 'fresh-3');
  assert.equal(second.status, 'shadow-qualified');
  assert.equal(second.exactMatchCount, 2);
  assert.equal(second.shadowQualified, true);
  assert.equal(second.actualReuseEligible, false);
  assert.equal(second.authority.canAuthorizeCompletion, false);
  assert.deepEqual(await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key }), second);

  const confirmedPotential = await observe(root, key, capture, 'fresh-4');
  assert.equal(confirmedPotential.status, 'shadow-qualified');
  assert.equal(confirmedPotential.actualReuseEligible, false);

  const stateText = readFileSync(onlyStatePath(root), 'utf8');
  for (const forbidden of [
    'raw-screenshot-payload',
    'raw-axe-payload',
    'Fixture /',
    'signals',
    'checkedAt',
    'captureFingerprint',
    'elapsedMs',
    'evidence/home-desktop.png',
    'home-desktop-axe.json'
  ]) {
    assert.equal(stateText.includes(forbidden), false, forbidden);
  }
  assert.match(stateText, /artifactManifest/);
  assert.match(stateText, /sha256/);
  assert.equal(stateText.includes('fixture.ddev.site'), false);
  assert.equal(stateText.includes('view=full'), false);
  const stored = JSON.parse(stateText);
  assert.equal(stored.recentObservations.length, 4);
  assert.deepEqual(stored.recentObservations.map((entry) => entry.classification), [
    'seed',
    'exact-match',
    'shadow-qualified',
    'shadow-qualified'
  ]);
  assert.deepEqual(stored.recentObservations.map((entry) => entry.freshGlobalChromePhaseMs), [
    42.5, 42.5, 42.5, 42.5
  ]);
  assert.deepEqual(stored.recentObservations.map((entry) => entry.potentialAvoidablePhaseMs), [
    0, 0, 0, 42.5
  ]);
  const expectedReportText = `${JSON.stringify(persistedLiveReport(capture), null, 2)}\n`;
  assert.deepEqual(stored.recentObservations[0].observedReport, {
    sha256: sha256(expectedReportText),
    bytes: Buffer.byteLength(expectedReportText),
    path: 'review-packet/evidence/live-verification.json'
  });
  const summary = await summarizeGlobalChromeShadowReuse({ projectRoot: root });
  assert.equal(summary.status, 'ok');
  assert.equal(summary.namespaceCount, 1);
  assert.equal(summary.shadowQualifiedCount, 1);
  assert.equal(summary.quarantinedCount, 0);
  assert.equal(summary.retainedFreshObservationCount, 4);
  assert.equal(summary.retainedQualifiedMatchedObservationCount, 1);
  assert.equal(summary.retainedFreshGlobalChromePhaseMs, 170);
  assert.equal(summary.retainedPotentialAvoidablePhaseMs, 42.5);
  assert.equal(summary.actualReuseEligible, false);
});

test('bounded history remains valid after the seed and first confirmation are pruned', async () => {
  const root = projectRoot('bounded-history');
  const key = preflight();
  const capture = captured();
  for (let run = 1; run <= 10; run += 1) {
    const result = await observe(root, key, capture, `fresh-${run}`);
    assert.notEqual(result.status, 'storage-error', `fresh-${run}`);
  }

  const stored = JSON.parse(readFileSync(onlyStatePath(root), 'utf8'));
  assert.equal(stored.recentObservations.length, 8);
  assert.deepEqual(
    stored.recentObservations.map((entry) => entry.classification),
    Array(8).fill('shadow-qualified')
  );
  const lookup = await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key });
  assert.equal(lookup.status, 'shadow-qualified');
  assert.equal(lookup.actualReuseEligible, false);
});

test('lookup is read-only when no owned shadow state exists', async () => {
  const root = projectRoot('read-only-lookup');
  const result = await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: preflight() });
  assert.equal(result.status, 'missing');
  assert.equal(result.shadowQualified, false);
  assert.equal(existsSync(join(root, '.agent-ready-drupal')), false);
});

test('shadow lookup is fail-open and never replaces the exactly-once fresh capture', async () => {
  const key = preflight();
  const root = projectRoot('fresh-orchestration');
  const fresh = captured();
  let captureCount = 0;
  let lookupCount = 0;
  const shadow = await captureGlobalChromeWithShadowPrediction({
    reuseMode: 'shadow',
    projectRoot: root,
    preflightKey: key,
    lookupShadow: async () => {
      lookupCount += 1;
      throw new Error('forced lookup failure');
    },
    captureFresh: async () => {
      captureCount += 1;
      return fresh;
    }
  });
  assert.equal(lookupCount, 1);
  assert.equal(captureCount, 1);
  assert.equal(shadow.capture, fresh);
  assert.equal(shadow.shadowSession.prediction.status, 'storage-error');
  assert.equal(shadow.shadowSession.prediction.authority.canAuthorizeCompletion, false);

  captureCount = 0;
  const qualifiedPrediction = {
    schemaVersion: 'public-kit.global-chrome-shadow-result.1',
    authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
    status: 'shadow-qualified',
    keyFingerprint: key.fingerprint,
    seeded: true,
    exactMatchCount: 2,
    shadowQualified: true,
    quarantined: false,
    prediction: {
      outcomeFingerprint: digest('qualified-outcome'),
      artifactFingerprint: digest('qualified-artifact')
    },
    actualReuseEligible: false,
    actualReuseBlockers: [],
    errors: []
  };
  const qualified = await captureGlobalChromeWithShadowPrediction({
    reuseMode: 'shadow',
    projectRoot: root,
    preflightKey: key,
    lookupShadow: async () => qualifiedPrediction,
    captureFresh: async () => {
      captureCount += 1;
      return fresh;
    }
  });
  assert.equal(captureCount, 1);
  assert.equal(qualified.capture, fresh);
  assert.equal(qualified.shadowSession.prediction, qualifiedPrediction);

  lookupCount = 0;
  captureCount = 0;
  const off = await captureGlobalChromeWithShadowPrediction({
    reuseMode: 'off',
    projectRoot: root,
    preflightKey: key,
    lookupShadow: async () => {
      lookupCount += 1;
      throw new Error('off mode must not read shadow state');
    },
    captureFresh: async () => {
      captureCount += 1;
      return fresh;
    }
  });
  assert.equal(lookupCount, 0);
  assert.equal(captureCount, 1);
  assert.equal(off.capture, fresh);
  assert.equal(off.shadowSession, null);
  assert.equal(existsSync(join(root, '.agent-ready-drupal')), false);

  captureCount = 0;
  const invalidRoot = await captureGlobalChromeWithShadowPrediction({
    reuseMode: 'shadow',
    projectRoot: { toString() { throw new Error('invalid root'); } },
    preflightKey: key,
    captureFresh: async () => {
      captureCount += 1;
      return fresh;
    }
  });
  assert.equal(captureCount, 1);
  assert.equal(invalidRoot.capture, fresh);
  assert.equal(invalidRoot.shadowSession, null);
});

test('post-report shadow persistence is off-mode silent and failure cannot escape into verifier control flow', async () => {
  const sharedCapture = captured();
  const report = {
    valid: true,
    completeLocalBuildFromBriefClaimAllowed: true,
    currentSiteClaimAllowed: true,
    globalChromeCapture: sharedCapture
  };
  const reportBytes = JSON.stringify(report);
  const exitSentinel = { code: 0 };
  let recordCalls = 0;
  const shadowSession = {
    projectRoot: projectRoot('post-report-failure'),
    preflightKey: preflight(),
    capture: sharedCapture,
    prediction: null
  };
  const observabilityResult = { record: { runId: 'fresh-1' } };
  const recordShadow = async (input) => {
    recordCalls += 1;
    input.capture.status = 'mutated-by-diagnostic-recorder';
    input.observabilityRecord.runId = 'mutated-run';
    throw new Error('forced post-report storage failure');
  };
  const stderr = { write() {} };

  const off = await recordGlobalChromeShadowSessionSafely({
    reuseMode: 'off',
    shadowSession,
    observabilityResult,
    recordShadow,
    stderr
  });
  assert.equal(off, null);
  assert.equal(recordCalls, 0);

  let warning = '';
  const ineligible = await recordGlobalChromeShadowSessionSafely({
    reuseMode: 'shadow',
    shadowSession: {
      experimentDiagnostic: {
        status: 'ineligible',
        reason: 'fixture remote runtime is unavailable'
      }
    },
    observabilityResult,
    recordShadow,
    stderr: { write(value) { warning += value; } }
  });
  assert.equal(ineligible.status, 'ineligible');
  assert.match(warning, /fixture remote runtime is unavailable/);
  assert.equal(recordCalls, 0);

  const failedShadow = await recordGlobalChromeShadowSessionSafely({
    reuseMode: 'shadow',
    shadowSession,
    observabilityResult,
    recordShadow,
    stderr
  });
  assert.equal(failedShadow, null);
  assert.equal(recordCalls, 1);
  assert.equal(JSON.stringify(report), reportBytes);
  assert.equal(observabilityResult.record.runId, 'fresh-1');
  assert.equal(exitSentinel.code, 0);
});

test('fresh=false and malformed run identities cannot train the predictor', async () => {
  const root = projectRoot('fresh-required');
  const key = preflight();
  const notFresh = await recordGlobalChromeShadowObservation({
    projectRoot: root,
    preflightKey: key,
    capture: captured(),
    fresh: false,
    freshRunId: 'run-1'
  });
  assert.equal(notFresh.status, 'ineligible');
  assert.equal(existsSync(join(root, '.agent-ready-drupal')), false);

  const unsafeId = await recordGlobalChromeShadowObservation({
    projectRoot: root,
    preflightKey: key,
    capture: captured(),
    fresh: true,
    freshRunId: '../run-1'
  });
  assert.equal(unsafeId.status, 'ineligible');
  assert.equal(existsSync(join(root, '.agent-ready-drupal')), false);
});

test('training is bound to the exact capture in the persisted report and exact persisted observability run', async () => {
  const key = preflight();
  const callerCapture = captured();

  const reportMismatchRoot = projectRoot('report-capture-binding');
  const reportMismatchRun = 'fresh-report-mismatch';
  const blockedReportCapture = captured({ status: 'blocked', authoritative: false });
  const reportMismatchRecord = observabilityRecord(
    reportMismatchRoot,
    reportMismatchRun,
    callerCapture,
    { reportCapture: blockedReportCapture }
  );
  const reportMismatch = await recordGlobalChromeShadowObservation({
    projectRoot: reportMismatchRoot,
    preflightKey: key,
    capture: callerCapture,
    fresh: true,
    freshRunId: reportMismatchRun,
    observabilityRecord: reportMismatchRecord,
    preCapturePrediction: await lookupGlobalChromeShadowReuse({
      projectRoot: reportMismatchRoot,
      preflightKey: key
    })
  });
  assert.equal(reportMismatch.status, 'ineligible');
  assert.match(reportMismatch.errors.join(' '), /does not exactly match/);
  assert.equal(existsSync(stateDirectory(reportMismatchRoot)), false);

  const runMismatchRoot = projectRoot('observability-run-binding');
  const runMismatchId = 'fresh-run-mismatch';
  const suppliedRecord = observabilityRecord(runMismatchRoot, runMismatchId, callerCapture);
  const runMismatchPrediction = await lookupGlobalChromeShadowReuse({
    projectRoot: runMismatchRoot,
    preflightKey: key
  });
  suppliedRecord.command = { status: 'completed', failureClass: '', injected: true };
  const runMismatch = await recordGlobalChromeShadowObservationSafely({
    projectRoot: runMismatchRoot,
    preflightKey: key,
    capture: callerCapture,
    fresh: true,
    freshRunId: runMismatchId,
    observabilityRecord: suppliedRecord,
    preCapturePrediction: runMismatchPrediction
  });
  assert.equal(runMismatch.status, 'storage-error');
  assert.match(runMismatch.errors.join(' '), /exact persisted same-run record/);
  assert.equal(existsSync(stateDirectory(runMismatchRoot)), false);

  const stateMismatchRoot = projectRoot('report-state-binding');
  const stateMismatchId = 'fresh-state-mismatch';
  const stateMismatchRecord = observabilityRecord(
    stateMismatchRoot,
    stateMismatchId,
    callerCapture,
    { reportBuildFingerprint: digest('different-build-state') }
  );
  const stateMismatch = await recordGlobalChromeShadowObservationSafely({
    projectRoot: stateMismatchRoot,
    preflightKey: key,
    capture: callerCapture,
    fresh: true,
    freshRunId: stateMismatchId,
    observabilityRecord: stateMismatchRecord,
    preCapturePrediction: await lookupGlobalChromeShadowReuse({
      projectRoot: stateMismatchRoot,
      preflightKey: key
    })
  });
  assert.equal(stateMismatch.status, 'storage-error');
  assert.match(stateMismatch.errors.join(' '), /complete state-bound/);
  assert.equal(existsSync(stateDirectory(stateMismatchRoot)), false);
});

test('report and observability bindings reject symlinked ancestors and hard links', async (t) => {
  const key = preflight();
  const captureValue = captured();

  await t.test('report ancestor symlink', async () => {
    const root = projectRoot('report-ancestor-symlink');
    const runId = 'fresh-report-symlink';
    const record = observabilityRecord(root, runId, captureValue);
    const reportPath = join(root, record.observedReport.path);
    const outside = projectRoot('report-ancestor-outside');
    writeFileSync(join(outside, 'report.json'), readFileSync(reportPath));
    symlinkSync(outside, join(root, 'linked-report'));
    record.observedReport.path = 'linked-report/report.json';
    writeFileSync(
      join(root, '.agent-ready-drupal', 'verification-metrics', 'runs', `${runId}.json`),
      `${JSON.stringify(record, null, 2)}\n`
    );
    const result = await recordGlobalChromeShadowObservationSafely({
      projectRoot: root,
      preflightKey: key,
      capture: captureValue,
      fresh: true,
      freshRunId: runId,
      observabilityRecord: record,
      preCapturePrediction: await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key })
    });
    assert.equal(result.status, 'storage-error');
    assert.match(result.errors.join(' '), /resolves outside/);
  });

  await t.test('hard-linked report', async () => {
    const root = projectRoot('hard-linked-report');
    const runId = 'fresh-hard-report';
    const record = observabilityRecord(root, runId, captureValue);
    linkSync(join(root, record.observedReport.path), join(projectRoot('hard-report-outside'), 'report.json'));
    const result = await recordGlobalChromeShadowObservationSafely({
      projectRoot: root,
      preflightKey: key,
      capture: captureValue,
      fresh: true,
      freshRunId: runId,
      observabilityRecord: record,
      preCapturePrediction: await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key })
    });
    assert.equal(result.status, 'storage-error');
    assert.match(result.errors.join(' '), /single-link/);
  });

  await t.test('hard-linked observability run', async () => {
    const root = projectRoot('hard-linked-run');
    const runId = 'fresh-hard-run';
    const record = observabilityRecord(root, runId, captureValue);
    const runPath = join(root, '.agent-ready-drupal', 'verification-metrics', 'runs', `${runId}.json`);
    linkSync(runPath, join(projectRoot('hard-run-outside'), 'run.json'));
    const result = await recordGlobalChromeShadowObservationSafely({
      projectRoot: root,
      preflightKey: key,
      capture: captureValue,
      fresh: true,
      freshRunId: runId,
      observabilityRecord: record,
      preCapturePrediction: await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key })
    });
    assert.equal(result.status, 'storage-error');
    assert.match(result.errors.join(' '), /single-link/);
  });
});

test('stored qualification must be supported by bounded fresh-observation history', async () => {
  const root = projectRoot('forged-qualification');
  const key = preflight();
  await observe(root, key, captured(), 'fresh-1');
  const statePath = onlyStatePath(root);
  const forged = JSON.parse(readFileSync(statePath, 'utf8'));
  forged.status = 'shadow-qualified';
  forged.exactMatchCount = 2;
  writeFileSync(statePath, `${JSON.stringify(forged, null, 2)}\n`);
  const result = await lookupGlobalChromeShadowReuseSafely({ projectRoot: root, preflightKey: key });
  assert.equal(result.status, 'storage-error');
  assert.match(result.errors.join(' '), /history does not/);
  assert.equal(result.shadowQualified, false);
});

test('one mismatch permanently quarantines the exact dependency namespace', async () => {
  const root = projectRoot('quarantine');
  const key = preflight();
  const baseline = captured();
  await observe(root, key, baseline, 'fresh-1');
  const drift = structuredClone(baseline);
  drift.routes[0].screenshot.sha256 = digest('drifted-screenshot');
  refingerprint(drift);
  const mismatch = await observe(root, key, drift, 'fresh-2');
  assert.equal(mismatch.status, 'quarantined');
  assert.equal(mismatch.quarantined, true);
  assert.equal(mismatch.prediction, null);
  assert.equal(mismatch.shadowQualified, false);

  const laterMatch = await observe(root, key, baseline, 'fresh-3');
  assert.equal(laterMatch.status, 'quarantined');
  assert.equal(laterMatch.quarantined, true);

  const differentNamespace = preflight({ drupalPreflightFingerprint: digest('new-preflight') });
  const differentCapture = captured({ resultStateFingerprint: digest('new-site-state') });
  const otherSeed = await observe(root, differentNamespace, differentCapture, 'fresh-other-1');
  assert.equal(otherSeed.status, 'seeded');
  assert.equal(otherSeed.quarantined, false);
});

test('concurrent divergent fresh observations serialize and preserve quarantine', async () => {
  const root = projectRoot('concurrent-quarantine');
  const key = preflight();
  const baseline = captured();
  await observe(root, key, baseline, 'fresh-1');
  const preCapturePrediction = await lookupGlobalChromeShadowReuse({
    projectRoot: root,
    preflightKey: key
  });
  const drift = structuredClone(baseline);
  drift.routes[0].screenshot.sha256 = digest('concurrent-drift');
  refingerprint(drift);
  const baselineRecord = observabilityRecord(root, 'fresh-2', baseline, {
    reportName: 'live-verification-fresh-2.json'
  });
  const driftRecord = observabilityRecord(root, 'fresh-3', drift, {
    reportName: 'live-verification-fresh-3.json'
  });
  const options = (captureValue, runId, record) => ({
    projectRoot: root,
    preflightKey: key,
    capture: captureValue,
    fresh: true,
    freshRunId: runId,
    observabilityRecord: record,
    preCapturePrediction
  });
  await Promise.all([
    recordGlobalChromeShadowObservationSafely(options(baseline, 'fresh-2', baselineRecord)),
    recordGlobalChromeShadowObservationSafely(options(drift, 'fresh-3', driftRecord))
  ]);
  const finalState = await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key });
  assert.equal(finalState.status, 'quarantined');
  assert.equal(finalState.shadowQualified, false);
  assert.equal(finalState.prediction, null);
});

test('concurrent divergent first observations initialize once and quarantine', async () => {
  const root = projectRoot('concurrent-first-quarantine');
  const key = preflight();
  const baseline = captured();
  const drift = structuredClone(baseline);
  drift.routes[0].screenshot.sha256 = digest('concurrent-first-drift');
  refingerprint(drift);
  const baselineRecord = observabilityRecord(root, 'fresh-first-1', baseline, {
    reportName: 'live-verification-first-1.json'
  });
  const driftRecord = observabilityRecord(root, 'fresh-first-2', drift, {
    reportName: 'live-verification-first-2.json'
  });
  const missingPrediction = await lookupGlobalChromeShadowReuse({
    projectRoot: root,
    preflightKey: key
  });
  const options = (captureValue, runId, record) => ({
    projectRoot: root,
    preflightKey: key,
    capture: captureValue,
    fresh: true,
    freshRunId: runId,
    observabilityRecord: record,
    preCapturePrediction: missingPrediction
  });
  const results = await Promise.all([
    recordGlobalChromeShadowObservationSafely(options(baseline, 'fresh-first-1', baselineRecord)),
    recordGlobalChromeShadowObservationSafely(options(drift, 'fresh-first-2', driftRecord))
  ]);
  assert.equal(
    results.some((result) => result.status === 'storage-error'),
    false,
    JSON.stringify(results, null, 2)
  );
  const finalState = await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key });
  assert.equal(finalState.status, 'quarantined');
  assert.equal(finalState.shadowQualified, false);
});

test('stale locks require manual cleanup and simultaneous contenders never steal a recycled live owner', async () => {
  const root = projectRoot('lock-recovery');
  const key = preflight();
  const capture = captured();
  await observe(root, key, capture, 'fresh-1');
  const lockPath = join(root, '.agent-ready-drupal', 'global-chrome-shadow-reuse.lock');
  const ownerPath = join(lockPath, 'owner.json');
  const abandonedPath = `${lockPath}.test-abandoned`;
  const lockOwner = (pid, token) => ({
    schemaVersion: 'public-kit.global-chrome-shadow-lock-owner.1',
    token,
    pid,
    hostFingerprint: sha256(hostname()),
    acquiredAt: new Date(Date.now() - 60_000).toISOString()
  });

  mkdirSync(lockPath);
  writeFileSync(ownerPath, `${JSON.stringify(lockOwner(
    2147483647,
    '11111111-1111-4111-8111-111111111111'
  ))}\n`);
  const blocked = observe(root, key, capture, 'fresh-2');
  await delay(100);
  assert.equal(
    JSON.parse(readFileSync(ownerPath, 'utf8')).token,
    '11111111-1111-4111-8111-111111111111',
    'a stale owner must remain until the operator removes it'
  );
  unlinkSync(ownerPath);
  rmdirSync(lockPath);
  assert.equal((await blocked).status, 'exact-match');

  mkdirSync(lockPath);
  writeFileSync(ownerPath, `${JSON.stringify(lockOwner(
    2147483647,
    '22222222-2222-4222-8222-222222222222'
  ))}\n`);

  const originalReadFile = fs.promises.readFile;
  let staleOwnerReads = 0;
  let releaseStaleReads;
  const staleReadsReleased = new Promise((resolvePromise) => {
    releaseStaleReads = resolvePromise;
  });
  let resolveBothStaleReads;
  const bothStaleReads = new Promise((resolvePromise) => {
    resolveBothStaleReads = resolvePromise;
  });
  fs.promises.readFile = async (path, ...args) => {
    const value = await originalReadFile(path, ...args);
    if (resolve(String(path)) === resolve(ownerPath) && staleOwnerReads < 2) {
      staleOwnerReads += 1;
      if (staleOwnerReads === 2) resolveBothStaleReads();
      await staleReadsReleased;
    }
    return value;
  };
  syncBuiltinESMExports();

  const contenders = [
    observe(root, key, capture, 'fresh-3'),
    observe(root, key, capture, 'fresh-4')
  ];
  try {
    await bothStaleReads;
    renameSync(lockPath, abandonedPath);
    mkdirSync(lockPath);
    writeFileSync(ownerPath, `${JSON.stringify(lockOwner(
      process.pid,
      '33333333-3333-4333-8333-333333333333'
    ))}\n`);
    releaseStaleReads();
    await delay(100);
    assert.equal(
      JSON.parse(readFileSync(ownerPath, 'utf8')).token,
      '33333333-3333-4333-8333-333333333333',
      'stale lock snapshots must never delete or replace a recycled live owner'
    );
    unlinkSync(ownerPath);
    rmdirSync(lockPath);
    unlinkSync(join(abandonedPath, 'owner.json'));
    rmdirSync(abandonedPath);
    const results = await Promise.all(contenders);
    assert.deepEqual(results.map((result) => result.status), ['shadow-qualified', 'shadow-qualified']);
  } finally {
    releaseStaleReads();
    fs.promises.readFile = originalReadFile;
    syncBuiltinESMExports();
    if (existsSync(ownerPath)) unlinkSync(ownerPath);
    if (existsSync(lockPath)) rmdirSync(lockPath);
    if (existsSync(join(abandonedPath, 'owner.json'))) unlinkSync(join(abandonedPath, 'owner.json'));
    if (existsSync(abandonedPath)) rmdirSync(abandonedPath);
    await Promise.allSettled(contenders);
  }
});

test('lookup during a paused atomic write preserves a concurrent mismatch quarantine', async () => {
  const root = projectRoot('reader-during-write');
  const key = preflight();
  const baseline = captured();
  await observe(root, key, baseline, 'fresh-1');
  const statePath = onlyStatePath(root);
  const preCapturePrediction = await lookupGlobalChromeShadowReuse({
    projectRoot: root,
    preflightKey: key
  });
  const exactRecord = observabilityRecord(root, 'fresh-2', baseline, {
    reportName: 'live-verification-fresh-2.json'
  });
  const drift = structuredClone(baseline);
  drift.routes[0].screenshot.sha256 = digest('reader-during-write-drift');
  refingerprint(drift);
  const driftRecord = observabilityRecord(root, 'fresh-3', drift, {
    reportName: 'live-verification-fresh-3.json'
  });

  const originalRename = fs.promises.rename;
  let temporaryPath = '';
  let resolveWritePaused;
  const writePaused = new Promise((resolvePromise) => {
    resolveWritePaused = resolvePromise;
  });
  let releaseWrite;
  const writeReleased = new Promise((resolvePromise) => {
    releaseWrite = resolvePromise;
  });
  fs.promises.rename = async (source, destination, ...args) => {
    if (resolve(String(destination)) === resolve(statePath) && !temporaryPath) {
      temporaryPath = String(source);
      resolveWritePaused();
      await writeReleased;
    }
    return originalRename(source, destination, ...args);
  };
  syncBuiltinESMExports();

  const exactWriter = recordGlobalChromeShadowObservation({
    projectRoot: root,
    preflightKey: key,
    capture: baseline,
    fresh: true,
    freshRunId: 'fresh-2',
    observabilityRecord: exactRecord,
    preCapturePrediction
  });
  let mismatchWriter = null;
  try {
    await writePaused;
    assert.equal(dirname(temporaryPath), join(root, '.agent-ready-drupal'));
    assert.equal(existsSync(temporaryPath), true);
    assert.equal(
      readdirSync(stateDirectory(root)).some((name) => name.endsWith('.tmp')),
      false,
      'atomic state-write temporaries must stay outside the enumerated namespace directory'
    );
    const mismatchPrediction = await lookupGlobalChromeShadowReuseSafely({
      projectRoot: root,
      preflightKey: key
    });
    assert.equal(mismatchPrediction.status, 'tracking');
    mismatchWriter = recordGlobalChromeShadowObservation({
      projectRoot: root,
      preflightKey: key,
      capture: drift,
      fresh: true,
      freshRunId: 'fresh-3',
      observabilityRecord: driftRecord,
      preCapturePrediction: mismatchPrediction
    });
    releaseWrite();
    assert.equal((await exactWriter).status, 'exact-match');
    assert.equal((await mismatchWriter).status, 'quarantined');
  } finally {
    releaseWrite();
    fs.promises.rename = originalRename;
    syncBuiltinESMExports();
    await Promise.allSettled([exactWriter, ...(mismatchWriter ? [mismatchWriter] : [])]);
  }
  const finalState = await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key });
  assert.equal(finalState.status, 'quarantined');
  assert.equal(finalState.shadowQualified, false);
  assert.equal(finalState.prediction, null);
});

test('symlinked storage fails safely and cannot gain evidence authority', async () => {
  const root = projectRoot('symlink');
  const outside = projectRoot('symlink-outside');
  symlinkSync(outside, join(root, '.agent-ready-drupal'));
  const key = preflight();
  await assert.rejects(
    lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key }),
    /real directory/
  );
  const safeLookup = await lookupGlobalChromeShadowReuseSafely({ projectRoot: root, preflightKey: key });
  assert.equal(safeLookup.status, 'storage-error');
  assert.equal(safeLookup.shadowQualified, false);
  assert.deepEqual(safeLookup.authority, GLOBAL_CHROME_SHADOW_AUTHORITY);
  const safeRecord = await recordGlobalChromeShadowObservationSafely({
    projectRoot: root,
    preflightKey: key,
    capture: captured(),
    fresh: true,
    freshRunId: 'fresh-1',
    observabilityRecord: observabilityRecord(root, 'fresh-1', captured(), { persist: false }),
    preCapturePrediction: safeLookup
  });
  assert.equal(safeRecord.status, 'ineligible');
  assert.equal(safeRecord.authority.canAuthorizeCompletion, false);
  assert.deepEqual(readdirSync(outside), []);
});

test('hard-linked, oversized, and corrupt namespace files fail closed', async (t) => {
  await t.test('hard link', async () => {
    const root = projectRoot('hardlink');
    const key = preflight();
    await observe(root, key, captured(), 'fresh-1');
    linkSync(onlyStatePath(root), join(projectRoot('hardlink-outside'), 'linked-state.json'));
    const result = await lookupGlobalChromeShadowReuseSafely({ projectRoot: root, preflightKey: key });
    assert.equal(result.status, 'storage-error');
    assert.match(result.errors.join(' '), /single-link/);
  });

  await t.test('oversized', async () => {
    const root = projectRoot('oversized');
    const key = preflight();
    await observe(root, key, captured(), 'fresh-1');
    writeFileSync(onlyStatePath(root), 'x'.repeat(GLOBAL_CHROME_SHADOW_LIMITS.maxStateFileBytes + 1));
    const result = await lookupGlobalChromeShadowReuseSafely({ projectRoot: root, preflightKey: key });
    assert.equal(result.status, 'storage-error');
    assert.match(result.errors.join(' '), /byte limit/);
  });

  await t.test('corrupt JSON', async () => {
    const root = projectRoot('corrupt');
    const key = preflight();
    await observe(root, key, captured(), 'fresh-1');
    writeFileSync(onlyStatePath(root), '{not-json');
    const result = await lookupGlobalChromeShadowReuseSafely({ projectRoot: root, preflightKey: key });
    assert.equal(result.status, 'storage-error');
    assert.match(result.errors.join(' '), /corrupt/);
  });
});

test('storage refuses new namespaces at the fixed bound without evicting quarantine', async () => {
  const root = projectRoot('bounds');
  const key = preflight();
  const baseline = captured();
  await observe(root, key, baseline, 'fresh-1');
  const drift = structuredClone(baseline);
  drift.routes[0].screenshot.sha256 = digest('quarantine-before-cap');
  refingerprint(drift);
  await observe(root, key, drift, 'fresh-2');

  const directory = stateDirectory(root);
  const existing = new Set(readdirSync(directory));
  for (let index = 0; existing.size < GLOBAL_CHROME_SHADOW_LIMITS.maxNamespaces; index += 1) {
    const name = `${index.toString(16).padStart(64, '0')}.json`;
    if (existing.has(name)) continue;
    writeFileSync(join(directory, name), '{}\n');
    existing.add(name);
  }
  const otherKey = preflight({ drupalPreflightFingerprint: digest('bounded-new-preflight') });
  const otherCapture = captured({ resultStateFingerprint: digest('bounded-new-state') });
  const bounded = await recordGlobalChromeShadowObservationSafely({
    projectRoot: root,
    preflightKey: otherKey,
    capture: otherCapture,
    fresh: true,
    freshRunId: 'fresh-other',
    observabilityRecord: observabilityRecord(root, 'fresh-other', otherCapture),
    preCapturePrediction: await lookupGlobalChromeShadowReuse({
      projectRoot: root,
      preflightKey: otherKey
    })
  });
  assert.equal(bounded.status, 'storage-error');
  assert.match(bounded.errors.join(' '), /namespace limit/);

  const quarantined = await lookupGlobalChromeShadowReuse({ projectRoot: root, preflightKey: key });
  assert.equal(quarantined.status, 'quarantined');
  assert.equal(quarantined.shadowQualified, false);
});

test('artifact projection enforces its fixed entry bound', () => {
  const tooMany = captured();
  tooMany.routes = Array.from(
    { length: GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries + 1 },
    (_, index) => ({
      ...structuredClone(tooMany.routes[0]),
      path: `/route-${index}`
    })
  );
  assert.throws(() => projectGlobalChromeArtifacts(tooMany), /1-128/);
  assert.throws(() => projectGlobalChromeOutcome(tooMany), /128-entry/);
});
