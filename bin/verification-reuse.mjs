import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readdir, readFile, realpath, rename, rmdir, unlink, writeFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { canonicalJson, sha256 } from './state-fingerprint.mjs';
import { validateGlobalChromeCapture, verifierAxeCompletionErrors } from './global-chrome.mjs';

export const GLOBAL_CHROME_PREFLIGHT_KEY_SCHEMA = 'public-kit.global-chrome-preflight-key.1';
export const GLOBAL_CHROME_OUTCOME_PROJECTION_SCHEMA = 'public-kit.global-chrome-outcome-projection.1';
export const GLOBAL_CHROME_ARTIFACT_PROJECTION_SCHEMA = 'public-kit.global-chrome-artifact-projection.1';
export const GLOBAL_CHROME_SHADOW_OBSERVATION_SCHEMA = 'public-kit.global-chrome-shadow-observation.1';
export const GLOBAL_CHROME_SHADOW_STATE_SCHEMA = 'public-kit.global-chrome-shadow-state.1';
export const GLOBAL_CHROME_SHADOW_RESULT_SCHEMA = 'public-kit.global-chrome-shadow-result.1';
export const GLOBAL_CHROME_SHADOW_SUMMARY_SCHEMA = 'public-kit.global-chrome-shadow-summary.1';

export const GLOBAL_CHROME_SHADOW_AUTHORITY = Object.freeze({
  evidenceAuthority: 'none',
  diagnosticOnly: true,
  canAuthorizeCompletion: false
});

export const GLOBAL_CHROME_SHADOW_LIMITS = Object.freeze({
  maxArtifactEntries: 128,
  maxDependencyManifestBytes: 64 * 1024,
  maxNamespaces: 128,
  maxObservabilityRecordBytes: 1024 * 1024,
  maxObservedReportBytes: 16 * 1024 * 1024,
  maxProjectionBytes: 1024 * 1024,
  maxRecentObservationIds: 8,
  maxStateFileBytes: 64 * 1024
});

const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const RUN_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const LOCAL_STATE_DIRECTORY = '.agent-ready-drupal';
const LOCAL_STATE_OWNER_FILE = '.agent-ready-drupal-build-kit-owner';
const LOCAL_STATE_OWNER_TEXT = 'agent-ready-drupal-build-kit verification state v1\n';
const REUSE_DIRECTORY = 'global-chrome-shadow-reuse';
const REUSE_LOCK_DIRECTORY = `${REUSE_DIRECTORY}.lock`;
const REUSE_LOCK_OWNER_FILE = 'owner.json';
const REUSE_LOCK_OWNER_SCHEMA = 'public-kit.global-chrome-shadow-lock-owner.1';
const REUSE_LOCK_OWNER_MAX_BYTES = 1024;
const REUSE_LOCK_EMPTY_STALE_MS = 60_000;
const REUSE_LOCK_DEAD_PROCESS_GRACE_MS = 250;
const STATE_FILE_RE = /^[a-f0-9]{64}\.json$/;
const PREFLIGHT_DEPENDENCY_SCHEMA = 'public-kit.global-chrome-preflight-dependencies.1';
const ACTUAL_REUSE_BLOCKERS = Object.freeze([
  'External resource state is not captured before browser execution.',
  'Time and request-context variation are not captured by this key.',
  'Drupal cache metadata is not yet bound to this key.',
  'The final browser identity is only known after browser preflight.'
]);

function diagnosticResult(overrides = {}) {
  return {
    schemaVersion: GLOBAL_CHROME_SHADOW_RESULT_SCHEMA,
    authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
    status: 'missing',
    keyFingerprint: '',
    seeded: false,
    exactMatchCount: 0,
    shadowQualified: false,
    quarantined: false,
    prediction: null,
    actualReuseEligible: false,
    actualReuseBlockers: [...ACTUAL_REUSE_BLOCKERS],
    errors: [],
    ...overrides
  };
}

function boundedError(error) {
  const value = String(error?.message ?? error ?? 'Unknown shadow reuse error.');
  return Buffer.byteLength(value) <= 512
    ? value
    : `${Buffer.from(value).subarray(0, 509).toString('utf8').replace(/\uFFFD+$/u, '')}...`;
}

function normalizeHash(value, label, errors) {
  const hash = String(value ?? '').trim();
  if (!HASH_RE.test(hash)) errors.push(`${label} must be a sha256 fingerprint.`);
  return hash;
}

function normalizeTargetOrigin(value, errors) {
  const input = String(value ?? '').trim();
  if (!input) {
    errors.push('targetOrigin is required.');
    return '';
  }
  try {
    const url = new URL(input);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('unsupported protocol');
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
      throw new Error('targetOrigin must contain only an HTTP(S) origin');
    }
    return url.origin;
  } catch {
    errors.push('targetOrigin must be an HTTP(S) origin without credentials, path, query, or fragment.');
    return '';
  }
}

function normalizeRoute(value) {
  const text = String(value?.targetPath ?? value?.path ?? value ?? '').trim();
  if (!text.startsWith('/') || text.startsWith('//')) {
    throw new Error(`Global chrome route must be root-relative: ${text}`);
  }
  const url = new URL(text, 'https://global-chrome-shadow.invalid');
  if (url.hash) throw new Error(`Global chrome route must not contain a fragment: ${text}`);
  return `${url.pathname || '/'}${url.search}`;
}

function privacyPreservingRoute(value) {
  const route = normalizeRoute(value);
  const url = new URL(route, 'https://global-chrome-shadow.invalid');
  return `${url.pathname || '/'}${url.search
    ? `?query-sha256=${sha256(url.search).slice('sha256:'.length)}`
    : ''}`;
}

function captureHasAuthoritativeQueryPrivacy(capture) {
  return canonicalJson(capture?.queryPrivacy ?? null) === canonicalJson({
    schemaVersion: 'public-kit.query-privacy.1',
    method: 'sha256',
    authoritative: true
  });
}

function privacyPreservingCaptureRoute(value, capture) {
  const route = normalizeRoute(value);
  if (!captureHasAuthoritativeQueryPrivacy(capture)) return privacyPreservingRoute(route);
  const url = new URL(route, 'https://global-chrome-shadow.invalid');
  if (url.search && !/^\?query-sha256=[a-f0-9]{64}$/.test(url.search)) {
    throw new Error('Authoritatively privacy-bound global chrome routes must use the canonical query identity.');
  }
  return route;
}

function normalizeRoutes(values, errors) {
  if (!Array.isArray(values) || values.length === 0) {
    errors.push('primaryRoutes must contain at least one route.');
    return [];
  }
  if (values.length > GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries) {
    errors.push(`primaryRoutes exceeds the ${GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries}-route limit.`);
    return [];
  }
  try {
    return [...new Set(values.map(privacyPreservingRoute))].sort();
  } catch (error) {
    errors.push(error.message);
    return [];
  }
}

function normalizeAdditionalDependencies(value, errors) {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    errors.push('additionalDependencyFingerprints must be an object of sha256 fingerprints.');
    return {};
  }
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(key)) {
      errors.push(`additionalDependencyFingerprints has an invalid key: ${key}`);
      continue;
    }
    result[key] = normalizeHash(value[key], `additionalDependencyFingerprints.${key}`, errors);
  }
  return result;
}

/**
 * Build the canonical key used to compare fresh shadow observations. Eligibility
 * here means shadow-prediction eligibility only; it never authorizes actual reuse.
 */
export function buildGlobalChromePreflightKey(input = {}) {
  const errors = [];
  const manifest = {
    schemaVersion: PREFLIGHT_DEPENDENCY_SCHEMA,
    drupalPreflightFingerprint: normalizeHash(
      input.drupalPreflightFingerprint,
      'drupalPreflightFingerprint',
      errors
    ),
    runtimeEnvironmentFingerprint: normalizeHash(
      input.runtimeEnvironmentFingerprint,
      'runtimeEnvironmentFingerprint',
      errors
    ),
    browserRuntimeFingerprint: normalizeHash(
      input.browserRuntimeFingerprint,
      'browserRuntimeFingerprint',
      errors
    ),
    captureImplementationFingerprint: normalizeHash(
      input.captureImplementationFingerprint,
      'captureImplementationFingerprint',
      errors
    ),
    contractFingerprint: normalizeHash(input.contractFingerprint, 'contractFingerprint', errors),
    targetOriginFingerprint: (() => {
      const origin = normalizeTargetOrigin(input.targetOrigin, errors);
      return origin ? sha256(origin) : '';
    })(),
    primaryRoutes: normalizeRoutes(input.primaryRoutes, errors),
    additionalDependencyFingerprints: normalizeAdditionalDependencies(
      input.additionalDependencyFingerprints,
      errors
    )
  };
  let encoded = '';
  try {
    encoded = canonicalJson(manifest);
    if (Buffer.byteLength(encoded) > GLOBAL_CHROME_SHADOW_LIMITS.maxDependencyManifestBytes) {
      errors.push(
        `Global chrome dependency manifest exceeds ${GLOBAL_CHROME_SHADOW_LIMITS.maxDependencyManifestBytes} bytes.`
      );
    }
  } catch (error) {
    errors.push(`Global chrome dependency manifest is not canonicalizable: ${error.message}`);
  }
  const eligible = errors.length === 0;
  return {
    schemaVersion: GLOBAL_CHROME_PREFLIGHT_KEY_SCHEMA,
    authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
    eligible,
    actualReuseEligible: false,
    actualReuseBlockers: [...ACTUAL_REUSE_BLOCKERS],
    fingerprint: eligible ? sha256(manifest) : '',
    manifest: eligible ? manifest : null,
    errors
  };
}

function validatedPreflightKey(value) {
  if (
    !value ||
    value.schemaVersion !== GLOBAL_CHROME_PREFLIGHT_KEY_SCHEMA ||
    value.eligible !== true ||
    !HASH_RE.test(String(value.fingerprint ?? '')) ||
    !value.manifest ||
    sha256(value.manifest) !== value.fingerprint
  ) {
    throw new Error('Global chrome shadow reuse requires an eligible, untampered preflight key.');
  }
  const manifest = value.manifest;
  const manifestKeys = [
    'additionalDependencyFingerprints',
    'browserRuntimeFingerprint',
    'captureImplementationFingerprint',
    'contractFingerprint',
    'drupalPreflightFingerprint',
    'primaryRoutes',
    'runtimeEnvironmentFingerprint',
    'schemaVersion',
    'targetOriginFingerprint'
  ];
  const hashes = [
    manifest.browserRuntimeFingerprint,
    manifest.captureImplementationFingerprint,
    manifest.contractFingerprint,
    manifest.drupalPreflightFingerprint,
    manifest.runtimeEnvironmentFingerprint,
    manifest.targetOriginFingerprint,
    ...Object.values(manifest.additionalDependencyFingerprints ?? {})
  ];
  const routes = Array.isArray(manifest.primaryRoutes) ? manifest.primaryRoutes : [];
  if (
    !sameCanonical(Object.keys(manifest).sort(), manifestKeys) ||
    manifest.schemaVersion !== PREFLIGHT_DEPENDENCY_SCHEMA ||
    hashes.some((hash) => !HASH_RE.test(String(hash ?? ''))) ||
    !manifest.additionalDependencyFingerprints ||
    typeof manifest.additionalDependencyFingerprints !== 'object' ||
    Array.isArray(manifest.additionalDependencyFingerprints) ||
    Object.keys(manifest.additionalDependencyFingerprints).some((key) => !/^[a-z][a-z0-9-]{0,63}$/.test(key)) ||
    routes.length === 0 ||
    routes.length > GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries ||
    !sameCanonical(routes, [...new Set(routes)].sort()) ||
    routes.some((route) => !/^\/(?:[^?#]*)(?:\?query-sha256=[a-f0-9]{64})?$/.test(String(route))) ||
    Buffer.byteLength(canonicalJson(manifest)) > GLOBAL_CHROME_SHADOW_LIMITS.maxDependencyManifestBytes
  ) {
    throw new Error('Global chrome preflight dependency manifest is invalid.');
  }
  return value;
}

function normalizedViewport(viewport = {}) {
  const name = String(viewport.name ?? '').trim();
  const width = Number(viewport.width);
  const height = Number(viewport.height);
  if (!name || !Number.isSafeInteger(width) || width <= 0 || !Number.isSafeInteger(height) || height <= 0) {
    throw new Error('Global chrome route viewport requires a name and positive integer dimensions.');
  }
  return { name, width, height };
}

function routeIdentity(route) {
  const path = normalizeRoute(route?.path);
  const viewport = normalizedViewport(route?.viewport);
  return { key: `${path}\0${viewport.name}`, path, viewport };
}

function projectSemanticAxe(axe) {
  if (!axe || typeof axe !== 'object') return null;
  return {
    schemaVersion: String(axe.schemaVersion ?? ''),
    status: String(axe.status ?? ''),
    source: axe.source ?? null,
    ruleScope: axe.ruleScope ?? null,
    summary: axe.summary ?? null,
    errors: Array.isArray(axe.errors) ? axe.errors.map(String) : []
  };
}

function projectionWithinLimit(projection, label) {
  const bytes = Buffer.byteLength(canonicalJson(projection));
  if (bytes > GLOBAL_CHROME_SHADOW_LIMITS.maxProjectionBytes) {
    throw new Error(`${label} exceeds its ${GLOBAL_CHROME_SHADOW_LIMITS.maxProjectionBytes}-byte limit.`);
  }
  return projection;
}

/**
 * Project completion-relevant semantics while discarding known volatility and
 * all screenshot/axe report payload or artifact fields.
 */
export function projectGlobalChromeOutcome(capture = {}) {
  if (!capture || typeof capture !== 'object' || Array.isArray(capture)) {
    throw new Error('Global chrome outcome projection requires a capture object.');
  }
  const routeValues = Array.isArray(capture.routes) ? capture.routes : [];
  if (routeValues.length > GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries) {
    throw new Error(`Global chrome capture exceeds the ${GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries}-entry limit.`);
  }
  const seen = new Set();
  const routes = routeValues.map((route) => {
    const identity = routeIdentity(route);
    if (seen.has(identity.key)) throw new Error(`Global chrome capture duplicates ${identity.path} ${identity.viewport.name}.`);
    seen.add(identity.key);
    return {
      path: identity.path,
      viewport: identity.viewport,
      signals: route?.signals ?? null,
      axe: projectSemanticAxe(route?.axe)
    };
  }).sort((left, right) => `${left.path}\0${left.viewport.name}`.localeCompare(`${right.path}\0${right.viewport.name}`));
  const budget = capture.budget && typeof capture.budget === 'object'
    ? {
        attempted: capture.budget.attempted === true,
        capturedRouteViewportCount: Number(capture.budget.capturedRouteViewportCount ?? 0),
        deadlineExceeded: capture.budget.deadlineExceeded === true,
        deadlineMs: Number(capture.budget.deadlineMs ?? 0),
        maxRoutes: Number(capture.budget.maxRoutes ?? 0),
        operationTimeoutMs: Number(capture.budget.operationTimeoutMs ?? 0),
        routeCount: Number(capture.budget.routeCount ?? 0),
        scheduledRouteViewportCount: Number(capture.budget.scheduledRouteViewportCount ?? 0),
        viewportCount: Number(capture.budget.viewportCount ?? 0)
      }
    : null;
  return projectionWithinLimit({
    schemaVersion: GLOBAL_CHROME_OUTCOME_PROJECTION_SCHEMA,
    captureSchemaVersion: String(capture.schemaVersion ?? ''),
    status: String(capture.status ?? ''),
    authoritative: capture.authoritative === true,
    captureMode: String(capture.captureMode ?? ''),
    targetOrigin: String(capture.targetOrigin ?? ''),
    resultStateFingerprint: String(capture.resultStateFingerprint ?? ''),
    contractFingerprint: String(capture.contract?.fingerprint ?? ''),
    browser: {
      product: String(capture.browser?.product ?? '')
    },
    runtime: capture.runtime && typeof capture.runtime === 'object'
      ? {
          backend: String(capture.runtime.backend ?? ''),
          executionBoundary: String(capture.runtime.executionBoundary ?? ''),
          service: String(capture.runtime.service ?? ''),
          addOnRelease: String(capture.runtime.addOnRelease ?? ''),
          image: String(capture.runtime.image ?? ''),
          executable: String(capture.runtime.executable ?? ''),
          product: String(capture.runtime.product ?? ''),
          protocolVersion: String(capture.runtime.protocolVersion ?? ''),
          ready: capture.runtime.ready === true
        }
      : null,
    primaryRoutes: [...new Set((Array.isArray(capture.primaryRoutes) ? capture.primaryRoutes : []).map(normalizeRoute))].sort(),
    budget,
    routes,
    warnings: Array.isArray(capture.warnings) ? capture.warnings.map(String) : [],
    errors: Array.isArray(capture.errors) ? capture.errors.map(String) : []
  }, 'Global chrome outcome projection');
}

function artifactDescriptor(route, capture) {
  const identity = routeIdentity(route);
  const screenshot = route?.screenshot;
  if (
    !screenshot ||
    !HASH_RE.test(String(screenshot.sha256 ?? '')) ||
    !Number.isSafeInteger(screenshot.size) ||
    screenshot.size <= 0
  ) {
    throw new Error(`Global chrome ${identity.path} ${identity.viewport.name} lacks a screenshot digest and size.`);
  }
  const width = Number(screenshot.width);
  const height = Number(screenshot.height);
  if (!Number.isSafeInteger(width) || width <= 0 || !Number.isSafeInteger(height) || height <= 0) {
    throw new Error(`Global chrome ${identity.path} ${identity.viewport.name} screenshot dimensions are invalid.`);
  }
  return {
    path: privacyPreservingCaptureRoute(identity.path, capture),
    viewport: identity.viewport,
    screenshot: {
      sha256: screenshot.sha256,
      size: screenshot.size,
      width,
      height,
      clipped: screenshot.clipped === true
    }
  };
}

/** Project only stable artifact manifests; paths and result payloads are absent. */
export function projectGlobalChromeArtifacts(capture = {}) {
  const routeValues = Array.isArray(capture?.routes) ? capture.routes : [];
  if (routeValues.length === 0 || routeValues.length > GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries) {
    throw new Error(
      `Global chrome artifact projection requires 1-${GLOBAL_CHROME_SHADOW_LIMITS.maxArtifactEntries} route/viewports.`
    );
  }
  const routes = routeValues.map((route) => artifactDescriptor(route, capture))
    .sort((left, right) => `${left.path}\0${left.viewport.name}`.localeCompare(`${right.path}\0${right.viewport.name}`));
  const identities = routes.map((route) => `${route.path}\0${route.viewport.name}`);
  if (new Set(identities).size !== identities.length) {
    throw new Error('Global chrome artifact projection contains a duplicate route/viewport.');
  }
  return projectionWithinLimit({
    schemaVersion: GLOBAL_CHROME_ARTIFACT_PROJECTION_SCHEMA,
    routes
  }, 'Global chrome artifact projection');
}

function sameCanonical(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export function buildGlobalChromeShadowObservation({ preflightKey, capture } = {}) {
  let key;
  try {
    key = validatedPreflightKey(preflightKey);
  } catch (error) {
    return {
      schemaVersion: GLOBAL_CHROME_SHADOW_OBSERVATION_SCHEMA,
      authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
      eligible: false,
      keyFingerprint: '',
      errors: [error.message]
    };
  }
  const errors = [];
  try {
    validateGlobalChromeCapture(capture, {
      stateFingerprint: String(capture?.resultStateFingerprint ?? ''),
      requireAuthoritative: true
    });
    errors.push(...verifierAxeCompletionErrors(capture));
  } catch (error) {
    errors.push(`Only a strict final verifier-owned capture can train the shadow predictor: ${error.message}`);
  }
  if (!HASH_RE.test(String(capture?.resultStateFingerprint ?? ''))) {
    errors.push('Global chrome capture lacks a final result-state fingerprint.');
  }
  const captureOriginErrors = [];
  const captureOrigin = normalizeTargetOrigin(capture?.targetOrigin, captureOriginErrors);
  if (
    captureOriginErrors.length > 0 ||
    !captureOrigin ||
    sha256(captureOrigin) !== key.manifest.targetOriginFingerprint
  ) errors.push('Global chrome target origin does not match the preflight dependency key.');
  if (String(capture?.contract?.fingerprint ?? '') !== key.manifest.contractFingerprint) {
    errors.push('Global chrome contract fingerprint does not match the preflight dependency key.');
  }
  try {
    const observedRoutes = [...new Set(
      (capture?.primaryRoutes ?? []).map((route) => privacyPreservingCaptureRoute(route, capture))
    )].sort();
    if (!sameCanonical(observedRoutes, key.manifest.primaryRoutes)) {
      errors.push('Global chrome route coverage does not match the preflight dependency key.');
    }
  } catch (error) {
    errors.push(error.message);
  }
  let outcomeProjection;
  let artifactProjection;
  try {
    outcomeProjection = projectGlobalChromeOutcome(capture);
    artifactProjection = projectGlobalChromeArtifacts(capture);
  } catch (error) {
    errors.push(error.message);
  }
  if (errors.length > 0) {
    return {
      schemaVersion: GLOBAL_CHROME_SHADOW_OBSERVATION_SCHEMA,
      authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
      eligible: false,
      keyFingerprint: key.fingerprint,
      errors
    };
  }
  return {
    schemaVersion: GLOBAL_CHROME_SHADOW_OBSERVATION_SCHEMA,
    authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
    eligible: true,
    keyFingerprint: key.fingerprint,
    outcomeFingerprint: sha256(outcomeProjection),
    artifactFingerprint: sha256(artifactProjection),
    artifactManifest: artifactProjection,
    errors: []
  };
}

function portableReportPath(value) {
  const path = String(value ?? '').trim();
  const segments = path.split('/');
  if (
    !path ||
    Buffer.byteLength(path) > 512 ||
    path.startsWith('/') ||
    path.includes('\\') ||
    path.includes('?') ||
    path.includes('#') ||
    path.includes('\0') ||
    segments.some((segment) => !segment || segment === '.' || segment === '..')
  ) throw new Error('Observed report path must be a bounded project-relative portable path.');
  return path;
}

function normalizeObservabilityBinding(record, freshRunId) {
  if (
    !record ||
    record.schemaVersion !== 'public-kit.verification-observability.1' ||
    !sameCanonical(record.authority, GLOBAL_CHROME_SHADOW_AUTHORITY) ||
    record.command?.status !== 'completed' ||
    String(record.runId ?? '') !== freshRunId
  ) {
    throw new Error('Shadow training requires the completed observability record from the same verifier run.');
  }
  const observedReport = record.observedReport;
  if (
    observedReport?.available !== true ||
    observedReport?.persisted !== true ||
    !HASH_RE.test(String(observedReport?.sha256 ?? '')) ||
    !Number.isSafeInteger(observedReport?.bytes) ||
    observedReport.bytes <= 0 ||
    observedReport.bytes > GLOBAL_CHROME_SHADOW_LIMITS.maxObservedReportBytes
  ) throw new Error('Shadow training requires an exact persisted observed-report binding.');
  const reportPath = portableReportPath(observedReport.path);
  const phases = Array.isArray(record.timing?.phases)
    ? record.timing.phases.filter((phase) => phase?.id === 'global-chrome')
    : [];
  if (
    record.timing?.schemaVersion !== 'public-kit.verification-phase-timing.1' ||
    phases.length !== 1 ||
    phases[0].status !== 'completed' ||
    phases[0].details?.attempted !== true
  ) throw new Error('Shadow training requires one completed, attempted global-chrome phase from the same verifier run.');
  const phase = phases[0];
  const startOffsetMs = Number(phase.startOffsetMs);
  const endOffsetMs = Number(phase.endOffsetMs);
  const durationMs = Number(phase.durationMs);
  if (
    ![startOffsetMs, endOffsetMs, durationMs].every(Number.isFinite) ||
    startOffsetMs < 0 ||
    endOffsetMs < startOffsetMs ||
    durationMs < 0 ||
    Math.abs((endOffsetMs - startOffsetMs) - durationMs) > 0.01
  ) throw new Error('Global chrome phase timing is invalid.');
  return {
    runId: freshRunId,
    observedReport: {
      sha256: observedReport.sha256,
      bytes: observedReport.bytes,
      path: reportPath
    },
    globalChromePhase: {
      status: 'completed',
      attempted: true,
      startOffsetMs,
      endOffsetMs,
      durationMs
    },
    freshGlobalChromePhaseMs: durationMs
  };
}

async function verifyPersistedObservedReport(projectRoot, binding) {
  const project = resolve(projectRoot);
  const path = resolve(project, ...binding.observedReport.path.split('/'));
  if (!pathIsInside(project, path)) throw new Error('Observed report path escaped the project root.');
  const metadata = await safeMetadata(path, { maxBytes: GLOBAL_CHROME_SHADOW_LIMITS.maxObservedReportBytes });
  if (!metadata) throw new Error('The observability-bound report is no longer persisted.');
  const [realProject, realReport] = await Promise.all([realpath(project), realpath(path)]);
  if (!pathIsInside(realProject, realReport)) {
    throw new Error('The observability-bound report resolves outside the project root.');
  }
  const bytes = await readFile(path);
  if (
    bytes.length !== binding.observedReport.bytes ||
    sha256(bytes) !== binding.observedReport.sha256
  ) throw new Error('The persisted report bytes do not match their observability binding.');
  let report;
  try {
    report = JSON.parse(bytes);
  } catch (error) {
    throw new Error(`The observability-bound report is not valid JSON: ${error.message}`);
  }
  if (
    report?.schemaVersion !== 'public-kit.live-verification.2' ||
    report?.buildState?.complete !== true ||
    !HASH_RE.test(String(report?.buildState?.fingerprint ?? '')) ||
    report?.globalChromeCapture?.resultStateFingerprint !== report.buildState.fingerprint
  ) {
    throw new Error('Shadow training requires a complete state-bound live-verification report.');
  }
  return report;
}

async function requireRealDirectory(path, label) {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a real directory.`);
  }
}

async function verifyPersistedObservabilityRecord(projectRoot, record) {
  const project = resolve(projectRoot);
  const root = join(project, LOCAL_STATE_DIRECTORY);
  const metrics = join(root, 'verification-metrics');
  const runs = join(metrics, 'runs');
  await requireRealDirectory(project, 'Shadow-training project root');
  await requireRealDirectory(root, 'Project-local verification state root');
  await requireRealDirectory(metrics, 'Verification metrics directory');
  await requireRealDirectory(runs, 'Verification metrics run directory');
  const ownerPath = join(root, LOCAL_STATE_OWNER_FILE);
  const ownerMetadata = await safeMetadata(ownerPath, { maxBytes: Buffer.byteLength(LOCAL_STATE_OWNER_TEXT) });
  if (!ownerMetadata || await readFile(ownerPath, 'utf8') !== LOCAL_STATE_OWNER_TEXT) {
    throw new Error('The project-local verification state ownership marker is invalid.');
  }
  const ignorePath = join(root, '.gitignore');
  const ignoreMetadata = await safeMetadata(ignorePath, { maxBytes: 2 });
  if (!ignoreMetadata || await readFile(ignorePath, 'utf8') !== '*\n') {
    throw new Error('The project-local verification ignore marker is invalid.');
  }
  const runPath = join(runs, `${record.runId}.json`);
  const runMetadata = await safeMetadata(runPath, {
    maxBytes: GLOBAL_CHROME_SHADOW_LIMITS.maxObservabilityRecordBytes
  });
  if (!runMetadata) throw new Error('The same-run observability record is not persisted.');
  let persisted;
  try {
    persisted = JSON.parse(await readFile(runPath, 'utf8'));
  } catch (error) {
    throw new Error(`The persisted observability record is invalid: ${error.message}`);
  }
  if (!sameCanonical(persisted, record)) {
    throw new Error('The supplied observability record does not match its exact persisted same-run record.');
  }
}

function pathIsInside(parent, child) {
  const relation = relative(parent, child);
  return relation === '' || (
    relation !== '..' &&
    !relation.startsWith(`..${sep}`) &&
    !isAbsolute(relation)
  );
}

async function safeMetadata(path, { maxBytes = Infinity } = {}) {
  try {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
      throw new Error('Global chrome shadow state files must be single-link regular files.');
    }
    if (metadata.size > maxBytes) {
      throw new Error(`Global chrome shadow state file exceeds its ${maxBytes}-byte limit.`);
    }
    return metadata;
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function ensureOwnedStateDirectory(projectRoot) {
  const project = resolve(projectRoot);
  const projectMetadata = await lstat(project);
  if (projectMetadata.isSymbolicLink() || !projectMetadata.isDirectory()) {
    throw new Error('Global chrome shadow reuse requires a real project directory.');
  }
  const root = join(project, LOCAL_STATE_DIRECTORY);
  const rootMetadata = await lstat(root);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
    throw new Error('The project-local verification state root must be a real directory.');
  }
  const ownerPath = join(root, LOCAL_STATE_OWNER_FILE);
  const ownerMetadata = await safeMetadata(ownerPath, { maxBytes: Buffer.byteLength(LOCAL_STATE_OWNER_TEXT) });
  if (!ownerMetadata || await readFile(ownerPath, 'utf8') !== LOCAL_STATE_OWNER_TEXT) {
    throw new Error('The project-local verification state ownership marker is invalid.');
  }
  const ignorePath = join(root, '.gitignore');
  const ignoreMetadata = await safeMetadata(ignorePath, { maxBytes: 2 });
  if (!ignoreMetadata) {
    await writeTextAtomic(ignorePath, '*\n');
  } else if (await readFile(ignorePath, 'utf8') !== '*\n') {
    throw new Error('The project-local verification ignore marker is non-canonical.');
  }
  const directory = join(root, REUSE_DIRECTORY);
  if (!pathIsInside(root, directory)) throw new Error('Global chrome shadow state escaped its local state root.');
  try {
    const metadata = await lstat(directory);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error('Global chrome shadow reuse state must be a real directory.');
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    try {
      await mkdir(directory, { mode: 0o700 });
    } catch (mkdirError) {
      if (mkdirError?.code !== 'EEXIST') throw mkdirError;
      const metadata = await lstat(directory);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error('Global chrome shadow reuse state must be a real directory.');
      }
    }
  }
  return directory;
}

async function existingOwnedStateDirectory(projectRoot) {
  const project = resolve(projectRoot);
  const projectMetadata = await lstat(project);
  if (projectMetadata.isSymbolicLink() || !projectMetadata.isDirectory()) {
    throw new Error('Global chrome shadow reuse requires a real project directory.');
  }
  const root = join(project, LOCAL_STATE_DIRECTORY);
  try {
    const metadata = await lstat(root);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error('The project-local verification state root must be a real directory.');
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  const ownerPath = join(root, LOCAL_STATE_OWNER_FILE);
  const ownerMetadata = await safeMetadata(ownerPath, { maxBytes: Buffer.byteLength(LOCAL_STATE_OWNER_TEXT) });
  if (!ownerMetadata || await readFile(ownerPath, 'utf8') !== LOCAL_STATE_OWNER_TEXT) {
    throw new Error('The project-local verification state ownership marker is invalid.');
  }
  const ignorePath = join(root, '.gitignore');
  const ignoreMetadata = await safeMetadata(ignorePath, { maxBytes: 2 });
  if (!ignoreMetadata || await readFile(ignorePath, 'utf8') !== '*\n') {
    throw new Error('The project-local verification ignore marker is invalid.');
  }
  const directory = join(root, REUSE_DIRECTORY);
  try {
    const metadata = await lstat(directory);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error('Global chrome shadow reuse state must be a real directory.');
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  return directory;
}

async function writeTextAtomic(path, value) {
  if (Buffer.byteLength(value) > GLOBAL_CHROME_SHADOW_LIMITS.maxStateFileBytes) {
    throw new Error(`Global chrome shadow state exceeds its ${GLOBAL_CHROME_SHADOW_LIMITS.maxStateFileBytes}-byte limit.`);
  }
  await safeMetadata(path, { maxBytes: GLOBAL_CHROME_SHADOW_LIMITS.maxStateFileBytes });
  const temporary = join(resolve(path, '..'), `.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, value, { flag: 'wx', mode: 0o600 });
    await rename(temporary, path);
  } catch (error) {
    try {
      const metadata = await lstat(temporary);
      if (metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1) await unlink(temporary);
    } catch {}
    throw error;
  }
}

async function stateFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !STATE_FILE_RE.test(entry.name)) {
      throw new Error('Global chrome shadow state directory contains an unexpected entry.');
    }
  }
  if (entries.length > GLOBAL_CHROME_SHADOW_LIMITS.maxNamespaces) {
    throw new Error(`Global chrome shadow state exceeds its ${GLOBAL_CHROME_SHADOW_LIMITS.maxNamespaces}-namespace limit.`);
  }
  return entries.map((entry) => entry.name).sort();
}

function lockHostFingerprint() {
  return sha256(hostname());
}

function newLockOwner() {
  return {
    schemaVersion: REUSE_LOCK_OWNER_SCHEMA,
    token: randomUUID(),
    pid: process.pid,
    hostFingerprint: lockHostFingerprint(),
    acquiredAt: new Date().toISOString()
  };
}

function validateLockOwner(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !sameCanonical(Object.keys(value).sort(), [
      'acquiredAt',
      'hostFingerprint',
      'pid',
      'schemaVersion',
      'token'
    ]) ||
    value.schemaVersion !== REUSE_LOCK_OWNER_SCHEMA ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value.token ?? '')) ||
    !Number.isSafeInteger(value.pid) ||
    value.pid <= 0 ||
    !HASH_RE.test(String(value.hostFingerprint ?? '')) ||
    !Number.isFinite(Date.parse(value.acquiredAt))
  ) {
    throw new Error('Global chrome shadow state lock owner is invalid.');
  }
  return value;
}

async function inspectGlobalStateLock(lockPath) {
  let metadata;
  try {
    metadata = await lstat(lockPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error('Global chrome shadow state lock must be a real directory.');
  }
  const entries = await readdir(lockPath, { withFileTypes: true });
  if (entries.length === 0) return { metadata, owner: null };
  if (
    entries.length !== 1 ||
    entries[0].name !== REUSE_LOCK_OWNER_FILE ||
    !entries[0].isFile()
  ) {
    throw new Error('Global chrome shadow state lock contains unexpected entries.');
  }
  const ownerPath = join(lockPath, REUSE_LOCK_OWNER_FILE);
  const ownerMetadata = await safeMetadata(ownerPath, { maxBytes: REUSE_LOCK_OWNER_MAX_BYTES });
  if (!ownerMetadata) throw new Error('Global chrome shadow state lock owner disappeared.');
  let owner;
  try {
    owner = validateLockOwner(JSON.parse(await readFile(ownerPath, 'utf8')));
  } catch (error) {
    throw new Error(`Global chrome shadow state lock owner is invalid: ${error.message}`);
  }
  return { metadata, owner };
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

async function recoverAbandonedGlobalStateLock(lockPath, inspected) {
  const current = await inspectGlobalStateLock(lockPath);
  if (!current) return true;
  if (!sameCanonical(current.owner, inspected.owner)) return false;
  if (current.owner) await unlink(join(lockPath, REUSE_LOCK_OWNER_FILE));
  try {
    await rmdir(lockPath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return true;
}

async function withGlobalStateLock(directory, operation) {
  const lockPath = join(dirname(directory), REUSE_LOCK_DIRECTORY);
  let acquiredOwner = null;
  try {
    for (let attempt = 0; attempt < 200 && !acquiredOwner; attempt += 1) {
      try {
        await mkdir(lockPath, { mode: 0o700 });
        const owner = newLockOwner();
        try {
          await writeFile(
            join(lockPath, REUSE_LOCK_OWNER_FILE),
            `${JSON.stringify(owner)}\n`,
            { flag: 'wx', mode: 0o600 }
          );
        } catch (error) {
          try { await rmdir(lockPath); } catch {}
          throw error;
        }
        acquiredOwner = owner;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
        const inspected = await inspectGlobalStateLock(lockPath);
        if (!inspected) continue;
        const now = Date.now();
        const directoryAgeMs = Math.max(0, now - inspected.metadata.mtimeMs);
        const ownerAgeMs = inspected.owner
          ? Math.max(0, now - Date.parse(inspected.owner.acquiredAt))
          : directoryAgeMs;
        const emptyLockAbandoned = !inspected.owner && directoryAgeMs >= REUSE_LOCK_EMPTY_STALE_MS;
        const deadOwnerAbandoned = Boolean(
          inspected.owner &&
          inspected.owner.hostFingerprint === lockHostFingerprint() &&
          ownerAgeMs >= REUSE_LOCK_DEAD_PROCESS_GRACE_MS &&
          !processIsAlive(inspected.owner.pid)
        );
        if (
          (emptyLockAbandoned || deadOwnerAbandoned) &&
          await recoverAbandonedGlobalStateLock(lockPath, inspected)
        ) {
          continue;
        }
        if (attempt === 199) {
          throw new Error(
            'Another global chrome shadow state update did not release its lock. ' +
            'Confirm no verifier process is active before manually removing the local lock directory.'
          );
        }
        await delay(25);
      }
    }
    const inspected = await inspectGlobalStateLock(lockPath);
    if (!inspected?.owner || !sameCanonical(inspected.owner, acquiredOwner)) {
      throw new Error('Global chrome shadow state lock ownership changed before the update.');
    }
    return await operation();
  } finally {
    if (acquiredOwner) {
      const inspected = await inspectGlobalStateLock(lockPath);
      if (!inspected?.owner || !sameCanonical(inspected.owner, acquiredOwner)) {
        throw new Error('Global chrome shadow state lock ownership changed before release.');
      }
      await unlink(join(lockPath, REUSE_LOCK_OWNER_FILE));
      await rmdir(lockPath);
    }
  }
}

function statePath(directory, keyFingerprint) {
  if (!HASH_RE.test(keyFingerprint)) throw new Error('Global chrome shadow key fingerprint is invalid.');
  return join(directory, `${keyFingerprint.slice('sha256:'.length)}.json`);
}

function storedPredictionSnapshotValid(value, expectedPrediction) {
  if (
    !value ||
    !sameCanonical(Object.keys(value).sort(), [
      'exactMatchCount',
      'prediction',
      'quarantined',
      'shadowQualified',
      'status'
    ]) ||
    !['missing', 'tracking', 'shadow-qualified', 'quarantined'].includes(value.status) ||
    !Number.isSafeInteger(value.exactMatchCount) ||
    value.exactMatchCount < 0 ||
    value.exactMatchCount > 2 ||
    typeof value.shadowQualified !== 'boolean' ||
    typeof value.quarantined !== 'boolean'
  ) return false;
  const hasExpectedPrediction = sameCanonical(value.prediction, expectedPrediction);
  return (
    (value.status === 'missing' &&
      value.exactMatchCount === 0 &&
      !value.shadowQualified &&
      !value.quarantined &&
      value.prediction === null) ||
    (value.status === 'tracking' &&
      value.exactMatchCount < 2 &&
      !value.shadowQualified &&
      !value.quarantined &&
      hasExpectedPrediction) ||
    (value.status === 'shadow-qualified' &&
      value.exactMatchCount === 2 &&
      value.shadowQualified &&
      !value.quarantined &&
      hasExpectedPrediction) ||
    (value.status === 'quarantined' &&
      !value.shadowQualified &&
      value.quarantined &&
      value.prediction === null)
  );
}

function validateStoredState(state, key) {
  const expectedTopLevel = [
    'authority',
    'createdAt',
    'exactMatchCount',
    'expected',
    'keyFingerprint',
    'preflightManifest',
    'quarantine',
    'recentObservations',
    'schemaVersion',
    'status',
    'updatedAt'
  ];
  const recent = Array.isArray(state?.recentObservations) ? state.recentObservations : [];
  if (
    !state ||
    typeof state !== 'object' ||
    Array.isArray(state) ||
    !sameCanonical(Object.keys(state).sort(), expectedTopLevel) ||
    state.schemaVersion !== GLOBAL_CHROME_SHADOW_STATE_SCHEMA ||
    !sameCanonical(state.authority, GLOBAL_CHROME_SHADOW_AUTHORITY) ||
    state.keyFingerprint !== key.fingerprint ||
    !sameCanonical(state.preflightManifest, key.manifest) ||
    !['tracking', 'shadow-qualified', 'quarantined'].includes(state.status) ||
    !Number.isSafeInteger(state.exactMatchCount) ||
    state.exactMatchCount < 0 ||
    state.exactMatchCount > 2 ||
    recent.length === 0 ||
    recent.length > GLOBAL_CHROME_SHADOW_LIMITS.maxRecentObservationIds ||
    new Set(recent.map((entry) => entry?.runId)).size !== recent.length ||
    recent.some((entry) => (
      !entry ||
      !sameCanonical(Object.keys(entry).sort(), [
        'classification',
        'freshGlobalChromePhaseMs',
        'globalChromePhase',
        'observedArtifactFingerprint',
        'observedOutcomeFingerprint',
        'observedReport',
        'potentialAvoidablePhaseMs',
        'preCapture',
        'runId'
      ]) ||
      !RUN_ID_RE.test(String(entry.runId)) ||
      !['seed', 'exact-match', 'shadow-qualified', 'mismatch'].includes(entry.classification) ||
      !HASH_RE.test(String(entry.observedOutcomeFingerprint ?? '')) ||
      !HASH_RE.test(String(entry.observedArtifactFingerprint ?? '')) ||
      !HASH_RE.test(String(entry.observedReport?.sha256 ?? '')) ||
      !Number.isSafeInteger(entry.observedReport?.bytes) ||
      entry.observedReport.bytes <= 0 ||
      entry.observedReport.bytes > GLOBAL_CHROME_SHADOW_LIMITS.maxObservedReportBytes ||
      portableReportPath(entry.observedReport?.path) !== entry.observedReport.path ||
      entry.globalChromePhase?.status !== 'completed' ||
      entry.globalChromePhase?.attempted !== true ||
      !Number.isFinite(entry.globalChromePhase?.startOffsetMs) ||
      entry.globalChromePhase.startOffsetMs < 0 ||
      !Number.isFinite(entry.globalChromePhase?.endOffsetMs) ||
      entry.globalChromePhase.endOffsetMs < entry.globalChromePhase.startOffsetMs ||
      !Number.isFinite(entry.globalChromePhase?.durationMs) ||
      entry.globalChromePhase.durationMs < 0 ||
      Math.abs(
        (entry.globalChromePhase.endOffsetMs - entry.globalChromePhase.startOffsetMs) -
        entry.globalChromePhase.durationMs
      ) > 0.01 ||
      !Number.isFinite(entry.freshGlobalChromePhaseMs) ||
      entry.freshGlobalChromePhaseMs !== entry.globalChromePhase.durationMs ||
      !Number.isFinite(entry.potentialAvoidablePhaseMs) ||
      ![0, entry.freshGlobalChromePhaseMs].includes(entry.potentialAvoidablePhaseMs) ||
      !entry.preCapture ||
      !sameCanonical(Object.keys(entry.preCapture).sort(), [
        'exactMatchCount',
        'prediction',
        'quarantined',
        'shadowQualified',
        'status'
      ])
    ))
  ) {
    throw new Error('Global chrome shadow state is invalid or does not match its dependency key.');
  }
  if (
    !state.expected ||
    !HASH_RE.test(String(state.expected.outcomeFingerprint ?? '')) ||
    !HASH_RE.test(String(state.expected.artifactFingerprint ?? '')) ||
    sha256(state.expected.artifactManifest) !== state.expected.artifactFingerprint
  ) {
    throw new Error('Global chrome shadow state has an invalid fingerprint-only prediction.');
  }
  if (state.status === 'tracking' && state.exactMatchCount >= 2) {
    throw new Error('Global chrome shadow tracking state has an invalid match count.');
  }
  if (state.status === 'shadow-qualified' && state.exactMatchCount !== 2) {
    throw new Error('Global chrome shadow qualification lacks two exact fresh matches.');
  }
  if ((state.status === 'quarantined') !== Boolean(state.quarantine)) {
    throw new Error('Global chrome shadow quarantine disposition is invalid.');
  }
  if (
    recent[0].classification !== 'seed' &&
    recent.length !== GLOBAL_CHROME_SHADOW_LIMITS.maxRecentObservationIds
  ) {
    throw new Error('Pruned global chrome shadow history must retain a full bounded observation window.');
  }
  const expectedPrediction = {
    outcomeFingerprint: state.expected.outcomeFingerprint,
    artifactFingerprint: state.expected.artifactFingerprint
  };
  let derivedStatus;
  let derivedExactMatchCount;
  if (recent[0].classification === 'seed') {
    derivedStatus = 'missing';
    derivedExactMatchCount = 0;
  } else if (recent[0].classification === 'exact-match') {
    // The first prune drops the seed while retaining the first confirmation.
    // Reconstruct the pre-window tracking state from that classification.
    derivedStatus = 'tracking';
    derivedExactMatchCount = 0;
  } else {
    derivedStatus = 'shadow-qualified';
    derivedExactMatchCount = 2;
  }
  let derivedQuarantined = false;
  for (let index = 0; index < recent.length; index += 1) {
    const entry = recent[index];
    const matches =
      entry.observedOutcomeFingerprint === state.expected.outcomeFingerprint &&
      entry.observedArtifactFingerprint === state.expected.artifactFingerprint;
    let expectedClassification;
    if (derivedStatus === 'missing') {
      expectedClassification = 'seed';
      derivedStatus = 'tracking';
    } else if (!matches) {
      expectedClassification = 'mismatch';
      derivedStatus = 'quarantined';
      derivedQuarantined = true;
    } else if (derivedStatus === 'tracking' && derivedExactMatchCount === 0) {
      expectedClassification = 'exact-match';
      derivedExactMatchCount = 1;
    } else if (derivedStatus === 'tracking' && derivedExactMatchCount === 1) {
      expectedClassification = 'shadow-qualified';
      derivedExactMatchCount = 2;
      derivedStatus = 'shadow-qualified';
    } else if (derivedStatus === 'shadow-qualified') {
      expectedClassification = 'shadow-qualified';
    } else {
      throw new Error('Global chrome shadow state contains an observation after quarantine.');
    }
    const expectedPotentialMs =
      entry.preCapture.shadowQualified && matches
        ? entry.freshGlobalChromePhaseMs
        : 0;
    if (
      !storedPredictionSnapshotValid(entry.preCapture, expectedPrediction) ||
      entry.classification !== expectedClassification ||
      entry.potentialAvoidablePhaseMs !== expectedPotentialMs ||
      (expectedClassification === 'seed' && !matches) ||
      (expectedClassification === 'mismatch' && index !== recent.length - 1)
    ) {
      throw new Error('Global chrome shadow state history does not support its qualification status.');
    }
  }
  if (
    (derivedStatus === 'missing' ? 'tracking' : derivedStatus) !== state.status ||
    derivedExactMatchCount !== state.exactMatchCount ||
    derivedQuarantined !== Boolean(state.quarantine)
  ) {
    throw new Error('Global chrome shadow state history does not derive its stored disposition.');
  }
  if (state.status === 'quarantined') {
    const mismatch = recent.at(-1);
    if (
      state.quarantine?.freshRunId !== mismatch.runId ||
      !HASH_RE.test(String(state.quarantine?.observedOutcomeFingerprint ?? '')) ||
      !HASH_RE.test(String(state.quarantine?.observedArtifactFingerprint ?? '')) ||
      state.quarantine.observedOutcomeFingerprint !== mismatch.observedOutcomeFingerprint ||
      state.quarantine.observedArtifactFingerprint !== mismatch.observedArtifactFingerprint ||
      state.quarantine.outcomeMismatch !== (
        mismatch.observedOutcomeFingerprint !== state.expected.outcomeFingerprint
      ) ||
      state.quarantine.artifactMismatch !== (
        mismatch.observedArtifactFingerprint !== state.expected.artifactFingerprint
      ) ||
      (state.quarantine?.outcomeMismatch !== true && state.quarantine?.artifactMismatch !== true)
    ) {
      throw new Error('Global chrome shadow quarantine does not match its terminal mismatch observation.');
    }
  }
  return state;
}

async function readState(directory, key) {
  const path = statePath(directory, key.fingerprint);
  const metadata = await safeMetadata(path, { maxBytes: GLOBAL_CHROME_SHADOW_LIMITS.maxStateFileBytes });
  if (!metadata) return null;
  let parsed;
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`Global chrome shadow state is corrupt: ${error.message}`);
  }
  return validateStoredState(parsed, key);
}

async function writeState(directory, key, state) {
  validateStoredState(state, key);
  await writeTextAtomic(statePath(directory, key.fingerprint), `${JSON.stringify(state, null, 2)}\n`);
}

function resultFromState(state, keyFingerprint = '') {
  if (!state) return diagnosticResult({ keyFingerprint });
  return diagnosticResult({
    status: state.status,
    keyFingerprint: state.keyFingerprint,
    seeded: true,
    exactMatchCount: state.exactMatchCount,
    shadowQualified: state.status === 'shadow-qualified',
    quarantined: state.status === 'quarantined',
    prediction: state.status === 'quarantined'
      ? null
      : {
          outcomeFingerprint: state.expected.outcomeFingerprint,
          artifactFingerprint: state.expected.artifactFingerprint
        }
  });
}

export async function lookupGlobalChromeShadowReuse({ projectRoot, preflightKey } = {}) {
  const key = validatedPreflightKey(preflightKey);
  const directory = await existingOwnedStateDirectory(projectRoot);
  if (!directory) return diagnosticResult({ keyFingerprint: key.fingerprint });
  await stateFiles(directory);
  return resultFromState(await readState(directory, key), key.fingerprint);
}

export async function lookupGlobalChromeShadowReuseSafely(options = {}) {
  try {
    return await lookupGlobalChromeShadowReuse(options);
  } catch (error) {
    return diagnosticResult({ status: 'storage-error', errors: [boundedError(error)] });
  }
}

/**
 * Read a diagnostic prediction before invoking the unchanged fresh-capture
 * operation. Shadow lookup is deliberately fail-open and can never replace,
 * suppress, or alter the capture returned by captureFresh.
 */
export async function captureGlobalChromeWithShadowPrediction({
  reuseMode = 'off',
  projectRoot = '',
  preflightKey = null,
  captureFresh,
  lookupShadow = lookupGlobalChromeShadowReuseSafely
} = {}) {
  if (!['off', 'shadow'].includes(reuseMode)) {
    throw new Error('Global chrome reuse mode must be off or shadow; no actual reuse mode exists.');
  }
  if (typeof captureFresh !== 'function') {
    throw new Error('Global chrome shadow orchestration requires a fresh-capture operation.');
  }

  let prediction = null;
  let resolvedProjectRoot = '';
  try {
    resolvedProjectRoot = projectRoot ? resolve(String(projectRoot)) : '';
  } catch {
    resolvedProjectRoot = '';
  }
  const shadowEnabled = Boolean(
    reuseMode === 'shadow' &&
    resolvedProjectRoot &&
    preflightKey?.eligible === true
  );
  if (shadowEnabled) {
    try {
      prediction = await lookupShadow({ projectRoot: resolvedProjectRoot, preflightKey });
    } catch (error) {
      prediction = diagnosticResult({
        status: 'storage-error',
        keyFingerprint: String(preflightKey?.fingerprint ?? ''),
        errors: [boundedError(error)]
      });
    }
  }

  const capture = await captureFresh();
  return {
    capture,
    shadowSession: shadowEnabled
      ? {
          projectRoot: resolvedProjectRoot,
          preflightKey,
          prediction
        }
      : null
  };
}

function isoNow(now) {
  const date = now instanceof Date ? now : new Date(now);
  if (!Number.isFinite(date.getTime())) throw new Error('Global chrome shadow observation time is invalid.');
  return date.toISOString();
}

function predictionSnapshot(value, key) {
  if (
    !value ||
    value.schemaVersion !== GLOBAL_CHROME_SHADOW_RESULT_SCHEMA ||
    !sameCanonical(value.authority, GLOBAL_CHROME_SHADOW_AUTHORITY) ||
    value.keyFingerprint !== key.fingerprint ||
    value.actualReuseEligible !== false ||
    !['missing', 'tracking', 'shadow-qualified', 'quarantined'].includes(value.status) ||
    typeof value.shadowQualified !== 'boolean' ||
    typeof value.quarantined !== 'boolean' ||
    !Number.isSafeInteger(value.exactMatchCount) ||
    value.exactMatchCount < 0 ||
    value.exactMatchCount > 2
  ) {
    throw new Error('Shadow training requires the exact pre-capture lookup snapshot.');
  }
  const prediction = value.prediction === null
    ? null
    : {
        outcomeFingerprint: String(value.prediction?.outcomeFingerprint ?? ''),
        artifactFingerprint: String(value.prediction?.artifactFingerprint ?? '')
      };
  if (
    (prediction && (
      !HASH_RE.test(prediction.outcomeFingerprint) ||
      !HASH_RE.test(prediction.artifactFingerprint)
    )) ||
    (value.status === 'missing' && (
      value.exactMatchCount !== 0 || value.shadowQualified || value.quarantined || prediction
    )) ||
    (value.status === 'tracking' && (
      !prediction || value.shadowQualified || value.quarantined || value.exactMatchCount >= 2
    )) ||
    (value.status === 'shadow-qualified' && (
      !prediction || !value.shadowQualified || value.quarantined || value.exactMatchCount !== 2
    )) ||
    (value.status === 'quarantined' && (
      prediction || value.shadowQualified || !value.quarantined
    ))
  ) {
    throw new Error('The pre-capture shadow lookup snapshot is internally inconsistent.');
  }
  return {
    status: value.status,
    exactMatchCount: value.exactMatchCount,
    shadowQualified: value.shadowQualified,
    quarantined: value.quarantined,
    prediction
  };
}

function recentObservation(binding, classification, observation, preCapture, potentialAvoidablePhaseMs = 0) {
  return {
    ...binding,
    classification,
    observedOutcomeFingerprint: observation.outcomeFingerprint,
    observedArtifactFingerprint: observation.artifactFingerprint,
    preCapture,
    potentialAvoidablePhaseMs
  };
}

function nextRecentObservations(existing, observation) {
  return [...existing, observation].slice(-GLOBAL_CHROME_SHADOW_LIMITS.maxRecentObservationIds);
}

export async function recordGlobalChromeShadowObservation({
  projectRoot,
  preflightKey,
  capture,
  fresh = false,
  freshRunId,
  observabilityRecord,
  preCapturePrediction,
  now = new Date()
} = {}) {
  let key;
  try {
    key = validatedPreflightKey(preflightKey);
  } catch (error) {
    return diagnosticResult({ status: 'ineligible', errors: [error.message] });
  }
  const runId = String(freshRunId ?? '').trim();
  if (fresh !== true || !RUN_ID_RE.test(runId)) {
    return diagnosticResult({
      status: 'ineligible',
      keyFingerprint: key.fingerprint,
      errors: ['Shadow training requires a fresh capture and a bounded unique freshRunId.']
    });
  }
  let binding;
  try {
    binding = normalizeObservabilityBinding(observabilityRecord, runId);
  } catch (error) {
    return diagnosticResult({
      status: 'ineligible',
      keyFingerprint: key.fingerprint,
      errors: [error.message]
    });
  }
  let preCapture;
  try {
    preCapture = predictionSnapshot(preCapturePrediction, key);
  } catch (error) {
    return diagnosticResult({
      status: 'ineligible',
      keyFingerprint: key.fingerprint,
      errors: [error.message]
    });
  }
  const callerObservation = buildGlobalChromeShadowObservation({ preflightKey: key, capture });
  if (!callerObservation.eligible) {
    return diagnosticResult({
      status: 'ineligible',
      keyFingerprint: key.fingerprint,
      errors: callerObservation.errors
    });
  }
  const observedAt = isoNow(now);
  const persistedReport = await verifyPersistedObservedReport(projectRoot, binding);
  await verifyPersistedObservabilityRecord(projectRoot, observabilityRecord);
  if (!sameCanonical(persistedReport.globalChromeCapture, capture)) {
    return diagnosticResult({
      status: 'ineligible',
      keyFingerprint: key.fingerprint,
      errors: ['The supplied capture does not exactly match the persisted live-verification report.']
    });
  }
  const observation = buildGlobalChromeShadowObservation({
    preflightKey: key,
    capture: persistedReport.globalChromeCapture
  });
  if (
    !observation.eligible ||
    observation.outcomeFingerprint !== callerObservation.outcomeFingerprint ||
    observation.artifactFingerprint !== callerObservation.artifactFingerprint
  ) {
    return diagnosticResult({
      status: 'ineligible',
      keyFingerprint: key.fingerprint,
      errors: observation.errors.length > 0
        ? observation.errors
        : ['The persisted capture projection does not match the supplied fresh capture.']
    });
  }
  const directory = await ensureOwnedStateDirectory(projectRoot);
  return withGlobalStateLock(directory, async () => {
    const files = await stateFiles(directory);
    let state = await readState(directory, key);
    if (!state) {
      if (files.length >= GLOBAL_CHROME_SHADOW_LIMITS.maxNamespaces) {
        throw new Error(`Global chrome shadow state reached its ${GLOBAL_CHROME_SHADOW_LIMITS.maxNamespaces}-namespace limit.`);
      }
      state = {
        schemaVersion: GLOBAL_CHROME_SHADOW_STATE_SCHEMA,
        authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
        keyFingerprint: key.fingerprint,
        preflightManifest: key.manifest,
        status: 'tracking',
        exactMatchCount: 0,
        expected: {
          outcomeFingerprint: observation.outcomeFingerprint,
          artifactFingerprint: observation.artifactFingerprint,
          artifactManifest: observation.artifactManifest
        },
        recentObservations: [recentObservation(binding, 'seed', observation, preCapture)],
        quarantine: null,
        createdAt: observedAt,
        updatedAt: observedAt
      };
      await writeState(directory, key, state);
      return diagnosticResult({
        ...resultFromState(state),
        status: 'seeded'
      });
    }
    if (state.status === 'quarantined') return resultFromState(state);
    if (state.recentObservations.some((entry) => entry.runId === runId)) {
      return diagnosticResult({
        ...resultFromState(state),
        status: 'duplicate-observation',
        errors: ['freshRunId was already observed for this dependency key.']
      });
    }
    const outcomeMatches = state.expected.outcomeFingerprint === observation.outcomeFingerprint;
    const artifactMatches = state.expected.artifactFingerprint === observation.artifactFingerprint;
    if (!outcomeMatches || !artifactMatches) {
      state = {
        ...state,
        status: 'quarantined',
        recentObservations: nextRecentObservations(
          state.recentObservations,
          recentObservation(binding, 'mismatch', observation, preCapture)
        ),
        quarantine: {
          detectedAt: observedAt,
          freshRunId: runId,
          outcomeMismatch: !outcomeMatches,
          artifactMismatch: !artifactMatches,
          observedOutcomeFingerprint: observation.outcomeFingerprint,
          observedArtifactFingerprint: observation.artifactFingerprint
        },
        updatedAt: observedAt
      };
      await writeState(directory, key, state);
      return resultFromState(state);
    }
    const exactMatchCount = Math.min(2, state.exactMatchCount + 1);
    const classification = exactMatchCount >= 2 ? 'shadow-qualified' : 'exact-match';
    const potentialAvoidablePhaseMs = preCapture.shadowQualified
      ? binding.freshGlobalChromePhaseMs
      : 0;
    state = {
      ...state,
      status: exactMatchCount >= 2 ? 'shadow-qualified' : 'tracking',
      exactMatchCount,
      recentObservations: nextRecentObservations(
        state.recentObservations,
        recentObservation(
          binding,
          classification,
          observation,
          preCapture,
          potentialAvoidablePhaseMs
        )
      ),
      updatedAt: observedAt
    };
    await writeState(directory, key, state);
    return diagnosticResult({
      ...resultFromState(state),
      status: state.status === 'shadow-qualified' ? 'shadow-qualified' : 'exact-match'
    });
  });
}

export async function recordGlobalChromeShadowObservationSafely(options = {}) {
  try {
    return await recordGlobalChromeShadowObservation(options);
  } catch (error) {
    return diagnosticResult({
      status: 'storage-error',
      keyFingerprint: String(options?.preflightKey?.fingerprint ?? ''),
      errors: [boundedError(error)]
    });
  }
}

function shadowSummary(overrides = {}) {
  return {
    schemaVersion: GLOBAL_CHROME_SHADOW_SUMMARY_SCHEMA,
    authority: { ...GLOBAL_CHROME_SHADOW_AUTHORITY },
    status: 'missing',
    namespaceCount: 0,
    trackingCount: 0,
    shadowQualifiedCount: 0,
    quarantinedCount: 0,
    retainedFreshObservationCount: 0,
    retainedQualifiedMatchedObservationCount: 0,
    retainedFreshGlobalChromePhaseMs: 0,
    retainedPotentialAvoidablePhaseMs: 0,
    retainedMedianFreshGlobalChromePhaseMs: 0,
    retainedMedianPotentialAvoidablePhaseMs: 0,
    actualReuseEligible: false,
    actualReuseBlockers: [...ACTUAL_REUSE_BLOCKERS],
    errors: [],
    ...overrides
  };
}

function median(values) {
  const sorted = values.map(Number).filter(Number.isFinite).sort((left, right) => left - right);
  if (sorted.length === 0) return 0;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : Math.round(((sorted[middle - 1] + sorted[middle]) / 2) * 1000) / 1000;
}

export async function summarizeGlobalChromeShadowReuse({ projectRoot } = {}) {
  const directory = await existingOwnedStateDirectory(projectRoot);
  if (!directory) return shadowSummary();
  const names = await stateFiles(directory);
  const states = [];
  for (const name of names) {
    const path = join(directory, name);
    const metadata = await safeMetadata(path, { maxBytes: GLOBAL_CHROME_SHADOW_LIMITS.maxStateFileBytes });
    if (!metadata) throw new Error('Global chrome shadow state disappeared during summary.');
    let state;
    try {
      state = JSON.parse(await readFile(path, 'utf8'));
    } catch (error) {
      throw new Error(`Global chrome shadow state is corrupt: ${error.message}`);
    }
    const key = validatedPreflightKey({
      schemaVersion: GLOBAL_CHROME_PREFLIGHT_KEY_SCHEMA,
      eligible: true,
      fingerprint: state?.keyFingerprint,
      manifest: state?.preflightManifest
    });
    if (name !== `${key.fingerprint.slice('sha256:'.length)}.json`) {
      throw new Error('Global chrome shadow state filename does not match its dependency key.');
    }
    states.push(validateStoredState(state, key));
  }
  const observations = states.flatMap((state) => state.recentObservations);
  const freshDurations = observations.map((entry) => entry.freshGlobalChromePhaseMs);
  const potentialDurations = observations
    .map((entry) => entry.potentialAvoidablePhaseMs)
    .filter((value) => value > 0);
  const total = (values) => Math.round(values.reduce((sum, value) => sum + value, 0) * 1000) / 1000;
  return shadowSummary({
    status: 'ok',
    namespaceCount: states.length,
    trackingCount: states.filter((state) => state.status === 'tracking').length,
    shadowQualifiedCount: states.filter((state) => state.status === 'shadow-qualified').length,
    quarantinedCount: states.filter((state) => state.status === 'quarantined').length,
    retainedFreshObservationCount: observations.length,
    retainedQualifiedMatchedObservationCount: potentialDurations.length,
    retainedFreshGlobalChromePhaseMs: total(freshDurations),
    retainedPotentialAvoidablePhaseMs: total(potentialDurations),
    retainedMedianFreshGlobalChromePhaseMs: median(freshDurations),
    retainedMedianPotentialAvoidablePhaseMs: median(potentialDurations)
  });
}

export async function summarizeGlobalChromeShadowReuseSafely(options = {}) {
  try {
    return await summarizeGlobalChromeShadowReuse(options);
  } catch (error) {
    return shadowSummary({ status: 'storage-error', errors: [boundedError(error)] });
  }
}
