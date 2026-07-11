#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, collectFileManifest, sha256 } from './state-fingerprint.mjs';
import {
  compareGlobalChromeCaptures,
  globalChromeImpact,
  normalizeGlobalChromeContract,
  validateGlobalChromeCapture,
  validateScreenshotArtifacts
} from './global-chrome.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const KIT_ROOT = resolve(dirname(SCRIPT_PATH), '..');
const LIFECYCLE_SCHEMA = 'public-kit.lifecycle.1';
const BASELINE_SCHEMA = 'public-kit.initial-baseline.1';
const CHECKPOINT_SCHEMA = 'public-kit.checkpoint.1';
const CURRENT_STATE_SCHEMA = 'public-kit.current-state.1';
const CHANGE_SCHEMA = 'public-kit.change.1';
const CHANGE_VERIFICATION_SCHEMA = 'public-kit.change-verification.1';
const CHANGE_FULL_VERIFICATION_SCHEMA = 'public-kit.change-full-verification.1';
const CHANGE_ABANDONMENT_SCHEMA = 'public-kit.change-abandonment.1';
const SITE_STATE_SCHEMA = 'public-kit.site-state.1';
const GLOBAL_CHROME_ANCHOR_SCHEMA = 'public-kit.global-chrome-anchor.1';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const ID_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const FRESH_INSPECTION_MS = 10 * 60 * 1000;
const FUTURE_SKEW_MS = 2 * 60 * 1000;
const UNIVERSAL_MACHINE_CHECK_IDS = new Set(['state-bound', 'config-clean', 'baseline-route-smoke']);
const MACHINE_CHECK_IDS = new Set([...UNIVERSAL_MACHINE_CHECK_IDS, 'global-chrome-regression']);

function loadChangePolicy() {
  const path = join(KIT_ROOT, 'gates.json');
  let gates;
  try {
    gates = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`Lifecycle change policy must be readable from gates.json: ${error.message}`);
  }
  if (!isObject(gates.changeChecks) || !isObject(gates.changeImpactProfiles)) {
    throw new Error('gates.json must define changeChecks and changeImpactProfiles objects.');
  }
  const checks = Object.freeze({ ...gates.changeChecks });
  const profiles = Object.freeze({ ...gates.changeImpactProfiles });
  for (const required of ['universal', 'repair', 'extension', 'unknown']) {
    if (!isObject(profiles[required]) || !Array.isArray(profiles[required].checks) ||
        !Array.isArray(profiles[required].components)) {
      throw new Error(`gates.json changeImpactProfiles.${required} is required.`);
    }
  }
  for (const [profileId, profile] of Object.entries(profiles)) {
    if (!isObject(profile) || !Array.isArray(profile.checks) || !Array.isArray(profile.components)) {
      throw new Error(`gates.json change impact profile ${profileId} must define checks and components arrays.`);
    }
    for (const checkId of profile.checks) {
      if (!String(checks[checkId] ?? '').trim()) {
        throw new Error(`gates.json change impact profile ${profileId} references unknown check ${checkId}.`);
      }
    }
  }
  if (canonicalJson([...profiles.universal.checks].sort(comparePortable)) !==
      canonicalJson([...UNIVERSAL_MACHINE_CHECK_IDS].sort(comparePortable))) {
    throw new Error('gates.json universal change checks must match the lifecycle machine evaluators.');
  }
  return { checks, profiles };
}

const CHANGE_POLICY = loadChangePolicy();
const SURFACES = new Set(
  Object.keys(CHANGE_POLICY.profiles)
    .filter((profile) => !['universal', 'repair', 'extension'].includes(profile))
);
const PUBLIC_ROUTE_SURFACES = new Set([
  'accessibility',
  'canvas',
  'content',
  'media',
  'navigation',
  'routing',
  'seo',
  'theme-global',
  'theme-route',
  'unknown'
]);

const USAGE = `Usage: node <path-to-skill>/scripts/lifecycle.mjs <command> [options]

Commands:
  status
    Show the initial baseline, structurally derived change state, and last inspected current state.

  begin --id <slug> --kind <repair|extension> --summary <text>
        [--surface <surface>]... ([--route </affected-path>]... | --no-public-route)
        --acceptance <criterion>... [--adopt-current]
    Create the sole active change intent from the latest structural anchor.

  complete --id <slug> --verification <path>
    Run a fresh live inspection and create a targeted evidence transition.

  abandon --id <slug> --reason <text>
    Create an abandonment transition for the active change.

Shared option:
  --packet <path>  Review packet directory (default: review-packet)

Surface values:
  ${[...SURFACES].sort(comparePortable).join(', ')}
`;

class UsageError extends Error {}

function comparePortable(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cloneCanonical(value) {
  return JSON.parse(canonicalJson(value));
}

function isInside(parent, child) {
  const fromParent = relative(parent, child);
  return fromParent === '' || (
    fromParent !== '..' &&
    !fromParent.startsWith(`..${sep}`) &&
    !isAbsolute(fromParent)
  );
}

function assertDirectoryNotSymlink(path, label) {
  if (!existsSync(path)) return;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a file or symbolic link.`);
  }
}

function packetEvidence(packetDir) {
  const requested = resolve(packetDir);
  if (!existsSync(requested) || !statSync(requested).isDirectory()) {
    throw new Error(`Review packet directory does not exist: ${requested}`);
  }
  if (lstatSync(requested).isSymbolicLink()) {
    throw new Error('Review packet directory must not be a symbolic link.');
  }
  const packet = realpathSync(requested);
  const evidence = join(packet, 'evidence');
  assertDirectoryNotSymlink(evidence, 'Review packet evidence directory');
  const root = join(evidence, 'lifecycle');
  assertDirectoryNotSymlink(root, 'Lifecycle directory');
  return { packet, root };
}

function ensureLifecycleDirectories(root) {
  mkdirSync(join(root, 'changes'), { recursive: true });
  mkdirSync(join(root, 'checkpoints'), { recursive: true });
  mkdirSync(join(root, 'chrome', 'anchors'), { recursive: true });
  for (const path of [root, join(root, 'changes'), join(root, 'checkpoints'), join(root, 'chrome'), join(root, 'chrome', 'anchors')]) {
    assertDirectoryNotSymlink(path, 'Lifecycle directory');
  }
}

function safeId(value, label = 'ID') {
  const id = String(value ?? '').trim();
  if (!ID_RE.test(id)) {
    throw new Error(`${label} must be a lowercase slug using letters, digits, and internal hyphens (maximum 64 characters).`);
  }
  return id;
}

function timestamp(value, label) {
  const text = String(value ?? '').trim();
  if (!ISO_RE.test(text) || !Number.isFinite(Date.parse(text))) {
    throw new Error(`${label} must be a UTC ISO timestamp.`);
  }
  return text;
}

function fingerprint(value, label) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!HASH_RE.test(text)) {
    throw new Error(`${label} must be a SHA-256 fingerprint.`);
  }
  return text;
}

function normalizedRoutePath(value, label = 'Affected route') {
  const text = String(value ?? '').trim();
  if (text === '*') return '*';
  if (!text.startsWith('/') || text.startsWith('//')) {
    throw new Error(`${label} must be a root-relative path beginning with / or the global * marker.`);
  }
  try {
    const route = new URL(text, 'https://lifecycle.invalid');
    return `${route.pathname || '/'}${route.search}`;
  } catch {
    throw new Error(`${label} must be a valid root-relative path.`);
  }
}

function assertTimeBounds(value, label, { notBefore = '', fresh = false, now = Date.now() } = {}) {
  const text = timestamp(value, label);
  const instant = Date.parse(text);
  if (notBefore && instant < Date.parse(timestamp(notBefore, `${label} lower bound`))) {
    throw new Error(`${label} must not predate the change opening time.`);
  }
  if (instant > now + FUTURE_SKEW_MS) {
    throw new Error(`${label} is implausibly far in the future.`);
  }
  if (fresh && now - instant > FRESH_INSPECTION_MS) {
    throw new Error(`${label} is stale; run a fresh live inspection before continuing.`);
  }
  return text;
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${label} must be valid JSON: ${error.message}`);
  }
}

function assertRegularFile(path, label, { nonEmpty = true } = {}) {
  if (!existsSync(path)) throw new Error(`${label} does not exist: ${path}`);
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file.`);
  }
  if (nonEmpty && metadata.size === 0) throw new Error(`${label} must not be empty.`);
}

function assertContainedRegularFile(projectRoot, path, label) {
  const root = realpathSync(projectRoot);
  const requested = resolve(path);
  if (!isInside(root, requested)) throw new Error(`${label} must be inside the Drupal project.`);
  assertRegularFile(requested, label);
  let current = requested;
  while (current !== root) {
    const metadata = lstatSync(current);
    if (metadata.isSymbolicLink()) {
      throw new Error(`${label} must not traverse a symbolic link.`);
    }
    current = dirname(current);
    if (!isInside(root, current)) throw new Error(`${label} escapes the Drupal project.`);
  }
  return requested;
}

function writeCreateOnlyJson(path, value, label) {
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error(`${label} already exists and is create-only: ${path}`);
    throw error;
  }
}

function writeAtomicJson(path, value, label) {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path) && (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile())) {
    throw new Error(`${label} must be a regular non-symlink file.`);
  }
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function certificatePayload(value) {
  const payload = { ...value };
  delete payload.certificateSha256;
  return payload;
}

function certify(value) {
  const payload = cloneCanonical(value);
  return { ...payload, certificateSha256: sha256(certificatePayload(payload)) };
}

function verifyCertificate(value, label) {
  if (!isObject(value)) throw new Error(`${label} must be an object.`);
  const recorded = fingerprint(value.certificateSha256, `${label} certificateSha256`);
  const expected = sha256(certificatePayload(value));
  if (recorded !== expected) {
    throw new Error(`${label} certificate hash is invalid; the create-only record may have been modified.`);
  }
}

function validateBuildState(buildState, label = 'buildState') {
  if (!isObject(buildState) || buildState.schemaVersion !== SITE_STATE_SCHEMA) {
    throw new Error(`${label} must use schemaVersion ${SITE_STATE_SCHEMA}.`);
  }
  const stateFingerprint = fingerprint(buildState.fingerprint, `${label}.fingerprint`);
  if (!isObject(buildState.componentFingerprints)) {
    throw new Error(`${label}.componentFingerprints must be an object.`);
  }
  for (const [name, value] of Object.entries(buildState.componentFingerprints)) {
    fingerprint(value, `${label}.componentFingerprints.${name}`);
  }
  const expected = sha256({
    schemaVersion: SITE_STATE_SCHEMA,
    componentFingerprints: buildState.componentFingerprints
  });
  if (expected !== stateFingerprint) {
    throw new Error(`${label}.fingerprint does not match its component fingerprints.`);
  }
  return stateFingerprint;
}

function authoritativePassingReport(report) {
  return isObject(report) &&
    report.completeLocalRebuildClaimAllowed === true &&
    report.verificationMode === 'live-target-and-packet' &&
    report.drupalRuntime?.authoritativeForCompletion === true &&
    report.valid === true;
}

function validatePassingReport(report, label) {
  if (!authoritativePassingReport(report)) {
    throw new Error(`${label} must be a valid, authoritative live-target report that allows the complete local rebuild claim.`);
  }
  timestamp(report.checkedAt, `${label}.checkedAt`);
  return validateBuildState(report.buildState, `${label}.buildState`);
}

function validateInspectableReport(report, label, { notBefore = '', fresh = false } = {}) {
  if (!isObject(report) || report.verificationMode !== 'live-target-and-packet' || report.valid !== true) {
    throw new Error(`${label} must be a valid live-target-and-packet report.`);
  }
  assertTimeBounds(report.checkedAt, `${label}.checkedAt`, { notBefore, fresh });
  validateBuildState(report.buildState, `${label}.buildState`);
  if (!isObject(report.drupalRuntime)) throw new Error(`${label}.drupalRuntime is required.`);
  return report;
}

function routeInventoryFromReport(report) {
  const collect = (checks) => [...new Set((Array.isArray(checks) ? checks : [])
    .map((check) => String(check?.targetPath ?? '').trim())
    .filter(Boolean))].sort(comparePortable);
  return {
    primary: collect(report?.routeChecks),
    targetRequired: collect(report?.targetRequiredRouteChecks)
  };
}

function machineFacts(report, label = 'Fresh inspection', baselineRoutes = null, affectedRoutes = null) {
  const stateReady = report.buildState?.complete === true &&
    Array.isArray(report.buildState?.blockers) && report.buildState.blockers.length === 0 &&
    report.drupalRuntime?.entityInventory?.confirmed === true &&
    report.drupalRuntime?.runtimeFacts?.confirmed === true &&
    report.drupalRuntime?.runtimeFacts?.databaseUpdatesPending !== true;
  const identityBound = report.drupalRuntime?.confirmed === true &&
    report.drupalRuntime?.targetOriginMatches === true &&
    report.drupalRuntime?.siteUuidMatchesPacket === true &&
    report.drupalRuntime?.frontPageMatchesPacket === true &&
    report.drupalRuntime?.configSyncDirectoryMatchesPacket === true;
  const configClean = report.drupalRuntime?.authoritativeForCompletion === true &&
    report.drupalRuntime?.configStatusClean === true &&
    report.drupalRuntime?.configSyncTracked === true &&
    report.drupalRuntime?.configSyncDirectoryMatchesPacket === true &&
    report.drupalRuntime?.trackedConfigReadbackMatches === true &&
    report.drupalRuntime?.trackedConfigYamlPresent !== false;
  const primary = Array.isArray(report.routeChecks) ? report.routeChecks : [];
  const required = Array.isArray(report.targetRequiredRouteChecks) ? report.targetRequiredRouteChecks : [];
  const baselinePrimary = Array.isArray(baselineRoutes?.primary) ? baselineRoutes.primary : [];
  const baselineRequired = Array.isArray(baselineRoutes?.targetRequired) ? baselineRoutes.targetRequired : [];
  const primaryByPath = new Map(primary.map((check) => [check?.targetPath, check]));
  const requiredByPath = new Map(required.map((check) => [check?.targetPath, check]));
  const baselineRoutesPresent = baselinePrimary.every((path) => primaryByPath.has(path)) &&
    baselineRequired.every((path) => requiredByPath.has(path));
  const declaredAffectedRoutes = Array.isArray(affectedRoutes) ? affectedRoutes : [];
  const checkedByPath = new Map([...primary, ...required].map((check) => [
    normalizedRoutePath(check?.targetPath, 'Inspected route'),
    check
  ]));
  const affectedRoutesPresent = declaredAffectedRoutes.includes('*') ||
    declaredAffectedRoutes.every((path) => checkedByPath.has(path));
  const routesClean = report.liveTargetValid === true && primary.length > 0 && baselineRoutesPresent &&
    affectedRoutesPresent &&
    [...primary, ...required].every((check) => check?.passed === true && (check.errors ?? []).length === 0);
  if (!stateReady || !identityBound) {
    throw new Error(
      `${label} cannot satisfy state-bound: Drupal/runtime identity, entity inventory, runtime facts, ` +
      'database-update state, or the complete build-state fingerprint is not ready.'
    );
  }
  if (!configClean) {
    throw new Error(`${label} cannot satisfy config-clean: active configuration is dirty, untracked, or does not exactly match tracked readback.`);
  }
  if (!routesClean) {
    const missingAffected = declaredAffectedRoutes
      .filter((path) => path !== '*' && !checkedByPath.has(path));
    const suffix = missingAffected.length
      ? ` Declared affected routes were not live-checked: ${missingAffected.join(', ')}.`
      : '';
    throw new Error(`${label} cannot satisfy baseline-route-smoke: one or more required live route checks did not pass.${suffix}`);
  }
  return {
    stateReady,
    identityBound,
    configClean,
    baselinePrimaryRoutes: baselinePrimary,
    baselineTargetRequiredRoutes: baselineRequired,
    declaredAffectedRoutes,
    affectedRoutesPresent,
    primaryRouteCount: primary.length,
    targetRequiredRouteCount: required.length,
    routesClean
  };
}

function baselinePath(root) {
  return join(root, 'initial-baseline.json');
}

function currentStatePath(root) {
  return join(root, 'current-state.json');
}

function changeDirectory(root, id) {
  return join(root, 'changes', safeId(id, 'Change ID'));
}

function changePath(root, id) {
  return join(changeDirectory(root, id), 'change.json');
}

function changeVerificationPath(root, id) {
  return join(changeDirectory(root, id), 'verification.json');
}

function changeFullVerificationPath(root, id) {
  return join(changeDirectory(root, id), 'full-verification.json');
}

function changeAbandonmentPath(root, id) {
  return join(changeDirectory(root, id), 'abandonment.json');
}

function checkpointPath(root, id) {
  return join(root, 'checkpoints', `${safeId(id, 'Checkpoint ID')}.json`);
}

function globalChromeAnchorPath(root, type, id) {
  if (!['initial', 'change', 'checkpoint'].includes(type)) throw new Error(`Unsupported global chrome anchor type ${type}.`);
  return join(root, 'chrome', 'anchors', `${type}-${safeId(id, 'Global chrome anchor ID')}.json`);
}

function validateGlobalChromeAnchor(anchor, root, expected = {}) {
  if (!isObject(anchor) || anchor.schemaVersion !== GLOBAL_CHROME_ANCHOR_SCHEMA) {
    throw new Error(`Global chrome anchor must use schemaVersion ${GLOBAL_CHROME_ANCHOR_SCHEMA}.`);
  }
  if (!['initial', 'change', 'checkpoint'].includes(anchor.anchorType)) throw new Error('Global chrome anchor type is invalid.');
  safeId(anchor.anchorId, 'Global chrome anchor ID');
  if (expected.type && anchor.anchorType !== expected.type || expected.id && anchor.anchorId !== expected.id) {
    throw new Error('Global chrome anchor path identity does not match its record.');
  }
  const state = fingerprint(anchor.siteStateFingerprint, 'Global chrome anchor siteStateFingerprint');
  timestamp(anchor.capturedAt, 'Global chrome anchor capturedAt');
  const capture = validateGlobalChromeCapture(anchor.capture, { stateFingerprint: state, requireAuthoritative: true });
  if (capture.captureFingerprint !== anchor.captureFingerprint) throw new Error('Global chrome anchor capture fingerprint is invalid.');
  verifyCertificate(anchor, 'Global chrome anchor');
  validateScreenshotArtifacts(resolve(root, '..', '..'), capture);
  return anchor;
}

function readGlobalChromeAnchor(root, type, id, { required = false } = {}) {
  const path = globalChromeAnchorPath(root, type, id);
  if (!existsSync(path)) {
    if (required) throw new Error(`Latest verified anchor ${type}:${id} has no executable global chrome capture. Run the live verifier while the current state still matches that anchor before beginning global-impact work.`);
    return null;
  }
  assertRegularFile(path, `Global chrome anchor ${type}:${id}`);
  return validateGlobalChromeAnchor(readJson(path, `Global chrome anchor ${type}:${id}`), root, { type, id });
}

function latestVerifiedGraphAnchor(graph) {
  return [...graph.chain].reverse().find((anchor) =>
    ['initial', 'checkpoint'].includes(anchor.type) || anchor.credential === 'full_verified'
  ) ?? null;
}

function persistMatchingGlobalChromeAnchor(root, graph, report) {
  const capture = report?.globalChromeCapture;
  if (!capture || capture.status !== 'captured' || capture.authoritative !== true) return null;
  const matching = [...graph.chain].reverse().find((anchor) =>
    anchor.fingerprint === report.buildState?.fingerprint &&
    (['initial', 'checkpoint'].includes(anchor.type) || anchor.credential === 'full_verified')
  );
  if (!matching) return null;
  const path = globalChromeAnchorPath(root, matching.type, matching.id);
  if (existsSync(path)) return readGlobalChromeAnchor(root, matching.type, matching.id, { required: true });
  validateGlobalChromeCapture(capture, { stateFingerprint: matching.fingerprint, requireAuthoritative: true });
  validateScreenshotArtifacts(resolve(root, '..', '..'), capture);
  const value = certify({
    schemaVersion: GLOBAL_CHROME_ANCHOR_SCHEMA,
    anchorType: matching.type,
    anchorId: matching.id,
    credential: matching.credential,
    capturedAt: capture.checkedAt,
    siteStateFingerprint: matching.fingerprint,
    captureFingerprint: capture.captureFingerprint,
    capture: cloneCanonical(capture)
  });
  writeCreateOnlyJson(path, value, `Global chrome anchor ${matching.type}:${matching.id}`);
  return validateGlobalChromeAnchor(value, root, { type: matching.type, id: matching.id });
}

export function globalChromeCaptureContext({ packetDir = 'review-packet' } = {}) {
  const { root } = packetEvidence(packetDir);
  ensureLifecycleDirectories(root);
  const baseline = readInitialBaseline(root);
  if (!baseline) return { lifecyclePresent: false, latestVerifiedAnchor: null, contract: null };
  const graph = buildLifecycleGraph(root, baseline);
  const latest = latestVerifiedGraphAnchor(graph);
  const anchor = latest ? readGlobalChromeAnchor(root, latest.type, latest.id) : null;
  return {
    lifecyclePresent: true,
    latestVerifiedAnchor: latest
      ? { id: latest.id, type: latest.type, fingerprint: latest.fingerprint, credential: latest.credential }
      : null,
    contract: anchor ? normalizeGlobalChromeContract(anchor.capture.contract) : null,
    anchorCaptureFingerprint: anchor?.captureFingerprint ?? ''
  };
}

function validateInitialBaseline(baseline) {
  if (!isObject(baseline) || baseline.schemaVersion !== BASELINE_SCHEMA || baseline.status !== 'passed') {
    throw new Error(`Initial baseline must use schemaVersion ${BASELINE_SCHEMA} with status passed.`);
  }
  if (baseline.baselineId !== 'initial') throw new Error('Initial baseline baselineId must be initial.');
  timestamp(baseline.passedAt, 'Initial baseline passedAt');
  const state = fingerprint(baseline.siteStateFingerprint, 'Initial baseline siteStateFingerprint');
  const reportState = validatePassingReport(baseline.passingReport, 'Initial baseline passingReport');
  const buildState = validateBuildState(baseline.buildState, 'Initial baseline buildState');
  if (state !== reportState || state !== buildState) {
    throw new Error('Initial baseline fingerprint does not match its build state and passing report.');
  }
  verifyCertificate(baseline, 'Initial baseline');
  return baseline;
}

function readInitialBaseline(root, { required = false } = {}) {
  const path = baselinePath(root);
  if (!existsSync(path)) {
    if (required) throw new Error('No initial baseline exists. Run a fresh authoritative full verification first.');
    return null;
  }
  assertRegularFile(path, 'Initial baseline');
  return validateInitialBaseline(readJson(path, 'Initial baseline'));
}

function impactChecks(kind, surfaces) {
  const checks = new Map();
  const add = (id, description, source) => {
    const existing = checks.get(id) ?? {
      id,
      description,
      evaluator: MACHINE_CHECK_IDS.has(id) ? 'machine' : 'authored',
      sourceSurfaces: []
    };
    if (!existing.sourceSurfaces.includes(source)) existing.sourceSurfaces.push(source);
    checks.set(id, existing);
  };
  for (const profileId of ['universal', kind, ...surfaces]) {
    const profile = CHANGE_POLICY.profiles[profileId];
    if (!profile) {
      throw new Error(`No gates.json change impact profile exists for ${profileId}.`);
    }
    const source = profileId === 'universal' ? 'all' : profileId;
    for (const id of profile.checks) {
      add(id, CHANGE_POLICY.checks[id], source);
    }
  }
  return [...checks.values()]
    .map((check) => ({ ...check, sourceSurfaces: check.sourceSurfaces.sort(comparePortable) }))
    .sort((left, right) => comparePortable(left.id, right.id));
}

function validateChangeIntent(intent, expectedId = '') {
  if (!isObject(intent) || intent.schemaVersion !== CHANGE_SCHEMA) {
    throw new Error(`Change intent must use schemaVersion ${CHANGE_SCHEMA}.`);
  }
  const id = safeId(intent.id, 'Change ID');
  if (expectedId && id !== expectedId) throw new Error(`Change path ${expectedId} does not match change id ${id}.`);
  if (!['repair', 'extension'].includes(intent.kind)) throw new Error('Change kind must be repair or extension.');
  if (!String(intent.summary ?? '').trim()) throw new Error(`Change ${id} requires a summary.`);
  timestamp(intent.openedAt, `Change ${id} openedAt`);
  const base = fingerprint(intent.baseFingerprint, `Change ${id} baseFingerprint`);
  safeId(intent.baseAnchorId, `Change ${id} baseAnchorId`);
  if (!['initial', 'change', 'checkpoint'].includes(intent.baseAnchorType)) {
    throw new Error(`Change ${id} has an invalid baseAnchorType.`);
  }
  if (!isObject(intent.baseComponentFingerprints)) {
    throw new Error(`Change ${id} baseComponentFingerprints must be an object.`);
  }
  for (const [name, value] of Object.entries(intent.baseComponentFingerprints)) {
    fingerprint(value, `Change ${id} baseComponentFingerprints.${name}`);
  }
  if (sha256({ schemaVersion: SITE_STATE_SCHEMA, componentFingerprints: intent.baseComponentFingerprints }) !== base) {
    throw new Error(`Change ${id} baseComponentFingerprints do not match baseFingerprint.`);
  }
  if (intent.baseBuildState !== undefined && validateBuildState(intent.baseBuildState, `Change ${id} baseBuildState`) !== base) {
    throw new Error(`Change ${id} baseBuildState does not match baseFingerprint.`);
  }
  if (!Array.isArray(intent.baseRouteManifest) ||
      sha256(intent.baseRouteManifest) !== intent.baseComponentFingerprints.routeManifest) {
    throw new Error(`Change ${id} baseRouteManifest does not match its routeManifest component fingerprint.`);
  }
  fingerprint(intent.observedCurrentFingerprint, `Change ${id} observedCurrentFingerprint`);
  if (!isObject(intent.observedCurrentComponentFingerprints)) {
    throw new Error(`Change ${id} observedCurrentComponentFingerprints must be an object.`);
  }
  if (typeof intent.adoptedCurrentState !== 'boolean') throw new Error(`Change ${id} adoptedCurrentState must be boolean.`);
  if (!Array.isArray(intent.surfaces) || intent.surfaces.length === 0) {
    throw new Error(`Change ${id} requires at least one impact surface.`);
  }
  for (const surface of intent.surfaces) {
    if (!String(surface ?? '').trim()) throw new Error(`Change ${id} has an invalid snapshotted impact surface.`);
  }
  if (intent.adoptedCurrentState && !intent.surfaces.includes('unknown')) {
    throw new Error(`Change ${id} adopted current state must include the unknown surface.`);
  }
  if (!Array.isArray(intent.affectedRoutes) ||
      intent.affectedRoutes.some((path) => normalizedRoutePath(path) !== path) ||
      new Set(intent.affectedRoutes).size !== intent.affectedRoutes.length) {
    throw new Error(`Change ${id} has an invalid snapshotted affectedRoutes array.`);
  }
  const routeScopeValid =
    (intent.publicRouteScope === 'all' && canonicalJson(intent.affectedRoutes) === canonicalJson(['*'])) ||
    (intent.publicRouteScope === 'declared' && intent.affectedRoutes.length > 0 && !intent.affectedRoutes.includes('*')) ||
    (intent.publicRouteScope === 'none' && intent.affectedRoutes.length === 0);
  if (!routeScopeValid) {
    throw new Error(`Change ${id} has an invalid snapshotted publicRouteScope.`);
  }
  if (!Array.isArray(intent.acceptanceCriteria) || intent.acceptanceCriteria.length === 0 ||
      intent.acceptanceCriteria.some((criterion) => !isObject(criterion) ||
        !ID_RE.test(String(criterion.id ?? '')) || !String(criterion.text ?? '').trim()) ||
      new Set(intent.acceptanceCriteria.map((criterion) => criterion.id)).size !== intent.acceptanceCriteria.length) {
    throw new Error(`Change ${id} requires non-empty acceptance criteria.`);
  }
  if (!isObject(intent.baselineRoutes) || !Array.isArray(intent.baselineRoutes.primary) ||
      !Array.isArray(intent.baselineRoutes.targetRequired) || intent.baselineRoutes.primary.length === 0 ||
      [...intent.baselineRoutes.primary, ...intent.baselineRoutes.targetRequired]
        .some((path) => !String(path ?? '').trim())) {
    throw new Error(`Change ${id} requires a snapshotted baseline route inventory.`);
  }
  if (!Array.isArray(intent.requiredChecks) || intent.requiredChecks.length === 0) {
    throw new Error(`Change ${id} requires a snapshotted requiredChecks array.`);
  }
  const checkIds = new Set();
  for (const check of intent.requiredChecks) {
    if (!isObject(check) || !String(check.id ?? '').trim() || !String(check.description ?? '').trim() ||
        !['machine', 'authored'].includes(check.evaluator) ||
        !Array.isArray(check.sourceSurfaces) || check.sourceSurfaces.length === 0) {
      throw new Error(`Change ${id} has an invalid snapshotted required check.`);
    }
    if (checkIds.has(check.id)) throw new Error(`Change ${id} has duplicate required check ${check.id}.`);
    checkIds.add(check.id);
  }
  if (!intent.requiredChecks.some((check) => check.evaluator === 'machine')) {
    throw new Error(`Change ${id} requiredChecks must snapshot its machine-evaluated checks.`);
  }
  if (!isObject(intent.wideningCheck) || !String(intent.wideningCheck.id ?? '').trim() ||
      !String(intent.wideningCheck.description ?? '').trim() || intent.wideningCheck.evaluator !== 'authored' ||
      !Array.isArray(intent.wideningCheck.sourceSurfaces) || intent.wideningCheck.sourceSurfaces.length === 0) {
    throw new Error(`Change ${id} requires a snapshotted authored wideningCheck.`);
  }
  if (!Array.isArray(intent.expectedComponents) || intent.expectedComponents.length === 0 ||
      intent.expectedComponents.some((name) => !String(name ?? '').trim())) {
    throw new Error(`Change ${id} requires a snapshotted expectedComponents array.`);
  }
  verifyCertificate(intent, `Change ${id} intent`);
  return intent;
}

function changedComponents(baseComponents, resultComponents) {
  const names = new Set([...Object.keys(baseComponents), ...Object.keys(resultComponents)]);
  return [...names]
    .filter((name) => baseComponents[name] !== resultComponents[name])
    .sort(comparePortable);
}

function changedRoutePaths(baseBuildState, resultBuildState) {
  const baseRoutes = Array.isArray(baseBuildState?.routeManifest) ? baseBuildState.routeManifest : null;
  const resultRoutes = Array.isArray(resultBuildState?.routeManifest) ? resultBuildState.routeManifest : null;
  if (!baseRoutes || !resultRoutes) {
    return baseBuildState?.componentFingerprints?.routeManifest !== resultBuildState?.componentFingerprints?.routeManifest
      ? ['*']
      : [];
  }
  const index = (routes) => new Map(routes.map((route) => [
    `${String(route?.path ?? '')}\0${String(route?.routeKind ?? '')}`,
    sha256(route)
  ]));
  const base = index(baseRoutes);
  const result = index(resultRoutes);
  const keys = new Set([...base.keys(), ...result.keys()]);
  return [...new Set([...keys]
    .filter((key) => base.get(key) !== result.get(key))
    .map((key) => key.split('\0')[0] || '/'))].sort(comparePortable);
}

function undeclaredRouteChanges(changedRoutes, affectedRoutes) {
  if (affectedRoutes.includes('*')) return [];
  const declared = new Set(affectedRoutes);
  return changedRoutes.filter((path) => path === '*' || !declared.has(path));
}

function expectedComponents(surfaces, allComponents) {
  if (surfaces.includes('unknown')) return new Set(allComponents);
  const expected = new Set();
  for (const surface of surfaces) {
    for (const component of CHANGE_POLICY.profiles[surface]?.components ?? []) expected.add(component);
  }
  return expected;
}

function requiredChecksForTransition(change, unexpected, chromeImpact = { triggered: false }) {
  const checks = cloneCanonical(change.requiredChecks);
  if (chromeImpact.triggered && !checks.some((check) => check.id === 'global-chrome-regression')) {
    checks.push({
      id: 'global-chrome-regression',
      description: CHANGE_POLICY.checks['global-chrome-regression'],
      evaluator: 'machine',
      sourceSurfaces: ['detected-global-chrome-impact']
    });
  }
  if (unexpected.length && !checks.some((check) => check.id === change.wideningCheck.id)) {
    checks.push(cloneCanonical(change.wideningCheck));
  }
  return checks.sort((left, right) => comparePortable(left.id, right.id));
}

function validateEvidenceManifest(entries, label, root = '') {
  if (!Array.isArray(entries) || entries.length === 0) throw new Error(`${label} requires hashed evidence.`);
  const packet = root ? resolve(root, '..', '..') : '';
  const projectRoot = root ? projectRootForPacket(packet) : '';
  for (const [index, entry] of entries.entries()) {
    if (!isObject(entry) || !String(entry.path ?? '').trim()) throw new Error(`${label}[${index}] requires a path.`);
    fingerprint(entry.sha256, `${label}[${index}].sha256`);
    if (!Number.isInteger(entry.size) || entry.size < 0) throw new Error(`${label}[${index}].size must be non-negative.`);
    if (root) {
      const path = assertContainedRegularFile(
        projectRoot,
        resolve(projectRoot, entry.path),
        `${label}[${index}] snapshot`
      );
      const manifest = collectFileManifest(projectRoot, [portableProjectPath(projectRoot, path)]);
      if (manifest.entries[0].sha256 !== entry.sha256 || manifest.entries[0].size !== entry.size) {
        throw new Error(`${label}[${index}] snapshot bytes no longer match the certified evidence.`);
      }
    }
  }
}

function validateTargetedVerification(verification, intent, root = '') {
  const label = `Change ${intent.id} targeted verification`;
  if (!isObject(verification) || verification.schemaVersion !== CHANGE_VERIFICATION_SCHEMA ||
      verification.changeId !== intent.id) {
    throw new Error(`${label} identity is invalid.`);
  }
  verifyCertificate(verification, label);
  if (verification.verificationMode !== 'evidence-bound-targeted' || verification.authoritative !== false ||
      verification.currentStateVerified !== false || verification.semanticEvidenceIndependentlyEvaluated !== false) {
    throw new Error(`${label} must be explicitly non-authoritative and evidence-only.`);
  }
  const base = fingerprint(verification.baseFingerprint, `${label} baseFingerprint`);
  const result = fingerprint(verification.resultFingerprint, `${label} resultFingerprint`);
  if (base !== intent.baseFingerprint || base === result) throw new Error(`${label} fingerprints are invalid.`);
  assertTimeBounds(verification.checkedAt, `${label} checkedAt`, { notBefore: intent.openedAt });
  assertTimeBounds(verification.evidenceCheckedAt, `${label} evidenceCheckedAt`, { notBefore: intent.openedAt });
  const resultState = validateBuildState(verification.resultBuildState, `${label} resultBuildState`);
  if (resultState !== result) throw new Error(`${label} resultBuildState does not match resultFingerprint.`);
  if (!isObject(verification.inspectionReport)) throw new Error(`${label} requires its embedded fresh inspection report.`);
  const reportHash = fingerprint(verification.inspectionReportSha256, `${label} inspectionReportSha256`);
  if (sha256(verification.inspectionReport) !== reportHash) throw new Error(`${label} embedded inspection report hash is invalid.`);
  validateInspectableReport(verification.inspectionReport, `${label} inspectionReport`, { notBefore: intent.openedAt });
  if (verification.inspectionReport.buildState.fingerprint !== result) {
    throw new Error(`${label} embedded inspection report does not match resultFingerprint.`);
  }
  const facts = machineFacts(
    verification.inspectionReport,
    label,
    intent.baselineRoutes,
    intent.affectedRoutes
  );
  if (canonicalJson(facts) !== canonicalJson(verification.machineFacts)) throw new Error(`${label} machine facts are invalid.`);
  const detected = changedComponents(intent.baseComponentFingerprints, verification.resultBuildState.componentFingerprints);
  if (canonicalJson(detected) !== canonicalJson(verification.changedComponents)) {
    throw new Error(`${label} changed component inventory is invalid.`);
  }
  const expected = new Set(intent.expectedComponents);
  const unexpected = detected.filter((name) => !expected.has(name));
  if (canonicalJson(unexpected) !== canonicalJson(verification.unexpectedComponents)) {
    throw new Error(`${label} unexpected component inventory is invalid.`);
  }
  const changedRoutes = changedRoutePaths(
    { componentFingerprints: intent.baseComponentFingerprints, routeManifest: intent.baseRouteManifest },
    verification.resultBuildState
  );
  if (canonicalJson(changedRoutes) !== canonicalJson(verification.changedRoutes)) {
    throw new Error(`${label} changed route inventory is invalid.`);
  }
  const unexpectedRoutes = undeclaredRouteChanges(changedRoutes, intent.affectedRoutes);
  if (canonicalJson(unexpectedRoutes) !== canonicalJson(verification.unexpectedRoutes)) {
    throw new Error(`${label} unexpected route inventory is invalid.`);
  }
  const widened = unexpected.length > 0 || unexpectedRoutes.length > 0;
  const effectiveSurfaces = [...new Set([...intent.surfaces, ...(widened ? ['unknown'] : [])])].sort(comparePortable);
  if (canonicalJson(effectiveSurfaces) !== canonicalJson(verification.effectiveSurfaces)) {
    throw new Error(`${label} effective surfaces are invalid.`);
  }
  const chromeImpact = globalChromeImpact(intent.baseBuildState ?? {}, verification.resultBuildState);
  if (canonicalJson(chromeImpact) !== canonicalJson(verification.globalChromeImpact)) {
    throw new Error(`${label} global chrome impact inventory is invalid.`);
  }
  const required = requiredChecksForTransition(
    intent,
    widened ? [...unexpected, ...unexpectedRoutes] : [],
    chromeImpact
  );
  const checks = new Map((verification.checks ?? []).map((check) => [check?.id, check]));
  if (!Array.isArray(verification.checks) || checks.size !== verification.checks.length) {
    throw new Error(`${label} has duplicate or invalid check identifiers.`);
  }
  for (const requiredCheck of required) {
    const check = checks.get(requiredCheck.id);
    if (!isObject(check) || check.status !== 'pass' || !String(check.observation ?? '').trim()) {
      throw new Error(`${label} is missing passing required check ${requiredCheck.id}.`);
    }
    if (requiredCheck.evaluator !== 'machine') {
      validateEvidenceManifest(check.evidenceManifest, `${label} check ${check.id} evidenceManifest`, root);
    }
  }
  if (checks.size !== required.length) throw new Error(`${label} contains checks outside its derived required set.`);
  if (required.some((check) => check.id === 'global-chrome-regression')) {
    const anchorType = String(verification.globalChromeAnchor?.type ?? '');
    const anchorId = String(verification.globalChromeAnchor?.id ?? '');
    const anchor = readGlobalChromeAnchor(root, anchorType, anchorId, { required: true });
    const currentCapture = validateGlobalChromeCapture(
      verification.inspectionReport.globalChromeCapture,
      { stateFingerprint: result, requireAuthoritative: true }
    );
    validateScreenshotArtifacts(resolve(root, '..', '..'), currentCapture);
    const compared = compareGlobalChromeCaptures({
      anchor: anchor.capture,
      current: currentCapture,
      primaryRoutes: intent.baselineRoutes.primary
    });
    if (canonicalJson(compared) !== canonicalJson(verification.globalChromeRegression) || compared.passed !== true) {
      throw new Error(`${label} executable global chrome regression comparison is invalid or failing.`);
    }
  } else if (verification.globalChromeRegression !== null || verification.globalChromeAnchor !== null) {
    throw new Error(`${label} contains unrequired global chrome regression evidence.`);
  }
  const acceptance = new Map((verification.acceptanceEvidence ?? []).map((claim) => [claim?.criterionId, claim]));
  if (!Array.isArray(verification.acceptanceEvidence) ||
      acceptance.size !== verification.acceptanceEvidence.length) {
    throw new Error(`${label} has duplicate or invalid acceptance evidence identifiers.`);
  }
  for (const criterion of intent.acceptanceCriteria) {
    const claim = acceptance.get(criterion.id);
    if (!isObject(claim) || claim.status !== 'pass' || claim.criterionText !== criterion.text ||
        !String(claim.observation ?? '').trim()) {
      throw new Error(`${label} is missing passing evidence for acceptance criterion ${criterion.id}.`);
    }
    validateEvidenceManifest(claim.evidenceManifest, `${label} acceptance ${criterion.id} evidenceManifest`, root);
  }
  if (acceptance.size !== intent.acceptanceCriteria.length) {
    throw new Error(`${label} contains acceptance evidence outside its snapshotted criteria.`);
  }
  return verification;
}

function validateFullVerification(full, intent, targeted) {
  const label = `Change ${intent.id} full verification`;
  if (!isObject(full) || full.schemaVersion !== CHANGE_FULL_VERIFICATION_SCHEMA || full.changeId !== intent.id) {
    throw new Error(`${label} identity is invalid.`);
  }
  verifyCertificate(full, label);
  if (full.verificationMode !== 'authoritative-full-live' || full.authoritative !== true) {
    throw new Error(`${label} must be authoritative-full-live.`);
  }
  if ('checks' in full) throw new Error(`${label} must not synthesize semantic check passes.`);
  const base = fingerprint(full.baseFingerprint, `${label} baseFingerprint`);
  const result = fingerprint(full.resultFingerprint, `${label} resultFingerprint`);
  if (base !== intent.baseFingerprint || result !== targeted.resultFingerprint) {
    throw new Error(`${label} fingerprints do not match the evidence-recorded transition.`);
  }
  assertTimeBounds(full.checkedAt, `${label} checkedAt`, { notBefore: targeted.checkedAt });
  if (!isObject(full.embeddedPassingReport)) throw new Error(`${label} requires an embedded passing report.`);
  const reportHash = fingerprint(full.embeddedPassingReportSha256, `${label} embeddedPassingReportSha256`);
  if (sha256(full.embeddedPassingReport) !== reportHash) throw new Error(`${label} embedded passing report hash is invalid.`);
  const reportState = validatePassingReport(full.embeddedPassingReport, `${label} embeddedPassingReport`);
  if (reportState !== result) throw new Error(`${label} passing report does not match resultFingerprint.`);
  return full;
}

function validateAbandonment(abandonment, intent) {
  const label = `Change ${intent.id} abandonment`;
  if (!isObject(abandonment) || abandonment.schemaVersion !== CHANGE_ABANDONMENT_SCHEMA ||
      abandonment.changeId !== intent.id) {
    throw new Error(`${label} identity is invalid.`);
  }
  verifyCertificate(abandonment, label);
  if (!String(abandonment.reason ?? '').trim()) throw new Error(`${label} requires a reason.`);
  assertTimeBounds(abandonment.abandonedAt, `${label} abandonedAt`, { notBefore: intent.openedAt });
  if (fingerprint(abandonment.baseFingerprint, `${label} baseFingerprint`) !== intent.baseFingerprint) {
    throw new Error(`${label} baseFingerprint does not match the intent.`);
  }
  return abandonment;
}

function readOptionalTransition(path, label, validator) {
  if (!existsSync(path)) return null;
  assertRegularFile(path, label);
  return validator(readJson(path, label));
}

function readChangeRecord(root, id) {
  const intentPath = changePath(root, id);
  assertRegularFile(intentPath, `Change ${id} intent`);
  const intent = validateChangeIntent(readJson(intentPath, `Change ${id} intent`), id);
  const targeted = readOptionalTransition(
    changeVerificationPath(root, id),
    `Change ${id} targeted verification`,
    (value) => validateTargetedVerification(value, intent, root)
  );
  const full = readOptionalTransition(
    changeFullVerificationPath(root, id),
    `Change ${id} full verification`,
    (value) => {
      if (!targeted) throw new Error(`Change ${id} cannot have full verification before targeted evidence is recorded.`);
      return validateFullVerification(value, intent, targeted);
    }
  );
  const abandonment = readOptionalTransition(
    changeAbandonmentPath(root, id),
    `Change ${id} abandonment`,
    (value) => validateAbandonment(value, intent)
  );
  if (abandonment && (targeted || full)) {
    throw new Error(`Change ${id} has conflicting abandonment and verification transitions.`);
  }
  const status = abandonment ? 'abandoned' : full ? 'full_verified' : targeted ? 'evidence_recorded' : 'in_progress';
  return {
    ...intent,
    status,
    resultFingerprint: targeted?.resultFingerprint ?? '',
    evidenceRecordedAt: targeted?.checkedAt ?? '',
    fullVerifiedAt: full?.checkedAt ?? '',
    abandonedAt: abandonment?.abandonedAt ?? '',
    targetedVerification: targeted,
    fullVerification: full,
    abandonment
  };
}

function readChanges(root) {
  const directory = join(root, 'changes');
  assertDirectoryNotSymlink(directory, 'Changes directory');
  if (!existsSync(directory)) return [];
  const changes = [];
  for (const name of readdirSync(directory).sort(comparePortable)) {
    const directoryPath = join(directory, name);
    if (lstatSync(directoryPath).isSymbolicLink() || !lstatSync(directoryPath).isDirectory()) {
      throw new Error(`Lifecycle changes must contain only real directories: ${name}`);
    }
    const id = safeId(name, 'Change directory');
    changes.push(readChangeRecord(root, id));
  }
  return changes;
}

function validateCheckpoint(checkpoint, expectedId = '') {
  if (!isObject(checkpoint) || checkpoint.schemaVersion !== CHECKPOINT_SCHEMA || checkpoint.status !== 'passed') {
    throw new Error(`Checkpoint must use schemaVersion ${CHECKPOINT_SCHEMA} with status passed.`);
  }
  const id = safeId(checkpoint.checkpointId, 'Checkpoint ID');
  if (expectedId && id !== expectedId) throw new Error(`Checkpoint path ${expectedId} does not match checkpointId ${id}.`);
  timestamp(checkpoint.passedAt, `Checkpoint ${id} passedAt`);
  if (checkpoint.parentAnchorType !== 'change') throw new Error(`Checkpoint ${id} must bind a full-verified change anchor.`);
  safeId(checkpoint.parentAnchorId, `Checkpoint ${id} parentAnchorId`);
  safeId(checkpoint.changeId, `Checkpoint ${id} changeId`);
  const parent = fingerprint(checkpoint.parentSiteStateFingerprint, `Checkpoint ${id} parentSiteStateFingerprint`);
  const state = fingerprint(checkpoint.siteStateFingerprint, `Checkpoint ${id} siteStateFingerprint`);
  if (parent !== state) throw new Error(`Checkpoint ${id} must bind the exact full-verified change state.`);
  const buildState = validateBuildState(checkpoint.buildState, `Checkpoint ${id} buildState`);
  const reportState = validatePassingReport(checkpoint.passingReport, `Checkpoint ${id} passingReport`);
  if (state !== buildState || state !== reportState) throw new Error(`Checkpoint ${id} state does not match its report.`);
  verifyCertificate(checkpoint, `Checkpoint ${id}`);
  return checkpoint;
}

function readCheckpoints(root) {
  const directory = join(root, 'checkpoints');
  assertDirectoryNotSymlink(directory, 'Checkpoint directory');
  if (!existsSync(directory)) return [];
  const checkpoints = [];
  for (const name of readdirSync(directory).sort(comparePortable)) {
    const path = join(directory, name);
    if (!name.endsWith('.json')) throw new Error(`Unexpected file in checkpoint directory: ${name}`);
    assertRegularFile(path, `Checkpoint ${name}`);
    checkpoints.push(validateCheckpoint(readJson(path, `Checkpoint ${name}`), name.slice(0, -5)));
  }
  return checkpoints;
}

function anchorKey(type, id) {
  return `${type}:${id}`;
}

function buildLifecycleGraph(root, baseline = readInitialBaseline(root)) {
  const changes = readChanges(root);
  const checkpoints = readCheckpoints(root);
  if (!baseline) {
    if (changes.length || checkpoints.length) throw new Error('Lifecycle changes and checkpoints require an initial baseline.');
    return { anchors: new Map(), chain: [], changes, checkpoints, tail: null };
  }
  const initial = {
    id: 'initial',
    type: 'initial',
    fingerprint: baseline.siteStateFingerprint,
    buildState: baseline.buildState,
    routeInventory: routeInventoryFromReport(baseline.passingReport),
    credential: 'full_verified',
    passedAt: baseline.passedAt
  };
  const anchors = new Map([[anchorKey('initial', 'initial'), initial]]);
  const children = new Map();
  const pending = [];
  for (const change of changes.filter((item) => ['evidence_recorded', 'full_verified'].includes(item.status))) {
    pending.push({
      key: anchorKey('change', change.id),
      parentKey: anchorKey(change.baseAnchorType, change.baseAnchorId),
      parentFingerprint: change.baseFingerprint,
      anchor: {
        id: change.id,
        type: 'change',
        fingerprint: change.resultFingerprint,
        buildState: change.targetedVerification.resultBuildState,
        routeInventory: routeInventoryFromReport(change.targetedVerification.inspectionReport),
        credential: change.status,
        passedAt: change.fullVerifiedAt || change.evidenceRecordedAt
      }
    });
  }
  for (const checkpoint of checkpoints) {
    const change = changes.find((item) => item.id === checkpoint.changeId);
    if (!change || change.status !== 'full_verified') {
      throw new Error(`Checkpoint ${checkpoint.checkpointId} does not bind a full_verified change.`);
    }
    pending.push({
      key: anchorKey('checkpoint', checkpoint.checkpointId),
      parentKey: anchorKey(checkpoint.parentAnchorType, checkpoint.parentAnchorId),
      parentFingerprint: checkpoint.parentSiteStateFingerprint,
      anchor: {
        id: checkpoint.checkpointId,
        type: 'checkpoint',
        fingerprint: checkpoint.siteStateFingerprint,
        buildState: checkpoint.buildState,
        routeInventory: routeInventoryFromReport(checkpoint.passingReport),
        credential: 'full_verified',
        passedAt: checkpoint.passedAt,
        changeId: checkpoint.changeId
      }
    });
  }
  const remaining = [...pending].sort((left, right) => comparePortable(left.key, right.key));
  let progressed = true;
  while (remaining.length && progressed) {
    progressed = false;
    for (let index = remaining.length - 1; index >= 0; index -= 1) {
      const candidate = remaining[index];
      const parent = anchors.get(candidate.parentKey);
      if (!parent) continue;
      if (parent.fingerprint !== candidate.parentFingerprint) {
        throw new Error(`Lifecycle anchor ${candidate.key} base fingerprint does not match ${candidate.parentKey}.`);
      }
      if (anchors.has(candidate.key)) throw new Error(`Duplicate lifecycle anchor ${candidate.key}.`);
      const existingChild = children.get(candidate.parentKey);
      if (existingChild && existingChild !== candidate.key) {
        throw new Error(`Lifecycle fork detected at ${candidate.parentKey}: ${existingChild} and ${candidate.key}.`);
      }
      children.set(candidate.parentKey, candidate.key);
      anchors.set(candidate.key, candidate.anchor);
      remaining.splice(index, 1);
      progressed = true;
    }
  }
  if (remaining.length) {
    throw new Error(`Lifecycle contains unreachable or circular anchors: ${remaining.map((item) => item.key).sort(comparePortable).join(', ')}.`);
  }
  const chain = [];
  let cursor = anchorKey('initial', 'initial');
  while (cursor) {
    const anchor = anchors.get(cursor);
    if (!anchor) throw new Error(`Lifecycle chain references missing anchor ${cursor}.`);
    chain.push(anchor);
    cursor = children.get(cursor) ?? '';
  }
  const tail = chain.at(-1);
  for (const change of changes) {
    const base = anchors.get(anchorKey(change.baseAnchorType, change.baseAnchorId));
    if (!base || base.fingerprint !== change.baseFingerprint) {
      throw new Error(`Change ${change.id} does not bind an existing structural anchor.`);
    }
    if (change.status === 'in_progress' && (base.type !== tail.type || base.id !== tail.id)) {
      throw new Error(`Active change ${change.id} does not begin at the latest structural anchor.`);
    }
  }
  const active = changes.filter((change) => change.status === 'in_progress');
  if (active.length > 1) throw new Error(`Lifecycle contains multiple active changes: ${active.map((item) => item.id).join(', ')}.`);
  return { anchors, chain, changes, checkpoints, tail, active: active[0] ?? null };
}

function validateCurrentState(state) {
  if (!isObject(state) || state.schemaVersion !== CURRENT_STATE_SCHEMA) {
    throw new Error(`Current lifecycle state must use schemaVersion ${CURRENT_STATE_SCHEMA}.`);
  }
  timestamp(state.checkedAt, 'Current lifecycle state checkedAt');
  fingerprint(state.currentSiteStateFingerprint, 'Current lifecycle state fingerprint');
  const buildState = validateBuildState(state.buildState, 'Current lifecycle state buildState');
  if (buildState !== state.currentSiteStateFingerprint) {
    throw new Error('Current lifecycle state buildState does not match currentSiteStateFingerprint.');
  }
  if (typeof state.currentStateVerified !== 'boolean' || typeof state.currentStateEvidenceRecorded !== 'boolean') {
    throw new Error('Current lifecycle state verification classifications must be boolean.');
  }
  verifyCertificate(state, 'Current lifecycle state');
  return state;
}

function readCurrentState(root, { required = true } = {}) {
  const path = currentStatePath(root);
  if (!existsSync(path)) {
    if (required) throw new Error('Current lifecycle state does not exist. Run the live verifier to inspect the current Drupal state.');
    return null;
  }
  assertRegularFile(path, 'Current lifecycle state');
  return validateCurrentState(readJson(path, 'Current lifecycle state'));
}

function compactCurrentState(state) {
  if (!state) return null;
  return {
    schemaVersion: state.schemaVersion,
    checkedAt: state.checkedAt,
    recordedAt: state.recordedAt,
    initialBaseline: state.initialBaseline,
    latestCheckpoint: state.latestCheckpoint,
    latestAnchor: state.latestAnchor,
    latestVerifiedAnchor: state.latestVerifiedAnchor,
    currentSiteStateFingerprint: state.currentSiteStateFingerprint,
    relation: state.relation,
    activeChange: state.activeChange,
    classifiedCurrentState: state.classifiedCurrentState,
    currentStateVerified: state.currentStateVerified,
    currentStateEvidenceRecorded: state.currentStateEvidenceRecorded,
    currentStateClassification: state.currentStateClassification,
    currentVerification: state.currentVerification
  };
}

function compactChange(change) {
  return {
    id: change.id,
    kind: change.kind,
    status: change.status,
    summary: change.summary,
    openedAt: change.openedAt,
    baseAnchorId: change.baseAnchorId,
    baseAnchorType: change.baseAnchorType,
    baseFingerprint: change.baseFingerprint,
    surfaces: change.surfaces,
    publicRouteScope: change.publicRouteScope,
    affectedRoutes: change.affectedRoutes,
    acceptanceCriteria: change.acceptanceCriteria,
    requiredChecks: change.requiredChecks,
    resultFingerprint: change.resultFingerprint,
    evidenceRecordedAt: change.evidenceRecordedAt,
    fullVerifiedAt: change.fullVerifiedAt,
    abandonedAt: change.abandonedAt
  };
}

function projectRootForPacket(packet) {
  let candidate = packet;
  while (true) {
    if (existsSync(join(candidate, '.ddev', 'config.yaml')) || existsSync(join(candidate, 'composer.json'))) return candidate;
    const parent = dirname(candidate);
    if (parent === candidate) return dirname(packet);
    candidate = parent;
  }
}

function portableProjectPath(projectRoot, path) {
  return relative(projectRoot, path).split(sep).join('/');
}

function safeEvidenceReference(projectRoot, packet, reference) {
  const text = String(reference ?? '').trim().replaceAll('\\', '/');
  if (!text || isAbsolute(text) || text.startsWith('/') || /^[a-z]:\//i.test(text) ||
      text.split('/').some((part) => part === '..' || part === '')) {
    throw new Error(`Evidence reference must be a non-traversing project-relative path: ${String(reference)}`);
  }
  const path = ['evidence/', 'lifecycle/'].some((prefix) => text.startsWith(prefix))
    ? resolve(packet, text)
    : resolve(projectRoot, text);
  const safePath = assertContainedRegularFile(projectRoot, path, `Evidence reference ${text}`);
  const manifest = collectFileManifest(projectRoot, [portableProjectPath(projectRoot, safePath)]);
  return {
    path: text,
    absolutePath: safePath,
    sha256: manifest.entries[0].sha256,
    size: manifest.entries[0].size
  };
}

function snapshotEvidenceReference({ root, projectRoot, changeId, reference }) {
  const suffix = basename(reference.absolutePath).replace(/[^a-zA-Z0-9._-]+/g, '-') || 'evidence';
  const filename = `${reference.sha256.slice('sha256:'.length)}-${suffix}`;
  const directory = join(changeDirectory(root, changeId), 'evidence');
  mkdirSync(directory, { recursive: true });
  assertDirectoryNotSymlink(directory, `Change ${changeId} evidence snapshot directory`);
  const path = join(directory, filename);
  if (existsSync(path)) {
    assertRegularFile(path, `Change ${changeId} evidence snapshot`);
  } else {
    writeFileSync(path, readFileSync(reference.absolutePath), { flag: 'wx' });
  }
  const manifest = collectFileManifest(projectRoot, [portableProjectPath(projectRoot, path)]);
  if (manifest.entries[0].sha256 !== reference.sha256 || manifest.entries[0].size !== reference.size) {
    throw new Error(`Change ${changeId} evidence snapshot does not match ${reference.path}.`);
  }
  return {
    originalPath: reference.path,
    path: portableProjectPath(projectRoot, path),
    sha256: reference.sha256,
    size: reference.size
  };
}

function loadVerificationInput(verification, projectRoot) {
  if (isObject(verification)) return cloneCanonical(verification);
  const text = String(verification ?? '').trim();
  if (!text) throw new Error('A change verification object or in-project JSON path is required.');
  const path = assertContainedRegularFile(
    projectRoot,
    resolve(process.cwd(), text),
    'Change verification input'
  );
  return readJson(path, 'Change verification input');
}

function derivedMachineChecks(report, resultFingerprint, baselineRoutes, affectedRoutes, globalChromeRegression = null) {
  const reportHash = sha256(report);
  const facts = machineFacts(report, 'Fresh inspection', baselineRoutes, affectedRoutes);
  const checks = new Map([
    ['state-bound', {
      id: 'state-bound',
      status: 'pass',
      observation: `Fresh live inspection bound the exact result state ${resultFingerprint}.`,
      evidence: [`embedded-inspection-report:${reportHash}`]
    }],
    ['config-clean', {
      id: 'config-clean',
      status: 'pass',
      observation: 'Fresh live inspection reported clean active configuration, tracked YAML, and exact tracked readback.',
      evidence: [`embedded-inspection-report:${reportHash}`]
    }],
    ['baseline-route-smoke', {
      id: 'baseline-route-smoke',
      status: 'pass',
      observation: `Fresh live inspection passed ${facts.primaryRouteCount} primary and ${facts.targetRequiredRouteCount} target-required route checks.`,
      evidence: [`embedded-inspection-report:${reportHash}`]
    }]
  ]);
  if (globalChromeRegression) {
    checks.set('global-chrome-regression', {
      id: 'global-chrome-regression',
      status: 'pass',
      observation: `Verifier-owned desktop/mobile capture comparison passed ${globalChromeRegression.findings.length} primary-route viewport checks against ${globalChromeRegression.anchorStateFingerprint}.`,
      evidence: [
        `anchor-capture:${globalChromeRegression.anchorCaptureFingerprint}`,
        `result-capture:${globalChromeRegression.resultCaptureFingerprint}`,
        `comparison:${globalChromeRegression.comparisonFingerprint}`
      ]
    });
  }
  return checks;
}

function buildTargetedVerification({ input, change, report, projectRoot, packet, root, globalChromeAnchor }) {
  if (!isObject(input) || input.schemaVersion !== CHANGE_VERIFICATION_SCHEMA || input.changeId !== change.id) {
    throw new Error(`Change verification must use schemaVersion ${CHANGE_VERIFICATION_SCHEMA} for ${change.id}.`);
  }
  assertTimeBounds(input.checkedAt, 'Change verification checkedAt', { notBefore: change.openedAt });
  const base = fingerprint(input.baseFingerprint, 'Change verification baseFingerprint');
  const result = fingerprint(input.resultFingerprint, 'Change verification resultFingerprint');
  if (base !== change.baseFingerprint) throw new Error('Change verification baseFingerprint does not match the change intent.');
  if (result !== report.buildState.fingerprint) {
    throw new Error('Change verification resultFingerprint does not match the fresh inspected current site state.');
  }
  if (base === result) throw new Error('Change verification result must differ from its base fingerprint.');
  const changed = changedComponents(change.baseComponentFingerprints, report.buildState.componentFingerprints);
  const expected = new Set(change.expectedComponents);
  const unexpected = changed.filter((name) => !expected.has(name));
  const changedRoutes = changedRoutePaths(
    { componentFingerprints: change.baseComponentFingerprints, routeManifest: change.baseRouteManifest },
    report.buildState
  );
  const unexpectedRoutes = undeclaredRouteChanges(changedRoutes, change.affectedRoutes);
  const widened = unexpected.length > 0 || unexpectedRoutes.length > 0;
  const effectiveSurfaces = [...new Set([...change.surfaces, ...(widened ? ['unknown'] : [])])].sort(comparePortable);
  const chromeImpact = globalChromeImpact(change.baseBuildState ?? {}, report.buildState);
  const required = requiredChecksForTransition(
    change,
    widened ? [...unexpected, ...unexpectedRoutes] : [],
    chromeImpact
  );
  let globalChromeRegression = null;
  let globalChromeAnchorIdentity = null;
  if (required.some((check) => check.id === 'global-chrome-regression')) {
    if (!globalChromeAnchor) {
      throw new Error('Executable global chrome regression requires a persisted latest verified anchor capture.');
    }
    const currentCapture = validateGlobalChromeCapture(report.globalChromeCapture, {
      stateFingerprint: result,
      requireAuthoritative: true
    });
    validateScreenshotArtifacts(packet, currentCapture);
    globalChromeRegression = compareGlobalChromeCaptures({
      anchor: globalChromeAnchor.capture,
      current: currentCapture,
      primaryRoutes: change.baselineRoutes.primary
    });
    if (!globalChromeRegression.passed) {
      throw new Error(`Executable global chrome regression failed: ${globalChromeRegression.errors.join(' ')}`);
    }
    globalChromeAnchorIdentity = {
      type: globalChromeAnchor.anchorType,
      id: globalChromeAnchor.anchorId,
      stateFingerprint: globalChromeAnchor.siteStateFingerprint,
      captureFingerprint: globalChromeAnchor.captureFingerprint
    };
  }
  if (!Array.isArray(input.checks)) {
    throw new Error('Change verification checks must be an array.');
  }
  const authored = new Map();
  for (const check of input.checks) {
    if (!isObject(check) || !String(check.id ?? '').trim()) throw new Error('Every change verification check requires an id.');
    if (authored.has(check.id)) throw new Error(`Change verification has duplicate check ${check.id}.`);
    authored.set(check.id, check);
  }
  if (authored.size !== input.checks.length) {
    throw new Error('Change verification has duplicate or invalid check identifiers.');
  }
  const machine = derivedMachineChecks(
    report,
    result,
    change.baselineRoutes,
    change.affectedRoutes,
    globalChromeRegression
  );
  const checks = [];
  for (const requiredCheck of required) {
    if (requiredCheck.evaluator === 'machine') {
      const evaluated = machine.get(requiredCheck.id);
      if (!evaluated) {
        throw new Error(`No machine evaluator is available for snapshotted check ${requiredCheck.id}.`);
      }
      checks.push(evaluated);
      continue;
    }
    const check = authored.get(requiredCheck.id);
    if (!isObject(check) || check.status !== 'pass') {
      throw new Error(`Change verification is missing passing required check ${requiredCheck.id}.`);
    }
    if (!String(check.observation ?? '').trim()) {
      throw new Error(`Change verification check ${requiredCheck.id} requires a non-empty observation.`);
    }
    if (!Array.isArray(check.evidence) || check.evidence.length === 0) {
      throw new Error(`Change verification check ${requiredCheck.id} requires packet- or project-local evidence.`);
    }
    const evidenceManifest = check.evidence
      .map((reference) => safeEvidenceReference(projectRoot, packet, reference))
      .map((reference) => snapshotEvidenceReference({
        root,
        projectRoot,
        changeId: change.id,
        reference
      }));
    checks.push({
      id: requiredCheck.id,
      status: 'pass',
      observation: String(check.observation).trim(),
      evidence: evidenceManifest.map((entry) => entry.path),
      sourceEvidence: evidenceManifest.map((entry) => entry.originalPath),
      evidenceManifest
    });
  }
  const authoredAcceptance = new Map((input.acceptanceEvidence ?? []).map((claim) => [claim?.criterionId, claim]));
  if (!Array.isArray(input.acceptanceEvidence) || authoredAcceptance.size !== input.acceptanceEvidence.length) {
    throw new Error('Change verification has duplicate or invalid acceptance evidence identifiers.');
  }
  const acceptanceEvidence = [];
  for (const criterion of change.acceptanceCriteria) {
    const claim = authoredAcceptance.get(criterion.id);
    if (!isObject(claim) || claim.status !== 'pass' || !String(claim.observation ?? '').trim() ||
        !Array.isArray(claim.evidence) || claim.evidence.length === 0) {
      throw new Error(`Change verification is missing passing evidence for acceptance criterion ${criterion.id}.`);
    }
    const evidenceManifest = claim.evidence
      .map((reference) => safeEvidenceReference(projectRoot, packet, reference))
      .map((reference) => snapshotEvidenceReference({
        root,
        projectRoot,
        changeId: change.id,
        reference
      }));
    acceptanceEvidence.push({
      criterionId: criterion.id,
      criterionText: criterion.text,
      status: 'pass',
      observation: String(claim.observation).trim(),
      evidence: evidenceManifest.map((entry) => entry.path),
      sourceEvidence: evidenceManifest.map((entry) => entry.originalPath),
      evidenceManifest
    });
  }
  if (authoredAcceptance.size !== change.acceptanceCriteria.length) {
    throw new Error('Change verification contains acceptance evidence outside the snapshotted criteria.');
  }
  const inspectionReport = cloneCanonical(report);
  return certify({
    schemaVersion: CHANGE_VERIFICATION_SCHEMA,
    changeId: change.id,
    checkedAt: report.checkedAt,
    evidenceCheckedAt: input.checkedAt,
    baseFingerprint: base,
    resultFingerprint: result,
    verificationMode: 'evidence-bound-targeted',
    authoritative: false,
    currentStateVerified: false,
    semanticEvidenceIndependentlyEvaluated: false,
    declaredSurfaces: change.surfaces,
    effectiveSurfaces,
    changedComponents: changed,
    unexpectedComponents: unexpected,
    changedRoutes,
    unexpectedRoutes,
    resultBuildState: cloneCanonical(report.buildState),
    inspectionReportSha256: sha256(inspectionReport),
    inspectionReport,
    machineFacts: machineFacts(report, 'Fresh inspection', change.baselineRoutes, change.affectedRoutes),
    globalChromeImpact: chromeImpact,
    globalChromeAnchor: globalChromeAnchorIdentity,
    globalChromeRegression,
    checks: checks.sort((left, right) => comparePortable(left.id, right.id)),
    acceptanceEvidence: acceptanceEvidence.sort((left, right) => comparePortable(left.criterionId, right.criterionId))
  });
}

function createInitialBaseline(root, report) {
  const stateFingerprint = validatePassingReport(report, 'Initial passing report');
  const value = certify({
    schemaVersion: BASELINE_SCHEMA,
    baselineId: 'initial',
    status: 'passed',
    passedAt: report.checkedAt,
    claimScope: 'complete-local-rebuild',
    siteStateFingerprint: stateFingerprint,
    buildState: cloneCanonical(report.buildState),
    passingReport: cloneCanonical(report)
  });
  writeCreateOnlyJson(baselinePath(root), value, 'Initial baseline');
  return validateInitialBaseline(value);
}

function bindAuthoritativeFullVerification({ root, changeId, report }) {
  const id = safeId(changeId, 'Change ID');
  const change = readChangeRecord(root, id);
  if (!change.targetedVerification) {
    throw new Error(`Change ${id} must be evidence_recorded before a full verification can bind it.`);
  }
  const result = validatePassingReport(report, `Change ${id} full live verification`);
  machineFacts(
    report,
    `Change ${id} full live verification`,
    change.baselineRoutes,
    change.affectedRoutes
  );
  assertTimeBounds(report.checkedAt, `Change ${id} full live verification checkedAt`, {
    notBefore: change.targetedVerification.checkedAt,
    fresh: true
  });
  if (result !== change.resultFingerprint) {
    throw new Error(`Change ${id} full verification result does not match its evidence-recorded state.`);
  }
  const path = changeFullVerificationPath(root, id);
  if (existsSync(path)) {
    const existing = validateFullVerification(readJson(path, `Change ${id} full verification`), change, change.targetedVerification);
    if (existing.resultFingerprint !== result) {
      throw new Error(`Change ${id} already has a different create-only full verification.`);
    }
    return readChangeRecord(root, id);
  }
  const embeddedPassingReport = cloneCanonical(report);
  const value = certify({
    schemaVersion: CHANGE_FULL_VERIFICATION_SCHEMA,
    changeId: id,
    checkedAt: report.checkedAt,
    baseFingerprint: change.baseFingerprint,
    resultFingerprint: result,
    verificationMode: 'authoritative-full-live',
    authoritative: true,
    embeddedPassingReportSha256: sha256(embeddedPassingReport),
    embeddedPassingReport
  });
  writeCreateOnlyJson(path, value, `Change ${id} full verification`);
  return readChangeRecord(root, id);
}

function createCheckpoint({ root, checkpointId, report, changeId }) {
  const id = safeId(checkpointId, 'Checkpoint ID');
  if (existsSync(checkpointPath(root, id))) {
    throw new Error(`Checkpoint ${id} already exists and is create-only: ${checkpointPath(root, id)}`);
  }
  const change = readChangeRecord(root, safeId(changeId, 'Change ID'));
  if (change.status !== 'full_verified') {
    throw new Error(`Checkpoint ${id} requires change ${change.id} to be full_verified.`);
  }
  const state = validatePassingReport(report, `Checkpoint ${id} passing report`);
  if (state !== change.resultFingerprint) {
    throw new Error(`Checkpoint ${id} does not match full_verified change ${change.id}.`);
  }
  const graph = buildLifecycleGraph(root, readInitialBaseline(root, { required: true }));
  if (graph.active) {
    throw new Error(`Checkpoint ${id} cannot be created while change ${graph.active.id} is active.`);
  }
  if (graph.tail.type !== 'change' || graph.tail.id !== change.id) {
    throw new Error(`Checkpoint ${id} would fork the lifecycle; ${change.id} is not the latest structural anchor.`);
  }
  const value = certify({
    schemaVersion: CHECKPOINT_SCHEMA,
    checkpointId: id,
    status: 'passed',
    passedAt: report.checkedAt,
    parentAnchorId: change.id,
    parentAnchorType: 'change',
    parentSiteStateFingerprint: change.resultFingerprint,
    siteStateFingerprint: state,
    changeId: change.id,
    buildState: cloneCanonical(report.buildState),
    passingReport: cloneCanonical(report)
  });
  writeCreateOnlyJson(checkpointPath(root, id), value, `Checkpoint ${id}`);
  return validateCheckpoint(value, id);
}

function currentStateForReport(root, baseline, report, { boundChangeId = '', checkpointId = '' } = {}) {
  const fingerprintValue = validateBuildState(report.buildState, 'Current report buildState');
  const graph = buildLifecycleGraph(root, baseline);
  const matching = graph.chain.filter((anchor) => anchor.fingerprint === fingerprintValue).at(-1) ?? null;
  const verifiedCredential = matching && ['initial', 'checkpoint'].includes(matching.type) ||
    matching?.credential === 'full_verified';
  const evidenceCredential = matching?.type === 'change' && matching.credential === 'evidence_recorded';
  const authoritativePass = authoritativePassingReport(report);
  const relation = !baseline
    ? 'no-initial-baseline'
    : !matching
      ? 'changed-since-latest-anchor'
      : evidenceCredential
        ? 'matches-evidence-recorded-change'
        : matching.type === 'change'
          ? 'matches-full-verified-change'
        : matching.type === 'checkpoint'
            ? 'matches-checkpoint'
            : 'matches-initial-baseline';
  const currentStateVerified = Boolean(authoritativePass && verifiedCredential);
  const currentStateEvidenceRecorded = Boolean(evidenceCredential);
  const facts = isObject(report.drupalRuntime) && Array.isArray(report.routeChecks)
    ? {
        configClean: report.drupalRuntime.configStatusClean === true &&
          report.drupalRuntime.configSyncTracked === true &&
          report.drupalRuntime.configSyncDirectoryMatchesPacket === true &&
          report.drupalRuntime.trackedConfigReadbackMatches === true &&
          report.drupalRuntime.trackedConfigYamlPresent !== false,
        primaryRouteCount: report.routeChecks.length,
        targetRequiredRouteCount: Array.isArray(report.targetRequiredRouteChecks) ? report.targetRequiredRouteChecks.length : 0,
        routesClean: report.liveTargetValid === true && report.routeChecks.length > 0 &&
          [...report.routeChecks, ...(report.targetRequiredRouteChecks ?? [])]
            .every((check) => check?.passed === true && (check.errors ?? []).length === 0)
      }
    : null;
  return certify({
    schemaVersion: CURRENT_STATE_SCHEMA,
    lifecycleSchemaVersion: LIFECYCLE_SCHEMA,
    checkedAt: timestamp(report.checkedAt, 'Current report checkedAt'),
    recordedAt: new Date().toISOString(),
    currentSiteStateFingerprint: fingerprintValue,
    buildState: cloneCanonical(report.buildState),
    inspectionReportSha256: sha256(report),
    machineFacts: facts,
    initialBaseline: baseline
      ? {
          baselineId: 'initial',
          status: 'passed',
          passedAt: baseline.passedAt,
          siteStateFingerprint: baseline.siteStateFingerprint
        }
      : { baselineId: 'initial', status: 'not-recorded' },
    latestCheckpoint: (() => {
      const latest = [...graph.chain].reverse().find((anchor) => anchor.type === 'checkpoint');
      return latest
        ? {
            checkpointId: latest.id,
            passedAt: latest.passedAt,
            siteStateFingerprint: latest.fingerprint,
            changeId: latest.changeId ?? ''
          }
        : null;
    })(),
    latestAnchor: graph.tail
      ? {
          anchorId: graph.tail.id,
          anchorType: graph.tail.type,
          credential: graph.tail.credential,
          passedAt: graph.tail.passedAt,
          siteStateFingerprint: graph.tail.fingerprint
        }
      : null,
    latestVerifiedAnchor: (() => {
      const latest = [...graph.chain].reverse().find((anchor) =>
        ['initial', 'checkpoint'].includes(anchor.type) || anchor.credential === 'full_verified'
      );
      return latest
        ? {
            anchorId: latest.id,
            anchorType: latest.type,
            credential: latest.credential,
            passedAt: latest.passedAt,
            siteStateFingerprint: latest.fingerprint
          }
        : null;
    })(),
    relation,
    activeChange: graph.active
      ? {
          id: graph.active.id,
          kind: graph.active.kind,
          status: graph.active.status,
          baseAnchorId: graph.active.baseAnchorId,
          baseAnchorType: graph.active.baseAnchorType,
          baseFingerprint: graph.active.baseFingerprint
        }
      : null,
    classifiedCurrentState: Boolean(matching || graph.active),
    currentStateVerified,
    currentStateEvidenceRecorded,
    currentStateClassification: matching
      ? {
          id: matching.id,
          kind: matching.type,
          status: matching.credential
        }
      : graph.active
        ? { id: graph.active.id, kind: graph.active.kind, status: 'in_progress' }
        : { id: '', kind: 'unclassified', status: 'unverified' },
    currentVerification: {
      checkedAt: report.checkedAt,
      completeLocalRebuildClaimAllowed: report.completeLocalRebuildClaimAllowed === true,
      authoritative: report.drupalRuntime?.authoritativeForCompletion === true,
      boundChangeId,
      checkpointCreated: checkpointId
    }
  });
}

function recordCurrentState(root, baseline, report, operation = {}) {
  const value = currentStateForReport(root, baseline, report, operation);
  writeAtomicJson(currentStatePath(root), value, 'Current lifecycle state');
  return compactCurrentState(validateCurrentState(value));
}

/** Record lifecycle truth for a live verification report. */
export function applyVerificationLifecycle({
  packetDir = 'review-packet',
  report,
  checkpointId = '',
  changeId = ''
} = {}) {
  if (!isObject(report)) throw new Error('applyVerificationLifecycle requires a verification report object.');
  const { root } = packetEvidence(packetDir);
  ensureLifecycleDirectories(root);
  let baseline = readInitialBaseline(root);
  if (!baseline && authoritativePassingReport(report)) baseline = createInitialBaseline(root, report);
  if (checkpointId) {
    const preflightGraph = buildLifecycleGraph(root, baseline);
    if (preflightGraph.active) {
      throw new Error(`A checkpoint cannot be created while change ${preflightGraph.active.id} is active.`);
    }
  }
  let boundChange = null;
  if (changeId) {
    if (!authoritativePassingReport(report)) {
      throw new Error('Binding a change requires a currently passing authoritative full verification report.');
    }
    boundChange = bindAuthoritativeFullVerification({ root, changeId, report });
  }
  let checkpoint = null;
  if (checkpointId) {
    if (!changeId || !boundChange) throw new Error('A checkpoint must bind the same full_verified change.');
    checkpoint = createCheckpoint({ root, checkpointId, report, changeId: boundChange.id });
  }
  const finalGraph = buildLifecycleGraph(root, baseline);
  const chromeAnchor = persistMatchingGlobalChromeAnchor(root, finalGraph, report);
  const current = recordCurrentState(root, baseline, report, {
    boundChangeId: boundChange?.id ?? '',
    checkpointId: checkpoint?.checkpointId ?? ''
  });
  return {
    ...current,
    globalChromeAnchor: chromeAnchor
      ? {
          anchorType: chromeAnchor.anchorType,
          anchorId: chromeAnchor.anchorId,
          siteStateFingerprint: chromeAnchor.siteStateFingerprint,
          captureFingerprint: chromeAnchor.captureFingerprint
        }
      : null
  };
}

/** Read and validate lifecycle records plus the generated current-state snapshot. */
export function readLifecycleStatus(options = {}) {
  const packetDir = typeof options === 'string' ? options : options.packetDir ?? 'review-packet';
  const { root } = packetEvidence(packetDir);
  ensureLifecycleDirectories(root);
  const baseline = readInitialBaseline(root);
  const graph = buildLifecycleGraph(root, baseline);
  const currentState = readCurrentState(root, { required: false });
  return {
    schemaVersion: LIFECYCLE_SCHEMA,
    initialBaseline: baseline
      ? {
          baselineId: baseline.baselineId,
          status: baseline.status,
          passedAt: baseline.passedAt,
          siteStateFingerprint: baseline.siteStateFingerprint
        }
      : null,
    checkpoints: graph.checkpoints.map((checkpoint) => ({
      checkpointId: checkpoint.checkpointId,
      passedAt: checkpoint.passedAt,
      siteStateFingerprint: checkpoint.siteStateFingerprint,
      changeId: checkpoint.changeId,
      parentAnchorId: checkpoint.parentAnchorId,
      parentAnchorType: checkpoint.parentAnchorType
    })),
    changes: graph.changes.map((change) => ({
      id: change.id,
      kind: change.kind,
      status: change.status,
      summary: change.summary,
      baseAnchorId: change.baseAnchorId,
      baseAnchorType: change.baseAnchorType,
      baseFingerprint: change.baseFingerprint,
      surfaces: change.surfaces,
      publicRouteScope: change.publicRouteScope,
      affectedRoutes: change.affectedRoutes,
      resultFingerprint: change.resultFingerprint,
      evidenceRecordedAt: change.evidenceRecordedAt,
      fullVerifiedAt: change.fullVerifiedAt,
      abandonedAt: change.abandonedAt
    })),
    latestAnchor: graph.tail
      ? {
          id: graph.tail.id,
          type: graph.tail.type,
          credential: graph.tail.credential,
          fingerprint: graph.tail.fingerprint
        }
      : null,
    currentState: compactCurrentState(currentState),
    currentStateFresh: currentState
      ? Date.now() - Date.parse(currentState.checkedAt) <= FRESH_INSPECTION_MS &&
        Date.parse(currentState.checkedAt) <= Date.now() + FUTURE_SKEW_MS
      : false
  };
}

/** Create the sole active repair or extension intent from the structural tail. */
export function beginChange({
  packetDir = 'review-packet',
  id,
  kind,
  summary,
  surfaces = [],
  routes = [],
  noPublicRoute = false,
  acceptance = [],
  adoptCurrent = false
} = {}) {
  const { root } = packetEvidence(packetDir);
  ensureLifecycleDirectories(root);
  const baseline = readInitialBaseline(root, { required: true });
  const graph = buildLifecycleGraph(root, baseline);
  const changeId = safeId(id, 'Change ID');
  if (!['repair', 'extension'].includes(kind)) throw new Error('Change kind must be repair or extension.');
  if (graph.active) throw new Error(`Change ${graph.active.id} is already in progress; complete or abandon it first.`);
  const textSummary = String(summary ?? '').trim();
  if (!textSummary) throw new Error('Change summary is required.');
  const current = readCurrentState(root);
  assertTimeBounds(current.checkedAt, 'Current lifecycle state checkedAt', { fresh: true });
  const latestAbandonment = graph.changes
    .filter((change) => change.status === 'abandoned')
    .map((change) => change.abandonedAt)
    .sort(comparePortable)
    .at(-1);
  if (latestAbandonment && Date.parse(current.checkedAt) < Date.parse(latestAbandonment)) {
    throw new Error(
      'Current lifecycle state predates the latest abandonment. Run a fresh live verifier inspection, ' +
      'then revert the abandoned edits or use --adopt-current to classify any state that remains.'
    );
  }
  const alreadyChanged = current.currentSiteStateFingerprint !== graph.tail.fingerprint;
  if (alreadyChanged && !adoptCurrent) {
    throw new Error(
      'The freshly inspected current state differs from the latest structural anchor. ' +
      'Use --adopt-current only when this change intentionally classifies that existing state.'
    );
  }
  const normalizedSurfaces = [...new Set((Array.isArray(surfaces) ? surfaces : [surfaces])
    .map((surface) => String(surface).trim()).filter(Boolean))];
  if (normalizedSurfaces.length === 0) normalizedSurfaces.push('unknown');
  const explicitlyRequestedUnknown = normalizedSurfaces.includes('unknown');
  if (adoptCurrent && !normalizedSurfaces.includes('unknown')) normalizedSurfaces.push('unknown');
  normalizedSurfaces.sort(comparePortable);
  for (const surface of normalizedSurfaces) {
    if (!SURFACES.has(surface)) {
      throw new Error(`Unsupported change surface ${surface}. Supported values: ${[...SURFACES].sort(comparePortable).join(', ')}.`);
    }
  }
  const globalRouteImpact = normalizedSurfaces.some((surface) => ['theme-global', 'navigation'].includes(surface));
  if (globalRouteImpact && noPublicRoute) {
    throw new Error('Global theme or navigation impact cannot use --no-public-route.');
  }
  const declaredPublicImpact = normalizedSurfaces.some((surface) => (
    PUBLIC_ROUTE_SURFACES.has(surface) &&
    !(surface === 'unknown' && adoptCurrent && noPublicRoute && !explicitlyRequestedUnknown)
  ));
  if (declaredPublicImpact && noPublicRoute) {
    throw new Error(
      `--no-public-route cannot be used with a public-output or unresolved surface: ${normalizedSurfaces.join(', ')}.`
    );
  }
  const affectedRoutes = globalRouteImpact
    ? ['*']
    : [...new Set((Array.isArray(routes) ? routes : [routes])
        .map((path) => String(path).trim())
        .filter(Boolean)
        .map((path) => normalizedRoutePath(path)))].sort(comparePortable);
  if (!globalRouteImpact && affectedRoutes.includes('*')) {
    throw new Error('Literal --route * is reserved for automatically derived global theme or navigation impact.');
  }
  if (!globalRouteImpact && affectedRoutes.length === 0 && !noPublicRoute) {
    throw new Error('Declare at least one affected --route or explicitly use --no-public-route.');
  }
  if (affectedRoutes.length > 0 && noPublicRoute) {
    throw new Error('--no-public-route cannot be combined with --route.');
  }
  const publicRouteScope = globalRouteImpact ? 'all' : noPublicRoute ? 'none' : 'declared';
  const criterionTexts = [...new Set((Array.isArray(acceptance) ? acceptance : [acceptance])
    .map((criterion) => String(criterion).trim()).filter(Boolean))];
  if (criterionTexts.length === 0) throw new Error('At least one --acceptance criterion is required.');
  const criteria = criterionTexts.map((text, index) => ({ id: `criterion-${index + 1}`, text }));
  const requiredChecks = impactChecks(kind, normalizedSurfaces);
  if (requiredChecks.some((check) => check.id === 'global-chrome-regression')) {
    const latestVerified = latestVerifiedGraphAnchor(graph);
    if (!latestVerified) throw new Error('Global-impact work requires a latest verified lifecycle anchor.');
    readGlobalChromeAnchor(root, latestVerified.type, latestVerified.id, { required: true });
  }
  const directory = changeDirectory(root, changeId);
  if (existsSync(directory)) throw new Error(`Change ${changeId} already exists and lifecycle change IDs are never reused.`);
  const intent = certify({
    schemaVersion: CHANGE_SCHEMA,
    id: changeId,
    kind,
    summary: textSummary,
    openedAt: new Date().toISOString(),
    baseAnchorId: graph.tail.id,
    baseAnchorType: graph.tail.type,
    baseFingerprint: graph.tail.fingerprint,
    baseBuildState: cloneCanonical(graph.tail.buildState),
    baseComponentFingerprints: cloneCanonical(graph.tail.buildState.componentFingerprints),
    baseRouteManifest: cloneCanonical(graph.tail.buildState.routeManifest ?? []),
    adoptedCurrentState: Boolean(adoptCurrent),
    observedCurrentFingerprint: current.currentSiteStateFingerprint,
    observedCurrentComponentFingerprints: cloneCanonical(current.buildState.componentFingerprints),
    surfaces: normalizedSurfaces,
    publicRouteScope,
    affectedRoutes,
    expectedComponents: [...expectedComponents(
      normalizedSurfaces,
      Object.keys(graph.tail.buildState.componentFingerprints)
    )].sort(comparePortable),
    wideningCheck: {
      id: 'conservative-full-regression',
      description: CHANGE_POLICY.checks['conservative-full-regression'],
      evaluator: 'authored',
      sourceSurfaces: ['unknown']
    },
    baselineRoutes: cloneCanonical(graph.tail.routeInventory),
    acceptanceCriteria: criteria,
    requiredChecks
  });
  const validatedIntent = validateChangeIntent(intent, changeId);
  mkdirSync(directory, { recursive: false });
  writeCreateOnlyJson(changePath(root, changeId), intent, `Change ${changeId} intent`);
  return { ...validatedIntent, status: 'in_progress' };
}

function runFreshLiveInspection(packet, projectRoot) {
  const verifier = join(dirname(SCRIPT_PATH), 'verify.mjs');
  const result = spawnSync(process.execPath, [verifier, '--packet', packet], {
    cwd: projectRoot,
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024
  });
  if (result.error) throw new Error(`Fresh live inspection could not start: ${result.error.message}`);
  if (![0, 2].includes(result.status)) {
    throw new Error(
      `Fresh live inspection failed before producing usable state (exit ${result.status}): ` +
      `${String(result.stderr ?? result.stdout ?? '').trim()}`
    );
  }
  const reportPath = join(packet, 'evidence', 'live-verification.json');
  assertContainedRegularFile(projectRoot, reportPath, 'Fresh live inspection report');
  return readJson(reportPath, 'Fresh live inspection report');
}

/** Run fresh inspection and create a non-authoritative targeted evidence transition. */
export function completeChange({
  packetDir = 'review-packet',
  id,
  verification,
  diagnosticReport,
  testOnlyAllowInjectedReport = false
} = {}) {
  const { packet, root } = packetEvidence(packetDir);
  ensureLifecycleDirectories(root);
  const baseline = readInitialBaseline(root, { required: true });
  const graph = buildLifecycleGraph(root, baseline);
  const changeId = safeId(id, 'Change ID');
  const change = graph.changes.find((item) => item.id === changeId);
  if (!change) throw new Error(`Change ${changeId} does not exist.`);
  if (change.status !== 'in_progress') throw new Error(`Change ${changeId} is already ${change.status}.`);
  if (!graph.active || graph.active.id !== changeId) throw new Error(`Change ${changeId} is not the sole active change.`);
  if (diagnosticReport !== undefined && testOnlyAllowInjectedReport !== true) {
    throw new Error('Injected lifecycle reports are diagnostic-only and require testOnlyAllowInjectedReport: true.');
  }
  const projectRoot = projectRootForPacket(packet);
  const report = diagnosticReport === undefined
    ? runFreshLiveInspection(packet, projectRoot)
    : cloneCanonical(diagnosticReport);
  validateInspectableReport(report, `Change ${changeId} fresh inspection`, { notBefore: change.openedAt, fresh: true });
  machineFacts(
    report,
    `Change ${changeId} fresh inspection`,
    change.baselineRoutes,
    change.affectedRoutes
  );
  const input = loadVerificationInput(verification, projectRoot);
  const latestVerified = latestVerifiedGraphAnchor(graph);
  const globalChromeAnchor = latestVerified
    ? readGlobalChromeAnchor(root, latestVerified.type, latestVerified.id)
    : null;
  const accepted = buildTargetedVerification({
    input,
    change,
    report,
    projectRoot,
    packet,
    root,
    globalChromeAnchor
  });
  writeCreateOnlyJson(changeVerificationPath(root, changeId), accepted, `Change ${changeId} targeted verification`);
  const updated = readChangeRecord(root, changeId);
  recordCurrentState(root, baseline, report, { boundChangeId: changeId });
  return compactChange(updated);
}

/** Create an abandonment transition without mutating the original change intent. */
export function abandonChange({ packetDir = 'review-packet', id, reason } = {}) {
  const { root } = packetEvidence(packetDir);
  ensureLifecycleDirectories(root);
  const baseline = readInitialBaseline(root, { required: true });
  const graph = buildLifecycleGraph(root, baseline);
  const changeId = safeId(id, 'Change ID');
  const change = graph.changes.find((item) => item.id === changeId);
  if (!change) throw new Error(`Change ${changeId} does not exist.`);
  if (change.status !== 'in_progress') throw new Error(`Change ${changeId} is already ${change.status}.`);
  const textReason = String(reason ?? '').trim();
  if (!textReason) throw new Error('Abandonment reason is required.');
  const value = certify({
    schemaVersion: CHANGE_ABANDONMENT_SCHEMA,
    changeId,
    abandonedAt: new Date().toISOString(),
    baseFingerprint: change.baseFingerprint,
    reason: textReason
  });
  writeCreateOnlyJson(changeAbandonmentPath(root, changeId), value, `Change ${changeId} abandonment`);
  return compactChange(readChangeRecord(root, changeId));
}

function parseCli(argv) {
  const command = argv[2];
  if (!command || command === '--help' || command === '-h') return { help: true };
  if (!['status', 'begin', 'complete', 'abandon'].includes(command)) {
    throw new UsageError(`Unknown lifecycle command: ${command}.`);
  }
  const options = {
    acceptance: [],
    adoptCurrent: false,
    noPublicRoute: false,
    command,
    packetDir: 'review-packet',
    routes: [],
    surfaces: []
  };
  const repeatable = new Map([
    ['--surface', 'surfaces'],
    ['--route', 'routes'],
    ['--acceptance', 'acceptance']
  ]);
  const values = new Map([
    ['--packet', 'packetDir'],
    ['--id', 'id'],
    ['--kind', 'kind'],
    ['--summary', 'summary'],
    ['--verification', 'verification'],
    ['--reason', 'reason']
  ]);
  for (let index = 3; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }
    if (argument === '--adopt-current') {
      options.adoptCurrent = true;
      continue;
    }
    if (argument === '--no-public-route') {
      options.noPublicRoute = true;
      continue;
    }
    const equalsIndex = argument.indexOf('=');
    const option = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    if (!values.has(option) && !repeatable.has(option)) throw new UsageError(`Unknown option: ${argument}.`);
    const value = equalsIndex === -1 ? argv[index + 1] : argument.slice(equalsIndex + 1);
    if (!value || (equalsIndex === -1 && value.startsWith('--'))) throw new UsageError(`${option} requires a value.`);
    if (equalsIndex === -1) index += 1;
    if (repeatable.has(option)) options[repeatable.get(option)].push(value);
    else options[values.get(option)] = value;
  }
  return options;
}

function main() {
  const args = parseCli(process.argv);
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }
  let result;
  if (args.command === 'status') {
    result = readLifecycleStatus({ packetDir: args.packetDir });
  } else if (args.command === 'begin') {
    result = beginChange({
      packetDir: args.packetDir,
      id: args.id,
      kind: args.kind,
      summary: args.summary,
      surfaces: args.surfaces,
      routes: args.routes,
      noPublicRoute: args.noPublicRoute,
      acceptance: args.acceptance,
      adoptCurrent: args.adoptCurrent
    });
  } else if (args.command === 'complete') {
    result = completeChange({
      packetDir: args.packetDir,
      id: args.id,
      verification: args.verification
    });
  } else {
    result = abandonChange({ packetDir: args.packetDir, id: args.id, reason: args.reason });
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (isDirectRun()) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    if (error instanceof UsageError) process.stderr.write(USAGE);
    process.exitCode = 1;
  }
}
