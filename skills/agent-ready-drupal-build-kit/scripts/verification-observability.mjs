#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import {
  lstat,
  mkdir,
  readdir,
  readFile,
  rename,
  rmdir,
  unlink,
  writeFile
} from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const OBSERVABILITY_SCHEMA = 'public-kit.verification-observability.1';
const AGENT_NEXT_SCHEMA = 'public-kit.agent-next.1';
const LOCAL_STATE_DIRECTORY = '.agent-ready-drupal';
const LOCAL_STATE_OWNER_FILE = '.agent-ready-drupal-build-kit-owner';
const LOCAL_STATE_OWNER_TEXT = 'agent-ready-drupal-build-kit verification state v1\n';
const LOCAL_STATE_LOCK_DIRECTORY = '.verification-observability-write-lock';
const LOCAL_STATE_LOCK_OWNER_FILE = 'owner.json';
const LOCAL_STATE_LOCK_SCHEMA = 'public-kit.verification-observability-lock.1';
const LOCAL_STATE_LOCK_MAX_BYTES = 1_024;
const LOCAL_STATE_LOCK_STALE_MS = 5 * 60 * 1_000;
const LOCAL_STATE_LOCK_WAIT_MS = 2_000;
const LOCAL_STATE_LOCK_RETRY_MS = 20;
const LOCAL_STATE_OWNER_WAIT_MS = 500;
const MAX_AGENT_NEXT_BLOCKERS = 32;
const MAX_BLOCKER_MESSAGE_BYTES = 512;
const MAX_JSON_FILE_BYTES = 1024 * 1024;
const MAX_JSONL_FILE_BYTES = 2 * 1024 * 1024;
const MAX_HISTORY_RECORDS = 256;
const MAX_RUN_FILES = 256;
const DIAGNOSTIC_AUTHORITY = Object.freeze({
  evidenceAuthority: 'none',
  diagnosticOnly: true,
  canAuthorizeCompletion: false
});

function comparePortable(left, right) {
  return String(left).localeCompare(String(right), 'en');
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(comparePortable)
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function observabilityFingerprint(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function byteFingerprint(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function roundedMilliseconds(value) {
  return Math.round(Math.max(0, Number(value) || 0) * 1000) / 1000;
}

export function createPhaseRecorder({
  clock = () => performance.now(),
  now = () => new Date()
} = {}) {
  const origin = clock();
  const startedAt = now().toISOString();
  const phases = [];
  const active = new Set();
  let finished = false;

  function start(id, details = {}) {
    if (finished) throw new Error('Cannot start a phase after the recorder is finished.');
    const phaseId = String(id ?? '').trim();
    if (!phaseId) throw new Error('Phase id is required.');
    const startOffsetMs = roundedMilliseconds(clock() - origin);
    let ended = false;
    const handle = {
      end(outcome = {}) {
        if (ended) throw new Error(`Phase ${phaseId} was already ended.`);
        ended = true;
        active.delete(handle);
        const endOffsetMs = roundedMilliseconds(clock() - origin);
        const phase = {
          id: phaseId,
          startOffsetMs,
          endOffsetMs,
          durationMs: roundedMilliseconds(endOffsetMs - startOffsetMs),
          status: outcome.status ?? 'completed',
          details: canonicalValue({ ...details, ...(outcome.details ?? {}) })
        };
        phases.push(phase);
        return phase;
      }
    };
    active.add(handle);
    return handle;
  }

  return {
    start,
    async measure(id, operation, details = {}) {
      const phase = start(id, details);
      try {
        const value = await operation();
        if (!finished) phase.end();
        return value;
      } catch (error) {
        if (!finished) {
          phase.end({
            status: 'failed',
            details: { errorClass: error?.constructor?.name ?? 'Error' }
          });
        }
        throw error;
      }
    },
    measureSync(id, operation, details = {}) {
      const phase = start(id, details);
      try {
        const value = operation();
        if (!finished) phase.end();
        return value;
      } catch (error) {
        if (!finished) {
          phase.end({
            status: 'failed',
            details: { errorClass: error?.constructor?.name ?? 'Error' }
          });
        }
        throw error;
      }
    },
    finish(outcome = {}) {
      if (finished) throw new Error('Phase recorder was already finished.');
      for (const phase of [...active]) {
        phase.end({
          status: 'aborted',
          details: { reason: 'verification-ended-before-phase-completion' }
        });
      }
      finished = true;
      return {
        schemaVersion: 'public-kit.verification-phase-timing.1',
        startedAt,
        finishedAt: now().toISOString(),
        totalWallClockMs: roundedMilliseconds(clock() - origin),
        status: outcome.status ?? 'completed',
        phases: [...phases].sort((left, right) => (
          left.startOffsetMs - right.startOffsetMs || comparePortable(left.id, right.id)
        )),
        overlapAware: true,
        note: 'Phase spans can overlap; their durations must not be summed as total wall time.'
      };
    }
  };
}

function allRouteChecks(report) {
  return [
    ...(Array.isArray(report?.routeChecks)
      ? report.routeChecks.map((route) => ({ role: 'primary', route }))
      : []),
    ...(Array.isArray(report?.targetRequiredRouteChecks)
      ? report.targetRequiredRouteChecks.map((route) => ({ role: 'target-required', route }))
      : []),
    ...(Array.isArray(report?.browserRepresentativeRouteChecks)
      ? report.browserRepresentativeRouteChecks.map((route) => ({ role: 'browser-representative', route }))
      : [])
  ];
}

export function buildVerificationWorkload(report) {
  const routes = allRouteChecks(report)
    .map(({ role, route }) => ({
      role,
      routeKind: route?.routeKind ?? '',
      target: route?.requestTarget || route?.targetPath || route?.finalUrl || ''
    }))
    .filter((route) => route.target)
    .sort((left, right) => comparePortable(canonicalJson(left), canonicalJson(right)));
  const buildMode = report?.buildMode === 'brief' ? 'brief' : 'source_site';
  const target = String(report?.target?.resolvedBaseUrl ?? '').trim();
  const source = String(report?.target?.declaredSourceBaseUrl ?? '').trim();
  const browserContract = report?.globalChromeCapture?.contract;
  const browserRuntime = report?.globalChromeCapture?.runtime ?? report?.globalChromeCapture?.browser;
  const inputs = {
    buildMode,
    siteState: report?.buildState?.fingerprint ?? '',
    verifier: report?.buildState?.evidenceBindings?.verifierFingerprint ?? '',
    packetEvidence: report?.buildState?.evidenceBindings?.packetFingerprint ?? '',
    machineEnvironment: report?.buildState?.evidenceBindings?.machineLocalEnvironment?.fingerprint ?? '',
    runtimeEnvironment: report?.buildState?.evidenceBindings?.runtimeEnvironment?.fingerprint ?? '',
    routeMatrix: report?.evidenceBinding?.routeMatrixSha256 ?? '',
    sourceSurface: report?.evidenceBinding?.sourceSurfaceSha256 ?? '',
    target: target ? observabilityFingerprint(target) : '',
    source: source ? observabilityFingerprint(source) : '',
    browserContract: browserContract && Object.keys(browserContract).length > 0
      ? observabilityFingerprint(browserContract)
      : '',
    browserRuntime: browserRuntime && Object.keys(browserRuntime).length > 0
      ? observabilityFingerprint(browserRuntime)
      : '',
    routeSet: routes.length > 0 ? observabilityFingerprint(routes) : '',
    routeCount: routes.length
  };
  const required = [
    'siteState',
    'verifier',
    'packetEvidence',
    'machineEnvironment',
    'runtimeEnvironment',
    'routeMatrix',
    'target',
    'browserContract',
    'browserRuntime',
    'routeSet'
  ];
  if (buildMode === 'source_site') required.push('source', 'sourceSurface');
  const missing = required.filter((name) => !inputs[name]);
  const workloadIdentity = { ...inputs };
  delete workloadIdentity.verifier;
  return {
    schemaVersion: 'public-kit.verification-workload.1',
    comparable: missing.length === 0,
    fingerprint: missing.length === 0 ? observabilityFingerprint(workloadIdentity) : '',
    inputs: canonicalValue(inputs),
    missing
  };
}

function localStateRoot(projectRoot) {
  return resolve(projectRoot, LOCAL_STATE_DIRECTORY);
}

function wait(milliseconds) {
  return new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));
}

async function validateLocalStateOwner(root) {
  const ownerPath = join(root, LOCAL_STATE_OWNER_FILE);
  const ownerMetadata = await lstat(ownerPath);
  if (
    ownerMetadata.isSymbolicLink() ||
    !ownerMetadata.isFile() ||
    ownerMetadata.nlink !== 1 ||
    await readFile(ownerPath, 'utf8') !== LOCAL_STATE_OWNER_TEXT
  ) {
    throw new Error('The project-local verification state ownership marker is invalid.');
  }
}

async function waitForConcurrentStateOwner(root, rootMetadata) {
  const ageMs = Math.max(0, Date.now() - rootMetadata.mtimeMs);
  if (ageMs > LOCAL_STATE_OWNER_WAIT_MS) return false;
  const deadline = Date.now() + LOCAL_STATE_OWNER_WAIT_MS;
  while (Date.now() < deadline) {
    try {
      await validateLocalStateOwner(root);
      return true;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    await wait(LOCAL_STATE_LOCK_RETRY_MS);
  }
  return false;
}

async function readOwnedWriteLock(lockPath) {
  const metadata = await lstat(lockPath);
  if (
    metadata.isSymbolicLink() ||
    !metadata.isDirectory()
  ) {
    throw new Error('The verification observability write lock is not a real directory.');
  }
  const entries = await readdir(lockPath);
  if (entries.length === 0) return { acquiredAtMs: metadata.mtimeMs, metadata, owner: null };
  if (entries.length !== 1 || entries[0] !== LOCAL_STATE_LOCK_OWNER_FILE) {
    throw new Error('The verification observability write lock contains unexpected entries.');
  }
  const ownerPath = join(lockPath, LOCAL_STATE_LOCK_OWNER_FILE);
  const ownerMetadata = await lstat(ownerPath);
  if (
    ownerMetadata.isSymbolicLink() ||
    !ownerMetadata.isFile() ||
    ownerMetadata.nlink !== 1 ||
    ownerMetadata.size > LOCAL_STATE_LOCK_MAX_BYTES
  ) {
    throw new Error('The verification observability write lock owner is invalid.');
  }
  const owner = JSON.parse(await readFile(ownerPath, 'utf8'));
  const acquiredAtMs = Date.parse(String(owner?.acquiredAt ?? ''));
  const token = String(owner?.token ?? '');
  if (
    owner?.schemaVersion !== LOCAL_STATE_LOCK_SCHEMA ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(token) ||
    !Number.isFinite(acquiredAtMs)
  ) {
    throw new Error('The verification observability write lock owner record is invalid.');
  }
  return { acquiredAtMs, metadata, owner, ownerPath, token };
}

async function recoverStaleWriteLock(root, lockPath) {
  let lock;
  try {
    lock = await readOwnedWriteLock(lockPath);
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
  if (Date.now() - lock.acquiredAtMs < LOCAL_STATE_LOCK_STALE_MS) return false;
  const stalePath = join(root, `.${LOCAL_STATE_LOCK_DIRECTORY}.stale-${randomUUID()}`);
  try {
    await rename(lockPath, stalePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return true;
    throw error;
  }
  const moved = await readOwnedWriteLock(stalePath);
  if (
    moved.token !== lock.token ||
    moved.metadata.dev !== lock.metadata.dev ||
    moved.metadata.ino !== lock.metadata.ino
  ) {
    try { await rename(stalePath, lockPath); } catch {}
    throw new Error('The verification observability write lock changed during stale-lock recovery.');
  }
  if (moved.owner) await unlink(moved.ownerPath);
  await rmdir(stalePath);
  return true;
}

async function acquireWriteLock(root) {
  const token = randomUUID();
  const lockPath = join(root, LOCAL_STATE_LOCK_DIRECTORY);
  const ownerPath = join(lockPath, LOCAL_STATE_LOCK_OWNER_FILE);
  const temporaryOwnerPath = join(root, `.${LOCAL_STATE_LOCK_DIRECTORY}.owner-${token}.tmp`);
  const owner = {
    schemaVersion: LOCAL_STATE_LOCK_SCHEMA,
    token,
    acquiredAt: new Date().toISOString()
  };
  const deadline = Date.now() + LOCAL_STATE_LOCK_WAIT_MS;
  while (true) {
    try {
      await mkdir(lockPath, { mode: 0o700 });
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    if (await recoverStaleWriteLock(root, lockPath)) continue;
    if (Date.now() >= deadline) {
      throw new Error('Verification observability is busy; this run skipped local metrics after a bounded wait.');
    }
    await wait(LOCAL_STATE_LOCK_RETRY_MS);
  }
  try {
    await writeFile(temporaryOwnerPath, `${JSON.stringify(owner)}\n`, { flag: 'wx', mode: 0o600 });
    await rename(temporaryOwnerPath, ownerPath);
  } catch (error) {
    try { await unlink(temporaryOwnerPath); } catch {}
    try { await rmdir(lockPath); } catch {}
    throw error;
  }
  return async () => {
    const lock = await readOwnedWriteLock(lockPath);
    if (lock.token !== token) {
      throw new Error('Verification observability cannot release a write lock owned by another run.');
    }
    await unlink(ownerPath);
    await rmdir(lockPath);
  };
}

async function withWriteLock(root, operation) {
  const release = await acquireWriteLock(root);
  try {
    return await operation();
  } finally {
    await release();
  }
}

export function findDrupalDdevRoot(cwd) {
  let candidate = resolve(cwd);
  while (true) {
    const configPath = join(candidate, '.ddev', 'config.yaml');
    if (existsSync(configPath)) {
      try {
        const config = readFileSync(configPath, 'utf8');
        if (/^\s*type:\s*["']?drupal(?:\d+)?["']?\s*(?:#.*)?$/mi.test(config)) {
          return realpathSync(candidate);
        }
      } catch {
        return '';
      }
    }
    const parent = dirname(candidate);
    if (parent === candidate) return '';
    candidate = parent;
  }
}

function pathIsInside(parent, child) {
  const relation = relative(parent, child);
  return relation === '' || (
    !relation.startsWith(`..${sep}`) &&
    relation !== '..' &&
    !relation.startsWith(sep)
  );
}

async function ensureSafeDirectory(projectRoot, directory) {
  const project = resolve(projectRoot);
  const root = localStateRoot(project);
  if (!pathIsInside(root, directory)) {
    throw new Error('Verification observability paths must remain inside the project-local state directory.');
  }
  const projectMetadata = await lstat(project);
  if (projectMetadata.isSymbolicLink() || !projectMetadata.isDirectory()) {
    throw new Error('Verification observability requires a real project directory.');
  }
  let rootCreated = false;
  try {
    const rootMetadata = await lstat(root);
    if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
      throw new Error('The project-local verification state root must be a real directory.');
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    try {
      await mkdir(root, { mode: 0o700 });
      rootCreated = true;
    } catch (mkdirError) {
      if (mkdirError?.code !== 'EEXIST') throw mkdirError;
      const rootMetadata = await lstat(root);
      if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) {
        throw new Error('The project-local verification state root must be a real directory.');
      }
    }
  }
  const ownerPath = join(root, LOCAL_STATE_OWNER_FILE);
  if (rootCreated) {
    await writeFile(ownerPath, LOCAL_STATE_OWNER_TEXT, { flag: 'wx', mode: 0o600 });
  } else {
    try {
      await validateLocalStateOwner(root);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        const rootMetadata = await lstat(root);
        if (!await waitForConcurrentStateOwner(root, rootMetadata)) {
          throw new Error(
            'The existing .agent-ready-drupal directory is not owned by the build kit; local metrics were not written.'
          );
        }
      } else {
        throw error;
      }
    }
  }
  const ignorePath = join(root, '.gitignore');
  try {
    const metadata = await lstat(ignorePath);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
      throw new Error('The project-local verification ignore marker must be a single-link regular file.');
    }
    if (await readFile(ignorePath, 'utf8') !== '*\n') {
      throw new Error(
        'The project-local verification ignore marker is non-canonical; local metrics were not written.'
      );
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      await writeTextAtomic(ignorePath, '*\n');
    } else {
      throw error;
    }
  }
  let cursor = root;
  for (const part of relative(root, directory).split(sep).filter(Boolean)) {
    cursor = join(cursor, part);
    let metadata;
    try {
      metadata = await lstat(cursor);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      try {
        await mkdir(cursor, { mode: 0o700 });
      } catch (mkdirError) {
        if (mkdirError?.code !== 'EEXIST') throw mkdirError;
      }
      metadata = await lstat(cursor);
    }
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error('Verification observability state directories must not be symbolic links.');
    }
  }
}

async function assertSafeLocalFile(path, { maxBytes = Infinity } = {}) {
  try {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
      throw new Error(
        'Verification observability state files must be single-link regular files, not symbolic or hard links.'
      );
    }
    if (metadata.size > maxBytes) {
      throw new Error(`Verification observability state file exceeds its ${maxBytes}-byte read limit.`);
    }
    return metadata;
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function readJson(path, fallback = null, maxBytes = MAX_JSON_FILE_BYTES) {
  const metadata = await assertSafeLocalFile(path, { maxBytes });
  if (!metadata) return fallback;
  return JSON.parse(await readFile(path, 'utf8'));
}

async function writeJsonAtomic(path, value) {
  await writeTextAtomic(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function writeTextAtomic(path, value) {
  await assertSafeLocalFile(path);
  const temporary = join(dirname(path), `.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, value, {
      flag: 'wx',
      mode: 0o600
    });
    await rename(temporary, path);
  } catch (error) {
    try {
      const metadata = await lstat(temporary);
      if (metadata.isFile() && !metadata.isSymbolicLink()) {
        await unlink(temporary);
      }
    } catch {}
    throw error;
  }
}

function boundedUtf8(value, maxBytes) {
  const text = String(value ?? '');
  if (Buffer.byteLength(text) <= maxBytes) return text;
  const suffix = '…';
  const budget = Math.max(0, maxBytes - Buffer.byteLength(suffix));
  let bounded = Buffer.from(text).subarray(0, budget).toString('utf8');
  while (Buffer.byteLength(bounded) > budget) bounded = bounded.slice(0, -1);
  return `${bounded.replace(/\uFFFD+$/u, '')}${suffix}`;
}

function blockerRecords(report, failureClass = '') {
  const messages = [
    ...(Array.isArray(report?.completionBlockedReasons) ? report.completionBlockedReasons : []),
    ...(Array.isArray(report?.currentStateBlockedReasons) ? report.currentStateBlockedReasons : []),
    ...(Array.isArray(report?.errors) ? report.errors : [])
  ].map((message) => String(message).trim()).filter(Boolean);
  if (failureClass) messages.push(`Verification command failed (${failureClass}).`);
  const records = [...new Set(messages)].map((message) => ({
    id: `blocker-${observabilityFingerprint(message).slice('sha256:'.length, 'sha256:'.length + 12)}`,
    message: boundedUtf8(message, MAX_BLOCKER_MESSAGE_BYTES)
  })).sort((left, right) => comparePortable(left.id, right.id));
  return {
    blockers: records.slice(0, MAX_AGENT_NEXT_BLOCKERS),
    totalBlockerCount: records.length,
    omittedBlockerCount: Math.max(0, records.length - MAX_AGENT_NEXT_BLOCKERS)
  };
}

export async function recordVerificationObservability({
  projectRoot,
  report = null,
  reportPath = '',
  reportPersisted = false,
  timing,
  verificationPreObservabilityMs = timing?.totalWallClockMs ?? 0,
  failureClass = '',
  runId = randomUUID(),
  now = () => new Date()
}) {
  const instrumentationStartedAtMs = Date.now();
  const instrumentationClockStartedAt = performance.now();
  const project = resolve(projectRoot);
  const normalizedRunId = safeRunId(runId);
  const root = localStateRoot(project);
  const metricsDirectory = join(root, 'verification-metrics');
  const runDirectory = join(metricsDirectory, 'runs');
  await ensureSafeDirectory(project, root);
  return withWriteLock(root, async () => {
    await ensureSafeDirectory(project, metricsDirectory);
    await ensureSafeDirectory(project, runDirectory);
    const historyPath = join(metricsDirectory, 'runs.jsonl');
    const runPath = join(runDirectory, `${normalizedRunId}.json`);
    const agentNextPath = join(root, 'agent-next.json');
    const [, runMetadata] = await Promise.all([
      assertSafeLocalFile(historyPath),
      assertSafeLocalFile(runPath),
      assertSafeLocalFile(agentNextPath)
    ]);
    if (runMetadata) {
      throw new Error(`Verification observability run ${normalizedRunId} already exists.`);
    }
    const previousAgentNext = await readJson(agentNextPath, null);
  const evaluated = blockerRecords(report, failureClass);
  const resolutionUnknown = !report;
  const previousBlockers = Array.isArray(previousAgentNext?.blockers)
    ? previousAgentNext.blockers
    : [];
  const blockerCandidates = resolutionUnknown
    ? [...evaluated.blockers, ...previousBlockers]
    : evaluated.blockers;
  const blockers = [...new Map(blockerCandidates.map((blocker) => [blocker.id, blocker])).values()]
    .slice(0, MAX_AGENT_NEXT_BLOCKERS);
  const previousTotalBlockerCount = Math.max(
    Number(previousAgentNext?.totalBlockerCount) || 0,
    previousBlockers.length
  );
  const newlyKnownBlockerCount = evaluated.blockers.filter(
    (blocker) => !previousBlockers.some((previous) => previous.id === blocker.id)
  ).length;
  const totalBlockerCount = resolutionUnknown
    ? Math.max(blockers.length, previousTotalBlockerCount + newlyKnownBlockerCount)
    : evaluated.totalBlockerCount;
  const previousIds = new Set((previousAgentNext?.blockers ?? []).map((blocker) => blocker.id));
  const currentIds = new Set(blockers.map((blocker) => blocker.id));
  const reportText = report ? `${JSON.stringify(report, null, 2)}\n` : '';
  const absoluteReportPath = reportPath ? resolve(reportPath) : '';
  const observedReport = {
    available: Boolean(report),
    persisted: Boolean(report && reportPersisted),
    sha256: report ? byteFingerprint(reportText) : '',
    bytes: report ? Buffer.byteLength(reportText) : 0,
    path: absoluteReportPath && pathIsInside(project, absoluteReportPath)
      ? relative(project, absoluteReportPath).split(sep).join('/')
      : ''
  };
  const agentNext = {
    schemaVersion: AGENT_NEXT_SCHEMA,
    authority: DIAGNOSTIC_AUTHORITY,
    generatedAt: now().toISOString(),
    stateFingerprint: report?.buildState?.fingerprint ?? previousAgentNext?.stateFingerprint ?? '',
    observedReport,
    observedReportVerdict: failureClass ? 'error' : report?.verdict ?? 'unknown',
    requiredAction: failureClass
      ? 'repair-verification-command'
      : report?.agentContinuation?.requiredAction ?? '',
    blockers,
    totalBlockerCount,
    omittedBlockerCount: Math.max(0, totalBlockerCount - blockers.length),
    delta: {
      added: blockers.filter((blocker) => !previousIds.has(blocker.id)),
      resolved: resolutionUnknown
        ? []
        : (previousAgentNext?.blockers ?? []).filter((blocker) => !currentIds.has(blocker.id)),
      resolutionUnknown
    }
  };
  const reportBytes = observedReport.bytes;
  const agentNextBytes = Buffer.byteLength(JSON.stringify(agentNext));
  const record = {
    schemaVersion: OBSERVABILITY_SCHEMA,
    authority: DIAGNOSTIC_AUTHORITY,
    runId: normalizedRunId,
    recordedAt: now().toISOString(),
    instrumentationStartedAt: new Date(instrumentationStartedAtMs).toISOString(),
    verificationPreObservabilityMs: roundedMilliseconds(verificationPreObservabilityMs),
    verificationTimingBoundary: 'before-observability-preparation-and-persistence',
    timing,
    workload: report ? buildVerificationWorkload(report) : {
      schemaVersion: 'public-kit.verification-workload.1',
      comparable: false,
      fingerprint: '',
      inputs: {},
      missing: ['report']
    },
    observedReport,
    command: {
      status: failureClass ? 'failed' : 'completed',
      failureClass,
    },
    observedReportOutcome: {
      valid: report?.valid === true,
      verdict: report?.verdict ?? 'error',
      completeLocalRebuildClaimAllowed: report?.completeLocalRebuildClaimAllowed === true,
      completeLocalBuildFromBriefClaimAllowed: report?.completeLocalBuildFromBriefClaimAllowed === true,
      currentSiteClaimAllowed: report?.currentSiteClaimAllowed === true,
      stateFingerprint: report?.buildState?.fingerprint ?? ''
    },
    counters: {
      liveHttpRequests: report?.liveHttpBudget?.requestCount ?? 0,
      liveHttpTasks: report?.liveHttpBudget?.taskCount ?? 0,
      primaryRoutes: Array.isArray(report?.routeChecks) ? report.routeChecks.length : 0,
      browserRoutes: Array.isArray(report?.globalChromeCapture?.routes)
        ? report.globalChromeCapture.routes.length
        : 0
    },
    agentReadReduction: {
      fullReportBytes: reportBytes,
      agentNextBytes,
      byteReduction: Math.max(0, reportBytes - agentNextBytes),
      reductionPercent: reportBytes > 0
        ? Math.round((1 - agentNextBytes / reportBytes) * 10_000) / 100
        : 0
    },
    instrumentationPrePersistenceMs: 0,
    instrumentationBoundary: 'after-agent-next-before-metric-record-persistence',
  };
  record.instrumentationPrePersistenceMs = roundedMilliseconds(
    performance.now() - instrumentationClockStartedAt
  );
  const runText = `${JSON.stringify(record, null, 2)}\n`;
  if (Buffer.byteLength(runText) > MAX_JSON_FILE_BYTES) {
    throw new Error(`Verification observability run exceeds its ${MAX_JSON_FILE_BYTES}-byte limit.`);
  }
  await writeJsonAtomic(agentNextPath, agentNext);
  const history = await readJsonLines(historyPath, {
    maxBytes: MAX_JSONL_FILE_BYTES,
    maxRecords: MAX_HISTORY_RECORDS
  });
  await writeBoundedJsonLines(historyPath, [...history, record], {
    maxBytes: MAX_JSONL_FILE_BYTES,
    maxRecords: MAX_HISTORY_RECORDS
  });
  await writeFile(runPath, runText, {
    flag: 'wx',
    mode: 0o600
  });
  await pruneRunFiles(runDirectory);
    return {
      record,
      paths: {
        agentNext: relative(project, agentNextPath).split(sep).join('/'),
        history: relative(project, historyPath).split(sep).join('/'),
        run: relative(project, runPath).split(sep).join('/')
      }
    };
  });
}

function median(values) {
  const sorted = values.map(Number).filter(Number.isFinite).sort((left, right) => left - right);
  if (sorted.length === 0) return 0;
  const middle = Math.floor(sorted.length / 2);
  return roundedMilliseconds(
    sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
  );
}

function commandStatus(record) {
  return record?.command?.status ?? record?.outcome?.commandStatus ?? 'unknown';
}

function observedReportValid(record) {
  return (record?.observedReportOutcome?.valid ?? record?.outcome?.valid) === true;
}

function summarizePhases(records) {
  const phases = new Map();
  for (const record of records) {
    const commandCompleted = commandStatus(record) === 'completed';
    for (const phase of record?.timing?.phases ?? []) {
      const summary = phases.get(phase.id) ?? {
        runCount: 0,
        measuredRunCount: 0,
        skippedRunCount: 0,
        failedRunCount: 0,
        abortedRunCount: 0,
        discardedRunCount: 0,
        durations: []
      };
      summary.runCount += 1;
      const skipped = phase?.details?.attempted === false || phase?.details?.applicable === false;
      if (phase?.status === 'aborted') {
        summary.abortedRunCount += 1;
      } else if (phase?.status === 'failed') {
        summary.failedRunCount += 1;
      } else if (skipped) {
        summary.skippedRunCount += 1;
      } else if (!commandCompleted) {
        summary.discardedRunCount += 1;
      } else if (phase?.status === 'completed') {
        summary.measuredRunCount += 1;
        summary.durations.push(phase.durationMs);
      }
      phases.set(phase.id, summary);
    }
  }
  return Object.fromEntries(
    [...phases.entries()]
      .sort(([left], [right]) => comparePortable(left, right))
      .map(([id, summary]) => [id, {
        runCount: summary.runCount,
        measuredRunCount: summary.measuredRunCount,
        skippedRunCount: summary.skippedRunCount,
        failedRunCount: summary.failedRunCount,
        abortedRunCount: summary.abortedRunCount,
        discardedRunCount: summary.discardedRunCount,
        medianDurationMs: median(summary.durations)
      }])
  );
}

function summarizeImplementations(records) {
  const groups = new Map();
  for (const record of records) {
    const implementation = record?.workload?.inputs?.verifier || 'unknown';
    const implementationRecords = groups.get(implementation) ?? [];
    implementationRecords.push(record);
    groups.set(implementation, implementationRecords);
  }
  return Object.fromEntries(
    [...groups.entries()]
      .sort(([left], [right]) => comparePortable(left, right))
      .map(([implementation, implementationRecords]) => {
        const completed = implementationRecords.filter(
          (record) => commandStatus(record) === 'completed'
        );
        return [implementation, {
          runCount: implementationRecords.length,
          completedRunCount: completed.length,
          failedCommandRunCount: implementationRecords.length - completed.length,
          validRunCount: completed.filter((record) => observedReportValid(record)).length,
          invalidRunCount: completed.filter((record) => !observedReportValid(record)).length,
          medianVerificationPreObservabilityMs: median(
            completed.map((record) => record.verificationPreObservabilityMs)
          ),
          medianInstrumentationPrePersistenceMs: median(
            completed.map((record) => record.instrumentationPrePersistenceMs ?? 0)
          ),
          phases: summarizePhases(implementationRecords)
        }];
      })
  );
}

export function summarizeVerificationRuns(runs) {
  const completedRuns = runs.filter((run) => commandStatus(run) === 'completed');
  const workloadRuns = Object.create(null);
  for (const run of runs) {
    if (run?.workload?.comparable === true && run?.workload?.fingerprint) {
      workloadRuns[run.workload.fingerprint] ??= [];
      workloadRuns[run.workload.fingerprint].push(run);
    }
  }
  return {
    schemaVersion: 'public-kit.verification-observability-summary.1',
    runCount: runs.length,
    completedRunCount: completedRuns.length,
    failedCommandRunCount: runs.filter((run) => commandStatus(run) === 'failed').length,
    validRunCount: completedRuns.filter(observedReportValid).length,
    invalidRunCount: completedRuns.filter((run) => !observedReportValid(run)).length,
    medianVerificationPreObservabilityMs: median(
      completedRuns.map((run) => run.verificationPreObservabilityMs)
    ),
    medianInstrumentationPrePersistenceMs: median(
      completedRuns.map((run) => run.instrumentationPrePersistenceMs ?? 0)
    ),
    comparableWorkloads: Object.fromEntries(
      Object.entries(workloadRuns)
        .sort(([left], [right]) => comparePortable(left, right))
        .map(([fingerprint, records]) => {
          const completed = records.filter(
            (record) => commandStatus(record) === 'completed'
          );
          return [fingerprint, {
            runCount: records.length,
            completedRunCount: completed.length,
            failedCommandRunCount: records.length - completed.length,
            validRunCount: completed.filter(observedReportValid).length,
            invalidRunCount: completed.filter((record) => !observedReportValid(record)).length,
            medianVerificationPreObservabilityMs: median(
              completed.map((record) => record.verificationPreObservabilityMs)
            ),
            medianInstrumentationPrePersistenceMs: median(
              completed.map((record) => record.instrumentationPrePersistenceMs ?? 0)
            ),
            phases: summarizePhases(records),
            implementations: summarizeImplementations(records)
          }];
        })
    ),
    phases: summarizePhases(runs)
  };
}

async function readJsonLines(path, {
  maxBytes = MAX_JSONL_FILE_BYTES,
  maxRecords = MAX_HISTORY_RECORDS
} = {}) {
  const metadata = await assertSafeLocalFile(path, { maxBytes });
  if (!metadata) return [];
  const lines = (await readFile(path, 'utf8')).split(/\r?\n/).filter(Boolean);
  return lines.slice(-maxRecords).map((line) => JSON.parse(line));
}

async function writeBoundedJsonLines(path, records, {
  maxBytes,
  maxRecords
}) {
  const bounded = records.slice(-maxRecords);
  let text = bounded.map((record) => JSON.stringify(record)).join('\n');
  if (text) text += '\n';
  while (Buffer.byteLength(text) > maxBytes && bounded.length > 1) {
    bounded.shift();
    text = `${bounded.map((record) => JSON.stringify(record)).join('\n')}\n`;
  }
  if (Buffer.byteLength(text) > maxBytes) {
    throw new Error(`Verification observability record exceeds its ${maxBytes}-byte retention limit.`);
  }
  await writeTextAtomic(path, text);
}

async function safeDirectoryEntries(directory, maxEntries) {
  let metadata;
  try {
    metadata = await lstat(directory);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error('Verification observability state directories must be real directories.');
  }
  const entries = await readdir(directory);
  if (entries.length > maxEntries) {
    throw new Error(`Verification observability state directory exceeds its ${maxEntries}-entry limit.`);
  }
  return entries;
}

async function assertReadableLocalStateRoot(projectRoot) {
  const root = localStateRoot(projectRoot);
  let metadata;
  try {
    metadata = await lstat(root);
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error('The project-local verification state root must be a real directory.');
  }
  return true;
}

async function pruneRunFiles(runDirectory) {
  const names = (await safeDirectoryEntries(runDirectory, MAX_RUN_FILES + 64))
    .filter((name) => name.endsWith('.json'));
  if (names.length <= MAX_RUN_FILES) return;
  const records = [];
  for (const name of names) {
    const path = join(runDirectory, name);
    const record = await readJson(path, null, MAX_JSON_FILE_BYTES);
    records.push({
      name,
      recordedAt: Date.parse(String(record?.recordedAt ?? '')) || 0
    });
  }
  records.sort((left, right) => left.recordedAt - right.recordedAt || comparePortable(left.name, right.name));
  for (const { name } of records.slice(0, Math.max(0, records.length - MAX_RUN_FILES))) {
    const path = join(runDirectory, name);
    await assertSafeLocalFile(path, { maxBytes: MAX_JSON_FILE_BYTES });
    await unlink(path);
  }
}

async function readVerificationRuns(projectRoot) {
  if (!await assertReadableLocalStateRoot(projectRoot)) return [];
  const metricsDirectory = join(localStateRoot(projectRoot), 'verification-metrics');
  await safeDirectoryEntries(metricsDirectory, MAX_RUN_FILES + 4);
  const history = await readJsonLines(join(metricsDirectory, 'runs.jsonl'), {
    maxBytes: MAX_JSONL_FILE_BYTES,
    maxRecords: MAX_HISTORY_RECORDS
  });
  const byRunId = new Map(history
    .filter((record) => record?.runId)
    .map((record) => [record.runId, record]));
  const runDirectory = join(metricsDirectory, 'runs');
  const names = await safeDirectoryEntries(runDirectory, MAX_RUN_FILES + 64);
  const safeNames = names.filter((value) => {
    if (!value.endsWith('.json')) return false;
    try {
      safeRunId(value.slice(0, -'.json'.length));
      return true;
    } catch {
      return false;
    }
  });
  for (const name of safeNames.sort(comparePortable)) {
    const path = join(runDirectory, name);
    const record = await readJson(path, null, MAX_JSON_FILE_BYTES);
    if (record?.runId) byRunId.set(record.runId, record);
  }
  return [...byRunId.values()].sort((left, right) => (
    Date.parse(String(left.recordedAt ?? '')) - Date.parse(String(right.recordedAt ?? ''))
  ));
}

function usage() {
  return `Usage: node <path-to-skill>/scripts/verification-observability.mjs <command> [options]

Commands:
  report [--json]  Summarize verifier timing and matched workload cohorts
`;
}

function parseCli(argv) {
  const [command = '', ...values] = argv;
  const options = { command, json: false };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === '--json') {
      options.json = true;
      continue;
    }
    throw new Error(`Unknown option ${value}.`);
  }
  return options;
}

function safeRunId(value) {
  const id = String(value ?? '').trim();
  if (!/^[a-z0-9][a-z0-9._-]{0,79}$/i.test(id)) {
    throw new Error('Run id must use 1-80 letters, numbers, dots, underscores, or hyphens.');
  }
  return id;
}

async function main() {
  const options = parseCli(process.argv.slice(2));
  if (options.command === '--help' || options.command === '-h') {
    process.stdout.write(usage());
    return;
  }
  const projectRoot = findDrupalDdevRoot(process.cwd()) || resolve(process.cwd());
  if (options.command === 'report') {
    const summary = {
      schemaVersion: 'public-kit.verification-observability-report.1',
      authority: DIAGNOSTIC_AUTHORITY,
      verification: summarizeVerificationRuns(await readVerificationRuns(projectRoot))
    };
    if (options.json) {
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    } else {
      process.stdout.write(`Verification runs: ${summary.verification.runCount}\n`);
      process.stdout.write(
        `Global pre-observability verification median (coarse inventory; not comparable across workloads): ` +
        `${Math.round(summary.verification.medianVerificationPreObservabilityMs)} ms\n`
      );
      process.stdout.write(
        `Median metrics preparation time (excludes metric persistence): ` +
        `${Math.round(summary.verification.medianInstrumentationPrePersistenceMs)} ms\n`
      );
      const slowPhases = Object.entries(summary.verification.phases)
        .sort(([, left], [, right]) => right.medianDurationMs - left.medianDurationMs)
        .slice(0, 5);
      if (slowPhases.length > 0) {
        process.stdout.write(`Global phase inventory (non-comparative): ${slowPhases.map(([id, value]) => (
          `${id} ${Math.round(value.medianDurationMs)} ms`
        )).join(', ')}\n`);
      }
      const workloads = Object.entries(summary.verification.comparableWorkloads).slice(0, 8);
      if (workloads.length === 0) {
        process.stdout.write('Matched workload cohorts: none yet\n');
      } else {
        process.stdout.write('Matched workload cohorts (compare only implementations within one cohort):\n');
        for (const [fingerprint, workload] of workloads) {
          process.stdout.write(`- ${fingerprint.slice(0, 19)}…: ${workload.runCount} run(s)\n`);
          for (const [implementation, values] of Object.entries(workload.implementations)) {
            process.stdout.write(
              `  - implementation ${implementation.slice(0, 19)}…: ` +
              `n=${values.completedRunCount}, ` +
              `pre-observability median=${Math.round(values.medianVerificationPreObservabilityMs)} ms\n`
            );
          }
        }
        if (Object.keys(summary.verification.comparableWorkloads).length > workloads.length) {
          process.stdout.write('  Additional cohorts omitted; use report --json for the bounded full summary.\n');
        }
      }
    }
    return;
  }
  process.stdout.write(usage());
  if (options.command) process.exitCode = 1;
}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n${usage()}`);
    process.exitCode = 1;
  });
}
