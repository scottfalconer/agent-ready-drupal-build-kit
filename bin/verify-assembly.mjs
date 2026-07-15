#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeFileSync
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assemblyTargetKey,
  assertInitialMutation,
  assertNoOpDryRun,
  assertPrefixDeletesAuthorized,
  assertProvenanceReadbackCoverage,
  assertStateMetadataStable,
  deriveAssemblyChanges,
  fixtureTargetsSurvived,
  loadValidatedAssemblyInputs,
  parseAssemblyDryRun,
  reconcileDryRun,
  reconcileDryRunPrefix,
  selectAssemblyInterruptionCutPoints
} from './assembly-contract.mjs';
import {
  assertDryRunSurfacesAvailable,
  assertFixturePlanAgainstCapabilities,
  captureAssemblyFixtureIdentity,
  discoverAssemblyCapabilities,
  installAssemblyExtensionFixtures
} from './assembly-fixtures.mjs';
import {
  assertDisposableSourceBytesEqual,
  assertExactEntityIdentityEquality,
  assertExactPersistenceEquality,
  assertExactProvenanceStorageResidual,
  assertFirstRunPersistenceChanges,
  assertNoOpPersistence,
  assertRestoredPersistence,
  captureAssemblyPersistenceSnapshot,
  captureDisposableSourceBytes,
  captureProvenanceEntityIdentity,
  captureProvenanceStorageResidual,
  compareProvenanceEntityIdentity,
  createAssemblyFileBackup,
  disposeAssemblyFileBackup,
  registerVerifierDatabaseSourceExclusion,
  restoreAssemblyFileBackup
} from './assembly-persistence.mjs';
import {
  assertDeclaredEmptyAdapters,
  boundedFailureDetail,
  cleanupDisposable,
  confirmDisposableDdevIdentity,
  createDisposableClone,
  createRecordedExecutor,
  exactHeadRuntimeBinding,
  provisioningSteps,
  safeProjectRelativePath
} from './disposable-ddev.mjs';
import {
  capturePortableDrupalState,
  comparePortableReproductionStates
} from './reproduction-state.mjs';
import { canonicalJson, collectFileManifest, sha256 } from './state-fingerprint.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPORT_SCHEMA = 'public-kit.assembly-verification.1';
const DEFAULT_PLAN = 'assembly-plan.json';
const DEFAULT_OUTPUT = 'review-packet/evidence/assembly-verification.json';
const ADAPTER_MODES = new Set(['plan', 'apply-prefix']);
const DEFAULT_BUDGET = Object.freeze({
  maxCommands: 5_000,
  reservedFinalizationCommands: 16,
  maxElapsedMs: 75 * 60 * 1_000,
  reservedFinalizationMs: 5 * 60 * 1_000,
  maxOutputBytes: 512 * 1024 * 1024,
  reservedFinalizationOutputBytes: 8 * 1024 * 1024
});
const USAGE = `Usage: node <path-to-skill>/scripts/verify-assembly.mjs [options]

Verifier-owned assembly rerun proof inside an exact-HEAD disposable DDEV clone.

  --project <path>       Existing Drupal/DDEV project (default: detect from cwd)
  --plan <path>          Exact-HEAD typed plan (default: assembly-plan.json)
  --out <path>           Evidence under review-packet/evidence
  --allow-owned-deletes  Explicitly authorize only provenance-ledger delete rows
  --help                 Show this help
`;

class UsageError extends Error {}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

function parseArgs(argv) {
  const options = { allowOwnedDeletes: false, out: DEFAULT_OUTPUT, plan: DEFAULT_PLAN, project: '' };
  const values = new Map([['--project', 'project'], ['--plan', 'plan'], ['--out', 'out']]);
  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { help: true };
    if (argument === '--allow-owned-deletes') {
      options.allowOwnedDeletes = true;
      continue;
    }
    const equals = argument.indexOf('=');
    const option = equals === -1 ? argument : argument.slice(0, equals);
    if (!values.has(option)) throw new UsageError(`Unknown option: ${argument}.`);
    const value = equals === -1 ? argv[index + 1] : argument.slice(equals + 1);
    if (!value || (equals === -1 && value.startsWith('--'))) throw new UsageError(`${option} requires a value.`);
    if (equals === -1) index += 1;
    options[values.get(option)] = value;
  }
  return options;
}

function ddevDrupalRoot(cwd) {
  let candidate = resolve(cwd);
  while (true) {
    const config = join(candidate, '.ddev', 'config.yaml');
    if (existsSync(config) && !lstatSync(config).isSymbolicLink() && lstatSync(config).isFile()) {
      try {
        if (/^\s*type:\s*["']?drupal(?:\d+)?["']?\s*(?:#.*)?$/mi.test(readFileSync(config, 'utf8'))) {
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

function firstError(error) {
  return String(error?.message ?? error ?? 'Unknown error').trim().split(/\r?\n/)[0];
}

function checkedOutput(execute, command, args, options, { trim = true } = {}) {
  const result = execute(command, args, options);
  if (!result || result.status !== 0) {
    const detail = boundedFailureDetail(result);
    throw new Error(`${options.phase} failed${detail ? `: ${detail}` : ''}`);
  }
  const output = String(result.stdout ?? '');
  return trim ? output.trim() : output;
}

function sourceSnapshot(execute, projectRoot, phase, target = 'working') {
  const head = checkedOutput(execute, 'git', ['rev-parse', 'HEAD'], {
    cwd: projectRoot,
    phase: `${phase}:head`,
    target
  });
  if (!/^[a-f0-9]{40}$/i.test(head)) throw new Error('Working source HEAD is not a full Git object ID.');
  const status = checkedOutput(execute, 'git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    cwd: projectRoot,
    phase: `${phase}:status`,
    target
  });
  const trackedDiff = checkedOutput(execute, 'git', ['diff', '--binary', '--no-ext-diff', 'HEAD', '--'], {
    cwd: projectRoot,
    phase: `${phase}:tracked-worktree-bytes`,
    target
  }, { trim: false });
  const untracked = checkedOutput(execute, 'git', ['ls-files', '--others', '--exclude-standard', '-z'], {
    cwd: projectRoot,
    phase: `${phase}:untracked-paths`,
    target
  }, { trim: false }).split('\0').filter(Boolean);
  const untrackedManifest = collectFileManifest(projectRoot, untracked);
  return {
    head: head.toLowerCase(),
    statusSha256: sha256(status),
    trackedWorktreeSha256: sha256(trackedDiff),
    untrackedWorktree: {
      entryCount: untrackedManifest.entryCount,
      fingerprint: untrackedManifest.fingerprint
    },
    runtimeCode: exactHeadRuntimeBinding(projectRoot)
  };
}

function isFinalizationPhase(phase) {
  return (
    String(phase).startsWith('working-after:') ||
    phase === 'confirm-disposable-ddev-identity-before-delete' ||
    phase === 'delete-owned-disposable-ddev'
  );
}

/** One aggregate command/time/output budget with an explicit cleanup/final-proof reserve. */
export function createAssemblyBudget({ execute, limits = DEFAULT_BUDGET, now = () => Date.now() }) {
  const started = now();
  let commands = 0;
  let outputBytes = 0;
  let exceeded = false;
  const budgeted = (command, args, options = {}) => {
    const finalization = isFinalizationPhase(options.phase);
    const elapsed = now() - started;
    const commandCeiling = finalization ? limits.maxCommands : limits.maxCommands - limits.reservedFinalizationCommands;
    const timeCeiling = finalization ? limits.maxElapsedMs : limits.maxElapsedMs - limits.reservedFinalizationMs;
    const outputCeiling = finalization
      ? limits.maxOutputBytes
      : limits.maxOutputBytes - limits.reservedFinalizationOutputBytes;
    if (commands >= commandCeiling || elapsed >= timeCeiling || outputBytes >= outputCeiling) {
      exceeded = true;
      throw new Error(`Assembly aggregate budget exhausted before ${options.phase ?? command}; cleanup/final-proof reserve remains protected.`);
    }
    const remaining = Math.max(1, timeCeiling - elapsed);
    const remainingOutput = Math.max(1, outputCeiling - outputBytes);
    const perStreamBuffer = Math.max(1, Math.floor(remainingOutput / 2));
    const result = execute(command, args, {
      ...options,
      maxBuffer: Math.min(options.maxBuffer ?? 64 * 1024 * 1024, perStreamBuffer),
      timeout: Math.min(options.timeout ?? 60_000, remaining)
    });
    commands += 1;
    outputBytes += Buffer.byteLength(String(result?.stdout ?? '')) + Buffer.byteLength(String(result?.stderr ?? ''));
    if (commands > commandCeiling || now() - started > timeCeiling || outputBytes > outputCeiling) {
      exceeded = true;
      throw new Error(`Assembly aggregate budget exceeded during ${options.phase ?? command}; cleanup/final-proof reserve remains protected.`);
    }
    return result;
  };
  budgeted.snapshot = () => ({
    limits,
    commandCount: commands,
    outputBytes,
    elapsedMs: now() - started,
    exceeded,
    cleanupAndFinalProofReserve: {
      commands: limits.reservedFinalizationCommands,
      elapsedMs: limits.reservedFinalizationMs,
      outputBytes: limits.reservedFinalizationOutputBytes
    }
  });
  return budgeted;
}

function runProvisioningStep(execute, disposable, step) {
  const result = execute(step.command, step.args, {
    cwd: disposable.root,
    phase: `provision:${step.adapter}`,
    target: 'disposable',
    timeout: step.timeout
  });
  if (!result || result.status !== 0) {
    const detail = boundedFailureDetail(result);
    throw new Error(`Typed substrate adapter ${step.adapter} failed${detail ? `: ${detail}` : ''}`);
  }
}

export function assemblyAdapterArgs(adapterSourcePath, mode, options = {}) {
  if (!ADAPTER_MODES.has(mode)) throw new Error(`Unsupported fixed assembly adapter mode: ${mode}.`);
  if (mode === 'plan') {
    if (Object.keys(options).length > 0) throw new Error('Assembly plan mode accepts no adapter arguments.');
    return ['drush', 'php:script', adapterSourcePath, '--', mode];
  }
  const prefixCount = Number(options.prefixCount);
  const planFingerprint = String(options.planFingerprint ?? '');
  if (!Number.isSafeInteger(prefixCount) || prefixCount < 0 || prefixCount > 5_000) {
    throw new Error('Assembly apply-prefix count must be an integer from 0 through 5000.');
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(planFingerprint)) {
    throw new Error('Assembly apply-prefix requires the exact dry-run SHA-256 fingerprint.');
  }
  return ['drush', 'php:script', adapterSourcePath, '--', mode, String(prefixCount), planFingerprint];
}

function invokeAdapter(execute, disposable, sourcePath, mode, options = {}) {
  const result = execute('ddev', assemblyAdapterArgs(sourcePath, mode, options), {
    cwd: disposable.root,
    phase: `assembly-adapter:${mode}`,
    target: 'disposable',
    timeout: 600_000
  });
  if (!result || result.status !== 0) {
    const detail = boundedFailureDetail(result);
    throw new Error(`Fixed assembly adapter mode ${mode} failed${detail ? `: ${detail}` : ''}`);
  }
  return result;
}

function invokeAdapterPrefix(execute, disposable, sourcePath, dryRun, prefixCount, allowOwnedDeletes) {
  const deleteCount = assertPrefixDeletesAuthorized(dryRun, prefixCount, allowOwnedDeletes);
  invokeAdapter(execute, disposable, sourcePath, 'apply-prefix', {
    prefixCount,
    planFingerprint: dryRun.fingerprint
  });
  return deleteCount;
}

function createVerifierDatabaseBackup(execute, disposable) {
  const name = `agent-ready-assembly-${randomUUID()}.sql.gz`;
  const relativePath = `.ddev/${name}`;
  const path = join(disposable.root, relativePath);
  if (existsSync(path)) throw new Error('Verifier database backup path unexpectedly already exists.');
  checkedOutput(execute, 'ddev', ['export-db', '--skip-hooks', `--file=${relativePath}`], {
    cwd: disposable.root,
    phase: 'verifier-database-backup',
    target: 'disposable',
    timeout: 600_000
  });
  if (!existsSync(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) {
    throw new Error('Verifier database backup was not created as an owned regular file.');
  }
  return {
    relativePath,
    bytes: lstatSync(path).size,
    sha256: collectFileManifest(disposable.root, [relativePath]).fingerprint
  };
}

function restoreVerifierDatabaseBackup(execute, disposable, backup) {
  const path = join(disposable.root, backup.relativePath);
  if (!existsSync(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) {
    throw new Error('Verifier database backup identity changed before restoration.');
  }
  const current = collectFileManifest(disposable.root, [backup.relativePath]).fingerprint;
  if (current !== backup.sha256) throw new Error('Verifier database backup bytes changed before restoration.');
  checkedOutput(execute, 'ddev', ['import-db', '--skip-hooks', '--no-progress', `--file=${backup.relativePath}`], {
    cwd: disposable.root,
    phase: 'verifier-database-restore',
    target: 'disposable',
    timeout: 600_000
  });
}

function dryRun(execute, disposable, sourcePath, provenance) {
  const result = invokeAdapter(execute, disposable, sourcePath, 'plan');
  let value;
  try {
    value = JSON.parse(String(result.stdout ?? ''));
  } catch {
    throw new Error('Assembly plan mode returned invalid JSON; stdout must contain only the typed dry-run object.');
  }
  return parseAssemblyDryRun(value, provenance);
}

function exactStateComparison(expected, actual) {
  return comparePortableReproductionStates(expected, actual);
}

function requireExactComparison(comparison, label) {
  if (!comparison.match) throw new Error(`${label} did not preserve exact verifier-derived Drupal state.`);
}

function sourceUnchanged(before, after) {
  return Boolean(before && after && (
    before.head === after.head &&
    before.statusSha256 === after.statusSha256 &&
    before.trackedWorktreeSha256 === after.trackedWorktreeSha256 &&
    before.untrackedWorktree.fingerprint === after.untrackedWorktree.fingerprint &&
    before.runtimeCode.fingerprint === after.runtimeCode.fingerprint
  ));
}

function captureOwnedDisposableSource({ captureSource, databaseSourceExclusion, execute, fileBackup, projectRoot }) {
  return captureSource({
    execute,
    projectRoot,
    excludedFileBackups: fileBackup ? [fileBackup] : [],
    excludedSourceArtifacts: databaseSourceExclusion ? [databaseSourceExclusion] : []
  });
}

function requireDisposableSourceUnchanged(options, expected, label) {
  const actual = captureOwnedDisposableSource(options);
  assertDisposableSourceBytesEqual(expected, actual, label);
  return actual;
}

function emptyComparison() {
  return {
    schemaVersion: 'public-kit.reproduction-comparison.1',
    match: false,
    expectedFingerprint: '',
    actualFingerprint: '',
    componentMatches: {},
    mismatchCount: 0,
    mismatchesTruncated: false,
    mismatches: []
  };
}

export function assertIdentityTransitionsMatchPrefix(
  before,
  after,
  dryRunValue,
  prefixCount,
  label,
  allowOwnedDeletes = false
) {
  const comparison = compareProvenanceEntityIdentity(before, after);
  const allowed = new Set(dryRunValue.operations.slice(0, prefixCount)
    .filter(({ action, target }) => action !== 'unchanged' && target.kind === 'entity')
    .map(({ target }) => assemblyTargetKey(target)));
  const outside = comparison.changedTargetKeys.filter((key) => !allowed.has(key));
  if (outside.length > 0) {
    throw new Error(`${label} changed opaque storage/revision identity outside the applied operation prefix: ${outside[0]}.`);
  }
  const beforeRows = new Map(before.rows.map((row) => [row.key, row]));
  const afterRows = new Map(after.rows.map((row) => [row.key, row]));
  for (const [index, operation] of dryRunValue.operations.entries()) {
    if (operation.target.kind !== 'entity') continue;
    const key = assemblyTargetKey(operation.target);
    const beforeRow = beforeRows.get(key);
    const afterRow = afterRows.get(key);
    if (!beforeRow || !afterRow) throw new Error(`${label} is missing opaque identity for ${key}.`);
    const action = index < prefixCount ? operation.action : 'unchanged';
    if (action === 'unchanged') {
      if (sha256(beforeRow) !== sha256(afterRow)) {
        throw new Error(`${label} changed opaque identity for unchanged target ${key}.`);
      }
    } else if (action === 'create') {
      if (beforeRow.present || !afterRow.present) {
        throw new Error(`${label} create identity transition is invalid for ${key}.`);
      }
    } else if (action === 'update') {
      if (!beforeRow.present || !afterRow.present) {
        throw new Error(`${label} update identity transition is invalid for ${key}.`);
      }
      if (beforeRow.storageIdentitySha256 !== afterRow.storageIdentitySha256) {
        throw new Error(`${label} update deleted and recreated ${key}; storage identity must remain exact.`);
      }
    } else if (action === 'delete') {
      if (allowOwnedDeletes !== true) {
        throw new Error(`${label} delete identity transition lacks explicit --allow-owned-deletes authorization.`);
      }
      if (!beforeRow.present || afterRow.present) {
        throw new Error(`${label} delete identity transition is invalid for ${key}.`);
      }
    }
  }
  return comparison;
}

function assertIdentityPresenceMatchesState(identity, provenance, state, label) {
  const present = new Set(Object.entries(state?.entities?.types ?? {}).flatMap(([entityType, type]) => (
    (type?.items ?? []).map(({ stableId }) => `entity:${entityType}:${stableId}`)
  )));
  const expectedKeys = provenance.resources
    .filter(({ target }) => target.kind === 'entity')
    .map(({ target }) => assemblyTargetKey(target))
    .sort();
  const rows = [...identity.rows].sort((left, right) => String(left.key).localeCompare(String(right.key)));
  if (canonicalJson(rows.map(({ key }) => key)) !== canonicalJson(expectedKeys)) {
    throw new Error(`${label} identity rows do not cover every provenance entity target.`);
  }
  const mismatch = rows.find((row) => row.present !== present.has(row.key));
  if (mismatch) throw new Error(`${label} identity presence disagrees with portable state for ${mismatch.key}.`);
  return true;
}

export function operationPrefixProvenance(dryRunValue, prefixCount) {
  const resources = dryRunValue.operations.slice(0, prefixCount)
    .filter(({ action }) => action !== 'unchanged')
    .map(({ action: _action, ...resource }) => resource);
  return { resources };
}

export function deriveOperationPrefixSequenceTableIds({ dryRunValue, entityIdentity, prefixCount }) {
  const identityByKey = new Map(entityIdentity.rows.map((row) => [row.key, row]));
  const allowed = new Set();
  for (const operation of dryRunValue.operations.slice(0, prefixCount)) {
    if (operation.target.kind !== 'entity') continue;
    const identity = identityByKey.get(assemblyTargetKey(operation.target));
    if (!identity) throw new Error(`Assembly sequence mapping is missing for ${assemblyTargetKey(operation.target)}.`);
    const tableIds = operation.action === 'create'
      ? identity.createSequenceTableIds
      : operation.action === 'update'
        ? identity.updateSequenceTableIds
        : [];
    for (const tableId of tableIds) allowed.add(tableId);
  }
  return [...allowed].sort();
}

/**
 * Run the launch-only assembly state machine. Nothing here reads or invokes
 * Drupal in the working target; all Drupal commands are bound to the clone.
 */
export function runDisposableAssembly({
  allowOwnedDeletes = false,
  captureFixtureIdentity = captureAssemblyFixtureIdentity,
  capturePersistence = captureAssemblyPersistenceSnapshot,
  captureProvenanceIdentity = captureProvenanceEntityIdentity,
  captureSource = captureDisposableSourceBytes,
  captureState = capturePortableDrupalState,
  cleanup = cleanupDisposable,
  createFileBackup = createAssemblyFileBackup,
  captureStorageResidual = captureProvenanceStorageResidual,
  discoverCapabilities = discoverAssemblyCapabilities,
  disposeFileBackup = disposeAssemblyFileBackup,
  execute,
  installFixtures = installAssemblyExtensionFixtures,
  planPath = DEFAULT_PLAN,
  projectRoot,
  registerDatabaseSourceExclusion = registerVerifierDatabaseSourceExclusion,
  restoreFileBackup = restoreAssemblyFileBackup,
  tempParent
}) {
  const checkedAt = new Date().toISOString();
  const commandLog = [];
  const recorded = execute ?? createRecordedExecutor({ commandLog });
  const sourceCommandLog = execute?.commandLog ?? commandLog;
  const run = createAssemblyBudget({ execute: recorded });
  const errors = [];
  let sourceBefore = null;
  let sourceAfter = null;
  let disposableSourceBeforeAssembly = null;
  let disposableSourceAfterAssembly = null;
  let disposableSourceOptions = null;
  let validated = null;
  let disposable = null;
  let ddevStartAttempted = false;
  let cleanupResult = { deletedDdevProject: false, removedClone: false };
  let exactHeadClone = false;
  let disposableSourceVerified = false;
  let completed = false;
  let capabilities = null;
  let fixtureResult = null;
  let baseline = null;
  let firstPlanState = null;
  let firstState = null;
  let secondPlanState = null;
  let secondState = null;
  let fixtureState = null;
  let extensionPlanState = null;
  let extensionState = null;
  let restoredState = null;
  let firstDryRun = null;
  let secondDryRun = null;
  let extensionDryRun = null;
  let restoredDryRun = null;
  let firstReconciliation = null;
  let secondReconciliation = null;
  let extensionReconciliation = null;
  let secondComparison = emptyComparison();
  let extensionComparison = emptyComparison();
  let restorationComparison = emptyComparison();
  let fixtureSurvival = { valid: false, rows: [] };
  let fixtureInstallationChanges = [];
  let fixtureIdentityBefore = null;
  let fixtureIdentityAfter = null;
  let databaseBackup = null;
  let databaseSourceExclusion = null;
  let fileSurfaceBaseline = null;
  let fileBackup = null;
  let fileBackupDisposed = false;
  let allowedStorageTableIds = [];
  let firstRunAllowedStorageTableIds = [];
  let firstRunAllowedSequenceTableIds = [];
  let firstRunStorageResidualBefore = null;
  let firstRunStorageResidualAfter = null;
  let firstRunStorageResidualComparison = null;
  let baselinePersistence = null;
  let firstPlanPersistence = null;
  let firstPersistence = null;
  let secondPlanPersistence = null;
  let secondPersistence = null;
  let fixturePersistence = null;
  let extensionPlanPersistence = null;
  let extensionPersistence = null;
  let restoredPersistence = null;
  let baselineProvenanceIdentity = null;
  let firstPlanProvenanceIdentity = null;
  let firstProvenanceIdentity = null;
  let secondPlanProvenanceIdentity = null;
  let secondProvenanceIdentity = null;
  let fixtureProvenanceIdentity = null;
  let extensionPlanProvenanceIdentity = null;
  let extensionProvenanceIdentity = null;
  let restoredProvenanceIdentity = null;
  let interruptionCutPoints = [];
  let interruptionTrials = [];
  let substrateReady = false;

  try {
    sourceBefore = sourceSnapshot(run, projectRoot, 'working-before');
    validated = loadValidatedAssemblyInputs({ execute: run, planPath, projectRoot });
    disposable = createDisposableClone({
      execute: run,
      head: sourceBefore.head,
      projectRoot,
      ...(tempParent ? { tempParent } : {})
    });
    const disposableRun = (command, args, options = {}) => run(command, args, {
      ...options,
      ...(command === 'ddev' ? { ddevXdgConfigHome: disposable.ddevXdgConfigHome } : {}),
      target: 'disposable'
    });
    disposableRun.snapshot = run.snapshot;
    const cloned = loadValidatedAssemblyInputs({
      execute: disposableRun,
      planPath: validated.planPath,
      projectRoot: disposable.root
    });
    const clonedRuntime = disposable.exactHeadRuntime;
    exactHeadClone = (
      sourceBefore.runtimeCode.fingerprint === clonedRuntime.fingerprint &&
      sha256(validated.plan) === sha256(cloned.plan) &&
      sha256(validated.provenance) === sha256(cloned.provenance) &&
      sha256(validated.substrate.plan) === sha256(cloned.substrate.plan) &&
      canonicalJson(validated.routes) === canonicalJson(cloned.routes)
    );
    if (!exactHeadClone) throw new Error('Disposable clone assembly inputs or runtime code do not match exact working-source HEAD.');
    const readPersistence = (target) => capturePersistence({
      execute: disposableRun,
      projectRoot: disposable.root,
      target
    });
    const readProvenanceIdentity = (target, state) => {
      const identity = captureProvenanceIdentity({
        execute: disposableRun,
        projectRoot: disposable.root,
        provenance: cloned.provenance,
        target
      });
      assertIdentityPresenceMatchesState(identity, cloned.provenance, state, target);
      return identity;
    };
    const readStorageResidual = (provenance, target) => captureStorageResidual({
      execute: disposableRun,
      projectRoot: disposable.root,
      provenance,
      target
    });

    for (const step of provisioningSteps(cloned.substrate.plan)) {
      if (step.adapter === 'ddev_start') ddevStartAttempted = true;
      runProvisioningStep(disposableRun, disposable, step);
      if (step.adapter === 'ddev_start') confirmDisposableDdevIdentity({ disposable, execute: run });
    }
    baseline = captureState({
      execute: disposableRun,
      projectRoot: disposable.root,
      routes: cloned.routes,
      target: 'assembly-substrate'
    });
    if (!baseline.confirmed || !baseline.configStatusClean) {
      throw new Error('Assembly substrateReady barrier requires confirmed readback and clean active configuration.');
    }
    if (baseline.configSyncDirectory !== cloned.substrate.plan.trackedConfig.path) {
      throw new Error('Assembly substrateReady barrier found a config-sync path mismatch.');
    }
    assertDeclaredEmptyAdapters(cloned.substrate.plan, baseline);
    assertProvenanceReadbackCoverage(cloned.provenance, baseline);
    capabilities = discoverCapabilities({
      execute: disposableRun,
      projectRoot: disposable.root,
      target: 'assembly-substrate'
    });
    assertFixturePlanAgainstCapabilities(cloned.plan.extensionFixtures, capabilities);
    substrateReady = true;

    baselinePersistence = readPersistence('assembly-substrate');
    fileSurfaceBaseline = {
      files: baselinePersistence.files,
      aggregateSha256: sha256(baselinePersistence.files)
    };
    baselineProvenanceIdentity = readProvenanceIdentity('assembly-substrate', baseline);
    fileBackup = createFileBackup({
      execute: disposableRun,
      projectRoot: disposable.root,
      target: 'assembly-substrate',
      baseline: fileSurfaceBaseline
    });
    databaseBackup = createVerifierDatabaseBackup(disposableRun, disposable);
    databaseSourceExclusion = registerDatabaseSourceExclusion({
      projectRoot: disposable.root,
      relativePath: databaseBackup.relativePath,
      expectedFingerprint: databaseBackup.sha256
    });
    disposableSourceOptions = {
      captureSource,
      databaseSourceExclusion,
      execute: disposableRun,
      fileBackup,
      projectRoot: disposable.root
    };
    disposableSourceBeforeAssembly = captureOwnedDisposableSource(disposableSourceOptions);
    firstDryRun = dryRun(disposableRun, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(firstDryRun, capabilities);
    assertInitialMutation(firstDryRun);
    firstPlanState = captureState({
      execute: disposableRun,
      projectRoot: disposable.root,
      routes: cloned.routes,
      target: 'assembly-after-first-plan'
    });
    assertStateMetadataStable(baseline, firstPlanState, 'First assembly plan');
    requireExactComparison(exactStateComparison(baseline, firstPlanState), 'First assembly plan');
    firstPlanPersistence = readPersistence('assembly-after-first-plan');
    assertExactPersistenceEquality(baselinePersistence, firstPlanPersistence, 'First assembly plan persistence');
    firstPlanProvenanceIdentity = readProvenanceIdentity('assembly-after-first-plan', firstPlanState);
    assertExactEntityIdentityEquality(
      baselineProvenanceIdentity,
      firstPlanProvenanceIdentity,
      'First assembly plan entity identity'
    );
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'First assembly plan source bytes');
    interruptionCutPoints = selectAssemblyInterruptionCutPoints(firstDryRun);
    for (const prefixCount of interruptionCutPoints) {
      const prefixProvenance = operationPrefixProvenance(firstDryRun, prefixCount);
      const storageResidualBefore = readStorageResidual(
        prefixProvenance,
        `assembly-before-interrupted-prefix-${prefixCount}`
      );
      const deleteCount = invokeAdapterPrefix(
        disposableRun,
        disposable,
        cloned.plan.adapter.source.path,
        firstDryRun,
        prefixCount,
        allowOwnedDeletes
      );
      const partialState = captureState({
        execute: disposableRun,
        projectRoot: disposable.root,
        routes: cloned.routes,
        target: `assembly-interrupted-prefix-${prefixCount}`
      });
      assertStateMetadataStable(baseline, partialState, `Assembly interrupted prefix ${prefixCount}`);
      const prefixReconciliation = reconcileDryRunPrefix(firstDryRun, prefixCount, baseline, partialState);
      if (!prefixReconciliation.valid) {
        throw new Error(`Verifier-controlled operation prefix ${prefixCount} does not reconcile with independently derived state.`);
      }
      const observedChanges = deriveAssemblyChanges(baseline, partialState);
      if (observedChanges.length === 0) {
        throw new Error(`Verifier-controlled operation prefix ${prefixCount} produced no independently observed mutation.`);
      }
      const storageResidualAfter = readStorageResidual(
        prefixProvenance,
        `assembly-after-interrupted-prefix-${prefixCount}`
      );
      const storageResidualComparison = assertExactProvenanceStorageResidual(
        storageResidualBefore,
        storageResidualAfter,
        `Assembly interrupted prefix ${prefixCount}`
      );
      const prefixAllowedStorageTableIds = storageResidualBefore.tables.map(({ id }) => id);
      const prefixAllowedSequenceTableIds = deriveOperationPrefixSequenceTableIds({
        dryRunValue: firstDryRun,
        entityIdentity: baselineProvenanceIdentity,
        prefixCount
      });
      const partialPersistence = readPersistence(`assembly-interrupted-prefix-${prefixCount}`);
      const persistenceComparison = assertFirstRunPersistenceChanges({
        before: baselinePersistence,
        after: partialPersistence,
        allowedTableIds: prefixAllowedStorageTableIds,
        allowedSequenceTableIds: prefixAllowedSequenceTableIds,
        label: `Assembly interrupted prefix ${prefixCount}`
      });
      const partialProvenanceIdentity = readProvenanceIdentity(`assembly-interrupted-prefix-${prefixCount}`, partialState);
      const identityComparison = assertIdentityTransitionsMatchPrefix(
        baselineProvenanceIdentity,
        partialProvenanceIdentity,
        firstDryRun,
        prefixCount,
        `Assembly interrupted prefix ${prefixCount}`,
        allowOwnedDeletes
      );
      requireDisposableSourceUnchanged(
        disposableSourceOptions,
        disposableSourceBeforeAssembly,
        `Interrupted prefix ${prefixCount} source bytes`
      );
      restoreVerifierDatabaseBackup(disposableRun, disposable, databaseBackup);
      const restoredFileSurfaces = restoreFileBackup({
        execute: disposableRun,
        projectRoot: disposable.root,
        backup: fileBackup,
        target: `assembly-restored-prefix-${prefixCount}`
      });
      restoredState = captureState({
        execute: disposableRun,
        projectRoot: disposable.root,
        routes: cloned.routes,
        target: `assembly-restored-prefix-${prefixCount}`
      });
      assertStateMetadataStable(baseline, restoredState, `Verifier-owned restoration after prefix ${prefixCount}`);
      const exactRestorationComparison = exactStateComparison(baseline, restoredState);
      requireExactComparison(exactRestorationComparison, `Verifier-owned restoration after prefix ${prefixCount}`);
      restoredPersistence = readPersistence(`assembly-restored-prefix-${prefixCount}`);
      const persistenceRestorationComparison = assertRestoredPersistence(
        baselinePersistence,
        restoredPersistence
      );
      restoredProvenanceIdentity = readProvenanceIdentity(`assembly-restored-prefix-${prefixCount}`, restoredState);
      const identityRestorationComparison = assertExactEntityIdentityEquality(
        baselineProvenanceIdentity,
        restoredProvenanceIdentity,
        `Verifier-owned restoration after prefix ${prefixCount}`
      );
      requireDisposableSourceUnchanged(
        disposableSourceOptions,
        disposableSourceBeforeAssembly,
        `Restored prefix ${prefixCount} source bytes`
      );
      restoredDryRun = dryRun(disposableRun, disposable, cloned.plan.adapter.source.path, cloned.provenance);
      if (restoredDryRun.fingerprint !== firstDryRun.fingerprint) {
        throw new Error(`Verifier-owned restoration after prefix ${prefixCount} did not restore the exact first-run plan.`);
      }
      requireDisposableSourceUnchanged(
        disposableSourceOptions,
        disposableSourceBeforeAssembly,
        `Restored plan ${prefixCount} source bytes`
      );
      const restoredPlanState = captureState({
        execute: disposableRun,
        projectRoot: disposable.root,
        routes: cloned.routes,
        target: `assembly-after-restored-plan-prefix-${prefixCount}`
      });
      const exactPlanComparison = exactStateComparison(baseline, restoredPlanState);
      requireExactComparison(exactPlanComparison, `Restored plan after prefix ${prefixCount}`);
      const restoredPlanPersistence = readPersistence(`assembly-after-restored-plan-prefix-${prefixCount}`);
      const persistencePlanComparison = assertExactPersistenceEquality(
        baselinePersistence,
        restoredPlanPersistence,
        `Restored plan after prefix ${prefixCount}`
      );
      const restoredPlanIdentity = readProvenanceIdentity(
        `assembly-after-restored-plan-prefix-${prefixCount}`,
        restoredPlanState
      );
      const identityPlanComparison = assertExactEntityIdentityEquality(
        baselineProvenanceIdentity,
        restoredPlanIdentity,
        `Restored plan after prefix ${prefixCount}`
      );
      requireDisposableSourceUnchanged(
        disposableSourceOptions,
        disposableSourceBeforeAssembly,
        `Restored plan ${prefixCount} source bytes after readback`
      );
      interruptionTrials.push({
        prefixCount,
        deleteCount,
        allowedStorageTableIds: prefixAllowedStorageTableIds,
        allowedSequenceTableIds: prefixAllowedSequenceTableIds,
        storageResidualBefore,
        storageResidualAfter,
        storageResidualComparison,
        observedChanges,
        persistenceComparison,
        identityComparison,
        prefixReconciliation,
        partialPersistence,
        partialProvenanceIdentity,
        restoredFileSurfaces,
        exactRestorationComparison,
        persistenceRestorationComparison,
        identityRestorationComparison,
        exactPlanComparison,
        persistencePlanComparison,
        identityPlanComparison,
        restoredPlanFingerprint: restoredDryRun.fingerprint
      });
    }

    const firstRunProvenance = operationPrefixProvenance(firstDryRun, firstDryRun.operations.length);
    firstRunStorageResidualBefore = readStorageResidual(firstRunProvenance, 'assembly-before-first');
    firstRunAllowedStorageTableIds = firstRunStorageResidualBefore.tables.map(({ id }) => id);
    allowedStorageTableIds = firstRunAllowedStorageTableIds;
    firstRunAllowedSequenceTableIds = deriveOperationPrefixSequenceTableIds({
      dryRunValue: firstDryRun,
      entityIdentity: baselineProvenanceIdentity,
      prefixCount: firstDryRun.operations.length
    });
    invokeAdapterPrefix(
      disposableRun,
      disposable,
      cloned.plan.adapter.source.path,
      firstDryRun,
      firstDryRun.operations.length,
      allowOwnedDeletes
    );
    firstState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-first' });
    assertStateMetadataStable(baseline, firstState, 'First assembly run');
    if (!firstState.configStatusClean) throw new Error('First assembly run left active configuration out of sync.');
    firstReconciliation = reconcileDryRun(firstDryRun, baseline, firstState);
    if (!firstReconciliation.valid) throw new Error('First assembly dry-run does not reconcile with verifier-derived state changes.');
    firstRunStorageResidualAfter = readStorageResidual(firstRunProvenance, 'assembly-first');
    firstRunStorageResidualComparison = assertExactProvenanceStorageResidual(
      firstRunStorageResidualBefore,
      firstRunStorageResidualAfter,
      'First assembly run'
    );
    firstPersistence = readPersistence('assembly-first');
    assertFirstRunPersistenceChanges({
      before: baselinePersistence,
      after: firstPersistence,
      allowedTableIds: firstRunAllowedStorageTableIds,
      allowedSequenceTableIds: firstRunAllowedSequenceTableIds,
      label: 'First assembly run'
    });
    firstProvenanceIdentity = readProvenanceIdentity('assembly-first', firstState);
    assertIdentityTransitionsMatchPrefix(
      baselineProvenanceIdentity,
      firstProvenanceIdentity,
      firstDryRun,
      firstDryRun.operations.length,
      'First assembly run',
      allowOwnedDeletes
    );
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'First assembly source bytes');

    secondDryRun = dryRun(disposableRun, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(secondDryRun, capabilities);
    assertNoOpDryRun(secondDryRun, 'Second assembly dry-run');
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'Second assembly plan source bytes');
    secondPlanState = captureState({
      execute: disposableRun,
      projectRoot: disposable.root,
      routes: cloned.routes,
      target: 'assembly-after-second-plan'
    });
    requireExactComparison(exactStateComparison(firstState, secondPlanState), 'Second assembly plan');
    secondPlanPersistence = readPersistence('assembly-after-second-plan');
    assertExactPersistenceEquality(firstPersistence, secondPlanPersistence, 'Second assembly plan persistence');
    secondPlanProvenanceIdentity = readProvenanceIdentity('assembly-after-second-plan', secondPlanState);
    assertExactEntityIdentityEquality(
      firstProvenanceIdentity,
      secondPlanProvenanceIdentity,
      'Second assembly plan entity identity'
    );
    requireDisposableSourceUnchanged(
      disposableSourceOptions,
      disposableSourceBeforeAssembly,
      'Second assembly plan source bytes after readback'
    );
    invokeAdapterPrefix(
      disposableRun,
      disposable,
      cloned.plan.adapter.source.path,
      secondDryRun,
      secondDryRun.operations.length,
      allowOwnedDeletes
    );
    secondState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-second' });
    assertStateMetadataStable(firstState, secondState, 'Second assembly run');
    if (!secondState.configStatusClean) throw new Error('Second assembly run left active configuration out of sync.');
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'Second assembly source bytes');
    secondReconciliation = reconcileDryRun(secondDryRun, firstState, secondState);
    if (!secondReconciliation.valid) throw new Error('Second assembly no-op plan does not reconcile with verifier-derived state.');
    secondComparison = exactStateComparison(firstState, secondState);
    requireExactComparison(secondComparison, 'Second assembly run');
    secondPersistence = readPersistence('assembly-second');
    assertNoOpPersistence(firstPersistence, secondPersistence);
    secondProvenanceIdentity = readProvenanceIdentity('assembly-second', secondState);
    assertExactEntityIdentityEquality(
      firstProvenanceIdentity,
      secondProvenanceIdentity,
      'Second assembly run entity identity'
    );
    requireDisposableSourceUnchanged(
      disposableSourceOptions,
      disposableSourceBeforeAssembly,
      'Second assembly source bytes after readback'
    );

    fixtureResult = installFixtures({
      execute: disposableRun,
      fixtures: cloned.plan.extensionFixtures,
      projectRoot: disposable.root,
      target: 'assembly-extension-fixtures'
    });
    fixtureState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-fixtures-before-rerun' });
    assertStateMetadataStable(secondState, fixtureState, 'Extension fixture installation');
    fixtureInstallationChanges = deriveAssemblyChanges(secondState, fixtureState);
    const expectedFixtureKeys = fixtureResult.targets.map(({ target }) => assemblyTargetKey(target)).sort();
    const observedFixtureKeys = fixtureInstallationChanges.map(({ key }) => key).sort();
    if (canonicalJson(expectedFixtureKeys) !== canonicalJson(observedFixtureKeys)) {
      throw new Error('Verifier fixture injection changed state outside its exact returned target set or failed to change a declared fixture target.');
    }
    const installed = fixtureTargetsSurvived(fixtureResult.targets, fixtureState, fixtureState);
    if (!installed.valid) throw new Error('Verifier-owned extension fixture targets were not all present after installation.');
    if (fixtureResult.targets.some(({ target }) => target.kind === 'config') && fixtureState.configStatusClean) {
      throw new Error('Verifier-owned config fixtures did not produce independently visible active-config additions.');
    }
    fixtureIdentityBefore = captureFixtureIdentity({
      execute: disposableRun,
      projectRoot: disposable.root,
      target: 'assembly-fixtures-before-rerun',
      targets: fixtureResult.targets
    });
    fixturePersistence = readPersistence('assembly-fixtures-before-rerun');
    fixtureProvenanceIdentity = readProvenanceIdentity('assembly-fixtures-before-rerun', fixtureState);
    assertExactEntityIdentityEquality(
      secondProvenanceIdentity,
      fixtureProvenanceIdentity,
      'Extension fixture installation provenance identity'
    );
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'Extension fixture source bytes');

    extensionDryRun = dryRun(disposableRun, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(extensionDryRun, capabilities);
    assertNoOpDryRun(extensionDryRun, 'Post-extension assembly dry-run');
    extensionPlanState = captureState({
      execute: disposableRun,
      projectRoot: disposable.root,
      routes: cloned.routes,
      target: 'assembly-after-extension-plan'
    });
    requireExactComparison(exactStateComparison(fixtureState, extensionPlanState), 'Post-extension assembly plan');
    extensionPlanPersistence = readPersistence('assembly-after-extension-plan');
    assertExactPersistenceEquality(
      fixturePersistence,
      extensionPlanPersistence,
      'Post-extension assembly plan persistence'
    );
    extensionPlanProvenanceIdentity = readProvenanceIdentity('assembly-after-extension-plan', extensionPlanState);
    assertExactEntityIdentityEquality(
      fixtureProvenanceIdentity,
      extensionPlanProvenanceIdentity,
      'Post-extension assembly plan entity identity'
    );
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'Extension plan source bytes');
    invokeAdapterPrefix(
      disposableRun,
      disposable,
      cloned.plan.adapter.source.path,
      extensionDryRun,
      extensionDryRun.operations.length,
      allowOwnedDeletes
    );
    extensionState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-extension-rerun' });
    assertStateMetadataStable(fixtureState, extensionState, 'Post-extension assembly rerun');
    extensionReconciliation = reconcileDryRun(extensionDryRun, fixtureState, extensionState);
    if (!extensionReconciliation.valid) throw new Error('Post-extension no-op plan does not reconcile with verifier-derived state.');
    extensionComparison = exactStateComparison(fixtureState, extensionState);
    requireExactComparison(extensionComparison, 'Post-extension assembly rerun');
    fixtureSurvival = fixtureTargetsSurvived(fixtureResult.targets, fixtureState, extensionState);
    if (!fixtureSurvival.valid) throw new Error('Assembly rerun changed or removed a verifier-owned extension fixture.');
    fixtureIdentityAfter = captureFixtureIdentity({
      execute: disposableRun,
      projectRoot: disposable.root,
      target: 'assembly-extension-rerun',
      targets: fixtureResult.targets
    });
    if (fixtureIdentityBefore.fingerprint !== fixtureIdentityAfter.fingerprint) {
      throw new Error('Assembly rerun deleted, recreated, or re-revisioned a verifier-owned extension entity.');
    }
    extensionPersistence = readPersistence('assembly-extension-rerun');
    assertExactPersistenceEquality(
      fixturePersistence,
      extensionPersistence,
      'Post-extension assembly rerun persistence'
    );
    extensionProvenanceIdentity = readProvenanceIdentity('assembly-extension-rerun', extensionState);
    assertExactEntityIdentityEquality(
      fixtureProvenanceIdentity,
      extensionProvenanceIdentity,
      'Post-extension assembly rerun entity identity'
    );
    requireDisposableSourceUnchanged(disposableSourceOptions, disposableSourceBeforeAssembly, 'Extension rerun source bytes');

    restorationComparison = interruptionTrials.at(-1)?.exactRestorationComparison ?? emptyComparison();
    disposableSourceAfterAssembly = captureOwnedDisposableSource(disposableSourceOptions);
    assertDisposableSourceBytesEqual(
      disposableSourceBeforeAssembly,
      disposableSourceAfterAssembly,
      'Final disposable source bytes'
    );
    disposableSourceVerified = true;
    completed = true;
  } catch (error) {
    errors.push(firstError(error));
  } finally {
    if (disposable) {
      if (fileBackup) {
        try {
          fileBackupDisposed = disposeFileBackup({ projectRoot: disposable.root, backup: fileBackup });
        } catch (error) {
          errors.push(`Verifier file-backup cleanup failed: ${firstError(error)}`);
        }
      }
      try {
        cleanupResult = cleanup({ ddevStartAttempted, disposable, execute: run });
      } catch (error) {
        errors.push(`Disposable cleanup retained the target: ${firstError(error)}`);
      }
    }
    try {
      if (sourceBefore) sourceAfter = sourceSnapshot(run, projectRoot, 'working-after');
    } catch (error) {
      errors.push(`Working-source after-proof failed: ${firstError(error)}`);
    }
  }

  const workingSourceUnchanged = sourceUnchanged(sourceBefore, sourceAfter);
  const workingDdevCommands = sourceCommandLog.filter((command) => (
    command.target === 'working' && command.argv?.[0] === 'ddev'
  )).length;
  const cleanupComplete = Boolean(!disposable || cleanupResult.removedClone);
  const verifierBackupsDisposed = Boolean(!fileBackup || fileBackupDisposed);
  const budget = run.snapshot();
  const valid = Boolean(
    errors.length === 0 && completed && substrateReady && exactHeadClone && workingSourceUnchanged &&
    workingDdevCommands === 0 && cleanupComplete && verifierBackupsDisposed && !budget.exceeded
  );
  const states = {
    baseline,
    firstPlanState,
    firstState,
    secondPlanState,
    secondState,
    fixtureState,
    extensionPlanState,
    extensionState,
    restoredState
  };
  return {
    schemaVersion: REPORT_SCHEMA,
    gateId: 'G-ASSEMBLY-01',
    checkedAt,
    valid,
    runStatus: errors.length > 0 ? 'operational_failure' : valid ? 'pass' : 'mismatch',
    evidenceScope: {
      launchEvidence: true,
      authoritativeForDefaultHandoff: false,
      rationale: 'This separate launch verifier proves assembly semantics only in an owned exact-HEAD clone; it never promotes the default local handoff verdict.'
    },
    source: {
      head: sourceBefore?.head ?? '',
      planPath: validated?.planPath ?? safeProjectRelativePath(planPath, 'Assembly plan path'),
      planSha256: validated ? sha256(validated.plan) : '',
      provenanceSha256: validated ? sha256(validated.provenance) : '',
      runtimeCodeFingerprint: sourceBefore?.runtimeCode?.fingerprint ?? '',
      exactHeadClone
    },
    declaredInputs: validated?.inputs ?? [],
    adapter: {
      protocol: validated?.plan?.adapter?.protocol ?? '',
      fixedModes: ['plan', 'apply-prefix'],
      failureProof: validated?.plan?.adapter?.failureProof ?? '',
      arbitraryCommandSurface: false
    },
    deletionProof: {
      policy: validated?.plan?.deletion?.policy ?? '',
      cliOptIn: allowOwnedDeletes,
      firstRunDeleteCount: firstDryRun?.summary?.delete ?? 0,
      interruptedPrefixDeleteCount: interruptionTrials.reduce((total, trial) => total + trial.deleteCount, 0)
    },
    workingTargetProof: {
      untouched: workingSourceUnchanged && workingDdevCommands === 0,
      drupalCommandCount: workingDdevCommands,
      sourceUnchanged: workingSourceUnchanged,
      headBefore: sourceBefore?.head ?? '',
      headAfter: sourceAfter?.head ?? '',
      trackedWorktreeBeforeSha256: sourceBefore?.trackedWorktreeSha256 ?? '',
      trackedWorktreeAfterSha256: sourceAfter?.trackedWorktreeSha256 ?? '',
      untrackedWorktreeBeforeFingerprint: sourceBefore?.untrackedWorktree?.fingerprint ?? '',
      untrackedWorktreeAfterFingerprint: sourceAfter?.untrackedWorktree?.fingerprint ?? '',
      runtimeCodeBeforeFingerprint: sourceBefore?.runtimeCode?.fingerprint ?? '',
      runtimeCodeAfterFingerprint: sourceAfter?.runtimeCode?.fingerprint ?? ''
    },
    disposable: {
      projectName: disposable?.name ?? '',
      ownershipNamespaceConfirmed: Boolean(disposable?.name?.startsWith('agent-ready-repro-')),
      sourceTreeUnchanged: disposableSourceVerified,
      sourceTreeBeforeFingerprint: disposableSourceBeforeAssembly?.aggregateSha256 ?? '',
      sourceTreeAfterFingerprint: disposableSourceAfterAssembly?.aggregateSha256 ?? '',
      fileBackupDisposed,
      cleanup: cleanupResult
    },
    substrate: {
      ready: substrateReady,
      mode: validated?.substrate?.plan?.mode ?? '',
      adapters: validated ? provisioningSteps(validated.substrate.plan).map((step) => step.adapter) : [],
      capabilities
    },
    dryRuns: {
      first: firstDryRun,
      secondNoOp: secondDryRun,
      postExtensionNoOp: extensionDryRun,
      postRestorationPlan: restoredDryRun
    },
    firstRun: { reconciliation: firstReconciliation },
    secondRun: { reconciliation: secondReconciliation, exactComparison: secondComparison },
    extensionSurvival: {
      fixtureResult,
      fixtureInstallationChanges,
      fixtureIdentityBefore,
      fixtureIdentityAfter,
      reconciliation: extensionReconciliation,
      exactComparison: extensionComparison,
      targetProof: fixtureSurvival
    },
    failureAndRestoration: {
      mode: validated?.plan?.adapter?.failureProof ?? '',
      databaseBackup,
      databaseSourceExclusion,
      fileBackup,
      interruptionCutPoints,
      trials: interruptionTrials,
      exactRestorationComparison: restorationComparison
    },
    persistenceProof: {
      allowedStorageTableIds,
      firstRunAllowedStorageTableIds,
      firstRunAllowedSequenceTableIds,
      baseline: baselinePersistence,
      firstPlan: firstPlanPersistence,
      firstRun: firstPersistence,
      secondPlan: secondPlanPersistence,
      secondRun: secondPersistence,
      extensionFixtures: fixturePersistence,
      extensionPlan: extensionPlanPersistence,
      extensionRun: extensionPersistence,
      restored: restoredPersistence
    },
    storageResidualProof: {
      firstRunBefore: firstRunStorageResidualBefore,
      firstRunAfter: firstRunStorageResidualAfter,
      firstRunComparison: firstRunStorageResidualComparison
    },
    provenanceEntityIdentity: {
      baseline: baselineProvenanceIdentity,
      firstPlan: firstPlanProvenanceIdentity,
      firstRun: firstProvenanceIdentity,
      secondPlan: secondPlanProvenanceIdentity,
      secondRun: secondProvenanceIdentity,
      extensionFixtures: fixtureProvenanceIdentity,
      extensionPlan: extensionPlanProvenanceIdentity,
      extensionRun: extensionProvenanceIdentity,
      restored: restoredProvenanceIdentity
    },
    stateChecksums: Object.fromEntries(Object.entries(states).map(([name, state]) => [name, state?.fingerprint ?? ''])),
    readback: states,
    budget,
    commands: sourceCommandLog,
    errors
  };
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function safeEvidenceOutput(projectRoot, value) {
  const relativePath = safeProjectRelativePath(value, 'Assembly evidence output');
  if (!relativePath.startsWith('review-packet/evidence/')) {
    throw new Error('Assembly evidence output must be under review-packet/evidence/.');
  }
  const path = resolve(projectRoot, relativePath);
  if (!isInside(projectRoot, path)) throw new Error('Assembly evidence output escaped the project root.');
  let current = dirname(path);
  while (current !== projectRoot) {
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
      throw new Error('Assembly evidence output must not traverse a symbolic link.');
    }
    current = dirname(current);
  }
  if (existsSync(path) && (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile())) {
    throw new Error('Assembly evidence output must be a regular non-symlink file.');
  }
  return { path, relativePath };
}

export function writeAssemblyEvidence(projectRoot, output, report) {
  const { path, relativePath } = safeEvidenceOutput(projectRoot, output);
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  renameSync(temporary, path);
  return relativePath;
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }
  const projectRoot = ddevDrupalRoot(args.project || process.cwd());
  if (!projectRoot) throw new UsageError('No Drupal DDEV project was found at or above --project/current directory.');
  const commandLog = [];
  const execute = createRecordedExecutor({ commandLog });
  execute.commandLog = commandLog;
  const report = runDisposableAssembly({
    allowOwnedDeletes: args.allowOwnedDeletes,
    execute,
    planPath: args.plan,
    projectRoot
  });
  const output = writeAssemblyEvidence(projectRoot, args.out, report);
  if (!report.valid) {
    process.stderr.write(`Disposable assembly verification failed closed. Report: ${output}\n`);
    for (const error of report.errors) process.stderr.write(`- ${error}\n`);
    process.exitCode = report.runStatus === 'operational_failure' ? 1 : 2;
    return;
  }
  process.stdout.write(`Disposable assembly reruns, extension survival, and restoration passed. Report: ${output}\n`);
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
