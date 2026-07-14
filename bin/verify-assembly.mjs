#!/usr/bin/env node

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
  assertChangesWithinProvenance,
  assertDeletesAuthorized,
  assertInitialMutation,
  assertNoOpDryRun,
  assertStateMetadataStable,
  deriveAssemblyChanges,
  fixtureTargetsSurvived,
  loadValidatedAssemblyInputs,
  parseAssemblyDryRun,
  reconcileDryRun
} from './assembly-contract.mjs';
import {
  assertDryRunSurfacesAvailable,
  assertFixturePlanAgainstCapabilities,
  captureAssemblyFixtureIdentity,
  discoverAssemblyCapabilities,
  installAssemblyExtensionFixtures
} from './assembly-fixtures.mjs';
import {
  assertDeclaredEmptyAdapters,
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
const ADAPTER_MODES = new Set(['plan', 'apply', 'failpoint', 'restore']);
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
    const detail = String(result?.stderr ?? result?.error?.message ?? '').trim().split(/\r?\n/)[0];
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
    const detail = String(result?.stderr ?? result?.error?.message ?? '').trim().split(/\r?\n/)[0];
    throw new Error(`Typed substrate adapter ${step.adapter} failed${detail ? `: ${detail}` : ''}`);
  }
}

export function assemblyAdapterArgs(adapterSourcePath, mode) {
  if (!ADAPTER_MODES.has(mode)) throw new Error(`Unsupported fixed assembly adapter mode: ${mode}.`);
  return ['drush', 'php:script', adapterSourcePath, '--', mode];
}

function invokeAdapter(execute, disposable, sourcePath, mode, { expectFailure = false } = {}) {
  const result = execute('ddev', assemblyAdapterArgs(sourcePath, mode), {
    cwd: disposable.root,
    phase: `assembly-adapter:${mode}`,
    target: 'disposable',
    timeout: 600_000
  });
  if (expectFailure) {
    if (!result || !Number.isInteger(result.status) || result.status === 0 || result.signal || result.error) {
      throw new Error('Assembly failpoint must exit non-zero under verifier control without timeout, signal, or spawn failure.');
    }
  } else if (!result || result.status !== 0) {
    const detail = String(result?.stderr ?? result?.error?.message ?? '').trim().split(/\r?\n/)[0];
    throw new Error(`Fixed assembly adapter mode ${mode} failed${detail ? `: ${detail}` : ''}`);
  }
  return result;
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

/**
 * Run the launch-only assembly state machine. Nothing here reads or invokes
 * Drupal in the working target; all Drupal commands are bound to the clone.
 */
export function runDisposableAssembly({
  allowOwnedDeletes = false,
  captureFixtureIdentity = captureAssemblyFixtureIdentity,
  captureState = capturePortableDrupalState,
  cleanup = cleanupDisposable,
  discoverCapabilities = discoverAssemblyCapabilities,
  execute,
  installFixtures = installAssemblyExtensionFixtures,
  planPath = DEFAULT_PLAN,
  projectRoot,
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
  let validated = null;
  let disposable = null;
  let ddevStartAttempted = false;
  let cleanupResult = { deletedDdevProject: false, removedClone: false };
  let exactHeadClone = false;
  let completed = false;
  let capabilities = null;
  let fixtureResult = null;
  let baseline = null;
  let firstState = null;
  let secondState = null;
  let fixtureState = null;
  let extensionState = null;
  let failureState = null;
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
  let fixtureIdentityRestored = null;
  let failureChanges = [];
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
    const disposableRun = (command, args, options = {}) => run(command, args, { ...options, target: 'disposable' });
    disposableRun.snapshot = run.snapshot;
    const cloned = loadValidatedAssemblyInputs({
      execute: disposableRun,
      planPath: validated.planPath,
      projectRoot: disposable.root
    });
    const clonedRuntime = exactHeadRuntimeBinding(disposable.root);
    exactHeadClone = (
      sourceBefore.runtimeCode.fingerprint === clonedRuntime.fingerprint &&
      sha256(validated.plan) === sha256(cloned.plan) &&
      sha256(validated.provenance) === sha256(cloned.provenance) &&
      sha256(validated.substrate.plan) === sha256(cloned.substrate.plan) &&
      canonicalJson(validated.routes) === canonicalJson(cloned.routes)
    );
    if (!exactHeadClone) throw new Error('Disposable clone assembly inputs or runtime code do not match exact working-source HEAD.');

    for (const step of provisioningSteps(cloned.substrate.plan)) {
      if (step.adapter === 'ddev_start') ddevStartAttempted = true;
      runProvisioningStep(run, disposable, step);
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
    capabilities = discoverCapabilities({
      execute: disposableRun,
      projectRoot: disposable.root,
      target: 'assembly-substrate'
    });
    assertFixturePlanAgainstCapabilities(cloned.plan.extensionFixtures, capabilities);
    disposableSourceBeforeAssembly = sourceSnapshot(
      run,
      disposable.root,
      'disposable-before-assembly',
      'disposable'
    );
    substrateReady = true;

    firstDryRun = dryRun(run, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(firstDryRun, capabilities);
    assertInitialMutation(firstDryRun);
    assertDeletesAuthorized(firstDryRun, allowOwnedDeletes);
    invokeAdapter(run, disposable, cloned.plan.adapter.source.path, 'apply');
    firstState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-first' });
    assertStateMetadataStable(baseline, firstState, 'First assembly run');
    if (!firstState.configStatusClean) throw new Error('First assembly run left active configuration out of sync.');
    firstReconciliation = reconcileDryRun(firstDryRun, baseline, firstState);
    if (!firstReconciliation.valid) throw new Error('First assembly dry-run does not reconcile with verifier-derived state changes.');

    secondDryRun = dryRun(run, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(secondDryRun, capabilities);
    assertNoOpDryRun(secondDryRun, 'Second assembly dry-run');
    invokeAdapter(run, disposable, cloned.plan.adapter.source.path, 'apply');
    secondState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-second' });
    assertStateMetadataStable(firstState, secondState, 'Second assembly run');
    if (!secondState.configStatusClean) throw new Error('Second assembly run left active configuration out of sync.');
    secondReconciliation = reconcileDryRun(secondDryRun, firstState, secondState);
    if (!secondReconciliation.valid) throw new Error('Second assembly no-op plan does not reconcile with verifier-derived state.');
    secondComparison = exactStateComparison(firstState, secondState);
    requireExactComparison(secondComparison, 'Second assembly run');

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

    extensionDryRun = dryRun(run, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(extensionDryRun, capabilities);
    assertNoOpDryRun(extensionDryRun, 'Post-extension assembly dry-run');
    invokeAdapter(run, disposable, cloned.plan.adapter.source.path, 'apply');
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

    invokeAdapter(run, disposable, cloned.plan.adapter.source.path, 'failpoint', { expectFailure: true });
    let failureCaptureError = null;
    try {
      failureState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-failpoint' });
    } catch (error) {
      failureCaptureError = error;
    }
    let restorationError = null;
    try {
      invokeAdapter(run, disposable, cloned.plan.adapter.source.path, 'restore');
      restoredState = captureState({ execute: disposableRun, projectRoot: disposable.root, routes: cloned.routes, target: 'assembly-restored' });
    } catch (error) {
      restorationError = error;
    }
    if (failureCaptureError) throw new Error(`Failpoint state could not be independently read before restoration: ${firstError(failureCaptureError)}`);
    if (restorationError) throw new Error(`Fixed restoration path failed: ${firstError(restorationError)}`);
    assertStateMetadataStable(extensionState, failureState, 'Assembly failpoint');
    failureChanges = deriveAssemblyChanges(extensionState, failureState);
    if (failureChanges.length === 0) throw new Error('Assembly failpoint exited non-zero without an independently observed mid-run state change.');
    assertChangesWithinProvenance(failureChanges, cloned.provenance, 'Assembly failpoint');
    if (failureChanges.some(({ action }) => action === 'delete') && !allowOwnedDeletes) {
      throw new Error('Assembly failpoint performed a provenance-owned delete without explicit --allow-owned-deletes authorization.');
    }
    restorationComparison = exactStateComparison(extensionState, restoredState);
    requireExactComparison(restorationComparison, 'Fixed assembly restoration');
    fixtureIdentityRestored = captureFixtureIdentity({
      execute: disposableRun,
      projectRoot: disposable.root,
      target: 'assembly-restored',
      targets: fixtureResult.targets
    });
    if (fixtureIdentityAfter.fingerprint !== fixtureIdentityRestored.fingerprint) {
      throw new Error('Fixed restoration deleted, recreated, or re-revisioned a verifier-owned extension entity.');
    }
    restoredDryRun = dryRun(run, disposable, cloned.plan.adapter.source.path, cloned.provenance);
    assertDryRunSurfacesAvailable(restoredDryRun, capabilities);
    assertNoOpDryRun(restoredDryRun, 'Post-restoration assembly dry-run');
    disposableSourceAfterAssembly = sourceSnapshot(
      run,
      disposable.root,
      'disposable-after-assembly',
      'disposable'
    );
    if (!sourceUnchanged(disposableSourceBeforeAssembly, disposableSourceAfterAssembly)) {
      throw new Error('Assembly or restoration changed the disposable clone source tree outside Drupal state.');
    }
    completed = true;
  } catch (error) {
    errors.push(firstError(error));
  } finally {
    if (disposable) {
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
  const budget = run.snapshot();
  const valid = Boolean(
    errors.length === 0 && completed && substrateReady && exactHeadClone && workingSourceUnchanged &&
    workingDdevCommands === 0 && cleanupComplete && !budget.exceeded
  );
  const states = { baseline, firstState, secondState, fixtureState, extensionState, failureState, restoredState };
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
      fixedModes: ['plan', 'apply', 'failpoint', 'restore'],
      failureProof: validated?.plan?.adapter?.failureProof ?? '',
      arbitraryCommandSurface: false
    },
    deletionProof: {
      policy: validated?.plan?.deletion?.policy ?? '',
      cliOptIn: allowOwnedDeletes,
      firstRunDeleteCount: firstDryRun?.summary?.delete ?? 0,
      failpointDeleteCount: failureChanges.filter(({ action }) => action === 'delete').length
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
      sourceTreeUnchanged: sourceUnchanged(disposableSourceBeforeAssembly, disposableSourceAfterAssembly),
      sourceTreeBeforeFingerprint: disposableSourceBeforeAssembly?.runtimeCode?.fingerprint ?? '',
      sourceTreeAfterFingerprint: disposableSourceAfterAssembly?.runtimeCode?.fingerprint ?? '',
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
      postRestorationNoOp: restoredDryRun
    },
    firstRun: { reconciliation: firstReconciliation },
    secondRun: { reconciliation: secondReconciliation, exactComparison: secondComparison },
    extensionSurvival: {
      fixtureResult,
      fixtureInstallationChanges,
      fixtureIdentityBefore,
      fixtureIdentityAfter,
      fixtureIdentityRestored,
      reconciliation: extensionReconciliation,
      exactComparison: extensionComparison,
      targetProof: fixtureSurvival
    },
    failureAndRestoration: {
      mode: validated?.plan?.adapter?.failureProof ?? '',
      observedMidRunChangeCount: failureChanges.length,
      observedMidRunChanges: failureChanges,
      exactRestorationComparison: restorationComparison
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
