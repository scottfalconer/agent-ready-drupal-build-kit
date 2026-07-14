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
  assertDeclaredEmptyAdapters,
  cleanupDisposable,
  confirmDisposableDdevIdentity,
  createDisposableClone,
  createRecordedExecutor,
  exactHeadRuntimeBinding,
  loadValidatedReproductionInputs,
  provisioningSteps,
  safeProjectRelativePath
} from './disposable-ddev.mjs';
import {
  capturePortableDrupalState,
  comparePortableReproductionStates
} from './reproduction-state.mjs';
import { canonicalJson, collectFileManifest, sha256 } from './state-fingerprint.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPORT_SCHEMA = 'public-kit.reproduction-verification.1';
const DEFAULT_PLAN = 'reproduction-plan.json';
const DEFAULT_OUTPUT = 'review-packet/evidence/reproduction-verification.json';
const USAGE = `Usage: node <path-to-skill>/scripts/verify-reproduction.mjs [options]

Verifier-owned disposable Drupal reproduction for maintainer/launch evidence.

  --project <path>  Existing working Drupal/DDEV project (default: detect from cwd)
  --plan <path>     Exact-HEAD typed plan (default: reproduction-plan.json)
  --out <path>      Generated evidence under review-packet/evidence
  --help            Show this help
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
  const options = { out: DEFAULT_OUTPUT, plan: DEFAULT_PLAN, project: '' };
  const values = new Map([['--project', 'project'], ['--plan', 'plan'], ['--out', 'out']]);
  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { help: true };
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

function commandOutput(execute, command, args, options, { trim = true } = {}) {
  const result = execute(command, args, options);
  if (!result || result.status !== 0) {
    const detail = String(result?.stderr ?? result?.error?.message ?? '').trim().split(/\r?\n/)[0];
    throw new Error(`${options.phase} failed${detail ? `: ${detail}` : ''}`);
  }
  const output = String(result.stdout ?? '');
  return trim ? output.trim() : output;
}

function sourceSnapshot(execute, projectRoot, phase) {
  const head = commandOutput(execute, 'git', ['rev-parse', 'HEAD'], {
    cwd: projectRoot,
    phase: `${phase}:head`,
    target: 'working'
  });
  if (!/^[a-f0-9]{40}$/i.test(head)) throw new Error('Working target HEAD is not a full Git object ID.');
  const status = commandOutput(execute, 'git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    cwd: projectRoot,
    phase: `${phase}:status`,
    target: 'working'
  });
  const trackedDiff = commandOutput(execute, 'git', ['diff', '--binary', '--no-ext-diff', 'HEAD', '--'], {
    cwd: projectRoot,
    phase: `${phase}:tracked-worktree-bytes`,
    target: 'working'
  }, { trim: false });
  const untrackedOutput = commandOutput(execute, 'git', ['ls-files', '--others', '--exclude-standard', '-z'], {
    cwd: projectRoot,
    phase: `${phase}:untracked-paths`,
    target: 'working'
  }, { trim: false });
  const untrackedPaths = untrackedOutput.split('\0').filter(Boolean);
  const untrackedManifest = collectFileManifest(projectRoot, untrackedPaths);
  return {
    head: head.toLowerCase(),
    statusSha256: sha256(status),
    dirty: Boolean(status),
    trackedWorktreeSha256: sha256(trackedDiff),
    untrackedWorktree: {
      entryCount: untrackedManifest.entryCount,
      fingerprint: untrackedManifest.fingerprint
    },
    runtimeCode: exactHeadRuntimeBinding(projectRoot)
  };
}

function firstError(error) {
  return String(error?.message ?? error ?? 'Unknown error').trim().split(/\r?\n/)[0];
}

function confirmDisposableIdentity(execute, disposable) {
  confirmDisposableDdevIdentity({ disposable, execute });
}

function runStep(execute, disposable, step) {
  const result = execute(step.command, step.args, {
    cwd: disposable.root,
    phase: `provision:${step.adapter}`,
    target: 'disposable',
    timeout: step.timeout
  });
  if (!result || result.status !== 0) {
    const detail = String(result?.stderr ?? result?.error?.message ?? '').trim().split(/\r?\n/)[0];
    throw new Error(`Typed adapter ${step.adapter} failed${detail ? `: ${detail}` : ''}`);
  }
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
 * Execute one bounded reproduction run. Dependency injection is intentionally
 * narrow so tests can exercise orchestration without provisioning local DDEV.
 */
export function runDisposableReproduction({
  captureState = capturePortableDrupalState,
  cleanup = cleanupDisposable,
  execute,
  planPath = DEFAULT_PLAN,
  projectRoot,
  tempParent
}) {
  const checkedAt = new Date().toISOString();
  const commands = [];
  const run = execute ?? createRecordedExecutor({ commandLog: commands });
  const commandLog = execute?.commandLog ?? commands;
  const errors = [];
  let sourceBefore = null;
  let sourceAfter = null;
  let validated = null;
  let workingBefore = null;
  let workingAfter = null;
  let disposableState = null;
  let disposable = null;
  let ddevStartAttempted = false;
  let cleanupResult = { deletedDdevProject: false, removedClone: false };
  let reproductionComparison = emptyComparison();
  let workingTargetComparison = emptyComparison();
  let exactHeadClone = false;
  let completedRun = false;

  try {
    sourceBefore = sourceSnapshot(run, projectRoot, 'working-before');
    validated = loadValidatedReproductionInputs({ execute: run, planPath, projectRoot });
    workingBefore = captureState({
      execute: run,
      projectRoot,
      routes: validated.routes,
      target: 'working-before'
    });
    if (!workingBefore.confirmed || !workingBefore.configStatusClean) {
      throw new Error('Working target portable readback is not confirmed with clean active configuration.');
    }
    if (workingBefore.configSyncDirectory !== validated.plan.trackedConfig.path) {
      throw new Error(`Working target config sync directory does not match declared trackedConfig.path ${validated.plan.trackedConfig.path}.`);
    }
    assertDeclaredEmptyAdapters(validated.plan, workingBefore);
    disposable = createDisposableClone({
      execute: run,
      head: sourceBefore.head,
      projectRoot,
      ...(tempParent ? { tempParent } : {})
    });
    const disposableRun = (command, args, options = {}) => run(command, args, { ...options, target: 'disposable' });
    const cloned = loadValidatedReproductionInputs({
      execute: disposableRun,
      planPath: validated.planPath,
      projectRoot: disposable.root
    });
    const clonedRuntime = exactHeadRuntimeBinding(disposable.root);
    exactHeadClone = (
      sourceBefore.runtimeCode.fingerprint === clonedRuntime.fingerprint &&
      sha256(validated.plan) === sha256(cloned.plan) &&
      sha256(validated.inputs) === sha256(cloned.inputs) &&
      canonicalJson(validated.routes) === canonicalJson(cloned.routes)
    );
    if (!exactHeadClone) throw new Error('Disposable clone inputs or portable runtime code do not match exact working-target HEAD.');

    for (const step of provisioningSteps(validated.plan)) {
      if (step.adapter === 'ddev_start') ddevStartAttempted = true;
      runStep(run, disposable, step);
      if (step.adapter === 'ddev_start') confirmDisposableIdentity(run, disposable);
    }
    disposableState = captureState({
      execute: disposableRun,
      projectRoot: disposable.root,
      routes: validated.routes,
      target: 'disposable'
    });
    if (disposableState.configSyncDirectory !== validated.plan.trackedConfig.path) {
      throw new Error(`Disposable config sync directory does not match declared trackedConfig.path ${validated.plan.trackedConfig.path}.`);
    }
    reproductionComparison = comparePortableReproductionStates(workingBefore, disposableState);
    completedRun = true;
  } catch (error) {
    errors.push(firstError(error));
  } finally {
    if (disposable) {
      try {
        cleanupResult = cleanup({ ddevStartAttempted, disposable, execute: run });
      } catch (error) {
        errors.push(`Disposable cleanup failed: ${firstError(error)}`);
      }
    }
    try {
      if (sourceBefore && validated && workingBefore) {
        sourceAfter = sourceSnapshot(run, projectRoot, 'working-after');
        workingAfter = captureState({
          execute: run,
          projectRoot,
          routes: validated.routes,
          target: 'working-after'
        });
        workingTargetComparison = comparePortableReproductionStates(workingBefore, workingAfter);
      }
    } catch (error) {
      errors.push(`Working-target after-proof failed: ${firstError(error)}`);
    }
  }

  const sourceUnchanged = Boolean(sourceBefore && sourceAfter && (
    sourceBefore.head === sourceAfter.head &&
    sourceBefore.statusSha256 === sourceAfter.statusSha256 &&
    sourceBefore.trackedWorktreeSha256 === sourceAfter.trackedWorktreeSha256 &&
    sourceBefore.untrackedWorktree.fingerprint === sourceAfter.untrackedWorktree.fingerprint &&
    sourceBefore.runtimeCode.fingerprint === sourceAfter.runtimeCode.fingerprint
  ));
  const workingTargetUntouched = sourceUnchanged && workingTargetComparison.match;
  const cleanupComplete = Boolean(!disposable || cleanupResult.removedClone);
  const valid = (
    errors.length === 0 &&
    completedRun &&
    exactHeadClone &&
    reproductionComparison.match &&
    workingTargetUntouched &&
    cleanupComplete
  );
  return {
    schemaVersion: REPORT_SCHEMA,
    gateId: 'G-REPRO-01',
    checkedAt,
    valid,
    mode: validated?.plan?.mode ?? '',
    evidenceScope: {
      maintainerOrLaunchEvidence: true,
      authoritativeForDefaultHandoff: false,
      rationale: 'This separate verifier provisions an exact-HEAD disposable target; it does not alter the default local handoff verdict.'
    },
    runStatus: errors.length > 0 ? 'operational_failure' : completedRun ? (valid ? 'pass' : 'mismatch') : 'operational_failure',
    source: {
      head: sourceBefore?.head ?? '',
      planPath: validated?.planPath ?? safeProjectRelativePath(planPath, 'Reproduction plan path'),
      planSha256: validated ? sha256(validated.plan) : '',
      exactHeadClone,
      runtimeCodeFingerprint: sourceBefore?.runtimeCode?.fingerprint ?? ''
    },
    declaredInputs: validated?.inputs ?? [],
    declaredPrimaryRouteCount: validated?.routes?.length ?? 0,
    declaredPrimaryRoutes: validated?.routes ?? [],
    adapters: validated ? provisioningSteps(validated.plan).map((step) => step.adapter) : [],
    workingTargetProof: {
      untouched: workingTargetUntouched,
      sourceUnchanged,
      headBefore: sourceBefore?.head ?? '',
      headAfter: sourceAfter?.head ?? '',
      gitStatusBeforeSha256: sourceBefore?.statusSha256 ?? '',
      gitStatusAfterSha256: sourceAfter?.statusSha256 ?? '',
      trackedWorktreeBeforeSha256: sourceBefore?.trackedWorktreeSha256 ?? '',
      trackedWorktreeAfterSha256: sourceAfter?.trackedWorktreeSha256 ?? '',
      untrackedWorktreeBeforeFingerprint: sourceBefore?.untrackedWorktree?.fingerprint ?? '',
      untrackedWorktreeAfterFingerprint: sourceAfter?.untrackedWorktree?.fingerprint ?? '',
      runtimeCodeBeforeFingerprint: sourceBefore?.runtimeCode?.fingerprint ?? '',
      runtimeCodeAfterFingerprint: sourceAfter?.runtimeCode?.fingerprint ?? '',
      stateComparison: workingTargetComparison
    },
    disposable: {
      projectName: disposable?.name ?? '',
      ownershipNamespaceConfirmed: Boolean(disposable?.name?.startsWith('agent-ready-repro-')),
      cleanup: cleanupResult
    },
    reproductionComparison,
    readback: {
      workingBefore,
      disposable: disposableState,
      workingAfter
    },
    commands: commandLog,
    errors
  };
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function safeEvidenceOutput(projectRoot, value) {
  const relativePath = safeProjectRelativePath(value, 'Reproduction evidence output');
  if (!relativePath.startsWith('review-packet/evidence/')) {
    throw new Error('Reproduction evidence output must be under review-packet/evidence/.');
  }
  const path = resolve(projectRoot, relativePath);
  if (!isInside(projectRoot, path)) throw new Error('Reproduction evidence output escaped the project root.');
  let current = dirname(path);
  while (current !== projectRoot) {
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
      throw new Error('Reproduction evidence output must not traverse a symbolic link.');
    }
    current = dirname(current);
  }
  if (existsSync(path) && (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile())) {
    throw new Error('Reproduction evidence output must be a regular non-symlink file.');
  }
  return { path, relativePath };
}

export function writeReproductionEvidence(projectRoot, output, report) {
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
  const report = runDisposableReproduction({ execute, planPath: args.plan, projectRoot });
  const output = writeReproductionEvidence(projectRoot, args.out, report);
  if (!report.valid) {
    process.stderr.write(`Disposable reproduction failed closed. Report: ${output}\n`);
    for (const error of report.errors) process.stderr.write(`- ${error}\n`);
    process.exitCode = report.runStatus === 'operational_failure' ? 1 : 2;
    return;
  }
  process.stdout.write(`Disposable reproduction matched the working target and left it unchanged. Report: ${output}\n`);
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
