import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import {
  collectFileManifest,
  collectRuntimeCodeManifest,
  sha256
} from './state-fingerprint.mjs';

export const REPRODUCTION_PLAN_SCHEMA = 'public-kit.reproduction-plan.1';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const DATABASE_ARCHIVE_RE = /\.(?:sql|mysql)(?:\.(?:gz|bz2|xz))?$|\.(?:zip|tgz|tar\.gz)$/i;
const FILE_ARCHIVE_RE = /\.(?:zip|tgz|tar|tar\.gz|tar\.bz2|tar\.xz)$/i;
const OWNERSHIP_MARKER = '.agent-ready-disposable-owner.json';
const MAX_REPRODUCTION_ROUTES = 256;

function comparePortable(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function normalizedHash(value, label) {
  const text = String(value ?? '').trim().toLowerCase();
  const digest = /^[a-f0-9]{64}$/.test(text) ? `sha256:${text}` : text;
  if (!HASH_RE.test(digest)) throw new Error(`${label} must be a SHA-256 digest.`);
  return digest;
}

export function safeProjectRelativePath(value, label = 'Path') {
  const path = String(value ?? '').trim().replaceAll('\\', '/').replace(/^\.\//, '');
  if (
    !path || path === '.' || isAbsolute(path) || path.startsWith('/') || /^[a-z]:\//i.test(path) ||
    path.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`${label} must be a non-empty project-relative path without traversal.`);
  }
  return path;
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function assertNoSymlinkPath(projectRoot, path, label) {
  let current = path;
  while (current !== projectRoot) {
    if (!existsSync(current)) throw new Error(`${label} is missing.`);
    if (lstatSync(current).isSymbolicLink()) throw new Error(`${label} must not traverse a symbolic link.`);
    const parent = resolve(current, '..');
    if (!isInside(projectRoot, parent)) throw new Error(`${label} escaped the project root.`);
    current = parent;
  }
}

function assertExactKeys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new Error(`${label} contains unsupported field(s): ${unknown.sort(comparePortable).join(', ')}.`);
}

function boundSource(value, label) {
  assertExactKeys(value, ['path', 'sha256'], label);
  return {
    path: safeProjectRelativePath(value.path, `${label}.path`),
    sha256: normalizedHash(value.sha256, `${label}.sha256`)
  };
}

function exactInteger(value, expected, label) {
  if (value !== expected) throw new Error(`${label} must be exactly ${expected}.`);
  return expected;
}

/** Parse a plan without accepting command strings or arbitrary argv. */
export function parseReproductionPlan(value) {
  assertExactKeys(value, [
    'schemaVersion', 'mode', 'dependencies', 'trackedConfig', 'databaseSnapshot', 'content', 'files'
  ], 'Reproduction plan');
  if (value.schemaVersion !== REPRODUCTION_PLAN_SCHEMA) {
    throw new Error(`Reproduction plan schemaVersion must be ${REPRODUCTION_PLAN_SCHEMA}.`);
  }
  const mode = String(value.mode ?? '').trim();
  if (!['clean_install_config_import', 'snapshot_restore'].includes(mode)) {
    throw new Error('Reproduction plan mode must be clean_install_config_import or snapshot_restore.');
  }

  assertExactKeys(value.dependencies, ['adapter', 'lockFile'], 'Reproduction plan dependencies');
  if (value.dependencies.adapter !== 'ddev_composer_install') {
    throw new Error('Reproduction plan dependencies.adapter must be ddev_composer_install.');
  }
  const lockFile = boundSource(value.dependencies.lockFile, 'Reproduction plan dependencies.lockFile');
  if (lockFile.path !== 'composer.lock') throw new Error('The dependency lock input must be composer.lock.');
  const trackedConfig = boundSource(value.trackedConfig, 'Reproduction plan trackedConfig');

  assertExactKeys(value.content, ['adapter', 'source', 'expectedEntityCount'], 'Reproduction plan content');
  const contentAdapter = String(value.content.adapter ?? '').trim();
  let content;
  if (mode === 'snapshot_restore') {
    if (contentAdapter !== 'database_snapshot') {
      throw new Error('snapshot_restore content.adapter must be database_snapshot.');
    }
    if (Object.hasOwn(value.content, 'source') || Object.hasOwn(value.content, 'expectedEntityCount')) {
      throw new Error('database_snapshot content does not accept source or expectedEntityCount fields.');
    }
    content = { adapter: contentAdapter };
  } else if (contentAdapter === 'drush_php_script') {
    if (Object.hasOwn(value.content, 'expectedEntityCount')) {
      throw new Error('drush_php_script content does not accept expectedEntityCount.');
    }
    content = { adapter: contentAdapter, source: boundSource(value.content.source, 'Reproduction plan content.source') };
    if (!content.source.path.endsWith('.php')) throw new Error('drush_php_script content source must be a .php file.');
  } else if (contentAdapter === 'none') {
    if (Object.hasOwn(value.content, 'source')) throw new Error('none content does not accept a source.');
    content = {
      adapter: contentAdapter,
      expectedEntityCount: exactInteger(value.content.expectedEntityCount, 0, 'Reproduction plan content.expectedEntityCount')
    };
  } else {
    throw new Error('clean_install_config_import content.adapter must be drush_php_script or none.');
  }

  assertExactKeys(value.files, ['adapter', 'source', 'expectedManagedFileCount'], 'Reproduction plan files');
  const filesAdapter = String(value.files.adapter ?? '').trim();
  let files;
  if (filesAdapter === 'ddev_import_files_archive') {
    if (Object.hasOwn(value.files, 'expectedManagedFileCount')) {
      throw new Error('ddev_import_files_archive files do not accept expectedManagedFileCount.');
    }
    files = { adapter: filesAdapter, source: boundSource(value.files.source, 'Reproduction plan files.source') };
    if (!FILE_ARCHIVE_RE.test(files.source.path)) throw new Error('The files source must be a supported DDEV archive.');
  } else if (filesAdapter === 'none') {
    if (Object.hasOwn(value.files, 'source')) throw new Error('none files do not accept a source.');
    files = {
      adapter: filesAdapter,
      expectedManagedFileCount: exactInteger(value.files.expectedManagedFileCount, 0, 'Reproduction plan files.expectedManagedFileCount')
    };
  } else {
    throw new Error('Reproduction plan files.adapter must be ddev_import_files_archive or none.');
  }

  let databaseSnapshot = null;
  if (mode === 'snapshot_restore') {
    assertExactKeys(value.databaseSnapshot, ['adapter', 'source'], 'Reproduction plan databaseSnapshot');
    if (value.databaseSnapshot.adapter !== 'ddev_import_db_archive') {
      throw new Error('Reproduction plan databaseSnapshot.adapter must be ddev_import_db_archive.');
    }
    databaseSnapshot = {
      adapter: value.databaseSnapshot.adapter,
      source: boundSource(value.databaseSnapshot.source, 'Reproduction plan databaseSnapshot.source')
    };
    if (!DATABASE_ARCHIVE_RE.test(databaseSnapshot.source.path)) {
      throw new Error('The database snapshot source must be a supported DDEV SQL archive.');
    }
  } else if (Object.hasOwn(value, 'databaseSnapshot')) {
    throw new Error('clean_install_config_import must not declare databaseSnapshot.');
  }
  return {
    schemaVersion: REPRODUCTION_PLAN_SCHEMA,
    mode,
    dependencies: { adapter: value.dependencies.adapter, lockFile },
    trackedConfig,
    databaseSnapshot,
    content,
    files
  };
}

function machineLocalInputPath(path) {
  return (
    /(^|\/)\.env(?:\.|$)/.test(path) ||
    /^\.ddev\/(?:config\.local\.ya?ml|\.env(?:\.|$))/.test(path) ||
    /(^|\/)(?:settings|services)\.local\.(?:php|ya?ml)$/.test(path) ||
    /^(?:web|docroot)\/sites\/[^/]+\/(?:files|private)(?:\/|$)/.test(path) ||
    /^review-packet\/evidence(?:\/|$)/.test(path)
  );
}

function checkedResult(execute, command, args, options, label) {
  const result = execute(command, args, options);
  if (!result || result.status !== 0) {
    const detail = String(result?.stderr ?? result?.error?.message ?? '').trim().split(/\r?\n/)[0];
    throw new Error(`${label}${detail ? `: ${detail}` : ''}`);
  }
  return result;
}

function gitTrackedPaths(execute, projectRoot, path) {
  const result = checkedResult(execute, 'git', ['ls-files', '--', path], {
    cwd: projectRoot,
    phase: `git-track-check:${path}`,
    target: 'working'
  }, `Git could not inspect tracked input ${path}`);
  return String(result.stdout ?? '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean).sort(comparePortable);
}

function assertHeadExact(execute, projectRoot, path) {
  const result = execute('git', ['diff', '--quiet', 'HEAD', '--', path], {
    cwd: projectRoot,
    phase: `git-head-check:${path}`,
    target: 'working'
  });
  if (result?.status === 1) throw new Error(`Required input ${path} differs from exact Git HEAD.`);
  if (!result || result.status !== 0) throw new Error(`Git could not compare required input ${path} to HEAD.`);
}

function validateBoundInput({ execute, expectedKind, label, projectRoot, source }) {
  if (machineLocalInputPath(source.path)) throw new Error(`${label} must not use a machine-local input path: ${source.path}.`);
  const path = resolve(projectRoot, source.path);
  if (!isInside(projectRoot, path)) throw new Error(`${label} escaped the project root.`);
  assertNoSymlinkPath(projectRoot, path, label);
  const metadata = lstatSync(path);
  const trackedPaths = gitTrackedPaths(execute, projectRoot, source.path);
  if (trackedPaths.length === 0) throw new Error(`${label} must be checked into Git at exact HEAD.`);
  assertHeadExact(execute, projectRoot, source.path);
  if (expectedKind === 'directory') {
    if (!metadata.isDirectory()) throw new Error(`${label} must be a directory.`);
    const manifest = collectFileManifest(projectRoot, [source.path]);
    if (manifest.entryCount === 0) throw new Error(`${label} must contain at least one file.`);
    const manifestPaths = manifest.entries.map((entry) => entry.path);
    if (manifestPaths.some((entry) => !trackedPaths.includes(entry)) || trackedPaths.some((entry) => !manifestPaths.includes(entry))) {
      throw new Error(`${label} must contain only present Git-tracked files from exact HEAD.`);
    }
    if (!manifest.entries.some((entry) => /\.ya?ml$/i.test(entry.path))) {
      throw new Error(`${label} must contain tracked YAML configuration.`);
    }
    if (manifest.fingerprint !== source.sha256) throw new Error(`${label} digest does not match declared SHA-256.`);
    return {
      label,
      kind: 'directory-manifest',
      path: source.path,
      declaredSha256: source.sha256,
      actualSha256: manifest.fingerprint,
      entryCount: manifest.entryCount
    };
  }
  if (!metadata.isFile()) throw new Error(`${label} must be a regular file.`);
  if (trackedPaths.length !== 1 || trackedPaths[0] !== source.path) {
    throw new Error(`${label} must name one exact Git-tracked file.`);
  }
  const bytes = readFileSync(path);
  const actualSha256 = sha256(bytes);
  if (actualSha256 !== source.sha256) throw new Error(`${label} digest does not match declared SHA-256.`);
  return {
    label,
    kind: 'file',
    path: source.path,
    declaredSha256: source.sha256,
    actualSha256,
    size: bytes.length
  };
}

function parseBoundJson({ execute, path, projectRoot, schemaVersion }) {
  const source = { path, sha256: sha256(readFileSync(resolve(projectRoot, path))) };
  const input = validateBoundInput({ execute, expectedKind: 'file', label: path, projectRoot, source });
  let value;
  try {
    value = JSON.parse(readFileSync(resolve(projectRoot, path), 'utf8'));
  } catch {
    throw new Error(`${path} must contain valid JSON.`);
  }
  if (schemaVersion && value?.schemaVersion !== schemaVersion) {
    throw new Error(`${path} must use schemaVersion ${schemaVersion}.`);
  }
  return { input, value };
}

function normalizedRoutePath(value, label) {
  const text = String(value ?? '').trim();
  if (!text.startsWith('/')) throw new Error(`${label} must be a target-relative path.`);
  const url = new URL(text, 'https://agent-ready.invalid/');
  if (url.origin !== 'https://agent-ready.invalid') throw new Error(`${label} must stay on the target origin.`);
  url.hash = '';
  return `${url.pathname}${url.search}`;
}

export function reproductionRoutePaths(routeMatrix) {
  const paths = new Set();
  const primary = (Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : [])
    .filter((row) => String(row?.targetPath ?? '').trim());
  if (primary.length === 0) throw new Error('route-matrix.json must declare at least one primary route.');
  for (const [index, row] of primary.entries()) {
    if (row.accepted !== true) throw new Error(`route-matrix.json primaryRoutes[${index}] is not accepted.`);
    paths.add(normalizedRoutePath(row.targetPath, `route-matrix.json primaryRoutes[${index}].targetPath`));
  }
  for (const [index, row] of (Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : []).entries()) {
    if (row?.accepted === true && String(row?.targetPath ?? '').trim()) {
      paths.add(normalizedRoutePath(row.targetPath, `route-matrix.json routes[${index}].targetPath`));
    }
  }
  for (const [index, row] of (Array.isArray(routeMatrix?.targetRequiredRoutes) ? routeMatrix.targetRequiredRoutes : []).entries()) {
    if (
      row?.accepted === true &&
      ['public_200', 'redirect', 'noindex'].includes(String(row?.expectedPublicBehavior ?? '')) &&
      String(row?.targetPath ?? '').trim()
    ) {
      paths.add(normalizedRoutePath(row.targetPath, `route-matrix.json targetRequiredRoutes[${index}].targetPath`));
    }
  }
  const result = [...paths].sort(comparePortable);
  if (result.length > MAX_REPRODUCTION_ROUTES) {
    throw new Error(`Disposable reproduction is bounded to ${MAX_REPRODUCTION_ROUTES} declared public routes.`);
  }
  return result;
}

/** Validate the exact-HEAD plan, route matrix, and every digest-bound input. */
export function loadValidatedReproductionInputs({ execute, planPath = 'reproduction-plan.json', projectRoot }) {
  const root = realpathSync(resolve(projectRoot));
  const normalizedPlanPath = safeProjectRelativePath(planPath, 'Reproduction plan path');
  const { input: planInput, value: rawPlan } = parseBoundJson({
    execute,
    path: normalizedPlanPath,
    projectRoot: root,
    schemaVersion: REPRODUCTION_PLAN_SCHEMA
  });
  const plan = parseReproductionPlan(rawPlan);
  const evidence = [planInput];
  evidence.push(validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Composer lock input',
    projectRoot: root,
    source: plan.dependencies.lockFile
  }));
  evidence.push(validateBoundInput({
    execute,
    expectedKind: 'directory',
    label: 'Tracked config input',
    projectRoot: root,
    source: plan.trackedConfig
  }));
  if (plan.databaseSnapshot) evidence.push(validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Database snapshot input',
    projectRoot: root,
    source: plan.databaseSnapshot.source
  }));
  if (plan.content.source) evidence.push(validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Content import input',
    projectRoot: root,
    source: plan.content.source
  }));
  if (plan.files.source) evidence.push(validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Files archive input',
    projectRoot: root,
    source: plan.files.source
  }));
  const { input: routeMatrixInput, value: routeMatrix } = parseBoundJson({
    execute,
    path: 'review-packet/route-matrix.json',
    projectRoot: root,
    schemaVersion: 'public-kit.route-matrix.1'
  });
  evidence.push({ ...routeMatrixInput, label: 'Primary anonymous route contract' });
  return {
    plan,
    planPath: normalizedPlanPath,
    routes: reproductionRoutePaths(routeMatrix),
    inputs: evidence
  };
}

/** Fixed adapter registry. No plan field is interpolated as a command string. */
export function provisioningSteps(plan) {
  const steps = [
    { adapter: 'ddev_start', command: 'ddev', args: ['start'], timeout: 300_000 },
    {
      adapter: plan.dependencies.adapter,
      command: 'ddev',
      args: ['composer', 'install', '--no-interaction', '--no-progress', '--prefer-dist'],
      timeout: 600_000
    }
  ];
  if (plan.mode === 'snapshot_restore') {
    steps.push({
      adapter: plan.databaseSnapshot.adapter,
      command: 'ddev',
      args: ['import-db', `--file=${plan.databaseSnapshot.source.path}`, '--no-progress'],
      timeout: 600_000
    });
  } else {
    steps.push({
      adapter: 'drush_site_install_existing_config',
      command: 'ddev',
      args: ['drush', 'site:install', '--existing-config', '--yes'],
      timeout: 600_000
    });
  }
  if (plan.files.adapter === 'ddev_import_files_archive') {
    steps.push({
      adapter: plan.files.adapter,
      command: 'ddev',
      args: ['import-files', `--source=${plan.files.source.path}`],
      timeout: 600_000
    });
  }
  if (plan.content.adapter === 'drush_php_script') {
    steps.push({
      adapter: plan.content.adapter,
      command: 'ddev',
      args: ['drush', 'php:script', plan.content.source.path],
      timeout: 600_000
    });
  }
  steps.push(
    {
      adapter: 'drush_config_import',
      command: 'ddev',
      args: ['drush', 'config:import', '--yes'],
      timeout: 300_000
    },
    {
      adapter: 'drush_cache_rebuild',
      command: 'ddev',
      args: ['drush', 'cache:rebuild'],
      timeout: 300_000
    }
  );
  return steps;
}

export function createRecordedExecutor({ commandLog, environment = process.env, spawn = spawnSync }) {
  if (!Array.isArray(commandLog)) throw new Error('commandLog must be an array.');
  const execute = (command, args, options = {}) => {
    const startedAt = new Date().toISOString();
    const started = Date.now();
    const result = spawn(command, args, {
      cwd: options.cwd,
      encoding: 'utf8',
      env: environment,
      input: options.input,
      maxBuffer: 64 * 1024 * 1024,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: options.timeout ?? 60_000
    });
    const stdout = String(result.stdout ?? '');
    const stderr = String(result.stderr ?? '');
    commandLog.push({
      sequence: commandLog.length + 1,
      phase: String(options.phase ?? 'command'),
      target: String(options.target ?? 'verifier'),
      cwd: String(options.recordedCwd ?? options.target ?? 'verifier'),
      argv: [command, ...(options.recordedArgs ?? args)].map(String),
      startedAt,
      durationMs: Date.now() - started,
      exitStatus: Number.isInteger(result.status) ? result.status : null,
      signal: result.signal ? String(result.signal) : '',
      stdoutSha256: sha256(stdout),
      stderrSha256: sha256(stderr),
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr)
    });
    return { ...result, stdout, stderr };
  };
  execute.commandLog = commandLog;
  return execute;
}

function requiredCommand(execute, command, args, options) {
  return checkedResult(execute, command, args, options, `${options.phase} failed`);
}

function ddevName(head) {
  return `agent-ready-repro-${head.slice(0, 8)}-${randomUUID().slice(0, 8)}`;
}

/** Create an independent exact-HEAD clone and a machine-local DDEV identity. */
export function createDisposableClone({ execute, head, projectRoot, tempParent = tmpdir() }) {
  const root = mkdtempSync(join(tempParent, 'agent-ready-drupal-reproduction-'));
  const token = randomUUID();
  const name = ddevName(head);
  try {
    requiredCommand(execute, 'git', ['clone', '--no-local', '--no-checkout', '--quiet', '--', projectRoot, root], {
      cwd: tempParent,
      phase: 'clone-exact-head',
      target: 'disposable',
      recordedArgs: ['clone', '--no-local', '--no-checkout', '--quiet', '--', '<working-target>', '<disposable-target>']
    });
    requiredCommand(execute, 'git', ['checkout', '--detach', '--quiet', head], {
      cwd: root,
      phase: 'checkout-exact-head',
      target: 'disposable'
    });
    const ddevDirectory = resolve(root, '.ddev');
    if (!existsSync(ddevDirectory) || !lstatSync(ddevDirectory).isDirectory() || lstatSync(ddevDirectory).isSymbolicLink()) {
      throw new Error('Exact HEAD does not contain a regular .ddev directory.');
    }
    const localConfig = join(ddevDirectory, 'config.local.yaml');
    if (existsSync(localConfig)) throw new Error('Disposable clone unexpectedly contains .ddev/config.local.yaml.');
    writeFileSync(localConfig, `# Verifier-owned machine-local identity.\nname: ${name}\n`, { flag: 'wx', mode: 0o600 });
    writeFileSync(join(root, OWNERSHIP_MARKER), `${JSON.stringify({ name, token }, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    return { name, root, token };
  } catch (error) {
    rmSync(root, { force: true, recursive: true });
    throw error;
  }
}

export function assertDisposableOwnership(disposable) {
  const root = resolve(disposable?.root ?? '');
  if (!root || !existsSync(root) || lstatSync(root).isSymbolicLink() || !lstatSync(root).isDirectory()) {
    throw new Error('Disposable cleanup root is missing or unsafe.');
  }
  const markerPath = join(root, OWNERSHIP_MARKER);
  assertNoSymlinkPath(root, markerPath, 'Disposable ownership marker');
  let marker;
  try {
    marker = JSON.parse(readFileSync(markerPath, 'utf8'));
  } catch {
    throw new Error('Disposable ownership marker is invalid.');
  }
  if (marker?.token !== disposable.token || marker?.name !== disposable.name) {
    throw new Error('Disposable ownership marker does not match this verifier run.');
  }
  if (!/^agent-ready-repro-[a-f0-9]{8}-[a-f0-9]{8}$/.test(disposable.name)) {
    throw new Error('Disposable DDEV name is outside the verifier-owned namespace.');
  }
  return root;
}

function descriptionHasName(value, expected) {
  if (!value || typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value)) {
    if (['name', 'project_name', 'projectName'].includes(key) && String(child) === expected) return true;
    if (descriptionHasName(child, expected)) return true;
  }
  return false;
}

/** Confirm that DDEV resolves this owned clone to the verifier-generated project name. */
export function confirmDisposableDdevIdentity({ disposable, execute, phase = 'confirm-disposable-ddev-identity' }) {
  const root = assertDisposableOwnership(disposable);
  const output = requiredCommand(execute, 'ddev', ['describe', '-j'], {
    cwd: root,
    phase,
    target: 'disposable',
    timeout: 20_000
  }).stdout;
  let description;
  try {
    description = JSON.parse(output);
  } catch {
    throw new Error('Disposable DDEV description returned invalid JSON.');
  }
  if (!descriptionHasName(description, disposable.name)) {
    throw new Error('DDEV did not confirm the verifier-owned disposable project identity.');
  }
}

/** Delete only the UUID-owned DDEV project, then remove only its temp clone. */
export function cleanupDisposable({ ddevStartAttempted, disposable, execute }) {
  const root = assertDisposableOwnership(disposable);
  if (ddevStartAttempted) {
    // A failed or partial `ddev start` can register a different project under
    // the generated name. Re-confirm the live DDEV identity immediately before
    // deletion; on failure this throws before either the project or clone is
    // removed, leaving the owned target available for manual inspection.
    confirmDisposableDdevIdentity({
      disposable,
      execute,
      phase: 'confirm-disposable-ddev-identity-before-delete'
    });
    requiredCommand(execute, 'ddev', ['delete', '--omit-snapshot', '--yes', disposable.name], {
      cwd: root,
      phase: 'delete-owned-disposable-ddev',
      target: 'disposable'
    });
  }
  rmSync(root, { force: true, recursive: true });
  return { deletedDdevProject: ddevStartAttempted, removedClone: true };
}

export function exactHeadRuntimeBinding(projectRoot) {
  const manifest = collectRuntimeCodeManifest(projectRoot);
  return {
    schemaVersion: manifest.schemaVersion,
    entryCount: manifest.entryCount,
    fingerprint: manifest.fingerprint
  };
}

export function assertDeclaredEmptyAdapters(plan, workingState) {
  if (plan.content.adapter === 'none' && workingState.entities.count !== plan.content.expectedEntityCount) {
    throw new Error(`content.adapter none requires exactly 0 portable entities; working target has ${workingState.entities.count}.`);
  }
  if (plan.files.adapter === 'none' && workingState.managedFiles.count !== plan.files.expectedManagedFileCount) {
    throw new Error(`files.adapter none requires exactly 0 managed files; working target has ${workingState.managedFiles.count}.`);
  }
}
