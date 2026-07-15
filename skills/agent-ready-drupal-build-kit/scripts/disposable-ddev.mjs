import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

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
const MAX_DDEV_CONFIG_BYTES = 1024 * 1024;
const SOURCE_DDEV_ROOT_FIELDS = new Set([
  'additional_fqdns',
  'additional_hostnames',
  'composer_version',
  'corepack_enable',
  'database',
  'docroot',
  'name',
  'php_version',
  'type',
  'use_dns_when_possible',
  'web_environment',
  'webserver_type',
  'xdebug_enabled'
]);

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

function sourceDdevConfigFile(projectRoot) {
  const ddevRoot = resolve(projectRoot, '.ddev');
  if (!existsSync(ddevRoot) || lstatSync(ddevRoot).isSymbolicLink() || !lstatSync(ddevRoot).isDirectory()) {
    throw new Error('Exact HEAD must contain a regular .ddev directory.');
  }
  const entries = readdirSync(ddevRoot, { withFileTypes: true })
    .sort((left, right) => comparePortable(left.name, right.name));
  if (entries.length !== 1 || entries[0].name !== 'config.yaml') {
    const extras = entries.filter((entry) => entry.name !== 'config.yaml').map((entry) => `.ddev/${entry.name}`);
    throw new Error(
      extras.length > 0
        ? `Disposable DDEV verification rejects every project .ddev file or directory except .ddev/config.yaml: ${extras.join(', ')}.`
        : 'Exact HEAD must contain only a regular .ddev/config.yaml.'
    );
  }
  const configPath = join(ddevRoot, 'config.yaml');
  const metadata = lstatSync(configPath);
  if (entries[0].isSymbolicLink() || metadata.isSymbolicLink() || !metadata.isFile() || (metadata.mode & 0o111) !== 0) {
    throw new Error('Exact HEAD must contain a regular non-symlink, non-executable .ddev/config.yaml.');
  }
  if (metadata.size > MAX_DDEV_CONFIG_BYTES) {
    throw new Error(`Exact HEAD .ddev/config.yaml exceeds ${MAX_DDEV_CONFIG_BYTES} bytes.`);
  }
  return { ddevRoot, path: configPath };
}

function restrictedYamlScalar(raw, label) {
  const text = String(raw ?? '').trim();
  let match = text.match(/^"([^"\\]*)"\s*(?:#.*)?$/);
  if (match) return match[1];
  match = text.match(/^'([^']*)'\s*(?:#.*)?$/);
  if (match) return match[1];
  match = text.match(/^([^#\r\n]*?)\s*(?:#.*)?$/);
  const value = String(match?.[1] ?? '').trim();
  if (!value || /["'\\\[\]{}&*!|>@`]/.test(value)) {
    throw new Error(`${label} must use one bounded plain or simply quoted scalar.`);
  }
  return value;
}

function restrictedYamlBoolean(raw, label) {
  const value = restrictedYamlScalar(raw, label).toLowerCase();
  if (!['true', 'false'].includes(value)) throw new Error(`${label} must be true or false.`);
  return value === 'true';
}

function restrictedYamlEmptyList(raw, label) {
  if (!/^\[\]\s*(?:#.*)?$/.test(String(raw ?? '').trim())) {
    throw new Error(`${label} must be an explicit empty list.`);
  }
  return [];
}

function safeDdevDocroot(projectRoot, value) {
  const docroot = safeProjectRelativePath(value, 'DDEV docroot');
  const path = resolve(projectRoot, docroot);
  if (!isInside(projectRoot, path)) throw new Error('DDEV docroot escaped the exact-HEAD project root.');
  assertNoSymlinkPath(projectRoot, path, 'DDEV docroot');
  const metadata = lstatSync(path);
  if (!metadata.isDirectory()) throw new Error('DDEV docroot must be a regular project directory.');
  return docroot;
}

function sourceDdevRuntimeFacts(projectRoot, text) {
  if (text.includes('\u0000') || /\\(?:u[0-9a-f]{4}|x[0-9a-f]{2})/i.test(text)) {
    throw new Error('Exact HEAD .ddev/config.yaml must not contain escaped or control key material.');
  }
  const values = new Map();
  const database = new Map();
  let section = '';
  for (const [index, line] of String(text).replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (line.includes('\t')) throw new Error(`Exact HEAD .ddev/config.yaml line ${index + 1} must not contain tabs.`);
    if (/^\s/.test(line)) {
      if (section !== 'database') {
        throw new Error(`Exact HEAD .ddev/config.yaml line ${index + 1} contains unsupported nested configuration.`);
      }
      const child = line.match(/^ {2,4}([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
      if (!child || !['type', 'version'].includes(child[1])) {
        throw new Error(`Exact HEAD .ddev/config.yaml database accepts only type and version.`);
      }
      if (database.has(child[1])) throw new Error(`Exact HEAD .ddev/config.yaml contains duplicate database.${child[1]}.`);
      database.set(child[1], restrictedYamlScalar(child[2], `DDEV database.${child[1]}`));
      continue;
    }
    const root = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/);
    if (!root) throw new Error(`Exact HEAD .ddev/config.yaml line ${index + 1} uses unsupported YAML syntax.`);
    const [, key, raw] = root;
    if (!SOURCE_DDEV_ROOT_FIELDS.has(key)) {
      throw new Error(`Exact HEAD .ddev/config.yaml contains unsupported field ${key}.`);
    }
    if (values.has(key)) throw new Error(`Exact HEAD .ddev/config.yaml contains duplicate field ${key}.`);
    values.set(key, raw);
    section = key;
    if (key === 'database') {
      if (!/^\s*(?:#.*)?$/.test(raw)) throw new Error('DDEV database must be a nested type/version mapping.');
      continue;
    }
    if (key === 'web_environment') restrictedYamlEmptyList(raw, 'DDEV web_environment');
    section = '';
  }

  const sourceName = restrictedYamlScalar(values.get('name'), 'DDEV name');
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(sourceName)) throw new Error('DDEV name must use a bounded portable project name.');
  const type = restrictedYamlScalar(values.get('type'), 'DDEV type');
  if (!/^drupal(?:9|10|11|12)?$/.test(type)) throw new Error('DDEV type must be a supported Drupal project type.');
  const docroot = safeDdevDocroot(projectRoot, restrictedYamlScalar(values.get('docroot'), 'DDEV docroot'));
  const phpVersion = values.has('php_version') ? restrictedYamlScalar(values.get('php_version'), 'DDEV php_version') : '';
  if (phpVersion && !/^8\.[1-5]$/.test(phpVersion)) throw new Error('DDEV php_version must be an allowed PHP 8 minor version.');
  const webserverType = values.has('webserver_type')
    ? restrictedYamlScalar(values.get('webserver_type'), 'DDEV webserver_type')
    : '';
  if (webserverType && !['apache-fpm', 'nginx-fpm'].includes(webserverType)) {
    throw new Error('DDEV webserver_type must be apache-fpm or nginx-fpm.');
  }
  if (values.has('xdebug_enabled')) restrictedYamlBoolean(values.get('xdebug_enabled'), 'DDEV xdebug_enabled');
  if (values.has('additional_hostnames')) restrictedYamlEmptyList(values.get('additional_hostnames'), 'DDEV additional_hostnames');
  if (values.has('additional_fqdns')) restrictedYamlEmptyList(values.get('additional_fqdns'), 'DDEV additional_fqdns');
  if (values.has('use_dns_when_possible')) restrictedYamlBoolean(values.get('use_dns_when_possible'), 'DDEV use_dns_when_possible');
  if (values.has('corepack_enable')) restrictedYamlBoolean(values.get('corepack_enable'), 'DDEV corepack_enable');
  if (values.has('composer_version') && restrictedYamlScalar(values.get('composer_version'), 'DDEV composer_version') !== '2') {
    throw new Error('DDEV composer_version must use the default major version 2.');
  }
  if (values.has('web_environment')) restrictedYamlEmptyList(values.get('web_environment'), 'DDEV web_environment');

  const databaseType = database.has('type') ? database.get('type') : '';
  const databaseVersion = database.has('version') ? database.get('version') : '';
  if (values.has('database') && (!databaseType || !databaseVersion)) {
    throw new Error('DDEV database must declare both type and version.');
  }
  if (databaseType && !['mariadb', 'mysql', 'postgres'].includes(databaseType)) {
    throw new Error('DDEV database.type must be mariadb, mysql, or postgres.');
  }
  if (databaseVersion && !/^\d+(?:\.\d+){0,2}$/.test(databaseVersion)) {
    throw new Error('DDEV database.version must be a numeric version.');
  }
  return { databaseType, databaseVersion, docroot, phpVersion, type, webserverType };
}

/**
 * Project DDEV configuration is data, never an execution boundary. Accept one
 * bounded config.yaml, project only strict typed runtime facts, and reject every
 * extra .ddev file/directory before replacing the directory wholesale.
 */
export function assertSafeDisposableDdevConfig(projectRoot) {
  const config = sourceDdevConfigFile(projectRoot);
  const bytes = readFileSync(config.path);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('Exact HEAD .ddev/config.yaml must be valid UTF-8.');
  }
  const facts = sourceDdevRuntimeFacts(projectRoot, text);
  return {
    checkedFileCount: 1,
    facts,
    fingerprint: sha256([{ path: '.ddev/config.yaml', sha256: sha256(bytes) }])
  };
}

function establishVerifierOwnedDdevConfig(projectRoot, name, facts) {
  const ddevRoot = resolve(projectRoot, '.ddev');
  rmSync(ddevRoot, { force: false, recursive: true });
  mkdirSync(ddevRoot, { mode: 0o700 });
  const lines = [
    '# Verifier-owned minimal DDEV runtime; project .ddev files are not executed.',
    `name: ${JSON.stringify(name)}`,
    `type: ${JSON.stringify(facts.type)}`,
    `docroot: ${JSON.stringify(facts.docroot)}`,
    'project_tld: "ddev.site"',
    'xdebug_enabled: false'
  ];
  if (facts.phpVersion) lines.push(`php_version: ${JSON.stringify(facts.phpVersion)}`);
  if (facts.webserverType) lines.push(`webserver_type: ${JSON.stringify(facts.webserverType)}`);
  if (facts.databaseType && facts.databaseVersion) {
    lines.push('database:');
    lines.push(`  type: ${JSON.stringify(facts.databaseType)}`);
    lines.push(`  version: ${JSON.stringify(facts.databaseVersion)}`);
  }
  const contents = `${lines.join('\n')}\n`;
  writeFileSync(join(ddevRoot, 'config.yaml'), contents, { flag: 'wx', mode: 0o600 });
  return { configSha256: sha256(contents), factsSha256: sha256(facts) };
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

export function validateBoundInput({ execute, expectedKind, label, projectRoot, source }) {
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
    let commandEnvironment = environment;
    if (command === 'ddev' && options.ddevXdgConfigHome) {
      const requestedConfigHome = resolve(String(options.ddevXdgConfigHome));
      const metadata = lstatSync(requestedConfigHome);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new Error('Verifier-owned DDEV_XDG_CONFIG_HOME must be a regular directory.');
      }
      const configHome = realpathSync(requestedConfigHome);
      commandEnvironment = Object.fromEntries(Object.entries(environment)
        .filter(([key]) => !/^(?:DDEV|COMPOSE)_/i.test(key)));
      commandEnvironment.DDEV_XDG_CONFIG_HOME = configHome;
    }
    const result = spawn(command, args, {
      cwd: options.cwd,
      encoding: 'utf8',
      env: commandEnvironment,
      input: options.input,
      maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
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
  const ownerRoot = mkdtempSync(join(tempParent, 'agent-ready-drupal-reproduction-'));
  const root = join(ownerRoot, 'project');
  const ddevXdgConfigHome = join(ownerRoot, 'xdg');
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
    const exactHeadRuntime = exactHeadRuntimeBinding(root);
    const ddevSafety = assertSafeDisposableDdevConfig(root);
    const runtime = establishVerifierOwnedDdevConfig(root, name, ddevSafety.facts);
    mkdirSync(ddevXdgConfigHome, { mode: 0o700 });
    writeFileSync(join(ownerRoot, OWNERSHIP_MARKER), `${JSON.stringify({
      ddevXdgDirectory: 'xdg',
      name,
      projectDirectory: 'project',
      token
    }, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    return { ddevSafety, ddevXdgConfigHome, exactHeadRuntime, name, ownerRoot, root, runtime, token };
  } catch (error) {
    rmSync(ownerRoot, { force: true, recursive: true });
    throw error;
  }
}

export function assertDisposableOwnership(disposable) {
  const ownerRoot = resolve(disposable?.ownerRoot ?? '');
  const root = resolve(disposable?.root ?? '');
  const ddevXdgConfigHome = resolve(disposable?.ddevXdgConfigHome ?? '');
  if (
    !ownerRoot || !existsSync(ownerRoot) || lstatSync(ownerRoot).isSymbolicLink() || !lstatSync(ownerRoot).isDirectory() ||
    !basename(ownerRoot).startsWith('agent-ready-drupal-reproduction-') ||
    !root || !existsSync(root) || lstatSync(root).isSymbolicLink() || !lstatSync(root).isDirectory() ||
    !ddevXdgConfigHome || !existsSync(ddevXdgConfigHome) || lstatSync(ddevXdgConfigHome).isSymbolicLink() ||
    !lstatSync(ddevXdgConfigHome).isDirectory() ||
    dirname(root) !== ownerRoot || dirname(ddevXdgConfigHome) !== ownerRoot ||
    basename(root) !== 'project' || basename(ddevXdgConfigHome) !== 'xdg'
  ) {
    throw new Error('Disposable cleanup root is missing or unsafe.');
  }
  const markerPath = join(ownerRoot, OWNERSHIP_MARKER);
  assertNoSymlinkPath(ownerRoot, markerPath, 'Disposable ownership marker');
  let marker;
  try {
    marker = JSON.parse(readFileSync(markerPath, 'utf8'));
  } catch {
    throw new Error('Disposable ownership marker is invalid.');
  }
  if (
    marker?.token !== disposable.token || marker?.name !== disposable.name ||
    marker?.projectDirectory !== 'project' || marker?.ddevXdgDirectory !== 'xdg'
  ) {
    throw new Error('Disposable ownership marker does not match this verifier run.');
  }
  if (!/^agent-ready-repro-[a-f0-9]{8}-[a-f0-9]{8}$/.test(disposable.name)) {
    throw new Error('Disposable DDEV name is outside the verifier-owned namespace.');
  }
  return root;
}

function sameRealPath(left, right) {
  try {
    return realpathSync(String(left)) === realpathSync(String(right));
  } catch {
    return false;
  }
}

function descriptionHasIdentity(value, expectedName, expectedRoot) {
  if (!value || typeof value !== 'object') return false;
  if (!Array.isArray(value)) {
    const name = ['name', 'project_name', 'projectName']
      .map((key) => value[key])
      .find((candidate) => typeof candidate === 'string' && candidate.trim());
    const appRoot = ['approot', 'app_root', 'appRoot', 'project_root', 'projectRoot']
      .map((key) => value[key])
      .find((candidate) => typeof candidate === 'string' && candidate.trim());
    if (String(name ?? '') === expectedName && appRoot && sameRealPath(appRoot, expectedRoot)) return true;
  }
  return Object.values(value).some((child) => descriptionHasIdentity(child, expectedName, expectedRoot));
}

/** Confirm that DDEV resolves this owned clone to the verifier-generated project name. */
export function confirmDisposableDdevIdentity({ disposable, execute, phase = 'confirm-disposable-ddev-identity' }) {
  const root = assertDisposableOwnership(disposable);
  const output = requiredCommand(execute, 'ddev', ['describe', '-j'], {
    cwd: root,
    ddevXdgConfigHome: disposable.ddevXdgConfigHome,
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
  if (!descriptionHasIdentity(description, disposable.name, root)) {
    throw new Error('DDEV did not confirm the verifier-owned disposable project name and real app root.');
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
      ddevXdgConfigHome: disposable.ddevXdgConfigHome,
      phase: 'delete-owned-disposable-ddev',
      target: 'disposable'
    });
  }
  rmSync(disposable.ownerRoot, { force: true, recursive: true });
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
