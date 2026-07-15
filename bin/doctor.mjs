#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  linkSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const KIT_ROOT = resolve(dirname(SCRIPT_PATH), '..');
const REPORT_SCHEMA = 'public-kit.doctor.1';
const MAX_DDEV_CONFIG_BYTES = 1024 * 1024;
const MAX_RECIPE_BYTES = 2 * 1024 * 1024;
const MAX_DISCOVERED_RECIPES = 64;
const MAX_CONFIG_TARGETS = 64;
const MAX_ROUTE_BYTES = 1024 * 1024;
const PACKAGE_RE = /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/;

class UsageError extends Error {}

function usage() {
  return `Usage: node <path-to-skill>/scripts/doctor.mjs [options]

Run non-authoring, pre-baseline diagnostics for the current Drupal/DDEV project.

Options:
  --project <path>       Drupal project root (default: nearest project)
  --out <path>           New JSON report under review-packet/evidence (default: review-packet/evidence/doctor.json)
  --base-url <url>       Current local DDEV web URL when it cannot be discovered
  --route <path>         First route to smoke (default: /)
  --recipe <path>        Inspect this packet-local/project-local Recipe; repeatable
  --package <name>       Query one audited Composer candidate; repeatable
  --skip-browser         Skip the pinned browser-runtime smoke explicitly
  --help                 Show this help

The report is diagnostic-only. It never applies a Recipe, intentionally changes
Drupal content or configuration, or authorizes a completion claim.
`;
}

function parseArgs(argv) {
  const options = {
    baseUrl: '',
    browser: true,
    out: 'review-packet/evidence/doctor.json',
    packages: [],
    project: '',
    recipes: [],
    route: '/'
  };
  const repeatable = new Map([['--package', 'packages'], ['--recipe', 'recipes']]);
  const values = new Map([
    ['--base-url', 'baseUrl'],
    ['--out', 'out'],
    ['--project', 'project'],
    ['--route', 'route']
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { ...options, help: true };
    if (argument === '--skip-browser') {
      options.browser = false;
      continue;
    }
    const equals = argument.indexOf('=');
    const key = equals === -1 ? argument : argument.slice(0, equals);
    if (!values.has(key) && !repeatable.has(key)) throw new UsageError(`Unknown option: ${argument}`);
    const value = equals === -1 ? argv[index + 1] : argument.slice(equals + 1);
    if (!value || (equals === -1 && value.startsWith('--'))) throw new UsageError(`${key} requires a value.`);
    if (equals === -1) index += 1;
    if (repeatable.has(key)) options[repeatable.get(key)].push(value);
    else options[values.get(key)] = value;
  }
  if (!isSafeRootRelativeRoute(options.route)) {
    throw new UsageError('--route must be an unambiguous root-relative path without a fragment.');
  }
  for (const name of options.packages) {
    if (!PACKAGE_RE.test(name)) throw new UsageError(`Invalid Composer package name: ${name}`);
  }
  return options;
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function isSafeRootRelativeRoute(value) {
  const route = String(value ?? '');
  return route.startsWith('/') &&
    !route.startsWith('//') &&
    !route.includes('\\') &&
    !route.includes('#') &&
    !/[\u0000-\u001f\u007f]/.test(route) &&
    !/^\/[a-z][a-z0-9+.-]*:\/\//i.test(route);
}

function redactRouteQuery(value) {
  if (!isSafeRootRelativeRoute(value)) return 'invalid-route';
  const url = new URL(String(value ?? ''), 'https://doctor.invalid/');
  if (!url.search) return url.pathname;
  return `${url.pathname}?query-sha256=${createHash('sha256').update(url.search).digest('hex')}`;
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${label} must be valid JSON: ${error.message}`);
  }
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function assertNoSymlinkAncestors(root, path, label) {
  let current = path;
  while (current !== root) {
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
      throw new Error(`${label} must not traverse a symbolic link: ${relative(root, current).split(sep).join('/')}`);
    }
    const parent = dirname(current);
    if (!isInside(root, parent)) throw new Error(`${label} escapes the Drupal project.`);
    current = parent;
  }
}

function projectMarkers(directory) {
  const composerPath = join(directory, 'composer.json');
  const ddevPath = join(directory, '.ddev', 'config.yaml');
  if (!existsSync(composerPath) || !existsSync(ddevPath)) return false;
  try {
    const composer = readJson(composerPath, 'composer.json');
    const requires = composer?.require ?? {};
    return ['drupal/cms', 'drupal/recommended-project'].includes(composer?.name) ||
      Boolean(requires['drupal/core'] || requires['drupal/core-recommended']);
  } catch {
    return false;
  }
}

function findProjectRoot(start, explicit = false) {
  let candidate = resolve(start);
  if (explicit) return projectMarkers(candidate) ? realpathSync(candidate) : '';
  while (true) {
    if (projectMarkers(candidate)) return realpathSync(candidate);
    const parent = dirname(candidate);
    if (parent === candidate) return '';
    candidate = parent;
  }
}

function cleanYamlLine(line) {
  const trimmed = line.trimEnd();
  if (!trimmed.trim() || trimmed.trimStart().startsWith('#')) return '';
  return trimmed.replace(/\s+#.*$/, '');
}

function unquoteYamlScalar(value) {
  const text = String(value ?? '').trim();
  if ((text.startsWith("'") && text.endsWith("'")) || (text.startsWith('"') && text.endsWith('"'))) {
    return text.slice(1, -1);
  }
  return text;
}

function topLevelScalar(lines, key) {
  const match = lines.find((line) => line.match(new RegExp(`^${key}:\\s*.+$`)));
  return match ? unquoteYamlScalar(match.slice(match.indexOf(':') + 1)) : '';
}

function configuredDdevDocroot(projectRoot) {
  const ddevDirectory = join(projectRoot, '.ddev');
  const configPath = join(ddevDirectory, 'config.yaml');
  if (lstatSync(ddevDirectory).isSymbolicLink() || lstatSync(configPath).isSymbolicLink()) {
    return { path: projectRoot, relativePath: '.', error: '.ddev/config.yaml must not traverse a symbolic link.' };
  }
  const bytes = readFileSync(configPath);
  if (bytes.length > MAX_DDEV_CONFIG_BYTES || bytes.includes(0)) {
    return { path: projectRoot, relativePath: '.', error: '.ddev/config.yaml is oversized or contains NUL bytes.' };
  }
  const lines = bytes.toString('utf8').split(/\r?\n/).map(cleanYamlLine).filter(Boolean);
  const configured = topLevelScalar(lines, 'docroot') || '.';
  if (configured.includes('\\')) {
    return { path: projectRoot, relativePath: '.', error: 'DDEV docroot contains an ambiguous path separator.' };
  }
  const path = resolve(projectRoot, configured);
  if (!isInside(projectRoot, path)) {
    return { path: projectRoot, relativePath: '.', error: 'DDEV docroot escapes the Drupal project.' };
  }
  if (existsSync(path)) {
    try {
      assertNoSymlinkAncestors(projectRoot, path, 'DDEV docroot');
    } catch (error) {
      return { path: projectRoot, relativePath: '.', error: error.message };
    }
    if (!isInside(projectRoot, realpathSync(path))) {
      return { path: projectRoot, relativePath: '.', error: 'DDEV docroot escapes the Drupal project.' };
    }
  }
  return { path, relativePath: relative(projectRoot, path).split(sep).join('/') || '.', error: '' };
}

function listUnderTopLevel(lines, key) {
  const values = [];
  let active = false;
  for (const line of lines) {
    const top = line.match(/^([a-zA-Z][a-zA-Z0-9_-]*):/);
    if (top) {
      active = top[1] === key;
      continue;
    }
    if (active) {
      const item = line.match(/^\s{2}-\s+(.+)$/);
      if (item) values.push(unquoteYamlScalar(item[1]));
    }
  }
  return values;
}

function configKeys(lines, subsection) {
  const values = [];
  let inConfig = false;
  let inSubsection = false;
  for (const line of lines) {
    const top = line.match(/^([a-zA-Z][a-zA-Z0-9_-]*):/);
    if (top) {
      inConfig = top[1] === 'config';
      inSubsection = false;
      continue;
    }
    if (!inConfig) continue;
    const second = line.match(/^\s{2}([a-zA-Z][a-zA-Z0-9_-]*):/);
    if (second) {
      inSubsection = second[1] === subsection;
      continue;
    }
    if (inSubsection) {
      const key = line.match(/^\s{4}([^\s:#][^:]*):/);
      if (key) values.push(unquoteYamlScalar(key[1]));
    }
  }
  return values;
}

function inspectConfigImports(lines) {
  const providers = [];
  const targets = [];
  const wildcardProviders = [];
  let incomplete = false;
  let inConfig = false;
  let inImport = false;
  let currentProvider = '';
  const recordValue = (provider, rawValue) => {
    const value = unquoteYamlScalar(rawValue);
    if (value === '*') {
      wildcardProviders.push(provider);
      incomplete = true;
    } else if (/^[a-z0-9_.-]+$/i.test(value)) {
      targets.push(value);
    } else if (value) {
      incomplete = true;
    }
  };
  for (const line of lines) {
    const top = line.match(/^([a-zA-Z][a-zA-Z0-9_-]*):/);
    if (top) {
      inConfig = top[1] === 'config';
      inImport = false;
      currentProvider = '';
      continue;
    }
    if (!inConfig) continue;
    const second = line.match(/^\s{2}([a-zA-Z][a-zA-Z0-9_-]*):/);
    if (second) {
      inImport = second[1] === 'import';
      currentProvider = '';
      continue;
    }
    if (!inImport) continue;
    const provider = line.match(/^\s{4}([^\s:#][^:]*):\s*(.*)$/);
    if (provider) {
      currentProvider = unquoteYamlScalar(provider[1]);
      providers.push(currentProvider);
      const inline = provider[2].trim();
      if (!inline) continue;
      const inlineList = inline.match(/^\[(.*)\]$/);
      if (inlineList) {
        for (const value of inlineList[1].split(',').map((item) => item.trim()).filter(Boolean)) {
          recordValue(currentProvider, value);
        }
      } else {
        recordValue(currentProvider, inline);
      }
      continue;
    }
    const item = currentProvider ? line.match(/^\s{6}-\s+(.+)$/) : null;
    if (item) recordValue(currentProvider, item[1]);
    else if (line.trim()) incomplete = true;
  }
  return {
    providers: [...new Set(providers)].sort(),
    targets: [...new Set(targets)].sort(),
    wildcardProviders: [...new Set(wildcardProviders)].sort(),
    incomplete
  };
}

export function inspectRecipeManifest(text) {
  if (!Buffer.byteLength(text) || Buffer.byteLength(text) > MAX_RECIPE_BYTES || text.includes('\0')) {
    throw new Error(`recipe.yml must be nonempty, NUL-free, and at most ${MAX_RECIPE_BYTES} bytes.`);
  }
  const lines = String(text).split(/\r?\n/).map(cleanYamlLine).filter(Boolean);
  const topLevelKeys = lines
    .map((line) => line.match(/^([a-zA-Z][a-zA-Z0-9_-]*):/)?.[1] ?? '')
    .filter(Boolean);
  const imports = inspectConfigImports(lines);
  const includedRecipes = listUnderTopLevel(lines, 'recipes');
  const installExtensions = listUnderTopLevel(lines, 'install');
  const configActionTargets = configKeys(lines, 'actions');
  const executableSectionsPresent = ['config', 'content', 'input', 'install', 'recipes']
    .filter((key) => topLevelKeys.includes(key));
  const configTargetInspectionIncomplete =
    imports.targets.length > MAX_CONFIG_TARGETS || configActionTargets.length > MAX_CONFIG_TARGETS;
  const manifestInspectionIncomplete = executableSectionsPresent.length > 0 ||
    includedRecipes.length > 256 ||
    installExtensions.length > 256 ||
    imports.providers.length > 256 ||
    imports.wildcardProviders.length > 256 ||
    configTargetInspectionIncomplete;
  return {
    name: topLevelScalar(lines, 'name'),
    type: topLevelScalar(lines, 'type'),
    descriptionPresent: Boolean(topLevelScalar(lines, 'description')),
    topLevelKeys: [...new Set(topLevelKeys)].sort(),
    includedRecipes: includedRecipes.slice(0, 256).sort(),
    installExtensions: installExtensions.slice(0, 256).sort(),
    configImports: imports.providers.slice(0, 256),
    configImportTargets: imports.targets.slice(0, MAX_CONFIG_TARGETS),
    wildcardConfigImports: imports.wildcardProviders.slice(0, 256),
    configImportInspectionIncomplete: imports.incomplete,
    configActionTargets: configActionTargets.slice(0, MAX_CONFIG_TARGETS).sort(),
    configTargetInspectionIncomplete,
    manifestInspectionIncomplete,
    executableSectionsPresent,
    declaredCounts: {
      includedRecipes: includedRecipes.length,
      installExtensions: installExtensions.length,
      configImportProviders: imports.providers.length,
      configImportTargets: imports.targets.length,
      wildcardConfigImports: imports.wildcardProviders.length,
      configActionTargets: configActionTargets.length
    }
  };
}

function walkRecipeFiles(root, output, limit = MAX_DISCOVERED_RECIPES + 1, state = { skippedSymlink: false }) {
  if (!existsSync(root) || output.length >= limit) return;
  for (const entry of readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (output.length >= limit) return;
    const path = join(root, entry.name);
    if (entry.isSymbolicLink()) {
      state.skippedSymlink = true;
      continue;
    }
    if (entry.isDirectory()) walkRecipeFiles(path, output, limit, state);
    else if (entry.isFile() && entry.name === 'recipe.yml') output.push(path);
  }
}

function discoverRecipes(projectRoot, requested, ddevDocroot) {
  const paths = [];
  const scanState = { skippedSymlink: false };
  if (requested.length > 0) {
    if (requested.length > MAX_DISCOVERED_RECIPES) {
      throw new Error(`Explicit Recipe inspection is limited to ${MAX_DISCOVERED_RECIPES} manifests.`);
    }
    for (const value of requested) {
      const candidate = resolve(projectRoot, value);
      if (!isInside(projectRoot, candidate)) throw new Error(`Recipe path escapes the Drupal project: ${value}`);
      const manifest = statSync(candidate).isDirectory() ? join(candidate, 'recipe.yml') : candidate;
      assertNoSymlinkAncestors(projectRoot, manifest, 'Recipe path');
      if (!existsSync(manifest) || lstatSync(manifest).isSymbolicLink() || !statSync(manifest).isFile()) {
        throw new Error(`Recipe path does not contain a regular recipe.yml: ${value}`);
      }
      const resolvedManifest = realpathSync(manifest);
      if (!isInside(projectRoot, resolvedManifest)) throw new Error(`Recipe path escapes the Drupal project: ${value}`);
      paths.push(resolvedManifest);
    }
  } else {
    for (const root of [join(projectRoot, 'recipes'), join(ddevDocroot, 'core', 'recipes')]) {
      if (!existsSync(root)) continue;
      assertNoSymlinkAncestors(projectRoot, root, 'Automatic Recipe discovery root');
      if (!isInside(projectRoot, realpathSync(root))) {
        throw new Error('Automatic Recipe discovery root escapes the Drupal project.');
      }
      walkRecipeFiles(root, paths, MAX_DISCOVERED_RECIPES + 1, scanState);
    }
  }
  const uniquePaths = [...new Set(paths)].sort();
  return {
    mode: requested.length > 0 ? 'explicit' : 'automatic',
    paths: uniquePaths.slice(0, MAX_DISCOVERED_RECIPES),
    truncated: uniquePaths.length > MAX_DISCOVERED_RECIPES,
    skippedSymlink: scanState.skippedSymlink
  };
}

function recipeConfigNames(projectRoot, recipeDir) {
  const names = [];
  let incomplete = false;
  const visit = (directory) => {
    if (!existsSync(directory) || names.length >= 512) return;
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        incomplete = true;
        continue;
      }
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) names.push(entry.name.replace(/\.ya?ml$/i, ''));
    }
  };
  const configRoot = join(recipeDir, 'config');
  if (existsSync(configRoot)) {
    try {
      assertNoSymlinkAncestors(projectRoot, configRoot, 'Recipe config root');
      if (!isInside(projectRoot, realpathSync(configRoot))) incomplete = true;
      else visit(configRoot);
    } catch {
      incomplete = true;
    }
  }
  return { names: [...new Set(names)].sort(), incomplete: incomplete || names.length >= 512 };
}

function packageRecords(lock) {
  return [...(lock?.packages ?? []), ...(lock?.['packages-dev'] ?? [])].map((record) => ({
    name: String(record?.name ?? ''),
    type: String(record?.type ?? ''),
    version: String(record?.version ?? ''),
    require: record?.require ?? {}
  }));
}

function packageCandidatesForRecipe(records, manifestPath) {
  const normalizedId = (value) => String(value ?? '')
    .toLowerCase()
    .replace(/^drupal[_-]/, '')
    .replace(/[^a-z0-9]/g, '');
  const recipeId = normalizedId(basename(dirname(manifestPath)));
  return records.filter((record) => {
    const packageId = normalizedId(record.name.split('/').pop());
    return packageId === recipeId;
  });
}

function commandEvidence(result, display) {
  const stdout = String(result?.stdout ?? '');
  const stderr = String(result?.stderr ?? '');
  return {
    command: display,
    exitCode: Number.isInteger(result?.status) ? result.status : 1,
    signal: result?.signal ?? null,
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(stderr)
  };
}

function defaultCommandRunner({ args, command, cwd, environment }) {
  return spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: environment,
    maxBuffer: 1024 * 1024,
    timeout: 30_000
  });
}

function projectCommand(insideDdev, kind, args) {
  if (kind === 'drush') {
    return insideDdev
      ? { command: 'drush', args, display: `drush ${args.join(' ')}` }
      : { command: 'ddev', args: ['drush', ...args], display: `ddev drush ${args.join(' ')}` };
  }
  if (kind === 'composer') {
    return insideDdev
      ? { command: 'composer', args, display: `composer ${args.join(' ')}` }
      : { command: 'ddev', args: ['composer', ...args], display: `ddev composer ${args.join(' ')}` };
  }
  if (kind === 'exec') {
    return insideDdev
      ? { command: args[0], args: args.slice(1), display: args.join(' ') }
      : { command: 'ddev', args: ['exec', ...args], display: `ddev exec ${args.join(' ')}` };
  }
  throw new Error(`Unknown command kind: ${kind}`);
}

function runRecordedCommand(commandRunner, descriptor, projectRoot, environment) {
  const raw = commandRunner({ ...descriptor, cwd: descriptor.cwd ?? projectRoot, environment });
  return { raw, evidence: commandEvidence(raw, descriptor.display) };
}

function recipeRunnerCommand(insideDdev, projectRoot, runnerPath) {
  const normalizedRunner = relative(projectRoot, runnerPath).split(sep).join('/');
  if (normalizedRunner === 'vendor/bin/dr') {
    if (insideDdev) {
      return {
        command: runnerPath,
        args: ['recipe:apply', '--help'],
        cwd: projectRoot,
        display: 'vendor/bin/dr recipe:apply --help'
      };
    }
    return {
      command: 'ddev',
      args: ['exec', 'vendor/bin/dr', 'recipe:apply', '--help'],
      display: 'ddev exec vendor/bin/dr recipe:apply --help'
    };
  }
  const docroot = resolve(dirname(runnerPath), '..', '..');
  const relativeDocroot = relative(projectRoot, docroot).split(sep).join('/');
  if (insideDdev) {
    return {
      command: 'php',
      args: ['core/scripts/drupal', 'recipe', '--help'],
      cwd: docroot,
      display: `cd ${relativeDocroot || '.'} && php core/scripts/drupal recipe --help`
    };
  }
  const containerDocroot = relativeDocroot && relativeDocroot !== '.'
    ? `/var/www/html/${relativeDocroot}`
    : '/var/www/html';
  return {
    command: 'ddev',
    args: ['exec', '-d', containerDocroot, 'php', 'core/scripts/drupal', 'recipe', '--help'],
    display: `ddev exec -d ${containerDocroot} php core/scripts/drupal recipe --help`
  };
}

function parseStatusJson(raw) {
  try {
    const parsed = JSON.parse(String(raw?.stdout ?? ''));
    return {
      bootstrap: String(parsed?.bootstrap ?? parsed?.['Drupal bootstrap'] ?? ''),
      dbStatus: String(parsed?.['db-status'] ?? parsed?.['Database'] ?? ''),
      drupalVersion: String(parsed?.['drupal-version'] ?? parsed?.['Drupal version'] ?? ''),
      root: String(parsed?.root ?? parsed?.['Drupal root'] ?? '')
    };
  } catch {
    return null;
  }
}

function normalizedVersion(value) {
  return String(value ?? '').trim().replace(/^v/i, '');
}

function normalizedRuntimeRoot(value) {
  return String(value ?? '').trim().replace(/\\/g, '/').replace(/\/$/, '');
}

function runtimeStatusFacts(status, { coreVersion, ddevDocroot, insideDdev, projectRoot }) {
  const relativeDocroot = ddevDocroot === '.' ? '' : ddevDocroot;
  const expectedRoots = new Set([
    relativeDocroot || '.',
    normalizedRuntimeRoot(resolve(projectRoot, relativeDocroot)),
    normalizedRuntimeRoot(`/var/www/html/${relativeDocroot}`)
  ]);
  const observedRoot = normalizedRuntimeRoot(status?.root);
  return {
    bootstrap: String(status?.bootstrap ?? ''),
    dbStatus: String(status?.dbStatus ?? ''),
    drupalVersion: String(status?.drupalVersion ?? ''),
    coreVersionMatchesLock: Boolean(normalizedVersion(coreVersion)) &&
      normalizedVersion(status?.drupalVersion) === normalizedVersion(coreVersion),
    rootMatchesDdevDocroot: Boolean(observedRoot) && expectedRoots.has(observedRoot),
    executionContext: insideDdev ? 'ddev-container' : 'ddev-host'
  };
}

function runtimeStatusReady(status, facts) {
  return Boolean(status) &&
    status.bootstrap.trim().toLowerCase() === 'successful' &&
    status.dbStatus.trim().toLowerCase() === 'connected' &&
    facts.coreVersionMatchesLock &&
    facts.rootMatchesDdevDocroot;
}

function extractDdevPrimaryUrl(raw) {
  try {
    const parsed = JSON.parse(String(raw?.stdout ?? ''));
    return String(parsed?.raw?.primary_url ?? parsed?.raw?.primaryUrl ?? parsed?.primary_url ?? '');
  } catch {
    return '';
  }
}

function validLocalUrl(value, trustedUrls = []) {
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    const trustedOrigins = new Set(trustedUrls.filter(Boolean).map((candidate) => {
      try { return new URL(candidate).origin; } catch { return ''; }
    }).filter(Boolean));
    return !url.username && !url.password && ['http:', 'https:'].includes(url.protocol) && (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host.endsWith('.ddev.site') ||
      trustedOrigins.has(url.origin)
    );
  } catch {
    return false;
  }
}

function sameOrigin(left, right) {
  try {
    return new URL(left).origin === new URL(right).origin;
  } catch {
    return false;
  }
}

async function boundedResponseText(response) {
  if (!response.body?.getReader) return (await response.text()).slice(0, MAX_ROUTE_BYTES);
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_ROUTE_BYTES) {
      await reader.cancel();
      throw new Error(`Route response exceeds ${MAX_ROUTE_BYTES} bytes.`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((value) => Buffer.from(value))).toString('utf8');
}

async function routeSmoke(baseUrl, route, fetchImpl, trustedUrls = []) {
  const routeIdentity = redactRouteQuery(route);
  if (!isSafeRootRelativeRoute(route)) {
    return { id: 'route', status: 'fail', errors: ['Route must be an unambiguous root-relative path.'], facts: {} };
  }
  if (!validLocalUrl(baseUrl, trustedUrls)) {
    return { id: 'route', status: 'fail', errors: ['A current local DDEV base URL could not be discovered.'], facts: {} };
  }
  const base = new URL('/', baseUrl);
  const requested = new URL(route, base);
  if (requested.origin !== base.origin) {
    return { id: 'route', status: 'fail', errors: ['Route escaped the discovered local DDEV origin.'], facts: {} };
  }
  try {
    const response = await fetchImpl(requested, { redirect: 'manual', signal: AbortSignal.timeout(15_000) });
    const body = await boundedResponseText(response);
    const title = body.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/<[^>]+>/g, '').trim() ?? '';
    const h1 = body.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i)?.[1]?.replace(/<[^>]+>/g, '').trim() ?? '';
    const finalUrl = new URL(response.url || requested);
    const passed = response.status >= 200 && response.status < 300 &&
      finalUrl.origin === requested.origin && Boolean(title || h1);
    return {
      id: 'route',
      status: passed ? 'pass' : 'fail',
      errors: passed ? [] : [`${routeIdentity} must return 2xx and render a title or H1.`],
      facts: {
        finalPath: redactRouteQuery(`${finalUrl.pathname}${finalUrl.search}`),
        hasH1: Boolean(h1),
        hasTitle: Boolean(title),
        h1Sha256: h1 ? sha256(h1) : '',
        status: response.status,
        titleSha256: title ? sha256(title) : ''
      }
    };
  } catch (error) {
    return {
      id: 'route',
      status: 'fail',
      errors: [`${routeIdentity} could not be inspected.`],
      facts: { errorSha256: sha256(String(error?.message ?? error)) }
    };
  }
}

async function defaultBrowserSmokeRunner({ insideDdev, projectRoot, environment }) {
  const candidates = [
    join(dirname(SCRIPT_PATH), 'browser-runtime-smoke.mjs'),
    join(KIT_ROOT, 'scripts', 'browser-runtime-smoke.mjs')
  ];
  const script = candidates.find((candidate) => existsSync(candidate));
  if (!script) throw new Error('browser-runtime-smoke.mjs is missing from the kit.');
  if (insideDdev) {
    const module = await import(pathToFileURL(script).href);
    return module.runBrowserRuntimeSmoke();
  }
  if (!isInside(projectRoot, script)) {
    throw new Error('Host doctor must run from the installed project-local skill to execute the DDEV browser smoke.');
  }
  const relativeScript = relative(projectRoot, script).split(sep).join('/');
  const result = spawnSync('ddev', ['exec', 'node', relativeScript], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment,
    maxBuffer: 1024 * 1024,
    timeout: 120_000
  });
  if (result.status !== 0) {
    throw new Error(`DDEV browser smoke failed (stderr ${sha256(String(result.stderr ?? ''))}).`);
  }
  return JSON.parse(String(result.stdout));
}

function summarizeStages(stages, recipes, packages) {
  const statuses = [
    ...stages.map((stage) => stage.status),
    ...recipes.map((recipe) => recipe.status),
    ...packages.map((record) => record.status)
  ];
  return {
    status: statuses.includes('fail')
      ? 'fail'
      : statuses.includes('warning') || statuses.includes('skipped')
        ? 'warning'
        : 'pass',
    passed: statuses.filter((status) => status === 'pass').length,
    warnings: statuses.filter((status) => status === 'warning').length,
    failed: statuses.filter((status) => status === 'fail').length,
    skipped: statuses.filter((status) => status === 'skipped').length,
    readyForFullVerification: !statuses.includes('fail') && !statuses.includes('skipped')
  };
}

export async function runDoctor({
  baseUrl = '',
  browser = true,
  browserSmokeRunner = defaultBrowserSmokeRunner,
  checkedAt = new Date().toISOString(),
  commandRunner = defaultCommandRunner,
  environment = process.env,
  fetchImpl = fetch,
  packages = [],
  projectRoot,
  recipes = [],
  route = '/'
}) {
  projectRoot = realpathSync(resolve(projectRoot));
  const insideDdev = environment.IS_DDEV_PROJECT === 'true' || Boolean(environment.DDEV_PROJECT);
  const composer = readJson(join(projectRoot, 'composer.json'), 'composer.json');
  const lock = existsSync(join(projectRoot, 'composer.lock'))
    ? readJson(join(projectRoot, 'composer.lock'), 'composer.lock')
    : { packages: [], 'packages-dev': [] };
  const lockedPackages = packageRecords(lock);
  const corePackage = lockedPackages.find((record) => record.name === 'drupal/core') ??
    lockedPackages.find((record) => record.name === 'drupal/core-recommended');
  const cmsPackage = lockedPackages.find((record) => record.name === 'drupal/cms');
  const stages = [];

  const ddevDocroot = configuredDdevDocroot(projectRoot);
  const runnerPath = [
    join(projectRoot, 'vendor', 'bin', 'dr'),
    ...[ddevDocroot.path, join(projectRoot, 'web'), join(projectRoot, 'docroot'), projectRoot]
      .map((docroot) => join(docroot, 'core', 'scripts', 'drupal'))
  ].find((candidate) => existsSync(candidate));
  const projectErrors = [];
  if (!existsSync(join(projectRoot, '.ddev', 'config.yaml'))) projectErrors.push('.ddev/config.yaml is missing.');
  if (ddevDocroot.error) projectErrors.push(ddevDocroot.error);
  if (!runnerPath) projectErrors.push('A supported Drupal Recipe runner is missing.');
  if (!corePackage) projectErrors.push('composer.lock does not identify Drupal core.');
  stages.push({
    id: 'substrate',
    status: projectErrors.length ? 'fail' : 'pass',
    errors: projectErrors,
    facts: {
      composerProject: String(composer?.name ?? ''),
      drupalCmsVersion: String(cmsPackage?.version ?? composer?.version ?? ''),
      drupalCoreVersion: String(corePackage?.version ?? ''),
      ddevDocroot: ddevDocroot.relativePath,
      recipeRunnerPath: runnerPath ? relative(projectRoot, runnerPath).split(sep).join('/') : ''
    }
  });

  let runtimeStatus = null;
  let runtimePassed = false;
  if (runnerPath) {
    const runner = runRecordedCommand(
      commandRunner,
      recipeRunnerCommand(insideDdev, projectRoot, runnerPath),
      projectRoot,
      environment
    );
    const status = runRecordedCommand(
      commandRunner,
      projectCommand(insideDdev, 'drush', ['status', '--fields=bootstrap,db-status,drupal-version,root', '--format=json']),
      projectRoot,
      environment
    );
    runtimeStatus = parseStatusJson(status.raw);
    const facts = runtimeStatusFacts(runtimeStatus, {
      coreVersion: corePackage?.version,
      ddevDocroot: ddevDocroot.relativePath,
      insideDdev,
      projectRoot
    });
    runtimePassed = runner.evidence.exitCode === 0 &&
      status.evidence.exitCode === 0 &&
      runtimeStatusReady(runtimeStatus, facts);
    stages.push({
      id: 'runtime',
      status: runtimePassed ? 'pass' : 'fail',
      errors: runtimePassed
        ? []
        : ['Drupal bootstrap, locked core version, DDEV docroot, or the discovered Recipe runner did not agree.'],
      facts,
      commands: [runner.evidence, status.evidence]
    });
  } else {
    stages.push({ id: 'runtime', status: 'fail', errors: ['Recipe runner is unavailable.'], facts: {}, commands: [] });
  }

  let authoritativeBaseUrl = insideDdev ? String(environment.DDEV_PRIMARY_URL ?? '') : '';
  let resolvedBaseUrl = authoritativeBaseUrl || baseUrl || '';
  const trustedBaseUrls = [authoritativeBaseUrl].filter(Boolean);
  if (!insideDdev) {
    const describe = runRecordedCommand(
      commandRunner,
      { command: 'ddev', args: ['describe', '-j'], display: 'ddev describe -j' },
      projectRoot,
      environment
    );
    const describedBaseUrl = extractDdevPrimaryUrl(describe.raw);
    authoritativeBaseUrl = describedBaseUrl;
    if (describedBaseUrl) resolvedBaseUrl = describedBaseUrl;
    if (describedBaseUrl) trustedBaseUrls.push(describedBaseUrl);
    stages.push({
      id: 'ddev-url-discovery',
      status: describe.evidence.exitCode === 0 && validLocalUrl(describedBaseUrl, trustedBaseUrls) ? 'pass' : 'fail',
      errors: validLocalUrl(describedBaseUrl, trustedBaseUrls) ? [] : ['DDEV did not report a supported local primary URL.'],
      facts: { discovered: validLocalUrl(describedBaseUrl, trustedBaseUrls) },
      commands: [describe.evidence]
    });
  }
  const explicitOriginMismatch = Boolean(baseUrl && authoritativeBaseUrl) &&
    !sameOrigin(baseUrl, authoritativeBaseUrl);
  stages.push({
    id: 'target-origin-binding',
    status: explicitOriginMismatch || !validLocalUrl(resolvedBaseUrl, trustedBaseUrls) ? 'fail' : 'pass',
    errors: explicitOriginMismatch
      ? ['Explicit base URL does not match the current DDEV project origin.']
      : validLocalUrl(resolvedBaseUrl, trustedBaseUrls)
        ? []
        : ['No current-project local DDEV origin is available.'],
    facts: {
      authoritativeOriginDiscovered: validLocalUrl(authoritativeBaseUrl, trustedBaseUrls),
      explicitBaseUrlProvided: Boolean(baseUrl),
      explicitOriginMatches: baseUrl && authoritativeBaseUrl ? sameOrigin(baseUrl, authoritativeBaseUrl) : null
    }
  });
  stages.push(await routeSmoke(resolvedBaseUrl, route, fetchImpl, trustedBaseUrls));

  if (browser) {
    try {
      const result = await browserSmokeRunner({ insideDdev, projectRoot, environment });
      const passed = Number(result?.axeRouteViewportCount) > 0 &&
        String(result?.executionBoundary ?? '') === 'ddev-add-on-sidecar' &&
        result?.ready !== false;
      stages.push({
        id: 'browser-runtime',
        status: passed ? 'pass' : 'fail',
        errors: passed ? [] : ['Pinned browser runtime did not return route, axe, and execution-boundary evidence.'],
        facts: {
          axeRouteViewportCount: Number(result?.axeRouteViewportCount ?? 0),
          browserVersion: String(result?.browserVersion ?? ''),
          executionBoundary: String(result?.executionBoundary ?? '')
        }
      });
    } catch (error) {
      stages.push({
        id: 'browser-runtime',
        status: 'fail',
        errors: ['Pinned browser runtime smoke failed.'],
        facts: { errorSha256: sha256(String(error?.message ?? error)) }
      });
    }
  } else {
    stages.push({
      id: 'browser-runtime',
      status: 'skipped',
      errors: [],
      facts: { reason: 'Explicit --skip-browser diagnostic scope.' }
    });
  }

  const recipeReports = [];
  let configChecksUsed = 0;
  const recipeDiscovery = discoverRecipes(projectRoot, recipes, ddevDocroot.path);
  stages.push({
    id: 'recipe-discovery',
    status: recipeDiscovery.truncated || recipeDiscovery.skippedSymlink ? 'warning' : 'pass',
    errors: [],
    warnings: [
      ...(recipeDiscovery.truncated
        ? [`Recipe discovery reached the ${MAX_DISCOVERED_RECIPES}-manifest diagnostic limit.`]
        : []),
      ...(recipeDiscovery.skippedSymlink
        ? ['Recipe discovery skipped one or more symbolic links and is incomplete.']
        : [])
    ],
    facts: {
      mode: recipeDiscovery.mode,
      recipeCount: recipeDiscovery.paths.length,
      truncated: recipeDiscovery.truncated,
      skippedSymlink: recipeDiscovery.skippedSymlink
    }
  });
  for (const manifestPath of recipeDiscovery.paths) {
    const manifestBytes = readFileSync(manifestPath);
    const manifest = inspectRecipeManifest(manifestBytes.toString('utf8'));
    const configInventory = recipeConfigNames(projectRoot, dirname(manifestPath));
    const configNames = configInventory.names;
    const activeConfigTargets = [];
    const configCommands = [];
    if (runtimePassed) {
      for (const configName of [
        ...new Set([...manifest.configActionTargets, ...manifest.configImportTargets, ...configNames])
      ].slice(0, MAX_CONFIG_TARGETS)) {
        if (configChecksUsed >= MAX_CONFIG_TARGETS) break;
        if (!/^[a-z0-9_.-]+$/i.test(configName)) continue;
        configChecksUsed += 1;
        const check = runRecordedCommand(
          commandRunner,
          projectCommand(insideDdev, 'drush', ['config:get', configName, '--format=json']),
          projectRoot,
          environment
        );
        configCommands.push(check.evidence);
        if (check.evidence.exitCode === 0) activeConfigTargets.push(configName);
      }
    }
    const errors = [];
    if (!manifest.name) errors.push('recipe.yml has no readable top-level name.');
    const targetCount = [
      ...new Set([...manifest.configActionTargets, ...manifest.configImportTargets, ...configNames])
    ].length;
    const activeConfigInspectionTruncated = manifest.configTargetInspectionIncomplete ||
      (runtimePassed && configChecksUsed >= MAX_CONFIG_TARGETS && targetCount > configCommands.length);
    const includedRecipeInspectionIncomplete = manifest.includedRecipes.length > 0;
    const warning = activeConfigTargets.length > 0 ||
      activeConfigInspectionTruncated ||
      manifest.configImportInspectionIncomplete ||
      manifest.manifestInspectionIncomplete ||
      includedRecipeInspectionIncomplete ||
      configInventory.incomplete;
    recipeReports.push({
      path: relative(projectRoot, manifestPath).split(sep).join('/'),
      status: errors.length ? 'fail' : warning ? 'warning' : 'pass',
      errors,
      warnings: [
        ...(activeConfigTargets.length > 0
          ? ['Recipe targets active configuration. Review action/import compatibility and rollback behavior before applying it.']
          : []),
        ...(activeConfigInspectionTruncated
          ? [`Active-config inspection reached the global ${MAX_CONFIG_TARGETS}-target diagnostic limit.`]
          : []),
        ...(manifest.configImportInspectionIncomplete
          ? ['Wildcard or unparsed config imports require manual compatibility review.']
          : []),
        ...(includedRecipeInspectionIncomplete
          ? ['Included Recipes were not recursively inspected and require manual compatibility review.']
          : []),
        ...(manifest.manifestInspectionIncomplete
          ? ['Recipe executable sections use a bounded heuristic scan and cannot be treated as complete manifest validation.']
          : []),
        ...(configInventory.incomplete
          ? ['Recipe config-file discovery encountered a symlink or its bounded file limit.']
          : [])
      ],
      applyReadiness: errors.length ? 'blocked' : 'manual_review_required',
      manifestSha256: sha256(manifestBytes),
      manifestBytes: manifestBytes.length,
      manifest,
      configInstallNames: configNames,
      configInstallInspectionIncomplete: configInventory.incomplete,
      activeConfigTargets: [...new Set(activeConfigTargets)].sort(),
      activeConfigInspectionTruncated,
      includedRecipeInspectionIncomplete,
      packageCandidates: packageCandidatesForRecipe(lockedPackages, manifestPath),
      commands: configCommands
    });
  }

  const upstreamPackages = [];
  for (const packageName of [...new Set(packages)].sort()) {
    const checked = runRecordedCommand(
      commandRunner,
      projectCommand(insideDdev, 'composer', ['show', '--all', '--format=json', packageName]),
      projectRoot,
      environment
    );
    let parsed = null;
    try { parsed = JSON.parse(String(checked.raw?.stdout ?? '')); } catch { /* evidence remains hash-only */ }
    const available = checked.evidence.exitCode === 0 && Boolean(parsed?.name);
    upstreamPackages.push({
      name: packageName,
      status: available ? 'pass' : 'fail',
      available,
      errors: available ? [] : ['Composer did not return machine-readable package metadata.'],
      package: available ? {
        name: String(parsed.name),
        type: String(parsed.type ?? ''),
        versions: Array.isArray(parsed.versions) ? parsed.versions.slice(0, 50).map(String) : [],
        requires: parsed.requires ?? {}
      } : null,
      command: checked.evidence
    });
  }

  const report = {
    schemaVersion: REPORT_SCHEMA,
    checkedAt,
    authority: 'diagnostic_only',
    completionAuthority: false,
    mutationPolicy: {
      appliesRecipes: false,
      changesDrupalContentOrConfig: false,
      writesReviewerVerdicts: false
    },
    project: {
      root: '.',
      insideDdev,
      route: redactRouteQuery(route),
      localBaseUrlDiscovered: validLocalUrl(resolvedBaseUrl, trustedBaseUrls)
    },
    stages,
    recipes: recipeReports,
    upstreamPackages,
    summary: null
  };
  report.summary = summarizeStages(stages, recipeReports, upstreamPackages);
  return report;
}

function assertSafeOutput(projectRoot, outputPath) {
  const evidenceRoot = resolve(projectRoot, 'review-packet', 'evidence');
  const output = resolve(projectRoot, outputPath);
  if (!isInside(evidenceRoot, output) || output === evidenceRoot) {
    throw new Error('--out must be a new file under review-packet/evidence.');
  }
  assertNoSymlinkAncestors(projectRoot, output, '--out');
  if (existsSync(output)) {
    throw new Error('--out refuses to overwrite an existing file.');
  }
  return output;
}

function writeReportAtomic(path, report) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  try {
    writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    try {
      linkSync(temporary, path);
    } catch (error) {
      if (error?.code === 'EEXIST') {
        throw new Error('--out refuses to overwrite an existing file.');
      }
      throw error;
    }
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  const projectRoot = findProjectRoot(options.project || process.cwd(), Boolean(options.project));
  if (!projectRoot) throw new UsageError('No Drupal/DDEV project root was found.');
  const output = assertSafeOutput(projectRoot, options.out);
  const report = await runDoctor({ ...options, projectRoot });
  writeReportAtomic(output, report);
  const relativeOutput = relative(projectRoot, output).split(sep).join('/');
  if (report.summary.status === 'fail') {
    process.stderr.write(`Doctor found blocking diagnostics. Report: ${relativeOutput}\n`);
    process.exitCode = 2;
  } else {
    process.stdout.write(`Doctor diagnostics ${report.summary.status}. Report: ${relativeOutput}\n`);
  }
}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(SCRIPT_PATH) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    if (error instanceof UsageError) process.stderr.write(usage());
    process.exitCode = 1;
  });
}
