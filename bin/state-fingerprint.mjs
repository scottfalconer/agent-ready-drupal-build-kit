import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync
} from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const FILE_MANIFEST_SCHEMA = 'public-kit.file-manifest.1';
const SITE_STATE_SCHEMA = 'public-kit.site-state.1';

function comparePortable(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function canonicalValue(value, seen = new Set(), inArray = false) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Canonical JSON cannot contain a non-finite number.');
    }
    return value;
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
    return inArray ? null : undefined;
  }
  if (typeof value === 'bigint') {
    throw new TypeError('Canonical JSON cannot contain bigint values.');
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.from(value).toString('base64');
  }
  if (typeof value !== 'object') {
    throw new TypeError(`Canonical JSON cannot contain ${typeof value} values.`);
  }
  if (seen.has(value)) {
    throw new TypeError('Canonical JSON cannot contain circular references.');
  }
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    result = value.map((child) => canonicalValue(child, seen, true));
  } else {
    // A null-prototype object makes keys such as __proto__ and constructor
    // ordinary data instead of prototype mutation primitives.
    result = Object.create(null);
    for (const key of Object.keys(value).sort(comparePortable)) {
      const child = canonicalValue(value[key], seen, false);
      if (child !== undefined) {
        result[key] = child;
      }
    }
  }
  seen.delete(value);
  return result;
}

/** Return deterministic JSON with recursively sorted object keys. */
export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

/** Return a prefixed SHA-256 digest for bytes, text, or canonical JSON data. */
export function sha256(value) {
  const input = typeof value === 'string' || Buffer.isBuffer(value) || value instanceof Uint8Array
    ? value
    : canonicalJson(value);
  return `sha256:${createHash('sha256').update(input).digest('hex')}`;
}

function portablePath(value) {
  return String(value).replaceAll('\\', '/').split(sep).join('/');
}

function safeRelativePath(value, label = 'Manifest path') {
  const path = portablePath(value).replace(/^\.\//, '');
  if (
    !path ||
    path === '.' ||
    isAbsolute(path) ||
    path.startsWith('/') ||
    /^[a-z]:\//i.test(path) ||
    path.split('/').some((part) => part === '..' || part === '.' || part === '')
  ) {
    throw new Error(`${label} must be a non-empty project-relative path without traversal: ${String(value)}`);
  }
  return path;
}

function normalizedHash(value, label) {
  const text = String(value ?? '').trim().toLowerCase();
  const hash = /^[a-f0-9]{64}$/.test(text) ? `sha256:${text}` : text;
  if (!HASH_RE.test(hash)) {
    throw new Error(`${label} must be a SHA-256 fingerprint.`);
  }
  return hash;
}

/**
 * Normalize and hash a path/hash entry list.
 *
 * Duplicate paths are rejected unless every recorded attribute is identical.
 */
export function hashManifest(entries) {
  if (!Array.isArray(entries)) {
    throw new TypeError('Manifest entries must be an array.');
  }
  const byPath = new Map();
  for (const [index, value] of entries.entries()) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new TypeError(`Manifest entry ${index} must be an object.`);
    }
    const path = safeRelativePath(value.path, `Manifest entry ${index} path`);
    const digest = normalizedHash(value.sha256 ?? value.hash, `Manifest entry ${path} hash`);
    const size = Number(value.size);
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error(`Manifest entry ${path} must have a non-negative integer size.`);
    }
    const entry = { path, sha256: digest, size };
    const existing = byPath.get(path);
    if (existing && canonicalJson(existing) !== canonicalJson(entry)) {
      throw new Error(`Manifest contains conflicting duplicate path: ${path}`);
    }
    byPath.set(path, entry);
  }
  const normalizedEntries = [...byPath.values()].sort((left, right) => comparePortable(left.path, right.path));
  return {
    schemaVersion: FILE_MANIFEST_SCHEMA,
    entryCount: normalizedEntries.length,
    entries: normalizedEntries,
    fingerprint: sha256(normalizedEntries)
  };
}

function rootEvidence(projectRoot) {
  const requestedRoot = resolve(projectRoot);
  if (!existsSync(requestedRoot) || !statSync(requestedRoot).isDirectory()) {
    throw new Error(`Project root is not a directory: ${requestedRoot}`);
  }
  if (lstatSync(requestedRoot).isSymbolicLink()) {
    throw new Error('Project root must not be a symbolic link.');
  }
  return { requestedRoot, realRoot: realpathSync(requestedRoot) };
}

function isInside(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (
    pathFromParent !== '..' &&
    !pathFromParent.startsWith(`..${sep}`) &&
    !isAbsolute(pathFromParent)
  );
}

function assertNoSymlinkAncestors(root, path) {
  let current = path;
  while (current !== root) {
    if (lstatSync(current).isSymbolicLink()) {
      throw new Error(`Fingerprint input must not traverse a symbolic link: ${portablePath(relative(root, current))}`);
    }
    const parent = resolve(current, '..');
    if (!isInside(root, parent)) {
      throw new Error('Fingerprint input escaped the project root.');
    }
    current = parent;
  }
}

function resolveInputPath(root, value) {
  const text = String(value ?? '').trim();
  if (!text) {
    throw new Error('Fingerprint input paths must not be empty.');
  }
  const path = resolve(root, text);
  if (!isInside(root, path)) {
    throw new Error(`Fingerprint input escapes the project root: ${text}`);
  }
  return path;
}

function collectEntries(root, inputPath, entries, shouldSkip = () => false) {
  if (!existsSync(inputPath)) {
    return;
  }
  const relativePath = portablePath(relative(root, inputPath));
  const metadata = lstatSync(inputPath);
  if (relativePath && shouldSkip(relativePath, metadata)) {
    return;
  }
  assertNoSymlinkAncestors(root, inputPath);
  if (metadata.isSymbolicLink()) {
    throw new Error(`Fingerprint input must not contain a symbolic link: ${relativePath}`);
  }
  if (metadata.isDirectory()) {
    for (const child of readdirSync(inputPath).sort(comparePortable)) {
      collectEntries(root, resolve(inputPath, child), entries, shouldSkip);
    }
    return;
  }
  if (!metadata.isFile()) {
    throw new Error(`Fingerprint input must contain only regular files and directories: ${relativePath}`);
  }
  const path = safeRelativePath(relativePath);
  const bytes = readFileSync(inputPath);
  entries.push({ path, sha256: sha256(bytes), size: bytes.length });
}

function collectFileManifestWithFilter(projectRoot, paths, shouldSkip) {
  if (!Array.isArray(paths)) {
    throw new TypeError('Fingerprint paths must be an array.');
  }
  const { realRoot } = rootEvidence(projectRoot);
  const entries = [];
  for (const value of paths) {
    const path = resolveInputPath(realRoot, value);
    collectEntries(realRoot, path, entries, shouldSkip);
  }
  return hashManifest(entries);
}

/** Collect a deterministic project-relative byte manifest for supplied files/directories. */
export function collectFileManifest(projectRoot, paths) {
  return collectFileManifestWithFilter(projectRoot, paths, () => false);
}

const RUNTIME_CODE_PATHS = Object.freeze([
  'composer.json',
  'composer.lock',
  'composer.patches.json',
  'patches.json',
  'patches.lock.json',
  'recipes',
  'patches',
  'scripts',
  'drush',
  'hooks',
  '.ddev',
  '.platform',
  '.acquia',
  '.buildkite',
  '.circleci',
  '.github',
  '.gitlab',
  'web/modules/custom',
  'web/themes/custom',
  'web/themes/contrib',
  'web/profiles/custom',
  'web/sites',
  'web/.htaccess',
  'web/robots.txt',
  'web/index.php',
  'web/autoload.php',
  'web/update.php',
  'docroot/modules/custom',
  'docroot/themes/custom',
  'docroot/themes/contrib',
  'docroot/profiles/custom',
  'docroot/sites',
  'docroot/.htaccess',
  'docroot/robots.txt',
  'docroot/index.php',
  'docroot/autoload.php',
  'docroot/update.php',
  'modules/custom',
  'themes/custom',
  'themes/contrib',
  'profiles/custom',
  'sites',
  '.htaccess',
  'robots.txt',
  'index.php',
  'autoload.php',
  'update.php'
]);

const ROOT_RUNTIME_FILES = new Set([
  '.babelrc',
  '.browserslistrc',
  '.editorconfig',
  '.eslintignore',
  '.eslintrc',
  '.node-version',
  '.npmrc',
  '.nvmrc',
  '.prettierignore',
  '.prettierrc',
  '.stylelintrc',
  '.yarnrc',
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  '.travis.yml',
  '.travis.yaml',
  '.lando.yml',
  '.lando.yaml',
  'Makefile',
  'Jenkinsfile',
  'Procfile',
  'Taskfile.yml',
  'Taskfile.yaml',
  'acquia-pipelines.yml',
  'acquia-pipelines.yaml',
  'app.yaml',
  'app.yml',
  'azure-pipelines.yml',
  'azure-pipelines.yaml',
  'bitbucket-pipelines.yml',
  'bitbucket-pipelines.yaml',
  'bun.lock',
  'bun.lockb',
  'codecov.yml',
  'codecov.yaml',
  'deno.json',
  'deno.jsonc',
  'drush.yml',
  'deploy.php',
  'gulpfile.js',
  'gulpfile.cjs',
  'gulpfile.mjs',
  'gulpfile.ts',
  'gruntfile.js',
  'gruntfile.cjs',
  'gruntfile.mjs',
  'gruntfile.ts',
  'jsconfig.json',
  'npm-shrinkwrap.json',
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'settings.php',
  'services.yml',
  'services.yaml',
  'sonar-project.properties',
  'yarn.lock'
]);

const ROOT_TOOLING_EVIDENCE_FILES = new Set([
  '.editorconfig',
  '.eslintignore',
  '.eslintrc',
  '.prettierignore',
  '.prettierrc',
  '.stylelintrc',
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  '.travis.yml',
  '.travis.yaml',
  'acquia-pipelines.yml',
  'acquia-pipelines.yaml',
  'azure-pipelines.yml',
  'azure-pipelines.yaml',
  'bitbucket-pipelines.yml',
  'bitbucket-pipelines.yaml',
  'Jenkinsfile',
  'codecov.yml',
  'codecov.yaml',
  'sonar-project.properties'
]);

function rootRuntimeFile(name) {
  if (ROOT_RUNTIME_FILES.has(name)) {
    return true;
  }
  return (
    /^\.env(?:\..+)?$/.test(name) ||
    /^\.(?:eslint|prettier|stylelint)(?:ignore|rc(?:\..+)?)$/.test(name) ||
    /^\.yarnrc\./.test(name) ||
    /^settings(?:\.local)?\.php$/.test(name) ||
    /^services(?:\.local)?\.ya?ml$/.test(name) ||
    /^(?:tsconfig|jsconfig)(?:\.[^.]+)*\.json$/.test(name) ||
    /^(?:docker-compose)(?:\.[^.]+)*\.ya?ml$/.test(name) ||
    /^(?:phpcs|phpunit)(?:\.[^.]+)*(?:\.xml(?:\.dist)?)?$/.test(name) ||
    /^(?:phpstan)(?:\.[^.]+)*\.neon(?:\.dist)?$/.test(name) ||
    /^(?:rector)(?:\.config)?\.php$/.test(name) ||
    /^(?:vite|webpack|rollup|esbuild|postcss|tailwind|babel|eslint|prettier|stylelint|commitlint|astro|svelte|next|nuxt)\.config\.(?:js|cjs|mjs|ts|cts|mts|json|ya?ml)$/.test(name) ||
    /^[^.][^/]*\.config\.(?:js|cjs|mjs|ts|cts|mts|json|ya?ml)$/.test(name)
  );
}

function exactRuntimeExclusion(path) {
  const normalized = portablePath(path).replace(/^\.\//, '');
  return (
    normalized === '.git' || normalized.startsWith('.git/') ||
    normalized === 'vendor' || normalized.startsWith('vendor/') ||
    normalized === 'review-packet' || normalized.startsWith('review-packet/') ||
    normalized === '.agents/skills/agent-ready-drupal-build-kit' ||
    normalized.startsWith('.agents/skills/agent-ready-drupal-build-kit/') ||
    normalized === '.ddev/.gitignore' ||
    normalized === '.ddev/.ddev-docker-compose-base.yaml' ||
    normalized === '.ddev/.ddev-docker-compose-full.yaml' ||
    normalized === '.ddev/.router-compose.yaml' ||
    normalized.startsWith('.ddev/.dbimageBuild/') ||
    normalized.startsWith('.ddev/.webimageBuild/') ||
    normalized.startsWith('.ddev/.homeadditions/') ||
    /(?:^|\/)node_modules(?:\/|$)/.test(normalized) ||
    /^(?:web|docroot)\/core(?:\/|$)/.test(normalized) ||
    /^(?:web|docroot)\/(?:modules|profiles)\/contrib(?:\/|$)/.test(normalized) ||
    /^(?:(?:web|docroot)\/)?sites\/[^/]+\/(?:files|private)(?:\/|$)/.test(normalized)
  );
}

function runtimePathExcluded(path, metadata) {
  return exactRuntimeExclusion(path, metadata);
}

function machineLocalRuntimePath(path) {
  const normalized = portablePath(path).replace(/^\.\//, '');
  return (
    /^\.env(?:\.(?!example$|dist$|template$).+)?$/.test(normalized) ||
    normalized === '.npmrc' ||
    /^\.ddev\/config\.local\.ya?ml$/.test(normalized) ||
    /^\.ddev\/\.env(?:\..+)?$/.test(normalized) ||
    /^(?:(?:web|docroot)\/)?sites\/[^/]+\/(?:settings\.local\.php|services\.local\.ya?ml)$/.test(normalized) ||
    normalized === 'settings.local.php' ||
    normalized === 'services.local.yml' ||
    normalized === 'services.local.yaml'
  );
}

function toolingEvidencePath(path) {
  const normalized = portablePath(path).replace(/^\.\//, '');
  const name = normalized.split('/').at(-1) ?? '';
  return (
    ROOT_TOOLING_EVIDENCE_FILES.has(normalized) ||
    normalized === '.github' || normalized.startsWith('.github/') ||
    normalized === '.buildkite' || normalized.startsWith('.buildkite/') ||
    normalized === '.circleci' || normalized.startsWith('.circleci/') ||
    normalized === '.gitlab' || normalized.startsWith('.gitlab/') ||
    /^\.(?:eslint|prettier|stylelint)(?:ignore|rc(?:\..+)?)$/.test(name) ||
    /^(?:phpcs|phpunit)(?:\.[^.]+)*(?:\.xml(?:\.dist)?)?$/.test(name) ||
    /^(?:phpstan)(?:\.[^.]+)*\.neon(?:\.dist)?$/.test(name) ||
    /^(?:rector)(?:\.config)?\.php$/.test(name) ||
    /^(?:eslint|prettier|stylelint|commitlint)\.config\.(?:js|cjs|mjs|ts|cts|mts|json|ya?ml)$/.test(name)
  );
}

function projectLocalPatchPath(projectRoot, value, label) {
  if (typeof value !== 'string') {
    return '';
  }
  const candidate = value.trim().replaceAll('\\', '/');
  if (
    !candidate ||
    candidate.includes('\0') ||
    candidate.startsWith('//') ||
    /^[a-z][a-z0-9+.-]*:/i.test(candidate)
  ) {
    return '';
  }
  try {
    const safe = safeRelativePath(candidate, label);
    const absolute = resolve(projectRoot, safe);
    return isInside(projectRoot, absolute) ? safe : '';
  } catch {
    return '';
  }
}

function patchDefinitionUrls(value) {
  const urls = [];
  const patches = value?.patches;
  if (Array.isArray(patches)) {
    for (const patch of patches) {
      if (patch && typeof patch === 'object' && typeof patch.url === 'string') {
        urls.push(patch.url);
      }
    }
    return urls;
  }
  if (!patches || typeof patches !== 'object') {
    return urls;
  }
  for (const definitions of Object.values(patches)) {
    if (Array.isArray(definitions)) {
      for (const patch of definitions) {
        if (patch && typeof patch === 'object' && typeof patch.url === 'string') {
          urls.push(patch.url);
        }
      }
      continue;
    }
    if (!definitions || typeof definitions !== 'object') {
      continue;
    }
    for (const patch of Object.values(definitions)) {
      if (typeof patch === 'string') {
        urls.push(patch);
      } else if (patch && typeof patch === 'object' && typeof patch.url === 'string') {
        urls.push(patch.url);
      }
    }
  }
  return urls;
}

function composerPatchFiles(projectRoot) {
  const composerPath = resolve(projectRoot, 'composer.json');
  if (
    !existsSync(composerPath) ||
    lstatSync(composerPath).isSymbolicLink() ||
    !lstatSync(composerPath).isFile()
  ) {
    return [];
  }
  assertNoSymlinkAncestors(projectRoot, composerPath);
  let composer;
  try {
    composer = JSON.parse(readFileSync(composerPath, 'utf8'));
  } catch {
    // composer.json itself remains in the runtime manifest. Composer will
    // provide the authoritative parse error during installation.
    return [];
  }
  const discovered = new Set();
  const addLocal = (value, label) => {
    const local = projectLocalPatchPath(projectRoot, value, label);
    if (local) {
      discovered.add(local);
    }
    return local;
  };
  for (const url of patchDefinitionUrls({ patches: composer?.extra?.patches })) {
    addLocal(url, 'composer.json inline patch URL');
  }
  const patchesFiles = new Set();
  const visit = (value, path = []) => {
    if (!value || typeof value !== 'object') {
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      const nextPath = [...path, key];
      if (key === 'patches-file' && path[0] === 'extra') {
        for (const candidate of Array.isArray(child) ? child : [child]) {
          if (typeof candidate !== 'string' || !candidate.trim()) {
            continue;
          }
          const local = addLocal(candidate, `composer.json ${nextPath.join('.')} value`);
          if (local) {
            patchesFiles.add(local);
          }
        }
      }
      visit(child, nextPath);
    }
  };
  visit(composer);
  // Composer Patches defaults to patches.json. Keep the other conventional
  // filename for compatibility with existing Drupal project templates.
  for (const conventional of ['patches.json', 'composer.patches.json', 'patches.lock.json']) {
    if (existsSync(resolve(projectRoot, conventional))) {
      discovered.add(conventional);
      patchesFiles.add(conventional);
    }
  }
  for (const patchesFile of patchesFiles) {
    const path = resolve(projectRoot, patchesFile);
    if (
      !existsSync(path) ||
      lstatSync(path).isSymbolicLink() ||
      !lstatSync(path).isFile()
    ) {
      continue;
    }
    assertNoSymlinkAncestors(projectRoot, path);
    try {
      const definitions = JSON.parse(readFileSync(path, 'utf8'));
      for (const url of patchDefinitionUrls(definitions)) {
        addLocal(url, `${patchesFile} patch URL`);
      }
    } catch {
      // The declaration file itself remains bound. Composer supplies the
      // authoritative parse error if malformed JSON is used during install.
    }
  }
  return [...discovered].sort(comparePortable);
}

/**
 * Collect portable runtime/custom-code inputs. Secret-bearing settings and
 * local override files are included by path and digest only; their contents
 * are never returned.
 */
export function collectRuntimeCodeManifest(projectRoot) {
  const { realRoot } = rootEvidence(projectRoot);
  const patchInputs = composerPatchFiles(realRoot);
  const patchInputSet = new Set(patchInputs);
  const rootFiles = readdirSync(realRoot, { withFileTypes: true })
    .filter((entry) => (entry.isFile() || entry.isSymbolicLink()) && rootRuntimeFile(entry.name))
    .map((entry) => entry.name)
    .sort(comparePortable);
  const allInputs = collectFileManifestWithFilter(
    realRoot,
    [...new Set([...RUNTIME_CODE_PATHS, ...rootFiles, ...patchInputs])],
    (path, metadata) => !patchInputSet.has(path) && runtimePathExcluded(path, metadata)
  );
  const environmentManifest = hashManifest(allInputs.entries.filter((entry) => (
    !patchInputSet.has(entry.path) && machineLocalRuntimePath(entry.path)
  )));
  const projectEvidenceManifest = hashManifest(allInputs.entries.filter((entry) => (
    !patchInputSet.has(entry.path) && !machineLocalRuntimePath(entry.path) && toolingEvidencePath(entry.path)
  )));
  const runtimeManifest = hashManifest(allInputs.entries.filter((entry) => (
    patchInputSet.has(entry.path) || (!machineLocalRuntimePath(entry.path) && !toolingEvidencePath(entry.path))
  )));
  return {
    ...runtimeManifest,
    environmentBinding: {
      schemaVersion: 'public-kit.environment-binding.1',
      entryCount: environmentManifest.entryCount,
      fingerprint: environmentManifest.fingerprint
    },
    projectEvidenceBinding: {
      schemaVersion: 'public-kit.project-evidence-binding.1',
      entryCount: projectEvidenceManifest.entryCount,
      fingerprint: projectEvidenceManifest.fingerprint
    }
  };
}

function normalizedManifest(value, label) {
  if (Array.isArray(value)) {
    return hashManifest(value);
  }
  if (!value || typeof value !== 'object' || !Array.isArray(value.entries)) {
    throw new Error(`${label} must be a file manifest or manifest entry array.`);
  }
  const manifest = hashManifest(value.entries);
  if (value.fingerprint && normalizedHash(value.fingerprint, `${label} fingerprint`) !== manifest.fingerprint) {
    throw new Error(`${label} fingerprint does not match its entries.`);
  }
  return manifest;
}

function optionalFingerprint(value, label) {
  const text = String(value ?? '').trim();
  return text ? normalizedHash(text, label) : '';
}

function normalizedAggregateBinding(value, label, schemaVersion = 'public-kit.environment-binding.1') {
  if (!value) {
    return {
      schemaVersion,
      entryCount: 0,
      fingerprint: hashManifest([]).fingerprint
    };
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a digest-only aggregate binding.`);
  }
  const entryCount = Number(value.entryCount);
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) {
    throw new Error(`${label}.entryCount must be a non-negative integer.`);
  }
  return {
    schemaVersion: String(value.schemaVersion || schemaVersion),
    entryCount,
    fingerprint: normalizedHash(value.fingerprint, `${label}.fingerprint`)
  };
}

/**
 * Build a certifiable Drupal site-state fingerprint.
 *
 * Packet and verifier fingerprints are evidence bindings and deliberately do
 * not participate in the aggregate site fingerprint: upgrading the kit must
 * not make an otherwise unchanged Drupal site appear changed.
 */
export function buildSiteState({
  targetIdentity,
  configManifest,
  codeManifest,
  entityInventory,
  routeManifest,
  runtimeFacts = {},
  packetFingerprint = '',
  packetEvidenceManifest = null,
  verifierFingerprint = ''
}) {
  if (!targetIdentity || typeof targetIdentity !== 'object' || Array.isArray(targetIdentity)) {
    throw new Error('targetIdentity must be an object.');
  }
  const config = normalizedManifest(configManifest, 'configManifest');
  const code = normalizedManifest(codeManifest, 'codeManifest');
  const machineLocalEnvironment = normalizedAggregateBinding(
    codeManifest?.environmentBinding,
    'codeManifest.environmentBinding'
  );
  const projectEvidence = normalizedAggregateBinding(
    codeManifest?.projectEvidenceBinding,
    'codeManifest.projectEvidenceBinding',
    'public-kit.project-evidence-binding.1'
  );
  const packetEvidence = packetEvidenceManifest
    ? normalizedManifest(packetEvidenceManifest, 'packetEvidenceManifest')
    : null;
  const explicitPacketFingerprint = optionalFingerprint(packetFingerprint, 'packetFingerprint');
  if (packetEvidence && explicitPacketFingerprint && packetEvidence.fingerprint !== explicitPacketFingerprint) {
    throw new Error('packetFingerprint does not match packetEvidenceManifest.');
  }
  const routes = Array.isArray(routeManifest)
    ? canonicalValue(routeManifest)
    : (() => { throw new Error('routeManifest must be an array.'); })();
  const components = {
    targetIdentity: sha256(targetIdentity),
    configTree: config.fingerprint,
    runtimeCodeTree: code.fingerprint,
    runtimeFacts: sha256(runtimeFacts ?? {}),
    entityInventory: sha256(entityInventory ?? {}),
    routeManifest: sha256(routes)
  };
  const aggregateInput = {
    schemaVersion: SITE_STATE_SCHEMA,
    componentFingerprints: components
  };
  return {
    schemaVersion: SITE_STATE_SCHEMA,
    fingerprint: sha256(aggregateInput),
    componentFingerprints: components,
    targetIdentity: canonicalValue(targetIdentity),
    configManifest: config,
    codeManifest: code,
    entityInventory: canonicalValue(entityInventory ?? {}),
    entityInventoryFingerprint: components.entityInventory,
    routeManifest: routes,
    routeManifestFingerprint: components.routeManifest,
    evidenceBindings: {
      packetFingerprint: packetEvidence?.fingerprint ?? explicitPacketFingerprint,
      packetEvidenceManifest: packetEvidence,
      verifierFingerprint: optionalFingerprint(verifierFingerprint, 'verifierFingerprint'),
      machineLocalEnvironment,
      projectEvidence
    }
  };
}
