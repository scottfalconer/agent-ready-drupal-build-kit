import { randomUUID } from 'node:crypto';
import { posix } from 'node:path';

import { canonicalJson, sha256 } from './state-fingerprint.mjs';

export const REPRODUCTION_READBACK_SCHEMA = 'public-kit.reproduction-readback.1';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const MAX_MISMATCH_DETAILS = 200;

function comparePortable(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function normalizedHash(value, label) {
  const text = String(value ?? '').trim().toLowerCase();
  const digest = /^[a-f0-9]{64}$/.test(text) ? `sha256:${text}` : text;
  if (!HASH_RE.test(digest)) {
    throw new Error(`${label} must be a SHA-256 digest.`);
  }
  return digest;
}

function normalizedString(value, label) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${label} must not be empty.`);
  return text;
}

function normalizeRows(rows, { key, label, project }) {
  if (!Array.isArray(rows)) throw new Error(`${label} must be an array.`);
  const byKey = new Map();
  for (const [index, value] of rows.entries()) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`${label}[${index}] must be an object.`);
    }
    const row = project(value, index);
    const rowKey = normalizedString(row[key], `${label}[${index}].${key}`);
    if (byKey.has(rowKey)) throw new Error(`${label} contains duplicate ${key} ${rowKey}.`);
    byKey.set(rowKey, { ...row, [key]: rowKey });
  }
  return [...byKey.values()].sort((left, right) => comparePortable(left[key], right[key]));
}

function normalizedRoutePath(value, label = 'Route path') {
  const text = normalizedString(value, label);
  let url;
  try {
    url = new URL(text, 'https://agent-ready.invalid/');
  } catch {
    throw new Error(`${label} is not a usable path.`);
  }
  if (url.origin !== 'https://agent-ready.invalid' || !text.startsWith('/')) {
    throw new Error(`${label} must be a project-relative HTTP path.`);
  }
  url.hash = '';
  return `${url.pathname}${url.search}`;
}

function normalizedConfigSyncDirectory(value, drupalRoot = '') {
  const text = normalizedString(value, 'Drupal config sync directory')
    .replaceAll('\\', '/')
    .replace(/\/$/, '');
  const root = String(drupalRoot ?? '').trim().replaceAll('\\', '/').replace(/\/$/, '');
  const resolved = text.startsWith('/') || !root.startsWith('/') ? text : posix.resolve(root, text);
  return resolved.replace(/^\/var\/www\/html\//, '').replace(/^\.\//, '');
}

function entityTypes(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Drupal reproduction readback entities.types must be an object.');
  }
  return Object.fromEntries(Object.entries(value)
    .map(([entityType, type]) => {
      const name = normalizedString(entityType, 'Entity type name');
      const items = normalizeRows(type?.items, {
        key: 'stableId',
        label: `entities.types.${name}.items`,
        project: (row, index) => ({
          stableId: row.stableId,
          bundle: String(row.bundle ?? ''),
          sha256: normalizedHash(row.sha256, `entities.types.${name}.items[${index}].sha256`)
        })
      });
      return [name, {
        count: items.length,
        items,
        fingerprint: sha256(items)
      }];
    })
    .sort(([left], [right]) => comparePortable(left, right)));
}

/**
 * Normalize verifier-owned Drupal facts and bind every comparison component.
 * Raw field/config values never leave Drupal; only stable identifiers and
 * digests are retained here.
 */
export function buildPortableReproductionState({
  config,
  configStatusClean,
  configSyncDirectory,
  drupalRoot = '',
  confirmed,
  entities,
  errors = [],
  managedFiles,
  routes,
  siteUuid
}) {
  const configItems = normalizeRows(config?.items, {
    key: 'name',
    label: 'config.items',
    project: (row, index) => ({
      name: row.name,
      sha256: normalizedHash(row.sha256, `config.items[${index}].sha256`)
    })
  });
  const types = entityTypes(entities?.types);
  const entityItems = Object.entries(types).flatMap(([entityType, value]) => (
    value.items.map((item) => ({ entityType, ...item }))
  ));
  const fileItems = normalizeRows(managedFiles?.items, {
    key: 'stableId',
    label: 'managedFiles.items',
    project: (row, index) => ({
      stableId: row.stableId,
      scheme: normalizedString(row.scheme, `managedFiles.items[${index}].scheme`),
      uriSha256: normalizedHash(row.uriSha256, `managedFiles.items[${index}].uriSha256`),
      bytesSha256: normalizedHash(row.bytesSha256, `managedFiles.items[${index}].bytesSha256`),
      size: (() => {
        const size = Number(row.size);
        if (!Number.isSafeInteger(size) || size < 0) {
          throw new Error(`managedFiles.items[${index}].size must be a non-negative integer.`);
        }
        return size;
      })()
    })
  });
  const routeItems = normalizeRows(routes, {
    key: 'path',
    label: 'routes',
    project: (row, index) => ({
      path: normalizedRoutePath(row.path, `routes[${index}].path`),
      status: (() => {
        const status = Number(row.status);
        if (!Number.isInteger(status) || status < 100 || status > 599) {
          throw new Error(`routes[${index}].status must be an HTTP status.`);
        }
        return status;
      })(),
      finalPath: normalizedRoutePath(row.finalPath, `routes[${index}].finalPath`),
      titleSha256: normalizedHash(row.titleSha256, `routes[${index}].titleSha256`),
      h1Sha256: normalizedHash(row.h1Sha256, `routes[${index}].h1Sha256`),
      bodyTextSha256: normalizedHash(row.bodyTextSha256, `routes[${index}].bodyTextSha256`),
      redirectChainSha256: normalizedHash(
        row.redirectChainSha256 ?? sha256([]),
        `routes[${index}].redirectChainSha256`
      ),
      bodyTextLength: (() => {
        const length = Number(row.bodyTextLength);
        if (!Number.isSafeInteger(length) || length < 0) {
          throw new Error(`routes[${index}].bodyTextLength must be a non-negative integer.`);
        }
        return length;
      })()
    })
  });
  const normalizedErrors = [...new Set((Array.isArray(errors) ? errors : [])
    .map((error) => String(error ?? '').trim())
    .filter(Boolean))].sort(comparePortable);
  const components = {
    activeConfig: sha256(configItems),
    stableEntities: sha256(entityItems),
    managedFileBytes: sha256(fileItems),
    publicRoutes: sha256(routeItems)
  };
  const state = {
    schemaVersion: REPRODUCTION_READBACK_SCHEMA,
    confirmed: confirmed === true && normalizedErrors.length === 0,
    errors: normalizedErrors,
    siteUuid: normalizedString(siteUuid, 'Drupal site UUID').toLowerCase(),
    configSyncDirectory: normalizedConfigSyncDirectory(configSyncDirectory, drupalRoot),
    configStatusClean: configStatusClean === true,
    config: {
      count: configItems.length,
      items: configItems,
      fingerprint: components.activeConfig
    },
    entities: {
      count: entityItems.length,
      typeCount: Object.keys(types).length,
      types,
      fingerprint: components.stableEntities
    },
    managedFiles: {
      count: fileItems.length,
      items: fileItems,
      fingerprint: components.managedFileBytes
    },
    routes: routeItems,
    routeCount: routeItems.length,
    componentFingerprints: components
  };
  return {
    ...state,
    fingerprint: sha256({
      schemaVersion: REPRODUCTION_READBACK_SCHEMA,
      siteUuid: state.siteUuid,
      configSyncDirectory: state.configSyncDirectory,
      configStatusClean: state.configStatusClean,
      componentFingerprints: components
    })
  };
}

function rowDifferences(leftRows, rightRows, key, fields, component) {
  const differences = [];
  const left = new Map(leftRows.map((row) => [row[key], row]));
  const right = new Map(rightRows.map((row) => [row[key], row]));
  for (const rowKey of [...new Set([...left.keys(), ...right.keys()])].sort(comparePortable)) {
    if (differences.length >= MAX_MISMATCH_DETAILS) break;
    if (!left.has(rowKey)) {
      differences.push({ component, key: rowKey, kind: 'unexpected' });
      continue;
    }
    if (!right.has(rowKey)) {
      differences.push({ component, key: rowKey, kind: 'missing' });
      continue;
    }
    const changedFields = fields.filter((field) => canonicalJson(left.get(rowKey)[field]) !== canonicalJson(right.get(rowKey)[field]));
    if (changedFields.length > 0) differences.push({ component, key: rowKey, kind: 'changed', fields: changedFields });
  }
  return differences;
}

/** Compare expected working-target state to a disposable or post-run state. */
export function comparePortableReproductionStates(expected, actual) {
  const details = [];
  details.push(...rowDifferences(expected.config.items, actual.config.items, 'name', ['sha256'], 'activeConfig'));
  const expectedEntities = Object.entries(expected.entities.types).flatMap(([entityType, type]) => (
    type.items.map((row) => ({ ...row, key: `${entityType}:${row.stableId}` }))
  ));
  const actualEntities = Object.entries(actual.entities.types).flatMap(([entityType, type]) => (
    type.items.map((row) => ({ ...row, key: `${entityType}:${row.stableId}` }))
  ));
  details.push(...rowDifferences(expectedEntities, actualEntities, 'key', ['bundle', 'sha256'], 'stableEntities'));
  details.push(...rowDifferences(
    expected.managedFiles.items,
    actual.managedFiles.items,
    'stableId',
    ['scheme', 'uriSha256', 'bytesSha256', 'size'],
    'managedFileBytes'
  ));
  details.push(...rowDifferences(
    expected.routes,
    actual.routes,
    'path',
    ['status', 'finalPath', 'titleSha256', 'h1Sha256', 'bodyTextSha256', 'bodyTextLength', 'redirectChainSha256'],
    'publicRoutes'
  ));
  for (const [field, component] of [
    ['siteUuid', 'siteUuid'],
    ['configSyncDirectory', 'configSyncDirectory'],
    ['configStatusClean', 'configStatusClean']
  ]) {
    if (canonicalJson(expected[field]) !== canonicalJson(actual[field])) {
      details.push({ component, kind: 'changed', fields: [field] });
    }
  }
  if (expected.confirmed !== true) details.push({ component: 'expectedReadback', kind: 'unconfirmed' });
  if (actual.confirmed !== true) details.push({ component: 'actualReadback', kind: 'unconfirmed' });
  const exactFingerprintMatch = expected.fingerprint === actual.fingerprint;
  const match = exactFingerprintMatch && details.length === 0;
  return {
    schemaVersion: 'public-kit.reproduction-comparison.1',
    match,
    expectedFingerprint: expected.fingerprint,
    actualFingerprint: actual.fingerprint,
    componentMatches: Object.fromEntries(Object.keys(expected.componentFingerprints).map((component) => [
      component,
      expected.componentFingerprints[component] === actual.componentFingerprints[component]
    ])),
    mismatchCount: details.length,
    mismatchesTruncated: details.length >= MAX_MISMATCH_DETAILS,
    mismatches: details.slice(0, MAX_MISMATCH_DETAILS)
  };
}

function decodeHtmlEntities(value) {
  return String(value)
    .replace(/&#(\d+);/g, (_, code) => String.fromCodePoint(Number(code)))
    .replace(/&#x([a-f0-9]+);/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (_, name) => ({
      amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' '
    })[name.toLowerCase()]);
}

function visibleText(html, origin) {
  const escapedOrigin = String(origin).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const originNeutral = escapedOrigin
    ? String(html).replace(new RegExp(escapedOrigin, 'gi'), '<target-origin>')
    : String(html);
  return decodeHtmlEntities(originNeutral
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<[^>]+>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

function firstElementText(html, tag) {
  const match = String(html).match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}\\s*>`, 'i'));
  return match ? visibleText(match[1], '') : '';
}

/** Convert an HTTP response into an origin-independent route record. */
export function normalizeRouteResponse({ body, effectiveUrl, origin, path, redirects = [], status }) {
  const final = new URL(effectiveUrl);
  if (final.origin !== origin) throw new Error(`Route ${path} left the DDEV target origin.`);
  const text = visibleText(body, origin);
  return {
    path: normalizedRoutePath(path),
    status: Number(status),
    finalPath: `${final.pathname}${final.search}`,
    titleSha256: sha256(firstElementText(body, 'title')),
    h1Sha256: sha256(firstElementText(body, 'h1')),
    bodyTextSha256: sha256(text),
    bodyTextLength: text.length,
    redirectChainSha256: sha256(redirects)
  };
}

function recursiveStringForKey(value, keys) {
  if (!value || typeof value !== 'object') return '';
  for (const [key, child] of Object.entries(value)) {
    if (keys.has(key) && typeof child === 'string' && child.trim()) return child.trim();
  }
  for (const child of Object.values(value)) {
    const found = recursiveStringForKey(child, keys);
    if (found) return found;
  }
  return '';
}

function configStatusIsClean(output) {
  const text = String(output ?? '').trim();
  if (!text) return true;
  try {
    const parsed = JSON.parse(text);
    return (Array.isArray(parsed) && parsed.length === 0) || (
      parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length === 0
    );
  } catch {
    return false;
  }
}

export const DRUPAL_REPRODUCTION_READBACK_EVAL = String.raw`
$normalize = function ($value) use (&$normalize) {
  if (!is_array($value)) return $value;
  if (!array_is_list($value)) ksort($value, SORT_STRING);
  foreach ($value as $key => $child) $value[$key] = $normalize($child);
  return $value;
};
$encode = static function ($value): string {
  $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
  return $encoded === FALSE ? serialize($value) : $encoded;
};
$digest = static fn ($value): string => 'sha256:' . hash('sha256', $value);
$errors = [];

// Active storage, including non-default collections, is hashed without
// emitting values. Config-sync bytes are independently bound by the Node
// verifier before provisioning.
$storage = \Drupal::service('config.storage');
$collections = array_merge([''], method_exists($storage, 'getAllCollectionNames') ? $storage->getAllCollectionNames() : []);
$collections = array_values(array_unique(array_map('strval', $collections)));
sort($collections, SORT_STRING);
$config_items = [];
foreach ($collections as $collection) {
  $collection_storage = $collection === '' ? $storage : $storage->createCollection($collection);
  $names = $collection_storage->listAll();
  sort($names, SORT_STRING);
  foreach ($names as $name) {
    $data = $normalize($collection_storage->read($name));
    $config_items[] = [
      'name' => ($collection === '' ? '' : $collection . ':') . $name,
      'sha256' => $digest($encode($data)),
    ];
  }
}

$manager = \Drupal::entityTypeManager();
$definitions = $manager->getDefinitions();
$excluded_types = array_fill_keys([
  'user', 'webform_submission', 'contact_message', 'easy_email',
  'oauth2_token', 'oauth2_refresh_token', 'oauth2_auth_code',
  'simple_oauth_token', 'simple_oauth_refresh_token', 'simple_oauth_auth_code',
  'search_api_task', 'content_moderation_state', 'workspace', 'workspace_association',
  'commerce_order', 'commerce_order_item', 'commerce_payment',
  'commerce_payment_method', 'commerce_log', 'consumer'
], TRUE);
$limit_per_type = 10000;
$entities_by_type = [];
$stable_ids = [];
$loaded_by_type = [];
foreach ($definitions as $entity_type_id => $definition) {
  if (!($definition instanceof \Drupal\Core\Entity\ContentEntityTypeInterface) || isset($excluded_types[$entity_type_id])) continue;
  try {
    $storage_handler = $manager->getStorage($entity_type_id);
    $query = $storage_handler->getQuery()->accessCheck(FALSE);
    $count = (int) $query->count()->execute();
    if ($count > $limit_per_type) {
      $errors[] = 'Entity type ' . $entity_type_id . ' exceeds the portable reproduction limit of ' . $limit_per_type . '.';
      continue;
    }
    $id_key = $definition->getKey('id');
    $id_query = $storage_handler->getQuery()->accessCheck(FALSE);
    if ($id_key) $id_query->sort($id_key, 'ASC');
    $ids = array_values($id_query->execute());
    $loaded_by_type[$entity_type_id] = $storage_handler->loadMultiple($ids);
    foreach ($loaded_by_type[$entity_type_id] as $entity) {
      $id = (string) $entity->id();
      $uuid = method_exists($entity, 'uuid') ? strtolower((string) $entity->uuid()) : '';
      if ($uuid !== '') {
        $stable_ids[$entity_type_id][$id] = 'uuid:' . $uuid;
      }
      elseif ($id !== '' && !ctype_digit($id)) {
        $stable_ids[$entity_type_id][$id] = 'id:' . $id;
      }
      else {
        $errors[] = 'Entity ' . $entity_type_id . ':' . $digest($id) . ' has no portable stable identifier.';
      }
    }
  }
  catch (\Throwable $exception) {
    $errors[] = 'Entity type ' . $entity_type_id . ' could not be read for portable reproduction.';
  }
}

foreach ($loaded_by_type as $entity_type_id => $entities) {
  $definition = $definitions[$entity_type_id];
  $id_key = (string) ($definition->getKey('id') ?? '');
  $revision_key = (string) ($definition->getKey('revision') ?? '');
  $items = [];
  foreach ($entities as $entity) {
    $entity_id = (string) $entity->id();
    $stable_id = $stable_ids[$entity_type_id][$entity_id] ?? '';
    if ($stable_id === '') continue;
    $languages = method_exists($entity, 'getTranslationLanguages')
      ? array_keys($entity->getTranslationLanguages(TRUE))
      : [(string) $entity->language()->getId()];
    sort($languages, SORT_STRING);
    $translations = [];
    foreach ($languages as $langcode) {
      $translation = method_exists($entity, 'hasTranslation') && $entity->hasTranslation($langcode)
        ? $entity->getTranslation($langcode)
        : $entity;
      $projected = [];
      foreach ($translation->getFieldDefinitions() as $field_name => $field_definition) {
        if ($field_name === $id_key || ($revision_key !== '' && $field_name === $revision_key) || $field_definition->isComputed()) continue;
        if (!$translation->hasField($field_name)) continue;
        $field_type = (string) $field_definition->getType();
        $target_type = in_array($field_type, ['file', 'image'], TRUE)
          ? 'file'
          : (string) ($field_definition->getSetting('target_type') ?? '');
        if ($target_type !== '' && isset($excluded_types[$target_type])) continue;
        $values = $translation->get($field_name)->getValue();
        if ($target_type !== '') {
          foreach ($values as $delta => $item) {
            if (!is_array($item) || !array_key_exists('target_id', $item)) continue;
            $target_id = (string) $item['target_id'];
            unset($item['target_id'], $item['target_revision_id']);
            $target_stable = $stable_ids[$target_type][$target_id] ?? '';
            if (
              $target_stable === '' &&
              ($definitions[$target_type] ?? NULL) instanceof \Drupal\Core\Config\Entity\ConfigEntityTypeInterface &&
              $target_id !== ''
            ) {
              $target_stable = 'id:' . $target_id;
            }
            if ($target_stable === '') {
              $errors[] = 'Entity reference from ' . $entity_type_id . ':' . $stable_id . ' to ' . $target_type . ' lacks a stable target.';
              $target_stable = 'missing-stable-target';
            }
            $values[$delta] = ['targetStableId' => $target_stable] + $item;
          }
        }
        $projected[(string) $field_name] = $normalize($values);
      }
      ksort($projected, SORT_STRING);
      $translations[(string) $langcode] = $digest($encode($projected));
    }
    ksort($translations, SORT_STRING);
    $record = [
      'stableId' => $stable_id,
      'bundle' => method_exists($entity, 'bundle') ? (string) $entity->bundle() : '',
      'translations' => $translations,
    ];
    $items[] = [
      'stableId' => $stable_id,
      'bundle' => $record['bundle'],
      'sha256' => $digest($encode($record)),
    ];
  }
  usort($items, static fn ($left, $right): int => strcmp($left['stableId'], $right['stableId']));
  $entities_by_type[(string) $entity_type_id] = ['items' => $items];
}
ksort($entities_by_type, SORT_STRING);

$managed_files = [];
foreach ($loaded_by_type['file'] ?? [] as $file) {
  $id = (string) $file->id();
  $stable_id = $stable_ids['file'][$id] ?? '';
  if ($stable_id === '') continue;
  $uri = method_exists($file, 'getFileUri') ? (string) $file->getFileUri() : '';
  $scheme = (string) (\Drupal\Core\StreamWrapper\StreamWrapperManager::getScheme($uri) ?? '');
  if (!in_array($scheme, ['public', 'private'], TRUE)) {
    $errors[] = 'Managed file ' . $stable_id . ' uses unsupported or mutable scheme ' . ($scheme === '' ? '(none)' : $scheme) . '.';
    continue;
  }
  $handle = @fopen($uri, 'rb');
  if (!is_resource($handle)) {
    $errors[] = 'Managed file bytes are missing for ' . $stable_id . '.';
    continue;
  }
  $context = hash_init('sha256');
  $size = hash_update_stream($context, $handle);
  fclose($handle);
  $managed_files[] = [
    'stableId' => $stable_id,
    'scheme' => $scheme,
    'uriSha256' => $digest($uri),
    'bytesSha256' => 'sha256:' . hash_final($context),
    'size' => (int) $size,
  ];
}
usort($managed_files, static fn ($left, $right): int => strcmp($left['stableId'], $right['stableId']));
sort($errors, SORT_STRING);
print json_encode([
  'schemaVersion' => 'public-kit.reproduction-drupal-facts.1',
  'confirmed' => count($errors) === 0,
  'errors' => $errors,
  'siteUuid' => strtolower((string) (\Drupal::config('system.site')->get('uuid') ?? '')),
  'config' => ['items' => $config_items],
  'entities' => ['types' => $entities_by_type],
  'managedFiles' => ['items' => $managed_files],
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;

function runChecked(execute, command, args, options) {
  const result = execute(command, args, options);
  if (!result || result.status !== 0) {
    const summary = String(result?.stderr ?? result?.error?.message ?? 'command failed').trim().split(/\r?\n/)[0];
    throw new Error(`${options.phase}: ${command} ${args.join(' ')} failed${summary ? `: ${summary}` : ''}`);
  }
  return String(result.stdout ?? '');
}

/** Read active config/content/files and the declared public routes from one DDEV target. */
export function capturePortableDrupalState({ execute, projectRoot, routes, target }) {
  const factsOutput = runChecked(execute, 'ddev', ['drush', 'php:eval', DRUPAL_REPRODUCTION_READBACK_EVAL], {
    cwd: projectRoot,
    phase: 'portable-drupal-readback',
    target,
    timeout: 120_000,
    recordedArgs: ['drush', 'php:eval', `<verifier-owned:${sha256(DRUPAL_REPRODUCTION_READBACK_EVAL)}>`]
  });
  let facts;
  try {
    facts = JSON.parse(factsOutput);
  } catch {
    throw new Error(`${target} portable Drupal readback returned invalid JSON.`);
  }
  if (facts?.schemaVersion !== 'public-kit.reproduction-drupal-facts.1') {
    throw new Error(`${target} portable Drupal readback returned an unsupported schema.`);
  }
  const configStatus = runChecked(execute, 'ddev', ['drush', 'config:status', '--format=json'], {
    cwd: projectRoot,
    phase: 'config-status-readback',
    target,
    timeout: 30_000
  });
  const configSyncDirectory = runChecked(execute, 'ddev', ['drush', 'status', '--field=config-sync'], {
    cwd: projectRoot,
    phase: 'config-sync-readback',
    target,
    timeout: 30_000
  }).trim();
  const drupalRoot = runChecked(execute, 'ddev', ['drush', 'status', '--field=root'], {
    cwd: projectRoot,
    phase: 'drupal-root-readback',
    target,
    timeout: 30_000
  }).trim();
  const descriptionOutput = runChecked(execute, 'ddev', ['describe', '-j'], {
    cwd: projectRoot,
    phase: 'target-url-readback',
    target,
    timeout: 20_000
  });
  let description;
  try {
    description = JSON.parse(descriptionOutput);
  } catch {
    throw new Error(`${target} DDEV description returned invalid JSON.`);
  }
  const baseUrl = recursiveStringForKey(description, new Set(['primary_url', 'primaryUrl']));
  let origin;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    throw new Error(`${target} DDEV description did not provide a valid primary URL.`);
  }
  const routeReadback = routes.map((path) => {
    const routePath = normalizedRoutePath(path);
    let requestUrl = new URL(routePath.replace(/^\//, ''), `${origin}/`).href;
    const redirects = [];
    for (let hop = 0; hop <= 10; hop += 1) {
      const marker = `__AGENT_READY_ROUTE_META_${randomUUID()}__`;
      const output = runChecked(execute, 'curl', [
        '--insecure', '--silent', '--show-error', '--max-time', '30', '--max-filesize', '5242880',
        '--write-out', `\n${marker}%{http_code}\t%{url_effective}\t%{redirect_url}`,
        requestUrl
      ], {
        cwd: projectRoot,
        phase: `public-route-readback:${routePath}:hop-${hop}`,
        target,
        timeout: 40_000
      });
      const markerIndex = output.lastIndexOf(`\n${marker}`);
      if (markerIndex < 0) throw new Error(`${target} route ${routePath} did not return curl metadata.`);
      const body = output.slice(0, markerIndex);
      const [statusText, effectiveUrl, redirectUrl = ''] = output.slice(markerIndex + marker.length + 1).trim().split('\t');
      const status = Number(statusText);
      if (status >= 300 && status < 400 && redirectUrl) {
        const next = new URL(redirectUrl, effectiveUrl);
        if (next.origin !== origin) throw new Error(`${target} route ${routePath} redirects outside the DDEV target origin.`);
        redirects.push({
          status,
          from: `${new URL(effectiveUrl).pathname}${new URL(effectiveUrl).search}`,
          to: `${next.pathname}${next.search}`
        });
        requestUrl = next.href;
        continue;
      }
      return normalizeRouteResponse({ body, effectiveUrl, origin, path: routePath, redirects, status });
    }
    throw new Error(`${target} route ${routePath} exceeded 10 same-origin redirects.`);
  });
  return buildPortableReproductionState({
    ...facts,
    configStatusClean: configStatusIsClean(configStatus),
    configSyncDirectory,
    drupalRoot,
    routes: routeReadback
  });
}
