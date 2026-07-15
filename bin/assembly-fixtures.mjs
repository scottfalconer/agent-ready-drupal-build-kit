import { randomUUID } from 'node:crypto';

import { assemblyTargetKey, parseAssemblyTarget } from './assembly-contract.mjs';
import { boundedFailureDetail } from './disposable-ddev.mjs';
import { sha256 } from './state-fingerprint.mjs';

export const ASSEMBLY_CAPABILITIES_SCHEMA = 'public-kit.assembly-capabilities.1';
export const ASSEMBLY_FIXTURES_SCHEMA = 'public-kit.assembly-fixtures.1';
export const ASSEMBLY_FIXTURE_IDENTITY_SCHEMA = 'public-kit.assembly-fixture-identity.1';
const MAX_CAPABILITY_ROWS = 20_000;

function comparePortable(left, right) {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function assertExactKeys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort(comparePortable);
  if (unknown.length > 0) throw new Error(`${label} contains unsupported field(s): ${unknown.join(', ')}.`);
}

function sortedUniqueStrings(value, label) {
  if (!Array.isArray(value) || value.length > MAX_CAPABILITY_ROWS) throw new Error(`${label} must be a bounded array.`);
  const rows = value.map((row, index) => {
    const text = String(row ?? '').trim();
    if (!text) throw new Error(`${label}[${index}] must not be empty.`);
    return text;
  });
  if (new Set(rows).size !== rows.length) throw new Error(`${label} contains duplicates.`);
  return rows.sort(comparePortable);
}

function parseStringMap(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => comparePortable(left, right)).map(([key, rows]) => [
    String(key), sortedUniqueStrings(rows, `${label}.${key}`)
  ]));
}

export function parseAssemblyCapabilities(value) {
  assertExactKeys(value, [
    'schemaVersion', 'entityTypes', 'bundleKeys', 'bundles', 'nodeBundles', 'menus',
    'viewsAvailable', 'canvasEntityTypes', 'canvasComponentConfigs', 'sitemapConfigs'
  ], 'Assembly capabilities');
  if (value.schemaVersion !== ASSEMBLY_CAPABILITIES_SCHEMA) {
    throw new Error(`Assembly capabilities schemaVersion must be ${ASSEMBLY_CAPABILITIES_SCHEMA}.`);
  }
  const entityTypes = sortedUniqueStrings(value.entityTypes, 'Assembly capabilities entityTypes');
  const bundleKeys = (() => {
    if (!value.bundleKeys || typeof value.bundleKeys !== 'object' || Array.isArray(value.bundleKeys)) {
      throw new Error('Assembly capabilities bundleKeys must be an object.');
    }
    return Object.fromEntries(Object.entries(value.bundleKeys).sort(([left], [right]) => comparePortable(left, right)).map(([key, child]) => [
      String(key), String(child ?? '')
    ]));
  })();
  const capabilities = {
    schemaVersion: ASSEMBLY_CAPABILITIES_SCHEMA,
    entityTypes,
    bundleKeys,
    bundles: parseStringMap(value.bundles, 'Assembly capabilities bundles'),
    nodeBundles: sortedUniqueStrings(value.nodeBundles, 'Assembly capabilities nodeBundles'),
    menus: sortedUniqueStrings(value.menus, 'Assembly capabilities menus'),
    viewsAvailable: value.viewsAvailable === true,
    canvasEntityTypes: sortedUniqueStrings(value.canvasEntityTypes, 'Assembly capabilities canvasEntityTypes'),
    canvasComponentConfigs: sortedUniqueStrings(value.canvasComponentConfigs, 'Assembly capabilities canvasComponentConfigs'),
    sitemapConfigs: sortedUniqueStrings(value.sitemapConfigs, 'Assembly capabilities sitemapConfigs')
  };
  const aggregateRows = (
    capabilities.entityTypes.length + Object.keys(capabilities.bundleKeys).length +
    Object.values(capabilities.bundles).reduce((sum, rows) => sum + rows.length, 0) +
    capabilities.nodeBundles.length + capabilities.menus.length + capabilities.canvasEntityTypes.length +
    capabilities.canvasComponentConfigs.length + capabilities.sitemapConfigs.length
  );
  if (aggregateRows > MAX_CAPABILITY_ROWS) {
    throw new Error(`Assembly capabilities exceed the aggregate limit of ${MAX_CAPABILITY_ROWS} rows.`);
  }
  capabilities.applicable = {
    node: entityTypes.includes('node') && capabilities.nodeBundles.length > 0,
    menu: entityTypes.includes('menu_link_content') && capabilities.menus.length > 0,
    alias: entityTypes.includes('path_alias'),
    view: capabilities.viewsAvailable,
    canvas: capabilities.canvasEntityTypes.length > 0 || capabilities.canvasComponentConfigs.length > 0,
    sitemap: capabilities.sitemapConfigs.length > 0
  };
  return capabilities;
}

export const DRUPAL_ASSEMBLY_CAPABILITIES_EVAL = String.raw`
$manager = \Drupal::entityTypeManager();
$definitions = $manager->getDefinitions();
$entity_types = array_keys($definitions);
sort($entity_types, SORT_STRING);
$bundle_keys = [];
$bundles = [];
$bundle_info = \Drupal::service('entity_type.bundle.info');
foreach ($definitions as $entity_type_id => $definition) {
  $bundle_keys[$entity_type_id] = (string) ($definition->getKey('bundle') ?? '');
  try {
    $names = array_keys($bundle_info->getBundleInfo($entity_type_id));
    sort($names, SORT_STRING);
    $bundles[$entity_type_id] = $names;
  }
  catch (\Throwable $exception) {
    $bundles[$entity_type_id] = [];
  }
}
ksort($bundle_keys, SORT_STRING);
ksort($bundles, SORT_STRING);
$storage = \Drupal::service('config.storage');
$config_names = $storage->listAll();
sort($config_names, SORT_STRING);
$menus = [];
$canvas_configs = [];
$sitemap_configs = [];
foreach ($config_names as $name) {
  if (str_starts_with($name, 'system.menu.')) $menus[] = substr($name, strlen('system.menu.'));
  if (preg_match('/^(?:canvas|experience_builder)\.component\./', $name)) $canvas_configs[] = $name;
  if (preg_match('/^(?:simple_sitemap\.(?:sitemap|type)\.|xmlsitemap\.)/', $name)) $sitemap_configs[] = $name;
}
$canvas_entity_types = [];
foreach ($entity_types as $entity_type_id) {
  if (
    $definitions[$entity_type_id] instanceof \Drupal\Core\Entity\ContentEntityTypeInterface &&
    ($entity_type_id === 'canvas_page' || preg_match('/(?:canvas|experience_builder|^xb_)/', $entity_type_id))
  ) {
    $canvas_entity_types[] = $entity_type_id;
  }
}
sort($menus, SORT_STRING);
sort($canvas_configs, SORT_STRING);
sort($sitemap_configs, SORT_STRING);
sort($canvas_entity_types, SORT_STRING);
print json_encode([
  'schemaVersion' => 'public-kit.assembly-capabilities.1',
  'entityTypes' => $entity_types,
  'bundleKeys' => $bundle_keys,
  'bundles' => $bundles,
  'nodeBundles' => $bundles['node'] ?? [],
  'menus' => $menus,
  'viewsAvailable' => \Drupal::moduleHandler()->moduleExists('views'),
  'canvasEntityTypes' => $canvas_entity_types,
  'canvasComponentConfigs' => $canvas_configs,
  'sitemapConfigs' => $sitemap_configs,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;

function runEval(execute, projectRoot, target, phase, source, timeout = 120_000) {
  const result = execute('ddev', ['drush', 'php:eval', source], {
    cwd: projectRoot,
    phase,
    target,
    timeout,
    recordedArgs: ['drush', 'php:eval', `<verifier-owned:${sha256(source)}>`]
  });
  if (!result || result.status !== 0) {
    const detail = boundedFailureDetail(result);
    throw new Error(`${phase} failed${detail ? `: ${detail}` : ''}`);
  }
  return String(result.stdout ?? '');
}

export function discoverAssemblyCapabilities({ execute, projectRoot, target = 'disposable' }) {
  const output = runEval(
    execute,
    projectRoot,
    target,
    'assembly-capability-readback',
    DRUPAL_ASSEMBLY_CAPABILITIES_EVAL
  );
  let value;
  try {
    value = JSON.parse(output);
  } catch {
    throw new Error('Assembly capability readback returned invalid JSON.');
  }
  return parseAssemblyCapabilities(value);
}

function requireDisposition(surface, declaration, applicable) {
  if (applicable && declaration.status !== 'required') {
    throw new Error(`Extension fixture surface ${surface} is live/applicable but the assembly plan declares it not_applicable.`);
  }
  if (!applicable && declaration.status === 'required') {
    throw new Error(`Extension fixture surface ${surface} is required by the plan but unavailable in the live substrate.`);
  }
}

/** Bind applicability to the live disposable substrate, never to packet prose. */
export function assertFixturePlanAgainstCapabilities(fixtures, capabilities) {
  for (const surface of ['node', 'menu', 'alias', 'view', 'canvas', 'sitemap']) {
    requireDisposition(surface, fixtures[surface], capabilities.applicable[surface]);
  }
  if (fixtures.node.status === 'required' && !capabilities.nodeBundles.includes(fixtures.node.bundle)) {
    throw new Error(`Declared node fixture bundle ${fixtures.node.bundle} is unavailable in the live substrate.`);
  }
  if (fixtures.menu.status === 'required' && !capabilities.menus.includes(fixtures.menu.menuName)) {
    throw new Error(`Declared menu fixture ${fixtures.menu.menuName} is unavailable in the live substrate.`);
  }
  if (fixtures.canvas.status === 'required') {
    if (!capabilities.canvasEntityTypes.includes(fixtures.canvas.pageEntityType)) {
      throw new Error(`Declared Canvas page entity type ${fixtures.canvas.pageEntityType} is unavailable.`);
    }
    if (!capabilities.canvasComponentConfigs.includes(fixtures.canvas.componentConfigName)) {
      throw new Error(`Declared Canvas component config ${fixtures.canvas.componentConfigName} is unavailable.`);
    }
    const bundleKey = capabilities.bundleKeys[fixtures.canvas.pageEntityType] ?? '';
    const bundles = capabilities.bundles[fixtures.canvas.pageEntityType] ?? [];
    if (bundleKey && (!fixtures.canvas.pageBundle || !bundles.includes(fixtures.canvas.pageBundle))) {
      throw new Error(`Canvas page entity type ${fixtures.canvas.pageEntityType} requires a live declared pageBundle.`);
    }
    if (!bundleKey && fixtures.canvas.pageBundle) {
      throw new Error(`Canvas page entity type ${fixtures.canvas.pageEntityType} does not accept pageBundle.`);
    }
  }
  if (fixtures.sitemap.status === 'required' && !capabilities.sitemapConfigs.includes(fixtures.sitemap.configName)) {
    throw new Error(`Declared sitemap config ${fixtures.sitemap.configName} is unavailable.`);
  }
  if (fixtures.alias.status === 'required' && fixtures.node.status !== 'required') {
    throw new Error('A live alias fixture requires the verifier-owned node fixture as its stable internal path.');
  }
  return true;
}

function surfaceSupported(operation, capabilities) {
  const target = operation.target;
  if (operation.surface === 'node') return capabilities.applicable.node;
  if (operation.surface === 'menu') return capabilities.applicable.menu;
  if (operation.surface === 'alias') return capabilities.applicable.alias;
  if (operation.surface === 'view') return capabilities.applicable.view;
  if (operation.surface === 'canvas_page' || operation.surface === 'canvas_component') return capabilities.applicable.canvas;
  if (operation.surface === 'sitemap') return capabilities.applicable.sitemap;
  if (operation.surface === 'entity') return capabilities.entityTypes.includes(target.entityType);
  if (operation.surface === 'managed_file') return capabilities.entityTypes.includes('file');
  return operation.surface === 'config' || operation.surface === 'route';
}

export function assertDryRunSurfacesAvailable(dryRun, capabilities) {
  const unsupported = dryRun.operations.filter((operation) => !surfaceSupported(operation, capabilities));
  if (unsupported.length > 0) {
    const first = unsupported[0];
    throw new Error(`Assembly dry-run touches unsupported live surface ${first.surface} at ${assemblyTargetKey(first.target)}.`);
  }
}

function fixtureSpecification(fixtures) {
  const token = randomUUID().replaceAll('-', '');
  return {
    token,
    node: fixtures.node.status === 'required' ? { bundle: fixtures.node.bundle, uuid: randomUUID() } : null,
    menu: fixtures.menu.status === 'required' ? { menuName: fixtures.menu.menuName, uuid: randomUUID() } : null,
    alias: fixtures.alias.status === 'required' ? { uuid: randomUUID() } : null,
    view: fixtures.view.status === 'required' ? { uuid: randomUUID() } : null,
    canvas: fixtures.canvas.status === 'required' ? {
      pageEntityType: fixtures.canvas.pageEntityType,
      pageBundle: fixtures.canvas.pageBundle,
      componentConfigName: fixtures.canvas.componentConfigName,
      pageUuid: randomUUID(),
      markerUuid: randomUUID()
    } : null,
    sitemap: fixtures.sitemap.status === 'required' ? {
      configName: fixtures.sitemap.configName,
      markerUuid: randomUUID()
    } : null
  };
}

function fixtureEval(specification) {
  const encoded = Buffer.from(JSON.stringify(specification), 'utf8').toString('base64');
  return String.raw`
$spec = json_decode(base64_decode('${encoded}', TRUE), TRUE, 512, JSON_THROW_ON_ERROR);
$manager = \Drupal::entityTypeManager();
$targets = [];
$node_path = '';
$alias_path = '/agent-ready-extension-fixture/' . $spec['token'];
$add_entity_target = static function (string $surface, string $entity_type, $entity) use (&$targets): void {
  $uuid = method_exists($entity, 'uuid') ? strtolower((string) $entity->uuid()) : '';
  if ($uuid === '') throw new \RuntimeException('Verifier fixture entity has no UUID: ' . $entity_type);
  $targets[] = ['surface' => $surface, 'target' => ['kind' => 'entity', 'entityType' => $entity_type, 'stableId' => 'uuid:' . $uuid]];
};
$mark_config = static function (string $surface, string $name, string $token, string $uuid) use (&$targets): void {
  $editable = \Drupal::configFactory()->getEditable($name);
  if ($editable->isNew()) throw new \RuntimeException('Verifier fixture config is missing: ' . $name);
  $markers = $editable->get('third_party_settings.agent_ready_drupal_build_kit.extension_fixtures') ?? [];
  if (!is_array($markers)) $markers = [];
  $markers[$token] = $uuid;
  ksort($markers, SORT_STRING);
  $editable->set('third_party_settings.agent_ready_drupal_build_kit.extension_fixtures', $markers)->save(TRUE);
  $targets[] = ['surface' => $surface, 'target' => ['kind' => 'config', 'name' => $name]];
};

if (is_array($spec['node'])) {
  $node = $manager->getStorage('node')->create([
    'type' => $spec['node']['bundle'],
    'uuid' => $spec['node']['uuid'],
    'title' => 'Verifier extension fixture ' . $spec['token'],
    'status' => 0,
  ]);
  $node->save();
  $node_path = '/node/' . $node->id();
  $add_entity_target('node', 'node', $node);
}
if (is_array($spec['alias'])) {
  if ($node_path === '') throw new \RuntimeException('Alias fixture requires a verifier-owned node path.');
  $alias = $manager->getStorage('path_alias')->create([
    'uuid' => $spec['alias']['uuid'],
    'path' => $node_path,
    'alias' => $alias_path,
    'langcode' => 'und',
  ]);
  $alias->save();
  $add_entity_target('alias', 'path_alias', $alias);
}
if (is_array($spec['menu'])) {
  $link = $manager->getStorage('menu_link_content')->create([
    'uuid' => $spec['menu']['uuid'],
    'bundle' => 'menu_link_content',
    'title' => 'Verifier extension fixture ' . $spec['token'],
    'menu_name' => $spec['menu']['menuName'],
    'link' => ['uri' => 'internal:' . $alias_path],
    'enabled' => 0,
  ]);
  $link->save();
  $add_entity_target('menu', 'menu_link_content', $link);
}
if (is_array($spec['view'])) {
  $name = 'views.view.agent_ready_extension_' . $spec['token'];
  $data = [
    'uuid' => $spec['view']['uuid'],
    'langcode' => 'en',
    'status' => FALSE,
    'dependencies' => [],
    'id' => 'agent_ready_extension_' . $spec['token'],
    'label' => 'Verifier extension fixture ' . $spec['token'],
    'module' => 'views',
    'description' => '',
    'tag' => 'default',
    'base_table' => 'node_field_data',
    'base_field' => 'nid',
    'display' => [
      'default' => [
        'id' => 'default',
        'display_title' => 'Default',
        'display_plugin' => 'default',
        'position' => 0,
        'display_options' => [
          'access' => ['type' => 'none'],
          'cache' => ['type' => 'tag'],
          'query' => ['type' => 'views_query'],
          'exposed_form' => ['type' => 'basic', 'options' => []],
          'pager' => ['type' => 'some', 'options' => ['items_per_page' => 10]],
          'style' => ['type' => 'default'],
          'row' => ['type' => 'fields'],
          'fields' => [],
        ],
      ],
    ],
  ];
  $view = $manager->getStorage('view')->create($data);
  $view->save();
  if (\Drupal::service('config.storage')->read($name) === FALSE) {
    throw new \RuntimeException('Verifier View fixture did not create its expected config entity.');
  }
  $targets[] = ['surface' => 'view', 'target' => ['kind' => 'config', 'name' => $name]];
}
if (is_array($spec['canvas'])) {
  $entity_type = $spec['canvas']['pageEntityType'];
  $definition = $manager->getDefinition($entity_type);
  $values = [];
  $uuid_key = (string) ($definition->getKey('uuid') ?? '');
  if ($uuid_key === '') throw new \RuntimeException('Canvas page entity type has no UUID key: ' . $entity_type);
  $values[$uuid_key] = $spec['canvas']['pageUuid'];
  $bundle_key = (string) ($definition->getKey('bundle') ?? '');
  if ($bundle_key !== '') $values[$bundle_key] = $spec['canvas']['pageBundle'];
  $label_key = (string) ($definition->getKey('label') ?? '');
  if ($label_key !== '') $values[$label_key] = 'Verifier extension fixture ' . $spec['token'];
  $published_key = (string) ($definition->getKey('published') ?? '');
  if ($published_key !== '') $values[$published_key] = 0;
  $page = $manager->getStorage($entity_type)->create($values);
  $page->save();
  $add_entity_target('canvas_page', $entity_type, $page);
  $mark_config('canvas_component', $spec['canvas']['componentConfigName'], $spec['token'], $spec['canvas']['markerUuid']);
}
if (is_array($spec['sitemap'])) {
  $mark_config('sitemap', $spec['sitemap']['configName'], $spec['token'], $spec['sitemap']['markerUuid']);
}
usort($targets, static fn ($left, $right): int => strcmp(json_encode($left), json_encode($right)));
print json_encode([
  'schemaVersion' => 'public-kit.assembly-fixtures.1',
  'tokenSha256' => 'sha256:' . hash('sha256', $spec['token']),
  'targets' => $targets,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;
}

function parseFixtureResult(value, fixtures) {
  assertExactKeys(value, ['schemaVersion', 'tokenSha256', 'targets'], 'Assembly fixture result');
  if (value.schemaVersion !== ASSEMBLY_FIXTURES_SCHEMA) {
    throw new Error(`Assembly fixture result schemaVersion must be ${ASSEMBLY_FIXTURES_SCHEMA}.`);
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(String(value.tokenSha256 ?? ''))) {
    throw new Error('Assembly fixture result tokenSha256 is invalid.');
  }
  if (!Array.isArray(value.targets) || value.targets.length > 8) throw new Error('Assembly fixture targets are unbounded.');
  const seen = new Set();
  const targets = value.targets.map((row, index) => {
    assertExactKeys(row, ['surface', 'target'], `Assembly fixture targets[${index}]`);
    const surface = String(row.surface ?? '').trim();
    const target = parseAssemblyTarget(row.target, `Assembly fixture targets[${index}].target`);
    const validTarget = {
      node: target.kind === 'entity' && target.entityType === 'node',
      menu: target.kind === 'entity' && target.entityType === 'menu_link_content',
      alias: target.kind === 'entity' && target.entityType === 'path_alias',
      view: target.kind === 'config' && target.name.startsWith('views.view.agent_ready_extension_'),
      canvas_page: target.kind === 'entity' && target.entityType === fixtures.canvas.pageEntityType,
      canvas_component: target.kind === 'config' && target.name === fixtures.canvas.componentConfigName,
      sitemap: target.kind === 'config' && target.name === fixtures.sitemap.configName
    }[surface];
    if (!validTarget) throw new Error(`Assembly fixture target ${surface} is not bound to its declared live surface.`);
    const key = `${surface}|${assemblyTargetKey(target)}`;
    if (seen.has(key)) throw new Error(`Assembly fixture result contains duplicate target ${key}.`);
    seen.add(key);
    return { surface, target };
  }).sort((left, right) => comparePortable(`${left.surface}|${assemblyTargetKey(left.target)}`, `${right.surface}|${assemblyTargetKey(right.target)}`));
  const expected = [
    ...(fixtures.node.status === 'required' ? ['node'] : []),
    ...(fixtures.menu.status === 'required' ? ['menu'] : []),
    ...(fixtures.alias.status === 'required' ? ['alias'] : []),
    ...(fixtures.view.status === 'required' ? ['view'] : []),
    ...(fixtures.canvas.status === 'required' ? ['canvas_page', 'canvas_component'] : []),
    ...(fixtures.sitemap.status === 'required' ? ['sitemap'] : [])
  ].sort(comparePortable);
  const actual = targets.map((row) => row.surface).sort(comparePortable);
  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    throw new Error('Assembly fixture result does not cover every live/applicable declared surface exactly once.');
  }
  return { schemaVersion: ASSEMBLY_FIXTURES_SCHEMA, tokenSha256: value.tokenSha256, targets };
}

export function installAssemblyExtensionFixtures({ execute, fixtures, projectRoot, target = 'disposable' }) {
  const source = fixtureEval(fixtureSpecification(fixtures));
  const output = runEval(execute, projectRoot, target, 'install-assembly-extension-fixtures', source, 180_000);
  let value;
  try {
    value = JSON.parse(output);
  } catch {
    throw new Error('Assembly fixture installer returned invalid JSON.');
  }
  return parseFixtureResult(value, fixtures);
}

function fixtureIdentityEval(targets) {
  const specification = targets.map(({ target }) => ({ key: assemblyTargetKey(target), target }));
  const encoded = Buffer.from(JSON.stringify(specification), 'utf8').toString('base64');
  return String.raw`
$targets = json_decode(base64_decode('${encoded}', TRUE), TRUE, 512, JSON_THROW_ON_ERROR);
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
$rows = [];
foreach ($targets as $row) {
  $target = $row['target'];
  if ($target['kind'] === 'entity') {
    if (!str_starts_with($target['stableId'], 'uuid:')) throw new \RuntimeException('Fixture entity identity requires UUID.');
    $uuid = substr($target['stableId'], strlen('uuid:'));
    $definition = \Drupal::entityTypeManager()->getDefinition($target['entityType']);
    $uuid_key = (string) ($definition->getKey('uuid') ?? '');
    if ($uuid_key === '') throw new \RuntimeException('Fixture entity type has no UUID key.');
    $entities = \Drupal::entityTypeManager()->getStorage($target['entityType'])->loadByProperties([$uuid_key => $uuid]);
    if (count($entities) !== 1) throw new \RuntimeException('Fixture UUID did not resolve to exactly one entity.');
    $entity = reset($entities);
    $revision_id = method_exists($entity, 'getRevisionId') ? (string) ($entity->getRevisionId() ?? '') : '';
    $identity = ['entityType' => $target['entityType'], 'storageId' => (string) $entity->id(), 'revisionId' => $revision_id];
  }
  elseif ($target['kind'] === 'config') {
    $data = \Drupal::service('config.storage')->read($target['name']);
    if ($data === FALSE) throw new \RuntimeException('Fixture config identity is missing.');
    $identity = ['configName' => $target['name'], 'data' => $normalize($data)];
  }
  else {
    throw new \RuntimeException('Unsupported fixture identity target kind.');
  }
  $rows[] = ['key' => $row['key'], 'identitySha256' => 'sha256:' . hash('sha256', $encode($identity))];
}
usort($rows, static fn ($left, $right): int => strcmp($left['key'], $right['key']));
print json_encode([
  'schemaVersion' => 'public-kit.assembly-fixture-identity.1',
  'rows' => $rows,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;
}

function parseFixtureIdentity(value, targets) {
  assertExactKeys(value, ['schemaVersion', 'rows'], 'Assembly fixture identity');
  if (value.schemaVersion !== ASSEMBLY_FIXTURE_IDENTITY_SCHEMA) {
    throw new Error(`Assembly fixture identity schemaVersion must be ${ASSEMBLY_FIXTURE_IDENTITY_SCHEMA}.`);
  }
  if (!Array.isArray(value.rows) || value.rows.length !== targets.length) {
    throw new Error('Assembly fixture identity must contain exactly one row per fixture target.');
  }
  const rows = value.rows.map((row, index) => {
    assertExactKeys(row, ['key', 'identitySha256'], `Assembly fixture identity rows[${index}]`);
    const key = String(row.key ?? '').trim();
    const identitySha256 = String(row.identitySha256 ?? '').trim();
    if (!/^sha256:[a-f0-9]{64}$/.test(identitySha256)) {
      throw new Error(`Assembly fixture identity rows[${index}].identitySha256 is invalid.`);
    }
    return { key, identitySha256 };
  }).sort((left, right) => comparePortable(left.key, right.key));
  const expected = targets.map(({ target }) => assemblyTargetKey(target)).sort(comparePortable);
  if (JSON.stringify(rows.map(({ key }) => key)) !== JSON.stringify(expected)) {
    throw new Error('Assembly fixture identity keys do not match the exact fixture target set.');
  }
  return {
    schemaVersion: ASSEMBLY_FIXTURE_IDENTITY_SCHEMA,
    rows,
    fingerprint: sha256(rows)
  };
}

/**
 * Hash internal entity IDs/revisions without exposing them. UUID/content hashes
 * prove portable state; this additional probe detects delete-and-recreate churn.
 */
export function captureAssemblyFixtureIdentity({ execute, projectRoot, target = 'disposable', targets }) {
  const source = fixtureIdentityEval(targets);
  const output = runEval(execute, projectRoot, target, 'assembly-fixture-identity-readback', source, 120_000);
  let value;
  try {
    value = JSON.parse(output);
  } catch {
    throw new Error('Assembly fixture identity readback returned invalid JSON.');
  }
  return parseFixtureIdentity(value, targets);
}
