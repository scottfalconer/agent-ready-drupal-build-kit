#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const QUALITY_SCHEMA = 'public-kit.build-benchmark-quality.1';
const PACKET_SCHEMA = 'public-kit.packet-verification.2';
const SEED_SCHEMA = 'public-kit.build-benchmark-seed.1';
const OWNER_SCHEMA = 'public-kit.build-benchmark-run-owner.1';
const SEED_TREE_SCHEMA = 'public-kit.build-benchmark-seed-tree.1';
const OWNER_FILE = 'run-owner.json';
const MAX_BUFFER = 32 * 1024 * 1024;
const REQUIRED_GRANTS = Object.freeze({
  'Community Garden Starter Grant': {
    amount: 2500,
    deadline: '2026-09-30'
  },
  'Neighborhood Resilience Grant': {
    amount: 7500,
    deadline: '2026-10-15'
  },
  'Youth Arts Access Grant': {
    amount: 5000,
    deadline: '2026-11-01'
  }
});
const REQUIRED_TITLES = Object.freeze(Object.keys(REQUIRED_GRANTS).sort());
const REQUIRED_RENDERED_VALUES = Object.freeze([
  '2500.00',
  '7500.00',
  '5000.00',
  '2026-09-30',
  '2026-10-15',
  '2026-11-01'
]);
const FOCUSED_CONFIG_NAMES = Object.freeze([
  'node.type.grant',
  'field.storage.node.field_grant_amount',
  'field.field.node.grant.field_grant_amount',
  'field.storage.node.field_application_deadline',
  'field.field.node.grant.field_application_deadline',
  'views.view.grants'
]);
const EXPECTED_ADDED_CONFIG_NAMES = Object.freeze([
  ...FOCUSED_CONFIG_NAMES,
  'core.entity_form_display.node.grant.default',
  'core.entity_view_display.node.grant.default'
].sort());
const EXPECTED_CHANGED_CONFIG_NAMES = Object.freeze([
  'user.role.content_editor',
  'workflows.workflow.basic_editorial'
]);
const EXPECTED_CONFIG_SYNC_PATHS = Object.freeze([
  ...EXPECTED_ADDED_CONFIG_NAMES,
  ...EXPECTED_CHANGED_CONFIG_NAMES
].map((name) => `config/sync/${name}.yml`).sort());
const REQUIRED_EDITOR_PERMISSIONS = Object.freeze([
  'create grant content',
  'edit own grant content',
  'use basic_editorial transition create_new_draft',
  'use basic_editorial transition publish'
]);
const FORBIDDEN_EDITOR_PERMISSIONS = Object.freeze([
  'administer content types',
  'administer nodes',
  'bypass node access'
]);
const OUTCOME_LABELS = Object.freeze({
  drupalBootstrapPass: 'Drupal did not bootstrap through DDEV.',
  grantContentTypePass: 'The active grant content type was not found.',
  grantFieldsPass: 'The required, single-value decimal amount and datetime deadline fields were not active.',
  grantFieldValuesPass: 'The required Grant amounts or deadlines were not populated exactly.',
  grantConfigurationParityPass: 'The complete active and sync configuration sets were not identical, or the focused Grant configs were absent.',
  boundedConfigDeltaPass: 'The final config changed names or values outside the explicit Grant, workflow, and content-editor contract.',
  grantEditorialGovernancePass: 'The Grant workflow, editor widgets, displays, or bounded content-editor permissions were not configured.',
  preexistingDurableStatePass: 'Pre-existing nodes, users, taxonomy, media, aliases, files, blocks, redirects, or menu content changed, or a Grant alias was created.',
  grantsViewDefinitionPass: 'The active grants View did not exactly own the bounded /grants page, display, and handler contract.',
  grantsViewExecutionPass: 'Executing the grants View did not return exactly the three required Grant nodes.',
  publishedGrantContentPass: 'Exactly the three required published Grant nodes were not present.',
  grantsListingHttpPass: 'The /grants page did not return successfully.',
  grantsListingContentPass: 'The rendered /grants page did not contain all required titles, amounts, and deadlines.',
  boundedCustomCodeFootprintPass: 'The build changed protected project bytes or persisted paths outside config sync and the review packet.',
  gitWorktreeCleanPass: 'The final Git worktree was not clean.',
  packetOnlyVerifierPass: 'The fixed evaluator kit packet-only verifier did not report a valid packet.'
});

const BENCHMARK_BRIEF = `# Grants micro build benchmark

This is a bounded benchmark brief, not a general site-completion claim.

- BR-001: Provide a Drupal node type with machine name \`grant\`.
- BR-002: Grant nodes have decimal \`field_grant_amount\` and datetime
  \`field_application_deadline\` fields. Both are required, single-value fields
  with visible editor widgets and public display formatters.
- BR-003: Provide a Drupal View with machine name \`grants\` and page path
  \`/grants\`, exactly three visible fields and published-Grant filters,
  without extra displays or handlers.
- BR-004: Publish exactly three Grant nodes with these values:
  - Community Garden Starter Grant: 2500.00, 2026-09-30
  - Neighborhood Resilience Grant: 7500.00, 2026-10-15
  - Youth Arts Access Grant: 5000.00, 2026-11-01
- BR-005: The Drupal View executes to exactly those nodes and the rendered
  listing visibly includes all three titles, amounts, and deadlines.
- BR-006: Export the Drupal configuration and leave all build changes committed.
- BR-007: Keep this bounded slice configuration-and-content-only; do not
  persist a custom module or theme.
- BR-008: Add Grant to the existing basic editorial workflow and give the
  existing content editor role bounded create, edit-own, draft, and publish
  access without administrative or node-access bypass permissions.
`;

const BENCHMARK_AGENTS = `# Grants benchmark agent guidance

This is an isolated, disposable Drupal benchmark project. Work only in this
repository and use the installed
\`.agents/skills/agent-ready-drupal-build-kit/SKILL.md\` workflow.

- You are already inside the DDEV web container. Run Drush, PHP, Composer, Git,
  and Node commands directly; do not prefix them with \`ddev\`.
- Do not inspect authentication files, credential-like environment variables,
  SSH-agent paths, host mounts, or unrelated filesystem locations.
- Do not use external network access, add dependencies, or install modules.
- Keep the requested slice configuration-and-content-only and commit only
  truthful build/packet changes.
`;

const DRUPAL_FACTS_PHP = String.raw`
$definitions = \Drupal::service('entity_field.manager')->getFieldDefinitions('node', 'grant');
$allIds = \Drupal::entityQuery('node')
  ->accessCheck(FALSE)
  ->condition('type', 'grant')
  ->execute();
$publishedIds = \Drupal::entityQuery('node')
  ->accessCheck(FALSE)
  ->condition('type', 'grant')
  ->condition('status', 1)
  ->execute();
$grantRows = [];
foreach (\Drupal::entityTypeManager()->getStorage('node')->loadMultiple($allIds) as $node) {
  $grantRows[] = [
    'title' => $node->label(),
    'bundle' => $node->bundle(),
    'published' => $node->isPublished(),
    'amount' => $node->get('field_grant_amount')->value,
    'deadline' => $node->get('field_application_deadline')->value,
  ];
}
usort($grantRows, static fn(array $a, array $b): int => strcmp($a['title'], $b['title']));
$grantPaths = array_map(
  static fn(int|string $id): string => '/node/' . $id,
  array_values($allIds),
);
$grantAliasCount = 0;
if ($grantPaths !== []) {
  $grantAliasCount = count(\Drupal::entityQuery('path_alias')
    ->accessCheck(FALSE)
    ->condition('path', $grantPaths, 'IN')
    ->execute());
}

$normalizeConfig = static function (mixed $value) use (&$normalizeConfig): mixed {
  if (!is_array($value)) {
    return $value;
  }
  $normalized = [];
  foreach ($value as $key => $item) {
    $normalized[$key] = $normalizeConfig($item);
  }
  if (!array_is_list($normalized)) {
    ksort($normalized);
  }
  return $normalized;
};
$activeStorage = \Drupal::service('config.storage');
$exportStorage = \Drupal::service('config.storage.export');
$syncStorage = \Drupal::service('config.storage.sync');
$configParity = [];
foreach ([
  'node.type.grant',
  'field.storage.node.field_grant_amount',
  'field.field.node.grant.field_grant_amount',
  'field.storage.node.field_application_deadline',
  'field.field.node.grant.field_application_deadline',
  'views.view.grants',
] as $configName) {
  $active = $exportStorage->read($configName);
  $sync = $syncStorage->read($configName);
  $configParity[$configName] =
    is_array($active) &&
    is_array($sync) &&
    $normalizeConfig($active) === $normalizeConfig($sync);
}
$collectionNames = array_values(array_unique(array_merge(
  [''],
  $exportStorage->getAllCollectionNames(),
  $syncStorage->getAllCollectionNames(),
)));
sort($collectionNames);
$globalConfigDifferenceCount = 0;
foreach ($collectionNames as $collectionName) {
  $activeCollection = $collectionName === '' ? $exportStorage : $exportStorage->createCollection($collectionName);
  $syncCollection = $collectionName === '' ? $syncStorage : $syncStorage->createCollection($collectionName);
  $activeNames = $activeCollection->listAll();
  $syncNames = $syncCollection->listAll();
  sort($activeNames);
  sort($syncNames);
  $globalConfigDifferenceCount += count(array_diff($activeNames, $syncNames));
  $globalConfigDifferenceCount += count(array_diff($syncNames, $activeNames));
  foreach (array_intersect($activeNames, $syncNames) as $configName) {
    if ($normalizeConfig($activeCollection->read($configName)) !== $normalizeConfig($syncCollection->read($configName))) {
      $globalConfigDifferenceCount += 1;
    }
  }
}

$amountDefinition = $definitions['field_grant_amount'] ?? NULL;
$deadlineDefinition = $definitions['field_application_deadline'] ?? NULL;
$formDisplay = \Drupal::entityTypeManager()->getStorage('entity_form_display')->load('node.grant.default');
$viewDisplay = \Drupal::entityTypeManager()->getStorage('entity_view_display')->load('node.grant.default');
$formComponentsPass =
  $formDisplay &&
  is_array($formDisplay->getComponent('field_grant_amount')) &&
  is_array($formDisplay->getComponent('field_application_deadline'));
$viewComponentsPass =
  $viewDisplay &&
  is_array($viewDisplay->getComponent('field_grant_amount')) &&
  is_array($viewDisplay->getComponent('field_application_deadline'));
$workflowBundles = (array) \Drupal::config('workflows.workflow.basic_editorial')->get('type_settings.entity_types.node');
$contentEditor = \Drupal::entityTypeManager()->getStorage('user_role')->load('content_editor');
$requiredEditorPermissions = [
  'create grant content',
  'edit own grant content',
  'use basic_editorial transition create_new_draft',
  'use basic_editorial transition publish',
];
$forbiddenEditorPermissions = [
  'administer content types',
  'administer nodes',
  'bypass node access',
];
$editorPermissionsPass =
  $contentEditor &&
  count(array_filter($requiredEditorPermissions, static fn(string $permission): bool => !$contentEditor->hasPermission($permission))) === 0 &&
  count(array_filter($forbiddenEditorPermissions, static fn(string $permission): bool => $contentEditor->hasPermission($permission))) === 0;

$view = \Drupal\views\Views::getView('grants');
$viewData = \Drupal::config('views.view.grants')->getRawData();
$viewPaths = [];
$viewDisplayPlugins = [];
$matchingPageDisplayIds = [];
$pageDisplayId = '';
$viewStorageEnabled = $view ? (bool) $view->storage->status() : false;
$viewSetDisplayPass = false;
$viewDisplayEnabled = false;
$viewExecutePass = false;
if ($view) {
  foreach (($viewData['display'] ?? []) as $displayId => $display) {
    $viewDisplayPlugins[(string) $displayId] = (string) ($display['display_plugin'] ?? '');
    if (($display['display_plugin'] ?? '') !== 'page' || !$view->setDisplay($displayId)) {
      continue;
    }
    $path = (string) ($view->display_handler->getOption('path') ?? '');
    if ($path !== '') {
      $normalizedPath = '/' . ltrim($path, '/');
      $viewPaths[] = $normalizedPath;
      if ($normalizedPath === '/grants') {
        $matchingPageDisplayIds[] = (string) $displayId;
      }
    }
  }
}
ksort($viewDisplayPlugins);
if (count($matchingPageDisplayIds) === 1) {
  $pageDisplayId = $matchingPageDisplayIds[0];
}
$viewResultTitles = [];
$viewResultRows = [];
$viewFiltersGrant = false;
$viewFiltersPublished = false;
$viewFieldsPass = false;
$viewHandlerIds = [
  'arguments' => NULL,
  'empty' => NULL,
  'fields' => NULL,
  'filters' => NULL,
  'footer' => NULL,
  'header' => NULL,
  'relationships' => NULL,
  'sorts' => NULL,
];
if ($view && $pageDisplayId !== '') {
  $viewSetDisplayPass = $view->setDisplay($pageDisplayId);
  if ($viewSetDisplayPass) {
    $viewDisplayEnabled = (bool) $view->display_handler->isEnabled();
    foreach (array_keys($viewHandlerIds) as $handlerType) {
      $handlers = $view->display_handler->getOption($handlerType);
      if (is_array($handlers)) {
        $ids = array_map('strval', array_keys($handlers));
        sort($ids);
        $viewHandlerIds[$handlerType] = $ids;
      }
    }
    $filters = $view->display_handler->getOption('filters') ?? [];
    foreach ($filters as $filter) {
      if (($filter['table'] ?? '') !== 'node_field_data') {
        continue;
      }
      if (($filter['field'] ?? '') === 'type') {
        $value = $filter['value'] ?? [];
        $values = is_array($value) ? array_values($value) : [$value];
        $values = array_values(array_unique(array_map('strval', $values)));
        sort($values);
        $operator = (string) ($filter['operator'] ?? '');
        $viewFiltersGrant =
          $values === ['grant'] &&
          ($filter['plugin_id'] ?? '') === 'bundle' &&
          ($operator === '' || $operator === 'in') &&
          ($filter['exposed'] ?? false) === false;
      }
      if (($filter['field'] ?? '') === 'status') {
        $value = $filter['value'] ?? NULL;
        $operator = (string) ($filter['operator'] ?? '');
        $viewFiltersPublished =
          ($value === 1 || $value === '1' || $value === TRUE) &&
          ($filter['plugin_id'] ?? '') === 'boolean' &&
          ($operator === '' || $operator === '=') &&
          ($filter['exposed'] ?? false) === false;
      }
    }
    $fields = $view->display_handler->getOption('fields') ?? [];
    $titleField = $fields['title'] ?? [];
    $amountField = $fields['field_grant_amount'] ?? [];
    $deadlineField = $fields['field_application_deadline'] ?? [];
    $viewFieldsPass =
      ($titleField['table'] ?? '') === 'node_field_data' &&
      ($titleField['field'] ?? '') === 'title' &&
      ($titleField['plugin_id'] ?? '') === 'field' &&
      ($titleField['exclude'] ?? false) === false &&
      ($amountField['table'] ?? '') === 'node__field_grant_amount' &&
      ($amountField['field'] ?? '') === 'field_grant_amount' &&
      ($amountField['plugin_id'] ?? '') === 'field' &&
      ($amountField['exclude'] ?? false) === false &&
      ($amountField['type'] ?? '') === 'number_decimal' &&
      (string) ($amountField['settings']['scale'] ?? '') === '2' &&
      ($deadlineField['table'] ?? '') === 'node__field_application_deadline' &&
      ($deadlineField['field'] ?? '') === 'field_application_deadline' &&
      ($deadlineField['plugin_id'] ?? '') === 'field' &&
      ($deadlineField['exclude'] ?? false) === false &&
      ($deadlineField['type'] ?? '') === 'datetime_custom' &&
      ($deadlineField['settings']['date_format'] ?? '') === 'Y-m-d';
    $viewExecutePass = $view->execute($pageDisplayId);
    if ($viewExecutePass) {
      foreach ($view->result as $row) {
        $entity = $row->_entity ?? NULL;
        if ($entity && $entity->getEntityTypeId() === 'node') {
          $viewResultTitles[] = $entity->label();
          $viewResultRows[] = [
            'title' => $entity->label(),
            'bundle' => $entity->bundle(),
            'published' => $entity->isPublished(),
            'amount' => $entity->get('field_grant_amount')->value,
            'deadline' => $entity->get('field_application_deadline')->value,
          ];
        }
      }
    }
  }
}
sort($viewResultTitles);
usort($viewResultRows, static fn(array $a, array $b): int => strcmp($a['title'], $b['title']));

$routeName = '';
try {
  $url = \Drupal::service('path.validator')->getUrlIfValidWithoutAccessCheck('/grants');
  $routeName = $url ? (string) $url->getRouteName() : '';
}
catch (\Throwable $error) {
  $routeName = '';
}

echo json_encode([
  'grantTypeExists' => (bool) \Drupal::entityTypeManager()->getStorage('node_type')->load('grant'),
  'amountFieldType' => $amountDefinition ? $amountDefinition->getType() : '',
  'deadlineFieldType' => $deadlineDefinition ? $deadlineDefinition->getType() : '',
  'amountFieldRequired' => $amountDefinition ? $amountDefinition->isRequired() : false,
  'deadlineFieldRequired' => $deadlineDefinition ? $deadlineDefinition->isRequired() : false,
  'amountFieldCardinality' => $amountDefinition ? $amountDefinition->getFieldStorageDefinition()->getCardinality() : 0,
  'deadlineFieldCardinality' => $deadlineDefinition ? $deadlineDefinition->getFieldStorageDefinition()->getCardinality() : 0,
  'formComponentsPass' => $formComponentsPass,
  'viewComponentsPass' => $viewComponentsPass,
  'grantWorkflowPass' => in_array('grant', $workflowBundles, TRUE),
  'editorPermissionsPass' => $editorPermissionsPass,
  'grantCount' => count($allIds),
  'publishedGrantCount' => count($publishedIds),
  'grantRows' => $grantRows,
  'grantAliasCount' => $grantAliasCount,
  'grantsViewExists' => (bool) $view,
  'grantsViewStorageEnabled' => $viewStorageEnabled,
  'grantsViewBaseTable' => $viewData['base_table'] ?? '',
  'grantsViewPaths' => $viewPaths,
  'grantsViewDisplayIds' => array_keys($viewDisplayPlugins),
  'grantsViewDisplayPlugins' => $viewDisplayPlugins,
  'grantsViewHandlerIds' => $viewHandlerIds,
  'grantsMatchingPageDisplayCount' => count($matchingPageDisplayIds),
  'grantsPageDisplayId' => $pageDisplayId,
  'grantsViewSetDisplayPass' => $viewSetDisplayPass,
  'grantsViewDisplayEnabled' => $viewDisplayEnabled,
  'grantsViewExecutePass' => $viewExecutePass,
  'grantsRouteName' => $routeName,
  'grantsViewFiltersGrant' => $viewFiltersGrant,
  'grantsViewFiltersPublished' => $viewFiltersPublished,
  'grantsViewFieldsPass' => $viewFieldsPass,
  'grantsViewResultTitles' => $viewResultTitles,
  'grantsViewResultRows' => $viewResultRows,
  'configParity' => $configParity,
  'globalConfigDifferenceCount' => $globalConfigDifferenceCount,
  'globalConfigParity' => $globalConfigDifferenceCount === 0,
]);
`;

const STATE_PROJECTION_PHP = String.raw`
$normalize = static function (mixed $value) use (&$normalize): mixed {
  if (!is_array($value)) {
    return $value;
  }
  $normalized = [];
  foreach ($value as $key => $item) {
    $normalized[$key] = $normalize($item);
  }
  if (!array_is_list($normalized)) {
    ksort($normalized);
  }
  return $normalized;
};
$encode = static fn(mixed $value): string => json_encode(
  $normalize($value),
  JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
);
$activeStorage = \Drupal::service('config.storage');
$exportStorage = \Drupal::service('config.storage.export');
$syncStorage = \Drupal::service('config.storage.sync');
$collectionNames = array_values(array_unique(array_merge(
  [''],
  $activeStorage->getAllCollectionNames(),
  $exportStorage->getAllCollectionNames(),
  $syncStorage->getAllCollectionNames(),
)));
sort($collectionNames);
$storageHashes = static function ($rootStorage) use ($collectionNames, $encode): array {
  $hashes = [];
  foreach ($collectionNames as $collectionName) {
    $storage = $collectionName === '' ? $rootStorage : $rootStorage->createCollection($collectionName);
    $configNames = $storage->listAll();
    sort($configNames);
    foreach ($configNames as $configName) {
      $key = ($collectionName === '' ? 'default' : $collectionName) . ':' . $configName;
      $hashes[$key] = hash('sha256', $encode($storage->read($configName)));
    }
  }
  ksort($hashes);
  return $hashes;
};
$configHashes = $storageHashes($activeStorage);
$exportConfigHashes = $storageHashes($exportStorage);
$syncConfigHashes = $storageHashes($syncStorage);

$entityTypes = [
  'block_content',
  'file',
  'media',
  'menu_link_content',
  'node',
  'path_alias',
  'redirect',
  'taxonomy_term',
  'user',
];
$durableEntities = [];
$entityTypeManager = \Drupal::entityTypeManager();
foreach ($entityTypes as $entityTypeId) {
  if (!$entityTypeManager->hasDefinition($entityTypeId)) {
    continue;
  }
  $storage = $entityTypeManager->getStorage($entityTypeId);
  $ids = $storage->getQuery()->accessCheck(FALSE)->execute();
  $rows = [];
  foreach ($storage->loadMultiple($ids) as $entity) {
    if ($entityTypeId === 'node' && $entity->bundle() === 'grant') {
      continue;
    }
    $rows[] = [
      'id' => (string) $entity->id(),
      'uuid' => (string) $entity->uuid(),
      'bundle' => (string) $entity->bundle(),
      'values' => $entity->toArray(),
    ];
  }
  usort($rows, static fn(array $left, array $right): int => strcmp(
    $left['id'] . "\0" . $left['uuid'],
    $right['id'] . "\0" . $right['uuid'],
  ));
  $durableEntities[$entityTypeId] = [
    'count' => count($rows),
    'sha256' => hash('sha256', $encode($rows)),
  ];
}
ksort($durableEntities);

echo json_encode([
  'configHashes' => $configHashes,
  'exportConfigHashes' => $exportConfigHashes,
  'syncConfigHashes' => $syncConfigHashes,
  'contentEditorConfig' => $normalize($activeStorage->read('user.role.content_editor')),
  'workflowConfig' => $normalize($activeStorage->read('workflows.workflow.basic_editorial')),
  'durableEntities' => $durableEntities,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
`;

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (!name.startsWith('--')) {
      throw new Error(`Unexpected argument: ${name}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`${name} requires a value.`);
    }
    if (Object.hasOwn(options, name)) {
      throw new Error(`${name} may be supplied only once.`);
    }
    options[name] = value;
    index += 1;
  }
  return options;
}

function requiredOption(options, name) {
  const value = options[name];
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function isWithin(path, parent) {
  const child = resolve(path);
  const root = resolve(parent);
  const rel = relative(root, child);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function existingDirectory(value, label) {
  if (!isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  const path = realpathSync(value);
  if (!lstatSync(path).isDirectory()) {
    throw new Error(`${label} must be a directory.`);
  }
  return path;
}

function commandResult(command, args, { cwd, timeoutMs = 20 * 60 * 1000 } = {}) {
  const sanitizedEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => (
      !/(?:CREDENTIAL|KEY|PASSWORD|SECRET|TOKEN)/i.test(name) &&
      name !== 'SSH_AUTH_SOCK'
    ))
  );
  return spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...sanitizedEnvironment,
      DDEV_NO_INSTRUMENTATION: 'true'
    },
    maxBuffer: MAX_BUFFER,
    timeout: timeoutMs
  });
}

function resultDetail(result) {
  if (result.error) {
    return result.error.message;
  }
  const detail = `${result.stderr ?? ''}\n${result.stdout ?? ''}`.trim();
  return detail.slice(-4000) || `exit ${String(result.status)}`;
}

function commandLabel(command, args) {
  const rendered = args.map((arg) => (
    arg.length > 160 ? `<argument:${arg.length}-chars>` : arg
  ));
  return [command, ...rendered].join(' ');
}

function runChecked(command, args, options = {}) {
  const result = commandResult(command, args, options);
  if (result.error || result.status !== 0) {
    throw new Error(`${commandLabel(command, args)} failed: ${resultDetail(result)}`);
  }
  return result;
}

function projectDrushArgs(args) {
  // DDEV's shell mode expands PHP variables before Drush sees php:eval input.
  // Raw mode preserves every argv byte and also avoids the shared host Drush
  // command cache.
  return ['exec', '--raw', '--', 'vendor/bin/drush', ...args];
}

function cleanPreview(workspace) {
  return runChecked(
    'git',
    ['-C', workspace, 'status', '--porcelain=v1', '--untracked-files=all'],
    { cwd: workspace, timeoutMs: 60_000 }
  ).stdout.trim();
}

function copySeed(seedProject, workspace) {
  if (readdirSync(workspace).length !== 0) {
    throw new Error('The trial workspace must be empty before seed preparation.');
  }
  if (
    seedProject === workspace ||
    isWithin(workspace, seedProject) ||
    isWithin(seedProject, workspace)
  ) {
    throw new Error('The seed project and trial workspace must be disjoint.');
  }
  for (const entry of readdirSync(seedProject)) {
    if (entry === '.git') {
      continue;
    }
    cpSync(join(seedProject, entry), join(workspace, entry), {
      recursive: true,
      force: false,
      errorOnExist: true,
      preserveTimestamps: true,
      verbatimSymlinks: true
    });
  }
  function preserveModes(sourceDirectory, destinationDirectory) {
    for (const entry of readdirSync(sourceDirectory)) {
      if (sourceDirectory === seedProject && entry === '.git') {
        continue;
      }
      const sourcePath = join(sourceDirectory, entry);
      const destinationPath = join(destinationDirectory, entry);
      const projectPath = relative(seedProject, sourcePath).split(sep).join('/');
      if (pathHasPrefix(projectPath, '.ddev/traefik')) {
        continue;
      }
      const sourceEntry = lstatSync(sourcePath);
      if (sourceEntry.isDirectory()) {
        preserveModes(sourcePath, destinationPath);
      }
      chmodSync(destinationPath, sourceEntry.mode & 0o777);
    }
  }
  preserveModes(seedProject, workspace);
  // DDEV router state is host-runtime metadata, not a substrate input. It can
  // change while another project starts and is recreated for each copied run.
  rmSync(join(workspace, '.ddev', 'traefik'), { recursive: true, force: true });
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fileSha256(path) {
  return sha256Bytes(readFileSync(path));
}

function treeProjection(seedProject, root) {
  if (!existsSync(root) || !lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) {
    throw new Error(`Seed tree must be a regular directory: ${relative(seedProject, root)}`);
  }
  const rows = [];
  function walk(directory) {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const entry = lstatSync(path);
      if (entry.isSymbolicLink()) {
        throw new Error(`Seed fingerprint tree contains a symbolic link: ${relative(seedProject, path)}`);
      }
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile()) {
        const projectPath = relative(seedProject, path).split(sep).join('/');
        rows.push(`${projectPath}\0${fileSha256(path)}`);
      } else {
        throw new Error(`Seed fingerprint tree contains an unsupported entry: ${relative(seedProject, path)}`);
      }
    }
  }
  walk(root);
  return {
    files: rows.length,
    sha256: sha256Bytes(rows.join('\n'))
  };
}

function pathHasPrefix(path, prefix) {
  return path === prefix || path.startsWith(`${prefix}/`);
}

function contentTreeProjection(projectRoot, { exclude = () => false } = {}) {
  const rows = [];
  let files = 0;
  let directories = 0;
  let bytes = 0;
  function walk(directory) {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const projectPath = relative(projectRoot, path).split(sep).join('/');
      if (exclude(projectPath)) {
        continue;
      }
      const entry = lstatSync(path);
      if (entry.isSymbolicLink()) {
        throw new Error(`Fingerprint tree contains a symbolic link: ${projectPath}`);
      }
      const mode = (entry.mode & 0o777).toString(8).padStart(3, '0');
      if (entry.isDirectory()) {
        directories += 1;
        rows.push(`d\0${projectPath}\0${mode}`);
        walk(path);
      } else if (entry.isFile()) {
        files += 1;
        bytes += entry.size;
        rows.push(`f\0${projectPath}\0${mode}\0${entry.size}\0${fileSha256(path)}`);
      } else {
        throw new Error(`Fingerprint tree contains an unsupported entry: ${projectPath}`);
      }
    }
  }
  walk(projectRoot);
  return {
    files,
    directories,
    bytes,
    sha256: sha256Bytes(rows.join('\n'))
  };
}

export function copiedSeedProjection(seedProject) {
  return contentTreeProjection(seedProject, {
    // Repository metadata and DDEV's host-router state are not copied.
    exclude: (path) => (
      pathHasPrefix(path, '.git') ||
      pathHasPrefix(path, '.ddev/traefik')
    )
  });
}

const BUILD_INVARIANT_EXCLUSIONS = Object.freeze([
  '.git',
  '.benchmark-runtime',
  '.ddev/traefik',
  'config/sync',
  'review-packet'
]);
const GENERATED_RUNTIME_PATHS = Object.freeze([
  'web/sites/default/files/css',
  'web/sites/default/files/js',
  'web/sites/default/files/php',
  'web/sites/default/files/styles'
]);
const PRE_INIT_INVARIANT_EXCLUSIONS = Object.freeze([
  ...BUILD_INVARIANT_EXCLUSIONS,
  '.agents',
  'AGENTS.md',
  ...GENERATED_RUNTIME_PATHS
]);

export function buildInvariantProjection(workspace) {
  return contentTreeProjection(workspace, {
    exclude: (path) => BUILD_INVARIANT_EXCLUSIONS.some((prefix) => pathHasPrefix(path, prefix))
  });
}

function preInitInvariantProjection(workspace) {
  return contentTreeProjection(workspace, {
    exclude: (path) => PRE_INIT_INVARIANT_EXCLUSIONS.some((prefix) => pathHasPrefix(path, prefix))
  });
}

function configSyncProjection(workspace) {
  return contentTreeProjection(resolve(workspace, 'config', 'sync'));
}

function assertPreInitInvariant(owner, workspace) {
  if (
    !owner?.preInitInvariantProjection ||
    !owner?.preInitConfigProjection ||
    !sameJson(preInitInvariantProjection(workspace), owner.preInitInvariantProjection) ||
    !sameJson(configSyncProjection(workspace), owner.preInitConfigProjection)
  ) {
    throw new Error('The kit initializer changed bytes outside its allowed skill, AGENTS, and review-packet surfaces.');
  }
}

function regularDirectoryChainExists(root, projectPath) {
  const realRoot = realpathSync(root);
  let current = root;
  for (const component of projectPath.split('/')) {
    current = join(current, component);
    if (!existsSync(current)) {
      return false;
    }
    const entry = lstatSync(current);
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      throw new Error(`Unsafe directory component: ${relative(root, current).split(sep).join('/')}`);
    }
    if (!isWithin(realpathSync(current), realRoot)) {
      throw new Error(`Directory resolves outside the owned root: ${relative(root, current).split(sep).join('/')}`);
    }
  }
  return true;
}

export function clearGeneratedRuntimeTrees(workspace) {
  for (const projectPath of GENERATED_RUNTIME_PATHS) {
    const path = resolve(workspace, projectPath);
    if (!isWithin(path, workspace) || path === workspace) {
      throw new Error(`Unsafe generated runtime path: ${projectPath}`);
    }
    if (regularDirectoryChainExists(workspace, projectPath)) {
      rmSync(path, { recursive: true, force: true });
    }
  }
}

export function assertSafeSeedOutputPaths(seedProject) {
  const realSeedProject = realpathSync(seedProject);
  const seedDirectory = join(seedProject, 'benchmark-seed');
  if (existsSync(seedDirectory)) {
    const seedEntry = lstatSync(seedDirectory);
    if (seedEntry.isSymbolicLink() || !seedEntry.isDirectory()) {
      throw new Error('benchmark-seed must be a regular non-symlink directory.');
    }
    if (!isWithin(realpathSync(seedDirectory), realSeedProject)) {
      throw new Error('benchmark-seed resolves outside the seed project.');
    }
  }
  for (const name of ['manifest.json', 'seed.sql.gz']) {
    const path = join(seedDirectory, name);
    if (
      existsSync(path) &&
      (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile())
    ) {
      throw new Error(`benchmark-seed/${name} must be a regular non-symlink file.`);
    }
  }
}

function selectedFileProjection(root, projectPaths) {
  const rows = [];
  for (const projectPath of [...projectPaths].sort()) {
    const path = resolve(root, projectPath);
    if (
      !isWithin(path, root) ||
      !existsSync(path) ||
      !lstatSync(path).isFile() ||
      lstatSync(path).isSymbolicLink()
    ) {
      throw new Error(`Protected control file is missing or unsafe: ${projectPath}`);
    }
    const entry = lstatSync(path);
    rows.push([
      projectPath,
      (entry.mode & 0o777).toString(8).padStart(3, '0'),
      entry.size,
      fileSha256(path)
    ].join('\0'));
  }
  return {
    files: rows.length,
    sha256: sha256Bytes(rows.join('\n'))
  };
}

function gitControlProjection(workspace) {
  return selectedFileProjection(workspace, [
    '.git/HEAD',
    '.git/config',
    '.git/info/exclude'
  ]);
}

function assertGitControlInvariant(owner, workspace) {
  if (!owner?.gitControlProjection) {
    throw new Error('The ownership marker has no protected Git-control projection.');
  }
  if (!sameJson(gitControlProjection(workspace), owner.gitControlProjection)) {
    throw new Error('Protected Git control files changed during the measured build.');
  }
}

export function configOnlyPathViolations(changedPaths) {
  return changedPaths.filter((path) => (
    !/^config\/sync\/[^/]+\.yml$/.test(path) &&
    !/^review-packet\/.+\.(?:json|md|ya?ml|png|jpe?g|webp)$/.test(path)
  ));
}

export function exactConfigSyncDiffPass(changedPaths) {
  const actual = changedPaths
    .filter((path) => path.startsWith('config/sync/'))
    .sort();
  return sameJson(actual, EXPECTED_CONFIG_SYNC_PATHS);
}

function sortedUniqueStrings(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(String))].sort();
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function boundedGrantsViewStructurePass(facts) {
  if (!facts || typeof facts !== 'object' || Array.isArray(facts)) {
    return false;
  }
  const pageDisplayId = facts.grantsPageDisplayId;
  const displayPlugins = facts.grantsViewDisplayPlugins;
  const handlerIds = facts.grantsViewHandlerIds;
  if (
    typeof pageDisplayId !== 'string' ||
    pageDisplayId === '' ||
    !displayPlugins ||
    typeof displayPlugins !== 'object' ||
    Array.isArray(displayPlugins) ||
    !handlerIds ||
    typeof handlerIds !== 'object' ||
    Array.isArray(handlerIds)
  ) {
    return false;
  }
  const exactIds = (actual, expected) => (
    Array.isArray(actual) &&
    sameJson([...actual].sort(), [...expected].sort())
  );
  return (
    exactIds(facts.grantsViewDisplayIds, ['default', pageDisplayId]) &&
    displayPlugins.default === 'default' &&
    displayPlugins[pageDisplayId] === 'page' &&
    Object.keys(displayPlugins).length === 2 &&
    exactIds(handlerIds.fields, [
      'field_application_deadline',
      'field_grant_amount',
      'title'
    ]) &&
    exactIds(handlerIds.filters, ['status', 'type']) &&
    ['arguments', 'empty', 'footer', 'header', 'relationships', 'sorts'].every(
      (handlerType) => exactIds(handlerIds[handlerType], [])
    )
  );
}

function configDelta(before, after) {
  const beforeKeys = Object.keys(before ?? {}).sort();
  const afterKeys = Object.keys(after ?? {}).sort();
  return {
    added: afterKeys.filter((key) => !Object.hasOwn(before ?? {}, key)),
    deleted: beforeKeys.filter((key) => !Object.hasOwn(after ?? {}, key)),
    changed: beforeKeys.filter((key) => (
      Object.hasOwn(after ?? {}, key) && before[key] !== after[key]
    ))
  };
}

function normalizeExactAddedConfigDependency(baselineConfig, finalConfig, dependency) {
  const baselineDependencies = baselineConfig?.dependencies?.config;
  const finalDependencies = finalConfig?.dependencies?.config;
  if (!Array.isArray(baselineDependencies) || !Array.isArray(finalDependencies)) {
    return false;
  }
  const baselineNormalized = sortedUniqueStrings(baselineDependencies);
  const finalNormalized = sortedUniqueStrings(finalDependencies);
  if (
    baselineNormalized.length !== baselineDependencies.length ||
    finalNormalized.length !== finalDependencies.length ||
    !sameJson(
      finalNormalized,
      sortedUniqueStrings([...baselineNormalized, dependency])
    )
  ) {
    return false;
  }
  baselineConfig.dependencies.config = baselineNormalized;
  finalConfig.dependencies.config = baselineNormalized;
  return true;
}

export function boundedConfigDeltaPass(baseline, final) {
  const delta = configDelta(baseline?.configHashes, final?.configHashes);
  const expectedAdded = EXPECTED_ADDED_CONFIG_NAMES.map((name) => `default:${name}`).sort();
  const expectedChanged = EXPECTED_CHANGED_CONFIG_NAMES.map((name) => `default:${name}`).sort();
  if (
    !sameJson(delta.added, expectedAdded) ||
    delta.deleted.length !== 0 ||
    !sameJson(delta.changed, expectedChanged)
  ) {
    return false;
  }

  const baselineRole = structuredClone(baseline?.contentEditorConfig ?? {});
  const finalRole = structuredClone(final?.contentEditorConfig ?? {});
  if (!normalizeExactAddedConfigDependency(baselineRole, finalRole, 'node.type.grant')) {
    return false;
  }
  const baselinePermissions = sortedUniqueStrings(baselineRole.permissions);
  const expectedPermissions = sortedUniqueStrings([
    ...baselinePermissions,
    ...REQUIRED_EDITOR_PERMISSIONS
  ]);
  const finalPermissions = sortedUniqueStrings(finalRole.permissions);
  if (
    !sameJson(finalPermissions, expectedPermissions) ||
    FORBIDDEN_EDITOR_PERMISSIONS.some((permission) => finalPermissions.includes(permission))
  ) {
    return false;
  }
  baselineRole.permissions = baselinePermissions;
  finalRole.permissions = baselinePermissions;
  if (!sameJson(baselineRole, finalRole)) {
    return false;
  }

  const baselineWorkflow = structuredClone(baseline?.workflowConfig ?? {});
  const finalWorkflow = structuredClone(final?.workflowConfig ?? {});
  if (!normalizeExactAddedConfigDependency(baselineWorkflow, finalWorkflow, 'node.type.grant')) {
    return false;
  }
  const baselineBundles = sortedUniqueStrings(
    baselineWorkflow?.type_settings?.entity_types?.node
  );
  const finalBundles = sortedUniqueStrings(
    finalWorkflow?.type_settings?.entity_types?.node
  );
  if (!sameJson(finalBundles, sortedUniqueStrings([...baselineBundles, 'grant']))) {
    return false;
  }
  if (!baselineWorkflow.type_settings?.entity_types || !finalWorkflow.type_settings?.entity_types) {
    return false;
  }
  baselineWorkflow.type_settings.entity_types.node = baselineBundles;
  finalWorkflow.type_settings.entity_types.node = baselineBundles;
  return sameJson(baselineWorkflow, finalWorkflow);
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function parseJsonFile(path, label) {
  return parseJson(readFileSync(path, 'utf8'), label);
}

function assertHexSha256(value, label) {
  if (!/^[a-f0-9]{64}$/.test(value ?? '')) {
    throw new Error(`${label} must be a lowercase SHA-256 hex digest.`);
  }
}

function verifySeed(seedProject, expectedFingerprint, expectedTreeFingerprint) {
  assertHexSha256(expectedFingerprint, '--seed-fingerprint');
  assertHexSha256(expectedTreeFingerprint, '--seed-tree-fingerprint');
  const manifestPath = join(seedProject, 'benchmark-seed', 'manifest.json');
  if (
    !existsSync(manifestPath) ||
    !lstatSync(manifestPath).isFile() ||
    lstatSync(manifestPath).isSymbolicLink()
  ) {
    throw new Error('The seed project must contain benchmark-seed/manifest.json as a regular non-symlink file.');
  }
  const manifest = parseJsonFile(manifestPath, 'Seed manifest');
  if (manifest.schemaVersion !== SEED_SCHEMA) {
    throw new Error(`Seed manifest schemaVersion must be ${SEED_SCHEMA}.`);
  }
  for (const [label, value] of [
    ['manifest.fingerprint', manifest.fingerprint],
    ['manifest.databaseSha256', manifest.databaseSha256],
    ['manifest.composerJsonSha256', manifest.composerJsonSha256],
    ['manifest.composerLockSha256', manifest.composerLockSha256],
    ['manifest.config.sha256', manifest.config?.sha256],
    ['manifest.publicFiles.sha256', manifest.publicFiles?.sha256]
  ]) {
    assertHexSha256(value, label);
  }
  assertHexSha256(manifest.installerSha256, 'manifest.installerSha256');
  for (const [label, value] of [
    ['manifest.createdAt', manifest.createdAt],
    ['manifest.drupalCmsVersion', manifest.drupalCmsVersion],
    ['manifest.drupalCoreVersion', manifest.drupalCoreVersion],
    ['manifest.ddevVersion', manifest.ddevVersion]
  ]) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new Error(`${label} must be a nonempty string.`);
    }
  }
  if (manifest.fingerprint !== expectedFingerprint) {
    throw new Error('The supplied seed fingerprint does not match benchmark-seed/manifest.json.');
  }
  const { fingerprint, ...identity } = manifest;
  if (sha256Bytes(JSON.stringify(identity)) !== fingerprint) {
    throw new Error('The seed manifest fingerprint does not match its canonical identity fields.');
  }

  for (const [projectPath, expected] of [
    ['benchmark-seed/seed.sql.gz', manifest.databaseSha256],
    ['composer.json', manifest.composerJsonSha256],
    ['composer.lock', manifest.composerLockSha256]
  ]) {
    const path = join(seedProject, projectPath);
    if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
      throw new Error(`Seed manifest input must be a regular non-symlink file: ${projectPath}`);
    }
    if (fileSha256(path) !== expected) {
      throw new Error(`Seed manifest hash mismatch: ${projectPath}`);
    }
  }

  for (const [projectPath, expected] of [
    ['config/sync', manifest.config],
    ['web/sites/default/files', manifest.publicFiles]
  ]) {
    if (!Number.isSafeInteger(expected?.files) || expected.files < 0) {
      throw new Error(`Seed manifest file count is invalid: ${projectPath}`);
    }
    const actual = treeProjection(seedProject, join(seedProject, projectPath));
    if (actual.files !== expected.files || actual.sha256 !== expected.sha256) {
      throw new Error(`Seed manifest tree mismatch: ${projectPath}`);
    }
  }
  const completeProjection = copiedSeedProjection(seedProject);
  if (completeProjection.sha256 !== expectedTreeFingerprint) {
    throw new Error('The complete copied seed tree does not match --seed-tree-fingerprint.');
  }
  return { manifest, completeProjection };
}

function ddevProjectName(experimentId, runId) {
  const match = runId.match(/^(\d{3,})-trial$/);
  if (!match) {
    throw new Error('The benchmark run ID does not have the expected opaqueable ordinal form.');
  }
  const trialId = `trial-${match[1]}`;
  const identity = `${experimentId}\0${trialId}`;
  const slug = `${experimentId}-${trialId}`
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  const suffix = sha256Bytes(identity).slice(0, 10);
  const value = `arb-grants-${slug.slice(0, 24).replace(/-+$/g, '')}-${suffix}`;
  if (!/^[a-z0-9][a-z0-9-]+$/.test(value)) {
    throw new Error('Unable to derive a valid DDEV project name from the experiment and run IDs.');
  }
  return value;
}

function ddevConfigName(workspace) {
  const configPath = join(workspace, '.ddev', 'config.yaml');
  if (
    !existsSync(configPath) ||
    !lstatSync(configPath).isFile() ||
    lstatSync(configPath).isSymbolicLink()
  ) {
    throw new Error('The seed project must contain a regular non-symlink .ddev/config.yaml file.');
  }
  const matches = readFileSync(configPath, 'utf8').match(/^name:\s*["']?([^"'#\s]+)["']?\s*(?:#.*)?$/gm) ?? [];
  if (matches.length !== 1) {
    throw new Error('.ddev/config.yaml must contain exactly one root name entry.');
  }
  const parsed = matches[0].match(/^name:\s*["']?([^"'#\s]+)/);
  return parsed?.[1] ?? '';
}

function setDdevProjectName(workspace, projectName) {
  const configPath = join(workspace, '.ddev', 'config.yaml');
  ddevConfigName(workspace);
  const current = readFileSync(configPath, 'utf8');
  const matches = current.match(/^name:\s*.*$/gm) ?? [];
  if (matches.length > 1) {
    throw new Error('.ddev/config.yaml contains more than one root name entry.');
  }
  const next = matches.length === 1
    ? current.replace(/^name:\s*.*$/m, `name: ${projectName}`)
    : `name: ${projectName}\n${current}`;
  writeFileSync(configPath, next);
}

function configureDdevIsolation(workspace, runDir) {
  const credentialSeed = join(runDir, 'credential-seed');
  const isolatedCache = join(runDir, 'ddev-cache');
  mkdirSync(credentialSeed, { recursive: true, mode: 0o700 });
  mkdirSync(isolatedCache, { recursive: true, mode: 0o700 });

  const composePath = join(workspace, '.ddev', 'docker-compose.ddev-assistant-codex.yaml');
  if (
    !existsSync(composePath) ||
    !lstatSync(composePath).isFile() ||
    lstatSync(composePath).isSymbolicLink()
  ) {
    throw new Error('The seed project must contain the DDEV Codex compose fragment.');
  }
  const legacyMount = '"${HOME}/.codex:${HOME}/.cred-seed/codex:ro"';
  const minimalMount = '"${DDEV_APPROOT}/../credential-seed:/home/${USER}/.cred-seed/codex:ro"';
  const current = readFileSync(composePath, 'utf8');
  if (!current.includes(minimalMount)) {
    if ((current.match(new RegExp(legacyMount.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? []).length !== 1) {
      throw new Error('The DDEV Codex credential mount did not match the expected seed contract.');
    }
    writeFileSync(composePath, current.replace(legacyMount, minimalMount));
  }

  const commandPath = join(workspace, '.ddev', 'commands', 'web', 'codex');
  if (
    !existsSync(commandPath) ||
    !lstatSync(commandPath).isFile() ||
    lstatSync(commandPath).isSymbolicLink()
  ) {
    throw new Error('The seed project must contain the DDEV Codex command wrapper.');
  }
  const hardenedWrapper = `#!/bin/bash
for variable_name in $(compgen -e); do
  case "\${variable_name}" in
    *CREDENTIAL*|*KEY*|*PASSWORD*|*SECRET*|*TOKEN*)
      unset "\${variable_name}"
      ;;
  esac
done
export SSH_AUTH_SOCK=/nonexistent
exec codex "$@"
  `;
  writeFileSync(commandPath, hardenedWrapper);

  writeFileSync(
    join(workspace, '.ddev', 'docker-compose.benchmark-isolation.yaml'),
    `services:
  db:
    volumes:
      - "\${DDEV_APPROOT}/../ddev-cache:/mnt/ddev-global-cache"

  web:
    environment:
      NODE_EXTRA_CA_CERTS: ""
      SSH_AUTH_SOCK: ""
    volumes: !override
      - "../:/var/www/html:cached"
      - "./:/mnt/ddev_config:ro"
      - "\${DDEV_APPROOT}/../ddev-cache:/mnt/ddev-global-cache"
      - "\${DDEV_APPROOT}/../credential-seed:/home/\${USER}/.cred-seed/codex:ro"

volumes:
  ddev-global-cache: !reset null
  ddev-ssh-agent_socket_dir: !reset null
`
  );
  writeFileSync(
    join(workspace, '.ddev', 'config.benchmark-isolation.yaml'),
    `fail_on_hook_fail: true

hooks:
  post-start:
    - exec-host: "bash .ddev/benchmark-isolate-network.sh"
`
  );
  writeFileSync(
    join(workspace, '.ddev', 'benchmark-isolate-network.sh'),
    `#!/usr/bin/env bash

set -euo pipefail

readonly shared_network="ddev_default"

for service in web db; do
  container="ddev-\${DDEV_SITENAME}-\${service}"
  if ! docker inspect "\${container}" >/dev/null 2>&1; then
    echo "Benchmark isolation: expected container \${container} was not found." >&2
    exit 1
  fi
  attached="$(
    docker inspect \
      --format '{{if index .NetworkSettings.Networks "ddev_default"}}yes{{else}}no{{end}}' \
      "\${container}"
  )"
  if [[ "\${attached}" == "yes" ]]; then
    docker network disconnect "\${shared_network}" "\${container}"
  fi
  remaining="$(
    docker inspect \
      --format '{{if index .NetworkSettings.Networks "ddev_default"}}yes{{else}}no{{end}}' \
      "\${container}"
  )"
  if [[ "\${remaining}" != "no" ]]; then
    echo "Benchmark isolation: \${container} remains attached to \${shared_network}." >&2
    exit 1
  fi
done
`,
    { mode: 0o755 }
  );
}

function configureTrackedSyncDirectory(workspace) {
  const syncDirectory = join(workspace, 'config', 'sync');
  if (
    !existsSync(syncDirectory) ||
    !lstatSync(syncDirectory).isDirectory() ||
    lstatSync(syncDirectory).isSymbolicLink()
  ) {
    throw new Error('The seed project must contain a regular config/sync directory.');
  }
  const settingsPath = join(workspace, 'web', 'sites', 'default', 'settings.php');
  if (
    !existsSync(settingsPath) ||
    !lstatSync(settingsPath).isFile() ||
    lstatSync(settingsPath).isSymbolicLink()
  ) {
    throw new Error('The seed project must contain a regular Drupal settings.php.');
  }
  const current = readFileSync(settingsPath, 'utf8');
  const configured = "$settings['config_sync_directory'] = '../config/sync';";
  if (current.includes(configured)) {
    return;
  }
  const example = "# $settings['config_sync_directory'] = '/directory/outside/webroot';";
  if (current.split(example).length !== 2) {
    throw new Error('Drupal settings.php did not match the expected config-sync example.');
  }
  writeFileSync(settingsPath, current.replace(example, configured));
}

function assertWorkspaceRunDir(workspace, runDir) {
  if (!isWithin(workspace, runDir) || workspace === runDir) {
    throw new Error('--workspace must be a child of --run-dir.');
  }
}

function ownerPath(runDir) {
  return join(runDir, OWNER_FILE);
}

function readOwner(runDir) {
  const path = ownerPath(runDir);
  if (!existsSync(path)) {
    return null;
  }
  if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
    throw new Error('The benchmark ownership marker must be a regular non-symlink file.');
  }
  const owner = parseJsonFile(path, 'Benchmark ownership marker');
  if (owner.schemaVersion !== OWNER_SCHEMA) {
    throw new Error(`Benchmark ownership marker schemaVersion must be ${OWNER_SCHEMA}.`);
  }
  return owner;
}

function writeOwner(runDir, owner, { allowExisting = false } = {}) {
  const path = ownerPath(runDir);
  if (existsSync(path)) {
    if (!allowExisting) {
      throw new Error('The benchmark run directory already contains an ownership marker.');
    }
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
      throw new Error('Refusing to replace a non-regular benchmark ownership marker.');
    }
  }
  const temporaryPath = join(runDir, `.run-owner-${process.pid}.tmp`);
  writeFileSync(temporaryPath, `${JSON.stringify(owner, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600
  });
  renameSync(temporaryPath, path);
}

function assertOwnerWorkspace(owner, workspace) {
  if (owner?.appRoot !== workspace) {
    throw new Error('The benchmark ownership marker does not match this workspace.');
  }
}

function inspectOwnedContainer(owner, workspace, service, { required = true } = {}) {
  const containerName = `ddev-${owner.projectName}-${service}`;
  const result = commandResult('docker', ['inspect', containerName], {
    cwd: workspace,
    timeoutMs: 60_000
  });
  if (result.error || result.status !== 0) {
    if (!required && !result.error && /no such object/i.test(result.stderr ?? '')) {
      return null;
    }
    throw new Error(`Unable to inspect owned ${service} container: ${resultDetail(result)}`);
  }
  const inspected = parseJson(result.stdout, `Docker inspection for ${service}`);
  const container = inspected?.[0];
  const labels = container?.Config?.Labels ?? {};
  if (
    labels['com.ddev.platform'] !== 'ddev' ||
    labels['com.ddev.site-name'] !== owner.projectName ||
    labels['com.ddev.approot'] !== workspace ||
    labels['com.docker.compose.project'] !== `ddev-${owner.projectName}` ||
    labels['com.docker.compose.service'] !== service
  ) {
    throw new Error(`The ${service} container labels do not match the external run owner.`);
  }
  const mounts = Array.isArray(container?.Mounts) ? container.Mounts : [];
  if (service === 'web') {
    const projectMount = mounts.find((mount) => mount?.Destination === '/var/www/html');
    if (projectMount?.Type !== 'bind' || projectMount?.Source !== workspace || projectMount?.RW !== true) {
      throw new Error('The web container project mount does not match the owned workspace.');
    }
  }
  return { containerName, container, mounts };
}

function inspectedCredentialHome(inspected) {
  const credentialMount = inspected.mounts.find((mount) => (
    typeof mount?.Destination === 'string' &&
    mount.Destination.endsWith('/.cred-seed/codex')
  ));
  const home = credentialMount?.Destination?.slice(0, -'/.cred-seed/codex'.length);
  if (!/^\/home\/[a-z_][a-z0-9_-]*$/i.test(home ?? '')) {
    throw new Error('The owned web container credential-home mount is invalid.');
  }
  return home;
}

function assertRuntimeIsolation(owner, workspace, runDir) {
  const expectedNetwork = `ddev-${owner.projectName}_default`;
  const expectedCache = join(runDir, 'ddev-cache');
  const expectedCredentialSeed = join(runDir, 'credential-seed');
  for (const service of ['web', 'db']) {
    const { container, mounts } = inspectOwnedContainer(owner, workspace, service);
    const networks = Object.keys(container?.NetworkSettings?.Networks ?? {}).sort();
    if (!sameJson(networks, [expectedNetwork])) {
      throw new Error(`The ${service} container is not confined to the owned project network.`);
    }
    if (mounts.some((mount) => (
      mount?.Name === 'ddev-global-cache' ||
      mount?.Name === 'ddev-ssh-agent_socket_dir' ||
      mount?.Destination === '/home/.ssh-agent'
    ))) {
      throw new Error(`The ${service} container retained a shared cache or SSH-agent mount.`);
    }
    const cacheMount = mounts.find((mount) => mount?.Destination === '/mnt/ddev-global-cache');
    if (cacheMount?.Type !== 'bind' || cacheMount?.Source !== expectedCache || cacheMount?.RW !== true) {
      throw new Error(`The ${service} container does not use the run-owned DDEV cache.`);
    }
    if (service === 'web') {
      const credentialMount = mounts.find((mount) => (
        typeof mount?.Destination === 'string' &&
        mount.Destination.endsWith('/.cred-seed/codex')
      ));
      if (
        credentialMount?.Type !== 'bind' ||
        credentialMount?.Source !== expectedCredentialSeed ||
        credentialMount?.RW !== false
      ) {
        throw new Error('The web container credential seed is not the read-only run-owned copy.');
      }
    }
  }
  const containerBoundary = runChecked(
    'ddev',
    [
      'exec',
      'node',
      '-e',
      'const fs=require("fs");if(process.env.SSH_AUTH_SOCK||fs.existsSync("/home/.ssh-agent/socket"))process.exit(7);'
    ],
    { cwd: workspace, timeoutMs: 60_000 }
  );
  if (containerBoundary.status !== 0) {
    throw new Error('The web container still exposes an SSH-agent environment or socket.');
  }
}

function assertOwnedDdev(owner, workspace, runDir) {
  if (ddevConfigName(workspace) !== owner.projectName) {
    throw new Error('The DDEV configuration is not owned by this benchmark run.');
  }
  const description = lastJsonObject(
    runChecked('ddev', ['describe', '-j'], {
      cwd: workspace,
      timeoutMs: 60_000
    }).stdout,
    'DDEV description'
  );
  const describedRoot = description?.raw?.approot;
  if (
    description?.raw?.name !== owner.projectName ||
    !describedRoot ||
    realpathSync(describedRoot) !== workspace
  ) {
    throw new Error('DDEV did not confirm the owned project name and app root.');
  }
  assertRuntimeIsolation(owner, workspace, runDir);
}

function assertBuildInvariant(owner, workspace) {
  if (!owner?.buildInvariantProjection) {
    throw new Error('The ownership marker has no protected build-tree projection.');
  }
  const current = buildInvariantProjection(workspace);
  if (!sameJson(current, owner.buildInvariantProjection)) {
    throw new Error('Protected project bytes changed after the timed kit installation.');
  }
  return current;
}

function revokeRuntimeCredential(owner, workspace, runDir) {
  rmSync(join(runDir, 'credential-seed', 'auth.json'), { force: true });
  const inspected = inspectOwnedContainer(owner, workspace, 'web', { required: false });
  if (!inspected) {
    return;
  }
  const credentialHome = inspectedCredentialHome(inspected);
  const result = commandResult(
    'docker',
    [
      'exec',
      inspected.containerName,
      'node',
      '-e',
      'const fs=require("fs"),p=require("path").join(process.argv[1],".codex","auth.json");fs.rmSync(p,{force:true});if(fs.existsSync(p))process.exit(8);',
      credentialHome
    ],
    { cwd: workspace, timeoutMs: 60_000 }
  );
  if (!result.error && result.status === 0) {
    return;
  }
  // If the owned web container is no longer executable, removing this exact
  // externally validated disposable container also removes its writable auth
  // copy. Cleanup will remove the remaining owned service or abort later runs.
  runChecked(
    'docker',
    [
      'rm',
      '--force',
      inspected.containerName
    ],
    { cwd: workspace, timeoutMs: 60_000 }
  );
}

function provisionRuntimeCredential(owner, workspace, runDir) {
  const hostHome = process.env.HOME;
  if (!hostHome || !isAbsolute(hostHome)) {
    throw new Error('HOME must be absolute so the trusted harness can locate Codex authentication.');
  }
  const hostAuth = join(hostHome, '.codex', 'auth.json');
  if (
    !existsSync(hostAuth) ||
    !lstatSync(hostAuth).isFile() ||
    lstatSync(hostAuth).isSymbolicLink()
  ) {
    throw new Error('A regular host ~/.codex/auth.json file is required for measured agent builds.');
  }
  const credentialSeed = join(runDir, 'credential-seed');
  mkdirSync(credentialSeed, { recursive: true, mode: 0o700 });
  writeFileSync(join(credentialSeed, 'auth.json'), readFileSync(hostAuth), {
    mode: 0o600
  });
  const inspected = inspectOwnedContainer(owner, workspace, 'web');
  const credentialHome = inspectedCredentialHome(inspected);
  runChecked(
    'docker',
    [
      'exec',
      inspected.containerName,
      'node',
      '-e',
      'const fs=require("fs"),p=require("path"),h=process.argv[1],s=p.join(h,".cred-seed","codex","auth.json"),d=p.join(h,".codex"),t=p.join(d,"auth.json"),o=fs.statSync(h);if(!fs.lstatSync(s).isFile())process.exit(9);fs.mkdirSync(d,{recursive:true,mode:0o700});fs.chmodSync(d,0o700);fs.copyFileSync(s,t);fs.chmodSync(t,0o600);const ds=fs.statSync(d),ts=fs.statSync(t);if(ds.uid!==o.uid||ts.uid!==o.uid||(ds.mode&0o077)!==0||(ts.mode&0o077)!==0)process.exit(10);',
      credentialHome
    ],
    { cwd: workspace, timeoutMs: 60_000 }
  );
}

function removeOwnedContainers(owner, workspace) {
  for (const service of ['web', 'db']) {
    const inspected = inspectOwnedContainer(owner, workspace, service, { required: false });
    if (!inspected) {
      continue;
    }
    runChecked(
      'docker',
      [
        'rm',
        '--force',
        inspected.containerName
      ],
      { cwd: workspace, timeoutMs: 60_000 }
    );
  }
}

function assertContainerCredentialRevoked(owner, workspace) {
  const inspected = inspectOwnedContainer(owner, workspace, 'web', { required: false });
  if (!inspected) {
    return;
  }
  const credentialHome = inspectedCredentialHome(inspected);
  runChecked(
    'docker',
    [
      'exec',
      inspected.containerName,
      'node',
      '-e',
      'const fs=require("fs"),p=require("path").join(process.argv[1],".codex","auth.json");if(fs.existsSync(p))process.exit(8);',
      credentialHome
    ],
    { cwd: workspace, timeoutMs: 60_000 }
  );
}

function commitAll(workspace, message) {
  runChecked('git', ['-C', workspace, 'add', '--all'], { cwd: workspace, timeoutMs: 5 * 60 * 1000 });
  const staged = commandResult('git', ['-C', workspace, 'diff', '--cached', '--quiet'], {
    cwd: workspace,
    timeoutMs: 60_000
  });
  if (staged.error || ![0, 1].includes(staged.status)) {
    throw new Error(`Unable to inspect prepared Git changes: ${resultDetail(staged)}`);
  }
  if (staged.status === 1) {
    runChecked(
      'git',
      ['-C', workspace, 'commit', '--no-verify', '-m', message],
      { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
    );
  }
  const status = cleanPreview(workspace);
  if (status) {
    throw new Error(`Commit did not leave a clean Git worktree: ${status.slice(0, 1000)}`);
  }
}

function addLocalGitExclude(workspace, pattern) {
  const path = join(workspace, '.git', 'info', 'exclude');
  const current = existsSync(path) ? readFileSync(path, 'utf8') : '';
  const lines = current.split(/\r?\n/);
  if (lines.includes(pattern)) {
    return;
  }
  const separator = current === '' || current.endsWith('\n') ? '' : '\n';
  writeFileSync(path, `${current}${separator}${pattern}\n`);
}

function prepare(options) {
  const seedProject = existingDirectory(requiredOption(options, '--seed-project'), '--seed-project');
  const workspace = existingDirectory(requiredOption(options, '--workspace'), '--workspace');
  const runDir = existingDirectory(requiredOption(options, '--run-dir'), '--run-dir');
  const seedFingerprint = requiredOption(options, '--seed-fingerprint');
  const seedTreeFingerprint = requiredOption(options, '--seed-tree-fingerprint');
  const codexVersion = requiredOption(options, '--codex-version');
  const experimentId = requiredOption(options, '--experiment-id');
  const runId = requiredOption(options, '--run-id');
  assertWorkspaceRunDir(workspace, runDir);
  if (!/^\d+\.\d+\.\d+$/.test(codexVersion)) {
    throw new Error('--codex-version must be an exact semantic version.');
  }

  const verifiedSeed = verifySeed(seedProject, seedFingerprint, seedTreeFingerprint);
  const actualDdevVersion = String(lastJsonObject(
    runChecked(
      'ddev',
      ['version', '-j'],
      { cwd: seedProject, timeoutMs: 60_000 }
    ).stdout,
    'DDEV version'
  )?.raw?.['DDEV version'] ?? '').replace(/^v/, '');
  if (actualDdevVersion !== verifiedSeed.manifest.ddevVersion) {
    throw new Error(
      `DDEV version mismatch: expected ${verifiedSeed.manifest.ddevVersion}, got ${actualDdevVersion || '<empty>'}.`
    );
  }
  copySeed(seedProject, workspace);
  verifySeed(workspace, seedFingerprint, seedTreeFingerprint);

  // Assign the owned identity before any DDEV operation can register this copy.
  const projectName = ddevProjectName(experimentId, runId);
  setDdevProjectName(workspace, projectName);
  configureDdevIsolation(workspace, runDir);
  configureTrackedSyncDirectory(workspace);
  writeOwner(runDir, {
    schemaVersion: OWNER_SCHEMA,
    experimentId,
    runId,
    projectName,
    appRoot: workspace,
    seedFingerprint,
    seedTreeFingerprint,
    seedTreeProjection: verifiedSeed.completeProjection,
    baselineState: null,
    preInitInvariantProjection: null,
    preInitConfigProjection: null,
    preInitGitControlProjection: null,
    buildInvariantProjection: null,
    gitControlProjection: null,
    initializedCommit: null
  });
  const transientPaths = [
    '.ddev/traefik',
    '.benchmark-runtime',
    '.agent-ready-drupal',
    '.agents',
    'benchmark-brief.md',
    'review-packet'
  ];
  for (const path of transientPaths) {
    const target = resolve(workspace, path);
    if (!isWithin(target, workspace) || target === workspace) {
      throw new Error(`Unsafe transient path: ${path}`);
    }
    rmSync(target, { recursive: true, force: true });
  }

  writeFileSync(join(workspace, 'AGENTS.md'), BENCHMARK_AGENTS);
  writeFileSync(join(workspace, 'benchmark-brief.md'), BENCHMARK_BRIEF);

  runChecked('git', ['-C', workspace, 'init', '--initial-branch=benchmark-base'], {
    cwd: workspace,
    timeoutMs: 60_000
  });
  // DDEV writes router state for multiple registered projects here. Keep that
  // host-runtime state out of the measured Git cleanliness contract.
  addLocalGitExclude(workspace, '.ddev/traefik/');
  addLocalGitExclude(workspace, '.benchmark-runtime/');
  runChecked('git', ['-C', workspace, 'config', 'user.name', 'Agent Ready Benchmark'], {
    cwd: workspace,
    timeoutMs: 60_000
  });
  runChecked('git', ['-C', workspace, 'config', 'user.email', 'benchmark@example.invalid'], {
    cwd: workspace,
    timeoutMs: 60_000
  });
  commitAll(workspace, 'chore: create frozen grants benchmark substrate');

  runChecked('ddev', ['start'], { cwd: workspace });
  assertOwnedDdev(readOwner(runDir), workspace, runDir);
  const actualCodexVersion = runChecked(
    'ddev',
    ['codex', '--version'],
    { cwd: workspace, timeoutMs: 60_000 }
  ).stdout.trim();
  if (actualCodexVersion !== `codex-cli ${codexVersion}`) {
    throw new Error(`Codex CLI version mismatch: expected ${codexVersion}, got ${actualCodexVersion || '<empty>'}.`);
  }
  runChecked('ddev', ['import-db', '--file', 'benchmark-seed/seed.sql.gz'], { cwd: workspace });
  const actualSyncDirectory = runChecked(
    'ddev',
    projectDrushArgs([
      'php:eval',
      'echo \\Drupal\\Core\\Site\\Settings::get("config_sync_directory", ""), PHP_EOL;'
    ]),
    { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
  ).stdout.trim();
  if (actualSyncDirectory !== '../config/sync') {
    throw new Error(`Drupal config-sync mismatch: expected ../config/sync, got ${actualSyncDirectory || '<empty>'}.`);
  }
  runChecked(
    'ddev',
    projectDrushArgs(['status', '--field=bootstrap', '--format=string']),
    { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
  );
  const baselineState = readStateProjection(workspace);
  writeOwner(runDir, {
    ...readOwner(runDir),
    baselineState,
    preInitInvariantProjection: preInitInvariantProjection(workspace),
    preInitConfigProjection: configSyncProjection(workspace),
    preInitGitControlProjection: gitControlProjection(workspace)
  }, { allowExisting: true });
  const preparedStatus = cleanPreview(workspace);
  if (preparedStatus) {
    throw new Error(`Preparation did not leave a clean Git worktree: ${preparedStatus.slice(0, 1000)}`);
  }

  process.stdout.write(`${JSON.stringify({
    prepared: true,
    projectName,
    codexVersion,
    seedFingerprint,
    seedTreeFingerprint,
    seedTreeProjection: verifiedSeed.completeProjection,
    workspace
  })}\n`);
}

function precheck(options) {
  const workspace = existingDirectory(requiredOption(options, '--workspace'), '--workspace');
  const runDir = existingDirectory(requiredOption(options, '--run-dir'), '--run-dir');
  assertWorkspaceRunDir(workspace, runDir);
  const owner = readOwner(runDir);
  if (!owner) {
    throw new Error('The benchmark precheck requires the external ownership marker.');
  }
  assertOwnerWorkspace(owner, workspace);
  assertPreInitInvariant(owner, workspace);
  if (!sameJson(gitControlProjection(workspace), owner.preInitGitControlProjection)) {
    throw new Error('Git control files changed before kit initialization.');
  }
  assertOwnedDdev(owner, workspace, runDir);
  if (!sameJson(readStateProjection(workspace), owner.baselineState)) {
    throw new Error('Drupal state changed before kit initialization.');
  }
  process.stdout.write(`${JSON.stringify({ prechecked: true, workspace })}\n`);
}

function install(options) {
  const workspace = existingDirectory(requiredOption(options, '--workspace'), '--workspace');
  const runDir = existingDirectory(requiredOption(options, '--run-dir'), '--run-dir');
  const armKit = existingDirectory(requiredOption(options, '--arm-kit'), '--arm-kit');
  assertWorkspaceRunDir(workspace, runDir);
  const owner = readOwner(runDir);
  if (!owner) {
    throw new Error('The timed install requires the external benchmark ownership marker.');
  }
  assertOwnerWorkspace(owner, workspace);
  const armSkill = join(armKit, 'skills', 'agent-ready-drupal-build-kit');
  if (!existsSync(join(armSkill, 'SKILL.md'))) {
    throw new Error('--arm-kit does not contain skills/agent-ready-drupal-build-kit/SKILL.md.');
  }
  const installedSkill = join(workspace, '.agents', 'skills', 'agent-ready-drupal-build-kit');
  mkdirSync(join(workspace, '.agents', 'skills'), { recursive: true });
  cpSync(armSkill, installedSkill, {
    recursive: true,
    force: false,
    errorOnExist: true,
    preserveTimestamps: true,
    verbatimSymlinks: true
  });
  runChecked(
    'ddev',
    [
      'exec',
      'node',
      '.agents/skills/agent-ready-drupal-build-kit/scripts/init-kit.mjs',
      '--brief-file',
      'benchmark-brief.md',
      '--project',
      '/var/www/html'
    ],
    { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
  );
  process.stdout.write(`${JSON.stringify({
    installed: true,
    workspace
  })}\n`);
}

function seal(options) {
  const workspace = existingDirectory(requiredOption(options, '--workspace'), '--workspace');
  const runDir = existingDirectory(requiredOption(options, '--run-dir'), '--run-dir');
  assertWorkspaceRunDir(workspace, runDir);
  const owner = readOwner(runDir);
  if (!owner) {
    throw new Error('The benchmark seal requires the external ownership marker.');
  }
  assertOwnerWorkspace(owner, workspace);

  // Check host-only protected trees before invoking any project-controlled
  // DDEV or Git surface from the measured initializer revision.
  assertPreInitInvariant(owner, workspace);
  if (!sameJson(gitControlProjection(workspace), owner.preInitGitControlProjection)) {
    throw new Error('The kit initializer changed protected Git control files.');
  }
  assertOwnedDdev(owner, workspace, runDir);
  if (!sameJson(readStateProjection(workspace), owner.baselineState)) {
    throw new Error('The kit initializer changed the frozen Drupal state.');
  }
  clearGeneratedRuntimeTrees(workspace);
  containerCommitAll(workspace, 'chore: initialize grants benchmark kit');
  const initializedCommit = containerGitChecked(
    workspace,
    ['rev-parse', '--verify', 'HEAD']
  ).stdout.trim();
  if (!/^[a-f0-9]{40,64}$/.test(initializedCommit)) {
    throw new Error('Unable to record the initialized Git commit.');
  }
  const sealedOwner = {
    ...owner,
    initializedCommit,
    buildInvariantProjection: buildInvariantProjection(workspace),
    gitControlProjection: gitControlProjection(workspace)
  };
  writeOwner(runDir, sealedOwner, { allowExisting: true });

  // Recreate the owned containers after arm-controlled initialization so no
  // initializer process or writable container layer survives into the
  // credentialed agent turn.
  removeOwnedContainers(sealedOwner, workspace);
  runChecked('ddev', ['start'], { cwd: workspace, timeoutMs: 10 * 60 * 1000 });
  clearGeneratedRuntimeTrees(workspace);
  assertBuildInvariant(sealedOwner, workspace);
  assertGitControlInvariant(sealedOwner, workspace);
  assertOwnedDdev(sealedOwner, workspace, runDir);
  if (!sameJson(readStateProjection(workspace), sealedOwner.baselineState)) {
    throw new Error('Container recreation did not preserve the frozen Drupal state.');
  }
  clearGeneratedRuntimeTrees(workspace);
  assertBuildInvariant(sealedOwner, workspace);
  assertGitControlInvariant(sealedOwner, workspace);
  provisionRuntimeCredential(sealedOwner, workspace, runDir);
  process.stdout.write(`${JSON.stringify({ sealed: true, workspace })}\n`);
}

function lastJsonObject(output, label) {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const start = lines[index].indexOf('{');
    if (start === -1) {
      continue;
    }
    try {
      return JSON.parse(lines[index].slice(start));
    } catch {
      // Continue toward older lines in case DDEV emitted a suffix message.
    }
  }
  throw new Error(`${label} did not return a JSON object.`);
}

function readStateProjection(workspace) {
  const projection = lastJsonObject(
    runChecked(
      'ddev',
      projectDrushArgs(['php:eval', STATE_PROJECTION_PHP]),
      { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
    ).stdout,
    'Drupal baseline state projection'
  );
  if (
    !projection?.configHashes ||
    typeof projection.configHashes !== 'object' ||
    Array.isArray(projection.configHashes) ||
    Object.keys(projection.configHashes).length === 0 ||
    Object.keys(projection.configHashes).length > 5000
  ) {
    throw new Error('Drupal state projection returned an invalid config hash map.');
  }
  for (const [label, hashes] of [
    ['active', projection.configHashes],
    ['export', projection.exportConfigHashes],
    ['sync', projection.syncConfigHashes]
  ]) {
    if (
      !hashes ||
      typeof hashes !== 'object' ||
      Array.isArray(hashes) ||
      Object.keys(hashes).length === 0 ||
      Object.keys(hashes).length > 5000
    ) {
      throw new Error(`Drupal state projection returned an invalid ${label} config hash map.`);
    }
    for (const [name, digest] of Object.entries(hashes)) {
      if (!name.includes(':') || !/^[a-f0-9]{64}$/.test(digest)) {
        throw new Error(`Drupal state projection returned an invalid ${label} config identity.`);
      }
    }
  }
  if (!sameJson(projection.exportConfigHashes, projection.syncConfigHashes)) {
    throw new Error('Drupal canonical export and sync configuration must be globally identical.');
  }
  if (
    !projection.durableEntities ||
    typeof projection.durableEntities !== 'object' ||
    Array.isArray(projection.durableEntities)
  ) {
    throw new Error('Drupal state projection returned an invalid durable-entity map.');
  }
  for (const value of Object.values(projection.durableEntities)) {
    if (
      !Number.isSafeInteger(value?.count) ||
      value.count < 0 ||
      !/^[a-f0-9]{64}$/.test(value?.sha256 ?? '')
    ) {
      throw new Error('Drupal state projection returned an invalid durable-entity identity.');
    }
  }
  if (
    !projection.contentEditorConfig ||
    typeof projection.contentEditorConfig !== 'object' ||
    !projection.workflowConfig ||
    typeof projection.workflowConfig !== 'object'
  ) {
    throw new Error('Drupal state projection omitted the governed role or workflow config.');
  }
  return projection;
}

function containerGitArgs(args) {
  return [
    'exec',
    'env',
    'GIT_CONFIG_NOSYSTEM=1',
    'GIT_CONFIG_GLOBAL=/dev/null',
    'GIT_EXTERNAL_DIFF=',
    'GIT_NO_REPLACE_OBJECTS=1',
    'git',
    '--git-dir=/var/www/html/.git',
    '--work-tree=/var/www/html',
    '-c',
    'core.hooksPath=/dev/null',
    '-c',
    'core.fsmonitor=false',
    '-c',
    'commit.gpgsign=false',
    ...args
  ];
}

function containerGitResult(workspace, args, timeoutMs = 60_000) {
  return commandResult('ddev', containerGitArgs(args), {
    cwd: workspace,
    timeoutMs
  });
}

function containerGitChecked(workspace, args, timeoutMs = 60_000) {
  return runChecked('ddev', containerGitArgs(args), {
    cwd: workspace,
    timeoutMs
  });
}

function containerCleanPreview(workspace) {
  return containerGitChecked(
    workspace,
    ['status', '--porcelain=v1', '--untracked-files=all']
  ).stdout.trim();
}

function containerCommitAll(workspace, message) {
  containerGitChecked(workspace, ['add', '--all'], 5 * 60 * 1000);
  const staged = containerGitResult(workspace, ['diff', '--cached', '--quiet']);
  if (staged.error || ![0, 1].includes(staged.status)) {
    throw new Error(`Unable to inspect prepared Git changes inside DDEV: ${resultDetail(staged)}`);
  }
  if (staged.status === 1) {
    containerGitChecked(
      workspace,
      ['commit', '--no-verify', '-m', message],
      5 * 60 * 1000
    );
  }
  const status = containerCleanPreview(workspace);
  if (status) {
    throw new Error(`Container commit did not leave a clean Git worktree: ${status.slice(0, 1000)}`);
  }
}

function collectAllowedTreeFiles(workspace) {
  const rows = [];
  function walk(directory, projectRoot) {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const projectPath = relative(workspace, path).split(sep).join('/');
      const entry = lstatSync(path);
      if (entry.isSymbolicLink()) {
        throw new Error(`Committed output tree contains a symbolic link: ${projectPath}`);
      }
      if (entry.isDirectory()) {
        walk(path, projectRoot);
      } else if (entry.isFile()) {
        rows.push({
          path: projectPath,
          mode: entry.mode & 0o111 ? '100755' : '100644',
          bytes: readFileSync(path)
        });
      } else {
        throw new Error(`Committed output tree contains an unsupported entry: ${projectPath}`);
      }
    }
  }
  for (const projectRoot of ['config/sync', 'review-packet']) {
    const root = resolve(workspace, projectRoot);
    if (!existsSync(root) || !lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) {
      throw new Error(`Committed output tree is missing or unsafe: ${projectRoot}`);
    }
    walk(root, projectRoot);
  }
  return rows;
}

function gitBlobHash(bytes, objectFormat) {
  if (!['sha1', 'sha256'].includes(objectFormat)) {
    throw new Error(`Unsupported Git object format: ${objectFormat}`);
  }
  return createHash(objectFormat)
    .update(`blob ${bytes.length}\0`)
    .update(bytes)
    .digest('hex');
}

function assertAllowedTreesCommitted(workspace) {
  containerGitChecked(workspace, ['fsck', '--full', '--no-dangling'], 5 * 60 * 1000);
  const objectFormat = containerGitChecked(
    workspace,
    ['rev-parse', '--show-object-format']
  ).stdout.trim();
  const actualRows = collectAllowedTreeFiles(workspace).map(({ path, mode, bytes }) => (
    `${mode}\0${path}\0${gitBlobHash(bytes, objectFormat)}`
  )).sort();
  const treeOutput = containerGitChecked(
    workspace,
    ['ls-tree', '-r', '-z', 'HEAD', '--', 'config/sync', 'review-packet']
  ).stdout;
  const headRows = treeOutput.split('\0').filter(Boolean).map((row) => {
    const match = row.match(/^(\d{6}) (blob) ([a-f0-9]+)\t(.+)$/s);
    if (!match || !['100644', '100755'].includes(match[1])) {
      throw new Error('HEAD contains a non-regular or malformed committed output entry.');
    }
    return `${match[1]}\0${match[4]}\0${match[3]}`;
  }).sort();
  if (!sameJson(actualRows, headRows)) {
    throw new Error('Config sync or review-packet bytes do not exactly match the final HEAD tree.');
  }
}

function qualityResult(outcomes, blockers) {
  const uniqueBlockers = [...new Set(blockers.map((value) => String(value).replace(/\s+/g, ' ').trim().slice(0, 1000)))];
  for (const [name, message] of Object.entries(OUTCOME_LABELS)) {
    if (!outcomes[name]) {
      uniqueBlockers.push(message);
    }
  }
  const normalizedBlockers = [...new Set(uniqueBlockers)];
  return {
    schemaVersion: QUALITY_SCHEMA,
    valid:
      Object.values(outcomes).every((value) => value === true) &&
      normalizedBlockers.length === 0,
    outcomes,
    blockers: normalizedBlockers
  };
}

function canonicalDeadline(value) {
  const match = String(value ?? '').match(/^(\d{4}-\d{2}-\d{2})(?:T00:00:00)?$/);
  return match?.[1] ?? null;
}

function rowsMatchRequiredValues(rows, { requireGrantBundle = false } = {}) {
  if (!Array.isArray(rows) || rows.length !== REQUIRED_TITLES.length) {
    return false;
  }
  const sortedRows = [...rows].sort((left, right) => String(left?.title).localeCompare(String(right?.title)));
  if (
    JSON.stringify(sortedRows.map((row) => row?.title)) !==
    JSON.stringify(REQUIRED_TITLES)
  ) {
    return false;
  }
  return sortedRows.every((row) => {
    const required = REQUIRED_GRANTS[row.title];
    const amount = Number(row.amount);
    return (
      required &&
      row.published === true &&
      (!requireGrantBundle || row.bundle === 'grant') &&
      Number.isFinite(amount) &&
      amount === required.amount &&
      canonicalDeadline(row.deadline) === required.deadline
    );
  });
}

function evaluate(options) {
  const outcomes = Object.fromEntries(Object.keys(OUTCOME_LABELS).map((name) => [name, false]));
  const blockers = [];
  let grantAliasesAbsentPass = false;
  const workspace = existingDirectory(requiredOption(options, '--workspace'), '--workspace');
  const runDir = existingDirectory(requiredOption(options, '--run-dir'), '--run-dir');
  const evaluatorKit = existingDirectory(requiredOption(options, '--evaluator-kit'), '--evaluator-kit');
  assertWorkspaceRunDir(workspace, runDir);
  const owner = readOwner(runDir);
  if (!owner) {
    throw new Error('The evaluator requires the external benchmark ownership marker.');
  }
  assertOwnerWorkspace(owner, workspace);

  // Revoke auth through externally validated Docker identity before invoking
  // any project-controlled DDEV or Git surface. Then discard both mutable
  // service containers so agent-spawned processes and writable layers cannot
  // participate in the fixed evaluation.
  revokeRuntimeCredential(owner, workspace, runDir);
  removeOwnedContainers(owner, workspace);
  clearGeneratedRuntimeTrees(workspace);
  assertBuildInvariant(owner, workspace);
  assertGitControlInvariant(owner, workspace);
  runChecked('ddev', ['start'], { cwd: workspace, timeoutMs: 10 * 60 * 1000 });
  clearGeneratedRuntimeTrees(workspace);
  assertBuildInvariant(owner, workspace);
  assertGitControlInvariant(owner, workspace);
  assertOwnedDdev(owner, workspace, runDir);
  assertContainerCredentialRevoked(owner, workspace);

  try {
    const bootstrap = runChecked(
      'ddev',
      projectDrushArgs(['status', '--field=bootstrap', '--format=string']),
      { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
    ).stdout.trim();
    outcomes.drupalBootstrapPass = /successful/i.test(bootstrap);
    runChecked(
      'ddev',
      projectDrushArgs(['cr']),
      { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
    );
  } catch (error) {
    blockers.push(`Drupal bootstrap check failed: ${error.message}`);
  }

  try {
    const result = runChecked(
      'ddev',
      projectDrushArgs(['php:eval', DRUPAL_FACTS_PHP]),
      { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
    );
    const facts = lastJsonObject(result.stdout, 'Drupal facts check');
    grantAliasesAbsentPass = facts.grantAliasCount === 0;
    outcomes.grantContentTypePass = facts.grantTypeExists === true;
    outcomes.grantFieldsPass =
      facts.amountFieldType === 'decimal' &&
      facts.deadlineFieldType === 'datetime' &&
      facts.amountFieldRequired === true &&
      facts.deadlineFieldRequired === true &&
      facts.amountFieldCardinality === 1 &&
      facts.deadlineFieldCardinality === 1;
    const rows = Array.isArray(facts.grantRows) ? facts.grantRows : [];
    const rowTitles = rows.map((row) => row?.title).sort();
    outcomes.publishedGrantContentPass =
      facts.grantCount === REQUIRED_TITLES.length &&
      facts.publishedGrantCount === REQUIRED_TITLES.length &&
      rows.length === REQUIRED_TITLES.length &&
      rows.every((row) => row?.published === true) &&
      JSON.stringify(rowTitles) === JSON.stringify(REQUIRED_TITLES);
    outcomes.grantFieldValuesPass = rowsMatchRequiredValues(rows, { requireGrantBundle: true });
    outcomes.grantsViewDefinitionPass =
      facts.grantsViewExists === true &&
      facts.grantsViewStorageEnabled === true &&
      facts.grantsViewBaseTable === 'node_field_data' &&
      Array.isArray(facts.grantsViewPaths) &&
      facts.grantsViewPaths.includes('/grants') &&
      facts.grantsMatchingPageDisplayCount === 1 &&
      typeof facts.grantsPageDisplayId === 'string' &&
      facts.grantsPageDisplayId !== '' &&
      facts.grantsViewSetDisplayPass === true &&
      facts.grantsViewDisplayEnabled === true &&
      facts.grantsRouteName === `view.grants.${facts.grantsPageDisplayId}` &&
      facts.grantsViewFiltersGrant === true &&
      facts.grantsViewFiltersPublished === true &&
      facts.grantsViewFieldsPass === true &&
      boundedGrantsViewStructurePass(facts);
    outcomes.grantsViewExecutionPass =
      facts.grantsViewExecutePass === true &&
      rowsMatchRequiredValues(facts.grantsViewResultRows, { requireGrantBundle: true });
    outcomes.grantConfigurationParityPass =
      facts.globalConfigParity === true &&
      facts.globalConfigDifferenceCount === 0 &&
      facts.configParity &&
      JSON.stringify(Object.keys(facts.configParity).sort()) ===
        JSON.stringify([...FOCUSED_CONFIG_NAMES].sort()) &&
      Object.values(facts.configParity).every((value) => value === true);
    outcomes.grantEditorialGovernancePass =
      facts.formComponentsPass === true &&
      facts.viewComponentsPass === true &&
      facts.grantWorkflowPass === true &&
      facts.editorPermissionsPass === true &&
      facts.grantsViewFieldsPass === true;
  } catch (error) {
    blockers.push(`Drupal facts check failed: ${error.message}`);
  }

  try {
    const finalState = readStateProjection(workspace);
    outcomes.boundedConfigDeltaPass = boundedConfigDeltaPass(owner.baselineState, finalState);
    outcomes.preexistingDurableStatePass = sameJson(
      owner.baselineState?.durableEntities,
      finalState.durableEntities
    ) && grantAliasesAbsentPass;
  } catch (error) {
    blockers.push(`Bounded state comparison failed: ${error.message}`);
  }

  try {
    const listing = runChecked(
      'ddev',
      [
        'exec',
        'curl',
        '--fail',
        '--silent',
        '--show-error',
        '--max-time',
        '60',
        'http://web/grants'
      ],
      { cwd: workspace, timeoutMs: 90_000 }
    ).stdout;
    const normalizedListing = listing.replaceAll(',', '');
    outcomes.grantsListingHttpPass = true;
    outcomes.grantsListingContentPass =
      REQUIRED_TITLES.every((title) => normalizedListing.includes(title)) &&
      REQUIRED_RENDERED_VALUES.every((value) => normalizedListing.includes(value));
  } catch (error) {
    blockers.push(`Rendered listing check failed: ${error.message}`);
  }

  try {
    if (!/^[a-f0-9]{40,64}$/.test(owner.initializedCommit ?? '')) {
      throw new Error('The ownership marker does not contain a valid initialized commit.');
    }
    containerGitChecked(workspace, ['cat-file', '-e', `${owner.initializedCommit}^{commit}`]);
    const ancestor = containerGitResult(
      workspace,
      ['merge-base', '--is-ancestor', owner.initializedCommit, 'HEAD']
    );
    if (ancestor.error || ancestor.status !== 0) {
      throw new Error(`The initialized commit is not an ancestor of HEAD: ${resultDetail(ancestor)}`);
    }
    const changedPaths = containerGitChecked(
      workspace,
      [
        'diff',
        '--name-only',
        '--diff-filter=ACDMRTUXB',
        `${owner.initializedCommit}..HEAD`
      ]
    ).stdout.split(/\r?\n/).map((path) => path.trim()).filter(Boolean);
    const pathViolations = configOnlyPathViolations(changedPaths);
    const exactConfigPaths = exactConfigSyncDiffPass(changedPaths);
    assertAllowedTreesCommitted(workspace);
    outcomes.boundedCustomCodeFootprintPass =
      pathViolations.length === 0 &&
      exactConfigPaths;
    if (pathViolations.length > 0) {
      blockers.push(`Paths outside config sync or review packet: ${pathViolations.join(', ').slice(0, 1000)}`);
    }
    if (!exactConfigPaths) {
      blockers.push('Final config-sync filenames did not exactly match the eight additions plus the role and workflow changes.');
    }
  } catch (error) {
    blockers.push(`Custom-code footprint check failed: ${error.message}`);
  }

  try {
    outcomes.gitWorktreeCleanPass = containerCleanPreview(workspace) === '';
  } catch (error) {
    blockers.push(`Git cleanliness check failed: ${error.message}`);
  }

  try {
    const evaluatorSkill = join(
      evaluatorKit,
      'skills',
      'agent-ready-drupal-build-kit'
    );
    const sourceVerifier = join(evaluatorSkill, 'scripts', 'verify-packet.mjs');
    if (
      !existsSync(sourceVerifier) ||
      !lstatSync(sourceVerifier).isFile() ||
      lstatSync(sourceVerifier).isSymbolicLink()
    ) {
      throw new Error('The evaluator kit packet-only verifier is missing.');
    }
    const runtimeRoot = join(workspace, '.benchmark-runtime');
    rmSync(runtimeRoot, { recursive: true, force: true });
    mkdirSync(runtimeRoot, { recursive: true });
    cpSync(evaluatorSkill, join(runtimeRoot, 'evaluator'), {
      recursive: true,
      force: false,
      errorOnExist: true,
      preserveTimestamps: true,
      verbatimSymlinks: true
    });
    const packetReport = join(runtimeRoot, 'packet-only-evaluation.json');
    const result = commandResult(
      'ddev',
      [
        'exec',
        'node',
        '.benchmark-runtime/evaluator/scripts/verify-packet.mjs',
        '--packet',
        'review-packet',
        '--out',
        '.benchmark-runtime/packet-only-evaluation.json'
      ],
      { cwd: workspace, timeoutMs: 20 * 60 * 1000 }
    );
    let report = null;
    if (existsSync(packetReport)) {
      report = JSON.parse(readFileSync(packetReport, 'utf8'));
    }
    outcomes.packetOnlyVerifierPass =
      !result.error &&
      result.status === 0 &&
      report?.schemaVersion === PACKET_SCHEMA &&
      report?.verificationMode === 'packet-only' &&
      report?.valid === true;
    if (!outcomes.packetOnlyVerifierPass) {
      blockers.push(`Packet-only verifier failed: ${resultDetail(result)}`);
    }
  } catch (error) {
    blockers.push(`Packet-only verifier check failed: ${error.message}`);
  }

  try {
    clearGeneratedRuntimeTrees(workspace);
    assertBuildInvariant(owner, workspace);
    assertGitControlInvariant(owner, workspace);
    assertAllowedTreesCommitted(workspace);
    if (containerCleanPreview(workspace) !== '') {
      outcomes.gitWorktreeCleanPass = false;
      throw new Error('The evaluator did not leave the final Git worktree clean.');
    }
  } catch (error) {
    outcomes.boundedCustomCodeFootprintPass = false;
    outcomes.gitWorktreeCleanPass = false;
    blockers.push(`Final protected-tree check failed: ${error.message}`);
  }

  return qualityResult(outcomes, blockers);
}

function cleanup(options) {
  const workspace = existingDirectory(requiredOption(options, '--workspace'), '--workspace');
  const runDir = existingDirectory(requiredOption(options, '--run-dir'), '--run-dir');
  const experimentId = requiredOption(options, '--experiment-id');
  const runId = requiredOption(options, '--run-id');
  assertWorkspaceRunDir(workspace, runDir);
  const expectedProjectName = ddevProjectName(experimentId, runId);
  const provisionalOwner = {
    projectName: expectedProjectName,
    appRoot: workspace
  };
  rmSync(join(runDir, 'credential-seed', 'auth.json'), { force: true });
  let owner;
  try {
    owner = readOwner(runDir);
  } catch (error) {
    revokeRuntimeCredential(provisionalOwner, workspace, runDir);
    removeOwnedContainers(provisionalOwner, workspace);
    throw error;
  }
  if (!owner) {
    revokeRuntimeCredential(provisionalOwner, workspace, runDir);
    removeOwnedContainers(provisionalOwner, workspace);
    process.stdout.write('No owned DDEV project required cleanup.\n');
    return;
  }
  if (
    owner.experimentId !== experimentId ||
    owner.runId !== runId ||
    owner.projectName !== expectedProjectName ||
    owner.appRoot !== workspace
  ) {
    revokeRuntimeCredential(provisionalOwner, workspace, runDir);
    removeOwnedContainers(provisionalOwner, workspace);
    throw new Error('Refusing cleanup because the ownership marker does not match this run.');
  }
  revokeRuntimeCredential(owner, workspace, runDir);
  let configuredProjectName = '';
  try {
    configuredProjectName = ddevConfigName(workspace);
  } catch (error) {
    removeOwnedContainers(owner, workspace);
    throw error;
  }
  if (configuredProjectName !== expectedProjectName) {
    removeOwnedContainers(owner, workspace);
    throw new Error('Cleanup removed owned containers after detecting a mismatched DDEV configuration.');
  }
  try {
    // Discard the agent-visible process namespace before touching generated
    // host trees. Exact Docker labels and mounts are validated by removal.
    removeOwnedContainers(owner, workspace);
    clearGeneratedRuntimeTrees(workspace);
    if (owner.buildInvariantProjection) {
      assertBuildInvariant(owner, workspace);
    }
    if (owner.gitControlProjection) {
      assertGitControlInvariant(owner, workspace);
    }
    runChecked(
      'ddev',
      ['stop', expectedProjectName, '--unlist', '--skip-hooks'],
      { cwd: workspace, timeoutMs: 5 * 60 * 1000 }
    );
  } catch (error) {
    removeOwnedContainers(owner, workspace);
    throw error;
  }
  process.stdout.write('DDEV project stopped and unlisted.\n');
}

function fingerprint(options) {
  const seedProject = existingDirectory(requiredOption(options, '--seed-project'), '--seed-project');
  process.stdout.write(`${JSON.stringify({
    schemaVersion: SEED_TREE_SCHEMA,
    ...copiedSeedProjection(seedProject)
  })}\n`);
}

function packageVersion(composerLock, names) {
  const packages = [
    ...(Array.isArray(composerLock?.packages) ? composerLock.packages : []),
    ...(Array.isArray(composerLock?.['packages-dev']) ? composerLock['packages-dev'] : [])
  ];
  for (const name of names) {
    const match = packages.find((item) => item?.name === name);
    if (typeof match?.version === 'string' && match.version !== '') {
      return match.version.replace(/^v/, '');
    }
  }
  throw new Error(`composer.lock does not contain any of: ${names.join(', ')}`);
}

function freezeSeed(options) {
  const seedProject = existingDirectory(requiredOption(options, '--seed-project'), '--seed-project');
  const installerSha256 = requiredOption(options, '--installer-sha256');
  assertHexSha256(installerSha256, '--installer-sha256');
  const composerJsonPath = join(seedProject, 'composer.json');
  const composerLockPath = join(seedProject, 'composer.lock');
  const composerJson = parseJsonFile(composerJsonPath, 'Seed composer.json');
  const composerLock = parseJsonFile(composerLockPath, 'Seed composer.lock');
  if (typeof composerJson.version !== 'string' || composerJson.version === '') {
    throw new Error('Seed composer.json must declare the exact Drupal CMS version.');
  }
  const drupalCoreVersion = packageVersion(composerLock, [
    'drupal/core-recommended',
    'drupal/core'
  ]);
  const ddevVersion = String(lastJsonObject(
    runChecked(
      'ddev',
      ['version', '-j'],
      { cwd: seedProject, timeoutMs: 60_000 }
    ).stdout,
    'DDEV version'
  )?.raw?.['DDEV version'] ?? '').replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+/.test(ddevVersion)) {
    throw new Error('Unable to determine an exact DDEV version.');
  }
  // A frozen seed is only valid when its canonical export already represents
  // the complete active configuration. readStateProjection fails on any
  // collection, name, or normalized-value drift.
  readStateProjection(seedProject);

  assertSafeSeedOutputPaths(seedProject);
  const seedDirectory = join(seedProject, 'benchmark-seed');
  mkdirSync(seedDirectory, { recursive: true });
  assertSafeSeedOutputPaths(seedProject);
  const databasePath = join(seedDirectory, 'seed.sql.gz');
  const temporaryDatabasePath = join(seedDirectory, `.seed-${process.pid}.sql.gz`);
  rmSync(temporaryDatabasePath, { force: true });
  runChecked(
    'ddev',
    ['export-db', '--file', temporaryDatabasePath, '--gzip'],
    { cwd: seedProject, timeoutMs: 30 * 60 * 1000 }
  );
  if (
    !existsSync(temporaryDatabasePath) ||
    !lstatSync(temporaryDatabasePath).isFile() ||
    lstatSync(temporaryDatabasePath).isSymbolicLink()
  ) {
    throw new Error('DDEV did not create a regular compressed seed database.');
  }
  renameSync(temporaryDatabasePath, databasePath);

  const identity = {
    schemaVersion: SEED_SCHEMA,
    createdAt: new Date().toISOString(),
    installerSha256,
    drupalCmsVersion: composerJson.version,
    drupalCoreVersion,
    ddevVersion,
    composerJsonSha256: fileSha256(composerJsonPath),
    composerLockSha256: fileSha256(composerLockPath),
    databaseSha256: fileSha256(databasePath),
    config: treeProjection(seedProject, join(seedProject, 'config', 'sync')),
    publicFiles: treeProjection(seedProject, join(seedProject, 'web', 'sites', 'default', 'files'))
  };
  const manifest = {
    ...identity,
    fingerprint: sha256Bytes(JSON.stringify(identity))
  };
  writeFileSync(
    join(seedDirectory, 'manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`
  );
  process.stdout.write(`${JSON.stringify({
    manifest,
    completeTree: {
      schemaVersion: SEED_TREE_SCHEMA,
      ...copiedSeedProjection(seedProject)
    }
  })}\n`);
}

function main() {
  const command = process.argv[2] ?? '';
  const rawOptions = process.argv.slice(3);
  if (command === 'evaluate') {
    let result;
    try {
      result = evaluate(parseOptions(rawOptions));
    } catch (error) {
      const outcomes = Object.fromEntries(Object.keys(OUTCOME_LABELS).map((name) => [name, false]));
      result = qualityResult(outcomes, [`Evaluator failed safely: ${error.message}`]);
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }

  try {
    const options = parseOptions(rawOptions);
    if (command === 'prepare') {
      prepare(options);
    } else if (command === 'precheck') {
      precheck(options);
    } else if (command === 'install') {
      install(options);
    } else if (command === 'seal') {
      seal(options);
    } else if (command === 'cleanup') {
      cleanup(options);
    } else if (command === 'fingerprint') {
      fingerprint(options);
    } else if (command === 'freeze-seed') {
      freezeSeed(options);
    } else {
      throw new Error('Usage: node adapter.mjs <freeze-seed|fingerprint|prepare|precheck|install|seal|evaluate|cleanup> [options]');
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  main();
}
