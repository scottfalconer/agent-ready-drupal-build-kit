<?php

/**
 * @file
 * Creates or guarded-replaces one Drupal Canvas page from a JSON manifest.
 */

declare(strict_types=1);

use Drupal\canvas\AutoSave\AutoSaveManager;
use Drupal\canvas\Entity\Component;
use Drupal\canvas\Entity\Page;
use Drupal\canvas\PropSource\PropSource;
use Drupal\Component\Uuid\Uuid;
use Symfony\Component\Validator\ConstraintViolationList;

/**
 * Creates or guarded-replaces one Drupal Canvas page from a JSON manifest.
 *
 * Run through Drush's bootstrapped php:script command. The first argument in
 * $extra is the manifest path. The second argument must be --dry-run to
 * validate without saving or --apply to authorize the write explicitly.
 */

if (!\Drupal::moduleHandler()->moduleExists('canvas')) {
  throw new RuntimeException('Drupal Canvas is not enabled. Inspect the installed substrate before choosing a non-Canvas fallback.');
}
if (
  !isset($extra) || !is_array($extra) || count($extra) !== 2 ||
  !isset($extra[0], $extra[1]) ||
  !in_array($extra[1], ['--dry-run', '--apply'], TRUE)
) {
  throw new InvalidArgumentException('Usage: drush php:script canvas-author-page -- /absolute/path/to/manifest.json --dry-run|--apply');
}

$manifest_path = realpath((string) $extra[0]);
if ($manifest_path === FALSE || !is_file($manifest_path) || !is_readable($manifest_path)) {
  throw new InvalidArgumentException(sprintf('Canvas manifest is not a readable file: %s', (string) $extra[0]));
}
$dry_run = $extra[1] === '--dry-run';
$manifest = json_decode((string) file_get_contents($manifest_path), TRUE, 512, JSON_THROW_ON_ERROR);
if (!is_array($manifest)) {
  throw new InvalidArgumentException('Canvas manifest root must be a JSON object.');
}

$allowed_manifest_keys = [
  'operation',
  'pageUuid',
  'expectedExistingAuthoringStateSha256',
  'title',
  'description',
  'path',
  'published',
  'revisionLog',
  'components',
];
$unknown_manifest_keys = array_diff(array_keys($manifest), $allowed_manifest_keys);
if ($unknown_manifest_keys !== []) {
  throw new InvalidArgumentException('Unknown manifest keys: ' . implode(', ', $unknown_manifest_keys));
}

$module_info = \Drupal::service('extension.list.module')->getExtensionInfo('canvas');
$canvas_version = (string) ($module_info['version'] ?? '');
if (preg_match('/^1\.8\./', $canvas_version) !== 1) {
  throw new RuntimeException(sprintf('These headless helpers are tested against Canvas 1.8.x; found %s. Revalidate the API contract before use.', $canvas_version ?: 'an unknown version'));
}

/**
 * Canonicalizes a value before hashing it.
 */
function canvas_kit_author_canonicalize(mixed $value): mixed {
  if (!is_array($value)) {
    return $value;
  }
  if (array_is_list($value)) {
    return array_map(canvas_kit_author_canonicalize(...), $value);
  }
  ksort($value, SORT_STRING);
  foreach ($value as &$item) {
    $item = canvas_kit_author_canonicalize($item);
  }
  unset($item);
  return $value;
}

/**
 * Returns the optimistic-lock digest for a component tree.
 */
function canvas_kit_author_tree_digest(array $tree): string {
  return hash('sha256', json_encode(
    canvas_kit_author_canonicalize($tree),
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
  ));
}

/**
 * Binds every author-controlled Page value that a replacement could overwrite.
 */
function canvas_kit_author_state_digest(Page $page, array $tree, string $canonical_url): string {
  return hash('sha256', json_encode(
    canvas_kit_author_canonicalize([
      'title' => (string) $page->label(),
      'description' => (string) $page->get('description')->value,
      'published' => $page->isPublished(),
      'canonicalUrl' => $canonical_url,
      'componentTree' => $tree,
    ]),
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
  ));
}

/**
 * Builds a round-trippable default client model without rendering a preview.
 */
function canvas_kit_author_default_client_model(Component $component): array {
  $source = $component->getComponentSource();
  if (!$source->requiresExplicitInput()) {
    return ['resolved' => []];
  }
  if ($source->getPluginId() === 'block') {
    return $source->inputToClientModel($source->getDefaultExplicitInput());
  }

  $explicit_input = ['source' => [], 'resolved' => []];
  foreach ($source->getDefaultExplicitInput() as $prop_name => $stored_input) {
    $prop_source = PropSource::parse($stored_input);
    $explicit_input['source'][$prop_name] = $prop_source->toArray();
    $explicit_input['resolved'][$prop_name] = $prop_source->evaluate(NULL, is_required: FALSE);
  }
  return $source->inputToClientModel($explicit_input);
}

/**
 * Formats entity/component constraint violations for a hard failure.
 */
function canvas_kit_author_violation_message(iterable $violations): string {
  $messages = [];
  foreach ($violations as $violation) {
    $messages[] = sprintf('%s: %s', (string) $violation->getPropertyPath(), (string) $violation->getMessage());
  }
  return implode('; ', $messages);
}

$operation = $manifest['operation'] ?? NULL;
if (!in_array($operation, ['create', 'replace'], TRUE)) {
  throw new InvalidArgumentException('manifest.operation must be exactly "create" or "replace"; implicit upserts are not allowed.');
}
$title = $manifest['title'] ?? NULL;
if (!is_string($title) || trim($title) === '') {
  throw new InvalidArgumentException('manifest.title must be a non-empty string.');
}
$title = trim($title);
$path_alias = $manifest['path'] ?? NULL;
if (!is_string($path_alias) || trim($path_alias) === '' || !str_starts_with($path_alias, '/') || str_starts_with($path_alias, '//')) {
  throw new InvalidArgumentException('manifest.path must be a root-relative alias such as /services, not a URL.');
}
$path_alias = trim($path_alias);
if (!isset($manifest['pageUuid']) || !is_string($manifest['pageUuid']) || !Uuid::isValid($manifest['pageUuid'])) {
  throw new InvalidArgumentException('manifest.pageUuid is required and must be a stable lower-case UUID.');
}
$page_uuid = $manifest['pageUuid'];
if (array_key_exists('description', $manifest) && !is_string($manifest['description'])) {
  throw new InvalidArgumentException('manifest.description must be a string when supplied.');
}
if (array_key_exists('published', $manifest) && !is_bool($manifest['published'])) {
  throw new InvalidArgumentException('manifest.published must be a JSON boolean when supplied.');
}
if (array_key_exists('revisionLog', $manifest) && !is_string($manifest['revisionLog'])) {
  throw new InvalidArgumentException('manifest.revisionLog must be a string when supplied.');
}
$component_specs = $manifest['components'] ?? NULL;
if (!is_array($component_specs) || !array_is_list($component_specs) || $component_specs === []) {
  throw new InvalidArgumentException('manifest.components must be a non-empty JSON array.');
}

$entity_type_manager = \Drupal::entityTypeManager();
if (!$entity_type_manager->hasDefinition(Page::ENTITY_TYPE_ID)) {
  throw new RuntimeException('Canvas is enabled but the canvas_page entity type is unavailable.');
}
$page_storage = $entity_type_manager->getStorage(Page::ENTITY_TYPE_ID);

$matches = $page_storage->loadByProperties(['uuid' => $page_uuid]);
$existing_by_uuid = $matches ? reset($matches) : NULL;
$existing_by_alias = NULL;
$alias_records = $entity_type_manager->getStorage('path_alias')->loadByProperties(['alias' => $path_alias]);
foreach ($alias_records as $alias_record) {
  $internal_path = $alias_record->getPath();
  if (preg_match('@^/page/(\d+)$@', $internal_path, $path_matches) !== 1) {
    throw new RuntimeException(sprintf('Path refused: %s is already owned by the non-Canvas route %s.', $path_alias, $internal_path));
  }
  $candidate = $page_storage->load((int) $path_matches[1]);
  if (!$candidate instanceof Page) {
    throw new RuntimeException(sprintf('Path refused: %s points at missing Canvas page %s.', $path_alias, $internal_path));
  }
  if ($existing_by_alias && $existing_by_alias->id() !== $candidate->id()) {
    throw new RuntimeException(sprintf('Path refused: %s ambiguously identifies multiple Canvas pages.', $path_alias));
  }
  $existing_by_alias = $candidate;
}
if ($existing_by_uuid && $existing_by_alias && $existing_by_uuid->id() !== $existing_by_alias->id()) {
  throw new RuntimeException('manifest.pageUuid and manifest.path identify different Canvas pages.');
}
$page = $existing_by_uuid ?: $existing_by_alias;

if ($operation === 'create' && $page) {
  throw new RuntimeException('Create refused: a Canvas page already owns the requested UUID or path. Use replace with its observed authoring-state digest.');
}
if ($operation === 'replace' && !$page) {
  throw new RuntimeException('Replace refused: no Canvas page owns the requested UUID or path. Use create for a new page.');
}
if ($operation === 'create' && array_key_exists('expectedExistingAuthoringStateSha256', $manifest)) {
  throw new InvalidArgumentException('A create manifest must not contain expectedExistingAuthoringStateSha256.');
}

if ($page) {
  assert($page instanceof Page);
  $expected_digest_value = $manifest['expectedExistingAuthoringStateSha256'] ?? NULL;
  $expected_digest = is_string($expected_digest_value) ? strtolower(trim($expected_digest_value)) : '';
  if (preg_match('/^[a-f0-9]{64}$/', $expected_digest) !== 1) {
    throw new InvalidArgumentException('A replace manifest requires expectedExistingAuthoringStateSha256 from canvas-discover.php.');
  }
  $actual_tree = $page->getComponentTree()->getValue();
  $actual_digest = canvas_kit_author_state_digest($page, $actual_tree, $page->toUrl()->toString());
  if (!hash_equals($expected_digest, $actual_digest)) {
    throw new RuntimeException(sprintf('Replace refused: authoring state changed (expected %s, found %s). Rediscover and review before replacing.', $expected_digest, $actual_digest));
  }
}
else {
  $page_values = [
    'uuid' => $page_uuid,
    'title' => $title,
    'status' => $manifest['published'] ?? FALSE,
  ];
  $page = Page::create($page_values);
}
assert($page instanceof Page);

$page->set('title', $title);
if (array_key_exists('description', $manifest) || $page->isNew()) {
  $page->set('description', $manifest['description'] ?? '');
}
if (array_key_exists('published', $manifest) || $page->isNew()) {
  $page->set('status', $manifest['published'] ?? FALSE);
}
$path_value = ['alias' => $path_alias];
if (!$page->isNew() && !$page->get('path')->isEmpty()) {
  $existing_path_value = $page->get('path')->first()->getValue();
  $path_value += array_intersect_key($existing_path_value, array_flip(['pid', 'langcode']));
}
$page->set('path', $path_value);

$keys = [];
$instance_uuids = [];
$component_entities = [];
foreach ($component_specs as $index => $spec) {
  if (!is_array($spec)) {
    throw new InvalidArgumentException(sprintf('components[%d] must be an object.', $index));
  }
  $unknown_component_keys = array_diff(
    array_keys($spec),
    ['key', 'uuid', 'componentId', 'clientModel', 'parent', 'slot'],
  );
  if ($unknown_component_keys !== []) {
    throw new InvalidArgumentException(sprintf('components[%d] has unknown keys: %s', $index, implode(', ', $unknown_component_keys)));
  }
  $key = $spec['key'] ?? NULL;
  $component_id = $spec['componentId'] ?? NULL;
  if (!is_string($key) || !is_string($component_id)) {
    throw new InvalidArgumentException(sprintf('components[%d].key and componentId must be strings.', $index));
  }
  $key = trim($key);
  $component_id = trim($component_id);
  if ($key === '' || isset($keys[$key])) {
    throw new InvalidArgumentException(sprintf('components[%d].key must be non-empty and unique.', $index));
  }
  $component = Component::load($component_id);
  if (!$component instanceof Component) {
    throw new InvalidArgumentException(sprintf('components[%d].componentId is not an enabled Canvas component: %s', $index, $component_id));
  }
  if (!$component->status()) {
    throw new InvalidArgumentException(sprintf('components[%d].componentId is disabled in Canvas: %s', $index, $component_id));
  }
  if ($component->getComponentSource()->isBroken()) {
    throw new RuntimeException(sprintf('Component %s is broken and cannot be authored safely.', $component_id));
  }
  $keys[$key] = $index;
  $instance_uuid = $spec['uuid'] ?? NULL;
  if (!is_string($instance_uuid)) {
    throw new InvalidArgumentException(sprintf('components[%d].uuid is required so dry-run and apply address the same instance.', $index));
  }
  $instance_uuid = trim($instance_uuid);
  if (!Uuid::isValid($instance_uuid) || in_array($instance_uuid, $instance_uuids, TRUE)) {
    throw new InvalidArgumentException(sprintf('components[%d].uuid must be a unique valid lower-case UUID.', $index));
  }
  $instance_uuids[$key] = $instance_uuid;
  $component_entities[$key] = $component;
}

$tree = [];
foreach ($component_specs as $index => $spec) {
  $key = (string) $spec['key'];
  $component = $component_entities[$key];
  if (isset($spec['parent']) && !is_string($spec['parent'])) {
    throw new InvalidArgumentException(sprintf('components[%d].parent must be a string when supplied.', $index));
  }
  if (isset($spec['slot']) && !is_string($spec['slot'])) {
    throw new InvalidArgumentException(sprintf('components[%d].slot must be a string when supplied.', $index));
  }
  $parent_key = isset($spec['parent']) ? trim($spec['parent']) : '';
  $slot = isset($spec['slot']) ? trim($spec['slot']) : '';
  if (($parent_key === '') !== ($slot === '')) {
    throw new InvalidArgumentException(sprintf('components[%d] must supply both parent and slot, or neither for a top-level component.', $index));
  }
  if ($parent_key !== '') {
    if (!isset($keys[$parent_key]) || $keys[$parent_key] >= $index) {
      throw new InvalidArgumentException(sprintf('components[%d].parent must name an earlier component key.', $index));
    }
    $allowed_slots = array_keys($component_entities[$parent_key]->getSlotDefinitions());
    if (!in_array($slot, $allowed_slots, TRUE)) {
      throw new InvalidArgumentException(sprintf('components[%d].slot is not defined by parent %s; allowed slots: %s', $index, $parent_key, implode(', ', $allowed_slots)));
    }
  }

  $source = $component->getComponentSource();
  $input_violations = new ConstraintViolationList();
  $uses_client_model = array_key_exists('clientModel', $spec) || $source->requiresExplicitInput();
  try {
    if ($uses_client_model) {
      $client_model = $spec['clientModel'] ?? canvas_kit_author_default_client_model($component);
      if (!is_array($client_model)) {
        throw new InvalidArgumentException(sprintf('components[%d].clientModel must be an object when supplied.', $index));
      }
      $inputs = $source->clientModelToInput($instance_uuids[$key], $component, $client_model, $page, $input_violations);
    }
    else {
      $inputs = $source->getDefaultExplicitInput();
    }
    $source_violations = $source->validateComponentInput($inputs, $instance_uuids[$key], $page);
    foreach ($source_violations as $violation) {
      $input_violations->add($violation);
    }
  }
  finally {
    if ($uses_client_model) {
      // Block sources persist form violations while converting client input.
      // Validation above consumed them; never leave per-instance residue.
      \Drupal::service(AutoSaveManager::class)->saveComponentInstanceFormViolations($instance_uuids[$key]);
    }
  }
  if (count($input_violations) > 0) {
    throw new InvalidArgumentException(sprintf('Invalid input for component %s: %s', $key, canvas_kit_author_violation_message($input_violations)));
  }

  $row = [
    'uuid' => $instance_uuids[$key],
    'component_id' => $component->id(),
    'component_version' => $component->getActiveVersion(),
    'inputs' => $inputs,
  ];
  if ($parent_key !== '') {
    $row['parent_uuid'] = $instance_uuids[$parent_key];
    $row['slot'] = $slot;
  }
  $tree[] = $row;
}

$page->setComponentTree($tree);
if (!$page->isNew()) {
  $page->setNewRevision(TRUE);
  $page->setRevisionLogMessage((string) ($manifest['revisionLog'] ?? 'Guarded programmatic Canvas composition update.'));
}

$violations = $page->validate();
if ($violations->count() > 0) {
  throw new InvalidArgumentException('Canvas page validation failed: ' . canvas_kit_author_violation_message($violations));
}

$normalized_tree = $page->getComponentTree()->getValue();
$proposed_digest = canvas_kit_author_tree_digest($normalized_tree);
$proposed_state_digest = canvas_kit_author_state_digest($page, $normalized_tree, $path_alias);
if (!$dry_run) {
  $connection = \Drupal::database();
  $transaction = NULL;
  try {
    if (!$page->isNew()) {
      $transaction = $connection->startTransaction();
      $page_entity_type = $entity_type_manager->getDefinition(Page::ENTITY_TYPE_ID);
      $locked_id = $connection->select($page_entity_type->getBaseTable(), 'canvas_page')
        ->fields('canvas_page', [$page_entity_type->getKey('id')])
        ->condition($page_entity_type->getKey('id'), $page->id())
        ->forUpdate()
        ->execute()
        ->fetchField();
      if ((int) $locked_id !== (int) $page->id()) {
        throw new RuntimeException('Replace refused: the Canvas page disappeared before it could be locked.');
      }
      $page_storage->resetCache([(int) $page->id()]);
      $locked_page = $page_storage->load((int) $page->id());
      assert($locked_page instanceof Page);
      $locked_tree = $locked_page->getComponentTree()->getValue();
      $locked_digest = canvas_kit_author_state_digest($locked_page, $locked_tree, $locked_page->toUrl()->toString());
      if (!hash_equals($expected_digest, $locked_digest)) {
        throw new RuntimeException(sprintf('Replace refused: authoring state changed before save (expected %s, found %s). Rediscover and review before replacing.', $expected_digest, $locked_digest));
      }
    }
    $page->save();
    $page_storage->resetCache([(int) $page->id()]);
    $reloaded = $page_storage->load((int) $page->id());
    assert($reloaded instanceof Page);
    $persisted_digest = canvas_kit_author_tree_digest($reloaded->getComponentTree()->getValue());
    if (!hash_equals($proposed_digest, $persisted_digest)) {
      throw new RuntimeException('Canvas page saved, but the persisted component tree does not match the validated proposal.');
    }
    $persisted_state_digest = canvas_kit_author_state_digest($reloaded, $reloaded->getComponentTree()->getValue(), $reloaded->toUrl()->toString());
    if (!hash_equals($proposed_state_digest, $persisted_state_digest)) {
      throw new RuntimeException('Canvas page saved, but its persisted authoring state does not match the validated proposal.');
    }
    if ($transaction && $connection->inTransaction()) {
      $transaction->commitOrRelease();
    }
  }
  catch (Throwable $throwable) {
    if ($transaction && $connection->inTransaction()) {
      $transaction->rollBack();
    }
    throw $throwable;
  }
  $page = $reloaded;
}

$output = [
  'schemaVersion' => 'public-kit.canvas-authoring-result.1',
  'dryRun' => $dry_run,
  'operation' => $operation,
  'page' => [
    'id' => $page->isNew() ? NULL : (int) $page->id(),
    'uuid' => $page->uuid(),
    'title' => (string) $page->label(),
    'path' => $path_alias,
    'published' => $page->isPublished(),
    'componentCount' => count($normalized_tree),
    'componentTreeSha256' => $proposed_digest,
    'authoringStateSha256' => $proposed_state_digest,
  ],
];
print json_encode($output, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
