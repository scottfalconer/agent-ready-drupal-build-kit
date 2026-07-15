<?php

declare(strict_types=1);

use Drupal\node\Entity\Node;

const ASSEMBLY_SMOKE_ID = 'disposable_assembly_smoke';
const ASSEMBLY_SMOKE_SCHEMA = 'public-kit.assembly-dry-run.1';
const ASSEMBLY_SMOKE_TIMESTAMP = 1704067200;

/**
 * Load one exact node by stable UUID.
 */
function assembly_smoke_load_node(string $uuid): ?Node {
  $storage = \Drupal::entityTypeManager()->getStorage('node');
  $ids = $storage->getQuery()
    ->accessCheck(FALSE)
    ->condition('uuid', $uuid)
    ->execute();
  if (count($ids) > 1) {
    throw new RuntimeException(sprintf('Node UUID %s is not unique.', $uuid));
  }
  if ($ids === []) {
    return NULL;
  }
  $node = $storage->load(reset($ids));
  if (!$node instanceof Node) {
    throw new RuntimeException(sprintf('Node UUID %s could not be loaded.', $uuid));
  }
  return $node;
}

/**
 * Return whether a node already has the exact assembly-owned values.
 */
function assembly_smoke_node_matches(Node $node, string $title): bool {
  return $node->bundle() === 'proof'
    && $node->getTitle() === $title
    && $node->isPublished()
    && (int) $node->getOwnerId() === 1;
}

/**
 * Build the canonical provenance-bound operation stream from live state.
 */
function assembly_smoke_operations(): array {
  $specifications = [
    [
      'role' => 'create',
      'sourceKey' => 'assembly_smoke:01_create',
      'uuid' => '91111111-1111-4111-8111-111111111111',
      'title' => 'Assembly smoke created',
    ],
    [
      'role' => 'delete',
      'sourceKey' => 'assembly_smoke:02_delete',
      'uuid' => '93333333-3333-4333-8333-333333333333',
      'title' => 'Assembly smoke delete target',
    ],
    [
      'role' => 'update',
      'sourceKey' => 'assembly_smoke:03_update',
      'uuid' => '92222222-2222-4222-8222-222222222222',
      'title' => 'Assembly smoke updated',
    ],
    [
      'role' => 'unchanged',
      'sourceKey' => 'assembly_smoke:04_unchanged',
      'uuid' => '94444444-4444-4444-8444-444444444444',
      'title' => 'Assembly smoke unchanged',
    ],
  ];

  $operations = [];
  foreach ($specifications as $specification) {
    $node = assembly_smoke_load_node($specification['uuid']);
    if ($specification['role'] === 'delete') {
      $action = $node === NULL ? 'unchanged' : 'delete';
    }
    elseif ($node === NULL) {
      $action = 'create';
    }
    else {
      $action = assembly_smoke_node_matches($node, $specification['title']) ? 'unchanged' : 'update';
    }
    $operations[] = [
      'action' => $action,
      'sourceKey' => $specification['sourceKey'],
      'surface' => 'node',
      'target' => [
        'kind' => 'entity',
        'entityType' => 'node',
        'stableId' => 'uuid:' . $specification['uuid'],
      ],
    ];
  }
  return $operations;
}

/**
 * Recursively order object keys exactly like the verifier's canonical JSON.
 */
function assembly_smoke_canonicalize(mixed $value): mixed {
  if (!is_array($value)) {
    return $value;
  }
  if (array_is_list($value)) {
    return array_map('assembly_smoke_canonicalize', $value);
  }
  ksort($value, SORT_STRING);
  foreach ($value as $key => $child) {
    $value[$key] = assembly_smoke_canonicalize($child);
  }
  return $value;
}

/**
 * Fingerprint operations with the verifier's canonical SHA-256 format.
 */
function assembly_smoke_fingerprint(array $operations): string {
  $json = json_encode(
    assembly_smoke_canonicalize($operations),
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
  );
  return 'sha256:' . hash('sha256', $json);
}

/**
 * Find the desired values associated with one canonical source key.
 */
function assembly_smoke_desired(string $source_key): array {
  return match ($source_key) {
    'assembly_smoke:01_create' => [
      'uuid' => '91111111-1111-4111-8111-111111111111',
      'title' => 'Assembly smoke created',
    ],
    'assembly_smoke:02_delete' => [
      'uuid' => '93333333-3333-4333-8333-333333333333',
      'title' => 'Assembly smoke delete target',
    ],
    'assembly_smoke:03_update' => [
      'uuid' => '92222222-2222-4222-8222-222222222222',
      'title' => 'Assembly smoke updated',
    ],
    'assembly_smoke:04_unchanged' => [
      'uuid' => '94444444-4444-4444-8444-444444444444',
      'title' => 'Assembly smoke unchanged',
    ],
    default => throw new RuntimeException(sprintf('Unknown assembly source key %s.', $source_key)),
  };
}

/**
 * Apply one already-planned operation through Drupal's entity API.
 */
function assembly_smoke_apply(array $operation): void {
  if ($operation['action'] === 'unchanged') {
    return;
  }
  $desired = assembly_smoke_desired($operation['sourceKey']);
  $node = assembly_smoke_load_node($desired['uuid']);
  if ($operation['action'] === 'delete') {
    if ($node === NULL) {
      throw new RuntimeException(sprintf('Delete target %s disappeared after planning.', $desired['uuid']));
    }
    $node->delete();
    return;
  }
  if ($operation['action'] === 'create') {
    if ($node !== NULL) {
      throw new RuntimeException(sprintf('Create target %s appeared after planning.', $desired['uuid']));
    }
    $node = Node::create([
      'uuid' => $desired['uuid'],
      'type' => 'proof',
      'title' => $desired['title'],
      'status' => 1,
      'uid' => 1,
      'created' => ASSEMBLY_SMOKE_TIMESTAMP,
      'changed' => ASSEMBLY_SMOKE_TIMESTAMP,
      'revision_timestamp' => ASSEMBLY_SMOKE_TIMESTAMP,
    ]);
    $node->save();
    return;
  }
  if ($operation['action'] !== 'update' || $node === NULL) {
    throw new RuntimeException(sprintf('Update target %s is unavailable.', $desired['uuid']));
  }
  $node->setTitle($desired['title']);
  $node->setPublished(TRUE);
  $node->setOwnerId(1);
  $node->setChangedTime(ASSEMBLY_SMOKE_TIMESTAMP);
  $node->setRevisionCreationTime(ASSEMBLY_SMOKE_TIMESTAMP);
  $node->save();
}

$arguments = array_values(is_array($extra ?? NULL) ? $extra : []);
$mode = $arguments[0] ?? '';
$operations = assembly_smoke_operations();

if ($mode === 'plan') {
  if (count($arguments) !== 1) {
    throw new InvalidArgumentException('Assembly plan mode accepts no extra arguments.');
  }
  $summary = [
    'create' => 0,
    'update' => 0,
    'delete' => 0,
    'unchanged' => 0,
    'total' => count($operations),
  ];
  foreach ($operations as $operation) {
    $summary[$operation['action']]++;
  }
  print json_encode([
    'schemaVersion' => ASSEMBLY_SMOKE_SCHEMA,
    'assemblyId' => ASSEMBLY_SMOKE_ID,
    'operations' => $operations,
    'summary' => $summary,
  ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  return;
}

if ($mode !== 'apply-prefix' || count($arguments) !== 3) {
  throw new InvalidArgumentException('Expected plan or apply-prefix <count> <plan-fingerprint>.');
}
$prefix_count = filter_var($arguments[1], FILTER_VALIDATE_INT, [
  'options' => ['min_range' => 0, 'max_range' => count($operations)],
]);
if ($prefix_count === FALSE || (string) $prefix_count !== $arguments[1]) {
  throw new InvalidArgumentException('Assembly prefix count is invalid.');
}
$fingerprint = assembly_smoke_fingerprint($operations);
if (!hash_equals($fingerprint, $arguments[2])) {
  throw new RuntimeException('Assembly plan fingerprint changed before apply-prefix.');
}
for ($index = 0; $index < $prefix_count; $index++) {
  assembly_smoke_apply($operations[$index]);
}
