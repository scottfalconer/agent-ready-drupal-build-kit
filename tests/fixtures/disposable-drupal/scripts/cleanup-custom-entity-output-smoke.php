<?php

declare(strict_types=1);

use Drupal\Core\Entity\Entity\EntityViewDisplay;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\media\Entity\MediaType;
use Drupal\node\Entity\NodeType;

$entity_repository = \Drupal::service('entity.repository');
foreach ([
  ['node', 'f039a4de-ccf5-4f54-ab6e-32bf7812b387'],
  ['media', 'ed363033-e645-42f7-a940-5df63e7ed0f9'],
  ['file', '0869d341-f0ba-4a2d-b09c-d01baf35d3da'],
  ['file', '4cdd2af4-6c57-43b4-a978-f80f07fa53b1'],
] as [$entity_type, $uuid]) {
  $entity = $entity_repository->loadEntityByUuid($entity_type, $uuid);
  if ($entity) {
    $entity->delete();
  }
}

$fixture_uri = 'public://phase-c/entity-output.txt';
$thumbnail_uri = 'public://phase-c/generic.png';
$fixture_directory = 'public://phase-c';
$file_system = \Drupal::service('file_system');
foreach ([$fixture_uri, $thumbnail_uri] as $owned_uri) {
  if (file_exists($owned_uri)) {
    $file_system->delete($owned_uri);
  }
}
if (is_dir($fixture_directory)) {
  $file_system->deleteRecursive($fixture_directory);
}

$icon_base_snapshot_key = 'agent_ready.phase_c.entity_output.original_icon_base_uri';
$state = \Drupal::state();
$original_icon_base_uri = $state->get($icon_base_snapshot_key);
if (is_string($original_icon_base_uri)) {
  \Drupal::configFactory()
    ->getEditable('media.settings')
    ->set('icon_base_uri', $original_icon_base_uri)
    ->save();
  $state->delete($icon_base_snapshot_key);
}
$media_icon_base_restored = is_string($original_icon_base_uri)
  ? (string) \Drupal::config('media.settings')->get('icon_base_uri') === $original_icon_base_uri
  : (string) \Drupal::config('media.settings')->get('icon_base_uri') !== $fixture_directory;

foreach ([
  EntityViewDisplay::load('node.phase_c_output.default'),
  EntityViewDisplay::load('media.phase_c_file.default'),
  FieldConfig::loadByName('node', 'phase_c_output', 'field_phase_c_media'),
  FieldConfig::loadByName('media', 'phase_c_file', 'field_phase_c_file'),
] as $configuration) {
  if ($configuration) {
    $configuration->delete();
  }
}
\Drupal::service('entity_field.manager')->clearCachedFieldDefinitions();

foreach ([
  NodeType::load('phase_c_output'),
  MediaType::load('phase_c_file'),
] as $bundle) {
  if ($bundle) {
    $bundle->delete();
  }
}
\Drupal::service('entity_field.manager')->clearCachedFieldDefinitions();

foreach ([
  FieldStorageConfig::loadByName('node', 'field_phase_c_media'),
  FieldStorageConfig::loadByName('media', 'field_phase_c_file'),
] as $storage) {
  if ($storage) {
    $storage->delete();
  }
}

$module_handler = \Drupal::moduleHandler();
if ($module_handler->moduleExists('quality_smoke')) {
  \Drupal::service('module_installer')->uninstall(['quality_smoke']);
}

$system_theme = \Drupal::configFactory()->getEditable('system.theme');
if (in_array((string) $system_theme->get('default'), ['quality_smoke_child', 'quality_smoke_base'], TRUE)) {
  $system_theme->set('default', 'stark')->save();
}
$installed_themes = (array) \Drupal::config('core.extension')->get('theme');
$smoke_themes = array_values(array_filter(
  ['quality_smoke_child', 'quality_smoke_base'],
  static fn (string $theme_name): bool => array_key_exists($theme_name, $installed_themes),
));
if ($smoke_themes !== []) {
  \Drupal::service('theme_installer')->uninstall($smoke_themes);
}
drupal_flush_all_caches();

$remaining_themes = (array) \Drupal::config('core.extension')->get('theme');

print json_encode([
  'schemaVersion' => 'public-kit.custom-entity-output-smoke-cleanup.1',
  'cleaned' => TRUE,
  'fixtureFileRemoved' => !file_exists($fixture_uri),
  'fixtureThumbnailRemoved' => !file_exists($thumbnail_uri),
  'fixtureDirectoryRemoved' => !is_dir($fixture_directory),
  'mediaIconBaseRestored' => $media_icon_base_restored,
  'mediaIconBaseSnapshotRemoved' => $state->get($icon_base_snapshot_key) === NULL,
  'themesRemoved' => !array_key_exists('quality_smoke_child', $remaining_themes) &&
    !array_key_exists('quality_smoke_base', $remaining_themes),
], JSON_UNESCAPED_SLASHES);
