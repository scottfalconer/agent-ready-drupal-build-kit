<?php

declare(strict_types=1);

use Drupal\Core\Entity\Entity\EntityViewDisplay;
use Drupal\Core\Field\FieldStorageDefinitionInterface;
use Drupal\Core\File\FileExists;
use Drupal\Core\File\FileSystemInterface;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\media\Entity\Media;
use Drupal\media\Entity\MediaType;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;

$module_installer = \Drupal::service('module_installer');
if (!$module_installer->install(['quality_smoke'])) {
  throw new RuntimeException('The quality_smoke module could not be enabled.');
}

$system_theme = \Drupal::configFactory()->getEditable('system.theme');
if ((string) $system_theme->get('default') !== 'stark') {
  throw new RuntimeException('The Phase C smoke fixture requires Stark as its clean default theme.');
}
\Drupal::service('theme_installer')->install([
  'quality_smoke_base',
  'quality_smoke_child',
]);
$installed_themes = (array) \Drupal::config('core.extension')->get('theme');
foreach (['quality_smoke_base', 'quality_smoke_child'] as $theme_name) {
  if (!array_key_exists($theme_name, $installed_themes)) {
    throw new RuntimeException("The {$theme_name} smoke theme could not be enabled.");
  }
}
$system_theme->set('default', 'quality_smoke_child')->save();

$node_type = NodeType::load('phase_c_output');
if (!$node_type) {
  $node_type = NodeType::create([
    'type' => 'phase_c_output',
    'name' => 'Phase C entity output',
    'new_revision' => FALSE,
    'display_submitted' => FALSE,
  ]);
  $node_type->save();
}

$media_type = MediaType::load('phase_c_file');
if (!$media_type) {
  $media_type = MediaType::create([
    'id' => 'phase_c_file',
    'label' => 'Phase C file',
    'source' => 'file',
    'source_configuration' => [
      'source_field' => 'field_phase_c_file',
    ],
    'queue_thumbnail_downloads' => FALSE,
    'new_revision' => FALSE,
    'field_map' => [],
  ]);
  $media_type->save();
}

if (!FieldStorageConfig::loadByName('media', 'field_phase_c_file')) {
  FieldStorageConfig::create([
    'field_name' => 'field_phase_c_file',
    'entity_type' => 'media',
    'type' => 'file',
    'settings' => [
      'target_type' => 'file',
      'display_field' => FALSE,
      'display_default' => FALSE,
      'uri_scheme' => 'public',
    ],
    'cardinality' => 1,
    'translatable' => FALSE,
  ])->save();
}
if (!FieldConfig::loadByName('media', 'phase_c_file', 'field_phase_c_file')) {
  FieldConfig::create([
    'field_name' => 'field_phase_c_file',
    'entity_type' => 'media',
    'bundle' => 'phase_c_file',
    'label' => 'File',
    'required' => TRUE,
    'settings' => [
      'handler' => 'default:file',
      'handler_settings' => [],
      'file_directory' => 'phase-c',
      'file_extensions' => 'txt',
      'max_filesize' => '',
      'description_field' => FALSE,
    ],
  ])->save();
}

if (!FieldStorageConfig::loadByName('node', 'field_phase_c_media')) {
  FieldStorageConfig::create([
    'field_name' => 'field_phase_c_media',
    'entity_type' => 'node',
    'type' => 'entity_reference',
    'settings' => ['target_type' => 'media'],
    'cardinality' => FieldStorageDefinitionInterface::CARDINALITY_UNLIMITED,
    'translatable' => FALSE,
  ])->save();
}
if (!FieldConfig::loadByName('node', 'phase_c_output', 'field_phase_c_media')) {
  FieldConfig::create([
    'field_name' => 'field_phase_c_media',
    'entity_type' => 'node',
    'bundle' => 'phase_c_output',
    'label' => 'Media',
    'required' => TRUE,
    'settings' => [
      'handler' => 'default:media',
      'handler_settings' => [
        'target_bundles' => ['phase_c_file' => 'phase_c_file'],
      ],
    ],
  ])->save();
}

$media_display = EntityViewDisplay::load('media.phase_c_file.default')
  ?? EntityViewDisplay::create([
    'targetEntityType' => 'media',
    'bundle' => 'phase_c_file',
    'mode' => 'default',
    'status' => TRUE,
  ]);
$media_display->setComponent('field_phase_c_file', [
  'type' => 'file_default',
  'label' => 'visually_hidden',
  'settings' => [],
  'third_party_settings' => [],
  'weight' => 0,
  'region' => 'content',
])->save();

$node_display = EntityViewDisplay::load('node.phase_c_output.default')
  ?? EntityViewDisplay::create([
    'targetEntityType' => 'node',
    'bundle' => 'phase_c_output',
    'mode' => 'default',
    'status' => TRUE,
  ]);
$node_display->setComponent('field_phase_c_media', [
  'type' => 'quality_smoke_entity_reference',
  'label' => 'hidden',
  'settings' => ['view_mode' => 'default'],
  'third_party_settings' => [],
  'weight' => 0,
  'region' => 'content',
])->save();

$entity_repository = \Drupal::service('entity.repository');
foreach ([
  ['node', 'f039a4de-ccf5-4f54-ab6e-32bf7812b387'],
  ['media', 'ed363033-e645-42f7-a940-5df63e7ed0f9'],
  ['file', '0869d341-f0ba-4a2d-b09c-d01baf35d3da'],
] as [$entity_type, $uuid]) {
  if ($entity_repository->loadEntityByUuid($entity_type, $uuid)) {
    throw new RuntimeException("A stale verifier-owned {$entity_type} fixture already exists.");
  }
}

$file_system = \Drupal::service('file_system');
$file_directory = 'public://phase-c';
if (!$file_system->prepareDirectory(
  $file_directory,
  FileSystemInterface::CREATE_DIRECTORY | FileSystemInterface::MODIFY_PERMISSIONS,
)) {
  throw new RuntimeException('The verifier-owned file directory could not be prepared.');
}
$file_uri = $file_system->saveData(
  "Phase C cacheability proof.\n",
  $file_directory . '/entity-output.txt',
  FileExists::Replace,
);
if (!is_string($file_uri) || $file_uri === '') {
  throw new RuntimeException('The verifier-owned file fixture could not be written.');
}
$file = File::create([
  'uuid' => '0869d341-f0ba-4a2d-b09c-d01baf35d3da',
  'filename' => 'entity-output.txt',
  'uri' => $file_uri,
  'status' => 1,
]);
$file->save();

$media = Media::create([
  'uuid' => 'ed363033-e645-42f7-a940-5df63e7ed0f9',
  'bundle' => 'phase_c_file',
  'name' => 'Phase C file output',
  'status' => 1,
  'uid' => 1,
  'field_phase_c_file' => ['target_id' => $file->id()],
]);
$media->save();

$node = Node::create([
  'uuid' => 'f039a4de-ccf5-4f54-ab6e-32bf7812b387',
  'type' => 'phase_c_output',
  'title' => 'Phase C entity output',
  'status' => 1,
  'uid' => 1,
  'field_phase_c_media' => ['target_id' => $media->id()],
]);
$node->save();

\Drupal::service('router.builder')->rebuild();
drupal_flush_all_caches();

print json_encode([
  'schemaVersion' => 'public-kit.custom-entity-output-smoke-fixture.1',
  'nodeId' => (int) $node->id(),
  'mediaId' => (int) $media->id(),
  'fileId' => (int) $file->id(),
  'routePath' => '/quality-smoke/' . $node->id(),
  'entityViewRoutePath' => '/quality-smoke-entity-view/' . $node->id(),
  'nodeBundle' => 'phase_c_output',
  'nodeField' => 'field_phase_c_media',
  'defaultTheme' => 'quality_smoke_child',
  'baseTheme' => 'quality_smoke_base',
], JSON_UNESCAPED_SLASHES);
