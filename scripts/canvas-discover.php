<?php

/**
 * @file
 * Discovers the live Drupal Canvas authoring surface without changing it.
 */

declare(strict_types=1);

use Drupal\canvas\Entity\Component;
use Drupal\canvas\Entity\Page;
use Drupal\canvas\PropSource\PropSource;

/**
 * Discovers the live Canvas authoring surface for headless build agents.
 *
 * Run through Drush's bootstrapped php:script command. This file is
 * deliberately read-only: its component-tree digests are the optimistic-lock
 * inputs consumed by canvas-author-page.php.
 */

if (!\Drupal::moduleHandler()->moduleExists('canvas')) {
  throw new RuntimeException('Drupal Canvas is not enabled. Do not declare Canvas unavailable until installed capability and project constraints have been inspected.');
}
$module_info = \Drupal::service('extension.list.module')->getExtensionInfo('canvas');
$canvas_version = (string) ($module_info['version'] ?? '');
if (preg_match('/^1\.8\./', $canvas_version) !== 1) {
  throw new RuntimeException(sprintf('These headless helpers are tested against Canvas 1.8.x; found %s. Revalidate the API contract before use.', $canvas_version ?: 'an unknown version'));
}

$entity_type_manager = \Drupal::entityTypeManager();
if (!$entity_type_manager->hasDefinition(Page::ENTITY_TYPE_ID)) {
  throw new RuntimeException('Canvas is enabled but the canvas_page entity type is unavailable.');
}

/**
 * Canonicalizes a value before hashing it.
 */
function canvas_kit_canonicalize(mixed $value): mixed {
  if (!is_array($value)) {
    return $value;
  }
  if (array_is_list($value)) {
    return array_map(canvas_kit_canonicalize(...), $value);
  }
  ksort($value, SORT_STRING);
  foreach ($value as &$item) {
    $item = canvas_kit_canonicalize($item);
  }
  unset($item);
  return $value;
}

/**
 * Returns the digest used to guard a later component-tree replacement.
 */
function canvas_kit_tree_digest(array $tree): string {
  return hash('sha256', json_encode(
    canvas_kit_canonicalize($tree),
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
  ));
}

/**
 * Binds every author-controlled Page value that a replacement could overwrite.
 */
function canvas_kit_authoring_state_digest(Page $page, array $tree, string $canonical_url): string {
  return hash('sha256', json_encode(
    canvas_kit_canonicalize([
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
 * Reproduces the client model Canvas initializes when a component is placed.
 */
function canvas_kit_default_client_model(Component $component): array {
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

$default_theme = (string) \Drupal::config('system.theme')->get('default');
$enabled_themes = array_keys((array) \Drupal::config('core.extension')->get('theme'));
$theme_list = \Drupal::service('extension.list.theme')->getList();
$mercury = $theme_list['mercury'] ?? NULL;

$components = [];
$disabled_components = [];
foreach (Component::loadMultiple() as $component) {
  assert($component instanceof Component);
  if (!$component->status()) {
    $disabled_components[] = $component->id();
    continue;
  }
  $source = $component->getComponentSource();
  $broken = $source->isBroken();
  $components[] = [
    'id' => $component->id(),
    'label' => (string) $component->label(),
    'sourcePlugin' => $source->getPluginId(),
    'activeVersion' => $component->getActiveVersion(),
    'slots' => array_keys($component->getSlotDefinitions()),
    'defaultClientModel' => $broken ? NULL : canvas_kit_default_client_model($component),
    'defaultStoredInput' => $broken ? NULL : $source->getDefaultExplicitInput(),
    'broken' => $broken,
  ];
}
usort($components, static fn (array $left, array $right): int => strcmp((string) $left['id'], (string) $right['id']));
sort($disabled_components, SORT_STRING);

$pages = [];
foreach ($entity_type_manager->getStorage(Page::ENTITY_TYPE_ID)->loadMultiple() as $page) {
  assert($page instanceof Page);
  $tree = $page->getComponentTree()->getValue();
  $canonical_url = $page->toUrl()->toString();
  $pages[] = [
    'id' => (int) $page->id(),
    'uuid' => $page->uuid(),
    'title' => (string) $page->label(),
    'description' => (string) $page->get('description')->value,
    'published' => $page->isPublished(),
    'canonicalUrl' => $canonical_url,
    'revisionId' => (int) $page->getRevisionId(),
    'componentCount' => count($tree),
    'componentTreeSha256' => canvas_kit_tree_digest($tree),
    'authoringStateSha256' => canvas_kit_authoring_state_digest($page, $tree, $canonical_url),
    'componentTree' => $tree,
  ];
}
usort($pages, static fn (array $left, array $right): int => $left['id'] <=> $right['id']);

$output = [
  'schemaVersion' => 'public-kit.canvas-discovery.1',
  'canvas' => [
    'enabled' => TRUE,
    'version' => $module_info['version'] ?? NULL,
    'pageEntityType' => Page::ENTITY_TYPE_ID,
    'componentTreeField' => 'components',
  ],
  'presentation' => [
    'defaultTheme' => $default_theme,
    'mercury' => [
      'installed' => $mercury !== NULL,
      'enabled' => in_array('mercury', $enabled_themes, TRUE),
      'isDefault' => $default_theme === 'mercury',
      'version' => $mercury?->info['version'] ?? NULL,
      'path' => $mercury?->getPath(),
    ],
  ],
  'components' => $components,
  'disabledComponentIds' => $disabled_components,
  'pages' => $pages,
];

print json_encode($output, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
