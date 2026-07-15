<?php

declare(strict_types=1);

namespace Drupal\quality_smoke\Controller;

use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\node\NodeInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Renders a node through Drupal's entity view builder for the runtime smoke.
 */
final class EntityOutputController implements ContainerInjectionInterface {

  /**
   * Constructs the controller.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {
  }

  /**
   * Builds the complete node render array.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The route-matched node.
   *
   * @return array
   *   The node render array.
   */
  public function view(NodeInterface $node): array {
    return $this->entityTypeManager
      ->getViewBuilder('node')
      ->view($node, 'full');
  }

  /**
   * Builds node-derived output without referenced Media or File metadata.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The route-matched node.
   *
   * @return array
   *   A deliberately incomplete node render array.
   */
  public function viewWithoutReferencedDependencies(
    NodeInterface $node,
  ): array {
    $build = [
      '#plain_text' => (string) $node->id(),
      '#cache' => [
        'tags' => $node->getCacheTagsToInvalidate(),
      ],
    ];
    CacheableMetadata::createFromObject($node->access('view', NULL, TRUE))
      ->applyTo($build);

    return $build;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new self($container->get('entity_type.manager'));
  }

}
