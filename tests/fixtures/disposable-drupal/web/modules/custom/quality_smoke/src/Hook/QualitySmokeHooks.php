<?php

declare(strict_types=1);

namespace Drupal\quality_smoke\Hook;

use Drupal\Core\Hook\Attribute\Hook;

/**
 * Provides an active object-oriented render hook for runtime verification.
 */
final class QualitySmokeHooks {

  /**
   * Adds a harmless marker while preserving the complete render variables.
   */
  #[Hook('preprocess_node')]
  public function preprocessNode(array &$variables): void {
    $variables['quality_smoke_oop_hook_ran'] = TRUE;
  }

}
