<?php

declare(strict_types=1);

namespace Drupal\quality_smoke\Plugin\Field\FieldFormatter;

use Drupal\Core\Field\Attribute\FieldFormatter;
use Drupal\Core\Field\Plugin\Field\FieldFormatter\EntityReferenceEntityFormatter;
use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * Provides an active custom formatter for Phase C provenance verification.
 */
#[FieldFormatter(
  id: 'quality_smoke_entity_reference',
  label: new TranslatableMarkup('Quality smoke rendered entity'),
  description: new TranslatableMarkup('Renders referenced entities for the Phase C runtime smoke test.'),
  field_types: [
    'entity_reference',
  ],
)]
final class PhaseCEntityReferenceFormatter extends EntityReferenceEntityFormatter {
}
