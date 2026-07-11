# Off-Road Inventory

Use this packet to list every place the build leaves Drupal's normal paved path. An item here is not automatically wrong. It is a maintainer review surface: name what was bypassed, why the Drupal-native tool did not fit, and what evidence proves the exception is safe and maintainable.

## Summary

- Site:
- Checked at:
- Reviewer:
- Overall status: `accepted | blocked | needs maintainer review`

## Inventory

| ID | Area | Off-road move | Drupal-native option considered | Why exception exists | Evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| OR-001 | Custom code | Custom module, route controller, or endpoint | Views, entity display, block, Canvas, ECA, Webform, contrib/recipe | UNKNOWN | UNKNOWN | blocked |
| OR-002 | Rendering | Entity query plus rendering in preprocess, template, or controller | Views, entity reference display, view mode, block | UNKNOWN | UNKNOWN | blocked |
| OR-003 | Public copy | Hardcoded copy or dynamic value in Twig, template, Views text area, or import script | Field, menu link, block, config, Canvas prop | UNKNOWN | UNKNOWN | blocked |
| OR-004 | Access/cache/rendering | `accessCheck(FALSE)`, `_access: TRUE`, forced max-age=0, raw markup, or raw SQL | Access-checked entity query, route permission, cache metadata, render API | UNKNOWN | UNKNOWN | blocked |
| OR-005 | Text formats | Bespoke or unfiltered text format for content | Filtered text format with allowed tags and editor workflow | UNKNOWN | UNKNOWN | blocked |
| OR-006 | Derived data | Field value computed once at import from other entities with no live derivation | View, computed field, ECA, queue, update/recompute path | UNKNOWN | UNKNOWN | blocked |
| OR-007 | Contrib/config defaults | Contrib token or metadata default pointing at a missing field | Map token/default to actual model field | UNKNOWN | UNKNOWN | blocked |
| OR-008 | Aliases | Pathauto pattern that does not cover custom bundles | Bundle-specific Pathauto pattern or explicit alias rule | UNKNOWN | UNKNOWN | blocked |
| OR-009 | Config portability | Hardcoded entity ID in config | UUID/config dependency/content reference/default content strategy | UNKNOWN | UNKNOWN | blocked |
| OR-010 | Editorial access | Custom content type with no non-admin editor role access | Role/permission/workflow configuration | UNKNOWN | UNKNOWN | blocked |
| OR-011 | Embeds/markup | Raw iframe, script, inline event handler, style attribute, or source HTML in editorial fields | Media/oEmbed, typed provider field, configured block, Webform/integration plugin, filtered text format | UNKNOWN | UNKNOWN | blocked |
| OR-012 | Local rebuild cleanup | Direct SQL, table purge, alias reset, or destructive import cleanup | Drupal APIs, entity deletes, migrations rollback, config import, clean rebuild scripts | UNKNOWN | UNKNOWN | blocked |

## Custom code enumeration

List every directory under `web/modules/custom/` and `web/themes/custom/`. The live verifier enumerates the same directories and their `*.routing.yml` files mechanically: a directory without a matching `CC-` row is a hard failure; a machine-derived public custom route (route requirements grant anonymous access via `_access: TRUE`, an anonymous-held permission such as `access content`, or the anonymous role) must appear in `route-matrix.json` or in this file; and a machine name matching the declared source domain or site name needs an `accepted` row with a named owner and rationale. Replace the table with `No custom modules or themes.` when both directories are empty.

| ID | Path | Kind | Public routes | Controllers | Disposition | Accepted by | Rationale |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CC-001 | web/modules/custom/UNKNOWN | module | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |

## Required Notes

- Custom code that remains:
- Drupal-native alternatives rejected:
- Config/import reproduction risks:
- Editor/permission risks:
- SEO/token/default risks:
- Accessibility/cache/access risks:
- Raw embed or source-markup findings and safer Drupal-native owner:
- Direct database cleanup performed, local-only safety boundary, and production-safe alternative:
- Maintainer decision needed:
