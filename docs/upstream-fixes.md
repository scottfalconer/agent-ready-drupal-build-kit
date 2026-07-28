# Upstream Fixes

These are useful improvements to Drupal CMS, recipes, or the kit ecosystem. They are not requirements for using this public kit today.

## Durable Intent Config Carrier

Add an approved config carrier for durable intent, including schema, export/import behavior, config hash validation, and stale-intent fail-safe behavior.

## Recipe-By-Construction

Make generated site bundles compose more directly from maintained Drupal CMS recipes, with site-specific overlays only where needed.

Target state:

- start from maintained `drupal_cms_*` recipes when they fit the source architecture;
- record inherited recipe decisions explicitly;
- keep custom overlays small and reviewable;
- verify the composed result through config export/import and browser-rendered target QA.

## Third-Party Detection

Improve detection and classification of analytics, embeds, forms, ticketing, video, maps, payments, consent systems, and external data providers.

## Maintainer Workflow

Define a public maintainer review workflow for accepting, rejecting, or revising agent-authored build evidence.

## Evidence Bundle Interchange

Standardize a portable evidence bundle format that separates generated packets from accepted launch evidence.

## Drush Structured Introspection

A build agent reconstructs the site's content model by stitching `field:info`,
`field:base-info`, `config:get core.entity_form_display.*`, `role:list` and
`views:list`, or by writing ad hoc `php:eval` one-liners. Drush has good
per-command JSON output but no single command that returns the model.

Wanted:

- `drush model:export --format=json` covering bundles, fields, widgets, form and
  view displays, and permissions in one bootstrap. Related entity-inspection
  prior art exists in [drush-ops/drush#1727](https://github.com/drush-ops/drush/issues/1727)
  and the contrib [Drush Entity](https://www.drupal.org/project/drush_entity)
  module, but neither is the requested canonical whole-model export.
- `drush config:status --format=json --with-diff`, so a drift check reports *how*
  active configuration differs rather than only *which* items differ.
- A batched mode such as `drush batch --commands-file=cmds.json` that bootstraps
  once and returns an array of results. Multi-command workflows that currently
  bootstrap once per command may pay avoidable latency; benchmark the affected
  command sequence rather than assuming the same multiplier for every
  automation.

Honest scope: the observations that motivated these proposals found a small
share of large tool output but measurable wall time. These are primarily
correctness and ergonomics improvements; benchmark the affected workflow before
making a broader performance claim. See
[agent-context-budget.md](agent-context-budget.md) for the separate context-cost
controls.
