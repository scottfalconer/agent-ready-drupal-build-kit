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
