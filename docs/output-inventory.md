# Packet Outputs And Gates

The machine-readable source of truth is [../gates.json](../gates.json). This page explains the same output and gate vocabulary for humans; if it conflicts with `gates.json`, fix both before shipping the kit.

## Core Architecture Packet

These files must exist for every run:

- `source-audit.json`
- `pattern-map.json`
- `recipe-start-point.md`
- `durable-intent.yml`
- `scoped-gap-list.md`
- `off-road-inventory.md`
- `maintainer-review.md`

## Gate Records

These files must also exist. Early runs should create blocked stubs when accepted evidence does not exist yet:

- `operator-run.md`
- `production-target.md`
- `parity-report.json`
- `route-matrix.json`
- `browser-evidence.json`
- `independent-verification.json`
- `drupal-readback.json`
- `field-output-matrix.json`
- `launch-checklist.md`

## Hard Launch Gates

Launch readiness requires accepted evidence for every hard gate in `gates.json`. The summary below is explanatory, not a second source of truth:

- Independent operator run.
- Production-equivalent Drupal target.
- Full route inventory or accepted route boundary.
- Browser-first source route expansion.
- Public browser-rendered evidence.
- Independent verifier pass that tries to falsify completion claims against the live site.
- Per-route item reconciliation for repeated source items.
- Collection ownership ledger and editor add-a-row evidence.
- Target-required route checks for privacy/legal/footer, sitemap/robots when enabled, login/admin expectations, front page behavior, and locally introduced menu/footer links.
- Source route drift classification and disposition.
- Raw embed and source-markup scan with off-road inventory entries.
- Canvas placeholder detection and build type declaration.
- First-fold and brand-asset parity for primary routes.
- Source/target visual comparison evidence.
- Canvas authoring ownership evidence for composed pages.
- Authenticated non-admin editor browser task evidence.
- Homepage/front-page and canonical route parity.
- Front-page alias decision.
- Unexpected public-route cleanup.
- Starter route cleanup.
- Structured content ownership evidence.
- Composition model declaration for every flexible landing-like route.
- Composition-owner fidelity checks for selected owners, route rationales, sections, data sources, expected editor actions, acceptance proof, and deviation records.
- Canvas component model fidelity when Canvas is public or part of the rebuild: component inventory, slots, typed props, entity/media/View references, monolithic component detection, string-blob prop detection, and repeatable-section Drupal ownership.
- Content parity.
- Media parity.
- Visual/design parity.
- Functional parity.
- Navigation parity.
- Views and page parity.
- Forms and integrations.
- Redirects and SEO.
- Accessibility.
- Performance.
- Security and privacy.
- Editorial handoff.
- Field-to-public-output evidence.
- Presentation ownership evidence.
- Utility Page exception evidence.
- Config sync directory evidence.
- Off-road inventory evidence.
- Direct database cleanup recorded as local-only off-road evidence with a production-safe alternative.
- Durable intent validation.
- Maintainer signoff.
- Final QA.

Generated files can identify a gate or record a blocked stub. They cannot clear a gate by themselves.
