# Packet Outputs And Gates

This is the canonical output and gate vocabulary for the kit.

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
- `drupal-readback.json`
- `field-output-matrix.json`
- `launch-checklist.md`

## Hard Launch Gates

Launch readiness requires accepted evidence for every hard gate:

- Independent operator run.
- Production-equivalent Drupal target.
- Full route inventory or accepted route boundary.
- Browser-first source route expansion.
- Homepage/front-page and canonical route parity.
- Front-page alias decision.
- Unexpected public-route cleanup.
- Starter route cleanup.
- Structured content ownership evidence.
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
- Config sync directory evidence.
- Off-road inventory evidence.
- Durable intent validation.
- Maintainer signoff.
- Final QA.

Generated files can identify a gate or record a blocked stub. They cannot clear a gate by themselves.
