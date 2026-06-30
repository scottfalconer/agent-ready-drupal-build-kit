# Agent Workflow

## Phase 1: Observe

- Start from public URLs supplied by the owner or reviewer.
- Record permission status.
- Capture source facts: titles, routes, content patterns, navigation, media signals, forms, integrations, redirects, and visible technology signals.
- Record limitations and unfetched candidate routes.

## Phase 2: Decide

- Build a pattern map.
- Identify target Drupal CMS content types and fields.
- Identify vocabularies, media types, menus, Views, forms, redirects, SEO, integrations, editorial workflow, and access rules.
- Record why each target decision exists.

## Phase 3: Prepare

- Use DDEV as the default local Drupal CMS runtime when building a reviewable target.
- Create durable intent sidecar records for load-bearing decisions.
- Create owner permission and operator-run packets.
- Create production target and maintainer review packets.
- Create parity, accessibility, performance, security, privacy, and final QA plans.

## Phase 4: Verify

- Verify the packet is internally consistent.
- Verify generated recipe material only as recipe material.
- Verify lab application only as lab proof.
- Verify production target claims only from production-equivalent target evidence.
- Verify local Drupal CMS build claims with DDEV/Drush status, exported config, public anonymous routes, and browser-rendered evidence.
- Reject static previews and non-Drupal prototypes as Drupal CMS build evidence.

## Phase 5: Hand Off

- Hand off blocked gates by role.
- Keep launch blockers separate from accepted launch evidence.
- Ask maintainers to review architecture, not to rubber-stamp generated output.
