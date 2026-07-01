# Agent Workflow

## Phase 1: Observe

- Start from public URLs supplied by the owner or reviewer.
- Record source capture assumptions and unknowns.
- Capture source facts: titles, routes, content patterns, navigation, media signals, design signals, forms, integrations, redirects, and visible technology signals.
- Record limitations and unfetched candidate routes.

## Phase 2: Decide

- Build a pattern map.
- Identify target Drupal CMS content types and fields.
- Identify vocabularies, media types, menus, Views, forms, redirects, SEO, integrations, editorial workflow, and access rules.
- Record why each target decision exists.

## Phase 3: Prepare

- Use DDEV as the default local Drupal CMS runtime when building a reviewable target.
- Create durable intent sidecar records for load-bearing decisions.
- Create operator-run packets.
- Create production target and maintainer review packets.
- Create content, visual, functional, accessibility, performance, security, privacy, and final QA plans.

## Phase 4: Verify

- Run the packet verifier: `node agent-ready-drupal-build-kit/bin/verify-packet.mjs --packet review-packet`.
- Use `gates.json` as the stable gate vocabulary.
- Verify the packet is internally consistent.
- Run independent verification against the live Drupal site and packet before handoff.
- Verify generated recipe material only as recipe material.
- Verify lab application only as lab proof.
- Verify production target evidence only from production-equivalent targets.
- Verify local Drupal CMS builds with DDEV/Drush status, exported config, public anonymous routes, content inventory, visual/design checks, functional checks, and browser-rendered evidence.
- Reject static previews and non-Drupal prototypes as Drupal CMS build evidence.

## Phase 5: Hand Off

- Hand off blocked gates by role.
- Keep launch blockers separate from accepted launch evidence.
- Ask maintainers to review architecture, not to rubber-stamp generated output.
