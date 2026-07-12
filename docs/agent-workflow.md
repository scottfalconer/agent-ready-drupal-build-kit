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

- Use the One Line Installer-created DDEV Drupal CMS project as the single reviewable target; do not create another site for the kit.
- Initialize the installed skill in place, preserve all existing managed `AGENTS.md` regions, and use its concise project block to route agents to `references/build-contract.md`.
- Create durable intent sidecar records for load-bearing decisions.
- Create operator-run packets.
- Create production target and maintainer review packets.
- Create content, visual, functional, accessibility, performance, security, privacy, and final QA plans.

## Phase 4: Verify

- From the host at the target Drupal project, run the installed skill's default live verifier: `ddev exec node .agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs --packet review-packet`.
- Confirm it fetched the actual primary and target-required routes, rejected non-success responses, inspected rendered primary-route canonical/meta-description/`og:image`, and independently found real Git-tracked YAML in the current config-sync directory.
- Use `.agents/skills/agent-ready-drupal-build-kit/gates.json` as the stable gate vocabulary.
- Verify the packet is internally consistent.
- Run independent verification against the live Drupal site and packet before handoff.
- Treat `scripts/verify-packet.mjs`, packet-authored values, and injected test runtimes as diagnostic only; they cannot certify the site.
- Verify generated recipe material only as recipe material.
- Verify lab application only as lab proof.
- Verify production target evidence only from production-equivalent targets.
- Verify local Drupal CMS builds with DDEV/Drush status, exported config, public anonymous routes, content inventory, visual/design checks, functional checks, and browser-rendered evidence.
- Require every declared collection row to have count, ownership, and editor add-a-row proof; every custom/repeating public bundle to have a non-admin workflow; and every load-bearing/anonymous-output field to have a falsification check.
- Require the actual composition owner to match its declaration or a target-bound accepted deviation. Require reviewed rationale and evidence for SEO `not_applicable`.
- Reject static previews and non-Drupal prototypes as Drupal CMS build evidence.

## Phase 5: Hand Off

- Hand off blocked gates by role.
- Keep external blockers blocked; they do not replace primary-route coverage. Any accepted out-of-scope blind-review item needs a recorded accepter label, specific reason, and evidence. Local attribution is self-attested; authenticated approval is separate.
- Keep launch blockers separate from accepted launch evidence.
- Ask maintainers to review architecture, not to rubber-stamp generated output.
