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
- Keep external blockers blocked; they do not replace primary-route coverage. Any accepted out-of-scope blind-review item needs a named accepter, specific reason, and evidence.
- Keep launch blockers separate from accepted launch evidence.
- Ask maintainers to review architecture, not to rubber-stamp generated output.

## Phase 6: Steward The Verified Foundation

- Preserve the first successful full verification as a create-once, integrity-checked historical baseline under kit tooling. Later work must not rewrite or retroactively revoke it; do not describe it as cryptographically immutable or tamper-proof.
- Run `scripts/lifecycle.mjs status` before meaningful post-baseline work, and remember it reports the last inspected cached state rather than performing a live inspection.
- Classify an original omission, defect, or regression as a `repair`; classify genuinely new requested scope as an `extension`.
- Before editing, refresh with the default verifier when cached lifecycle state is not fresh, then record concrete acceptance criteria, every affected anonymous `--route` or explicit `--no-public-route`, and affected content, model, composition, presentation, editor, access, code, dependency, and integration surfaces with `scripts/lifecycle.mjs begin`; it retains `baseAnchorId` from the latest verified or evidence-recorded anchor.
- Use `--adopt-current` only to classify existing edits; it always adds conservative `unknown` impact. Use `abandon --reason "..."` when the active record will not be completed.
- Run impact-targeted change evidence. Always check current Drupal identity, exact state, declared acceptance criteria, affected routes, and undeclared changes; detected component impact may widen required checks and must never be narrowed by the agent.
- After implementation, run the default full verifier to refresh current live state; exit `2` can be expected while lifecycle evidence is pending. Then use `scripts/lifecycle.mjs complete`; it performs its own fresh inspection before recording authored semantic evidence as `evidence_recorded`. Supply evidence for every criterion ID and non-machine check returned by `begin`; the command snapshots those bytes. This evidence is integrity-bound, not independently evaluated, and not a new completion certificate.
- Only after targeted evidence is recorded, use `verify.mjs --change` to re-evaluate and bind the current packet/live state against the full original verifier gates without synthesizing semantic passes from the authored evidence. The command validates existing review artifacts; it does not recreate them.
- Optionally create a release-sized full checkpoint when renewed whole-site confidence is warranted. Never overwrite the initial baseline.
- Do not require a full source crawl, blind review, Git commit, Canvas, or launch gates for every localized post-baseline change.
