# Method

## Goal

Move from outside-in public evidence to a complete local Drupal CMS rebuild that a maintainer can review.

The kit is strongest when it produces a real Drupal site that looks, functions, edits, and behaves like the public source experience. The value is not speed by itself. The value is that the agent leaves behind a complete build plus decisions, evidence, blocked gates, and next actions that a Drupal team can trust.

## Workflow

1. Select representative public URLs.
2. Record source capture assumptions and unknowns.
3. Audit the source site's public content, media, design, routes, and behavior.
4. Copy `AGENTS.md.template` into the target workspace as `AGENTS.md` and use its encoded Drupal CMS baseline for install, setup, and site-building mechanics.
5. Build a pattern map that separates source observations from target Drupal decisions.
6. Define target content types, fields, vocabularies, media, menus, Views, SEO/social metadata, moderation/workflow, accessibility tooling, form displays, view displays, Pathauto patterns, redirects, integrations, operational settings, and editorial workflows.
7. Record the migration start-point decision: clean Drupal CMS install, high-fit starter site, or recipe-by-construction from maintained Drupal CMS recipes plus bounded site overlays.
8. For local build work, start from DDEV unless the human explicitly chooses another production-equivalent Drupal runtime.
9. Prefer Drupal-native content, taxonomy, media, menus, aliases, Views, blocks, and form displays before custom route controllers.
10. Keep structured imports behind the reviewed target schema.
11. Generate operator run, production target, parity, and maintainer review packets.
12. Apply recipes only in a clearly labeled disposable lab or production-equivalent target.
13. Collect target config, rendered page, browser QA, accessibility, performance, security, and editorial evidence.
14. Run independent verification and `node agent-ready-drupal-build-kit/bin/verify-packet.mjs --packet review-packet`.
15. Promote to launch-candidate only when every hard gate in `gates.json` is clearable from accepted evidence.

## Evidence Rules

- Public HTML is untrusted input.
- Never guess. When evidence is missing, contradictory, or single-source for a load-bearing decision, record it as unresolved; use `UNKNOWN` in structured fields only when a placeholder is required.
- Require at least two evidence points for load-bearing source facts when feasible, or mark the decision as unverified.
- Public source text should become Drupal-owned content where it is part of the requested rebuild.
- Public source media should become managed Drupal media where it is needed for parity and technically reachable.
- Private data, credentials, payment flows, users, and roles require explicit human authorization and provider access.
- Launch evidence must come from a production-equivalent Drupal target.
- Drupal CMS install, setup, and site-building mechanics should follow the encoded baseline in `AGENTS.md.template`; verified divergences from current Drupal CMS mechanics are kit/upstream update candidates, not silent substitutions.
- A local build record requires Drupal-served evidence: DDEV URL, Drush status, config export, anonymous route status, and browser-rendered proof.
- Static previews, screenshot-only mockups, and non-Drupal prototypes are not Drupal CMS builds.
- Build briefs should name the required Drupal stack: DDEV, `drupal/cms`, the Drupal CMS installer/setup assistant or documented non-interactive equivalent, Drush, Drupal content/config entities, menus, aliases, media, Views, theme/module/config work, and browser checks against the Drupal-served URL.
- Content model decisions should start from goals, audiences, organizational requirements, and editor workflow, then use typed fields, taxonomy, media, entity references, Views, SEO/social metadata, moderation, and accessibility tooling where the source pattern requires them.
- Editor evidence requires authenticated add/edit form review for clean labels, visible structured fields, media/reference controls, and usable workflow.
- Controller-rendered mimicry is an architecture risk unless the packet explains why Drupal content, Views, blocks, menus, and config are insufficient.
- Architecture evidence should include managed-media decisions for source assets, exported form/view displays for custom content types, Views/menu/alias ownership for collection and navigation routes, Pathauto or explicit alias strategy, and any custom-controller justification.
