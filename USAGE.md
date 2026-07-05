# Using This Kit With An Agent

Use one prompt. Let the agent do the setup work.

## Canonical Prompt

Give your agent a source URL. Replace the bracketed value and give this to your coding agent from the parent workspace where the kit and Drupal project should sit:

```text
Use this Agent-Ready Build Kit for a Drupal CMS rebuild.

Source site: [SOURCE_URL]

Build the complete public-facing Drupal CMS rebuild: content, media, visual design, routes, functionality, and editor experience.
Do not hand back a partial or representative build as the result. A partial or incomplete site is a failed run unless a real blocker outside the local agent's control is recorded.

Run these preflight checks first:

docker info >/dev/null
ddev version
node --version

If Docker, DDEV, or Node.js 20+ is unavailable, stop and report the blocker.

If this agent runtime supports Agent Skills, read agent-ready-drupal-build-kit/docs/recommended-agent-skills.md. Install only skills that fit this run. AGENTS.md remains the operating contract. Record installed skill repos, selected skills, and versions or commit SHAs in review-packet/operator-run.md.

Create a clean Drupal CMS project workspace alongside the kit folder.
Copy agent-ready-drupal-build-kit/AGENTS.md.template from the kit folder into that workspace as AGENTS.md.
Fill the AGENTS.md placeholders from this prompt and the local workspace path.

Build a complete local Drupal CMS site with DDEV and drupal/cms. Do not substitute static HTML, screenshots, a local file preview, a CMS-shaped packet, a stock-theme placeholder, a partial/sample catalog, or a separate frontend.

Work in review loops: build, verify, self-review against AGENTS.md, fix the highest-impact gaps, update the review packet, and repeat until the complete local rebuild bar is met or a real blocker is recorded.

Before building flexible landing-like pages, declare the composition model in review-packet/pattern-map.json: selected Drupal authoring owner, route rationale, sections, data sources, expected editor actions, Canvas component model when Canvas is used, and any deviation records. Canvas is not mandatory for every homepage, but any public or rebuild-owned Canvas page must have a usable component model, not one monolithic component, JSON/newline URL/string blobs, or repeatable content detached from Drupal-owned data.

Before final handoff, run a fresh independent mechanical verification pass. Use a separate subagent, new context, review-only task, or clearly separated skeptic checklist that did not build the site. Its job is to falsify packet and live-site completion claims, not to summarize the builder's work. It must produce review-packet/independent-verification.json and check per-route item counts, collection ownership, rendered embeds/media, raw embed/markup scans, footer/menu/legal/target-required routes, source route drift dispositions, placeholder or starter content, Canvas placeholder leaks, composition model fidelity, Canvas component model fidelity, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness. If same-context fallback is unavoidable, record degraded independence.

Then run a blind adversarial product review in a fresh agent/context. Give that reviewer only the original brief, target URL or artifact, explicit source-of-truth materials from the brief, credentials needed for editor checks, and a restricted primary-route list extracted from route-matrix.json with route paths and source-truth references only. Do not show implementation files, review-packet files, builder notes, config/scripts, prior build conversation, or self-authored claims before the public/artifact review. The blind reviewer's job is to decide whether the target is good enough against the actual requested outcome. It must produce review-packet/blind-adversarial-review.json, store raw evidence under review-packet/evidence/blind-adversarial-review/, cover every primary route from the restricted route list at desktop and mobile widths unless an accepted omission is recorded, reference real screenshot evidence files, and evaluate visual/interaction parity, route content hierarchy, media/art fidelity, navigation, links, forms, embeds, editor maintainability, accessibility, SEO, console errors, and obvious usability defects. If a fresh blind reviewer/context is unavailable, record the degraded review honestly and leave completeLocalRebuildClaimAllowed false. Fix or item-block every failed mechanical or blind-review claim before calling the site complete.

At final handoff, produce review-packet/open-decisions.md with only decisions a human owner, operator, legal/privacy reviewer, maintainer, or launch authority can make. This is not a reason to stop early. Keep building and fixing everything the agent can resolve; do not list agent-resolvable implementation work as a human decision.

Follow the copied AGENTS.md as the operating guide. Start with public source audit, browser-first source route expansion, browser-rendered route manifest, content inventory, design capture, functionality capture, and pattern map, then make the recipe start-point decision, build with Drupal-native primitives, export structure to the tracked config sync directory, import reachable public content and media, match the source design language, record durable intent for load-bearing decisions, name scoped gaps, verify route matrix parity, browser-evidence.json, composition model fidelity, Canvas authoring ownership and component-model fidelity for composed pages, Drupal readback, field-to-output behavior, starter route cleanup, rendered SEO output, visual/function parity, non-admin editor forms, off-road-inventory.md, and produce every file named in docs/output-inventory.md.

Use the packet templates. From the target Drupal project workspace, copy matching files from ../agent-ready-drupal-build-kit/templates/ into review-packet/, remove the .template suffix in the target filename, and fill them with run-specific evidence or blocked stubs. Before final handoff, run:

node ../agent-ready-drupal-build-kit/bin/verify-packet.mjs --packet review-packet

Create the review packet inside the target workspace at review-packet/.

Mark uncertain facts, missing evidence, and assumptions clearly in the review packet instead of inventing details.
```

## Expected Workspace

The agent should create this shape:

```text
parent-folder/
  agent-ready-drupal-build-kit/
    START.md
    USAGE.md
    AGENTS.md.template
    templates/
    docs/
  drupal-project/
    AGENTS.md
    web/
    vendor/
    config/
    review-packet/
      source-audit.json
      pattern-map.json
      recipe-start-point.md
      durable-intent.yml
      scoped-gap-list.md
      open-decisions.md
      off-road-inventory.md
      operator-run.md
      production-target.md
      parity-report.json
      route-matrix.json
      browser-evidence.json
      independent-verification.json
      blind-adversarial-review.json
      drupal-readback.json
      field-output-matrix.json
      launch-checklist.md
      evidence/
        independent-verification/
        blind-adversarial-review/
        packet-verification.json
      maintainer-review.md
```

The kit folder is reference material. The Drupal project folder is the DDEV Drupal CMS project and active build workspace.

## What The Agent Must Prove

Before calling the local build successful, the agent must record:

- DDEV project URL;
- `ddev drush status`;
- enabled modules/profile;
- exported config, active config sync directory, tracked config directory, and clean config-import reproduction evidence;
- recipe start-point decision and any applied recipes;
- optional Agent Skills used, including repo, selected skill, version or commit SHA, and any conflict with `AGENTS.md`;
- content inventory and import evidence;
- design-system capture and target theme evidence;
- content types, fields, form displays, view displays, Views, menus, aliases, media, taxonomy, workflow, and permissions evidence;
- route matrix evidence for source-rendered routes, target statuses/H1s, homepage/front-page behavior, redirects, legal/footer links, and unexpected public 200 routes;
- browser-evidence.json with source/target browser-rendered screenshots or equivalent evidence for visitor-facing routes, visual/functional comparison, Canvas authoring ownership for composed pages, and authenticated non-admin editor tasks;
- independent-verification.json from a fresh verifier context that tries to falsify mechanical packet and live-site completion claims, including per-route item counts, collection ownership, rendered embed/media presence, raw embed/markup scans, footer/legal/target-required route resolution, route drift dispositions, placeholder/starter scans, Canvas placeholder leaks, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness;
- blind-adversarial-review.json from a fresh reviewer that did not build the site, saw only the brief, target, and source-of-truth materials before public review, covered desktop and mobile, and judged whether the produced site is good enough against the actual requested outcome;
- packet-verification.json from `node ../agent-ready-drupal-build-kit/bin/verify-packet.mjs --packet review-packet`, with a zero exit code and `completeLocalRebuildClaimAllowed: true` before any complete local rebuild claim;
- unfiltered Drupal readback for front page, config sync directory, all nodes including unpublished/default content, all aliases including duplicates, menus/menu links, Canvas pages when available, media counts, themes, and config status;
- field-to-output matrix showing which editor fields affect anonymous public output and which are editor-only metadata;
- off-road inventory for custom code, hardcoded public copy, raw rendering, Pathauto gaps, missing editor-role access, missing SEO token fields, and other places Drupal's normal guarantees were bypassed;
- rendered SEO evidence for public content types, including non-empty meta description and image/social metadata where applicable;
- anonymous public route checks;
- functional checks for source-like behaviors;
- browser-rendered homepage, listing, detail, search, contact, legal, and other representative route evidence;
- authenticated non-admin editor add/edit form checks with clean labels, visible load-bearing fields, and create/edit permission proof;
- a scoped gap list for operator, maintainer, content/business review, legal/privacy, integration, accessibility, performance, security, SEO, and launch evidence;
- an open decisions handoff that lists only human-owned decisions with current evidence, options, owner role, impact, and affected gate.

The verifier's zero exit code means the packet is structurally valid. The agent may claim a complete local rebuild only when `review-packet/evidence/packet-verification.json` records `completeLocalRebuildClaimAllowed: true` and the independent and blind-review evidence support that value.

## Fallback

If an agent cannot read the whole kit, give it only `AGENTS.md.template` plus the canonical prompt above. `AGENTS.md.template` is the single source of truth for build behavior.
