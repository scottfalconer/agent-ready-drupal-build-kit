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

If Docker or DDEV is unavailable, stop and report the blocker.

If this agent runtime supports Agent Skills, read docs/recommended-agent-skills.md. Install only skills that fit this run. AGENTS.md remains the operating contract. Record installed skill repos, selected skills, and versions or commit SHAs in review-packet/operator-run.md.

Create a clean Drupal CMS project workspace alongside the kit folder.
Copy AGENTS.md.template from the kit folder into that workspace as AGENTS.md.
Fill the AGENTS.md placeholders from this prompt and the local workspace path.

Build a complete local Drupal CMS site with DDEV and drupal/cms. Do not substitute static HTML, screenshots, a local file preview, a CMS-shaped packet, a stock-theme placeholder, a partial/sample catalog, or a separate frontend.

Work in review loops: build, verify, self-review against AGENTS.md, fix the highest-impact gaps, update the review packet, and repeat until the complete local rebuild bar is met or a real blocker is recorded.

Follow the copied AGENTS.md as the operating guide. Start with public source audit, browser-first source route expansion, browser-rendered route manifest, content inventory, design capture, functionality capture, and pattern map, then make the recipe start-point decision, build with Drupal-native primitives, export structure to the tracked config sync directory, import reachable public content and media, match the source design language, record durable intent for load-bearing decisions, name scoped gaps, verify route matrix parity, browser-evidence.json, Canvas authoring ownership for composed pages, Drupal readback, field-to-output behavior, starter route cleanup, rendered SEO output, visual/function parity, non-admin editor forms, off-road-inventory.md, and produce every file named in docs/output-inventory.md.

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
      off-road-inventory.md
      operator-run.md
      production-target.md
      parity-report.json
      route-matrix.json
      browser-evidence.json
      drupal-readback.json
      field-output-matrix.json
      launch-checklist.md
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
- unfiltered Drupal readback for front page, config sync directory, all nodes including unpublished/default content, all aliases including duplicates, menus/menu links, Canvas pages when available, media counts, themes, and config status;
- field-to-output matrix showing which editor fields affect anonymous public output and which are editor-only metadata;
- off-road inventory for custom code, hardcoded public copy, raw rendering, Pathauto gaps, missing editor-role access, missing SEO token fields, and other places Drupal's normal guarantees were bypassed;
- rendered SEO evidence for public content types, including non-empty meta description and image/social metadata where applicable;
- anonymous public route checks;
- functional checks for source-like behaviors;
- browser-rendered homepage, listing, detail, search, contact, legal, and other representative route evidence;
- authenticated non-admin editor add/edit form checks with clean labels, visible load-bearing fields, and create/edit permission proof;
- a scoped gap list for operator, maintainer, content/business review, legal/privacy, integration, accessibility, performance, security, SEO, and launch evidence.

## Fallback

If an agent cannot read the whole kit, give it only `AGENTS.md.template` plus the canonical prompt above. Do not use the older multi-prompt patterns; `AGENTS.md.template` is the single source of truth for build behavior.
