# Using This Kit With An Agent

Use one prompt. Let the agent do the setup work.

## Canonical Prompt

Give your agent a source URL. Add a target site name only if you care about it. Replace the bracketed value and give this to your coding agent from the kit folder:

```text
Use this Agent-Ready Build Kit for a Drupal CMS rebuild.

Source site: [SOURCE_URL]

Run these preflight checks first:

docker info >/dev/null
ddev version

If Docker or DDEV is unavailable, stop and report the blocker.

Derive TARGET_SITE_NAME and SITE_SLUG from the source site or supplied target name.
Create a clean sibling workspace named ${SITE_SLUG}-drupal.
Copy AGENTS.md.template from this kit into that workspace as AGENTS.md.
Fill the AGENTS.md placeholders from this prompt and your derived values.

Build a local Drupal CMS site with DDEV and drupal/cms. Do not substitute static HTML, screenshots, a local file preview, a CMS-shaped packet, or a separate frontend.

Follow the copied AGENTS.md as the operating guide. Start with public source audit and pattern map, then make the recipe start-point decision, build with Drupal-native primitives, record durable intent for load-bearing decisions, name scoped gaps, verify public routes and editor forms, and produce every file named in docs/output-inventory.md.

Create the review packet inside the target workspace at review-packet/.

Mark uncertain facts, missing evidence, and assumptions clearly in the review packet instead of inventing details.
Only use source sites you are allowed to inspect and rebuild. Do not copy source content, images, files, videos, private data, credentials, tracking IDs, or third-party integrations unless you have the right to use them.
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
  site-slug-drupal/
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
      owner-permission.md
      operator-run.md
      production-target.md
      parity-report.json
      launch-checklist.md
      maintainer-review.md
```

The kit folder is reference material. The `site-slug-drupal/` folder is the DDEV Drupal CMS project and active build workspace.

## What The Agent Must Prove

Before calling the local build successful, the agent must record:

- DDEV project URL;
- `ddev drush status`;
- enabled modules/profile;
- exported config;
- recipe start-point decision and any applied recipes;
- content types, fields, form displays, view displays, Views, menus, aliases, media, taxonomy, workflow, and permissions evidence;
- anonymous public route checks;
- browser-rendered homepage, listing, detail, search, contact, legal, and other representative route evidence;
- authenticated editor add/edit form checks with clean labels and visible load-bearing fields;
- a scoped gap list for owner, operator, maintainer, content, legal/privacy, integration, accessibility, performance, security, SEO, and launch evidence.

## Fallback

If an agent cannot read the whole kit, give it only `AGENTS.md.template` plus the canonical prompt above. Do not use the older multi-prompt patterns; `AGENTS.md.template` is the single source of truth for build behavior.
