# Using This Kit With An Agent

## Canonical Prompt

Open Codex, Claude Code, or OpenCode in an empty folder. Replace the bracketed source URL and paste the whole prompt:

```text
Rebuild the source site below as a complete local Drupal CMS site.

Source site: [SOURCE_URL]
Build kit: https://github.com/scottfalconer/agent-ready-drupal-build-kit

Use the build kit as your instructions and handle all setup yourself. If needed, use its recommended One Line Installer path. Work in exactly one Drupal project, install and initialize the kit there, then continue until the real Drupal site passes the kit's verification.

As soon as the first meaningful source-shaped route works, share its DDEV URL with me, then continue. Do not hand back a partial or representative build as the result.
```

You can stop here—the agent handles setup, the rebuild, real-site verification, and the review packet. Everything below is optional reference or manual setup.

Already have a clean DDEV Drupal CMS project? Open the coding agent in its root instead of an empty folder; the same prompt tells the agent to use it in place. If this file is inside an installed build-kit skill, setup is already complete.

## Manual Setup (Optional)

If you prefer to prepare the Drupal target yourself, use the official One Line Installer to create one Drupal CMS project and install this kit into that project.

From the directory that should contain the project:

```bash
bash <(curl -fsSL https://project.pages.drupalcode.org/one_line_installer/drupalaibp)
```

The current installer supports macOS and Linux.

Choose Drupal CMS and the coding agent you want. When the installer leaves you in the new project directory, install the build-kit skill for every supported agent target:

```bash
ddev exec npx --yes skills add https://github.com/scottfalconer/agent-ready-drupal-build-kit --skill agent-ready-drupal-build-kit -a codex -a claude-code -a opencode -y --copy
```

Start the agent you selected with `ddev codex`, `ddev claude`, or `ddev opencode`. The installer-created project is the rebuild target. Do not create a second Drupal project.

## Expected Workspace

The completed workflow uses and produces this single-project shape; evidence directories and verifier reports appear as the review passes run:

```text
drupal-project/
  .ddev/
  .agents/
    skills/
      agent-ready-drupal-build-kit/
        SKILL.md
        gates.json
        assets/
        references/
        scripts/
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
        live-verification.json
        packet-verification.json
      maintainer-review.md
```

The installed skill is project-local reference material. The surrounding Drupal project is both the DDEV target and the active build workspace.

## What The Agent Must Prove

Before calling the local build successful, the agent must record:

- DDEV project URL;
- `ddev drush status`;
- enabled modules/profile;
- exported config, a non-empty tracked config sync directory, and evidence that active configuration has no drift from it;
- the installed Drupal CMS substrate, the post-audit Recipe fit decision, and any applied Recipes;
- optional Agent Skills used, including repo, selected skill, version or commit SHA, and any conflict with `AGENTS.md`;
- content inventory and import evidence;
- a collection ledger row for every declared list, grid, schedule, directory, archive, catalog, feed, gallery, or search-like route, with source and target counts, Drupal ownership, and non-admin editor add-a-row evidence; counts must match unless a named owner accepts an evidence-backed exclusion, and a private or unreachable item needs evidence of that boundary;
- design-system capture and target theme evidence;
- content types, fields, form displays, view displays, Views, menus, aliases, media, taxonomy, workflow, and permissions evidence;
- route matrix evidence for source-rendered routes, target statuses/H1s, homepage/front-page behavior, redirects, legal/footer links, and unexpected public 200 routes;
- browser-evidence.json with source/target browser-rendered screenshots or equivalent evidence for visitor-facing routes, visual/functional comparison, Canvas authoring ownership for composed pages, and authenticated non-admin editor tasks;
- independent-verification.json from a fresh verifier context that tries to falsify mechanical packet and live-site completion claims, including per-route item counts, collection ownership, rendered embed/media presence, raw embed/markup scans, footer/legal/target-required route resolution, route drift dispositions, placeholder/starter scans, Canvas placeholder leaks, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness;
- blind-adversarial-review.json from a fresh reviewer that did not build the site, saw only the brief, target, and source-of-truth materials before public review, covered desktop and mobile, and judged whether the produced site is good enough against the actual requested outcome;
- live-verification.json from `node .agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs --packet review-packet`, with a zero exit code, matching current DDEV target origin, Drupal site UUID, front-page setting, config-sync directory, and clean config status, plus `completeLocalRebuildClaimAllowed: true` before any complete local rebuild claim;
- unfiltered Drupal readback for the `system.site` UUID, front page, config sync directory, all nodes including unpublished/default content, all aliases including duplicates, menus/menu links, Canvas pages when available, media counts, themes, and config status;
- field-to-output matrix showing which editor fields affect anonymous public output and which are editor-only metadata;
- a usable non-admin editor workflow for every custom public bundle and every bundle that owns repeating public content, plus falsification checks for every load-bearing field and every field claimed to affect anonymous output;
- off-road inventory for custom code, hardcoded public copy, raw rendering, Pathauto gaps, missing editor-role access, missing SEO token fields, and other places Drupal's normal guarantees were bypassed;
- composition evidence showing the target's actual route owner matches the declared owner, or a target-bound accepted deviation names the fallback, rationale, accepter, and evidence;
- rendered SEO evidence for every primary route, including one usable canonical, a non-empty meta description, and `og:image` where applicable; each `not_applicable` disposition needs reviewed rationale and evidence;
- environment-portable exported SEO defaults with request/entity/media tokens instead of literal DDEV, localhost, loopback, or any current authoritative DDEV web-origin URL, including a custom FQDN;
- anonymous public route checks;
- raw in-browser axe-core evidence with accepted full-default or WCAG-tagged rule scope; every incomplete disposition must use structured evidence bound to the exact URL, rule, target, result, and timestamp, plus keyboard, focus, accessible-name, and applicable form-error checks;
- anonymous public-form source/model/browser/independent alignment by stable `formKey`; invalid and valid synthetic submissions; and structured, mode-specific outcome and vendor-neutral abuse-protection evidence bound to the same target (the live verifier accepts a local-only exception only for authoritative project web origins, including custom FQDNs but excluding service URLs; local proof does not establish production delivery or privacy compliance);
- one browser-verified representative detail route whose fields cover required and anonymous-output fields, match a concrete Drupal owner config ID, and have selector-bound computed visibility plus an independent matching check, for every collection with separate public item details;
- functional checks for source-like behaviors;
- browser-rendered homepage, listing, detail, search, contact, legal, and other representative route evidence;
- authenticated non-admin editor add/edit form checks with clean labels, visible load-bearing fields, and create/edit permission proof;
- a scoped gap list for operator, maintainer, content/business review, legal/privacy, integration, accessibility, performance, security, SEO, and launch evidence;
- an open decisions handoff that lists only human-owned decisions with current evidence, options, owner role, impact, and affected gate.

The default verifier exits zero only when the detected live DDEV target, packet readiness, Drupal site identity, independent verification, and blind review all authorize completion. It fetches primary, target-required, and browser-representative routes under one shared route/request/deadline budget, preserves representative query states, rejects self-consistent `5xx` failures, inspects required actual rendered canonical/meta-description/`og:image` output, and independently requires real Git-tracked YAML in the current config-sync directory. An explicit target must match one of the current project's authoritative DDEV web origins; configured custom FQDNs qualify, service URLs such as Mailpit do not. Packet-only data and injected test runtimes may help diagnostics, but can never authorize completion. Exit `2` means structurally valid but incomplete; exit `1` means invalid packet or live-target checks. This local verdict is not production or launch approval.

## Fallback

If an agent cannot load the installed skill, give it the merged build-kit region in `AGENTS.md` plus the canonical prompt above. Do not replace the other managed regions in `AGENTS.md`.
