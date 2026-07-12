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
        lifecycle/
          initial-baseline.json
          current-state.json
          changes/
            change-id/
              change.json
              verification.json
          checkpoints/
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
- a collection ledger row for every declared list, grid, schedule, directory, archive, catalog, feed, gallery, or search-like route, with source and target counts, Drupal ownership, and non-admin editor add-a-row evidence; counts must match unless a recorded owner label, reason, and evidence disposition an exclusion (local attribution is self-attested), and a private or unreachable item needs evidence of that boundary;
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

The default verifier exits zero only when the detected live DDEV target, machine-checkable packet readiness, Drupal site identity, independent verification, and blind review all authorize the complete-local-rebuild machine claim. It runs primary, target-required, browser-representative, accepted full-surface, server-rendered link, source-origin, and redirect-materialization checks through one shared concurrency/request/task/deadline budget; every redirect hop consumes that budget, and exhaustion blocks completion. It preserves query-distinct states while redacting query values in reports, requires discovered same-origin targets to be declared or exactly dispositioned, validates expected external redirects without fetching the external origin, blocks direct source-origin links without exact evidenced acceptance, materializes source path+query mappings through a first-hop `301` or `308` to the exact same-origin target path+query unless a named, evidenced exception is accepted, rejects self-consistent `5xx` failures, checks required rendered canonical/meta-description/`og:image` output, and independently requires real Git-tracked YAML in the current config-sync directory. It does not execute JavaScript; browser-only and imported-body routes must be recorded during route expansion. Every discovered route role needs a representative primary route. An explicit target must match one of the current project's authoritative DDEV web origins; configured custom FQDNs qualify, service URLs such as Mailpit do not. Packet-only data and injected test runtimes may help diagnostics, but can never authorize completion. Exit `2` means the packet and live checks are valid but required machine evidence is incomplete; exit `1` means invalid packet or live-target checks. `recordedHumanGateStatus` separately reports builder-writable names and choices as self-attested record status; it does not affect machine completion, verdict, or exit code. Authenticated human approval and production or launch approval remain separate.

## Continue After The Initial Pass

The first successful full verification creates a create-once, integrity-checked historical baseline under kit tooling for that exact initial rebuild state. The initial rebuild remains done when development continues; this is an integrity-checked record, not a claim of cryptographic immutability or tamper-proof storage.

Before later work, inspect the lifecycle:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/lifecycle.mjs status --packet review-packet
```

`status` reports the last inspected cached state; it does not inspect DDEV. Commands in this section use host `node`; replace the leading `node` with `ddev exec node` when Node is available only inside DDEV. If `currentStateFresh` is false, run the default verifier before `begin`; use `--adopt-current` when that inspection exposes existing drift. The first executable-global-chrome run also needs one refresh while the site still matches its latest verified anchor. Classify the request as a `repair` when it corrects something the initial rebuild should have delivered, or an `extension` when it adds new scope. Run `lifecycle.mjs begin` before editing so the record captures `baseAnchorId` from the latest verified or evidence-recorded anchor. Repeat `--route /path` for every anonymous route expected to change, or explicitly use `--no-public-route` when the change has no anonymous route effect; an omitted route classification is rejected. Implement the change, then run the default full verifier to refresh the exact live-state fingerprint. Exit `2` can be expected while that changed state still lacks lifecycle evidence.

Write a `public-kit.change-verification.1` JSON containing one `acceptanceEvidence` claim for every stable criterion ID returned by `begin`, every generated non-machine semantic check, and project-relative evidence. Copy `baseFingerprint` from the `begin` output and `resultFingerprint` from `.buildState.fingerprint` in the fresh `review-packet/evidence/live-verification.json`. Every concrete affected route must also appear in the packet's primary or target-required route matrix and pass the fresh anonymous fetch. Then run `lifecycle.mjs complete --verification <path>`. Completion performs its own fresh live inspection, derives state/config/route checks, and machine-evaluates applicable global chrome against the latest verified state-bound desktop/mobile anchor. Authored chrome pass booleans are ignored. It snapshots other referenced evidence bytes and records the result as `evidence_recorded`. The authored semantic evidence is integrity-bound to that inspected state, but the kit does not independently evaluate it and this is not a new completion certificate. Detected component or undeclared-route impact can widen the required checks; an agent must not remove or narrow them. If Chrome/Chromium is not found for an applicable check, set `CHROME_PATH` or install it; the check fails closed. The authored input may include `conservative-full-regression` proactively for widening. Use `lifecycle.mjs abandon --reason "..."` instead when the active record will not be completed. After abandonment, refresh with the default verifier and either revert leftover edits or classify them with `--adopt-current` before beginning again.

Only after targeted evidence is recorded may `verify.mjs --change <change-id>` re-evaluate the current packet/live state against the full original verifier gates and bind its report. This path does not synthesize passing semantic checks from the targeted evidence, and it does not itself recreate source crawls, editor runs, or independent/blind reviews. Refresh affected evidence first. Add `--checkpoint <checkpoint-id>` when that passing full result should promote the exact current state to a new checkpoint. Neither operation overwrites the historical initial baseline.

Unclassified changes are not evidence-recorded or fully verified, even though the initial baseline remains passed. The kit does not require a Git commit, Canvas, launch evidence, or a full source/blind-review rerun for every post-baseline change. See the canonical [site lifecycle reference](https://github.com/scottfalconer/agent-ready-drupal-build-kit/blob/main/docs/site-lifecycle.md).

## Fallback

If an agent cannot load the installed skill, give it the merged build-kit region in `AGENTS.md` plus the canonical prompt above. Do not replace the other managed regions in `AGENTS.md`.
