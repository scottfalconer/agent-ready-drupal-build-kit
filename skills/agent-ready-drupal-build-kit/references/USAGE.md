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

Already have a clean DDEV Drupal CMS project? Open the coding agent in its root instead of an empty folder; the same prompt tells the agent to use it in place. If this file is inside an installed build-kit skill, that proves only that the skill copy is present, not that the managed browser is ready; the standard path runs `setup-browser-runtime.sh` before launching the agent.

## Brief-Only Prompt

The source-site prompt above is recommended. When there is no source site, save the requirements as a local file, replace the bracketed path, and paste this prompt instead:

```text
Build the site described in the brief below as a complete local Drupal CMS site.

Brief: [BRIEF_FILE]
Build kit: https://github.com/scottfalconer/agent-ready-drupal-build-kit

Use the build kit as your instructions and handle all setup yourself. If needed, use its recommended One Line Installer path. Work in exactly one Drupal project, install and initialize the kit in brief mode, then continue until the real Drupal site passes the kit's verification.

As soon as the first meaningful brief-defined route works, share its DDEV URL with me, then continue. Preserve the original brief, verify every accepted requirement, and do not claim source-site parity.
```

Brief mode keeps the original file in the review packet, derives stable requirement IDs and route-bound acceptance checks, and records assumptions, exclusions, and blockers. Its machine claim is `complete-local-build-from-brief`; source parity is neither required nor implied. The initializer replaces the source-audit and parity templates with brief-hash-bound `not_applicable` dispositions, so they cannot be mistaken for unfinished source-site evidence.

## Manual Setup (Optional)

If you prefer to prepare the Drupal target yourself, use the official One Line Installer to create one Drupal CMS project and install this kit into that project.

From the directory that should contain the project:

```bash
bash <(curl -fsSL https://project.pages.drupalcode.org/one_line_installer/drupalaibp)
```

The current installer supports macOS and Linux.

Choose Drupal CMS and the coding agent you want. When the installer leaves you in the new project directory, install the build-kit skill for every supported agent target:

```bash
ddev exec npx --yes skills add https://github.com/scottfalconer/agent-ready-drupal-build-kit --skill agent-ready-drupal-build-kit -a codex -a claude-code -a opencode -y --copy &&
bash .agents/skills/agent-ready-drupal-build-kit/scripts/setup-browser-runtime.sh
```

The setup script requires DDEV 1.25.3 or newer, pins and starts the supported DDEV Selenium/Chromium add-on, and
runs a real-target Chrome/CDP/axe smoke from the `web` container. It must finish before the agent starts; the first image pull can
take several minutes and reports progress. Then start the selected agent with `ddev codex`, `ddev claude`, or
`ddev opencode`. The installer-created project is the rebuild target. Do not create a second Drupal project or
choose another browser runtime.

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
      build-input.json
      brief-acceptance.json
      original-brief.md                 # brief mode only
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
      next-cycle-verification.json
      independent-verification.json
      blind-adversarial-review.json
      drupal-readback.json
      field-output-matrix.json
      negative-route-consent.json
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
        next-cycle/
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
- next-cycle-verification.json with machine-backed discovery of recurring date/year/season/period/taxonomy dimensions, a least-privilege non-admin future-cycle publish/public-output probe when applicable, and evidence-backed cleanup with no content, revision, alias, or term residue;
- the root `review-packet/evidence/review-handoff.json` and strict `review-handoff-independent.json` / `review-handoff-blind.json` reviewer projections from `ddev exec node .agents/skills/agent-ready-drupal-build-kit/scripts/review-handoff.mjs --packet review-packet` after a preliminary live run has established the finished builder state; give each reviewer only its own projection and byte-bound packet-local inputs, and require both reviewer artifacts to reference the exact root digest. The bundle is builder-writable, self-attested, and has no reviewer-identity, verdict, or completion authority; the final verifier re-discovers the complete declared input membership, re-hashes it, and rejects state, projection, membership, or byte drift;
- independent-verification.json from a fresh verifier context that tries to falsify mechanical packet and live-site completion claims, including per-route item counts, collection ownership, rendered embed/media presence, raw embed/markup scans, footer/legal/target-required route resolution, route drift dispositions, placeholder/starter scans, Canvas placeholder leaks, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness;
- blind-adversarial-review.json from a fresh reviewer that did not build the site, saw only the brief, target, and source-of-truth materials before public review, covered desktop and mobile, and judged whether the produced site is good enough against the actual requested outcome;
- live-verification.json from `ddev exec node .agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs --packet review-packet`, with a zero exit code, matching current DDEV target origin, Drupal site UUID, front-page setting, config-sync directory, and clean config status, plus the active typed claim set to true: `completeLocalRebuildClaimAllowed` or `completeLocalBuildFromBriefClaimAllowed`;
- unfiltered Drupal readback for the `system.site` UUID, front page, config sync directory, all nodes including unpublished/default content, all aliases including duplicates, menus/menu links, Canvas pages when available, media counts, themes, and config status;
- field-to-output matrix showing which editor fields affect anonymous public output and which are editor-only metadata;
- a usable non-admin editor workflow for every custom public bundle and every bundle that owns repeating public content, plus falsification checks for every load-bearing field and every field claimed to affect anonymous output;
- off-road inventory for custom code, hardcoded public copy, raw rendering, Pathauto gaps, missing editor-role access, missing SEO token fields, and other places Drupal's normal guarantees were bypassed;
- composition evidence showing the target's actual route owner matches the declared owner, or a target-bound accepted deviation names the fallback, rationale, accepter, and evidence;
- rendered SEO evidence for every primary route, including one usable canonical, a non-empty meta description, and `og:image` where applicable; each `not_applicable` disposition needs reviewed rationale and evidence;
- negative-route and consent evidence: a generated 404 with title/H1, noindex policy, and absent-or-self canonical; access-wall canonical checks; all rendered internal legal/privacy links; active consent managers/applications and controlled resources; and fresh before-consent browser evidence for every primary route with consent storage cleared;
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

The default verifier exits zero only when the detected live DDEV target, machine-checkable packet readiness, Drupal site identity, independent verification, and blind review all authorize the active typed machine claim. In source-site mode that claim is `complete-local-rebuild`; in brief mode it is `complete-local-build-from-brief`. Both modes verify the target and Drupal runtime. Source census, source-origin leaks, and legacy-source redirect materialization apply only in source-site mode; brief mode instead requires the preserved brief hash, accepted `BR-###` requirements, target-route bindings, and independent requirement checks. Packet-only data and injected test runtimes may help diagnostics, but can never authorize completion. Exit `2` means the packet and live checks are valid but required machine evidence is incomplete; exit `1` means invalid packet or live-target checks. Non-zero outcomes normally write `agentContinuation.requiredAction: repair-and-reverify` and `shouldContinue: true`; the agent fixes locally resolvable reasons and reruns without waiting for human review. When every remaining blocker is verifier-confirmed external, the report instead writes `status: externally_blocked`, `requiredAction: pause-and-report`, `agentMayPause: true`, and `shouldContinue: false`. Each structured blocker names its verifier-owned origin, resolution class, attempted evidence, missing input, and next action. A builder-authored `external_blocker` label cannot downgrade a machine-detected failure, and an external blocker never authorizes completion or handoff. `recordedHumanGateStatus` separately reports builder-writable names and choices as self-attested record status; it does not affect machine completion, verdict, exit code, or the agent's ability to continue. Authenticated human approval and production or launch approval remain separate.

When a maintainer or launch review requires actual clean-install or snapshot reproduction, follow `references/disposable-reproduction.md` and run `scripts/verify-reproduction.mjs` from the DDEV host. Its typed, digest-bound exact-HEAD plan and generated `evidence/reproduction-verification.json` are separate from the default handoff verdict; never treat a snapshot run as clean-install/config-import proof.

When launch review claims that a project-local assembly workflow is idempotent, extension-safe, or recoverable, follow `references/disposable-assembly.md` and run `scripts/verify-assembly.mjs` from the DDEV host. `G-ASSEMBLY-01` starts from a separately declared pre-assembly substrate and writes `evidence/assembly-verification.json`; it is distinct from final-state reproduction (`G-REPRO-01`) and never changes the default handoff verdict. Do not make an idempotence claim from a builder-authored rerun note or browser screenshots.

In source-site mode, the verifier-owned source census uses explicit route, sitemap, request, task, body-size, concurrency, and wall-clock limits. It fetches the homepage and declared primary routes, follows same-origin rendered links, reads sitemap hints, and requires newly discovered reachable paths to be represented by accepted source routes. This source-only work is reported as `not_applicable` in brief mode and does not block the brief claim.

That same shared HTTP budget covers the generated missing route, access-wall routes, and rendered legal/privacy links. When any application declares controlled resources—including selector-only and attachment-only declarations—the verifier records CDP network requests from a fresh isolated context for every primary route before interaction, regardless of enabled or `required` status. The capture is bound to the exact target, route set, time, and Drupal state and uses the browser route ceiling plus aggregate deadline. Matching requests, unavailable Chrome, incomplete coverage, unsettled network, or budget exhaustion fail closed. `required: true` alone cannot exempt a controlled resource; pre-consent loading requires an explicit essential-service classification, rationale, and packet-local evidence.

## Continue After The Initial Pass

The first successful full verification creates a create-once, integrity-checked historical baseline under kit tooling for that exact initial rebuild state. The initial rebuild remains done when development continues; this is an integrity-checked record, not a claim of cryptographic immutability or tamper-proof storage.

Before later work, inspect the lifecycle:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/lifecycle.mjs status --packet review-packet
```

`status` reports the last inspected cached state; it does not inspect DDEV. Cached-state commands such as `status`, `begin`, and `abandon` may use host `node`. Every default verifier, `verify.mjs --change`, and `lifecycle.mjs complete` run performs live inspection and must execute inside DDEV: use plain `node` from the active DDEV agent, or prefix the command with `ddev exec` from a host terminal. If `currentStateFresh` is false, run the default verifier before `begin`; use `--adopt-current` when that inspection exposes existing drift. The first executable-global-chrome run also needs one refresh while the site still matches its latest verified anchor. Classify the request as a `repair` when it corrects something the initial rebuild should have delivered, or an `extension` when it adds new scope. Run `lifecycle.mjs begin` before editing so the record captures `baseAnchorId` from the latest verified or evidence-recorded anchor. Repeat `--route /path` for every anonymous route expected to change, or explicitly use `--no-public-route` when the change has no anonymous route effect; an omitted route classification is rejected. Implement the change, then run the default full verifier to refresh the exact live-state fingerprint. Exit `2` can be expected while that changed state still lacks lifecycle evidence.

Write a `public-kit.change-verification.1` JSON containing one `acceptanceEvidence` claim for every stable criterion ID returned by `begin`, every generated non-machine semantic check, and project-relative evidence. Copy `baseFingerprint` from the `begin` output and `resultFingerprint` from `.buildState.fingerprint` in the fresh `review-packet/evidence/live-verification.json`. Every concrete affected route must also appear in the packet's primary or target-required route matrix and pass the fresh anonymous fetch. Then run `ddev exec node .agents/skills/agent-ready-drupal-build-kit/scripts/lifecycle.mjs complete --verification <path>` from the host, or omit `ddev exec` inside the active DDEV agent. Completion performs its own fresh live inspection, derives state/config/route checks, and machine-evaluates applicable global chrome against the latest verified state-bound desktop/mobile anchor. Authored chrome pass booleans are ignored. It snapshots other referenced evidence bytes and records the result as `evidence_recorded`. The authored semantic evidence is integrity-bound to that inspected state, but the kit does not independently evaluate it and this is not a new completion certificate. Detected component or undeclared-route impact can widen the required checks; an agent must not remove or narrow them. If the managed browser runtime is unavailable, leave the active agent running and execute `bash .agents/skills/agent-ready-drupal-build-kit/scripts/repair-browser-runtime.sh` from a separate host terminal at the DDEV project root; do not install Chrome or set `CHROME_PATH` as a fallback. The authored input may include `conservative-full-regression` proactively for widening. Use `lifecycle.mjs abandon --reason "..."` instead when the active record will not be completed. After abandonment, refresh with the default verifier and either revert leftover edits or classify them with `--adopt-current` before beginning again.

Only after targeted evidence is recorded may `verify.mjs --change <change-id>` re-evaluate the current packet/live state against the full original verifier gates and bind its report. This path does not synthesize passing semantic checks from the targeted evidence, and it does not itself recreate source crawls, editor runs, or independent/blind reviews. Refresh affected evidence first. Add `--checkpoint <checkpoint-id>` when that passing full result should promote the exact current state to a new checkpoint. Neither operation overwrites the historical initial baseline.

Unclassified changes are not evidence-recorded or fully verified, even though the initial baseline remains passed. The kit does not require a Git commit, Canvas, launch evidence, or a full source/blind-review rerun for every post-baseline change. See the canonical [site lifecycle reference](https://github.com/scottfalconer/agent-ready-drupal-build-kit/blob/main/docs/site-lifecycle.md).

## Fallback

If an agent cannot load the installed skill, give it the merged build-kit region in `AGENTS.md` plus the canonical prompt above. Do not replace the other managed regions in `AGENTS.md`.
