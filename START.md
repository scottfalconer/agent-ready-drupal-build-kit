# Start Here

**Turn an existing site into a real Drupal site, and let your AI agent do the Drupal.**

This page walks you through it step by step. You bring a site you want to rebuild and a coding agent. The kit brings the Drupal expertise, so you do not have to learn it first.

By the end of a run you will have a working Drupal site on your machine that looks, functions, and edits like the source site's public experience, plus a written record of every decision the agent made, a short list of the calls only a human can make, and evidence a senior Drupal developer could put their name on. You do not even need to know the difference between "Drupal" and "Drupal CMS"; the kit handles that.

A partial or representative site is not a successful run. If the site is missing reachable public content, media, source-like design, public behavior, or editor forms, the agent keeps working or records the real blocker.

Want the fast path? Use the canonical copy-paste prompt in [USAGE.md](USAGE.md). Want to understand what the agent is actually doing? Read the four moves and the review bar further down. For the full case - who it is for, why Drupal CMS, and when not to use it - see [docs/positioning.md](docs/positioning.md).

## Prerequisites

You need:

- a public source URL.
- permission to inspect and rebuild that site.
- on macOS, Docker Desktop or OrbStack installed and running. The installer can provision Docker on supported Linux systems, but its macOS path expects a working Docker runtime.

The official Drupal [One Line Installer](https://www.drupal.org/project/one_line_installer) checks and prepares the remaining stack: DDEV, Drupal CMS, and an in-container coding agent. Run it from the folder that should contain the new project:

```bash
bash <(curl -fsSL https://project.pages.drupalcode.org/one_line_installer/drupalaibp)
```

The current installer supports macOS and Linux.

Choose **Drupal CMS** and your preferred coding agent. The installer creates the project and leaves your shell in its root. This is the one Drupal target for the rebuild.

Install the build kit into that target and start Codex:

```bash
ddev exec npx --yes skills add https://github.com/scottfalconer/agent-ready-drupal-build-kit --skill agent-ready-drupal-build-kit -a codex -a claude-code -a opencode -y --copy
ddev codex
```

`ddev codex` is the Codex example. Use `ddev claude` or `ddev opencode` for the matching installer choice.

Node.js is provided inside DDEV, so a host Node installation is not required. From the project root, the relevant environment checks are:

```bash
ddev describe
ddev drush status
ddev exec node --version
```

If you already have a clean DDEV Drupal CMS project, skip the installer and install the skill there. A normal web chat alone is not enough because the agent needs filesystem, shell, Drupal, and browser access.

## Run Shape

Expect an iterative local build, not a single short chat response. Small sites can still take multiple agent passes because the agent must build the Drupal target, capture evidence, run verifier checks, fix gaps, and produce independent and blind-review artifacts. If the run stops mid-way, resume from the target Drupal project workspace and ask the agent to continue from `review-packet/`, current Drupal readback, and the last verifier output instead of starting over.

The first successful full verification creates a create-once, integrity-checked historical baseline under kit tooling. The initial rebuild remains done if the site is later changed. The installed kit can remain in the project to guide repairs and extensions and report whether the latest inspected state is unclassified, evidence-recorded, or fully verified.

## One Prompt

Copy the prompt from [USAGE.md](USAGE.md). Replace the bracketed source URL and send it to the agent.

You will not hand-edit anything yourself. The agent does the setup and review loop for you:

1. it adopts the Drupal CMS project created by the One Line Installer as the target and does not create another site;
2. it initializes the installed skill in that target;
3. it merges a concise build-kit project block into `AGENTS.md` while preserving regions managed by Drupal CMS, AI Best Practices, and the One Line Installer; that block points to the detailed contract packaged as `references/build-contract.md`;
4. it fills in the build-kit placeholders from your prompt and builds in the existing Drupal CMS site;
5. once the first meaningful source-shaped route works, it shares that real DDEV URL with you and then keeps building;
6. it verifies the result, fixes the highest-impact gaps, and repeats until the complete local rebuild bar is met or a real blocker is recorded;
7. it runs an independent live verification pass that tries to falsify packet and real-site claims;
8. it runs a blind adversarial product review against the original brief/source-of-truth and target, without showing the reviewer the builder's rationale first;
9. it produces `open-decisions.md` with only the decisions a human can make;
10. it uses the installed skill's packet templates, creates `review-packet/` with the evidence, and runs the target-local live verifier before handoff.

## Continue From The Verified Foundation

After the initial rebuild passes, do not restart the source-rebuild workflow for every request. Ask the agent to continue in the same Drupal project. It should inspect lifecycle status, classify the work before editing, and collect evidence for every surface the change can affect. `status` reads the last inspected cached state; it does not inspect the live Drupal runtime:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/lifecycle.mjs status --packet review-packet
```

These examples use host `node`; when Node is available only in DDEV, use `ddev exec node` in place of the leading `node`.

A repair addresses an original omission, regression, or defect. An extension adds new scope such as a feature, content model, integration, or composed experience. The original baseline remains passed in either case. If lifecycle `status` is not fresh, run the default verifier before `begin`; use `--adopt-current` when that inspection exposes existing drift. Begin the record before editing and declare each anonymous route expected to change with `--route`, or explicitly use `--no-public-route` for work with no anonymous route effect; omission is not an opt-out. Every concrete route must also be in the packet route matrix so the verifier actually fetches it. After implementation, run the full verifier once to refresh the exact live-state fingerprint; exit `2` can be expected while the changed state awaits lifecycle evidence. Then `complete` performs another fresh live inspection and records integrity-bound, authored evidence for the exact result. This targeted result is `evidence_recorded`, not independent verification or a new completion certificate. Every generated acceptance criterion needs its own evidence claim. After abandonment, refresh the live state and revert or explicitly adopt any leftover edits before beginning again.

Detected component impact can add required checks; agents must not remove or narrow those checks. Use `--adopt-current` only to classify edits that already exist; it always adds conservative `unknown` impact. Use `lifecycle.mjs abandon --reason "..."` when an active record will not be completed. After targeted evidence is recorded, a meaningful release-sized set of changes may use `verify.mjs --change` to re-evaluate the current packet/live state against the original full verifier gates and optionally create a fresh checkpoint. The command validates existing evidence; it does not itself recreate source crawls or blind reviews. See [docs/site-lifecycle.md](docs/site-lifecycle.md).

## Workspace Topology

Here is the shape you will end up with. Everything belongs to one DDEV project:

```text
drupal-project/                                  # the One Line Installer target
  .ddev/
  .agents/skills/agent-ready-drupal-build-kit/   # installed workflow, contract, and verifier
  AGENTS.md                                      # coexisting managed regions
  config/
  review-packet/                                 # evidence and handoff packet
    evidence/lifecycle/                          # historical baseline and later change state
  web/
```

Do not clone the kit beside this project, create a nested DDEV project, or replace `AGENTS.md` wholesale. The installed skill carries the workflow, templates, gate vocabulary, and verifier into the target.

## The Four Moves

Under the hood, the agent works in four moves and repeats them as a review loop. You do not have to drive these, but they are what keeps the result inspectable instead of a black box:

1. **Introspect:** read the source site: routes, content inventory, media, design system, public behaviors, and unresolved facts it must not invent.
2. **Assemble:** work on the Drupal CMS substrate already installed in the DDEV target, decide which bounded Recipes fit the audited source, declare the composition owner for flexible pages, then build with Drupal-native content types, fields, taxonomy, media, menus, Views, aliases, workflows, Canvas/Experience Builder or another declared owner where appropriate, theme/config work, and source-like public behavior.
3. **Capture intent:** record why each load-bearing decision was made, so a later agent or human is not guessing.
4. **Name gaps and decisions:** list remaining implementation gaps by role, then separately present only the decisions a human must make: production target, provider credentials, legal/privacy approval, accepted route/content dispositions, maintainer signoff, launch go/no-go, and authenticated acceptance of evidence-backed out-of-scope items. The local packet can record self-attested attribution but cannot provide that authentication. This decision list is not a reason to stop early; the agent keeps building everything it can before final handoff. An external blocker stays blocked and does not count as completed route coverage.

Before handoff, the agent also needs two skeptic passes. A fresh independent verifier checks the live Drupal site for missing routes, dropped collection items, broken embeds, unresolved footer/legal links, placeholder content, starter routes, composition model drift, fake Canvas component models, editor add-a-row failures, and stale evidence. The default target-local command independently identifies the DDEV target; binds its origin to the Drupal site UUID, front-page setting, config-sync directory, and clean config status read from that runtime; requires real Git-tracked YAML in that current sync directory; fetches every accepted route and target-required public route; checks links present in server-rendered response HTML; requires discovered same-origin targets to be declared or exactly dispositioned; validates expected external redirects without fetching the external origin; blocks unaccepted direct links back to the source origin; rejects non-success responses even when packet data repeats the same `5xx`; and checks the fetched primary routes' response canonical, meta description, and `og:image` against browser evidence. This HTTP check does not execute JavaScript; browser-only links must come from browser-first expansion and be represented in the route matrix. Every discovered route role needs a representative primary route, including detail pages when present. It does not independently perform authenticated editor tasks or prove collection/editor behavior without the separately required falsification evidence. Packet-only data and injected test runtimes cannot authorize completion. The blind adversarial reviewer sees only the original brief, the target, and source-of-truth materials before public review, then decides whether the produced site is actually good enough.

Before inspecting target parity, that same full verifier performs a separately budgeted source census from `sourceBaseUrl`: homepage and declared primary routes, same-origin server-rendered links, `robots.txt` Sitemap directives, bounded sitemap indexes, and bounded URL sets. It stores source status, final URL, title, H1, canonical, body hashes, and provenance. Every newly discovered reachable public path must be represented by an accepted source route; a builder-authored legacy, test, or intentionally-drop disposition cannot clear it. The agent adds and implements the route, then reruns. A private or persistently unreachable response may use a matching machine-evidenced boundary record without waiting for human review.

The same verifier probes a random missing route and access walls, resolves rendered legal/privacy links under the shared HTTP budget, and reconciles active consent config with verifier-owned before-consent network evidence. Optional or disabled controlled resources—including selector-only and attachment-only controls—require fresh per-primary-route CDP capture under the browser route ceiling and aggregate deadline.

## The Review Bar

This is what separates a complete Drupal rebuild from a foundation or lookalike. The build is measured against the questions a senior Drupal developer would ask before signing off:

- Is the build on Drupal CMS best practices using Drupal-native primitives?
- Is the architecture sound for the source site's real shape?
- Does it include the public content and media needed to review the site as a rebuild?
- Does it match the source site's visual language and public behavior?
- Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?
- Do flexible pages have a real authoring owner, and do Canvas pages have usable section-level component models when Canvas is used?
- Are the load-bearing decisions captured and usable by later agents?
- Are the remaining business, legal, integration, production, and launch gaps named?
- Did an independent verifier try to falsify the mechanical completion claims against the live site?
- Did a blind adversarial reviewer decide the target is good enough against the original brief and source-of-truth materials?
- Would a Drupal maintainer put their name on this as a complete local starting point?

If any answer is "no," the result can still be useful. It just is not yet something to stand behind.

## Required Packet

The canonical output list is in [gates.json](gates.json) and [docs/output-inventory.md](docs/output-inventory.md). From the target Drupal project, the agent should run the installed skill's default live verifier before handoff:

```bash
ddev exec node .agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs --packet review-packet
```

Use `scripts/verify-packet.mjs` only for explicit packet-only lint. Packet-only success never authorizes a complete rebuild claim.

An explicit verifier target must match one of the current project's authoritative DDEV web origins. Configured custom FQDNs qualify; service URLs such as Mailpit do not. Exit `0` authorizes the complete-local-rebuild machine claim, exit `2` means required machine evidence is incomplete, and exit `1` means packet or live-target validation failed. The report also carries `recordedHumanGateStatus`, but those builder-writable names and choices are self-attested status only and do not affect the machine verdict. Authenticated human approval, production readiness, and launch approval remain separate.

Early runs still create blocked stubs for gate records that are not earned yet. Missing gate files are worse than blocked ones, because missing files hide what remains.
