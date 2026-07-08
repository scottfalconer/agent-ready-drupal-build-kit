# Start Here

**Turn an existing site into a real Drupal site, and let your AI agent do the Drupal.**

This page walks you through it step by step. You bring a site you want to rebuild and a coding agent. The kit brings the Drupal expertise, so you do not have to learn it first.

By the end of a run you will have a working Drupal site on your machine that looks, functions, and edits like the source site's public experience, plus a written record of every decision the agent made, a short list of the calls only a human can make, and evidence a senior Drupal developer could put their name on. You do not even need to know the difference between "Drupal" and "Drupal CMS"; the kit handles that.

A partial or representative site is not a successful run. If the site is missing reachable public content, media, source-like design, public behavior, or editor forms, the agent keeps working or records the real blocker.

Want the fast path? Use the canonical copy-paste prompt in [USAGE.md](USAGE.md). Want to understand what the agent is actually doing? Read the four moves and the review bar further down. For the full case - who it is for, why Drupal CMS, and when not to use it - see [docs/positioning.md](docs/positioning.md).

## Prerequisites

You will need a few things on your machine first:

- Docker running;
- DDEV installed;
- Node.js 20 or newer;
- a local coding agent with filesystem and shell access, such as Claude Code, Codex, Cursor, Windsurf, Cline, RooCode, or a comparable local agentic IDE/tool;
- a public source URL.

A normal web chat alone is not enough, because the agent must create files and run local commands.

Run this preflight first, or ask the agent to run it:

```bash
docker info >/dev/null
ddev version
node --version
```

If Docker, DDEV, or Node.js 20+ is unavailable, the fastest fix is the Drupal [One Line Installer](https://www.drupal.org/project/one_line_installer), which sets up the full environment in one command:

```bash
bash <(curl -fsSL https://project.pages.drupalcode.org/one_line_installer/drupalaibp)
```

## Run Shape

Expect an iterative local build, not a single short chat response. Small sites can still take multiple agent passes because the agent must build the Drupal target, capture evidence, run verifier checks, fix gaps, and produce independent and blind-review artifacts. If the run stops mid-way, resume from the target Drupal project workspace and ask the agent to continue from `review-packet/`, current Drupal readback, and the last verifier output instead of starting over.

## One Prompt

Copy the prompt from [USAGE.md](USAGE.md). Replace the bracketed source URL and send it to the agent.

You will not hand-edit anything yourself. The agent does the setup and review loop for you:

1. it keeps the kit as reference material and creates a clean Drupal CMS project workspace beside it;
2. it copies `AGENTS.md.template` into that workspace as `AGENTS.md`, which is what carries Drupal's best practices into the build;
3. it fills in the placeholders from your prompt;
4. it builds the Drupal CMS site with DDEV and `drupal/cms`;
5. it verifies the result, fixes the highest-impact gaps, and repeats until the complete local rebuild bar is met or a real blocker is recorded;
6. it runs an independent mechanical verifier pass that tries to falsify packet and live-site claims;
7. it runs a blind adversarial product review against the original brief/source-of-truth and target, without showing the reviewer the builder's rationale first;
8. it produces `open-decisions.md` with only the decisions a human can make;
9. it copies the needed packet templates from `templates/`, creates `review-packet/` with the evidence, and runs `bin/verify-packet.mjs` before handoff.

## Workspace Topology

Here is the shape you will end up with:

```text
parent-folder/
  agent-ready-drupal-build-kit/        # this kit, reference only
  drupal-project/                     # DDEV Drupal CMS project, your new site
    AGENTS.md                         # copied from AGENTS.md.template
    review-packet/                    # evidence and handoff packet
```

The kit folder is not the Drupal site. It sits beside the Drupal project as reference material.

## The Four Moves

Under the hood, the agent works in four moves and repeats them as a review loop. You do not have to drive these, but they are what keeps the result inspectable instead of a black box:

1. **Introspect:** read the source site: routes, content inventory, media, design system, public behaviors, and unresolved facts it must not invent.
2. **Assemble:** stand up DDEV plus `drupal/cms`, decide the recipe start point, declare the composition owner for flexible pages, then build with Drupal-native content types, fields, taxonomy, media, menus, Views, aliases, workflows, Canvas/Experience Builder or another declared owner where appropriate, theme/config work, and source-like public behavior.
3. **Capture intent:** record why each load-bearing decision was made, so a later agent or human is not guessing.
4. **Name gaps and decisions:** list remaining implementation gaps by role, then separately present only the decisions a human must make: production target, provider credentials, legal/privacy approval, accepted route/content dispositions, maintainer signoff, launch go/no-go, and accepted out-of-scope blockers. This decision list is not a reason to stop early; the agent keeps building everything it can before final handoff.

Before handoff, the agent also needs two skeptic passes. The mechanical verifier checks the live Drupal site against the packet for missing routes, dropped collection items, broken embeds, unresolved footer/legal links, placeholder content, starter routes, composition model drift, fake Canvas component models, editor add-a-row failures, and stale evidence. The blind adversarial reviewer sees only the original brief, the target, and source-of-truth materials before public review, then decides whether the produced site is actually good enough.

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

The canonical output list is in [gates.json](gates.json) and [docs/output-inventory.md](docs/output-inventory.md). From the target Drupal project workspace, the agent should run `node ../agent-ready-drupal-build-kit/bin/verify-packet.mjs --packet review-packet` before handoff.

Early runs still create blocked stubs for gate records that are not earned yet. Missing gate files are worse than blocked ones, because missing files hide what remains.
