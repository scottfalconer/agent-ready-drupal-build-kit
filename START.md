# Start Here

**Turn an existing site into a real Drupal site, and let your AI agent do the Drupal.**

This page walks you through it step by step. You bring a site you want to rebuild and a coding agent. The kit brings the Drupal expertise, so you do not have to learn it first.

By the end of a run you will have a working Drupal site on your machine that looks, functions, and edits like the source site's public experience, plus a written record of every decision the agent made, a short list of the calls that still need a human, and evidence a senior Drupal developer could put their name on. You do not even need to know the difference between "Drupal" and "Drupal CMS"; the kit handles that.

A partial or representative site is not a successful run. If the site is missing reachable public content, media, source-like design, public behavior, or editor forms, the agent keeps working or records the real blocker.

Want the fast path? The lightweight README prompt gets the agent started. Want the strict copy-paste run instructions? Use [USAGE.md](USAGE.md). Want to understand what the agent is actually doing? Read the four moves and the review bar further down. For the full case - who it is for, why Drupal CMS, and when not to use it - see [docs/positioning.md](docs/positioning.md).

## Prerequisites

You will need a few things on your machine first:

- Docker running;
- DDEV installed;
- a local coding agent with filesystem and shell access, such as Codex, Cursor, Windsurf, Cline, RooCode, or a comparable local agentic IDE/tool;
- a public source URL.

A normal web chat alone is not enough, because the agent must create files and run local commands.

Run this preflight first, or ask the agent to run it:

```bash
docker info >/dev/null
ddev version
```

If either command fails, fix the local environment before asking for a build.

## One Prompt

Copy the lightweight prompt from [README.md](README.md), or the full strict prompt from [USAGE.md](USAGE.md). Replace the bracketed source URL and send it to the agent.

You will not hand-edit anything yourself. The agent does the setup and review loop for you:

1. it keeps the kit as reference material and creates a clean Drupal CMS project workspace beside it;
2. it copies `AGENTS.md.template` into that workspace as `AGENTS.md`, which is what carries Drupal's best practices into the build;
3. it fills in the placeholders from your prompt;
4. it builds the Drupal CMS site with DDEV and `drupal/cms`;
5. it verifies the result, fixes the highest-impact gaps, and repeats until the complete local rebuild bar is met or a real blocker is recorded;
6. it runs an independent verifier pass that tries to falsify the completion claims against the live site;
7. it creates `review-packet/` with the evidence.

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
2. **Assemble:** stand up DDEV plus `drupal/cms`, decide the recipe start point, then build with Drupal-native content types, fields, taxonomy, media, menus, Views, aliases, workflows, theme/config work, and source-like public behavior.
3. **Capture intent:** record why each load-bearing decision was made, so a later agent or human is not guessing.
4. **Name gaps:** list what still needs a human: private access, provider credentials, legal/privacy, integrations, accessibility, performance, security, SEO, production target, launch, and maintainer review.

Before handoff, the agent also needs a fresh verifier pass. The verifier acts as a skeptic: it checks the live Drupal site against the packet for missing routes, dropped collection items, broken embeds, unresolved footer/legal links, placeholder content, starter routes, editor add-a-row failures, and stale evidence.

## The Review Bar

This is what separates a complete Drupal rebuild from a foundation or lookalike. The build is measured against the questions a senior Drupal developer would ask before signing off:

- Is the build on Drupal CMS best practices using Drupal-native primitives?
- Is the architecture sound for the source site's real shape?
- Does it include the public content and media needed to review the site as a rebuild?
- Does it match the source site's visual language and public behavior?
- Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?
- Are the load-bearing decisions captured and usable by later agents?
- Are the remaining business, legal, integration, production, and launch gaps named?
- Did an independent verifier try to falsify the completion claims against the live site?
- Would a Drupal maintainer put their name on this as a complete local starting point?

If any answer is "no," the result can still be useful. It just is not yet something to stand behind.

## Required Packet

The canonical output list is in [docs/output-inventory.md](docs/output-inventory.md).

Early runs still create blocked stubs for gate records that are not earned yet. Missing gate files are worse than blocked ones, because missing files hide what remains.
