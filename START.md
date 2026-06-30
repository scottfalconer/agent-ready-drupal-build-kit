# Start Here

**Turn an existing site into a real Drupal site, and let your AI agent do the Drupal.**

This page walks you through it step by step. You bring a site you want to rebuild and a coding agent. The kit brings the Drupal expertise, so you do not have to learn it first.

By the end of a run you will have a working Drupal site on your machine, a written record of every decision the agent made, a short list of the calls that still need a human, and evidence a senior Drupal developer could put their name on. You do not even need to know the difference between "Drupal" and "Drupal CMS"; the kit handles that.

Want the fast path? The lightweight README prompt gets the agent started. Want the strict copy-paste run instructions? Use [USAGE.md](USAGE.md). Want to understand what the agent is actually doing? Read the four moves and the review bar further down. For the full case - who it is for, why Drupal CMS, and when not to use it - see [docs/positioning.md](docs/positioning.md).

## Prerequisites

You will need a few things on your machine first:

- Docker running;
- DDEV installed;
- a local coding agent with filesystem and shell access, such as Codex, Cursor, Windsurf, Cline, RooCode, or a comparable local agentic IDE/tool;
- a public source URL;
- owner permission status, even if the status is `UNKNOWN`.

A normal web chat alone is not enough, because the agent must create files and run local commands.

Run this preflight first, or ask the agent to run it:

```bash
docker info >/dev/null
ddev version
```

If either command fails, fix the local environment before asking for a build.

## One Prompt

Copy the lightweight prompt from [README.md](README.md), or the full strict prompt from [USAGE.md](USAGE.md). Replace the bracketed values and send it to the agent.

You will not hand-edit anything yourself. The agent does the setup for you:

1. it creates a clean sibling workspace for the new site;
2. it copies `AGENTS.md.template` into that workspace as `AGENTS.md`, which is what carries Drupal's best practices into the build;
3. it fills in the placeholders from your prompt;
4. it builds the Drupal CMS site with DDEV and `drupal/cms`;
5. it creates `review-packet/` with the evidence.

## Workspace Topology

Here is the shape you will end up with:

```text
parent-folder/
  agent-ready-build-kit-2026-06-29/   # this kit, reference only
  site-slug-drupal/                   # DDEV Drupal CMS project, your new site
    AGENTS.md                         # copied from AGENTS.md.template
    review-packet/                    # evidence and handoff packet
```

The kit folder is not the Drupal site. The sibling `site-slug-drupal/` folder is the Drupal site.

## The Four Moves

Under the hood, the agent works in four moves. You do not have to drive these, but they are what keeps the result inspectable instead of a black box:

1. **Introspect:** read the source site: representative routes, the patterns it is made of, owner permission status, and anything it cannot be sure about (`UNKNOWN`).
2. **Assemble:** stand up DDEV plus `drupal/cms`, decide the recipe start point, then build with Drupal-native content types, fields, taxonomy, media, menus, Views, aliases, workflows, and theme/config work.
3. **Capture intent:** record why each load-bearing decision was made, so a later agent or human is not guessing.
4. **Name gaps:** list what still needs a human: owner approval, content, legal/privacy, integrations, accessibility, performance, security, SEO, production target, launch, and maintainer review.

## The Review Bar

This is what separates a foundation from a lookalike. The build is measured against the five questions a senior Drupal developer would ask before signing off:

- Is the build on Drupal CMS best practices using Drupal-native primitives?
- Is the architecture sound for the source site's real shape?
- Are the load-bearing decisions captured and usable by later agents?
- Are the remaining business, content, legal, integration, and launch gaps named?
- Would a Drupal maintainer put their name on this as a starting position?

If any answer is "no," the result can still be useful. It just is not yet a trusted starting point.

## Required Packet

The canonical output list is in [docs/output-inventory.md](docs/output-inventory.md).

Early runs still create blocked stubs for gate records that are not earned yet. Missing gate files are worse than blocked ones, because missing files hide what remains.

## What Not To Claim

Do not claim:

- launch readiness;
- production target parity;
- owner approval;
- maintainer signoff;
- speed advantage;
- that the rebuild is better than the original.

The kit produces a governed head start, not a launch decision.
