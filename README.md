# Agent-Ready Build Kit for Drupal CMS

**Build a real Drupal CMS site with your AI coding agent.**

Give your agent a source URL and a target site name. This kit gives the agent the Drupal-specific instructions it needs to create a local Drupal CMS build, model the site with Drupal-native content structures, and produce a review packet that explains what it built, what it assumed, and what still needs a human call.

This is not a screenshot, static export, or CMS-shaped demo. It is a real Drupal CMS project running locally, with evidence another developer can inspect.

## Who This Is For

This kit is for developers, designers, agencies, and site builders who want to try Drupal CMS without becoming Drupal-fluent first.

You bring:

- a site to study;
- a local AI coding agent;
- Docker and DDEV;
- a permission status for the source site.

The kit gives your agent the Drupal operating model: how to choose Drupal-native structures, how to record important decisions, how to avoid unsafe claims, and how to leave behind a reviewable handoff packet.

Already fluent in Drupal? Use this as a repeatable agent workflow and review harness.

## Quick Start

You need:

- Docker running;
- DDEV installed;
- a local coding agent with filesystem and shell access;
- a public source URL;
- owner permission status: `APPROVED`, `PENDING`, `DENIED`, or `UNKNOWN`.

A normal web chat is not enough, because the agent needs to create files and run local commands.

From this kit folder, send your agent this:

```text
Use this Agent-Ready Build Kit to rebuild the source site as a local Drupal CMS project.

Source site: [SOURCE_URL]
Target site name: [TARGET_SITE_NAME]
Owner permission status: [APPROVED | PENDING | DENIED | UNKNOWN]

Read USAGE.md for the canonical run instructions.
Use AGENTS.md.template as the operating guide for the target workspace.
Create the Drupal CMS project as a sibling folder.
Create the review packet at review-packet/.
Do not copy source content or assets unless owner permission is APPROVED.
Write UNKNOWN instead of guessing.
```

Need the full strict prompt? See [USAGE.md](USAGE.md). Want the guided version? Start with [START.md](START.md).

## What The Agent Produces

- A local Drupal CMS site you can open in your browser.
- Drupal-native content structure: content types, fields, media, menus, Views, taxonomy, aliases, and editor forms where appropriate.
- A `review-packet/` explaining decisions, assumptions, gaps, and verification evidence.
- A clear list of what still requires human approval before production use.

The precise file-by-file packet is listed in [docs/output-inventory.md](docs/output-inventory.md).

## Why This Is Different

Most AI site builds optimize for something that looks finished. This kit optimizes for something a Drupal developer can inspect.

Every run asks:

- Did the agent build with Drupal CMS instead of a static lookalike?
- Did it use Drupal-native content structures?
- Did it explain the important decisions?
- Did it name the gaps instead of hiding them?
- Did it leave evidence another developer can review?

The kit produces a governed head start, not a launch decision. Do not claim launch readiness, production target parity, owner approval, maintainer signoff, speed advantage, or that the rebuild is better than the original unless the required evidence exists.

For the full case, see [docs/positioning.md](docs/positioning.md): who this is for, why Drupal CMS, why the kit, and when not to use it.

## What Is In The Kit

- `START.md`: expanded quickstart and operator flow for humans who want more detail.
- `USAGE.md`: the full canonical agent prompt.
- `AGENTS.md.template`: the self-contained file an agent copies into the target Drupal CMS workspace as `AGENTS.md`. This is what carries Drupal's best practices into the build.
- `templates/`: packet templates for source audit, pattern map, recipe start point, durable intent, scoped gaps, launch gates, and maintainer review.
- `docs/positioning.md`: who this is for, why Drupal CMS, why the kit, and when not to use it.
- `docs/output-inventory.md`: the canonical packet and gate vocabulary.
- `docs/`: reference material and rationale.
- `examples/fictional-community-arts-center/`: a filled fictional packet showing the expected shape without copying third-party content.

## Requirements

Local builds run on DDEV and `drupal/cms` by default. Static HTML, screenshots, local file previews, and non-Drupal frontends do not count as Drupal CMS builds.

## License

This package is shared under the MIT License. See [LICENSE.md](LICENSE.md).
