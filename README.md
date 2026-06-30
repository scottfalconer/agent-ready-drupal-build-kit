# Agent-Ready Build Kit for Drupal CMS

**Build a real Drupal CMS site with your AI coding agent.**

Give your agent a source URL. This kit gives the agent the Drupal-specific instructions it needs to create a complete local Drupal CMS rebuild: real public content, source-shaped content structures, source-like visual design, public routes and functionality, editorial workflows, and a review packet that explains the work.

This is not a screenshot, static export, or CMS-shaped demo. It is a real Drupal CMS project running locally, built to look, function, and edit like a site another developer could stand behind.

Send your local AI coding agent this from the parent folder where you want the Drupal project created:

```text
Use the Agent-Ready Drupal Build Kit to rebuild the source site as a local Drupal CMS project.

Source site: [SOURCE_URL]

Build the complete public-facing Drupal CMS rebuild: content, media, visual design, routes, functionality, and editor experience.
Do not hand back a partial or representative build as the result. A partial or incomplete site is a failed run unless a real blocker outside the local agent's control is recorded.

Make the kit available locally as reference material beside the Drupal project:

git clone https://github.com/scottfalconer/agent-ready-drupal-build-kit.git

Run the preflight checks in agent-ready-drupal-build-kit/USAGE.md first. If Docker or DDEV is unavailable, stop and report the blocker.
Read agent-ready-drupal-build-kit/USAGE.md for the canonical run instructions.
Create a clean Drupal CMS project workspace alongside agent-ready-drupal-build-kit.
Copy agent-ready-drupal-build-kit/AGENTS.md.template into that target workspace as AGENTS.md.
Fill the AGENTS.md placeholders from this prompt and the local workspace path.
Work in review loops: build, verify, self-review against AGENTS.md, fix the highest-impact gaps, update the review packet, and repeat until the complete local rebuild bar is met or a real blocker is recorded.
Create the review packet at review-packet/.
Mark uncertain facts, missing evidence, and assumptions clearly in the review packet instead of inventing details.
```

## Who This Is For

This kit is for developers, designers, agencies, and site builders who want to try Drupal CMS without becoming Drupal-fluent first.

You bring:

- a site to study;
- a local AI coding agent;
- Docker and DDEV.

The kit gives your agent the Drupal operating model: how to choose Drupal-native structures, how to record important decisions, how to keep evidence attached, and how to leave behind a reviewable handoff packet.

Already fluent in Drupal? Use this as a repeatable agent workflow and review harness.

## Quick Start

You need:

- Docker running;
- DDEV installed;
- a local coding agent with filesystem and shell access;
- a public source URL.

A normal web chat is not enough, because the agent needs to create files and run local commands.

Need the full strict prompt? See [USAGE.md](USAGE.md). Want the guided version? Start with [START.md](START.md).

## What The Agent Produces

- A local Drupal CMS site you can open in your browser.
- Real public content and media needed for the rebuild, modeled as Drupal content and Media entities.
- Source-like visual design: palette, typography, spacing, layout, components, and responsive behavior.
- Source-like public functionality: routes, navigation, listings, detail pages, search, forms, embeds, and integrations where reachable.
- Drupal-native content structure: content types, fields, media, menus, Views, taxonomy, aliases, and editor forms where appropriate.
- A `review-packet/` explaining decisions, remaining gaps, and verification evidence.

Partial or representative builds are not useful deliverables. If reachable public content, media, routes, visual patterns, behavior, or editor forms are missing, the agent keeps working or records the specific blocker.

The precise file-by-file packet is listed in [docs/output-inventory.md](docs/output-inventory.md).

## Why This Is Different

Most AI site builds optimize for something that looks finished. This kit optimizes for a stable, trusted, production-ready Drupal site that looks complete, functions completely, and can be maintained in Drupal.

That is where Drupal matters: reusable structured content instead of one-off pages, editor workflows instead of hand-edited layouts, media management, roles and permissions, SEO, accessibility, integrations, and the governance evidence needed to know what is ready and what still needs a human decision.

Every run asks:

- Did the agent build with Drupal CMS instead of a static lookalike?
- Did it use Drupal-native content structures?
- Does it contain the public content and media needed for review?
- Does it match the source site's visual language and public behavior?
- Did it explain the important decisions?
- Did it name the gaps instead of hiding them?
- Did it leave evidence another developer can review?

The review packet shows what is built, what is still blocked, and what another developer should inspect next.

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

## Rights

Use this kit only with sites you are allowed to inspect and rebuild. The agent assumes the source URL you provide is authorized for a public-facing local rebuild; it does not adjudicate rights for you.

## License

This package is shared under the MIT License. See [LICENSE.md](LICENSE.md).
