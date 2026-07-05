# Agent-Ready Build Kit for Drupal CMS

**Build a real Drupal CMS site with your AI coding agent.**

Give your agent a source URL. This kit gives the agent the Drupal-specific instructions it needs to create a complete local Drupal CMS rebuild: real public content, source-shaped content structures, source-like visual design, public routes and functionality, editorial workflows, and a review packet that explains the work.

This is not a screenshot, static export, or CMS-shaped demo. It is a real Drupal CMS project running locally, built to look, function, and edit like a site another developer could stand behind.

Use one prompt. From the parent folder where the kit and Drupal project should sit, clone this repository if it is not already present, then give your local coding agent the canonical prompt in [USAGE.md](USAGE.md).

```bash
git clone https://github.com/scottfalconer/agent-ready-drupal-build-kit.git
```

## Who This Is For

This kit is for developers, designers, agencies, and site builders who want to try Drupal CMS without becoming Drupal-fluent first.

You bring:

- a site to study;
- a local AI coding agent;
- Docker, DDEV, and Node.js 20 or newer.

The kit gives your agent the Drupal operating model: how to choose Drupal-native structures, how to record important decisions, how to keep evidence attached, and how to leave behind a reviewable handoff packet.

Already fluent in Drupal? Use this as a repeatable agent workflow and review harness.

## Quick Start

You need:

- Docker running;
- DDEV installed;
- Node.js 20 or newer for the packet verifier;
- a local coding agent with filesystem and shell access;
- a public source URL.

A normal web chat is not enough, because the agent needs to create files and run local commands.

Need the copy-paste prompt? See [USAGE.md](USAGE.md). Want the guided version? Start with [START.md](START.md).

If your agent supports Agent Skills, see [docs/recommended-agent-skills.md](docs/recommended-agent-skills.md). Skills are optional accelerators; this kit remains the operating contract.

## What The Agent Produces

- A local Drupal CMS site you can open in your browser.
- Real public content and media needed for the rebuild, modeled as Drupal content and Media entities.
- Source-like visual design: palette, typography, spacing, layout, components, and responsive behavior.
- Source-like public functionality: routes, navigation, listings, detail pages, search, forms, embeds, and integrations where reachable.
- Drupal-native content structure: content types, fields, media, menus, Views, taxonomy, aliases, and editor forms where appropriate.
- Composition ownership for flexible pages: Canvas/Experience Builder, structured landing content, Layout Builder, Views, entity displays, or documented exceptions, with section-level editor proof.
- Browser-first route discovery, Starter route cleanup, front-page/alias decisions, and Drupal readback that another developer can inspect.
- Version-controlled config as the source of truth, rendered SEO/social evidence, non-admin editor-role verification, and an off-road inventory for any custom code or hardcoded behavior.
- Independent mechanical verification from a fresh verifier context that tries to break completion claims against the live site before handoff: route item counts, collection ownership, embeds, target-owned links, route drift, Canvas placeholders, composition model fidelity, Canvas component fidelity, brand assets, editor add-a-row tasks, labels, field output, and off-road cleanup.
- Blind adversarial product review from a reviewer that did not build the site and sees only the original brief, target, and source-of-truth materials before public review. This catches "the checks pass, but this is not the requested site" failures.
- A machine-readable `gates.json` vocabulary and `bin/verify-packet.mjs` packet verifier that fail when required packet files are missing, JSON is invalid, verifier independence is degraded without consequences, blind-review completion evidence is missing or not good enough, recipe discovery/default-owner evidence is missing, or accepted durable intent lacks a valid hash.
- A `review-packet/` explaining architecture decisions, remaining gaps, human-only open decisions, and verification evidence.

The verifier's zero exit code means the packet is structurally valid. A complete rebuild claim is allowed only when the generated `packet-verification.json` also records `completeLocalRebuildClaimAllowed: true`.

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
- `gates.json`: the stable machine-readable gate vocabulary.
- `bin/verify-packet.mjs`: a self-contained packet verifier the agent and reviewer can rerun.
- `templates/`: packet templates for source audit, pattern map, recipe start point, durable intent, route matrix, browser evidence, independent verification, blind adversarial review, Drupal readback, field-output matrix, scoped gaps, open decisions, launch gates, and maintainer review.
- `docs/recommended-agent-skills.md`: optional companion skill recommendations and install guidance.
- `docs/positioning.md`: who this is for, why Drupal CMS, why the kit, and when not to use it.
- `docs/output-inventory.md`: the canonical packet and gate vocabulary.
- `docs/`: reference material and rationale.

## Requirements

Local builds run on DDEV and `drupal/cms` by default. Static HTML, screenshots, local file previews, and non-Drupal frontends do not count as Drupal CMS builds.

## Rights

Use this kit only with sites you are allowed to inspect and rebuild. The agent assumes the source URL you provide is authorized for a public-facing local rebuild; it does not adjudicate rights for you.

## License

This package is shared under the MIT License. See [LICENSE.md](LICENSE.md).
