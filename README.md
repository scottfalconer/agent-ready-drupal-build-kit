# Agent-Ready Build Kit for Drupal CMS

**Build a real Drupal CMS site with your AI coding agent.**

Give your agent a source URL. This kit gives the agent the Drupal-specific instructions it needs to create a complete local Drupal CMS rebuild: real public content, source-shaped content structures, source-like visual design, public routes and functionality, editorial workflows, and a review packet that explains the work.

This is not a screenshot, static export, or CMS-shaped demo. It is a real Drupal CMS project running locally, built to look, function, and edit like a site another developer could stand behind.

## Quick Start

You need:

- [Docker](https://www.docker.com/) running;
- [DDEV](https://ddev.com/) installed;
- [Node.js](https://nodejs.org/) 20 or newer for the packet verifier;
- a local coding agent with filesystem and shell access, such as Claude Code, Codex, or Cursor;
- a public source URL: the site you want rebuilt.

A normal web chat is not enough, because the agent needs to create files and run local commands.

Open your coding agent in the folder where the work should live — an empty folder is fine; the kit and the Drupal project will sit side by side inside it. Replace `[SOURCE_URL]` with the site you want to rebuild, then paste this:

```text
Use the Agent-Ready Drupal Build Kit to rebuild the source site as a complete local Drupal CMS project.

Source site: [SOURCE_URL]

If the folder agent-ready-drupal-build-kit is not already present here, clone it:

git clone https://github.com/scottfalconer/agent-ready-drupal-build-kit.git

Then read agent-ready-drupal-build-kit/USAGE.md and follow its canonical prompt exactly, using the source site above.
Do not hand back a partial or representative build as the result.
```

The agent does the rest: it clones the kit, checks your tools, builds the site locally with DDEV and `drupal/cms`, and hands back a working site plus a `review-packet/` explaining what it built and why. Expect an iterative build over multiple agent passes, not one quick chat response.

The full canonical prompt lives in [USAGE.md](USAGE.md). Want the guided walkthrough? Start with [START.md](START.md).

If your agent supports Agent Skills, see [docs/recommended-agent-skills.md](docs/recommended-agent-skills.md). Skills are optional accelerators; this kit remains the operating contract.

## Who This Is For

This kit is for developers, designers, agencies, and site builders who want to try Drupal CMS without becoming Drupal-fluent first.

You bring a site to study and the prerequisites above. The kit gives your agent the Drupal operating model: how to choose Drupal-native structures, how to record important decisions, how to keep evidence attached, and how to leave behind a reviewable handoff packet.

Already fluent in Drupal? Use this as a repeatable agent workflow and review harness.

## What The Agent Produces

- A local Drupal CMS site you can open in your browser.
- Real public content and media needed for the rebuild, modeled as Drupal content and Media entities.
- Source-like visual design: palette, typography, spacing, layout, components, and responsive behavior.
- Source-like public functionality: routes, navigation, listings, detail pages, search, forms, embeds, and integrations where reachable.
- Drupal-native content structure: content types, fields, media, menus, Views, taxonomy, aliases, and editor forms where appropriate.
- Pages editors can actually maintain: each flexible page declares which Drupal tool owns its composition (Canvas/Experience Builder, Layout Builder, Views, structured content, or a documented exception), proven with a non-admin editor account.
- Version-controlled config as the source of truth, plus evidence another developer can inspect: route-by-route comparisons, rendered SEO output, browser evidence, and an inventory of any custom code or hardcoded behavior.
- Independent verification and a blind adversarial review that try to break the build's completion claims before handoff. This catches "the checks pass, but this is not the requested site" failures.
- A `review-packet/` explaining architecture decisions, remaining gaps, human-only open decisions, and verification evidence — machine-checked: `bin/verify-packet.mjs` fails the packet when required evidence is missing, and a complete rebuild claim is allowed only when the verifier output records it.

Partial or representative builds are not useful deliverables. If reachable public content, media, routes, visual patterns, behavior, or editor forms are missing, the agent keeps working or records the specific blocker.

The precise file-by-file packet and gate vocabulary are listed in [docs/output-inventory.md](docs/output-inventory.md).

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
- `templates/`: packet templates for every required review artifact, from source audit to blind adversarial review.
- `docs/recommended-agent-skills.md`: optional companion skill recommendations and install guidance.
- `docs/positioning.md`: who this is for, why Drupal CMS, why the kit, and when not to use it.
- `docs/output-inventory.md`: the canonical packet and gate vocabulary.
- `docs/`: reference material and rationale.

## Rights

Use this kit only with sites you are allowed to inspect and rebuild. The agent assumes the source URL you provide is authorized for a public-facing local rebuild; it does not adjudicate rights for you.

## License

This package is shared under the MIT License. See [LICENSE.md](LICENSE.md).
