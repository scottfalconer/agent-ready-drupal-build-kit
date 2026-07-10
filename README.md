# Agent-Ready Build Kit for Drupal CMS

**Build a real Drupal CMS site with your AI coding agent.**

Give your agent a source URL. This kit gives the agent the Drupal-specific instructions it needs to create a complete local Drupal CMS rebuild: real public content, source-shaped content structures, source-like visual design, public routes and functionality, editorial workflows, and a review packet that explains the work.

This is not a screenshot, static export, or CMS-shaped demo. It is a real Drupal CMS project running locally, built to look, function, and edit like a site another developer could stand behind.

## Quick Start

The fastest path uses the official Drupal [One Line Installer](https://www.drupal.org/project/one_line_installer) to create the one Drupal project you will rebuild. Run it from the folder that should contain your new site:

```bash
bash <(curl -fsSL https://project.pages.drupalcode.org/one_line_installer/drupalaibp)
```

The current installer supports macOS and Linux.

Choose **Drupal CMS** and your preferred coding agent when prompted. The installer creates the DDEV project, installs Drupal CMS and the selected agent in the container, and leaves your shell in the new project directory. That project is the rebuild target; do not create a second Drupal site beside or inside it.

From that new Drupal project, install this kit for the supported agent targets and start the agent you selected:

```bash
ddev exec npx --yes skills add https://github.com/scottfalconer/agent-ready-drupal-build-kit --skill agent-ready-drupal-build-kit -a codex -a claude-code -a opencode -y --copy
ddev codex
```

`ddev codex` is the Codex example. Use `ddev claude` or `ddev opencode` when that is the agent you selected.

Then replace `[SOURCE_URL]` and give the selected agent this prompt:

```text
Use the installed agent-ready-drupal-build-kit skill to rebuild the source site in this existing Drupal CMS project.

Source site: [SOURCE_URL]

Do not create another Drupal project. Preserve all existing managed sections in AGENTS.md when adding the build-kit contract.
Initialize the kit in place, follow the skill and its canonical run instructions, verify the real DDEV site, and produce the review packet.
As soon as the first meaningful source-shaped route is working, share its DDEV URL with me, then continue the full rebuild and verification loop.
Do not hand back a partial or representative build as the result.
```

The agent does the rest in the project the installer created and hands back a working site plus a `review-packet/` explaining what it built and why. Expect an iterative build over multiple agent passes, not one quick chat response.

Already have a clean DDEV Drupal CMS project with a supported coding agent? Skip the One Line Installer, install the skill there, and start that agent. A normal web chat is not enough because the agent needs filesystem, shell, Drupal, and browser access.

The same canonical prompt lives in [USAGE.md](USAGE.md). Want the guided walkthrough? Start with [START.md](START.md).

For optional companion Agent Skills, see [docs/recommended-agent-skills.md](docs/recommended-agent-skills.md). Companion skills are accelerators; the installed build-kit skill remains the operating contract.

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
- A `review-packet/` explaining architecture decisions, remaining gaps, human-only open decisions, and verification evidence. The default verifier fetches the real DDEV site's primary and target-required routes, rejects non-success responses even when the packet reports the same failure, inspects rendered canonical, meta-description, and `og:image` output, and independently requires real Git-tracked YAML in the current config-sync directory. Packet-only data and injected test runtimes cannot authorize a completed rebuild.

Partial or representative builds are not useful deliverables. If reachable public content, media, routes, visual patterns, behavior, or editor forms are missing, the agent keeps working or records the specific blocker.

The precise file-by-file packet and gate vocabulary are listed in [docs/output-inventory.md](docs/output-inventory.md).

## Why This Is Different

Most AI site builds optimize for something that looks finished. This kit optimizes for a stable, trusted, maintainable local Drupal rebuild that looks complete, functions completely, and is suitable for launch planning.

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

This is a complete-local-rebuild bar, not production approval. Deployment, production hardening, credentials, legal/privacy review, rollback, and launch acceptance remain separate human-owned gates.

For the full case, see [docs/positioning.md](docs/positioning.md): who this is for, why Drupal CMS, why the kit, and when not to use it.

## What Is In The Kit

- `START.md`: expanded quickstart and operator flow for humans who want more detail.
- `USAGE.md`: the copy-ready canonical agent prompt and expected evidence shape.
- `skills/agent-ready-drupal-build-kit/`: the canonical installable Agent Skill, including its in-place initializer, references, templates, gate vocabulary, and verifier.
- `AGENTS.md.template`: the canonical detailed build contract, packaged in the installed skill as `references/build-contract.md`. The initializer adds only a concise marker-managed project block to `AGENTS.md` that points agents to the detailed contract, preserving sections managed by Drupal CMS, AI Best Practices, and the One Line Installer.
- `gates.json`: the stable machine-readable gate vocabulary.
- `bin/verify.mjs`: the default target-local verifier; it checks the detected DDEV site, rendered primary and target-required routes, packet readiness, target origin, Drupal site UUID, front-page setting, config-sync directory, clean config status, and Git-tracked config YAML before authorizing local completion.
- `bin/verify-packet.mjs`: the packet-lint layer used by the target-local verification flow. On its own it checks packet structure; it does not inspect or certify the live Drupal site.
- `templates/`: packet templates for every required review artifact, from source audit to blind adversarial review.
- `docs/recommended-agent-skills.md`: optional companion skill recommendations and install guidance.
- `docs/positioning.md`: who this is for, why Drupal CMS, why the kit, and when not to use it.
- `docs/output-inventory.md`: the canonical packet and gate vocabulary.
- `docs/`: reference material and rationale.

## Rights

Use this kit only with sites you are allowed to inspect and rebuild. The agent assumes the source URL you provide is authorized for a public-facing local rebuild; it does not adjudicate rights for you.

## License

This package is shared under the MIT License. See [LICENSE](LICENSE).

## Problems And Contributions

Found a problem or have a focused improvement? [Open an issue](https://github.com/scottfalconer/agent-ready-drupal-build-kit/issues) or read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request. Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).
