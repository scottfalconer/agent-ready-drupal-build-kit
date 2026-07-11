# Agent-Ready Build Kit for Drupal CMS

**Give your coding agent a source URL. Get back a real, editable Drupal CMS site.**

## Copy This Prompt

Open Codex, Claude Code, or OpenCode in an empty folder. Change only the `Source site` line, then paste the whole prompt:

```text
Rebuild the source site below as a complete local Drupal CMS site.

Source site: [SOURCE_URL]
Build kit: https://github.com/scottfalconer/agent-ready-drupal-build-kit

Use the build kit as your instructions and handle all setup yourself. If needed, use its recommended One Line Installer path. Work in exactly one Drupal project, install and initialize the kit there, then continue until the real Drupal site passes the kit's verification.

As soon as the first meaningful source-shaped route works, share its DDEV URL with me, then continue. Do not hand back a partial or representative build as the result.
```

Prerequisite: macOS or Linux. On macOS, start Docker Desktop or OrbStack. After that, the prompt is the whole human workflow: the agent handles Drupal setup, skill installation, the rebuild, live verification, and the review packet.

Already have a clean DDEV Drupal CMS project? Open the coding agent in its root instead of an empty folder; the same prompt tells the agent to use it in place. The agent should stop only for a genuinely human decision or something it cannot access, such as private source content or external credentials.

The result is not a screenshot, static export, or CMS-shaped demo. It is a real Drupal CMS project running locally, built to look, function, and edit like a site another developer could stand behind.

## What The Agent Does

The kit gives the agent the Drupal-specific instructions it needs to create a complete local Drupal CMS rebuild: real public content, source-shaped content structures, source-like visual design, public routes and functionality, editorial workflows, and a review packet that explains the work.

For a new project, the agent uses the official Drupal [One Line Installer](https://www.drupal.org/project/one_line_installer) to create the one Drupal project it will rebuild. The current installer supports macOS and Linux. It chooses **Drupal CMS** and the current coding agent, then treats the resulting DDEV project as the rebuild target rather than creating another site beside or inside it.

A normal web chat is not enough because the agent needs filesystem, shell, Drupal, and browser access. Expect an iterative build over multiple agent passes, not one quick chat response.

## Manual Setup (Optional)

If you prefer to perform setup yourself, run the One Line Installer from the folder that should contain the new site:

```bash
bash <(curl -fsSL https://project.pages.drupalcode.org/one_line_installer/drupalaibp)
```

Choose **Drupal CMS** and your preferred coding agent when prompted. The installer creates the DDEV project, installs Drupal CMS and the selected agent in the container, and leaves your shell in the new project directory. That project is the rebuild target; do not create a second Drupal site beside or inside it.

From that new Drupal project, install this kit for the supported agent targets and start the agent you selected:

```bash
ddev exec npx --yes skills add https://github.com/scottfalconer/agent-ready-drupal-build-kit --skill agent-ready-drupal-build-kit -a codex -a claude-code -a opencode -y --copy
ddev codex
```

`ddev codex` is the Codex example. Use `ddev claude` or `ddev opencode` when that is the agent you selected.

Then paste the prompt at the top of this README. The agent does the rest in the project the installer created and hands back a working site plus a `review-packet/` explaining what it built and why.

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
- A create-once, integrity-checked historical baseline under kit tooling after the first successful full verification, including the exact tracked config, portable runtime code, effective Drupal runtime facts, declared editorial entities/revisions, managed public-file bytes, stable route semantics, bounded critical same-origin rendered-asset bytes, and packet evidence manifest inspected in that run. Machine-local bindings stay outside intrinsic site identity. The initial rebuild remains done; later changes are reported separately as unclassified, evidence-recorded, or fully verified.

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

## After The First Verification

Keep the installed kit in the Drupal project. Future agents can use it as a stewardship layer instead of starting the source rebuild again.

- A **repair** corrects something the initial rebuild should already have delivered.
- An **extension** adds genuinely new scope and is judged against the new request, with regression checks for affected existing surfaces.
- Change evidence is impact-targeted. A localized content edit should not automatically trigger a full source crawl and blind review; a global theme or page-region change should trigger broader route and site-chrome checks. Detected component impact can widen the required checks, and an agent must not narrow that detected impact.
- Targeted completion records authored semantic evidence against an exact inspected state. It does not independently evaluate that evidence and is not a new completion certificate.
- A coherent set of evidence-recorded changes can optionally receive a fresh full checkpoint by re-evaluating the current packet/live state against the original full verifier gates. The verifier validates existing evidence rather than recreating reviews; affected evidence must be refreshed first. Checkpoints never rewrite the historical initial baseline.

If the current Drupal state differs without a classified change whose evidence is bound to that state, the kit reports it as unclassified. It does not retroactively revoke the initial rebuild pass. Lifecycle `status` reports the last inspected cached state; the live verifier and `complete` command perform fresh inspections. See [docs/site-lifecycle.md](docs/site-lifecycle.md) for the lifecycle and commands.

For the full case, see [docs/positioning.md](docs/positioning.md): who this is for, why Drupal CMS, why the kit, and when not to use it.

## What Is In The Kit

- `START.md`: expanded quickstart and operator flow for humans who want more detail.
- `USAGE.md`: the copy-ready canonical agent prompt and expected evidence shape.
- `skills/agent-ready-drupal-build-kit/`: the canonical installable Agent Skill, including its in-place initializer, references, templates, gate vocabulary, and verifier.
- `AGENTS.md.template`: the canonical detailed build contract, packaged in the installed skill as `references/build-contract.md`. The initializer adds only a concise marker-managed project block to `AGENTS.md` that points agents to the detailed contract, preserving sections managed by Drupal CMS, AI Best Practices, and the One Line Installer.
- `gates.json`: the stable machine-readable gate vocabulary.
- `bin/lifecycle.mjs`: the status, repair/extension, completed-change, and checkpoint lifecycle interface used after the initial rebuild passes.
- `bin/verify.mjs`: the default target-local verifier; it checks the detected DDEV site, rendered primary and target-required routes, packet readiness, target origin, Drupal site UUID, front-page setting, config-sync directory, clean config status, and Git-tracked config YAML before authorizing local completion.
- `bin/verify-packet.mjs`: the packet-lint layer used by the target-local verification flow. On its own it checks packet structure; it does not inspect or certify the live Drupal site.
- `templates/`: packet templates for every required review artifact, from source audit to blind adversarial review.
- `docs/recommended-agent-skills.md`: optional companion skill recommendations and install guidance.
- `docs/positioning.md`: who this is for, why Drupal CMS, why the kit, and when not to use it.
- `docs/output-inventory.md`: the canonical packet and gate vocabulary.
- `docs/site-lifecycle.md`: the post-baseline repair, extension, targeted-verification, and checkpoint workflow.
- `docs/`: reference material and rationale.

## Rights

Use this kit only with sites you are allowed to inspect and rebuild. The agent assumes the source URL you provide is authorized for a public-facing local rebuild; it does not adjudicate rights for you.

## License

This package is shared under the MIT License. See [LICENSE](LICENSE).

## Problems And Contributions

Found a problem or have a focused improvement? [Open an issue](https://github.com/scottfalconer/agent-ready-drupal-build-kit/issues) or read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request. Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).
