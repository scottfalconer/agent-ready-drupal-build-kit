# Recommended Agent Skills

This kit is self-contained. Additional Agent Skills are optional accelerators, not requirements. Root `AGENTS.md` remains the project entrypoint, and the installed build kit's `references/build-contract.md` remains the detailed operating contract for the rebuild.

Install a small set that fits the run. More skills are not automatically better, and broad packs that rewrite project workflow can conflict with this kit.

The commands below assume the coding agent is already inside DDEV. From the host, prefix each `npx` command with `ddev exec`.

Record every installed skill repo, selected skill, version or commit SHA, and any conflict in `review-packet/operator-run.md`.

## Default Recommendation

Use the Drupal Canvas skills for most serious runs, especially when the source needs composed pages, Canvas pages, or Canvas Code Components:

```bash
npx skills add drupal-canvas/skills
```

Why this fits:

- Canvas component definition, metadata, naming, composability, slots, utilities, styling, data fetching, page definition, content templates, regions, navigation components, and Workbench/push workflows.
- Reinforces this kit's node-vs-Canvas rule: nodes model reusable information; Canvas composes experiences.

Source: <https://github.com/drupal-canvas/skills>

## Strong Drupal Companions

Use these when the run needs deeper Drupal implementation support.

### Grasmash Drupal Claude Skills

```bash
npx skills add grasmash/drupal-claude-skills
```

Use skills-only mode. Do not install its agents, settings, or workflow guide by default: root `AGENTS.md` remains the project entrypoint, and the installed `references/build-contract.md` remains the build-kit contract.

Most relevant skills:

- `drupal-ddev` for DDEV setup, Drush, database operations, and local troubleshooting.
- `drupal-config-mgmt` and `drupal-config-reconcile` for safer config import/export and drift handling.
- `drupal-testing` for real Drupal test discipline.
- `drupal-search-api` when source-like search/discovery is in scope.
- `drupal-canvas-sdc` when the rebuild uses Twig SDC alongside or instead of Canvas Code Components.
- `drupal-contrib-mgmt` when maintained contrib modules are part of the build.

Source: <https://github.com/grasmash/drupal-claude-skills>

### DrupalTools Skills

```bash
npx skills add https://github.com/drupaltools/skills
```

Use for stronger Drupal architecture and maintainer-style support, not as the default newcomer path.

Most relevant areas:

- content architecture and editorial modeling;
- Drupal best-practices and coding-standards review;
- frontend/theme work, SDC, Twig, responsive images, and accessibility-sensitive theming;
- site audit, migration planning, contrib lookup/search, and contribution-readiness checks.

Source: <https://github.com/drupaltools/skills>

### Drupal Intent Testing

```bash
npx skills add scottfalconer/drupal-intent-testing
```

Use when the run needs browser-backed proof that the local Drupal site works like the intended public/editor experience. This is a strong fit for this kit's review loop because it captures route behavior, editor workflows, screenshots, accessibility-tree snapshots, console errors, and exploratory QA evidence.

Requires `agent-browser` and a local/dev Drupal target.

Source: <https://github.com/scottfalconer/drupal-intent-testing>

## Upstream And Contrib Skills

Use these when a rebuild exposes Drupal core/contrib bugs, missing recipes, or upstream documentation gaps.

### Drupal Issue Queue

```bash
npx skills add scottfalconer/drupal-issue-queue
```

Use for read-only Drupal.org issue search and issue summarization before filing or duplicating upstream work.

Source: <https://github.com/scottfalconer/drupal-issue-queue>

### Drupal Contribute Fix

```bash
npx skills add scottfalconer/drupal-contribute-fix
```

Use when the agent is about to patch Drupal core or contrib locally. It searches upstream first, avoids auto-posting, and produces human-reviewed contribution artifacts instead of noisy issue-queue churn.

Source: <https://github.com/scottfalconer/drupal-contribute-fix>

## Hosting And Operations Skills

Use only when the target environment makes them relevant.

### Acquia Skills

```bash
npx skills add acquia/acquia-skills
```

Use for Acquia Cloud, Acquia CLI, Pipelines CLI, remote Drush/log access, dependency updates, and Acquia deployment playbooks. Do not install this for a plain local Drupal CMS rebuild with no Acquia target.

Source: <https://github.com/acquia/acquia-skills>

## Do Not Default-Install

Do not default-install:

- skill packs that rewrite `AGENTS.md`, `CLAUDE.md`, or completion criteria;
- broad orchestration frameworks that create their own project lifecycle;
- skills that assume a production deployment target not provided by the human;
- private/local-only skills that do not have a public install path;
- broad evidence, audit, governance, or second-review packs unless the human explicitly asks for them;
- stale repos when a maintained replacement exists.

If any skill conflicts with the installed build contract, current Drupal CMS behavior, or live target evidence, follow this kit and record the mismatch as a kit or upstream-skill issue.
