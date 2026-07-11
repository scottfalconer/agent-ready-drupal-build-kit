# Installed Baseline And Recipe Fit Decision

## Site

- Source URL:
- Target site name:
- Target workspace:
- Source-use boundary:
- Decision date:
- Decision owner:

## Installed Substrate And Assembly Decision

Choose one:

- [ ] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.
- [ ] Retain a site template selected before installation plus bounded source-fit Recipes and overlays.
- [ ] Retain another existing Drupal CMS substrate and extend it without replacing it.
- [ ] Use bounded custom overlays because maintained Recipes do not fit the audited source patterns.

Decision:

Rationale:

Installed substrate evidence (installed Recipe/template, Drupal CMS/core versions, public theme, front page, and starter content):

## Source Pattern Drivers

List the source patterns that affect the post-install assembly decision.

| Source pattern | Evidence | Drupal CMS implication | Confidence |
| --- | --- | --- | --- |
|  |  |  | UNKNOWN |

## Recipe Candidate Review

Do not install every recipe by default. Verify availability in the target project before relying on a recipe name.

Before creating a custom content type, View, workflow, or cross-cutting feature, check whether a maintained Drupal CMS recipe already owns that pattern. A matching maintained recipe is the default owner. If you reject or block it, record the evidence and rationale here before building a custom overlay.

From the DDEV Drupal project root, collect recipe evidence with:

```bash
ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'
ddev exec sed -n '1,220p' recipes/drupal_cms_media/recipe.yml
ddev composer show -a 'drupal/<candidate>'
```

Discovery does not end at the on-disk `recipes/` directory. If a named `drupal_cms_*` candidate is absent from `recipes/` and the installed package list, check whether `drupal/<candidate>` is composer-installable (`ddev composer show -a 'drupal/<candidate>'` or its Packagist page) before recording it `blocked`, and record the upstream availability with the decision. A maintained upstream recipe package is preferred over hand-rolled equivalent config: every `blocked` candidate whose upstream availability is `available` needs a matching `open-decisions.md` row recording the composer-require-versus-hand-rolled-overlay decision for the human owner.

Apply a recipe only after recording why it fits the pattern map:

```bash
ddev exec -d /var/www/html/web php core/scripts/drupal recipe ../recipes/drupal_cms_media -v
```

Inside a DDEV agent shell, use `cd web && php core/scripts/drupal recipe ../recipes/drupal_cms_media -v`. Replace the example with the verified Recipe path. Do not assume a separate `dr` executable exists. If the core runner or Recipe path is unavailable, record the candidate as blocked or not applicable.

Do not select or apply a different full site template here. Record the template only when it was already selected before site installation; normal post-audit assembly uses bounded Recipes and overlays on the installed substrate.

| Candidate recipe | Fit | Decision | Upstream availability | Evidence | Notes |
| --- | --- | --- | --- | --- | --- |
| `drupal_cms_admin_ui` | Editorial/admin experience | UNKNOWN |  |  |  |
| `drupal_cms_media` | Media handling | UNKNOWN |  |  |  |
| `drupal_cms_search` | Public search/discovery | UNKNOWN |  |  |  |
| `drupal_cms_forms` | Forms | UNKNOWN |  |  |  |
| `drupal_cms_seo_basic` / `drupal_cms_seo_tools` | SEO metadata/checklist | UNKNOWN |  |  |  |
| `drupal_cms_accessibility_tools` | Accessibility tooling | UNKNOWN |  |  |  |
| `drupal_cms_privacy_basic` | Privacy/legal baseline | UNKNOWN |  |  |  |
| `drupal_cms_authentication` | Authentication/login | UNKNOWN |  |  |  |
| `drupal_cms_google_analytics` | Analytics | UNKNOWN |  |  |  |
| `drupal_cms_ai` | AI features | UNKNOWN |  |  |  |
| `drupal_cms_events` | Event content type/listing candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |
| `drupal_cms_person` | Person/staff/speaker/artist profile candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |
| `drupal_cms_news` | News/article content type candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |
| `drupal_cms_blog` | Blog/post content type candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |
| `drupal_cms_page` | Basic/landing page content candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |
| `drupal_cms_project` | Project/work/case item candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |
| `drupal_cms_case_study` | Case study content type candidate | UNKNOWN |  |  | Verify exact name/path in target before use. |

Decision values: `apply`, `reject`, `blocked`, `not_applicable`, `UNKNOWN`.

Upstream availability values: `installed` (present in the target), `available` (composer-installable upstream but not installed), `not-published` (no maintained upstream package). Required for every `blocked` row, backed by candidate-specific evidence recorded in this file (`composer show -a 'drupal/<candidate>'` output or that candidate's Packagist page); leave blank otherwise. Keep the `Decision` cell a bare enum value and put annotations such as "no such path/package" in Evidence or Notes.

## Site-Specific Overlay Boundary

List custom config/code that remains after using Drupal CMS core primitives and maintained recipes.

| Overlay | Why recipe/core does not cover it | Evidence | Maintainer risk |
| --- | --- | --- | --- |
|  |  |  | UNKNOWN |

For every custom content type, View, workflow, or feature in this table, include the recipe default-owner decision: matching recipe checked, exact recipe evidence, decision (`apply`, `reject`, `blocked`, `not_applicable`, `UNKNOWN`), and why a custom overlay remains.

## Commands And Evidence

Record exact commands and readbacks.

```bash
ddev drush status
ddev drush pm:list --status=enabled
ddev drush config:export -y
ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'
ddev composer show -a 'drupal/<candidate>'
```

Recipe discovery / apply evidence:

```text
UNKNOWN
```

## Evidence Scope

This decision records the installed substrate and post-audit assembly path. Pair it with source capture, content import, target parity, and launch-gate records when those decisions are needed.
