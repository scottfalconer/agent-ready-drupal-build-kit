# Recipe Start-Point Decision

## Site

- Source URL:
- Target site name:
- Target workspace:
- Source-use boundary:
- Decision date:
- Decision owner:

## Recommended Start Point

Choose one:

- [ ] Clean Drupal CMS Starter plus bounded overlays.
- [ ] High-fit Drupal CMS template or site template.
- [ ] Maintained Drupal CMS recipes plus bounded site-specific overlays.
- [ ] Custom Drupal CMS build because recipes/templates do not fit.

Decision:

Rationale:

## Source Pattern Drivers

List the source patterns that affect the start point.

| Source pattern | Evidence | Drupal CMS implication | Confidence |
| --- | --- | --- | --- |
|  |  |  | UNKNOWN |

## Recipe Candidate Review

Do not install every recipe by default. Verify availability in the target project before relying on a recipe name.

From the DDEV Drupal project root, collect recipe evidence with:

```bash
ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'
ddev exec dr list recipe
ddev exec dr recipe:info ../recipes/drupal_cms_media
```

Apply a recipe only after recording why it fits the pattern map:

```bash
ddev exec dr recipe:apply ../recipes/drupal_cms_media
```

If `dr list recipe` does not show recipe commands, record recipe application as blocked or use the current documented Drupal core recipe path only after verifying it in the target. Replace `../recipes/drupal_cms_media` with the verified recipe path. The `dr` command resolves paths from the Drupal webroot after bootstrap, so project-root recipes usually need `../recipes/...`.

| Candidate recipe | Fit | Decision | Evidence | Notes |
| --- | --- | --- | --- | --- |
| `drupal_cms_starter` | Baseline starter site | UNKNOWN |  |  |
| `drupal_cms_admin_ui` | Editorial/admin experience | UNKNOWN |  |  |
| `drupal_cms_media` | Media handling | UNKNOWN |  |  |
| `drupal_cms_search` | Public search/discovery | UNKNOWN |  |  |
| `drupal_cms_forms` | Forms | UNKNOWN |  |  |
| `drupal_cms_seo_basic` / `drupal_cms_seo_tools` | SEO metadata/checklist | UNKNOWN |  |  |
| `drupal_cms_accessibility_tools` | Accessibility tooling | UNKNOWN |  |  |
| `drupal_cms_privacy_basic` | Privacy/legal baseline | UNKNOWN |  |  |
| `drupal_cms_authentication` | Authentication/login | UNKNOWN |  |  |
| `drupal_cms_google_analytics` | Analytics | UNKNOWN |  |  |
| `drupal_cms_ai` | AI features | UNKNOWN |  |  |
| `drupal_cms_content_type_base` / `drupal_cms_site_template_base` | Content/template foundation | UNKNOWN |  |  |

Decision values: `apply`, `reject`, `blocked`, `not_applicable`, `UNKNOWN`.

## Site-Specific Overlay Boundary

List custom config/code that remains after using Drupal CMS core primitives and maintained recipes.

| Overlay | Why recipe/core does not cover it | Evidence | Maintainer risk |
| --- | --- | --- | --- |
|  |  |  | UNKNOWN |

## Commands And Evidence

Record exact commands and readbacks.

```bash
ddev drush status
ddev drush pm:list --status=enabled
ddev drush config:export -y
ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'
ddev exec dr list recipe
```

Recipe discovery / apply evidence:

```text
UNKNOWN
```

## Evidence Scope

This decision chooses a build start point. Pair it with source capture, content import, target parity, and launch-gate records when those decisions are needed.
