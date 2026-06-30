# Recipe Start-Point Decision

## Site

- Source URL: `https://example.invalid/community-arts`
- Target site name: Fictional Community Arts Center
- Target workspace: `fictional-community-arts-drupal`
- Source-use boundary: `fictional-example`
- Decision date: 2026-06-30

## Recommended Start Point

Decision: Clean Drupal CMS Starter plus bounded overlays.

Rationale: The source shape is a standard content/editorial site with events, classes, staff profiles, landing pages, media, menus, listings, forms, and external providers. Drupal CMS Starter plus maintained recipe candidates should cover the baseline. Site-specific overlays are limited to content types, vocabularies, Views, aliases, and packet evidence.

## Recipe Candidate Review

| Candidate recipe | Fit | Decision | Evidence | Notes |
| --- | --- | --- | --- | --- |
| `drupal_cms_starter` | Baseline starter site | apply | Fictional example | Starter is the default start point. |
| `drupal_cms_admin_ui` | Editorial/admin experience | apply | Fictional example | Needed for editor handoff. |
| `drupal_cms_media` | Media handling | apply | Fictional example | Required for event/class/person images. |
| `drupal_cms_search` | Public search/discovery | blocked | UNKNOWN | Source search behavior not verified. |
| `drupal_cms_forms` | Forms | blocked | UNKNOWN | Newsletter form provider/privacy evidence missing. |
| `drupal_cms_seo_basic` / `drupal_cms_seo_tools` | SEO metadata/checklist | apply | Fictional example | Needed for event/class discovery. |
| `drupal_cms_accessibility_tools` | Accessibility tooling | apply | Fictional example | Required for public venue/event pages. |
| `drupal_cms_privacy_basic` | Privacy/legal baseline | apply | Fictional example | Footer/privacy ownership required. |
| `drupal_cms_google_analytics` | Analytics | blocked | UNKNOWN | Analytics decision and ID missing. |

## Site-Specific Overlay Boundary

| Overlay | Why recipe/core does not cover it | Evidence | Maintainer risk |
| --- | --- | --- | --- |
| `event` content type and `events_listing` View | Event calendar pattern is site-specific | Pattern map | Low if config-exported with editor forms. |
| `class` content type and `classes_listing` View | Class catalog pattern is site-specific | Pattern map | Low if filters and registration links are reviewed. |
| `person` content type | Staff/artist profile pattern is site-specific | Pattern map | Low. |
| `audience`, `program_area`, `season` vocabularies | Public filters use controlled terms | Pattern map | Low. |

## Evidence Scope

This is a fictional decision example. Verify recipe availability and launch gates in a real target.
