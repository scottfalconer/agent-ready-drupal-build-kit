# Drupal CMS Build Playbook

This playbook records common build issues that can cause agents to misread evidence or produce brittle Drupal targets.

## Official Drupal CMS Baseline

The copyable `AGENTS.md.template` file encodes the Drupal CMS build baseline an agent needs for local work.

That baseline is drawn from the Drupal CMS User Guide and includes installation, DDEV setup, the setup assistant or install profile, content modeling concepts, editor workflow, media, SEO, accessibility, privacy/legal, updates, backups, and other Drupal CMS mechanics. This kit adds governed source audit, pattern mapping, Drupal architecture guardrails, evidence gates, and maintainer review.

If a maintainer or agent verifies that current Drupal CMS docs conflict with the encoded baseline, follow current Drupal CMS mechanics, continue only if the build remains reviewable, and record the conflict as a kit or upstream-fix item. Do not block routine use of this kit on a separate reading pass.

## Local Runtime

Use DDEV as the default local runtime for Drupal CMS rebuilds. Start from a clean project unless the task explicitly says to continue an existing target:

```bash
mkdir my-drupal-site && cd my-drupal-site
ddev config --project-type=drupal11 --docroot=web
ddev composer create-project drupal/cms
ddev launch
ddev status
```

For automated builds, use a documented equivalent Drupal CMS install/setup path. After installation, gather Drush and config evidence with commands such as `ddev drush status` and `ddev drush config:export -y`.

Before accepting a local build, record:

- `ddev describe`;
- `ddev drush status`;
- enabled modules/profile;
- exported config;
- anonymous public route checks;
- browser-rendered evidence.

Do not accept static HTML, local file previews, screenshots, or a non-Drupal server as a Drupal CMS build.

## Drupal Build Primitives

Name the expected primitives in the build brief and align them to the encoded Drupal CMS baseline. A Drupal CMS rebuild should use Drupal to hold the site architecture:

- content types and fields for recurring content patterns;
- taxonomies for categories, topics, audiences, conditions, locations, or other controlled lists;
- media entities, media reference fields, image styles, and file handling for owner-approved assets;
- menus, menu blocks, path aliases, redirects, and Pathauto patterns for navigation and route parity;
- Views or Drupal routes for listings, search-like pages, and landing pages;
- theme templates/CSS or Drupal theme settings for presentation;
- custom modules, recipes, or config overlays for site-specific behavior;
- Drush and config export for repeatable verification.

If the output does not contain Drupal entities/config/code that a maintainer can inspect, it is not a Drupal-side build. A visually close static site is a design artifact, not successful execution of this kit.

## Drupal CMS Guide Best Practices

The Drupal CMS guide frames content modeling around the site's goals, audiences, organizational requirements, and editor workflow. The kit should preserve that order. Do not let an agent begin by cloning source pages into generic body fields.

For target architecture:

- Use content types for recurring content patterns and fields for the specific pieces of information editors manage.
- Store filterable or sortable values as typed fields, taxonomy terms, dates, numbers, addresses, geofields, or entity references. Avoid burying product attributes, prices, dates, regions, categories, approvals, or relationships in formatted body text.
- Plan Views during content modeling. Identify teaser fields, exposed filters, contextual filters, sort criteria, related-content blocks, directories, homepage blocks, and search-like routes before importing content.
- Use taxonomy for categories, regions, topics, audiences, product families, conditions, or other controlled language that supports filtering, URL structure, SEO, and landing pages.
- Use Media Library for approved images and files. Record alt text, reuse requirements, responsive image styles, image compression/performance needs, and whether hero, thumbnail, and Open Graph images are shared or separate fields.
- Include SEO and social metadata where the source depends on discovery: URL aliases, meta title, meta description, SEO image, Open Graph title/description/image, heading-level strategy, schema.org-supporting fields, taxonomy landing pages, and related-content/internal-linking Views.
- Use Drupal CMS moderation/workflow for team-edited, regulated, or claim-sensitive content. Record states such as draft, needs review, published, and unpublished, plus role permissions for create, review, publish, unpublish, and update actions.
- Apply Drupal CMS Accessibility Tools/Editoria11y when accessibility review is in scope. Record content accessibility report status, alt text, heading structure, contrast, embed descriptions, and unresolved manual checks.
- Record site settings and operations that affect handoff: site name, site email, caching/aggregation, backup strategy, update readiness, security updates, Composer-managed files, and whether updates are handled through Drupal CMS UI, Composer, hosting tools, or another approved path.

## Regulated Product And Compliance Content

For regulated, healthcare, financial, legal, safety-sensitive, or otherwise claim-sensitive sites, make governance part of the content model:

- use distinct product/content categories when the source distinguishes medicine, non-medicine, regulated service, advisory content, legal content, or professional content;
- add fields for source/approval status, claim status, review status, required disclosure/label text, intended use, intended audience or suitability, warnings or restrictions, and blocked evidence notes;
- keep external retailer/provider links separate from internal links and mark their approval/source status;
- model professional or practitioner sections separately from consumer journeys when the brief requires separation;
- model FAQ, advice/blog, retailer/location, legal/footer, and contact workflows explicitly when the source has those recurring patterns;
- do not invent dosage, safety statements, legal advice, medical claims, comparisons, guarantees, clinical data, professional materials, endorsements, or production contact handling.

Safe placeholders are allowed only when they say what evidence is missing and who must approve it. Placeholder content is not launch content.

## Drupal-Native Pages Before Controller Mimicry

Use Drupal primitives before custom route controllers:

- Use nodes or other content entities for editable landing, product, article, campaign, retailer, location, and utility pages.
- Use Views for listings, search-like routes, filtered collections, related-content blocks, retailer/location directories, and product/advice indexes.
- Use menus, menu blocks, aliases, redirects, and Pathauto patterns for navigation and route ownership.
- Keep theme templates focused on presentation of Drupal-owned data.

Custom controllers are allowed only when content entities, Views, blocks, menus, recipes, or config are not a reasonable fit. If a controller is used, record:

- why Drupal config primitives were insufficient;
- access requirements beyond `_access: TRUE`;
- cacheability metadata;
- which editable content or config drives the output;
- what route/alias tests prove the route is public and not a hard-coded mimic.

Controller-rendered pages that replace editable Drupal content, Views listings, menus, or search should be flagged for maintainer review.

Do not use forced `max-age=0`, `_access: TRUE`, or unsafe raw body/source rendering as a shortcut. If a controller needs unusual access, cache, or markup handling, record the reason and put it in the maintainer review packet.

## Config and Module Source of Truth

The target must be reproducible from reviewable Drupal artifacts:

- use exported config for custom bundles, fields, form displays, view displays, Views, menus, vocabularies, image styles, roles, workflows, and Pathauto patterns;
- use one clear source of truth for the content model, not duplicate definitions split across config and install hooks;
- use documented default-content/import records for sample content, aliases, and menu links that are not config;
- avoid empty custom modules that only mark ownership;
- keep module install/update hooks idempotent and limited to behavior or data that cannot be represented cleanly in config.

Config that imports but leaves editor forms unusable is not acceptable architecture.

## Editor Experience Bar

The build is not reviewable until an editor can use it. Before handoff:

- log in as an editor or administrator;
- open add/edit forms for every custom content type;
- confirm human-readable labels and help text for load-bearing fields;
- confirm raw machine names, translation keys, or broken labels are not exposed;
- confirm media, related links, benefits, usage, page roles, retailer links, and source/reference fields are editable where relevant;
- confirm form displays are not limited to title/meta controls when the source pattern requires structured fields.
- confirm widgets match field types, such as entity reference autocomplete for taxonomy/media references and media library controls for image/media fields.
- confirm view displays render the public fields with appropriate formatters, not machine labels or empty placeholders.
- for regulated or claim-sensitive content, confirm editors can see and update approval status, source status, required disclosure/label text, warnings/restrictions, professional/consumer audience separation, and blocked-evidence notes.

Record unresolved editor-experience gaps in the handoff instead of hiding them behind public-page screenshots.

## Media Strategy

Prefer Drupal Media entities and media reference fields for approved images, files, and video records. When source media is not approved:

- use local placeholders or explicit external-reference fields;
- record owner approval status;
- preserve alt-text requirements;
- explain whether placeholders, URL fields, or media references are the primary rendering path;
- avoid broken external URLs or root-relative URI values that Drupal field formatters cannot render.

When media is approved, import or stage it into Drupal-managed file storage, reference it through Media entities, preserve alt-text requirements, and render it through Drupal field formatters and image styles. Avoid raw `<img src>` output, CDN hotlinking, and URI/image-url fields as the primary public rendering path unless the owner explicitly chooses an external-asset strategy.

URL/image fields can be useful evidence carriers, but they should not silently replace a real Drupal media strategy.

## Content Field Formats

Text fields often need both value and format. Do not import formatted text without an explicit text format decision and owner approval.

Record:

- target field;
- allowed text format;
- sanitizer or transform;
- owner approval requirement.

## Content Moderation and Visibility

Draft content may not be visible to anonymous users. A route that works for an editor can still 404 or redirect for the public visitor.

Check public visitor behavior separately from CMS readback.

## Path Aliases and Pathauto

Pathauto can generate useful aliases, but it can also overwrite or diverge from preserved source paths.

For each important route, decide:

- preserve source alias;
- generate new Drupal alias;
- redirect old source route;
- retire route.

Run a route/alias smoke check for every representative top-level source route and listing route. For condition/product/advice sites, this usually includes routes like `/`, condition hubs, product listings, advice listings, product details, article details, where-to-buy, search, contact, legal, privacy, and cookie pages when present. Record intended canonicalization, including trailing-slash behavior and Pathauto-generated alternates.

Custom content types should have Pathauto patterns or an explicit documented reason why aliases will be hand-managed. Editor-created content should not fall back to unpredictable `/node/{id}` URLs when the source pattern depends on readable routes.

Preserve source-intent aliases when the source has recognizable routes that differ from the improved target IA. For example, if the target introduces `/products`, but the source used `/range`, `/shop`, or `/nytol-range`, either preserve, redirect, or explicitly retire the source-style route.

Detail-route checks must prove rendered content, not only HTTP status. For product/article/legal routes, record title or H1, canonical/alias behavior, and the presence of load-bearing fields such as product type, approval status, safety/disclosure copy, retailer/provider links, and media/placeholders where relevant.

## Databases and Files

Do not place databases, private files, exports, or credentials inside the public web root.

A target build must record:

- public files location;
- private files location;
- database boundary;
- backup and rollback evidence;
- credential handling.

## Config Export and Import

Recipe apply is not enough. Export target config and, when possible, import it into a clean target to prove portability.

Use config evidence for configuration review. Rendered parity and launch readiness require browser and launch-gate evidence.

## Cache and Field Discovery

After enabling modules or applying recipes, rebuild caches before assuming field plugins, entity displays, or typed data definitions are available.

## Views Are Configuration

A prose plan for listings is not Views parity. Views/page parity needs exported Views config, route/display proof, access checks, sorting, filters, pagination, cache behavior, and browser-rendered evidence.

Listings and search-like routes should default to Views. If a custom controller replaces a View for a collection route, document why and flag it for maintainer review.

Views should render useful teasers, not only titles, when the source collection depends on summaries, imagery, product attributes, retailer/location details, or calls to action. Use exposed filters or contextual arguments when taxonomy or route context is load-bearing.

Search/discovery needs a deliberate decision. Provide a Views-backed search/discovery route, Drupal core search with public permissions and documented limitations, or a blocked production-search note. A search route that returns 403/404 anonymously is a handoff risk.

## SEO Metadata

For rebuilds that need SEO preservation, record the metadata strategy:

- metatag module defaults or equivalent fields;
- page-specific editor workflow for titles/descriptions;
- canonical URL and alias decisions;
- sitemap or route-discovery behavior;
- redirects for retired source routes;
- blocked production SEO evidence.

Do not treat readable aliases alone as SEO parity.

## Third-Party Services

Analytics, maps, video embeds, donations, ticketing, email marketing, search, consent, and payment systems need owner approval, provider decisions, privacy review, performance review, credentials, and target proof.

Detection alone is not implementation evidence.

## Security Defaults

Before launch review, verify:

- security update status;
- trusted host and environment configuration;
- private file handling;
- headers and cookies;
- permissions and roles;
- forms and spam protection;
- third-party scripts and consent;
- database and backup boundaries.
