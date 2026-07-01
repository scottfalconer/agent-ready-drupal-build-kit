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

## Primary Route Gate

Treat the homepage as a primary route, not just one route in a smoke list. Capture the browser-rendered source `/` after JavaScript, including final URL, status, title, H1, key body intent, canonical link, and screenshot. Then compare target `/` against that same evidence.

A target fails the local rebuild bar when `/` renders a different source pattern, wrong canonical content, unrelated default node, or duplicate content shortcut, even if the correct page exists at another alias such as `/artist` or `/home`. Only accept a redirect when the source homepage also redirects or the route matrix records an explicit, reviewed canonicalization decision.

## Browser-First Route Discovery

Route discovery starts in the browser, not in curl. Curl is useful for headers and status codes, but a curl response alone cannot close the route inventory for JavaScript, static-bundle, smart-link, SPA, or app-like sources.

Use browser-rendered pages as the source truth, then expand with evidence from:

- rendered navigation, footer, legal links, canonical links, Open Graph/social metadata, and click targets;
- source bundle route data, client-side router manifests, sitemap/robots hints, and embedded JSON;
- asset names, artwork filenames, media manifests, API payloads, and source naming patterns that imply likely public slugs;
- no-follow redirect checks, not only final pages after `curl -L`.

Every likely public slug gets one disposition in the route matrix: preserved, redirected, intentionally retired, private/unreachable, or item-blocked with the evidence and next action. A seed prompt that names three pages does not excuse missing other browser-discovered public routes.

## Starter Content And Route Drift Cleanup

Drupal CMS Starter content is useful scaffolding, not acceptable leftover public content. Before handoff, run anonymous checks for `/home`, `/page/1`, `/privacy-policy`, raw `/node/*` routes, starter Canvas pages, default menu/footer links, duplicate aliases, and unexpected public 200 routes.

For each leftover route, either:

- remove or unpublish it;
- convert it into source-owned Drupal content;
- redirect it deliberately;
- record it as a blocked legal/privacy/footer decision.

The packet should prove cleanup, because stale starter routes can make a Drupal build look more complete than it is.

## Front Page And Alias Ownership

Drupal's route-normalizer can redirect aliases for the configured front page. That is normal Drupal behavior, but it must be a decision, not a surprise.

When `/` and another source route represent the same or related public concept, choose and record one approach:

- canonical redirect;
- distinct Drupal display route;
- View/route composition;
- duplication with synchronization warning.

The cleaner Drupal answer is usually one content owner plus a deliberate display/canonicalization decision. Duplicating content to satisfy two URLs is allowed only when the packet names the synchronization risk.

## Standard Drupal Readback

Every run should emit comparable Drupal readback. At minimum include:

- `ddev drush status`, enabled modules, default/admin themes, install profile, site name, front page, and config status;
- the active config sync directory and whether it is the tracked/reviewed directory;
- content types, field storage, field instances, form displays, view displays, widgets, formatters, workflows, and roles/permissions notes;
- nodes including unpublished/default/demo content, aliases including duplicates, redirects, menus/menu links, blocks, Views, Canvas pages when available, and unexpected public routes;
- media counts/items, source asset locations, alt text, responsive image styles, and whether imports rely on cached local evidence or live remote downloads.

If root `config/sync` is empty but Drupal's active sync directory is `web/sites/default/files/sync` or another path, say that plainly. A reviewer should not have to guess where the real config export lives.

## Reproducible Config As Source Of Truth

Drupal configuration is the reviewable source of truth for site structure. Content types, fields, form displays, view displays, Views, menus, roles, workflows, image styles, Pathauto patterns, and theme settings should live in exported config or a recipe, not only in a build script.

For DDEV Drupal CMS projects with a `web` docroot, set the active config sync directory to a version-controlled project path such as `../config/sync` and export there. Do not leave `web/sites/default/files/sync` as the only source of config evidence; it is normally runtime file storage and easy to miss or ignore.

The clean-import proof is the real test. A clean install plus `drush config:import` should reproduce the custom structure. At minimum, assert that `system.theme:default` is the intended public theme, custom content types and fields exist, Views and menus import, and Starter defaults do not come back as the only public site.

Scripts can still be useful for one-shot content/media import or repeatable local setup, but if the content model exists only in a script, the Drupal architecture is not reproducible enough for maintainer handoff.

## SEO Is Rendered Output, Not Enabled Modules

For public-facing rebuilds, SEO and social metadata are part of public behavior. Prefer the maintained Drupal CMS SEO recipe or configured contrib path when available, then map tokens and defaults to fields the target model actually has.

Do not treat "Metatag is enabled" or "SEO recipe applied" as evidence. Fetch anonymous published pages and verify rendered output: a non-empty meta description per public content type, canonical URL behavior, and `og:image` where the source or content model has meaningful imagery. Empty tags caused by tokens pointing at missing fields are failed evidence, not harmless defaults.

## Non-Admin Editor Verification

Drupal access and workflow are part of the build, not admin polish. A content type is not editorially complete until a non-admin editor role can create and edit it when that workflow is required.

Seed at least one editor user for local verification. Run add/edit form checks as that user, not uid=1. Administrator success proves the site owner can bypass permissions; it does not prove the editorial experience works.

## Drupal Build Primitives

Name the expected primitives in the build brief and align them to the encoded Drupal CMS baseline. A Drupal CMS rebuild should use Drupal to hold the site architecture:

- content types and fields for recurring content patterns;
- taxonomies for categories, topics, audiences, conditions, locations, or other controlled lists;
- media entities, media reference fields, image styles, and file handling for source assets;
- menus, menu blocks, path aliases, redirects, and Pathauto patterns for navigation and route parity;
- Canvas pages / Experience Builder for one-off composed experiences when available;
- Views or Drupal routes for listings, search-like pages, taxonomy/category pages, and collection behavior;
- theme templates/CSS or Drupal theme settings for presentation;
- recipes, maintained contrib, config overlays, ECA, Webform, and theme code before custom modules for site-specific behavior;
- Drush and config export for repeatable verification.

If the output does not contain Drupal entities/config/code that a maintainer can inspect, it is not a Drupal-side build. A visually close static site is a design artifact, not successful execution of this kit.

## Structured Content First

A Drupal content model starts with the source site's nouns, not its screenshots or page count. Before import or theming, identify the repeatable objects visitors and editors actually work with: articles, releases, tracks, artists, sessions, events, venues, speakers, products, services, locations, episodes, FAQs, resources, legal notices, retailers, sponsors, taxonomy terms, and media assets.

Generic Page or Utility Page bundles are not acceptable owners for recurring source objects. A generic page can own a simple one-off informational page; it should not own every speaker profile, schedule item, catalog entry, release, product, or article because that hides the schema in body fields and makes future listings, filters, search, APIs, permissions, workflow, and editor training brittle.

Use this decision test:

- repeatable thing with stable attributes -> content type with typed fields;
- controlled category or classification -> taxonomy vocabulary;
- reusable file/image/video/document -> Media entity;
- collection, grid, directory, schedule, archive, catalog, feed, or search result -> View over structured content;
- one-off composed marketing or storytelling page -> Canvas page / Experience Builder, usually placing structured content rather than replacing it.

Store facts as Drupal facts. Dates, venues, categories, people, prices, statuses, audiences, CTAs, external IDs, provider URLs, descriptions, images, alt text, legal labels, and relationships should be fields, taxonomy terms, entity references, media references, links, dates, booleans, or numbers where those values matter to visitors, editors, filters, search, SEO, integrations, or future agents. Do not bury them only in formatted body text, raw HTML, JSON blobs, Canvas-only copies, or theme arrays.

Canvas is a composition layer, not a loophole around content modeling. Use Canvas for page-level narrative and arrangement. Keep products, events, people, resources, articles, releases, and other reusable data as canonical Drupal content, then render or bind that content into Canvas where the experience needs it.

Source audit and migration evidence are not normal editorial fields. `Source URL`, source route status, crawl notes, source HTML, source CSS, and route evidence belong in the review packet, import manifest, migration map, logs, or an admin-only audit surface when there is a real governance reason. They should not clutter the authoring form for ordinary editors.

The gate is practical: a non-admin editor must be able to add a new representative item, fill meaningful fields, save it, and see it appear in the expected public View, listing, detail route, search result, menu placement, or Canvas composition without code changes. If that cannot happen, the build has not proved Drupal ownership of the content.

## Drupal CMS Guide Best Practices

The Drupal CMS guide frames content modeling around the site's goals, audiences, organizational requirements, and editor workflow. The kit should preserve that order. Do not let an agent begin by cloning source pages into generic body fields.

For target architecture:

- Use content types for recurring content patterns and fields for the specific pieces of information editors manage.
- Store filterable or sortable values as typed fields, taxonomy terms, dates, numbers, addresses, geofields, or entity references. Avoid burying product attributes, prices, dates, regions, categories, approvals, or relationships in formatted body text.
- Plan Views during content modeling. Identify teaser fields, exposed filters, contextual filters, sort criteria, related-content blocks, directories, homepage blocks, and search-like routes before importing content.
- Use taxonomy for categories, regions, topics, audiences, product families, conditions, or other controlled language that supports filtering, URL structure, SEO, and landing pages.
- Use Media Library for source images and files needed for parity. Record alt text, reuse requirements, responsive image styles, image compression/performance needs, and whether hero, thumbnail, and Open Graph images are shared or separate fields.
- Include SEO and social metadata where the source depends on discovery: URL aliases, meta title, meta description, SEO image, Open Graph title/description/image, heading-level strategy, schema.org-supporting fields, taxonomy landing pages, and related-content/internal-linking Views.
- Use Drupal CMS moderation/workflow for team-edited, regulated, or claim-sensitive content. Record states such as draft, needs review, published, and unpublished, plus role permissions for create, review, publish, unpublish, and update actions.
- Apply Drupal CMS Accessibility Tools/Editoria11y when accessibility review is in scope. Record content accessibility report status, alt text, heading structure, contrast, embed descriptions, and unresolved manual checks.
- Record site settings and operations that affect handoff: site name, site email, caching/aggregation, backup strategy, update readiness, security updates, Composer-managed files, and whether updates are handled through Drupal CMS UI, Composer, hosting tools, or another chosen path.

## Regulated Product And Compliance Content

For regulated, healthcare, financial, legal, safety-sensitive, or otherwise claim-sensitive sites, make governance part of the content model:

- use distinct product/content categories when the source distinguishes medicine, non-medicine, regulated service, advisory content, legal content, or professional content;
- add fields for source status, claim status, review status, required disclosure/label text, intended use, intended audience or suitability, warnings or restrictions, and blocked evidence notes;
- keep external retailer/provider links separate from internal links and mark their source or review status;
- model professional or practitioner sections separately from consumer journeys when the brief requires separation;
- model FAQ, advice/blog, retailer/location, legal/footer, and contact workflows explicitly when the source has those recurring patterns;
- do not invent dosage, safety statements, legal advice, medical claims, comparisons, guarantees, clinical data, professional materials, endorsements, or production contact handling.

Safe placeholders are allowed only when they say what input is missing and who owns the next action. Placeholder content is not launch content.

## Native Tools Before Custom Code

Drupal is the gate: build through its APIs and systems so Drupal enforces access, validation, cacheability, sanitization, routing, and editorial workflow. `AGENTS.md.template` names the Drupal tool for each need: Views, Canvas/Experience Builder or Blocks/Layout Builder, ECA, the Entity and Field APIs, Configuration Management, roles and permissions, and configured contrib or Drupal CMS recipes. Custom code is the exception because it can opt out of that enforcement.

When custom code is genuinely required, record why no Drupal-native tool could express the need, which editable content or config drives it, which platform guarantees it must now handle directly, and what evidence proves it preserves access, cacheability, sanitization, validation, and editor workflow.

Review attention should concentrate where a framework gate was switched off. Inventory these off-road moves and justify each one:

- a custom module, route controller, or endpoint;
- an entity query/load plus render inside theme preprocess, a template, or a controller where a View or entity display should own it;
- human copy or dynamic values such as a year, count, status, CTA label, footer link, navigation label, or rollup hardcoded in a template, Views text area, or import script;
- a bespoke or unfiltered text format used for site content;
- `accessCheck(FALSE)`, forced `max-age=0`, `_access: TRUE`, raw render arrays, unsafe source markup, or raw SQL;
- a field value computed once at import from other entities with no live derivation, View, computed field, ECA rule, or recompute path;
- contrib or recipe defaults, tokens, metadata, consent, moderation, email, search, sitemap, alias, or SEO config pointing at fields or behaviors the target model does not actually have;
- a content type with no non-admin role able to create or edit it when the editorial workflow requires that;
- exported config that is not what a clean install plus config import would load.

None of these is automatically wrong, but each must earn its exception in the review packet.

## Off-Road Inventory

Create `review-packet/off-road-inventory.md` for every run. This is not an automatic fail list; it is the maintainer's map of where Drupal's normal guarantees were bypassed and what evidence makes that acceptable.

Inventory custom modules/controllers/endpoints, entity queries plus rendering outside Views/entity displays, hardcoded public copy or dynamic values, bespoke text formats, `accessCheck(FALSE)`, forced `max-age=0`, raw markup, raw SQL, one-shot computed field values, contrib tokens/default metadata pointing at missing fields, Pathauto patterns that miss custom bundles, hardcoded entity IDs in config, and custom content types without non-admin editor-role access.

## Custom Modules As Last Resort

The preferred local rebuild has no custom module. Drupal config, recipes, maintained contrib, Views, Canvas/Experience Builder, blocks, Layout Builder, ECA, Webform, menus, aliases, theme code, and import scripts should cover most rebuild work.

Do not create catch-all modules named after the source site, client, brand, or project to collect unrelated routes, templates, CSS, one-off imports, click handlers, endpoints, or miscellaneous glue. That shape is hard to hand off because it hides which parts are Drupal architecture and which parts are one-off agent decisions.

If custom behavior is genuinely required, make the module Drupal-shaped:

- name it for the reusable capability, not the source site;
- keep source-specific routes, labels, tokens, selectors, and provider values in config or content;
- expose config entities, plugins, services, events, or hooks when future variation is likely;
- preserve access checks, CSRF expectations, cache metadata, output sanitization, validation, and privacy-safe logging;
- include install/update paths or config schema only for behavior that cannot live in exported config;
- record maintained-contrib and recipe alternatives checked before writing the module.

For example, local click collection should first be a no-op/provider-aware stub or contrib-backed analytics decision. If a local endpoint is unavoidable, build an extensible event-tracking capability with config and validation rather than a bespoke source-site controller.

## Node And Canvas Ownership

Use nodes when the primary asset is reusable information. Use Canvas pages / Experience Builder when the primary asset is a one-off composed experience.

Nodes model content. Canvas composes experiences. Use a node when the content should survive its current presentation. Use a Canvas page when the presentation is the content.

Lean toward nodes/content types when:

- there will be many similar items;
- the thing has fields other systems should understand;
- it will be listed, filtered, searched, related, syndicated, translated field-by-field, indexed, exposed through JSON:API, or used by an agent/integration;
- it needs multiple displays such as teaser, card, full page, RSS, email, API, app view, or related-content widget;
- twenty similar Canvas pages would repeat the same component pattern manually.

Lean toward Canvas pages / Experience Builder when:

- the main editorial work is arranging sections, components, media, calls to action, and narrative flow;
- the page is a unique marketing, campaign, launch, donor appeal, temporary microsite, conference splash, partner, homepage, or presentation-heavy about experience;
- a content type would create many one-off layout fields no other page will reuse.

The best architecture is often hybrid: node = canonical data, Canvas = composed presentation. A product, event, article, case study, person, location, or resource should usually stay a node while Canvas arranges components, node teasers, field-bound components, calls to action, and media around it.

Use another Drupal-native owner when it fits the route:

- Views owns collection, search, directory, taxonomy/category, and listing pages.
- Entity view displays and templates own repeatable detail pages.
- Blocks or Layout Builder can own page regions when Canvas is unavailable or the page pattern is simpler and the packet records the reason.
- Theme templates own presentation of Drupal data, not editor-owned page composition.

Bad Canvas use: building repeatable structured content as hand-assembled pages. Bad node use: building a one-off landing page as a tortured content type with fields for every section, button color, logo row, promo card, and layout variant. A build that does either, or hand-codes homepage or landing-page content in Twig, a Views text area, a custom controller, or generic custom markup without this ownership decision, should return to the review loop.

## Config and Module Source of Truth

The target must be reproducible from reviewable Drupal artifacts:

- use exported config for custom bundles, fields, form displays, view displays, Views, menus, vocabularies, image styles, roles, workflows, and Pathauto patterns;
- use one clear source of truth for the content model, not duplicate definitions split across config and install hooks;
- confirm the tracked config directory is the active sync directory, and that a clean install plus `config:import` would reproduce the site structure;
- use documented default-content/import records for sample content, aliases, and menu links that are not config;
- avoid empty custom modules that only mark ownership;
- avoid source-site catch-all modules; custom modules should be reusable capabilities with explicit extension points and review evidence;
- keep module install/update hooks idempotent and limited to behavior or data that cannot be represented cleanly in config.

Config that imports but leaves editor forms unusable is not acceptable architecture.

## Editor Experience Bar

The build is not reviewable until an editor can use it. Before handoff:

- log in as the seeded non-admin editor user for primary editor checks; administrator checks can supplement but do not replace this;
- open add/edit forms for every custom content type;
- confirm human-readable labels and help text for load-bearing fields;
- confirm raw machine names, translation keys, or broken labels are not exposed;
- confirm media, related links, benefits, usage, page roles, retailer links, and source/reference fields are editable where relevant;
- confirm form displays are not limited to title/meta controls when the source pattern requires structured fields.
- confirm widgets match field types, such as entity reference autocomplete for taxonomy/media references and media library controls for image/media fields.
- confirm view displays render the public fields with appropriate formatters, not machine labels or empty placeholders.
- for regulated or claim-sensitive content, confirm editors can see and update source status, review status, required disclosure/label text, warnings/restrictions, professional/consumer audience separation, and blocked-evidence notes.

Record unresolved editor-experience gaps in the handoff instead of hiding them behind public-page screenshots.

## Presentation Boundary

Content fields are not a place to store CSS or theme implementation. Do not expose editor fields such as `Background gradient CSS`, raw class names, style attributes, HTML snippets, JavaScript, iframe markup, or arbitrary theme strings.

Theme templates are also not a hidden CMS. Do not put public navigation, footer links, CTA labels, or source-owned public copy only in Twig when editors should maintain it through Drupal menus, fields, blocks, Canvas components, or config. Template microcopy can be acceptable for generic UI chrome, but source-specific public content needs a Drupal owner or a documented exception.

If visual variation is part of the source pattern and editors should control it, model it as constrained data:

- a theme or layout variant with allowed values;
- a taxonomy or config entity representing a palette;
- a validated color token when color itself is editor-owned;
- a boolean or enum for source-observed display states.

The theme, Canvas/Experience Builder, Blocks/Layout Builder, or Drupal config should translate those choices into CSS. Full CSS declarations, gradients, media queries, classes, and implementation selectors belong in theme code/config or source evidence, not node fields.

Flag any raw presentation field in the maintainer review. It is usually a sign the build escaped Drupal's editor model and handed implementation details to content editors.

Also flag raw field-value rendering that bypasses Drupal text formatters, rendered labels used inside attributes, invalid alt text, visible links hidden from assistive technology, and hardcoded public strings in Twig that should have been fields, menu links, blocks, or Canvas component props.

## Media Strategy

Prefer Drupal Media entities and media reference fields for source images, files, and video records. When source media is private, unavailable, or technically blocked:

- use local placeholders or explicit external-reference fields;
- record the missing input or blocker;
- preserve alt-text requirements;
- explain whether placeholders, URL fields, or media references are the primary rendering path;
- avoid broken external URLs or root-relative URI values that Drupal field formatters cannot render.

When media is usable, import or stage it into Drupal-managed file storage, reference it through Media entities, preserve alt-text requirements, and render it through Drupal field formatters and image styles. Avoid raw `<img src>` output, CDN hotlinking, and URI/image-url fields as the primary public rendering path unless the project explicitly chooses an external-asset strategy.

URL/image fields can be useful evidence carriers, but they should not silently replace a real Drupal media strategy.

## Content Field Formats

Text fields often need both value and format. Do not import formatted text without an explicit text format decision.

Record:

- target field;
- allowed text format;
- sanitizer or transform;
- decision owner and rationale.

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

Detail-route checks must prove rendered content, not only HTTP status. For product/article/legal routes, record title or H1, canonical/alias behavior, and the presence of load-bearing fields such as product type, review status, safety/disclosure copy, retailer/provider links, and media/placeholders where relevant.

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

Analytics, maps, video embeds, donations, ticketing, email marketing, search, consent, and payment systems need an explicit human decision, provider details, privacy review, performance review, credentials where applicable, and target proof.

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
