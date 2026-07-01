# Maintainer Review Packet

## Review Scope

- Site:
- Target:
- Reviewer:
- Date:

## Architecture Review

- Official Drupal CMS guide baseline:
- Structured content first:
- Content model:
- Field model:
- Node vs Canvas ownership:
- Presentation-boundary model:
- Taxonomy:
- Media:
- Media rendering and image styles:
- Content completeness:
- Visual/design parity:
- Menus and routing:
- Menu/block ownership:
- Views and listings:
- Search and collection behavior:
- SEO metadata and canonical behavior:
- Open Graph/social metadata:
- Schema.org-supporting fields:
- Path aliases and canonicalization:
- Pathauto patterns:
- Source-intent aliases and redirects:
- Forms and integrations:
- Functional parity:
- Editorial workflow:
- Moderation/workflow states and roles:
- Editor add/edit experience:
- Accessibility tooling and content report:
- Site settings, caching, backup, and update workflow:
- Regulated/claim-sensitive content governance:
- Legal/footer content model:
- Config/source-of-truth:
- Custom module/controller scope:
- Custom module last-resort rationale:
- Native-first exceptions/off-road inventory:
- Security and privacy:

## Evidence Reviewed

- Source audit:
- Pattern map:
- Durable intent:
- Off-road inventory (`off-road-inventory.md`):
- Production target:
- Browser QA:
- Route matrix:
- Drupal readback:
- Field-output matrix:
- Launch gates:

## Stake-My-Name Verdict

Answer these questions exactly. This is the canonical signoff bar used by `README.md`, `START.md`, the worked example, and this template.

- [ ] Is the build on Drupal CMS best practices using Drupal-native primitives?
- [ ] Is the architecture sound for the source site's real shape?
- [ ] Does it contain the public content and media needed to review the site as a rebuild?
- [ ] Does it match the source site's visual language and public behavior?
- [ ] Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?
- [ ] Are the load-bearing decisions captured and usable by later agents?
- [ ] Are the remaining business, legal, integration, production, and launch gaps named?
- [ ] Would a Drupal maintainer put their name on this as a complete local starting point?

## Binary Verdict

Choose exactly one:

- [ ] I would stake my name on this as a complete local Drupal CMS rebuild.
- [ ] I would not stake my name on this as a complete local Drupal CMS rebuild.

A partial or incomplete site is an automatic "would not stake my name" verdict. Missing reachable public content, media, source-like design, public behavior, editor forms, current packet evidence, or a front page that renders the wrong source intent cannot be treated as polish.

## Architecture Review Checklist

Use this checklist to support the verdict. It is not a second rubric.

- [ ] The architecture is understandable from the packet.
- [ ] Drupal CMS install, setup, and site-building mechanics followed the encoded baseline in `AGENTS.md.template`, or every verified divergence from current Drupal CMS mechanics is documented as a maintainer-visible kit/upstream issue.
- [ ] Content modeling starts from goals, audiences, organizational requirements, and editor workflow, not only a source-page clone.
- [ ] Structured content first: recurring source objects are identified before import, theming, or Canvas composition.
- [ ] Generic Page or Utility Page bundles are not used for recurring content objects such as articles, releases, tracks, artists, sessions, events, venues, speakers, products, services, locations, episodes, FAQs, resources, legal notices, retailers, sponsors, taxonomy terms, or media assets.
- [ ] Lists, grids, schedules, directories, archives, catalogs, feeds, and search results are backed by structured content plus Views or another documented Drupal-native collection owner.
- [ ] The target model fits the load-bearing source patterns.
- [ ] Filterable, sortable, relational, governed, and reusable values are typed fields, taxonomy terms, or entity references rather than hidden in body text.
- [ ] Dates, venues, categories, people, prices, statuses, audiences, CTAs, provider URLs, external IDs, descriptions, images, alt text, legal labels, and relationships are modeled as Drupal fields/references where those values affect visitors, editors, filters, search, SEO, integrations, or future agents.
- [ ] Source-audit and crawl-provenance fields are not exposed on normal editorial bundles unless an admin-only governance surface is deliberately justified.
- [ ] Editor fields do not store raw CSS declarations, gradients, style attributes, class names, HTML snippets, JavaScript, iframe markup, or theme implementation strings.
- [ ] Editor-owned visual variation is modeled as constrained semantic data such as theme variants, palette terms, booleans/enums, or validated color tokens, with theme/config responsible for CSS output.
- [ ] Listings, search, and collection routes use Views or have a documented reason for custom controller ownership.
- [ ] Reusable information is modeled as nodes/content types with fields, view modes, workflow, search/indexing, and API-ready structure rather than hand-assembled Canvas pages.
- [ ] One-off composed experiences use Canvas pages / Experience Builder when available rather than tortured content types with single-use layout fields.
- [ ] Hybrid pages keep nodes as canonical data and use Canvas as composed presentation where that fits the source pattern.
- [ ] Views own collection/listing/search routes and entity displays own repeatable detail pages; Canvas composition does not replace those Drupal primitives.
- [ ] Automation, derived values, rollups, and light workflow use ECA or another maintained Drupal automation path before custom hook code.
- [ ] Data relationships use the Entity and Field APIs, entity references, taxonomy, computed fields, and access-checked queries instead of custom tables or raw SQL for normal content modeling.
- [ ] Views were planned from the content model, including teaser fields, exposed/contextual filters, sorting, related-content blocks, and directory/search-like behavior where needed.
- [ ] Views render useful teasers, status/bundle filters, sorting, pager/filter behavior, and browser evidence for source-like collection routes.
- [ ] Search/discovery behavior is deliberate and anonymously reachable or explicitly blocked with next actions.
- [ ] SEO metadata, canonical URLs, sitemap/discovery, and editor title/description workflow are explicit or intentionally blocked.
- [ ] A maintained Drupal CMS SEO recipe or configured contrib path was applied when available for public pages, mapped to fields the model actually has, and verified by rendered anonymous output; an enabled module is not evidence.
- [ ] One published node per public content type was checked for non-empty `<meta name="description">` and non-empty `og:image` when the source/content type has meaningful image media.
- [ ] Open Graph/social metadata, schema.org-supporting fields, taxonomy landing pages, and internal related-content links are modeled or explicitly out of scope.
- [ ] Editor add/edit forms expose the load-bearing fields with clean human-readable labels.
- [ ] Field widgets and formatters match the field types; taxonomy/media references are not plain text fallbacks unless documented.
- [ ] A seeded non-admin editor role and user can create/edit every custom content type that holds content; verification was performed as that user, never uid=1.
- [ ] A new representative item can be created by a non-admin editor and appears in the expected public View or detail route without code changes.
- [ ] hardcoded public strings in Twig, templates, preprocess code, Views text areas, and import scripts are inventoried; source-owned public copy has a Drupal owner or a documented exception.
- [ ] Public navigation, footer links, CTA labels, and legal/privacy links are owned by Drupal menus, blocks, Canvas components, fields, or config unless the packet documents why template ownership is acceptable.
- [ ] Raw field-value rendering that bypasses Drupal text formatters, rendered labels inside HTML attributes, invalid alt text, and visible links hidden from assistive technology are absent or explicitly blocked.
- [ ] Regulated or claim-sensitive content has source/review status, required disclosure/label text, warning/restriction fields, audience/suitability fields, and blocked-evidence notes where relevant.
- [ ] FAQ, advice/article, retailer/location, legal/footer, professional/audience-specific, and contact workflows are modeled explicitly where the source requires them.
- [ ] Media strategy is explicit: Drupal media references, source assets, unavailable assets, placeholders, or external references are not conflated.
- [ ] Public source assets use managed Media and image styles, or the packet documents why raw URI fields, CDN hotlinks, or placeholders remain.
- [ ] Alt text, responsive image styles, image reuse, and hero/thumbnail/social-image field decisions are explicit.
- [ ] Primary navigation and footer navigation are owned by Drupal menus/blocks or have a documented exception.
- [ ] Custom content types have Pathauto patterns or an explicit alias-management decision.
- [ ] The content model has one reviewable source of truth; install hooks are not the only place custom structure exists.
- [ ] The tracked config directory is the active sync directory, and a clean install plus config import would reproduce the site structure; if Drupal exports to `web/sites/default/files/sync` or another active path, the packet names that config sync directory and representative files.
- [ ] Site structure lives in exported configuration or a recipe. If content types, fields, displays, Views, menus, roles, workflows, or theme settings exist only in scripts, the clean-import gate fails.
- [ ] Clean import/config reproduction evidence proves key config such as `system.theme:default`, custom content types, fields, Views, menus, and roles import as expected.
- [ ] The target has no custom module unless the packet proves config, recipes, maintained contrib, Views, Canvas/Experience Builder, blocks, Layout Builder, ECA, Webform, menus, aliases, theme code, and import scripts could not reasonably express the need.
- [ ] Custom modules are named for reusable Drupal capabilities, not source-site, client, brand, project, or miscellaneous helper buckets.
- [ ] Custom modules have purposeful bounded behavior, configuration or extension points where variation is likely, privacy-safe logging, and evidence for access, cacheability, sanitization, validation, and editor workflow.
- [ ] Empty marker modules are not used to imply architecture.
- [ ] Custom controllers, if present, are thin, access-controlled, cacheable, and driven by editable Drupal content/config.
- [ ] Off-road moves are inventoried and justified in `off-road-inventory.md`: custom modules/controllers/endpoints, preprocess/entity-query rendering, hardcoded copy or computed values, raw CSS/presentation fields, unfiltered formats, `accessCheck(FALSE)`, `_access: TRUE`, forced `max-age=0`, raw markup, raw SQL, one-shot derived fields, stale contrib defaults, missing Pathauto patterns, hardcoded entity IDs in config, or config that is not import-reproducible.
- [ ] Public rendering avoids unsafe raw body/source output and undocumented forced `max-age=0`.
- [ ] Moderation states, role permissions, draft/review/published/unpublished behavior, and claim-sensitive review flows are documented where relevant.
- [ ] Accessibility tooling, content accessibility report status, alt text, heading structure, contrast, embed descriptions, and manual accessibility gaps are documented.
- [ ] Site name/email, caching/aggregation, backup strategy, update readiness, security update posture, Composer-managed files, and update workflow are documented or intentionally blocked.
- [ ] Representative top-level, listing, detail, search, where-to-buy/contact/legal routes have anonymous route evidence and alias/canonicalization notes.
- [ ] Browser-first source route expansion checked likely public slugs from rendered links, source bundle route data, metadata, click targets, asset names, sitemap/robots hints, and naming patterns; curl-only evidence did not close route inventory.
- [ ] The homepage/front page matches the browser-rendered source intent, or any redirect/canonical difference is explicitly accepted with source evidence.
- [ ] Target `/` itself was checked against browser-rendered source `/` for final URL, status, title, H1, key body intent, canonical link, screenshot, and Drupal route ownership; a correct page at another alias does not satisfy this check by itself.
- [ ] The front-page alias decision is explicit: canonical redirect, distinct Drupal display route, View/route composition, or duplication with synchronization warning.
- [ ] Every browser-rendered source route is preserved, redirected, or explicitly item-blocked; missing source routes are not hidden by a passing smoke check.
- [ ] Starter route cleanup is complete for `/home`, `/page/1`, `/privacy-policy`, raw `/node/*`, starter Canvas pages, stale menu/footer links, duplicate aliases, and unexpected public 200 routes.
- [ ] Unexpected public 200 routes from duplicate aliases, duplicate content, stale menu links, default demo content, or route-normalization shortcuts are removed or explicitly accepted.
- [ ] Legal, privacy, footer, and menu links resolve anonymously or are explicitly blocked with next actions.
- [ ] Product, article, and legal detail routes render the expected H1/title and load-bearing fields, not only HTTP 200.
- [ ] Important source-intent routes are preserved, redirected, or explicitly retired.
- [ ] Drupal readback is unfiltered and includes front-page setting, all nodes including unpublished/default content, aliases including duplicates, menus and menu links, Canvas pages when available, media counts, themes, config sync directory, config status, and unexpected public routes.
- [ ] Every required or load-bearing editor field either renders publicly, has a documented admin-only rationale, or is removed from the editor workflow; no required field exists only to carry theme implementation.
- [ ] No senior Drupal maintainer would reject the approach on sight.
- [ ] Source observations are either supported by evidence or marked `UNKNOWN`.
- [ ] Recipe and configuration choices are reviewable.
- [ ] Durable intent is current or treated as absent.
- [ ] Route, content, media, integration, accessibility, performance, security, and editorial risks are explicit.
- [ ] Launch readiness is tied to accepted evidence.
- [ ] The packet does not present a sample, representative, placeholder-heavy, stale, or partial build as complete.

## Required Rationale

- Reasons to accept:
- Reasons to reject or revise:
- Anti-patterns a senior maintainer would remove:
- Restrictions or follow-up evidence required:

## Boundary

Maintainer review is required before launch review. A positive stake-my-name verdict accepts the local Drupal CMS rebuild as reviewable.
