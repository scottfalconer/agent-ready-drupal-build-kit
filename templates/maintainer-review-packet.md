# Maintainer Review Packet

## Review Scope

- Site:
- Target:
- Reviewer:
- Date:

## Architecture Review

- Official Drupal CMS guide baseline:
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
- [ ] The target model fits the load-bearing source patterns.
- [ ] Filterable, sortable, relational, governed, and reusable values are typed fields, taxonomy terms, or entity references rather than hidden in body text.
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
- [ ] Open Graph/social metadata, schema.org-supporting fields, taxonomy landing pages, and internal related-content links are modeled or explicitly out of scope.
- [ ] Editor add/edit forms expose the load-bearing fields with clean human-readable labels.
- [ ] Field widgets and formatters match the field types; taxonomy/media references are not plain text fallbacks unless documented.
- [ ] Regulated or claim-sensitive content has source/review status, required disclosure/label text, warning/restriction fields, audience/suitability fields, and blocked-evidence notes where relevant.
- [ ] FAQ, advice/article, retailer/location, legal/footer, professional/audience-specific, and contact workflows are modeled explicitly where the source requires them.
- [ ] Media strategy is explicit: Drupal media references, source assets, unavailable assets, placeholders, or external references are not conflated.
- [ ] Public source assets use managed Media and image styles, or the packet documents why raw URI fields, CDN hotlinks, or placeholders remain.
- [ ] Alt text, responsive image styles, image reuse, and hero/thumbnail/social-image field decisions are explicit.
- [ ] Primary navigation and footer navigation are owned by Drupal menus/blocks or have a documented exception.
- [ ] Custom content types have Pathauto patterns or an explicit alias-management decision.
- [ ] The content model has one reviewable source of truth; install hooks are not the only place custom structure exists.
- [ ] The tracked config directory is the active sync directory, and a clean install plus config import would reproduce the site structure.
- [ ] The target has no custom module unless the packet proves config, recipes, maintained contrib, Views, Canvas/Experience Builder, blocks, Layout Builder, ECA, Webform, menus, aliases, theme code, and import scripts could not reasonably express the need.
- [ ] Custom modules are named for reusable Drupal capabilities, not source-site buckets such as `refwd_site`, `dangertv_site`, `site_custom`, or miscellaneous helper modules.
- [ ] Custom modules have purposeful bounded behavior, configuration or extension points where variation is likely, privacy-safe logging, and evidence for access, cacheability, sanitization, validation, and editor workflow.
- [ ] Empty marker modules are not used to imply architecture.
- [ ] Custom controllers, if present, are thin, access-controlled, cacheable, and driven by editable Drupal content/config.
- [ ] Off-road moves are inventoried and justified: custom modules/controllers/endpoints, preprocess/entity-query rendering, hardcoded copy or computed values, raw CSS/presentation fields, unfiltered formats, `accessCheck(FALSE)`, `_access: TRUE`, forced `max-age=0`, raw markup, raw SQL, one-shot derived fields, stale contrib defaults, or config that is not import-reproducible.
- [ ] Public rendering avoids unsafe raw body/source output and undocumented forced `max-age=0`.
- [ ] Moderation states, role permissions, draft/review/published/unpublished behavior, and claim-sensitive review flows are documented where relevant.
- [ ] Accessibility tooling, content accessibility report status, alt text, heading structure, contrast, embed descriptions, and manual accessibility gaps are documented.
- [ ] Site name/email, caching/aggregation, backup strategy, update readiness, security update posture, Composer-managed files, and update workflow are documented or intentionally blocked.
- [ ] Representative top-level, listing, detail, search, where-to-buy/contact/legal routes have anonymous route evidence and alias/canonicalization notes.
- [ ] The homepage/front page matches the browser-rendered source intent, or any redirect/canonical difference is explicitly accepted with source evidence.
- [ ] Target `/` itself was checked against browser-rendered source `/` for final URL, status, title, H1, key body intent, canonical link, screenshot, and Drupal route ownership; a correct page at another alias does not satisfy this check by itself.
- [ ] Every browser-rendered source route is preserved, redirected, or explicitly item-blocked; missing source routes are not hidden by a passing smoke check.
- [ ] Unexpected public 200 routes from duplicate aliases, duplicate content, stale menu links, default demo content, or route-normalization shortcuts are removed or explicitly accepted.
- [ ] Legal, privacy, footer, and menu links resolve anonymously or are explicitly blocked with next actions.
- [ ] Product, article, and legal detail routes render the expected H1/title and load-bearing fields, not only HTTP 200.
- [ ] Important source-intent routes are preserved, redirected, or explicitly retired.
- [ ] Drupal readback is unfiltered and includes front-page setting, all nodes including unpublished/default content, aliases including duplicates, menus, media counts, themes, config status, and unexpected public routes.
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
