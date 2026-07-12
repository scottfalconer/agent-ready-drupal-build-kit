# Maintainer Review Packet

## Review Scope

- Site:
- Target:
- Reviewer:
- Builder identity:
- Date:

`Builder identity` names the agent/runtime that produced the build. `Reviewer` is a recorded label, not an authenticated identity. The local verifier reports whether the strings match but does not infer that a different string proves an independent human.

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
- Browser evidence:
- Canvas authoring ownership:
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
- Utility Page exceptions:
- Bundle label policy:
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
- Open decisions (`open-decisions.md`):
- Production target:
- Browser QA:
- Browser evidence (`browser-evidence.json`):
- Independent verification (`independent-verification.json`):
- Blind adversarial review (`blind-adversarial-review.json`):
- Route matrix:
- Drupal readback:
- Field-output matrix:
- Launch gates:

## Stake-My-Name Verdict

Answer these questions exactly. `gates.json` is the machine-readable gate vocabulary; this verdict is the human maintainer view over those gates.

- [ ] Is the build on Drupal CMS best practices using Drupal-native primitives?
- [ ] Is the architecture sound for the source site's real shape?
- [ ] Does it contain the public content and media needed to review the site as a rebuild?
- [ ] Does it match the source site's visual language and public behavior?
- [ ] Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?
- [ ] Are the load-bearing decisions captured and usable by later agents?
- [ ] Are the remaining business, legal, integration, production, and launch gaps named?
- [ ] Would a Drupal maintainer put their name on this as a complete local starting point?

## Binary Verdict

This is the human-facing `G-MAINTAINER-01` record. An authorized maintainer should check one verdict. Because this file is builder-writable, the local verifier reports the choice as self-attested status only; pending or recorded acceptance does not change the machine completion verdict or exit code.

Choose exactly one:

- [ ] I would stake my name on this as a complete local Drupal CMS rebuild.
- [ ] I would not stake my name on this as a complete local Drupal CMS rebuild.

A partial or incomplete site is an automatic "would not stake my name" verdict. Missing reachable public content, media, source-like design, public behavior, editor forms, current packet evidence, or a front page that renders the wrong source intent cannot be treated as polish.

## Architecture Review Checklist

Use this checklist to support the verdict. It is not a second rubric.

- [ ] The architecture is understandable from the packet.
- [ ] Drupal CMS install, setup, and site-building mechanics followed the installed `references/build-contract.md` referenced by root `AGENTS.md`, or every verified divergence from current Drupal CMS mechanics is documented as a maintainer-visible kit/upstream issue.
- [ ] Content modeling starts from goals, audiences, organizational requirements, and editor workflow, not only a source-page clone.
- [ ] Structured content first: recurring source objects are identified before import, theming, or Canvas composition.
- [ ] Generic Page or Utility Page bundles are not used for recurring content objects such as articles, releases, tracks, artists, sessions, events, venues, speakers, products, services, locations, episodes, FAQs, resources, legal notices, retailers, sponsors, taxonomy terms, or media assets.
- [ ] Lists, grids, schedules, directories, archives, catalogs, feeds, and search results are backed by structured content plus Views or another documented Drupal-native collection owner.
- [ ] Every collection route has a collection ownership ledger entry with source item count, Drupal entity/bundle owner, required fields, View or collection owner, detail route owner, and editor add-a-row evidence.
- [ ] Per-route item reconciliation compares source and target counts for repeated items such as videos, cards, events, gallery images, sponsors, posts/articles, downloads/documents, form fields, products, people, and locations.
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
- [ ] Composition modeling happened before implementation for every flexible landing-like route, and `pattern-map.json` records the selected owner, route rationale, sections, data sources, expected editor actions, and acceptance proof.
- [ ] Canvas is not treated as a route mandate for `/`; every homepage, landing, campaign, splash, section landing, and presentation-heavy page has an explicit Drupal authoring owner that fits the editor mental model.
- [ ] Repeatable collections inside composed pages remain Drupal-owned through entities, media, entity references, Views, slots, or child components backed by Drupal data.
- [ ] Any deviation from the declared composition owner or component model has a deviation record; silent fallback to theme-only composition or a blob component is not accepted.
- [ ] Canvas authoring ownership: The public homepage or landing-page composition is editable in Canvas when Canvas is the selected owner.
- [ ] Public or rebuild-owned Canvas pages have a usable rational component model, not one monolithic component wrapping the whole flexible page.
- [ ] Canvas props use typed values for singleton data and references/Views/slots/child components for repeatable data; JSON strings, newline URL lists, multi-URL string props, and body/source HTML blobs are rejected.
- [ ] Canvas component Twig does not hardcode source-owned CTA text, links, media URLs, sponsor names, section copy, or route-specific public strings that the composition model declared editor-owned.
- [ ] Canvas component inventory, slots, typed props, entity/media/View references, and repeatable-section data sources match the declared `compositionModel.canvasComponentModel`.
- [ ] Non-admin editor proof shows a meaningful declared section/component can be changed through the selected owner and the anonymous public route changes without code.
- [ ] No starter Canvas placeholder is counted as evidence for the rebuilt public route; starter Canvas pages are replaced, routed correctly, unpublished, or explicitly excluded.
- [ ] The run declares its build type: structured Drupal-native with Canvas intentionally unused, hybrid structured content plus Canvas composition, Canvas-heavy with structured data embedded, or constrained fallback because Canvas was unavailable or blocked.
- [ ] Major composed routes have section ownership records for hero copy, hero image, gallery, sponsor strip, CTA, media embeds, related items, footer CTA, and layout/order.
- [ ] Utility Page exception records exist for every public source route owned by Utility Page, including why Canvas/Experience Builder and structured content were not better owners.
- [ ] Editor-facing bundle labels are generic, portable nouns; source-site, client, brand, event, or campaign names are not exposed in content type labels unless they are part of the real content noun.
- [ ] Editor-facing bundle labels pass the cold-reader label test: they still make sense if the brand/site name changes but the content pattern stays the same.
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
- [ ] Raw iframe/script/widget markup, inline event handlers, style attributes, `javascript:` URLs, and raw source HTML in editorial fields were mechanically scanned and every remaining finding appears in `off-road-inventory.md`.
- [ ] Regulated or claim-sensitive content has source/review status, required disclosure/label text, warning/restriction fields, audience/suitability fields, and blocked-evidence notes where relevant.
- [ ] FAQ, advice/article, retailer/location, legal/footer, professional/audience-specific, and contact workflows are modeled explicitly where the source requires them.
- [ ] Media strategy is explicit: Drupal media references, source assets, unavailable assets, placeholders, or external references are not conflated.
- [ ] Public source assets use managed Media and image styles, or the packet documents why raw URI fields, CDN hotlinks, or placeholders remain.
- [ ] Alt text, responsive image styles, image reuse, and hero/thumbnail/social-image field decisions are explicit.
- [ ] Primary navigation and footer navigation are owned by Drupal menus/blocks or have a documented exception.
- [ ] Custom content types have Pathauto patterns or an explicit alias-management decision.
- [ ] The content model has one reviewable source of truth; install hooks are not the only place custom structure exists.
- [ ] The tracked config directory is the active sync directory, contains representative YAML, and has no active-to-sync drift; if Drupal exports to `web/sites/default/files/sync` or another active path, the packet names that path and does not misrepresent an empty project `config/sync` directory as authoritative.
- [ ] Site structure lives in exported configuration or a Recipe. If content types, fields, displays, Views, menus, roles, workflows, or theme settings exist only in scripts, the tracked-config handoff gate fails.
- [ ] Clean-install/import reproduction is explicitly marked evaluated or not evaluated. When claimed, command evidence proves key config such as `system.theme:default`, custom content types, fields, Views, menus, and roles import as expected; when not evaluated, the review does not claim production or launch readiness.
- [ ] The target has no custom module unless the packet proves config, recipes, maintained contrib, Views, Canvas/Experience Builder, blocks, Layout Builder, ECA, Webform, menus, aliases, theme code, and import scripts could not reasonably express the need.
- [ ] Custom modules are named for reusable Drupal capabilities, not source-site, client, brand, project, or miscellaneous helper buckets.
- [ ] Custom modules have purposeful bounded behavior, configuration or extension points where variation is likely, privacy-safe logging, and evidence for access, cacheability, sanitization, validation, and editor workflow.
- [ ] Empty marker modules are not used to imply architecture.
- [ ] Custom controllers, if present, are thin, access-controlled, cacheable, and driven by editable Drupal content/config.
- [ ] Off-road moves are inventoried and justified in `off-road-inventory.md`: custom modules/controllers/endpoints, preprocess/entity-query rendering, hardcoded copy or computed values, raw CSS/presentation fields, unfiltered formats, `accessCheck(FALSE)`, `_access: TRUE`, forced `max-age=0`, raw markup, raw SQL, one-shot derived fields, stale contrib defaults, missing Pathauto patterns, hardcoded entity IDs in config, or config that is not import-reproducible.
- [ ] Direct SQL cleanup, table purges, alias resets, or destructive import cleanup are recorded as local-only off-road moves with what changed, why Drupal APIs/config were insufficient, why it is safe in the clean workspace, and the production-safe alternative.
- [ ] Public rendering avoids unsafe raw body/source output and undocumented forced `max-age=0`.
- [ ] Moderation states, role permissions, draft/review/published/unpublished behavior, and claim-sensitive review flows are documented where relevant.
- [ ] Accessibility tooling, content accessibility report status, alt text, heading structure, contrast, embed descriptions, and manual accessibility gaps are documented.
- [ ] Site name/email, caching/aggregation, backup strategy, update readiness, security update posture, Composer-managed files, and update workflow are documented or intentionally blocked.
- [ ] Representative top-level, listing, detail, search, where-to-buy/contact/legal routes have anonymous route evidence and alias/canonicalization notes.
- [ ] Browser-first source route expansion checked likely public slugs from rendered links, source bundle route data, metadata, click targets, asset names, sitemap/robots hints, and naming patterns; curl-only evidence did not close route inventory.
- [ ] Source and target screenshots exist for the homepage, primary routes, and representative page patterns at desktop and mobile widths, with accepted exceptions or blockers named.
- [ ] Primary routes include first-fold and brand-asset parity evidence for reachable hero artwork, logo/lockup, campaign graphics, signature imagery, and primary CTA treatment.
- [ ] Visitor-facing visual parity, functional parity, homepage parity, and source-like behavior are supported by browser-rendered source/target evidence, not inferred from curl, route status, Drush, config export, Drupal readback, target-only screenshots, or prose review.
- [ ] Authenticated non-admin editor browser task evidence exists for every custom content type and load-bearing workflow, including create/edit task, fields/widgets verified, screenshots or captured evidence, result, and public output affected.
- [ ] Independent verification was performed by a fresh verifier context, subagent, review-only task, or clearly separated skeptic checklist; the same builder self-review is not counted as independent evidence.
- [ ] The independent verifier tried to falsify completion claims against the live site for per-route item counts, collection ownership, rendered embed/media presence, raw embed/markup scans, footer/legal/target-required route resolution, route drift dispositions, placeholder or starter content, Canvas placeholder leaks, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness.
- [ ] Every failed independent-verification claim is fixed, item-blocked with external evidence, or explicitly listed as a reason to reject the handoff.
- [ ] `open-decisions.md` lists only human-owned decisions and does not hide implementation work the builder could still resolve.
- [ ] Each open decision names an owner role, current evidence, options, impact if deferred, and affected gate.
- [ ] Blind adversarial review was performed by a fresh reviewer/context that did not build the target and saw only the original brief, target URL or artifact, explicit source-of-truth materials, and needed editor credentials before public/artifact review.
- [ ] The blind reviewer did not read implementation files, the review packet, builder notes, config/scripts, prior build conversation, self-authored claims, or the builder's final summary before reviewing the produced target.
- [ ] `blind-adversarial-review.json` includes desktop and mobile route notes, raw evidence under `review-packet/evidence/blind-adversarial-review/`, and a verdict of `good` or `good_enough` before any complete local rebuild claim.
- [ ] Blind route coverage includes every primary route from `route-matrix.json` at desktop and mobile widths, or `routeCoverage.omittedPrimaryRoutes` records accepted out-of-scope or external-blocker dispositions.
- [ ] Every screenshot path named in `routeViewportReviews` resolves to a real packet evidence file.
- [ ] The blind review checked the actual requested outcome, visual/interaction parity, content hierarchy, media/art fidelity, navigation, links, forms, embeds, editor/admin maintainability, accessibility, SEO, console errors, and obvious usability defects where applicable.
- [ ] Every blocker, critical, or high blind-review defect is fixed, externally blocked, or explicitly accepted as out of scope; fixed defects name the later `reviewPasses` entry that confirmed the fix.
- [ ] `acceptable_with_issues`, `not_good_enough`, or `blocked` is a reason to reject completion.
- [ ] The homepage/front page matches the browser-rendered source intent, or any redirect/canonical difference is explicitly accepted with source evidence.
- [ ] Target `/` itself was checked against browser-rendered source `/` for final URL, status, title, H1, key body intent, canonical link, screenshot, and Drupal route ownership; a correct page at another alias does not satisfy this check by itself.
- [ ] The front-page alias decision is explicit: canonical redirect, distinct Drupal display route, View/route composition, or duplication with synchronization warning.
- [ ] Every browser-rendered source route is preserved, redirected, or explicitly item-blocked; missing source routes are not hidden by a passing smoke check.
- [ ] Every browser-rendered source 200 route is classified as canonical, duplicate/alias, legacy, test/staging, private boundary, or unknown and has a target disposition.
- [ ] Starter route cleanup is complete for `/home`, `/page/1`, `/privacy-policy`, raw `/node/*`, starter Canvas pages, stale menu/footer links, duplicate aliases, and unexpected public 200 routes.
- [ ] Unexpected public 200 routes from duplicate aliases, duplicate content, stale menu links, default demo content, or route-normalization shortcuts are removed or explicitly accepted.
- [ ] Legal, privacy, footer, and menu links resolve anonymously or are explicitly blocked with next actions.
- [ ] Target-required routes introduced by the Drupal build, including privacy/legal/footer links, sitemap/robots behavior when enabled, login/admin expectations, canonical front page behavior, and locally introduced menu/footer links, resolve as intended or are blocked.
- [ ] Every same-origin link found in server-rendered response HTML resolves and is represented by accepted `routes`/`targetRequiredRoutes`, or has an exact evidence-backed disposition; direct source-origin links and expected external redirects use their exact exception records.
- [ ] JavaScript-only links were discovered through browser-executed route expansion and represented in the route matrix; the HTTP response-link check is not described as browser-DOM coverage.
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

Maintainer review is required before launch review. A positive stake-my-name record communicates the maintainer view, but the local verifier cannot authenticate it and does not use it to authorize the complete-local-rebuild machine claim.
