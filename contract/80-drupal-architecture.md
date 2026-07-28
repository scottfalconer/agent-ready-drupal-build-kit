## Build Order

1. Audit representative public source URLs.
2. Capture browser-first source route expansion, content inventory, media inventory, design system, public behavior, and unknowns.
3. Produce the pattern map before import or build-out.
4. Record the installed Drupal CMS substrate and post-audit Recipe fit decision before building site-specific structure.
5. Define the target Drupal model: content types, fields, vocabularies, media, menus, Views, aliases, redirects, forms, integrations, SEO, accessibility, privacy, and editorial workflow.
6. Build with Drupal CMS primitives first.
7. Import or recreate reachable public content and media.
8. Implement source-like theme, layout, components, and responsive behavior.
9. Rebuild source-like public functionality.
10. Export config and record entity/readback evidence.
11. Verify public routes anonymously.
12. Verify visual, content, and functional parity in a browser.
13. Verify editor add/edit forms while logged in.
14. Produce the scoped gap list.
15. Produce the human-only open decisions handoff.
16. Run independent verification against the live site and packet; fix or block every falsified claim.
17. Package maintainer review evidence.

## Drupal CMS Baseline To Encode In The Build

Use these Drupal CMS primitives deliberately:

- Content types are templates for recurring editorial objects such as products, articles, landing pages, events, locations, FAQs, people, legal pages, or testimonials.
- Fields store structured values in specific formats. Values needed for filtering, sorting, display variants, SEO, governance, or reuse should be typed fields, taxonomy terms, entity references, links, dates, numbers, booleans, text fields, media references, or formatted text, not body blobs.
- Taxonomy is for controlled categories such as topic, condition, audience, product type, region, event type, department, or tag.
- Entity references connect content to content, content to taxonomy, and content to media.
- Views owns dynamic listings, directories, filters, related-content blocks, search-like pages, homepage collections, taxonomy landing displays, and editorial/admin listings.
- Media Library owns reusable images, videos, documents, SVGs, and other files. Media fields should carry alt text and render through Drupal image or responsive image styles where appropriate.
- Menus own navigation links. Blocks place reusable content or Views displays into theme regions. Do not hard-code primary or footer navigation in templates when Drupal menus and blocks should own it.
- Pathauto creates SEO-friendly aliases from content structure. Use Pathauto patterns or explicit aliases for canonical routes and important source-intent paths.
- Workflows and Content Moderation manage draft, needs-review, published, and unpublished states for CMS content. Use them for collaborative, regulated, or claim-sensitive content.
- Recommended add-ons are installed through Extend > Recommended (`/admin/modules/browse/recommended`) and apply preconfigured Drupal CMS features. Record any add-on applied and any prompted configuration such as API keys or identifiers.
- SEO Tools, when used, should support meta title, meta description, SEO image, Open Graph/social metadata, clean aliases, schema-supporting fields, SEO analysis, and checklist evidence.
- Accessibility Tools, when used, should provide Editoria11y inline checks and the Content Accessibility report. Record unresolved alt text, heading, contrast, link text, table, and embed issues.
- Privacy and consent features need owned footer/legal content. Drupal CMS includes a stub privacy-policy pattern; update, publish, or explicitly block privacy/legal pages rather than leaving broken footer links.
- Email should be environment-aware. In DDEV, check Mailpit/settings behavior before sending real email. Do not configure real SMTP credentials unless explicitly approved.
- Update readiness and backups are part of handoff. Record whether updates are handled by Drupal CMS UI, Composer, hosting tooling, or another process. A complete backup plan includes database, user-uploaded files, codebase, and a tested rollback procedure.

## Drupal Architecture Defaults

Build through Drupal's own APIs and tools. Used as intended, Drupal enforces access, required fields, config schema, output sanitization, cacheability, routing, and editor workflow for you. Custom code, custom markup, and one-off import logic are exceptions because they can opt out of those platform gates; when you leave the paved road, you own the checks Drupal would otherwise provide.

Use the named Drupal tool before inventing one:

- Listings, related content, search, featured/latest, directories, homepage collections, and taxonomy collections -> Views.
- Reusable information such as articles, case studies, events, people, locations, products, services, reports, FAQs, jobs, resources, glossary terms, and press releases -> nodes/content types with fields, view modes, workflow, search/indexing, and API-ready structure.
- One-off composed experiences such as homepages, campaign landing pages, conference splash pages, product launch pages, donor appeals, temporary microsites, custom partner pages, and presentation-heavy about pages -> Canvas pages / Experience Builder when available in the target. Use Blocks or Layout Builder only when Canvas is unavailable or the page pattern has a documented reason. Do not bake editor-owned regions into theme templates, Views text areas, or generic custom markup.
- Automation, derived or rollup values, on-save side effects, and light workflow -> ECA or another maintained Drupal automation tool before a custom hook module.
- Data model and relationships -> the Entity and Field APIs: content types, fields, entity references, taxonomy, computed fields, and access-checked entity queries. Do not use custom tables or raw SQL for normal content modeling.
- Structure and handoff -> Configuration Management: config is the source of truth, the tracked config directory is the active sync directory, representative YAML exists, and active config has no drift. Treat a separate clean-install/import run as additional maintainer or launch evidence, not something a clean status proves.
- Access -> roles and permissions. A content type is not done until a non-admin role can create and edit it when the editorial workflow requires that.
- Cross-cutting features -> maintained contrib or Drupal CMS recipe modules such as Media, Metatag, Pathauto, Search API, Sitemap, Content Moderation, SEO, Accessibility, Privacy, and Forms, configured against the fields the model actually has.

Default to no custom modules. Do not create catch-all modules named after the source site, client, brand, or project to hold ordinary pages, routes, templates, CSS, imports, click handlers, one-off endpoints, or miscellaneous glue. First exhaust Drupal config, recipes, maintained contrib, Views, Canvas/Experience Builder, blocks, Layout Builder, ECA, Webform, menus, aliases, theme code, and Drush/import scripts.

Use custom code only when none of these tools can reasonably express the need. If a custom module is unavoidable, make it Drupal-shaped and reusable: name it after the capability rather than the source site, expose configuration or plugins where the behavior varies, keep source-specific values in config/content, and preserve access, cacheability, sanitization, validation, logging privacy, and editor workflow. An extensible local event or click tracker with config is a better shape than a bespoke source-site endpoint hardcoded for one rebuild. Record why the native or contrib path did not fit and what evidence proves the module is maintainable.

- Model recurring source patterns as content types with human-readable field labels and useful editorial form displays.
- Editor-facing content type labels are portable nouns: `Sponsor`, `Speaker`, `Product`, `Article`, `Episode`, not `Example Sponsor` or `Brand Product`. Do not label bundles with the source site, client, brand, event, or campaign name unless the name is part of the real content type. Machine names may use a project prefix when needed to avoid collisions or follow an existing convention.
- Apply the cold-reader label test: if the brand/site name changed but the content pattern stayed the same, the editor-facing bundle label should still make sense. If not, rename the label or record why the brand is part of the actual domain concept.
- Use site-specific machine-name prefixes for custom bundles, fields, views, and vocabularies when the project does not already provide a naming convention, but keep those prefixes out of editor-facing labels.
- Use taxonomy for controlled category, topic, audience, condition, product, or location lists.
- Use managed Media entities and image styles for public source assets; use explicit placeholders or external-reference fields only when assets are private, unavailable, technically blocked, or intentionally excluded. Do not silently rely on raw URI fields, CDN hotlinks, or root-relative source image paths.
- Use Drupal menus, menu blocks, path aliases, redirects, and Pathauto patterns for navigation and route preservation.
- Keep presentation implementation out of content fields. Do not create editor fields for raw CSS declarations, gradients, style attributes, class names, HTML snippets, JavaScript, or theme implementation strings. If per-content visual variation is real editor-owned data, model it as a constrained semantic choice such as a theme variant, palette term, boolean, enum, or validated color token, and let the theme/config translate that token into CSS.
- Scan editorial fields and rendered field output for raw `<iframe>`, `<script>`, inline event handlers, `javascript:` URLs, style attributes, and raw source HTML. YouTube/Vimeo-style video should usually be Media/oEmbed. Maps, widgets, or provider-specific embeds may use typed provider fields, configured blocks, Webform/integration plugins, or documented integration stubs. Any raw embed or source markup that remains must appear in `off-road-inventory.md` with rationale, text-format/sanitization details, editor implications, and the preferred Drupal-native replacement.
- Keep source-audit and crawl-provenance data out of normal editorial forms unless the project deliberately needs an admin-only governance surface. Evidence fields that editors cannot meaningfully maintain make the content model worse.
- Export `entity_form_display` and `entity_view_display` config for every custom content type.
- Keep custom modules purposeful, reusable, bounded, and idempotent. Do not create empty marker modules or miscellaneous source-site buckets.
- Do not render source-derived body markup with unsafe raw output.

## Content, Visual, And Functional Parity Requirements

The default build goal is a complete public-facing local rebuild, not a foundation, sample, or representative subset.

- Crawl or inspect enough public routes to cover homepage, major landing pages, listing pages, detail pages, search/discovery pages, legal/footer pages, forms, embeds, and representative media.
- Import or recreate public text, titles, taxonomy/category terms, summaries, dates, links, media references, and other load-bearing content needed to review the site as a rebuild.
- Build a Drupal-owned content model behind that content. Do not hard-code the final site as theme-only markup.
- Capture the source design language: background colors, accent colors, typography scale, card/list patterns, spacing, header/nav/footer, hero sections, media/poster grids, detail-page layout, buttons, forms, responsive breakpoints, and empty/loading/error states.
- Implement the visual design in Drupal theme/templates/CSS/blocks/regions. A stock theme is acceptable only as a starting scaffold, not as the final public experience.
- Use a node when the content should survive its current presentation. Use a Canvas page when the presentation is the content. The common high-quality pattern is node = canonical data and Canvas = composed presentation: products, events, articles, case studies, and similar structured things stay nodes, while Canvas can arrange those nodes, components, CTAs, and media into rich page experiences.
- Do not build repeatable structured content as hand-assembled Canvas pages. Do not build one-off campaign composition as a tortured content type full of single-use layout fields. Views still own dynamic collections, filters, and search-like pages. Entity view displays still own repeatable detail pages. Theme templates own presentation of Drupal data, not editor-owned page composition.
- Rebuild source-like public behavior: route structure, menus, listings, filters, pagination, search, forms, embeds, video/media behavior, provider links, redirects, and canonical metadata where present.
- Verify the result in a browser. A route that returns 200 but does not look or behave like the source pattern is not complete.
- Record any unreachable, private, credentialed, or provider-owned behavior as a scoped gap with the exact missing input.

## Installed Baseline And Recipe Fit Decision

The One Line Installer has already selected the install-time substrate. Before creating site-specific config, record which of these is true:

- retain the installed Drupal CMS Starter and add bounded source-fit Recipes/overlays;
- retain a site template that was deliberately selected before installation and add bounded source-fit Recipes/overlays;
- retain another existing Drupal CMS substrate supplied by the human and extend it without replacing it;
- use bounded custom overlays because maintained Recipes do not fit the audited source patterns.

Do not treat a different full site template as a post-install start-point switch. Drupal CMS site templates are install-time starting objects. If a human deliberately wants one, select it before site installation or begin with an already installed template target; do not layer it over an established Starter rebuild.

Prefer recipe-by-construction where maintained Drupal CMS recipes fit the source pattern. Before creating a custom content type, View, workflow, or cross-cutting feature, run recipe discovery and check whether a maintained Drupal CMS recipe already owns that pattern. A matching maintained recipe is the default owner; building custom config where a matching recipe exists requires a rationale in `review-packet/recipe-start-point.md` that names the recipe, availability evidence, why it was rejected or blocked, and what bounded overlay remains.

Do not install every recipe by default. For each candidate, record whether it is applied, rejected, blocked, or not applicable and why.

Known bounded Recipe families to check in the target project include:

- `drupal_cms_admin_ui` for the Drupal CMS editorial/admin experience.
- `drupal_cms_media` for media handling.
- `drupal_cms_search` for public search/discovery.
- `drupal_cms_forms` for form-building needs.
- `drupal_cms_seo_basic` or `drupal_cms_seo_tools` for SEO metadata and checklist behavior.
- `drupal_cms_accessibility_tools` for accessibility checks such as Editoria11y/content accessibility reports.
- `drupal_cms_privacy_basic` for privacy/legal starting points.
- `drupal_cms_authentication` for login/authentication needs.
- `drupal_cms_google_analytics` only when analytics are explicitly in scope and IDs exist.
- `drupal_cms_ai` only when AI features are explicitly in scope.
- content-type recipe candidates such as `drupal_cms_events`, `drupal_cms_person`, `drupal_cms_news`, `drupal_cms_blog`, `drupal_cms_page`, `drupal_cms_project`, and `drupal_cms_case_study` when the source has matching recurring objects. Verify exact recipe names in the target before relying on them.

Verify recipe availability in the actual target with Composer/recipe discovery before relying on a recipe name. Record missing recipes as blocked or not applicable. Site-specific overlays should be small, reviewable, and tied to the pattern map.

From the DDEV Drupal project root, collect recipe evidence with commands like:

```bash
ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'
ddev exec sed -n '1,220p' recipes/drupal_cms_media/recipe.yml
```

Apply a bounded Recipe only after recording why it fits the pattern map. From the host, the Drupal core Recipe runner shape for a standard DDEV `web` docroot is:

```bash
if ddev exec test -x vendor/bin/dr; then
  ddev exec vendor/bin/dr recipe:apply recipes/drupal_cms_media -v
else
  ddev exec -d /var/www/html/web php core/scripts/drupal recipe ../recipes/drupal_cms_media -v
fi
```

Inside a DDEV agent shell, use `vendor/bin/dr recipe:apply recipes/drupal_cms_media -v` when that executable is present; otherwise run the legacy equivalent from the Drupal webroot: `cd web && php core/scripts/drupal recipe ../recipes/drupal_cms_media -v`. Replace the example with the verified Recipe path. If the discovered runner or Recipe path is missing, record the candidate as blocked or not applicable instead of inventing a command or silently replacing it with custom config.

## Content Modeling Requirements

- Start from site goals, audiences, organizational requirements, and editor workflow, not only the source page tree.
- For each recurring pattern, decide whether it is a content type, taxonomy vocabulary, media type, menu, block, View, form, or theme concern.
- For each content type, define required fields, optional fields, cardinality, field type, widget, formatter, editor help text, validation expectations, and publication workflow.
- Include separate display needs in the model. A hero image, listing thumbnail, inline image, and social-share image may be one shared media field or separate fields, but the decision must be explicit.
- Separate content fields from presentation tokens. Editors should see meaningful choices such as `Release theme`, `Hero style`, or `Accent palette`, not raw implementation fields such as `Background gradient CSS`. Store raw CSS only in theme code/config or source evidence, not in node fields.
- Do not put public navigation, footer links, CTA labels, or source-owned public copy only in Twig, templates, preprocess code, or import scripts when editors should maintain it through Drupal menus, fields, blocks, Canvas components, or config. If a string is generic UI chrome rather than source content, record that exception in the field-output matrix.
- Plan Views at the same time as the content model. Record fields for teasers, exposed filters, contextual filters, sort criteria, related-content blocks, directories, search-like pages, and editorial/admin listings.
- Use numeric/date/link/reference field types when visitors or editors need sorting, filtering, ranges, relationships, or governed reuse.
- Use taxonomy terms instead of free-text categories when categories power filters, landing pages, permissions, SEO, or governance.
- Use references between content types for related articles, products, people, locations, events, testimonials, services, resources, and calls to action.
- Model FAQ, advice/article, retailer/location, legal/footer, contact, and landing-page roles explicitly when the source has them.
