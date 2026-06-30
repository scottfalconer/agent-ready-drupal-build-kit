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
- Taxonomy:
- Media:
- Media rendering and image styles:
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
- Editorial workflow:
- Moderation/workflow states and roles:
- Editor add/edit experience:
- Accessibility tooling and content report:
- Site settings, caching, backup, and update workflow:
- Regulated/claim-sensitive content governance:
- Legal/footer content model:
- Config/source-of-truth:
- Custom module/controller scope:
- Security and privacy:

## Evidence Reviewed

- Source audit:
- Pattern map:
- Durable intent:
- Production target:
- Browser QA:
- Launch gates:

## Stake-My-Name Verdict

Answer these five questions exactly. This is the canonical signoff bar used by `README.md`, `START.md`, the worked example, and this template.

- [ ] Is the build on Drupal CMS best practices using Drupal-native primitives?
- [ ] Is the architecture sound for the source site's real shape?
- [ ] Are the load-bearing decisions captured and usable by later agents?
- [ ] Are the remaining business, content, legal, integration, and launch gaps named?
- [ ] Would a Drupal maintainer put their name on this as a starting position?

## Binary Verdict

Choose exactly one:

- [ ] I would stake my name on this as a governed starting position.
- [ ] I would not stake my name on this as a governed starting position.

## Architecture Review Checklist

Use this checklist to support the five-question verdict. It is not a second rubric.

- [ ] The architecture is understandable from the packet.
- [ ] Drupal CMS install, setup, and site-building mechanics followed the encoded baseline in `AGENTS.md.template`, or every verified divergence from current Drupal CMS mechanics is documented as a maintainer-visible kit/upstream issue.
- [ ] Content modeling starts from goals, audiences, organizational requirements, and editor workflow, not only a source-page clone.
- [ ] The target model fits the load-bearing source patterns.
- [ ] Filterable, sortable, relational, governed, and reusable values are typed fields, taxonomy terms, or entity references rather than hidden in body text.
- [ ] Listings, search, and collection routes use Views or have a documented reason for custom controller ownership.
- [ ] Views were planned from the content model, including teaser fields, exposed/contextual filters, sorting, related-content blocks, and directory/search-like behavior where needed.
- [ ] Views render useful teasers, status/bundle filters, sorting, pager/filter behavior, and browser evidence for source-like collection routes.
- [ ] Search/discovery behavior is deliberate and anonymously reachable or explicitly blocked with next actions.
- [ ] SEO metadata, canonical URLs, sitemap/discovery, and editor title/description workflow are explicit or intentionally blocked.
- [ ] Open Graph/social metadata, schema.org-supporting fields, taxonomy landing pages, and internal related-content links are modeled or explicitly out of scope.
- [ ] Editor add/edit forms expose the load-bearing fields with clean human-readable labels.
- [ ] Field widgets and formatters match the field types; taxonomy/media references are not plain text fallbacks unless documented.
- [ ] Regulated or claim-sensitive content has approval/source status, required disclosure/label text, warning/restriction fields, audience/suitability fields, and blocked-evidence notes where relevant.
- [ ] FAQ, advice/article, retailer/location, legal/footer, professional/audience-specific, and contact workflows are modeled explicitly where the source requires them.
- [ ] Media strategy is explicit: Drupal media references, approved assets, placeholders, or external references are not conflated.
- [ ] Approved assets use managed Media and image styles, or the packet documents why raw URI fields, CDN hotlinks, or placeholders remain.
- [ ] Alt text, responsive image styles, image reuse, and hero/thumbnail/social-image field decisions are explicit.
- [ ] Primary navigation and footer navigation are owned by Drupal menus/blocks or have a documented exception.
- [ ] Custom content types have Pathauto patterns or an explicit alias-management decision.
- [ ] The content model has one reviewable source of truth; install hooks are not the only place custom structure exists.
- [ ] Custom modules have purposeful bounded behavior; empty marker modules are not used to imply architecture.
- [ ] Custom controllers, if present, are thin, access-controlled, cacheable, and driven by editable Drupal content/config.
- [ ] Public rendering avoids unsafe raw body/source output and undocumented forced `max-age=0`.
- [ ] Moderation states, role permissions, draft/review/published/unpublished behavior, and claim-sensitive approval flows are documented where relevant.
- [ ] Accessibility tooling, content accessibility report status, alt text, heading structure, contrast, embed descriptions, and manual accessibility gaps are documented.
- [ ] Site name/email, caching/aggregation, backup strategy, update readiness, security update posture, Composer-managed files, and update workflow are documented or intentionally blocked.
- [ ] Representative top-level, listing, detail, search, where-to-buy/contact/legal routes have anonymous route evidence and alias/canonicalization notes.
- [ ] Product, article, and legal detail routes render the expected H1/title and load-bearing fields, not only HTTP 200.
- [ ] Important source-intent routes are preserved, redirected, or explicitly retired.
- [ ] No senior Drupal maintainer would reject the approach on sight.
- [ ] Source observations are either supported by evidence or marked `UNKNOWN`.
- [ ] Recipe and configuration choices are reviewable.
- [ ] Durable intent is current or treated as absent.
- [ ] Route, content, media, integration, accessibility, performance, security, and editorial risks are explicit.
- [ ] Launch claims are blocked unless accepted evidence exists.

## Required Rationale

- Reasons to accept:
- Reasons to reject or revise:
- Anti-patterns a senior maintainer would remove:
- Restrictions or follow-up evidence required:

## Boundary

Maintainer review is required before launch claims. A positive stake-my-name verdict accepts the architecture as a starting position only; it is not owner permission, stakeholder launch approval, or production readiness.
