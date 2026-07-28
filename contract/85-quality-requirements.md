## SEO And Discovery

- Use clean canonical aliases for editor-created routes.
- Preserve or explicitly disposition important source-intent aliases and redirects.
- Apply a maintained Drupal CMS SEO recipe for public rebuilds when available, or record why it is blocked/not applicable. Map its tokens to fields the model actually has; stock tokens pointing at missing fields silently emit empty metadata.
- Verify rendered SEO output, not only module/config presence. For one published node per public content type, fetch the anonymous page and assert a non-empty `<meta name="description">`; assert a non-empty `og:image` when the source/content type has a meaningful image. An enabled module is not evidence.
- Keep exported SEO configuration environment-portable. Metatag and schema defaults should use request-aware Drupal tokens, entity/media tokens, or intentionally external asset URLs. Do not export literal DDEV, localhost, loopback, or any current authoritative DDEV web-origin URL, including a custom FQDN, merely to make local rendered checks pass.
- Include meta title, meta description, SEO image, Open Graph/social fields, logical heading structure, and schema-supporting fields where discovery matters.
- Use taxonomy landing pages and internal related-content links when they match the source architecture.
- Define public search behavior, search permissions, indexing assumptions, noindex cases, and blocked production-search gaps.
- A 403/404 search route, duplicate alias, or detail page without expected H1/title and load-bearing fields is a handoff risk.

## Editorial Experience Requirements

Before calling a local build successful, seed and verify a real editor path. Every custom content type that holds content must be creatable and editable by a non-admin editor role, and the build must seed at least one editor user for verification. The editor-form verification must be performed logged in as that editor user, never uid=1. An administrator can do it does not pass.

Before handoff:

- every custom content type has an add form and edit form;
- load-bearing fields are visible to editors with clean human labels;
- widgets match the field types and likely editor workflow;
- raw machine names, missing labels, and translation keys are not exposed as labels;
- source-site, client, brand, event, or campaign prefixes are not exposed in normal content type labels unless they are the actual reusable content noun;
- required fields, help text, allowed values, taxonomy references, media widgets, link fields, moderation controls, URL alias controls, and SEO fields are understandable;
- editors can create or update homepage, landing, product/detail, article/advice, FAQ, retailer/location, contact, legal/footer, and navigation content when those patterns exist;
- dashboard or admin listing affordances exist for editors to find and maintain content.

Public visual plausibility is not enough. A polished static-looking page with no credible Drupal editing path is a failed Drupal CMS rebuild. A tidy Drupal architecture that does not visually and functionally resemble the source is also incomplete.

## Anonymous Public Forms

For every anonymous submission form observed on the source, assign a stable `formKey` that identifies that form rather than only its route, then reuse it exactly in `source-audit.json`, `pattern-map.json`, `browser-evidence.json`, and `independent-verification.json`. Record purpose, Drupal/provider owner, and intended outcome. Preserve that purpose and outcome through the pattern map and browser check, and bind the browser result to the modeled owner; do not downgrade message delivery to submission storage. `other` is an explicit outcome that must match end to end, not a wildcard. Test the target in an anonymous browser session with synthetic data: exercise required-field errors, confirm error focus or summary behavior, submit valid data, verify the visible success state, and prove that the configured handler reached the intended outcome. A contact form that only stores a Webform submission but has no mail/provider delivery path is incomplete.

Outcome and abuse evidence must be packet-local JSON, not a generic screenshot or status file. Outcome evidence uses `public-kit.form-outcome-evidence.1`; abuse evidence uses `public-kit.form-abuse-evidence.1`. Each binds `checkedAt`, `formKey`, exact `targetUrl`, `mode`, `result`, and `observation`, plus the handler/result reference/provider or rendered selector/config owner/enforcement/local-target fields applicable to that mode. Successful implemented controls use `result: pass`; a local-only exception uses `result: accepted_gap` plus `localTargetVerified` and rationale. Independent verification must match the same form, target, and modes. Packet lint can validate that claim's structure, but the default live verifier accepts the exception only when the exact form and selected target origins belong to the current project's authoritative DDEV web-origin set; custom FQDNs are eligible, service URLs are not. A local mail-capture sink and evidenced local-only abuse exception can satisfy local rebuild scope, but do not prove production delivery, provider credentials, retention/privacy compliance, or launch readiness. Do not require a particular CAPTCHA or security vendor.

## Browser Accessibility

The default verifier injects its pinned axe-core source before other collector mutations on every primary route at desktop and mobile widths, saves each raw report beside the state-bound Chrome screenshot, and blocks completion on missing execution, incomplete route/viewport coverage, or WCAG 2.2 A/AA violations regardless of packet-authored axe passes. Keep `browser-evidence.json` route records for structured WCAG-tagged `incomplete` dispositions and manual keyboard navigation, visible focus, accessible names/labels, and form label/error/focus behavior. Every incomplete disposition must reference `public-kit.axe-incomplete-disposition.1` evidence that binds timestamp, exact URL, rule ID, target, disposition, passing result, and observation. This handoff gate catches browser-detectable defects; it does not claim a formal accessibility certification or replace a launch audit.

## Regulated Or Claim-Sensitive Content

For healthcare, financial, legal, safety-sensitive, product-claim, or otherwise regulated sites:

- model source, review, or claim status;
- model required disclosure or label text;
- model warnings, restrictions, intended use, and audience/suitability;
- separate professional and consumer journeys when the source requires that separation;
- keep external retailer/provider links separate from internal links and record source or review status;
- record blocked evidence notes for claims, labels, dosing, guarantees, comparisons, safety statements, professional materials, and legal or medical statements;
- do not invent claims, dosage, guarantees, comparisons, legal advice, medical statements, safety statements, endorsements, or professional materials.
