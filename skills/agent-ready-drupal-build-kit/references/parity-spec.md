# Parity Spec

Parity is easy to overstate. This spec keeps parity tied to evidence.

## Addressable Surface

Define the addressable surface before scoring parity:

- public routes in scope;
- routes intentionally excluded by a named human or maintainer decision with reason and evidence;
- routes blocked by private access, provider ownership, or unresolved redirects, with evidence of that boundary;
- functional behaviors in scope for the target;
- functional behaviors explicitly excluded by a named human or maintainer decision with reason and evidence.

Route discovery includes route-like references found inside imported content bodies, not only browser navigation, sitemaps, or bundle metadata. Record those candidates explicitly and classify each one before calling the inventory complete.

Score parity only over the accepted addressable surface. Do not hide excluded or blocked routes; list them separately. An external blocker leaves parity blocked and cannot stand in for route coverage.

## Route Parity

A route passes only when:

- the expected target route exists;
- it returns strict HTTP 200 for the intended public visitor state;
- it is not an unintended redirect;
- it is not an access wall, login page, draft-only page, or placeholder error;
- canonical URL and title behavior are reviewed;
- route-level redirect and SEO decisions are recorded.

When a legacy source path+query maps to a different target, parity requires a first-hop `301` or `308` ending on the exact same-origin target path+query. The only exception is a named, reasoned, packet-evidenced `noRedirectDisposition` with `accepted: true`; duplicate mapping contracts must fully agree.

Do not count 3xx, 401, 403, 404, 5xx, login pages, or unpublished draft 404s as passing route parity, even when the report expected the same response.

## Functional Parity

Functional parity is scored against the accepted behavior list, not against vague visual similarity.

For each behavior, record:

- source evidence;
- target implementation evidence;
- browser-rendered target evidence;
- reviewer decision;
- unresolved differences.

Anonymous submission forms pass only when source purpose/outcome, modeled purpose/outcome/owner, and browser purpose/owner/outcome agree, an anonymous browser exercised invalid and valid synthetic submissions, and the configured Drupal/provider handler reached the intended outcome. `other` is explicit rather than a wildcard, and storage alone does not satisfy a message-delivery form. The form also needs evidence of a rendered honeypot/challenge, configured rate limiting/provider protection, or a documented local-only exception; no particular vendor is required.

Examples:

- listing filters;
- pagination;
- event date sorting;
- media playback or embed fallback;
- forms and validation;
- search;
- account or private-content boundaries;
- redirects and canonical URLs.

## Visual And Content Parity

Visual and content parity are part of the default build goal.

Content parity requires reachable public source material to exist as Drupal-owned content, fields, taxonomy, media, menus, Views, blocks, or config. Placeholder content is acceptable only for private, credentialed, unavailable, or intentionally excluded material, and each placeholder needs boundary evidence or a named, reasoned, evidence-backed exclusion. Every declared collection needs matching source/target counts, Drupal ownership, and non-admin editor add-a-row evidence unless a named owner accepts a specific evidence-backed count exclusion.

Visual parity requires browser evidence for the source-like public experience: palette, typography, layout, navigation, card/detail patterns, media treatment, forms, responsive behavior, and major interaction states.

Each collection with separate public item details also needs one representative detail-route comparison. Its checked fields must cover required fields and fields mapped to anonymous detail output, match a concrete Drupal owner config ID across the model/browser/independent records, and prove computed visibility at field-local selectors. Every recorded public browser route needs raw axe-core output bound to the exact URL and accepted full-default or WCAG-tagged rule scope, with no unresolved WCAG A/AA violations, no incomplete nodes lacking structured exact-rule/target evidence, and applicable keyboard, focus, accessible-name, and form-error checks.

Each source form gets one stable `formKey` reused across source audit, pattern map, browser evidence, and independent verification so multiple forms on one route remain distinct. Outcome and abuse-protection evidence must be mode-specific packet-local JSON bound to that key and exact target; local mail capture or a local-only abuse exception does not establish production delivery, provider readiness, retention/privacy compliance, or launch approval.

## Minimum Parity Report Shape

```json
{
  "schemaVersion": "public-kit.parity-report.1",
  "targetUrl": "https://target.example",
  "addressableSurface": {
    "routesInScope": 0,
    "routesExcluded": 0,
    "exclusions": []
  },
  "routeChecks": [],
  "functionalChecks": [],
  "visualChecks": [],
  "contentChecks": [],
  "browserEvidence": [],
  "blockedEvidence": [],
  "verdict": "blocked | partial | pass",
  "evidenceScope": "Parity applies to the accepted addressable surface and evidence layers listed in this report."
}
```

## Pass Bar

A parity pass requires:

- strict route checks;
- browser-rendered evidence;
- content completeness evidence;
- visual/design evidence;
- functional behavior evidence;
- no unresolved hard blockers in scope;
- reviewer acceptance;
- launch-gate consistency.

Anything else is partial or blocked.

The parity pass is evidence for a complete local rebuild. It is not production or launch approval.
