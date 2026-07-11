# Parity Spec

Parity is easy to overstate. This spec keeps parity tied to evidence.

## Addressable Surface

Define the addressable surface before scoring parity:

- public routes in scope;
- routes intentionally excluded by a named human or maintainer decision with reason and evidence;
- routes blocked by private access, provider ownership, or unresolved redirects, with evidence of that boundary;
- functional behaviors in scope for the target;
- functional behaviors explicitly excluded by a named human or maintainer decision with reason and evidence.

Score parity only over the accepted addressable surface. Do not hide excluded or blocked routes; list them separately. An external blocker leaves parity blocked and cannot stand in for route coverage.

## Route Parity

A route passes only when:

- the expected target route exists;
- it returns strict HTTP 200 for the intended public visitor state;
- it is not an unintended redirect;
- it is not an access wall, login page, draft-only page, or placeholder error;
- canonical URL and title behavior are reviewed;
- route-level redirect and SEO decisions are recorded.

Do not count 3xx, 401, 403, 404, 5xx, login pages, or unpublished draft 404s as passing route parity, even when the report expected the same response.

## Functional Parity

Functional parity is scored against the accepted behavior list, not against vague visual similarity.

For each behavior, record:

- source evidence;
- target implementation evidence;
- browser-rendered target evidence;
- reviewer decision;
- unresolved differences.

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

Matching counts do not establish semantic parity. Every required field in a recurring collection needs a source-derived rule for population, normalized value, field ordering, reference integrity, or placeholder absence as appropriate. Target evaluation and Drupal readback must agree on the pass/violation counts, and exceptions must be item-level and evidenced.

Media parity is role-aware. Every reachable audited asset group must reconcile to managed Drupal Media, genuine external-provider behavior, or an item-level blocker. A source icon, tracking asset, or decorative image does not become valid content media merely because it was downloaded; unresolved assets, incompatible role assignments, and unexplained duplicate placements fail parity.

Visual parity requires browser evidence for the source-like public experience: palette, typography, layout, navigation, card/detail patterns, media treatment, forms, responsive behavior, and major interaction states.

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
