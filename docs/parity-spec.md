# Parity Spec

Parity is easy to overstate. This spec keeps parity tied to evidence.

## Addressable Surface

Define the addressable surface before scoring parity:

- public routes in scope;
- routes intentionally excluded by owner or maintainer decision;
- routes blocked by missing permission, private access, provider ownership, or unresolved redirects;
- functional behaviors in scope for the target;
- functional behaviors explicitly out of scope.

Score parity only over the approved addressable surface. Do not hide excluded or blocked routes; list them separately.

## Route Parity

A route passes only when:

- the expected target route exists;
- it returns strict HTTP 200 for the intended public visitor state;
- it is not an unintended redirect;
- it is not an access wall, login page, draft-only page, or placeholder error;
- canonical URL and title behavior are reviewed;
- route-level redirect and SEO decisions are recorded.

Do not count 3xx, 401, 403, 404, 5xx, login pages, or unpublished draft 404s as passing route parity.

## Functional Parity

Functional parity is scored against the approved behavior list, not against vague visual similarity.

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

## Visual and Content Parity

Visual and content parity require owner-approved content and production-equivalent browser evidence.

Content parity requires owner-approved source material and target Drupal evidence. Public samples may support review drafts, but they are not approved Drupal content.

## Minimum Parity Report Shape

```json
{
  "schemaVersion": "public-kit.1",
  "targetUrl": "https://target.example",
  "addressableSurface": {
    "routesInScope": 0,
    "routesExcluded": 0,
    "exclusions": []
  },
  "routeChecks": [],
  "functionalChecks": [],
  "browserEvidence": [],
  "blockedEvidence": [],
  "verdict": "blocked | partial | pass",
  "evidenceScope": "Parity applies to the approved addressable surface and evidence layers listed in this report."
}
```

## Pass Bar

A parity pass requires:

- strict route checks;
- browser-rendered evidence;
- no unresolved hard blockers in scope;
- reviewer acceptance;
- launch-gate consistency.

Anything else is partial or blocked.
