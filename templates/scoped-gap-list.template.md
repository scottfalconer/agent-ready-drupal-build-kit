# Scoped Gap List

## Site

- Source URL:
- Target site name:
- Target workspace:
- Date:

## Summary

Overall status: `blocked`

This gap list names what remains before the build can be considered a trusted starting point, production-equivalent target, or launch candidate. It uses the hard launch gate vocabulary from `docs/output-inventory.md`.

## Gaps

| ID | Gate | Owner role | Current evidence | Blocked reason | Next action | Status |
| --- | --- | --- | --- | --- | --- | --- |
| GAP-001 | Owner permission | Owner | UNKNOWN | Permission status missing or incomplete | Confirm content/asset/crawl/demo permissions | blocked |
| GAP-002 | Independent operator run | Operator | UNKNOWN | Non-builder operator evidence missing | Record independent operator run | blocked |
| GAP-003 | Production-equivalent Drupal target | Operator | UNKNOWN | Local DDEV is not production target evidence | Submit production target record | blocked |
| GAP-004 | Full route inventory or accepted route boundary | Builder/SEO | UNKNOWN | Source-intent aliases and redirects not reviewed | Complete route inventory and route boundary | blocked |
| GAP-005 | Content parity | Owner/Editor | UNKNOWN | Source text/assets not approved for import | Submit owner-approved content bundle | blocked |
| GAP-006 | Media parity | Owner/Editor | UNKNOWN | Approved files and alt text missing | Approve media inventory and alt text | blocked |
| GAP-007 | Navigation parity | Builder/Editor | UNKNOWN | Menu ownership and source-like navigation not verified | Review menus, aliases, and navigation evidence | blocked |
| GAP-008 | Views and page parity | Builder/Maintainer | UNKNOWN | Listings/details not verified against Drupal-owned data | Review Views, detail routes, and browser evidence | blocked |
| GAP-009 | Forms and integrations | Operator/Owner | UNKNOWN | Provider credentials and privacy review missing | Confirm form destinations and provider evidence | blocked |
| GAP-010 | Redirects and SEO | SEO/Editor | UNKNOWN | Metadata, aliases, redirects, and public search behavior not verified | Review SEO/search model and redirect plan | blocked |
| GAP-011 | Accessibility | Accessibility reviewer | UNKNOWN | Automated/manual accessibility evidence missing | Run accessibility checks and record exceptions | blocked |
| GAP-012 | Performance | Operator | UNKNOWN | Production-equivalent performance evidence missing | Run target performance budget checks | blocked |
| GAP-013 | Security and privacy | Security/Legal | UNKNOWN | Security/privacy/legal review missing | Complete security/privacy/legal packet | blocked |
| GAP-014 | Editorial handoff | Editor/Owner | UNKNOWN | Editor workflow and role acceptance missing | Review editor forms, roles, workflow, and acceptance | blocked |
| GAP-015 | Durable intent validation | Maintainer | UNKNOWN | Intent hashes/status not validated against exported config | Validate durable intent or treat it as absent | blocked |
| GAP-016 | Maintainer signoff | Drupal maintainer | UNKNOWN | Binary stake-my-name verdict missing | Review architecture and packet | blocked |
| GAP-017 | Final QA | Owner/QA/Maintainer | UNKNOWN | Launch evidence and final QA missing | Complete final QA after hard gates clear | blocked |

## Build-Architecture Gaps

Use this section for important non-launch-gate blockers such as target schema approval, recipe start-point uncertainty, unresolved content-model decisions, or custom-controller risk.

| ID | Area | Owner role | Current evidence | Blocked reason | Next action | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ARCH-001 | Target schema | Maintainer | UNKNOWN | Pattern map not approved | Review source audit and target model | blocked |
| ARCH-002 | Recipe start point | Builder/Maintainer | UNKNOWN | Recipe candidates not verified | Complete recipe start-point decision | blocked |

## Notes

- Keep `UNKNOWN` instead of guessing.
- Add site-specific gaps as needed.
- A gap list is not launch evidence; it is a role-oriented blocker map.
