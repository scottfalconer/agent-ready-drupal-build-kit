# Scoped Gap List

## Site

- Source URL:
- Target site name:
- Target workspace:
- Date:

## Summary

Overall status: `blocked`

This gap list names what remains before the build can be considered a complete local rebuild, production-equivalent target, or launch candidate. It uses the hard launch gate vocabulary from `docs/output-inventory.md`.

Human-only decisions belong in `open-decisions.md`. Do not use this gap list or `open-decisions.md` to hide work the agent can still resolve.

## Gaps

| ID | Gate | Owner role | Current evidence | Blocked reason | Next action | Status |
| --- | --- | --- | --- | --- | --- | --- |
| GAP-001 | Independent operator run | Operator | UNKNOWN | Non-builder operator evidence missing | Record independent operator run | blocked |
| GAP-002 | Production-equivalent Drupal target | Operator | UNKNOWN | Local DDEV is not production target evidence | Submit production target record | blocked |
| GAP-003 | Full route inventory or accepted route boundary | Builder/SEO | UNKNOWN | Source-intent aliases and redirects not reviewed | Complete route inventory and route boundary | blocked |
| GAP-004 | Content parity | Builder/Editor | UNKNOWN | Public source content not fully imported or recreated as Drupal content | Complete content inventory and import/recreation evidence | blocked |
| GAP-005 | Media parity | Builder/Editor | UNKNOWN | Public media, alt text, or video/embed handling incomplete | Complete media inventory and target media evidence | blocked |
| GAP-006 | Visual/design parity | Builder/Designer | UNKNOWN | Source design language not fully captured or implemented | Complete design capture and browser visual checks | blocked |
| GAP-007 | Functional parity | Builder/QA | UNKNOWN | Source-like public behaviors not fully verified | Complete functional behavior checks | blocked |
| GAP-008 | Navigation parity | Builder/Editor | UNKNOWN | Menu ownership and source-like navigation not verified | Review menus, aliases, and navigation evidence | blocked |
| GAP-009 | Views and page parity | Builder/Maintainer | UNKNOWN | Listings/details not verified against Drupal-owned data | Review Views, detail routes, and browser evidence | blocked |
| GAP-010 | Forms and integrations | Operator/Owner | UNKNOWN | Provider credentials and privacy review missing | Confirm form destinations and provider evidence | blocked |
| GAP-011 | Redirects and SEO | SEO/Editor | UNKNOWN | Metadata, aliases, redirects, and public search behavior not verified | Review SEO/search model and redirect plan | blocked |
| GAP-012 | Accessibility | Accessibility reviewer | UNKNOWN | Automated/manual accessibility evidence missing | Run accessibility checks and record exceptions | blocked |
| GAP-013 | Performance | Operator | UNKNOWN | Production-equivalent performance evidence missing | Run target performance budget checks | blocked |
| GAP-014 | Security and privacy | Security/Legal | UNKNOWN | Security/privacy/legal review missing | Complete security/privacy/legal packet | blocked |
| GAP-015 | Editorial handoff | Editor/Owner | UNKNOWN | Editor workflow and role acceptance missing | Review editor forms, roles, workflow, and acceptance | blocked |
| GAP-016 | Durable intent validation | Maintainer | UNKNOWN | Intent hashes/status not validated against exported config | Validate durable intent or treat it as absent | blocked |
| GAP-017 | Maintainer signoff | Drupal maintainer | UNKNOWN | Binary stake-my-name verdict missing | Review architecture and packet | blocked |
| GAP-018 | Final QA | Owner/QA/Maintainer | UNKNOWN | Launch evidence and final QA missing | Complete final QA after hard gates clear | blocked |

## Build-Architecture Gaps

Use this section for important non-launch-gate blockers such as target schema review, recipe start-point uncertainty, unresolved content-model decisions, or custom-controller risk.

| ID | Area | Owner role | Current evidence | Blocked reason | Next action | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ARCH-001 | Target schema | Maintainer | UNKNOWN | Pattern map not reviewed | Review source audit and target model | blocked |
| ARCH-002 | Recipe start point | Builder/Maintainer | UNKNOWN | Recipe candidates not verified | Complete recipe start-point decision | blocked |

## Notes

- Use `UNKNOWN` only as a status/value placeholder for unresolved evidence; explain the blocker in plain language.
- Add site-specific gaps as needed.
- A gap list is a role-oriented blocker map.
