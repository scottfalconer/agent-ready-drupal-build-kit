# Claim Boundaries

## Allowed Claims

Use these only when supported by evidence:

- Source audit completed from public evidence.
- Pattern map drafted or approved.
- Target content model proposed.
- Recipe review packet generated.
- Disposable lab apply completed.
- Local DDEV Drupal CMS build completed.
- Production target evidence submitted.
- Browser QA batch completed.
- Launch gate clearable from accepted evidence.

## Disallowed Claims

Do not claim:

- owner permission exists unless a permission packet says so;
- Drupal CMS build success from static HTML, screenshots, or a non-Drupal local server;
- target parity exists from a source audit alone;
- production target readiness from disposable lab proof;
- launch readiness from generated packets;
- accessibility, performance, security, or privacy readiness without production-equivalent target evidence;
- maintainer acceptance without named maintainer signoff.
- functional parity from HTTP 200 alone;
- rendered parity from API success or CMS readback alone;
- successful route parity from redirects, login pages, or draft-only pages.

## Language To Prefer

- "Blocked on owner permission."
- "Ready for maintainer review."
- "Recipe packet generated."
- "DDEV Drupal CMS build evidence collected."
- "Disposable lab proof only."
- "Production target evidence missing."
- "Launch readiness blocked."
- "UNKNOWN: evidence not found."
- "Single-source observation; not enough for a load-bearing decision."

## Language To Avoid

- "Migrated."
- "Launch-ready."
- "Production-ready."
- "Better than the original."
- "Fully automated."
- "Faster than a team."
- "Verified" without naming the verifier and evidence layer.

## Four-Layer Truth Model

1. API or command success: the operation returned success.
2. CMS readback: Drupal stores and returns the expected configuration or content.
3. Public route status: the expected route returns the expected status without unintended redirects or access walls.
4. Browser-rendered truth: a browser renders the expected page state, content, interaction, metadata, and accessibility/performance/security evidence.

Do not infer a higher layer from a lower layer. A config export does not prove browser-rendered parity. A 200 route does not prove functional parity. Browser smoke does not prove launch readiness.

For local Drupal CMS work, DDEV is the default proof substrate. The minimum evidence is a DDEV URL, `ddev drush status`, exported config, anonymous route status, and browser-rendered evidence. A static preview is Layer 0: useful as a design artifact, but not CMS proof.
