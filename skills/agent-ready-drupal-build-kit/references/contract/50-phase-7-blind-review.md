### Phase 7: Blind Adversarial Review

Before claiming a build is complete, run a blind adversarial product review in a fresh agent/context. The reviewer sees the thing the user asked for and the thing produced, not the builder's rationale.

The blind reviewer must receive only:

- `review-packet/evidence/review-handoff-blind.json`;
- any packet-local files named and byte-bound by that projection;
- any out-of-band credentials named only by the projection's credential labels when the brief requires CMS/editor experience.

That projection contains the original brief and acceptance criteria, target URLs or artifacts, explicit source-of-truth materials, and a restricted primary-route list with route paths and source-truth references only. It carries the root manifest path and exact `handoffDigest` but deliberately omits the root handoff, independent projection and file list, builder rationale, and packet claims. Do not give the blind reviewer either of the independent review inputs.

The blind reviewer must not read these before public/artifact review:

- implementation files;
- the review packet;
- prior build conversation beyond the original brief;
- builder notes, scripts, config, self-authored claims, or the builder's final summary.

The reviewer's job is to falsify completion against the brief and source-of-truth materials, not to validate the builder's checklist. The review must evaluate, as applicable:

- whether the target satisfies the user's actual requested outcome;
- visual and interaction parity against the source, design, or brief;
- desktop and mobile behavior;
- first-fold visual parity, navigation behavior, and mobile navigation;
- route-by-route content hierarchy, completeness, and editorial quality;
- media/artwork fidelity, not just asset counts;
- homepage/landing-page composition ownership and editor maintainability;
- navigation, routes, links, forms, embeds, and core workflows;
- editor/admin maintainability when the brief requires a CMS/editor experience;
- accessibility, SEO, console errors, and obvious usability defects.

Produce `review-packet/blind-adversarial-review.json` and raw evidence under `review-packet/evidence/blind-adversarial-review/`. Copy the projection's root manifest path and exact `handoffDigest` into `blind-adversarial-review.json.reviewHandoff`, and keep `reviewInputs` equal to the projection's blind `allowedInputs`. The final verifier rejects projection drift, unknown fields, changed packet-local brief/source bytes, or inputs outside the projection. The review must include desktop and mobile route notes. Any editor probe must be reversed before finalizing the review so the live target returns to the handed-off state. If a fresh blind reviewer/context is unavailable, record degraded independence honestly and leave the verdict and completion state blocked; the final verifier will not authorize completion. If the blind reviewer verdict is not clearly `good` or `good_enough`, the builder must fix the highest-impact failures and rerun blind review. A defect may be `accepted_out_of_scope` only when it records an accepter label, specific reason, and evidence. That label is self-attested packet attribution, not authenticated approval. An `external_blocker` always leaves completion blocked.

The blind review claim set comes from the brief, source-truth materials, target, and restricted route list, not the builder's preferences. A complete claim must cover every primary route in that restricted route list at desktop and mobile widths. `routeCoverage.omittedPrimaryRoutes` records why coverage is missing; it does not count as coverage. A recorded-attribution, reasoned, evidence-backed `accepted_out_of_scope` entry may remove a route from the machine-evaluated scope; authenticated human approval remains separate. An `external_blocker` leaves the verdict blocked. Each route review must use distinct, credible source and target captures for that viewport; every applicable route check must pass or be explicitly not applicable. Screenshot references must point at real files under `review-packet/evidence/blind-adversarial-review/` or another packet-local evidence path. Every product defect must have a valid severity and status; missing status is treated as open. A fixed defect must name the `reviewPasses` entry that confirmed the fix, so the artifact distinguishes rerun review from a builder-edited status.

Do not claim completion from self-authored assertions. Completion requires a blind public-site or artifact review that compares the live target visually, functionally, and editorially against the brief and source-of-truth materials on desktop and mobile.

After independent and blind verification, run the installed skill's default target-local verifier from the target workspace inside the active DDEV agent. The plain `node` command below assumes that context; from a host terminal, prefix it with `ddev exec`:

```bash
node [KIT_LOCAL_PATH]/scripts/verify.mjs --packet review-packet
```

Do not skip live verification from local cache state.

This command binds the packet to the identified live target and the current DDEV runtime by target origin, Drupal site UUID, front-page setting, config-sync directory, and clean config status. It independently requires real Git-tracked YAML in that current sync directory; derives a bounded metadata-only census of bundles/public roots, Views/displays, aliases, menus/links, redirects, Canvas pages/templates/components, sitemap surfaces, and custom extensions/routes; and requires `drupal-readback.json.liveSurfaceReconciliation` to disposition every live key exactly once as a specific packet declaration or named evidence-backed exclusion. Live-only and stale packet-only items fail. Non-public bundle/View/menu records require exclusions, while public-root bundles continue to fingerprint drafts and unpublished rows. One verifier-wide HTTP context bounds primary, target-required, browser-representative, accepted full-surface, server-rendered link, and redirect-materialization work under shared concurrency, request, task, and deadline limits; every redirect hop consumes the same request budget, and exhaustion blocks completion. Source-origin and legacy-source redirect checks additionally apply in `source_site` mode. The verifier preserves query-distinct route states while redacting query values from its report, rejects non-success responses, and checks required rendered canonical, meta-description, and `og:image` output against browser evidence. This HTTP verifier does not execute JavaScript. Links created only after JavaScript runs must be discovered through browser-first route expansion and represented in `route-matrix.json`. It then writes `review-packet/evidence/live-verification.json`. It exits zero only when all required Drupal readback, authenticated editor/browser, independent-verification, and blind-review evidence authorizes the active typed machine claim: `complete-local-rebuild` or `complete-local-build-from-brief`. Packet-only values and injected test runtimes cannot grant that authority. Exit `2` means the packet and live checks are valid but required machine evidence is incomplete; exit `1` means packet or live-target validation failed. Human-gate and independence declarations in the packet are builder-writable and reported as self-attested, not proven; recorded human status is separate and does not alter these exits.

The same live run generates a guaranteed-missing route, verifies declared access walls and rendered internal legal/privacy links through that shared HTTP budget, and reconciles active consent managers, applications, state, and controlled resources. Every application with controlled resources requires verifier-owned before-consent CDP capture for every primary route regardless of enabled or `required` status—even when Drupal identifies the resources only by selector or attachment. That browser capture uses the kit's fixed route ceiling and aggregate deadline; unavailable, incomplete, or unsettled evidence fails closed. Matching network evidence also fails unless the required application has the explicit, evidenced essential-service classification above. Packet-authored before-consent records remain diagnostic only.

Before target parity can pass, the full verifier creates a separately budgeted source route census directly from `sourceBaseUrl`. It fetches `/` and every declared primary source route, recursively follows same-origin server-rendered document links, reads `robots.txt` Sitemap directives, and traverses bounded sitemap indexes and URL sets. It records source status, final URL, title, H1, canonical, body hash, and discovery provenance without using target aliases as source facts. Every reachable public `2xx` HTML path must be an accepted route-matrix source path. Builder-authored legacy, test, intentionally-drop, or accepted-out-of-scope records cannot waive one; add and implement the route, then rerun. A `401`/`403` or persistent `404`/`410` response is immediately rechecked and may use a matching structured boundary disposition without human review. Source truncation or budget exhaustion fails closed and leaves agent-resolvable work.

Every passing independent completion claim must reference JSON evidence using `schemaVersion: public-kit.independent-claim-evidence.1`. The evidence may contain one claim or a `claims` array, but each referenced claim must match `claimId`, the completion `gate`, canonical `gateId`, the inspected `targetBaseUrl`, and `checkedAt`, with concrete checks containing `name`, `method`, `result: pass`, and an observation. A shared nonempty file or status-only record is not verifier evidence.

Completion packet readiness is semantic, not a file-presence check. The active build-input contract, pattern map, field-output matrix, target evidence, Drupal readback, recipe decision, scoped gaps, open decisions, off-road inventory, and durable intent must contain run-specific evidence. Source-site mode additionally requires authoritative source audit and parity evidence; brief mode requires a hash-bound original brief and accepted requirement matrix. Referenced browser and blind-review screenshots must be real packet-local images and match desktop/mobile dimensions; source and target captures must be distinct in source-site mode. Operator, maintainer, launch, and production-target records remain required human-facing boundaries, but their pending or recorded choices are self-attested status and do not authorize or block the narrower typed machine claim.

For explicit structural lint only, run `node [KIT_LOCAL_PATH]/scripts/verify.mjs --packet review-packet --packet-only`. It runs the same packet validator as the compatibility `verify-packet.mjs` entrypoint, writes a bounded diagnostic summary beside the authoritative full report, and advertises the summary first. Packet-only success can never authorize a complete rebuild claim.

The default verifier fetches only the detected DDEV project. An explicit `--target-url` must match one of the current project's authoritative web origins reported by DDEV, including configured custom FQDNs but excluding service URLs such as Mailpit. Redirects are never followed across origins.

This verdict covers only the active local claim: complete source-site rebuild or complete build from the accepted brief. Production deployment, hardening, credentials, legal/privacy acceptance, rollback, and launch approval remain separate gates.
