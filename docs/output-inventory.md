# Packet Outputs And Gates

The machine-readable source of truth is [../gates.json](../gates.json). This page explains the same output and gate vocabulary for humans; if it conflicts with `gates.json`, fix both before shipping the kit.

## Core Architecture Packet

These files must exist for every run:

- `source-audit.json`
- `pattern-map.json`
- `recipe-start-point.md`
- `durable-intent.yml`
- `scoped-gap-list.md`
- `open-decisions.md`
- `off-road-inventory.md`
- `maintainer-review.md`

## Gate Records

These files must also exist. Early runs should create blocked stubs when accepted evidence does not exist yet:

- `operator-run.md`
- `production-target.md`
- `parity-report.json`
- `route-matrix.json`
- `browser-evidence.json`
- `independent-verification.json`
- `blind-adversarial-review.json`
- `drupal-readback.json`
- `field-output-matrix.json`
- `launch-checklist.md`

## Generated Verifier Evidence

The verifier writes these files under `review-packet/evidence/`; agents do not create them by hand:

- `live-verification.json` from the default live-target-and-packet run.
- `packet-verification.json` from an explicit packet-only lint run.

## Referenced Browser Evidence

Browser records reference instance evidence under `review-packet/evidence/browser/`; these are not additional required top-level packet files:

- `public-kit.axe-incomplete-disposition.1` binds one axe incomplete disposition to `checkedAt`, exact `targetUrl`, `ruleId`, `target`, `disposition`, `result`, and `observation`.
- `public-kit.form-outcome-evidence.1` binds a form outcome to `checkedAt`, stable `formKey`, exact `targetUrl`, `mode`, `result`, `observation`, and applicable `handlerOwner`, `resultReference`, `provider`, or `rationale`.
- `public-kit.form-abuse-evidence.1` binds the same form and target to `checkedAt`, protection `mode`, `result`, `observation`, and applicable `renderedSelector`, `configurationOwner`, `provider`, `enforcementVerified`, `localTargetVerified`, or `rationale`; implemented controls use `pass`, while a local-only exception uses `accepted_gap`.

The matching `independent-verification.json` rows must use the same detail owner config ID or form key and must independently match the browser evidence. These local records do not replace production delivery, provider credentials, privacy/retention review, or launch approval.

## Gate Acceptance Criteria

`gates.json` declares whether each gate blocks local handoff or launch. These grouped criteria explain what the gate IDs mean; they do not create unnamed gates:

- `G-OPERATOR-01` and `G-HANDOFF-01`: record the operator run and present only genuinely human-owned open decisions.
- `G-TARGET-01`: identify and accept a production-equivalent target before a launch claim.
- `G-ROUTE-01` through `G-ROUTE-06`: cover the full source boundary, browser-expanded routes, repeated-item counts, route drift, fetched target-required routes, front-page behavior, aliases, unexpected public routes, and Starter cleanup. A packet expectation that repeats a live `5xx` does not make that response acceptable.
- `G-BROWSER-01`, `G-BROWSER-02`, `G-DETAIL-01`, `G-A11Y-01`, `G-FORM-01`, and `G-EDITOR-01`: provide source/target browser evidence, first-fold brand assets, selector-visible required/public-output detail fields with concrete Drupal ownership and independent matching, scoped raw real-browser accessibility results with structured incomplete dispositions, stable-keyed anonymous public-form outcomes plus vendor-neutral abuse-protection evidence, and authenticated non-admin editor tasks.
- `G-PARITY-01`: accept content, media, visual/design, functional, navigation, Views/page, form/integration, redirect, and public SEO parity for every applicable addressable surface.
- `G-CONTENT-01` and `G-CONTENT-02`: prove structured-content and collection ownership. Every declared collection row needs source/target counts, Drupal ownership, and non-admin editor add-a-row evidence; counts must match unless a named owner accepts a specific evidence-backed exclusion, and private/unreachable boundaries need evidence.
- `G-COMPOSITION-01`, `G-COMPOSITION-02`, and `G-CANVAS-01`: declare each flexible page's authoring owner and prove the actual target owner/component model matches, or record a target-bound accepted deviation with named acceptance and evidence.
- `G-RECIPE-01` and `G-CONFIG-01`: record the installed substrate and bounded Recipe decisions, then independently prove active config matches a non-empty current sync directory containing real Git-tracked YAML without drift.
- `G-INTENT-01`, `G-FIELD-01`, `G-OFFROAD-01`, and `G-SEO-01`: validate durable intent, field-to-output behavior, rendered SEO, exported SEO URL portability, raw embeds, custom/off-road work, and any local-only destructive cleanup. Every custom/repeating public bundle needs a non-admin workflow; every load-bearing/anonymous-output field needs falsification; rendered SEO `not_applicable` needs reviewed rationale and evidence.
- `G-VERIFY-01`, `G-VERIFY-02`, and `G-BLIND-01`: retain independent mechanical, live-target, and blind product-review evidence.
- `G-MAINTAINER-01`: record the named maintainer verdict required by the local handoff bar.
- `G-LAUNCH-01`: govern formal accessibility conformance, performance, security/privacy, final QA, rollback, deployment, production form delivery/abuse controls, and accepted-exception evidence beyond the browser-detectable handoff checks.

Generated files can identify a gate or record a blocked stub. They cannot clear a gate by themselves.

The installed skill's `scripts/verify.mjs` is the default target-local verifier. It binds the packet to the detected DDEV runtime by target origin, matching Drupal `system.site` UUID, front-page setting, config-sync directory, and clean config status; independently requires real Git-tracked YAML in that current sync directory; and runs primary, target-required, browser-representative, accepted full-surface, server-rendered link, source-origin, and redirect-materialization checks through one verifier-wide concurrency/request/task/deadline budget. It preserves query-distinct contracts while redacting query values from the report; captures bodies only for HTML/XHTML inspection while status-checking non-HTML files; requires discovered same-origin targets to be declared or exactly dispositioned; validates external redirects without fetching their destinations; blocks unaccepted source-origin links; requires mapped source path+query routes to first return `301` or `308` and end at the exact same-origin target path+query unless a named, evidenced exception is accepted; rejects non-success responses even when the packet repeats them; checks required rendered SEO against browser evidence; runs semantic packet-readiness checks; and writes `review-packet/evidence/live-verification.json`. It does not execute JavaScript, so browser-only links require browser-first route expansion and route-matrix coverage. Its success does not replace authenticated editor/browser evidence, independent verification, or blind review.

Completion readiness also fails closed when a required packet file is still byte-identical to its template, JSON contains unresolved enum sentinels, critical parity/browser/readback/route acceptance markers are open, passing completion claims lack non-empty packet-local verifier evidence, a blind `accepted_out_of_scope` record lacks named acceptance/reason/evidence, or an external blocker remains. An external blocker cannot stand in for primary-route coverage.

Independent claim evidence must be JSON with `schemaVersion: public-kit.independent-claim-evidence.1`. Each claim entry binds `claimId`, `gate`, `targetBaseUrl`, and `checkedAt` to concrete checks containing `name`, `method`, `result: pass`, and `observation`. A single evidence manifest may cover multiple claims through a `claims` array; a generic status-only file cannot clear them.

The verifier also parses the key local-rebuild handoff records rather than trusting an appended sentence: operator identity and run evidence, one resolved installed-substrate and Recipe-fit decision, a dispositioned gap list, evidence-backed human decisions or an explicit none declaration, accepted off-road review, current/explicitly empty durable intent, and a named positive maintainer verdict. `launch-checklist.md` and `production-target.md` remain required boundary records but do not mechanically authorize or block the narrower complete-local-rebuild claim.

`scripts/verify-packet.mjs` and `verify.mjs --packet-only` are structural lint only. Packet-only data and injected test runtimes cannot authorize a complete rebuild claim.

The default `verify.mjs` exits zero only when it authorizes completion, exits `2` when checks are valid but required evidence is incomplete, and exits `1` when packet or live-target validation fails.

It fetches only authoritative web origins for the current DDEV project. Any explicit `--target-url URL` must match that set; configured custom FQDNs qualify, service URLs such as Mailpit do not, and cross-origin redirects are rejected before the redirected URL is requested. The verdict is complete-local-rebuild evidence, not production or launch approval.
