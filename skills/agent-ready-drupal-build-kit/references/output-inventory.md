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
- `next-cycle-verification.json`
- `independent-verification.json`
- `blind-adversarial-review.json`
- `drupal-readback.json`
- `field-output-matrix.json`
- `launch-checklist.md`

## Generated Verifier Evidence

The verifier writes these files under `review-packet/evidence/`; agents do not create them by hand:

- `live-verification.json` from the default live-target-and-packet run.
- `packet-verification.json` from an explicit packet-only lint run.

After the first successful full verification, the kit also manages lifecycle evidence under `review-packet/evidence/lifecycle/`:

- `initial-baseline.json`: create-once, integrity-checked historical evidence under kit tooling for the exact initial state that passed the complete-local-rebuild bar, including its passing report, portable Drupal state components, and complete consumed packet-evidence manifest; it is not cryptographically immutable or tamper-proof.
- `current-state.json`: the last inspected cached comparison of Drupal state to the latest verified or evidence-recorded anchor; `status` reads this file and does not inspect DDEV.
- `changes/<change-id>/change.json`: create-once repair or extension intent, acceptance criteria, affected surfaces, and `baseAnchorId`; status is derived from transition records.
- `changes/<change-id>/verification.json`: integrity-bound authored evidence for an `evidence_recorded` state.
- `changes/<change-id>/full-verification.json`: optional later authoritative full report bound to the same result state.
- `changes/<change-id>/abandonment.json`: reasoned closure for a withdrawn or mistaken active intent.
- `checkpoints/<checkpoint-id>.json`: optional later full-verification checkpoints.

Lifecycle evidence is additive and is not required to structurally validate a packet created by an earlier kit version. A historical green report without a strong state fingerprint remains legacy evidence; it is not silently promoted into a baseline.

## Referenced Browser Evidence

Browser records reference instance evidence under `review-packet/evidence/browser/`; these are not additional required top-level packet files:

- `public-kit.axe-incomplete-disposition.1` binds one axe incomplete disposition to `checkedAt`, exact `targetUrl`, `ruleId`, `target`, `disposition`, `result`, and `observation`.
- `public-kit.form-outcome-evidence.1` binds a form outcome to `checkedAt`, stable `formKey`, exact `targetUrl`, `mode`, `result`, `observation`, and applicable `handlerOwner`, `resultReference`, `provider`, or `rationale`.
- `public-kit.form-abuse-evidence.1` binds the same form and target to `checkedAt`, protection `mode`, `result`, `observation`, and applicable `renderedSelector`, `configurationOwner`, `provider`, `enforcementVerified`, `localTargetVerified`, or `rationale`; implemented controls use `pass`, while a local-only exception uses `accepted_gap`.

The matching `independent-verification.json` rows must use the same detail owner config ID or form key and must independently match the browser evidence. These local records do not replace production delivery, provider credentials, privacy/retention review, or launch approval.

## Gate Checker Semantics

`gates.json` `checkedBySemantics` is the machine-readable definition of each `checkedBy` value. For `checkedBy: human` gates (`G-OPERATOR-01`, `G-TARGET-01`, `G-LAUNCH-01`, `G-MAINTAINER-01`), the packet stores human-facing status but cannot prove who entered it: every name and checkbox is builder-writable. The verifier therefore emits `recordedHumanGateStatus` with `authentication: self-attested-record-only`, reports same-string/different-string attribution without inferring identity or independence, and sets `affectsMachineCompletion: false`. Authenticated approval belongs in a separate external workflow. `G-HANDOFF-01` is a `verify-script` gate: it checks only that decisions declared human-owned are presented consistently, reports `completionEvidence.humanDecisionPresentationStatus`, and neither proves that ownership classification nor approves the decisions. Machine-evaluated exclusions and deviations can require an `acceptedBy`/owner label for packet integrity, but that label is also builder-writable; `completionEvidence.scopeDispositionAttribution` reports `builder-writable-self-attested`. Other `verify-script`, `verifier`, and `blind-verifier` gates are evaluated mechanically; their independence declarations are also builder-writable, so the verifier reports them as `self-attested` (subagent independence is allowed, labeled, and not proven).

## Gate Acceptance Criteria

`gates.json` declares whether each gate blocks local handoff or launch. These grouped criteria explain what the gate IDs mean; they do not create unnamed gates:

- `G-OPERATOR-01`: record the human-facing operator view separately from machine completion.
- `G-HANDOFF-01`: mechanically require decisions declared human-owned to be presented consistently, without proving that ownership or approving them; the classification is builder-authored and self-attested.
- `G-TARGET-01`: identify and accept a production-equivalent target before a launch claim.
- `G-ROUTE-01` through `G-ROUTE-06`: cover the full source boundary, browser-expanded routes, repeated-item counts, route drift, fetched target-required routes, front-page behavior, aliases, unexpected public routes, and Starter cleanup. A packet expectation that repeats a live `5xx` does not make that response acceptable.
- `G-BROWSER-01`, `G-BROWSER-02`, `G-DETAIL-01`, `G-A11Y-01`, `G-FORM-01`, and `G-EDITOR-01`: provide source/target browser evidence, first-fold brand assets, selector-visible required/public-output detail fields with concrete Drupal ownership and independent matching, scoped raw real-browser accessibility results with structured incomplete dispositions, stable-keyed anonymous public-form outcomes plus vendor-neutral abuse-protection evidence, and authenticated non-admin editor tasks.
- `G-EDITOR-02`: inventory recurring public models and their date, year, season, period, or taxonomy dimensions. When one exists, prove the actual least-privilege non-admin editor can use a value beyond the latest current cycle, publish future-dated content through the required workflow, expose it anonymously, and clean the probe without content, revision, alias, or term residue. Structured N/A is valid only when the default verifier's metadata-only live Drupal census confirms there are no date/datetime/year/period/season/day-like fields, cycle-like list options, or relevant taxonomy dimensions; authored packet inventories cannot establish N/A alone.
- `G-PARITY-01`: accept content, media, visual/design, functional, navigation, Views/page, form/integration, redirect, and public SEO parity for every applicable addressable surface.
- `G-CONTENT-01` and `G-CONTENT-02`: prove structured-content and collection ownership. Every declared collection row needs source/target counts, Drupal ownership, and non-admin editor add-a-row evidence; counts must match unless a recorded owner label, reason, and evidence disposition a specific exclusion, and private/unreachable boundaries need evidence. Local attribution is self-attested.
- `G-COMPOSITION-01`, `G-COMPOSITION-02`, and `G-CANVAS-01`: declare each flexible page's authoring owner and prove the actual target owner/component model matches, or record a target-bound accepted deviation with accepter attribution and evidence. The local packet does not authenticate the accepter.
- `G-RECIPE-01` and `G-CONFIG-01`: record the installed substrate and bounded Recipe decisions, then independently prove active config matches a non-empty current sync directory containing real Git-tracked YAML without drift.
- `G-SURFACE-01`: derive the bounded public/editorial Drupal surface from the current runtime before trusting packet claims. `drupal-readback.json.liveSurfaceReconciliation` must bind the current census fingerprint and exactly disposition every live bundle, View/display, alias, menu/link, redirect, Canvas page/template/component, sitemap surface, and custom extension/route as either a packet declaration or a named evidence-backed exclusion. Live-only and stale packet-only items both fail.
- `G-INTENT-01`, `G-FIELD-01`, `G-OFFROAD-01`, and `G-SEO-01`: validate durable intent, field-to-output behavior, rendered SEO, exported SEO URL portability, raw embeds, custom/off-road work, and any local-only destructive cleanup. Every custom/repeating public bundle needs a non-admin workflow; every load-bearing/anonymous-output field needs falsification; rendered SEO `not_applicable` needs reviewed rationale and evidence.
- `G-VERIFY-01`, `G-VERIFY-02`, and `G-BLIND-01`: retain independent mechanical, live-target, and blind product-review evidence.
- `G-MAINTAINER-01`: record the human-facing maintainer view separately from the machine-authorized local rebuild claim.
- `G-LAUNCH-01`: govern launch-only formal accessibility conformance, performance, security/privacy, final QA, rollback, deployment, production form delivery/abuse controls, and accepted-exception evidence beyond the browser-detectable handoff checks that the local verifier intentionally does not certify.

Generated files can identify a gate or record a blocked stub. They cannot clear a gate by themselves.

The installed skill's `scripts/verify.mjs` is the default target-local verifier. It binds the packet to the detected DDEV runtime by target origin, matching Drupal `system.site` UUID, front-page setting, config-sync directory, and clean config status; independently requires real Git-tracked YAML in that current sync directory; derives a metadata-only live Drupal surface and reconciles it bidirectionally; and runs primary, target-required, browser-representative, accepted full-surface, server-rendered link, source-origin, redirect-materialization, and applicable next-cycle cleanup checks through one verifier-wide concurrency/request/task/deadline budget. It preserves query-distinct contracts while redacting query values from its report; captures bodies only for HTML/XHTML inspection while status-checking non-HTML files; requires discovered same-origin targets to be declared or exactly dispositioned; validates external redirects without fetching their destinations; blocks unaccepted source-origin links; requires mapped source path+query routes to first return `301` or `308` and end at the exact same-origin target path+query unless a named, evidenced exception is accepted; rejects non-success responses even when the packet repeats them; checks required rendered SEO against browser evidence; re-fetches an applicable cleaned next-cycle probe URL and requires the recorded `404` or `410` with no redirect; runs semantic packet-readiness checks; and writes `review-packet/evidence/live-verification.json`. It does not execute JavaScript, so browser-only links require browser-first route expansion and route-matrix coverage. Its success does not replace authenticated editor/browser evidence, independent verification, or blind review.

The live census is capped at 5,000 stable records and emits machine identifiers, public paths, counts, status/classification metadata, and a fingerprint—not titles, body values, submissions, transactions, credentials, or broad user/file/media rows. Bundle definitions are all visible. A bundle, View/display, or menu classified non-public must use an owned exclusion rather than an ordinary declaration. Once a bundle is classified as a public editorial root, the exact-state entity closure still fingerprints all rows and bounded revisions in that bundle, including drafts and unpublished content; `publishedCount` is census metadata, not a state-fingerprint filter.

Completion readiness also fails closed when an authoritative machine-evidence file is still byte-identical to its template, JSON contains unresolved enum sentinels, critical parity/browser/readback/route acceptance markers are open, passing completion claims lack non-empty packet-local verifier evidence, a blind `accepted_out_of_scope` record lacks its required attribution/reason/evidence, or an external blocker remains. An external blocker cannot stand in for primary-route coverage. Human-facing operator, maintainer, production-target, and launch records are not machine authority and can remain pending without blocking the local machine claim. Every public-route visual comparison needs a supported method; `human_review` requires a recorded reviewer label and `pixel_diff` requires its diff artifact/score, but those labels remain self-attested. `G-HANDOFF-01` also requires each off-road row, blind/parity accepted exclusion, and route count `owner_approved_exclusion` to be linked from a substantive decision row by the exact reference token defined in `open-decisions.md`; unrelated rows and contradictory summaries fail. The verifier checks presentation consistency but does not authenticate an approver.

Independent claim evidence must be JSON with `schemaVersion: public-kit.independent-claim-evidence.1`. Each claim entry binds `claimId`, `gate`, `targetBaseUrl`, and `checkedAt` to concrete checks containing `name`, `method`, `result: pass`, and `observation`. A single evidence manifest may cover multiple claims through a `claims` array; a generic status-only file cannot clear them.

The verifier parses the machine-authoritative local-rebuild handoff records rather than trusting an appended sentence: one resolved installed-substrate and Recipe-fit decision, a dispositioned gap list, consistently presented human-only decisions or an exact none declaration, accepted off-road review, and current/explicitly empty durable intent. It reports operator, maintainer, production-target, and launch choices in `recordedHumanGateStatus`; those builder-writable fields do not mechanically authorize or block the complete-local-rebuild claim. Open-decision presentation is separate machine evidence in `completionEvidence.humanDecisionPresentationStatus` and does not mean the decisions were approved.

Once a strongly bound initial baseline exists, that original claim remains passed. Post-baseline lifecycle evidence answers a different question: whether the latest inspected state matches a known anchor, has an active change, or has an `evidence_recorded` repair or extension. Targeted completion performs a fresh live inspection and integrity-binds authored semantic evidence, but does not independently evaluate it or issue a completion certificate. Detected component impact can widen required checks and must not be narrowed. Unclassified changes leave current-state evidence open without rewriting the historical result.

Intrinsic state and environment evidence are separate. Tracked config, portable runtime code, effective active config/schema facts, declared editorial entities and revisions, managed public assets, and stable route semantics participate in the Drupal state fingerprint. Target origin/raw response evidence, verifier identity, and a digest-only machine-local environment binding are retained beside it but do not turn a local port or override change into a Drupal content change.

`scripts/verify-packet.mjs` and `verify.mjs --packet-only` are structural lint only. Packet-only data and injected test runtimes cannot authorize a complete rebuild claim.

The default `verify.mjs` exits zero only when it authorizes the complete-local-rebuild machine claim. It exits `2` with report `verdict: machine-incomplete` when packet and live-target validation are valid but required machine evidence is incomplete, and exits `1` when packet or live-target validation fails. Pending or recorded human status does not change those outcomes.

It fetches only authoritative web origins for the current DDEV project. Any explicit `--target-url URL` must match that set; configured custom FQDNs qualify, service URLs such as Mailpit do not, and cross-origin redirects are rejected before the redirected URL is requested. The verdict is complete-local-rebuild evidence, not production or launch approval.

For post-baseline work, use `scripts/lifecycle.mjs status|begin|complete|abandon`, targeted evidence, and an optional later full checkpoint. Begin before edits; use `--adopt-current` only for existing work, with conservative `unknown` impact. Refresh live state with the default verifier before `complete`. Only after evidence is recorded may `verify.mjs --change` re-evaluate and bind the current packet/live state against the full original verifier gates. See [site-lifecycle.md](site-lifecycle.md).
