# Packet Outputs And Gates

The machine-readable source of truth is [../gates.json](../gates.json). This page explains the same output and gate vocabulary for humans; if it conflicts with `gates.json`, fix both before shipping the kit.

## Core Architecture Packet

These files must exist for every run:

- `build-input.json`: immutable mode declaration and source URL or preserved-brief binding.
- `brief-acceptance.json`: stable brief requirements, target-route acceptance checks, assumptions, exclusions, and blockers; remains an empty structured record in source-site mode.
- `source-audit.json`
- `pattern-map.json`
- `recipe-start-point.md`
- `durable-intent.yml`
- `scoped-gap-list.md`
- `open-decisions.md`
- `off-road-inventory.md`
- `maintainer-review.md`

Brief mode also preserves the user's supplied input as `original-brief.md`. Its SHA-256 must match both `build-input.json` and `brief-acceptance.json`. Source-site mode does not create this file.

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
- `negative-route-consent.json`
- `launch-checklist.md`

## Generated Verifier Evidence

The verifier writes these files under `review-packet/evidence/`; agents do not create them by hand:

- `live-verification.json` from the default live-target-and-packet run.
- `packet-verification.json` from an explicit packet-only lint run.
- `assembly-verification.json` from the optional launch-only `G-ASSEMBLY-01` runner. It proves a provenance-bound first application, two verifier-selected interrupted prefixes with verifier-owned database/file restoration, durable persistence and opaque entity-identity invariants, exact no-op reruns, and live-applicable extension survival entirely inside an exact-HEAD disposable clone. It is explicitly non-authoritative for the default handoff verdict. See [disposable-assembly.md](disposable-assembly.md).
- `reproduction-verification.json` from an optional verifier-owned, exact-HEAD disposable DDEV run for `G-REPRO-01`. It is stronger maintainer/launch evidence and is explicitly non-authoritative for the default handoff verdict. See [disposable-reproduction.md](disposable-reproduction.md).

After the first successful full verification, the kit also manages lifecycle evidence under `review-packet/evidence/lifecycle/`:

- `initial-baseline.json`: create-once, integrity-checked historical evidence under kit tooling for the exact initial state that passed its typed completion bar (`complete-local-rebuild` or `complete-local-build-from-brief`), including its passing report, portable Drupal state components, and complete consumed packet-evidence manifest; it is not cryptographically immutable or tamper-proof.
- `current-state.json`: the last inspected cached comparison of Drupal state to the latest verified or evidence-recorded anchor; `status` reads this file and does not inspect DDEV.
- `changes/<change-id>/change.json`: create-once repair or extension intent, acceptance criteria, affected surfaces, and `baseAnchorId`; status is derived from transition records.
- `changes/<change-id>/verification.json`: integrity-bound authored evidence for an `evidence_recorded` state.
- `changes/<change-id>/full-verification.json`: optional later authoritative full report bound to the same result state.
- `changes/<change-id>/abandonment.json`: reasoned closure for a withdrawn or mistaken active intent.
- `checkpoints/<checkpoint-id>.json`: optional later full-verification checkpoints.
- `chrome/anchors/<type>-<id>.json`: create-once executable global-chrome anchors for fully verified states.
- `chrome/runs/<state-prefix>/*.png`: verifier-owned desktop/mobile primary-route captures, with byte hashes and bounded-capture route/viewport/deadline metrics bound into capture and comparison records.

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
- `G-ROUTE-01` through `G-ROUTE-06`: in source-site mode, cover the full source boundary, browser-expanded routes, repeated-item counts, and route drift. In both modes, cover accepted target routes, front-page behavior, aliases, unexpected public routes, and Starter cleanup. In brief mode, accepted target routes bind to stable brief requirement IDs. A packet expectation that repeats a live `5xx` does not make that response acceptable.
- `G-BROWSER-01`, `G-BROWSER-02`, `G-DETAIL-01`, `G-A11Y-01`, `G-FORM-01`, and `G-EDITOR-01`: provide source/target browser evidence, first-fold brand assets, selector-visible required/public-output detail fields with concrete Drupal ownership and independent matching, scoped raw real-browser accessibility results with structured incomplete dispositions, stable-keyed anonymous public-form outcomes plus vendor-neutral abuse-protection evidence, and authenticated non-admin editor tasks. For every `field-output-matrix.json` field that affects anonymous output or names a public render location, the default verifier also runs a read-only Drush census: the live field definition and default form display must exist, the widget must be visible, authored widget/required metadata must match live config, browser-declared editor roles must resolve, and each role must hold `use text format <format>` for every format found on existing values of that formatted-text field.
- `G-BROWSER-01`, `G-BROWSER-02`, `G-DETAIL-01`, `G-A11Y-01`, `G-FORM-01`, and `G-EDITOR-01`: provide source/target browser evidence, first-fold brand assets, selector-visible required/public-output detail fields with concrete Drupal ownership and independent matching, verifier-owned pinned axe-core execution and raw state-bound results for every primary route at desktop/mobile widths, packet-recorded structured incomplete dispositions and manual checks, stable-keyed anonymous public-form outcomes plus vendor-neutral abuse-protection evidence, and authenticated non-admin editor tasks. Packet-authored axe passes cannot clear verifier-observed WCAG 2.2 A/AA violations or missing verifier coverage.
- `G-EDITOR-02`: inventory recurring public models and their date, year, season, period, or taxonomy dimensions. When one exists, prove the actual least-privilege non-admin editor can use a value beyond the latest current cycle, publish future-dated content through the required workflow, expose it anonymously, and clean the probe without content, revision, alias, or term residue. Structured N/A is valid only when the default verifier's metadata-only live Drupal census confirms there are no date/datetime/year/period/season/day-like fields, cycle-like list options, or relevant taxonomy dimensions; authored packet inventories cannot establish N/A alone.
- `G-PARITY-01`: accept content, media, visual/design, functional, navigation, Views/page, form/integration, redirect, and public SEO parity for every applicable addressable surface.
- `G-CONTENT-01` and `G-CONTENT-02`: prove structured-content and collection ownership. Every declared collection row needs source/target counts, Drupal ownership, and non-admin editor add-a-row evidence; counts must match unless a recorded owner label, reason, and evidence disposition a specific exclusion, and private/unreachable boundaries need evidence. Local attribution is self-attested.
- `G-COMPOSITION-01`, `G-COMPOSITION-02`, and `G-CANVAS-01`: declare each flexible page's authoring owner and prove the actual target owner/component model matches, or record a target-bound accepted deviation with accepter attribution and evidence. The local packet does not authenticate the accepter.
- `G-RECIPE-01` and `G-CONFIG-01`: record the installed substrate and bounded Recipe decisions, then independently prove active config matches a non-empty current sync directory containing real Git-tracked YAML without drift.
- `G-SURFACE-01`: derive the bounded public/editorial Drupal surface from the current runtime before trusting packet claims. `drupal-readback.json.liveSurfaceReconciliation` must bind the current census fingerprint and exactly disposition every live bundle, View/display, alias, menu/link, redirect, Canvas page/template/component, sitemap surface, and custom extension/route as either a packet declaration or a named evidence-backed exclusion. Live-only and stale packet-only items both fail.
- `G-INTENT-01`, `G-FIELD-01`, `G-OFFROAD-01`, and `G-SEO-01`: validate durable intent, field-to-output behavior, rendered SEO, exported SEO URL portability, raw embeds, custom/off-road work, and any local-only destructive cleanup. Every custom/repeating public bundle needs a non-admin workflow; every load-bearing/anonymous-output field needs falsification; rendered SEO `not_applicable` needs reviewed rationale and evidence.
- `G-PRIVACY-01`: independently probe a guaranteed-missing route, access-wall canonicals, rendered internal legal/privacy links, and active Drupal consent config. For every application with controlled resources—including selector-only and attachment-only declarations—create a fresh isolated Chrome context per primary route, record CDP `Network.requestWillBeSent` events before interaction, require a bounded observation/network-idle contract, and bind the finalized capture to the exact target, route set, budget metrics, and Drupal result-state fingerprint. Enabled and `required` status never suppress this observation. Capture is capped at 64 declared routes and one 120-second aggregate wall-clock budget. Matching requests, incomplete coverage, unsettled network, budget exhaustion, or unavailable Chrome fail closed. A required application may load before consent only with an explicit essential-without-consent classification, rationale, and packet-local evidence; `required: true` alone is not proof. Packet-authored before-consent records remain non-authoritative diagnostics.
- `G-ASSEMBLY-01`: when launch claims rely on a repeatable assembly workflow, require the separate exact-HEAD pre-assembly runner. It rejects arbitrary command surfaces and unowned deletes, preauthorizes each exact operation prefix, independently reconciles dry-run rows, restores two verifier-selected interruptions from owned database/file backups, rejects durable mutation outside verifier-derived storage surfaces, requires no-op convergence without entity identity churn, and injects fixtures on live-applicable node/Canvas/menu/alias/View/sitemap surfaces. It runs zero working-target Drupal commands and does not participate in the default handoff verdict.
- `G-REPRO-01`: optionally require an exact-HEAD, verifier-owned disposable DDEV run for launch. The dedicated host-side script accepts only fixed typed adapters and Git-tracked digest-bound inputs, distinguishes clean install/config import from snapshot restore, compares portable config/entity/file/route state, and proves the working target is unchanged. This launch gate does not participate in the default handoff verdict.
- `G-VERIFY-01`, `G-VERIFY-02`, and `G-BLIND-01`: retain independent mechanical, live-target, and blind product-review evidence.
- `G-MAINTAINER-01`: record the human-facing maintainer view separately from the machine-authorized local rebuild claim.
- `G-LAUNCH-01`: govern launch-only formal accessibility conformance, performance, security/privacy, final QA, rollback, deployment, production form delivery/abuse controls, and accepted-exception evidence beyond the browser-detectable handoff checks that the local verifier intentionally does not certify.

Generated files can identify a gate or record a blocked stub. They cannot clear a gate by themselves.

In source-site mode, the live report also contains verifier-owned `sourceSurfaceCensus` evidence gathered from `sourceBaseUrl` under explicit source-only route, sitemap, request, task, body-size, concurrency, and wall-clock budgets. The census starts from the source homepage and declared primary routes, follows same-origin server-rendered links, reads `robots.txt` Sitemap directives, and traverses bounded sitemap indexes and URL sets. It records source status, final URL, title, H1, canonical, body hash, and discovery provenance. Every reachable public source path must be represented by an accepted source route; builder-authored legacy, test/staging, or intentionally-drop records cannot clear a public route. A private or persistently unreachable path may use a matching structured boundary only after the verifier confirms the boundary response with a second request, so that boundary does not require a human review pause. In brief mode, `sourceSurfaceCensus.status` is `not_applicable`; completion instead requires the preserved brief hash, accepted requirement matrix, route bindings, and independent requirement-level evidence.

The installed skill's `scripts/verify.mjs` is the default target-local verifier. It binds the packet to the detected DDEV runtime by target origin, matching Drupal `system.site` UUID, front-page setting, config-sync directory, and clean config status; independently requires real Git-tracked YAML in that current sync directory; derives a metadata-only live Drupal surface and reconciles it bidirectionally; and runs primary, target-required, browser-representative, accepted full-surface, server-rendered link, source-origin, redirect-materialization, and applicable next-cycle cleanup checks through one verifier-wide concurrency/request/task/deadline budget. It preserves query-distinct contracts while redacting query values from its report; captures bodies only for HTML/XHTML inspection while status-checking non-HTML files; requires discovered same-origin targets to be declared or exactly dispositioned; validates external redirects without fetching their destinations; blocks unaccepted source-origin links; requires mapped source path+query routes to first return `301` or `308` and end at the exact same-origin target path+query unless a named, evidenced exception is accepted; rejects non-success responses even when the packet repeats them; checks required rendered SEO against browser evidence; re-fetches an applicable cleaned next-cycle probe URL and requires the recorded `404` or `410` with no redirect; runs semantic packet-readiness checks; and writes `review-packet/evidence/live-verification.json`. It does not execute JavaScript, so browser-only links require browser-first route expansion and route-matrix coverage. Its success does not replace authenticated editor/browser evidence, independent verification, or blind review.

The verifier's generated missing-route, access-wall, and rendered legal/privacy requests use that same HTTP context rather than a side-channel request loop. Consent absence is evaluated separately through verifier-owned CDP capture under the browser route/deadline budget; packet-authored browser transcripts remain diagnostic only.

The live census is capped at 5,000 stable records and emits machine identifiers, public paths, counts, status/classification metadata, and a fingerprint—not titles, body values, submissions, transactions, credentials, or broad user/file/media rows. Bundle definitions are all visible. A bundle, View/display, or menu classified non-public must use an owned exclusion rather than an ordinary declaration. Once a bundle is classified as a public editorial root, the exact-state entity closure still fingerprints all rows and bounded revisions in that bundle, including drafts and unpublished content; `publishedCount` is census metadata, not a state-fingerprint filter.

Completion readiness also fails closed when an authoritative machine-evidence file is still byte-identical to its template, JSON contains unresolved enum sentinels, critical parity/browser/readback/route acceptance markers are open, passing completion claims lack non-empty packet-local verifier evidence, a blind `accepted_out_of_scope` record lacks its required attribution/reason/evidence, or an external blocker remains. An external blocker cannot stand in for primary-route coverage. Human-facing operator, maintainer, production-target, and launch records are not machine authority and can remain pending without blocking the local machine claim. Every public-route visual comparison needs a supported method; `human_review` requires a recorded reviewer label and `pixel_diff` requires its diff artifact/score, but those labels remain self-attested. `G-HANDOFF-01` also requires each off-road row, blind/parity accepted exclusion, and route count `owner_approved_exclusion` to be linked from a substantive decision row by the exact reference token defined in `open-decisions.md`; unrelated rows and contradictory summaries fail. The verifier checks presentation consistency but does not authenticate an approver.

Packet-authored before-consent browser evidence uses `schemaVersion: public-kit.before-consent-evidence.1`, names the target and route, records the claimed context, and lists observed resource URLs and blocked application IDs. This remains diagnostic and cannot clear the machine gate. The live report's `beforeConsentNetworkCapture` uses `schemaVersion: public-kit.before-consent-network-capture.1` and is verifier-owned, integrity-bound evidence. A production-only legal requirement needs a named, reasoned, packet-local disposition. An actively rendered broken legal/privacy link is agent-resolvable and can never be waived as production-only.

Independent claim evidence must be JSON with `schemaVersion: public-kit.independent-claim-evidence.1`. Each claim entry binds `claimId`, `gate`, `targetBaseUrl`, and `checkedAt` to concrete checks containing `name`, `method`, `result: pass`, and `observation`. A single evidence manifest may cover multiple claims through a `claims` array; a generic status-only file cannot clear them.

The verifier parses the machine-authoritative local-rebuild handoff records rather than trusting an appended sentence: one resolved installed-substrate and Recipe-fit decision, a dispositioned gap list, consistently presented human-only decisions or an exact none declaration, accepted off-road review, and current/explicitly empty durable intent. It reports operator, maintainer, production-target, and launch choices in `recordedHumanGateStatus`; those builder-writable fields do not mechanically authorize or block the complete-local-rebuild claim. Open-decision presentation is separate machine evidence in `completionEvidence.humanDecisionPresentationStatus` and does not mean the decisions were approved.

Once a strongly bound initial baseline exists, that original claim remains passed. Post-baseline lifecycle evidence answers a different question: whether the latest inspected state matches a known anchor, has an active change, or has an `evidence_recorded` repair or extension. Targeted completion performs a fresh live inspection and integrity-binds authored semantic evidence, but does not independently evaluate it or issue a completion certificate. Its state/config/route checks and applicable global-chrome comparison are machine-evaluated: the latter uses state-bound desktop/mobile captures rather than an authored pass boolean. Detected component impact can widen required checks and must not be narrowed. Unclassified changes leave current-state evidence open without rewriting the historical result.

Intrinsic state and environment evidence are separate. Tracked config, portable runtime code, effective active config/schema facts, declared editorial entities and revisions, managed public assets, stable route semantics, and bounded critical same-origin rendered-asset byte digests participate in the Drupal state fingerprint. Target origin/raw response evidence, verifier identity, third-party asset bytes, and a digest-only machine-local environment binding are retained beside it but do not turn a local port or override change into a Drupal content change.

`scripts/verify-packet.mjs` and `verify.mjs --packet-only` are structural lint only. Packet-only data and injected test runtimes cannot authorize a complete rebuild claim.

The default `verify.mjs` exits zero only when it authorizes the complete-local-rebuild machine claim. It exits `2` with report `verdict: machine-incomplete` when packet and live-target validation are valid but required machine evidence is incomplete, and exits `1` when packet or live-target validation fails. Pending or recorded human status does not change those outcomes.

It fetches only authoritative web origins for the current DDEV project. Any explicit `--target-url URL` must match that set; configured custom FQDNs qualify, service URLs such as Mailpit do not, and cross-origin redirects are rejected before the redirected URL is requested. The verdict is complete-local-rebuild evidence, not production or launch approval.

For post-baseline work, use `scripts/lifecycle.mjs status|begin|complete|abandon`, targeted evidence, and an optional later full checkpoint. Begin before edits; use `--adopt-current` only for existing work, with conservative `unknown` impact. Refresh live state with the default verifier before `complete`. Only after evidence is recorded may `verify.mjs --change` re-evaluate and bind the current packet/live state against the full original verifier gates. See [site-lifecycle.md](site-lifecycle.md).
