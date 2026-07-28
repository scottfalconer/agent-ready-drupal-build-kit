## Site Lifecycle After The Initial Pass

The first successful full verification creates a create-once, integrity-checked historical baseline under kit tooling in `review-packet/evidence/lifecycle/`. It records the exact Drupal state inspected for the initial complete-local-rebuild claim. The initial rebuild remains done. Do not overwrite that record or reinterpret later changes as proof that the original milestone did not pass. The adjacent integrity certificate detects unsupported edits under kit tooling; it is not cryptographic immutability or tamper-proof storage.

After a baseline exists, answer two questions separately:

1. Did the initial rebuild pass? A strongly bound initial baseline remains `passed`.
2. What is known about the latest inspected derived state? It may match the historical baseline, match a later fully verified checkpoint, match an evidence-recorded change, contain an active change, or contain unclassified changes.

Before post-baseline work, inspect lifecycle state. `status` reports the last inspected cached state; it does not inspect the live Drupal runtime. Cached `status`, `begin`, and `abandon` commands may use host `node`. Every `verify.mjs` run and `lifecycle.mjs complete` performs live inspection and must run inside DDEV: use plain `node` from the active DDEV agent, as in the live examples below, or prefix the command with `ddev exec` from a host terminal:

```bash
node [KIT_LOCAL_PATH]/scripts/lifecycle.mjs status --packet review-packet
```

If `currentStateFresh` is false, run the default verifier before `begin`. Exit `2` may identify already-existing drift; classify that state explicitly with `--adopt-current`.

Classify one coherent active change before implementation:

- `repair`: corrects an omission, defect, or regression against the original rebuild contract. Reference the applicable source, route, baseline claim, or gate in its acceptance criteria.
- `extension`: adds scope that the original source rebuild did not require. Use the human's new acceptance criteria, then regression-test affected baseline surfaces.

Create the record before editing with `lifecycle.mjs begin --id <change-id> --kind repair|extension --summary "..." --acceptance "..." --route </affected-path>`. It records `baseAnchorId` from the latest fully verified or evidence-recorded anchor. Do not use the change kind as a substitute for impact analysis. Record affected content, content model, composition, global presentation, routing/navigation, access/workflow, code/dependencies, integrations, every anonymous route expected to change, and editor workflows as applicable. Use explicit `--no-public-route` only when the change intentionally has no anonymous route effect; omission of both choices is rejected. If changes already exist, use `--adopt-current` explicitly; adopted work always adds conservative `unknown` impact. If the active change will not be completed, close it with `lifecycle.mjs abandon --id <change-id> --reason "..."` rather than deleting or rewriting its record.

Canvas/PageRegion, global theme, block placement, shared entity display, menu, navigation, and detected custom-theme or public menu-link impact automatically require the machine-evaluated `global-chrome-regression` check. The live verifier uses the setup-provisioned `selenium-chrome` DDEV add-on service through Grid-proxied raw CDP to capture every primary route at desktop and mobile widths within a fixed 64-route ceiling and one aggregate capture deadline, binds the capture, managed-runtime identity, execution boundary, and budget metrics to the exact Drupal state fingerprint, and compares brand, header, navigation, footer, meaningful hrefs, mobile-menu activation, and material layout/page-height signals to the latest verified anchor. Dynamic-region selectors come from that anchor and may not intersect global chrome. Authored screenshots or pass booleans cannot clear this check. If the managed runtime is unavailable or the bounded capture cannot complete, applicable work remains blocked. Leave the agent running and run `bash .agents/skills/agent-ready-drupal-build-kit/scripts/repair-browser-runtime.sh` from a separate host terminal at the DDEV project root; do not install Chrome or set `CHROME_PATH` as a fallback.

Verification after the baseline is impact-targeted:

- always bind evidence to the current Drupal identity and exact resulting state;
- prove the declared acceptance criteria and affected anonymous routes;
- rerun editor, field-output, config, composition, accessibility, SEO, security, or code checks when the change can affect them;
- check primary-route header, navigation, footer, branding, and responsive behavior after global theme, block, display, or page-region changes;
- widen the required checks when detected component impact exceeds the declared surfaces; never remove or narrow checks selected by detected impact;
- leave the current state unclassified when detected changes are not covered by the active record.

After implementation, run the default full verifier once to refresh the exact current live-state fingerprint:

```bash
node [KIT_LOCAL_PATH]/scripts/verify.mjs --packet review-packet
```

Exit `2` can be expected while the changed state awaits lifecycle evidence. Every concrete affected route must be present in the packet's primary or target-required route matrix and pass the fresh anonymous fetch. Write a separate `public-kit.change-verification.1` JSON containing a passing evidence claim for every stable acceptance-criterion ID and every generated non-machine check. Copy `baseFingerprint` from `begin` and `resultFingerprint` from `.buildState.fingerprint` in the fresh live-verification report; the input may include `conservative-full-regression` proactively if derived impact widens. Then run `lifecycle.mjs complete --packet review-packet --id <change-id> --verification <path>`. `complete` performs its own fresh live inspection, derives the machine checks, snapshots referenced evidence bytes, and records the result as `evidence_recorded`. The authored semantic evidence is integrity-bound to the base and exact resulting fingerprints, but the kit does not independently evaluate it. It is not a new completion certificate. After abandonment, run the default verifier again and either revert leftover edits or classify them with `--adopt-current` before beginning another change.

Only after targeted evidence is recorded may `verify.mjs --packet review-packet --change <change-id>` run the conservative path. It re-evaluates the current packet/live state against the full original verifier gates and binds that report without synthesizing passing semantic checks from targeted evidence. It validates existing source, editor, independent, and blind-review artifacts rather than recreating them, so refresh any artifact whose claim can be affected before running it.

A full source crawl, full blind adversarial review, and every original editor task are not mandatory for every localized change. Rerun the evidence whose claims can be affected, or run a fresh full checkpoint when renewed whole-site confidence is warranted:

```bash
node [KIT_LOCAL_PATH]/scripts/verify.mjs --packet review-packet --change <change-id> --checkpoint <checkpoint-id>
```

A checkpoint is optional and never replaces the historical initial baseline. Do not require a Git commit as the definition of state, Canvas when the site does not use it, or production/launch gates for ordinary local extension work. Read `[KIT_LOCAL_PATH]/references/site-lifecycle.md` for the detailed lifecycle model.

## Required Review Loop

Do not treat the first working pass as final. Work in review loops until the complete local rebuild bar is met or a real blocker prevents further progress.

The default verifier's `live-verification.json` contains `agentContinuation` and structured `completionBlockers`. Treat `shouldContinue: true` as a required autonomous repair loop: fix every locally resolvable reason, refresh affected evidence, and rerun the default verifier. Do not hand off, ask for routine human review, or wait for permission merely because the verifier returned exit `1` or `2`. Pause only when `requiredAction` is `pause-and-report` and `agentMayPause` is true; that state requires every remaining blocker to be verifier-confirmed external with attempted evidence, missing input, and a next action. Only `requiredAction: handoff` authorizes handoff.

If the agent runtime has a goal, plan, review, reflection, or task-loop feature, use it. If it does not, emulate the loop with a visible checklist in the conversation or working notes.

Each loop must:

1. Build or revise one coherent slice of the Drupal site.
2. Verify the slice with the strongest available evidence: command success, Drupal readback, anonymous public route checks, browser-rendered public checks, and authenticated editor form checks where relevant.
3. Self-review against the review bar: Drupal CMS primitives, content/media completeness, visual design, public behavior, editor experience, durable intent, and scoped gaps.
4. Fix the highest-impact gaps before moving to lower-value polish.
5. Update `review-packet/` with new evidence, decisions, and blockers. Commit each coherent slice — code plus exported config — with a descriptive message; the verifier rejects an active sync directory whose YAML does not exactly match `HEAD`.
6. Before final handoff, run the independent verification pass. Fix agent-resolvable failures; record genuine external blockers and leave completion blocked.
7. Run the blind adversarial review pass. Fix agent-resolvable failures; an external blocker does not count as route coverage and leaves completion blocked.
8. Run the installed skill's default live verifier. Fix failures or hand back a blocked result. Packet-only lint is diagnostic and cannot close the rebuild.

Stop only when the local Drupal CMS site has reviewable content, media, visual design, public functionality, editor forms, and packet evidence, or when a blocker outside the local agent's control is recorded with the missing input and next action.
