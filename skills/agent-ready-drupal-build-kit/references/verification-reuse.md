# Verification Reuse Experiment

The kit does not currently skip any live-verification phase. It provides an opt-in shadow experiment for the verifier-owned Global Chrome phase so maintainers can measure whether reuse could be both useful and safe before adding an actual reuse mode.

Run the normal live verifier with shadow observation enabled:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs \
  --packet review-packet \
  --reuse=shadow
```

`--reuse=shadow` always performs the same fresh browser capture. It cannot change the report, lifecycle result, completion claim, exit status, or evidence. `--reuse=actual` is rejected. Packet-only verification cannot use shadow mode.

Every shadow invocation prints a bounded diagnostic disposition. Ineligible runs name the missing remote-runtime/key/persistence prerequisite instead of silently producing no data; eligible runs report the seeded, matching, qualified, quarantined, or storage-error observation status. These messages remain non-authoritative and do not change the verifier exit.

## What The Shadow Key Covers

Shadow prediction is limited to the kit-managed remote DDEV Selenium/Chromium runtime. Local browser executions are ineligible. The pre-capture key binds digest-only representations of:

- Drupal site identity, front page, tracked configuration, active runtime facts, public entity inventory, live surface inventory, portable runtime code, and the digest-only machine-local runtime-code environment binding;
- the target origin and exact primary-route set, with the hostname hashed and query values replaced by digests in stored state;
- the normalized Global Chrome contract and route-matrix bytes;
- the pinned Selenium image/add-on, axe-core source, WebSocket bundle, runtime environment, verifier implementation, and shadow-policy version.

This is deliberately conservative, but it is not dependency-complete. External resources, time-dependent rendering, unexpected request context, Drupal cache metadata, and final browser identity are not fully known before capture. Drupal cache tags are useful supplemental invalidators; they do not replace cache contexts, cache max-age, code and configuration fingerprints, external-resource state, or browser/runtime closure. See Drupal's documentation for [cache tags](https://www.drupal.org/docs/develop/drupal-apis/cache-api/cache-tags), [cache contexts](https://www.drupal.org/docs/develop/drupal-apis/cache-api/cache-contexts), and [cache max-age](https://www.drupal.org/docs/develop/drupal-apis/cache-api/cache-max-age).

## Qualification And Quarantine

For one exact preflight key, the first strict finalized capture seeds a prediction. Two later distinct fresh captures must match both the semantic outcome fingerprint and screenshot artifact fingerprint before the key becomes `shadow-qualified`. A mismatch permanently quarantines that exact key. Concurrent updates are serialized so an exact match cannot overwrite a quarantine.

Training requires all of the following:

- the strict finalized verifier-owned capture, including its valid capture fingerprint, complete desktop/mobile contract coverage, state binding, screenshots, and axe-core result;
- the exact persisted `live-verification.json` bytes containing that capture and matching build-state fingerprint;
- the exact persisted same-run observability record and its completed attempted `global-chrome` phase;
- the prediction snapshot read before the fresh capture.

State is bounded under `.agent-ready-drupal/global-chrome-shadow-reuse/`. It stores dependency, result, and artifact fingerprints plus privacy-screened manifests—not screenshots, axe payloads, raw hostnames, or query values. Each key retains only its eight most recent observations, so report counts and timing aggregates are explicitly named as retained-window values rather than lifetime experiment totals. It has `evidenceAuthority: none`, must never enter `review-packet/`, and cannot authorize completion.

Concurrent updates use a local ownership lock. A dead same-host owner is recovered conservatively; a live, foreign-host, malformed, or ambiguous lock is never stolen. If a run reports an unreleased lock, first confirm no verifier process is active, then inspect and remove `.agent-ready-drupal/global-chrome-shadow-reuse.lock/` before rerunning the experiment.

The experiment retains at most 128 exact dependency-key namespaces and does not evict quarantines. If that ceiling is reached, preserve the JSON summary, end the current experiment, confirm no verifier process is active, and move or remove the entire `global-chrome-shadow-reuse/` directory before starting a separately reported experiment. Deleting selected quarantines and continuing the same evidence series is not valid.

## Measure Before Proposing Actual Reuse

Run at least four unchanged shadow verifications for a stable workload:

1. Seed the key.
2. Record the first exact fresh confirmation.
3. Record the second exact fresh confirmation and become shadow-qualified.
4. Run fresh again while already qualified to measure a real counterfactual.

Every observation records `freshGlobalChromePhaseMs`. `potentialAvoidablePhaseMs` remains zero during seeding and qualification and is populated only when a pre-capture prediction was already qualified and the new fresh result matched. It is a counterfactual phase duration, not realized wall-clock savings. Use `verification-observability.mjs report --json` to inspect matched workload timing, and do not sum overlapping phase durations.

Shadow mode intentionally performs an extra pre-capture runtime-code manifest scan to form the prediction key, while the verifier preserves its original late authoritative scan. The two fingerprints must match or the observation is discarded. The extra scan is recorded as `shadow-key-code-manifest`. Observability records classify otherwise matched runs as `standard` or `global-chrome-shadow`, so compare whole-run implementation medians—not only the Global Chrome counterfactual—before claiming a net benefit.

Then deliberately change configuration, runtime code, routes, contract selectors, and target/runtime inputs to confirm the key changes. Exercise dynamic or external output to confirm unexpected drift quarantines rather than qualifying. Do not add actual phase skipping until the experiment has representative matches and mismatches and a design closes the remaining external-resource, time, context, cache-metadata, and final-browser-identity gaps.
