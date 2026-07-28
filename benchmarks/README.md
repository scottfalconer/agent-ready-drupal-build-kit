# Build benchmark framework

This maintainer-only framework compares two build-kit revisions without making
the benchmark itself a source of Drupal completion authority. It records:

- separate prepare, timed build, independent evaluation, and cleanup phases;
- fresh Codex thread, token, tool-call, verifier-call, and tool-output metrics;
- exact output byte counts and hashes while keeping raw transcripts local;
- quality outcome fingerprints from one variant-independent evaluator;
- balanced ABBA ordering, adjacent paired deltas, medians, and dispersion;
- every failed, timed-out, contaminated, or quality-invalid run.

Raw artifacts belong in a new untracked directory outside the repository. The
checked-in scenario contains commands and frozen inputs, but not results.
The runner, scenario, prompt, seed inputs, arm commits, evaluator commit, raw
phase logs, and derived projections are fingerprinted. `report` re-hashes the
logs, re-derives token/tool and quality projections, rejects symlinked evidence,
and refuses interrupted or aborted experiments.

## Scenario contract

Each scenario is a JSON file with schema
`public-kit.build-benchmark-scenario.1`. Commands are argv arrays and run
without a shell. The four phases are:

1. `prepare`: create one fresh, ready substrate. This time is retained but is
   outside the primary agent measurement.
2. `build`: perform the work under comparison. One command may declare
   `"adapter": "codex-jsonl-v1"`. Build commands default to
   `"measurementRole": "product"`; fixed integrity work can declare
   `"measurementRole": "harness"`.
3. `evaluate`: run exactly one independent evaluator. It must write only this
   JSON shape to stdout:

   ```json
   {
     "schemaVersion": "public-kit.build-benchmark-quality.1",
     "valid": true,
     "outcomes": {
       "required_routes_pass": true,
       "structured_content_pass": true
     },
     "blockers": []
   }
   ```

4. `cleanup`: stop or unlist generated services even after a failed run.

The primary outcome timer starts with the first build command and ends when the
independent evaluator exits. The speed threshold uses product-role time, while
total build, fixed harness, and end-to-end outcome time remain separate. A
positive decision also requires the end-to-end outcome median to stay within
the declared non-regression tolerance. This keeps full-tree hashing and
independent evaluation from diluting the product comparison without hiding an
operational slowdown.

`measurementBoundary` describes that contiguous build-plus-evaluator outcome
interval. Product time is the sum of commands marked `measurementRole:
"product"` and may be separated by fixed harness commands.

The Grants pilot runs Codex inside a disposable DDEV web container. Nested
Linux user namespaces are not available there. The adapter removes shared
DDEV-network, SSH-agent, and cache surfaces. It runs kit initialization with no
Codex credential present. A harness precheck performs the full-tree,
Git-control, and Drupal-state comparisons outside product time. The harness
then verifies initializer effects, recreates the containers, and injects one
complete `auth.json` copy only for the measured Codex turn. Before using project
commands for evaluation, it removes the host credential seed, discards both
mutable service containers through externally validated Docker labels, and
starts fresh containers from the protected project definition.

This is not an untrusted-code sandbox: the measured agent can read its own
Codex auth while the turn is active, and model API egress remains. Use only
pre-reviewed, trusted kit revisions in disposable projects. A future
untrusted-PR service needs a scoped credential broker and egress policy.

Scenario commands may use `{repoRoot}`, `{scenarioDir}`, `{experimentDir}`,
`{experimentId}`,
`{runDir}`, `{workspace}`, `{runId}`, `{runOrdinal}`, `{scenarioId}`,
`{armId}`, `{armKit}`, `{evaluatorKit}`, and declared `{var:name}` values.
Variables are not stored as one general map, but values referenced by declared
runtime metadata are stored verbatim and process logs can echo command values.
Never use benchmark variables for secrets.

Commands adapted as `codex-jsonl-v1` must use the opaque `{workspace}` as their
working directory and cannot receive arm, kit, run, experiment, repository, or
host-workspace placeholders through argv, stdin, or environment. Scenario
adapters must also keep experiment evidence outside the agent-visible runtime.

Quality mode is `exact`: both arms must produce the same normalized outcome
fingerprint. Fresh-build evaluators must remove volatile run identity while
retaining every quality property that could regress.

## Freeze the Drupal seed

The Grants scenario requires both the canonical seed manifest fingerprint and a
complete copied-tree fingerprint. Start the intended Drupal CMS/DDEV substrate,
confirm the existing `content_editor` role and `basic_editorial` workflow, and
run:

```bash
node benchmarks/scenarios/grants-micro-v1/adapter.mjs freeze-seed \
  --seed-project /absolute/path/to/seed-project \
  --installer-sha256 <sha256-of-the-reviewed-provisioning-script>
```

This intentionally replaces
`benchmark-seed/seed.sql.gz`, writes the canonical manifest, and prints both
fingerprints. Root Git metadata and DDEV's host-generated `.ddev/traefik`
router state are neither copied nor fingerprinted. The frozen project must
contain:

- exact `composer.json` and `composer.lock` bytes;
- the DDEV Codex image, command, compose, and hook files used by the scenario;
- Drupal settings and a complete config export;
- the database export and public-file tree;
- the existing governed role/workflow substrate.

Recheck a frozen tree without changing it:

```bash
node benchmarks/scenarios/grants-micro-v1/adapter.mjs fingerprint \
  --seed-project /absolute/path/to/seed-project
```

## Run

Use isolated Git checkouts for the two revisions and the evaluator:

```bash
node scripts/benchmark-builds.mjs run \
  --scenario benchmarks/scenarios/grants-micro-v1/scenario.json \
  --baseline-kit /path/to/baseline-checkout \
  --candidate-kit /path/to/candidate-checkout \
  --evaluator-kit /path/to/candidate-checkout \
  --sequence ABBA-BAAB \
  --warmups-per-arm 1 \
  --var seedProject=/path/to/frozen-seed \
  --var seedFingerprint=<manifest-sha256> \
  --var seedTreeFingerprint=<complete-tree-sha256> \
  --output /private/tmp/agent-ready-build-benchmark/grants-001
```

`ABBA` is a pilot with two measured runs per arm. `ABBA-BAAB` supplies four per
arm and is the minimum recommended sequence for a stronger scenario-specific
claim. Run sequentially so DDEV, browser, disk, and provider contention do not
become arm-specific. Warm-ups are balanced and must pass; any failed warm-up or
cleanup aborts later runs and produces no comparison. Never delete or silently
rerun an invalid experiment.

Recompute the aggregate report without rerunning builds:

```bash
node scripts/benchmark-builds.mjs report \
  --experiment /private/tmp/agent-ready-build-benchmark/grants-001
```

The candidate is marked `improved` only when every measured run is eligible,
quality is comparable, the minimum sample is met, the median clears both
configured thresholds, and every adjacent AB/BA pair favors the candidate when
that guard is enabled.

Wall time, model tokens, and agent-visible tool-output bytes are separate
decision dimensions. `efficiency-improved` means token and/or tool-output cost
cleared its threshold while both product-role and end-to-end outcome medians
stayed within the scenario's explicit non-regression tolerance; it is not a
speed win. `productTimeNonRegressionMet` and
`outcomeTimeNonRegressionMet` report those checks independently, while
`speedNonRegressionMet` is their conjunction. The legacy
`medianImprovement*` and `medianRegression*` fields remain product-role aliases.
A token win paired with a material slowdown in either timing boundary is
`tradeoff`, not a positive headline. The default token and tool-output
thresholds are each 10%; equality never counts as an efficiency improvement. A
material slowdown without a compensating efficiency win is `regressed` and
returns a nonzero status. Quality and sample-size gates still apply.
Rendered-string command attribution is labelled heuristic; exact argv events
remain exact.

## Evidence boundary

The aggregate is scenario-specific diagnostic evidence. The evaluator must use
the current candidate verifier for both arms and derive claims from the
authoritative full report, never from a bounded diagnostic summary. New builds
may have different site UUIDs and evidence hashes; their normalized quality
projection should retain claim, gate, route, content-model, editor,
accessibility, and configuration outcomes while omitting volatile identity.

The Grants micro-build is a bounded functional/editorial non-regression layer.
It requires complete active/export parity in the frozen seed and final build,
the exact eight added config filenames plus only the role and workflow changes,
durable pre-existing state, required/cardinality/widgets/displays, workflow and
editor permissions, no Grant aliases, one default and one `/grants` page
display, exact field/filter handler sets with no sort or extra handler
collections, rendered values, committed bytes, and packet validity. It does not
establish browser, accessibility, migration completeness, or general build-kit
quality.
Verifier-output PRs also require a same-state high-error diagnosis
scenario that actually invokes the optimized live-verifier/report paths.

Use at least two layers:

- fresh Drupal builds for the user-facing outcome;
- a same-state high-error diagnosis scenario to attribute changes in terminal
  grouping, bounded gate findings, summary-first reads, and progressive
  contract disclosure.

One workload cannot establish that the kit generally speeds up Drupal builds.
