# High-error diagnosis benchmark

This same-state scenario measures diagnosis cost without changing the packet or
Drupal outcome. Before timing, the fixed evaluator kit initializes a real
review packet and replaces `route-matrix.json.primaryRoutes` with 300
deterministic rows carrying one invalid emitted enum value.

That one frozen defect exercises three independent mechanisms:

- repeated terminal findings (`#83`);
- repeated per-gate report storage (`#84`);
- bounded summary-first diagnostic reads (`#85`).

Run separate adjacent-revision experiments to attribute each mechanism. An
all-before versus all-after run measures only the bundle:

1. pre-`#83` versus post-`#83`;
2. post-`#83`/pre-`#84` versus post-`#84`;
3. post-`#84`/pre-`#85` versus post-`#85`.

Use one clean, fixed candidate checkout as `--evaluator-kit` in every
experiment. Start with one warm-up per arm and `ABBA`; use `ABBA-BAAB` for a
decision-quality run:

```bash
node scripts/benchmark-builds.mjs run \
  --scenario benchmarks/scenarios/high-error-diagnosis-v1/scenario.json \
  --baseline-kit /path/to/clean/baseline \
  --candidate-kit /path/to/clean/candidate \
  --evaluator-kit /path/to/clean/fixed-candidate \
  --sequence ABBA-BAAB \
  --warmups-per-arm 1 \
  --output /private/tmp/agent-ready-build-benchmark/high-error-001
```

The evaluator stdout remains the runner's all-boolean exact-quality contract.
Per-run byte counts and fingerprints are retained in
`high-error-diagnosis-evidence.json`:

- verifier stderr bytes and lines;
- authoritative report bytes;
- summary presence and bytes;
- diagnostic read events and attributable bytes;
- normalized valid, verdict, complete-error, and gate-status/count
  fingerprints.

Redundant helper reads do not change exact diagnosis quality. They remain
visible in the read-event count, attributable bytes, Codex tool-output bytes,
tokens, and wall time so the comparison can measure that inefficiency instead
of excluding it.

Do not substitute historical byte counts for a run. The mechanism gates require
the freshly generated corpus to contain at least 300 top-level errors, one
approximately 300-instance family, high-volume multi-gate fanout, and a fixed
evaluator summary with explicit omissions.

## Trust boundary

This is a host-Codex scenario for pre-reviewed trusted kit revisions only.
`workspace-write` limits writes but is not full host read isolation. The
scenario passes no arm, evaluator, experiment, or order placeholder to Codex;
blanks common credential and SSH environment variables; forbids parent, Git,
network, and credential inspection in the prompt; and fails on recognizable
forbidden patterns in logged command records as defense in depth. That audit
does not prove that no read occurred. Neither checked-in scenario is an
arbitrary-untrusted-PR sandbox; that would require a scoped credential broker
and stricter egress isolation.
