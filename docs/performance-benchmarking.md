# Performance benchmarking

Build-kit performance claims must preserve the same end result. A faster failed,
incomplete, less editable, less accessible, or less verifiable site is a
regression, not an optimization.

The repository-owned runner is documented in
[`benchmarks/README.md`](../benchmarks/README.md). It deliberately stays outside
the installed Agent Skill so ordinary Drupal projects do not receive benchmark
orchestration code.

## Claim ladder

Keep these claims separate:

1. **Mechanism evidence** — bounded diagnostics and summaries emit fewer bytes
   with low processing overhead.
2. **Agent-loop evidence** — a fixed diagnosis workload uses less wall
   time, context, or tool output with the same authoritative verdict.
3. **Fresh-build evidence** — agents starting from the same ready Drupal
   substrate reach independently evaluated, quality-equivalent outcomes faster.
4. **General product evidence** — the fresh-build result repeats across multiple
   representative briefs, substrates, and balanced blocks.

Do not promote evidence up this ladder without running the next layer.

## Measurement rules

- Pin the baseline and candidate commits, evaluator commit, prompt, substrate,
  model, reasoning effort, service tier, Codex version, DDEV version, and
  relevant runtime configuration.
- Provision and warm dependencies before the timed agent boundary, while still
  recording preparation time.
- Use a fresh workspace and fresh agent thread for every measured run.
- Run arms sequentially in balanced ABBA blocks. Preserve failures rather than
  retrying or silently excluding them.
- Measure outer process wall time through independent evaluation, and retain
  agent-only build time separately. Do not sum overlapping verifier phases.
- Store missing usage or timing as `null`, never zero.
- Keep raw JSONL and command logs local. Publish bounded metrics and hashes.
- Grade both arms with the same candidate evaluator after the timed run.
- For fresh builds, compare normalized outcomes rather than volatile site UUID,
  timestamp, path, DDEV origin, or evidence identity.

The default speed decision threshold is at least a 10% and five-second median
improvement, with every adjacent pair faster and no quality or success-rate
regression. Token and agent-visible tool-output efficiency are reported as
independent dimensions with a default 10% reduction threshold. Scenarios may
raise these thresholds for long or expensive builds.

The primary speed comparison excludes commands explicitly classified as fixed
benchmark harness work. Total build time, harness time, independent evaluation,
and end-to-end outcome time remain recorded separately. A positive speed or
token/tool-output result also requires the end-to-end outcome median to remain
within the declared non-regression tolerance. A token/tool-output result can be
`efficiency-improved` only when both product-role and end-to-end outcome medians
pass that check. A material slowdown at either boundary with an efficiency win
is a `tradeoff`, while a slowdown without one is `regressed`.

The scenario `measurementBoundary` names the contiguous interval from the first
build command through evaluator completion. Product time is a separate sum of
commands marked with the product measurement role and need not be contiguous.

For the checked-in Grants pilot, the agent runs only in a disposable DDEV
container. A harness precheck performs the expensive tree and Drupal-state
comparisons, so product time contains only kit initialization and the agent
turn. Kit initialization occurs before credentials exist. The harness checks
its allowed effects, recreates the containers, removes shared network, cache,
environment, and SSH-agent surfaces, then makes one complete `auth.json` copy
available only for the measured turn. Before evaluation it removes the credential seed,
discards both mutable service containers, and starts fresh containers from the
protected project definition.

That boundary still assumes pre-reviewed trusted kit revisions: the measured
agent can read its own auth during the turn and model API egress remains. It is
not suitable for arbitrary untrusted PR code without a scoped credential broker
and egress allowlist.

## Required quality projection

The independent evaluator should retain, as applicable:

- verifier validity, verdict, build mode, and authorized claim;
- sorted gate status and structured blocker codes;
- required route coverage and meaningful detail routes;
- content-model and Views ownership;
- least-privilege editor workflow;
- clean active and exported configuration;
- desktop/mobile browser, console, overflow, and accessibility outcomes;
- source/brief requirement coverage and blind-review disposition.

The benchmark never authorizes handoff. Existing verifier reports,
verification-observability records, reproduction/assembly evidence, and browser
artifacts remain the authorities for their respective claims.

For the current verifier-output changes, run both layers:

- the Grants fresh-build scenario for bounded Drupal quality non-regression;
- a same-state high-error diagnosis scenario that invokes each arm's
  verifier and measures stderr, report/summary reads, raw tool output, tokens,
  and product time while a fixed evaluator proves identical verdict and gate
  fingerprints.

The Grants projection rejects aliases for the three Grant nodes and rejects
additional View displays or field, filter, sort, argument, relationship,
header, footer, and empty-text handlers beyond the explicit `/grants` listing
contract.
