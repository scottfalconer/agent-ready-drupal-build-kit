# Agent Context Budget

Why this kit bounds what it prints and writes, what it costs when it does not,
and how to measure that honestly.

Read this before removing a cap, widening a report, or adding a file to the
review packet.

## The multiplier

A token that enters an agent's context is re-sent on **every later model turn in
that session**. It is not paid once. It is paid once per turn for the remaining
life of that context.

Measured on two contamination-free build corpora, two independent ways that
agree:

- **Empirically** — cumulative billed input divided by newly generated content
  was 100x on one build and 130x on the other.
- **Structurally** — the primary session of one build showed 13 context resets
  across 3,089 live turns, so a context lives about **221 turns**. Content
  arriving at a uniform rate is therefore resent roughly 110 times.

Working figure: **1 KB of tool output costs on the order of 27,000 cumulative
input tokens.**

Supporting shape: mean context per turn was 126K-148K tokens against a 353K
window, p90 204K-253K, and 75% of turns ran above 100K.

## What that buys

Three concrete measurements from a real report generated against a live DDEV
target, all reproducible:

| change | before | after |
| --- | --- | --- |
| grouped terminal findings | 103,190 bytes / 659 lines | 5,317 bytes / 41 lines |
| bounded per-gate findings | 16,228,416-byte report | 5,249,156 bytes |
| bounded report summary | no small view | 18,379 bytes (0.11%) |

None of these changed a verdict, a claim flag, or a gate status.

## Rules that follow

1. **Bound every list that can grow with site size**, and state the omission.
   `total`, `shown`, `omitted` - never a silent truncation. This is why
   `MAX_GATE_RESULT_ERRORS`, `MAX_SOURCE_CLI_FINDINGS`, `MAX_AGENT_NEXT_BLOCKERS`
   and the summary caps exist.
2. **Derive status before bounding.** A gate's outcome must come from the
   complete finding list; only the stored copy is bounded. Bounding must never
   be able to empty a non-empty list.
3. **Do not store the same text under several keys.** Gates share evidence
   files, so one finding is legitimately attributed to several gates. Attribution
   is not duplication - in one real report 2,339 of 2,363 distinct error strings
   appeared under more than one gate, worth 4.2 MB per block.
4. **A new file in the review packet is not free.** Packet contents are
   fingerprinted and bound into review handoffs. Anything regenerated per run
   must be excluded from `packetEvidenceManifest` and from
   `REVIEW_OUTPUT_PREFIXES`, or the packet fingerprint and handoff fingerprint
   drift on every verification.
5. **Give agents a small view of a large artifact.** The authoritative report
   stays authoritative; the bounded summary beside it is `diagnostic_only` and
   authorizes nothing.

## Measuring honestly

Agent transcripts are a treacherous data source. Every one of these produced a
wrong answer during the work that led to this document, and each was caught only
by checking:

- **Resumed sessions replay history.** A resumed transcript rewrites the prior
  conversation into the new file. Raw event counts overstated real model turns
  by 89% in one corpus. Discriminator: replayed events are written in bulk, so
  inter-event gaps are ~0 ms. A genuinely live session has none. Cross-check by
  confirming live turns track tool-call counts.
- **Working directory is not a project.** Sessions run in a build directory may
  be doing unrelated work - kit development, other projects, audits under
  `/tmp`. Score a corpus for contamination before trusting it, and exclude
  commands that reach outside the directory.
- **Classify commands by argv, not by substring.** A command that *mentions*
  `verify.mjs` is usually `sed`, `rg` or `git` reading its source, not a
  verifier run. Substring matching inflated one run count from 7 to 74.
- **Missing timing is unknown, not zero.** Treating an absent duration as 0 ms
  invented a "77% of runs fail in under 2 seconds" result that did not exist.
- **Attribute bytes to one file.** Crediting a command's whole output to every
  file it names inflates per-file totals; count only unambiguous single-file
  reads and treat the result as a floor.

State which corpus a number came from and how it was filtered. A performance
claim without that is not reviewable.

## Where the cost is not

Measured across two builds: Drush accounted for about **1%** of large tool-output
volume and roughly 38 minutes of wall time. Drupal-side execution is not the
bottleneck, and optimizing it will not take hours off a long build. The gaps
worth raising upstream are recorded in [upstream-fixes.md](upstream-fixes.md).
