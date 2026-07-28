# Agent Context Budget

Why this kit bounds what it prints and writes, what it costs when it does not,
and how to measure that honestly.

Read this before removing a cap, widening a report, or adding a file to the
review packet.

## The multiplier

Tool output can remain in an agent's active context and be carried through later
model turns. A large diagnostic is therefore not just a one-time read cost: it
can also reduce the useful context left for the build and increase later input.
The exact multiplier depends on the agent runtime, compaction behavior, and when
the output enters the session, so this repository does not use one universal
token conversion.

## What that buys

The verifier controls three independent sources of avoidable diagnostic volume:

- terminal findings are grouped into bounded families, with the largest groups
  first and explicit accounting for findings not shown;
- repeated per-gate findings are bounded only after each gate's status is
  derived from the complete finding list;
- every full report gets a bounded, `diagnostic_only` summary for the common
  agent queries, while the full report remains authoritative.

Tests bind these projections to the real report fields and require the complete
finding set to determine status. A size claim still needs a named corpus,
command, and saved measurement artifact; the mechanisms above do not depend on
one historical report size.

## Rules that follow

1. **Bound every list that can grow with site size**, and state the omission.
   `total`, `shown`, `omitted` - never a silent truncation. This is why
   `MAX_GATE_RESULT_ERRORS`, `MAX_SOURCE_CLI_FINDINGS`, `MAX_AGENT_NEXT_BLOCKERS`
   and the summary caps exist.
2. **Derive status before bounding.** A gate's outcome must come from the
   complete finding list; only the stored copy is bounded. Bounding must never
   be able to empty a non-empty list.
3. **Do not replicate complete finding sets under several keys.** Gates share
   evidence files, so one finding can legitimately be attributed to several
   gates. Preserve that attribution and a bounded set of examples, but do not
   copy the complete unbounded finding text into every gate row.
4. **A new file in the review packet is not free.** Packet contents are
   fingerprinted and bound into review handoffs. Add every regenerated verifier
   output to the shared `VERIFIER_OUTPUT_PACKET_PATHS` list consumed by all
   packet enumerators. A one-off exclusion in only one enumerator can make the
   packet and handoff fingerprints drift on every verification.
5. **Give agents a small view of a large artifact.** The authoritative report
   stays authoritative; the bounded summary beside it is `diagnostic_only` and
   authorizes nothing.

## Measuring honestly

Agent transcripts are a treacherous data source. Each of these can produce a
confident but incorrect measurement unless it is checked:

- **Resumed sessions replay history.** A resumed transcript may rewrite prior
  conversation into the new file and overstate real model turns. Replayed
  events are commonly written in a burst; cross-check candidate live turns
  against timing and tool-call counts.
- **Working directory is not a project.** Sessions run in a build directory may
  be doing unrelated work - kit development, other projects, audits under
  `/tmp`. Score a corpus for contamination before trusting it, and exclude
  commands that reach outside the directory.
- **Classify commands by argv, not by substring.** A command that *mentions*
  `verify.mjs` may be `sed`, `rg` or `git` reading its source rather than a
  verifier run.
- **Missing timing is unknown, not zero.** Treating an absent duration as 0 ms
  invents false fast-failure results.
- **Attribute bytes to one file.** Crediting a command's whole output to every
  file it names inflates per-file totals; count only unambiguous single-file
  reads and treat the result as a floor.

State which corpus a number came from and how it was filtered. A performance
claim without that is not reviewable.

## Where the cost is not

The observations that motivated this document found that Drush produced a small
share of large tool output while still consuming measurable wall time. That does
not establish that Drupal execution is never a bottleneck. It means context
volume and Drupal introspection ergonomics are separate claims that should be
measured separately. The upstream gaps are recorded in
[upstream-fixes.md](upstream-fixes.md).
