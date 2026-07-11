# Canonical Facts And Evidence Objects

The packet contains detailed domain records for editing and review, but repeated machine facts must not become competing sources of truth. The kit-owned canonical-facts generator extracts a bounded fact vocabulary from those records, rejects contradictions, and emits one deterministic key/value store plus a generated Markdown summary.

## Generate And Check

Fill `review-packet/fact-provenance.json`, then run:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/canonical-facts.mjs generate --packet review-packet
node .agents/skills/agent-ready-drupal-build-kit/scripts/canonical-facts.mjs check --packet review-packet
```

Run `generate` whenever a source fact, claim, reviewer, run, or referenced evidence file changes. The normal packet verifier recomputes the same artifacts without writing and blocks completion when the generated store is missing, stale, contradictory, or tampered.

## Source-Of-Truth Boundary

`evidence/facts/canonical-facts.json` contains each normalized site, route, config, ownership, and completion fact once. The generator compares duplicate declarations in the detailed packet and Drupal machine-readback records before choosing that value. Conflicting values fail; the generator does not silently select a preferred copy. Volatile prior live-verification output is not treated as a current fact source; the live verifier performs its own fresh runtime comparison.

`evidence/facts/summary.md` is generated deterministically from canonical facts and provenance metadata. Do not hand-edit it. Re-running with identical inputs produces identical bytes.

Detailed packet files remain the authoring surfaces for their domain schemas. The canonical store does not delete or rewrite them. It is the normalized read model and contradiction gate, not a migration that collapses all packet schemas.

## Evidence Object Store

Raw evidence bytes are copied to `evidence/objects/sha256/<64-hex-digest>`. Claims reference digests through `evidence/facts/claims.json`; `object-index.json` maps each object to claim IDs and original paths. Two claims or lifecycle changes that use identical bytes share one object.

Original evidence paths are never moved or deleted. Existing lifecycle records whose snapshots use the older per-change path remain valid. New lifecycle snapshots use the shared object store. Regeneration also leaves unreferenced existing objects in place; Git history and repository access remain the provenance boundary.

## Provenance Is Metadata, Not Evidence Bytes

`fact-provenance.json` identifies the run actor and each claim reviewer as exactly one of:

- `agent`: the current builder/reviewer agent;
- `subagent`: a child agent with `parentActorId`;
- `tool`: a named executable or service with `tool` recorded;
- `named_human`: a person who actually participated and is named by a stable identity.

Every record includes `id`, `name`, and `identityBasis`. This metadata is stored separately from object bytes, so copying a reviewer name cannot create a second evidence object or the appearance of independent evidence.

Fact claims always use `authority: evidence_observation`. `humanGateAcceptanceRecordedHere` must remain false. This store does not satisfy a `checkedBy: human` gate and does not replace the truthful human-acceptance semantics tracked by issue/PR #10. An agent-only run is valid provenance and is never required to pretend a human reviewed it.

## Contradictions

The generator fails on different normalized values for the same fact key, including:

- source or target site origins and Drupal site UUID;
- route status, final path, and acceptance;
- active/tracked config directories, clean status, and front page;
- page, composition, and section ownership;
- independent-claim and blind-review completion counts or verdicts.

Fix the underlying packet records and regenerate. Do not edit generated facts to hide the conflict.
