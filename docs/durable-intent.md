# Durable Intent

Durable intent records why a load-bearing Drupal decision exists.

## Current Carrier

For this public kit, durable intent is a sidecar file. Use `templates/durable-intent.template.yml`.

Do not write unsupported intent metadata into Drupal config unless the target project has an approved provider and schema for it.

## What To Record

- target config candidate;
- purpose;
- source evidence;
- decision rationale;
- reviewer status;
- config hash when available;
- last reviewed date;
- stale-intent behavior.

## Config Hash Convention

For a Drupal config object, `config_hash` is the SHA-256 of the exported YAML file in the tracked config sync directory after deleting `uuid:` and `_core:` lines and trimming trailing whitespace. Store the value as `sha256:<64 lowercase hex chars>`.

From the target Drupal project root:

```bash
sed '/^uuid: /d;/^_core:/d' config/sync/<config-name>.yml | sed 's/[[:space:]]*$//' | shasum -a 256
```

Then record the value as:

```yaml
config_hash: "sha256:<hash>"
```

If the intent record describes a behavior or external decision with no Drupal config object, set `config_hash: "not-applicable"` and explain the evidence in `source_evidence` and `rationale`.

Builders compute hashes after config export. Verifiers recompute them before trusting intent. A solo-agent run can move a record to `hash-valid` when the hash matches exported config. Only human maintainer review should move `draft` or `hash-valid` to `accepted`.

## Stale Intent Rule

If durable intent is missing, stale, mismatched, or unreviewed, treat it as no intent. Do not let stale intent guide an import, launch decision, or maintainer review.

## How Intent Is Used

Durable intent is not a decoration. It should affect later agent behavior.

Before changing a load-bearing content type, field, View, menu, workflow, alias pattern, integration decision, or custom controller:

1. Read `review-packet/durable-intent.yml`.
2. Find intent records whose `target_config` matches the config or behavior being changed.
3. If `config_hash` is present, compare it to the exported target config using the hash convention above.
4. If the hash is missing, stale, mismatched, or the intent status is neither `hash-valid` nor `accepted`, treat the record as advisory only and record that current intent is absent.
5. If the intent is current and `hash-valid`, preserve the rationale but do not treat it as human signoff.
6. If the intent is current and `accepted`, preserve the rationale or explicitly record why the new evidence supersedes it.

Example:

```text
Target change: replace events listing View with hardcoded controller cards.
Intent found: intent-events-as-content-type -> node.type.event / events_listing.
Intent says events need filtering, date sorting, related homepage blocks, and editor ownership.
Result: do not replace with hardcoded cards unless the pattern map and maintainer review approve a new decision.
```

When in doubt, fail safe: preserve Drupal-owned structured config and ask for maintainer review instead of silently flattening the model.
