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

## Stale Intent Rule

If durable intent is missing, stale, mismatched, or unreviewed, treat it as no intent. Do not let stale intent guide an import, launch decision, or maintainer review.

## How Intent Is Used

Durable intent is not a decoration. It should affect later agent behavior.

Before changing a load-bearing content type, field, View, menu, workflow, alias pattern, integration decision, or custom controller:

1. Read `review-packet/durable-intent.yml`.
2. Find intent records whose `target_config` matches the config or behavior being changed.
3. If `config_hash` is present, compare it to the exported target config.
4. If the hash is missing, stale, mismatched, or the intent status is not accepted, treat the record as advisory only and record that current intent is absent.
5. If the intent is current and accepted, preserve the rationale or explicitly record why the new evidence supersedes it.

Example:

```text
Target change: replace events listing View with hardcoded controller cards.
Intent found: intent-events-as-content-type -> node.type.event / events_listing.
Intent says events need filtering, date sorting, related homepage blocks, and editor ownership.
Result: do not replace with hardcoded cards unless the pattern map and maintainer review approve a new decision.
```

When in doubt, fail safe: preserve Drupal-owned structured config and ask for maintainer review instead of silently flattening the model.
