# Disposable assembly rerun verification

`verify-assembly.mjs` is the launch-only verifier for `G-ASSEMBLY-01`. It proves a narrower claim than `G-REPRO-01`: a declared assembly workflow has a machine-readable plan, converges on its first application, is an exact no-op on rerun, preserves independently inserted extension work, and recovers from verifier-selected partial interruptions. It does not participate in the default local handoff verdict.

The runner never invokes DDEV or Drupal in the working target. It reads exact Git state, creates an independent exact-`HEAD` clone with a UUID-owned `agent-ready-repro-*` DDEV identity, rejects project-controlled host hooks/custom commands and unsafe host-capability compose configuration before startup, provisions a pre-assembly substrate there, and performs every Drupal mutation in that clone. Cleanup re-confirms both the generated DDEV name and the clone's real app root immediately before deletion; if either binding fails, cleanup retains the disposable target for inspection.

## What the gate proves

One bounded run must establish all of the following:

1. `assembly-plan.json`, the provenance ledger, the fixed PHP adapter, the reproduction substrate plan, and every substrate input are Git-tracked, byte-exact to `HEAD`, and SHA-256 bound.
2. The substrate reaches a confirmed `substrateReady` barrier with clean active configuration before the assembly adapter runs. A clean-install substrate must declare `content.adapter: none`; executable content seeders are forbidden because the verifier cannot prove that a differently named wrapper did not run the assembly early. A digest-bound pre-assembly database snapshot is the seeded-data alternative.
3. Adapter `plan` output contains exactly one `create`, `update`, `delete`, or `unchanged` row for every checked-in provenance resource. Rows use a namespaced source key and either one exact config name or one UUID-bearing entity target. Titles, numeric or machine entity IDs, wildcard selectors, bulk deletion, arbitrary commands, and packet-provided argv are rejected.
4. Before the converged run, the verifier chooses two distinct partial cut points in the canonical operation stream. Each cut point is applied through the same typed `apply-prefix` mode used for the full run, is reconciled against independently read state, and is then restored with verifier-owned database and persistent-file backups. The adapter has no `failpoint` or `restore` mode.
5. Delete authorization is checked against the exact prefix before every adapter invocation. A checked-in provenance row never substitutes for explicit `--allow-owned-deletes` consent. Entity `update` must preserve opaque storage identity; a delete-and-recreate is rejected as a false update even when delete consent was supplied.
6. The full first `apply-prefix` produces exactly the independently read Drupal state transitions declared by the dry run and leaves configuration clean. At least three real mutations are required so the verifier can exercise two partial cut points.
7. A second `plan` contains only `unchanged` rows, and a full-prefix rerun leaves portable state, durable row/schema/sequence checksums, disposable runtime bindings, and every provenance entity's separate opaque storage-ID and revision-ID identities exactly equal to the first result.
8. The verifier discovers live node, menu, alias, View, Canvas, and sitemap applicability. It inserts extension-owned fixtures on every applicable declared surface, checks that fixture injection changed only the exact returned fixture targets, records opaque storage-ID/revision checksums, reruns the assembly, and requires the whole state, persistence guard, storage identities, and every fixture target to remain unchanged. This detects delete-and-recreate or gratuitous new-revision churn even when a UUID and visible fields are copied back. An applicable surface declared `not_applicable`, or a declared surface unavailable in the substrate, fails closed.
9. One aggregate command, elapsed-time, and output budget covers provisioning, readback, adapter runs, fixture work, restoration, and cleanup, with an explicit reserve for identity-safe cleanup and the final working-source proof. The disposable clone's tracked, nonignored-untracked, and full runtime-code/environment bindings—including ignored local runtime settings—must remain unchanged across every partial, full, and no-op cycle.

The generated report includes all dry-run rows, live capability facts, before/after inventories and fingerprints, independently derived changes, fixture survival rows, restoration comparison, command argv with output digests, the aggregate budget, cleanup result, and proof that zero working-target DDEV commands ran.

## Files

Create these project-local, Git-tracked inputs:

- `assembly-plan.json` — the typed verifier contract;
- `assembly-provenance.json` — the complete assembly-owned resource ledger;
- one PHP adapter implementing `drush_assembly_contract_v2`;
- the `reproduction-plan.json` substrate contract described in [disposable-reproduction.md](disposable-reproduction.md), plus its bound inputs.

All paths are project-relative. Machine-local files, symlinks, untracked files, dirty versions that differ from `HEAD`, and absolute paths are rejected.

## Assembly plan

```json
{
  "schemaVersion": "public-kit.assembly-plan.1",
  "assemblyId": "site_assembly",
  "substratePlan": {
    "path": "reproduction-plan.json",
    "sha256": "sha256:<digest-of-file>"
  },
  "provenance": {
    "path": "assembly-provenance.json",
    "sha256": "sha256:<digest-of-file>"
  },
  "deletion": {
    "policy": "provenance_owned_only"
  },
  "adapter": {
    "protocol": "drush_assembly_contract_v2",
    "source": {
      "path": "scripts/site-assembly.php",
      "sha256": "sha256:<digest-of-file>"
    },
    "failureProof": "verifier_controlled_restoration"
  },
  "extensionFixtures": {
    "node": { "status": "required", "bundle": "page" },
    "menu": { "status": "required", "menuName": "main" },
    "alias": { "status": "required" },
    "view": { "status": "required" },
    "canvas": {
      "status": "required",
      "pageEntityType": "canvas_page",
      "pageBundle": "",
      "componentConfigName": "canvas.component.block.views_block.events"
    },
    "sitemap": {
      "status": "required",
      "configName": "simple_sitemap.type.default"
    }
  }
}
```

Use `{ "status": "not_applicable" }` only when that surface is truly absent from the live pre-assembly substrate. Applicability is verifier-derived; the declaration cannot hide an installed surface. Canvas requires both a creatable UUID-bearing page entity type and one exact existing component config to receive an extension-owned marker. Sitemap requires one exact existing sitemap config.

## Provenance ledger and dry-run output

The checked-in ledger names the only targets the adapter owns:

```json
{
  "schemaVersion": "public-kit.assembly-provenance.1",
  "assemblyId": "site_assembly",
  "namespace": "site_import",
  "resources": [
    {
      "sourceKey": "site_import:page/home",
      "surface": "node",
      "target": {
        "kind": "entity",
        "entityType": "node",
        "stableId": "uuid:11111111-1111-4111-8111-111111111111"
      }
    },
    {
      "sourceKey": "site_import:page/about",
      "surface": "node",
      "target": {
        "kind": "entity",
        "entityType": "node",
        "stableId": "uuid:22222222-2222-4222-8222-222222222222"
      }
    },
    {
      "sourceKey": "site_import:view/events",
      "surface": "view",
      "target": { "kind": "config", "name": "views.view.events" }
    }
  ]
}
```

`plan` mode must write only this JSON shape to stdout:

```json
{
  "schemaVersion": "public-kit.assembly-dry-run.1",
  "assemblyId": "site_assembly",
  "operations": [
    {
      "action": "create",
      "sourceKey": "site_import:page/home",
      "surface": "node",
      "target": {
        "kind": "entity",
        "entityType": "node",
        "stableId": "uuid:11111111-1111-4111-8111-111111111111"
      }
    },
    {
      "action": "create",
      "sourceKey": "site_import:page/about",
      "surface": "node",
      "target": {
        "kind": "entity",
        "entityType": "node",
        "stableId": "uuid:22222222-2222-4222-8222-222222222222"
      }
    },
    {
      "action": "create",
      "sourceKey": "site_import:view/events",
      "surface": "view",
      "target": { "kind": "config", "name": "views.view.events" }
    }
  ],
  "summary": {
    "create": 3,
    "update": 0,
    "delete": 0,
    "unchanged": 0,
    "total": 3
  }
}
```

The dry run is untrusted input. The verifier derives the actual config/entity/file/route transition after `apply-prefix` and rejects missing, extra, differently classified, or out-of-order changes.

Restorable provenance target forms are:

- `{ "kind": "config", "name": "one.exact.config_name" }`
- `{ "kind": "entity", "entityType": "node", "stableId": "uuid:<UUID>" }`

Managed-file and route targets are rejected. Persistent file roots are verifier-owned restoration surfaces, while routes are observations derived from the config/entity result rather than storage owners.

Every entity target must use a UUID and resolve to verifier-readable SQL content-entity storage. An entity type excluded from portable readback, a custom storage backend the verifier cannot map, or a target without UUID identity fails before the adapter runs.

## Durable persistence boundary

Portable Drupal state is not the only mutation surface. On the currently supported MySQL/MariaDB DDEV database driver, the verifier hashes every database table's rows, `SHOW CREATE TABLE` definition, triggers, and auto-increment state, plus every public/private file entry, without emitting raw rows, schema text, paths, identifiers, or bytes. Other database drivers fail closed. Hard caps on tables, rows, entries, individual files, aggregate bytes, elapsed time, and output fail closed instead of silently truncating evidence.

For each interrupted prefix and for the full first run, the verifier captures an opaque storage-residual checksum immediately before and after execution. It resolves exact config-name or entity-UUID ownership itself and hashes every non-owned row in the covered tables. Entity ownership spans mapped base, data, revision, and dedicated-field tables; exact auxiliary selectors cover `node_access`, `menu_tree`, and View-owned `router` rows. A later-prefix owner, unrelated entity or revision, unrelated auxiliary row, overlapping selector, or unmappable storage surface fails closed. Only the residual's exact table coverage can authorize owned row changes. Key/value, queues, excluded entity storage, user/order data, custom tables, and every other durable table remain outside that coverage.

Database definitions and triggers are immutable even in an owned table. Auto-increment changes are separately allowed only on verifier-derived base/revision allocation tables for a matching `create` or `update`; deletes and config operations authorize no sequence movement. Entity action proof uses separate storage and revision identities: create is absent-to-present, update is present-to-present with the same storage identity, delete is present-to-absent with explicit consent, and unchanged/out-of-prefix identities remain exact. These are final-state invariants; they do not claim to trace every internal SQL statement when an implementation could reconstruct byte-identical state and identity.

Only fixed cache tables (`cache`, `cache_*`, `cachetags`, and `semaphore`) are classified as ephemeral. Public `css/`, `js/`, `php/`, and `styles/` subtrees are likewise reported separately as generated output; private files have no ephemeral prefix. Their changes never disappear from evidence: every physical byte is still included in the verifier-owned file backup, and restoration must reproduce its exact physical fingerprint before Drupal readback resumes. All other public/private files are durable and must remain unchanged because managed-file assembly targets are forbidden.

The verifier exports the complete DDEV database with hooks skipped and copies every live public/private stream-wrapper root into an owned, identity-bound backup. File roots must be mutually disjoint and must not contain the backup root. After each partial prefix it imports the database, restores the file roots, verifies the physical backup fingerprint, and then re-reads portable state, durable persistence, source bytes, and opaque provenance identity. The adapter never receives backup paths or restoration authority.

## Fixed adapter modes

The verifier invokes the single digest-bound PHP source through fixed argument arrays only:

```text
ddev drush php:script scripts/site-assembly.php -- plan
ddev drush php:script scripts/site-assembly.php -- apply-prefix <operation-count> <plan-fingerprint>
```

The adapter reads the fixed Drush script arguments (commonly available in `$extra`) and implements exactly those two modes. `plan` emits the typed object in canonical source-key/target order. `apply-prefix` verifies the supplied `sha256:` fingerprint of that canonical operation array and applies exactly the first N operations from the same stream; the verifier uses it for both partial interruption trials and full convergence. The verifier supplies no shell, command string, arbitrary argv, source title, or numeric entity identifier.

If any invoked prefix contains a `delete`, the checked-in ledger and `provenance_owned_only` policy are necessary but not sufficient. The operator must also opt in on that invocation:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/verify-assembly.mjs --allow-owned-deletes
```

Without deletes:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/verify-assembly.mjs
```

Exit `0` means every proof passed and cleanup succeeded. Exit `1` means plan validation, provisioning, adapter execution, readback, restoration, budget, or cleanup failed operationally. A completed state mismatch exits `2`. Every report sets `evidenceScope.authoritativeForDefaultHandoff` to `false`.

## Relationship to reproduction

`G-ASSEMBLY-01` and `G-REPRO-01` are deliberately separate:

- `G-ASSEMBLY-01` begins with a pre-assembly substrate and proves bounded convergence, rerun behavior, extension survival, and restoration.
- `G-REPRO-01` begins with exact `HEAD` plus declared inputs and proves the final disposable result matches the working target.

Neither result can substitute for the other, and neither changes the default local handoff verdict.
