# Disposable assembly rerun verification

`verify-assembly.mjs` is the launch-only verifier for `G-ASSEMBLY-01`. It proves a narrower claim than `G-REPRO-01`: a declared assembly workflow has a machine-readable plan, converges on its first application, is an exact no-op on rerun, preserves independently inserted extension work, and recovers from an observed partial failure. It does not participate in the default local handoff verdict.

The runner never invokes DDEV or Drupal in the working target. It reads exact Git state, creates an independent exact-`HEAD` clone with a UUID-owned `agent-ready-repro-*` DDEV identity, provisions a pre-assembly substrate there, performs every mutation in that clone, re-confirms the live DDEV identity immediately before deletion, and removes only the matching owned clone. If identity cannot be re-confirmed, cleanup fails closed and retains the disposable target for inspection.

## What the gate proves

One bounded run must establish all of the following:

1. `assembly-plan.json`, the provenance ledger, the fixed PHP adapter, the reproduction substrate plan, and every substrate input are Git-tracked, byte-exact to `HEAD`, and SHA-256 bound.
2. The substrate reaches a confirmed `substrateReady` barrier with clean active configuration before the assembly adapter runs. A clean-install substrate must declare `content.adapter: none`; executable content seeders are forbidden because the verifier cannot prove that a differently named wrapper did not run the assembly early. A digest-bound pre-assembly database snapshot is the seeded-data alternative.
3. Adapter `plan` output contains exactly one `create`, `update`, `delete`, or `unchanged` row for every checked-in provenance resource. Rows use a namespaced source key and an exact config name, route, non-numeric machine ID, or UUID. Titles, numeric entity IDs, wildcard selectors, bulk deletion, arbitrary commands, and packet-provided argv are rejected.
4. The first `apply` produces exactly the independently read Drupal state transitions declared by the dry run and leaves configuration clean. At least one transition must be a real create, update, or delete.
5. A second `plan` contains only `unchanged` rows, and the second `apply` leaves the full portable state exactly equal to the first result.
6. The verifier discovers live node, menu, alias, View, Canvas, and sitemap applicability. It inserts extension-owned fixtures on every applicable declared surface, checks that fixture injection changed only the exact returned fixture targets, records opaque storage-ID/revision checksums for fixture entities, reruns the assembly, and requires the whole state, storage identities, and every fixture target to remain unchanged. This detects delete-and-recreate or gratuitous new-revision churn even when a UUID and visible fields are copied back. An applicable surface declared `not_applicable`, or a declared surface unavailable in the substrate, fails closed.
7. The fixed `failpoint` mode exits non-zero after an independently visible mid-run mutation limited to provenance-owned targets. The fixed `restore` mode must then return the complete portable state—including extension fixtures—to the exact pre-failure checksum. A post-restoration dry run must again be a no-op. The gate reports `tested_restoration`; it does not relabel this as transactional rollback.
8. One aggregate command, elapsed-time, and output budget covers provisioning, readback, adapter runs, fixture work, restoration, and cleanup, with an explicit reserve for identity-safe cleanup and the final working-source proof. The disposable clone's tracked/untracked source binding must also be unchanged from the pre-assembly barrier through restoration.

The generated report includes all dry-run rows, live capability facts, before/after inventories and fingerprints, independently derived changes, fixture survival rows, restoration comparison, command argv with output digests, the aggregate budget, cleanup result, and proof that zero working-target DDEV commands ran.

## Files

Create these project-local, Git-tracked inputs:

- `assembly-plan.json` — the typed verifier contract;
- `assembly-provenance.json` — the complete assembly-owned resource ledger;
- one PHP adapter implementing `drush_assembly_contract_v1`;
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
    "protocol": "drush_assembly_contract_v1",
    "source": {
      "path": "scripts/site-assembly.php",
      "sha256": "sha256:<digest-of-file>"
    },
    "failureProof": "tested_restoration"
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
      "action": "unchanged",
      "sourceKey": "site_import:view/events",
      "surface": "view",
      "target": { "kind": "config", "name": "views.view.events" }
    }
  ],
  "summary": {
    "create": 1,
    "update": 0,
    "delete": 0,
    "unchanged": 1,
    "total": 2
  }
}
```

The dry run is untrusted input. The verifier derives the actual config/entity/file/route transition after `apply` and rejects missing, extra, or differently classified changes.

Supported target forms are:

- `{ "kind": "config", "name": "one.exact.config_name" }`
- `{ "kind": "entity", "entityType": "node", "stableId": "uuid:<UUID>" }`
- `{ "kind": "entity", "entityType": "custom_type", "stableId": "id:<non-numeric-machine-id>" }`
- `{ "kind": "managed_file", "stableId": "uuid:<UUID>" }`
- `{ "kind": "route", "path": "/one/exact/path" }`

## Fixed adapter modes

The verifier invokes the single digest-bound PHP source through fixed argument arrays only:

```text
ddev drush php:script scripts/site-assembly.php -- plan
ddev drush php:script scripts/site-assembly.php -- apply
ddev drush php:script scripts/site-assembly.php -- failpoint
ddev drush php:script scripts/site-assembly.php -- restore
```

The adapter reads the first fixed Drush script argument (commonly available as `$extra[0]`) and implements exactly those modes. `plan` emits the typed object. `apply` converges declared resources. `failpoint` performs a deterministic partial mutation inside the provenance ledger and exits non-zero. `restore` repairs that partial mutation without resetting, replacing, or deleting extension-owned work. The verifier supplies no shell, command string, arbitrary argv, source title, or numeric entity identifier.

If first-run `plan` contains any `delete`, or the observed failpoint uses a delete to create its partial state, the checked-in ledger and `provenance_owned_only` policy are necessary but not sufficient. The operator must also opt in on that invocation:

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
