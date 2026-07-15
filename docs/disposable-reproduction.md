# Disposable Drupal Reproduction

`verify-reproduction.mjs` is an optional host-side maintainer/launch verifier for `G-REPRO-01`. It proves that exact Git `HEAD` plus declared, digest-bound inputs can produce the same portable Drupal state in a separately cloned DDEV project. It does not participate in the default handoff verdict.

The runner never reinstalls or imports into the working target. It reads that target before and after the run, provisions only a UUID-named `agent-ready-repro-*` project in an independent temporary clone, and deletes only a clone whose external ownership marker, generated DDEV name, and real DDEV app root all match the current run immediately before cleanup. Exact-`HEAD` provenance is not treated as an execution sandbox: the runner accepts only one regular project `.ddev/config.yaml`, parses it with a constrained typed grammar, carries forward only safe Drupal type/docroot/PHP/webserver/database facts, rejects every other project `.ddev` file or directory, and replaces the source directory with a verifier-owned minimal config before `ddev start`. Every disposable DDEV command removes ambient `DDEV_*` and `COMPOSE_*` variables and uses a fresh sibling `DDEV_XDG_CONFIG_HOME`, outside the container-mounted project root. Unsupported customized DDEV projects block rather than being heuristically blessed. Failed or partial starts still require live name and real-app-root confirmation before deletion. If either configuration safety or live identity cannot be proven, the run fails closed and retains the owned temporary target for manual inspection. Its one intentional working-tree write happens after the after-readback: `review-packet/evidence/reproduction-verification.json`.

## Preconditions

- Run this command from the DDEV host, not inside the web container. Host `git`, `ddev`, `curl`, and Node 20 or newer must be available.
- The working target must already be running and have clean active-to-sync configuration.
- `reproduction-plan.json`, every declared input, and `review-packet/route-matrix.json` must be present, Git-tracked, and byte-exact to `HEAD`.
- The declared config directory must contain only present, tracked files and at least one YAML file.
- Every primary route row must be accepted. The verifier also reads accepted full-surface routes and accepted public target-required routes.
- Machine-local paths such as `.env`, `.ddev/config.local.yaml`, local settings/services files, live site files directories, and generated packet evidence cannot be declared as inputs.

Run:

```bash
node .agents/skills/agent-ready-drupal-build-kit/scripts/verify-reproduction.mjs
```

Exit `0` means the disposable state matched and the working target's Git state, portable runtime-code binding, active config, stable entities, managed-file bytes, and declared public routes remained unchanged. Exit `2` means a completed reproduction did not match. Exit `1` means provisioning, readback, ownership-safe cleanup, or another required operation failed. Every outcome that reaches report creation writes verifier-owned evidence; a non-zero outcome remains failed evidence.

## Typed Plan

The plan has no command list or free-form argv. It selects only fixed verifier adapters. Every file input uses a SHA-256 of its bytes. `trackedConfig.sha256` is the `public-kit.file-manifest.1` fingerprint of the whole declared directory, including project-relative paths, sizes, and byte digests.

For a true clean install/config import:

```json
{
  "schemaVersion": "public-kit.reproduction-plan.1",
  "mode": "clean_install_config_import",
  "dependencies": {
    "adapter": "ddev_composer_install",
    "lockFile": {
      "path": "composer.lock",
      "sha256": "sha256:REPLACE_WITH_64_HEX_CHARACTERS"
    }
  },
  "trackedConfig": {
    "path": "config/sync",
    "sha256": "sha256:REPLACE_WITH_CONFIG_MANIFEST_FINGERPRINT"
  },
  "content": {
    "adapter": "drush_php_script",
    "source": {
      "path": "scripts/import-canonical-content.php",
      "sha256": "sha256:REPLACE_WITH_64_HEX_CHARACTERS"
    }
  },
  "files": {
    "adapter": "ddev_import_files_archive",
    "source": {
      "path": "artifacts/canonical-files.tar.gz",
      "sha256": "sha256:REPLACE_WITH_64_HEX_CHARACTERS"
    }
  }
}
```

This mode runs only the fixed sequence: DDEV start, locked Composer install, `drush site:install --existing-config`, optional files import, optional digest-bound PHP content importer, `drush config:import`, cache rebuild, and fresh readback. A project with no portable content or managed files may explicitly use `{ "adapter": "none", "expectedEntityCount": 0 }` or `{ "adapter": "none", "expectedManagedFileCount": 0 }`; the working-target readback must prove the corresponding count is exactly zero.

For snapshot restoration, replace the content declaration with `{ "adapter": "database_snapshot" }` and add:

```json
{
  "databaseSnapshot": {
    "adapter": "ddev_import_db_archive",
    "source": {
      "path": "artifacts/canonical-db.sql.gz",
      "sha256": "sha256:REPLACE_WITH_64_HEX_CHARACTERS"
    }
  }
}
```

Snapshot mode runs DDEV start, locked Composer install, exact database import, optional exact files import, tracked config import, cache rebuild, and readback. A passing snapshot run is labeled `snapshot_restore`; it is not presented as clean-install/config-import evidence.

To calculate file and config-manifest digests with the same implementation used by the verifier, run these from the project root and substitute the relevant paths:

```bash
node --input-type=module -e "import {readFileSync} from 'node:fs'; import {sha256} from './.agents/skills/agent-ready-drupal-build-kit/scripts/state-fingerprint.mjs'; console.log(sha256(readFileSync('composer.lock')))"
node --input-type=module -e "import {collectFileManifest} from './.agents/skills/agent-ready-drupal-build-kit/scripts/state-fingerprint.mjs'; console.log(collectFileManifest(process.cwd(), ['config/sync']).fingerprint)"
```

## Portable Readback

The verifier hashes active configuration across config collections without emitting values. It enumerates non-private content entity types, requires UUIDs or stable string IDs, removes numeric entity/revision identity, rewrites entity references to stable target identifiers, skips computed fields and known private/volatile entity types, and emits only stable IDs, bundles, counts, and value digests. All managed `public://` and `private://` file entities must have readable bytes; unsupported or mutable stream-wrapper schemes fail closed. Public route comparison is bounded to 256 declared routes and five MiB per response, refuses cross-origin redirects, and binds the same-origin redirect chain, final status/path, title, H1, and origin-neutral visible-text digest.

The generated report records the typed adapters, exact input checksums, command argv and output digests, working before/after bindings, disposable comparison, and cleanup result. It deliberately sets `evidenceScope.authoritativeForDefaultHandoff` to `false`; use it only as the stronger maintainer or launch evidence it actually represents.
