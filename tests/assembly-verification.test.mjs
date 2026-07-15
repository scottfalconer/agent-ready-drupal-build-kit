import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  assemblyTargetKey,
  assertChangesWithinProvenance,
  assertDeletesAuthorized,
  assertPrefixDeletesAuthorized,
  assertProvenanceReadbackCoverage,
  deriveAssemblyChanges,
  loadValidatedAssemblyInputs,
  parseAssemblyDryRun,
  parseAssemblyPlan,
  parseAssemblyProvenance,
  reconcileDryRun,
  reconcileDryRunPrefix,
  selectAssemblyInterruptionCutPoints
} from '../bin/assembly-contract.mjs';
import {
  assertDryRunSurfacesAvailable,
  assertFixturePlanAgainstCapabilities,
  captureAssemblyFixtureIdentity,
  discoverAssemblyCapabilities,
  parseAssemblyCapabilities
} from '../bin/assembly-fixtures.mjs';
import { createRecordedExecutor } from '../bin/disposable-ddev.mjs';
import { buildPortableReproductionState } from '../bin/reproduction-state.mjs';
import { collectFileManifest, sha256 } from '../bin/state-fingerprint.mjs';
import {
  assemblyAdapterArgs,
  assertIdentityTransitionsMatchPrefix,
  createAssemblyBudget,
  deriveOperationPrefixSequenceTableIds,
  operationPrefixProvenance,
  runDisposableAssembly
} from '../bin/verify-assembly.mjs';

const UUID = '11111111-1111-4111-8111-111111111111';
const TARGET_UUID = '22222222-2222-4222-8222-222222222222';
const TARGET_UUID_2 = '33333333-3333-4333-8333-333333333333';
const TARGET_UUID_3 = '44444444-4444-4444-8444-444444444444';
const DIGEST = `sha256:${'a'.repeat(64)}`;

test('checked-in disposable assembly fixture binds its current input bytes', () => {
  const fixtureRoot = new URL('./fixtures/disposable-drupal/', import.meta.url);
  const planBytes = readFileSync(new URL('assembly-plan.json', fixtureRoot));
  const substrateBytes = readFileSync(new URL('assembly-substrate-plan.json', fixtureRoot));
  const plan = JSON.parse(planBytes);
  const substrate = JSON.parse(substrateBytes);

  assert.equal(
    substrate.dependencies.lockFile.sha256,
    sha256(readFileSync(new URL(substrate.dependencies.lockFile.path, fixtureRoot)))
  );
  assert.equal(plan.substratePlan.sha256, sha256(substrateBytes));
  assert.equal(
    plan.provenance.sha256,
    sha256(readFileSync(new URL(plan.provenance.path, fixtureRoot)))
  );
  assert.equal(
    plan.adapter.source.sha256,
    sha256(readFileSync(new URL(plan.adapter.source.path, fixtureRoot)))
  );
});

test('assembly capability failures use bounded redacted diagnostics', () => {
  assert.throws(() => discoverAssemblyCapabilities({
    execute: () => ({
      status: null,
      stderr: 'Upgraded DDEV v1.25.3 is available!\nPlease visit https://github.com/ddev/ddev/releases/tag/v1.25.3',
      error: { message: 'spawnSync ddev ETIMEDOUT Authorization: Bearer exposed-token' }
    }),
    projectRoot: '/tmp',
    target: 'disposable'
  }), (error) => {
    assert.equal(
      error.message,
      'assembly-capability-readback failed: spawnSync ddev ETIMEDOUT Authorization: <redacted>'
    );
    assert.equal(error.message.includes('exposed-token'), false);
    return true;
  });
});

function git(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function notApplicableFixtures() {
  return Object.fromEntries(['node', 'menu', 'alias', 'view', 'canvas', 'sitemap'].map((surface) => [
    surface, { status: 'not_applicable' }
  ]));
}

function planValue(overrides = {}) {
  return {
    schemaVersion: 'public-kit.assembly-plan.1',
    assemblyId: 'fixture_assembly',
    substratePlan: { path: 'reproduction-plan.json', sha256: DIGEST },
    provenance: { path: 'assembly-provenance.json', sha256: DIGEST },
    deletion: { policy: 'provenance_owned_only' },
    adapter: {
      protocol: 'drush_assembly_contract_v2',
      source: { path: 'scripts/assembly.php', sha256: DIGEST },
      failureProof: 'verifier_controlled_restoration'
    },
    extensionFixtures: notApplicableFixtures(),
    ...overrides
  };
}

function provenanceValue(target = { kind: 'entity', entityType: 'thing', stableId: `uuid:${TARGET_UUID}` }) {
  return {
    schemaVersion: 'public-kit.assembly-provenance.1',
    assemblyId: 'fixture_assembly',
    namespace: 'fixture',
    resources: [{ sourceKey: 'fixture:primary', surface: 'entity', target }]
  };
}

function dryValue(action, target = { kind: 'entity', entityType: 'thing', stableId: `uuid:${TARGET_UUID}` }) {
  return {
    schemaVersion: 'public-kit.assembly-dry-run.1',
    assemblyId: 'fixture_assembly',
    operations: [{ action, sourceKey: 'fixture:primary', surface: 'entity', target }],
    summary: {
      create: action === 'create' ? 1 : 0,
      update: action === 'update' ? 1 : 0,
      delete: action === 'delete' ? 1 : 0,
      unchanged: action === 'unchanged' ? 1 : 0,
      total: 1
    }
  };
}

function multiProvenanceValue() {
  return {
    schemaVersion: 'public-kit.assembly-provenance.1',
    assemblyId: 'fixture_assembly',
    namespace: 'fixture',
    resources: [TARGET_UUID, TARGET_UUID_2, TARGET_UUID_3].map((uuid, index) => ({
      sourceKey: `fixture:item-${index + 1}`,
      surface: 'entity',
      target: { kind: 'entity', entityType: 'thing', stableId: `uuid:${uuid}` }
    }))
  };
}

function multiDryValue(action) {
  const operations = multiProvenanceValue().resources.map((resource) => ({ action, ...resource }));
  return {
    schemaVersion: 'public-kit.assembly-dry-run.1',
    assemblyId: 'fixture_assembly',
    operations,
    summary: {
      create: action === 'create' ? operations.length : 0,
      update: action === 'update' ? operations.length : 0,
      delete: action === 'delete' ? operations.length : 0,
      unchanged: action === 'unchanged' ? operations.length : 0,
      total: operations.length
    }
  };
}

function portableState({ entityHash = '', entityHashes = [], extension = false, clean = true } = {}) {
  const configItems = [{ name: 'system.site', sha256: sha256({ uuid: UUID }) }];
  if (extension) configItems.push({ name: 'agent_ready.extension_fixture', sha256: sha256({ marker: true }) });
  const hashes = entityHashes.length > 0 ? entityHashes : entityHash ? [entityHash] : [];
  const targetUuids = [TARGET_UUID, TARGET_UUID_2, TARGET_UUID_3];
  return buildPortableReproductionState({
    confirmed: true,
    errors: [],
    siteUuid: UUID,
    configSyncDirectory: 'config/sync',
    configStatusClean: clean,
    config: { items: configItems },
    entities: {
      types: {
        thing: {
          items: hashes.map((hash, index) => ({
            stableId: `uuid:${targetUuids[index]}`,
            bundle: 'thing',
            sha256: hash
          }))
        }
      }
    },
    managedFiles: { items: [] },
    routes: [{
      path: '/', status: 200, finalPath: '/',
      titleSha256: sha256('Fixture'), h1Sha256: sha256('Fixture'),
      bodyTextSha256: sha256('Fixture'), bodyTextLength: 7
    }]
  });
}

function persistenceSnapshot() {
  const files = [
    {
      id: 'file:private', available: false, fileCount: 0, directoryCount: 0, byteCount: 0,
      ephemeralPrefixes: [], sha256: sha256('private-durable'), physicalSha256: sha256('private-physical')
    },
    {
      id: 'file:public', available: true, fileCount: 0, directoryCount: 0, byteCount: 0,
      ephemeralPrefixes: ['css/', 'js/', 'php/', 'styles/'],
      sha256: sha256('public-durable'), physicalSha256: sha256('public-physical')
    }
  ];
  const tables = [{
    id: 'table:thing',
    policy: 'durable',
    rowCount: 0,
    sha256: sha256('thing-table'),
    definitionSha256: sha256('thing-definition'),
    sequenceSha256: sha256('thing-sequence')
  }];
  return {
    schemaVersion: 'public-kit.assembly-persistence.1',
    complete: true,
    tableCount: tables.length,
    aggregateRowCount: 0,
    ephemeralTableIds: [],
    tables,
    files,
    aggregateSha256: sha256({ files, tables })
  };
}

function provenanceIdentityForTarget(provenance, target) {
  const prefix = String(target).match(/assembly-interrupted-prefix-(\d+)/);
  const presentCount = prefix ? Number(prefix[1]) : (
    /assembly-(?:first|second|fixtures-before-rerun|after-second-plan|after-extension-plan|extension-rerun)/.test(String(target))
      ? 3
      : 0
  );
  const rows = provenance.resources.map(({ target: entityTarget }, index) => {
    const key = `entity:${entityTarget.entityType}:${entityTarget.stableId}`;
    const present = index < presentCount;
    return {
      key,
      present,
      storageIdentitySha256: sha256({ key, present, storageOrdinal: present ? index + 1 : 0 }),
      revisionIdentitySha256: sha256({ key, present, revisionOrdinal: present ? index + 1 : 0 }),
      tableIds: ['table:thing'],
      createSequenceTableIds: ['table:thing'],
      updateSequenceTableIds: []
    };
  });
  for (const row of rows) {
    row.identitySha256 = sha256({
      storageIdentitySha256: row.storageIdentitySha256,
      revisionIdentitySha256: row.revisionIdentitySha256
    });
  }
  return {
    schemaVersion: 'public-kit.assembly-entity-identity.1',
    rows,
    aggregateSha256: sha256(rows)
  };
}

function sourceBytesSnapshot() {
  const snapshot = {
    schemaVersion: 'public-kit.assembly-source-bytes.1',
    head: 'a'.repeat(40),
    trackedDiffSha256: sha256('tracked'),
    untrackedFileCount: 0,
    untrackedByteCount: 0,
    untrackedSha256: sha256([]),
    runtimeBindingSha256: sha256('runtime-binding'),
    excludedArtifactCount: 2,
    excludedArtifactSha256: sha256('owned-backups')
  };
  return { ...snapshot, aggregateSha256: sha256(snapshot) };
}

function persistenceDependencies(tracker = {}) {
  const persistence = persistenceSnapshot();
  const publicFile = persistence.files.find(({ id }) => id === 'file:public');
  const fileBackup = {
    schemaVersion: 'public-kit.assembly-file-backup.1',
    relativePath: '.ddev/.agent-ready-assembly-files-fixture',
    tokenSha256: sha256('file-backup-token'),
    surfaces: ['public'],
    files: [publicFile],
    aggregateSha256: sha256([publicFile])
  };
  return {
    capturePersistence: () => {
      tracker.persistenceCaptures = (tracker.persistenceCaptures ?? 0) + 1;
      return persistence;
    },
    captureProvenanceIdentity: ({ provenance, target }) => {
      tracker.identityCaptures = (tracker.identityCaptures ?? 0) + 1;
      return provenanceIdentityForTarget(provenance, target);
    },
    captureStorageResidual: ({ provenance }) => {
      tracker.storageResidualCaptures = (tracker.storageResidualCaptures ?? 0) + 1;
      const ownerKeys = provenance.resources.map(({ target }) => assemblyTargetKey(target)).sort();
      const owners = provenance.resources.map(({ target }) => ({
        key: assemblyTargetKey(target),
        tableIds: [target.kind === 'config' ? 'table:config' : 'table:thing']
      })).sort((left, right) => left.key.localeCompare(right.key));
      const tableIds = [...new Set(owners.flatMap(({ tableIds: ids }) => ids))].sort();
      const tables = tableIds.map((id) => ({
        id,
        residualRowCount: 0,
        residualSha256: sha256({ id, rows: [] })
      }));
      return {
        schemaVersion: 'public-kit.assembly-storage-residual.1',
        complete: true,
        ownerKeys,
        owners,
        tables,
        aggregateSha256: sha256({ ownerKeys, owners, tables })
      };
    },
    captureSource: () => {
      tracker.sourceCaptures = (tracker.sourceCaptures ?? 0) + 1;
      return sourceBytesSnapshot();
    },
    createFileBackup: () => fileBackup,
    disposeFileBackup: () => {
      tracker.fileBackupDisposals = (tracker.fileBackupDisposals ?? 0) + 1;
      return true;
    },
    registerDatabaseSourceExclusion: ({ relativePath, expectedFingerprint }) => ({
      schemaVersion: 'public-kit.assembly-database-source-exclusion.1',
      relativePath,
      fingerprint: expectedFingerprint
    }),
    restoreFileBackup: () => {
      tracker.fileRestores = (tracker.fileRestores ?? 0) + 1;
      return {
        schemaVersion: 'public-kit.assembly-file-surfaces.1',
        complete: true,
        files: fileBackup.files,
        aggregateSha256: fileBackup.aggregateSha256
      };
    }
  };
}

function repositoryFixture() {
  const root = mkdtempSync(join(tmpdir(), 'assembly-verification-fixture-'));
  mkdirSync(join(root, '.ddev'), { recursive: true });
  mkdirSync(join(root, 'config', 'sync'), { recursive: true });
  mkdirSync(join(root, 'review-packet'), { recursive: true });
  mkdirSync(join(root, 'scripts'), { recursive: true });
  mkdirSync(join(root, 'web'), { recursive: true });
  writeFileSync(join(root, '.ddev', 'config.yaml'), 'name: assembly-fixture\ntype: drupal11\ndocroot: web\n');
  writeFileSync(join(root, 'composer.json'), '{"name":"fixture/site"}\n');
  writeFileSync(join(root, 'composer.lock'), '{"packages":[]}\n');
  writeFileSync(join(root, 'config', 'sync', 'system.site.yml'), `uuid: ${UUID}\n`);
  writeFileSync(join(root, 'review-packet', 'route-matrix.json'), `${JSON.stringify({
    schemaVersion: 'public-kit.route-matrix.1',
    primaryRoutes: [{ targetPath: '/', accepted: true }],
    routes: [],
    targetRequiredRoutes: []
  }, null, 2)}\n`);
  writeFileSync(join(root, 'scripts', 'assembly.php'), '<?php // Fixed fixture adapter; fake DDEV owns test output.\n');
  writeFileSync(join(root, 'web', 'index.php'), '<?php // Tracked fixture docroot required by the disposable DDEV sandbox.\n');
  const reproduction = {
    schemaVersion: 'public-kit.reproduction-plan.1',
    mode: 'clean_install_config_import',
    dependencies: {
      adapter: 'ddev_composer_install',
      lockFile: { path: 'composer.lock', sha256: sha256(readFileSync(join(root, 'composer.lock'))) }
    },
    trackedConfig: { path: 'config/sync', sha256: collectFileManifest(root, ['config/sync']).fingerprint },
    content: { adapter: 'none', expectedEntityCount: 0 },
    files: { adapter: 'none', expectedManagedFileCount: 0 }
  };
  writeFileSync(join(root, 'reproduction-plan.json'), `${JSON.stringify(reproduction, null, 2)}\n`);
  const provenance = multiProvenanceValue();
  writeFileSync(join(root, 'assembly-provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
  const plan = planValue({
    substratePlan: { path: 'reproduction-plan.json', sha256: sha256(readFileSync(join(root, 'reproduction-plan.json'))) },
    provenance: { path: 'assembly-provenance.json', sha256: sha256(readFileSync(join(root, 'assembly-provenance.json'))) },
    adapter: {
      protocol: 'drush_assembly_contract_v2',
      source: { path: 'scripts/assembly.php', sha256: sha256(readFileSync(join(root, 'scripts', 'assembly.php'))) },
      failureProof: 'verifier_controlled_restoration'
    }
  });
  writeFileSync(join(root, 'assembly-plan.json'), `${JSON.stringify(plan, null, 2)}\n`);
  git(root, ['init', '--quiet']);
  git(root, ['add', '.']);
  git(root, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'fixture']);
  return { root };
}

test('assembly plan accepts only the fixed adapter protocol and provenance-owned deletion policy', () => {
  const parsed = parseAssemblyPlan(planValue());
  assert.equal(parsed.adapter.protocol, 'drush_assembly_contract_v2');
  assert.equal(parsed.deletion.policy, 'provenance_owned_only');

  assert.throws(() => parseAssemblyPlan({ ...planValue(), command: 'sh -c anything' }), /unsupported field.*command/i);
  assert.throws(() => parseAssemblyPlan({
    ...planValue(),
    adapter: { ...planValue().adapter, argv: ['anything'] }
  }), /unsupported field.*argv/i);
  assert.throws(() => parseAssemblyPlan({
    ...planValue(),
    deletion: { policy: 'delete_all' }
  }), /provenance_owned_only/);
});

test('provenance rejects titles, numeric IDs, wildcards, duplicate targets, and malformed dry summaries', () => {
  assert.throws(() => parseAssemblyProvenance({
    ...provenanceValue(),
    resources: [{
      sourceKey: 'fixture:123', surface: 'entity',
      target: { kind: 'entity', entityType: 'thing', stableId: 'id:123' }
    }]
  }), /numeric|titles/i);
  assert.throws(() => parseAssemblyProvenance({
    ...provenanceValue(),
    resources: [{
      sourceKey: 'fixture:machine', surface: 'entity',
      target: { kind: 'entity', entityType: 'thing', stableId: 'id:machine_id' }
    }]
  }), /must use UUID identity/);
  assert.throws(() => parseAssemblyProvenance({
    ...provenanceValue(),
    resources: [{
      sourceKey: 'fixture:all*', surface: 'config', target: { kind: 'config', name: 'fixture.*' }
    }]
  }), /wildcard|exact configuration/i);
  for (const target of [
    { kind: 'managed_file', stableId: `uuid:${TARGET_UUID}` },
    { kind: 'route', path: '/owned-by-rendering' }
  ]) {
    assert.throws(() => parseAssemblyProvenance({
      ...provenanceValue(),
      resources: [{
        sourceKey: 'fixture:forbidden',
        surface: target.kind,
        target
      }]
    }), /observational|restorable storage owner/i);
  }

  const provenance = parseAssemblyProvenance(provenanceValue());
  assert.throws(() => parseAssemblyDryRun({
    ...dryValue('create'), summary: { create: 0, update: 0, delete: 0, unchanged: 0, total: 1 }
  }, provenance), /summary\.create/);
  const canonicalMulti = multiDryValue('create');
  assert.throws(() => parseAssemblyDryRun({
    ...canonicalMulti,
    operations: [...canonicalMulti.operations].reverse()
  }, parseAssemblyProvenance(multiProvenanceValue())), /canonical provenance operation order/);
});

test('dry-run claims are reconciled against verifier-derived state and failure changes stay in provenance', () => {
  const provenance = parseAssemblyProvenance(provenanceValue());
  const baseline = portableState();
  const created = portableState({ entityHash: sha256({ value: 'created' }) });
  const dry = parseAssemblyDryRun(dryValue('create'), provenance);
  assert.equal(reconcileDryRun(dry, baseline, created).valid, true);
  assert.equal(reconcileDryRun(parseAssemblyDryRun(dryValue('update'), provenance), baseline, created).valid, false);
  assert.doesNotThrow(() => assertChangesWithinProvenance(deriveAssemblyChanges(baseline, created), provenance, 'Failure'));

  const outside = portableState({ entityHash: sha256({ value: 'created' }), extension: true, clean: false });
  assert.throws(
    () => assertChangesWithinProvenance(deriveAssemblyChanges(created, outside), provenance, 'Failure'),
    /outside the exact provenance ledger/
  );
});

test('delete rows require explicit CLI opt-in in addition to exact provenance', () => {
  const provenance = parseAssemblyProvenance(provenanceValue());
  const dry = parseAssemblyDryRun(dryValue('delete'), provenance);
  assert.throws(() => assertDeletesAuthorized(dry, false), /--allow-owned-deletes/);
  assert.equal(assertDeletesAuthorized(dry, true), 1);
  assert.throws(() => assertPrefixDeletesAuthorized(dry, 1, false), /--allow-owned-deletes/);
  assert.equal(assertPrefixDeletesAuthorized(dry, 0, false), 0);
  assert.equal(assertPrefixDeletesAuthorized(dry, 1, true), 1);
});

test('entity action identity transitions reject update-by-delete-and-recreate', () => {
  const key = `entity:thing:uuid:${TARGET_UUID}`;
  const identity = ({ present, storage, revision }) => {
    const storageIdentitySha256 = sha256({ key, present, storage });
    const revisionIdentitySha256 = sha256({ key, present, revision });
    const rows = [{
      key,
      present,
      identitySha256: sha256({ storageIdentitySha256, revisionIdentitySha256 }),
      storageIdentitySha256,
      revisionIdentitySha256,
      tableIds: ['table:thing'],
      createSequenceTableIds: ['table:thing'],
      updateSequenceTableIds: []
    }];
    return { rows, aggregateSha256: sha256(rows) };
  };
  const before = identity({ present: true, storage: 'opaque-a', revision: 'opaque-r1' });
  const revised = identity({ present: true, storage: 'opaque-a', revision: 'opaque-r2' });
  const recreated = identity({ present: true, storage: 'opaque-b', revision: 'opaque-r2' });
  const absent = identity({ present: false, storage: '', revision: '' });

  assert.doesNotThrow(() => assertIdentityTransitionsMatchPrefix(
    absent,
    before,
    dryValue('create'),
    1,
    'Create'
  ));
  assert.doesNotThrow(() => assertIdentityTransitionsMatchPrefix(
    before,
    revised,
    dryValue('update'),
    1,
    'Update'
  ));
  assert.throws(() => assertIdentityTransitionsMatchPrefix(
    before,
    recreated,
    dryValue('update'),
    1,
    'Update',
    true
  ), /deleted and recreated/);
  assert.throws(() => assertIdentityTransitionsMatchPrefix(
    before,
    revised,
    dryValue('update'),
    0,
    'Unapplied update'
  ), /outside the applied operation prefix|unchanged target/);
  assert.throws(() => assertIdentityTransitionsMatchPrefix(
    before,
    absent,
    dryValue('delete'),
    1,
    'Delete'
  ), /--allow-owned-deletes/);
  assert.doesNotThrow(() => assertIdentityTransitionsMatchPrefix(
    before,
    absent,
    dryValue('delete'),
    1,
    'Delete',
    true
  ));
});

test('verifier selects two partial operation cut points and reconciles only the applied prefix', () => {
  const provenance = parseAssemblyProvenance(multiProvenanceValue());
  const dry = parseAssemblyDryRun(multiDryValue('create'), provenance);
  assert.deepEqual(selectAssemblyInterruptionCutPoints(dry), [1, 2]);
  assert.deepEqual(
    operationPrefixProvenance(dry, 1).resources.map(({ sourceKey }) => sourceKey),
    ['fixture:item-1']
  );
  const partial = portableState({ entityHashes: [sha256('first')] });
  assert.equal(reconcileDryRunPrefix(dry, 1, portableState(), partial).valid, true);
  assert.equal(reconcileDryRunPrefix(dry, 2, portableState(), partial).valid, false);
  assert.throws(
    () => selectAssemblyInterruptionCutPoints(parseAssemblyDryRun(dryValue('create'), parseAssemblyProvenance(provenanceValue()))),
    /at least three first-run mutations/
  );
});

test('interrupted sequence allowlists include only entity allocation surfaces for the applied prefix', () => {
  const dryRunValue = {
    operations: [
      {
        action: 'create',
        sourceKey: 'fixture:node',
        surface: 'node',
        target: { kind: 'entity', entityType: 'node', stableId: `uuid:${TARGET_UUID}` }
      },
      {
        action: 'create',
        sourceKey: 'fixture:menu',
        surface: 'menu',
        target: { kind: 'entity', entityType: 'menu_link_content', stableId: `uuid:${TARGET_UUID_2}` }
      },
      {
        action: 'update',
        sourceKey: 'fixture:config',
        surface: 'config',
        target: { kind: 'config', name: 'system.site' }
      }
    ]
  };
  const rows = [
    {
      key: `entity:node:uuid:${TARGET_UUID}`,
      present: false,
      identitySha256: sha256('missing-node'),
      tableIds: ['table:node', 'table:node_field_data', 'table:node_revision'],
      createSequenceTableIds: ['table:node', 'table:node_revision'],
      updateSequenceTableIds: ['table:node_revision']
    },
    {
      key: `entity:menu_link_content:uuid:${TARGET_UUID_2}`,
      present: false,
      identitySha256: sha256('missing-menu-link'),
      tableIds: ['table:menu_link_content', 'table:menu_link_content_data'],
      createSequenceTableIds: ['table:menu_link_content'],
      updateSequenceTableIds: []
    }
  ];
  const entityIdentity = { rows, aggregateSha256: sha256(rows) };
  assert.deepEqual(deriveOperationPrefixSequenceTableIds({
    dryRunValue,
    entityIdentity,
    prefixCount: 1
  }), ['table:node', 'table:node_revision']);
  assert.deepEqual(deriveOperationPrefixSequenceTableIds({
    dryRunValue,
    entityIdentity,
    prefixCount: 2
  }), ['table:menu_link_content', 'table:node', 'table:node_revision']);
});

test('provenance entity types outside portable readback are forbidden before execution', () => {
  const provenance = parseAssemblyProvenance(provenanceValue());
  assert.equal(assertProvenanceReadbackCoverage(provenance, portableState()), true);
  const uncovered = buildPortableReproductionState({
    ...portableState(),
    config: portableState().config,
    entities: { types: {} },
    managedFiles: portableState().managedFiles,
    routes: portableState().routes
  });
  assert.throws(() => assertProvenanceReadbackCoverage(provenance, uncovered), /outside portable entity readback coverage/);
});

test('clean assembly substrate rejects every executable content importer even under another path', () => {
  const { root } = repositoryFixture();
  try {
    const reproductionPath = join(root, 'reproduction-plan.json');
    const reproduction = JSON.parse(readFileSync(reproductionPath, 'utf8'));
    writeFileSync(join(root, 'scripts', 'seed.php'), '<?php // wrapper\n');
    reproduction.content = {
      adapter: 'drush_php_script',
      source: { path: 'scripts/seed.php', sha256: sha256(readFileSync(join(root, 'scripts', 'seed.php'))) }
    };
    writeFileSync(reproductionPath, `${JSON.stringify(reproduction, null, 2)}\n`);
    const planPath = join(root, 'assembly-plan.json');
    const plan = JSON.parse(readFileSync(planPath, 'utf8'));
    plan.substratePlan.sha256 = sha256(readFileSync(reproductionPath));
    writeFileSync(planPath, `${JSON.stringify(plan, null, 2)}\n`);
    git(root, ['add', '.']);
    git(root, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'executable substrate']);
    const execute = createRecordedExecutor({ commandLog: [] });
    assert.throws(
      () => loadValidatedAssemblyInputs({ execute, projectRoot: root }),
      /must use content\.adapter none/
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('live applicability rejects not-applicable declarations and unsupported touched surfaces', () => {
  const capabilities = parseAssemblyCapabilities({
    schemaVersion: 'public-kit.assembly-capabilities.1',
    entityTypes: ['menu_link_content', 'node', 'path_alias'],
    bundleKeys: { menu_link_content: 'bundle', node: 'type', path_alias: '' },
    bundles: { menu_link_content: ['menu_link_content'], node: ['page'], path_alias: ['path_alias'] },
    nodeBundles: ['page'],
    menus: ['main'],
    viewsAvailable: true,
    canvasEntityTypes: ['canvas_page'],
    canvasComponentConfigs: ['experience_builder.component.hero'],
    sitemapConfigs: ['simple_sitemap.type.default']
  });
  assert.throws(
    () => assertFixturePlanAgainstCapabilities(parseAssemblyPlan(planValue()).extensionFixtures, capabilities),
    /node is live\/applicable/
  );
  const provenance = parseAssemblyProvenance(provenanceValue());
  const dry = parseAssemblyDryRun(dryValue('create'), provenance);
  assert.throws(() => assertDryRunSurfacesAvailable(dry, capabilities), /unsupported live surface entity/);
});

test('aggregate budget protects final cleanup/proof reserve after ordinary work is exhausted', () => {
  const calls = [];
  let clock = 0;
  const execute = (command, args, options) => {
    calls.push({ command, args, options });
    clock += 1;
    return { status: 0, stdout: 'x', stderr: '' };
  };
  const budget = createAssemblyBudget({
    execute,
    now: () => clock,
    limits: {
      maxCommands: 5,
      reservedFinalizationCommands: 2,
      maxElapsedMs: 100,
      reservedFinalizationMs: 10,
      maxOutputBytes: 100,
      reservedFinalizationOutputBytes: 10
    }
  });
  for (let index = 0; index < 3; index += 1) budget('tool', [], { phase: `work-${index}` });
  assert.throws(() => budget('tool', [], { phase: 'work-exhausted' }), /reserve remains protected/);
  assert.equal(budget('tool', [], { phase: 'working-after:head' }).status, 0);
  assert.equal(budget('tool', [], { phase: 'delete-owned-disposable-ddev' }).status, 0);
  assert.equal(calls.length, 5);
});

test('fixed adapter registry exposes modes, not packet command or shell strings', () => {
  assert.deepEqual(assemblyAdapterArgs('scripts/assembly.php', 'plan'), [
    'drush', 'php:script', 'scripts/assembly.php', '--', 'plan'
  ]);
  assert.deepEqual(assemblyAdapterArgs('scripts/assembly.php', 'apply-prefix', {
    prefixCount: 2,
    planFingerprint: DIGEST
  }), [
    'drush', 'php:script', 'scripts/assembly.php', '--', 'apply-prefix', '2', DIGEST
  ]);
  assert.throws(() => assemblyAdapterArgs('scripts/assembly.php', 'failpoint'), /unsupported fixed/i);
  assert.throws(() => assemblyAdapterArgs('scripts/assembly.php', 'restore'), /unsupported fixed/i);
  assert.throws(() => assemblyAdapterArgs('scripts/assembly.php', 'sh -c anything'), /unsupported fixed/i);
});

test('fixture identity probe binds opaque storage identity to the exact target set', () => {
  const target = { kind: 'entity', entityType: 'node', stableId: `uuid:${TARGET_UUID}` };
  const identity = captureAssemblyFixtureIdentity({
    execute: () => ({
      status: 0,
      stdout: JSON.stringify({
        schemaVersion: 'public-kit.assembly-fixture-identity.1',
        rows: [{ key: `entity:node:uuid:${TARGET_UUID}`, identitySha256: sha256('opaque-id-and-revision') }]
      }),
      stderr: ''
    }),
    projectRoot: process.cwd(),
    targets: [{ surface: 'node', target }]
  });
  assert.equal(identity.rows.length, 1);
  assert.match(identity.fingerprint, /^sha256:/);
});

test('disposable runner rejects an interrupted delete prefix before invoking the adapter', () => {
  const { root } = repositoryFixture();
  const commandLog = [];
  let applyPrefixCalls = 0;
  const spawn = (command, args, options) => {
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'describe') {
      const config = readFileSync(join(options.cwd, '.ddev', 'config.yaml'), 'utf8');
      const name = JSON.parse(config.match(/^name:\s*(.+)$/m)[1]);
      return {
        status: 0,
        stdout: JSON.stringify({ raw: { name, approot: options.cwd, primary_url: `https://${name}.ddev.site` } }),
        stderr: '',
        signal: null
      };
    }
    if (command === 'ddev' && args[0] === 'export-db') {
      const relativePath = args.find((argument) => argument.startsWith('--file='))?.slice('--file='.length);
      writeFileSync(join(options.cwd, relativePath), 'verifier-owned-database-backup');
      return { status: 0, stdout: 'exported', stderr: '', signal: null };
    }
    if (command === 'ddev' && args[0] === 'drush' && args[1] === 'php:script') {
      if (args[4] === 'plan') {
        return { status: 0, stdout: JSON.stringify(multiDryValue('delete')), stderr: '', signal: null };
      }
      applyPrefixCalls += 1;
      return { status: 0, stdout: '', stderr: '', signal: null };
    }
    if (command === 'ddev') return { status: 0, stdout: 'ok', stderr: '', signal: null };
    throw new Error(`Unexpected command: ${command} ${args.join(' ')}`);
  };
  const execute = createRecordedExecutor({ commandLog, spawn });
  execute.commandLog = commandLog;
  try {
    const report = runDisposableAssembly({
      ...persistenceDependencies(),
      captureState: () => portableState(),
      discoverCapabilities: () => parseAssemblyCapabilities({
        schemaVersion: 'public-kit.assembly-capabilities.1',
        entityTypes: ['thing'],
        bundleKeys: { thing: '' },
        bundles: { thing: [] },
        nodeBundles: [],
        menus: [],
        viewsAvailable: false,
        canvasEntityTypes: [],
        canvasComponentConfigs: [],
        sitemapConfigs: []
      }),
      execute,
      projectRoot: root
    });
    assert.equal(report.valid, false);
    assert.match(report.errors.join('\n'), /--allow-owned-deletes/);
    assert.equal(applyPrefixCalls, 0);
    assert.equal(commandLog.some((row) => row.argv?.includes('apply-prefix')), false);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('mocked disposable run proves two verifier-selected interruptions, exact restoration, no-op rerun, and fixture survival', () => {
  const { root } = repositoryFixture();
  const commandLog = [];
  const spawnCalls = [];
  let planCall = 0;
  const spawn = (command, args, options) => {
    spawnCalls.push({ command, args, options });
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'start') {
      const config = readFileSync(join(options.cwd, '.ddev', 'config.yaml'), 'utf8');
      assert.match(config, /^performance_mode: "none"$/m);
      assert.doesNotMatch(config, /performance_mode: "mutagen"/);
      return { status: 0, stdout: 'started', stderr: '', signal: null };
    }
    if (command === 'ddev' && args[0] === 'describe') {
      const config = readFileSync(join(options.cwd, '.ddev', 'config.yaml'), 'utf8');
      const name = JSON.parse(config.match(/^name:\s*(.+)$/m)[1]);
      return { status: 0, stdout: JSON.stringify({ raw: { name, approot: options.cwd, primary_url: `https://${name}.ddev.site` } }), stderr: '', signal: null };
    }
    if (command === 'ddev' && args[0] === 'export-db') {
      const relativePath = args.find((argument) => argument.startsWith('--file='))?.slice('--file='.length);
      assert.ok(relativePath);
      writeFileSync(join(options.cwd, relativePath), 'verifier-owned-database-backup');
      return { status: 0, stdout: 'exported', stderr: '', signal: null };
    }
    if (command === 'ddev' && args[0] === 'import-db') {
      return { status: 0, stdout: 'imported', stderr: '', signal: null };
    }
    if (command === 'ddev' && args[0] === 'drush' && args[1] === 'php:script') {
      const mode = args[4];
      if (mode === 'plan') {
        const action = planCall < 3 ? 'create' : 'unchanged';
        planCall += 1;
        return { status: 0, stdout: JSON.stringify(multiDryValue(action)), stderr: '', signal: null };
      }
      assert.equal(mode, 'apply-prefix');
      return { status: 0, stdout: '', stderr: '', signal: null };
    }
    if (command === 'ddev') return { status: 0, stdout: 'ok', stderr: '', signal: null };
    throw new Error(`Unexpected command: ${command} ${args.join(' ')}`);
  };
  const execute = createRecordedExecutor({
    commandLog,
    environment: {
      ...process.env,
      COMPOSE_FILE: '/tmp/ambient-compose.yaml',
      COMPOSE_PROJECT_NAME: 'ambient-project',
      DDEV_NO_TUI: 'false',
      DDEV_XDG_CONFIG_HOME: '/tmp/ambient-ddev-home',
      XDG_CONFIG_HOME: '/tmp/ambient-xdg-home'
    },
    spawn
  });
  execute.commandLog = commandLog;
  const createdHashes = [sha256('created-1'), sha256('created-2'), sha256('created-3')];
  const states = [
    portableState(),
    portableState(),
    portableState({ entityHashes: createdHashes.slice(0, 1) }),
    portableState(),
    portableState(),
    portableState({ entityHashes: createdHashes.slice(0, 2) }),
    portableState(),
    portableState(),
    portableState({ entityHashes: createdHashes }),
    portableState({ entityHashes: createdHashes }),
    portableState({ entityHashes: createdHashes }),
    portableState({ entityHashes: createdHashes, extension: true, clean: false }),
    portableState({ entityHashes: createdHashes, extension: true, clean: false }),
    portableState({ entityHashes: createdHashes, extension: true, clean: false })
  ];
  const capabilities = parseAssemblyCapabilities({
    schemaVersion: 'public-kit.assembly-capabilities.1',
    entityTypes: ['thing'],
    bundleKeys: { thing: '' },
    bundles: { thing: [] },
    nodeBundles: [],
    menus: [],
    viewsAvailable: false,
    canvasEntityTypes: [],
    canvasComponentConfigs: [],
    sitemapConfigs: []
  });
  const persistenceTracker = {};
  try {
    const report = runDisposableAssembly({
      ...persistenceDependencies(persistenceTracker),
      captureFixtureIdentity: () => ({
        schemaVersion: 'public-kit.assembly-fixture-identity.1',
        rows: [{ key: 'config:agent_ready.extension_fixture', identitySha256: sha256('fixture-identity') }],
        fingerprint: sha256('stable-fixture-identity')
      }),
      captureState() {
        const state = states.shift();
        assert.ok(state, 'unexpected extra state capture');
        return state;
      },
      discoverCapabilities: () => capabilities,
      execute,
      installFixtures: () => ({
        schemaVersion: 'public-kit.assembly-fixtures.1',
        tokenSha256: sha256('fixture'),
        targets: [{ surface: 'view', target: { kind: 'config', name: 'agent_ready.extension_fixture' } }]
      }),
      projectRoot: root
    });

    assert.equal(report.valid, true, JSON.stringify(report.errors));
    assert.equal(report.gateId, 'G-ASSEMBLY-01');
    assert.equal(report.substrate.ready, true);
    assert.equal(report.dryRuns.first.summary.create, 3);
    assert.equal(report.dryRuns.secondNoOp.summary.unchanged, 3);
    assert.equal(report.dryRuns.postExtensionNoOp.summary.unchanged, 3);
    assert.equal(report.secondRun.exactComparison.match, true);
    assert.equal(report.extensionSurvival.targetProof.valid, true);
    assert.equal(report.extensionSurvival.fixtureInstallationChanges.length, 1);
    assert.deepEqual(report.failureAndRestoration.interruptionCutPoints, [1, 2]);
    assert.equal(report.failureAndRestoration.trials.length, 2);
    assert.deepEqual(report.failureAndRestoration.trials.map((trial) => trial.observedChanges.length), [1, 2]);
    assert.equal(report.failureAndRestoration.exactRestorationComparison.match, true);
    assert.equal(persistenceTracker.fileRestores, 2);
    assert.equal(persistenceTracker.fileBackupDisposals, 1);
    assert.ok(persistenceTracker.persistenceCaptures >= 10);
    assert.ok(persistenceTracker.identityCaptures >= 10);
    assert.equal(persistenceTracker.storageResidualCaptures, 6);
    assert.equal(commandLog.filter((row) => row.argv?.[1] === 'import-db').length, 2);
    assert.equal(report.workingTargetProof.drupalCommandCount, 0);
    assert.equal(report.workingTargetProof.untouched, true);
    assert.equal(report.disposable.cleanup.removedClone, true);
    assert.equal(report.evidenceScope.authoritativeForDefaultHandoff, false);
    const ddevCalls = spawnCalls.filter((call) => call.command === 'ddev');
    assert.ok(ddevCalls.length > 0);
    assert.equal(new Set(ddevCalls.map((call) => call.options.env.XDG_CONFIG_HOME)).size, 1);
    assert.equal(ddevCalls[0].options.env.XDG_CONFIG_HOME.endsWith('/xdg'), true);
    assert.notEqual(ddevCalls[0].options.env.XDG_CONFIG_HOME, '/tmp/ambient-xdg-home');
    for (const call of ddevCalls) {
      assert.deepEqual(
        Object.keys(call.options.env).filter((key) => /^(?:DDEV|COMPOSE)_/i.test(key)).sort(),
        ['DDEV_NO_INSTRUMENTATION', 'DDEV_NO_TUI']
      );
      assert.equal(call.options.env.DDEV_NO_INSTRUMENTATION, 'true');
      assert.equal(call.options.env.DDEV_NO_TUI, 'true');
    }
    const identityAndCleanupCalls = ddevCalls.filter((call) => ['describe', 'delete'].includes(call.args[0]));
    assert.ok(identityAndCleanupCalls.some((call) => call.args[0] === 'describe'));
    assert.ok(identityAndCleanupCalls.some((call) => call.args[0] === 'delete'));
    assert.ok(identityAndCleanupCalls.every((call) => call.options.env.XDG_CONFIG_HOME === ddevCalls[0].options.env.XDG_CONFIG_HOME));
    assert.equal(states.length, 0);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
