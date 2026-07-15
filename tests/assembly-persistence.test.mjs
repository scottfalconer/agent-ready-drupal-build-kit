import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  ASSEMBLY_ENTITY_IDENTITY_SCHEMA,
  ASSEMBLY_FILE_SURFACES_SCHEMA,
  ASSEMBLY_PERSISTENCE_SCHEMA,
  ASSEMBLY_STORAGE_RESIDUAL_SCHEMA,
  DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS,
  assertDisposableSourceBytesEqual,
  assertExactEntityIdentityEquality,
  assertExactPersistenceEquality,
  assertExactProvenanceStorageResidual,
  assertFirstRunPersistenceChanges,
  assertNoOpPersistence,
  captureAssemblyPersistenceSnapshot,
  captureDisposableSourceBytes,
  captureProvenanceEntityIdentity,
  captureProvenanceStorageResidual,
  compareAssemblyPersistenceSnapshots,
  compareProvenanceEntityIdentity,
  createAssemblyFileBackup,
  disposeAssemblyFileBackup,
  parseAssemblyFileSurfaceSnapshot,
  parseAssemblyPersistenceSnapshot,
  parseProvenanceEntityIdentity,
  parseProvenanceStorageResidual,
  registerVerifierDatabaseSourceExclusion,
  restoreAssemblyFileBackup
} from '../bin/assembly-persistence.mjs';
import { sha256 } from '../bin/state-fingerprint.mjs';

const UUID = '11111111-2222-4333-8444-555555555555';

function table(id, version = 'baseline', rowCount = 1, policy = 'durable', metadata = {}) {
  return {
    id: `table:${id}`,
    policy,
    rowCount,
    sha256: sha256(`${id}:rows:${version}`),
    definitionSha256: metadata.definitionSha256 ?? sha256(`${id}:definition`),
    sequenceSha256: metadata.sequenceSha256 ?? sha256(`${id}:sequence`)
  };
}

function fileSurface(id, version = 'baseline', { available = true, fileCount = 1, directoryCount = 0, byteCount = 8 } = {}) {
  return {
    id: `file:${id}`,
    available,
    fileCount: available ? fileCount : 0,
    directoryCount: available ? directoryCount : 0,
    byteCount: available ? byteCount : 0,
    ephemeralPrefixes: id === 'public' ? ['css/', 'js/', 'php/', 'styles/'] : [],
    sha256: sha256(`${id}:durable:${version}:${available}`),
    physicalSha256: sha256(`${id}:physical:${version}:${available}`)
  };
}

function snapshot({ tables, files = [fileSurface('private'), fileSurface('public')] }) {
  const sortedTables = [...tables].sort((left, right) => left.id.localeCompare(right.id));
  const sortedFiles = [...files].sort((left, right) => left.id.localeCompare(right.id));
  return parseAssemblyPersistenceSnapshot({
    schemaVersion: ASSEMBLY_PERSISTENCE_SCHEMA,
    complete: true,
    tableCount: sortedTables.length,
    aggregateRowCount: sortedTables.reduce((sum, row) => sum + row.rowCount, 0),
    ephemeralTableIds: sortedTables.filter(({ policy }) => policy === 'ephemeral').map(({ id }) => id),
    tables: sortedTables,
    files: sortedFiles,
    aggregateSha256: sha256({ files: sortedFiles, tables: sortedTables })
  });
}

function fileSnapshot(files) {
  const rows = [...files].sort((left, right) => left.id.localeCompare(right.id));
  return parseAssemblyFileSurfaceSnapshot({
    schemaVersion: ASSEMBLY_FILE_SURFACES_SCHEMA,
    complete: true,
    files: rows,
    aggregateSha256: sha256(rows)
  }, { surfaces: rows.map(({ id }) => id.replace('file:', '')) });
}

function identityRaw(version, {
  present = true,
  tableIds = ['table:node', 'table:node_field_data'],
  createSequenceTableIds = ['table:node'],
  updateSequenceTableIds = [],
  storageIdentitySha256 = sha256(`storage:${version}`),
  revisionIdentitySha256 = sha256(`revision:${version}`)
} = {}) {
  const identitySha256 = sha256({ storageIdentitySha256, revisionIdentitySha256 });
  const rows = [{
    key: `entity:node:uuid:${UUID}`,
    present,
    identitySha256,
    storageIdentitySha256,
    revisionIdentitySha256,
    tableIds,
    createSequenceTableIds,
    updateSequenceTableIds
  }];
  return {
    schemaVersion: ASSEMBLY_ENTITY_IDENTITY_SCHEMA,
    rows,
    aggregateSha256: sha256(rows)
  };
}

const identityTargets = [{ key: `entity:node:uuid:${UUID}` }];

test('whole-table snapshots are deterministic and keep narrow ephemeral policy explicit', () => {
  const ordered = snapshot({ tables: [
    table('users_field_data'),
    table('cache_render', 'volatile', 3, 'ephemeral'),
    table('config', 'active', 2)
  ] });
  const reordered = snapshot({ tables: [
    table('config', 'active', 2),
    table('users_field_data'),
    table('cache_render', 'volatile', 3, 'ephemeral')
  ] });
  assert.deepEqual(ordered, reordered);
  assert.deepEqual(ordered.ephemeralTableIds, ['table:cache_render']);

  const cacheChanged = snapshot({ tables: [
    table('config', 'active', 2),
    table('users_field_data'),
    table('cache_render', 'repopulated', 4, 'ephemeral')
  ] });
  const comparison = compareAssemblyPersistenceSnapshots(ordered, cacheChanged);
  assert.equal(comparison.exact, true);
  assert.equal(comparison.physicalExact, false);
  assert.deepEqual(comparison.changedEphemeralTableIds, ['table:cache_render']);
});

test('user, order, and key-value mutations remain durable and outside a config allowlist', () => {
  const names = ['users_field_data', 'commerce_order', 'key_value'];
  const baselineTables = [table('config'), ...names.map((name) => table(name))];
  const baseline = snapshot({ tables: baselineTables });
  for (const name of names) {
    const changed = snapshot({
      tables: baselineTables.map((row) => row.id === `table:${name}` ? table(name, 'secret mutation') : row)
    });
    assert.throws(() => assertFirstRunPersistenceChanges({
      before: baseline,
      after: changed,
      allowedTableIds: ['table:config']
    }), new RegExp(`table:${name}`));
  }
});

test('database definitions are immutable and sequence changes require their own exact allowlist', () => {
  const baseline = snapshot({ tables: [table('node')] });
  const definitionChanged = snapshot({ tables: [table('node', 'baseline', 1, 'durable', {
    definitionSha256: sha256('node:changed-definition')
  })] });
  assert.throws(() => assertFirstRunPersistenceChanges({
    before: baseline,
    after: definitionChanged,
    allowedTableIds: ['table:node'],
    allowedSequenceTableIds: ['table:node']
  }), /never authorize DDL/);
  assert.throws(() => assertExactPersistenceEquality(baseline, definitionChanged), /not durably persistence-equivalent/);

  const sequenceChanged = snapshot({ tables: [table('node', 'baseline', 1, 'durable', {
    sequenceSha256: sha256('node:changed-sequence')
  })] });
  assert.throws(() => assertFirstRunPersistenceChanges({
    before: baseline,
    after: sequenceChanged,
    allowedTableIds: ['table:node']
  }), /table:node/);
  assert.equal(assertFirstRunPersistenceChanges({
    before: baseline,
    after: sequenceChanged,
    allowedTableIds: ['table:node'],
    allowedSequenceTableIds: ['table:node']
  }).changedSequenceTableIds[0], 'table:node');
});

test('storage residuals bind exact owners and reject unrelated rows in an allowed entity table', () => {
  const key = `entity:node:uuid:${UUID}`;
  const provenance = {
    resources: [{
      sourceKey: 'fixture:node',
      surface: 'node',
      target: { kind: 'entity', entityType: 'node', stableId: `uuid:${UUID}` }
    }]
  };
  const raw = (version = 'baseline') => {
    const ownerKeys = [key];
    const owners = [{ key, tableIds: ['table:node', 'table:node_access', 'table:node_revision'] }];
    const tables = owners[0].tableIds.map((id) => ({
      id,
      residualRowCount: 1,
      residualSha256: sha256(`${id}:unrelated:${version}`)
    }));
    return {
      schemaVersion: ASSEMBLY_STORAGE_RESIDUAL_SCHEMA,
      complete: true,
      ownerKeys,
      owners,
      tables,
      aggregateSha256: sha256({ ownerKeys, owners, tables })
    };
  };
  const baseline = parseProvenanceStorageResidual(raw(), provenance);
  assert.equal(assertExactProvenanceStorageResidual(baseline, baseline).exact, true);
  const unrelatedRevisionChanged = parseProvenanceStorageResidual(raw('changed'), provenance);
  assert.throws(() => assertExactProvenanceStorageResidual(
    baseline,
    unrelatedRevisionChanged
  ), /outside exact prefix ownership/);

  const missingCoverage = raw();
  missingCoverage.owners[0].tableIds.push('table:node_field_data');
  missingCoverage.aggregateSha256 = sha256({
    ownerKeys: missingCoverage.ownerKeys,
    owners: missingCoverage.owners,
    tables: missingCoverage.tables
  });
  assert.throws(() => parseProvenanceStorageResidual(missingCoverage, provenance), /table coverage/);

  let source = '';
  const actual = captureProvenanceStorageResidual({
    projectRoot: '/disposable',
    provenance,
    execute(_command, args) {
      source = args[2];
      return { status: 0, stdout: JSON.stringify(raw()) };
    }
  });
  assert.equal(actual.aggregateSha256, baseline.aggregateSha256);
  assert.match(source, /storage_residual_selector_overlap/);
  assert.match(source, /node_access/);
  assert.match(source, /menu_tree/);
  assert.match(source, /views\.view\./);
  assert.match(source, /'router'/);
  assert.match(source, /entity_id/);
});

test('table, row, file-entry, file-byte, and explicit truncation caps fail closed', () => {
  const oneTable = snapshot({ tables: [table('config')] });
  assert.throws(() => parseAssemblyPersistenceSnapshot({
    ...oneTable,
    tables: [table('config'), table('key_value')],
    tableCount: 2,
    aggregateRowCount: 2,
    ephemeralTableIds: [],
    aggregateSha256: sha256({ files: oneTable.files, tables: [table('config'), table('key_value')] })
  }, { limits: { ...DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS, maxTables: 1 } }), /table/i);

  const oversizedRow = table('users_field_data', 'many', 2);
  assert.throws(() => parseAssemblyPersistenceSnapshot({
    schemaVersion: ASSEMBLY_PERSISTENCE_SCHEMA,
    complete: true,
    tableCount: 1,
    aggregateRowCount: 2,
    ephemeralTableIds: [],
    tables: [oversizedRow],
    files: oneTable.files,
    aggregateSha256: sha256({ files: oneTable.files, tables: [oversizedRow] })
  }, { limits: { ...DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS, maxRowsPerTable: 1 } }), /rowCount/i);

  const tooManyFiles = fileSurface('public', 'many', { fileCount: 2 });
  assert.throws(() => parseAssemblyFileSurfaceSnapshot({
    schemaVersion: ASSEMBLY_FILE_SURFACES_SCHEMA,
    complete: true,
    files: [tooManyFiles],
    aggregateSha256: sha256([tooManyFiles])
  }, {
    surfaces: ['public'],
    limits: { ...DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS, maxEntriesPerFileSurface: 1 }
  }), /fileCount/i);

  const tooManyBytes = fileSurface('public', 'large', { byteCount: 2 });
  assert.throws(() => parseAssemblyFileSurfaceSnapshot({
    schemaVersion: ASSEMBLY_FILE_SURFACES_SCHEMA,
    complete: true,
    files: [tooManyBytes],
    aggregateSha256: sha256([tooManyBytes])
  }, {
    surfaces: ['public'],
    limits: { ...DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS, maxBytesPerFileSurface: 1 }
  }), /byteCount/i);

  assert.throws(() => parseAssemblyPersistenceSnapshot({
    schemaVersion: ASSEMBLY_PERSISTENCE_SCHEMA,
    complete: false,
    reason: 'table_row_cap'
  }), /truncated|incomplete/i);
});

test('no-op and restoration equality detect durable tables and public/private surface changes', () => {
  const baseline = snapshot({ tables: [table('config'), table('key_value')] });
  assert.equal(assertNoOpPersistence(baseline, baseline).exact, true);
  const baselinePublic = baseline.files.find(({ id }) => id === 'file:public');
  const generatedOnly = snapshot({
    tables: baseline.tables,
    files: [
      baseline.files.find(({ id }) => id === 'file:private'),
      { ...baselinePublic, physicalSha256: sha256('regenerated public css') }
    ]
  });
  const generatedComparison = compareAssemblyPersistenceSnapshots(baseline, generatedOnly);
  assert.equal(generatedComparison.exact, true);
  assert.equal(generatedComparison.physicalExact, false);
  assert.deepEqual(generatedComparison.changedEphemeralFileSurfaceIds, ['file:public']);
  const fileChanged = snapshot({
    tables: baseline.tables,
    files: [fileSurface('private'), fileSurface('public', 'changed')]
  });
  assert.throws(() => assertNoOpPersistence(baseline, fileChanged), /file:public/);
  const dbChanged = snapshot({ tables: [table('config'), table('key_value', 'changed')] });
  assert.throws(() => assertNoOpPersistence(baseline, dbChanged), /table:key_value/);
});

test('opaque entity identity catches delete/recreate churn without exposing storage or revision IDs', () => {
  const before = parseProvenanceEntityIdentity(identityRaw(sha256('storage=77;revision=91')), identityTargets);
  const after = parseProvenanceEntityIdentity(identityRaw(sha256('storage=88;revision=92')), identityTargets);
  const comparison = compareProvenanceEntityIdentity(before, after);
  assert.deepEqual(comparison.changedTargetKeys, [`entity:node:uuid:${UUID}`]);
  assert.deepEqual(comparison.changedStorageTargetKeys, [`entity:node:uuid:${UUID}`]);
  assert.deepEqual(comparison.changedRevisionTargetKeys, [`entity:node:uuid:${UUID}`]);
  assert.throws(() => assertExactEntityIdentityEquality(before, after), /storage\/revision identity/);
  const evidence = JSON.stringify({ before, after });
  assert.doesNotMatch(evidence, /storage=77|revision=91|storage=88|revision=92/);
});

test('entity identity fails closed for non-UUID, unsupported storage, malformed output, and extra raw fields', () => {
  const unsupportedProvenance = {
    resources: [{ target: { kind: 'entity', entityType: 'shortcut', stableId: 'id:admin' } }]
  };
  assert.throws(() => captureProvenanceEntityIdentity({
    execute: () => assert.fail('unsupported target must fail before command execution'),
    projectRoot: '/unused',
    provenance: unsupportedProvenance
  }), /UUID identity/);

  const provenance = {
    resources: [{ target: { kind: 'entity', entityType: 'node', stableId: `uuid:${UUID}` } }]
  };
  assert.throws(() => captureProvenanceEntityIdentity({
    execute: () => ({ status: 1, stderr: 'raw database secret must not be repeated' }),
    projectRoot: '/unused',
    provenance
  }), /^Error: assembly-entity-identity-readback failed\.$/);

  const malformed = identityRaw(sha256('opaque'));
  malformed.rows[0].storageId = '987654321';
  assert.throws(() => parseProvenanceEntityIdentity(malformed, identityTargets), /unsupported field/);
  assert.throws(() => parseProvenanceEntityIdentity(identityRaw(sha256('opaque'), { tableIds: [] }), identityTargets), /non-empty/);
  assert.throws(() => parseProvenanceEntityIdentity({
    ...identityRaw(sha256('opaque')),
    aggregateSha256: sha256('wrong')
  }, identityTargets), /aggregate fingerprint/);
});

test('fixed identity readback accepts no packet command and records only a verifier source digest', () => {
  const provenance = {
    resources: [{ target: { kind: 'entity', entityType: 'node', stableId: `uuid:${UUID}` } }]
  };
  const storageSecret = 'internal-storage-id-987654321';
  let recordedArgs;
  const value = captureProvenanceEntityIdentity({
    projectRoot: '/disposable',
    provenance,
    execute(command, args, options) {
      assert.equal(command, 'ddev');
      assert.deepEqual(args.slice(0, 2), ['drush', 'php:eval']);
      assert.equal(args.length, 3);
      assert.doesNotMatch(args[2], /packetCommand|adapterCommand/);
      recordedArgs = options.recordedArgs;
      return { status: 0, stdout: JSON.stringify(identityRaw(sha256(storageSecret))) };
    }
  });
  assert.match(recordedArgs[2], /^<verifier-owned:sha256:/);
  assert.doesNotMatch(JSON.stringify(value), new RegExp(storageSecret));
});

test('whole-database readback is fixed verifier PHP and returns no raw row or file values', () => {
  const secret = 'customer@example.test order-424242 private-file-name.pdf';
  const expected = snapshot({ tables: [table('users_field_data', sha256(secret)), table('commerce_order', sha256(secret))] });
  let source;
  let recordedArgs;
  const actual = captureAssemblyPersistenceSnapshot({
    projectRoot: '/disposable',
    execute(command, args, options) {
      assert.equal(command, 'ddev');
      assert.deepEqual(args.slice(0, 2), ['drush', 'php:eval']);
      source = args[2];
      recordedArgs = options.recordedArgs;
      return { status: 0, stdout: JSON.stringify(expected) };
    }
  });
  assert.match(source, /findTables\('%'\)/);
  assert.match(source, /hash\('sha256', \$bytes\)/);
  assert.match(source, /SHOW CREATE TABLE/);
  assert.match(source, /information_schema\.TRIGGERS/);
  assert.match(source, /AUTO_INCREMENT/);
  assert.doesNotMatch(source, /packetCommand|adapterCommand/);
  assert.match(recordedArgs[2], /^<verifier-owned:sha256:/);
  assert.doesNotMatch(JSON.stringify(actual), /customer@example\.test|order-424242|private-file-name/);
});

test('file backup handles are temp-owned, can exclude only their own source bytes, and reject symlink replacement', () => {
  const root = mkdtempSync(join(tmpdir(), 'assembly-file-backup-'));
  mkdirSync(join(root, '.ddev'));
  const publicFiles = [fileSurface('public')];
  const publicSnapshot = fileSnapshot(publicFiles);
  const baselineSnapshot = fileSnapshot([fileSurface('private', 'missing', { available: false }), ...publicFiles]);
  let backupSource = '';
  const execute = (_command, args, options) => {
    if (options.phase === 'assembly-file-surface-backup' || options.phase === 'assembly-file-surface-restore') {
      if (options.phase === 'assembly-file-surface-backup') backupSource = args[2];
      return { status: 0, stdout: JSON.stringify({
        schemaVersion: ASSEMBLY_FILE_SURFACES_SCHEMA,
        complete: true,
        files: publicSnapshot.files,
        aggregateSha256: publicSnapshot.aggregateSha256
      }) };
    }
    assert.fail(`Unexpected phase ${options.phase}`);
  };
  const backup = createAssemblyFileBackup({ execute, projectRoot: root, baseline: baselineSnapshot });
  assert.match(backupSource, /file_surface_overlaps_backup/);
  assert.match(backupSource, /file_surfaces_overlap/);
  assert.deepEqual(backup.surfaces, ['public']);
  assert.match(backup.relativePath, /^\.ddev\/\.agent-ready-assembly-files-/);
  assert.equal(restoreAssemblyFileBackup({ execute, projectRoot: root, backup }).aggregateSha256, backup.aggregateSha256);

  const backupRoot = join(root, backup.relativePath);
  const outside = mkdtempSync(join(tmpdir(), 'assembly-file-backup-outside-'));
  rmSync(backupRoot, { recursive: true });
  symlinkSync(outside, backupRoot);
  assert.throws(() => restoreAssemblyFileBackup({ execute, projectRoot: root, backup }), /symbolic link/);
});

test('source snapshots bind tracked, nonignored, and ignored runtime files while excluding only owned backup bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'assembly-source-bytes-'));
  mkdirSync(join(root, '.ddev'));
  writeFileSync(join(root, '.gitignore'), 'ignored.txt\nsettings.local.php\n');
  writeFileSync(join(root, 'tracked.txt'), 'baseline\n');
  writeFileSync(join(root, 'settings.local.php'), '<?php // baseline local runtime settings.\n');
  execFileSync('git', ['init', '--quiet'], { cwd: root });
  execFileSync('git', ['add', '.'], { cwd: root });
  execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'baseline'], { cwd: root });
  const execute = (command, args, options) => {
    const result = spawnSync(command, args, { cwd: options.cwd, encoding: null, maxBuffer: options.maxBuffer });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr, error: result.error };
  };
  const baseline = captureDisposableSourceBytes({ execute, projectRoot: root });
  writeFileSync(join(root, 'ignored.txt'), 'ignored mutation\n');
  assert.equal(assertDisposableSourceBytesEqual(baseline, captureDisposableSourceBytes({ execute, projectRoot: root })), true);

  writeFileSync(join(root, 'settings.local.php'), '<?php // mutated local runtime settings.\n');
  assert.throws(() => assertDisposableSourceBytesEqual(
    baseline,
    captureDisposableSourceBytes({ execute, projectRoot: root })
  ), /changed/);
  writeFileSync(join(root, 'settings.local.php'), '<?php // baseline local runtime settings.\n');

  writeFileSync(join(root, 'tracked.txt'), 'tracked mutation\n');
  assert.throws(() => assertDisposableSourceBytesEqual(
    baseline,
    captureDisposableSourceBytes({ execute, projectRoot: root })
  ), /changed/);
  writeFileSync(join(root, 'tracked.txt'), 'baseline\n');
  writeFileSync(join(root, 'untracked.txt'), 'untracked mutation\n');
  assert.throws(() => assertDisposableSourceBytesEqual(
    baseline,
    captureDisposableSourceBytes({ execute, projectRoot: root })
  ), /changed/);

  rmSync(join(root, 'untracked.txt'));
  const publicSnapshot = fileSnapshot([fileSurface('public')]);
  const backup = createAssemblyFileBackup({
    projectRoot: root,
    surfaces: ['public'],
    execute: () => ({ status: 0, stdout: JSON.stringify(publicSnapshot) })
  });
  const databasePath = '.ddev/agent-ready-assembly-12345678-1234-4123-8123-123456789abc.sql.gz';
  writeFileSync(join(root, databasePath), 'verifier database backup bytes');
  const databaseExclusion = registerVerifierDatabaseSourceExclusion({ projectRoot: root, relativePath: databasePath });
  const ownedBaseline = captureDisposableSourceBytes({
    execute,
    projectRoot: root,
    excludedFileBackups: [backup],
    excludedSourceArtifacts: [databaseExclusion]
  });
  assert.equal(assertDisposableSourceBytesEqual(
    ownedBaseline,
    captureDisposableSourceBytes({
      execute,
      projectRoot: root,
      excludedFileBackups: [backup],
      excludedSourceArtifacts: [databaseExclusion]
    })
  ), true);
  writeFileSync(join(root, databasePath), 'mutated database backup bytes');
  assert.throws(() => captureDisposableSourceBytes({
    execute,
    projectRoot: root,
    excludedFileBackups: [backup],
    excludedSourceArtifacts: [databaseExclusion]
  }), /bytes changed/);
  assert.equal(disposeAssemblyFileBackup({ projectRoot: root, backup }), true);
  assert.match(readFileSync(join(root, 'tracked.txt'), 'utf8'), /baseline/);
});
