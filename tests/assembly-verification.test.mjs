import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  assertChangesWithinProvenance,
  assertDeletesAuthorized,
  deriveAssemblyChanges,
  loadValidatedAssemblyInputs,
  parseAssemblyDryRun,
  parseAssemblyPlan,
  parseAssemblyProvenance,
  reconcileDryRun
} from '../bin/assembly-contract.mjs';
import {
  assertDryRunSurfacesAvailable,
  assertFixturePlanAgainstCapabilities,
  captureAssemblyFixtureIdentity,
  parseAssemblyCapabilities
} from '../bin/assembly-fixtures.mjs';
import { createRecordedExecutor } from '../bin/disposable-ddev.mjs';
import { buildPortableReproductionState } from '../bin/reproduction-state.mjs';
import { collectFileManifest, sha256 } from '../bin/state-fingerprint.mjs';
import {
  assemblyAdapterArgs,
  createAssemblyBudget,
  runDisposableAssembly
} from '../bin/verify-assembly.mjs';

const UUID = '11111111-1111-4111-8111-111111111111';
const TARGET_UUID = '22222222-2222-4222-8222-222222222222';
const DIGEST = `sha256:${'a'.repeat(64)}`;

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
      protocol: 'drush_assembly_contract_v1',
      source: { path: 'scripts/assembly.php', sha256: DIGEST },
      failureProof: 'tested_restoration'
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

function portableState({ entityHash = '', extension = false, clean = true } = {}) {
  const configItems = [{ name: 'system.site', sha256: sha256({ uuid: UUID }) }];
  if (extension) configItems.push({ name: 'agent_ready.extension_fixture', sha256: sha256({ marker: true }) });
  return buildPortableReproductionState({
    confirmed: true,
    errors: [],
    siteUuid: UUID,
    configSyncDirectory: 'config/sync',
    configStatusClean: clean,
    config: { items: configItems },
    entities: {
      types: entityHash ? { thing: { items: [{ stableId: `uuid:${TARGET_UUID}`, bundle: 'thing', sha256: entityHash }] } } : {}
    },
    managedFiles: { items: [] },
    routes: [{
      path: '/', status: 200, finalPath: '/',
      titleSha256: sha256('Fixture'), h1Sha256: sha256('Fixture'),
      bodyTextSha256: sha256('Fixture'), bodyTextLength: 7
    }]
  });
}

function repositoryFixture() {
  const root = mkdtempSync(join(tmpdir(), 'assembly-verification-fixture-'));
  mkdirSync(join(root, '.ddev'), { recursive: true });
  mkdirSync(join(root, 'config', 'sync'), { recursive: true });
  mkdirSync(join(root, 'review-packet'), { recursive: true });
  mkdirSync(join(root, 'scripts'), { recursive: true });
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
  const provenance = provenanceValue();
  writeFileSync(join(root, 'assembly-provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
  const plan = planValue({
    substratePlan: { path: 'reproduction-plan.json', sha256: sha256(readFileSync(join(root, 'reproduction-plan.json'))) },
    provenance: { path: 'assembly-provenance.json', sha256: sha256(readFileSync(join(root, 'assembly-provenance.json'))) },
    adapter: {
      protocol: 'drush_assembly_contract_v1',
      source: { path: 'scripts/assembly.php', sha256: sha256(readFileSync(join(root, 'scripts', 'assembly.php'))) },
      failureProof: 'tested_restoration'
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
  assert.equal(parsed.adapter.protocol, 'drush_assembly_contract_v1');
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
      sourceKey: 'fixture:all*', surface: 'config', target: { kind: 'config', name: 'fixture.*' }
    }]
  }), /wildcard|exact configuration/i);

  const provenance = parseAssemblyProvenance(provenanceValue());
  assert.throws(() => parseAssemblyDryRun({
    ...dryValue('create'), summary: { create: 0, update: 0, delete: 0, unchanged: 0, total: 1 }
  }, provenance), /summary\.create/);
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

test('mocked disposable run proves first change, no-op rerun, fixture survival, dirty failpoint, and exact restoration', () => {
  const { root } = repositoryFixture();
  const commandLog = [];
  let planCall = 0;
  const spawn = (command, args, options) => {
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'describe') {
      const local = readFileSync(join(options.cwd, '.ddev', 'config.local.yaml'), 'utf8');
      const name = local.match(/^name:\s*(.+)$/m)?.[1]?.trim();
      return { status: 0, stdout: JSON.stringify({ raw: { name, primary_url: `https://${name}.ddev.site` } }), stderr: '', signal: null };
    }
    if (command === 'ddev' && args[0] === 'drush' && args[1] === 'php:script') {
      const mode = args.at(-1);
      if (mode === 'plan') {
        const action = planCall === 0 ? 'create' : 'unchanged';
        planCall += 1;
        return { status: 0, stdout: JSON.stringify(dryValue(action)), stderr: '', signal: null };
      }
      if (mode === 'failpoint') return { status: 42, stdout: '', stderr: 'intentional fixture failpoint', signal: null };
      return { status: 0, stdout: '', stderr: '', signal: null };
    }
    if (command === 'ddev') return { status: 0, stdout: 'ok', stderr: '', signal: null };
    throw new Error(`Unexpected command: ${command} ${args.join(' ')}`);
  };
  const execute = createRecordedExecutor({ commandLog, spawn });
  execute.commandLog = commandLog;
  const createdHash = sha256({ value: 'created' });
  const failureHash = sha256({ value: 'mid-run-failure' });
  const states = [
    portableState(),
    portableState({ entityHash: createdHash }),
    portableState({ entityHash: createdHash }),
    portableState({ entityHash: createdHash, extension: true, clean: false }),
    portableState({ entityHash: createdHash, extension: true, clean: false }),
    portableState({ entityHash: failureHash, extension: true, clean: false }),
    portableState({ entityHash: createdHash, extension: true, clean: false })
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
  try {
    const report = runDisposableAssembly({
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
    assert.equal(report.dryRuns.first.summary.create, 1);
    assert.equal(report.dryRuns.secondNoOp.summary.unchanged, 1);
    assert.equal(report.dryRuns.postExtensionNoOp.summary.unchanged, 1);
    assert.equal(report.secondRun.exactComparison.match, true);
    assert.equal(report.extensionSurvival.targetProof.valid, true);
    assert.equal(report.extensionSurvival.fixtureInstallationChanges.length, 1);
    assert.equal(report.failureAndRestoration.observedMidRunChangeCount, 1);
    assert.equal(report.failureAndRestoration.exactRestorationComparison.match, true);
    assert.equal(report.workingTargetProof.drupalCommandCount, 0);
    assert.equal(report.workingTargetProof.untouched, true);
    assert.equal(report.disposable.cleanup.removedClone, true);
    assert.equal(report.evidenceScope.authoritativeForDefaultHandoff, false);
    assert.equal(states.length, 0);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
