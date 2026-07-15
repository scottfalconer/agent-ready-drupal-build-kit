#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const reportPath = resolve(process.argv[2] ?? '');
if (!process.argv[2]) {
  throw new Error('Usage: node tests/assert-disposable-reproduction-smoke.mjs <report.json>');
}

const report = JSON.parse(readFileSync(reportPath, 'utf8'));
const expectedAdapters = [
  'ddev_start',
  'ddev_composer_install',
  'drush_site_install_existing_config',
  'ddev_import_files_archive',
  'drush_php_script',
  'drush_config_import',
  'drush_cache_rebuild'
];

assert.equal(report.schemaVersion, 'public-kit.reproduction-verification.1');
assert.equal(report.gateId, 'G-REPRO-01');
assert.equal(report.valid, true, JSON.stringify(report.errors));
assert.equal(report.runStatus, 'pass');
assert.equal(report.mode, 'clean_install_config_import');
assert.equal(report.source.exactHeadClone, true);
assert.deepEqual(report.adapters, expectedAdapters);
assert.equal(report.declaredPrimaryRouteCount, 1);
assert.deepEqual(report.declaredPrimaryRoutes, ['/reproduction-proof']);
assert.ok(report.declaredInputs.length >= 6);
assert.ok(report.declaredInputs.every((input) => input.declaredSha256 === input.actualSha256));

assert.equal(report.reproductionComparison.match, true);
assert.equal(report.workingTargetProof.untouched, true);
assert.equal(report.workingTargetProof.sourceUnchanged, true);
assert.equal(report.workingTargetProof.stateComparison.match, true);
assert.equal(report.disposable.ownershipNamespaceConfirmed, true);
assert.deepEqual(report.disposable.cleanup, { deletedDdevProject: true, removedClone: true });

const before = report.readback.workingBefore;
const disposable = report.readback.disposable;
const after = report.readback.workingAfter;
for (const state of [before, disposable, after]) {
  assert.equal(state.confirmed, true);
  assert.equal(state.configStatusClean, true);
  assert.equal(state.configSyncDirectory, 'config/sync');
  assert.ok(state.config.count > 0);
  assert.ok(state.entities.count >= 3);
  assert.equal(state.managedFiles.count, 1);
  assert.equal(state.routeCount, 1);
  assert.equal(state.routes[0].path, '/reproduction-proof');
  assert.equal(state.routes[0].status, 200);
  assert.ok(state.routes[0].bodyTextLength > 0);
}
assert.equal(before.fingerprint, disposable.fingerprint);
assert.equal(before.fingerprint, after.fingerprint);

const stableIds = Object.values(before.entities.types)
  .flatMap((type) => type.items)
  .map((item) => item.stableId);
for (const uuid of [
  'uuid:303c7d48-7a90-4fc3-bb50-789da1baedc1',
  'uuid:74cc8780-79e8-4eda-8e75-b9f6f4b2fac7',
  'uuid:b5496955-cf0f-4d2c-8e12-bb51e4e2f856'
]) {
  assert.ok(stableIds.includes(uuid), `Missing stable entity ${uuid}`);
}

assert.ok(report.commands.length > expectedAdapters.length);
assert.ok(report.commands.every((command) => command.exitStatus === 0));
const disposablePhases = new Set(report.commands
  .filter((command) => command.target === 'disposable')
  .map((command) => command.phase));
for (const phase of [
  'provision:ddev_start',
  'provision:ddev_composer_install',
  'provision:drush_site_install_existing_config',
  'provision:ddev_import_files_archive',
  'provision:drush_php_script',
  'provision:drush_config_import',
  'provision:drush_cache_rebuild',
  'portable-drupal-readback',
  'delete-owned-disposable-ddev'
]) {
  assert.ok(disposablePhases.has(phase), `Missing real disposable command phase ${phase}`);
}

process.stdout.write('Real disposable Drupal reproduction evidence is complete and internally consistent.\n');
