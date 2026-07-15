#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const reportPath = resolve(process.argv[2] ?? '');
if (!process.argv[2]) {
  throw new Error('Usage: node tests/assert-disposable-assembly-smoke.mjs <report.json>');
}

const report = JSON.parse(readFileSync(reportPath, 'utf8'));
const hashPattern = /^sha256:[a-f0-9]{64}$/;
const expectedSources = [
  'assembly_smoke:01_create',
  'assembly_smoke:02_delete',
  'assembly_smoke:03_update',
  'assembly_smoke:04_unchanged'
];
const expectedStableIds = [
  'uuid:91111111-1111-4111-8111-111111111111',
  'uuid:93333333-3333-4333-8333-333333333333',
  'uuid:92222222-2222-4222-8222-222222222222',
  'uuid:94444444-4444-4444-8444-444444444444'
];

assert.equal(report.schemaVersion, 'public-kit.assembly-verification.1');
assert.equal(report.gateId, 'G-ASSEMBLY-01');
assert.equal(report.valid, true, JSON.stringify(report.errors));
assert.equal(report.runStatus, 'pass');
assert.deepEqual(report.errors, []);
assert.equal(report.evidenceScope.launchEvidence, true);
assert.equal(report.evidenceScope.authoritativeForDefaultHandoff, false);

assert.equal(report.source.planPath, 'assembly-plan.json');
assert.equal(report.source.exactHeadClone, true);
assert.match(report.source.head, /^[a-f0-9]{40}$/);
assert.match(report.source.runtimeCodeFingerprint, hashPattern);
assert.equal(report.declaredInputs.length, 9);
assert.ok(report.declaredInputs.every((input) => input.declaredSha256 === input.actualSha256));

assert.equal(report.adapter.protocol, 'drush_assembly_contract_v2');
assert.deepEqual(report.adapter.fixedModes, ['plan', 'apply-prefix']);
assert.equal(report.adapter.failureProof, 'verifier_controlled_restoration');
assert.equal(report.adapter.arbitraryCommandSurface, false);
assert.equal(report.deletionProof.policy, 'provenance_owned_only');
assert.equal(report.deletionProof.cliOptIn, true);
assert.equal(report.deletionProof.firstRunDeleteCount, 1);
assert.equal(report.deletionProof.interruptedPrefixDeleteCount, 1);

assert.equal(report.workingTargetProof.untouched, true);
assert.equal(report.workingTargetProof.sourceUnchanged, true);
assert.equal(report.workingTargetProof.drupalCommandCount, 0);
assert.equal(report.workingTargetProof.headBefore, report.workingTargetProof.headAfter);
assert.equal(
  report.workingTargetProof.trackedWorktreeBeforeSha256,
  report.workingTargetProof.trackedWorktreeAfterSha256
);
assert.equal(
  report.workingTargetProof.untrackedWorktreeBeforeFingerprint,
  report.workingTargetProof.untrackedWorktreeAfterFingerprint
);
assert.equal(
  report.workingTargetProof.runtimeCodeBeforeFingerprint,
  report.workingTargetProof.runtimeCodeAfterFingerprint
);

assert.equal(report.disposable.ownershipNamespaceConfirmed, true);
assert.equal(report.disposable.sourceTreeUnchanged, true);
assert.equal(report.disposable.fileBackupDisposed, true);
assert.deepEqual(report.disposable.cleanup, { deletedDdevProject: true, removedClone: true });

assert.equal(report.substrate.ready, true);
assert.equal(report.substrate.mode, 'snapshot_restore');
assert.deepEqual(report.substrate.capabilities.applicable, {
  node: true,
  menu: true,
  alias: true,
  view: true,
  canvas: true,
  sitemap: true
});
assert.ok(report.substrate.capabilities.nodeBundles.includes('proof'));
assert.ok(report.substrate.capabilities.menus.includes('main'));
assert.ok(report.substrate.capabilities.canvasEntityTypes.includes('canvas_page'));
assert.ok(report.substrate.capabilities.canvasComponentConfigs.includes('canvas.component.block.system_branding_block'));
assert.ok(report.substrate.capabilities.sitemapConfigs.includes('simple_sitemap.sitemap.default'));

const first = report.dryRuns.first;
assert.deepEqual(first.summary, { create: 1, update: 1, delete: 1, unchanged: 1, total: 4 });
assert.deepEqual(first.operations.map(({ action }) => action), ['create', 'delete', 'update', 'unchanged']);
assert.deepEqual(first.operations.map(({ sourceKey }) => sourceKey), expectedSources);
assert.deepEqual(first.operations.map(({ target }) => target.stableId), expectedStableIds);
assert.ok(first.operations.every(({ surface, target }) => surface === 'node' && target.kind === 'entity' && target.entityType === 'node'));
assert.match(first.fingerprint, hashPattern);
for (const dryRun of [report.dryRuns.secondNoOp, report.dryRuns.postExtensionNoOp]) {
  assert.deepEqual(dryRun.summary, { create: 0, update: 0, delete: 0, unchanged: 4, total: 4 });
  assert.deepEqual(dryRun.operations.map(({ action }) => action), ['unchanged', 'unchanged', 'unchanged', 'unchanged']);
  assert.deepEqual(dryRun.operations.map(({ sourceKey }) => sourceKey), expectedSources);
}
assert.equal(report.dryRuns.postRestorationPlan.fingerprint, first.fingerprint);

assert.equal(report.firstRun.reconciliation.valid, true);
assert.equal(report.secondRun.reconciliation.valid, true);
assert.equal(report.secondRun.exactComparison.match, true);
assert.equal(report.extensionSurvival.reconciliation.valid, true);
assert.equal(report.extensionSurvival.exactComparison.match, true);
assert.equal(report.extensionSurvival.targetProof.valid, true);
assert.deepEqual(
  report.extensionSurvival.targetProof.rows.map(({ surface }) => surface).sort(),
  ['alias', 'canvas_component', 'canvas_page', 'menu', 'node', 'sitemap', 'view']
);
assert.ok(report.extensionSurvival.targetProof.rows.every(({ presentBefore, presentAfter, unchanged }) => (
  presentBefore && presentAfter && unchanged
)));
assert.equal(
  report.extensionSurvival.fixtureIdentityBefore.fingerprint,
  report.extensionSurvival.fixtureIdentityAfter.fingerprint
);

assert.deepEqual(report.failureAndRestoration.interruptionCutPoints, [1, 2]);
assert.equal(report.failureAndRestoration.trials.length, 2);
assert.deepEqual(report.failureAndRestoration.trials.map(({ prefixCount }) => prefixCount), [1, 2]);
assert.deepEqual(report.failureAndRestoration.trials.map(({ deleteCount }) => deleteCount), [0, 1]);
assert.ok(report.failureAndRestoration.trials.some(({ deleteCount }) => deleteCount === 1));
assert.deepEqual(report.failureAndRestoration.trials.map(({ observedChanges }) => observedChanges.length), [1, 2]);
for (const trial of report.failureAndRestoration.trials) {
  assert.equal(trial.prefixReconciliation.valid, true);
  assert.equal(trial.storageResidualComparison.exact, true);
  assert.equal(trial.exactRestorationComparison.match, true);
  assert.equal(trial.persistenceRestorationComparison.exact, true);
  assert.equal(trial.identityRestorationComparison.exact, true);
  assert.equal(trial.exactPlanComparison.match, true);
  assert.equal(trial.persistencePlanComparison.exact, true);
  assert.equal(trial.identityPlanComparison.exact, true);
  assert.equal(trial.restoredPlanFingerprint, first.fingerprint);
}
assert.equal(report.failureAndRestoration.exactRestorationComparison.match, true);

const checksums = report.stateChecksums;
assert.ok(Object.values(checksums).every((value) => hashPattern.test(value)));
assert.equal(checksums.baseline, checksums.firstPlanState);
assert.equal(checksums.baseline, checksums.restoredState);
assert.equal(checksums.firstState, checksums.secondPlanState);
assert.equal(checksums.firstState, checksums.secondState);
assert.equal(checksums.fixtureState, checksums.extensionPlanState);
assert.equal(checksums.fixtureState, checksums.extensionState);
assert.notEqual(checksums.baseline, checksums.firstState);
assert.notEqual(checksums.firstState, checksums.fixtureState);

const persistence = report.persistenceProof;
for (const snapshot of Object.values(persistence).filter((value) => value?.aggregateSha256)) {
  assert.match(snapshot.aggregateSha256, hashPattern);
}
assert.equal(persistence.baseline.aggregateSha256, persistence.firstPlan.aggregateSha256);
assert.equal(persistence.firstRun.aggregateSha256, persistence.secondPlan.aggregateSha256);
assert.equal(persistence.firstRun.aggregateSha256, persistence.secondRun.aggregateSha256);
assert.equal(persistence.extensionFixtures.aggregateSha256, persistence.extensionPlan.aggregateSha256);
assert.equal(persistence.extensionFixtures.aggregateSha256, persistence.extensionRun.aggregateSha256);
assert.equal(persistence.baseline.aggregateSha256, persistence.restored.aggregateSha256);

assert.equal(report.storageResidualProof.firstRunComparison.exact, true);
assert.equal(report.budget.exceeded, false);
assert.ok(report.commands.length > 0);
assert.ok(report.commands.every((command) => command.exitStatus === 0));
assert.equal(report.commands.some((command) => command.target === 'working' && command.argv?.[0] === 'ddev'), false);

process.stdout.write('Real disposable Drupal assembly evidence is complete and internally consistent.\n');
