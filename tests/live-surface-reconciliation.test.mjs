import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  materializeLiveSurfaceReconciliation,
  parseReconcileArgs,
  readbackWithLiveSurfaceReconciliation,
  refreshLiveSurfaceDraft
} from '../bin/reconcile.mjs';
import { liveSurfaceReconciliationErrors, reconcilableLiveSurface } from '../bin/verify.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const reconcileScript = join(repoRoot, 'bin', 'reconcile.mjs');

function inventory(items, fingerprintCharacter = 'a') {
  const countsByKind = {};
  for (const item of items) {
    countsByKind[item.kind] = (countsByKind[item.kind] ?? 0) + 1;
  }
  return {
    schemaVersion: 'public-kit.drupal-live-surface.1',
    confirmed: true,
    bounded: true,
    limit: 5_000,
    truncated: false,
    itemCount: items.length,
    fingerprint: `sha256:${fingerprintCharacter.repeat(64)}`,
    countsByKind,
    items,
    publicEditorialRoots: { node: ['page'] },
    excludedEntityTypes: {},
    errors: [],
    policy: { metadataOnly: true, rawContentRowsEmitted: false, privateEntityRowsQueried: false }
  };
}

function publicBundle(publishedCount = 1) {
  return {
    key: 'bundle:node:page',
    kind: 'bundle',
    entityType: 'node',
    bundle: 'page',
    publicEditorialRoot: true,
    publicSurface: true,
    publishedCount
  };
}

function privateView() {
  return {
    key: 'view_display:content:page_admin',
    kind: 'view_display',
    viewId: 'content',
    displayId: 'page_admin',
    path: '/admin/content',
    publicSurface: false
  };
}

function canvasCapability(available = false) {
  return {
    key: 'canvas_capability:runtime',
    kind: 'canvas_capability',
    available,
    status: available ? 'available' : 'unavailable',
    enabledModules: available ? ['canvas'] : [],
    editorRoutes: available ? ['canvas.boot.empty', 'canvas.boot.entity'] : [],
    reasonCodes: []
  };
}

function resolveDraft(draft) {
  const resolved = structuredClone(draft);
  for (const row of resolved.items) {
    if (row.key === 'bundle:node:page') {
      row.disposition.status = 'declare';
      row.disposition.packetReferences = ['pattern-map.json#contentTypes'];
    } else {
      row.disposition.status = 'exclude';
      row.disposition.owner = 'site maintainer';
      row.disposition.rationale = 'Administrative-only View.';
      row.disposition.evidence = ['evidence/live-surface/admin-view.txt'];
    }
  }
  return resolved;
}

test('reconcile CLI requires one mode and supports equals-form packet paths', () => {
  assert.deepEqual(parseReconcileArgs(['--draft', '--packet=review-packet']), {
    help: false,
    mode: 'draft',
    packet: 'review-packet'
  });
  assert.throws(() => parseReconcileArgs([]), /Choose exactly one/);
  assert.throws(() => parseReconcileArgs(['--draft', '--materialize']), /mutually exclusive/);

  const result = spawnSync(process.execPath, [reconcileScript, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--draft/);
  assert.match(result.stdout, /--materialize/);
});

test('draft refresh is deterministic and never auto-dispositions live surfaces', () => {
  const live = inventory([publicBundle(), privateView()]);
  const first = refreshLiveSurfaceDraft(live);
  const second = refreshLiveSurfaceDraft(live, { priorDraft: first });

  assert.equal(`${JSON.stringify(second, null, 2)}\n`, `${JSON.stringify(first, null, 2)}\n`);
  assert.deepEqual(first.items.map((row) => row.disposition.status), ['unresolved', 'unresolved']);
  assert.deepEqual(first.items.map((row) => row.recommendedDisposition), ['declare', 'exclude']);
  assert.deepEqual(first.items[0].disposition.packetReferences, []);
  assert.equal(first.authority, 'non_passing_work_queue');
  assert.equal(first.summary.unresolved, 2);
});

test('bundle candidate references follow the Drupal entity type instead of treating every bundle as a content type', () => {
  const live = inventory([
    publicBundle(),
    {
      key: 'bundle:media:image',
      kind: 'bundle',
      entityType: 'media',
      bundle: 'image',
      publicEditorialRoot: true,
      publicSurface: true,
      publishedCount: 1
    },
    {
      key: 'bundle:taxonomy_term:tags',
      kind: 'bundle',
      entityType: 'taxonomy_term',
      bundle: 'tags',
      publicEditorialRoot: true,
      publicSurface: true,
      publishedCount: 1
    },
    {
      key: 'bundle:block_content:basic',
      kind: 'bundle',
      entityType: 'block_content',
      bundle: 'basic',
      publicEditorialRoot: true,
      publicSurface: true,
      publishedCount: 1
    }
  ]);
  const draft = refreshLiveSurfaceDraft(live);
  const candidates = Object.fromEntries(
    draft.items.map((row) => [row.key, row.candidatePacketReferences])
  );

  assert.deepEqual(candidates['bundle:node:page'], ['pattern-map.json#contentTypes']);
  assert.deepEqual(candidates['bundle:media:image'], ['pattern-map.json#media']);
  assert.deepEqual(candidates['bundle:taxonomy_term:tags'], ['pattern-map.json#vocabularies']);
  assert.deepEqual(candidates['bundle:block_content:basic'], ['pattern-map.json#structuredContentModel']);
  assert.equal(candidates['bundle:media:image'].includes('pattern-map.json#contentTypes'), false);
});

test('unchanged dispositions survive refresh and count-only facts do not invalidate ownership', () => {
  const original = inventory([publicBundle(1), privateView()]);
  const authored = resolveDraft(refreshLiveSurfaceDraft(original));
  const refreshed = refreshLiveSurfaceDraft(
    inventory([publicBundle(4), privateView()], 'b'),
    { priorDraft: authored }
  );

  assert.equal(refreshed.items[0].disposition.status, 'declare');
  assert.deepEqual(refreshed.items[0].disposition.packetReferences, ['pattern-map.json#contentTypes']);
  assert.equal(refreshed.items[0].observed.publishedCount, 4);
  assert.equal(refreshed.items[0].invalidatedDisposition, null);
  assert.equal(refreshed.items[1].disposition.status, 'exclude');
  assert.equal(refreshed.summary.unresolved, 0);
});

test('changed disposition facts invalidate authored choices and preserve them only as history', () => {
  const original = inventory([publicBundle()]);
  const authored = resolveDraft(refreshLiveSurfaceDraft(original));
  const changedItem = { ...publicBundle(), publicEditorialRoot: false, publicSurface: false };
  const changed = refreshLiveSurfaceDraft(inventory([changedItem], 'c'), { priorDraft: authored });

  assert.equal(changed.items[0].disposition.status, 'unresolved');
  assert.equal(changed.items[0].invalidatedDisposition.reason, 'observed_disposition_basis_changed');
  assert.equal(changed.items[0].invalidatedDisposition.disposition.status, 'declare');
  assert.deepEqual(changed.unresolved[0].reasons, ['disposition_invalidated', 'disposition_required']);

  const repeated = refreshLiveSurfaceDraft(inventory([changedItem], 'c'), { priorDraft: changed });
  assert.deepEqual(repeated.items[0].invalidatedDisposition, changed.items[0].invalidatedDisposition);
});

test('new surfaces are unresolved and deleted or fabricated rows become stale until acknowledged', () => {
  const original = inventory([publicBundle(), privateView()]);
  const authored = resolveDraft(refreshLiveSurfaceDraft(original));
  const replacement = {
    key: 'menu:main',
    kind: 'menu',
    configName: 'system.menu.main',
    publicSurface: true
  };
  const changed = refreshLiveSurfaceDraft(inventory([publicBundle(), replacement], 'd'), { priorDraft: authored });

  assert.equal(changed.items.find((row) => row.key === 'menu:main').disposition.status, 'unresolved');
  assert.deepEqual(changed.staleItems.map((row) => row.key), ['view_display:content:page_admin']);
  assert.equal(changed.staleItems[0].acknowledgedRemoved, false);

  const acknowledged = structuredClone(changed);
  acknowledged.staleItems[0].acknowledgedRemoved = true;
  const pruned = refreshLiveSurfaceDraft(inventory([publicBundle(), replacement], 'd'), { priorDraft: acknowledged });
  assert.deepEqual(pruned.staleItems, []);

  const staleReadback = {
    schemaVersion: 'public-kit.live-surface-reconciliation.1',
    inventoryFingerprint: `sha256:${'0'.repeat(64)}`,
    declarations: [],
    exclusions: [
      {
        key: 'view_display:content:page_admin',
        kind: 'view_display',
        owner: 'site maintainer',
        rationale: 'Old administrative View.',
        evidence: ['evidence/live-surface/admin-view.txt']
      }
    ]
  };
  const importedStale = refreshLiveSurfaceDraft(inventory([publicBundle()], 'e'), {
    readbackReconciliation: staleReadback
  });
  importedStale.staleItems[0].acknowledgedRemoved = true;
  const acknowledgedReadbackStale = refreshLiveSurfaceDraft(inventory([publicBundle()], 'e'), {
    priorDraft: importedStale,
    readbackReconciliation: staleReadback
  });
  assert.equal(acknowledgedReadbackStale.staleItems[0].acknowledgedRemoved, true);
  assert.equal(acknowledgedReadbackStale.unresolved.some((row) => row.key === 'view_display:content:page_admin'), false);
  const acknowledgedSecondRefresh = refreshLiveSurfaceDraft(inventory([publicBundle()], 'e'), {
    priorDraft: acknowledgedReadbackStale,
    readbackReconciliation: staleReadback
  });
  assert.equal(acknowledgedSecondRefresh.staleItems[0].acknowledgedRemoved, true);
  acknowledgedSecondRefresh.items[0].disposition.status = 'declare';
  acknowledgedSecondRefresh.items[0].disposition.packetReferences = ['pattern-map.json#contentTypes'];
  const materializableAcknowledgment = refreshLiveSurfaceDraft(inventory([publicBundle()], 'e'), {
    priorDraft: acknowledgedSecondRefresh,
    readbackReconciliation: staleReadback
  });
  const acknowledgmentPacket = mkdtempSync(join(tmpdir(), 'live-surface-stale-ack-'));
  writeFileSync(join(acknowledgmentPacket, 'pattern-map.json'), '{"contentTypes":[]}\n');
  assert.deepEqual(
    materializeLiveSurfaceReconciliation(
      inventory([publicBundle()], 'e'),
      materializableAcknowledgment,
      acknowledgmentPacket
    ).errors,
    []
  );
  const prunedAfterMaterialization = refreshLiveSurfaceDraft(inventory([publicBundle()], 'e'), {
    priorDraft: materializableAcknowledgment,
    readbackReconciliation: {
      ...staleReadback,
      inventoryFingerprint: `sha256:${'e'.repeat(64)}`,
      exclusions: []
    }
  });
  assert.deepEqual(prunedAfterMaterialization.staleItems, []);
});

test('materialization reuses the strict live-surface gate and changes only the readback block', () => {
  const packetDir = mkdtempSync(join(tmpdir(), 'live-surface-materialize-'));
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  writeFileSync(join(packetDir, 'pattern-map.json'), '{"contentTypes":[{"machineName":"page"}]}\n');
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'admin-view.txt'), 'Administrative-only View.\n');

  const live = inventory([publicBundle(), privateView()]);
  const authored = resolveDraft(refreshLiveSurfaceDraft(live));
  const current = refreshLiveSurfaceDraft(live, { priorDraft: authored });
  const result = materializeLiveSurfaceReconciliation(live, current, packetDir);

  assert.deepEqual(result.errors, []);
  assert.deepEqual(liveSurfaceReconciliationErrors(live, result.reconciliation, packetDir), []);
  assert.equal(result.reconciliation.reconciliationComplete, true);
  assert.equal(result.reconciliation.declarations.length, 1);
  assert.equal(result.reconciliation.exclusions.length, 1);

  const readback = {
    schemaVersion: 'public-kit.drupal-readback.1',
    site: 'https://example.ddev.site',
    checkedAt: 'preserved',
    liveSurfaceReconciliation: { old: true },
    readbackComplete: false,
    blockers: ['preserved']
  };
  const updated = readbackWithLiveSurfaceReconciliation(readback, result.reconciliation);
  assert.deepEqual({ ...updated, liveSurfaceReconciliation: readback.liveSurfaceReconciliation }, readback);
  assert.equal(updated.readbackComplete, false);
  assert.deepEqual(updated.blockers, ['preserved']);
});

test('materialization refuses unresolved rows, stale facts, and missing packet evidence', () => {
  const packetDir = mkdtempSync(join(tmpdir(), 'live-surface-refusal-'));
  writeFileSync(join(packetDir, 'pattern-map.json'), '{"contentTypes":[]}\n');
  const live = inventory([publicBundle(), privateView()]);
  const unresolved = refreshLiveSurfaceDraft(live);
  const unresolvedResult = materializeLiveSurfaceReconciliation(live, unresolved, packetDir);
  assert.equal(unresolvedResult.reconciliation, null);
  assert.match(unresolvedResult.errors.join('\n'), /disposition_required/);

  const authored = resolveDraft(unresolved);
  const current = refreshLiveSurfaceDraft(live, { priorDraft: authored });
  const missingEvidence = materializeLiveSurfaceReconciliation(live, current, packetDir);
  assert.equal(missingEvidence.reconciliation, null);
  assert.match(missingEvidence.errors.join('\n'), /named owner, rationale, and non-empty packet-local evidence/);

  const altered = structuredClone(current);
  altered.items[0].observedFingerprint = `sha256:${'f'.repeat(64)}`;
  assert.throws(
    () => materializeLiveSurfaceReconciliation(live, altered, packetDir),
    /stale or altered verifier-owned facts/
  );
});

test('materialization rejects traversal, absolute, and symlink packet references', () => {
  const packetDir = mkdtempSync(join(tmpdir(), 'live-surface-unsafe-reference-'));
  const outsideDir = mkdtempSync(join(tmpdir(), 'live-surface-outside-'));
  const outsideEvidence = join(outsideDir, 'outside.txt');
  writeFileSync(outsideEvidence, 'outside\n');
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  symlinkSync(outsideEvidence, join(packetDir, 'evidence', 'live-surface', 'linked.txt'));
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'internal.txt'), 'inside\n');
  symlinkSync(
    join(packetDir, 'evidence', 'live-surface', 'internal.txt'),
    join(packetDir, 'evidence', 'live-surface', 'internal-linked.txt')
  );

  const bundleLive = inventory([publicBundle()]);
  const bundleDraft = refreshLiveSurfaceDraft(bundleLive);
  bundleDraft.items[0].disposition.status = 'declare';
  bundleDraft.items[0].disposition.packetReferences = ['../outside.json#contentTypes'];
  const traversalDraft = refreshLiveSurfaceDraft(bundleLive, { priorDraft: bundleDraft });
  assert.match(
    materializeLiveSurfaceReconciliation(bundleLive, traversalDraft, packetDir).errors.join('\n'),
    /specific section/
  );

  bundleDraft.items[0].disposition.packetReferences = [`${outsideEvidence}#contentTypes`];
  const absoluteDraft = refreshLiveSurfaceDraft(bundleLive, { priorDraft: bundleDraft });
  assert.match(
    materializeLiveSurfaceReconciliation(bundleLive, absoluteDraft, packetDir).errors.join('\n'),
    /specific section/
  );

  const viewLive = inventory([privateView()], 'b');
  const viewDraft = refreshLiveSurfaceDraft(viewLive);
  viewDraft.items[0].disposition.status = 'exclude';
  viewDraft.items[0].disposition.owner = 'site maintainer';
  viewDraft.items[0].disposition.rationale = 'Administrative-only View.';
  viewDraft.items[0].disposition.evidence = ['evidence/live-surface/linked.txt'];
  const linkedDraft = refreshLiveSurfaceDraft(viewLive, { priorDraft: viewDraft });
  assert.match(
    materializeLiveSurfaceReconciliation(viewLive, linkedDraft, packetDir).errors.join('\n'),
    /packet-local evidence/
  );

  viewDraft.items[0].disposition.evidence = ['evidence/live-surface/internal-linked.txt'];
  const internalLinkedDraft = refreshLiveSurfaceDraft(viewLive, { priorDraft: viewDraft });
  assert.match(
    materializeLiveSurfaceReconciliation(viewLive, internalLinkedDraft, packetDir).errors.join('\n'),
    /packet-local evidence/
  );
});

test('CLI refreshes a fake DDEV census and materializes only after explicit dispositions', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'live-surface-cli-'));
  const packetDir = join(projectRoot, 'review-packet');
  const fakeBin = join(projectRoot, 'fake-bin');
  mkdirSync(join(projectRoot, '.ddev'), { recursive: true });
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  mkdirSync(fakeBin);
  writeFileSync(
    join(projectRoot, '.ddev', 'config.yaml'),
    'name: reconcile-fixture\ntype: drupal11\ndocroot: web\n'
  );
  const readbackPath = join(packetDir, 'drupal-readback.json');
  const originalReadback = {
    schemaVersion: 'public-kit.drupal-readback.1',
    site: 'https://fixture.ddev.site',
    checkedAt: 'preserved',
    liveSurfaceReconciliation: {
      schemaVersion: 'public-kit.live-surface-reconciliation.1',
      inventoryFingerprint: '',
      countsByKind: {},
      declarations: [],
      exclusions: [],
      reconciliationComplete: false,
      blockers: []
    },
    readbackComplete: false,
    blockers: ['preserved']
  };
  writeFileSync(readbackPath, `${JSON.stringify(originalReadback, null, 2)}\n`);
  writeFileSync(join(packetDir, 'pattern-map.json'), '{"contentTypes":[{"machineName":"page"}]}\n');
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'admin-view.txt'), 'Administrative-only View.\n');

  const fakeDdev = join(fakeBin, 'ddev');
  writeFileSync(fakeDdev, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] !== 'drush' || args[1] !== 'php:eval') process.exit(1);
process.stdout.write(process.env.FAKE_LIVE_SURFACE + '\\n');
`);
  chmodSync(fakeDdev, 0o755);
  const live = inventory([publicBundle(), privateView()]);
  const environment = {
    ...process.env,
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_LIVE_SURFACE: JSON.stringify(live)
  };

  const draftResult = spawnSync(process.execPath, [reconcileScript, '--draft'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment
  });
  assert.equal(draftResult.status, 0, draftResult.stderr);
  assert.match(draftResult.stdout, /2 live, 2 unresolved/);
  const draftPath = join(packetDir, 'live-surface-reconciliation-draft.json');
  const draft = JSON.parse(readFileSync(draftPath, 'utf8'));
  assert.deepEqual(draft.items.map((row) => row.disposition.status), ['unresolved', 'unresolved']);

  const blockedResult = spawnSync(process.execPath, [reconcileScript, '--materialize'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment
  });
  assert.equal(blockedResult.status, 2, blockedResult.stderr);
  assert.deepEqual(JSON.parse(readFileSync(readbackPath, 'utf8')), originalReadback);

  writeFileSync(draftPath, `${JSON.stringify(resolveDraft(draft), null, 2)}\n`);
  const materializedResult = spawnSync(process.execPath, [reconcileScript, '--materialize'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment
  });
  assert.equal(materializedResult.status, 0, materializedResult.stderr);
  const materializedReadback = JSON.parse(readFileSync(readbackPath, 'utf8'));
  assert.equal(materializedReadback.checkedAt, 'preserved');
  assert.equal(materializedReadback.readbackComplete, false);
  assert.deepEqual(materializedReadback.blockers, ['preserved']);
  assert.equal(materializedReadback.liveSurfaceReconciliation.reconciliationComplete, true);
  assert.equal(materializedReadback.liveSurfaceReconciliation.declarations.length, 1);
  assert.equal(materializedReadback.liveSurfaceReconciliation.exclusions.length, 1);
});

test('reconcilableLiveSurface drops control-kind surfaces so Canvas capability is never surfaced for disposition', () => {
  const full = inventory([publicBundle(), privateView(), canvasCapability(false)]);
  const reconcilable = reconcilableLiveSurface(full);

  // Control-kind surfaces are removed from items/itemCount/countsByKind...
  assert.equal(reconcilable.items.length, 2);
  assert.equal(reconcilable.itemCount, 2);
  assert.equal(reconcilable.items.some((item) => item.kind === 'canvas_capability'), false);
  assert.equal('canvas_capability' in reconcilable.countsByKind, false);
  // ...but the census fingerprint still identifies the full live surface, so the
  // recorded reconciliation still matches the verifier's fresh census.
  assert.equal(reconcilable.fingerprint, full.fingerprint);

  const packetDir = mkdtempSync(join(tmpdir(), 'live-surface-canvas-'));
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  writeFileSync(join(packetDir, 'pattern-map.json'), '{"contentTypes":[{"machineName":"page"}]}\n');
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'admin-view.txt'), 'Administrative-only View.\n');

  const authored = resolveDraft(refreshLiveSurfaceDraft(reconcilable));
  const current = refreshLiveSurfaceDraft(reconcilable, { priorDraft: authored });
  const result = materializeLiveSurfaceReconciliation(reconcilable, current, packetDir);

  assert.deepEqual(result.errors, []);
  assert.equal(result.reconciliation.declarations.length, 1);
  assert.equal(result.reconciliation.exclusions.length, 1);
  // The materialized reconciliation is accepted by the strict validator run
  // against the FULL live inventory, which still contains the control kind.
  assert.deepEqual(liveSurfaceReconciliationErrors(full, result.reconciliation, packetDir), []);
});

test('CLI excludes the Canvas capability control surface from the worksheet (regression)', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'live-surface-canvas-cli-'));
  const packetDir = join(projectRoot, 'review-packet');
  const fakeBin = join(projectRoot, 'fake-bin');
  mkdirSync(join(projectRoot, '.ddev'), { recursive: true });
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  mkdirSync(fakeBin);
  writeFileSync(
    join(projectRoot, '.ddev', 'config.yaml'),
    'name: reconcile-canvas\ntype: drupal11\ndocroot: web\n'
  );
  const readbackPath = join(packetDir, 'drupal-readback.json');
  writeFileSync(readbackPath, `${JSON.stringify({
    schemaVersion: 'public-kit.drupal-readback.1',
    site: 'https://fixture.ddev.site',
    checkedAt: 'preserved',
    liveSurfaceReconciliation: {
      schemaVersion: 'public-kit.live-surface-reconciliation.1',
      inventoryFingerprint: '',
      countsByKind: {},
      declarations: [],
      exclusions: [],
      reconciliationComplete: false,
      blockers: []
    },
    readbackComplete: false,
    blockers: ['preserved']
  }, null, 2)}\n`);
  writeFileSync(join(packetDir, 'pattern-map.json'), '{"contentTypes":[{"machineName":"page"}]}\n');
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'admin-view.txt'), 'Administrative-only View.\n');

  const fakeDdev = join(fakeBin, 'ddev');
  writeFileSync(fakeDdev, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] !== 'drush' || args[1] !== 'php:eval') process.exit(1);
process.stdout.write(process.env.FAKE_LIVE_SURFACE + '\\n');
`);
  chmodSync(fakeDdev, 0o755);
  // The live census always emits canvas_capability:runtime; the worksheet must not.
  const live = inventory([publicBundle(), privateView(), canvasCapability(false)]);
  const environment = {
    ...process.env,
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_LIVE_SURFACE: JSON.stringify(live)
  };

  const draftResult = spawnSync(process.execPath, [reconcileScript, '--draft'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment
  });
  assert.equal(draftResult.status, 0, draftResult.stderr);
  assert.match(draftResult.stdout, /2 live, 2 unresolved/);
  const draftPath = join(packetDir, 'live-surface-reconciliation-draft.json');
  const draft = JSON.parse(readFileSync(draftPath, 'utf8'));
  assert.equal(draft.items.some((row) => row.kind === 'canvas_capability'), false);

  writeFileSync(draftPath, `${JSON.stringify(resolveDraft(draft), null, 2)}\n`);
  const materializedResult = spawnSync(process.execPath, [reconcileScript, '--materialize'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment
  });
  assert.equal(materializedResult.status, 0, materializedResult.stderr);
  const readback = JSON.parse(readFileSync(readbackPath, 'utf8'));
  assert.equal(readback.liveSurfaceReconciliation.reconciliationComplete, true);
  assert.equal('canvas_capability' in readback.liveSurfaceReconciliation.countsByKind, false);
});

// --- Upgrade path -----------------------------------------------------------
// Projects that ran reconcile before control kinds were excluded have a
// worksheet and/or a drupal-readback.json disposition that still names
// canvas_capability:runtime. The current census no longer emits it, so it must
// be pruned from every carry-forward source instead of stranding the project on
// "stale surface acknowledgment required" forever.

function preFixDraft({ acknowledgedRemoved = false, stale = false, dropKind = false } = {}) {
  const full = inventory([publicBundle(), privateView(), canvasCapability(false)]);
  const draft = refreshLiveSurfaceDraft(full);
  if (!stale) {
    assert.ok(
      draft.items.some((row) => row.key === 'canvas_capability:runtime'),
      'fixture must reproduce a pre-fix worksheet that lists the control kind'
    );
    if (dropKind) {
      for (const row of draft.items) {
        if (row.key === 'canvas_capability:runtime') delete row.kind;
      }
    }
    return draft;
  }
  draft.items = draft.items.filter((row) => row.key !== 'canvas_capability:runtime');
  draft.staleItems = [{
    key: 'canvas_capability:runtime',
    kind: 'canvas_capability',
    observedFingerprint: '',
    observed: {},
    previousDisposition: { status: 'unresolved', packetReferences: [], owner: '', rationale: '', evidence: [] },
    acknowledgedRemoved
  }];
  return draft;
}

const upgradeInventory = () =>
  reconcilableLiveSurface(inventory([publicBundle(), privateView(), canvasCapability(false)]));

test('a pre-fix worksheet listing the control kind does not strand the upgrade as a stale surface', () => {
  const draft = refreshLiveSurfaceDraft(upgradeInventory(), { priorDraft: preFixDraft() });

  assert.equal(draft.staleItems.some((row) => row.key === 'canvas_capability:runtime'), false);
  assert.equal(draft.unresolved.some((row) => row.key === 'canvas_capability:runtime'), false);
  assert.equal(draft.items.some((row) => row.kind === 'canvas_capability'), false);
  assert.equal(draft.summary.stale, 0);
});

test('a pre-fix worksheet that already demoted the control kind to an unacknowledged stale row is pruned', () => {
  const draft = refreshLiveSurfaceDraft(upgradeInventory(), { priorDraft: preFixDraft({ stale: true }) });

  assert.equal(draft.staleItems.some((row) => row.key === 'canvas_capability:runtime'), false);
  assert.equal(draft.unresolved.some((row) => row.key === 'canvas_capability:runtime'), false);
  assert.equal(draft.summary.stale, 0);
});

test('a pre-fix readback disposition for the control kind does not resurrect it as a stale surface', () => {
  const draft = refreshLiveSurfaceDraft(upgradeInventory(), {
    readbackReconciliation: {
      inventoryFingerprint: `sha256:${'a'.repeat(64)}`,
      countsByKind: { bundle: 1, view_display: 1, canvas_capability: 1 },
      declarations: [{ key: 'canvas_capability:runtime', kind: 'canvas_capability', packetReferences: ['pattern-map.json#canvas'] }],
      exclusions: []
    }
  });

  assert.equal(draft.staleItems.some((row) => row.key === 'canvas_capability:runtime'), false);
  assert.equal(draft.unresolved.some((row) => row.key === 'canvas_capability:runtime'), false);
});

test('a control-kind row that lost its kind field is still recognized by its key prefix', () => {
  const draft = refreshLiveSurfaceDraft(upgradeInventory(), { priorDraft: preFixDraft({ dropKind: true }) });

  assert.equal(draft.staleItems.some((row) => row.key === 'canvas_capability:runtime'), false);
  assert.equal(draft.unresolved.some((row) => row.key === 'canvas_capability:runtime'), false);
});

test('a genuinely removed non-control surface still requires stale acknowledgment', () => {
  // Guard against the prune being too broad: only control kinds may be dropped.
  const priorDraft = refreshLiveSurfaceDraft(inventory([publicBundle(), privateView(), canvasCapability(false)]));
  const shrunk = reconcilableLiveSurface(inventory([publicBundle(), canvasCapability(false)]));
  const draft = refreshLiveSurfaceDraft(shrunk, { priorDraft });

  assert.deepEqual(draft.staleItems.map((row) => row.key), ['view_display:content:page_admin']);
  assert.ok(draft.unresolved.some((row) =>
    row.key === 'view_display:content:page_admin' && row.reasons.includes('stale_surface_acknowledgment_required')));
});

test('CLI upgrades a project whose worksheet and readback were written before the control-kind exclusion', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'live-surface-canvas-upgrade-'));
  const packetDir = join(projectRoot, 'review-packet');
  const fakeBin = join(projectRoot, 'fake-bin');
  mkdirSync(join(projectRoot, '.ddev'), { recursive: true });
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  mkdirSync(fakeBin);
  writeFileSync(
    join(projectRoot, '.ddev', 'config.yaml'),
    'name: reconcile-canvas-upgrade\ntype: drupal11\ndocroot: web\n'
  );
  writeFileSync(join(packetDir, 'pattern-map.json'), '{"contentTypes":[{"machineName":"page"}]}\n');
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'admin-view.txt'), 'Administrative-only View.\n');

  const live = inventory([publicBundle(), privateView(), canvasCapability(false)]);

  // Exactly what a pre-fix run left on disk: a worksheet listing all three
  // surfaces, and a readback disposition that includes the control kind.
  const legacyDraft = resolveDraft(refreshLiveSurfaceDraft(live));
  writeFileSync(
    join(packetDir, 'live-surface-reconciliation-draft.json'),
    `${JSON.stringify(legacyDraft, null, 2)}\n`
  );
  const readbackPath = join(packetDir, 'drupal-readback.json');
  writeFileSync(readbackPath, `${JSON.stringify({
    schemaVersion: 'public-kit.drupal-readback.1',
    site: 'https://fixture.ddev.site',
    checkedAt: 'preserved',
    liveSurfaceReconciliation: {
      schemaVersion: 'public-kit.live-surface-reconciliation.1',
      inventoryFingerprint: live.fingerprint,
      countsByKind: live.countsByKind,
      declarations: [
        { key: 'bundle:node:page', kind: 'bundle', packetReferences: ['pattern-map.json#contentTypes'] },
        { key: 'canvas_capability:runtime', kind: 'canvas_capability', packetReferences: ['pattern-map.json#canvas'] }
      ],
      exclusions: [{
        key: 'view_display:content:page_admin',
        kind: 'view_display',
        owner: 'site maintainer',
        rationale: 'Administrative-only View.',
        evidence: ['evidence/live-surface/admin-view.txt']
      }],
      reconciliationComplete: true,
      blockers: []
    },
    readbackComplete: false,
    blockers: ['preserved']
  }, null, 2)}\n`);

  const fakeDdev = join(fakeBin, 'ddev');
  writeFileSync(fakeDdev, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] !== 'drush' || args[1] !== 'php:eval') process.exit(1);
process.stdout.write(process.env.FAKE_LIVE_SURFACE + '\\n');
`);
  chmodSync(fakeDdev, 0o755);
  const environment = {
    ...process.env,
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_LIVE_SURFACE: JSON.stringify(live)
  };

  // Before the upgrade prune this reported:
  //   Unresolved live surface canvas_capability:runtime: stale surface acknowledgment required.
  const materialized = spawnSync(process.execPath, [reconcileScript, '--materialize'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: environment
  });
  assert.equal(materialized.status, 0, materialized.stderr);
  assert.doesNotMatch(materialized.stderr, /canvas_capability:runtime/);

  const readback = JSON.parse(readFileSync(readbackPath, 'utf8'));
  assert.equal(readback.liveSurfaceReconciliation.reconciliationComplete, true);
  assert.equal('canvas_capability' in readback.liveSurfaceReconciliation.countsByKind, false);
  assert.equal(
    readback.liveSurfaceReconciliation.declarations.some((row) => row.key === 'canvas_capability:runtime'),
    false
  );
  // The materialized result must still satisfy the strict validator run against
  // the FULL census, which continues to emit the control kind.
  assert.deepEqual(liveSurfaceReconciliationErrors(live, readback.liveSurfaceReconciliation, packetDir), []);
});

test('the control-kind prune is scoped to exactly the canvas_capability namespace', () => {
  // The key-prefix fallback must not swallow sibling Canvas kinds, multi-colon
  // keys, case variants, or a leading-colon key.
  const keep = [
    { key: 'canvas_page:home', kind: 'canvas_page' },
    { key: 'canvas_component:hero', kind: 'canvas_component' },
    { key: 'canvas_capabilityX:runtime', kind: 'canvas_capabilityX' },
    // Multi-colon key; deliberately not the live publicBundle() key, so it is
    // genuinely removed rather than reconciled as a current surface.
    { key: 'bundle:node:article', kind: 'bundle' },
    { key: 'CANVAS_CAPABILITY:runtime', kind: 'CANVAS_CAPABILITY' },
    { key: ':canvas_capability', kind: '' },
    { key: 'nocolonkey', kind: '' }
  ];
  const priorDraft = {
    schemaVersion: 'public-kit.live-surface-reconciliation-draft.1',
    scope: 'live_surface',
    authority: 'non_passing_work_queue',
    inventoryFingerprint: `sha256:${'a'.repeat(64)}`,
    countsByKind: {},
    items: [],
    staleItems: [
      ...keep.map((row) => ({ ...row, acknowledgedRemoved: false })),
      { key: 'canvas_capability:runtime', kind: 'canvas_capability', acknowledgedRemoved: false }
    ],
    unresolved: [],
    summary: { live: 0, unresolved: 0, invalidated: 0, stale: keep.length + 1 }
  };

  const draft = refreshLiveSurfaceDraft(
    reconcilableLiveSurface(inventory([publicBundle(), canvasCapability(false)])),
    { priorDraft }
  );
  const staleKeys = draft.staleItems.map((row) => row.key).sort();

  assert.deepEqual(staleKeys, keep.map((row) => row.key).sort(), 'only the control kind may be pruned');
  assert.equal(staleKeys.includes('canvas_capability:runtime'), false);
});

test('a mislabelled row for a live surface keeps its authored disposition as history', () => {
  // Relabelling a real surface's kind to a control kind must not delete the
  // authored owner/rationale/evidence. The key is still live, so it is a
  // mislabel, not a stranded control-kind row, and the normal kind-mismatch
  // path must record it as invalidated history.
  const live = reconcilableLiveSurface(inventory([publicBundle(), canvasCapability(false)]));
  const priorDraft = {
    schemaVersion: 'public-kit.live-surface-reconciliation-draft.1',
    scope: 'live_surface',
    authority: 'non_passing_work_queue',
    inventoryFingerprint: live.fingerprint,
    countsByKind: live.countsByKind,
    items: [{
      key: 'bundle:node:page',
      kind: 'canvas_capability',
      observedFingerprint: 'sha256:stale',
      dispositionBasisFingerprint: 'sha256:stale',
      observed: {},
      disposition: {
        status: 'exclude',
        packetReferences: [],
        owner: 'site maintainer',
        rationale: 'Authored rationale that must survive.',
        evidence: ['evidence/live-surface/admin-view.txt']
      },
      invalidatedDisposition: null
    }],
    staleItems: [],
    unresolved: [],
    summary: { live: 1, unresolved: 0, invalidated: 0, stale: 0 }
  };

  const draft = refreshLiveSurfaceDraft(live, { priorDraft });
  const row = draft.items.find((item) => item.key === 'bundle:node:page');

  assert.ok(row, 'the live surface must still be present');
  assert.equal(row.kind, 'bundle', 'the row is re-derived from the live census, not the mislabel');
  assert.ok(row.invalidatedDisposition, 'the authored disposition must be preserved as history');
  assert.equal(row.invalidatedDisposition.disposition.rationale, 'Authored rationale that must survive.');
  assert.equal(draft.staleItems.length, 0, 'a live surface must never be demoted to stale');
});
