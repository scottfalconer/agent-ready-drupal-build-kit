import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  customMutableIdentityAuditErrors,
  inspectCustomMutableIdentity
} from '../bin/custom-mutable-identity-audit.mjs';
import { inspectCustomCodeFilesystem } from '../bin/verify.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workerPath = join(repoRoot, 'bin', 'mutable-identity-worker.mjs');

function javascriptFixture(source, {
  path = 'web/modules/custom/catalog/js/catalog.js',
  extraFiles = {}
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'custom-mutable-identity-'));
  const write = (path, contents) => {
    const absolute = join(root, path);
    mkdirSync(dirname(absolute), { recursive: true });
    writeFileSync(absolute, contents);
  };
  write('.ddev/config.yaml', 'name: custom-mutable-identity\ntype: drupal11\ndocroot: web\n');
  write('web/modules/custom/catalog/catalog.info.yml', 'name: Catalog\ntype: module\ncore_version_requirement: ^11\n');
  write(path, source);
  for (const [extraPath, contents] of Object.entries(extraFiles)) write(extraPath, contents);
  const inventory = inspectCustomCodeFilesystem(root);
  assert.equal(inventory.completed, true, inventory.errors.join('\n'));
  return { inventory, root };
}

test('inventories TypeScript source without pretending Acorn analyzed non-executable syntax', () => {
  const { inventory, root } = javascriptFixture(
    'const title: string = document.title;\n',
    { path: 'web/modules/custom/catalog/src/catalog.ts' }
  );
  const source = inventory.sourceFiles.find((candidate) => candidate.path.endsWith('/catalog.ts'));
  assert.equal(source.kind, 'typescript_source');
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.equal(audit.status, 'not_applicable');
  assert.equal(audit.completed, true);
  assert.deepEqual(audit.expectedFileIds, []);
  assert.deepEqual(audit.excludedTestFileIds, []);
  assert.deepEqual(audit.runtimeTypeScriptSurfaceIds, []);
  assert.deepEqual(audit.unboundRuntimeTypeScriptSurfaceIds, []);
  assert.deepEqual(audit.runtimeJavascriptSurfaceIds, []);
  assert.deepEqual(audit.unboundRuntimeJavascriptSurfaceIds, []);
});

test('a Drupal library cannot load TypeScript bytes as an unaudited runtime asset', () => {
  const { inventory, root } = javascriptFixture(
    'if (document.title === "Hero") choose();\n',
    {
      path: 'web/modules/custom/catalog/src/catalog.ts',
      extraFiles: {
        'web/modules/custom/catalog/catalog.libraries.yml': 'runtime:\n  js:\n    src/catalog.ts: {}\n'
      }
    }
  );
  const source = inventory.sourceFiles.find((candidate) => candidate.path.endsWith('/catalog.ts'));
  const runtimeSurface = inventory.sourceFiles
    .flatMap((candidate) => candidate.surfaces)
    .find((surface) => surface.kind === 'runtime_typescript_asset');
  assert.ok(runtimeSurface);
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.equal(audit.status, 'blocked');
  assert.equal(audit.completed, false);
  assert.deepEqual(audit.expectedFileIds, [source.id]);
  assert.deepEqual(audit.runtimeTypeScriptSurfaceIds, [runtimeSurface.id]);
  assert.deepEqual(audit.unboundRuntimeTypeScriptSurfaceIds, []);
  assert.ok(audit.javascript.blockers.some(({ code }) => code === 'unsupported_typescript'));
});

test('a Drupal library runtime registration overrides the test-path JavaScript exclusion', () => {
  const { inventory, root } = javascriptFixture(
    "if (window.location.pathname === '/hero') chooseTheme();\n",
    {
      path: 'web/modules/custom/catalog/tests/runtime.js',
      extraFiles: {
        'web/modules/custom/catalog/catalog.libraries.yml': 'runtime:\n  js:\n    tests/runtime.js: {}\n'
      }
    }
  );
  const source = inventory.sourceFiles.find((candidate) => candidate.path.endsWith('/tests/runtime.js'));
  assert.ok(source, 'Runtime-registered test-path JavaScript must remain in the source inventory.');
  const runtimeSurface = inventory.sourceFiles
    .flatMap((candidate) => candidate.surfaces)
    .find((surface) => surface.kind === 'runtime_javascript_asset');
  assert.ok(runtimeSurface);

  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.equal(audit.status, 'fail');
  assert.deepEqual(audit.expectedFileIds, [source.id]);
  assert.deepEqual(audit.excludedTestFileIds, []);
  assert.ok(audit.javascript.findings.some(({ fileId, identityKind, sinkKind }) =>
    fileId === source.id && identityKind === 'alias_or_path' && sinkKind === 'branch'
  ), JSON.stringify(audit.javascript));

  const unboundInventory = structuredClone(inventory);
  unboundInventory.sourceFiles = unboundInventory.sourceFiles.filter((candidate) => candidate.id !== source.id);
  const unboundAudit = inspectCustomMutableIdentity(root, unboundInventory, {});
  assert.equal(unboundAudit.status, 'blocked');
  assert.deepEqual(unboundAudit.unboundRuntimeJavascriptSurfaceIds, [runtimeSurface.id]);
  assert.ok(unboundAudit.javascript.blockers.some(({ code }) => code === 'runtime_script_asset_unbound'));
});

test('a local runtime JavaScript registration binds an exact source even under an excluded vendor directory', () => {
  const { inventory, root } = javascriptFixture(
    "if (window.location.pathname === '/hero') chooseTheme();\n",
    {
      path: 'web/modules/custom/catalog/vendor/runtime.js',
      extraFiles: {
        'web/modules/custom/catalog/catalog.libraries.yml': 'runtime:\n  js:\n    vendor/runtime.js: {}\n'
      }
    }
  );
  const source = inventory.sourceFiles.find((candidate) => candidate.path.endsWith('/vendor/runtime.js'));
  assert.ok(source, 'Every local registered JavaScript asset must bind an inventoried source.');
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.equal(audit.status, 'fail');
  assert.deepEqual(audit.expectedFileIds, [source.id]);
  assert.ok(audit.javascript.findings.some(({ fileId, identityKind, sinkKind }) =>
    fileId === source.id && identityKind === 'alias_or_path' && sinkKind === 'branch'
  ), JSON.stringify(audit.javascript));
});

test('legacy procedural test files remain inventoried but are excluded from production identity analysis', () => {
  const { inventory, root } = javascriptFixture(
    '<?php\nfunction catalog_test_label($node) { return $node->label(); }\n',
    { path: 'web/modules/custom/catalog/catalog.test' }
  );
  const source = inventory.sourceFiles.find((candidate) => candidate.path.endsWith('/catalog.test'));
  assert.equal(source.kind, 'procedural_php');
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.equal(audit.status, 'not_applicable');
  assert.equal(audit.completed, true);
  assert.deepEqual(audit.expectedFileIds, []);
  assert.deepEqual(audit.excludedTestFileIds, [source.id]);
});

test('combined mutable-identity audit passes direct display and binds exact source identities', () => {
  const { inventory, root } = javascriptFixture(`
    heading.textContent = document.title;
    image.alt = drupalSettings.media.name;
  `);
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.equal(audit.completed, true);
  assert.equal(audit.status, 'pass');
  assert.equal(audit.findingCount, 0);
  assert.equal(audit.blockerCount, 0);
  assert.deepEqual(audit.expectedFileIds, inventory.sourceFiles
    .filter((source) => source.kind === 'javascript')
    .map((source) => source.id));
  const runtime = {
    ...inventory,
    filesystemFingerprint: inventory.fingerprint,
    mutableIdentityAudit: audit
  };
  assert.deepEqual(customMutableIdentityAuditErrors(runtime), []);
});

test('combined mutable-identity audit fails exact and indirect JavaScript identity selection', () => {
  const { inventory, root } = javascriptFixture(`
    const alias = window.location.pathname;
    if (alias === '/preview') document.body.dataset.variant = 'preview';
    const first = second;
    const second = third;
    const third = document.title;
    if (first === 'News') document.body.className = 'news';
    const selected = cards[drupalSettings['media']['name']];
  `);
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  assert.ok(['fail', 'blocked'].includes(audit.status));
  assert.ok(audit.findingCount > 0 || audit.blockerCount > 0);
  const serialized = JSON.stringify(audit);
  assert.equal(serialized.includes('/preview'), false);
  assert.equal(serialized.includes('News'), false);
  assert.equal(serialized.includes('cards'), false);
});

test('combined mutable-identity audit blocks malformed and timed-out JavaScript workers', () => {
  const malformed = javascriptFixture('if (window.location.pathname === {');
  const malformedAudit = inspectCustomMutableIdentity(malformed.root, malformed.inventory, {});
  assert.equal(malformedAudit.status, 'blocked');
  assert.equal(malformedAudit.completed, false);

  const timed = javascriptFixture('heading.textContent = document.title;');
  const timedAudit = inspectCustomMutableIdentity(timed.root, timed.inventory, {}, {
    javascriptRunner: () => ({ timedOut: true })
  });
  assert.equal(timedAudit.status, 'blocked');
  assert.equal(timedAudit.completed, false);
  assert.ok(timedAudit.javascript.blockers.some((blocker) => blocker.code === 'worker_timeout'));
});

test('combined audit rejects worker file-record schema smuggling without retaining raw data', () => {
  const fixture = javascriptFixture('heading.textContent = document.title;');
  const audit = inspectCustomMutableIdentity(fixture.root, fixture.inventory, {}, {
    javascriptRunner: ({ input }) => {
      const execution = spawnSync(process.execPath, [workerPath], { encoding: 'utf8', input });
      assert.equal(execution.status, 0, execution.stderr);
      const forged = JSON.parse(execution.stdout);
      forged.files[0].sourceText = '/secret/customer/title';
      return { status: 0, stdout: JSON.stringify(forged) };
    }
  });
  assert.equal(audit.status, 'blocked');
  assert.equal(audit.completed, false);
  assert.ok(audit.javascript.blockers.some((blocker) => blocker.code === 'worker_invalid_output'));
  assert.doesNotMatch(JSON.stringify(audit), /secret|customer|sourceText/);
});

test('mutable-identity reconciliation rejects stale and forged result bindings', () => {
  const { inventory, root } = javascriptFixture('heading.textContent = document.title;');
  const audit = inspectCustomMutableIdentity(root, inventory, {});
  const runtime = {
    ...inventory,
    filesystemFingerprint: inventory.fingerprint,
    mutableIdentityAudit: audit
  };
  const stale = structuredClone(runtime);
  stale.mutableIdentityAudit.inputInventoryFingerprint = `sha256:${'f'.repeat(64)}`;
  assert.ok(customMutableIdentityAuditErrors(stale).some((error) => /fingerprint|not bound/.test(error)));

  const forged = structuredClone(runtime);
  forged.mutableIdentityAudit.javascript.findings.push({ rawSource: '/secret-alias' });
  assert.ok(customMutableIdentityAuditErrors(forged).some((error) => /fingerprint/.test(error)));
});
