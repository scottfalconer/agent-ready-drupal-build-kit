import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, parse, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { deflateSync } from 'node:zlib';

import {
  CUSTOM_CONFIG_SCHEMA_AUDIT_PHP,
  CUSTOM_ROUTE_AUDIT_PHP,
  customCapabilityId,
  customCodeReconciliationErrors,
  customCodeResultFingerprint,
  customExtensionFiles,
  customTestMethodId,
  agentContinuation,
  createCriticalAssetContext,
  createLiveHttpContext,
  DRUPAL_ENTITY_INVENTORY_EVAL,
  DRUPAL_LIVE_EDITOR_SURFACE_EVAL,
  DRUPAL_LIVE_SURFACE_EVAL,
  DRUPAL_RUNTIME_FACTS_EVAL,
  exportedSeoUrlPortabilityFindings,
  formatSourceSurfaceProgress,
  inspectCustomCodeFilesystem,
  inspectSourceSurface,
  inspectCriticalAssets,
  SOURCE_SURFACE_LIMITS,
  sourceSurfaceCompletionBlocker,
  sourceSurfaceLimitsForRouteCount,
  stateBoundRuntimeFacts,
  liveSurfaceReconciliationErrors,
  yamlTreeMatchesHead,
  reconcileLifecycleContinuation,
  verifyLive
} from '../bin/verify.mjs';
import { customCodeReviewReasons, MACHINE_GATE_EVALUATORS, perGateResults, validatePacket } from '../bin/verify-packet.mjs';
import {
  reviewHandoffInputFileBindings,
  reviewHandoffReference,
  sealReviewHandoff,
  sealReviewHandoffBundle
} from '../bin/review-handoff.mjs';
import { validatePacket as validateInstalledPacket } from '../skills/agent-ready-drupal-build-kit/scripts/verify-packet.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const templatesDir = join(repoRoot, 'templates');
const testSiteUuid = '11111111-1111-4111-8111-111111111111';
const testCheckedAt = new Date().toISOString();

function committedConfigTree() {
  const root = mkdtempSync(join(tmpdir(), 'config-head-bytes-'));
  const configDirectories = ['config/sync', 'config/split/local'];
  const yamlFiles = [
    'config/sync/system.site.yml',
    'config/split/local/system.logging.yml'
  ];
  for (const directory of configDirectories) {
    mkdirSync(join(root, directory), { recursive: true });
  }
  writeFileSync(join(root, yamlFiles[0]), 'name: Fixture\n');
  writeFileSync(join(root, yamlFiles[1]), 'error_level: hide\n');
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['add', '--', ...yamlFiles], { cwd: root });
  execFileSync('git', [
    '-c', 'user.name=Fixture Committer',
    '-c', 'user.email=fixture@example.invalid',
    '-c', 'commit.gpgsign=false',
    'commit', '-q', '--no-verify', '-m', 'Export fixture config'
  ], { cwd: root });
  return { configDirectories, root, yamlFiles };
}

function scopedConfigStatus(root, configDirectories) {
  return execFileSync(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all', '--', ...configDirectories],
    { cwd: root, encoding: 'utf8' }
  );
}

test('config YAML blob comparison accepts an ordinary clean sync and Config Split tree', () => {
  const { configDirectories, root, yamlFiles } = committedConfigTree();

  assert.equal(scopedConfigStatus(root, configDirectories), '');
  assert.equal(yamlTreeMatchesHead(root, [...yamlFiles].reverse(), configDirectories), true);
});

test('config YAML blob comparison rejects bytes hidden by assume-unchanged', () => {
  const { configDirectories, root, yamlFiles } = committedConfigTree();
  execFileSync('git', ['update-index', '--assume-unchanged', '--', yamlFiles[0]], { cwd: root });
  writeFileSync(join(root, yamlFiles[0]), 'name: Changed\n');

  assert.equal(scopedConfigStatus(root, configDirectories), '');
  assert.equal(yamlTreeMatchesHead(root, yamlFiles, configDirectories), false);
});

test('config YAML blob comparison rejects Config Split bytes hidden by skip-worktree', () => {
  const { configDirectories, root, yamlFiles } = committedConfigTree();
  execFileSync('git', ['update-index', '--skip-worktree', '--', yamlFiles[1]], { cwd: root });
  writeFileSync(join(root, yamlFiles[1]), 'error_level: verbose\n');

  assert.equal(scopedConfigStatus(root, configDirectories), '');
  assert.equal(yamlTreeMatchesHead(root, yamlFiles, configDirectories), false);
});

test('agent continuation pauses only for verifier-confirmed external-only blockers', () => {
  const externalBlocker = {
    attemptedEvidence: ['evidence/provider-response.json'],
    code: 'blind.defect.DEF-EXT-1',
    message: 'Provider credentials are unavailable.',
    missingInput: 'A provider-issued API credential.',
    nextAction: 'The owner supplies the credential, then the agent reruns verification.',
    origin: 'packet-verifier:blind-adversarial-review.productDefects[0]',
    resolutionClass: 'external',
    verifierConfirmedExternal: true
  };
  const externalOnly = agentContinuation({ blockers: [externalBlocker] });
  assert.equal(externalOnly.status, 'externally_blocked');
  assert.equal(externalOnly.requiredAction, 'pause-and-report');
  assert.equal(externalOnly.shouldContinue, false);
  assert.equal(externalOnly.agentMayPause, true);
  assert.equal(externalOnly.agentMayStop, false);
  assert.equal(externalOnly.blockers[0].resolutionClass, 'external');
  assert.deepEqual(externalOnly.blockers[0].attemptedEvidence, externalBlocker.attemptedEvidence);

  const mixed = agentContinuation({
    blockers: [
      externalBlocker,
      {
        code: 'runtime.config-status',
        message: 'Current DDEV config status is not clean.',
        origin: 'live-verifier',
        resolutionClass: 'agent_resolvable'
      }
    ]
  });
  assert.equal(mixed.status, 'continue_required');
  assert.equal(mixed.requiredAction, 'repair-and-reverify');
  assert.equal(mixed.shouldContinue, true);
  assert.equal(mixed.agentMayPause, false);
  assert.match(mixed.instruction, /Do not hand off or pause while any agent-resolvable blocker remains/);

  const unconfirmedAuthoredLabel = agentContinuation({
    blockers: [{ ...externalBlocker, verifierConfirmedExternal: false }]
  });
  assert.equal(unconfirmedAuthoredLabel.status, 'continue_required');
  assert.equal(unconfirmedAuthoredLabel.blockers[0].resolutionClass, 'agent_resolvable');

  for (const [name, incompleteBlocker] of [
    ['missing code', { ...externalBlocker, code: '' }],
    ['non-verifier origin', { ...externalBlocker, origin: 'blind-adversarial-review.productDefects[0]' }],
    ['missing attempted evidence', { ...externalBlocker, attemptedEvidence: [] }],
    ['missing input', { ...externalBlocker, missingInput: '' }],
    ['missing next action', { ...externalBlocker, nextAction: '' }]
  ]) {
    const incomplete = agentContinuation({ blockers: [incompleteBlocker] });
    assert.equal(incomplete.status, 'continue_required', name);
    assert.equal(incomplete.requiredAction, 'repair-and-reverify', name);
    assert.equal(incomplete.shouldContinue, true, name);
    assert.equal(incomplete.agentMayPause, false, name);
    assert.equal(incomplete.blockers[0].resolutionClass, 'agent_resolvable', name);
  }

  const complete = agentContinuation({ complete: true, blockers: [externalBlocker] });
  assert.equal(complete.status, 'complete');
  assert.equal(complete.requiredAction, 'handoff');
  assert.equal(complete.agentMayStop, true);
  assert.equal(complete.agentMayPause, false);
  assert.deepEqual(complete.blockers, []);
});

test('lifecycle continuation keeps canonical blockers and compatibility reasons aligned', () => {
  const report = {
    agentContinuation: null,
    claimScope: 'complete-local-rebuild',
    completionBlockers: [{
      attemptedEvidence: ['evidence/provider-response.json'],
      code: 'blind.defect.DEF-EXT-1',
      message: 'Provider credentials are unavailable.',
      missingInput: 'A provider-issued API credential.',
      nextAction: 'Supply the credential and rerun verification.',
      origin: 'packet-verifier:blind-adversarial-review.productDefects[0]',
      resolutionClass: 'external',
      verifierConfirmedExternal: true
    }],
    completionBlockedReasons: ['stale compatibility value'],
    currentSiteClaimAllowed: false,
    currentStateBlockedReasons: ['Current lifecycle state is unclassified.']
  };

  reconcileLifecycleContinuation(report, { baseCompletionAllowed: true });

  assert.deepEqual(
    report.completionBlockedReasons,
    report.completionBlockers.map((blocker) => blocker.message)
  );
  assert.equal(report.completionBlockers.at(-1).origin, 'lifecycle-verifier');
  assert.equal(report.agentContinuation.status, 'continue_required');
  assert.equal(report.agentContinuation.shouldContinue, true);
  assert.equal(report.agentContinuation.blockers.length, report.completionBlockers.length);
});

test('Drupal entity state inventory is a batched, revision-bounded public reference closure', () => {
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /ContentEntityTypeInterface/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /accessCheck\(FALSE\)/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /count\(\$batch\) < 100/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /getTranslationLanguages/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /fopen\(\$uri, 'rb'\)/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /hash_update_stream/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /\$scheme === 'public'/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /getRevisionTable/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /getRevisionMetadataKey\('revision_default'\)/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /loadMultipleRevisions/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'revisionCount'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'publicAuthorUserDigest'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /\['name', 'status', 'user_picture', 'langcode'\]/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /pass\|password\|mail\|email/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'rawPerItemRowsEmitted'\s*=>\s*FALSE/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'user'\s*=>\s*'excluded as a broad root/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'webform_submission'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'contact_message'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'search_api_task'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'commerce_order'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /live_editorial_roots/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /declared_public_fields/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /public_route_paths/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /entity_reference_revisions/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'file', 'image'/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /transitive-public-reference/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /referenced-file-presentation-state/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /condition\('entity_type', 'file'\)/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /latest-non-default/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'missingLiveRoots'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'closureCounts'\s*=>/);
  assert.match(DRUPAL_ENTITY_INVENTORY_EVAL, /'excludedEntityTypes'\s*=>/);
  assert.doesNotMatch(DRUPAL_ENTITY_INVENTORY_EVAL, /hash_file\('sha256'/);
  assert.doesNotMatch(DRUPAL_ENTITY_INVENTORY_EVAL, /allRevisions\(\)/);
  assert.doesNotMatch(DRUPAL_ENTITY_INVENTORY_EVAL, /'items'\s*=>/);
  assert.doesNotMatch(DRUPAL_ENTITY_INVENTORY_EVAL, /loadMultiple\(\s*\)/);
  const liveRootQuery = DRUPAL_ENTITY_INVENTORY_EVAL.slice(
    DRUPAL_ENTITY_INVENTORY_EVAL.indexOf('foreach ($live_editorial_roots as'),
    DRUPAL_ENTITY_INVENTORY_EVAL.indexOf('sort($missing_live_roots')
  );
  assert.doesNotMatch(liveRootQuery, /getKey\('status'\)|condition\(\$status_key/);
  const infrastructureQuery = DRUPAL_ENTITY_INVENTORY_EVAL.slice(
    DRUPAL_ENTITY_INVENTORY_EVAL.indexOf('foreach ($infrastructure_type_policy as'),
    DRUPAL_ENTITY_INVENTORY_EVAL.indexOf('$privacy_safe_user_values')
  );
  assert.match(infrastructureQuery, /getKey\('status'\)/);
  assert.match(infrastructureQuery, /condition\(\$status_key, TRUE\)/);
});

test('Drupal live surface census is bounded, metadata-only, privacy-safe, and live-first', () => {
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\$surface_limit = 5000/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /entity_type\.bundle\.info/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /views\.view\./);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /path_alias/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /menu_link_content/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /canvas_component/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /sitemap_route/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /custom_extension/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /custom_route/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'webform_submission'\s*=>/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'commerce_payment_method'\s*=>/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'rawContentRowsEmitted'\s*=>\s*FALSE/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'privateEntityRowsQueried'\s*=>\s*FALSE/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'publicSurface'\s*=>\s*\$public_surface/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'publicEditorialRoot'\s*=>\s*\$is_public_root_type/);
  assert.doesNotMatch(DRUPAL_LIVE_SURFACE_EVAL, /->label\(\)|->getTitle\(\)|->toArray\(\)/);
});

test('custom code inventory is realpath-safe, stable, bounded, and covers Drupal lexical/registration surfaces', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'custom-code-inventory-'));
  const writeFixture = (path, contents) => {
    mkdirSync(dirname(join(projectRoot, path)), { recursive: true });
    writeFileSync(join(projectRoot, path), contents);
  };
  writeFixture('.ddev/config.yaml', 'name: inventory-fixture\ndocroot: web\n');
  writeFixture('web/modules/custom/catalog/catalog.info.yml', 'name: Catalog\ntype: module\ncore_version_requirement: ^11\n');
  writeFixture('web/modules/custom/catalog/catalog.module', '<?php\nfunction catalog_help() {}\n');
  writeFixture('web/modules/custom/catalog/src/Controller/CatalogController.php', '<?php\nfinal class CatalogController {}\n');
  writeFixture('web/modules/custom/catalog/src/Plugin/Block/CatalogBlock.php', '<?php\nfinal class CatalogBlock {}\n');
  writeFixture('web/modules/custom/catalog/src/CommentOnly.php', '<?php\n// class Phantom {}\n$example = "class Ghost";\n');
  writeFixture('web/modules/custom/catalog/catalog.services.yml', 'services:\n  catalog.repository:\n    class: Drupal\\catalog\\Repository\n');
  writeFixture('web/modules/custom/catalog/catalog.routing.yml', "catalog.item:\n  path: '/catalog/{node}'\n  defaults:\n    _controller: 'Drupal\\\\catalog\\\\Controller\\\\CatalogController::view'\n");
  writeFixture('web/modules/custom/catalog/templates/catalog.html.twig', '<article>{{ title }}</article>\n');
  writeFixture('web/modules/custom/catalog/js/catalog.js', 'Drupal.behaviors.catalogFilters = {};\n');
  writeFixture('web/modules/custom/catalog/css/catalog.css', '.catalog { display: grid; }\n');
  writeFixture('web/modules/custom/catalog/components/card/card.component.yml', 'name: Card\nstatus: stable\n');
  writeFixture('web/modules/custom/catalog/config/install/catalog.settings.yml', 'enabled: true\n');
  writeFixture('web/modules/custom/catalog/config/schema/catalog.schema.yml', 'catalog.settings:\n  type: config_object\n');
  writeFixture('web/modules/custom/catalog/tests/src/Kernel/CatalogTest.php', '<?php\nfinal class CatalogTest {\n  public function testCatalogRoute() {}\n}\n');
  writeFixture('web/modules/custom/catalog/assets/large-photo.jpg', Buffer.alloc(6 * 1024 * 1024));

  const first = inspectCustomCodeFilesystem(projectRoot);
  const second = inspectCustomCodeFilesystem(projectRoot);
  assert.equal(first.completed, true, first.errors.join('\n'));
  assert.equal(first.fingerprint, second.fingerprint);
  assert.equal(first.extensions.length, 1);
  assert.equal(first.controllers.length, 1);
  assert.equal(first.routes[0].name, 'catalog.item');
  assert.equal(first.tests[0].testMethods[0].methodName, 'testCatalogRoute');
  assert.equal(first.tests[0].testMethods[0].className, 'CatalogTest');
  assert.match(first.tests[0].testMethods[0].id, /^TESTMETHOD-[a-f0-9]{16}$/);
  const surfaceKinds = new Set(first.sourceFiles.flatMap((source) => source.surfaces.map((surface) => surface.kind)));
  for (const kind of [
    'hook_or_callback', 'controller_class', 'plugin_class', 'service_registration', 'route',
    'twig_template', 'drupal_behavior', 'stylesheet', 'sdc_component', 'shipped_config'
  ]) {
    assert.ok(surfaceKinds.has(kind), `missing ${kind}: ${[...surfaceKinds].join(', ')}`);
  }
  for (const source of first.sourceFiles) {
    assert.match(source.id, /^SOURCE-[a-f0-9]{16}$/);
    for (const surface of source.surfaces) {
      assert.match(surface.id, /^SURFACE-[a-f0-9]{16}$/);
    }
  }
  assert.equal(first.sourceFiles.flatMap((source) => source.surfaces).some((surface) => ['Phantom', 'Ghost'].includes(surface.name)), false);
  assert.ok(first.sourceFiles.some((source) => source.kind === 'extension_metadata'));
  writeFixture('web/modules/custom/catalog/dist/catalog.min.js', 'window.catalogBuild = true;\n');
  const builtAssetInventory = inspectCustomCodeFilesystem(projectRoot);
  assert.ok(builtAssetInventory.sourceFiles.some((source) => source.path.endsWith('/dist/catalog.min.js')));
  assert.notEqual(builtAssetInventory.fingerprint, first.fingerprint);
  const invalidUtf8Path = join(projectRoot, 'web/modules/custom/catalog/dist/invalid.min.js');
  writeFileSync(invalidUtf8Path, Buffer.from([0xff]));
  const invalidUtf8First = inspectCustomCodeFilesystem(projectRoot);
  writeFileSync(invalidUtf8Path, Buffer.from([0xfe]));
  const invalidUtf8Second = inspectCustomCodeFilesystem(projectRoot);
  assert.notEqual(
    invalidUtf8First.sourceFiles.find((source) => source.path.endsWith('/dist/invalid.min.js')).sha256,
    invalidUtf8Second.sourceFiles.find((source) => source.path.endsWith('/dist/invalid.min.js')).sha256
  );

  const outside = mkdtempSync(join(tmpdir(), 'custom-code-outside-'));
  writeFileSync(join(outside, 'escaped.php'), '<?php\n');
  symlinkSync(outside, join(projectRoot, 'web/modules/custom/catalog/escape'));
  const walked = customExtensionFiles(
    join(projectRoot, 'web/modules/custom/catalog'),
    'web/modules/custom/catalog'
  );
  assert.ok(walked.errors.some((error) => /resolves outside custom extension root/.test(error)));
  assert.equal(walked.files.some((path) => path.endsWith('escaped.php')), false);
  const deadline = customExtensionFiles(
    join(projectRoot, 'web/modules/custom/catalog'),
    'web/modules/custom/catalog',
    { deadlineMs: 5, now: (() => { let value = 0; return () => (value += 10); })() }
  );
  assert.ok(deadline.errors.some((error) => /deadline/.test(error)));
  const byteBound = customExtensionFiles(
    join(projectRoot, 'web/modules/custom/catalog'),
    'web/modules/custom/catalog',
    { fileBytesLimit: 1 }
  );
  assert.ok(byteBound.errors.some((error) => /source file limit/.test(error)));

  const portableRoot = mkdtempSync(join(tmpdir(), 'custom-code-portable-order-'));
  mkdirSync(join(portableRoot, 'z'), { recursive: true });
  mkdirSync(join(portableRoot, 'ä'), { recursive: true });
  writeFileSync(join(portableRoot, 'z/first.php'), '<?php\n');
  writeFileSync(join(portableRoot, 'ä/first.php'), '<?php\n');
  const portableTraversal = customExtensionFiles(
    portableRoot,
    'portable-order-fixture',
    { fileLimit: 1 }
  );
  assert.ok(portableTraversal.files[0].endsWith('/ä/first.php'), portableTraversal.files[0]);

  const aggregateBytes = inspectCustomCodeFilesystem(projectRoot, { totalBytesLimit: 1 });
  assert.ok(aggregateBytes.errors.some((error) => /aggregate exceeded 1 total source bytes/.test(error)));
  const aggregateDeadline = inspectCustomCodeFilesystem(projectRoot, {
    deadlineMs: 5,
    now: (() => { let value = 0; return () => (value += 10); })()
  });
  assert.ok(aggregateDeadline.errors.some((error) => /aggregate exceeded its 5ms deadline/.test(error)));

  writeFixture('web/modules/custom/second/second.info.yml', 'name: Second\ntype: module\ncore_version_requirement: ^11\n');
  const aggregateExtensions = inspectCustomCodeFilesystem(projectRoot, { extensionLimit: 1 });
  assert.ok(aggregateExtensions.errors.some((error) => /aggregate exceeded 1 custom extensions/.test(error)));

  writeFixture('web/themes/custom/catalog/catalog.info.yml', 'name: Catalog theme\ntype: theme\ncore_version_requirement: ^11\n');
  const duplicateIdentity = inspectCustomCodeFilesystem(projectRoot);
  assert.ok(duplicateIdentity.errors.some((error) => /machine name catalog is declared more than once/.test(error)));

  const surfaceRoot = mkdtempSync(join(tmpdir(), 'custom-code-surface-bound-'));
  mkdirSync(join(surfaceRoot, 'web/modules/custom/many'), { recursive: true });
  writeFileSync(join(surfaceRoot, 'web/modules/custom/many/many.info.yml'), 'name: Many\ntype: module\ncore_version_requirement: ^11\n');
  writeFileSync(
    join(surfaceRoot, 'web/modules/custom/many/many.module'),
    `<?php\n${Array.from({ length: 5_001 }, (_, index) => `function many_${index}() {}`).join('\n')}\n`
  );
  const surfaceBound = inspectCustomCodeFilesystem(surfaceRoot);
  assert.ok(surfaceBound.errors.some((error) => /exceeded 5000 lexical\/registration custom-code surfaces/.test(error)));

  const nestedRoot = mkdtempSync(join(tmpdir(), 'custom-code-nested-extension-'));
  mkdirSync(join(nestedRoot, 'web/modules/custom/parent/modules/child'), { recursive: true });
  writeFileSync(join(nestedRoot, 'web/modules/custom/parent/parent.info.yml'), 'name: Parent\ntype: module\n');
  writeFileSync(join(nestedRoot, 'web/modules/custom/parent/modules/child/child.info.yml'), 'name: Child\ntype: module\n');
  const nestedExtension = inspectCustomCodeFilesystem(nestedRoot);
  assert.ok(nestedExtension.errors.some((error) => /nested custom extension/.test(error)));

  const testMethodRoot = mkdtempSync(join(tmpdir(), 'custom-code-test-method-bound-'));
  mkdirSync(join(testMethodRoot, 'web/modules/custom/many_tests/tests/src/Unit'), { recursive: true });
  writeFileSync(join(testMethodRoot, 'web/modules/custom/many_tests/many_tests.info.yml'), 'name: Many tests\ntype: module\n');
  writeFileSync(
    join(testMethodRoot, 'web/modules/custom/many_tests/tests/src/Unit/ManyTest.php'),
    `<?php\nfinal class ManyTest {\n${Array.from({ length: 5_001 }, (_, index) => `public function test${index}() {}`).join('\n')}\n}\n`
  );
  const testMethodBound = inspectCustomCodeFilesystem(testMethodRoot);
  assert.ok(testMethodBound.errors.some((error) => /exceeded 5000 discovered test methods/.test(error)));
});

test('G-CODE route and schema probes use Drupal routing, anonymous access manager, and SchemaCheckTrait', () => {
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /router\.no_access_checks/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /request_stack/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /\$request_stack->push\(\$request\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /finally \{\s*\$request_stack->pop\(\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /matchRequest\(\$request\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /AnonymousUserSession/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /access_manager->checkRequest\(\$request, \$anonymous, TRUE\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /anonymous_access_mismatch/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /expectedAnonymousAccess/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /custom_extension_runtime_path_mismatch/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /\$custom_route_callback_class = static function/);
  assert.doesNotMatch(CUSTOM_ROUTE_AUDIT_PHP, /function custom_route_/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /convertedParameterTypes/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /route_scan_limit = 5000/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /SchemaCheckTrait/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /checkConfigSchema\(\$typed_config, \$config_name, \$dataset\['data'\], TRUE\)/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /\['source' => 'active', 'data' => \$active_data\]/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /\['source' => 'shipped', 'data' => \$shipped\['data'\]\]/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /skippedInactiveOptionalConfigNames/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /shipped_config_file_limit_exceeded/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /config_ownership_scan_limit_exceeded/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /aggregate_config_ownership_name_limit_exceeded/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /ownership_nodes_scanned > 1000000/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /aggregate_config_schema_dataset_limit_exceeded/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /custom_extension_runtime_path_mismatch/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /\$record\['status'\] = 'not_applicable'/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /\$custom_schema_data_contains = static function/);
  assert.doesNotMatch(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /function custom_schema_/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /custom_schema_data_contains/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /config\/(?:' \.[^\n]+)?install|\['install', 'optional'\]/);
  assert.match(CUSTOM_CONFIG_SCHEMA_AUDIT_PHP, /active_config_name_limit_exceeded/);
});

function completeSolutionLadder() {
  return [
    { stage: 'core', checked: true, decision: 'no_candidate', rationale: 'Core has no equivalent.', evidence: ['recipe-start-point.md#core'] },
    { stage: 'installed_drupal_cms', checked: true, decision: 'no_candidate', rationale: 'Installed packages have no equivalent.', evidence: ['recipe-start-point.md#installed'] },
    { stage: 'recipe', checked: true, decision: 'no_candidate', rationale: 'Recipe discovery found no fit.', evidence: ['recipe-start-point.md#recipes'] },
    { stage: 'maintained_contrib', checked: true, decision: 'rejected', rationale: 'Maintained contrib does not meet the route contract.', evidence: ['scoped-gap-list.md#catalog'] },
    { stage: 'custom_exception', checked: true, decision: 'accepted', rationale: 'A bounded custom route is required.', evidence: ['off-road-inventory.md#catalog'] }
  ];
}

test('G-CODE reconciliation binds every stable source surface and representative custom route', () => {
  const surfaceId = 'SURFACE-0123456789abcdef';
  const fingerprint = `sha256:${'d'.repeat(64)}`;
  const testFileId = 'TEST-0123456789abcdef';
  const testPath = 'web/modules/custom/catalog/tests/src/Kernel/CatalogTest.php';
  const testMethodId = customTestMethodId('catalog', testPath, 'Drupal\\Tests\\catalog\\Kernel\\CatalogTest', 'testCatalogRoute');
  const executionBudget = {
    commandsExecuted: 12,
    outputBytes: 4096,
    commandLimit: 384,
    outputLimit: 64 * 1024 * 1024,
    deadlineMs: 900_000,
    cleanupReserveMs: 30_000,
    cleanupCommandReserve: 2
  };
  const bindResult = (record) => ({ ...record, resultFingerprint: customCodeResultFingerprint(record) });
  const packageRecord = (name, binary = '') => ({
    binary,
    distUrlSha256: `sha256:${'1'.repeat(64)}`,
    name,
    packagePath: `vendor/${name}`,
    packageTree: { bytes: 1024, files: 4, sha256: `sha256:${'2'.repeat(64)}` },
    reference: 'a'.repeat(40),
    sourceUrlSha256: `sha256:${'3'.repeat(64)}`,
    version: '1.0.0'
  });
  const provenance = (packages) => ({
    autoloadTreeBytes: 2048,
    autoloadTreeFiles: 8,
    autoloadTreeSha256: `sha256:${'d'.repeat(64)}`,
    closureIdentitySha256: `sha256:${'e'.repeat(64)}`,
    closurePackageBytes: 8192,
    closurePackageCount: packages.length,
    closurePackageFiles: 32,
    closurePackageTreeSha256: `sha256:${'f'.repeat(64)}`,
    composerJsonSha256: `sha256:${'0'.repeat(64)}`,
    composerLockSha256: `sha256:${'4'.repeat(64)}`,
    sourceComposerLockSha256: `sha256:${'6'.repeat(64)}`,
    installedMetadataSha256: `sha256:${'5'.repeat(64)}`,
    rootAutoloadBytes: 512,
    rootAutoloadSha256: `sha256:${'7'.repeat(64)}`,
    packages
  });
  const isolation = {
    schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
    status: 'cleaned',
    workspaceId: 'DISPOSABLE-fixture',
    head: 'b'.repeat(40),
    projectNameSha256: `sha256:${'6'.repeat(64)}`,
    exactHead: true,
    freshDatabase: true,
    executionBoundary: 'exact-head-disposable-ddev',
    auditVendor: 'fresh-composer-install',
    runtimeOwner: 'verifier-generated-minimal-ddev-config',
    runtimeConfigSha256: `sha256:${'b'.repeat(64)}`,
    runtimeDdevTreeSha256: `sha256:${'d'.repeat(64)}`,
    runtimeSpecSha256: `sha256:${'c'.repeat(64)}`,
    workingTargetSnapshotBeforeSha256: `sha256:${'7'.repeat(64)}`,
    workingTargetSnapshotAfterSha256: `sha256:${'7'.repeat(64)}`,
    setupCommandResultHashes: [`sha256:${'8'.repeat(64)}`],
    cleanupCommandResultHashes: [`sha256:${'9'.repeat(64)}`, `sha256:${'a'.repeat(64)}`]
  };
  const runtime = {
    schemaVersion: 'public-kit.custom-code-inventory.2',
    completed: true,
    errors: [],
    fingerprint,
    extensions: [{ machineName: 'catalog', type: 'module' }],
    sourceFiles: [{
      id: 'SOURCE-0123456789abcdef',
      extension: 'catalog',
      path: 'web/modules/custom/catalog/src/Controller/CatalogController.php',
      kind: 'php_class',
      surfaces: [{ id: surfaceId, kind: 'controller_class', name: 'CatalogController', line: 3 }]
    }],
    tests: [{
      id: testFileId,
      extension: 'catalog',
      path: testPath,
      testMethods: [{ id: testMethodId, className: 'Drupal\\Tests\\catalog\\Kernel\\CatalogTest', methodName: 'testCatalogRoute' }]
    }],
    configSchema: { completed: true, extensions: [], violations: [] },
    routeAudit: {
      completed: true,
      violations: [],
      routes: [{
        name: 'catalog.item',
        requestMatched: true,
        parameterConversionCompleted: true,
        accessCheckCompleted: true,
        anonymousAccess: 'allowed'
      }]
    },
    qualityAudit: bindResult({
      schemaVersion: 'public-kit.custom-code-quality.1',
      applies: true,
      completed: true,
      status: 'pass',
      inputInventoryFingerprint: fingerprint,
      executionBudget,
      tools: {
        phpcs: {
          status: 'pass',
          provenance: provenance([
            packageRecord('squizlabs/php_codesniffer', 'vendor/squizlabs/php_codesniffer/bin/phpcs'),
            packageRecord('drupal/coder'),
            packageRecord('slevomat/coding-standard'),
            packageRecord('sirbrillig/phpcs-variable-analysis')
          ])
        },
        phpstan: { status: 'not_supported', version: '', config: '', configSha256: '' }
      },
      checks: {
        phpSyntax: { status: 'pass', expectedFileIds: ['SOURCE-0123456789abcdef', testFileId], completedFileIds: ['SOURCE-0123456789abcdef', testFileId], findings: [] },
        phpcs: { status: 'pass', expectedFileIds: ['SOURCE-0123456789abcdef', testFileId], completedFileIds: ['SOURCE-0123456789abcdef', testFileId], findings: [] },
        phpstan: { status: 'not_supported', expectedFileIds: ['SOURCE-0123456789abcdef', testFileId], requestedFileIds: [], reportedFileIds: [], findings: [] }
      },
      isolation,
      failures: []
    }),
    focusedTestExecution: null
  };
  const capabilityKey = 'catalog_item_route';
  const review = {
    schemaVersion: 'public-kit.custom-code-review.2',
    applies: true,
    runtimeFingerprint: fingerprint,
    capabilities: [{
      capabilityId: customCapabilityId('catalog', capabilityKey),
      capabilityKey,
      extension: 'catalog',
      need: 'Expose one catalog item route.',
      responsibility: 'Route matching, access, and render response.',
      loadBearing: true,
      acceptanceCriteria: [{ id: 'AC-CATALOG-01', criterion: 'Anonymous users receive the intended response.' }],
      solutionLadder: completeSolutionLadder(),
      sourceSurfaceIds: [surfaceId]
    }],
    testCoverage: [{
      acceptanceCriterionId: 'AC-CATALOG-01',
      runner: 'phpunit',
      testFileId,
      className: 'Drupal\\Tests\\catalog\\Kernel\\CatalogTest',
      methodName: 'testCatalogRoute',
      testMethodId
    }],
    routeBindings: [{
      name: 'catalog.item',
      requestMethod: 'GET',
      routeParameters: { node: '1' },
      expectedAnonymousAccess: 'allowed'
    }],
    inventoryComplete: true,
    blockers: []
  };
  runtime.focusedTestExecution = bindResult({
    schemaVersion: 'public-kit.custom-code-test-execution.1',
    applies: true,
    completed: true,
    status: 'pass',
    inputInventoryFingerprint: fingerprint,
    executionBudget,
    tools: {
      phpunit: {
        status: 'pass', version: 'PHPUnit 11', config: 'phpunit.xml', configSha256: `sha256:${'a'.repeat(64)}`,
        provenance: provenance([packageRecord('phpunit/phpunit', 'vendor/phpunit/phpunit/phpunit')])
      },
      ddevDatabaseFamily: { status: 'pass', family: 'mysql' }
    },
    expectedTestMethodIds: [testMethodId],
    completedTestMethodIds: [testMethodId],
    discovery: [],
    runs: [{ testMethodId, status: 'pass', testcaseCount: 1, assertionCount: 1 }],
    isolation,
    failures: []
  });
  assert.deepEqual(customCodeReconciliationErrors(runtime, review), []);
  assert.deepEqual(customCodeReviewReasons({ implementationQuality: { customCodeInventory: review } }), []);
  const reusedMethodCoverage = structuredClone(review);
  reusedMethodCoverage.capabilities[0].acceptanceCriteria.push({
    id: 'AC-CATALOG-02',
    criterion: 'The same route remains accessible after parameter conversion.'
  });
  reusedMethodCoverage.testCoverage.push({
    ...reusedMethodCoverage.testCoverage[0],
    acceptanceCriterionId: 'AC-CATALOG-02'
  });
  assert.deepEqual(customCodeReviewReasons({ implementationQuality: { customCodeInventory: reusedMethodCoverage } }), []);
  assert.deepEqual(customCodeReconciliationErrors(runtime, reusedMethodCoverage), []);
  const packetDir = mkdtempSync(join(tmpdir(), 'custom-code-evidence-'));
  writeFileSync(join(packetDir, 'recipe-start-point.md'), '# Core\n# Installed\n# Recipes\n');
  writeFileSync(join(packetDir, 'scoped-gap-list.md'), '# Catalog\n');
  writeFileSync(join(packetDir, 'off-road-inventory.md'), '# Catalog\n');
  assert.deepEqual(customCodeReconciliationErrors(runtime, review, packetDir), []);
  const missingEvidence = structuredClone(review);
  missingEvidence.capabilities[0].solutionLadder[0].evidence = ['missing.md#core'];
  assert.ok(customCodeReconciliationErrors(runtime, missingEvidence, packetDir)
    .some((error) => /missing packet-local file#fragment/.test(error)));

  const missingSurface = structuredClone(review);
  missingSurface.capabilities[0].sourceSurfaceIds = [];
  assert.ok(customCodeReconciliationErrors(runtime, missingSurface).some((error) => /sourceSurfaceIds|not bound/.test(error)));
  const neutralAccess = structuredClone(runtime);
  neutralAccess.routeAudit.routes[0].anonymousAccess = 'neutral';
  assert.ok(customCodeReconciliationErrors(neutralAccess, review).some((error) => /anonymous access-manager/.test(error)));
  const unexpectedAccess = structuredClone(runtime);
  unexpectedAccess.routeAudit.routes[0].anonymousAccess = 'denied';
  assert.ok(customCodeReconciliationErrors(unexpectedAccess, review).some((error) => /does not match expected allowed/.test(error)));
  const missingExpectedAccess = structuredClone(review);
  delete missingExpectedAccess.routeBindings[0].expectedAnonymousAccess;
  assert.ok(customCodeReviewReasons({ implementationQuality: { customCodeInventory: missingExpectedAccess } })
    .some((error) => /expectedAnonymousAccess/.test(error)));
  const contradictoryLadder = structuredClone(review);
  contradictoryLadder.capabilities[0].solutionLadder[0].decision = 'selected';
  assert.ok(customCodeReviewReasons({ implementationQuality: { customCodeInventory: contradictoryLadder } })
    .some((error) => /incomplete core solution-ladder/.test(error)));
  const unknownTest = structuredClone(review);
  unknownTest.testCoverage[0].testFileId = 'TEST-fedcba9876543210';
  assert.ok(customCodeReconciliationErrors(runtime, unknownTest).some((error) => /unknown_test_method|absent from the verifier inventory/.test(error)));
  const schemaFailure = structuredClone(runtime);
  schemaFailure.configSchema.violations = [{ extension: 'catalog', configName: 'catalog.settings', reason: 'missing_schema' }];
  assert.ok(customCodeReconciliationErrors(schemaFailure, review).some((error) => /schema violation/.test(error)));
});

test('Drupal live editor-surface census is read-only, bounded, and emits no field values', () => {
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /getFieldDefinitions/);
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /entity_form_display/);
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /getComponent\(\$field_name\)/);
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /->accessCheck\(FALSE\)/);
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /->range\(0, \$entity_limit \+ 1\)/);
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /use text format/);
  assert.match(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /'rawFieldValuesEmitted' => FALSE/);
  assert.doesNotMatch(DRUPAL_LIVE_EDITOR_SURFACE_EVAL, /'fieldValue'\s*=>|'rawValue'\s*=>/);
});

test('Drupal runtime identity emits digest-only active config, schema, settings, and database-update facts', () => {
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /Drupal::VERSION/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /PHP_VERSION/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /system\.schema/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /Settings::getAll/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /Settings::getHashSalt/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /hash_hmac\('sha256'/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /configFactory\(\)/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /getRawData\(\)/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /effectiveActiveConfigSha256/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /update\.post_update_registry/);
  assert.match(DRUPAL_RUNTIME_FACTS_EVAL, /pendingDatabaseUpdateCount/);
  assert.doesNotMatch(DRUPAL_RUNTIME_FACTS_EVAL, /effectiveSettingsSha256/);
  assert.doesNotMatch(DRUPAL_RUNTIME_FACTS_EVAL, /print json_encode\(\$settings/);
});

test('machine-local runtime changes are evidence-only while Drupal-owned runtime state stays intrinsic', () => {
  const facts = {
    coreVersion: '11.3.0',
    activeConfigEntryCount: 123,
    effectiveActiveConfigSha256: `sha256:${'1'.repeat(64)}`,
    systemSchemaEntryCount: 45,
    systemSchemaSha256: `sha256:${'2'.repeat(64)}`,
    databaseUpdateStatusConfirmed: true,
    pendingDatabaseUpdateCount: 0,
    databaseUpdatesPending: false,
    phpVersion: '8.3.0',
    databaseDriver: 'mysql',
    effectiveSettingsEntryCount: 12,
    effectiveSettingsHmacSha256: `sha256:${'3'.repeat(64)}`,
    configSplitDirectories: ['/var/www/html/config/dev']
  };
  const baseline = stateBoundRuntimeFacts(facts);
  const moved = stateBoundRuntimeFacts({
    ...facts,
    phpVersion: '8.4.0',
    databaseDriver: 'pgsql',
    effectiveSettingsHmacSha256: `sha256:${'4'.repeat(64)}`,
    configSplitDirectories: ['/opt/drupal/config/dev']
  });

  assert.deepEqual(moved.intrinsic, baseline.intrinsic);
  assert.notEqual(moved.environmentBinding.fingerprint, baseline.environmentBinding.fingerprint);
  assert.equal(JSON.stringify(baseline.intrinsic).includes('phpVersion'), false);
  assert.equal(JSON.stringify(baseline.intrinsic).includes('effectiveSettings'), false);
});

test('live-derived surfaces reconcile bidirectionally and non-public items require owned exclusions', () => {
  const packetDir = mkdtempSync(join(tmpdir(), 'surface-reconciliation-'));
  mkdirSync(join(packetDir, 'evidence', 'live-surface'), { recursive: true });
  writeJson(join(packetDir, 'pattern-map.json'), { contentTypes: [{ machineName: 'page' }] });
  writeJson(join(packetDir, 'drupal-readback.json'), { liveSurfaceReconciliation: {} });
  writeFileSync(join(packetDir, 'evidence', 'live-surface', 'admin-view.txt'), 'Reviewed as an administrative-only View.');
  const inventory = {
    schemaVersion: 'public-kit.drupal-live-surface.1',
    confirmed: true,
    fingerprint: `sha256:${'a'.repeat(64)}`,
    countsByKind: { bundle: 1, view_display: 1 },
    items: [
      { key: 'bundle:node:page', kind: 'bundle', publicEditorialRoot: true, publicSurface: true },
      { key: 'view_display:content:page_admin', kind: 'view_display', publicSurface: false }
    ]
  };
  const reconciliation = {
    schemaVersion: 'public-kit.live-surface-reconciliation.1',
    inventoryFingerprint: inventory.fingerprint,
    countsByKind: inventory.countsByKind,
    declarations: [
      {
        key: 'bundle:node:page',
        kind: 'bundle',
        packetReferences: ['pattern-map.json#contentTypes']
      }
    ],
    exclusions: [
      {
        key: 'view_display:content:page_admin',
        kind: 'view_display',
        owner: 'site maintainer',
        rationale: 'Administrative-only report, not anonymous output.',
        evidence: ['evidence/live-surface/admin-view.txt']
      }
    ],
    reconciliationComplete: true,
    blockers: []
  };
  assert.deepEqual(liveSurfaceReconciliationErrors(inventory, reconciliation, packetDir), []);

  const omitted = structuredClone(reconciliation);
  omitted.declarations = [];
  assert.match(liveSurfaceReconciliationErrors(inventory, omitted, packetDir).join('\n'), /Live-only bundle/);

  const stale = structuredClone(reconciliation);
  stale.declarations.push({
    key: 'menu:stale',
    kind: 'menu',
    packetReferences: ['pattern-map.json#contentTypes']
  });
  assert.match(liveSurfaceReconciliationErrors(inventory, stale, packetDir).join('\n'), /Packet-only live surface menu:stale/);

  const nonPublicDeclared = structuredClone(reconciliation);
  nonPublicDeclared.declarations.push({
    key: 'view_display:content:page_admin',
    kind: 'view_display',
    packetReferences: ['pattern-map.json#contentTypes']
  });
  nonPublicDeclared.exclusions = [];
  assert.match(liveSurfaceReconciliationErrors(inventory, nonPublicDeclared, packetDir).join('\n'), /classified non-public/);

  const circular = structuredClone(reconciliation);
  circular.declarations[0].packetReferences = ['drupal-readback.json#liveSurfaceReconciliation.declarations'];
  assert.match(liveSurfaceReconciliationErrors(inventory, circular, packetDir).join('\n'), /specific section/);
});

test('verifier-owned source census rejects a target-derived one-route inventory and accepts complete source paths', async () => {
  await withHttpServer(async (request, response) => {
    const origin = `http://${request.headers.host}`;
    if (request.url === '/robots.txt') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end(`User-agent: *\nSitemap: ${origin}/sitemap.xml\n`);
      return;
    }
    if (request.url === '/sitemap.xml') {
      response.writeHead(200, { 'content-type': 'application/xml' });
      response.end(`<?xml version="1.0"?><sitemapindex><sitemap><loc>${origin}/pages.xml</loc></sitemap></sitemapindex>`);
      return;
    }
    if (request.url === '/pages.xml') {
      response.writeHead(200, { 'content-type': 'application/xml' });
      response.end(`<?xml version="1.0"?><urlset>
        <url><loc>${origin}/</loc></url>
        <url><loc>${origin}/projects</loc></url>
        <url><loc>${origin}/developers</loc></url>
        <url><loc>${origin}/podcasts</loc></url>
      </urlset>`);
      return;
    }
    const path = String(request.url ?? '').split('?')[0];
    const pages = new Map([
      ['/', ['Source home', 'Source home']],
      ['/projects', ['Projects', 'Project Tracker']],
      ['/developers', ['Developers', 'Developer Database']],
      ['/podcasts', ['Podcasts', 'Podcasts']]
    ]);
    const page = pages.get(path);
    if (!page) {
      response.writeHead(404, { 'content-type': 'text/html' });
      response.end('<title>Not found</title><h1>Not found</h1>');
      return;
    }
    const links = path === '/'
      ? '<nav><a href="/projects">Projects</a><a href="/developers">Developers</a><a href="/podcasts">Podcasts</a></nav>'
      : '';
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(`<!doctype html><html><head><title>${page[0]}</title><link rel="canonical" href="${origin}${path}"></head><body><h1>${page[1]}</h1>${links}</body></html>`);
  }, async (sourceBaseUrl) => {
    const matrix = {
      sourceBaseUrl,
      primaryRoutes: [{ sourcePath: '/', targetPath: '/', accepted: true }],
      routes: [{ sourcePath: '/', sourceStatus: 200, sourceFinalPath: '/', sourceTitle: 'Source home', sourceH1: 'Source home', accepted: true }],
      sourceRouteDriftClassification: []
    };
    const incomplete = await inspectSourceSurface({ routeMatrix: matrix });
    assert.equal(incomplete.status, 'blocked');
    assert.equal(incomplete.authoritative, true);
    assert.deepEqual(incomplete.discoveredPublicPaths, ['/', '/developers', '/podcasts', '/projects']);
    assert.match(incomplete.errors.join('\n'), /source route \/projects.*no accepted source route/i);
    assert.match(incomplete.errors.join('\n'), /source route \/developers.*no accepted source route/i);
    assert.match(incomplete.errors.join('\n'), /source route \/podcasts.*no accepted source route/i);
    const projects = incomplete.routes.find((route) => route.path === '/projects');
    assert.deepEqual(
      {
        canonical: projects.canonical,
        h1: projects.h1,
        status: projects.status,
        title: projects.title
      },
      {
        canonical: `${sourceBaseUrl}/projects`,
        h1: 'Project Tracker',
        status: 200,
        title: 'Projects'
      }
    );
    assert.match(projects.bodySha256, /^sha256:[a-f0-9]{64}$/);
    assert.ok(projects.provenance.some((record) => record.kind === 'rendered-link'));
    assert.ok(projects.provenance.some((record) => record.kind === 'sitemap-url'));
    assert.equal(incomplete.budget.deadlineMs, 180_000);
    assert.equal(incomplete.budget.maxRequests, 2_048);
    assert.equal(incomplete.budget.maxRoutes, 1_024);
    assert.equal(incomplete.budget.maxSitemaps, 24);
    assert.equal(incomplete.budget.maxTasks, 2_048);

    const locallyExcludedMatrix = structuredClone(matrix);
    locallyExcludedMatrix.routes.push(
      { sourcePath: '/developers', accepted: true },
      { sourcePath: '/podcasts', accepted: true }
    );
    locallyExcludedMatrix.sourceRouteDriftClassification.push({
      sourcePath: '/projects',
      sourceStatus: 200,
      classification: 'legacy',
      targetDisposition: 'intentionally_drop',
      ownerDecisionEvidence: 'Builder says this public route can be omitted.',
      accepted: true,
      notes: 'Locally accepted omission.'
    });
    const locallyExcluded = await inspectSourceSurface({
      independentVerification: {
        routeDriftDispositionChecks: [{
          sourcePath: '/projects',
          classification: 'legacy',
          targetDisposition: 'intentionally_drop',
          dispositionEvidence: 'Builder-authored review agrees.',
          status: 'pass'
        }]
      },
      routeMatrix: locallyExcludedMatrix
    });
    assert.equal(locallyExcluded.status, 'blocked');
    assert.match(
      locallyExcluded.errors.join('\n'),
      /source route \/projects.*cannot be excluded by builder-authored drift dispositions/i
    );

    const completeMatrix = structuredClone(matrix);
    for (const path of ['/projects', '/developers', '/podcasts']) {
      completeMatrix.routes.push({ sourcePath: path, accepted: true });
    }
    const complete = await inspectSourceSurface({ routeMatrix: completeMatrix });
    assert.equal(complete.status, 'passed', complete.errors.join('\n'));
    assert.equal(complete.errors.length, 0);
    assert.match(complete.fingerprint, /^sha256:[a-f0-9]{64}$/);

    const bounded = await inspectSourceSurface({ routeMatrix: matrix, limits: { maxRoutes: 2 } });
    assert.equal(bounded.status, 'blocked');
    assert.equal(bounded.budget.maxRoutes, 2);
    assert.ok(bounded.budget.droppedRouteCount > 0);
    assert.match(bounded.errors.join('\n'), /exceeded its 2 route limit/i);
  }, { defaultVerificationRoutes: false });
});

test('source crawl expansion couples every hard budget and gives an exact owner-authorized continuation', () => {
  const doubled = sourceSurfaceLimitsForRouteCount(2_048);
  assert.deepEqual(
    {
      deadlineMs: doubled.deadlineMs,
      maxRequests: doubled.maxRequests,
      maxRoutes: doubled.maxRoutes,
      maxSitemapLocs: doubled.maxSitemapLocs,
      maxSitemaps: doubled.maxSitemaps,
      maxTasks: doubled.maxTasks
    },
    {
      deadlineMs: 360_000,
      maxRequests: 4_096,
      maxRoutes: 2_048,
      maxSitemapLocs: 10_000,
      maxSitemaps: 48,
      maxTasks: 4_096
    }
  );
  const maximum = sourceSurfaceLimitsForRouteCount(8_192);
  assert.equal(maximum.maxSitemapLocs, 40_000);
  assert.equal(maximum.maxSitemaps, 192);
  assert.throws(() => sourceSurfaceLimitsForRouteCount(8_193), /through 8192/i);

  const blocker = sourceSurfaceCompletionBlocker({
    status: 'blocked',
    budget: {
      droppedRouteCount: 241,
      maxRequests: 2_048,
      maxRoutes: 1_024,
      requestCount: 1_026,
      routeCount: 1_024
    }
  });
  assert.equal(blocker.code, 'source.census-budget');
  assert.equal(blocker.resolutionClass, 'external');
  assert.match(blocker.message, /core target delivery checks completed/i);
  assert.match(blocker.nextAction, /--source-max-routes 2048/);
  assert.match(blocker.nextAction, /do not combine or accept partial crawl results/i);

  const maximumBlocker = sourceSurfaceCompletionBlocker({
    status: 'blocked',
    budget: { droppedRouteCount: 1, maxRoutes: 8_192, routeCount: 8_192 }
  });
  assert.doesNotMatch(maximumBlocker.nextAction, /16384/);
  assert.match(maximumBlocker.nextAction, /route-matrix treatment/i);

  const status = formatSourceSurfaceProgress({
    phase: 'discovery',
    status: 'progress',
    discoveredRoutes: 520,
    inspectedRoutes: 256,
    queuedRoutes: 264,
    requestCount: 258,
    elapsedMs: 12_300,
    limits: { maxRequests: 2_048 },
    sourceUrl: 'https://source.example/private?token=secret'
  });
  assert.match(status, /256 inspected, 520 discovered, 264 queued/);
  assert.doesNotMatch(status, /source\.example|token|secret/);
});

test('large source census checks primary delivery routes before a visible late crawl', async () => {
  // Issue #76 observed 512 inspected routes plus 241 discoveries beyond the old cap.
  const commentPaths = Array.from({ length: 751 }, (_value, index) => `/comment/${index + 1}`);
  const requestedPaths = [];
  const progress = [];

  await withHttpServer((request, response) => {
    const origin = `http://${request.headers.host}`;
    const path = String(request.url ?? '').split('?')[0];
    requestedPaths.push(path);
    if (path === '/robots.txt') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end(`User-agent: *\nSitemap: ${origin}/sitemap.xml\n`);
      return;
    }
    if (path === '/sitemap.xml') {
      response.writeHead(200, { 'content-type': 'application/xml' });
      response.end(`<?xml version="1.0"?><urlset>${commentPaths
        .map((commentPath) => `<url><loc>${origin}${commentPath}</loc></url>`)
        .join('')}</urlset>`);
      return;
    }
    if (path === '/' || path === '/landing' || commentPaths.includes(path)) {
      const canonical = path.startsWith('/comment/') ? '/landing' : path;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(`<!doctype html><title>${path}</title><link rel="canonical" href="${canonical}"><h1>${path}</h1>`);
      return;
    }
    response.writeHead(404, { 'content-type': 'text/html' });
    response.end('<title>Not found</title><h1>Not found</h1>');
  }, async (sourceBaseUrl) => {
    const routeMatrix = {
      sourceBaseUrl,
      primaryRoutes: [
        { sourcePath: '/', targetPath: '/', accepted: true },
        { sourcePath: '/landing', targetPath: '/landing', accepted: true }
      ],
      routes: ['/', '/landing', ...commentPaths].map((sourcePath) => ({ sourcePath, accepted: true })),
      sourceRouteDriftClassification: []
    };

    const census = await inspectSourceSurface({
      onProgress: (event) => progress.push(event),
      routeMatrix
    });

    assert.equal(SOURCE_SURFACE_LIMITS.maxRoutes, 1_024);
    assert.equal(census.status, 'passed', census.errors.join('\n'));
    assert.equal(census.budget.routeCount, 753);
    assert.equal(census.budget.droppedRouteCount, 0);
    assert.ok(requestedPaths.indexOf('/') < requestedPaths.indexOf('/sitemap.xml'));
    assert.ok(requestedPaths.indexOf('/landing') < requestedPaths.indexOf('/sitemap.xml'));
    assert.ok(progress.some((event) => event.phase === 'primary' && event.status === 'completed'));
    assert.ok(progress.some((event) => event.phase === 'discovery' && event.status === 'progress'));
    assert.equal(progress.at(-1)?.status, 'completed');
    assert.equal(progress.at(-1)?.inspectedRoutes, 753);
  }, { defaultVerificationRoutes: false });
});

test('verifier-owned source census records an evidenced private source boundary without human review', async () => {
  await withHttpServer((request, response) => {
    if (request.url === '/robots.txt' || request.url === '/sitemap.xml') {
      response.writeHead(404, { 'content-type': 'text/plain' });
      response.end('Not found');
      return;
    }
    if (request.url === '/private') {
      response.writeHead(403, { 'content-type': 'text/html' });
      response.end('<title>Private</title><h1>Private</h1>');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end('<title>Source</title><link rel="canonical" href="/"><h1>Source</h1><a href="/private">Private area</a>');
  }, async (sourceBaseUrl) => {
    const routeMatrix = {
      sourceBaseUrl,
      primaryRoutes: [{ sourcePath: '/', targetPath: '/', accepted: true }],
      routes: [{ sourcePath: '/', accepted: true }],
      sourceRouteDriftClassification: [{
        sourcePath: '/private',
        sourceStatus: 403,
        classification: 'private_boundary',
        targetDisposition: 'intentionally_drop',
        targetPath: '',
        ownerDecisionEvidence: 'Verifier-observed HTTP 403 boundary.',
        accepted: true,
        notes: 'The public source links to an authenticated private area.'
      }]
    };
    const independentVerification = {
      routeDriftDispositionChecks: [{
        sourcePath: '/private',
        classification: 'private_boundary',
        targetDisposition: 'intentionally_drop',
        dispositionEvidence: 'Fresh source request returned HTTP 403.',
        status: 'pass'
      }]
    };
    const census = await inspectSourceSurface({ independentVerification, routeMatrix });
    assert.equal(census.status, 'passed', census.errors.join('\n'));
    const boundary = census.routes.find((route) => route.path === '/private');
    assert.equal(boundary.status, 403);
    assert.equal(boundary.boundary, 'private');
    assert.equal(boundary.boundaryConfirmed, true);
    assert.equal(boundary.boundaryConfirmationStatus, 403);
    assert.equal(boundary.boundaryDisposition.classification, 'private_boundary');
  }, { defaultVerificationRoutes: false });
});

function templateName(packetFile) {
  const parsed = parse(packetFile);
  return `${parsed.name}.template${parsed.ext}`;
}

function copyTemplatePacket(packetDir) {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  mkdirSync(packetDir, { recursive: true });
  for (const file of gates.reviewPacketFiles) {
    cpSync(join(templatesDir, templateName(file)), join(packetDir, file));
  }
}

test('every non-human gate has an explicit machine evaluator and a supported blocking scope', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const expected = gates.gates.filter((gate) => gate.checkedBy !== 'human').map((gate) => gate.id).sort();

  assert.deepEqual(Object.keys(MACHINE_GATE_EVALUATORS).sort(), expected);
  assert.equal(MACHINE_GATE_EVALUATORS['G-HANDOFF-01'], 'humanDecisionPresentation');
  assert.deepEqual([...new Set(gates.gates.map((gate) => gate.blocking))].sort(), ['handoff', 'launch']);
  assert.equal(gates.gates.find((gate) => gate.id === 'G-SEO-01')?.evidenceFile, 'browser-evidence.json');
  assert.equal(gates.gates.find((gate) => gate.id === 'G-PRIVACY-01')?.evidenceFile, 'negative-route-consent.json');
  assert.equal(gates.gates.find((gate) => gate.id === 'G-EDITOR-02')?.evidenceFile, 'next-cycle-verification.json');
  assert.equal(MACHINE_GATE_EVALUATORS['G-CODE-01'], 'customCodeInventoryQualityTestsRouteSchema');
  assert.equal(MACHINE_GATE_EVALUATORS['G-REPRO-01'], 'disposableReproduction');
  assert.deepEqual(
    gates.gates.find((gate) => gate.id === 'G-REPRO-01'),
    {
      id: 'G-REPRO-01',
      title: 'Exact-HEAD Drupal build reproduced in a verifier-owned disposable DDEV environment',
      phase: 6,
      evidenceFile: 'evidence/reproduction-verification.json',
      checkedBy: 'verify-script',
      blocking: 'launch'
    }
  );
});

test('gates.json defines checker semantics, including the non-authoritative human-record rule', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  for (const checker of new Set(gates.gates.map((gate) => gate.checkedBy))) {
    assert.ok(
      String(gates.checkedBySemantics?.[checker] ?? '').trim(),
      `checkedBySemantics must define ${checker}`
    );
  }
  assert.match(gates.checkedBySemantics.human, /builder-writable/i);
  assert.match(gates.checkedBySemantics.human, /self-attested record status/i);
  assert.match(gates.checkedBySemantics.human, /does not authenticate/i);
  assert.match(gates.checkedBySemantics.human, /does not use them to determine machine completion/i);
});

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256File(path) {
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

function refreshCaptureEvidenceBindings(packetDir) {
  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    for (const check of browser.publicRouteChecks) {
      if (!check.captureState) continue;
      check.captureState.evidenceBindings = {
        sourceScreenshotSha256: String(check.sourceScreenshot ?? '').trim()
          ? sha256File(join(packetDir, check.sourceScreenshot))
          : 'not_applicable',
        targetScreenshotSha256: sha256File(join(packetDir, check.targetScreenshot)),
        accessibilityReportSha256: sha256File(join(packetDir, check.accessibilityCheck.report))
      };
    }
  });
}

function mutateJson(path, mutate) {
  const value = JSON.parse(readFileSync(path, 'utf8'));
  mutate(value);
  writeJson(path, value);
}

function mutateText(path, mutate) {
  writeFileSync(path, mutate(readFileSync(path, 'utf8')));
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])));
  return Buffer.concat([length, typeBytes, data, checksum]);
}

function screenshotPng(seed, width = 320, height = 240) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const scanlines = Buffer.alloc(height * (1 + width * 3));
  for (let row = 0; row < height; row += 1) {
    const offset = row * (1 + width * 3);
    scanlines[offset] = 0;
    scanlines[offset + 1] = seed;
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('tEXt', Buffer.alloc(1200, seed)),
    pngChunk('IDAT', deflateSync(scanlines)),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

function resolveEnumSentinels(value) {
  if (typeof value === 'string' && /^[a-z0-9_ -]+(?:\s*\|\s*[a-z0-9_ -]+)+$/i.test(value.trim())) {
    return value.split('|')[0].trim();
  }
  if (Array.isArray(value)) {
    return value.map(resolveEnumSentinels);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, resolveEnumSentinels(child)]));
  }
  return value;
}

async function withHttpServer(handler, callback, { defaultVerificationRoutes = true } = {}) {
  const server = createServer((request, response) => {
    if (defaultVerificationRoutes && request.url?.startsWith('/.well-known/agent-ready-missing-')) {
      response.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Page not found</title><meta name="robots" content="noindex"></head><body><h1>Page not found</h1></body></html>');
      return;
    }
    if (defaultVerificationRoutes && request.url === '/user/login') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Log in</title></head><body><h1>Log in</h1></body></html>');
      return;
    }
    handler(request, response);
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    return await callback(baseUrl);
  } finally {
    await new Promise((resolveClose, rejectClose) =>
      server.close((error) => (error ? rejectClose(error) : resolveClose()))
    );
  }
}

function fixtureTargetHtml(request) {
  const origin = `http://${request.headers.host}`;
  return `<!doctype html><html><head>
    <title>Target site</title>
    <link rel="canonical" href="${origin}/">
    <meta name="description" content="Fixture homepage description.">
  </head><body><h1>Target home</h1></body></html>`;
}

function runProcess(command, args, cwd, options = {}) {
  return new Promise((resolveProcess) => {
    const child = spawn(command, args, { cwd, ...options });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolveProcess({ status, stderr, stdout }));
  });
}

function liveRouteMatrix(baseUrl) {
  return {
    ...JSON.parse(readFileSync(join(templatesDir, 'route-matrix.template.json'), 'utf8')),
    site: 'Fixture rebuild',
    checkedAt: testCheckedAt,
    sourceBaseUrl: 'https://source.example',
    targetBaseUrl: baseUrl,
    browserFirstRouteExpansion: {
      browserRenderedSeedRoutes: ['/'],
      candidateRoutesFromBrowserRenderedLinks: [],
      candidateRoutesFromImportedContentBodies: [],
      candidateRoutesFromBundles: [],
      candidateRoutesFromMetadata: [],
      candidateRoutesFromAssets: [],
      candidateRoutesFromSitemapsOrRobots: [],
      candidateRoutesFromNamingPatterns: [],
      curlOnlyRoutesRejected: [],
      expansionComplete: true,
      notes: 'Browser-rendered homepage inspected.'
    },
    homepageParity: {
      sourcePath: '/',
      targetPath: '/',
      targetStatus: 200,
      targetFinalPath: '/',
      targetH1: 'Target home',
      targetTitle: 'Target site',
      accepted: true
    },
    frontPageAliasDecision: {
      sourceHasSeparateHomeAndAlias: false,
      targetDecision: 'not_applicable',
      finalUrlChecks: ['/'],
      noFollowRedirectChecks: ['/'],
      accepted: true,
      rationale: 'No separate source alias.'
    },
    sourceRouteDriftClassification: [],
    targetRequiredRoutes: [
      {
        targetPath: '/',
        reasonRequired: 'front_page',
        targetStatus: 200,
        targetFinalPath: '/',
        expectedPublicBehavior: 'public_200',
        drupalOwner: 'node',
        shouldBePublic: true,
        accepted: true,
        notes: 'The configured front page is public.'
      }
    ],
    perRouteItemReconciliation: [],
    firstFoldBrandAssetParity: ['desktop', 'mobile'].map((viewport) => ({
      sourcePath: '/',
      targetPath: '/',
      viewport,
      heroArtworkMatchesOrDispositioned: true,
      logoOrLockupMatchesOrDispositioned: true,
      signatureGraphicsMatchOrDispositioned: true,
      primaryCtaTreatmentMatchesOrDispositioned: true,
      sourceAssetsReachable: [],
      targetAssetsUsed: [],
      exceptions: [],
      accepted: true,
      notes: 'The fixture has a text lockup and no separate hero artwork.'
    })),
    primaryRoutes: [
      {
        sourcePath: '/',
        targetPath: '/',
        routeRole: 'homepage',
        sourceIntent: 'Source homepage',
        targetIntent: 'Target homepage',
        matchesBrowserRenderedSource: true,
        accepted: true,
        notes: ''
      }
    ],
    routes: [
      {
        sourcePath: '/',
        targetPath: '/',
        routeRole: 'homepage',
        targetStatus: 200,
        targetFinalPath: '/',
        targetTitle: 'Target site',
        targetH1: 'Target home',
        expectedRedirect: false,
        accepted: true,
        notes: ''
      }
    ],
    starterRouteCleanup: {
      checkedPaths: ['/home', '/page/1', '/privacy-policy'],
      rawNodeRoutesChecked: [],
      starterCanvasPages: [],
      starterCanvasPlaceholderChecks: [],
      staleMenuOrFooterLinks: [],
      duplicateAliases: [],
      unexpectedStarterPublic200s: [],
      accepted: true,
      notes: 'No starter routes leaked.'
    },
    canvasPlaceholderDetection: {
      canvasEnabled: false,
      starterCanvasRoutesChecked: [],
      placeholderTextFindings: [],
      disconnectedCanvasEditorRoutes: [],
      canvasIntentionallyUnused: true,
      documentedReasonIfUnused: 'Not required by this fixture.',
      hardFailIfPublicPlaceholderExists: true,
      accepted: true,
      notes: ''
    },
    unexpectedPublic200s: [],
    missingSourceRoutes: [],
    wrongPatternRoutes: [],
    blockedRoutes: []
  };
}

function injectedDrupalRuntime(baseUrl, overrides = {}) {
  return {
    baseUrl,
    confirmed: true,
    configStatusClean: true,
    configSyncMatchesHead: true,
    configSyncDirectory: '../config/sync',
    configSyncTracked: true,
    consentInventory: {
      applications: [],
      configNames: [],
      confirmed: true,
      detected: false,
      managerModules: [],
      reason: ''
    },
    frontPage: '/',
    liveEditorSurfaceCensus: {
      schemaVersion: 'public-kit.live-editor-surface-census.1',
      confirmed: true,
      readOnly: true,
      rawFieldValuesEmitted: false,
      entityInspectionLimitPerField: 5000,
      fieldCount: 1,
      roleCount: 1,
      fields: [
        {
          key: 'node.page.body',
          entityType: 'node',
          bundle: 'page',
          machineName: 'body',
          fieldDefinitionExists: true,
          configEntityExists: true,
          definitionSource: 'configurable',
          fieldType: 'text_long',
          required: true,
          defaultFormDisplayId: 'node.page.default',
          defaultFormDisplayExists: true,
          widgetVisible: true,
          widget: 'text_textarea',
          formattedText: true,
          existingFormatIds: [],
          formatInspectionTruncated: false,
          formatInspectionError: '',
          editorRolePermissionChecks: [
            {
              declared: 'content editor',
              resolved: true,
              ambiguous: false,
              roleId: 'content_editor',
              roleLabel: 'Content editor',
              administrator: false,
              requiredPermissions: [],
              missingPermissions: []
            }
          ]
        }
      ],
      roles: [
        {
          declared: 'content editor',
          resolved: true,
          ambiguous: false,
          roleId: 'content_editor',
          roleLabel: 'Content editor',
          administrator: false
        }
      ],
      errors: [],
      fingerprint: `sha256:${'7'.repeat(64)}`,
      reason: ''
    },
    liveNextCycleCensus: {
      schemaVersion: 'public-kit.live-next-cycle-census.1',
      confirmed: true,
      metadataOnly: true,
      privateContentRead: false,
      candidateCount: 0,
      fields: [],
      taxonomyDimensions: [],
      workflows: []
    },
    mode: 'test-injected',
    project: 'fixture',
    reason: '',
    siteUuid: testSiteUuid,
    trackedConfigDirectory: 'config/sync',
    trackedConfigYamlFiles: ['config/sync/system.site.yml', 'config/sync/system.theme.yml'],
    ...overrides
  };
}

function negativeRouteConsentRecord(targetBaseUrl) {
  return {
    schemaVersion: 'public-kit.negative-route-consent.1',
    site: targetBaseUrl,
    checkedAt: testCheckedAt,
    toolOrMethod: 'Live HTTP checks and active Drupal config inspection',
    missingRoute: {
      noindexPolicy: 'required',
      canonicalPolicy: 'absent_or_self',
      statusOnlyDisposition: { acceptedBy: '', rationale: '', evidence: [] }
    },
    accessWallRoutes: [
      {
        path: '/user/login',
        expectedBehavior: 'available',
        canonicalPolicy: 'absent_or_self',
        externalAuthDisposition: { expectedOrigin: '', acceptedBy: '', rationale: '', evidence: [] }
      }
    ],
    legalPrivacyScope: {
      reviewed: true,
      requirements: [],
      noRoutesReason: 'The fixture renders no legal or privacy links.'
    },
    consent: {
      discoveryStatus: 'not_installed',
      notInstalledReason: 'Active Drupal config contains no consent manager.',
      managers: [],
      applications: [],
      beforeConsentChecks: []
    },
    runSpecificEvidenceRecorded: true,
    notes: ''
  };
}

function addQualifyingMarkdownEvidence(packetDir, sourceBaseUrl, targetBaseUrl) {
  writeFileSync(join(packetDir, 'operator-run.md'), `# Independent Operator Run Record

## Operator

- Name: Fixture Operator
- Role: Independent operator
- Environment: DDEV Drupal fixture
- Environment provisioning (manual, One Line Installer, other): One Line Installer-equivalent fixture
- Builder identity: fixture-builder-agent
- Date: 2026-07-09

## Run Evidence

- DDEV project URL: ${targetBaseUrl}
- \`ddev drush status\`: Successful bootstrap recorded in drupal-readback.json
- Config export location: config/sync
- Anonymous route checks: browser-evidence.json
- Browser-rendered evidence: evidence/blind-adversarial-review/
- Command transcript: drupal-readback.json commands
- Reviewer: Fixture Reviewer

## Decision

- [ ] Repeatability not reviewed
- [ ] Repeatability blocked
- [x] Repeatability accepted
- [ ] Repeatability accepted with restrictions
`);

  writeFileSync(join(packetDir, 'maintainer-review.md'), `# Maintainer Review Packet

## Review Scope

- Site: Fixture rebuild
- Target: ${targetBaseUrl}
- Reviewer: Fixture Maintainer
- Builder identity: fixture-builder-agent
- Date: 2026-07-09

## Stake-My-Name Verdict

- [x] Is the build on Drupal CMS best practices using Drupal-native primitives?
- [x] Is the architecture sound for the source site's real shape?
- [x] Does it contain the public content and media needed to review the site as a rebuild?
- [x] Does it match the source site's visual language and public behavior?
- [x] Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?
- [x] Are the load-bearing decisions captured and usable by later agents?
- [x] Are the remaining business, legal, integration, production, and launch gaps named?
- [x] Would a Drupal maintainer put their name on this as a complete local starting point?

## Binary Verdict

- [x] I would stake my name on this as a complete local Drupal CMS rebuild.
- [ ] I would not stake my name on this as a complete local Drupal CMS rebuild.

## Required Rationale

- Reasons to accept: The live, editor, packet, config, and parity evidence is complete for the fixture.
- Reasons to reject or revise: None for the local rebuild claim.
`);

  writeFileSync(join(packetDir, 'recipe-start-point.md'), `# Installed Baseline And Recipe Fit Decision

## Site

- Source URL: ${sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Source-use boundary: Authorized public rebuild
- Decision date: 2026-07-09
- Decision owner: Fixture Maintainer

## Installed Substrate And Assembly Decision

- [x] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.
- [ ] Retain a site template selected before installation plus bounded source-fit Recipes and overlays.
- [ ] Retain another existing Drupal CMS substrate and extend it without replacing it.
- [ ] Use bounded custom overlays because maintained Recipes do not fit the audited source patterns.

Decision: Retain the installed Drupal CMS Starter.

Rationale: The source has one structured route and no higher-fit template.

Installed substrate evidence (installed Recipe/template, Drupal CMS/core versions, public theme, front page, and starter content): drupal-readback.json

## Recipe Candidate Review

The recipe default owner was checked before custom overlays.

ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'

All available recipe candidates were reviewed and dispositioned as not_applicable for this fixture.
`);

  writeFileSync(join(packetDir, 'scoped-gap-list.md'), `# Scoped Gap List

## Site

- Source URL: ${sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Date: 2026-07-09

## Summary

Overall status: \`complete-local-rebuild\`

## Gaps

No unresolved local-rebuild gaps remain. Launch-only production evidence is outside this fixture claim.
`);

  writeFileSync(join(packetDir, 'open-decisions.md'), `# Open Decisions

## Site

- Source URL: ${sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Date: 2026-07-09

## Decisions

No human-only decisions remain for the complete local rebuild.

## Handoff Summary

- Decisions still open: None
- Decisions accepted: Local rebuild architecture and evidence
- Decisions blocked by missing external input: None
- Agent-resolvable work deliberately excluded from this file: None
`);

  writeFileSync(join(packetDir, 'off-road-inventory.md'), `# Off-Road Inventory

## Summary

- Site: Fixture rebuild
- Checked at: 2026-07-09
- Reviewer: Fixture Maintainer
- Overall status: \`accepted\`

## Inventory

No off-road moves were used in this fixture.
`);

  writeFileSync(join(packetDir, 'durable-intent.yml'), `schema_version: public-kit.1
site: "${targetBaseUrl}"
intent_records: []
empty_intent_acceptance:
  disposition: "accepted_no_durable_intent"
  accepted_by: "Fixture Maintainer"
  rationale: "The reviewed fixture has no durable intent beyond its packet-owned architecture facts."
  evidence:
    - "pattern-map.json"
evidence_scope: "No durable intent records apply to this fixture."
`);
}

function attachFixtureReviewHandoff(packetDir, targetBaseUrl) {
  const projectRoot = dirname(packetDir);
  if (!existsSync(join(projectRoot, 'AGENTS.md'))) writeFileSync(join(projectRoot, 'AGENTS.md'), '# Fixture instructions\n');
  const routeMatrix = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8'));
  const buildInput = JSON.parse(readFileSync(join(packetDir, 'build-input.json'), 'utf8'));
  const independentPath = join(packetDir, 'independent-verification.json');
  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  const targetOrigin = new URL(targetBaseUrl).origin;
  const briefReference = String(blind.reviewInputs?.originalBrief ?? 'Rebuild the source site.');
  const primaryRoutes = routeMatrix.primaryRoutes.map((route) => ({
    briefRequirementIds: [...(route.briefRequirementIds ?? [])].sort(),
    sourceTruthReference: buildInput.mode === 'brief'
      ? briefReference
      : new URL(route.sourcePath || '/', routeMatrix.sourceBaseUrl).href,
    targetPath: route.targetPath,
    targetUrl: new URL(route.targetPath, targetOrigin).href
  }));
  const excludedBlindInputs = [
    'implementation files',
    'review packet before public or artifact review',
    'builder notes and scripts',
    'prior build conversation',
    'self-authored completion claims',
    'builder final summary'
  ];
  const fileBinding = (reference) => {
    const path = resolve(projectRoot, reference);
    const bytes = readFileSync(path);
    return {
      path: reference,
      size: statSync(path).size,
      sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`
    };
  };
  const briefPath = briefReference.startsWith('review-packet/') && existsSync(resolve(projectRoot, briefReference))
    ? resolve(projectRoot, briefReference)
    : '';
  const briefBytes = briefPath ? readFileSync(briefPath) : Buffer.from(briefReference);
  const brief = {
    kind: briefPath ? 'packet_file' : 'literal',
    reference: briefReference,
    size: briefBytes.length,
    sha256: `sha256:${createHash('sha256').update(briefBytes).digest('hex')}`
  };
  const sourceOfTruthMaterials = (blind.reviewInputs?.sourceOfTruthMaterials ?? []).map((material) => {
    if (/^https?:\/\//i.test(material.reference)) {
      return { kind: 'url', reference: new URL(material.reference).href, type: material.type };
    }
    const binding = fileBinding(material.reference);
    return {
      kind: 'packet_file',
      reference: binding.path,
      type: material.type,
      size: binding.size,
      sha256: binding.sha256
    };
  });
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const existingDeclaredPacketFiles = gates.reviewPacketFiles.filter((reference) =>
    existsSync(join(packetDir, reference))
  );
  const extraPacketPaths = [
    brief.kind === 'packet_file' ? brief.reference : '',
    ...sourceOfTruthMaterials
      .filter((material) => material.kind === 'packet_file')
      .map((material) => material.reference)
  ].filter(Boolean);
  const independentFiles = reviewHandoffInputFileBindings(
    projectRoot,
    packetDir,
    existingDeclaredPacketFiles,
    extraPacketPaths
  );
  const { manifest, projections } = sealReviewHandoffBundle({
    binding: {
      buildMode: buildInput.mode,
      configSyncDirectory: '../config/sync',
      frontPage: '/',
      packetPath: relative(projectRoot, packetDir),
      preliminaryPacketEvidenceFingerprint: `sha256:${'6'.repeat(64)}`,
      siteStateFingerprint: `sha256:${'4'.repeat(64)}`,
      siteUuid: testSiteUuid,
      targetIdentityFingerprint: `sha256:${'5'.repeat(64)}`,
      targetOrigin
    },
    blind: {
      allowedInputs: {
        acceptanceCriteria: [...(blind.reviewInputs?.acceptanceCriteria ?? [])],
        brief,
        credentialLabels: [...(blind.reviewInputs?.credentialsUsed ?? [])],
        primaryRoutes,
        sourceOfTruthMaterials,
        targetUrlsOrArtifacts: [...(blind.reviewInputs?.targetUrlsOrArtifacts ?? [])]
      },
      excludedInputs: excludedBlindInputs
    },
    independent: {
      allowedInputs: {
        credentialLabels: [],
        files: independentFiles,
        urls: [...new Set([
          `${targetOrigin}/`,
          ...primaryRoutes.map((route) => route.targetUrl),
          `${targetOrigin}/admin`,
          ...(buildInput.mode === 'source_site'
            ? [`${new URL(routeMatrix.sourceBaseUrl).origin}/`]
            : [])
        ])].sort()
      },
      excludedInputs: [
        'builder final summary',
        'prior build conversation',
        'independent-verification.json from an earlier run',
        'blind-adversarial-review.json from an earlier run'
      ]
    }
  });
  independent.artifactsReviewed = projections.independent.allowedInputs.files.map((binding) => binding.path);
  independent.reviewHandoff = reviewHandoffReference(manifest.handoffDigest);
  blind.reviewHandoff = reviewHandoffReference(manifest.handoffDigest);
  blind.reviewInputs = {
    originalBrief: projections.blind.allowedInputs.brief.reference,
    acceptanceCriteria: [...projections.blind.allowedInputs.acceptanceCriteria],
    targetUrlsOrArtifacts: [...projections.blind.allowedInputs.targetUrlsOrArtifacts],
    sourceOfTruthMaterials: structuredClone(projections.blind.allowedInputs.sourceOfTruthMaterials),
    credentialsUsed: [...projections.blind.allowedInputs.credentialLabels],
    excludedInputs: [...projections.blind.excludedInputs]
  };
  writeJson(independentPath, independent);
  writeJson(blindPath, blind);
  mkdirSync(join(packetDir, 'evidence'), { recursive: true });
  writeJson(join(packetDir, 'evidence', 'review-handoff.json'), manifest);
  writeJson(join(packetDir, 'evidence', 'review-handoff-independent.json'), projections.independent);
  writeJson(join(packetDir, 'evidence', 'review-handoff-blind.json'), projections.blind);
}

function writeOpenDecisionRow(packetDir, {
  currentEvidence = 'unrelated-evidence',
  includeAcceptedSummary = true,
  openSummary = '1',
  status = 'open'
} = {}) {
  const routeMatrix = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8'));
  const acceptedSummary = includeAcceptedSummary ? '- Decisions accepted: None\n' : '';
  writeFileSync(join(packetDir, 'open-decisions.md'), `# Open Decisions

## Site

- Source URL: ${routeMatrix.sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Date: 2026-07-09

## Decisions

| ID | Decision needed | Human owner | Current evidence | Options | Recommended default | Impact if deferred | Needed by gate | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DEC-900 | Review accepted deviation | Owner/Maintainer | ${currentEvidence} | Accept / reject / revise | Review evidence | Scope remains human-unapproved | G-HANDOFF-01 | ${status} |

## Handoff Summary

- Decisions still open: ${openSummary}
${acceptedSummary}- Decisions blocked by missing external input: None
- Agent-resolvable work deliberately excluded from this file: None
`);
}

function addQualifyingReviewEvidence(packetDir, targetBaseUrl) {
  const sourceBaseUrl = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8')).sourceBaseUrl;
  const independentPath = join(packetDir, 'independent-verification.json');
  const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
  independent.site = targetBaseUrl;
  independent.checkedAt = testCheckedAt;
  independent.verifier = {
    nameOrRole: 'fresh independent verifier',
    runtimeOrTool: 'browser and Drupal CLI',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    builderSummaryExcluded: true,
    independenceDegradedReason: '',
    liveSiteInspected: true,
    packetInspected: true,
    notes: ''
  };
  independent.target = {
    baseUrl: targetBaseUrl,
    ddevProject: 'test-target',
    adminUrl: `${targetBaseUrl}/admin`,
    editorUser: 'editor',
    editorRole: 'content editor'
  };
  independent.perRouteItemCounts = [];
  independent.collectionOwnershipChecks = [];
  independent.renderedEmbedChecks = [];
  independent.detailRouteChecks = [];
  independent.accessibilityChecks = [];
  independent.anonymousFormChecks = [];
  independent.rawEmbedAndMarkupScan = {
    fieldsScanned: ['node fields', 'theme templates'],
    patternsChecked: ['<iframe', '<script', 'onload=', 'onclick=', 'javascript:', 'style=', 'raw source HTML'],
    findings: [],
    offRoadInventoryUpdated: true,
    status: 'pass'
  };
  independent.footerAndMenuLinkChecks = [];
  independent.targetRequiredRouteChecks = [
    {
      targetPath: '/',
      reasonRequired: 'front_page',
      targetStatus: 200,
      targetFinalUrl: `${targetBaseUrl}/`,
      expectedPublicBehavior: 'public_200',
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.routeDriftDispositionChecks = [];
  independent.placeholderTextScan = {
    scannedRoutes: ['/'],
    scannedAdminSurfaces: ['/admin/content'],
    termsChecked: ['lorem ipsum', 'placeholder', 'sample', 'starter', 'TODO', 'test page'],
    findings: [],
    status: 'pass'
  };
  independent.starterRouteAndLeakChecks = {
    pathsChecked: ['/', '/home', '/page/1', '/privacy-policy'],
    rawNodeRoutesChecked: [],
    unexpectedPublic200s: [],
    duplicateAliases: [],
    disconnectedCanvasStarterPages: [],
    status: 'pass'
  };
  independent.canvasPlaceholderChecks = {
    canvasEnabled: false,
    starterCanvasPagesChecked: [],
    publicCanvasPlaceholderFindings: [],
    disconnectedCanvasEditorRoutes: [],
    canvasIntentionallyUnusedAndDocumented: true,
    status: 'pass'
  };
  independent.firstFoldBrandAssetChecks = ['desktop', 'mobile'].map((viewport) => ({
    sourceRoute: '/',
    targetRoute: '/',
    viewport,
    heroArtworkStatus: 'not_applicable',
    logoOrLockupStatus: 'pass',
    signatureGraphicStatus: 'not_applicable',
    primaryCtaTreatmentStatus: 'pass',
    reachableSourceAssetsMissingOrApproximated: [],
    evidence: 'claim-evidence.json'
  }));
  independent.compositionModelFidelityChecks = [
    {
      sourceRoute: '/',
      targetRoute: '/',
      declaredCompositionOwner: 'entity_display',
      actualCompositionOwner: 'entity_display',
      routeRationalePresent: true,
      sectionOwnershipDeclared: true,
      sectionsChecked: ['Introduction'],
      expectedEditorActionsVerified: true,
      nonAdminEditorPublicOutputProof: 'evidence/blind-adversarial-review/editor-task.json',
      deviationRecordRequired: false,
      deviationRecordPresent: false,
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.canvasComponentModelChecks = [];
  independent.editorAddRowChecks = [];
  independent.fieldOutputFalsification = [
    {
      entityType: 'node',
      bundle: 'page',
      field: 'body',
      claim: 'Body affects anonymous output.',
      actualEditorSurface: '/node/1/edit',
      actualPublicOutput: '/',
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.coldReaderLabelChecks = [
    {
      bundle: 'page',
      editorFacingLabel: 'Page',
      wouldMakeSenseIfBrandChanged: true,
      siteBrandingExposedToEditor: false,
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.directDatabaseCleanupChecks = [];
  independent.packetFreshnessChecks = [
    'route-matrix.json',
    'browser-evidence.json',
    'next-cycle-verification.json',
    'drupal-readback.json',
    'field-output-matrix.json',
    'negative-route-consent.json',
    'parity-report.json',
    'pattern-map.json'
  ].map((artifact) => ({
    artifact,
    claim: `${artifact} reflects the inspected target.`,
    liveSiteEvidence: 'claim-evidence.json',
    staleOrMissingEvidence: false,
    status: 'pass'
  }));
  const completionGateIds = {
    accessibility: 'G-A11Y-01',
    architecture: 'G-COMPOSITION-01',
    behavior: 'G-BROWSER-01',
    content: 'G-CONTENT-01',
    editor: 'G-EDITOR-01',
    media: 'G-PARITY-01',
    packet: 'G-VERIFY-01',
    route: 'G-ROUTE-01',
    security_privacy: 'G-PRIVACY-01',
    seo: 'G-SEO-01',
    visual: 'G-BROWSER-02'
  };
  independent.completionClaims = [
    'content',
    'media',
    'visual',
    'behavior',
    'editor',
    'route',
    'seo',
    'accessibility',
    'security_privacy',
    'architecture',
    'packet'
  ].map((gate) => ({
    claimId: `${gate}-checked`,
    claim: `The ${gate} completion evidence was independently checked.`,
    gate,
    gateId: completionGateIds[gate],
    builderEvidence: [],
    falsificationChecks: [`Attempted to falsify the ${gate} evidence against the target and packet.`],
    verifierEvidence: ['claim-evidence.json'],
    status: 'pass',
    failureEvidence: [],
    nextFix: ''
  }));
  independent.summary = {
    failedClaimCount: 0,
    blockedClaimCount: 0,
    highestRiskFailures: [],
    verdict: 'pass',
    notes: ''
  };
  writeJson(independentPath, independent);
  const independentEvidenceDir = join(packetDir, 'evidence', 'independent-verification');
  mkdirSync(independentEvidenceDir, { recursive: true });
  writeJson(join(independentEvidenceDir, 'claim-evidence.json'), {
    schemaVersion: 'public-kit.independent-claim-evidence.1',
    targetBaseUrl,
    checkedAt: testCheckedAt,
    claims: independent.completionClaims.map((claim) => ({
      claimId: claim.claimId,
      gate: claim.gate,
      gateId: claim.gateId,
      checks: [
        {
          name: `${claim.gate} falsification`,
          method: 'live target and packet inspection',
          result: 'pass',
          observation: `The ${claim.gate} evidence matched the inspected target and packet.`
        }
      ]
    }))
  });

  const blindEvidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  mkdirSync(blindEvidenceDir, { recursive: true });
  for (const [index, [name, width, height]] of [
    ['source-desktop.png', 1280, 800],
    ['target-desktop.png', 1280, 800],
    ['source-mobile.png', 390, 844],
    ['target-mobile.png', 390, 844]
  ].entries()) {
    writeFileSync(join(blindEvidenceDir, name), screenshotPng(index + 1, width, height));
  }
  writeJson(join(blindEvidenceDir, 'editor-task.json'), {
    targetAdminUrl: `${targetBaseUrl}/admin/content`,
    editorRole: 'content editor',
    action: 'Created representative Page content as the non-admin editor.',
    resultingPublicUrl: `${targetBaseUrl}/`,
    publicOutputChanged: true,
    checkedAt: testCheckedAt
  });

  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  blind.site = targetBaseUrl;
  blind.checkedAt = testCheckedAt;
  blind.reviewer = {
    nameOrRole: 'fresh blind reviewer',
    runtimeOrTool: 'browser',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    didNotBuildTarget: true,
    inputsRestrictedToBriefTargetAndSourceTruth: true,
    implementationFilesReadBeforePublicReview: false,
    reviewPacketReadBeforePublicReview: false,
    priorBuildConversationRead: false,
    builderSummaryExcluded: true,
    notes: ''
  };
  blind.reviewInputs = {
    originalBrief: 'Rebuild the source site.',
    acceptanceCriteria: [],
    targetUrlsOrArtifacts: [`${targetBaseUrl}/`],
    sourceOfTruthMaterials: [{ type: 'source_site', reference: sourceBaseUrl, notes: '' }],
    credentialsUsed: [],
    excludedInputs: []
  };
  blind.routeViewportReviews = ['desktop', 'mobile'].map((viewport) => ({
    route: '/',
    sourceTruthReference: sourceBaseUrl,
    targetUrlOrArtifact: `${targetBaseUrl}/`,
    viewport,
    sourceScreenshot: `source-${viewport}.png`,
    targetScreenshot: `target-${viewport}.png`,
    routeNotes: `${viewport} checked`,
    checks: {
      actualRequestedOutcome: 'pass',
      firstFoldVisualParity: 'pass',
      navigationBehavior: 'pass',
      contentHierarchyCompleteness: 'pass',
      mediaArtworkFidelity: 'pass',
      interactionParity: 'pass',
      editorialQuality: 'pass',
      accessibilitySeoConsoleObviousDefects: 'pass'
    },
    verdict: 'good',
    evidence: []
  }));
  blind.routeCoverage = {
    strategy: 'all_primary_routes',
    primaryRoutesReviewed: ['/'],
    omittedPrimaryRoutes: [],
    notes: ''
  };
  blind.editorExperienceReviews = [
    {
      task: 'create representative content',
      briefExpectation: 'A non-admin editor can update public output.',
      targetAdminUrl: `${targetBaseUrl}/admin/content`,
      editorRole: 'content editor',
      publicOutputExpectedToChange: '/',
      publicOutputChanged: true,
      notInspectedReason: '',
      verdict: 'good',
      evidence: ['editor-task.json']
    }
  ];
  blind.productDefects = [];
  blind.reviewPasses = [
    { id: 'pass-1', checkedAt: testCheckedAt, reviewer: 'fresh reviewer', verdict: 'good', notes: '' }
  ];
  blind.summary = {
    verdict: 'good',
    completionState: 'parity_reviewed',
    desktopMobileReviewed: true,
    routeNotesPresent: true,
    rawEvidencePresent: true,
    openBlockerIssueCount: 0,
    openCriticalIssueCount: 0,
    openHighIssueCount: 0,
    acceptedOutOfScopeIssueCount: 0,
    externalBlockerIssueCount: 0,
    notes: ''
  };
  writeJson(blindPath, blind);

  const sourceAuditPath = join(packetDir, 'source-audit.json');
  const sourceAudit = JSON.parse(readFileSync(sourceAuditPath, 'utf8'));
  sourceAudit.checkedAt = testCheckedAt;
  sourceAudit.site = { name: 'Source fixture', baseUrl: sourceBaseUrl };
  sourceAudit.representativeUrls = [`${sourceBaseUrl}/`];
  sourceAudit.evidencePoints = [
    { claim: 'The source homepage was captured.', url: `${sourceBaseUrl}/`, method: 'browser', result: 'observed' }
  ];
  sourceAudit.observedPatterns = [{ pattern: 'homepage', evidence: `${sourceBaseUrl}/` }];
  sourceAudit.contentInventory = [{ route: '/', type: 'homepage', title: 'Source home' }];
  sourceAudit.designSignals = [{ route: '/', signal: 'hero, navigation, and content hierarchy captured' }];
  sourceAudit.formsAndIntegrations = [];
  sourceAudit.routeInventorySummary = {
    attemptedRoutes: 1,
    successfulRoutes: 1,
    failedRoutes: 0,
    unfetchedCandidates: 0
  };
  writeJson(sourceAuditPath, sourceAudit);

  const patternMapPath = join(packetDir, 'pattern-map.json');
  const patternMap = JSON.parse(readFileSync(patternMapPath, 'utf8'));
  patternMap.checkedAt = testCheckedAt;
  patternMap.sourceSite = sourceBaseUrl;
  patternMap.contentTypes = [{ machineName: 'page', label: 'Page', sourceObjects: ['homepage'] }];
  patternMap.fields = [{ bundle: 'page', machineName: 'body', sourceFact: 'homepage copy' }];
  patternMap.structuredContentModel.collectionScope = {
    reviewed: true,
    applies: false,
    reason: 'The one-route fixture has no repeatable collection surface.'
  };
  patternMap.structuredContentModel.recurringSourceObjects = [];
  patternMap.structuredContentModel.collectionOwnershipLedger = [];
  patternMap.forms = [];
  patternMap.buildTypeDeclaration = {
    type: 'structured_drupal_native_canvas_unused',
    canvasAvailabilityEvidence: 'Canvas was inspected and is not needed for this one-route fixture.',
    whyThisTypeFitsSource: 'The fixture is a structured homepage.',
    editorOwnershipImplications: 'Editors maintain the page through fields.',
    accepted: true,
    notes: ''
  };
  patternMap.compositionModel.completedBeforeImplementation = true;
  patternMap.pageCompositionOwnership = [
    {
      sourceRoute: '/',
      routeRole: 'homepage',
      selectedOwner: 'node',
      ownerRationale: 'A structured Page entity owns the homepage.',
      canvasOrExperienceBuilderAvailable: true,
      canvasOwnsPublicRoute: false,
      editorCanOpenSelectedOwner: true,
      themeOwnsOnlyPresentation: true,
      starterCanvasPlaceholderDisconnected: true,
      editorVerificationEvidence: 'evidence/blind-adversarial-review/editor-task.json',
      accepted: true,
      notes: ''
    }
  ];
  patternMap.sectionOwnershipMatrix = [
    {
      sourceRoute: '/',
      section: 'other',
      editorFacingName: 'Introduction',
      editorOwnedBy: 'field',
      repeatability: 'singleton',
      dataSource: 'node.page.body',
      expectedEditorAction: 'Edit the Introduction field.',
      acceptanceProof: 'evidence/blind-adversarial-review/editor-task.json',
      drupalOwner: 'node.page.body',
      publicOutputLocation: '/',
      nonAdminEditorCanChange: true,
      themeOwnsOnlyPresentation: true,
      exceptionRationale: '',
      accepted: true,
      notes: ''
    }
  ];
  patternMap.contentTypeLabelPolicy = {
    editorFacingLabelsUsePortableNouns: true,
    coldReaderLabelTestPassed: true,
    siteBrandedEditorLabels: [],
    machineNamePrefixPolicy: 'Portable bundle and field names.',
    accepted: true,
    notes: ''
  };
  patternMap.seoMetadata = {
    strategy: 'Rendered canonical URL and description are verified on the public route.',
    metatagConfig: ['metatag.metatag_defaults.node'],
    editorFields: ['node.page.body'],
    canonicalDecisions: [{ route: '/', decision: 'self canonical', accepted: true }],
    blockedEvidence: []
  };
  patternMap.reviewStatus = 'reviewed';
  writeJson(patternMapPath, patternMap);

  const fieldOutputPath = join(packetDir, 'field-output-matrix.json');
  const fieldOutput = JSON.parse(readFileSync(fieldOutputPath, 'utf8'));
  fieldOutput.site = targetBaseUrl;
  fieldOutput.checkedAt = testCheckedAt;
  fieldOutput.bundles = [
    {
      entityType: 'node',
      bundle: 'page',
      fields: [
        {
          machineName: 'body',
          editorLabel: 'Introduction',
          required: true,
          fieldType: 'text_long',
          widget: 'text_textarea',
          formatter: 'text_default',
          publicRenderLocations: ['/'],
          affectsAnonymousOutput: true,
          containsRawPresentationImplementation: false,
          presentationBoundary: 'content_fact',
          editorOnlyRationale: '',
          accepted: true,
          notes: 'The editor task changed this output.'
        }
      ]
    }
  ];
  fieldOutput.blockedFields = [];
  writeJson(fieldOutputPath, fieldOutput);

  const parityPath = join(packetDir, 'parity-report.json');
  const parity = JSON.parse(readFileSync(parityPath, 'utf8'));
  parity.checkedAt = testCheckedAt;
  parity.targetUrl = targetBaseUrl;
  parity.addressableSurface = { routesInScope: 1, routesExcluded: 0, exclusions: [] };
  parity.routeChecks = [{ route: '/', status: 'pass', evidence: 'route-check.json' }];
  parity.functionalScope = {
    reviewed: true,
    applies: false,
    reason: 'The source fixture has no interactive behavior beyond navigation.'
  };
  parity.contentChecks = [{
    route: '/',
    sourceExpectation: 'Source homepage intent is present.',
    targetObservation: 'Target homepage carries the rebuilt intent.',
    status: 'pass',
    evidence: 'browser-evidence.json',
    notes: ''
  }];
  parity.visualChecks = [{
    route: '/',
    sourceExpectation: 'Text lockup and hierarchy match.',
    targetObservation: 'Target text lockup and hierarchy were compared.',
    status: 'pass',
    evidence: 'browser-evidence.json',
    notes: ''
  }];
  parity.functionalChecks = [];
  parity.browserEvidence = ['browser-evidence.json'];
  parity.blockedEvidence = [];
  parity.verdict = 'pass';
  writeJson(parityPath, parity);

  const browserPath = join(packetDir, 'browser-evidence.json');
  const browser = JSON.parse(readFileSync(browserPath, 'utf8'));
  const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
  mkdirSync(browserEvidenceDir, { recursive: true });
  for (const [viewport, width, height] of [['desktop', 1280, 800], ['mobile', 390, 844]]) {
    writeJson(join(browserEvidenceDir, `axe-home-${viewport}.json`), {
      testEngine: { name: 'axe-core', version: '4.10.2' },
      toolOptions: { runOnly: null, rules: {} },
      testEnvironment: {
        userAgent: 'Fixture Browser/1.0',
        windowWidth: width,
        windowHeight: height
      },
      timestamp: testCheckedAt,
      url: `${targetBaseUrl}/`,
      passes: [],
      violations: [],
      incomplete: [],
      inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
    });
  }
  browser.site = targetBaseUrl;
  browser.checkedAt = testCheckedAt;
  browser.toolOrMethod = 'browser';
  browser.publicRouteChecks = ['desktop', 'mobile'].map((viewport) => {
    const desktop = viewport === 'desktop';
    return {
      routeRole: 'homepage',
      sourceUrl: `${sourceBaseUrl}/`,
      sourceFinalUrl: `${sourceBaseUrl}/`,
      targetUrl: `${targetBaseUrl}/`,
      targetFinalUrl: `${targetBaseUrl}/`,
      viewport: { name: viewport, width: desktop ? 1280 : 390, height: desktop ? 800 : 844 },
      captureState: {
        id: 'default',
        authority: 'self_attested_capture_evidence',
        fixtureRevision: 'fixture-home-v1',
        evidenceBindings: {
          sourceScreenshotSha256: sha256File(join(blindEvidenceDir, `source-${viewport}.png`)),
          targetScreenshotSha256: sha256File(join(blindEvidenceDir, `target-${viewport}.png`)),
          accessibilityReportSha256: sha256File(join(browserEvidenceDir, `axe-home-${viewport}.json`))
        },
        interactionSteps: [],
        menuState: {
          toggleVisible: false,
          toggleSelector: '',
          controlledRegionSelector: '',
          requested: 'not_applicable',
          observed: 'not_applicable',
          observedExpanded: false,
          controlledRegionVisible: false
        },
        consentState: { requested: 'not_applicable', observed: 'not_applicable' },
        contentCountAssertions: [],
        dynamicMasks: []
      },
      sourceScreenshot: `evidence/blind-adversarial-review/source-${viewport}.png`,
      targetScreenshot: `evidence/blind-adversarial-review/target-${viewport}.png`,
      visualComparison: { method: 'agent_review', reviewer: '', diffImage: '', diffScore: null, status: 'pass', acceptedExceptions: [] },
      renderedSignals: {
        sourceTitle: 'Source home',
        targetTitle: 'Target site',
        sourceH1: 'Source home',
        targetH1: 'Target home',
        sourceKeyVisibleBodyIntent: 'Source homepage intent',
        targetKeyVisibleBodyIntent: 'Rebuilt homepage intent',
        sectionOrderMatches: true,
        headerFooterTreatmentMatches: true,
        typographySpacingMatches: true,
        mediaPlacementMatches: true,
        sourceLikeBehaviorMatches: true
      },
      firstFoldBrandAssetSignals: {
        sourceHeroArtwork: 'No hero artwork in fixture.',
        targetHeroArtwork: 'No hero artwork in fixture.',
        sourceLogoOrLockup: 'Text lockup',
        targetLogoOrLockup: 'Text lockup',
        sourceSignatureGraphics: [],
        targetSignatureGraphics: [],
        primaryCtaTreatmentMatches: true,
        brandDefiningAssetsMissingOrApproximated: []
      },
      renderedSeoSignals: {
        targetCanonicalUrl: `${targetBaseUrl}/`,
        targetMetaDescription: 'Fixture homepage description.',
        targetOpenGraphImage: '',
        metaDescriptionStatus: 'present',
        openGraphImageStatus: 'not_applicable',
        metaDescriptionApplicabilityReviewed: true,
        metaDescriptionNotApplicableRationale: '',
        openGraphImageApplicabilityReviewed: true,
        openGraphImageNotApplicableRationale: 'The source fixture has no social image.',
        accepted: true,
        evidence: 'browser route capture'
      },
      accessibilityCheck: {
        standard: 'WCAG 2.2 AA',
        engine: 'axe-core',
        engineVersion: '4.10.2',
        executedInBrowser: true,
        ruleScope: { mode: 'full_default', tags: [], accepted: true },
        report: `evidence/browser/axe-home-${viewport}.json`,
        incompleteReviewed: true,
        incompleteDispositions: [],
        manualChecks: {
          keyboardNavigation: 'pass',
          keyboardNavigationNotApplicableRationale: '',
          visibleFocus: 'pass',
          visibleFocusNotApplicableRationale: '',
          accessibleNamesAndLabels: 'pass',
          accessibleNamesAndLabelsNotApplicableRationale: '',
          formLabelsErrorsAndFocus: 'not_applicable',
          formLabelsErrorsAndFocusNotApplicableRationale: 'The fixture homepage has no submission form.'
        },
        status: 'pass',
        blockers: []
      },
      detailContentSignals: {
        contentTypeOrBundle: '',
        drupalOwner: '',
        ownerDeviation: { applies: false, rationale: '', evidence: '' },
        loadBearingFields: [],
        accepted: false
      },
      renderedItemCounts: [],
      notes: `Homepage checked at ${viewport}.`,
      accepted: true,
      blockers: []
    };
  });
  browser.anonymousFormChecks = [];
  browser.editorWorkflowChecks = [
    {
      workflow: 'create',
      entityType: 'node',
      bundle: 'page',
      editorUser: 'editor',
      editorRole: 'content editor',
      drupalRoute: '/admin/content',
      taskPerformed: 'Created representative content.',
      formScreenshot: 'evidence/blind-adversarial-review/target-desktop.png',
      resultScreenshot: 'evidence/blind-adversarial-review/target-mobile.png',
      fieldsAndWidgetsVerified: ['title', 'body'],
      publicOutputAffected: '/',
      visualOrBehaviorResult: 'Public output changed.',
      status: 'pass',
      acceptedExceptions: [],
      accepted: true,
      blockers: []
    }
  ];
  browser.canvasAuthoringChecks = [];
  browser.missingBrowserEvidence = [];
  browser.browserEvidenceComplete = true;
  writeJson(browserPath, browser);

  const readbackPath = join(packetDir, 'drupal-readback.json');
  const readback = JSON.parse(readFileSync(readbackPath, 'utf8'));
  readback.site = targetBaseUrl;
  readback.checkedAt = testCheckedAt;
  readback.commands = [
    'drush status',
    'drush config:get system.site uuid --format=string',
    'drush config:get system.site page.front --format=string',
    'drush php:eval config sync directory',
    'drush config:status',
    'git ls-files config/sync/*.yml'
  ];
  readback.drupal.status = { bootstrap: 'Successful', uri: targetBaseUrl };
  readback.drupal.siteUuid = testSiteUuid;
  readback.drupal.enabledModules = ['node', 'media', 'views'];
  readback.drupal.defaultTheme = 'fixture_theme';
  readback.drupal.adminTheme = 'claro';
  readback.drupal.frontPage = '/';
  readback.drupal.configSyncDirectory = '../config/sync';
  readback.drupal.trackedConfigDirectory = 'config/sync';
  readback.drupal.trackedConfigYamlFiles = ['config/sync/system.site.yml', 'config/sync/system.theme.yml'];
  readback.drupal.configSyncDirectoryMatchesTrackedDirectory = true;
  readback.drupal.configStatus = 'No differences';
  readback.drupal.configStatusClean = true;
  readback.content.nodes = [{ id: 1, type: 'page', title: 'Target home', published: true }];
  readback.content.contentTypes = [{ machineName: 'page', label: 'Page' }];
  readback.content.fieldStorage = [{ field: 'body', type: 'text_long' }];
  readback.content.formDisplays = [{ bundle: 'page', mode: 'default' }];
  readback.content.viewDisplays = [{ bundle: 'page', mode: 'full' }];
  readback.routing.menus = [{ id: 'main', label: 'Main navigation' }];
  readback.routing.menuLinks = [{ menu: 'main', title: 'Home', url: '/' }];
  readback.liveSurfaceReconciliation = {
    schemaVersion: 'public-kit.live-surface-reconciliation.1',
    inventoryFingerprint: `sha256:${'c'.repeat(64)}`,
    countsByKind: { bundle: 1 },
    declarations: [
      {
        key: 'bundle:node:page',
        kind: 'bundle',
        packetReferences: ['pattern-map.json#contentTypes']
      }
    ],
    exclusions: [],
    reconciliationComplete: true,
    blockers: []
  };
  readback.implementationQuality.customCodeInventory = {
    schemaVersion: 'public-kit.custom-code-review.2',
    applies: false,
    runtimeFingerprint: '',
    capabilities: [],
    testCoverage: [],
    routeBindings: [],
    inventoryComplete: true,
    blockers: []
  };
  readback.rolesAndPermissionsNotes = ['Content editor can create and edit Page content.'];
  readback.readbackComplete = true;
  readback.blockers = [];
  writeJson(readbackPath, readback);

  writeJson(join(packetDir, 'negative-route-consent.json'), negativeRouteConsentRecord(targetBaseUrl));
  const nextCycleEvidenceDir = join(packetDir, 'evidence', 'next-cycle');
  mkdirSync(nextCycleEvidenceDir, { recursive: true });
  writeJson(join(nextCycleEvidenceDir, 'discovery.json'), {
    schemaVersion: 'public-kit.next-cycle-discovery-evidence.1',
    targetBaseUrl,
    checkedAt: testCheckedAt,
    commands: [
      'drush php:eval field definitions',
      'drush php:eval taxonomy vocabularies',
      'drush php:eval workflows and role permissions'
    ],
    recurringPublicModels: [],
    temporalCycleDimensionsFound: 0
  });
  writeJson(join(packetDir, 'next-cycle-verification.json'), {
    schemaVersion: 'public-kit.next-cycle-verification.1',
    site: targetBaseUrl,
    checkedAt: testCheckedAt,
    applicability: {
      reviewed: true,
      applies: false,
      reason: 'The fixture has no recurring public model or temporal/cycle dimension.'
    },
    discovery: {
      commands: [
        'drush php:eval field definitions',
        'drush php:eval taxonomy vocabularies',
        'drush php:eval workflows and role permissions'
      ],
      fieldDefinitionsInspected: true,
      taxonomyVocabulariesInspected: true,
      workflowsInspected: true,
      recurringPublicModels: [],
      evidence: 'discovery.json'
    },
    blockers: [],
    notes: ''
  });

  addQualifyingMarkdownEvidence(packetDir, sourceBaseUrl, targetBaseUrl);

  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  for (const packetFile of gates.reviewPacketFiles) {
    const path = join(packetDir, packetFile);
    if (packetFile.endsWith('.json')) {
      const record = resolveEnumSentinels(JSON.parse(readFileSync(path, 'utf8')));
      record.runSpecificEvidenceRecorded = true;
      writeJson(path, record);
    }
  }
  attachFixtureReviewHandoff(packetDir, targetBaseUrl);
}

function convertQualifyingPacketToBrief(packetDir, targetBaseUrl) {
  const brief = '# Brief\n\nCreate a public homepage that editors can maintain.\n';
  const briefHash = `sha256:${createHash('sha256').update(brief).digest('hex')}`;
  const briefReference = 'review-packet/original-brief.md';
  const requirementEvidence = 'evidence/brief/BR-001.txt';
  writeFileSync(join(packetDir, 'original-brief.md'), brief);
  mkdirSync(join(packetDir, 'evidence', 'brief'), { recursive: true });
  writeFileSync(
    join(packetDir, requirementEvidence),
    'BR-001 passed: the public homepage renders and the non-admin editor workflow changes its output.\n'
  );
  writeJson(join(packetDir, 'build-input.json'), {
    schemaVersion: 'public-kit.build-input.1',
    mode: 'brief',
    sourceUrl: '',
    brief: { path: briefReference, sha256: briefHash }
  });
  writeJson(join(packetDir, 'brief-acceptance.json'), {
    schemaVersion: 'public-kit.brief-acceptance.1',
    briefSha256: briefHash,
    checkedAt: testCheckedAt,
    requirements: [
      {
        id: 'BR-001',
        requirement: 'Create a public homepage that a non-admin editor can maintain.',
        category: 'editorial',
        targetRoutes: ['/'],
        acceptanceChecks: [
          'The homepage returns 200 with the expected identity.',
          'A non-admin editor changes content that appears on the public homepage.'
        ],
        status: 'pass',
        evidence: [requirementEvidence]
      }
    ],
    assumptions: [],
    outOfScope: [],
    blockers: []
  });
  for (const artifact of ['source-audit.json', 'parity-report.json']) {
    writeJson(join(packetDir, artifact), {
      schemaVersion: 'public-kit.mode-disposition.1',
      artifact,
      buildMode: 'brief',
      claimScope: 'complete-local-build-from-brief',
      briefSha256: briefHash,
      status: 'not_applicable',
      reason: `Brief mode does not use ${artifact} as completion evidence.`
    });
  }

  mutateJson(join(packetDir, 'route-matrix.json'), (matrix) => {
    matrix.sourceBaseUrl = '';
    matrix.homepageTargetAcceptance = {
      targetPath: '/',
      targetStatus: 200,
      targetFinalPath: '/',
      targetH1: 'Target home',
      targetTitle: 'Target site',
      targetKeyBodyIntent: 'Maintainable public homepage',
      accepted: true,
      rationale: 'The target homepage is required by BR-001.'
    };
    for (const route of matrix.primaryRoutes) route.briefRequirementIds = ['BR-001'];
    for (const route of matrix.routes) route.briefRequirementIds = ['BR-001'];
  });
  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    for (const check of browser.publicRouteChecks) check.briefRequirementIds = ['BR-001'];
  });
  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    patternMap.sourceSite = '';
    for (const owner of patternMap.pageCompositionOwnership) owner.targetRoute = owner.sourceRoute;
    for (const owner of patternMap.sectionOwnershipMatrix) owner.targetRoute = owner.sourceRoute;
  });
  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.briefRequirementChecks = [
      {
        requirementId: 'BR-001',
        falsificationChecks: [
          'Fetched the target homepage and repeated the editor workflow as a non-admin user.'
        ],
        status: 'pass',
        evidence: [requirementEvidence]
      }
    ];
  });
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    blind.reviewInputs.originalBrief = briefReference;
    blind.reviewInputs.acceptanceCriteria = ['BR-001 Maintainable public homepage'];
    blind.reviewInputs.sourceOfTruthMaterials = [
      { type: 'written_spec', reference: briefReference, notes: 'Preserved original brief.' }
    ];
    for (const review of blind.routeViewportReviews) {
      review.sourceTruthReference = briefReference;
      review.briefRequirementIds = ['BR-001'];
    }
  });

  for (const file of ['recipe-start-point.md', 'scoped-gap-list.md', 'open-decisions.md']) {
    mutateText(join(packetDir, file), (text) => text.replace(
      /^- Source URL:.*$/m,
      '- Build basis: brief\n- Brief file: review-packet/original-brief.md'
    ));
  }
  mutateText(join(packetDir, 'scoped-gap-list.md'), (text) =>
    text.replace('Overall status: `complete-local-rebuild`', 'Overall status: `complete-local-build-from-brief`')
  );
  attachFixtureReviewHandoff(packetDir, targetBaseUrl);
}

function addAnonymousContactFormEvidence(packetDir, targetBaseUrl, outcomeMode = 'local_mail_capture') {
  const sourceBaseUrl = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8')).sourceBaseUrl;
  mutateJson(join(packetDir, 'source-audit.json'), (sourceAudit) => {
    sourceAudit.formsAndIntegrations = [{
      formKey: 'contact-main',
      kind: 'public_submission_form',
      sourceRoute: '/contact',
      purpose: 'contact_message',
      anonymousPublicUse: true,
      expectedOutcome: 'message_delivery',
      evidence: 'browser-evidence.json',
      notes: ''
    }];
    sourceAudit.functionalSignals = [{ route: '/contact', behavior: 'Anonymous contact submission.' }];
    sourceAudit.representativeUrls.push(`${sourceBaseUrl}/contact`);
    sourceAudit.evidencePoints.push({
      claim: 'The source contact form was captured.',
      url: `${sourceBaseUrl}/contact`,
      method: 'browser',
      result: 'observed'
    });
    sourceAudit.contentInventory.push({ route: '/contact', type: 'form', title: 'Contact' });
    sourceAudit.designSignals.push({ route: '/contact', signal: 'Public form hierarchy and labels captured' });
    sourceAudit.routeInventorySummary.attemptedRoutes += 1;
    sourceAudit.routeInventorySummary.successfulRoutes += 1;
  });
  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    patternMap.forms = [{
      formKey: 'contact-main',
      sourceRoute: '/contact',
      targetRoute: '/contact',
      purpose: 'contact_message',
      drupalOwner: 'webform',
      expectedOutcome: 'message_delivery',
      accepted: true,
      notes: 'The contact form is Drupal-owned.'
    }];
    patternMap.pageCompositionOwnership.push({
      ...structuredClone(patternMap.pageCompositionOwnership[0]),
      sourceRoute: '/contact',
      routeRole: 'form',
      ownerRationale: 'A Drupal Webform owns the contact route.'
    });
    patternMap.sectionOwnershipMatrix.push({
      ...structuredClone(patternMap.sectionOwnershipMatrix[0]),
      sourceRoute: '/contact',
      section: 'other',
      editorFacingName: 'Contact form',
      dataSource: 'webform.contact',
      expectedEditorAction: 'Edit the Contact Webform.',
      drupalOwner: 'webform.contact',
      publicOutputLocation: '/contact'
    });
  });
  mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
    routeMatrix.primaryRoutes.push({
      sourcePath: '/contact',
      targetPath: '/contact',
      routeRole: 'form',
      sourceIntent: 'Anonymous visitors can contact the organization.',
      targetIntent: 'A Drupal-owned public contact form.',
      matchesBrowserRenderedSource: true,
      accepted: true,
      notes: 'Representative form route.'
    });
    routeMatrix.routes.push({
      sourcePath: '/contact',
      sourceStatus: 200,
      sourceFinalPath: '/contact',
      sourceTitle: 'Contact',
      sourceH1: 'Contact',
      targetPath: '/contact',
      targetStatus: 200,
      targetFinalPath: '/contact',
      targetTitle: 'Contact',
      targetH1: 'Contact',
      expectedRedirect: false,
      routeRole: 'form',
      accepted: true,
      notes: 'Anonymous contact form route.'
    });
    routeMatrix.firstFoldBrandAssetParity.push(...routeMatrix.firstFoldBrandAssetParity
      .filter((record) => record.sourcePath === '/')
      .map((record) => ({
        ...structuredClone(record),
        sourcePath: '/contact',
        targetPath: '/contact',
        notes: 'The public contact form uses the same accepted brand treatment.'
      })));
  });
  mutateJson(join(packetDir, 'parity-report.json'), (parity) => {
    parity.functionalScope = {
      reviewed: true,
      applies: true,
      reason: 'The source has an anonymous contact form.'
    };
    parity.functionalChecks = [{
      route: '/contact',
      sourceExpectation: 'Anonymous visitors can send a contact message.',
      targetObservation: 'Invalid and valid submissions were exercised.',
      status: 'pass',
      evidence: 'browser-evidence.json',
      notes: ''
    }];
    parity.addressableSurface.routesInScope += 1;
    parity.routeChecks.push({ route: '/contact', status: 'pass', evidence: 'browser-evidence.json' });
    parity.contentChecks.push({
      route: '/contact',
      sourceExpectation: 'A public contact form is present.',
      targetObservation: 'The Drupal-owned contact form preserves that intent.',
      status: 'pass',
      evidence: 'browser-evidence.json',
      notes: ''
    });
    parity.visualChecks.push({
      route: '/contact',
      sourceExpectation: 'Form hierarchy and branding match.',
      targetObservation: 'The form route was compared in browser evidence.',
      status: 'pass',
      evidence: 'browser-evidence.json',
      notes: ''
    });
  });
  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.renderedEmbedChecks = [{
      route: '/contact',
      embedType: 'form',
      expectedSourceSignal: 'Anonymous contact form.',
      targetRenderedSignal: 'Drupal Webform.',
      providerLinkOrFallbackPresent: true,
      status: 'pass',
      evidence: 'claim-evidence.json'
    }];
    independent.anonymousFormChecks = [{
      formKey: 'contact-main',
      sourceRoute: '/contact',
      targetRoute: '/contact',
      purpose: 'contact_message',
      modeledOwner: 'webform',
      browserOwner: 'webform',
      expectedOutcome: 'message_delivery',
      browserOutcome: outcomeMode,
      anonymousInvalidAndValidSubmissionVerified: true,
      outcomeEvidence: 'evidence/browser/form-outcome.json',
      abuseProtectionDisposition: 'rendered_honeypot',
      abuseProtectionRationale: 'A credential-free honeypot is rendered and enforced locally.',
      abuseProtectionEvidence: 'evidence/browser/form-abuse-protection.json',
      status: 'pass',
      evidence: 'claim-evidence.json'
    }];
    independent.placeholderTextScan.scannedRoutes.push('/contact');
    independent.firstFoldBrandAssetChecks.push(...independent.firstFoldBrandAssetChecks
      .filter((record) => record.sourceRoute === '/')
      .map((record) => ({
        ...structuredClone(record),
        sourceRoute: '/contact',
        targetRoute: '/contact'
      })));
    independent.compositionModelFidelityChecks.push({
      ...structuredClone(independent.compositionModelFidelityChecks[0]),
      sourceRoute: '/contact',
      targetRoute: '/contact',
      sectionsChecked: ['Contact form']
    });
  });

  const browserPath = join(packetDir, 'browser-evidence.json');
  const browser = JSON.parse(readFileSync(browserPath, 'utf8'));
  const contactChecks = browser.publicRouteChecks.map((homeCheck) => {
    const contact = structuredClone(homeCheck);
    contact.routeRole = 'form';
    contact.sourceUrl = `${sourceBaseUrl}/contact`;
    contact.sourceFinalUrl = `${sourceBaseUrl}/contact`;
    contact.targetUrl = `${targetBaseUrl}/contact`;
    contact.targetFinalUrl = `${targetBaseUrl}/contact`;
    contact.renderedSignals.sourceTitle = 'Contact';
    contact.renderedSignals.targetTitle = 'Contact';
    contact.renderedSignals.sourceH1 = 'Contact';
    contact.renderedSignals.targetH1 = 'Contact';
    contact.renderedSeoSignals.targetCanonicalUrl = `${targetBaseUrl}/contact`;
    contact.renderedSeoSignals.targetMetaDescription = 'Contact the fixture site.';
    contact.accessibilityCheck.report = `evidence/browser/axe-contact-${homeCheck.viewport.name}.json`;
    contact.accessibilityCheck.manualChecks.formLabelsErrorsAndFocus = 'pass';
    contact.accessibilityCheck.manualChecks.formLabelsErrorsAndFocusNotApplicableRationale = '';
    return contact;
  });
  browser.publicRouteChecks.push(...contactChecks);
  browser.anonymousFormChecks = [{
    formKey: 'contact-main',
    sourceRoute: '/contact',
    targetUrl: `${targetBaseUrl}/contact`,
    purpose: 'contact_message',
    drupalOwner: 'webform',
    anonymousSession: true,
    syntheticTestData: true,
    invalidSubmission: { performed: true, errorsVisible: true, focusOrSummaryVerified: true },
    validSubmission: { performed: true, successStateVisible: true },
    outcome: { mode: outcomeMode, evidence: 'evidence/browser/form-outcome.json' },
    abuseProtection: {
      mode: 'rendered_honeypot',
      dispositionVerified: true,
      rationale: 'A credential-free honeypot is rendered and enforced locally.',
      evidence: 'evidence/browser/form-abuse-protection.json'
    },
    status: 'pass',
    accepted: true,
    blockers: []
  }];
  writeJson(browserPath, browser);

  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    const contactReviews = blind.routeViewportReviews.map((homeReview) => ({
      ...structuredClone(homeReview),
      route: '/contact',
      sourceTruthReference: `${sourceBaseUrl}/contact`,
      targetUrlOrArtifact: `${targetBaseUrl}/contact`,
      sourceScreenshot: `source-contact-${homeReview.viewport}.png`,
      targetScreenshot: `target-contact-${homeReview.viewport}.png`,
      routeNotes: `${homeReview.viewport} contact form checked`
    }));
    blind.reviewInputs.targetUrlsOrArtifacts.push(`${targetBaseUrl}/contact`);
    blind.routeViewportReviews.push(...contactReviews);
    blind.routeCoverage.primaryRoutesReviewed.push('/contact');
  });
  const blindEvidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  for (const [index, [viewport, width, height]] of [
    ['desktop', 1280, 800],
    ['mobile', 390, 844]
  ].entries()) {
    writeFileSync(join(blindEvidenceDir, `source-contact-${viewport}.png`), screenshotPng(20 + index, width, height));
    writeFileSync(join(blindEvidenceDir, `target-contact-${viewport}.png`), screenshotPng(30 + index, width, height));
  }

  const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
  for (const [viewport, width, height] of [['desktop', 1280, 800], ['mobile', 390, 844]]) {
    writeJson(join(browserEvidenceDir, `axe-contact-${viewport}.json`), {
      testEngine: { name: 'axe-core', version: '4.10.2' },
      toolOptions: { runOnly: null, rules: {} },
      testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: width, windowHeight: height },
      timestamp: testCheckedAt,
      url: `${targetBaseUrl}/contact`,
      passes: [],
      violations: [],
      incomplete: [],
      inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
    });
  }
  writeJson(join(browserEvidenceDir, 'form-outcome.json'), {
    schemaVersion: 'public-kit.form-outcome-evidence.1',
    checkedAt: testCheckedAt,
    formKey: 'contact-main',
    targetUrl: `${targetBaseUrl}/contact`,
    mode: outcomeMode,
    result: 'pass',
    handlerOwner: 'fixture outcome handler',
    resultReference: 'synthetic-result-1',
    provider: ['provider_delivery', 'provider_handoff'].includes(outcomeMode) ? 'Fixture provider' : '',
    rationale: outcomeMode === 'other' ? 'The explicit fixture outcome is intentionally custom.' : '',
    observation: 'Synthetic submission reached the configured local outcome.'
  });
  writeJson(join(browserEvidenceDir, 'form-abuse-protection.json'), {
    schemaVersion: 'public-kit.form-abuse-evidence.1',
    checkedAt: testCheckedAt,
    formKey: 'contact-main',
    targetUrl: `${targetBaseUrl}/contact`,
    mode: 'rendered_honeypot',
    result: 'pass',
    renderedSelector: 'input[name="fixture_honeypot"]',
    enforcementVerified: true,
    observation: 'The anonymous form rendered and enforced its honeypot field.'
  });
  writeJson(join(browserEvidenceDir, 'form-local-abuse-exception.json'), {
    schemaVersion: 'public-kit.form-abuse-evidence.1',
    checkedAt: testCheckedAt,
    formKey: 'contact-main',
    targetUrl: `${targetBaseUrl}/contact`,
    mode: 'local_only_exception',
    result: 'accepted_gap',
    localTargetVerified: true,
    rationale: 'The DDEV review target is local-only and requires a production control before launch.',
    observation: 'The DDEV review target is local-only and the production abuse-control choice remains a launch gap.'
  });
  writeJson(join(browserEvidenceDir, 'form-rate-limiting.json'), {
    schemaVersion: 'public-kit.form-abuse-evidence.1',
    checkedAt: testCheckedAt,
    formKey: 'contact-main',
    targetUrl: `${targetBaseUrl}/contact`,
    mode: 'configured_rate_limiting',
    result: 'pass',
    configurationOwner: 'fixture.rate_limit',
    enforcementVerified: true,
    observation: 'Anonymous submission throttling was read back from Drupal configuration and exercised.'
  });
  refreshCaptureEvidenceBindings(packetDir);
  attachFixtureReviewHandoff(packetDir, targetBaseUrl);
}

function addQueryPrimaryEvidence(packetDir, targetBaseUrl) {
  const sourceBaseUrl = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8')).sourceBaseUrl;
  const sourceRoute = '/search?state=featured';
  const targetRoute = '/search?state=featured';
  const sourceUrl = `${sourceBaseUrl}${sourceRoute}`;
  const targetUrl = `${targetBaseUrl}${targetRoute}`;

  mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
    routeMatrix.browserFirstRouteExpansion.browserRenderedSeedRoutes.push(sourceRoute);
    routeMatrix.primaryRoutes.push({
      sourcePath: sourceRoute,
      targetPath: targetRoute,
      routeRole: 'search',
      sourceIntent: 'A specific source search result state.',
      targetIntent: 'The equivalent target search result state.',
      matchesBrowserRenderedSource: true,
      accepted: true,
      notes: 'The query is part of the primary route identity.'
    });
    routeMatrix.routes.push({
      ...structuredClone(routeMatrix.routes[0]),
      sourcePath: sourceRoute,
      sourceStatus: 200,
      sourceFinalPath: sourceRoute,
      sourceTitle: 'Search',
      sourceH1: 'Search',
      targetPath: targetRoute,
      targetStatus: 200,
      targetFinalPath: targetRoute,
      targetTitle: 'Search',
      targetH1: 'Search',
      routeRole: 'search',
      notes: 'Exact query-bearing primary route.'
    });
    routeMatrix.firstFoldBrandAssetParity.push(...routeMatrix.firstFoldBrandAssetParity
      .filter((record) => record.sourcePath === '/')
      .map((record) => ({
        ...structuredClone(record),
        sourcePath: sourceRoute,
        targetPath: targetRoute,
        notes: 'The search state uses the accepted brand treatment.'
      })));
  });

  mutateJson(join(packetDir, 'source-audit.json'), (sourceAudit) => {
    sourceAudit.representativeUrls.push(sourceUrl);
    sourceAudit.evidencePoints.push({
      claim: 'The query-bearing source search state was captured.',
      url: sourceUrl,
      method: 'browser',
      result: 'observed'
    });
    sourceAudit.contentInventory.push({ route: sourceRoute, type: 'search', title: 'Search' });
    sourceAudit.designSignals.push({ route: sourceRoute, signal: 'Search hierarchy captured' });
    sourceAudit.routeInventorySummary.attemptedRoutes += 1;
    sourceAudit.routeInventorySummary.successfulRoutes += 1;
  });

  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    patternMap.pageCompositionOwnership.push({
      ...structuredClone(patternMap.pageCompositionOwnership[0]),
      sourceRoute,
      routeRole: 'search',
      ownerRationale: 'A structured Drupal search route owns this query state.'
    });
  });

  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.placeholderTextScan.scannedRoutes.push(targetRoute);
    independent.firstFoldBrandAssetChecks.push(...independent.firstFoldBrandAssetChecks
      .filter((record) => record.sourceRoute === '/')
      .map((record) => ({
        ...structuredClone(record),
        sourceRoute,
        targetRoute
      })));
    independent.compositionModelFidelityChecks.push({
      ...structuredClone(independent.compositionModelFidelityChecks[0]),
      sourceRoute,
      targetRoute,
      sectionsChecked: ['Search results']
    });
  });

  mutateJson(join(packetDir, 'parity-report.json'), (parity) => {
    parity.addressableSurface.routesInScope += 1;
    parity.routeChecks.push({ route: targetRoute, status: 'pass', evidence: 'browser-evidence.json' });
  });

  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    const queryChecks = browser.publicRouteChecks.map((homeCheck) => {
      const check = structuredClone(homeCheck);
      const viewport = check.viewport.name;
      check.routeRole = 'search';
      check.sourceUrl = sourceUrl;
      check.sourceFinalUrl = sourceUrl;
      check.targetUrl = targetUrl;
      check.targetFinalUrl = targetUrl;
      check.sourceScreenshot = `evidence/blind-adversarial-review/source-search-${viewport}.png`;
      check.targetScreenshot = `evidence/blind-adversarial-review/target-search-${viewport}.png`;
      check.renderedSignals.sourceTitle = 'Search';
      check.renderedSignals.targetTitle = 'Search';
      check.renderedSignals.sourceH1 = 'Search';
      check.renderedSignals.targetH1 = 'Search';
      check.renderedSeoSignals.targetCanonicalUrl = targetUrl;
      check.renderedSeoSignals.targetMetaDescription = 'Featured search results.';
      check.accessibilityCheck.report = `evidence/browser/axe-search-primary-${viewport}.json`;
      check.notes = `Exact query-bearing search state checked at ${viewport}.`;
      return check;
    });
    browser.publicRouteChecks.push(...queryChecks);
  });

  const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
  for (const [viewport, width, height] of [['desktop', 1280, 800], ['mobile', 390, 844]]) {
    writeJson(join(browserEvidenceDir, `axe-search-primary-${viewport}.json`), {
      testEngine: { name: 'axe-core', version: '4.10.2' },
      toolOptions: { runOnly: null, rules: {} },
      testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: width, windowHeight: height },
      timestamp: testCheckedAt,
      url: targetUrl,
      passes: [],
      violations: [],
      incomplete: [],
      inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
    });
  }

  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    const queryReviews = blind.routeViewportReviews
      .filter((review) => review.route === '/')
      .map((homeReview) => ({
        ...structuredClone(homeReview),
        route: targetRoute,
        sourceTruthReference: sourceUrl,
        targetUrlOrArtifact: targetUrl,
        sourceScreenshot: `source-search-${homeReview.viewport}.png`,
        targetScreenshot: `target-search-${homeReview.viewport}.png`,
        routeNotes: `${homeReview.viewport} query-bearing search state checked`
      }));
    blind.reviewInputs.targetUrlsOrArtifacts.push(targetUrl);
    blind.routeViewportReviews.push(...queryReviews);
    blind.routeCoverage.primaryRoutesReviewed.push(targetRoute);
  });

  const blindEvidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  for (const [index, [viewport, width, height]] of [
    ['desktop', 1280, 800],
    ['mobile', 390, 844]
  ].entries()) {
    writeFileSync(join(blindEvidenceDir, `source-search-${viewport}.png`), screenshotPng(40 + index, width, height));
    writeFileSync(join(blindEvidenceDir, `target-search-${viewport}.png`), screenshotPng(50 + index, width, height));
  }
  refreshCaptureEvidenceBindings(packetDir);
  attachFixtureReviewHandoff(packetDir, targetBaseUrl);
}

function addQualifyingNextCycleEvidence(packetDir, targetBaseUrl) {
  const evidenceDir = join(packetDir, 'evidence', 'next-cycle');
  mkdirSync(evidenceDir, { recursive: true });
  const createdAt = testCheckedAt;
  const futureDate = new Date(Date.parse(testCheckedAt) + 365 * 24 * 60 * 60 * 1000).toISOString();
  const evidenceRecord = {
    schemaVersion: 'public-kit.next-cycle-probe-evidence.1',
    targetBaseUrl,
    checkedAt: testCheckedAt,
    editorUser: 'editor',
    editorRole: 'content editor',
    probeId: 'next-cycle-probe-42',
    result: 'pass'
  };
  writeJson(join(evidenceDir, 'discovery.json'), {
    ...evidenceRecord,
    commands: ['field definitions', 'taxonomy vocabularies', 'workflows and permissions'],
    temporalCycleDimensionsFound: 1
  });
  writeJson(join(evidenceDir, 'probe.json'), {
    ...evidenceRecord,
    futureValue: '2027',
    futureDate,
    publicUrl: `${targetBaseUrl}/__next-cycle-probe-42`,
    anonymousStatus: 200,
    outputMarker: 'Next cycle probe 2027'
  });
  writeJson(join(evidenceDir, 'cleanup.json'), {
    ...evidenceRecord,
    contentResidueCount: 0,
    revisionResidueCount: 0,
    aliasResidueCount: 0,
    periodOrTermResidueCount: 0,
    publicUrlStatusAfterCleanup: 410
  });
  writeJson(join(packetDir, 'next-cycle-verification.json'), {
    schemaVersion: 'public-kit.next-cycle-verification.1',
    site: targetBaseUrl,
    checkedAt: testCheckedAt,
    applicability: {
      reviewed: true,
      applies: true,
      reason: 'The recurring event model has a festival-year dimension.'
    },
    discovery: {
      commands: [
        'drush php:eval field definitions',
        'drush php:eval taxonomy vocabularies',
        'drush php:eval workflows and role permissions'
      ],
      fieldDefinitionsInspected: true,
      taxonomyVocabulariesInspected: true,
      workflowsInspected: true,
      recurringPublicModels: [
        {
          entityType: 'node',
          bundle: 'event',
          publicRoutes: ['/events'],
          reviewed: true,
          dimensions: [
            {
              id: 'event-year',
              kind: 'year',
              machineName: 'field_year',
              configName: 'field.field.node.event.field_year',
              latestCurrentValue: '2026',
              latestCurrentComparable: 2026
            }
          ],
          noTemporalCycleDimensionRationale: ''
        }
      ],
      evidence: 'discovery.json'
    },
    leastPrivilegeEditor: {
      editorUser: 'editor',
      editorRole: 'content editor',
      leastPrivilegeRoleConfirmed: true,
      permissionChecks: [
        {
          capability: 'select_cycle_value',
          permission: 'select future festival year',
          granted: true,
          status: 'pass',
          evidence: 'probe.json'
        },
        {
          capability: 'publish_content',
          permission: 'create and publish event content',
          granted: true,
          status: 'pass',
          evidence: 'probe.json'
        }
      ]
    },
    futurePeriodOrTermProbe: {
      dimensionId: 'event-year',
      operation: 'selected_existing',
      value: '2027',
      comparable: 2027,
      editorUser: 'editor',
      editorRole: 'content editor',
      status: 'pass',
      evidence: 'probe.json'
    },
    futureContentProbe: {
      probeId: 'next-cycle-probe-42',
      entityType: 'node',
      bundle: 'event',
      editorUser: 'editor',
      editorRole: 'content editor',
      createdAt,
      futureDate,
      published: true,
      workflowTransition: {
        type: 'publication_status',
        fromState: 'unpublished',
        toState: 'published',
        status: 'pass',
        evidence: 'probe.json'
      },
      publicUrl: `${targetBaseUrl}/__next-cycle-probe-42`,
      anonymousStatus: 200,
      outputMarker: 'Next cycle probe 2027',
      outputObserved: true,
      status: 'pass',
      evidence: 'probe.json'
    },
    cleanup: {
      probeId: 'next-cycle-probe-42',
      checkedAt: testCheckedAt,
      probeContentDeleted: true,
      periodOrTermCleanup: 'not_created',
      contentResidueCount: 0,
      revisionResidueCount: 0,
      aliasResidueCount: 0,
      periodOrTermResidueCount: 0,
      publicUrlStatusAfterCleanup: 410,
      status: 'pass',
      evidence: 'cleanup.json'
    },
    blockers: [],
    notes: ''
  });
  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    browser.editorWorkflowChecks.push({
      workflow: 'create',
      entityType: 'node',
      bundle: 'event',
      editorUser: 'editor',
      editorRole: 'content editor',
      drupalRoute: '/node/add/event',
      taskPerformed: 'Created and published the future-cycle Event probe.',
      formScreenshot: 'evidence/blind-adversarial-review/target-desktop.png',
      resultScreenshot: 'evidence/blind-adversarial-review/target-mobile.png',
      fieldsAndWidgetsVerified: ['title', 'field_year', 'field_event_date'],
      publicOutputAffected: '/events',
      visualOrBehaviorResult: 'The future event appeared anonymously before cleanup.',
      status: 'pass',
      acceptedExceptions: [],
      accepted: true,
      blockers: []
    });
  });
  attachFixtureReviewHandoff(packetDir, targetBaseUrl);
}

test('default verifier fetches the declared real target and binds primary-route evidence', async () => {
  let requestCount = 0;
  await withHttpServer(
    (_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Target site</title></head><body><h1>Target home</h1></body></html>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-target-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.liveTargetValid, true);
      assert.equal(report.routeChecks.length, 1);
      assert.equal(report.routeChecks[0].passed, true, report.routeChecks[0].errors.join('\n'));
      assert.match(report.routeChecks[0].bodySha256, /^sha256:[a-f0-9]{64}$/);
      assert.match(report.target.targetFingerprint, /^sha256:[a-f0-9]{64}$/);
      assert.equal(report.target.resolutionSource, 'explicit');
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.deepEqual(report.agentContinuation, {
        schemaVersion: 'public-kit.agent-continuation.2',
        status: 'continue_required',
        requiredAction: 'repair-and-reverify',
        shouldContinue: true,
        agentMayPause: false,
        agentMayStop: false,
        stopConditionMet: false,
        humanReviewRequiredBeforeContinuing: false,
        externalBlockerMayPauseOnlyWhenRecorded: true,
        blockers: report.completionBlockers.map(({ verifierConfirmedExternal, ...blocker }) => blocker),
        blockedReasons: report.completionBlockedReasons,
        instruction: 'Continue autonomously: repair every agent-resolvable failure, refresh the evidence it affects, and rerun the default live verifier. Do not hand off or pause while any agent-resolvable blocker remains, even when other blockers are external. Do not wait for routine human review.'
      });
      assert.equal(report.packetVerification.completionEvidence.packetCompletionReady, false);
      assert.match(
        report.packetVerification.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /unchanged from the shipped template/
      );
      assert.match(report.completionBlockedReasons.join(' '), /Independent verification/);
    }
  );
  assert.equal(requestCount, 3, 'primary, target-required, and full rendered-surface checks should fetch the declared target');
});

test('live verifier blocks broken same-origin links present in accepted-route response HTML', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/missing') {
        response.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
        response.end('<!doctype html><html><body><h1>Missing</h1></body></html>');
        return;
      }
      if (request.url === '/large-manual.pdf') {
        response.writeHead(200, {
          'content-length': 6 * 1024 * 1024,
          'content-type': 'application/pdf'
        });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      if (request.url?.startsWith('/working')) {
        response.end('<!doctype html><html><body><h1>Working</h1></body></html>');
        return;
      }
      response.end(`<!doctype html><html><head><title>Target site</title></head><body>
        <h1>Target home</h1>
        <a href="/working?mode=public#result">Working</a>
        <a href="/working?mode=public#other">Working duplicate</a>
        <a href="/missing">Missing</a>
        <a href="/large-manual.pdf">Large manual</a>
        <a href="mailto:help@example.com">Email</a>
        <a href="https://external.example/path">External</a>
        <template><a href="/template-only-missing">Template-only</a></template>
        <script>const example = '<a href="/script-only-missing">Script-only</a>';</script>
      </body></html>`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-broken-response-link-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.routes.push(
        {
          sourcePath: '/working',
          targetPath: '/working',
          routeRole: 'detail',
          targetStatus: 200,
          targetFinalPath: '/working',
          targetTitle: 'Working',
          targetH1: 'Working',
          expectedRedirect: false,
          accepted: true,
          notes: 'Declared detail route used by the link-integrity fixture.'
        },
        {
          sourcePath: '/large-manual.pdf',
          targetPath: '/large-manual.pdf',
          routeRole: 'media',
          targetStatus: 200,
          targetFinalPath: '/large-manual.pdf',
          targetTitle: '',
          targetH1: '',
          expectedRedirect: false,
          accepted: true,
          notes: 'Declared non-HTML media route used by the response-body fixture.'
        }
      );
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      assert.equal(report.liveTargetValid, false);
      assert.equal(report.serverRenderedResponseSurface.uniqueInternalLinkCount, 3);
      const missing = report.serverRenderedResponseSurface.linkChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/missing'
      );
      assert.equal(missing?.passed, false);
      assert.equal(missing?.finalStatus, 404);
      assert.ok(missing?.referrers.some((url) => new URL(url).pathname === '/'));
      const largeManual = report.serverRenderedResponseSurface.linkChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/large-manual.pdf'
      );
      assert.equal(largeManual?.passed, true, 'status-only link checks must not download large linked files');
      const largeManualRoute = report.serverRenderedResponseSurface.routeChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/large-manual.pdf'
      );
      assert.equal(largeManualRoute?.passed, true, 'accepted non-HTML routes must not buffer large response bodies');
      assert.equal(largeManualRoute?.isHtml, false);
      assert.match(report.errors.join('\n'), /Server-rendered same-origin link .*\/missing.*HTTP 404/);
      assert.doesNotMatch(JSON.stringify(report), /mode=public/);
    }
  );
});

test('live verifier blocks source-origin link leaks unless the exact pair has an accepted exception', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>Target site</title></head><body>
        <h1>Target home</h1>
        <a href="https://source.example/archive?page=1#top">Legacy source archive</a>
      </body></html>`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-source-origin-link-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.sourceOriginLinkExceptions = [];
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const blocked = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(blocked.valid, false);
      assert.equal(blocked.serverRenderedResponseSurface.sourceOriginLinkCount, 1);
      assert.equal(blocked.serverRenderedResponseSurface.sourceOriginLinkChecks[0].passed, false);
      assert.equal(blocked.liveHttpBudget.tasksByKind['source-origin-link'], 1);
      assert.match(blocked.errors.join('\n'), /points back to source origin .* without an accepted per-link exception/);
      assert.doesNotMatch(JSON.stringify(blocked), /page=1/);

      mkdirSync(join(packetDir, 'evidence'), { recursive: true });
      writeFileSync(join(packetDir, 'evidence', 'source-link-exception.txt'), 'Approved retained source archive dependency.\n');
      routeMatrix.sourceOriginLinkExceptions = [{
        referrer: '/',
        target: 'https://source.example/archive?page=1',
        rationale: 'The source archive remains the named system of record for this public dependency.',
        accepter: 'Content owner',
        evidence: 'evidence/source-link-exception.txt',
        accepted: true
      }];
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const accepted = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(accepted.valid, true, accepted.errors.join('\n'));
      assert.equal(accepted.serverRenderedResponseSurface.sourceOriginLinkCount, 1);
      assert.equal(accepted.serverRenderedResponseSurface.sourceOriginLinkChecks[0].passed, true);
      assert.equal(
        accepted.serverRenderedResponseSurface.sourceOriginLinkChecks[0].acceptedException.accepter,
        'Content owner'
      );
      assert.doesNotMatch(JSON.stringify(accepted), /page=1/);
    }
  );
});

test('live verifier blocks an undeclared same-origin detail link even when it returns 200', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      if (request.url?.startsWith('/article/undeclared')) {
        response.end('<!doctype html><html><body><h1>Undeclared detail</h1></body></html>');
        return;
      }
      response.end(`<!doctype html><html><head><title>Target site</title></head><body>
        <h1>Target home</h1>
        <a href="/article/undeclared?preview=private-value#content">Undeclared detail</a>
      </body></html>`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-undeclared-detail-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      const detail = report.serverRenderedResponseSurface.linkChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/article/undeclared'
      );
      const expectedQueryDigest = createHash('sha256')
        .update('?preview=private-value')
        .digest('hex');
      const doubleRedactedDigest = createHash('sha256')
        .update(`?query-sha256=${expectedQueryDigest}`)
        .digest('hex');
      assert.equal(detail?.finalStatus, 200);
      assert.equal(detail?.passed, false);
      assert.equal(
        new URL(detail.requestedUrl).search,
        `?query-sha256=${expectedQueryDigest}`,
        'redacted query identities must remain stable across nested report sanitizers'
      );
      assert.match(
        report.errors.join('\n'),
        /not represented by an accepted routes or targetRequiredRoutes entry.*no exact accepted disposition/
      );
      assert.doesNotMatch(JSON.stringify(report), /private-value/);
      assert.doesNotMatch(JSON.stringify(report), new RegExp(doubleRedactedDigest));

      mkdirSync(join(packetDir, 'evidence'), { recursive: true });
      writeFileSync(join(packetDir, 'evidence', 'unlisted-detail.txt'), 'Approved dynamic detail endpoint.\n');
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.sameOriginLinkExceptions = [{
        referrer: '/',
        target: '/article/undeclared?preview=private-value',
        disposition: 'dynamic_endpoint',
        rationale: 'This runtime-generated detail endpoint is intentionally outside the static route inventory.',
        accepter: 'Application owner',
        evidence: 'evidence/unlisted-detail.txt',
        accepted: true
      }];
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const accepted = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(accepted.valid, true, accepted.errors.join('\n'));
      assert.equal(accepted.serverRenderedResponseSurface.linkChecks[0].passed, true);
      assert.equal(
        accepted.serverRenderedResponseSurface.linkChecks[0].acceptedDispositions[0].disposition,
        'dynamic_endpoint'
      );
      assert.doesNotMatch(JSON.stringify(accepted), /private-value/);
    }
  );
});

test('live verifier accepts an exact evidenced external redirect without fetching the external origin', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url?.startsWith('/donate')) {
        response.writeHead(302, {
          location: 'https://payments.example/checkout?session=private-final'
        });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>Target site</title></head><body>
        <h1>Target home</h1>
        <a href="/donate?token=private-start">Donate</a>
      </body></html>`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-external-redirect-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.expectedExternalLinkRedirects = [];
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const blocked = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(blocked.valid, false);
      assert.match(blocked.errors.join('\n'), /redirects externally.*without an exact accepted expectation/);
      assert.doesNotMatch(JSON.stringify(blocked), /private-start|private-final/);

      mkdirSync(join(packetDir, 'evidence'), { recursive: true });
      writeFileSync(join(packetDir, 'evidence', 'external-redirect.txt'), 'Approved external payment provider.\n');
      routeMatrix.expectedExternalLinkRedirects = [{
        referrer: '/',
        start: '/donate?token=private-start',
        finalMatch: 'exact_url',
        final: 'https://payments.example/checkout?session=private-final',
        rationale: 'Donation checkout is intentionally owned by the external payment provider.',
        accepter: 'Commerce owner',
        evidence: 'evidence/external-redirect.txt',
        accepted: true
      }];
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const accepted = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(accepted.valid, true, accepted.errors.join('\n'));
      const redirect = accepted.serverRenderedResponseSurface.linkChecks[0];
      assert.equal(redirect.passed, true);
      assert.equal(redirect.externalRedirect, true);
      assert.equal(redirect.finalStatus, 302);
      assert.equal(redirect.acceptedDispositions[0].finalMatch, 'exact_url');
      assert.doesNotMatch(JSON.stringify(accepted), /private-start|private-final/);
    }
  );
});

test('live verifier rejects credential-bearing same-origin and external redirects without leaking userinfo', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/same-origin-credential') {
        response.writeHead(302, {
          location: `http://private-user:same-origin-secret@${request.headers.host}/working`
        });
        response.end();
        return;
      }
      if (request.url === '/external-credential') {
        response.writeHead(302, {
          location: 'https://external-user:external-secret@payments.example/checkout'
        });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>Target site</title></head><body>
        <h1>Target home</h1>
        <a href="/same-origin-credential">Same-origin credential redirect</a>
        <a href="/external-credential">External credential redirect</a>
      </body></html>`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-credential-redirects-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      assert.equal(report.serverRenderedResponseSurface.linkChecks.length, 2);
      assert.ok(report.serverRenderedResponseSurface.linkChecks.every((check) => check.passed === false));
      assert.match(report.errors.join('\n'), /Refusing credential-bearing redirect/);
      assert.doesNotMatch(
        JSON.stringify(report),
        /private-user|same-origin-secret|external-user|external-secret/
      );
    }
  );
});

test('live report removes local packet paths before redacting query-like directory names', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'query-packet-path-'));
      const packetDir = join(temp, 'review?token=private-value');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      writeFileSync(join(packetDir, 'source-audit.json'), '{');

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      const serialized = JSON.stringify(report);
      const rawQueryIndex = serialized.indexOf('private-value');
      assert.equal(
        rawQueryIndex,
        -1,
        rawQueryIndex === -1 ? '' : serialized.slice(Math.max(0, rawQueryIndex - 120), rawQueryIndex + 160)
      );
      assert.equal(serialized.includes(temp), false);
      assert.match(report.packetDir, /^review\?query-sha256=[a-f0-9]{64}$/);
      assert.match(report.errors.join('\n'), /review\?query-sha256=[a-f0-9]{64}\/source-audit\.json/);
    }
  );
});

test('live verifier checks every accepted route row, not only primary routes', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/article/example') {
        response.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
        response.end('<!doctype html><html><body><h1>Missing article</h1></body></html>');
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Target site</title></head><body><h1>Target home</h1></body></html>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-full-route-surface-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.routes.push({
        sourcePath: '/article/example',
        targetPath: '/article/example',
        routeRole: 'detail',
        targetStatus: 200,
        targetFinalPath: '/article/example',
        targetTitle: 'Example article',
        targetH1: 'Example article',
        expectedRedirect: false,
        accepted: true,
        notes: 'Representative detail route.'
      });
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      const detail = report.serverRenderedResponseSurface.routeChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/article/example'
      );
      assert.equal(detail?.passed, false);
      assert.equal(detail?.finalStatus, 404);
      assert.match(report.errors.join('\n'), /\/article\/example ended with HTTP 404/);
      assert.match(detail?.errors.join('\n') ?? '', /returned status 404; expected 200/);
      assert.equal(Object.hasOwn(report.liveRouteBudget, 'maxRoutes'), true);
      assert.equal(Object.hasOwn(report.liveRouteBudget, 'routeCount'), true);
      assert.equal(Object.hasOwn(report.liveHttpBudget, 'maxTasks'), true);
      assert.equal(Object.hasOwn(report.liveHttpBudget, 'taskCount'), true);
      assert.equal(Object.hasOwn(report.liveHttpBudget, 'maxRoutes'), false);
    }
  );
});

test('packet validator rejects accepted route rows with blank source or target paths', async () => {
  for (const field of ['sourcePath', 'targetPath']) {
    const temp = mkdtempSync(join(tmpdir(), `blank-${field}-`));
    const packetDir = join(temp, 'review-packet');
    copyTemplatePacket(packetDir);
    const routeMatrix = liveRouteMatrix('https://target.example');
    const blankRoute = {
      ...structuredClone(routeMatrix.routes[0]),
      sourcePath: '/blank-route',
      targetPath: '/blank-route',
      targetFinalPath: '/blank-route',
      routeRole: 'other'
    };
    blankRoute[field] = '';
    if (field === 'targetPath') {
      blankRoute.targetFinalPath = '';
    }
    routeMatrix.routes.push(blankRoute);
    writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, field);
    assert.match(
      report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
      /route rows must declare a valid routeRole.*direct final 2xx path/i,
      field
    );
  }
});

test('packet completion accepts query-bearing primary routes only with exact evidence', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'packet-primary-query-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  addQueryPrimaryEvidence(packetDir, 'https://target.example');

  const exact = await validatePacket({ packetDir });
  assert.equal(
    exact.completionEvidence.packetSupportsCompletion,
    true,
    exact.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    const owner = patternMap.pageCompositionOwnership.find((record) => record.routeRole === 'search');
    owner.sourceRoute = '/search?state=other';
  });
  const wrongOwnerState = await validatePacket({ packetDir });
  assert.equal(wrongOwnerState.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    wrongOwnerState.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /pattern-map\.json must record reviewed Drupal structures plus accepted route composition/i
  );
  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    const owner = patternMap.pageCompositionOwnership.find((record) => record.routeRole === 'search');
    owner.sourceRoute = '/search?state=featured';
  });

  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    for (const check of browser.publicRouteChecks.filter((record) => record.routeRole === 'search')) {
      check.targetUrl = 'https://target.example/search';
      check.targetFinalUrl = 'https://target.example/search';
      check.renderedSeoSignals.targetCanonicalUrl = 'https://target.example/search';
    }
  });
  for (const viewport of ['desktop', 'mobile']) {
    mutateJson(join(packetDir, `evidence/browser/axe-search-primary-${viewport}.json`), (axe) => {
      axe.url = 'https://target.example/search';
    });
  }

  const pathOnly = await validatePacket({ packetDir });
  assert.equal(pathOnly.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    pathOnly.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /browser-evidence\.json must cover every primary route at desktop and mobile/i
  );
});

test('live verifier enforces redirect and final-path contracts for every accepted route row', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/article/example') {
        response.writeHead(302, { location: '/' });
        response.end();
        return;
      }
      if (request.url === '/expected-alias') {
        response.writeHead(302, { location: '/wrong-final' });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Target site</title></head><body><h1>Target home</h1></body></html>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-route-contracts-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.routes.push(
        {
          sourcePath: '/article/example',
          targetPath: '/article/example',
          routeRole: 'detail',
          targetStatus: 200,
          targetFinalPath: '/article/example',
          targetTitle: 'Example article',
          targetH1: 'Example article',
          expectedRedirect: false,
          accepted: true,
          notes: 'The detail route must remain a direct response.'
        },
        {
          sourcePath: '/expected-alias',
          targetPath: '/expected-alias',
          routeRole: 'other',
          targetStatus: 302,
          targetFinalPath: '/expected-final',
          targetTitle: 'Expected destination',
          targetH1: 'Expected destination',
          expectedRedirect: true,
          accepted: true,
          notes: 'The alias must retain its declared destination.'
        }
      );
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      const direct = report.serverRenderedResponseSurface.routeChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/article/example'
      );
      const alias = report.serverRenderedResponseSurface.routeChecks.find((check) =>
        new URL(check.requestedUrl).pathname === '/expected-alias'
      );
      assert.equal(direct?.passed, false);
      assert.match(direct?.errors.join('\n') ?? '', /declares a direct response but the live response redirected/);
      assert.match(direct?.errors.join('\n') ?? '', /resolved to \/; expected \/article\/example/);
      assert.equal(alias?.passed, false);
      assert.match(alias?.errors.join('\n') ?? '', /resolved to \/wrong-final; expected \/expected-final/);
    }
  );
});

test('host-mode target discovery ignores ambient DDEV variables and uses matching ddev describe output', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Target site</title></head><body><h1>Target home</h1></body></html>');
    },
    async (baseUrl) => {
      const root = mkdtempSync(join(tmpdir(), 'ambient-ddev-host-'));
      mkdirSync(join(root, '.ddev'), { recursive: true });
      mkdirSync(join(root, 'web'), { recursive: true });
      writeFileSync(join(root, '.ddev', 'config.yaml'), 'name: ambient-fixture\ntype: drupal11\ndocroot: web\n');
      const fakeBin = join(root, 'fake-bin');
      mkdirSync(fakeBin);
      const fakeDdev = join(fakeBin, 'ddev');
      writeFileSync(fakeDdev, `#!/usr/bin/env node
if (process.argv[2] === 'describe' && process.argv[3] === '-j') {
  process.stdout.write(JSON.stringify({ raw: { primary_url: process.env.FAKE_DDEV_URL } }));
  process.exit(0);
}
process.exit(1);
`);
      chmodSync(fakeDdev, 0o755);
      const packetDir = join(root, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        cwd: root,
        environment: {
          ...process.env,
          PATH: `${fakeBin}:${process.env.PATH}`,
          DDEV_PRIMARY_URL: 'https://stale-other-project.ddev.site',
          DDEV_PROJECT: 'ambient-fixture',
          DDEV_SITENAME: 'ambient-fixture',
          FAKE_DDEV_URL: baseUrl
        },
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.target.resolutionSource, 'ddev-describe');
      assert.equal(new URL(report.target.resolvedBaseUrl).origin, baseUrl);
      assert.equal(report.liveTargetValid, true, report.errors.join('\n'));
    }
  );
});

test('intrinsic route state ignores target origin and volatile form tokens while raw evidence remains bound', async () => {
  const capture = async (tokenSeed, campaign = 'meaningful-campaign-identifier-123456789', fragment = 'featured-speaker') => {
    let origin = '';
    let requestNumber = 0;
    return withHttpServer(
      (request, response) => {
        if (new URL(request.url, 'http://fixture.invalid').pathname === '/hero.jpg') {
          response.writeHead(200, { 'content-type': 'image/jpeg' });
          response.end('stable-hero-bytes');
          return;
        }
        requestNumber += 1;
        const token = `${tokenSeed}-${requestNumber}-${'x'.repeat(32)}`;
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(`<!doctype html><html><head>
          <title>Target site</title>
          <link rel="canonical" href="${origin}/">
        </head><body>
          <h1>Target home</h1>
          <a href="${origin}/people?page=2">People</a>
          <a href="${origin}/people?campaign=${campaign}#${fragment}">Campaign</a>
          <a href="${origin}/account?form_token=${token}">Account</a>
          <img src="${origin}/hero.jpg?v=${token}" alt="Hero">
          <form action="${origin}/search" method="post">
            <input type="hidden" name="form_build_id" value="${token}">
            <input type="search" name="keys">
          </form>
        </body></html>`);
      },
      async (baseUrl) => {
        origin = baseUrl;
        const temp = mkdtempSync(join(tmpdir(), 'intrinsic-route-state-'));
        const packetDir = join(temp, 'review-packet');
        copyTemplatePacket(packetDir);
        writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
        const report = await verifyLive({
          packetDir,
          targetUrl: baseUrl,
          cwd: repoRoot,
          environment: {},
          drupalRuntime: injectedDrupalRuntime(baseUrl)
        });
        return {
          bodySha256: report.routeChecks[0].bodySha256,
          intrinsicSemantics: report.routeChecks[0].intrinsicSemantics,
          siteStateFingerprint: report.buildState.fingerprint,
          targetIdentityFingerprint: report.buildState.componentFingerprints.targetIdentity,
          routeStateFingerprint: report.buildState.componentFingerprints.routeManifest,
          targetFingerprint: report.target.targetFingerprint
        };
      }
    );
  };

  const first = await capture('first');
  const second = await capture('second');
  assert.notEqual(first.bodySha256, second.bodySha256);
  assert.notEqual(first.targetFingerprint, second.targetFingerprint);
  assert.equal(first.targetIdentityFingerprint, second.targetIdentityFingerprint);
  assert.equal(first.routeStateFingerprint, second.routeStateFingerprint);
  assert.equal(first.siteStateFingerprint, second.siteStateFingerprint);
  assert.equal(first.intrinsicSemantics.fingerprint, second.intrinsicSemantics.fingerprint);
  assert.deepEqual(first.intrinsicSemantics, second.intrinsicSemantics);

  const changedLongQuery = await capture('third', 'meaningful-campaign-identifier-987654321');
  assert.notEqual(first.intrinsicSemantics.linkTargetsSha256, changedLongQuery.intrinsicSemantics.linkTargetsSha256);
  assert.notEqual(first.routeStateFingerprint, changedLongQuery.routeStateFingerprint);

  const changedFragment = await capture('fourth', 'meaningful-campaign-identifier-123456789', 'all-speakers');
  assert.notEqual(first.intrinsicSemantics.linkTargetsSha256, changedFragment.intrinsicSemantics.linkTargetsSha256);
});

test('critical same-origin rendered asset bytes are bounded, validated, and state-bound', async () => {
  let stylesheet = 'body{color:#111}';
  let stylesheetRequests = 0;
  await withHttpServer(
    (request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      if (pathname === '/site.css') {
        stylesheetRequests += 1;
        response.writeHead(200, { 'content-type': 'text/css; charset=utf-8' });
        response.end(stylesheet);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head>
        <title>Target site</title>
        <link rel="stylesheet" href="/site.css?v=stable-url">
        <script src="https://provider.example/external.js"></script>
      </head><body><h1>Target home</h1></body></html>`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'critical-route-assets-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      const inspect = () => verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      const first = await inspect();
      assert.equal(first.liveTargetValid, true, first.errors.join('\n'));
      assert.equal(first.routeChecks[0].criticalAssets.manifest.length, 1);
      assert.equal(first.routeChecks[0].criticalAssets.manifest[0].contentType, 'text/css');
      assert.equal(first.routeChecks[0].criticalAssets.manifest[0].path, 'local:/site.css?v=%7Basset-cache-buster%7D');
      assert.match(first.routeChecks[0].criticalAssets.manifest[0].sha256, /^sha256:[a-f0-9]{64}$/);
      assert.equal(first.buildState.routeManifest[0].criticalAssetManifest.length, 1);
      assert.deepEqual(first.criticalAssetInspection, {
        distinctRequestCount: 1,
        totalBytes: Buffer.byteLength(stylesheet),
        limits: {
          requestCount: 160,
          perAssetBytes: 20 * 1024 * 1024,
          totalBytes: 100 * 1024 * 1024,
          concurrency: 12,
          wallClockMs: 90_000
        },
        sharesLiveHttpBudget: true
      });
      assert.equal(first.liveHttpBudget.tasksByKind['critical-asset'], 1);

      stylesheet = 'body{color:#222}';
      const second = await inspect();
      assert.equal(second.liveTargetValid, true, second.errors.join('\n'));
      assert.notEqual(
        first.routeChecks[0].criticalAssets.manifest[0].sha256,
        second.routeChecks[0].criticalAssets.manifest[0].sha256
      );
      assert.notEqual(
        first.buildState.componentFingerprints.routeManifest,
        second.buildState.componentFingerprints.routeManifest
      );
    }
  );
  assert.equal(stylesheetRequests, 2, 'the shared asset cache should fetch one stylesheet once per verification run');
});

test('critical asset inspection shares global concurrency and wall-clock bounds', async () => {
  let active = 0;
  let maximumActive = 0;
  await withHttpServer(
    (request, response) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      setTimeout(() => {
        response.writeHead(200, { connection: 'close', 'content-type': 'text/css' });
        response.end(`/* ${request.url} */`);
        active -= 1;
      }, 200);
    },
    async (baseUrl) => {
      const html = `<!doctype html><html><head>${Array.from(
        { length: 6 },
        (_, index) => `<link rel="stylesheet" href="/slow-${index}.css">`
      ).join('')}</head><body></body></html>`;
      const liveHttpContext = createLiveHttpContext({
        concurrency: 2,
        deadlineMs: 50,
        maxRequests: 160,
        maxTasks: 160
      });
      const context = createCriticalAssetContext({ liveHttpContext });
      const started = Date.now();
      const result = await inspectCriticalAssets(html, `${baseUrl}/`, context);
      const elapsed = Date.now() - started;

      assert.ok(elapsed < 500, `critical assets exceeded aggregate deadline: ${elapsed}ms`);
      assert.ok(maximumActive <= 2, `critical asset concurrency reached ${maximumActive}`);
      assert.equal(result.manifest.length, 0);
      assert.match(result.errors.join('\n'), /total wall-clock deadline/i);
      assert.equal(liveHttpContext.metrics().deadlineExceeded, true);
    }
  );
});

test('critical asset byte reservations stop queued fetches at the aggregate limit', async () => {
  let requests = 0;
  await withHttpServer(
    (_request, response) => {
      requests += 1;
      response.writeHead(200, { 'content-type': 'text/css' });
      response.end('12345678');
    },
    async (baseUrl) => {
      const html = `<!doctype html><html><head>${Array.from(
        { length: 6 },
        (_, index) => `<link rel="stylesheet" href="/asset-${index}.css">`
      ).join('')}</head><body></body></html>`;
      const liveHttpContext = createLiveHttpContext({
        concurrency: 4,
        deadlineMs: 1_000,
        maxRequests: 10,
        maxTasks: 10
      });
      const context = createCriticalAssetContext({
        liveHttpContext,
        maxAssetBytes: 10,
        maxRequests: 10,
        maxTotalBytes: 10
      });
      const result = await inspectCriticalAssets(html, `${baseUrl}/`, context);

      assert.equal(context.totalBytes, 8);
      assert.equal(result.manifest.length, 1);
      assert.equal(requests, 2, 'assets queued beyond the remaining aggregate bytes must not be fetched');
      assert.match(result.errors.join('\n'), /response body exceeds the 2 byte limit/i);
      assert.match(result.errors.join('\n'), /bytes exceed the 10 byte total limit/i);
    }
  );
});

test('critical same-origin rendered assets fail closed on HTTP and content-type errors', async () => {
  await withHttpServer(
    (request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      if (pathname === '/broken.css') {
        response.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
        response.end('<!doctype html><title>Missing</title>');
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Target site</title><link rel="stylesheet" href="/broken.css"></head><body><h1>Target home</h1></body></html>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'critical-route-assets-invalid-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(report.liveTargetValid, false);
      assert.match(report.routeChecks[0].errors.join('\n'), /broken\.css critical asset returned HTTP 404/i);
      assert.match(report.routeChecks[0].errors.join('\n'), /content type .*text\/html.*incompatible/i);
    }
  );
});

test('declared query route variants are fetched and state-bound distinctly while fragments are ignored', async () => {
  const requestedTargets = [];
  let origin = '';
  await withHttpServer(
    (request, response) => {
      requestedTargets.push(request.url);
      const requestUrl = new URL(request.url, origin);
      const searchRoute = requestUrl.pathname === '/search';
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head>
        <title>${searchRoute ? 'Search results' : 'Target site'}</title>
        <link rel="canonical" href="${origin}${searchRoute ? '/search' : request.url}">
        <meta name="description" content="${searchRoute ? 'Filtered search results.' : 'Fixture homepage description.'}">
      </head><body><h1>${searchRoute ? 'Search results' : 'Target home'}</h1></body></html>`);
    },
    async (baseUrl) => {
      origin = baseUrl;
      const temp = mkdtempSync(join(tmpdir(), 'query-route-state-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const addQueryRoute = (primaryTarget, recordTarget) => {
        routeMatrix.primaryRoutes.push({
          sourcePath: recordTarget,
          targetPath: primaryTarget,
          sourceIntent: 'Filtered search results',
          targetIntent: 'Filtered search results',
          matchesBrowserRenderedSource: true,
          accepted: true,
          notes: ''
        });
        routeMatrix.routes.push({
          sourcePath: recordTarget,
          targetPath: recordTarget,
          targetStatus: 200,
          targetFinalPath: recordTarget,
          targetTitle: 'Search results',
          targetH1: 'Search results',
          expectedRedirect: false,
          accepted: true,
          notes: ''
        });
      };
      addQueryRoute('/search?type=speaker&year=2026#ignored-fragment', '/search?type=speaker&year=2026');
      addQueryRoute('/search?year=2026&type=speaker', '/search?year=2026&type=speaker');
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
      mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
        const homepageChecks = [...browser.publicRouteChecks];
        for (const query of ['/search?type=speaker&year=2026', '/search?year=2026&type=speaker']) {
          for (const homepage of homepageChecks) {
            const check = structuredClone(homepage);
            check.routeRole = 'search';
            check.sourceUrl = `${routeMatrix.sourceBaseUrl}${query}`;
            check.sourceFinalUrl = `${routeMatrix.sourceBaseUrl}${query}`;
            check.targetUrl = `${baseUrl}${query}`;
            check.targetFinalUrl = `${baseUrl}${query}`;
            check.renderedSignals.sourceTitle = 'Search results';
            check.renderedSignals.targetTitle = 'Search results';
            check.renderedSignals.sourceH1 = 'Search results';
            check.renderedSignals.targetH1 = 'Search results';
            check.renderedSeoSignals.targetCanonicalUrl = `${baseUrl}/search`;
            check.renderedSeoSignals.targetMetaDescription = 'Filtered search results.';
            check.renderedSeoSignals.metaDescriptionStatus = 'present';
            check.renderedSeoSignals.accepted = true;
            browser.publicRouteChecks.push(check);
          }
        }
      });

      const inspect = () => verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      const first = await inspect();
      assert.equal(first.liveTargetValid, true, first.errors.join('\n'));
      assert.equal(
        first.routeChecks.filter((route) => route.targetPath.startsWith('/search'))
          .every((route) => route.actualMetadata.canonicalUrl === `${baseUrl}/search`),
        true
      );
      assert.equal(requestedTargets.includes('/search?type=speaker&year=2026'), true);
      assert.equal(requestedTargets.includes('/search?year=2026&type=speaker'), true);
      assert.equal(requestedTargets.some((target) => target.includes('#')), false);
      const queryRouteChecks = first.routeChecks.filter((route) => route.targetPath === '/search');
      assert.equal(queryRouteChecks.length, 2);
      assert.equal(
        queryRouteChecks.every((route) => /^\/search\?query-sha256=[a-f0-9]{64}$/.test(route.requestTarget)),
        true
      );
      assert.equal(new Set(queryRouteChecks.map((route) => route.requestTarget)).size, 2);
      const queryRouteStates = first.buildState.routeManifest.filter((route) => route.path.startsWith('/search'));
      assert.equal(queryRouteStates.length, 2);
      assert.equal(
        queryRouteStates.every((route) => /^\/search\?query-sha256=[a-f0-9]{64}$/.test(route.path)),
        true
      );
      assert.equal(new Set(queryRouteStates.map((route) => route.path)).size, 2);

      routeMatrix.primaryRoutes[2].targetPath = '/search?type=workshop&year=2026';
      routeMatrix.primaryRoutes[2].sourcePath = '/search?type=workshop&year=2026';
      routeMatrix.routes[2].targetPath = '/search?type=workshop&year=2026';
      routeMatrix.routes[2].sourcePath = '/search?type=workshop&year=2026';
      routeMatrix.routes[2].targetFinalPath = '/search?type=workshop&year=2026';
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
      const changedQuery = await inspect();
      assert.equal(changedQuery.liveTargetValid, true, changedQuery.errors.join('\n'));
      assert.equal(requestedTargets.includes('/search?type=workshop&year=2026'), true);
      assert.notEqual(
        first.buildState.componentFingerprints.routeManifest,
        changedQuery.buildState.componentFingerprints.routeManifest
      );
    }
  );
});

test('packet evidence recursively binds claim files while generated lifecycle/output files stay outside intrinsic state', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'packet-evidence-binding-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const browser = JSON.parse(readFileSync(join(packetDir, 'browser-evidence.json'), 'utf8'));
      const screenshot = join(packetDir, browser.publicRouteChecks[0].sourceScreenshot);
      const outPath = join(packetDir, 'evidence', 'custom-live-output.json');
      writeJson(outPath, { generation: 1 });

      const inspect = () => verifyLive({
        packetDir,
        targetUrl: baseUrl,
        outPath,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      const first = await inspect();
      const firstManifest = first.buildState.evidenceBindings.packetEvidenceManifest;
      assert.equal(firstManifest.fingerprint, first.buildState.evidenceBindings.packetFingerprint);
      assert.equal(
        firstManifest.entries.some((entry) => entry.path === relative(packetDir, screenshot).replaceAll('\\', '/')),
        true
      );
      assert.equal(firstManifest.entries.some((entry) => entry.path === 'evidence/custom-live-output.json'), false);
      assert.equal(firstManifest.entries.some((entry) => entry.path.startsWith('evidence/lifecycle/')), false);
      writeFileSync(screenshot, screenshotPng(199));
      const changedEvidence = await inspect();
      assert.notEqual(
        first.buildState.evidenceBindings.packetFingerprint,
        changedEvidence.buildState.evidenceBindings.packetFingerprint
      );
      assert.equal(first.buildState.fingerprint, changedEvidence.buildState.fingerprint);

      writeJson(outPath, { generation: 2, selfReferenceMustNotChangeFingerprint: true });
      writeJson(join(packetDir, 'evidence', 'live-verification.json'), { generated: true });
      writeJson(join(packetDir, 'evidence', 'packet-verification.json'), { generated: true });
      mkdirSync(join(packetDir, 'evidence', 'lifecycle'), { recursive: true });
      writeJson(join(packetDir, 'evidence', 'lifecycle', 'current-state.json'), { generated: true });
      const generatedOnly = await inspect();
      assert.equal(
        changedEvidence.buildState.evidenceBindings.packetFingerprint,
        generatedOnly.buildState.evidenceBindings.packetFingerprint
      );
      assert.equal(changedEvidence.buildState.fingerprint, generatedOnly.buildState.fingerprint);
    }
  );
});

test('live verification rejects a symlinked review packet before reading packet inputs', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'symlinked-live-packet-'));
  const actualPacket = join(temp, 'actual-packet');
  const linkedPacket = join(temp, 'linked-packet');
  copyTemplatePacket(actualPacket);
  symlinkSync(actualPacket, linkedPacket);

  await assert.rejects(
    verifyLive({ packetDir: linkedPacket, cwd: repoRoot, environment: {} }),
    /real directory.*symbolic link/i
  );
});

test('live route verification rejects identity mismatches and accepts a declared same-origin redirect', async () => {
  let scenario = { status: 200, h1: 'Target home', title: 'Target site' };
  await withHttpServer(
    (request, response) => {
      if (scenario.redirect && request.url === '/') {
        response.writeHead(302, { location: '/home' });
        response.end();
        return;
      }
      response.writeHead(scenario.status, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>${scenario.title}</title></head><body><h1>${scenario.h1}</h1></body></html>`);
    },
    async (baseUrl) => {
      const mismatchCases = [
        {
          name: 'status',
          response: { status: 500, h1: 'Target home', title: 'Target site' },
          expected: /returned status 500; expected 200/
        },
        {
          name: 'final-path',
          response: { status: 200, h1: 'Target home', title: 'Target site' },
          mutate: (routeMatrix) => {
            routeMatrix.homepageParity.targetFinalPath = '/expected';
            routeMatrix.routes[0].targetFinalPath = '/expected';
          },
          expected: /resolved to \/; expected \/expected/
        },
        {
          name: 'h1',
          response: { status: 200, h1: 'Wrong home', title: 'Target site' },
          expected: /H1 was "Wrong home"; expected "Target home"/
        },
        {
          name: 'title',
          response: { status: 200, h1: 'Target home', title: 'Wrong site' },
          expected: /title was "Wrong site"; expected "Target site"/
        }
      ];

      for (const mismatch of mismatchCases) {
        scenario = mismatch.response;
        const temp = mkdtempSync(join(tmpdir(), `live-route-${mismatch.name}-`));
        const packetDir = join(temp, 'review-packet');
        copyTemplatePacket(packetDir);
        const routeMatrix = liveRouteMatrix(baseUrl);
        mismatch.mutate?.(routeMatrix);
        writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

        const report = await verifyLive({
          packetDir,
          targetUrl: baseUrl,
          cwd: repoRoot,
          environment: {},
          drupalRuntime: injectedDrupalRuntime(baseUrl)
        });

        assert.equal(report.valid, false, mismatch.name);
        assert.equal(report.routeChecks[0].passed, false, mismatch.name);
        assert.match(report.errors.join('\n'), mismatch.expected, mismatch.name);
      }

      scenario = { status: 500, h1: 'Target home', title: 'Target site' };
      const serverErrorTemp = mkdtempSync(join(tmpdir(), 'live-route-declared-500-'));
      const serverErrorPacket = join(serverErrorTemp, 'review-packet');
      copyTemplatePacket(serverErrorPacket);
      const serverErrorMatrix = liveRouteMatrix(baseUrl);
      serverErrorMatrix.homepageParity.targetStatus = 500;
      serverErrorMatrix.routes[0].targetStatus = 500;
      writeJson(join(serverErrorPacket, 'route-matrix.json'), serverErrorMatrix);

      const serverErrorReport = await verifyLive({
        packetDir: serverErrorPacket,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(serverErrorReport.valid, false);
      assert.equal(serverErrorReport.liveTargetValid, false);
      assert.equal(serverErrorReport.routeChecks[0].passed, false);
      assert.match(
        serverErrorReport.errors.join('\n'),
        /primary target route.*(?:cannot accept|must not accept).*500|HTTP 500.*cannot support/i
      );

      scenario = { redirect: true, status: 200, h1: 'Target home', title: 'Target site' };
      const temp = mkdtempSync(join(tmpdir(), 'live-route-redirect-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.homepageParity.targetFinalPath = '/home';
      routeMatrix.homepageParity.targetStatus = 302;
      routeMatrix.routes[0].targetFinalPath = '/home';
      routeMatrix.routes[0].targetStatus = 302;
      routeMatrix.routes[0].expectedRedirect = true;
      routeMatrix.targetRequiredRoutes[0].targetFinalPath = '/home';
      routeMatrix.targetRequiredRoutes[0].targetStatus = 302;
      routeMatrix.targetRequiredRoutes[0].expectedPublicBehavior = 'redirect';
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.routeChecks[0].passed, true, report.routeChecks[0].errors.join('\n'));
      assert.equal(report.routeChecks[0].initialStatus, 302);
      assert.equal(new URL(report.routeChecks[0].finalUrl).pathname, '/home');
      assert.equal(report.routeChecks[0].redirects.length, 1);
    }
  );
});

test('packet evidence can qualify but an injected Drupal runtime cannot authorize completion', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-complete-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text.replace('- [x] Repeatability accepted', '- [ ] Repeatability accepted'));
      mutateText(join(packetDir, 'maintainer-review.md'), (text) =>
        text.replace(
          '- [x] I would stake my name on this as a complete local Drupal CMS rebuild.',
          '- [ ] I would stake my name on this as a complete local Drupal CMS rebuild.'
        ));
      attachFixtureReviewHandoff(packetDir, baseUrl);

      const packetOnlyReport = await validatePacket({ packetDir });
      assert.equal(packetOnlyReport.valid, true, packetOnlyReport.errors.join('\n'));
      assert.equal(
        packetOnlyReport.completionEvidence.packetSupportsCompletion,
        true,
        JSON.stringify(packetOnlyReport.completionEvidence, null, 2)
      );
      assert.equal(packetOnlyReport.completeLocalRebuildClaimAllowed, false);
      assert.deepEqual(packetOnlyReport.completionEvidence.independence, {
        independentVerification: 'self-attested',
        blindAdversarialReview: 'self-attested'
      });
      assert.equal(
        packetOnlyReport.completionEvidence.scopeDispositionAttribution,
        'builder-writable-self-attested'
      );
      assert.equal(packetOnlyReport.claimScope, 'complete-local-rebuild');
      assert.equal(packetOnlyReport.productionReadinessEvaluated, false);
      assert.equal(packetOnlyReport.launchReady, false);

      const liveReport = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: {
          baseUrl,
          confirmed: true,
          configStatusClean: true,
          configSyncDirectory: '../config/sync',
          frontPage: '/',
          mode: 'test',
          project: 'fixture',
          reason: '',
          siteUuid: testSiteUuid
        }
      });
      assert.equal(liveReport.valid, true, liveReport.errors.join('\n'));
      assert.equal(liveReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(liveReport.claimScope, 'complete-local-rebuild');
      assert.equal(liveReport.productionReadinessEvaluated, false);
      assert.equal(liveReport.launchReady, false);
      assert.equal(liveReport.drupalRuntime.authoritativeForCompletion, false);
      assert.match(
        liveReport.completionBlockedReasons.join('\n'),
        /injected.*non-authoritative|non-authoritative.*injected/i
      );
    }
  );
});

test('brief mode verifies target routes without requiring or implying a source site', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-brief-mode-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      convertQualifyingPacketToBrief(packetDir, baseUrl);

      const packetReport = await validatePacket({ packetDir });
      assert.equal(packetReport.valid, true, packetReport.errors.join('\n'));
      assert.equal(
        packetReport.completionEvidence.packetSupportsCompletion,
        true,
        JSON.stringify(packetReport.completionEvidence, null, 2)
      );

      const parityPath = join(packetDir, 'parity-report.json');
      const parityDisposition = JSON.parse(readFileSync(parityPath, 'utf8'));
      writeJson(parityPath, { ...parityDisposition, briefSha256: `sha256:${'f'.repeat(64)}` });
      attachFixtureReviewHandoff(packetDir, baseUrl);
      const staleDispositionReport = await validatePacket({ packetDir });
      assert.equal(staleDispositionReport.valid, true, staleDispositionReport.errors.join('\n'));
      assert.equal(staleDispositionReport.completionEvidence.packetSupportsCompletion, false);
      assert.match(
        staleDispositionReport.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /parity-report\.json.*not-applicable disposition bound to the preserved brief/i
      );
      writeJson(parityPath, parityDisposition);
      attachFixtureReviewHandoff(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.buildMode, 'brief');
      assert.equal(report.claimScope, 'complete-local-build-from-brief');
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.completeLocalBuildFromBriefClaimAllowed, false);
      assert.equal(report.packetVerification.completionEvidence.packetSupportsCompletion, true);
      assert.equal(report.sourceSurfaceCensus.status, 'not_applicable');
      assert.equal(report.sourceSurfaceCensus.authoritative, true);
      assert.equal(report.routeChecks[0].passed, true, report.routeChecks[0].errors.join('\n'));
      assert.doesNotMatch(report.completionBlockedReasons.join('\n'), /source route discovery|sourceBaseUrl/i);
      assert.match(report.completionBlockedReasons.join('\n'), /non-authoritative/i);
    }
  );
});

test('completed reviewer artifacts fail closed when their review handoff digest drifts', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'review-handoff-digest-drift-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.reviewHandoff.digest = `sha256:${'f'.repeat(64)}`;
  });

  const report = await validatePacket({ packetDir });
  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /independent-verification\.json must reference the exact review-handoff\.json digest/);
});

test('completed reviewer artifacts fail closed when a byte-bound handoff input changes', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'review-handoff-input-drift-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  writeFileSync(join(packetDir, 'maintainer-review.md'), '# Changed after reviewer handoff\n');

  const report = await validatePacket({ packetDir });
  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /maintainer-review\.md.*no longer matches.*(?:size|sha256)/i);
});

test('malformed reviewer projections return structured packet errors instead of throwing', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'review-handoff-malformed-projection-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'evidence', 'review-handoff-independent.json'), (projection) => {
    projection.allowedInputs = 'malformed';
  });

  const report = await validatePacket({ packetDir });
  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /review-handoff-independent\.json\.allowedInputs must be a JSON object/i);
});

test('deeply nested reviewer projection JSON fails safely without escaping packet validation', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'review-handoff-deep-projection-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  const projectionPath = join(packetDir, 'evidence', 'review-handoff-blind.json');
  const deeplyNestedJson = `${'{"nested":'.repeat(20000)}null${'}'.repeat(20000)}`;
  const projectionJson = readFileSync(projectionPath, 'utf8').replace(
    /^\{/,
    `{"unexpectedDeepValue":${deeplyNestedJson},`
  );
  writeFileSync(projectionPath, projectionJson);

  const report = await validatePacket({ packetDir });
  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /validation depth limit|cannot be canonically hashed|failed safely/i);
});

test('packet validation rejects evidence added after the reviewer handoff', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'review-handoff-added-evidence-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  writeJson(join(packetDir, 'evidence', 'post-handoff-builder-claim.json'), { claim: 'not reviewed' });

  const report = await validatePacket({ packetDir });
  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /input added after handoff.*post-handoff-builder-claim\.json/i);
});

test('browser capture states bind state-specific artifacts and structured interaction semantics', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'browser-capture-states-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const canonicalReport = await validatePacket({ packetDir: canonicalPacket });
  assert.equal(
    canonicalReport.completionEvidence.packetSupportsCompletion,
    true,
    canonicalReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  function addOpenMenuState(browser, packetDir, options = {}) {
    const toggleSelector = '[data-test="mobile-menu-toggle"]';
    const controlledRegionSelector = '[data-test="mobile-menu-region"]';
    const mobile = browser.publicRouteChecks.find((check) => check.viewport.name === 'mobile');
    mobile.captureState.menuState = {
      toggleVisible: true,
      toggleSelector,
      controlledRegionSelector,
      requested: 'closed',
      observed: 'closed',
      observedExpanded: false,
      controlledRegionVisible: false
    };
    const open = structuredClone(mobile);
    const openToggleSelector = options.selectorMismatch ? '[data-test="other-toggle"]' : toggleSelector;
    open.captureState = {
      ...open.captureState,
      id: 'mobile-menu-open',
      fixtureRevision: options.fixtureRevision ?? mobile.captureState.fixtureRevision,
      interactionSteps: [{
        action: options.stepAction ?? 'click',
        target: openToggleSelector,
        value: options.stepValue ?? '',
        expectedState: 'The controlled navigation is visible and the toggle is expanded.'
      }],
      menuState: {
        toggleVisible: true,
        toggleSelector: openToggleSelector,
        controlledRegionSelector,
        requested: 'open',
        observed: 'open',
        observedExpanded: true,
        controlledRegionVisible: true
      }
    };

    if (!options.reuseArtifacts) {
      const blindEvidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
      const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
      const sourcePath = join(blindEvidenceDir, 'source-mobile-menu-open.png');
      const targetPath = join(blindEvidenceDir, 'target-mobile-menu-open.png');
      const axePath = join(browserEvidenceDir, 'axe-home-mobile-menu-open.json');
      writeFileSync(sourcePath, screenshotPng(70, 390, 844));
      writeFileSync(targetPath, screenshotPng(71, 390, 844));
      const axe = JSON.parse(readFileSync(join(browserEvidenceDir, 'axe-home-mobile.json'), 'utf8'));
      axe.captureStateObservation = 'mobile-menu-open';
      writeJson(axePath, axe);
      open.sourceScreenshot = 'evidence/blind-adversarial-review/source-mobile-menu-open.png';
      open.targetScreenshot = options.missingTarget
        ? 'evidence/blind-adversarial-review/missing-mobile-menu-open.png'
        : 'evidence/blind-adversarial-review/target-mobile-menu-open.png';
      open.accessibilityCheck.report = options.missingAxe
        ? 'evidence/browser/missing-mobile-menu-open.json'
        : 'evidence/browser/axe-home-mobile-menu-open.json';
      open.captureState.evidenceBindings = {
        sourceScreenshotSha256: sha256File(sourcePath),
        targetScreenshotSha256: options.missingTarget ? `sha256:${'0'.repeat(64)}` : sha256File(targetPath),
        accessibilityReportSha256: options.missingAxe ? `sha256:${'0'.repeat(64)}` : sha256File(axePath)
      };
    }
    open.notes = 'Captured after opening the mobile menu.';
    browser.publicRouteChecks.push(open);
  }

  const legacyPacket = join(temp, 'legacy-v1-default-only');
  cpSync(canonicalPacket, legacyPacket, { recursive: true });
  mutateJson(join(legacyPacket, 'browser-evidence.json'), (browser) => {
    browser.schemaVersion = 'public-kit.browser-evidence.1';
    for (const check of browser.publicRouteChecks) delete check.captureState;
  });
  attachFixtureReviewHandoff(legacyPacket, 'https://target.example');
  const legacyReport = await validatePacket({ packetDir: legacyPacket });
  assert.equal(
    legacyReport.completionEvidence.packetSupportsCompletion,
    true,
    legacyReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const legacyScaledPacket = join(temp, 'legacy-v1-device-pixel-screenshots');
  cpSync(legacyPacket, legacyScaledPacket, { recursive: true });
  const legacyBrowser = JSON.parse(readFileSync(join(legacyScaledPacket, 'browser-evidence.json'), 'utf8'));
  const legacyDesktop = legacyBrowser.publicRouteChecks.find((check) => check.viewport.name === 'desktop');
  writeFileSync(join(legacyScaledPacket, legacyDesktop.sourceScreenshot), screenshotPng(74, 2560, 1600));
  writeFileSync(join(legacyScaledPacket, legacyDesktop.targetScreenshot), screenshotPng(75, 2560, 1600));
  attachFixtureReviewHandoff(legacyScaledPacket, 'https://target.example');
  const legacyScaledReport = await validatePacket({ packetDir: legacyScaledPacket });
  assert.equal(
    legacyScaledReport.completionEvidence.packetSupportsCompletion,
    true,
    legacyScaledReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const cases = [
    {
      name: 'unsupported-browser-evidence-schema',
      expected: /must use schemaVersion public-kit\.browser-evidence\.1 or public-kit\.browser-evidence\.2/i,
      mutate(browser) {
        browser.schemaVersion = 'public-kit.browser-evidence.999';
      }
    },
    {
      name: 'missing-capture-state',
      expected: /publicRouteChecks\[0\]\.captureState is required/i,
      mutate(browser) {
        delete browser.publicRouteChecks[0].captureState;
      }
    },
    {
      name: 'missing-self-attested-authority',
      expected: /authority must be self_attested_capture_evidence/i,
      mutate(browser) {
        delete browser.publicRouteChecks[0].captureState.authority;
      }
    },
    {
      name: 'accessibility-report-is-directory',
      expected: /report must reference packet-local raw axe-core JSON/i,
      mutate(browser, packetDir) {
        mkdirSync(join(packetDir, 'evidence', 'browser', 'report-directory'));
        browser.publicRouteChecks[0].accessibilityCheck.report = 'evidence/browser/report-directory';
        browser.publicRouteChecks[0].captureState.evidenceBindings.accessibilityReportSha256 = '';
      }
    },
    {
      name: 'unstable-fixture-revision',
      expected: /fixtureRevision must be a non-empty stable revision/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.fixtureRevision = '';
      }
    },
    {
      name: 'normalized-tuple-duplicate',
      expected: /unique normalized target request, viewport name, and captureState\.id tuple; duplicate \/ mobile default/i,
      mutate(browser) {
        const duplicate = structuredClone(browser.publicRouteChecks.find((check) => check.viewport.name === 'mobile'));
        duplicate.targetUrl = 'https://target.example/?';
        duplicate.targetFinalUrl = 'https://target.example/?';
        browser.publicRouteChecks.push(duplicate);
      }
    },
    {
      name: 'missing-default-mobile-state',
      expected: /needs a default captureState for primary route \/ at mobile/i,
      mutate(browser) {
        browser.publicRouteChecks.find((check) => check.viewport.name === 'mobile').captureState.id = 'alternate';
      }
    },
    {
      name: 'too-many-interaction-steps',
      expected: /interactionSteps must be an array with at most 12 steps/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.interactionSteps = Array.from({ length: 13 }, () => ({
          action: 'click',
          target: '[data-test="control"]',
          value: '',
          expectedState: 'The control is active.'
        }));
      }
    },
    {
      name: 'mutating-default-state',
      expected: /must be empty or contain one non-mutating wait_for step for the default state/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.interactionSteps = [{
          action: 'click',
          target: '[data-test="control"]',
          value: '',
          expectedState: 'The control is active.'
        }];
      }
    },
    {
      name: 'count-assertion-mismatch',
      expected: /must use a unique selector and a passing bounded exact-count assertion/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.contentCountAssertions = [{
          selector: '.card',
          expectedCount: 4,
          observedCount: 3,
          status: 'pass'
        }];
      }
    },
    {
      name: 'contradictory-count-assertions',
      expected: /must use a unique selector/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.contentCountAssertions = [
          { selector: '.card', expectedCount: 4, observedCount: 4, status: 'pass' },
          { selector: '.card', expectedCount: 5, observedCount: 5, status: 'pass' }
        ];
      }
    },
    {
      name: 'page-wide-dynamic-mask',
      expected: /unique element-specific/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.dynamicMasks = [{
          selector: 'body',
          reason: 'Invalid page-wide mask.',
          observedRect: { x: 0, y: 0, width: 100, height: 100 }
        }];
      }
    },
    {
      name: 'universal-dynamic-mask',
      expected: /unique element-specific/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.dynamicMasks = [{
          selector: '*',
          reason: 'Invalid universal mask.',
          observedRect: { x: 0, y: 0, width: 100, height: 100 }
        }];
      }
    },
    {
      name: 'functional-pseudo-dynamic-mask',
      expected: /unique element-specific/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.dynamicMasks = [{
          selector: ':is(body)',
          reason: 'Invalid functional selector mask.',
          observedRect: { x: 0, y: 0, width: 100, height: 100 }
        }];
      }
    },
    {
      name: 'common-header-class-mask',
      expected: /common page\/global-chrome tokens/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.dynamicMasks = [{
          selector: '.header',
          reason: 'Invalid global-header mask.',
          observedRect: { x: 0, y: 0, width: 100, height: 100 }
        }];
      }
    },
    {
      name: 'common-header-data-value-mask',
      expected: /common page\/global-chrome tokens/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.dynamicMasks = [{
          selector: '[data-region=header]',
          reason: 'Invalid global-header data region mask.',
          observedRect: { x: 0, y: 0, width: 100, height: 100 }
        }];
      }
    },
    {
      name: 'oversized-mask-union',
      expected: /observed rectangle union must cover no more than 0\.25/i,
      mutate(browser) {
        browser.publicRouteChecks[0].captureState.dynamicMasks = [{
          selector: '[data-dynamic="weather"]',
          reason: 'Weather changes between captures.',
          observedRect: { x: 0, y: 0, width: 1280, height: 300 }
        }];
      }
    },
    {
      name: 'structured-visible-toggle-without-open-state',
      expected: /needs an explicit mobile-menu-open captureState.*declares a visible toggle/i,
      mutate(browser) {
        const mobile = browser.publicRouteChecks.find((check) => check.viewport.name === 'mobile');
        mobile.captureState.menuState = {
          toggleVisible: true,
          toggleSelector: '[data-test="mobile-menu-toggle"]',
          controlledRegionSelector: '[data-test="mobile-menu-region"]',
          requested: 'closed',
          observed: 'closed',
          observedExpanded: false,
          controlledRegionVisible: false
        };
      }
    },
    {
      name: 'reused-state-artifacts',
      expected: /must use a distinct packet-local target screenshot path and bytes/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir, { reuseArtifacts: true });
      }
    },
    {
      name: 'two-interacted-states-reuse-artifacts',
      expected: /must use a distinct packet-local target screenshot path and bytes from every other state/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir);
        const open = browser.publicRouteChecks.find((check) => check.captureState.id === 'mobile-menu-open');
        const alternate = structuredClone(open);
        alternate.captureState.id = 'alternate-menu-open';
        browser.publicRouteChecks.push(alternate);
      }
    },
    {
      name: 'mismatched-state-fixture',
      expected: /must use the default state's fixtureRevision/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir, { fixtureRevision: 'fixture-home-v2' });
      }
    },
    {
      name: 'interacted-state-wrong-final-route',
      expected: /must keep the default state's targetFinalUrl/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir);
        const open = browser.publicRouteChecks.find((check) => check.captureState.id === 'mobile-menu-open');
        open.targetFinalUrl = 'https://target.example/unrelated-state-page';
        const axePath = join(packetDir, open.accessibilityCheck.report);
        const axe = JSON.parse(readFileSync(axePath, 'utf8'));
        axe.url = open.targetFinalUrl;
        writeJson(axePath, axe);
        open.captureState.evidenceBindings.accessibilityReportSha256 = sha256File(axePath);
      }
    },
    {
      name: 'wait-only-menu-activation',
      expected: /clicks or presses Enter\/Space.*declared toggle selector/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir, { stepAction: 'wait_for' });
      }
    },
    {
      name: 'empty-key-menu-press',
      expected: /interactionSteps\[0\] must name a supported action, bounded target\/value/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir, { stepAction: 'press' });
      }
    },
    {
      name: 'mismatched-menu-toggle-selector',
      expected: /observes the same controlled region open/i,
      mutate(browser, packetDir) {
        addOpenMenuState(browser, packetDir, { selectorMismatch: true });
      }
    }
  ];

  for (const fixture of cases) {
    const packetDir = join(temp, fixture.name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => fixture.mutate(browser, packetDir));
    attachFixtureReviewHandoff(packetDir, 'https://target.example');
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, fixture.name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), fixture.expected, fixture.name);
  }

  const proseOnlyPacket = join(temp, 'prose-only-toggle-claim');
  cpSync(canonicalPacket, proseOnlyPacket, { recursive: true });
  mutateJson(join(proseOnlyPacket, 'browser-evidence.json'), (browser) => {
    browser.publicRouteChecks.find((check) => check.viewport.name === 'mobile').notes =
      'The mobile layout has a visible menu toggle.';
  });
  attachFixtureReviewHandoff(proseOnlyPacket, 'https://target.example');
  const proseOnlyReport = await validatePacket({ packetDir: proseOnlyPacket });
  assert.equal(
    proseOnlyReport.completionEvidence.packetSupportsCompletion,
    true,
    proseOnlyReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const boundedMaskPacket = join(temp, 'bounded-element-specific-mask');
  cpSync(canonicalPacket, boundedMaskPacket, { recursive: true });
  mutateJson(join(boundedMaskPacket, 'browser-evidence.json'), (browser) => {
    browser.publicRouteChecks[0].captureState.dynamicMasks = [{
      selector: '.weather-widget[data-dynamic=weather]',
      reason: 'The weather observation changes between captures.',
      observedRect: { x: 980, y: 620, width: 200, height: 100 }
    }];
  });
  attachFixtureReviewHandoff(boundedMaskPacket, 'https://target.example');
  const boundedMaskReport = await validatePacket({ packetDir: boundedMaskPacket });
  assert.equal(
    boundedMaskReport.completionEvidence.packetSupportsCompletion,
    true,
    boundedMaskReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const openMenuPacket = join(temp, 'structured-open-menu-state');
  cpSync(canonicalPacket, openMenuPacket, { recursive: true });
  mutateJson(
    join(openMenuPacket, 'browser-evidence.json'),
    (browser) => addOpenMenuState(browser, openMenuPacket)
  );
  attachFixtureReviewHandoff(openMenuPacket, 'https://target.example');
  const openMenuReport = await validatePacket({ packetDir: openMenuPacket });
  assert.equal(
    openMenuReport.completionEvidence.packetSupportsCompletion,
    true,
    openMenuReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const keyboardOpenMenuPacket = join(temp, 'structured-keyboard-open-menu-state');
  cpSync(canonicalPacket, keyboardOpenMenuPacket, { recursive: true });
  mutateJson(
    join(keyboardOpenMenuPacket, 'browser-evidence.json'),
    (browser) => addOpenMenuState(browser, keyboardOpenMenuPacket, { stepAction: 'press', stepValue: 'Enter' })
  );
  attachFixtureReviewHandoff(keyboardOpenMenuPacket, 'https://target.example');
  const keyboardOpenMenuReport = await validatePacket({ packetDir: keyboardOpenMenuPacket });
  assert.equal(
    keyboardOpenMenuReport.completionEvidence.packetSupportsCompletion,
    true,
    keyboardOpenMenuReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const briefMissingArtifactsRoot = join(temp, 'brief-interacted-state-missing-artifacts');
  const briefMissingArtifactsPacket = join(briefMissingArtifactsRoot, 'review-packet');
  mkdirSync(briefMissingArtifactsRoot, { recursive: true });
  cpSync(canonicalPacket, briefMissingArtifactsPacket, { recursive: true });
  convertQualifyingPacketToBrief(briefMissingArtifactsPacket, 'https://target.example');
  mutateJson(join(briefMissingArtifactsPacket, 'browser-evidence.json'), (browser) => {
    addOpenMenuState(browser, briefMissingArtifactsPacket, { missingTarget: true, missingAxe: true });
  });
  attachFixtureReviewHandoff(briefMissingArtifactsPacket, 'https://target.example');
  const briefMissingArtifactsReport = await validatePacket({ packetDir: briefMissingArtifactsPacket });
  const briefArtifactReasons = briefMissingArtifactsReport.completionEvidence.packetCompletionBlockedReasons.join('\n');
  assert.equal(briefMissingArtifactsReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(briefArtifactReasons, /targetScreenshot must reference a credible packet-local image/i);
  assert.match(briefArtifactReasons, /accessibilityCheck\.report must reference packet-local raw axe-core JSON/i);
  assert.doesNotMatch(briefArtifactReasons, /brief\.path|original brief/i);

  const briefFailedStateRoot = join(temp, 'brief-interacted-state-failed');
  const briefFailedStatePacket = join(briefFailedStateRoot, 'review-packet');
  mkdirSync(briefFailedStateRoot, { recursive: true });
  cpSync(canonicalPacket, briefFailedStatePacket, { recursive: true });
  convertQualifyingPacketToBrief(briefFailedStatePacket, 'https://target.example');
  mutateJson(join(briefFailedStatePacket, 'browser-evidence.json'), (browser) => {
    const desktop = browser.publicRouteChecks.find((check) => check.viewport.name === 'desktop');
    const failed = structuredClone(desktop);
    const blindEvidenceDir = join(briefFailedStatePacket, 'evidence', 'blind-adversarial-review');
    const browserEvidenceDir = join(briefFailedStatePacket, 'evidence', 'browser');
    const sourcePath = join(blindEvidenceDir, 'source-desktop-consent-accepted.png');
    const targetPath = join(blindEvidenceDir, 'target-desktop-consent-accepted.png');
    const axePath = join(browserEvidenceDir, 'axe-home-desktop-consent-accepted.json');
    writeFileSync(sourcePath, screenshotPng(72, 1280, 800));
    writeFileSync(targetPath, screenshotPng(73, 1280, 800));
    const axe = JSON.parse(readFileSync(join(browserEvidenceDir, 'axe-home-desktop.json'), 'utf8'));
    axe.captureStateObservation = 'consent-accepted';
    writeJson(axePath, axe);
    failed.captureState = {
      ...failed.captureState,
      id: 'consent-accepted',
      interactionSteps: [{
        action: 'click',
        target: '[data-test="accept-consent"]',
        value: '',
        expectedState: 'Consent is accepted.'
      }],
      consentState: { requested: 'accepted', observed: 'accepted' },
      evidenceBindings: {
        sourceScreenshotSha256: sha256File(sourcePath),
        targetScreenshotSha256: sha256File(targetPath),
        accessibilityReportSha256: sha256File(axePath)
      }
    };
    failed.sourceScreenshot = 'evidence/blind-adversarial-review/source-desktop-consent-accepted.png';
    failed.targetScreenshot = 'evidence/blind-adversarial-review/target-desktop-consent-accepted.png';
    failed.accessibilityCheck.report = 'evidence/browser/axe-home-desktop-consent-accepted.json';
    failed.accepted = false;
    failed.blockers = ['Consent interaction failed.'];
    failed.visualComparison.status = 'fail';
    browser.publicRouteChecks.push(failed);
  });
  attachFixtureReviewHandoff(briefFailedStatePacket, 'https://target.example');
  const briefFailedStateReport = await validatePacket({ packetDir: briefFailedStatePacket });
  const briefFailedStateReasons = briefFailedStateReport.completionEvidence.packetCompletionBlockedReasons.join('\n');
  assert.equal(briefFailedStateReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(briefFailedStateReasons, /capture state must be accepted and passing.*no blockers/i);
  assert.doesNotMatch(briefFailedStateReasons, /brief\.path|original brief/i);

  const privateQueryPacket = join(temp, 'private-query-duplicate');
  cpSync(canonicalPacket, privateQueryPacket, { recursive: true });
  mutateJson(join(privateQueryPacket, 'browser-evidence.json'), (browser) => {
    const first = structuredClone(browser.publicRouteChecks.find((check) => check.viewport.name === 'mobile'));
    first.targetUrl = 'https://target.example/search?preview_token=super-secret-value';
    first.targetFinalUrl = first.targetUrl;
    const second = structuredClone(first);
    browser.publicRouteChecks.push(first, second);
  });
  attachFixtureReviewHandoff(privateQueryPacket, 'https://target.example');
  const privateQueryReport = await validatePacket({ packetDir: privateQueryPacket });
  const privateQueryReasons = privateQueryReport.completionEvidence.packetCompletionBlockedReasons.join('\n');
  assert.equal(privateQueryReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(privateQueryReasons, /\/search\?query-sha256=[a-f0-9]{64}/i);
  assert.doesNotMatch(privateQueryReasons, /super-secret-value|preview_token/i);
});

test('live verifier rejects fetched SEO metadata that is missing or differs from packet claims', async () => {
  let scenario = {};
  await withHttpServer(
    (_request, response) => {
      const canonical = scenario.canonical === null
        ? ''
        : `<link rel="canonical" href="${scenario.canonical}">`;
      const description = scenario.description === null
        ? ''
        : `<meta name="description" content="${scenario.description}">`;
      const socialImage = scenario.socialImage === null
        ? ''
        : `<meta property="og:image" content="${scenario.socialImage}">`;
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>Target site</title>${canonical}${description}${socialImage}</head><body><h1>Target home</h1></body></html>`);
    },
    async (baseUrl) => {
      const expectedSeo = {
        canonical: `${baseUrl}/`,
        description: 'Fixture homepage description.',
        socialImage: `${baseUrl}/social.jpg`
      };
      const cases = [
        {
          name: 'missing-canonical',
          values: { ...expectedSeo, canonical: null },
          expected: /canonical.*missing|missing.*canonical/i
        },
        {
          name: 'mismatched-canonical',
          values: { ...expectedSeo, canonical: `${baseUrl}/wrong` },
          expected: /canonical.*(?:does not match|mismatch)|(?:does not match|mismatch).*canonical/i
        },
        {
          name: 'credential-bearing-canonical',
          values: { ...expectedSeo, canonical: baseUrl.replace('http://', 'http://user:secret@') },
          expected: /canonical.*missing|missing.*canonical/i
        },
        {
          name: 'missing-description',
          values: { ...expectedSeo, description: null },
          expected: /description.*missing|missing.*description/i
        },
        {
          name: 'mismatched-description',
          values: { ...expectedSeo, description: 'Wrong description.' },
          expected: /description.*(?:does not match|mismatch)|(?:does not match|mismatch).*description/i
        },
        {
          name: 'missing-social-image',
          values: { ...expectedSeo, socialImage: null },
          expected: /(?:og:image|social.image).*missing|missing.*(?:og:image|social.image)/i
        },
        {
          name: 'mismatched-social-image',
          values: { ...expectedSeo, socialImage: `${baseUrl}/wrong.jpg` },
          expected: /(?:og:image|social.image).*(?:does not match|mismatch)|(?:does not match|mismatch).*(?:og:image|social.image)/i
        }
      ];

      const temp = mkdtempSync(join(tmpdir(), 'live-seo-regressions-'));
      const canonicalPacket = join(temp, 'canonical');
      copyTemplatePacket(canonicalPacket);
      writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(canonicalPacket, baseUrl);
      mutateJson(join(canonicalPacket, 'browser-evidence.json'), (browser) => {
        for (const check of browser.publicRouteChecks) {
          check.renderedSeoSignals.targetCanonicalUrl = expectedSeo.canonical;
          check.renderedSeoSignals.targetMetaDescription = expectedSeo.description;
          check.renderedSeoSignals.metaDescriptionStatus = 'present';
          check.renderedSeoSignals.metaDescriptionApplicabilityReviewed = true;
          check.renderedSeoSignals.metaDescriptionNotApplicableRationale = '';
          check.renderedSeoSignals.targetOpenGraphImage = expectedSeo.socialImage;
          check.renderedSeoSignals.openGraphImageStatus = 'present';
          check.renderedSeoSignals.openGraphImageApplicabilityReviewed = true;
          check.renderedSeoSignals.openGraphImageNotApplicableRationale = '';
          check.renderedSeoSignals.accepted = true;
        }
      });

      for (const seoCase of cases) {
        scenario = seoCase.values;
        const packetDir = join(temp, seoCase.name);
        cpSync(canonicalPacket, packetDir, { recursive: true });

        const report = await verifyLive({
          packetDir,
          targetUrl: baseUrl,
          cwd: repoRoot,
          environment: {},
          drupalRuntime: {
            baseUrl,
            confirmed: true,
            configStatusClean: true,
            configSyncDirectory: '../config/sync',
            frontPage: '/',
            mode: 'test-injected',
            project: 'fixture',
            reason: '',
            siteUuid: testSiteUuid
          }
        });

        assert.equal(report.valid, false, seoCase.name);
        assert.equal(report.liveTargetValid, false, seoCase.name);
        assert.equal(report.completeLocalRebuildClaimAllowed, false, seoCase.name);
        assert.match(report.errors.join('\n'), seoCase.expected, seoCase.name);
      }
    }
  );
});

test('CLI discovers the DDEV Drupal runtime and requires clean status plus HEAD-matching tracked config YAML', async () => {
  let liveBaseUrl = '';
  let verifierAxeViolation = false;
  let sourceDiscoveryPaths = [];
  await withHttpServer(
    (request, response) => {
      if (request.url === '/sitemap.xml' && sourceDiscoveryPaths.length > 0) {
        const origin = `http://${request.headers.host}`;
        response.writeHead(200, { 'content-type': 'application/xml; charset=utf-8' });
        response.end(`<?xml version="1.0"?><urlset>${sourceDiscoveryPaths
          .map((path) => `<url><loc>${origin}${path}</loc></url>`)
          .join('')}</urlset>`);
        return;
      }
      if (request.url === '/robots.txt' || request.url === '/sitemap.xml') {
        response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Source site</title></head><body><h1>Source home</h1></body></html>');
    },
    async (sourceBaseUrl) => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html lang="en"><head>
        <title>Target site</title>
        <link rel="canonical" href="${liveBaseUrl}/">
        <meta name="description" content="Fixture homepage description.">
        <meta name="viewport" content="width=device-width">
        ${verifierAxeViolation ? '<style>.verifier-axe-fixture{color:#777;background:#888}</style>' : ''}
      </head><body><main><h1>Target home</h1><p class="verifier-axe-fixture">Verifier-owned accessibility fixture.</p></main></body></html>`);
    },
    async (baseUrl) => {
      liveBaseUrl = baseUrl;
      const targetRoot = mkdtempSync(join(tmpdir(), 'live-fake-ddev-'));
      mkdirSync(join(targetRoot, '.ddev'), { recursive: true });
      mkdirSync(join(targetRoot, 'web'), { recursive: true });
      mkdirSync(join(targetRoot, 'config', 'sync'), { recursive: true });
      mkdirSync(join(targetRoot, 'config', 'split', 'local'), { recursive: true });
      writeFileSync(join(targetRoot, '.ddev', 'config.yaml'), 'name: fake-runtime\ntype: drupal11\ndocroot: web\n');
      writeFileSync(join(targetRoot, 'config', 'sync', 'system.site.yml'), `uuid: ${testSiteUuid}\n`);
      writeFileSync(join(targetRoot, 'config', 'sync', 'system.theme.yml'), 'default: fixture_theme\nadmin: claro\n');
      writeFileSync(join(targetRoot, 'config', 'split', 'local', 'system.logging.yml'), 'error_level: verbose\n');

      const fakeBin = join(targetRoot, 'fake-bin');
      mkdirSync(fakeBin);
      const fakeDdev = join(fakeBin, 'ddev');
      writeFileSync(fakeDdev, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'describe' && args[1] === '-j') {
  process.stdout.write(JSON.stringify({ raw: { primary_url: process.env.FAKE_DDEV_URL } }) + '\\n');
  process.exit(0);
}
if (args[0] !== 'drush') {
  process.stderr.write('Unexpected fake DDEV command: ' + args.join(' ') + '\\n');
  process.exit(1);
}
if (args[1] === 'php:eval') {
  if (args[2].includes('public-kit.drupal-runtime-facts.2')) {
    process.stdout.write(JSON.stringify({
      schemaVersion: 'public-kit.drupal-runtime-facts.2',
      fingerprint: 'sha256:${'d'.repeat(64)}',
      coreVersion: '11.2.0',
      phpVersion: '8.3.0',
      databaseDriver: 'mysql',
      activeConfigEntryCount: 800,
      effectiveActiveConfigSha256: 'sha256:${'8'.repeat(64)}',
      systemSchemaEntryCount: 12,
      systemSchemaSha256: 'sha256:${'e'.repeat(64)}',
      effectiveSettingsEntryCount: 8,
      effectiveSettingsHmacSha256: 'sha256:${'f'.repeat(64)}',
      databaseUpdateStatusConfirmed: true,
      pendingDatabaseUpdateCount: 0,
      databaseUpdatesPending: false,
      configSplitDirectories: ['../config/split/local']
    }) + '\\n');
    process.exit(0);
  }
  if (args[2].includes('public-kit.consent-runtime.1')) {
    process.stdout.write(JSON.stringify({
      schemaVersion: 'public-kit.consent-runtime.1',
      confirmed: true,
      detected: false,
      managerModules: [],
      configNames: [],
      applications: []
    }) + '\\n');
    process.exit(0);
  }
  if (args[2].includes('public-kit.drupal-live-surface.1')) {
    process.stdout.write(JSON.stringify({
      schemaVersion: 'public-kit.drupal-live-surface.1',
      fingerprint: 'sha256:${'c'.repeat(64)}',
      confirmed: true,
      bounded: true,
      limit: 5000,
      truncated: false,
      itemCount: 1,
      countsByKind: { bundle: 1 },
      items: [
        {
          key: 'bundle:node:page',
          kind: 'bundle',
          entityType: 'node',
          bundle: 'page',
          publicEditorialRoot: true,
          publicSurface: true,
          publishedCount: 1
        }
      ],
      publicEditorialRoots: { node: ['page'] },
      excludedEntityTypes: { user: 'broad user rows are never swept' },
      errors: [],
      policy: { metadataOnly: true, rawContentRowsEmitted: false, privateEntityRowsQueried: false }
    }) + '\\n');
    process.exit(0);
  }
  if (args[2].includes('public-kit.live-next-cycle-census.1')) {
    process.stdout.write(JSON.stringify({
      schemaVersion: 'public-kit.live-next-cycle-census.1',
      metadataOnly: true,
      privateContentRead: false,
      candidateCount: 0,
      fields: [],
      taxonomyDimensions: [],
      workflows: []
    }) + '\\n');
    process.exit(0);
  }
  if (args[2].includes('public-kit.live-editor-surface-census.1')) {
    process.stdout.write(JSON.stringify({
      schemaVersion: 'public-kit.live-editor-surface-census.1',
      readOnly: true,
      rawFieldValuesEmitted: false,
      entityInspectionLimitPerField: 5000,
      fieldCount: 1,
      roleCount: 1,
      fields: [{
        key: 'node.page.body',
        entityType: 'node',
        bundle: 'page',
        machineName: 'body',
        fieldDefinitionExists: true,
        configEntityExists: true,
        definitionSource: 'configurable',
        fieldType: 'text_long',
        required: true,
        defaultFormDisplayId: 'node.page.default',
        defaultFormDisplayExists: true,
        widgetVisible: true,
        widget: 'text_textarea',
        formattedText: true,
        existingFormatIds: [],
        formatInspectionTruncated: false,
        formatInspectionError: '',
        editorRolePermissionChecks: [{
          declared: 'content editor',
          resolved: true,
          ambiguous: false,
          roleId: 'content_editor',
          roleLabel: 'Content editor',
          administrator: false,
          requiredPermissions: [],
          missingPermissions: []
        }]
      }],
      roles: [{
        declared: 'content editor',
        resolved: true,
        ambiguous: false,
        roleId: 'content_editor',
        roleLabel: 'Content editor',
        administrator: false
      }],
      errors: [],
      fingerprint: 'sha256:${'7'.repeat(64)}'
    }) + '\\n');
    process.exit(0);
  }
  process.stdout.write(JSON.stringify({
    schemaVersion: 'public-kit.drupal-entity-inventory.5',
    fingerprint: 'sha256:${'a'.repeat(64)}',
    entityTypeCount: 1,
    closureCounts: { entityCount: 1, entityTypeCount: 1 },
    excludedEntityTypes: { user: 'private authentication and login state' },
    missingLiveRoots: process.env.FAKE_DDEV_MISSING_ROOT === '1' ? ['node.page'] : [],
    missingManagedFileCount: 0,
    policy: { rawPerItemRowsEmitted: false },
    publicAuthorUserDigest: {
      count: 1,
      translationCount: 1,
      fingerprint: 'sha256:${'9'.repeat(64)}'
    },
    types: {
      node: {
        count: 1,
        translationCount: 1,
        revisionCount: 1,
        revisionTranslationCount: 1,
        missingManagedFileCount: 0,
        fingerprint: 'sha256:${'b'.repeat(64)}',
      }
    }
  }) + '\\n');
  process.exit(0);
}
const command = args.slice(1).join(' ');
if (command.startsWith('config:get') && command.includes('--field')) {
  process.stderr.write('The "--field" option does not exist.\\n');
  process.exit(1);
}
if (process.env.FAKE_DDEV_UUID_READBACK_FAILS === '1' && command === 'config:get system.site uuid --format=string') {
  process.stderr.write('Command "config:get" is not defined.\\n');
  process.exit(1);
}
const outputs = new Map([
  ['status --field=bootstrap', 'Successful'],
  ['status --field=root', 'web'],
  ['config:get system.site uuid --format=string', '${testSiteUuid}'],
  ['config:get system.site page.front --format=string', '/'],
  ['status --field=config-sync', '../config/sync'],
  ['config:status --format=json', process.env.FAKE_DDEV_CONFIG_DIRTY === '1' ? '{"changed":true}' : '[]']
]);
if (!outputs.has(command)) {
  process.stderr.write('Unexpected fake Drush command: ' + command + '\\n');
  process.exit(1);
}
process.stdout.write(outputs.get(command) + '\\n');
`);
      chmodSync(fakeDdev, 0o755);

      const packetDir = join(targetRoot, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.sourceBaseUrl = sourceBaseUrl;
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
      addQualifyingReviewEvidence(packetDir, baseUrl);
      mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text.replace('- [x] Repeatability accepted', '- [ ] Repeatability accepted'));
      mutateText(join(packetDir, 'maintainer-review.md'), (text) =>
        text.replace(
          '- [x] I would stake my name on this as a complete local Drupal CMS rebuild.',
          '- [ ] I would stake my name on this as a complete local Drupal CMS rebuild.'
        ));
      attachFixtureReviewHandoff(packetDir, baseUrl);

      const verifierArgs = [join(repoRoot, 'bin', 'verify.mjs'), '--packet', 'review-packet'];
      const cleanEnvironment = {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH}`,
        FAKE_DDEV_URL: baseUrl
      };

      const untrackedResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(untrackedResult.status, 2, untrackedResult.stderr);
      const untrackedReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(untrackedReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(untrackedReport.drupalRuntime.configSyncTracked, false);
      assert.equal(untrackedReport.drupalRuntime.trackedConfigYamlPresent, false);
      assert.match(untrackedReport.completionBlockedReasons.join('\n'), /Git-tracked.*YAML/i);

      execFileSync('git', ['init', '-q'], { cwd: targetRoot });
      execFileSync('git', [
        'add',
        'config/sync/system.site.yml',
        'config/sync/system.theme.yml',
        'config/split/local/system.logging.yml'
      ], { cwd: targetRoot });
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.drupal.trackedConfigYamlFiles.reverse();
        readback.drupal.trackedConfigYamlFiles.push('config/split/local/system.logging.yml');
      });
      attachFixtureReviewHandoff(packetDir, baseUrl);

      const missingRootResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: { ...cleanEnvironment, FAKE_DDEV_MISSING_ROOT: '1' }
      });
      assert.equal(missingRootResult.status, 2, missingRootResult.stderr);
      const missingRootReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(missingRootReport.drupalRuntime.entityInventory.confirmed, false);
      assert.match(missingRootReport.completionBlockedReasons.join('\n'), /live-derived roots were missing.*node\.page/i);

      const stagedOnlyResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(stagedOnlyResult.status, 2, stagedOnlyResult.stderr);
      const stagedOnlyReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(stagedOnlyReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(stagedOnlyReport.drupalRuntime.configSyncMatchesHead, false);
      assert.equal(stagedOnlyReport.drupalRuntime.configSyncTracked, true);
      assert.match(
        stagedOnlyReport.completionBlockedReasons.join('\n'),
        /config-sync YAML does not match HEAD/i
      );

      execFileSync(
        'git',
        [
          '-c', 'user.name=Fixture Committer',
          '-c', 'user.email=fixture@example.gov',
          '-c', 'commit.gpgsign=false',
          'commit', '-q', '--no-verify', '-m', 'Export site config'
        ],
        { cwd: targetRoot }
      );

      const handoffPrepResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(handoffPrepResult.status, 2, handoffPrepResult.stderr);
      const handoffPrepReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      const handoffPath = join(packetDir, 'evidence', 'review-handoff.json');
      const handoff = JSON.parse(readFileSync(handoffPath, 'utf8'));
      handoff.binding = {
        ...handoff.binding,
        buildMode: handoffPrepReport.buildMode,
        configSyncDirectory: handoffPrepReport.buildState.targetIdentity.configSyncDirectory,
        frontPage: handoffPrepReport.buildState.targetIdentity.frontPage,
        siteStateFingerprint: handoffPrepReport.buildState.fingerprint,
        siteUuid: handoffPrepReport.buildState.targetIdentity.siteUuid,
        targetIdentityFingerprint: handoffPrepReport.buildState.componentFingerprints.targetIdentity,
        targetOrigin: new URL(handoffPrepReport.target.resolvedBaseUrl).origin
      };
      const stateBoundHandoff = sealReviewHandoff(handoff);
      writeJson(handoffPath, stateBoundHandoff);
      for (const projectionFile of ['review-handoff-independent.json', 'review-handoff-blind.json']) {
        mutateJson(join(packetDir, 'evidence', projectionFile), (projection) => {
          projection.handoff = reviewHandoffReference(stateBoundHandoff.handoffDigest);
        });
      }
      for (const reviewerFile of ['independent-verification.json', 'blind-adversarial-review.json']) {
        mutateJson(join(packetDir, reviewerFile), (review) => {
          review.reviewHandoff = reviewHandoffReference(stateBoundHandoff.handoffDigest);
        });
      }

      const cleanResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(cleanResult.status, 0, cleanResult.stderr);
      assert.match(cleanResult.stdout, /complete local rebuild machine claim authorized/);
      assert.match(cleanResult.stdout, /independence evidence: self-attested/);
      assert.match(cleanResult.stdout, /recorded local-rebuild operator\/maintainer status: pending, self-attested record only/);
      const cleanReport = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(cleanReport.target.resolutionSource, 'ddev-describe');
      assert.equal(cleanReport.drupalRuntime.mode, 'ddev-host');
      assert.equal(cleanReport.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(cleanReport.drupalRuntime.configStatusClean, true);
      assert.equal(cleanReport.drupalRuntime.configSyncMatchesHead, true);
      assert.equal(cleanReport.drupalRuntime.configSyncTracked, true);
      assert.deepEqual(cleanReport.drupalRuntime.configSplitDirectories, ['config/split/local']);
      assert.equal(cleanReport.drupalRuntime.trackedConfigYamlPresent, true);
      assert.equal(cleanReport.completeLocalRebuildClaimAllowed, true);
      assert.equal(cleanReport.verdict, 'complete-local-rebuild');
      assert.equal(cleanReport.agentContinuation.requiredAction, 'handoff');
      assert.equal(cleanReport.agentContinuation.status, 'complete');
      assert.equal(cleanReport.agentContinuation.shouldContinue, false);
      assert.equal(cleanReport.agentContinuation.agentMayPause, false);
      assert.equal(cleanReport.agentContinuation.agentMayStop, true);
      assert.equal(cleanReport.agentContinuation.stopConditionMet, true);
      assert.equal(cleanReport.agentContinuation.humanReviewRequiredBeforeContinuing, false);
      assert.deepEqual(cleanReport.agentContinuation.blockedReasons, []);
      assert.deepEqual(cleanReport.agentContinuation.blockers, []);
      assert.equal(cleanReport.recordedHumanGateStatus.affectsMachineCompletion, false);
      assert.equal(cleanReport.recordedHumanGateStatus.localRebuildStatus, 'pending');
      assert.equal(cleanReport.verifierOwnedAccessibility.passed, true);
      assert.equal(cleanReport.verifierOwnedAccessibility.sourceVersion, '4.10.3');
      assert.equal(cleanReport.verifierOwnedAccessibility.routeViewportCount, 2);
      assert.equal(cleanReport.lifecycle.initialBaseline.status, 'passed');
      assert.equal(cleanReport.lifecycle.relation, 'matches-initial-baseline');
      assert.equal(cleanReport.lifecycle.currentStateVerified, true);
      assert.equal(cleanReport.lifecycle.initialBaseline.siteStateFingerprint, cleanReport.buildState.fingerprint);
      const baselinePath = join(packetDir, 'evidence', 'lifecycle', 'initial-baseline.json');
      const originalBaseline = readFileSync(baselinePath, 'utf8');
      const baseline = JSON.parse(originalBaseline);
      assert.equal(baseline.schemaVersion, 'public-kit.initial-baseline.1');
      assert.equal(baseline.status, 'passed');
      assert.equal(baseline.siteStateFingerprint, cleanReport.buildState.fingerprint);

      sourceDiscoveryPaths = ['/archive/1', '/archive/2'];
      const sourceProgress = [];
      const originalPath = process.env.PATH;
      const originalFakeDdevUrl = process.env.FAKE_DDEV_URL;
      process.env.PATH = cleanEnvironment.PATH;
      process.env.FAKE_DDEV_URL = cleanEnvironment.FAKE_DDEV_URL;
      let cappedSourceReport;
      try {
        cappedSourceReport = await verifyLive({
          packetDir,
          cwd: targetRoot,
          environment: cleanEnvironment,
          sourceSurfaceLimits: { maxRoutes: 1 },
          onSourceProgress: (event) => sourceProgress.push(event)
        });
      } finally {
        process.env.PATH = originalPath;
        if (originalFakeDdevUrl === undefined) {
          delete process.env.FAKE_DDEV_URL;
        } else {
          process.env.FAKE_DDEV_URL = originalFakeDdevUrl;
        }
        sourceDiscoveryPaths = [];
      }
      assert.equal(cappedSourceReport.valid, true, cappedSourceReport.errors.join('\n'));
      assert.equal(cappedSourceReport.liveTargetValid, true);
      assert.equal(cappedSourceReport.sourceSurfaceSupportsCompletion, false);
      assert.equal(cappedSourceReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(cappedSourceReport.verdict, 'machine-incomplete');
      assert.equal(cappedSourceReport.sourceSurfaceCensus.budget.maxRoutes, 1);
      assert.equal(cappedSourceReport.sourceSurfaceCensus.budget.droppedRouteCount, 2);
      assert.ok(sourceProgress.some((event) => event.phase === 'primary' && event.status === 'completed'));
      assert.equal(sourceProgress.at(-1)?.status, 'blocked');
      assert.equal(sourceProgress.at(-1)?.droppedRoutes, 2);
      assert.ok(cappedSourceReport.completionBlockers.some((blocker) => blocker.code === 'source.census-budget'));
      assert.equal(cappedSourceReport.completionBlockers.some((blocker) => blocker.code === 'target.validation'), false);
      assert.equal(cappedSourceReport.agentContinuation.status, 'externally_blocked');
      assert.match(
        cappedSourceReport.agentContinuation.blockers[0].nextAction,
        /--source-max-routes 2048/
      );

      // The packet still contains its authored passing axe reports. A fresh
      // verifier-owned browser violation must independently block completion.
      verifierAxeViolation = true;
      const axeViolationResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(axeViolationResult.status, 2, axeViolationResult.stderr);
      const axeViolationReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(axeViolationReport.packetVerification.completionEvidence.packetSupportsCompletion, true);
      assert.equal(axeViolationReport.verifierOwnedAccessibility.passed, false);
      assert.equal(axeViolationReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(axeViolationReport.sourceSurfaceCensus.status, 'not_run');
      assert.match(
        axeViolationReport.sourceSurfaceCensus.warnings.join('\n'),
        /deferred until every higher-priority.*accessibility/i
      );
      assert.match(
        axeViolationReport.completionBlockedReasons.join('\n'),
        /unresolved WCAG 2\.2 A\/AA.*color-contrast/i
      );
      verifierAxeViolation = false;

      const dirtyResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: { ...cleanEnvironment, FAKE_DDEV_CONFIG_DIRTY: '1' }
      });
      assert.equal(dirtyResult.status, 2, dirtyResult.stderr);
      const dirtyReport = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(dirtyReport.valid, true, dirtyReport.errors.join('\n'));
      assert.equal(dirtyReport.drupalRuntime.configStatusClean, false);
      assert.equal(dirtyReport.completeLocalRebuildClaimAllowed, false);
      assert.match(dirtyReport.completionBlockedReasons.join('\n'), /config status is not clean/i);
      assert.equal(dirtyReport.lifecycle.initialBaseline.status, 'passed');
      assert.equal(dirtyReport.buildState.fingerprint, cleanReport.buildState.fingerprint);
      assert.equal(dirtyReport.lifecycle.relation, 'matches-initial-baseline');
      assert.equal(dirtyReport.lifecycle.currentStateVerified, false);
      assert.equal(readFileSync(baselinePath, 'utf8'), originalBaseline);

      const failedReadbackResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: { ...cleanEnvironment, FAKE_DDEV_UUID_READBACK_FAILS: '1' }
      });
      assert.equal(failedReadbackResult.status, 2, failedReadbackResult.stderr);
      const failedReadbackReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(failedReadbackReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(failedReadbackReport.drupalRuntime.identityReadbackFailed, true);
      assert.match(
        failedReadbackReport.drupalRuntime.drushCommandFailures.join('\n'),
        /drush config:get system\.site uuid --format=string.*exit 1.*Command "config:get" is not defined\./
      );
      assert.match(
        failedReadbackReport.drupalRuntime.reason,
        /Drush runtime inspection command failed.*config:get system\.site uuid --format=string/
      );
      const failedReadbackBlockedReasons = failedReadbackReport.completionBlockedReasons.join('\n');
      assert.match(
        failedReadbackBlockedReasons,
        /Drush runtime inspection command failed.*config:get system\.site uuid --format=string.*Command "config:get" is not defined\./
      );
      assert.doesNotMatch(failedReadbackBlockedReasons, /runtime identity does not match/i);

      writeFileSync(
        join(targetRoot, 'config', 'sync', 'system.theme.yml'),
        'default: changed_theme\nadmin: claro\n'
      );
      const modifiedResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(modifiedResult.status, 2, modifiedResult.stderr);
      const modifiedReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(modifiedReport.drupalRuntime.configSyncTracked, true);
      assert.equal(modifiedReport.drupalRuntime.configSyncMatchesHead, false);
      assert.match(modifiedReport.completionBlockedReasons.join('\n'), /config-sync YAML does not match HEAD/i);

      writeFileSync(
        join(targetRoot, 'config', 'sync', 'system.theme.yml'),
        'default: fixture_theme\nadmin: claro\n'
      );
      writeFileSync(join(targetRoot, 'config', 'sync', 'untracked.settings.yml'), 'enabled: true\n');
      const untrackedYamlResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: cleanEnvironment
      });
      assert.equal(untrackedYamlResult.status, 2, untrackedYamlResult.stderr);
      const untrackedYamlReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(untrackedYamlReport.drupalRuntime.configSyncTracked, true);
      assert.equal(untrackedYamlReport.drupalRuntime.configSyncMatchesHead, false);
      assert.match(untrackedYamlReport.completionBlockedReasons.join('\n'), /config-sync YAML does not match HEAD/i);

      execFileSync('git', ['add', 'config/sync/untracked.settings.yml'], { cwd: targetRoot });
      const stagedNewYamlResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: cleanEnvironment
      });
      assert.equal(stagedNewYamlResult.status, 2, stagedNewYamlResult.stderr);
      const stagedNewYamlReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(stagedNewYamlReport.drupalRuntime.configSyncTracked, true);
      assert.equal(stagedNewYamlReport.drupalRuntime.configSyncMatchesHead, false);
      assert.match(stagedNewYamlReport.completionBlockedReasons.join('\n'), /config-sync YAML does not match HEAD/i);

      writeFileSync(join(targetRoot, 'config', 'sync', 'system.performance.yml'), 'cache:\n  page:\n    max_age: 900\n');
      execFileSync('git', ['add', 'config/sync/system.performance.yml'], { cwd: targetRoot });
      const extraTrackedConfigResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: cleanEnvironment
      });
      assert.equal(extraTrackedConfigResult.status, 2, extraTrackedConfigResult.stderr);
      const extraTrackedConfigReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(extraTrackedConfigReport.drupalRuntime.configStatusClean, true);
      assert.equal(extraTrackedConfigReport.drupalRuntime.trackedConfigReadbackMatches, false);
      assert.equal(extraTrackedConfigReport.completeLocalRebuildClaimAllowed, false);
      assert.match(extraTrackedConfigReport.completionBlockedReasons.join('\n'), /Git-tracked config evidence/i);
      assert.equal(extraTrackedConfigReport.lifecycle.initialBaseline.status, 'passed');
      assert.equal(extraTrackedConfigReport.lifecycle.relation, 'changed-since-latest-anchor');
      assert.equal(extraTrackedConfigReport.lifecycle.currentStateVerified, false);
      assert.equal(readFileSync(baselinePath, 'utf8'), originalBaseline);
    }
  );
    }
  );
});

test('the verifier never emits the Drush 13-removed config:get --field form', () => {
  const verifierSource = readFileSync(join(repoRoot, 'bin', 'verify.mjs'), 'utf8');
  const argvLiterals = [...verifierSource.matchAll(/(?:runDrush(?:Result)?|readDrush)\([^[)]*\[([^\]]*)\]/g)]
    .map(([, args]) => [...args.matchAll(/'([^']*)'/g)].map(([, value]) => value));
  assert.ok(argvLiterals.length >= 6, 'expected to find the runDrush argv literals in bin/verify.mjs');
  for (const argv of argvLiterals) {
    if (argv[0] === 'config:get') {
      assert.ok(
        !argv.some((argument) => argument.startsWith('--field')),
        `config:get must not use --field (removed in Drush 13): drush ${argv.join(' ')}`
      );
    }
  }
});

test('completion fails closed when structured gate evidence or applicability dispositions are missing', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'structured-gate-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');
  mkdirSync(join(canonicalPacket, 'evidence'), { recursive: true });
  writeFileSync(
    join(canonicalPacket, 'evidence', 'source-link-exception.txt'),
    'Approved retained source archive dependency.\n'
  );
  writeFileSync(
    join(canonicalPacket, 'evidence', 'same-origin-link-exception.txt'),
    'Approved dynamic same-origin endpoint.\n'
  );
  writeFileSync(
    join(canonicalPacket, 'evidence', 'external-redirect.txt'),
    'Approved external provider redirect.\n'
  );
  mutateJson(join(canonicalPacket, 'route-matrix.json'), (value) => {
    value.sourceOriginLinkExceptions = [{
      referrer: '/',
      target: 'https://source.example/archive',
      rationale: 'The source archive remains the named public system of record.',
      accepter: 'Content owner',
      evidence: 'evidence/source-link-exception.txt',
      accepted: true
    }];
    value.sameOriginLinkExceptions = [{
      referrer: '/',
      target: '/dynamic-endpoint?fixture=private',
      disposition: 'dynamic_endpoint',
      rationale: 'The endpoint is generated dynamically and intentionally outside the static route inventory.',
      accepter: 'Application owner',
      evidence: 'evidence/same-origin-link-exception.txt',
      accepted: true
    }];
    value.expectedExternalLinkRedirects = [{
      referrer: '/',
      start: '/provider-start?fixture=private',
      finalMatch: 'origin',
      final: 'https://provider.example',
      rationale: 'The provider owns the external workflow.',
      accepter: 'Integration owner',
      evidence: 'evidence/external-redirect.txt',
      accepted: true
    }];
  });

  const cases = [
    {
      name: 'collection-scope',
      file: 'pattern-map.json',
      expected: /explicitly review collection applicability/i,
      mutate: (value) => { value.structuredContentModel.collectionScope.reviewed = false; }
    },
    {
      name: 'functional-scope',
      file: 'parity-report.json',
      expected: /parity-report\.json/i,
      mutate: (value) => { value.functionalScope.reviewed = false; }
    },
    {
      name: 'route-drift',
      file: 'route-matrix.json',
      expected: /classify and accept every discovered source route/i,
      mutate: (value) => { value.browserFirstRouteExpansion.candidateRoutesFromBrowserRenderedLinks = ['/legacy']; }
    },
    {
      name: 'legacy-rendered-link-route-drift',
      file: 'route-matrix.json',
      expected: /classify and accept every discovered source route/i,
      mutate: (value) => {
        delete value.browserFirstRouteExpansion.candidateRoutesFromBrowserRenderedLinks;
        value.browserFirstRouteExpansion.candidateRoutesFromRenderedLinks = ['/legacy'];
      }
    },
    {
      name: 'conflicting-rendered-link-route-declarations',
      file: 'route-matrix.json',
      expected: /candidateRoutesFromRenderedLinks and candidateRoutesFromBrowserRenderedLinks declarations must describe the same discovered routes/i,
      mutate: (value) => {
        value.browserFirstRouteExpansion.candidateRoutesFromRenderedLinks = ['/legacy'];
        value.browserFirstRouteExpansion.candidateRoutesFromBrowserRenderedLinks = ['/current'];
      }
    },
    {
      name: 'route-role-coverage',
      file: 'route-matrix.json',
      expected: /representative of every discovered routeRole; missing detail/i,
      mutate: (value) => {
        value.routes.push({
          sourcePath: '/article/example',
          targetPath: '/article/example',
          routeRole: 'detail',
          targetStatus: 200,
          targetFinalPath: '/article/example',
          targetTitle: 'Example article',
          targetH1: 'Example article',
          expectedRedirect: false,
          accepted: true,
          notes: 'Representative detail route is not included in primaryRoutes.'
        });
      }
    },
    {
      name: 'source-origin-exception-accepter',
      file: 'route-matrix.json',
      expected: /sourceOriginLinkExceptions.*named accepter/i,
      mutate: (value) => { value.sourceOriginLinkExceptions[0].accepter = ''; }
    },
    {
      name: 'source-origin-exception-target',
      file: 'route-matrix.json',
      expected: /sourceOriginLinkExceptions.*source-origin target/i,
      mutate: (value) => { value.sourceOriginLinkExceptions[0].target = 'https://unrelated.example/archive'; }
    },
    {
      name: 'source-origin-exception-evidence',
      file: 'route-matrix.json',
      expected: /sourceOriginLinkExceptions.*packet-local evidence/i,
      mutate: (value) => { value.sourceOriginLinkExceptions[0].evidence = 'evidence/missing.txt'; }
    },
    {
      name: 'same-origin-exception-disposition',
      file: 'route-matrix.json',
      expected: /sameOriginLinkExceptions.*allowed disposition/i,
      mutate: (value) => { value.sameOriginLinkExceptions[0].disposition = 'blanket_allow'; }
    },
    {
      name: 'same-origin-exception-evidence',
      file: 'route-matrix.json',
      expected: /sameOriginLinkExceptions.*packet-local evidence/i,
      mutate: (value) => { value.sameOriginLinkExceptions[0].evidence = 'evidence/missing.txt'; }
    },
    {
      name: 'external-redirect-final-match',
      file: 'route-matrix.json',
      expected: /expectedExternalLinkRedirects.*external final origin or exact URL/i,
      mutate: (value) => { value.expectedExternalLinkRedirects[0].finalMatch = 'anywhere'; }
    },
    {
      name: 'external-redirect-evidence',
      file: 'route-matrix.json',
      expected: /expectedExternalLinkRedirects.*packet-local evidence/i,
      mutate: (value) => { value.expectedExternalLinkRedirects[0].evidence = 'evidence/missing.txt'; }
    },
    {
      name: 'target-required-route',
      file: 'route-matrix.json',
      expected: /accepted target-required route records/i,
      mutate: (value) => { value.targetRequiredRoutes[0].accepted = false; }
    },
    {
      name: 'item-reconciliation',
      file: 'route-matrix.json',
      expected: /reconcile every in-scope repeated-item count/i,
      mutate: (value) => {
        value.perRouteItemReconciliation = [{
          sourcePath: '/',
          targetPath: '/',
          itemType: 'card',
          sourceCount: 2,
          targetRenderedCount: 1,
          targetDrupalEntityCount: 1,
          mismatchDisposition: 'implementation_gap',
          accepted: false,
          notes: 'One card is missing.'
        }];
      }
    },
    {
      name: 'first-fold',
      file: 'route-matrix.json',
      expected: /first-fold brand parity.*mobile/i,
      mutate: (value) => { value.firstFoldBrandAssetParity = value.firstFoldBrandAssetParity.filter((entry) => entry.viewport !== 'mobile'); }
    },
    {
      name: 'rendered-seo',
      file: 'browser-evidence.json',
      expected: /rendered canonical, description, and social-image dispositions/i,
      mutate: (value) => {
        for (const check of value.publicRouteChecks) {
          check.renderedSeoSignals.accepted = false;
        }
      }
    },
    {
      name: 'off-road-scan',
      file: 'independent-verification.json',
      expected: /raw embed and markup scan must pass/i,
      mutate: (value) => { value.rawEmbedAndMarkupScan.status = 'blocked'; }
    },
    {
      name: 'tracked-config-yaml',
      file: 'drupal-readback.json',
      expected: /drupal-readback\.json must substantively identify/i,
      mutate: (value) => { value.drupal.trackedConfigYamlFiles = []; }
    },
    {
      name: 'content-parity',
      file: 'parity-report.json',
      expected: /parity-report\.json must pass/i,
      mutate: (value) => { value.contentChecks = []; }
    },
    {
      name: 'packet-freshness',
      file: 'independent-verification.json',
      expected: /packet freshness checks must pass pattern-map\.json/i,
      mutate: (value) => {
        value.packetFreshnessChecks = value.packetFreshnessChecks.filter((check) => check.artifact !== 'pattern-map.json');
      }
    }
  ];

  for (const { name, file, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, file), mutate);
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('conditionally applicable hard gates fail closed when their verifier evidence is missing or blocked', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'conditional-gate-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'collections',
      expected: [
        /passing, evidence-backed per-route item counts/i,
        /passing collection ownership and editor-add-row checks/i,
        /passing editor-add-row checks/i
      ],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.structuredContentModel.collectionScope = {
            reviewed: true,
            applies: true,
            reason: 'The source homepage contains a repeatable card collection.'
          };
          value.structuredContentModel.collectionOwnershipLedger = [{
            sourceRoute: '/',
            collectionPattern: 'grid',
            sourceObject: 'card',
            sourceItemCount: 2,
            drupalEntityType: 'node',
            contentTypeOrBundle: 'card',
            requiredFields: ['title'],
            collectionOwner: 'view',
            viewDisplayOrConfig: 'views.view.cards',
            detailRouteOwner: 'entity_view_display',
            editorAddRowEvidence: 'editor-task.json',
            exceptionRationale: '',
            accepted: true,
            notes: 'Cards are Drupal-owned.'
          }];
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.perRouteItemCounts = [{
            sourceRoute: '/',
            targetRoute: '/',
            expectedSourceItemCount: 2,
            targetRenderedItemCount: 1,
            targetDrupalEntityCount: 1,
            missingItems: ['Second card'],
            extraItems: [],
            status: 'blocked',
            evidence: ''
          }];
          value.collectionOwnershipChecks = [{
            sourceRoute: '/',
            drupalOwner: 'body_markup_or_blob',
            viewOrCollectionConfig: '',
            editorAddRowEvidence: '',
            status: 'blocked',
            evidence: ''
          }];
          value.editorAddRowChecks = [{
            editorUser: '',
            publicOutputChanged: false,
            listingOrDetailUpdatedWithoutCode: false,
            status: 'blocked',
            evidence: ''
          }];
        });
      }
    },
    {
      name: 'embeds',
      expected: [/passing rendered embed\/media checks/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'source-audit.json'), (value) => {
          value.mediaSignals = [{ route: '/', type: 'video', evidence: 'Source video observed.' }];
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.renderedEmbedChecks = [{ route: '', status: 'blocked', evidence: '' }];
        });
      }
    },
    {
      name: 'canvas',
      expected: [/Canvas component-model checks must pass/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.buildTypeDeclaration.type = 'structured_drupal_native_canvas';
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.canvasComponentModelChecks = [];
        });
      }
    },
    {
      name: 'functional-parity',
      expected: [/parity-report\.json must pass with populated route checks/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'source-audit.json'), (value) => {
          value.functionalSignals = [{ route: '/', behavior: 'interactive search', evidence: 'Source behavior observed.' }];
        });
        mutateJson(join(packetDir, 'parity-report.json'), (value) => {
          value.functionalScope = {
            reviewed: true,
            applies: true,
            reason: 'The source has interactive behavior.'
          };
          value.functionalChecks = [];
        });
      }
    },
    {
      name: 'accepted-route-drift',
      expected: [/pass every source-route drift disposition check with evidence/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
          value.browserFirstRouteExpansion.candidateRoutesFromBrowserRenderedLinks = ['/legacy'];
          value.sourceRouteDriftClassification = [{
            sourcePath: '/legacy',
            sourceStatus: 200,
            classification: 'legacy',
            targetDisposition: 'intentionally_drop',
            targetPath: '',
            ownerDecisionEvidence: 'The source route is obsolete.',
            accepted: true,
            notes: 'Accepted legacy-route disposition.'
          }];
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.routeDriftDispositionChecks = [];
        });
      }
    },
    {
      name: 'direct-database-cleanup',
      expected: [/direct-database cleanup checks must be local-only, recorded, passing/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.directDatabaseCleanupChecks = [{
            operation: 'direct_sql',
            localCleanRebuildOnly: false,
            recordedInOffRoadInventory: false,
            productionSafeAlternative: '',
            status: 'blocked',
            evidence: ''
          }];
        });
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);
    attachFixtureReviewHandoff(packetDir, 'https://target.example');

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    const blockedReasons = report.completionEvidence.packetCompletionBlockedReasons.join('\n');
    for (const expectedReason of expected) {
      assert.match(blockedReasons, expectedReason, name);
    }
  }
});

test('self-authored count and exclusion dispositions cannot hide collection shortfalls', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'collection-count-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'independent-pass-with-count-shortfall',
      expected: /per-route item counts.*(?:match|reconcile)|count shortfall/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.structuredContentModel.collectionScope = {
            reviewed: true,
            applies: true,
            reason: 'The source has a ten-item collection.'
          };
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.perRouteItemCounts = [{
            sourceRoute: '/',
            targetRoute: '/',
            expectedSourceItemCount: 10,
            targetRenderedItemCount: 5,
            targetDrupalEntityCount: 5,
            missingItems: [],
            extraItems: [],
            status: 'pass',
            evidence: 'count-evidence.json'
          }];
        });
      }
    },
    {
      name: 'none-disposition-with-count-shortfall',
      expected: /mismatchDisposition.*none.*(?:equal|matching)|count mismatch.*disposition/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
          value.perRouteItemReconciliation = [{
            sourcePath: '/',
            targetPath: '/',
            itemType: 'card',
            sourceCount: 10,
            targetRenderedCount: 5,
            targetDrupalEntityCount: 5,
            mismatchDisposition: 'none',
            accepted: true,
            notes: 'Incorrectly marked reconciled.'
          }];
        });
      }
    },
    {
      name: 'owner-exclusion-without-acceptance-evidence',
      expected: /owner_approved_exclusion.*(?:acceptedBy|dispositionEvidence)|(?:acceptedBy|dispositionEvidence).*owner_approved_exclusion/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
          value.perRouteItemReconciliation = [{
            sourcePath: '/',
            targetPath: '/',
            itemType: 'card',
            sourceCount: 10,
            targetRenderedCount: 5,
            targetDrupalEntityCount: 5,
            mismatchDisposition: 'owner_approved_exclusion',
            acceptedBy: '',
            dispositionEvidence: '',
            accepted: true,
            notes: 'Five items were excluded without recorded approval.'
          }];
        });
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);
    attachFixtureReviewHandoff(packetDir, 'https://target.example');

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('human-gate records are reported separately while packet contradictions fail closed', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'human-gate-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const humanRecordCases = [
    {
      name: 'maintainer-acceptance-pending',
      gate: 'G-MAINTAINER-01',
      expectedGateStatus: 'pending',
      expectedLocalStatus: 'pending',
      expectedRecordComplete: true,
      mutate: (packetDir) => mutateText(join(packetDir, 'maintainer-review.md'), (text) =>
        text.replace(
          '- [x] I would stake my name on this as a complete local Drupal CMS rebuild.',
          '- [ ] I would stake my name on this as a complete local Drupal CMS rebuild.'
        ))
    },
    {
      name: 'maintainer-self-signed',
      gate: 'G-MAINTAINER-01',
      expectedGateStatus: 'recorded-accepted',
      expectedLocalStatus: 'recorded-accepted',
      expectedRecordComplete: true,
      expectedIdentityComparison: 'same-string',
      mutate: (packetDir) => mutateText(join(packetDir, 'maintainer-review.md'), (text) =>
        text.replace('- Reviewer: Fixture Maintainer', '- Reviewer: fixture-builder-agent'))
    },
    {
      name: 'operator-acceptance-pending',
      gate: 'G-OPERATOR-01',
      expectedGateStatus: 'pending',
      expectedLocalStatus: 'pending',
      expectedRecordComplete: true,
      mutate: (packetDir) => mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text.replace('- [x] Repeatability accepted', '- [ ] Repeatability accepted'))
    },
    {
      name: 'operator-self-signed',
      gate: 'G-OPERATOR-01',
      expectedGateStatus: 'recorded-accepted',
      expectedLocalStatus: 'recorded-accepted',
      expectedRecordComplete: true,
      expectedIdentityComparison: 'same-string',
      mutate: (packetDir) => mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text.replace('- Name: Fixture Operator', '- Name: fixture-builder-agent'))
    },
    {
      name: 'operator-accepted-with-restrictions',
      gate: 'G-OPERATOR-01',
      expectedGateStatus: 'recorded-accepted-with-restrictions',
      expectedLocalStatus: 'recorded-accepted-with-restrictions',
      expectedRecordComplete: true,
      mutate: (packetDir) => mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text
          .replace('- [x] Repeatability accepted', '- [ ] Repeatability accepted')
          .replace('- [ ] Repeatability accepted with restrictions', '- [x] Repeatability accepted with restrictions'))
    },
    {
      name: 'operator-choice-with-incomplete-record',
      gate: 'G-OPERATOR-01',
      expectedGateStatus: 'recorded-accepted',
      expectedLocalStatus: 'pending',
      expectedRecordComplete: false,
      mutate: (packetDir) => mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text.replace('- Command transcript: drupal-readback.json commands', '- Command transcript:'))
    },
    {
      name: 'operator-choice-with-unknown-identity',
      gate: 'G-OPERATOR-01',
      expectedGateStatus: 'recorded-accepted',
      expectedLocalStatus: 'pending',
      expectedRecordComplete: false,
      mutate: (packetDir) => mutateText(join(packetDir, 'operator-run.md'), (text) =>
        text.replace('- Name: Fixture Operator', '- Name: UNKNOWN'))
    }
  ];

  const gateVocabulary = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const expectedHumanGateIds = gateVocabulary.gates
    .filter((record) => record.checkedBy === 'human')
    .map((record) => record.id)
    .sort();

  for (const {
    name,
    gate,
    expectedGateStatus,
    expectedIdentityComparison,
    expectedLocalStatus,
    expectedRecordComplete,
    mutate
  } of humanRecordCases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);
    attachFixtureReviewHandoff(packetDir, 'https://target.example');

    const report = await validatePacket({ packetDir });

    assert.equal(
      report.completionEvidence.packetSupportsCompletion,
      true,
      report.completionEvidence.packetCompletionBlockedReasons.join('\n')
    );
    assert.equal(report.recordedHumanGateStatus.affectsMachineCompletion, false, name);
    assert.equal(report.recordedHumanGateStatus.authentication, 'self-attested-record-only', name);
    assert.deepEqual(Object.keys(report.recordedHumanGateStatus.gates).sort(), expectedHumanGateIds, name);
    assert.equal(report.completionEvidence.humanDecisionPresentationStatus, 'presented-consistently', name);
    assert.equal(report.recordedHumanGateStatus.localRebuildStatus, expectedLocalStatus, name);
    assert.equal(report.recordedHumanGateStatus.gates[gate].status, expectedGateStatus, name);
    assert.equal(report.recordedHumanGateStatus.gates[gate].recordComplete, expectedRecordComplete, name);
    if (expectedIdentityComparison) {
      assert.equal(
        report.recordedHumanGateStatus.gates[gate].identityStringComparison,
        expectedIdentityComparison,
        name
      );
    }
  }

  const contradictionCases = [
    {
      name: 'none-declaration-with-off-road-rows',
      expected: /open-decisions\.md cannot declare "Decisions still open: None".*OR- exception rows/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => mutateText(join(packetDir, 'off-road-inventory.md'), (text) =>
        text.replace('No off-road moves were used in this fixture.', [
          '| ID | Area | Off-road move | Drupal-native option considered | Why exception exists | Evidence | Status |',
          '| --- | --- | --- | --- | --- | --- | --- |',
          '| OR-001 | Public copy | Hardcoded footer copy in Twig | Menu/block ownership | The footer link set is source-fixed | theme commit evidence | accepted |'
        ].join('\n')))
    },
    {
      name: 'none-declaration-with-blind-accepted-out-of-scope',
      expected: /open-decisions\.md cannot declare "Decisions still open: None".*accepted_out_of_scope defects/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
        blind.productDefects = [{
          id: 'DEF-001',
          severity: 'low',
          status: 'accepted_out_of_scope',
          acceptedBy: 'Fixture Owner',
          acceptedReason: 'The provider-owned widget is out of the local rebuild scope.',
          evidence: ['editor-task.json'],
          notes: ''
        }];
        blind.summary.acceptedOutOfScopeIssueCount = 1;
      })
    },
    {
      name: 'unrelated-decision-does-not-present-blind-deviation',
      expected: /Current evidence cell; missing DEF-001/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.productDefects = [{
            id: 'DEF-001',
            severity: 'low',
            status: 'accepted_out_of_scope',
            acceptedBy: 'Fixture Owner',
            acceptedReason: 'The provider-owned widget is outside the machine-evaluated scope.',
            evidence: ['editor-task.json'],
            notes: ''
          }];
          blind.summary.acceptedOutOfScopeIssueCount = 1;
        });
        writeOpenDecisionRow(packetDir);
      }
    },
    {
      name: 'deviation-reference-must-match-exact-token',
      expected: /Current evidence cell; missing OR-001/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => {
        mutateText(join(packetDir, 'off-road-inventory.md'), (text) =>
          text.replace('No off-road moves were used in this fixture.', [
            '| ID | Area | Off-road move | Drupal-native option considered | Why exception exists | Evidence | Status |',
            '| --- | --- | --- | --- | --- | --- | --- |',
            '| OR-001 | Public copy | Hardcoded footer copy in Twig | Menu/block ownership | Source-fixed footer | theme evidence | accepted |'
          ].join('\n')));
        writeOpenDecisionRow(packetDir, { currentEvidence: 'OR-0010' });
      }
    },
    {
      name: 'owner-approved-count-exclusion-needs-exact-decision',
      expected: /missing count-exclusion:\/->\/:gallery-image/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
          routeMatrix.perRouteItemReconciliation = [{
            sourcePath: '/',
            targetPath: '/',
            itemType: 'Gallery image',
            sourceCount: 10,
            targetRenderedCount: 5,
            targetDrupalEntityCount: 5,
            mismatchDisposition: 'owner_approved_exclusion',
            acceptedBy: 'Fixture Owner',
            dispositionEvidence: 'evidence/blind-adversarial-review/editor-task.json',
            accepted: true,
            notes: 'Five unavailable images are excluded.'
          }];
        });
        writeOpenDecisionRow(packetDir);
      }
    },
    {
      name: 'parity-exclusion-needs-token-safe-identity',
      expected: /stable IDs.*addressableSurface\.exclusions\[0\]/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'parity-report.json'), (parity) => {
          parity.addressableSurface.exclusions = [{ name: 'Legal pages', reason: 'Owner disposition.' }];
          parity.addressableSurface.routesExcluded = 1;
        });
        writeOpenDecisionRow(packetDir, { currentEvidence: 'parity-exclusion:Legal pages' });
      }
    },
    {
      name: 'composition-owner-deviation-needs-exact-decision',
      expected: /missing composition-deviation:\//i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
          const check = independent.compositionModelFidelityChecks[0];
          check.actualCompositionOwner = 'canvas_page';
          check.deviationRecordRequired = true;
          check.deviationRecordPresent = true;
          check.deviationTargetUrl = 'https://target.example/';
          check.deviationRationale = 'Accepted target-bound fallback.';
          check.deviationEvidence = 'claim-evidence.json';
        });
        writeOpenDecisionRow(packetDir);
      }
    },
    {
      name: 'none-summary-cannot-hide-open-row',
      expected: /cannot declare "Decisions still open: None" while a DEC row remains open/i,
      expectedPresentation: 'contradictory',
      mutate: (packetDir) => writeOpenDecisionRow(packetDir, { openSummary: 'None', status: 'open' })
    },
    {
      name: 'missing-handoff-summary-is-incomplete',
      expected: /exact handoff summaries/i,
      expectedPresentation: 'incomplete',
      mutate: (packetDir) => writeOpenDecisionRow(packetDir, { includeAcceptedSummary: false })
    },
    {
      name: 'none-declaration-must-be-exact',
      expected: /exact Decisions still open: None declaration/i,
      expectedPresentation: 'incomplete',
      mutate: (packetDir) => mutateText(join(packetDir, 'open-decisions.md'), (text) =>
        text.replace('- Decisions still open: None', '- Decisions still open: None yet'))
    },
    {
      name: 'human-review-without-named-reviewer',
      expected: /human_review requires a recorded reviewer label/i,
      expectedPresentation: 'presented-consistently',
      mutate: (packetDir) => mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
        browser.publicRouteChecks[0].visualComparison.method = 'human_review';
        browser.publicRouteChecks[0].visualComparison.reviewer = '';
      })
    }
  ];

  for (const { name, expected, expectedPresentation, mutate } of contradictionCases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
    assert.equal(report.completionEvidence.humanDecisionPresentationStatus, expectedPresentation, name);
  }

  const visualMethodCases = [
    { name: 'empty-visual-method', method: '', expected: /visualComparison\.method must be/ },
    { name: 'unknown-visual-method', method: 'manual_review', expected: /visualComparison\.method must be/ },
    { name: 'structural-review-is-diagnostic', method: 'structural_review', expected: /diagnostic-only/ },
    { name: 'other-review-is-diagnostic', method: 'other', expected: /diagnostic-only/ },
    {
      name: 'pixel-diff-needs-real-image',
      method: 'pixel_diff',
      expected: /real bounded packet-local diff image/,
      configure: (visualComparison) => {
        visualComparison.diffImage = 'missing-diff.png';
        visualComparison.diffScore = 0.1;
      }
    },
    {
      name: 'pixel-diff-cannot-reuse-source-capture',
      method: 'pixel_diff',
      expected: /distinct real bounded packet-local diff image/,
      configure: (visualComparison, check) => {
        visualComparison.diffImage = check.sourceScreenshot;
        visualComparison.diffScore = 0.1;
      }
    }
  ];
  for (const { name, method, expected, configure } of visualMethodCases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
      for (const check of browser.publicRouteChecks) {
        check.visualComparison.method = method;
        configure?.(check.visualComparison, check);
      }
    });
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }

  const exactDeviationPacket = join(temp, 'exact-deviation-reference');
  cpSync(canonicalPacket, exactDeviationPacket, { recursive: true });
  mutateJson(join(exactDeviationPacket, 'blind-adversarial-review.json'), (blind) => {
    blind.productDefects = [{
      id: 'DEF-001',
      severity: 'low',
      status: 'accepted_out_of_scope',
      acceptedBy: 'Fixture Owner',
      acceptedReason: 'The provider-owned widget is outside the machine-evaluated scope.',
      evidence: ['editor-task.json'],
      notes: ''
    }];
    blind.summary.acceptedOutOfScopeIssueCount = 1;
  });
  writeOpenDecisionRow(exactDeviationPacket, { currentEvidence: 'DEF-001' });
  attachFixtureReviewHandoff(exactDeviationPacket, 'https://target.example');
  const exactDeviationReport = await validatePacket({ packetDir: exactDeviationPacket });
  assert.equal(
    exactDeviationReport.completionEvidence.packetSupportsCompletion,
    true,
    exactDeviationReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );
  assert.equal(
    exactDeviationReport.completionEvidence.humanDecisionPresentationStatus,
    'presented-consistently'
  );

  const pixelDiffPacket = join(temp, 'pixel-diff-with-real-image');
  cpSync(canonicalPacket, pixelDiffPacket, { recursive: true });
  const pixelDiffEvidenceDir = join(pixelDiffPacket, 'evidence', 'browser');
  mkdirSync(pixelDiffEvidenceDir, { recursive: true });
  mutateJson(join(pixelDiffPacket, 'browser-evidence.json'), (browser) => {
    for (const [index, check] of browser.publicRouteChecks.entries()) {
      const diffName = `diff-${check.viewport.name}.png`;
      writeFileSync(
        join(pixelDiffEvidenceDir, diffName),
        screenshotPng(20 + index, check.viewport.width, check.viewport.height)
      );
      check.visualComparison.method = 'pixel_diff';
      check.visualComparison.diffImage = `evidence/browser/${diffName}`;
      check.visualComparison.diffScore = 0.01;
    }
  });
  attachFixtureReviewHandoff(pixelDiffPacket, 'https://target.example');
  const pixelDiffReport = await validatePacket({ packetDir: pixelDiffPacket });
  assert.equal(
    pixelDiffReport.completionEvidence.packetSupportsCompletion,
    true,
    pixelDiffReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const namedReviewerPacket = join(temp, 'human-review-with-named-reviewer');
  cpSync(canonicalPacket, namedReviewerPacket, { recursive: true });
  mutateJson(join(namedReviewerPacket, 'browser-evidence.json'), (browser) => {
    for (const check of browser.publicRouteChecks) {
      check.visualComparison.method = 'human_review';
      check.visualComparison.reviewer = 'Fixture Reviewer';
    }
  });
  attachFixtureReviewHandoff(namedReviewerPacket, 'https://target.example');
  const namedReviewerReport = await validatePacket({ packetDir: namedReviewerPacket });
  assert.equal(
    namedReviewerReport.completionEvidence.packetSupportsCompletion,
    true,
    namedReviewerReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const degradedPacket = join(temp, 'degraded-independence');
  cpSync(canonicalPacket, degradedPacket, { recursive: true });
  mutateJson(join(degradedPacket, 'independent-verification.json'), (independent) => {
    independent.verifier.freshContextUsed = false;
  });
  const degradedReport = await validatePacket({ packetDir: degradedPacket });
  assert.equal(degradedReport.completionEvidence.independence.independentVerification, 'degraded');
  assert.equal(degradedReport.completionEvidence.independentVerificationSupportsCompletion, false);
});

test('completion evidence uses exact Drupal identities and explicit SEO applicability', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'exact-identity-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'used-node-bundle-cannot-be-omitted-from-editor-evidence',
      expected: /field-output-matrix\.json must include the used node bundle node\.article/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.contentTypes.push({ machineName: 'article', label: 'Article', sourceObjects: ['news article'] });
        });
        mutateJson(join(packetDir, 'drupal-readback.json'), (value) => {
          value.content.nodes.push({ id: 2, type: 'article', title: 'News', published: true });
          value.content.contentTypes.push({ machineName: 'article', label: 'Article' });
        });
      }
    },
    {
      name: 'one-editor-workflow-cannot-cover-two-bundles',
      expected: /editor workflow mapped to node\.article/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'field-output-matrix.json'), (value) => {
        value.bundles.push({
          entityType: 'node',
          bundle: 'article',
          fields: [{
            ...value.bundles[0].fields[0],
            editorLabel: 'Article body'
          }]
        });
      })
    },
    {
      name: 'field-check-wrong-bundle',
      expected: /field-output falsification check for node\.page\.body/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
        value.fieldOutputFalsification[0].bundle = 'article';
      })
    },
    {
      name: 'composition-owner-mismatch',
      expected: /passing composition-fidelity check for \//i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
        value.compositionModelFidelityChecks[0].actualCompositionOwner = 'canvas_page';
        value.compositionModelFidelityChecks[0].deviationRecordRequired = true;
        value.compositionModelFidelityChecks[0].deviationRecordPresent = true;
        value.compositionModelFidelityChecks[0].deviationRationale = '';
        value.compositionModelFidelityChecks[0].deviationTargetUrl = '';
        value.compositionModelFidelityChecks[0].deviationEvidence = '';
      })
    },
    {
      name: 'admin-add-row',
      expected: /passing editor-add-row checks for in-scope collections/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.structuredContentModel.collectionScope = {
            reviewed: true,
            applies: true,
            reason: 'The source contains a repeatable collection.'
          };
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.editorAddRowChecks = [{
            editorUser: 'admin',
            editorRole: 'administrator',
            publicOutputChanged: true,
            listingOrDetailUpdatedWithoutCode: true,
            status: 'pass',
            evidence: 'claim-evidence.json'
          }];
        });
      }
    },
    {
      name: 'seo-not-applicable-without-rationale',
      expected: /rendered canonical, description, and social-image dispositions/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'browser-evidence.json'), (value) => {
        for (const check of value.publicRouteChecks) {
          check.renderedSeoSignals.openGraphImageStatus = 'not_applicable';
          check.renderedSeoSignals.openGraphImageApplicabilityReviewed = true;
          check.renderedSeoSignals.openGraphImageNotApplicableRationale = '';
        }
      })
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('a coherent but stale packet cannot authorize current local completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'stale-completion-packet-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  const staleCheckedAt = '2020-01-01T00:00:00Z';
  for (const file of [
    'source-audit.json',
    'pattern-map.json',
    'route-matrix.json',
    'parity-report.json',
    'browser-evidence.json',
    'next-cycle-verification.json',
    'independent-verification.json',
    'blind-adversarial-review.json',
    'drupal-readback.json',
    'field-output-matrix.json',
    'negative-route-consent.json'
  ]) {
    mutateJson(join(packetDir, file), (value) => { value.checkedAt = staleCheckedAt; });
  }

  const report = await validatePacket({ packetDir });
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /newest completion evidence is older than seven days/i
  );
});

test('next-cycle verification requires discovery, a least-privilege future publish probe, and residue-free cleanup', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'next-cycle-gate-'));
  const naPacket = join(temp, 'not-applicable');
  copyTemplatePacket(naPacket);
  writeJson(join(naPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(naPacket, 'https://target.example');
  const naReport = await validatePacket({ packetDir: naPacket });
  assert.equal(naReport.completionEvidence.packetSupportsCompletion, true, JSON.stringify(naReport.completionEvidence, null, 2));

  const canonicalPacket = join(temp, 'qualifying');
  cpSync(naPacket, canonicalPacket, { recursive: true });
  addQualifyingNextCycleEvidence(canonicalPacket, 'https://target.example');
  const qualifyingReport = await validatePacket({ packetDir: canonicalPacket });
  assert.equal(
    qualifyingReport.completionEvidence.packetSupportsCompletion,
    true,
    JSON.stringify(qualifyingReport.completionEvidence, null, 2)
  );
  const dateOnlyPacket = join(temp, 'qualifying-date-only');
  cpSync(canonicalPacket, dateOnlyPacket, { recursive: true });
  let futureDateOnly = '';
  mutateJson(join(dateOnlyPacket, 'next-cycle-verification.json'), (value) => {
    futureDateOnly = value.futureContentProbe.futureDate.slice(0, 10);
    value.futureContentProbe.futureDate = futureDateOnly;
  });
  mutateJson(join(dateOnlyPacket, 'evidence', 'next-cycle', 'probe.json'), (value) => {
    value.futureDate = futureDateOnly;
  });
  attachFixtureReviewHandoff(dateOnlyPacket, 'https://target.example');
  const dateOnlyReport = await validatePacket({ packetDir: dateOnlyPacket });
  assert.equal(dateOnlyReport.completionEvidence.packetSupportsCompletion, true, 'Drupal date-only values are valid future dates');

  const cases = [
    {
      name: 'n-a-cannot-hide-discovered-dimension',
      expected: /cannot use N\/A when discovery found/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.applicability.applies = false;
        value.applicability.reason = 'Claimed not applicable despite discovery.';
      })
    },
    {
      name: 'admin-role-cannot-run-probe',
      expected: /least-privilege non-admin editor identity/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.leastPrivilegeEditor.editorRole = 'administrator';
      })
    },
    {
      name: 'browser-proof-must-cover-probed-bundle',
      expected: /same recurring entity type and bundle/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'browser-evidence.json'), (value) => {
        value.editorWorkflowChecks = value.editorWorkflowChecks.filter((check) => check.bundle !== 'event');
      })
    },
    {
      name: 'future-value-must-exceed-current',
      expected: /beyond the latest current comparable value/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.futurePeriodOrTermProbe.comparable = 2026;
      })
    },
    {
      name: 'future-content-must-publish',
      expected: /future-dated non-admin publish transition and anonymous public output/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.futureContentProbe.published = false;
      })
    },
    {
      name: 'taxonomy-permission-is-required',
      expected: /create_taxonomy_term/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.discovery.recurringPublicModels[0].dimensions[0].kind = 'taxonomy';
        value.futurePeriodOrTermProbe.operation = 'created';
        value.cleanup.periodOrTermCleanup = 'deleted';
      })
    },
    {
      name: 'cleanup-residue-fails-closed',
      expected: /zero content, revision, alias, and period\/term residue/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.cleanup.revisionResidueCount = 1;
      })
    },
    {
      name: 'missing-machine-evidence-fails-closed',
      expected: /packet-local machine evidence/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'next-cycle-verification.json'), (value) => {
        value.discovery.evidence = 'missing.json';
      })
    },
    {
      name: 'generic-text-is-not-machine-evidence',
      expected: /structured JSON bound to the target, commands, timestamp/i,
      mutate: (packetDir) => {
        writeFileSync(join(packetDir, 'evidence', 'next-cycle', 'discovery.json'), 'looks good\n');
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('next-cycle N/A cannot omit a temporal field on a declared recurring public model', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'next-cycle-derived-dimension-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
    value.structuredContentModel.recurringSourceObjects = [{
      sourceObject: 'Event',
      drupalOwner: 'content_type',
      bundleOrConfigName: 'event',
      requiredFields: ['field_event_date'],
      relationships: [],
      collectionOwner: '',
      detailRouteOwner: 'entity_view_display',
      editorVerification: {
        nonAdminEditorCanCreate: true,
        appearsInPublicListingOrDetailWithoutCodeChange: true,
        evidence: 'evidence/blind-adversarial-review/editor-task.json'
      },
      accepted: true,
      notes: ''
    }];
  });
  mutateJson(join(packetDir, 'field-output-matrix.json'), (value) => {
    value.bundles.push({
      entityType: 'node',
      bundle: 'event',
      fields: [{
        machineName: 'field_event_date',
        editorLabel: 'Event date',
        required: true,
        fieldType: 'datetime',
        widget: 'datetime_default',
        formatter: 'datetime_default',
        publicRenderLocations: ['/events'],
        affectsAnonymousOutput: true,
        containsRawPresentationImplementation: false,
        presentationBoundary: 'content_fact',
        editorOnlyRationale: '',
        accepted: true,
        notes: ''
      }]
    });
  });

  const report = await validatePacket({ packetDir });
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /must identify temporal\/cycle field node\.event\.field_event_date/i
  );
});

test('live verification independently checks that the cleaned next-cycle probe URL is gone', async () => {
  for (const cleanupStatus of [410, 200]) {
    await withHttpServer(
      (request, response) => {
        if (request.url === '/__next-cycle-probe-42') {
          response.writeHead(cleanupStatus, { 'content-type': 'text/plain; charset=utf-8' });
          response.end(cleanupStatus === 410 ? 'gone' : 'residue');
          return;
        }
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(fixtureTargetHtml(request));
      },
      async (baseUrl) => {
        const temp = mkdtempSync(join(tmpdir(), `next-cycle-live-${cleanupStatus}-`));
        const packetDir = join(temp, 'review-packet');
        copyTemplatePacket(packetDir);
        writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
        addQualifyingReviewEvidence(packetDir, baseUrl);
        addQualifyingNextCycleEvidence(packetDir, baseUrl);

        const report = await verifyLive({
          packetDir,
          cwd: repoRoot,
          environment: {},
          targetUrl: baseUrl,
          drupalRuntime: injectedDrupalRuntime(baseUrl)
        });

        assert.equal(report.nextCycleCleanupCheck.actualStatus, cleanupStatus);
        assert.equal(report.nextCycleCleanupCheck.passed, cleanupStatus === 410);
        assert.equal(report.liveTargetValid, cleanupStatus === 410);
        if (cleanupStatus === 200) {
          assert.match(report.errors.join('\n'), /cleanup URL returned 200; expected 410/i);
        }
      }
    );
  }
});

test('live model census rejects authored N/A with omitted temporal fields and accepts a confirmed empty live model', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'next-cycle-live-census-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const validNaReport = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(validNaReport.liveNextCycleReconciliation.censusTrusted, true);
      assert.equal(validNaReport.liveNextCycleReconciliation.liveApplies, false);
      assert.equal(validNaReport.liveTargetValid, true, validNaReport.errors.join('\n'));

      const tremegaCandidates = [
        {
          key: 'node.happy_hour_event.field_event_date',
          entityType: 'node',
          bundle: 'happy_hour_event',
          machineName: 'field_event_date',
          fieldType: 'datetime',
          required: true,
          cardinality: 1,
          optionCount: 0,
          signalKinds: ['date', 'date_type'],
          targetVocabularies: []
        },
        {
          key: 'node.performer.field_festival_year',
          entityType: 'node',
          bundle: 'performer',
          machineName: 'field_festival_year',
          fieldType: 'entity_reference',
          required: true,
          cardinality: 1,
          optionCount: 0,
          signalKinds: ['taxonomy', 'year'],
          targetVocabularies: ['festival_year']
        },
        {
          key: 'node.performer.field_schedule_day',
          entityType: 'node',
          bundle: 'performer',
          machineName: 'field_schedule_day',
          fieldType: 'list_string',
          required: false,
          cardinality: 1,
          optionCount: 2,
          signalKinds: ['date', 'day', 'schedule'],
          targetVocabularies: []
        }
      ];
      const omittedLiveReport = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl, {
          liveNextCycleCensus: {
            schemaVersion: 'public-kit.live-next-cycle-census.1',
            confirmed: true,
            metadataOnly: true,
            privateContentRead: false,
            candidateCount: 4,
            fields: tremegaCandidates,
            taxonomyDimensions: [{
              key: 'taxonomy.festival_year',
              vocabulary: 'festival_year',
              signalKinds: ['year']
            }],
            workflows: []
          }
        })
      });
      assert.equal(omittedLiveReport.liveNextCycleReconciliation.liveApplies, true);
      assert.equal(omittedLiveReport.liveNextCycleReconciliation.passed, false);
      assert.equal(omittedLiveReport.nextCycleCleanupCheck.applicable, true);
      assert.equal(omittedLiveReport.nextCycleCleanupCheck.passed, false);
      assert.equal(omittedLiveReport.liveTargetValid, false);
      assert.match(
        omittedLiveReport.errors.join('\n'),
        /cannot use N\/A.*field_event_date.*field_festival_year.*field_schedule_day/i
      );
    }
  );
});

test('live model census fails closed for authored applicability when the census is untrusted or incomplete', async () => {
  await withHttpServer(
    (request, response) => {
      const status = request.url === '/__next-cycle-probe-42' ? 410 : 200;
      response.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
      response.end(status === 410 ? 'removed' : fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'next-cycle-live-census-fail-closed-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      addQualifyingNextCycleEvidence(packetDir, baseUrl);

      const untrustedReport = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl, {
          liveNextCycleCensus: {
            schemaVersion: 'public-kit.live-next-cycle-census.1',
            confirmed: false,
            metadataOnly: true,
            privateContentRead: false,
            candidateCount: 0,
            fields: [],
            taxonomyDimensions: [],
            workflows: []
          }
        })
      });
      assert.equal(untrustedReport.liveNextCycleReconciliation.authoredApplies, true);
      assert.equal(untrustedReport.liveNextCycleReconciliation.censusTrusted, false);
      assert.equal(untrustedReport.liveNextCycleReconciliation.passed, false);
      assert.equal(untrustedReport.liveTargetValid, false);
      assert.match(
        untrustedReport.errors.join('\n'),
        /requires a successful read-only Drush live model census/i
      );

      const incompleteReport = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl, {
          liveNextCycleCensus: {
            schemaVersion: 'public-kit.live-next-cycle-census.1',
            confirmed: true,
            metadataOnly: true,
            privateContentRead: false,
            candidateCount: 2,
            fields: [
              {
                key: 'node.event.field_year',
                entityType: 'node',
                bundle: 'event',
                machineName: 'field_year',
                fieldType: 'integer',
                required: true,
                cardinality: 1,
                optionCount: 0,
                signalKinds: ['year'],
                targetVocabularies: []
              },
              {
                key: 'node.event.field_season',
                entityType: 'node',
                bundle: 'event',
                machineName: 'field_season',
                fieldType: 'list_string',
                required: false,
                cardinality: 1,
                optionCount: 4,
                signalKinds: ['season'],
                targetVocabularies: []
              }
            ],
            taxonomyDimensions: [],
            workflows: []
          }
        })
      });
      assert.equal(incompleteReport.liveNextCycleReconciliation.censusTrusted, true);
      assert.deepEqual(
        incompleteReport.liveNextCycleReconciliation.unreviewedLiveCandidateKeys,
        ['node.event.field_season']
      );
      assert.equal(incompleteReport.liveNextCycleReconciliation.passed, false);
      assert.equal(incompleteReport.liveTargetValid, false);
      assert.match(
        incompleteReport.errors.join('\n'),
        /authored applicability omits live Drupal temporal\/cycle candidates.*field_season/i
      );
    }
  );
});

test('live editor-surface census rejects a hidden widget for a load-bearing public field', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-editor-hidden-widget-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const runtime = injectedDrupalRuntime(baseUrl);
      runtime.liveEditorSurfaceCensus.fields[0].widgetVisible = false;
      runtime.liveEditorSurfaceCensus.fields[0].widget = '';
      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: runtime
      });

      assert.equal(report.liveEditorSurfaceReconciliation.censusTrusted, true);
      assert.equal(report.liveEditorSurfaceReconciliation.passed, false);
      assert.equal(report.liveTargetValid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(
        report.errors.join('\n'),
        /node\.page\.body is hidden or has no visible widget.*default form display/i
      );
    }
  );
});

test('live editor-surface census requires the declared editor role to use existing text formats', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-editor-text-format-permission-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const runtime = injectedDrupalRuntime(baseUrl);
      const field = runtime.liveEditorSurfaceCensus.fields[0];
      field.existingFormatIds = ['content_format'];
      field.editorRolePermissionChecks[0].requiredPermissions = ['use text format content_format'];
      field.editorRolePermissionChecks[0].missingPermissions = ['use text format content_format'];
      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: runtime
      });

      assert.equal(report.liveEditorSurfaceReconciliation.censusTrusted, true);
      assert.equal(report.liveEditorSurfaceReconciliation.passed, false);
      assert.equal(report.liveTargetValid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(
        report.errors.join('\n'),
        /content editor cannot edit existing node\.page\.body values; missing use text format content_format/i
      );
    }
  );
});

test('live editor-surface census fails closed when its verifier-owned Drush readback is unavailable', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-editor-census-unavailable-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const runtime = injectedDrupalRuntime(baseUrl, {
        liveEditorSurfaceCensus: {
          schemaVersion: 'public-kit.live-editor-surface-census.1',
          confirmed: false,
          readOnly: true,
          rawFieldValuesEmitted: false,
          entityInspectionLimitPerField: 5000,
          fieldCount: 0,
          roleCount: 0,
          fields: [],
          roles: [],
          errors: [],
          fingerprint: '',
          reason: 'The read-only Drush live editor-surface census did not run.'
        }
      });
      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: runtime
      });

      assert.equal(report.liveEditorSurfaceReconciliation.censusTrusted, false);
      assert.equal(report.liveEditorSurfaceReconciliation.passed, false);
      assert.equal(report.liveTargetValid, false);
      assert.match(
        report.errors.join('\n'),
        /G-EDITOR-01 requires a successful verifier-owned read-only Drush live editor-surface census/i
      );
    }
  );
});

test('blanket-filled packet templates remain valid lint but cannot support completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blanket-filled-packet-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  for (const file of [
    'source-audit.json',
    'pattern-map.json',
    'field-output-matrix.json',
    'parity-report.json',
    'browser-evidence.json',
    'drupal-readback.json'
  ]) {
    const record = resolveEnumSentinels(JSON.parse(readFileSync(join(templatesDir, templateName(file)), 'utf8')));
    record.runSpecificEvidenceRecorded = true;
    writeJson(join(packetDir, file), record);
  }
  for (const file of [
    'operator-run.md',
    'maintainer-review.md',
    'recipe-start-point.md',
    'scoped-gap-list.md',
    'open-decisions.md',
    'off-road-inventory.md',
    'durable-intent.yml'
  ]) {
    writeFileSync(
      join(packetDir, file),
      `${readFileSync(join(templatesDir, templateName(file)), 'utf8')}\nRun-specific completion evidence recorded.\n`
    );
  }
  attachFixtureReviewHandoff(packetDir, 'https://target.example');

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, true);
  assert.equal(report.completionEvidence.packetCompletionReady, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /source-audit\.json/);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /recipe-start-point\.md/);
  assert.doesNotMatch(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /operator-run\.md|maintainer-review\.md/
  );
});

test('completed Markdown can retain instructional references to UNKNOWN without being treated as unresolved', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'completed-recipe-instructions-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  let recipe = readFileSync(join(templatesDir, 'recipe-start-point.template.md'), 'utf8');
  recipe = recipe
    .replace('- Source URL:', '- Source URL: https://source.example/')
    .replace('- Target site name:', '- Target site name: Fixture rebuild')
    .replace('- Target workspace:', '- Target workspace: DDEV fixture')
    .replace('- Source-use boundary:', '- Source-use boundary: Authorized public rebuild')
    .replace('- Decision date:', '- Decision date: 2026-07-09')
    .replace('- Decision owner:', '- Decision owner: Fixture Maintainer')
    .replace(
      '- [ ] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.',
      '- [x] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.'
    )
    .replace(/^Decision:\s*$/m, 'Decision: Retain the installed Drupal CMS Starter.')
    .replace(/^Rationale:\s*$/m, 'Rationale: The one-route source needs only bounded structured overlays.')
    .replace(/\|\s*UNKNOWN\s*\|/g, '| not_applicable |')
    .replace(/```text\s*UNKNOWN\s*```/m, '```text\nNo recipe was applied; discovery output reviewed.\n```');
  assert.match(recipe, /Decision values:.*UNKNOWN/);
  writeFileSync(join(packetDir, 'recipe-start-point.md'), recipe);
  attachFixtureReviewHandoff(packetDir, 'https://target.example');

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.packetSupportsCompletion, true, JSON.stringify(report.completionEvidence, null, 2));
});

test('every nonempty durable intent record must be current before completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'durable-intent-current-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  const validRecord = `schema_version: public-kit.1
site: "https://target.example"
intent_records:
  - id: "homepage-owner"
    target_config: "system.site"
    purpose: "Keep the verified homepage owner explicit."
    source_evidence:
      - "route-matrix.json"
    rationale: "The route identity is load-bearing."
    asserted_by: "Fixture Maintainer"
    last_reviewed: "2026-07-09"
    config_hash: "sha256:${'a'.repeat(64)}"
    status: "hash-valid"
    stale_behavior: "treat_as_no_intent"
`;
  writeFileSync(join(packetDir, 'durable-intent.yml'), validRecord);
  attachFixtureReviewHandoff(packetDir, 'https://target.example');
  const currentReport = await validatePacket({ packetDir });
  assert.equal(currentReport.completionEvidence.packetSupportsCompletion, true, JSON.stringify(currentReport, null, 2));

  writeFileSync(join(packetDir, 'durable-intent.yml'), `${validRecord}  - id: "stale-field"
    target_config: "field.storage.node.body"
    purpose: "Placeholder"
    source_evidence: []
    rationale: "Not reviewed"
    asserted_by: "Fixture"
    last_reviewed: "2026-07-09"
    config_hash: "not-applicable"
    status: "draft"
    stale_behavior: "treat_as_no_intent"
`);
  attachFixtureReviewHandoff(packetDir, 'https://target.example');
  const staleReport = await validatePacket({ packetDir });
  assert.equal(staleReport.valid, true, staleReport.errors.join('\n'));
  assert.equal(staleReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(staleReport.completionEvidence.packetCompletionBlockedReasons.join('\n'), /durable-intent\.yml/);
});

test('empty durable intent requires a named evidence-backed acceptance', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'durable-intent-empty-acceptance-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  const acceptedReport = await validatePacket({ packetDir });
  assert.equal(acceptedReport.completionEvidence.packetSupportsCompletion, true, JSON.stringify(acceptedReport, null, 2));

  const path = join(packetDir, 'durable-intent.yml');
  const withoutAcceptance = readFileSync(path, 'utf8').replace(
    /^empty_intent_acceptance:\s*$[\s\S]*?(?=^evidence_scope:)/m,
    ''
  );
  writeFileSync(path, withoutAcceptance);
  attachFixtureReviewHandoff(packetDir, 'https://target.example');
  const rejectedReport = await validatePacket({ packetDir });

  assert.equal(rejectedReport.valid, true, rejectedReport.errors.join('\n'));
  assert.equal(rejectedReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    rejectedReport.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /accepted_no_durable_intent/
  );
});

test('durable intent rejects statuses outside the canonical enum', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'durable-intent-status-enum-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  const path = join(packetDir, 'durable-intent.yml');
  writeFileSync(path, `schema_version: public-kit.1
site: "https://target.example"
intent_records:
  - id: "homepage-owner"
    target_config: "system.site"
    rationale: "Keep the homepage owner explicit."
    asserted_by: "Fixture Maintainer"
    last_reviewed: "2026-07-09"
    config_hash: "not-applicable"
    status: "looks-good"
`);

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.match(report.errors.join('\n'), /invalid durable intent status looks-good/);
});

test('structured artifacts reject unknown gate ids and ad hoc enum values', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'structured-enums-gates-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'independent-verification.json'), (record) => {
    record.completionClaims[0].gateId = 'G-MADE-UP-99';
  });
  mutateJson(join(packetDir, 'browser-evidence.json'), (record) => {
    record.publicRouteChecks[0].visualComparison.status = 'mostly-pass';
    record.publicRouteChecks[0].gateIds = 'G-ROUTE-01';
  });

  const report = await validatePacket({ packetDir });
  const installedReport = await validateInstalledPacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(installedReport.valid, false);
  assert.match(report.errors.join('\n'), /canonical gate id from gates\.json/);
  assert.match(report.errors.join('\n'), /gateIds must be an array of canonical gate ids/);
  assert.match(report.errors.join('\n'), /visualComparison\.status must be one of: pass, needs-review, fail, blocked/);
  assert.match(installedReport.errors.join('\n'), /visualComparison\.status must be one of: pass, needs-review, fail, blocked/);
});

test('per-gate results distinguish packet execution, live execution, and human review', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const packetResults = new Map(perGateResults(gates, []).map((result) => [result.gateId, result]));
  assert.deepEqual(
    [packetResults.get('G-ROUTE-01').status, packetResults.get('G-ROUTE-01').evaluatorCompleted],
    ['pass', true]
  );
  assert.deepEqual(
    [packetResults.get('G-CONFIG-01').status, packetResults.get('G-CONFIG-01').evaluatorCompleted],
    ['not_evaluated', false]
  );
  assert.deepEqual(
    [packetResults.get('G-MAINTAINER-01').status, packetResults.get('G-MAINTAINER-01').evaluatorCompleted],
    ['human_review', false]
  );
  const packetFailureResults = new Map(
    perGateResults(gates, ['browser-evidence.json has an invalid status.'])
      .map((result) => [result.gateId, result])
  );
  assert.deepEqual(
    [packetFailureResults.get('G-BROWSER-01').status, packetFailureResults.get('G-BROWSER-01').evaluatorCompleted],
    ['fail', false]
  );

  const liveResults = new Map(perGateResults(gates, [], { mode: 'live' }).map((result) => [result.gateId, result]));
  assert.deepEqual(
    [liveResults.get('G-CONFIG-01').status, liveResults.get('G-CONFIG-01').evaluatorCompleted],
    ['pass', true]
  );
  assert.deepEqual(
    [liveResults.get('G-MAINTAINER-01').status, liveResults.get('G-MAINTAINER-01').evaluatorCompleted],
    ['human_review', false]
  );

  const failedLiveResults = new Map(
    perGateResults(gates, ['G-VERIFY-02 Live target route verification failed.'], { mode: 'live' })
      .map((result) => [result.gateId, result])
  );
  assert.equal(failedLiveResults.get('G-ROUTE-01').status, 'fail');
  assert.match(failedLiveResults.get('G-ROUTE-01').errors.join('\n'), /Live target route verification failed/);
  assert.equal(failedLiveResults.get('G-MAINTAINER-01').status, 'human_review');

  const humanFindingResults = new Map(
    perGateResults(gates, ['maintainer-review.md is incomplete.'])
      .map((result) => [result.gateId, result])
  );
  assert.equal(humanFindingResults.get('G-MAINTAINER-01').status, 'human_review');
  assert.match(humanFindingResults.get('G-MAINTAINER-01').errors.join('\n'), /is incomplete/);
});

test('independent completion claims require target-bound concrete check evidence', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'generic-claim-evidence-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  writeJson(join(packetDir, 'evidence', 'independent-verification', 'claim-evidence.json'), {
    targetBaseUrl: 'https://target.example',
    status: 200
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /bound to its claimId, gate, gateId, target, checkedAt time, and concrete passing checks/);
});

test('blind completion evidence fails closed on missing declarations, all-N/A checks, and copied captures', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-fail-closed-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    delete blind.reviewer.runtimeOrTool;
    for (const review of blind.routeViewportReviews) {
      for (const check of Object.keys(review.checks)) {
        review.checks[check] = 'not_applicable';
      }
    }
  });
  const evidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  for (const name of ['target-desktop.png', 'source-mobile.png', 'target-mobile.png']) {
    cpSync(join(evidenceDir, 'source-desktop.png'), join(evidenceDir, name));
  }

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /named fresh verifier|reviewer is fresh/);
  assert.match(report.errors.join('\n'), /actualRequestedOutcome must be pass/);
  assert.match(report.errors.join('\n'), /duplicates the bytes/);
  assert.match(report.errors.join('\n'), /dimensions do not match its mobile viewport/);
});

test('blind route comparisons cannot use the target as source truth', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-source-as-target-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    for (const review of blind.routeViewportReviews) {
      review.sourceTruthReference = 'https://target.example/';
    }
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /sourceTruthReference must use the declared source origin/);
});

test('blind review cannot treat an external blocker as an accepted primary-route omission', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-external-blocker-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const routeMatrix = liveRouteMatrix('https://target.example');
  routeMatrix.primaryRoutes.push({
    sourcePath: '/about',
    targetPath: '/about',
    sourceIntent: 'Source about page',
    targetIntent: 'Target about page',
    matchesBrowserRenderedSource: true,
    accepted: true,
    notes: ''
  });
  writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    blind.routeCoverage = {
      strategy: 'representative_sample_with_rationale',
      primaryRoutesReviewed: ['/'],
      omittedPrimaryRoutes: [{
        route: '/about',
        disposition: 'external_blocker',
        rationale: 'The route could not be inspected.',
        acceptedBy: ''
      }],
      notes: ''
    };
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.errors.join('\n'),
    /external_blocker requires missingInput and nextAction|requires a rationale.*concrete packet-local evidence/i
  );
});

test('packet verification normalizes evidenced external blockers without authorizing completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-external-pause-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    blind.productDefects = [{
      id: 'DEF-EXT-1',
      severity: 'high',
      title: 'Provider credentials are unavailable',
      briefExpectation: 'The provider-backed behavior can be exercised.',
      sourceTruthEvidence: 'source-desktop.png',
      targetFinding: 'The verifier cannot exercise the provider without an owner-issued credential.',
      evidence: ['target-desktop.png'],
      recommendedFix: 'Supply the credential and rerun the provider behavior check.',
      status: 'external_blocker',
      resolvedByReviewPassId: '',
      acceptedBy: '',
      acceptedReason: 'The credential can be issued only by the external provider account owner.',
      missingInput: 'An owner-issued provider API credential.',
      nextAction: 'The owner supplies the credential; the agent then refreshes evidence and reruns verification.'
    }];
    blind.summary.verdict = 'blocked';
    blind.summary.completionState = 'blocked';
    blind.summary.externalBlockerIssueCount = 1;
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.equal(report.completionEvidence.externalBlockersOnly, true);
  assert.equal(report.completionEvidence.externalBlockers.length, 1);
  assert.deepEqual(report.completionEvidence.externalBlockers[0], {
    attemptedEvidence: ['target-desktop.png'],
    code: 'blind.defect.DEF-EXT-1',
    message: 'Provider credentials are unavailable',
    missingInput: 'An owner-issued provider API credential.',
    nextAction: 'The owner supplies the credential; the agent then refreshes evidence and reruns verification.',
    origin: 'packet-verifier:blind-adversarial-review.productDefects[0]',
    resolutionClass: 'external',
    verifierConfirmedExternal: true
  });

  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    blind.productDefects[0].id = 'unstable id';
  });
  const unstableIdReport = await validatePacket({ packetDir });
  assert.equal(unstableIdReport.valid, false);
  assert.match(unstableIdReport.errors.join('\n'), /requires a stable alphanumeric id/);
});

test('blind accepted-out-of-scope dispositions require an owner and reconciled summary counts', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-accepted-scope-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const acceptedDefect = {
    id: 'DEF-OUT-1',
    severity: 'medium',
    title: 'Known source-only behavior',
    briefExpectation: 'The behavior would normally be rebuilt.',
    sourceTruthEvidence: 'source-desktop.png',
    targetFinding: 'The target intentionally omits it.',
    evidence: ['target-desktop.png'],
    recommendedFix: 'Rebuild it if scope changes.',
    status: 'accepted_out_of_scope',
    resolvedByReviewPassId: '',
    acceptedBy: 'Fixture Owner',
    acceptedReason: 'Explicitly excluded from this rebuild.'
  };
  const cases = [
    {
      name: 'omission-missing-owner',
      expected: /accepted_out_of_scope.*acceptedBy|acceptedBy.*accepted_out_of_scope/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
          routeMatrix.primaryRoutes.push({
            sourcePath: '/about',
            targetPath: '/about',
            sourceIntent: 'Source about page',
            targetIntent: 'Target about page',
            matchesBrowserRenderedSource: true,
            accepted: true,
            notes: ''
          });
        });
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.routeCoverage = {
            strategy: 'representative_sample_with_rationale',
            primaryRoutesReviewed: ['/'],
            omittedPrimaryRoutes: [{
              route: '/about',
              disposition: 'accepted_out_of_scope',
              rationale: 'The owner allegedly excluded this route.',
              acceptedBy: ''
            }],
            notes: ''
          };
        });
      }
    },
    {
      name: 'defect-missing-owner',
      expected: /accepted_out_of_scope.*(?:acceptedBy|acceptedReason)|(?:acceptedBy|acceptedReason).*accepted_out_of_scope/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.productDefects = [{ ...acceptedDefect, acceptedBy: '', acceptedReason: '' }];
          blind.summary.acceptedOutOfScopeIssueCount = 1;
        });
      }
    },
    {
      name: 'summary-count-mismatch',
      expected: /summary\.acceptedOutOfScopeIssueCount must match/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.productDefects = [acceptedDefect];
          blind.summary.acceptedOutOfScopeIssueCount = 0;
        });
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false, name);
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.errors.join('\n'), expected, name);
  }
});

test('browser completion evidence requires real public and editor screenshots', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'browser-missing-screenshots-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    browser.publicRouteChecks[0].sourceScreenshot = 'evidence/browser/missing-source.png';
    browser.editorWorkflowChecks[0].formScreenshot = 'evidence/browser/missing-editor.png';
  });
  attachFixtureReviewHandoff(packetDir, 'https://target.example');

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.packetCompletionReady, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /browser-evidence\.json/);
});

test('browser completion evidence requires route-bound in-browser axe results with no WCAG violations', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'browser-accessibility-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'not-in-browser',
      expected: /passing in-browser axe-core WCAG 2\.2 AA check/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
        browser.publicRouteChecks[0].accessibilityCheck.executedInBrowser = false;
      })
    },
    {
      name: 'wrong-route',
      expected: /bind the reviewed target route to a real browser environment/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'evidence/browser/axe-home-desktop.json'), (axe) => {
        axe.url = 'https://target.example/wrong';
      })
    },
    {
      name: 'wcag-violation',
      expected: /unresolved WCAG A\/AA violations: color-contrast/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'evidence/browser/axe-home-desktop.json'), (axe) => {
        axe.violations = [{
          id: 'color-contrast',
          impact: 'serious',
          tags: ['wcag2aa', 'wcag143'],
          nodes: [{ target: ['.notice a'], html: '<a>Notice</a>', failureSummary: 'Insufficient contrast.' }]
        }];
      })
    },
    {
      name: 'partial-rule-scope',
      expected: /ruleScope and report toolOptions\.runOnly must include wcag2aa/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
          browser.publicRouteChecks[0].accessibilityCheck.ruleScope = {
            mode: 'wcag_tags',
            tags: ['wcag2a'],
            accepted: true
          };
        });
        mutateJson(join(packetDir, 'evidence/browser/axe-home-desktop.json'), (axe) => {
          axe.toolOptions.runOnly = { type: 'tag', values: ['wcag2a'] };
        });
      }
    },
    {
      name: 'empty-rule-results',
      expected: /has no evaluated axe rules/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'evidence/browser/axe-home-desktop.json'), (axe) => {
        axe.passes = [];
        axe.violations = [];
        axe.incomplete = [];
        axe.inapplicable = [];
      })
    },
    {
      name: 'query-state-mismatch',
      expected: /bind the reviewed target route to a real browser environment/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
          browser.publicRouteChecks[0].targetUrl = 'https://target.example/?state=claimed';
          browser.publicRouteChecks[0].targetFinalUrl = 'https://target.example/?state=claimed';
        });
        mutateJson(join(packetDir, 'evidence/browser/axe-home-desktop.json'), (axe) => {
          axe.url = 'https://target.example/?state=other';
        });
      }
    },
    {
      name: 'undispositioned-wcag-incomplete',
      expected: /incomplete WCAG result color-contrast.*needs a matching rationale and packet-local disposition evidence/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'evidence/browser/axe-home-desktop.json'), (axe) => {
        axe.incomplete = [{
          id: 'color-contrast',
          impact: 'serious',
          tags: ['wcag2aa', 'wcag143'],
          nodes: [{ target: ['.gradient-link'], html: '<a class="gradient-link">Link</a>' }]
        }];
      })
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }

  const realWcagTagsPacket = join(temp, 'real-axe-wcag-tags');
  cpSync(canonicalPacket, realWcagTagsPacket, { recursive: true });
  const realWcagTags = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
  mutateJson(join(realWcagTagsPacket, 'browser-evidence.json'), (browser) => {
    for (const check of browser.publicRouteChecks) {
      check.accessibilityCheck.ruleScope = { mode: 'wcag_tags', tags: realWcagTags, accepted: true };
    }
  });
  for (const viewport of ['desktop', 'mobile']) {
    mutateJson(join(realWcagTagsPacket, `evidence/browser/axe-home-${viewport}.json`), (axe) => {
      axe.toolOptions.runOnly = viewport === 'mobile'
        ? realWcagTags
        : { type: 'tag', values: realWcagTags };
    });
  }
  refreshCaptureEvidenceBindings(realWcagTagsPacket);
  attachFixtureReviewHandoff(realWcagTagsPacket, 'https://target.example');
  const realWcagTagsReport = await validatePacket({ packetDir: realWcagTagsPacket });
  assert.equal(
    realWcagTagsReport.completionEvidence.packetSupportsCompletion,
    true,
    realWcagTagsReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const dispositionedPacket = join(temp, 'dispositioned-wcag-incomplete');
  cpSync(canonicalPacket, dispositionedPacket, { recursive: true });
  mutateJson(join(dispositionedPacket, 'evidence/browser/axe-home-desktop.json'), (axe) => {
    axe.incomplete = [{
      id: 'color-contrast',
      impact: 'serious',
      tags: ['wcag2aa', 'wcag143'],
      nodes: [{ target: ['.gradient-link'], html: '<a class="gradient-link">Link</a>' }]
    }];
  });
  writeJson(join(dispositionedPacket, 'evidence/browser/axe-incomplete-review.json'), {
    schemaVersion: 'public-kit.axe-incomplete-disposition.1',
    checkedAt: testCheckedAt,
    targetUrl: 'https://target.example/',
    ruleId: 'color-contrast',
    target: ['.gradient-link'],
    disposition: 'manual_pass',
    result: 'pass',
    observation: 'Manual computed-style review confirmed a passing contrast ratio across the gradient.'
  });
  mutateJson(join(dispositionedPacket, 'browser-evidence.json'), (browser) => {
    browser.publicRouteChecks[0].accessibilityCheck.incompleteDispositions = [{
      ruleId: 'color-contrast',
      target: ['.gradient-link'],
      disposition: 'manual_pass',
      rationale: 'The automated engine could not resolve the gradient; manual browser measurement passed.',
      evidence: 'evidence/browser/axe-incomplete-review.json'
    }];
  });
  refreshCaptureEvidenceBindings(dispositionedPacket);
  attachFixtureReviewHandoff(dispositionedPacket, 'https://target.example');
  const dispositioned = await validatePacket({ packetDir: dispositionedPacket });
  assert.equal(
    dispositioned.completionEvidence.packetSupportsCompletion,
    true,
    dispositioned.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const mismatchedDispositionPacket = join(temp, 'mismatched-incomplete-evidence');
  cpSync(dispositionedPacket, mismatchedDispositionPacket, { recursive: true });
  mutateJson(join(mismatchedDispositionPacket, 'evidence/browser/axe-incomplete-review.json'), (evidence) => {
    evidence.target = ['.different-link'];
  });
  const mismatchedDisposition = await validatePacket({ packetDir: mismatchedDispositionPacket });
  assert.equal(mismatchedDisposition.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    mismatchedDisposition.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /needs a matching rationale and packet-local disposition evidence/i
  );
});

test('anonymous public forms require submissions, outcome handling, and a vendor-neutral abuse-protection disposition', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'anonymous-form-readiness-'));
  const passingPacket = join(temp, 'passing');
  copyTemplatePacket(passingPacket);
  writeJson(join(passingPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(passingPacket, 'https://target.example');
  addAnonymousContactFormEvidence(passingPacket, 'https://target.example');

  const passing = await validatePacket({ packetDir: passingPacket });
  assert.equal(
    passing.completionEvidence.packetSupportsCompletion,
    true,
    passing.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const twoFormsPacket = join(temp, 'two-forms-one-route');
  cpSync(passingPacket, twoFormsPacket, { recursive: true });
  mutateJson(join(twoFormsPacket, 'source-audit.json'), (sourceAudit) => {
    sourceAudit.formsAndIntegrations.push({
      ...structuredClone(sourceAudit.formsAndIntegrations[0]),
      formKey: 'newsletter-footer',
      purpose: 'newsletter',
      expectedOutcome: 'provider_handoff'
    });
  });
  mutateJson(join(twoFormsPacket, 'pattern-map.json'), (patternMap) => {
    patternMap.forms.push({
      ...structuredClone(patternMap.forms[0]),
      formKey: 'newsletter-footer',
      purpose: 'newsletter',
      drupalOwner: 'external_provider',
      expectedOutcome: 'provider_handoff'
    });
  });
  mutateJson(join(twoFormsPacket, 'browser-evidence.json'), (browser) => {
    const second = structuredClone(browser.anonymousFormChecks[0]);
    second.formKey = 'newsletter-footer';
    second.purpose = 'newsletter';
    second.drupalOwner = 'external_provider';
    second.outcome = { mode: 'provider_handoff', evidence: 'evidence/browser/newsletter-outcome.json' };
    second.abuseProtection = {
      mode: 'provider_managed',
      dispositionVerified: true,
      rationale: 'The provider manages anonymous abuse controls.',
      evidence: 'evidence/browser/newsletter-abuse.json'
    };
    browser.anonymousFormChecks.push(second);
  });
  mutateJson(join(twoFormsPacket, 'independent-verification.json'), (independent) => {
    const second = structuredClone(independent.anonymousFormChecks[0]);
    second.formKey = 'newsletter-footer';
    second.purpose = 'newsletter';
    second.modeledOwner = 'external_provider';
    second.browserOwner = 'external_provider';
    second.expectedOutcome = 'provider_handoff';
    second.browserOutcome = 'provider_handoff';
    second.outcomeEvidence = 'evidence/browser/newsletter-outcome.json';
    second.abuseProtectionDisposition = 'provider_managed';
    second.abuseProtectionEvidence = 'evidence/browser/newsletter-abuse.json';
    independent.anonymousFormChecks.push(second);
  });
  writeJson(join(twoFormsPacket, 'evidence/browser/newsletter-outcome.json'), {
    schemaVersion: 'public-kit.form-outcome-evidence.1', checkedAt: testCheckedAt,
    formKey: 'newsletter-footer', targetUrl: 'https://target.example/contact',
    mode: 'provider_handoff', result: 'pass', handlerOwner: 'Fixture provider adapter',
    resultReference: 'synthetic-handoff-1', provider: 'Fixture provider', observation: 'Synthetic handoff completed.'
  });
  writeJson(join(twoFormsPacket, 'evidence/browser/newsletter-abuse.json'), {
    schemaVersion: 'public-kit.form-abuse-evidence.1', checkedAt: testCheckedAt,
    formKey: 'newsletter-footer', targetUrl: 'https://target.example/contact',
    mode: 'provider_managed', result: 'pass', provider: 'Fixture provider',
    enforcementVerified: true, observation: 'Provider-managed protection was verified.'
  });
  attachFixtureReviewHandoff(twoFormsPacket, 'https://target.example');
  const twoForms = await validatePacket({ packetDir: twoFormsPacket });
  assert.equal(
    twoForms.completionEvidence.packetSupportsCompletion,
    true,
    twoForms.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const duplicateFormKeyPacket = join(temp, 'duplicate-form-key');
  cpSync(twoFormsPacket, duplicateFormKeyPacket, { recursive: true });
  mutateJson(join(duplicateFormKeyPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[1].formKey = 'contact-main';
  });
  const duplicateFormKey = await validatePacket({ packetDir: duplicateFormKeyPacket });
  assert.equal(duplicateFormKey.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    duplicateFormKey.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /unique, non-empty formKey/i
  );

  const wrongOutcomeEvidencePacket = join(temp, 'wrong-outcome-evidence-binding');
  cpSync(passingPacket, wrongOutcomeEvidencePacket, { recursive: true });
  mutateJson(join(wrongOutcomeEvidencePacket, 'evidence/browser/form-outcome.json'), (evidence) => {
    evidence.formKey = 'another-form';
  });
  const wrongOutcomeEvidence = await validatePacket({ packetDir: wrongOutcomeEvidencePacket });
  assert.equal(wrongOutcomeEvidence.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    wrongOutcomeEvidence.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /outcome-appropriate handler/i
  );

  const storageOnlyPacket = join(temp, 'storage-only');
  cpSync(passingPacket, storageOnlyPacket, { recursive: true });
  mutateJson(join(storageOnlyPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].outcome.mode = 'drupal_submission_storage';
  });
  const storageOnly = await validatePacket({ packetDir: storageOnlyPacket });
  assert.equal(storageOnly.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    storageOnly.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /outcome-appropriate handler for form \/contact/i
  );

  const downgradedModelPacket = join(temp, 'downgraded-model-outcome');
  cpSync(passingPacket, downgradedModelPacket, { recursive: true });
  mutateJson(join(downgradedModelPacket, 'pattern-map.json'), (patternMap) => {
    patternMap.forms[0].expectedOutcome = 'submission_storage';
  });
  mutateJson(join(downgradedModelPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].outcome.mode = 'drupal_submission_storage';
  });
  const downgradedModel = await validatePacket({ packetDir: downgradedModelPacket });
  assert.equal(downgradedModel.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    downgradedModel.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /without changing its source purpose or expectedOutcome/i
  );

  const browserOwnerMismatchPacket = join(temp, 'browser-owner-mismatch');
  cpSync(passingPacket, browserOwnerMismatchPacket, { recursive: true });
  mutateJson(join(browserOwnerMismatchPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].drupalOwner = 'contact_form';
  });
  const browserOwnerMismatch = await validatePacket({ packetDir: browserOwnerMismatchPacket });
  assert.equal(browserOwnerMismatch.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    browserOwnerMismatch.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /must preserve the modeled purpose and Drupal\/provider owner/i
  );

  const implicitOtherPacket = join(temp, 'other-is-not-a-wildcard');
  cpSync(passingPacket, implicitOtherPacket, { recursive: true });
  mutateJson(join(implicitOtherPacket, 'source-audit.json'), (sourceAudit) => {
    sourceAudit.formsAndIntegrations[0].expectedOutcome = 'other';
  });
  mutateJson(join(implicitOtherPacket, 'pattern-map.json'), (patternMap) => {
    patternMap.forms[0].expectedOutcome = 'other';
  });
  const implicitOther = await validatePacket({ packetDir: implicitOtherPacket });
  assert.equal(implicitOther.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    implicitOther.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /outcome-appropriate handler for form \/contact/i
  );

  const explicitOtherPacket = join(temp, 'explicit-other-outcome');
  cpSync(implicitOtherPacket, explicitOtherPacket, { recursive: true });
  mutateJson(join(explicitOtherPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].outcome.mode = 'other';
  });
  mutateJson(join(explicitOtherPacket, 'independent-verification.json'), (independent) => {
    independent.anonymousFormChecks[0].expectedOutcome = 'other';
    independent.anonymousFormChecks[0].browserOutcome = 'other';
  });
  mutateJson(join(explicitOtherPacket, 'evidence/browser/form-outcome.json'), (evidence) => {
    evidence.mode = 'other';
    evidence.rationale = 'The explicit fixture outcome is intentionally custom.';
  });
  attachFixtureReviewHandoff(explicitOtherPacket, 'https://target.example');
  const explicitOther = await validatePacket({ packetDir: explicitOtherPacket });
  assert.equal(
    explicitOther.completionEvidence.packetSupportsCompletion,
    true,
    explicitOther.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const missingModelPacket = join(temp, 'missing-model');
  cpSync(passingPacket, missingModelPacket, { recursive: true });
  mutateJson(join(missingModelPacket, 'pattern-map.json'), (patternMap) => {
    patternMap.forms = [];
  });
  const missingModel = await validatePacket({ packetDir: missingModelPacket });
  assert.equal(missingModel.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    missingModel.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /map every audited anonymous public submission form/i
  );

  const missingAbuseProtectionPacket = join(temp, 'missing-abuse-protection');
  cpSync(passingPacket, missingAbuseProtectionPacket, { recursive: true });
  mutateJson(join(missingAbuseProtectionPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].abuseProtection = {
      mode: '',
      dispositionVerified: false,
      rationale: '',
      evidence: ''
    };
  });
  const missingAbuseProtection = await validatePacket({ packetDir: missingAbuseProtectionPacket });
  assert.equal(missingAbuseProtection.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    missingAbuseProtection.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /vendor-neutral abuse-protection disposition with evidence/i
  );

  const localExceptionPacket = join(temp, 'local-only-exception');
  cpSync(passingPacket, localExceptionPacket, { recursive: true });
  mutateJson(join(localExceptionPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].abuseProtection = {
      mode: 'local_only_exception',
      dispositionVerified: true,
      rationale: 'This DDEV-only review target is not publicly reachable; a launch target must select an abuse control.',
      evidence: 'evidence/browser/form-local-abuse-exception.json'
    };
  });
  mutateJson(join(localExceptionPacket, 'independent-verification.json'), (independent) => {
    independent.anonymousFormChecks[0].abuseProtectionDisposition = 'local_only_exception';
    independent.anonymousFormChecks[0].abuseProtectionRationale = 'This DDEV-only review target remains a launch gap.';
    independent.anonymousFormChecks[0].abuseProtectionEvidence = 'evidence/browser/form-local-abuse-exception.json';
  });
  attachFixtureReviewHandoff(localExceptionPacket, 'https://target.example');
  const localException = await validatePacket({ packetDir: localExceptionPacket });
  assert.equal(
    localException.completionEvidence.packetSupportsCompletion,
    true,
    localException.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const localDdevExceptionPacket = join(temp, 'local-ddev-exception');
  cpSync(localExceptionPacket, localDdevExceptionPacket, { recursive: true });
  mutateJson(join(localDdevExceptionPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].targetUrl = 'https://fixture.ddev.site/contact';
  });
  mutateJson(join(localDdevExceptionPacket, 'evidence/browser/form-local-abuse-exception.json'), (evidence) => {
    evidence.targetUrl = 'https://fixture.ddev.site/contact';
  });
  mutateJson(join(localDdevExceptionPacket, 'evidence/browser/form-outcome.json'), (evidence) => {
    evidence.targetUrl = 'https://fixture.ddev.site/contact';
  });
  attachFixtureReviewHandoff(localDdevExceptionPacket, 'https://target.example');
  const localDdevException = await validatePacket({ packetDir: localDdevExceptionPacket });
  assert.equal(
    localDdevException.completionEvidence.packetSupportsCompletion,
    true,
    localDdevException.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const rateLimitedPacket = join(temp, 'configured-rate-limiting');
  cpSync(passingPacket, rateLimitedPacket, { recursive: true });
  mutateJson(join(rateLimitedPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].abuseProtection = {
      mode: 'configured_rate_limiting',
      dispositionVerified: true,
      rationale: 'Drupal-owned anonymous submission throttling is configured.',
      evidence: 'evidence/browser/form-rate-limiting.json'
    };
  });
  mutateJson(join(rateLimitedPacket, 'independent-verification.json'), (independent) => {
    independent.anonymousFormChecks[0].abuseProtectionDisposition = 'configured_rate_limiting';
    independent.anonymousFormChecks[0].abuseProtectionRationale = 'Drupal-owned anonymous submission throttling is configured.';
    independent.anonymousFormChecks[0].abuseProtectionEvidence = 'evidence/browser/form-rate-limiting.json';
  });
  attachFixtureReviewHandoff(rateLimitedPacket, 'https://target.example');
  const rateLimited = await validatePacket({ packetDir: rateLimitedPacket });
  assert.equal(
    rateLimited.completionEvidence.packetSupportsCompletion,
    true,
    rateLimited.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );

  const undocumentedExceptionPacket = join(temp, 'undocumented-local-only-exception');
  cpSync(localExceptionPacket, undocumentedExceptionPacket, { recursive: true });
  mutateJson(join(undocumentedExceptionPacket, 'browser-evidence.json'), (browser) => {
    browser.anonymousFormChecks[0].abuseProtection.rationale = '';
  });
  const undocumentedException = await validatePacket({ packetDir: undocumentedExceptionPacket });
  assert.equal(undocumentedException.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    undocumentedException.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /vendor-neutral abuse-protection disposition with evidence/i
  );
});

test('separate public collection details require browser proof of visible load-bearing fields', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'detail-route-proof-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    patternMap.structuredContentModel.collectionScope = {
      reviewed: true,
      applies: true,
      reason: 'The source has a public Event collection.'
    };
    patternMap.structuredContentModel.collectionOwnershipLedger = [{
      sourceRoute: '/',
      collectionPattern: 'schedule',
      sourceObject: 'Event',
      sourceItemCount: 1,
      drupalEntityType: 'node',
      contentTypeOrBundle: 'event',
      requiredFields: ['title', 'field_start'],
      collectionOwner: 'view',
      viewDisplayOrConfig: 'views.view.events',
      detailRouteOwner: 'entity_view_display',
      drupalOwnerConfigId: 'core.entity_view_display.node.event.full',
      detailRouteMode: 'separate_public_route',
      representativeDetailSourcePath: '/events/source-event',
      representativeDetailTargetPath: '/events/target-event',
      detailLoadBearingFields: ['title', 'field_start'],
      detailRouteRationale: '',
      editorAddRowEvidence: 'evidence/blind-adversarial-review/editor-task.json',
      exceptionRationale: '',
      accepted: true,
      notes: 'Events have public details.'
    }];
  });
  mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
    routeMatrix.routes.push({
      sourcePath: '/events/source-event',
      sourceStatus: 200,
      sourceFinalPath: '/events/source-event',
      sourceTitle: 'Source event',
      sourceH1: 'Source event',
      targetPath: '/events/target-event',
      targetStatus: 200,
      targetFinalPath: '/events/target-event',
      targetTitle: 'Target event',
      targetH1: 'Target event',
      expectedRedirect: false,
      accepted: true,
      notes: 'Representative Event detail.'
    });
  });

  const report = await validatePacket({ packetDir });
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields and rendered SEO for collection Event/i
  );

  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    const detail = structuredClone(browser.publicRouteChecks[0]);
    detail.routeRole = 'detail';
    detail.sourceUrl = 'https://source.example/events/source-event';
    detail.sourceFinalUrl = 'https://source.example/events/source-event';
    detail.targetUrl = 'https://target.example/events/target-event';
    detail.targetFinalUrl = 'https://target.example/events/target-event';
    detail.renderedSignals.sourceTitle = 'Source event';
    detail.renderedSignals.targetTitle = 'Target event';
    detail.renderedSignals.sourceH1 = 'Source event';
    detail.renderedSignals.targetH1 = 'Target event';
    detail.renderedSeoSignals.targetCanonicalUrl = 'https://target.example/events/target-event';
    detail.renderedSeoSignals.targetMetaDescription = 'Target event detail.';
    detail.accessibilityCheck.report = 'evidence/browser/axe-event-owner.json';
    detail.detailContentSignals = {
      contentTypeOrBundle: 'event',
      drupalOwner: 'custom_controller',
      drupalOwnerConfigId: 'mccall.event_controller',
      ownerDeviation: { applies: false, rationale: '', evidence: '' },
      loadBearingFields: [
        {
          field: 'title', sourceSignal: 'Source event', targetSignal: 'Target event', selector: 'h1',
          computedVisibility: { matchedElementCount: 1, display: 'block', visibility: 'visible', opacity: '1', hiddenAttribute: false, ariaHidden: false, boundingWidth: 600, boundingHeight: 48, text: 'Target event' },
          visible: true
        },
        {
          field: 'field_start', sourceSignal: 'July 10, 2026', targetSignal: 'July 10, 2026', selector: '.event-date',
          computedVisibility: { matchedElementCount: 1, display: 'block', visibility: 'visible', opacity: '1', hiddenAttribute: false, ariaHidden: false, boundingWidth: 220, boundingHeight: 24, text: 'July 10, 2026' },
          visible: true
        }
      ],
      accepted: true
    };
    browser.publicRouteChecks.push(detail);
  });
  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.detailRouteChecks = [{
      sourceRoute: '/events/source-event',
      targetRoute: '/events/target-event',
      contentTypeOrBundle: 'event',
      declaredDetailOwner: 'entity_view_display',
      observedDetailOwner: 'custom_controller',
      drupalOwnerConfigId: 'mccall.event_controller',
      ownerDeviationEvidence: '',
      loadBearingFieldsVerified: ['title', 'field_start'],
      status: 'pass',
      evidence: 'claim-evidence.json'
    }];
  });
  writeJson(join(packetDir, 'evidence/browser/axe-event-owner.json'), {
    testEngine: { name: 'axe-core', version: '4.10.2' },
    toolOptions: { runOnly: null, rules: {} },
    testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: 1280, windowHeight: 800 },
    timestamp: testCheckedAt,
    url: 'https://target.example/events/target-event',
    passes: [],
    violations: [],
    incomplete: [],
    inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
  });
  const ownerMismatch = await validatePacket({ packetDir });
  assert.match(
    ownerMismatch.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /detail owner\/config must match Drupal readback and collection Event owner entity_view_display/i
  );

  writeJson(join(packetDir, 'evidence/browser/detail-owner-deviation.json'), {
    checkedAt: testCheckedAt,
    route: '/events/target-event',
    declaredOwner: 'entity_view_display',
    actualOwner: 'custom_controller',
    observation: 'The reviewed exception explains the alternate owner.'
  });
  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    const detail = browser.publicRouteChecks.find((check) => check.routeRole === 'detail');
    detail.detailContentSignals.ownerDeviation = {
      applies: true,
      rationale: 'A maintained capability controller owns this provider-backed detail by reviewed exception.',
      evidence: 'evidence/browser/detail-owner-deviation.json'
    };
  });
  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.detailRouteChecks[0].ownerDeviationEvidence = 'evidence/browser/detail-owner-deviation.json';
  });
  const ownerDeviation = await validatePacket({ packetDir });
  assert.doesNotMatch(
    ownerDeviation.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /detail owner\/config must match Drupal readback and collection Event owner entity_view_display/i
  );

  const exactOwnerPacket = join(temp, 'exact-detail-owner-readback');
  cpSync(packetDir, exactOwnerPacket, { recursive: true });
  mutateJson(join(exactOwnerPacket, 'browser-evidence.json'), (browser) => {
    const signals = browser.publicRouteChecks.find((check) => check.routeRole === 'detail').detailContentSignals;
    signals.drupalOwner = 'entity_view_display';
    signals.drupalOwnerConfigId = 'core.entity_view_display.node.event.full';
    signals.ownerDeviation = { applies: false, rationale: '', evidence: '' };
  });
  mutateJson(join(exactOwnerPacket, 'independent-verification.json'), (independent) => {
    independent.detailRouteChecks[0].observedDetailOwner = 'entity_view_display';
    independent.detailRouteChecks[0].drupalOwnerConfigId = 'core.entity_view_display.node.event.full';
    independent.detailRouteChecks[0].ownerDeviationEvidence = '';
  });
  mutateJson(join(exactOwnerPacket, 'drupal-readback.json'), (readback) => {
    readback.content.viewDisplays.push('core.entity_view_display.node.event.full');
  });
  const exactOwner = await validatePacket({ packetDir: exactOwnerPacket });
  assert.doesNotMatch(
    exactOwner.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /detail owner\/config|owner\/config-bound passing detailRouteChecks row/i
  );

  const listingOnlyFieldPacket = join(temp, 'listing-only-public-field');
  cpSync(exactOwnerPacket, listingOnlyFieldPacket, { recursive: true });
  mutateJson(join(listingOnlyFieldPacket, 'field-output-matrix.json'), (matrix) => {
    matrix.bundles.push({
      entityType: 'node',
      bundle: 'event',
      fields: [{
        machineName: 'field_teaser', editorLabel: 'Teaser', required: false,
        fieldType: 'string', widget: 'string_textfield', formatter: 'string',
        publicRenderLocations: ['/events'], affectsAnonymousOutput: true,
        containsRawPresentationImplementation: false, presentationBoundary: 'content_fact',
        editorOnlyRationale: '', accepted: true, notes: 'Listing-only teaser.'
      }]
    });
  });
  const listingOnlyField = await validatePacket({ packetDir: listingOnlyFieldPacket });
  assert.doesNotMatch(
    listingOnlyField.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields/i
  );

  const declaredDetailLocationPacket = join(temp, 'declared-detail-public-field');
  cpSync(exactOwnerPacket, declaredDetailLocationPacket, { recursive: true });
  mutateJson(join(declaredDetailLocationPacket, 'field-output-matrix.json'), (matrix) => {
    matrix.bundles.push({
      entityType: 'node', bundle: 'event', fields: [{
        machineName: 'field_listing_only', editorLabel: 'Listing only', required: false,
        fieldType: 'string', widget: 'string_textfield', formatter: 'string',
        publicRenderLocations: ['/events'], affectsAnonymousOutput: true,
        containsRawPresentationImplementation: false, presentationBoundary: 'content_fact',
        editorOnlyRationale: '', accepted: true, notes: 'First split bundle row.'
      }]
    });
    matrix.bundles.push({
      entityType: 'node', bundle: 'event', fields: [{
        machineName: 'field_public_detail', editorLabel: 'Public detail', required: false,
        fieldType: 'string', widget: 'string_textfield', formatter: 'string',
        publicRenderLocations: ['canonical_detail'], affectsAnonymousOutput: true,
        containsRawPresentationImplementation: false, presentationBoundary: 'content_fact',
        editorOnlyRationale: '', accepted: true, notes: 'Explicit detail output.'
      }]
    });
  });
  const declaredDetailLocation = await validatePacket({ packetDir: declaredDetailLocationPacket });
  assert.match(
    declaredDetailLocation.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields/i
  );

  const hiddenFieldPacket = join(temp, 'hidden-detail-field');
  cpSync(packetDir, hiddenFieldPacket, { recursive: true });
  mutateJson(join(hiddenFieldPacket, 'browser-evidence.json'), (browser) => {
    const field = browser.publicRouteChecks.find((check) => check.routeRole === 'detail')
      .detailContentSignals.loadBearingFields.find((record) => record.field === 'field_start');
    field.computedVisibility.display = 'none';
  });
  const hiddenField = await validatePacket({ packetDir: hiddenFieldPacket });
  assert.match(
    hiddenField.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields/i
  );

  const broadSelectorPacket = join(temp, 'broad-detail-selector');
  cpSync(exactOwnerPacket, broadSelectorPacket, { recursive: true });
  mutateJson(join(broadSelectorPacket, 'browser-evidence.json'), (browser) => {
    const fields = browser.publicRouteChecks.find((check) => check.routeRole === 'detail').detailContentSignals.loadBearingFields;
    fields[0].selector = 'body';
    fields[0].computedVisibility.text = 'Target event July 10, 2026';
  });
  const broadSelector = await validatePacket({ packetDir: broadSelectorPacket });
  assert.match(
    broadSelector.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields/i
  );

  const reusedSelectorPacket = join(temp, 'reused-detail-selector');
  cpSync(exactOwnerPacket, reusedSelectorPacket, { recursive: true });
  mutateJson(join(reusedSelectorPacket, 'browser-evidence.json'), (browser) => {
    const fields = browser.publicRouteChecks.find((check) => check.routeRole === 'detail').detailContentSignals.loadBearingFields;
    fields[1].selector = fields[0].selector;
  });
  const reusedSelector = await validatePacket({ packetDir: reusedSelectorPacket });
  assert.match(
    reusedSelector.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields/i
  );

  const underdeclaredFieldPacket = join(temp, 'underdeclared-detail-field');
  cpSync(packetDir, underdeclaredFieldPacket, { recursive: true });
  mutateJson(join(underdeclaredFieldPacket, 'pattern-map.json'), (patternMap) => {
    patternMap.structuredContentModel.collectionOwnershipLedger[0].detailLoadBearingFields = ['title'];
  });
  const underdeclaredField = await validatePacket({ packetDir: underdeclaredFieldPacket });
  assert.match(
    underdeclaredField.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /representative detail route with visible load-bearing fields/i
  );

  const independentOwnerPacket = join(temp, 'independent-detail-owner-mismatch');
  cpSync(packetDir, independentOwnerPacket, { recursive: true });
  mutateJson(join(independentOwnerPacket, 'independent-verification.json'), (independent) => {
    independent.detailRouteChecks[0].drupalOwnerConfigId = 'different.owner.config';
  });
  const independentOwner = await validatePacket({ packetDir: independentOwnerPacket });
  assert.match(
    independentOwner.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /owner\/config-bound passing detailRouteChecks row/i
  );
});

test('live verification fetches non-primary representatives without treating body substrings as visibility proof', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/events/target-event') {
        const origin = `http://${request.headers.host}`;
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(`<!doctype html><html><head><title>Target event</title><link rel="canonical" href="${origin}/events/target-event"><meta name="description" content="Target event detail."></head><body><h1>Target event</h1><p>The date was accidentally omitted.</p></body></html>`);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'representative-live-route-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      writeFileSync(
        join(packetDir, 'evidence', 'event-route-remap.txt'),
        'The fixture intentionally verifies the target detail without preserving the synthetic source URL.\n'
      );
      mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
        routeMatrix.routes.push({
          sourcePath: '/events/source-event',
          sourceStatus: 200,
          sourceFinalPath: '/events/source-event',
          sourceTitle: 'Source event',
          sourceH1: 'Source event',
          targetPath: '/events/target-event',
          targetStatus: 200,
          targetFinalPath: '/events/target-event',
          targetTitle: 'Target event',
          targetH1: 'Target event',
          expectedRedirect: false,
          noRedirectDisposition: {
            accepted: true,
            acceptedBy: 'Fixture owner',
            rationale: 'The synthetic source fixture URL is not part of the target route contract.',
            evidence: 'evidence/event-route-remap.txt'
          },
          routeRole: 'detail',
          accepted: true,
          notes: 'Representative Event detail.'
        });
      });
      mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
        const detail = structuredClone(browser.publicRouteChecks[0]);
        detail.routeRole = 'detail';
        detail.sourceUrl = 'https://source.example/events/source-event';
        detail.sourceFinalUrl = 'https://source.example/events/source-event';
        detail.targetUrl = `${baseUrl}/events/target-event`;
        detail.targetFinalUrl = `${baseUrl}/events/target-event`;
        detail.renderedSignals.sourceTitle = 'Source event';
        detail.renderedSignals.targetTitle = 'Target event';
        detail.renderedSignals.sourceH1 = 'Source event';
        detail.renderedSignals.targetH1 = 'Target event';
        detail.renderedSeoSignals.targetCanonicalUrl = `${baseUrl}/events/target-event`;
        detail.renderedSeoSignals.targetMetaDescription = 'Target event detail.';
        detail.accessibilityCheck.report = 'evidence/browser/axe-event-detail.json';
        detail.detailContentSignals = {
          contentTypeOrBundle: 'event',
          drupalOwner: 'entity_view_display',
          loadBearingFields: [{
            field: 'field_start',
            sourceSignal: 'July 10, 2026',
            targetSignal: 'July 10, 2026',
            visible: true
          }],
          accepted: true
        };
        browser.publicRouteChecks.push(detail);
      });
      writeJson(join(packetDir, 'evidence/browser/axe-event-detail.json'), {
        testEngine: { name: 'axe-core', version: '4.10.2' },
        toolOptions: { runOnly: null, rules: {} },
        testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: 1280, windowHeight: 800 },
        timestamp: testCheckedAt,
        url: `${baseUrl}/events/target-event`,
        passes: [],
        violations: [],
        incomplete: [],
        inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
      });

      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(report.browserRepresentativeRouteChecks.length, 1);
      assert.equal(report.browserRepresentativeRouteChecks[0].passed, true);
      assert.doesNotMatch(report.browserRepresentativeRouteChecks[0].errors.join('\n'), /visible detail signal/i);
      assert.equal(report.liveTargetValid, true);
    }
  );
});

test('live verification preserves and independently checks representative query states', async () => {
  const seen = new Set();
  await withHttpServer(
    (request, response) => {
      if (request.url.startsWith('/search?')) {
        seen.add(request.url);
        const origin = `http://${request.headers.host}`;
        if (new URL(`${origin}${request.url}`).searchParams.get('state') === 'drop') {
          response.writeHead(302, { location: '/search' });
          response.end();
          return;
        }
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(`<!doctype html><html><head><title>Search</title><link rel="canonical" href="${origin}${request.url}"><meta name="description" content="State ${new URL(`${origin}${request.url}`).searchParams.get('state')}"></head><body><h1>Search</h1></body></html>`);
        return;
      }
      if (request.url === '/search') {
        const origin = `http://${request.headers.host}`;
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end(`<!doctype html><html><head><title>Search</title><link rel="canonical" href="${origin}/search?state=drop"><meta name="description" content="State drop"></head><body><h1>Search</h1></body></html>`);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'representative-query-states-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
        routeMatrix.routes.push({
          sourcePath: '/search', sourceStatus: 200, sourceFinalPath: '/search', sourceTitle: 'Search', sourceH1: 'Search',
          targetPath: '/search', targetStatus: 200, targetFinalPath: '/search', targetTitle: 'Search', targetH1: 'Search',
          expectedRedirect: false, routeRole: 'search', accepted: true, notes: 'Query-state fixture.'
        });
      });
      mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
        for (const state of ['a', 'b', 'drop']) {
          const check = structuredClone(browser.publicRouteChecks[0]);
          check.routeRole = 'other';
          check.sourceUrl = `https://source.example/search?state=${state}`;
          check.sourceFinalUrl = check.sourceUrl;
          check.targetUrl = `${baseUrl}/search?state=${state}`;
          check.targetFinalUrl = check.targetUrl;
          check.renderedSignals.sourceTitle = 'Search';
          check.renderedSignals.targetTitle = 'Search';
          check.renderedSignals.sourceH1 = 'Search';
          check.renderedSignals.targetH1 = 'Search';
          check.renderedSeoSignals.targetCanonicalUrl = check.targetUrl;
          check.renderedSeoSignals.targetMetaDescription = `State ${state}`;
          check.accessibilityCheck.report = `evidence/browser/axe-search-${state}.json`;
          browser.publicRouteChecks.push(check);
        }
      });
      for (const state of ['a', 'b', 'drop']) {
        writeJson(join(packetDir, `evidence/browser/axe-search-${state}.json`), {
          testEngine: { name: 'axe-core', version: '4.10.2' }, toolOptions: { runOnly: null, rules: {} },
          testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: 1280, windowHeight: 800 },
          timestamp: testCheckedAt, url: `${baseUrl}/search?state=${state}`,
          passes: [], violations: [], incomplete: [], inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
        });
      }

      const report = await verifyLive({
        packetDir, cwd: repoRoot, environment: {}, targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(report.browserRepresentativeRouteChecks.length, 3);
      assert.equal(report.browserRepresentativeRouteChecks.filter((check) => check.passed).length, 2);
      const droppedState = report.browserRepresentativeRouteChecks.find((check) => !check.passed);
      assert.match(
        droppedState.errors.join('\n'),
        /expected exact representative state \/search\?query-sha256=/i
      );
      assert.doesNotMatch(JSON.stringify(report), /state=(?:a|b|drop)/);
      assert.deepEqual([...seen].sort(), ['/search?state=a', '/search?state=b', '/search?state=drop']);
    }
  );
});

test('live verification fetches and reconciles primary query states exactly', async () => {
  const seen = new Set();
  await withHttpServer(
    (request, response) => {
      if (request.url === '/search?state=drop') {
        seen.add(request.url);
        response.writeHead(302, { location: '/search' });
        response.end();
        return;
      }
      if (request.url?.startsWith('/search')) {
        seen.add(request.url);
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end('<!doctype html><html><head><title>Search</title></head><body><h1>Search</h1></body></html>');
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'primary-query-states-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      for (const state of ['keep', 'drop']) {
        routeMatrix.primaryRoutes.push({
          sourcePath: `/search?state=${state}`,
          targetPath: `/search?state=${state}`,
          routeRole: 'search',
          sourceIntent: `Source search state ${state}.`,
          targetIntent: `Target search state ${state}.`,
          matchesBrowserRenderedSource: true,
          accepted: true,
          notes: 'Exact query-state fixture.'
        });
        routeMatrix.routes.push({
          sourcePath: `/search?state=${state}`,
          targetPath: `/search?state=${state}`,
          routeRole: 'search',
          targetStatus: 200,
          targetFinalPath: `/search?state=${state}`,
          targetTitle: 'Search',
          targetH1: 'Search',
          expectedRedirect: false,
          accepted: true,
          notes: 'Exact query-state fixture.'
        });
      }
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      const queryChecks = report.routeChecks.filter((check) => check.targetPath === '/search');
      assert.equal(queryChecks.length, 2);
      assert.equal(queryChecks.filter((check) => check.passed).length, 1);
      assert.match(queryChecks.find((check) => !check.passed)?.errors.join('\n') ?? '', /expected exact primary state/i);
      assert.deepEqual([...seen].filter((url) => url.includes('?')).sort(), ['/search?state=drop', '/search?state=keep']);
      assert.doesNotMatch(JSON.stringify(report), /state=(?:drop|keep)/);
    }
  );
});

test('imported-body route candidates require exact path-plus-query drift classification', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'imported-body-route-classification-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
    routeMatrix.browserFirstRouteExpansion.candidateRoutesFromImportedContentBodies = [
      '/legacy.aspx?item=one'
    ];
    routeMatrix.sourceRouteDriftClassification = [{
      sourcePath: '/legacy.aspx?item=two',
      sourceStatus: 200,
      classification: 'legacy',
      targetDisposition: 'intentionally_drop',
      targetPath: '',
      ownerDecisionEvidence: 'The other query variant was reviewed separately.',
      accepted: true,
      notes: 'Exact query variant disposition.'
    }];
  });

  const mismatched = await validatePacket({ packetDir });
  assert.equal(mismatched.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    mismatched.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /classify and accept every discovered source route/i
  );

  mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
    routeMatrix.sourceRouteDriftClassification[0].sourcePath = '/legacy.aspx?item=one';
  });
  mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
    independent.routeDriftDispositionChecks = [{
      sourcePath: '/legacy.aspx?item=one',
      disposition: 'intentionally_drop',
      status: 'pass',
      dispositionEvidence: 'The imported-body legacy link was independently reviewed.'
    }];
  });
  attachFixtureReviewHandoff(packetDir, 'https://target.example');
  const classified = await validatePacket({ packetDir });
  assert.equal(
    classified.completionEvidence.packetSupportsCompletion,
    true,
    classified.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );
});

test('noRedirectDisposition fails closed unless acceptance, owner, rationale, and packet evidence are all strong', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'no-redirect-disposition-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const routeMatrix = liveRouteMatrix('https://target.example');
  routeMatrix.routes.push({
    sourcePath: '/legacy?item=one',
    targetPath: '/',
    routeRole: 'homepage',
    targetStatus: 200,
    targetFinalPath: '/',
    targetTitle: 'Target site',
    targetH1: 'Target home',
    expectedRedirect: false,
    noRedirectDisposition: {
      accepted: true,
      acceptedBy: 'Fixture owner',
      rationale: 'The legacy URL is intentionally retired.',
      evidence: 'evidence/missing-approval.txt'
    },
    accepted: true,
    notes: 'Legacy mapping fixture.'
  });
  writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  const missingEvidence = await validatePacket({ packetDir });
  assert.match(
    missingEvidence.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /noRedirectDisposition exceptions must set accepted true.*packet-local evidence/i
  );

  mkdirSync(join(packetDir, 'evidence'), { recursive: true });
  writeFileSync(join(packetDir, 'evidence', 'redirect-approval.txt'), 'Approved by the fixture owner.\n');
  for (const weaken of [
    (disposition) => { disposition.accepted = false; },
    (disposition) => { disposition.acceptedBy = ''; },
    (disposition) => { disposition.rationale = ''; }
  ]) {
    mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
      value.routes[1].noRedirectDisposition = {
        accepted: true,
        acceptedBy: 'Fixture owner',
        rationale: 'The legacy URL is intentionally retired.',
        evidence: 'evidence/redirect-approval.txt'
      };
      weaken(value.routes[1].noRedirectDisposition);
    });
    const weak = await validatePacket({ packetDir });
    assert.match(
      weak.completionEvidence.packetCompletionBlockedReasons.join('\n'),
      /noRedirectDisposition exceptions must set accepted true.*packet-local evidence/i
    );
  }

  mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
    value.routes[1].noRedirectDisposition = {
      accepted: true,
      acceptedBy: 'Fixture owner',
      rationale: 'The legacy URL is intentionally retired.',
      evidence: 'evidence/redirect-approval.txt'
    };
  });
  attachFixtureReviewHandoff(packetDir, 'https://target.example');
  const strong = await validatePacket({ packetDir });
  assert.equal(
    strong.completionEvidence.packetSupportsCompletion,
    true,
    strong.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );
});

test('redirect materialization requires permanent first hop and exact same-origin final path-plus-query', async () => {
  let behavior = 'missing';
  await withHttpServer(
    (request, response) => {
      if (request.url === '/legacy?token=private-source') {
        const destinations = {
          permanent: [301, '/news?view=full'],
          permanent308: [308, '/news?view=full'],
          temporary: [302, '/news?view=full'],
          preserveMethodTemporary: [307, '/news?view=full'],
          wrongQuery: [301, '/news?view=wrong']
        };
        if (destinations[behavior]) {
          response.writeHead(destinations[behavior][0], { location: destinations[behavior][1] });
        } else {
          response.writeHead(404, { 'content-type': 'text/html; charset=utf-8' });
        }
        response.end();
        return;
      }
      if (request.url?.startsWith('/news')) {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        response.end('<!doctype html><html><head><title>News</title></head><body><h1>News</h1></body></html>');
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'redirect-materialization-contract-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.routes.push({
        sourcePath: '/legacy?token=private-source',
        targetPath: '/news?view=full',
        routeRole: 'homepage',
        targetStatus: 200,
        targetFinalPath: '/news?view=full',
        targetTitle: 'News',
        targetH1: 'News',
        expectedRedirect: false,
        accepted: true,
        notes: 'Legacy query mapping fixture.'
      });
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
      const run = () => verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      for (const [scenario, expected] of [
        ['missing', /initial status 404/i],
        ['temporary', /initial status 302/i],
        ['preserveMethodTemporary', /initial status 307/i],
        ['wrongQuery', /expects exact path\+query/i]
      ]) {
        behavior = scenario;
        const blocked = await run();
        assert.equal(blocked.liveTargetValid, false);
        assert.match(blocked.redirectMaterializationChecks[0].errors.join('\n'), expected);
        assert.doesNotMatch(JSON.stringify(blocked), /private-source|view=(?:full|wrong)/);
      }

      behavior = 'permanent';
      const passing = await run();
      assert.equal(passing.liveTargetValid, true, passing.errors.join('\n'));
      assert.equal(passing.redirectMaterializationChecks[0].initialStatus, 301);
      assert.equal(passing.redirectMaterializationChecks[0].passed, true);
      assert.match(passing.redirectMaterializationChecks[0].sourcePath, /query-sha256=/);
      assert.doesNotMatch(JSON.stringify(passing), /private-source|view=full/);

      behavior = 'permanent308';
      const passing308 = await run();
      assert.equal(passing308.liveTargetValid, true, passing308.errors.join('\n'));
      assert.equal(passing308.redirectMaterializationChecks[0].initialStatus, 308);
    }
  );
});

test('duplicate redirect mappings reconcile the complete destination and exception contract', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/legacy') {
        response.writeHead(301, { location: '/news' });
        response.end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(request.url === '/news'
        ? '<!doctype html><html><head><title>News</title></head><body><h1>News</h1></body></html>'
        : fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'duplicate-redirect-contract-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      mkdirSync(join(packetDir, 'evidence'), { recursive: true });
      writeFileSync(join(packetDir, 'evidence', 'retirement.txt'), 'Approved retirement.\n');
      const routeMatrix = liveRouteMatrix(baseUrl);
      const mapping = {
        sourcePath: '/legacy',
        targetPath: '/news',
        routeRole: 'homepage',
        targetStatus: 200,
        targetFinalPath: '/news',
        targetTitle: 'News',
        targetH1: 'News',
        expectedRedirect: false,
        accepted: true,
        notes: 'Duplicate contract fixture.'
      };
      routeMatrix.routes.push(mapping, {
        ...structuredClone(mapping),
        noRedirectDisposition: {
          accepted: true,
          acceptedBy: 'Fixture owner',
          rationale: 'This duplicate says the redirect may be absent.',
          evidence: 'evidence/retirement.txt'
        }
      });
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const conflicted = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(conflicted.liveTargetValid, false);
      assert.equal(conflicted.redirectMappingConflicts.length, 1);
      assert.match(conflicted.errors.join('\n'), /duplicate redirect mapping contracts.*do not fully agree/i);

      mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
        delete value.routes[2].noRedirectDisposition;
      });
      const reconciled = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(reconciled.redirectMappingConflicts.length, 0);
      assert.equal(reconciled.redirectMaterializationChecks.length, 1);
      assert.equal(reconciled.redirectMaterializationChecks[0].passed, true);
    }
  );
});

test('one live HTTP budget spans route classes, accepted seeds, rendered links, materialization, and redirect hops', async () => {
  let active = 0;
  let maximumActive = 0;
  let requestCount = 0;
  await withHttpServer(
    (request, response) => {
      requestCount += 1;
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      setTimeout(() => {
        active -= 1;
        if (request.url === '/legacy?private=one') {
          response.writeHead(301, { location: '/linked' });
          response.end();
          return;
        }
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        if (request.url === '/') {
          response.end('<!doctype html><html><head><title>Target site</title></head><body><h1>Target home</h1><a href="/linked">Linked</a></body></html>');
        } else {
          response.end('<!doctype html><html><head><title>Linked</title></head><body><h1>Linked</h1></body></html>');
        }
      }, 20);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'shared-live-http-budget-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.routes.push(
        {
          sourcePath: '/linked', targetPath: '/linked', routeRole: 'homepage', targetStatus: 200,
          targetFinalPath: '/linked', targetTitle: 'Linked', targetH1: 'Linked', expectedRedirect: false,
          accepted: true, notes: 'Rendered-link fixture.'
        },
        {
          sourcePath: '/legacy?private=one', targetPath: '/linked', routeRole: 'homepage', targetStatus: 200,
          targetFinalPath: '/linked', targetTitle: 'Linked', targetH1: 'Linked', expectedRedirect: false,
          accepted: true, notes: 'Redirect-materialization fixture.'
        }
      );
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const requestCapped = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl),
        liveHttpLimits: { concurrency: 2, deadlineMs: 2_000, maxRequests: 6, maxTasks: 20 }
      });
      assert.equal(requestCapped.liveTargetValid, false);
      assert.equal(requestCapped.liveHttpBudget.requestCapExhausted, true);
      assert.equal(requestCapped.liveHttpBudget.requestCount, 6);
      assert.equal(requestCount, 6);
      assert.ok(maximumActive > 1 && maximumActive <= 2, `observed HTTP concurrency ${maximumActive}`);
      assert.deepEqual(requestCapped.liveHttpBudget.tasksByKind, {
        'accepted-route-seed': 2,
        'access-wall-route': 1,
        'generated-missing-route': 1,
        'primary-route': 1,
        'redirect-materialization': 1,
        'server-rendered-link': 1,
        'target-required-route': 1
      });
      assert.match(requestCapped.errors.join('\n'), /exhausted its 6 HTTP request budget/i);
      assert.doesNotMatch(JSON.stringify(requestCapped), /private=one/);

      const taskCapped = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl),
        liveHttpLimits: { concurrency: 2, deadlineMs: 2_000, maxRequests: 50, maxTasks: 3 }
      });
      assert.equal(taskCapped.liveTargetValid, false);
      assert.equal(taskCapped.liveHttpBudget.taskCapExhausted, true);
      assert.equal(taskCapped.liveHttpBudget.taskCount, 2);
      assert.ok(taskCapped.liveHttpBudget.taskRejectedCount >= 2);
      assert.match(taskCapped.errors.join('\n'), /exhausted its 3 task budget/i);
    }
  );
});

test('live verification caps non-primary representative route concurrency', async () => {
  let activeRepresentativeRequests = 0;
  let maxRepresentativeRequests = 0;
  await withHttpServer(
    (request, response) => {
      if (request.url.startsWith('/representative-')) {
        activeRepresentativeRequests += 1;
        maxRepresentativeRequests = Math.max(maxRepresentativeRequests, activeRepresentativeRequests);
        const path = request.url;
        const index = path.split('-').at(-1);
        const origin = `http://${request.headers.host}`;
        setTimeout(() => {
          response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
          response.end(`<!doctype html><html><head><title>Representative ${index}</title><link rel="canonical" href="${origin}${path}"><meta name="description" content="Representative route ${index}."></head><body><h1>Representative ${index}</h1></body></html>`);
          activeRepresentativeRequests -= 1;
        }, 40);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'representative-concurrency-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const representativeCount = 18;
      mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
        for (let index = 0; index < representativeCount; index += 1) {
          routeMatrix.routes.push({
            sourcePath: `/representative-${index}`,
            sourceStatus: 200,
            sourceFinalPath: `/representative-${index}`,
            sourceTitle: `Representative ${index}`,
            sourceH1: `Representative ${index}`,
            targetPath: `/representative-${index}`,
            targetStatus: 200,
            targetFinalPath: `/representative-${index}`,
            targetTitle: `Representative ${index}`,
            targetH1: `Representative ${index}`,
            expectedRedirect: false,
            accepted: true,
            notes: 'Concurrency fixture.'
          });
        }
      });
      mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
        for (let index = 0; index < representativeCount; index += 1) {
          const check = structuredClone(browser.publicRouteChecks[0]);
          check.routeRole = 'other';
          check.sourceUrl = `https://source.example/representative-${index}`;
          check.sourceFinalUrl = check.sourceUrl;
          check.targetUrl = `${baseUrl}/representative-${index}`;
          check.targetFinalUrl = check.targetUrl;
          check.renderedSignals.sourceTitle = `Representative ${index}`;
          check.renderedSignals.targetTitle = `Representative ${index}`;
          check.renderedSignals.sourceH1 = `Representative ${index}`;
          check.renderedSignals.targetH1 = `Representative ${index}`;
          check.renderedSeoSignals.targetCanonicalUrl = check.targetUrl;
          check.renderedSeoSignals.targetMetaDescription = `Representative route ${index}.`;
          check.accessibilityCheck.report = `evidence/browser/axe-representative-${index}.json`;
          browser.publicRouteChecks.push(check);
        }
      });
      for (let index = 0; index < representativeCount; index += 1) {
        writeJson(join(packetDir, `evidence/browser/axe-representative-${index}.json`), {
          testEngine: { name: 'axe-core', version: '4.10.2' },
          toolOptions: { runOnly: null, rules: {} },
          testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: 1280, windowHeight: 800 },
          timestamp: testCheckedAt,
          url: `${baseUrl}/representative-${index}`,
          passes: [],
          violations: [],
          incomplete: [],
          inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
        });
      }

      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: {},
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });
      assert.equal(report.browserRepresentativeRouteChecks.length, representativeCount);
      assert.equal(report.browserRepresentativeRouteChecks.every((check) => check.passed), true);
      assert.ok(maxRepresentativeRequests > 1, 'fixture should exercise concurrent requests');
      assert.ok(maxRepresentativeRequests <= 12, `expected at most 12 concurrent representative requests, saw ${maxRepresentativeRequests}`);
    }
  );
});

test('exported SEO config rejects literal local origins while allowing tokens and external media URLs', () => {
  const temp = mkdtempSync(join(tmpdir(), 'seo-config-portability-'));
  const configDir = join(temp, 'config', 'sync');
  mkdirSync(configDir, { recursive: true });
  const localFile = 'config/sync/metatag.metatag_defaults.front.yml';
  const tokenFile = 'config/sync/metatag.metatag_defaults.node.yml';
  writeFileSync(join(temp, localFile), `tags:\n  canonical_url: 'https://fixture.ddev.site/'\n  og_image: 'https://fixture.ddev.site/media/hero.jpg'\n`);
  writeFileSync(join(temp, tokenFile), `tags:\n  canonical_url: '[current-page:url:absolute]'\n  og_image: 'https://cdn.example/media/hero.jpg'\n`);

  const localFindings = exportedSeoUrlPortabilityFindings(temp, [localFile, tokenFile], 'https://fixture.ddev.site');
  assert.equal(localFindings.length, 2);
  assert.deepEqual(localFindings.map((finding) => finding.key), ['canonical_url', 'og_image']);

  const portableFindings = exportedSeoUrlPortabilityFindings(temp, [tokenFile], 'https://fixture.ddev.site');
  assert.deepEqual(portableFindings, []);
});

test('literal local URLs in exported SEO config block live completion', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'seo-portability-live-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl, {
          exportedSeoUrlPortabilityFindings: [{
            file: 'config/sync/metatag.metatag_defaults.front.yml',
            line: 10,
            key: 'canonical_url',
            host: new URL(baseUrl).host
          }]
        })
      });

      assert.equal(report.drupalRuntime.seoUrlsPortable, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.completionBlockedReasons.join('\n'), /exported SEO configuration contains literal local-environment URLs/i);
    }
  );
});

test('blind editor evidence requires captures or a target-bound action record', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-weak-editor-evidence-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  writeJson(join(packetDir, 'evidence', 'blind-adversarial-review', 'editor-task.json'), {
    publicOutputChanged: true,
    role: 'content editor'
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /credible before\/after captures or structured target-bound editor action evidence/);
});

test('qualifying review evidence is bound to the same target the live verifier checks', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-stale-review-target-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const independentPath = join(packetDir, 'independent-verification.json');
      const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
      independent.target.baseUrl = 'https://stale-target.example/';
      writeJson(independentPath, independent);
      const claimEvidencePath = join(packetDir, 'evidence', 'independent-verification', 'claim-evidence.json');
      const claimEvidence = JSON.parse(readFileSync(claimEvidencePath, 'utf8'));
      claimEvidence.targetBaseUrl = 'https://stale-target.example/';
      writeJson(claimEvidencePath, claimEvidence);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /target\.baseUrl origin/);
    }
  );
});

test('every completion-bearing packet artifact is bound to the inspected source or target origin', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-artifact-origin-bindings-'));
      const canonicalPacket = join(temp, 'canonical-packet');
      copyTemplatePacket(canonicalPacket);
      writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(canonicalPacket, baseUrl);

      const cases = [
        ['parity-report.json', /parity-report\.json targetUrl origin/, (value) => { value.targetUrl = 'https://stale-target.example/'; }],
        ['browser-evidence.json', /browser-evidence\.json site origin/, (value) => { value.site = 'https://stale-target.example/'; }],
        ['browser-route-target.json', /publicRouteChecks\[0\]\.targetUrl origin/, (value) => {
          value.publicRouteChecks[0].targetUrl = 'https://stale-target.example/';
        }, 'browser-evidence.json'],
        ['browser-route-source.json', /publicRouteChecks\[0\]\.sourceUrl origin/, (value) => {
          value.publicRouteChecks[0].sourceUrl = 'https://wrong-source.example/';
        }, 'browser-evidence.json'],
        ['drupal-readback.json', /drupal-readback\.json site origin/, (value) => { value.site = 'https://stale-target.example/'; }],
        ['field-output-matrix.json', /field-output-matrix\.json site origin/, (value) => { value.site = 'https://stale-target.example/'; }],
        ['next-cycle-verification.json', /next-cycle-verification\.json site origin/, (value) => {
          value.site = 'https://stale-target.example/';
        }],
        ['pattern-map.json', /pattern-map\.json sourceSite origin/, (value) => { value.sourceSite = 'https://wrong-source.example/'; }],
        ['source-audit.json', /source-audit\.json site\.baseUrl origin/, (value) => {
          value.site.baseUrl = 'https://wrong-source.example/';
        }],
        ['independent-admin.json', /target\.adminUrl origin/, (value) => {
          value.target.adminUrl = 'https://stale-target.example/admin';
        }, 'independent-verification.json'],
        ['blind-editor.json', /editorExperienceReviews\[0\]\.targetAdminUrl origin/, (value) => {
          value.editorExperienceReviews[0].targetAdminUrl = 'https://stale-target.example/admin';
        }, 'blind-adversarial-review.json']
      ];

      for (const [name, expectedError, mutate, sourceFile = name] of cases) {
        const packetDir = join(temp, name.replace(/\.json$/, ''));
        cpSync(canonicalPacket, packetDir, { recursive: true });
        mutateJson(join(packetDir, sourceFile), mutate);
        const report = await verifyLive({ packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {} });
        assert.equal(report.valid, false, `${name} should invalidate live evidence`);
        assert.equal(report.completeLocalRebuildClaimAllowed, false, name);
        assert.match(report.errors.join('\n'), expectedError, name);
      }
    }
  );
});

test('completion is blocked when live Drupal site UUID differs from packet readback', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-site-uuid-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: {
          baseUrl,
          confirmed: true,
          configStatusClean: true,
          configSyncDirectory: '../config/sync',
          frontPage: '/',
          mode: 'test',
          project: 'fixture',
          reason: '',
          siteUuid: '22222222-2222-4222-8222-222222222222'
        }
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.completionBlockedReasons.join('\n'), /siteUuid/);
    }
  );
});

test('completion is blocked when live front-page or config state differs from packet readback', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-drupal-state-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: {
          baseUrl,
          confirmed: true,
          configStatusClean: false,
          configSyncDirectory: '../different-config/sync',
          frontPage: '/different-home',
          mode: 'test',
          project: 'fixture',
          reason: '',
          siteUuid: testSiteUuid
        }
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(report.drupalRuntime.frontPageMatchesPacket, false);
      assert.equal(report.drupalRuntime.configSyncDirectoryMatchesPacket, false);
      assert.equal(report.drupalRuntime.configStatusClean, false);
      assert.match(report.completionBlockedReasons.join('\n'), /front-page setting/);
      assert.match(report.completionBlockedReasons.join('\n'), /config-sync directory/);
      assert.match(report.completionBlockedReasons.join('\n'), /config status is not clean/);
    }
  );
});

test('completion is blocked when HTTP evidence and Drupal identity come from different targets', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-runtime-target-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: {
          baseUrl: 'https://different-project.ddev.site/',
          confirmed: true,
          configStatusClean: true,
          configSyncDirectory: '../config/sync',
          frontPage: '/',
          mode: 'test',
          project: 'different-project',
          reason: '',
          siteUuid: testSiteUuid
        }
      });

      assert.equal(report.valid, false);
      assert.equal(report.routeChecks.length, 0);
      assert.equal(report.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(report.drupalRuntime.targetOriginMatches, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /Explicit target HTTP checks are disabled/);
      assert.match(report.completionBlockedReasons.join('\n'), /runtime base URL/);
    }
  );
});

test('live verifier refuses to certify the original source origin as the target', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-source-equals-target-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.sourceBaseUrl = baseUrl;
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({ packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {} });

      assert.equal(report.valid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /same origin as sourceBaseUrl/);
    }
  );
});

test('live verifier rejects a target route that redirects back to the source origin', async () => {
  let sourceRequestCount = 0;
  await withHttpServer(
    (_request, response) => {
      sourceRequestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (sourceBaseUrl) => {
      await withHttpServer(
        (_request, response) => {
          response.writeHead(302, { location: `${sourceBaseUrl}/` });
          response.end();
        },
        async (targetBaseUrl) => {
          const temp = mkdtempSync(join(tmpdir(), 'live-target-redirects-source-'));
          const packetDir = join(temp, 'review-packet');
          copyTemplatePacket(packetDir);
          const routeMatrix = liveRouteMatrix(targetBaseUrl);
          routeMatrix.sourceBaseUrl = sourceBaseUrl;
          writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

          const report = await verifyLive({
            packetDir,
            targetUrl: targetBaseUrl,
            cwd: repoRoot,
            environment: {},
            drupalRuntime: injectedDrupalRuntime(targetBaseUrl)
          });

          assert.equal(report.valid, false);
          assert.match(report.errors.join('\n'), /Refusing cross-origin redirect/);
        }
      );
    }
  );
  assert.equal(sourceRequestCount, 0, 'the verifier must reject a cross-origin Location before requesting it');
});

test('an explicit target not bound to DDEV is not fetched and has no remote opt-in escape', async () => {
  let requestCount = 0;
  await withHttpServer(
    (_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-explicit-target-opt-in-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({ packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {} });

      assert.equal(report.valid, false);
      assert.equal(report.routeChecks.length, 0);
      assert.match(report.errors.join('\n'), /Explicit target HTTP checks are disabled/);
      assert.doesNotMatch(report.errors.join('\n'), /allow-remote-target/);
    }
  );
  assert.equal(requestCount, 0);
});

test('live verifier fails closed when the declared target cannot be reached', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'live-unavailable-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const unavailableUrl = 'http://127.0.0.1:1';
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(unavailableUrl));

  const report = await verifyLive({
    packetDir,
    targetUrl: unavailableUrl,
    cwd: repoRoot,
    environment: {},
    drupalRuntime: injectedDrupalRuntime(unavailableUrl)
  });

  assert.equal(report.valid, false);
  assert.equal(report.completeLocalRebuildClaimAllowed, false);
  assert.match(report.errors.join('\n'), /could not be fetched/);
});

test('live verifier rejects an HTTP response larger than the five MiB evidence limit', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, {
        'content-length': String(5 * 1024 * 1024 + 1),
        'content-type': 'text/html; charset=utf-8'
      });
      response.end('oversized');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-oversized-response-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /Response body exceeds the 5242880 byte limit/);
    }
  );
});

test('default mode does not trust the packet target URL as runtime discovery', async () => {
  let requestCount = 0;
  await withHttpServer(
    (_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-no-packet-fallback-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({ packetDir, cwd: temp, environment: {} });

      assert.equal(report.valid, false);
      assert.match(report.errors.join('\n'), /No live target URL found/);
    }
  );
  assert.equal(requestCount, 0);
});

test('default CLI ignores an ambient DDEV URL outside a matching project/container', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-cli-incomplete-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const result = await runProcess(process.execPath, [
        join(repoRoot, 'bin', 'verify.mjs'),
        '--packet',
        packetDir
      ], repoRoot, { env: { ...process.env, DDEV_PRIMARY_URL: baseUrl } });

      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /No live target URL found/);
      const report = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(report.valid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.verdict, 'blocked');
      assert.equal(report.recordedHumanGateStatus.affectsMachineCompletion, false);
      assert.equal(report.packetDir, 'review-packet');
      assert.doesNotMatch(JSON.stringify(report), new RegExp(temp.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    }
  );
});

test('packet-only verification rejects authored completion authority', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'authored-completion-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const independentPath = join(packetDir, 'independent-verification.json');
  const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
  independent.summary.completeLocalRebuildClaimAllowed = true;
  writeJson(independentPath, independent);

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completeLocalRebuildClaimAllowed, false);
  assert.match(report.errors.join('\n'), /completion authority belongs only to the live verifier/);
});

test('blind completion evidence rejects a text file named like a screenshot', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'fake-screenshot-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const evidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  mkdirSync(evidenceDir, { recursive: true });
  writeFileSync(join(evidenceDir, 'fake.png'), 'not an image\n');

  const routeMatrix = liveRouteMatrix('https://target.example');
  writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  blind.reviewer = {
    nameOrRole: 'fresh blind reviewer',
    runtimeOrTool: 'browser',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    didNotBuildTarget: true,
    inputsRestrictedToBriefTargetAndSourceTruth: true,
    implementationFilesReadBeforePublicReview: false,
    reviewPacketReadBeforePublicReview: false,
    priorBuildConversationRead: false,
    builderSummaryExcluded: true,
    notes: ''
  };
  blind.reviewInputs = {
    originalBrief: 'Rebuild the source site.',
    acceptanceCriteria: [],
    targetUrlsOrArtifacts: ['https://target.example/'],
    sourceOfTruthMaterials: [{ type: 'source_site', reference: 'https://source.example/', notes: '' }],
    credentialsUsed: [],
    excludedInputs: []
  };
  blind.routeViewportReviews = ['desktop', 'mobile'].map((viewport) => ({
    route: '/',
    sourceTruthReference: 'https://source.example/',
    targetUrlOrArtifact: 'https://target.example/',
    viewport,
    sourceScreenshot: 'fake.png',
    targetScreenshot: 'fake.png',
    routeNotes: `${viewport} checked`,
    checks: {},
    verdict: 'good',
    evidence: []
  }));
  blind.productDefects = [];
  blind.reviewPasses = [
    { id: 'pass-1', checkedAt: '2026-07-09T00:00:00Z', reviewer: 'fresh reviewer', verdict: 'good', notes: '' }
  ];
  blind.summary = {
    verdict: 'good',
    completionState: 'parity_reviewed',
    desktopMobileReviewed: true,
    routeNotesPresent: true,
    rawEvidencePresent: true,
    openBlockerIssueCount: 0,
    openCriticalIssueCount: 0,
    openHighIssueCount: 0,
    acceptedOutOfScopeIssueCount: 0,
    externalBlockerIssueCount: 0,
    notes: ''
  };
  writeJson(blindPath, blind);

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /checks\.actualRequestedOutcome must be pass/);
  assert.match(report.errors.join('\n'), /must be a credible packet-local PNG, JPEG, WebP, or GIF capture/);
});

test('generated missing-route verification rejects soft 404s, unrelated canonicals, and missing noindex', async () => {
  const cases = [
    {
      name: 'soft-404',
      status: 200,
      head: '<title>Page not found</title><meta name="robots" content="noindex">',
      expected: /must return exactly 404/i
    },
    {
      name: 'unrelated-canonical',
      status: 404,
      head: '<title>Page not found</title><meta name="robots" content="noindex"><link rel="canonical" href="/">',
      expected: /rendered canonical.*instead of itself/i
    },
    {
      name: 'missing-noindex',
      status: 404,
      head: '<title>Page not found</title>',
      expected: /required noindex/i
    }
  ];

  for (const fixture of cases) {
    await withHttpServer(
      (request, response) => {
        if (request.url?.startsWith('/.well-known/agent-ready-missing-')) {
          response.writeHead(fixture.status, { 'content-type': 'text/html' });
          response.end(`<html><head>${fixture.head}</head><body><h1>Page not found</h1></body></html>`);
          return;
        }
        if (request.url === '/user/login') {
          response.writeHead(200, { 'content-type': 'text/html' });
          response.end('<title>Log in</title><h1>Log in</h1>');
          return;
        }
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end('<title>Target site</title><h1>Target home</h1>');
      },
      async (baseUrl) => {
        const temp = mkdtempSync(join(tmpdir(), `negative-${fixture.name}-`));
        const packetDir = join(temp, 'review-packet');
        copyTemplatePacket(packetDir);
        writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
        writeJson(join(packetDir, 'negative-route-consent.json'), negativeRouteConsentRecord(baseUrl));

        const report = await verifyLive({ packetDir, targetUrl: baseUrl, drupalRuntime: injectedDrupalRuntime(baseUrl) });
        assert.equal(report.liveTargetValid, false, fixture.name);
        assert.match(report.errors.join('\n'), fixture.expected, fixture.name);
      },
      { defaultVerificationRoutes: false }
    );
  }
});

test('access-wall verification rejects a login page canonicalized to public content', async () => {
  await withHttpServer(
    (request, response) => {
      const origin = `http://${request.headers.host}`;
      if (request.url?.startsWith('/.well-known/agent-ready-missing-')) {
        response.writeHead(404, { 'content-type': 'text/html' });
        response.end('<title>Page not found</title><meta name="robots" content="noindex"><h1>Page not found</h1>');
        return;
      }
      if (request.url === '/user/login') {
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end(`<title>Log in</title><link rel="canonical" href="${origin}/canvas"><h1>Log in</h1>`);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'access-wall-canonical-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      writeJson(join(packetDir, 'negative-route-consent.json'), negativeRouteConsentRecord(baseUrl));

      const report = await verifyLive({ packetDir, targetUrl: baseUrl, drupalRuntime: injectedDrupalRuntime(baseUrl) });
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /user\/login.*unrelated canonical/i);
    },
    { defaultVerificationRoutes: false }
  );
});

test('rendered internal legal and privacy links must resolve even when no legal route was declared', async () => {
  await withHttpServer(
    (request, response) => {
      if (request.url === '/privacy') {
        response.writeHead(404, { 'content-type': 'text/html' });
        response.end('<title>Page not found</title><h1>Page not found</h1>');
        return;
      }
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1><footer><a href="/privacy">Privacy policy</a></footer>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'broken-privacy-link-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      writeJson(join(packetDir, 'negative-route-consent.json'), negativeRouteConsentRecord(baseUrl));

      const report = await verifyLive({ packetDir, targetUrl: baseUrl, drupalRuntime: injectedDrupalRuntime(baseUrl) });
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /legal\/privacy link.*HTTP 404.*cannot be treated as not applicable/i);
    }
  );
});

test('consent reconciliation rejects live violations and never promotes authored browser evidence to machine authority', async () => {
  let renderMap = true;
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(`<title>Target site</title><h1>Target home</h1>${renderMap ? '<iframe src="https://maps.google.com/embed/test"></iframe>' : ''}`);
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'consent-reconciliation-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      const evidence = negativeRouteConsentRecord(baseUrl);
      evidence.consent = {
        discoveryStatus: 'installed',
        notInstalledReason: '',
        managers: [{ id: 'klaro', module: 'klaro', configNames: ['klaro.application.google_maps'] }],
        applications: [{
          id: 'google_maps',
          managerId: 'klaro',
          configName: 'klaro.application.google_maps',
          enabled: false,
          required: false,
          controlledResources: [{ kind: 'iframe', pattern: 'maps.google.com' }],
          resourceDiscoveryDisposition: { acceptedBy: '', rationale: '', evidence: [] }
        }],
        beforeConsentChecks: [{
          route: '/',
          browserContextFresh: true,
          consentStorageCleared: true,
          observedResourceUrls: ['https://maps.google.com/embed/test'],
          blockedApplicationIds: [],
          status: 'pass',
          evidence: 'before-consent.json'
        }]
      };
      writeJson(join(packetDir, 'negative-route-consent.json'), evidence);
      const runtimeInventory = {
        applications: [{
          configName: 'klaro.application.google_maps',
          id: 'google_maps',
          enabled: false,
          required: false,
          resources: [{ kind: 'iframe', pattern: 'maps.google.com' }]
        }],
        configNames: ['klaro.application.google_maps'],
        confirmed: true,
        detected: true,
        managerModules: ['klaro'],
        reason: ''
      };

      let report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl, { consentInventory: runtimeInventory })
      });
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /loaded while its consent application is disabled/i);

      renderMap = false;
      evidence.consent.applications[0].enabled = true;
      evidence.consent.beforeConsentChecks[0].observedResourceUrls = [];
      evidence.consent.beforeConsentChecks[0].blockedApplicationIds = ['google_maps'];
      runtimeInventory.applications[0].enabled = true;
      writeJson(join(packetDir, 'negative-route-consent.json'), evidence);
      report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl, { consentInventory: runtimeInventory })
      });
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /requires verifier-owned fresh browser\/network capture/i);
      assert.equal(report.consentReconciliation.authoritativeBeforeConsentCapture, false);
      assert.deepEqual(report.consentReconciliation.browserObservedUrls, []);
      assert.deepEqual(report.consentReconciliation.authoredBrowserObservedUrls, []);

      runtimeInventory.applications[0].enabled = false;
      report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        drupalRuntime: injectedDrupalRuntime(baseUrl, { consentInventory: runtimeInventory })
      });
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /state contradicts active Drupal config/i);
    }
  );
});

test('negative-route and consent dispositions fail closed without named packet-local evidence', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'negative-consent-dispositions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'status-only-404',
      expected: /status-only.*named, evidenced disposition/i,
      mutate(record) {
        record.missingRoute.noindexPolicy = 'status_only_with_disposition';
      }
    },
    {
      name: 'production-only-legal',
      expected: /production-only.*named, evidenced disposition/i,
      mutate(record) {
        record.legalPrivacyScope.requirements = [{
          path: '/privacy', status: 'production_only', acceptedBy: '', rationale: '', evidence: []
        }];
      }
    },
    {
      name: 'missing-before-consent-evidence',
      expected: /before-consent check.*packet-local evidence/i,
      mutate(record) {
        record.consent = {
          discoveryStatus: 'installed',
          notInstalledReason: '',
          managers: [{ id: 'klaro', module: 'klaro', configNames: ['klaro.application.maps'] }],
          applications: [{
            id: 'maps', managerId: 'klaro', configName: 'klaro.application.maps', enabled: true, required: false,
            controlledResources: [{ kind: 'iframe', pattern: 'maps.example' }],
            resourceDiscoveryDisposition: { acceptedBy: '', rationale: '', evidence: [] }
          }],
          beforeConsentChecks: [{
            route: '/', browserContextFresh: true, consentStorageCleared: true,
            observedResourceUrls: [], blockedApplicationIds: ['maps'], status: 'pass', evidence: 'missing.json'
          }]
        };
      }
    },
    {
      name: 'required-without-essential-evidence',
      expected: /required consent application maps needs an explicit essential-without-consent classification/i,
      mutate(record) {
        record.consent = {
          discoveryStatus: 'installed',
          notInstalledReason: '',
          managers: [{ id: 'klaro', module: 'klaro', configNames: ['klaro.application.maps'] }],
          applications: [{
            id: 'maps', managerId: 'klaro', configName: 'klaro.application.maps', enabled: true, required: true,
            essentialWithoutConsent: false, essentialServiceRationale: '', essentialServiceEvidence: [],
            controlledResources: [{ kind: 'iframe', pattern: 'maps.example' }],
            resourceDiscoveryDisposition: { acceptedBy: '', rationale: '', evidence: [] }
          }],
          beforeConsentChecks: []
        };
      }
    }
  ];

  for (const fixture of cases) {
    const packetDir = join(temp, fixture.name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, 'negative-route-consent.json'), fixture.mutate);
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetCompletionReady, false, fixture.name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), fixture.expected, fixture.name);
  }

  const evidencedPacket = join(temp, 'evidenced-dispositions');
  cpSync(canonicalPacket, evidencedPacket, { recursive: true });
  writeFileSync(join(evidencedPacket, 'evidence', 'legal-disposition.txt'), 'Named owner accepted production-only legal copy.\n');
  writeFileSync(join(evidencedPacket, 'evidence', 'essential-service.txt'), 'The fixture service is technically required before consent.\n');
  writeJson(join(evidencedPacket, 'evidence', 'before-consent.json'), {
    schemaVersion: 'public-kit.before-consent-evidence.1',
    targetBaseUrl: 'https://target.example',
    checkedAt: testCheckedAt,
    route: '/',
    browserContextFresh: true,
    consentStorageCleared: true,
    observedResourceUrls: [],
    blockedApplicationIds: ['maps']
  });
  mutateJson(join(evidencedPacket, 'negative-route-consent.json'), (record) => {
    record.legalPrivacyScope.requirements = [{
      path: '/privacy',
      status: 'production_only',
      acceptedBy: 'Site owner',
      rationale: 'Final policy copy is approved only in production.',
      evidence: ['legal-disposition.txt']
    }];
    record.consent = {
      discoveryStatus: 'installed',
      notInstalledReason: '',
      managers: [{ id: 'klaro', module: 'klaro', configNames: ['klaro.application.maps'] }],
      applications: [{
        id: 'maps', managerId: 'klaro', configName: 'klaro.application.maps', enabled: true, required: true,
        essentialWithoutConsent: true,
        essentialServiceRationale: 'The fixture treats this service as technically essential.',
        essentialServiceEvidence: ['essential-service.txt'],
        controlledResources: [{ kind: 'iframe', pattern: 'maps.example' }],
        resourceDiscoveryDisposition: { acceptedBy: '', rationale: '', evidence: [] }
      }],
      beforeConsentChecks: [{
        route: '/', browserContextFresh: true, consentStorageCleared: true,
        observedResourceUrls: [], blockedApplicationIds: ['maps'], status: 'pass', evidence: 'before-consent.json'
      }]
    };
  });
  const evidencedReport = await validatePacket({ packetDir: evidencedPacket });
  assert.equal(
    evidencedReport.completionEvidence.packetCompletionReady,
    true,
    evidencedReport.completionEvidence.packetCompletionBlockedReasons.join('\n')
  );
});
