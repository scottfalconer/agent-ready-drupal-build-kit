import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  buildSiteState,
  canonicalJson,
  collectFileManifest,
  collectRuntimeCodeManifest,
  hashManifest,
  sha256
} from '../bin/state-fingerprint.mjs';
import {
  abandonChange,
  applyVerificationLifecycle,
  beginChange,
  completeChange,
  readLifecycleStatus
} from '../bin/lifecycle.mjs';

const digest = (seed) => `sha256:${seed.repeat(64)}`;

function manifestEntries(overrides = {}) {
  return [
    {
      path: 'config/sync/system.site.yml',
      sha256: digest('a'),
      size: 24,
      ...overrides.site
    },
    {
      path: 'config/sync/system.theme.yml',
      sha256: digest('b'),
      size: 40,
      ...overrides.theme
    }
  ];
}

function siteState(overrides = {}) {
  return buildSiteState({
    targetIdentity: {
      origin: 'https://fixture.ddev.site',
      siteUuid: '11111111-1111-4111-8111-111111111111'
    },
    configManifest: manifestEntries(),
    codeManifest: [
      { path: 'composer.lock', sha256: digest('c'), size: 500 },
      { path: 'web/themes/custom/fixture/fixture.info.yml', sha256: digest('d'), size: 80 }
    ],
    entityInventory: {
      nodes: [{ bundle: 'page', published: true, uuid: '22222222-2222-4222-8222-222222222222' }]
    },
    routeManifest: [{ owner: 'node', path: '/', status: 200 }],
    packetFingerprint: digest('e'),
    verifierFingerprint: digest('f'),
    ...overrides
  });
}

function passingReport(buildState = siteState(), overrides = {}) {
  const routeChecks = (buildState.routeManifest ?? []).map((route) => ({
    targetPath: route.path,
    passed: true,
    errors: []
  }));
  return {
    schemaVersion: 'public-kit.live-verification.1',
    checkedAt: new Date().toISOString(),
    verificationMode: 'live-target-and-packet',
    completeLocalRebuildClaimAllowed: true,
    valid: true,
    buildState: { ...buildState, complete: true, blockers: [] },
    liveTargetValid: true,
    routeChecks,
    targetRequiredRouteChecks: [],
    drupalRuntime: {
      authoritativeForCompletion: true,
      confirmed: true,
      configStatusClean: true,
      configSyncTracked: true,
      configSyncDirectoryMatchesPacket: true,
      entityInventory: { confirmed: true },
      frontPageMatchesPacket: true,
      runtimeFacts: { confirmed: true, databaseUpdatesPending: false },
      siteUuidMatchesPacket: true,
      targetOriginMatches: true,
      trackedConfigReadbackMatches: true,
      trackedConfigYamlPresent: true
    },
    ...overrides
  };
}

function lifecycleFixture() {
  const projectRoot = mkdtempSync(join(tmpdir(), 'site-lifecycle-'));
  const packetDir = join(projectRoot, 'review-packet');
  mkdirSync(join(packetDir, 'evidence'), { recursive: true });
  writeFileSync(join(projectRoot, 'composer.json'), '{"name":"fixture/site"}\n');
  writeFileSync(join(packetDir, 'evidence', 'change-check.json'), '{"status":"pass"}\n');
  return { packetDir, projectRoot };
}

function verificationFor(change, resultFingerprint, overrides = {}) {
  return {
    schemaVersion: 'public-kit.change-verification.1',
    changeId: change.id,
    checkedAt: new Date().toISOString(),
    baseFingerprint: change.baseFingerprint,
    resultFingerprint,
    acceptanceEvidence: change.acceptanceCriteria.map((criterion) => ({
      criterionId: criterion.id,
      status: 'pass',
      observation: `${criterion.id} passed against the fixture.`,
      evidence: ['evidence/change-check.json']
    })),
    checks: change.requiredChecks.map((check) => ({
      id: check.id,
      status: 'pass',
      observation: `${check.id} passed against the fixture.`,
      evidence: ['evidence/change-check.json']
    })),
    ...overrides
  };
}

test('canonical JSON and file manifests are deterministic without hiding changed bytes', () => {
  assert.equal(
    canonicalJson({ z: 1, nested: { y: true, a: 'first' }, a: 2 }),
    '{"a":2,"nested":{"a":"first","y":true},"z":1}'
  );
  assert.equal(sha256({ b: 2, a: 1 }), sha256({ a: 1, b: 2 }));
  const prototypeKey = JSON.parse('{"__proto__":{"polluted":true},"constructor":"content"}');
  assert.equal(
    canonicalJson(prototypeKey),
    '{"__proto__":{"polluted":true},"constructor":"content"}'
  );
  assert.equal({}.polluted, undefined);

  const forward = hashManifest(manifestEntries());
  const reversed = hashManifest([...manifestEntries()].reverse());
  assert.deepEqual(reversed, forward);
  assert.equal(forward.entryCount, 2);
  assert.deepEqual(forward.entries.map((entry) => entry.path), [
    'config/sync/system.site.yml',
    'config/sync/system.theme.yml'
  ]);
  const portableOrdering = hashManifest([
    { path: 'z.txt', sha256: digest('1'), size: 1 },
    { path: 'ä.txt', sha256: digest('2'), size: 1 },
    { path: 'Z.txt', sha256: digest('3'), size: 1 }
  ]);
  assert.deepEqual(portableOrdering.entries.map((entry) => entry.path), ['Z.txt', 'z.txt', 'ä.txt']);

  const changedBytes = hashManifest(manifestEntries({ theme: { sha256: digest('9') } }));
  assert.notEqual(changedBytes.fingerprint, forward.fingerprint);
  assert.throws(
    () => hashManifest([...manifestEntries(), { ...manifestEntries()[0], size: 25 }]),
    /conflicting duplicate path/i
  );
  assert.throws(
    () => hashManifest([{ path: '../settings.php', sha256: digest('a'), size: 1 }]),
    /without traversal/i
  );
});

test('filesystem manifests use project-relative bytes and reject symlink inputs', () => {
  const root = mkdtempSync(join(tmpdir(), 'site-state-files-'));
  mkdirSync(join(root, 'config', 'sync'), { recursive: true });
  writeFileSync(join(root, 'config', 'sync', 'system.site.yml'), 'name: Fixture\n');
  writeFileSync(join(root, 'config', 'sync', 'system.theme.yml'), 'default: fixture\n');

  const directoryManifest = collectFileManifest(root, ['config/sync']);
  const reorderedManifest = collectFileManifest(root, [
    'config/sync/system.theme.yml',
    'config/sync/system.site.yml'
  ]);
  assert.deepEqual(directoryManifest, reorderedManifest);
  assert.deepEqual(directoryManifest.entries.map((entry) => entry.path), [
    'config/sync/system.site.yml',
    'config/sync/system.theme.yml'
  ]);
  assert.equal(
    directoryManifest.entries[0].sha256,
    sha256(readFileSync(join(root, 'config', 'sync', 'system.site.yml')))
  );

  const outside = mkdtempSync(join(tmpdir(), 'site-state-outside-'));
  writeFileSync(join(outside, 'secret.yml'), 'secret: true\n');
  symlinkSync(join(outside, 'secret.yml'), join(root, 'config', 'sync', 'linked.yml'));
  assert.throws(() => collectFileManifest(root, ['config/sync']), /symbolic link/i);
  assert.throws(() => collectFileManifest(root, ['../outside']), /escapes the project root/i);
});

test('runtime manifests bind portable code intrinsically and machine-local secrets as evidence only', () => {
  const root = mkdtempSync(join(tmpdir(), 'site-state-code-'));
  for (const directory of [
    'web/themes/custom/fixture',
    'web/modules/custom/example',
    'web/modules/custom/example/contrib',
    'web/modules/custom/example/evidence',
    'web/modules/custom/example/files',
    'web/modules/contrib/ignored',
    'web/sites/default/files',
    'review-packet/evidence',
    'vendor/ignored',
    '.ddev',
    '.platform',
    '.acquia',
    '.github/workflows',
    'config',
    'payloads',
    'drush/Commands',
    'hooks/post-deploy'
  ]) {
    mkdirSync(join(root, directory), { recursive: true });
  }
  writeFileSync(join(root, 'composer.json'), JSON.stringify({
    name: 'fixture/site',
    extra: {
      patches: {
        'drupal/core': {
          'Inline local patch': 'payloads/inline.patch',
          'Local patch in an otherwise excluded tree': 'vendor/ignored/referenced.patch',
          'Remote patch': 'https://example.com/remote.patch',
          'Escaping patch': '../outside.patch'
        }
      },
      'composer-patches': { 'patches-file': 'config/custom-patches.json' }
    }
  }));
  writeFileSync(join(root, 'composer.lock'), '{}\n');
  writeFileSync(join(root, 'composer.patches.json'), '{"patches":{}}\n');
  writeFileSync(join(root, 'patches.lock.json'), JSON.stringify({
    _hash: 'fixture',
    patches: [{ description: 'Locked patch', url: 'payloads/locked.patch' }]
  }));
  writeFileSync(join(root, 'config', 'custom-patches.json'), JSON.stringify({
    patches: {
      'drupal/example': { 'External compact patch': 'payloads/external-compact.patch' },
      'drupal/other': [{ description: 'External expanded patch', url: 'payloads/external-expanded.patch' }]
    }
  }));
  for (const patchName of ['inline', 'locked', 'external-compact', 'external-expanded']) {
    writeFileSync(join(root, 'payloads', `${patchName}.patch`), `patch payload: ${patchName}\n`);
  }
  writeFileSync(join(root, '.ddev', 'config.yaml'), 'name: fixture\n');
  writeFileSync(join(root, '.ddev', 'config.local.yaml'), 'router_http_port: 9999\n');
  writeFileSync(join(root, '.ddev', '.ddev-docker-compose-full.yaml'), 'name: generated-machine-state\n');
  writeFileSync(join(root, '.platform', 'routes.yaml'), 'https://{default}/: { type: upstream }\n');
  writeFileSync(join(root, '.acquia', 'deploy.yml'), 'artifact: true\n');
  writeFileSync(join(root, 'drush', 'Commands', 'FixtureCommands.php'), '<?php\n');
  writeFileSync(join(root, 'hooks', 'post-deploy', 'cache-rebuild'), '#!/bin/sh\n');
  writeFileSync(join(root, '.env'), 'PRIVATE_TOKEN=do-not-expose\n');
  writeFileSync(join(root, '.editorconfig'), 'root = true\n');
  writeFileSync(join(root, 'phpunit.xml'), '<phpunit/>\n');
  writeFileSync(join(root, '.github', 'workflows', 'tests.yml'), 'name: tests\n');
  writeFileSync(join(root, 'package.json'), '{"scripts":{"build":"vite build"}}\n');
  writeFileSync(join(root, 'vite.config.mjs'), 'export default {};\n');
  writeFileSync(join(root, 'web/themes/custom/fixture/fixture.info.yml'), 'name: Fixture\n');
  writeFileSync(join(root, 'web/modules/custom/example/example.info.yml'), 'name: Example\n');
  writeFileSync(join(root, 'web/modules/custom/example/contrib/helper.php'), '<?php\n');
  writeFileSync(join(root, 'web/modules/custom/example/evidence/logic.php'), '<?php\n');
  writeFileSync(join(root, 'web/modules/custom/example/files/schema.yml'), 'type: mapping\n');
  writeFileSync(join(root, 'web/modules/contrib/ignored/ignored.info.yml'), 'name: Ignored\n');
  writeFileSync(join(root, 'web/sites/default/settings.php'), '<?php $settings["hash_salt"] = "secret";\n');
  writeFileSync(join(root, 'web/sites/default/settings.local.php'), '<?php $config["dev"] = TRUE;\n');
  writeFileSync(join(root, 'web/sites/default/services.yml'), 'parameters: {}\n');
  writeFileSync(join(root, 'web/sites/default/files/upload.txt'), 'uploaded content\n');
  writeFileSync(join(root, 'review-packet/evidence/live-verification.json'), '{}\n');
  writeFileSync(join(root, 'vendor/ignored/autoload.php'), '<?php\n');
  writeFileSync(join(root, 'vendor/ignored/referenced.patch'), 'explicitly referenced patch payload\n');

  const manifest = collectRuntimeCodeManifest(root);
  const paths = manifest.entries.map((entry) => entry.path);
  assert.deepEqual(paths, [
    '.acquia/deploy.yml',
    '.ddev/config.yaml',
    '.platform/routes.yaml',
    'composer.json',
    'composer.lock',
    'composer.patches.json',
    'config/custom-patches.json',
    'drush/Commands/FixtureCommands.php',
    'hooks/post-deploy/cache-rebuild',
    'package.json',
    'patches.lock.json',
    'payloads/external-compact.patch',
    'payloads/external-expanded.patch',
    'payloads/inline.patch',
    'payloads/locked.patch',
    'vendor/ignored/referenced.patch',
    'vite.config.mjs',
    'web/modules/custom/example/contrib/helper.php',
    'web/modules/custom/example/evidence/logic.php',
    'web/modules/custom/example/example.info.yml',
    'web/modules/custom/example/files/schema.yml',
    'web/sites/default/services.yml',
    'web/sites/default/settings.php',
    'web/themes/custom/fixture/fixture.info.yml'
  ]);
  assert.equal(manifest.environmentBinding.entryCount, 3);
  assert.match(manifest.environmentBinding.fingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal(manifest.projectEvidenceBinding.entryCount, 3);
  assert.match(manifest.projectEvidenceBinding.fingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal(paths.includes('web/modules/contrib/ignored/ignored.info.yml'), false);
  assert.equal(paths.includes('.ddev/.ddev-docker-compose-full.yaml'), false);
  assert.equal(paths.includes('web/sites/default/files/upload.txt'), false);
  assert.equal(paths.includes('vendor/ignored/autoload.php'), false);
  assert.equal(paths.some((path) => /^review-packet\//.test(path)), false);
  assert.equal(paths.some((path) => path.includes('outside.patch') || path.includes('remote.patch')), false);
  assert.doesNotMatch(JSON.stringify(manifest), /"(?:\.env|\.ddev\/config\.local|web\/sites\/default\/settings\.local)/);
  assert.doesNotMatch(JSON.stringify(manifest), /do-not-expose|hash_salt|\$config|uploaded content/);

  const baselineRuntimeFingerprint = manifest.fingerprint;
  const baselineProjectEvidenceFingerprint = manifest.projectEvidenceBinding.fingerprint;
  for (const [patchFile, changedValue, originalValue] of [
    ['composer.patches.json', '{"patches":{"drupal/core":{"Fix":"patches/fix.patch"}}}\n', '{"patches":{}}\n'],
    ['patches.lock.json', '{"_hash":"changed","patches":[]}\n', JSON.stringify({
      _hash: 'fixture',
      patches: [{ description: 'Locked patch', url: 'payloads/locked.patch' }]
    })]
  ]) {
    writeFileSync(join(root, patchFile), changedValue);
    assert.notEqual(collectRuntimeCodeManifest(root).fingerprint, baselineRuntimeFingerprint, patchFile);
    writeFileSync(join(root, patchFile), originalValue);
  }
  for (const patchFile of [
    'payloads/inline.patch',
    'payloads/locked.patch',
    'payloads/external-compact.patch',
    'payloads/external-expanded.patch',
    'vendor/ignored/referenced.patch'
  ]) {
    const original = readFileSync(join(root, patchFile), 'utf8');
    writeFileSync(join(root, patchFile), `${original}changed\n`);
    assert.notEqual(collectRuntimeCodeManifest(root).fingerprint, baselineRuntimeFingerprint, patchFile);
    writeFileSync(join(root, patchFile), original);
  }
  writeFileSync(join(root, 'config', 'custom-patches.json'), '{"patches":{"drupal/core":{"Fix":"payloads/inline.patch"}}}\n');
  const changedPatch = collectRuntimeCodeManifest(root);
  assert.notEqual(changedPatch.fingerprint, baselineRuntimeFingerprint);

  writeFileSync(join(root, 'config', 'custom-patches.json'), JSON.stringify({
    patches: {
      'drupal/example': { 'External compact patch': 'payloads/external-compact.patch' },
      'drupal/other': [{ description: 'External expanded patch', url: 'payloads/external-expanded.patch' }]
    }
  }));
  writeFileSync(join(root, '.editorconfig'), 'root = false\n');
  const changedTooling = collectRuntimeCodeManifest(root);
  assert.equal(changedTooling.fingerprint, baselineRuntimeFingerprint);
  assert.notEqual(changedTooling.projectEvidenceBinding.fingerprint, baselineProjectEvidenceFingerprint);
});

test('site-state fingerprints identify the component that changed and reject tampered manifests', () => {
  const baseline = siteState();
  assert.equal(
    canonicalJson(baseline.routeManifest),
    canonicalJson([{ owner: 'node', path: '/', status: 200 }])
  );
  assert.equal(sha256(baseline.routeManifest), baseline.componentFingerprints.routeManifest);
  const reordered = siteState({
    targetIdentity: {
      siteUuid: '11111111-1111-4111-8111-111111111111',
      origin: 'https://fixture.ddev.site'
    },
    configManifest: [...manifestEntries()].reverse()
  });
  assert.equal(reordered.fingerprint, baseline.fingerprint);
  assert.deepEqual(reordered.componentFingerprints, baseline.componentFingerprints);

  const changedConfig = siteState({
    configManifest: manifestEntries({ theme: { sha256: digest('9') } })
  });
  assert.notEqual(changedConfig.fingerprint, baseline.fingerprint);
  assert.notEqual(changedConfig.componentFingerprints.configTree, baseline.componentFingerprints.configTree);
  assert.equal(changedConfig.componentFingerprints.runtimeCodeTree, baseline.componentFingerprints.runtimeCodeTree);

  const changedCode = siteState({
    codeManifest: [{ path: 'composer.lock', sha256: digest('8'), size: 500 }]
  });
  assert.notEqual(changedCode.componentFingerprints.runtimeCodeTree, baseline.componentFingerprints.runtimeCodeTree);

  const changedEntities = siteState({
    entityInventory: {
      nodes: [
        { bundle: 'page', published: true, uuid: '22222222-2222-4222-8222-222222222222' },
        { bundle: 'person', published: true, uuid: '33333333-3333-4333-8333-333333333333' }
      ]
    }
  });
  assert.notEqual(changedEntities.componentFingerprints.entityInventory, baseline.componentFingerprints.entityInventory);

  const changedRoutes = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'node', path: '/people/example', status: 200 }
    ]
  });
  assert.notEqual(changedRoutes.componentFingerprints.routeManifest, baseline.componentFingerprints.routeManifest);

  const changedRuntime = siteState({
    runtimeFacts: {
      coreVersion: '11.3.0',
      phpVersion: '8.4.0',
      databaseDriver: 'mysql',
      systemSchemaSha256: digest('6'),
      effectiveSettingsHmacSha256: digest('7'),
      effectiveActiveConfigSha256: digest('8')
    }
  });
  assert.notEqual(changedRuntime.componentFingerprints.runtimeFacts, baseline.componentFingerprints.runtimeFacts);
  assert.notEqual(changedRuntime.fingerprint, baseline.fingerprint);

  const tamperedManifest = {
    ...baseline.configManifest,
    fingerprint: digest('0')
  };
  assert.throws(() => siteState({ configManifest: tamperedManifest }), /fingerprint does not match/i);
  assert.throws(() => siteState({ routeManifest: { path: '/' } }), /routeManifest must be an array/i);

  const changedEvidenceOnly = siteState({
    packetFingerprint: digest('1'),
    verifierFingerprint: digest('2')
  });
  assert.equal(changedEvidenceOnly.fingerprint, baseline.fingerprint);
  assert.notDeepEqual(changedEvidenceOnly.evidenceBindings, baseline.evidenceBindings);

  const codeEntries = [
    { path: 'composer.lock', sha256: digest('c'), size: 500 },
    { path: 'web/themes/custom/fixture/fixture.info.yml', sha256: digest('d'), size: 80 }
  ];
  const firstEnvironment = siteState({
    codeManifest: {
      ...hashManifest(codeEntries),
      environmentBinding: {
        schemaVersion: 'public-kit.environment-binding.1',
        entryCount: 1,
        fingerprint: digest('4')
      },
      projectEvidenceBinding: {
        schemaVersion: 'public-kit.project-evidence-binding.1',
        entryCount: 1,
        fingerprint: digest('6')
      }
    }
  });
  const changedEnvironment = siteState({
    codeManifest: {
      ...hashManifest(codeEntries),
      environmentBinding: {
        schemaVersion: 'public-kit.environment-binding.1',
        entryCount: 1,
        fingerprint: digest('5')
      },
      projectEvidenceBinding: {
        schemaVersion: 'public-kit.project-evidence-binding.1',
        entryCount: 1,
        fingerprint: digest('7')
      }
    }
  });
  assert.equal(firstEnvironment.fingerprint, changedEnvironment.fingerprint);
  assert.notEqual(
    firstEnvironment.evidenceBindings.machineLocalEnvironment.fingerprint,
    changedEnvironment.evidenceBindings.machineLocalEnvironment.fingerprint
  );
  assert.equal('entries' in firstEnvironment.evidenceBindings.machineLocalEnvironment, false);
  assert.notEqual(
    firstEnvironment.evidenceBindings.projectEvidence.fingerprint,
    changedEnvironment.evidenceBindings.projectEvidence.fingerprint
  );
});

test('the first authoritative pass creates one create-only baseline and later state changes do not revoke it', () => {
  const { packetDir } = lifecycleFixture();
  const baselineState = siteState();
  const first = applyVerificationLifecycle({ packetDir, report: passingReport(baselineState) });
  const baselinePath = join(packetDir, 'evidence', 'lifecycle', 'initial-baseline.json');

  assert.equal(first.initialBaseline.status, 'passed');
  assert.equal(first.initialBaseline.siteStateFingerprint, baselineState.fingerprint);
  assert.equal(first.relation, 'matches-initial-baseline');
  assert.equal(first.currentStateVerified, true);
  assert.equal(existsSync(baselinePath), true);
  const originalBaseline = readFileSync(baselinePath, 'utf8');

  const repeated = applyVerificationLifecycle({ packetDir, report: passingReport(baselineState) });
  assert.equal(repeated.relation, 'matches-initial-baseline');
  assert.equal(readFileSync(baselinePath, 'utf8'), originalBaseline);

  const changedState = siteState({
    entityInventory: {
      nodes: [
        { bundle: 'page', published: true, uuid: '22222222-2222-4222-8222-222222222222' },
        { bundle: 'person', published: true, uuid: '33333333-3333-4333-8333-333333333333' }
      ]
    }
  });
  const changed = applyVerificationLifecycle({
    packetDir,
    report: passingReport(changedState, { completeLocalRebuildClaimAllowed: false })
  });
  assert.equal(changed.initialBaseline.status, 'passed');
  assert.equal(changed.initialBaseline.siteStateFingerprint, baselineState.fingerprint);
  assert.equal(changed.currentSiteStateFingerprint, changedState.fingerprint);
  assert.equal(changed.relation, 'changed-since-latest-anchor');
  assert.equal(changed.currentStateVerified, false);
  assert.equal(readFileSync(baselinePath, 'utf8'), originalBaseline);

  const status = readLifecycleStatus(packetDir);
  assert.equal(status.initialBaseline.status, 'passed');
  assert.equal(status.currentState.relation, 'changed-since-latest-anchor');
});

test('a non-passing report records current state but cannot mint an initial baseline', () => {
  const { packetDir } = lifecycleFixture();
  const state = applyVerificationLifecycle({
    packetDir,
    report: passingReport(siteState(), { completeLocalRebuildClaimAllowed: false })
  });

  assert.equal(state.initialBaseline.status, 'not-recorded');
  assert.equal(state.relation, 'no-initial-baseline');
  assert.equal(state.currentStateVerified, false);
  assert.equal(existsSync(join(packetDir, 'evidence', 'lifecycle', 'initial-baseline.json')), false);
  assert.throws(
    () => beginChange({
      packetDir,
      id: 'too-early',
      kind: 'repair',
      summary: 'Cannot start without a baseline',
      acceptance: ['A baseline exists']
    }),
    /No initial baseline exists/i
  );
});

test('a later full pass does not silently authorize an unclassified changed state', () => {
  const { packetDir } = lifecycleFixture();
  const baselineState = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baselineState) });
  const changedState = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'canvas_page', path: '/new-scope', status: 200 }
    ]
  });

  const current = applyVerificationLifecycle({ packetDir, report: passingReport(changedState) });

  assert.equal(current.initialBaseline.status, 'passed');
  assert.equal(current.relation, 'changed-since-latest-anchor');
  assert.equal(current.currentStateVerified, false);
  assert.equal(current.currentStateClassification.kind, 'unclassified');
  assert.equal(current.currentStateClassification.status, 'unverified');
});

test('repair and extension records require classified impact and allow only one active change', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });

  const repair = beginChange({
    packetDir,
    id: 'restore-brand',
    kind: 'repair',
    summary: 'Restore the shared brand mark',
    surfaces: ['theme-global', 'navigation', 'theme-global'],
    acceptance: ['The brand mark appears on every primary route']
  });
  assert.equal(repair.kind, 'repair');
  assert.deepEqual(repair.surfaces, ['navigation', 'theme-global']);
  for (const required of ['state-bound', 'config-clean', 'baseline-route-smoke', 'repair-regression', 'global-chrome-regression']) {
    assert.ok(repair.requiredChecks.some((check) => check.id === required), required);
  }
  assert.deepEqual(
    repair.requiredChecks.filter((check) => check.evaluator === 'machine').map((check) => check.id),
    ['baseline-route-smoke', 'config-clean', 'state-bound']
  );
  assert.equal(repair.wideningCheck.evaluator, 'authored');
  assert.throws(
    () => beginChange({
      packetDir,
      id: 'personalized-bios',
      kind: 'extension',
      summary: 'Add personalized biography pages',
      surfaces: ['canvas'],
      acceptance: ['Editors can publish a composed biography']
    }),
    /already in progress/i
  );
  assert.throws(
    () => beginChange({
      packetDir,
      id: 'invalid-kind',
      kind: 'maintenance',
      summary: 'Unsupported classification',
      acceptance: ['It works']
    }),
    /repair or extension/i
  );
});

test('begin requires declared public routes or an explicit no-public-route disposition', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  assert.throws(() => beginChange({
    packetDir,
    id: 'missing-route-scope',
    kind: 'extension',
    summary: 'Add editorial behavior without classifying its public route impact',
    surfaces: ['content'],
    acceptance: ['The editorial behavior works']
  }), /--route or explicitly use --no-public-route/i);
  assert.throws(() => beginChange({
    packetDir,
    id: 'invalid-public-opt-out',
    kind: 'extension',
    summary: 'Try to hide a public content change behind an opt-out',
    surfaces: ['content'],
    noPublicRoute: true,
    acceptance: ['The public content behavior works']
  }), /public-output or unresolved surface/i);
  assert.throws(() => beginChange({
    packetDir,
    id: 'literal-global-route',
    kind: 'repair',
    summary: 'Try to self-declare a global route wildcard',
    surfaces: ['editor'],
    routes: ['*'],
    acceptance: ['The route scope is valid']
  }), /Literal --route \*/i);
  assert.equal(
    existsSync(join(packetDir, 'evidence', 'lifecycle', 'changes', 'literal-global-route')),
    false
  );
  const editorOnly = beginChange({
    packetDir,
    id: 'editor-only',
    kind: 'extension',
    summary: 'Add editor-only behavior',
    surfaces: ['editor'],
    noPublicRoute: true,
    acceptance: ['The editor-only behavior works']
  });
  assert.equal(editorOnly.publicRouteScope, 'none');
  assert.deepEqual(editorOnly.affectedRoutes, []);
});

test('change completion fails closed on missing checks and stale fingerprints, then binds exact evidence', () => {
  const { packetDir } = lifecycleFixture();
  const baselineState = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baselineState) });
  const change = beginChange({
    packetDir,
    id: 'restore-brand',
    kind: 'repair',
    summary: 'Restore the shared brand mark',
    surfaces: ['theme-global'],
    acceptance: ['The brand mark appears on every primary route']
  });
  const resultState = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('7'), size: 200 }]
  });
  applyVerificationLifecycle({
    packetDir,
    report: passingReport(resultState, { completeLocalRebuildClaimAllowed: false })
  });

  const completeVerification = verificationFor(change, resultState.fingerprint);
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: {
        ...completeVerification,
        checks: completeVerification.checks.filter((check) => check.id !== 'repair-regression')
      },
      diagnosticReport: passingReport(resultState, { completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /missing passing required check/i
  );
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: { ...completeVerification, resultFingerprint: baselineState.fingerprint },
      diagnosticReport: passingReport(resultState, { completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /does not match the fresh inspected current site state/i
  );

  const verified = completeChange({
    packetDir,
    id: change.id,
    verification: completeVerification,
    diagnosticReport: passingReport(resultState, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });
  assert.equal(verified.status, 'evidence_recorded');
  assert.equal(verified.resultFingerprint, resultState.fingerprint);
  const status = readLifecycleStatus(packetDir);
  assert.equal(status.changes[0].status, 'evidence_recorded');
  assert.equal(status.currentState.currentStateVerified, false);
  assert.equal(status.currentState.currentStateEvidenceRecorded, true);
  assert.equal(status.currentState.latestAnchor.anchorId, change.id);
  assert.equal(status.currentState.latestAnchor.credential, 'evidence_recorded');
  assert.equal(status.currentState.latestVerifiedAnchor.anchorId, 'initial');
  assert.equal(status.currentState.latestVerifiedAnchor.credential, 'full_verified');
  assert.equal(
    existsSync(join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'verification.json')),
    true
  );
  assert.throws(
    () => completeChange({ packetDir, id: change.id, verification: completeVerification }),
    /already evidence_recorded/i
  );
});

test('a verified extension can become a create-only checkpoint and a later change anchors to it', () => {
  const { packetDir } = lifecycleFixture();
  const baselineState = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baselineState) });
  const extension = beginChange({
    packetDir,
    id: 'personalized-bios',
    kind: 'extension',
    summary: 'Add personalized biography pages',
    surfaces: ['canvas', 'content'],
    routes: ['/people/example'],
    acceptance: ['Editors can publish a composed biography backed by canonical person content']
  });
  for (const required of ['extension-acceptance', 'drupal-ownership', 'canvas-model', 'global-chrome-regression']) {
    assert.ok(extension.requiredChecks.some((check) => check.id === required), required);
  }

  const resultState = siteState({
    entityInventory: {
      nodes: [
        { bundle: 'page', published: true, uuid: '22222222-2222-4222-8222-222222222222' },
        { bundle: 'person', published: true, uuid: '33333333-3333-4333-8333-333333333333' }
      ]
    },
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'canvas_page', path: '/people/example', status: 200 }
    ]
  });
  applyVerificationLifecycle({
    packetDir,
    report: passingReport(resultState, { completeLocalRebuildClaimAllowed: false })
  });
  completeChange({
    packetDir,
    id: extension.id,
    verification: verificationFor(extension, resultState.fingerprint),
    diagnosticReport: passingReport(resultState, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });

  const staleCheckpointState = siteState({
    routeManifest: [{ owner: 'node', path: '/unrelated-state', status: 200 }]
  });
  assert.throws(
    () => applyVerificationLifecycle({
      packetDir,
      report: passingReport(staleCheckpointState, {
        routeChecks: [
          { targetPath: '/', passed: true, errors: [] },
          { targetPath: '/people/example', passed: true, errors: [] }
        ]
      }),
      checkpointId: 'stale-bios-state',
      changeId: extension.id
    }),
    /does not match its evidence-recorded state/i
  );

  const checkpointState = applyVerificationLifecycle({
    packetDir,
    report: passingReport(resultState),
    checkpointId: 'post-bios',
    changeId: extension.id
  });
  assert.equal(checkpointState.latestCheckpoint.checkpointId, 'post-bios');
  assert.equal(checkpointState.latestCheckpoint.siteStateFingerprint, resultState.fingerprint);
  assert.equal(checkpointState.relation, 'matches-checkpoint');
  const status = readLifecycleStatus(packetDir);
  assert.deepEqual(status.checkpoints.map((checkpoint) => checkpoint.checkpointId), ['post-bios']);
  assert.equal(status.checkpoints[0].changeId, extension.id);

  assert.throws(
    () => applyVerificationLifecycle({
      packetDir,
      report: passingReport(resultState),
      checkpointId: 'post-bios',
      changeId: extension.id
    }),
    /already exists.*create-only/i
  );

  const next = beginChange({
    packetDir,
    id: 'add-directory',
    kind: 'extension',
    summary: 'Add a public people directory',
    surfaces: ['content', 'routing'],
    routes: ['/people'],
    acceptance: ['The directory lists published people']
  });
  assert.equal(next.baseAnchorId, 'post-bios');
  assert.equal(next.baseAnchorType, 'checkpoint');
  assert.equal(next.baseFingerprint, resultState.fingerprint);
});

test('tampering with a certified baseline or mismatching checkpoint state fails closed', () => {
  const { packetDir } = lifecycleFixture();
  const baselineState = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baselineState) });

  assert.throws(
    () => applyVerificationLifecycle({
      packetDir,
      report: passingReport(baselineState),
      checkpointId: 'unbound-checkpoint',
      changeId: 'missing-change'
    }),
    /does not exist|Change missing-change/i
  );

  const baselinePath = join(packetDir, 'evidence', 'lifecycle', 'initial-baseline.json');
  const tampered = JSON.parse(readFileSync(baselinePath, 'utf8'));
  tampered.claimScope = 'tampered-claim';
  writeFileSync(baselinePath, `${JSON.stringify(tampered, null, 2)}\n`);
  assert.throws(() => readLifecycleStatus(packetDir), /certificate hash is invalid/i);
});

test('begin requires a recent inspected current state and completion rejects stale or future inspections', () => {
  const staleFixture = lifecycleFixture();
  const staleTime = new Date(Date.now() - 11 * 60 * 1000).toISOString();
  applyVerificationLifecycle({
    packetDir: staleFixture.packetDir,
    report: passingReport(siteState(), { checkedAt: staleTime })
  });
  assert.throws(
    () => beginChange({
      packetDir: staleFixture.packetDir,
      id: 'stale-start',
      kind: 'repair',
      summary: 'Do not begin from stale state',
      acceptance: ['Fresh state is required']
    }),
    /stale.*fresh live inspection/i
  );

  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'bounded-time',
    kind: 'repair',
    summary: 'Check inspection time bounds',
    surfaces: ['theme-global'],
    acceptance: ['Inspection time is credible']
  });
  const result = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('7'), size: 200 }]
  });
  const beforeOpen = new Date(Date.parse(change.openedAt) - 1_000).toISOString();
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: passingReport(result, { checkedAt: beforeOpen, completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /must not predate/i
  );
  const future = new Date(Date.now() + 3 * 60 * 1000).toISOString();
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: passingReport(result, { checkedAt: future, completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /far in the future/i
  );
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint, { checkedAt: future }),
      diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /far in the future/i
  );
});

test('fresh machine facts reject dirty config even when authored checks claim pass', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'dirty-config',
    kind: 'repair',
    summary: 'Attempt to certify dirty config',
    surfaces: ['theme-global'],
    acceptance: ['Config is clean']
  });
  const result = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('6'), size: 200 }]
  });
  const dirtyReport = passingReport(result, { completeLocalRebuildClaimAllowed: false });
  dirtyReport.drupalRuntime.configStatusClean = false;
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false })
    }),
    /diagnostic-only.*testOnlyAllowInjectedReport/i
  );
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: dirtyReport,
      testOnlyAllowInjectedReport: true
    }),
    /cannot satisfy config-clean/i
  );
});

test('targeted completion rejects incomplete state fingerprints and mismatched Drupal identity', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'state-readiness',
    kind: 'repair',
    summary: 'Require complete state identity',
    surfaces: ['content'],
    routes: ['/'],
    acceptance: ['The exact Drupal target is ready']
  });
  const result = siteState({
    entityInventory: { nodes: [{ bundle: 'page' }, { bundle: 'person' }] }
  });
  const incomplete = passingReport(result, { completeLocalRebuildClaimAllowed: false });
  incomplete.buildState.complete = false;
  incomplete.buildState.blockers = ['Entity inventory unavailable.'];
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: incomplete,
      testOnlyAllowInjectedReport: true
    }),
    /state-bound.*not ready/i
  );

  const wrongTarget = passingReport(result, { completeLocalRebuildClaimAllowed: false });
  wrongTarget.drupalRuntime.targetOriginMatches = false;
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: wrongTarget,
      testOnlyAllowInjectedReport: true
    }),
    /state-bound.*not ready/i
  );
});

test('targeted evidence is non-authoritative until a separate certified full verification binds it', () => {
  const { packetDir } = lifecycleFixture();
  const baseline = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baseline) });
  const change = beginChange({
    packetDir,
    id: 'evidence-then-full',
    kind: 'repair',
    summary: 'Separate evidence from authority',
    surfaces: ['theme-global'],
    acceptance: ['The visual defect is fixed']
  });
  const intentPath = join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'change.json');
  const originalIntent = readFileSync(intentPath, 'utf8');
  const result = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('5'), size: 200 }]
  });
  const evidenceReport = passingReport(result, { completeLocalRebuildClaimAllowed: false });
  const evidence = completeChange({
    packetDir,
    id: change.id,
    verification: verificationFor(change, result.fingerprint),
    diagnosticReport: evidenceReport,
    testOnlyAllowInjectedReport: true
  });
  assert.equal(evidence.status, 'evidence_recorded');
  assert.equal(readFileSync(intentPath, 'utf8'), originalIntent);
  let status = readLifecycleStatus(packetDir);
  assert.equal(status.currentState.currentStateVerified, false);
  assert.equal(status.currentState.currentStateEvidenceRecorded, true);
  assert.equal(status.changes[0].status, 'evidence_recorded');

  const fullReport = passingReport(result);
  const full = applyVerificationLifecycle({ packetDir, report: fullReport, changeId: change.id });
  assert.equal(full.currentStateVerified, true);
  assert.equal(full.currentStateEvidenceRecorded, false);
  status = readLifecycleStatus(packetDir);
  assert.equal(status.changes[0].status, 'full_verified');
  const fullPath = join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'full-verification.json');
  assert.equal(existsSync(fullPath), true);
  const firstFullRecord = readFileSync(fullPath, 'utf8');

  const repeated = applyVerificationLifecycle({ packetDir, report: passingReport(result), changeId: change.id });
  assert.equal(repeated.currentStateVerified, true);
  assert.equal(readFileSync(fullPath, 'utf8'), firstFullRecord);
});

test('every acceptance criterion requires its own evidence claim', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'criteria-evidence',
    kind: 'extension',
    summary: 'Prove every requested outcome',
    surfaces: ['content'],
    routes: ['/'],
    acceptance: ['Editors can save it', 'Anonymous visitors can read it']
  });
  const result = siteState({ entityInventory: { nodes: [{ bundle: 'person' }] } });
  const verification = verificationFor(change, result.fingerprint);
  verification.acceptanceEvidence.pop();
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification,
      diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /acceptance criterion criterion-2/i
  );
});

test('adopt-current always widens impact to unknown and records the structural base components', () => {
  const { packetDir } = lifecycleFixture();
  const baseline = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baseline) });
  const changed = siteState({
    entityInventory: { nodes: [{ bundle: 'person', published: true, uuid: '33333333-3333-4333-8333-333333333333' }] }
  });
  applyVerificationLifecycle({
    packetDir,
    report: passingReport(changed, { completeLocalRebuildClaimAllowed: false })
  });
  assert.throws(
    () => beginChange({
      packetDir,
      id: 'unadopted',
      kind: 'extension',
      summary: 'Existing work',
      surfaces: ['content'],
      acceptance: ['Existing work is classified']
    }),
    /--adopt-current/i
  );
  const adopted = beginChange({
    packetDir,
    id: 'adopted',
    kind: 'extension',
    summary: 'Adopt existing work',
    surfaces: ['content'],
    routes: ['/'],
    acceptance: ['Existing work is classified'],
    adoptCurrent: true
  });
  assert.deepEqual(adopted.surfaces, ['content', 'unknown']);
  assert.ok(adopted.requiredChecks.some((check) => check.id === 'conservative-full-regression'));
  assert.equal(adopted.baseAnchorId, 'initial');
  assert.equal(adopted.baseFingerprint, baseline.fingerprint);
  assert.deepEqual(adopted.baseComponentFingerprints, baseline.componentFingerprints);
});

test('adopt-current permits an explicit non-public disposition for otherwise non-public surfaces', () => {
  const { packetDir } = lifecycleFixture();
  const baseline = siteState();
  applyVerificationLifecycle({ packetDir, report: passingReport(baseline) });
  const changed = siteState({
    codeManifest: [{ path: 'web/modules/custom/fixture/editor.module', sha256: digest('7'), size: 200 }]
  });
  applyVerificationLifecycle({
    packetDir,
    report: passingReport(changed, { completeLocalRebuildClaimAllowed: false })
  });
  const adopted = beginChange({
    packetDir,
    id: 'adopt-editor-only',
    kind: 'extension',
    summary: 'Adopt an existing editor-only extension',
    surfaces: ['editor'],
    noPublicRoute: true,
    acceptance: ['The editor-only extension is classified'],
    adoptCurrent: true
  });
  assert.equal(adopted.publicRouteScope, 'none');
  assert.deepEqual(adopted.affectedRoutes, []);
  assert.deepEqual(adopted.surfaces, ['editor', 'unknown']);
  assert.ok(adopted.requiredChecks.some((check) => check.id === 'conservative-full-regression'));
});

test('abandonment is a create-only transition and releases the structural tail for another change', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'discarded-work',
    kind: 'repair',
    summary: 'Try a repair',
    routes: ['/'],
    acceptance: ['The attempt is evaluated']
  });
  const intentPath = join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'change.json');
  const intentBytes = readFileSync(intentPath, 'utf8');
  const abandoned = abandonChange({ packetDir, id: change.id, reason: 'The approach was not viable.' });
  assert.equal(abandoned.status, 'abandoned');
  assert.equal(readFileSync(intentPath, 'utf8'), intentBytes);
  assert.equal(
    existsSync(join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'abandonment.json')),
    true
  );
  assert.throws(() => beginChange({
    packetDir,
    id: 'replacement-work',
    kind: 'repair',
    summary: 'Try a safer repair',
    acceptance: ['The replacement works']
  }), /predates the latest abandonment/i);
  applyVerificationLifecycle({
    packetDir,
    report: passingReport(siteState(), { checkedAt: new Date(Date.now() + 10).toISOString() })
  });
  const next = beginChange({
    packetDir,
    id: 'replacement-work',
    kind: 'repair',
    summary: 'Try a safer repair',
    routes: ['/'],
    acceptance: ['The replacement works']
  });
  assert.equal(next.baseAnchorId, 'initial');
  assert.equal(next.baseAnchorType, 'initial');
});

test('edits left behind by an abandoned change require explicit adopt-current classification', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const abandoned = beginChange({
    packetDir,
    id: 'abandoned-with-edits',
    kind: 'repair',
    summary: 'Attempt a code repair',
    surfaces: ['theme-route'],
    routes: ['/'],
    acceptance: ['The attempted repair is reviewed']
  });
  abandonChange({ packetDir, id: abandoned.id, reason: 'The implementation approach was withdrawn.' });
  const edited = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('8'), size: 200 }]
  });
  applyVerificationLifecycle({
    packetDir,
    report: passingReport(edited, { checkedAt: new Date(Date.now() + 10).toISOString() })
  });
  assert.throws(() => beginChange({
    packetDir,
    id: 'replacement-without-adoption',
    kind: 'repair',
    summary: 'Try another repair without classifying leftover edits',
    acceptance: ['The replacement is reviewed']
  }), /differs from the latest structural anchor/i);
  const replacement = beginChange({
    packetDir,
    id: 'replacement-with-adoption',
    kind: 'repair',
    summary: 'Classify the leftover edits before proceeding',
    routes: ['/'],
    acceptance: ['The retained state is explicitly reviewed'],
    adoptCurrent: true
  });
  assert.equal(replacement.adoptedCurrentState, true);
  assert.ok(replacement.surfaces.includes('unknown'));
});

test('intent tampering fails closed while certified historical check wording remains readable', () => {
  const historical = lifecycleFixture();
  applyVerificationLifecycle({ packetDir: historical.packetDir, report: passingReport() });
  const oldChange = beginChange({
    packetDir: historical.packetDir,
    id: 'historical-intent',
    kind: 'repair',
    summary: 'Keep historical contract wording',
    surfaces: ['theme-global'],
    acceptance: ['Historical intent remains valid']
  });
  const oldPath = join(historical.packetDir, 'evidence', 'lifecycle', 'changes', oldChange.id, 'change.json');
  const oldIntent = JSON.parse(readFileSync(oldPath, 'utf8'));
  oldIntent.requiredChecks = oldIntent.requiredChecks.map((check) => ({
    ...check,
    description: `Historical wording for ${check.id}`
  }));
  oldIntent.wideningCheck.description = 'Historical conservative widening wording';
  delete oldIntent.certificateSha256;
  oldIntent.certificateSha256 = sha256(oldIntent);
  writeFileSync(oldPath, `${JSON.stringify(oldIntent, null, 2)}\n`);
  assert.equal(readLifecycleStatus(historical.packetDir).changes[0].status, 'in_progress');

  const tampered = lifecycleFixture();
  applyVerificationLifecycle({ packetDir: tampered.packetDir, report: passingReport() });
  const change = beginChange({
    packetDir: tampered.packetDir,
    id: 'tampered-intent',
    kind: 'repair',
    summary: 'Detect mutation',
    routes: ['/'],
    acceptance: ['Mutation is rejected']
  });
  const path = join(tampered.packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'change.json');
  const intent = JSON.parse(readFileSync(path, 'utf8'));
  intent.summary = 'Silently changed';
  writeFileSync(path, `${JSON.stringify(intent, null, 2)}\n`);
  assert.throws(() => readLifecycleStatus(tampered.packetDir), /certificate hash is invalid/i);
});

test('an evidence-recorded change is the next structural anchor without timestamp selection', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const first = beginChange({
    packetDir,
    id: 'first-link',
    kind: 'extension',
    summary: 'Add the first link',
    surfaces: ['routing'],
    routes: ['/first'],
    acceptance: ['The first route works']
  });
  const result = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'node', path: '/first', status: 200 }
    ]
  });
  completeChange({
    packetDir,
    id: first.id,
    verification: verificationFor(first, result.fingerprint),
    diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });
  const second = beginChange({
    packetDir,
    id: 'second-link',
    kind: 'extension',
    summary: 'Add the second link',
    surfaces: ['routing'],
    routes: ['/second'],
    acceptance: ['The second route works']
  });
  assert.equal(second.baseAnchorId, first.id);
  assert.equal(second.baseAnchorType, 'change');
  assert.equal(second.baseFingerprint, result.fingerprint);
  assert.equal(readLifecycleStatus(packetDir).latestAnchor.id, first.id);
});

test('verification input cannot traverse a symlink ancestor', () => {
  const { packetDir, projectRoot } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'symlink-input',
    kind: 'repair',
    summary: 'Reject symlinked input',
    surfaces: ['theme-global'],
    acceptance: ['Unsafe input is rejected']
  });
  const result = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('4'), size: 200 }]
  });
  const realDirectory = join(projectRoot, 'real-input');
  mkdirSync(realDirectory);
  writeFileSync(join(realDirectory, 'verification.json'), `${JSON.stringify(verificationFor(change, result.fingerprint))}\n`);
  symlinkSync(realDirectory, join(projectRoot, 'linked-input'));
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: join(realpathSync(projectRoot), 'linked-input', 'verification.json'),
      diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
      testOnlyAllowInjectedReport: true
    }),
    /must not traverse a symbolic link/i
  );
});

test('targeted records preserve report and evidence hashes after mutable live output is overwritten', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'durable-evidence',
    kind: 'repair',
    summary: 'Preserve inspection evidence',
    surfaces: ['theme-global'],
    acceptance: ['Evidence remains bound']
  });
  const result = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('3'), size: 200 }]
  });
  completeChange({
    packetDir,
    id: change.id,
    verification: verificationFor(change, result.fingerprint),
    diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });
  const recordPath = join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'verification.json');
  const record = JSON.parse(readFileSync(recordPath, 'utf8'));
  assert.equal(record.inspectionReportSha256, sha256(record.inspectionReport));
  const semantic = record.checks.find((check) => check.id === 'repair-regression');
  assert.match(semantic.evidenceManifest[0].sha256, /^sha256:[a-f0-9]{64}$/);
  assert.match(semantic.evidenceManifest[0].path, /review-packet\/evidence\/objects\/sha256\/[a-f0-9]{64}$/);
  const referencedObjects = [
    ...record.checks.flatMap((check) => check.evidenceManifest ?? []),
    ...record.acceptanceEvidence.flatMap((claim) => claim.evidenceManifest ?? [])
  ].map((entry) => entry.path);
  assert.equal(new Set(referencedObjects).size, 1, 'checks and claims with identical evidence reuse one object');
  assert.equal(readFileSync(join(packetDir, 'evidence', 'change-check.json'), 'utf8'), '{"status":"pass"}\n');
  writeFileSync(join(packetDir, 'evidence', 'change-check.json'), '{"status":"changed later"}\n');
  writeFileSync(join(packetDir, 'evidence', 'live-verification.json'), '{"overwritten":true}\n');
  assert.equal(readLifecycleStatus(packetDir).changes[0].status, 'evidence_recorded');
  const snapshotPath = join(realpathSync(join(packetDir, '..')), semantic.evidenceManifest[0].path);
  writeFileSync(snapshotPath, 'tampered snapshot\n');
  assert.throws(() => readLifecycleStatus(packetDir), /snapshot bytes no longer match/i);
});

test('checkpoint creation refuses to wedge an already active child change', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const first = beginChange({
    packetDir,
    id: 'first-anchor',
    kind: 'repair',
    summary: 'Create the first anchor',
    surfaces: ['content'],
    routes: ['/'],
    acceptance: ['The first result works']
  });
  const result = siteState({ entityInventory: { nodes: [{ bundle: 'person' }] } });
  completeChange({
    packetDir,
    id: first.id,
    verification: verificationFor(first, result.fingerprint),
    diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });
  beginChange({
    packetDir,
    id: 'active-child',
    kind: 'extension',
    summary: 'Keep a child active',
    surfaces: ['content'],
    routes: ['/'],
    acceptance: ['The child remains active']
  });
  assert.throws(
    () => applyVerificationLifecycle({
      packetDir,
      report: passingReport(result),
      changeId: first.id,
      checkpointId: 'unsafe-checkpoint'
    }),
    /checkpoint.*active-child.*active/i
  );
  assert.equal(
    existsSync(join(packetDir, 'evidence', 'lifecycle', 'checkpoints', 'unsafe-checkpoint.json')),
    false
  );
  assert.equal(
    existsSync(join(packetDir, 'evidence', 'lifecycle', 'changes', first.id, 'full-verification.json')),
    false
  );
});

test('tampering with the separate full-verification certificate fails closed', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'full-cert',
    kind: 'repair',
    summary: 'Protect full verification',
    surfaces: ['theme-global'],
    acceptance: ['Full authority is certified']
  });
  const result = siteState({
    codeManifest: [{ path: 'web/themes/custom/fixture/fixture.theme', sha256: digest('2'), size: 200 }]
  });
  completeChange({
    packetDir,
    id: change.id,
    verification: verificationFor(change, result.fingerprint),
    diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });
  applyVerificationLifecycle({ packetDir, report: passingReport(result), changeId: change.id });
  const path = join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'full-verification.json');
  const full = JSON.parse(readFileSync(path, 'utf8'));
  full.authoritative = false;
  writeFileSync(path, `${JSON.stringify(full, null, 2)}\n`);
  assert.throws(() => readLifecycleStatus(packetDir), /certificate hash is invalid/i);
});

test('undeclared build-state components widen the transition to unknown and require its conservative check', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'widen-impact',
    kind: 'extension',
    summary: 'A content change unexpectedly changes runtime code',
    surfaces: ['content'],
    routes: ['/'],
    acceptance: ['The content extension works']
  });
  const result = siteState({
    codeManifest: [{ path: 'web/modules/custom/fixture/fixture.module', sha256: digest('1'), size: 200 }]
  });
  const report = passingReport(result, { completeLocalRebuildClaimAllowed: false });
  const input = verificationFor(change, result.fingerprint);
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: input,
      diagnosticReport: report,
      testOnlyAllowInjectedReport: true
    }),
    /conservative-full-regression/i
  );
  input.checks.push({
    id: 'conservative-full-regression',
    status: 'pass',
    observation: 'All baseline routes and editor boundaries were conservatively reviewed.',
    evidence: ['evidence/change-check.json']
  });
  completeChange({
    packetDir,
    id: change.id,
    verification: input,
    diagnosticReport: report,
    testOnlyAllowInjectedReport: true
  });
  const record = JSON.parse(readFileSync(
    join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'verification.json'),
    'utf8'
  ));
  assert.deepEqual(record.unexpectedComponents, ['runtimeCodeTree']);
  assert.deepEqual(record.effectiveSurfaces, ['content', 'unknown']);
});

test('route changes outside the declared route set widen the transition to unknown', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'route-boundary',
    kind: 'extension',
    summary: 'Add one explicitly scoped route',
    surfaces: ['routing'],
    routes: ['/declared'],
    acceptance: ['The declared route works']
  });
  const result = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'node', path: '/declared', status: 200 },
      { owner: 'node', path: '/undeclared', status: 200 }
    ]
  });
  const report = passingReport(result, { completeLocalRebuildClaimAllowed: false });
  const input = verificationFor(change, result.fingerprint);
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: input,
      diagnosticReport: report,
      testOnlyAllowInjectedReport: true
    }),
    /conservative-full-regression/i
  );
  input.checks.push({
    id: 'conservative-full-regression',
    status: 'pass',
    observation: 'The undeclared route impact received a conservative regression review.',
    evidence: ['evidence/change-check.json']
  });
  completeChange({
    packetDir,
    id: change.id,
    verification: input,
    diagnosticReport: report,
    testOnlyAllowInjectedReport: true
  });
  const record = JSON.parse(readFileSync(
    join(packetDir, 'evidence', 'lifecycle', 'changes', change.id, 'verification.json'),
    'utf8'
  ));
  assert.deepEqual(record.changedRoutes, ['/declared', '/undeclared']);
  assert.deepEqual(record.unexpectedRoutes, ['/undeclared']);
  assert.deepEqual(record.effectiveSurfaces, ['routing', 'unknown']);
});

test('a declared affected route must be present and passing in the fresh live inspection', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'missing-live-route',
    kind: 'extension',
    summary: 'Add a route that must be fetched',
    surfaces: ['routing'],
    routes: ['/must-be-fetched'],
    acceptance: ['The new route works anonymously']
  });
  const result = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'node', path: '/must-be-fetched', status: 200 }
    ]
  });
  const report = passingReport(result, {
    completeLocalRebuildClaimAllowed: false,
    routeChecks: [{ targetPath: '/', passed: true, errors: [] }]
  });
  assert.throws(
    () => completeChange({
      packetDir,
      id: change.id,
      verification: verificationFor(change, result.fingerprint),
      diagnosticReport: report,
      testOnlyAllowInjectedReport: true
    }),
    /Declared affected routes were not live-checked: \/must-be-fetched/i
  );
});

test('affected route checks keep query variants distinct', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'query-route',
    kind: 'extension',
    summary: 'Add one filtered schedule view',
    surfaces: ['routing'],
    routes: ['/schedule?day=1'],
    acceptance: ['The day-one schedule filter works']
  });
  const result = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'view', path: '/schedule?day=2', status: 200 }
    ]
  });
  assert.throws(() => completeChange({
    packetDir,
    id: change.id,
    verification: verificationFor(change, result.fingerprint),
    diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  }), /Declared affected routes were not live-checked: \/schedule\?day=1/i);
});

test('structural graph validation rejects two certified evidence anchors that fork from one parent', () => {
  const { packetDir } = lifecycleFixture();
  applyVerificationLifecycle({ packetDir, report: passingReport() });
  const change = beginChange({
    packetDir,
    id: 'canonical-child',
    kind: 'extension',
    summary: 'Create the canonical child',
    surfaces: ['routing'],
    routes: ['/child'],
    acceptance: ['The child route works']
  });
  const result = siteState({
    routeManifest: [
      { owner: 'node', path: '/', status: 200 },
      { owner: 'node', path: '/child', status: 200 }
    ]
  });
  completeChange({
    packetDir,
    id: change.id,
    verification: verificationFor(change, result.fingerprint),
    diagnosticReport: passingReport(result, { completeLocalRebuildClaimAllowed: false }),
    testOnlyAllowInjectedReport: true
  });

  const sourceDirectory = join(packetDir, 'evidence', 'lifecycle', 'changes', change.id);
  const forkDirectory = join(packetDir, 'evidence', 'lifecycle', 'changes', 'forked-child');
  mkdirSync(forkDirectory);
  const forkIntent = JSON.parse(readFileSync(join(sourceDirectory, 'change.json'), 'utf8'));
  forkIntent.id = 'forked-child';
  forkIntent.summary = 'A conflicting child of the same parent';
  delete forkIntent.certificateSha256;
  forkIntent.certificateSha256 = sha256(forkIntent);
  writeFileSync(join(forkDirectory, 'change.json'), `${JSON.stringify(forkIntent, null, 2)}\n`);
  const forkVerification = JSON.parse(readFileSync(join(sourceDirectory, 'verification.json'), 'utf8'));
  forkVerification.changeId = 'forked-child';
  delete forkVerification.certificateSha256;
  forkVerification.certificateSha256 = sha256(forkVerification);
  writeFileSync(join(forkDirectory, 'verification.json'), `${JSON.stringify(forkVerification, null, 2)}\n`);

  assert.throws(() => readLifecycleStatus(packetDir), /Lifecycle fork detected/i);
});
