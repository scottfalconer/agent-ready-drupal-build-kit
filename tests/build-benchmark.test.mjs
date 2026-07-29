import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildSchedule,
  canonicalJson,
  newOutputProjection,
  parseCodexJsonl,
  parseQuality,
  parseSequence,
  sha256,
  startSchedulerGapMonitor,
  summarizeExperiment,
  validateScenario
} from '../scripts/benchmark-builds.mjs';
import {
  benchmarkDatabaseVolumeOwnershipPass,
  boundedConfigDeltaPass,
  boundedGrantsViewStructurePass,
  buildInvariantProjection,
  clearGeneratedRuntimeTrees,
  configOnlyPathViolations,
  copiedSeedProjection,
  exactConfigSyncDiffPass,
  assertSafeSeedOutputPaths
} from '../benchmarks/scenarios/grants-micro-v1/adapter.mjs';
import { summaryPathFor } from '../skills/agent-ready-drupal-build-kit/scripts/verify.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runnerPath = resolve(repoRoot, 'scripts', 'benchmark-builds.mjs');
const liveSummaryPath = summaryPathFor('review-packet/evidence/live-verification.json');

function recomputeRunFingerprint(run) {
  return sha256(canonicalJson({
    schemaVersion: run.schemaVersion,
    authority: run.authority,
    experimentFingerprint: run.experimentFingerprint,
    runId: run.runId,
    order: run.order,
    identity: run.identity,
    eligibility: run.eligibility,
    timing: run.timing,
    context: run.context,
    quality: run.quality,
    artifacts: run.artifacts
  }));
}

function scenarioFixture(overrides = {}) {
  const base = {
    schemaVersion: 'public-kit.build-benchmark-scenario.1',
    id: 'test-build',
    description: 'Exercise a representative build benchmark workload.',
    measurementBoundary: {
      start: 'Immediately before the build command.',
      end: 'Immediately after the build command.'
    },
    quality: { mode: 'exact' },
    minimumValidRunsPerArm: 2,
    thresholds: {
      minimumMedianImprovementPercent: 10,
      minimumMedianImprovementMs: 100,
      minimumTokenImprovementPercent: 10,
      minimumToolOutputImprovementPercent: 10,
      maximumMedianRegressionPercent: 5,
      maximumMedianRegressionMs: 30_000,
      requireEveryPairFaster: true
    },
    variables: {},
    commands: {
      prepare: [],
      build: [{
        argv: [process.execPath, '-e', 'process.stdout.write("")'],
        adapter: 'codex-jsonl-v1'
      }],
      evaluate: [{
        argv: [process.execPath, '-e', 'process.stdout.write("{}")']
      }],
      cleanup: []
    }
  };
  return {
    ...base,
    ...overrides,
    measurementBoundary: {
      ...base.measurementBoundary,
      ...(overrides.measurementBoundary ?? {})
    },
    quality: {
      ...base.quality,
      ...(overrides.quality ?? {})
    },
    thresholds: {
      ...base.thresholds,
      ...(overrides.thresholds ?? {})
    },
    variables: overrides.variables ?? base.variables,
    commands: {
      ...base.commands,
      ...(overrides.commands ?? {})
    }
  };
}

function experimentFixture(overrides = {}) {
  const base = {
    fingerprint: 'sha256:experiment',
    quality: { mode: 'exact' },
    minimumValidRunsPerArm: 2,
    thresholds: {
      minimumMedianImprovementPercent: 5,
      minimumMedianImprovementMs: 40,
      minimumTokenImprovementPercent: 20,
      minimumToolOutputImprovementPercent: 20,
      maximumMedianRegressionPercent: 5,
      maximumMedianRegressionMs: 30_000,
      requireEveryPairFaster: true
    }
  };
  return {
    ...base,
    ...overrides,
    quality: { ...base.quality, ...(overrides.quality ?? {}) },
    thresholds: { ...base.thresholds, ...(overrides.thresholds ?? {}) }
  };
}

function benchmarkRun({
  ordinal,
  armId,
  durationMs,
  outcomeDurationMs = durationMs,
  totalTokens,
  toolOutputBytes,
  outcomeFingerprint = 'sha256:same-quality',
  eligible = true
}) {
  return {
    runId: `${String(ordinal).padStart(3, '0')}-${armId}`,
    order: {
      ordinal,
      armId,
      warmup: false
    },
    eligibility: {
      eligible,
      exclusionReasons: eligible ? [] : ['fixture-failure'],
      contaminationFlags: []
    },
    timing: {
      measuredOutcomeWallClockMs: outcomeDurationMs,
      measuredBuildWallClockMs: durationMs,
      measuredProductWallClockMs: durationMs,
      measuredHarnessWallClockMs: 0,
      totalWallClockMs: outcomeDurationMs + 100,
      schedulerGap: null
    },
    context: {
      coverage: 'complete',
      usageComplete: true,
      usage: {
        inputTokens: totalTokens - 10,
        cachedInputTokens: 10,
        outputTokens: 10,
        totalTokens
      },
      toolOutputBytes,
      toolCallCount: 3
    },
    quality: {
      valid: true,
      outcomeFingerprint
    }
  };
}

function balancedRuns({
  baselineMs = [1_000, 1_100],
  candidateMs = [800, 700],
  baselineOutcomeMs = baselineMs,
  candidateOutcomeMs = candidateMs,
  baselineTokens = 1_000,
  candidateTokens = 700,
  baselineToolBytes = 2_000,
  candidateToolBytes = 1_000,
  candidateFingerprint = 'sha256:same-quality'
} = {}) {
  return [
    benchmarkRun({
      ordinal: 1,
      armId: 'baseline',
      durationMs: baselineMs[0],
      outcomeDurationMs: baselineOutcomeMs[0],
      totalTokens: baselineTokens,
      toolOutputBytes: baselineToolBytes
    }),
    benchmarkRun({
      ordinal: 2,
      armId: 'candidate',
      durationMs: candidateMs[0],
      outcomeDurationMs: candidateOutcomeMs[0],
      totalTokens: candidateTokens,
      toolOutputBytes: candidateToolBytes,
      outcomeFingerprint: candidateFingerprint
    }),
    benchmarkRun({
      ordinal: 3,
      armId: 'candidate',
      durationMs: candidateMs[1],
      outcomeDurationMs: candidateOutcomeMs[1],
      totalTokens: candidateTokens,
      toolOutputBytes: candidateToolBytes,
      outcomeFingerprint: candidateFingerprint
    }),
    benchmarkRun({
      ordinal: 4,
      armId: 'baseline',
      durationMs: baselineMs[1],
      outcomeDurationMs: baselineOutcomeMs[1],
      totalTokens: baselineTokens,
      toolOutputBytes: baselineToolBytes
    })
  ];
}

test('validateScenario normalizes safe commands and rejects shells and unknown placeholders', () => {
  const scenario = validateScenario(scenarioFixture({
    variables: { fixturePath: null },
    commands: {
      prepare: [{
        argv: [process.execPath, '{scenarioDir}/prepare.mjs', '{var:fixturePath}'],
        cwd: '{runDir}',
        env: { BENCHMARK_ARM: '{armId}' }
      }]
    }
  }));

  assert.equal(scenario.minimumValidRunsPerArm, 2);
  assert.equal(scenario.commands.prepare[0].timeoutMs, 6 * 60 * 60 * 1_000);
  assert.equal(scenario.commands.prepare[0].adapter, null);
  assert.deepEqual(scenario.commands.prepare[0].env, { BENCHMARK_ARM: '{armId}' });

  assert.throws(
    () => validateScenario(scenarioFixture({
      commands: {
        build: [{
          argv: ['/bin/bash', '-lc', 'node build.mjs'],
          adapter: 'codex-jsonl-v1'
        }]
      }
    })),
    /must not invoke a shell/
  );

  assert.throws(
    () => validateScenario(scenarioFixture({
      commands: {
        prepare: [{
          argv: [process.execPath, '{unknownPath}/prepare.mjs']
        }]
      }
    })),
    /unknown placeholder \{unknownPath\}/
  );

  assert.throws(
    () => validateScenario(scenarioFixture({
      commands: {
        build: [{
          argv: [process.execPath, '-e', 'process.stdout.write("")'],
          adapter: 'codex-jsonl-v1',
          env: { OPENAI_API_KEY: 'must-not-reach-agent' }
        }]
      }
    })),
    /may only blank variables; measured agent inheritance is runner-owned \(OPENAI_API_KEY\)/
  );
});

test('grants micro production scenario binds frozen inputs, runtime, and external run ownership', () => {
  const scenarioDir = resolve(repoRoot, 'benchmarks', 'scenarios', 'grants-micro-v1');
  const scenario = validateScenario(JSON.parse(
    readFileSync(resolve(scenarioDir, 'scenario.json'), 'utf8')
  ));

  assert.equal(scenario.quality.mode, 'exact');
  assert.equal(scenario.minimumValidRunsPerArm, 2);
  const pilotSchedule = buildSchedule(parseSequence('ABBA'));
  assert.equal(
    pilotSchedule.filter(({ armId, warmup }) => armId === 'baseline' && !warmup).length,
    scenario.minimumValidRunsPerArm
  );
  assert.equal(
    pilotSchedule.filter(({ armId, warmup }) => armId === 'candidate' && !warmup).length,
    scenario.minimumValidRunsPerArm
  );

  assert.deepEqual(scenario.identityFiles, [
    { id: 'scenario-adapter', path: '{scenarioDir}/adapter.mjs' },
    { id: 'scenario-prompt', path: '{scenarioDir}/prompt.md' },
    { id: 'seed-manifest', path: '{var:seedProject}/benchmark-seed/manifest.json' },
    { id: 'seed-ddev-config', path: '{var:seedProject}/.ddev/config.yaml' },
    { id: 'seed-codex-image', path: '{var:seedProject}/.ddev/web-build/Dockerfile.ddev-assistant-codex' },
    { id: 'seed-codex-mount', path: '{var:seedProject}/.ddev/docker-compose.ddev-assistant-codex.yaml' },
    { id: 'seed-codex-hook', path: '{var:seedProject}/.ddev/config.ddev-assistant-codex.yaml' },
    { id: 'seed-drupal-settings', path: '{var:seedProject}/web/sites/default/settings.php' },
    { id: 'seed-ddev-settings', path: '{var:seedProject}/web/sites/default/settings.ddev.php' }
  ]);
  assert.deepEqual(scenario.runtime, {
    agentAdapter: 'ddev-codex',
    codexCliVersion: '{var:codexVersion}',
    model: '{var:model}',
    reasoningEffort: '{var:reasoningEffort}',
    serviceTier: '{var:serviceTier}',
    sandbox: 'trusted-revision-disposable-ddev',
    credentialPolicy: 'One complete Codex auth.json copy is agent-readable only during the measured turn, then revoked; use pre-reviewed trusted kit revisions only.',
    isolationPolicy: 'SSH agent, credential-like environment variables, shared DDEV cache, and shared DDEV network are removed; model API egress remains.'
  });
  assert.equal(scenario.variables.seedTreeFingerprint, null);

  const lifecycleCommands = {
    prepare: scenario.commands.prepare[0],
    precheck: scenario.commands.build.find(({ argv }) => argv.includes('precheck')),
    install: scenario.commands.build.find(({ argv }) => argv.includes('install')),
    seal: scenario.commands.build.find(({ argv }) => argv.includes('seal')),
    evaluate: scenario.commands.evaluate[0],
    cleanup: scenario.commands.cleanup[0]
  };
  for (const [phase, command] of Object.entries(lifecycleCommands)) {
    assert.ok(command, `${phase} command must be declared`);
    const optionIndex = command.argv.indexOf('--run-dir');
    assert.notEqual(optionIndex, -1, `${phase} must receive the external run directory`);
    assert.equal(command.argv[optionIndex + 1], '{runDir}');
  }
  assert.equal(lifecycleCommands.precheck.measurementRole, 'harness');
  assert.equal(lifecycleCommands.install.measurementRole, 'product');
  assert.equal(lifecycleCommands.seal.measurementRole, 'harness');
  const seedTreeOption = lifecycleCommands.prepare.argv.indexOf('--seed-tree-fingerprint');
  assert.notEqual(seedTreeOption, -1);
  assert.equal(
    lifecycleCommands.prepare.argv[seedTreeOption + 1],
    '{var:seedTreeFingerprint}'
  );
  const grantsAdapter = readFileSync(resolve(scenarioDir, 'adapter.mjs'), 'utf8');
  assert.match(grantsAdapter, /actualDdevVersion !== verifiedSeed\.manifest\.ddevVersion/);
  assert.doesNotMatch(grantsAdapter, /\$expectedGrantAliases|\$grantAliasByTitle/);
  assert.match(grantsAdapter, /facts\.grantAliasCount === 0/);
  assert.match(grantsAdapter, /boundedGrantsViewStructurePass\(facts\)/);
  assert.match(grantsAdapter, /removeOwnedDatabaseVolume\(owner, workspace\)/);
  assert.match(grantsAdapter, /\['volume', 'rm', volumeName\]/);
  assert.match(grantsAdapter, /\(\$operator === '' \|\| \$operator === 'in'\)/);
  assert.match(grantsAdapter, /\(\$operator === '' \|\| \$operator === '='\)/);

  const agentCommand = scenario.commands.build.find(({ adapter }) => adapter === 'codex-jsonl-v1');
  const sandboxIndex = agentCommand.argv.indexOf('--sandbox');
  assert.equal(agentCommand.argv[sandboxIndex + 1], 'danger-full-access');

  const prompt = readFileSync(resolve(scenarioDir, 'prompt.md'), 'utf8');
  assert.doesNotMatch(prompt, /(?:\.benchmark-run\.json|run-owner\.json)/);
  assert.match(prompt, /required, single-value fields/);
  assert.match(prompt, /basic_editorial/);
  assert.match(prompt, /pre-existing entities/);
  assert.match(prompt, /Do not create\s+temporary users, nodes, aliases/);
  assert.match(prompt, /Do not add other fields, filters, sorts/);
  assert.match(prompt, /Pathauto may create aliases automatically/);
  assert.match(prompt, /verify that no Grant alias remains/);
});

test('Grants View structure accepts only the bounded page and handler contract', () => {
  const boundedFacts = {
    grantsPageDisplayId: 'page_1',
    grantsViewDisplayIds: ['default', 'page_1'],
    grantsViewDisplayPlugins: {
      default: 'default',
      page_1: 'page'
    },
    grantsViewRawHandlerIds: {
      default: {
        arguments: [],
        empty: [],
        fields: ['field_application_deadline', 'field_grant_amount', 'title'],
        filters: ['status', 'type'],
        footer: [],
        header: [],
        relationships: [],
        sorts: []
      },
      page_1: {
        arguments: null,
        empty: null,
        fields: null,
        filters: null,
        footer: null,
        header: null,
        relationships: null,
        sorts: null
      }
    },
    grantsViewHandlerIds: {
      arguments: [],
      empty: [],
      fields: ['field_application_deadline', 'field_grant_amount', 'title'],
      filters: ['status', 'type'],
      footer: [],
      header: [],
      relationships: [],
      sorts: []
    }
  };
  assert.equal(boundedGrantsViewStructurePass(boundedFacts), true);

  for (const mutate of [
    (facts) => {
      facts.grantsViewDisplayIds.push('block_1');
      facts.grantsViewDisplayPlugins.block_1 = 'block';
    },
    (facts) => facts.grantsViewHandlerIds.fields.push('body'),
    (facts) => facts.grantsViewHandlerIds.filters.push('created'),
    (facts) => facts.grantsViewHandlerIds.sorts.push('title'),
    (facts) => facts.grantsViewHandlerIds.arguments.push('nid'),
    (facts) => facts.grantsViewHandlerIds.relationships.push('uid'),
    (facts) => facts.grantsViewHandlerIds.header.push('area_text_custom'),
    (facts) => facts.grantsViewHandlerIds.footer.push('result'),
    (facts) => facts.grantsViewHandlerIds.empty.push('area_text_custom'),
    (facts) => facts.grantsViewRawHandlerIds.default.sorts.push('title'),
    (facts) => facts.grantsViewRawHandlerIds.page_1.fields = ['title']
  ]) {
    const extraStructure = structuredClone(boundedFacts);
    mutate(extraStructure);
    assert.equal(boundedGrantsViewStructurePass(extraStructure), false);
  }
});

test('benchmark database-volume ownership requires the exact generated name and Compose label', () => {
  const projectName = 'arb-grants-grants-micro-v1-ms58iqc9-9c2b663441';
  const owned = {
    Name: `${projectName}-mariadb`,
    Driver: 'local',
    Scope: 'local',
    Labels: {
      'com.docker.compose.project': `ddev-${projectName}`
    }
  };
  assert.equal(benchmarkDatabaseVolumeOwnershipPass(owned, projectName), true);
  assert.equal(
    benchmarkDatabaseVolumeOwnershipPass(
      { ...owned, Name: 'arbk-speed-seed-mariadb' },
      projectName
    ),
    false
  );
  assert.equal(
    benchmarkDatabaseVolumeOwnershipPass(
      {
        ...owned,
        Labels: { 'com.docker.compose.project': 'ddev-arbk-speed-seed' }
      },
      projectName
    ),
    false
  );
  assert.equal(
    benchmarkDatabaseVolumeOwnershipPass(owned, 'arbk-speed-seed'),
    false
  );
  assert.equal(
    benchmarkDatabaseVolumeOwnershipPass({ ...owned, Driver: 'remote' }, projectName),
    false
  );
  assert.equal(
    benchmarkDatabaseVolumeOwnershipPass({ ...owned, Scope: 'global' }, projectName),
    false
  );
});

test('high-error diagnosis scenario keeps the measured host agent opaque and trusted-only', () => {
  const scenarioDir = resolve(repoRoot, 'benchmarks', 'scenarios', 'high-error-diagnosis-v1');
  const scenario = validateScenario(JSON.parse(
    readFileSync(resolve(scenarioDir, 'scenario.json'), 'utf8')
  ));

  assert.equal(scenario.quality.mode, 'exact');
  assert.equal(scenario.minimumValidRunsPerArm, 2);
  assert.deepEqual(
    scenario.identityFiles.map(({ id }) => id),
    ['scenario-adapter', 'scenario-prompt', 'diagnostic-reader']
  );
  assert.match(scenario.runtime.credentialPolicy, /pre-reviewed trusted kit revisions/i);
  assert.match(scenario.runtime.credentialPolicy, /defense in depth, not proof/);
  assert.match(scenario.runtime.isolationPolicy, /limits writes, not all reads/);
  const prepare = scenario.commands.prepare[0];
  const codexVersionOption = prepare.argv.indexOf('--codex-version');
  assert.notEqual(codexVersionOption, -1);
  assert.equal(prepare.argv[codexVersionOption + 1], '{var:codexVersion}');
  assert.equal(scenario.variables.codexVersion, '0.142.5');
  assert.equal(scenario.variables.model, 'gpt-5.4');

  const install = scenario.commands.build.find(({ argv }) => argv.includes('install'));
  const agent = scenario.commands.build.find(({ adapter }) => adapter === 'codex-jsonl-v1');
  assert.equal(install.measurementRole, 'harness');
  assert.equal(agent.measurementRole, 'product');
  assert.equal(agent.cwd, '{workspace}');
  assert.ok(agent.argv.includes('--skip-git-repo-check'));
  assert.deepEqual(
    Object.keys(agent.env).sort(),
    [
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
      'GH_TOKEN',
      'GITHUB_TOKEN',
      'GOOGLE_APPLICATION_CREDENTIALS',
      'NPM_TOKEN',
      'SSH_AUTH_SOCK'
    ]
  );
  assert.ok(Object.values(agent.env).every((value) => value === ''));
  const serializedAgentSurface = JSON.stringify({
    argv: agent.argv,
    cwd: agent.cwd,
    env: agent.env
  });
  assert.doesNotMatch(
    serializedAgentSurface,
    /\{(?:armId|armKit|evaluatorKit|experimentDir|experimentId|repoRoot|runDir|runId|runOrdinal|scenarioDir|scenarioId)\}/
  );

  const prompt = readFileSync(resolve(scenarioDir, 'prompt.md'), 'utf8');
  assert.match(prompt, /Invoke the installed arm verifier exactly once/);
  assert.match(prompt, /Do not repair/);
  assert.match(prompt, /diagnostic-only/);
  assert.match(prompt, /Do not run `pwd`/);
  assert.match(prompt, /Do not sum per-gate `errorCount` values/);
  assert.match(prompt, /top-level `errors` strings/);
  const adapter = readFileSync(resolve(scenarioDir, 'adapter.mjs'), 'utf8');
  assert.match(adapter, /Do not run \\`pwd\\`/);
  assert.match(adapter, /helperCommands\.length === readEvents\.length/);
  assert.match(adapter, /text\.includes\(ARM_REPORT\) \|\| text\.includes\(ARM_SUMMARY\)/);
  assert.doesNotMatch(adapter, /readEvents\.length\s*<=\s*2/);
  for (const name of ['adapter.mjs', 'read-diagnostic.mjs', 'README.md']) {
    const path = resolve(scenarioDir, name);
    assert.equal(lstatSync(path).isFile(), true);
    assert.equal(lstatSync(path).isSymbolicLink(), false);
  }
});

test('seed and protected-tree projections detect complete byte, mode, and path changes', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-tree-projection-test-'));
  const seedRoot = resolve(temporaryRoot, 'seed');
  const writeFixture = (root, path, value) => {
    mkdirSync(dirname(resolve(root, path)), { recursive: true });
    writeFileSync(resolve(root, path), value);
  };
  try {
    mkdirSync(seedRoot);
    writeFixture(seedRoot, '.git/metadata', 'ignored-a\n');
    writeFixture(seedRoot, 'vendor/example/library.txt', 'protected-a\n');
    writeFixture(seedRoot, 'scripts/tool.sh', '#!/bin/sh\nexit 0\n');
    chmodSync(resolve(seedRoot, 'scripts/tool.sh'), 0o755);

    const originalSeed = copiedSeedProjection(seedRoot);
    writeFixture(seedRoot, '.git/metadata', 'ignored-b\n');
    assert.deepEqual(copiedSeedProjection(seedRoot), originalSeed);

    writeFixture(seedRoot, 'vendor/example/library.txt', 'protected-b\n');
    assert.notEqual(copiedSeedProjection(seedRoot).sha256, originalSeed.sha256);
    writeFixture(seedRoot, 'vendor/example/library.txt', 'protected-a\n');
    chmodSync(resolve(seedRoot, 'scripts/tool.sh'), 0o644);
    assert.notEqual(copiedSeedProjection(seedRoot).sha256, originalSeed.sha256);

    const workspace = resolve(temporaryRoot, 'workspace');
    mkdirSync(workspace);
    for (const [path, value] of [
      ['.git/metadata', 'git-a\n'],
      ['.benchmark-runtime/evaluator.txt', 'runtime-a\n'],
      ['.ddev/traefik/router.txt', 'router-a\n'],
      ['config/sync/system.site.yml', 'site-a\n'],
      ['review-packet/evidence/result.json', '{}\n'],
      ['web/sites/default/files/css/generated.css', 'css-a\n'],
      ['vendor/example/library.txt', 'vendor-a\n'],
      ['.ddev/config.yaml', 'name: fixture\n']
    ]) {
      writeFixture(workspace, path, value);
    }
    const originalInvariant = buildInvariantProjection(workspace);
    for (const [path, value] of [
      ['.git/metadata', 'git-b\n'],
      ['.benchmark-runtime/evaluator.txt', 'runtime-b\n'],
      ['.ddev/traefik/router.txt', 'router-b\n'],
      ['config/sync/system.site.yml', 'site-b\n'],
      ['review-packet/evidence/result.json', '{"valid":true}\n']
    ]) {
      writeFixture(workspace, path, value);
    }
    assert.deepEqual(buildInvariantProjection(workspace), originalInvariant);
    writeFixture(workspace, 'web/sites/default/files/css/generated.css', 'css-b\n');
    assert.notEqual(buildInvariantProjection(workspace).sha256, originalInvariant.sha256);
    writeFixture(workspace, 'web/sites/default/files/css/generated.css', 'css-a\n');
    writeFixture(workspace, 'vendor/example/library.txt', 'vendor-b\n');
    assert.notEqual(buildInvariantProjection(workspace).sha256, originalInvariant.sha256);
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('generated-tree cleanup and seed freezing reject symlink traversal', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-safe-cleanup-test-'));
  const workspace = resolve(temporaryRoot, 'workspace');
  const outside = resolve(temporaryRoot, 'outside');
  const seed = resolve(temporaryRoot, 'seed');
  try {
    mkdirSync(resolve(workspace, 'web/sites/default'), { recursive: true });
    mkdirSync(outside);
    writeFileSync(resolve(outside, 'keep.txt'), 'keep\n');
    symlinkSync(outside, resolve(workspace, 'web/sites/default/files'));
    assert.throws(
      () => clearGeneratedRuntimeTrees(workspace),
      /Unsafe directory component/
    );
    assert.equal(readFileSync(resolve(outside, 'keep.txt'), 'utf8'), 'keep\n');

    mkdirSync(seed);
    symlinkSync(outside, resolve(seed, 'benchmark-seed'));
    assert.throws(
      () => assertSafeSeedOutputPaths(seed),
      /regular non-symlink directory/
    );
    rmSync(resolve(seed, 'benchmark-seed'));
    mkdirSync(resolve(seed, 'benchmark-seed'));
    symlinkSync(resolve(outside, 'keep.txt'), resolve(seed, 'benchmark-seed/manifest.json'));
    assert.throws(
      () => assertSafeSeedOutputPaths(seed),
      /manifest\.json.*regular non-symlink file/
    );
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('strict build paths and exact config delta allow only the bounded Grant contract', () => {
  const expectedConfigPaths = [
    'core.entity_form_display.node.grant.default',
    'core.entity_view_display.node.grant.default',
    'field.field.node.grant.field_application_deadline',
    'field.field.node.grant.field_grant_amount',
    'field.storage.node.field_application_deadline',
    'field.storage.node.field_grant_amount',
    'node.type.grant',
    'views.view.grants',
    'user.role.content_editor',
    'workflows.workflow.basic_editorial'
  ].map((name) => `config/sync/${name}.yml`);
  assert.equal(
    exactConfigSyncDiffPass([
      'review-packet/evidence/result.json',
      ...expectedConfigPaths
    ]),
    true
  );
  assert.equal(
    exactConfigSyncDiffPass([
      ...expectedConfigPaths,
      'config/sync/system.site.yml'
    ]),
    false
  );
  assert.equal(
    exactConfigSyncDiffPass(expectedConfigPaths.slice(1)),
    false
  );
  assert.deepEqual(
    configOnlyPathViolations([
      'config/sync/node.type.grant.yml',
      'review-packet/evidence/result.json',
      'review-packet/screenshot.webp'
    ]),
    []
  );
  assert.deepEqual(
    configOnlyPathViolations([
      'config/sync/language/fr/node.type.grant.yml',
      'composer.json',
      'web/modules/custom/grants/grants.module'
    ]),
    [
      'config/sync/language/fr/node.type.grant.yml',
      'composer.json',
      'web/modules/custom/grants/grants.module'
    ]
  );

  const baselinePermissions = [
    'access content',
    'use basic_editorial transition create_new_draft',
    'use basic_editorial transition publish'
  ];
  const baseline = {
    configHashes: {
      'default:system.site': '0'.repeat(64),
      'default:user.role.content_editor': '1'.repeat(64),
      'default:workflows.workflow.basic_editorial': '2'.repeat(64)
    },
    contentEditorConfig: {
      id: 'content_editor',
      dependencies: {
        config: ['node.type.page'],
        module: ['node']
      },
      permissions: baselinePermissions
    },
    workflowConfig: {
      id: 'basic_editorial',
      dependencies: {
        config: ['node.type.page'],
        module: ['content_moderation']
      },
      type_settings: {
        entity_types: {
          node: ['page']
        },
        states: {
          draft: { published: false },
          published: { published: true }
        }
      }
    }
  };
  const addedConfigNames = [
    'core.entity_form_display.node.grant.default',
    'core.entity_view_display.node.grant.default',
    'field.field.node.grant.field_application_deadline',
    'field.field.node.grant.field_grant_amount',
    'field.storage.node.field_application_deadline',
    'field.storage.node.field_grant_amount',
    'node.type.grant',
    'views.view.grants'
  ];
  const final = structuredClone(baseline);
  final.configHashes['default:user.role.content_editor'] = '3'.repeat(64);
  final.configHashes['default:workflows.workflow.basic_editorial'] = '4'.repeat(64);
  for (const name of addedConfigNames) {
    final.configHashes[`default:${name}`] = '5'.repeat(64);
  }
  final.contentEditorConfig.dependencies.config.push('node.type.grant');
  final.contentEditorConfig.permissions.push(
    'create grant content',
    'edit own grant content'
  );
  final.workflowConfig.dependencies.config.push('node.type.grant');
  final.workflowConfig.type_settings.entity_types.node.push('grant');

  assert.equal(boundedConfigDeltaPass(baseline, final), true);

  const extraPermission = structuredClone(final);
  extraPermission.contentEditorConfig.permissions.push('delete any grant content');
  assert.equal(boundedConfigDeltaPass(baseline, extraPermission), false);

  const extraConfig = structuredClone(final);
  extraConfig.configHashes['default:system.logging'] = '6'.repeat(64);
  assert.equal(boundedConfigDeltaPass(baseline, extraConfig), false);

  const missingDependency = structuredClone(final);
  missingDependency.workflowConfig.dependencies.config =
    missingDependency.workflowConfig.dependencies.config.filter((name) => name !== 'node.type.grant');
  assert.equal(boundedConfigDeltaPass(baseline, missingDependency), false);
});

test('parseSequence and buildSchedule preserve balanced ABBA blocks and balanced warmups', () => {
  const sequence = parseSequence(' abba-baab ');
  assert.deepEqual(sequence, ['A', 'B', 'B', 'A', 'B', 'A', 'A', 'B']);

  const schedule = buildSchedule(sequence, 1);
  assert.equal(schedule.length, 10);
  assert.deepEqual(
    schedule.slice(0, 2).map(({ armId, warmup, block }) => ({ armId, warmup, block })),
    [
      { armId: 'candidate', warmup: true, block: 0 },
      { armId: 'baseline', warmup: true, block: 0 }
    ]
  );
  assert.deepEqual(
    schedule.slice(2).map(({ armId }) => armId),
    ['baseline', 'candidate', 'candidate', 'baseline', 'candidate', 'baseline', 'baseline', 'candidate']
  );

  for (const block of [1, 2]) {
    const arms = schedule.filter((row) => row.block === block).map(({ armId }) => armId);
    assert.equal(arms.filter((arm) => arm === 'baseline').length, 2);
    assert.equal(arms.filter((arm) => arm === 'candidate').length, 2);
  }

  assert.throws(() => parseSequence('ABB'), /even ordering/);
  assert.throws(() => parseSequence('AAAB'), /equal A and B/);
  assert.throws(() => parseSequence('AABB'), /adjacent pair/);
  assert.throws(() => parseSequence('ABAB'), /balance AB and BA/);
  assert.throws(() => parseSequence('ABAB-BABA'), /ABBA or BAAB/);
  assert.deepEqual(
    parseSequence('BAAB-ABBA'),
    ['B', 'A', 'A', 'B', 'A', 'B', 'B', 'A']
  );
});

test('canonicalJson and sha256 are stable across object key order', () => {
  const left = {
    z: 1,
    a: {
      y: 'café',
      x: [3, 2, 1]
    }
  };
  const right = {
    a: {
      x: [3, 2, 1],
      y: 'café'
    },
    z: 1
  };

  assert.equal(canonicalJson(left), '{"a":{"x":[3,2,1],"y":"café"},"z":1}');
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(sha256(canonicalJson(left)), sha256(canonicalJson(right)));
  assert.notEqual(
    sha256(canonicalJson(left)),
    sha256(canonicalJson({ ...right, a: { ...right.a, x: [1, 2, 3] } }))
  );
});

test('new experiment output rejects a symlinked ancestor before creating evidence', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-output-symlink-test-'));
  const protectedRoot = resolve(temporaryRoot, 'protected');
  const link = resolve(temporaryRoot, 'linked-parent');
  try {
    mkdirSync(protectedRoot);
    symlinkSync(protectedRoot, link);
    assert.throws(
      () => newOutputProjection(resolve(link, 'nested', 'experiment')),
      /must not traverse a symbolic-link/
    );
    assert.equal(existsSync(resolve(protectedRoot, 'nested')), false);
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('scheduler gap monitor fails only above the threshold and fires once', () => {
  let wallClockMs = 0;
  let monotonicClockMs = 0;
  let tick;
  let clearCount = 0;
  let detections = 0;
  let evidence;
  const stopMonitor = startSchedulerGapMonitor({
    intervalMs: 5_000,
    thresholdMs: 60_000,
    wallClock: () => wallClockMs,
    monotonicClock: () => monotonicClockMs,
    setIntervalFn: (callback, intervalMs) => {
      assert.equal(intervalMs, 5_000);
      tick = callback;
      return 'fake-timer';
    },
    clearIntervalFn: (timer) => {
      assert.equal(timer, 'fake-timer');
      clearCount += 1;
    },
    onGap: (value) => {
      detections += 1;
      evidence = value;
    }
  });
  wallClockMs = 60_000;
  monotonicClockMs = 60_000;
  tick();
  assert.equal(detections, 0);
  wallClockMs += 60_001;
  monotonicClockMs += 5_000;
  tick();
  tick();
  stopMonitor();
  assert.equal(detections, 1);
  assert.equal(clearCount, 1);
  assert.deepEqual(evidence, {
    heartbeatIntervalMs: 5_000,
    thresholdMs: 60_000,
    observedWallClockIntervalMs: 60_001,
    observedMonotonicIntervalMs: 5_000
  });
});

test('scheduler gap monitor samples once on stop so a wake-up tail cannot escape', () => {
  let wallClockMs = 0;
  let monotonicClockMs = 0;
  let clearCount = 0;
  const detections = [];
  const stopMonitor = startSchedulerGapMonitor({
    intervalMs: 5_000,
    thresholdMs: 60_000,
    wallClock: () => wallClockMs,
    monotonicClock: () => monotonicClockMs,
    setIntervalFn: () => 'tail-timer',
    clearIntervalFn: (timer) => {
      assert.equal(timer, 'tail-timer');
      clearCount += 1;
    },
    onGap: (evidence) => detections.push(evidence)
  });
  wallClockMs = 60_001;
  monotonicClockMs = 60_001;
  stopMonitor();
  stopMonitor();
  assert.equal(clearCount, 1);
  assert.deepEqual(detections, [{
    heartbeatIntervalMs: 5_000,
    thresholdMs: 60_000,
    observedWallClockIntervalMs: 60_001,
    observedMonotonicIntervalMs: 60_001
  }]);
});

test('parseCodexJsonl counts UTF-8 bytes, usage, tools, reads, and fresh-thread signals', () => {
  const events = [
    { type: 'thread.started', thread_id: 'fresh-thread' },
    { type: 'turn.started' },
    { type: 'item.completed', item: { type: 'agent_message', text: 'naïve 🚀' } },
    {
      type: 'item.completed',
      item: {
        type: 'command_execution',
        command: ['node', 'tools/verify.mjs', '--packet', 'review-packet'],
        aggregated_output: 'αβ\n',
        exit_code: 0,
        status: 'completed'
      }
    },
    {
      type: 'item.completed',
      item: {
        type: 'command_execution',
        command: `node inspect.mjs ${liveSummaryPath}`,
        output: 'summary ✓',
        status: 'completed'
      }
    },
    {
      type: 'item.completed',
      item: {
        type: 'command_execution',
        command: ['node', 'inspect.mjs', 'review-packet/evidence/live-verification.json'],
        result: { message: 'é' },
        status: 'completed'
      }
    },
    {
      type: 'item.completed',
      item: {
        type: 'file_change',
        changes: [
          { path: '/workspace/review-packet/evidence.json', kind: 'add' }
        ],
        status: 'completed'
      }
    },
    {
      type: 'item.completed',
      item: {
        type: 'web_search',
        output: 'oops',
        status: 'failed'
      }
    },
    {
      type: 'turn.completed',
      usage: {
        input_tokens: 100,
        cached_input_tokens: 40,
        output_tokens: 20,
        reasoning_output_tokens: 5
      }
    }
  ];
  const jsonl = `${events.map((event) => JSON.stringify(event)).join('\n')}\n`;
  const metrics = parseCodexJsonl(jsonl);

  assert.equal(metrics.coverage, 'complete');
  assert.equal(metrics.eventCount, 9);
  assert.equal(metrics.threadStartedCount, 1);
  assert.equal(metrics.turnCompletedCount, 1);
  assert.equal(metrics.usageComplete, true);
  assert.equal(metrics.agentMessageBytes, Buffer.byteLength('naïve 🚀'));
  assert.equal(
    metrics.toolOutputBytes,
    Buffer.byteLength('αβ\n') +
      Buffer.byteLength('summary ✓') +
      Buffer.byteLength(canonicalJson({ message: 'é' })) +
      Buffer.byteLength(canonicalJson({
        changes: [
          { kind: 'add', path: '/workspace/review-packet/evidence.json' }
        ],
        status: 'completed'
      })) +
      Buffer.byteLength('oops')
  );
  assert.equal(metrics.toolCallCount, 5);
  assert.equal(metrics.failedToolCallCount, 1);
  assert.equal(metrics.commandAttributionCoverage, 'heuristic');
  assert.equal(metrics.heuristicCommandCount, 1);
  assert.equal(metrics.verifierInvocationCount, 1);
  assert.equal(metrics.summaryReadCount, 1);
  assert.equal(metrics.fullReportReadCount, 1);
  assert.deepEqual(metrics.usage, {
    inputTokens: 100,
    cachedInputTokens: 40,
    outputTokens: 20,
    reasoningOutputTokens: 5,
    totalTokens: 120
  });

  const stale = parseCodexJsonl([
    JSON.stringify({ type: 'thread.started' }),
    JSON.stringify({ type: 'thread.started' })
  ].join('\n'));
  assert.equal(stale.threadStartedCount, 2);
  assert.equal(stale.turnCompletedCount, 0);

  const partial = parseCodexJsonl([
    JSON.stringify({ type: 'thread.started' }),
    'not-json',
    JSON.stringify({ type: 'future.event' })
  ].join('\n'));
  assert.equal(partial.coverage, 'partial');
  assert.equal(partial.unsupportedEventCount, 2);

  const futureTool = parseCodexJsonl(JSON.stringify({
    type: 'item.completed',
    item: {
      type: 'future_tool',
      output: 'unaccounted agent-visible output',
      status: 'completed'
    }
  }));
  assert.equal(futureTool.coverage, 'partial');
  assert.equal(futureTool.unsupportedEventCount, 1);
  assert.equal(futureTool.toolOutputBytes, 0);

  const malformedFileChange = parseCodexJsonl(JSON.stringify({
    type: 'item.completed',
    item: {
      type: 'file_change',
      status: 'completed'
    }
  }));
  assert.equal(malformedFileChange.coverage, 'partial');
  assert.equal(malformedFileChange.unsupportedEventCount, 1);
  assert.equal(malformedFileChange.toolOutputBytes, 0);
});

test('parseQuality requires nonempty boolean outcomes and derives validity exactly', () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-quality-test-'));
  const qualityPath = resolve(temporaryRoot, 'quality.json');
  try {
    writeFileSync(qualityPath, `${JSON.stringify({
      schemaVersion: 'public-kit.build-benchmark-quality.1',
      valid: true,
      outcomes: {
        functionalPass: true,
        required_routes_pass: true
      },
      blockers: []
    })}\n`);
    assert.equal(parseQuality(qualityPath).valid, true);

    for (const quality of [
      {
        schemaVersion: 'public-kit.build-benchmark-quality.1',
        valid: true,
        outcomes: {},
        blockers: []
      },
      {
        schemaVersion: 'public-kit.build-benchmark-quality.1',
        valid: true,
        outcomes: { functionalPass: false },
        blockers: []
      },
      {
        schemaVersion: 'public-kit.build-benchmark-quality.1',
        valid: true,
        outcomes: { functionalPass: 'pass' },
        blockers: []
      },
      {
        schemaVersion: 'public-kit.build-benchmark-quality.1',
        valid: true,
        outcomes: { 'invalid-name': true },
        blockers: []
      }
    ]) {
      writeFileSync(qualityPath, `${JSON.stringify(quality)}\n`);
      assert.throws(() => parseQuality(qualityPath), /Quality/);
    }
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('summarizeExperiment gates speed on samples and quality while reporting efficiency independently', () => {
  const improved = summarizeExperiment(experimentFixture(), balancedRuns());
  assert.equal(improved.decision, 'improved');
  assert.equal(improved.qualityComparable, true);
  assert.equal(improved.minimumSampleMet, true);
  assert.equal(improved.thresholdsMet, true);
  assert.equal(improved.productTimingCoverageComplete, true);
  assert.equal(improved.outcomeTimingCoverageComplete, true);
  assert.equal(improved.productTimeNonRegressionMet, true);
  assert.equal(improved.outcomeTimeNonRegressionMet, true);
  assert.equal(improved.speedNonRegressionMet, true);
  assert.equal(improved.efficiency.tokenCoverageComplete, true);
  assert.equal(improved.efficiency.toolOutputCoverageComplete, true);
  assert.equal(improved.productMedianImprovementMs, improved.medianImprovementMs);
  assert.equal(improved.productMedianImprovementPercent, improved.medianImprovementPercent);
  assert.equal(improved.pairedDeltas.length, 2);
  assert.equal(improved.pairedDeltas.every(({ eligible, improvementMs }) => eligible && improvementMs > 0), true);
  assert.equal(
    improved.pairedDeltas.every(({ improvementMs, productImprovementMs }) => (
      improvementMs === productImprovementMs
    )),
    true
  );
  assert.deepEqual(improved.arms.baseline.observedCostPerValidOutcome, {
    diagnosticOnly: true,
    scheduledAttempts: 2,
    validOutcomes: 2,
    resources: {
      totalTokens: {
        coverage: 'complete',
        measuredAttempts: 2,
        total: 2_000,
        perValidOutcome: 1_000
      },
      toolOutputBytes: {
        coverage: 'complete',
        measuredAttempts: 2,
        total: 4_000,
        perValidOutcome: 2_000
      },
      productWallClockMs: {
        coverage: 'complete',
        measuredAttempts: 2,
        total: 2_100,
        perValidOutcome: 1_050
      },
      outcomeWallClockMs: {
        coverage: 'complete',
        measuredAttempts: 2,
        total: 2_100,
        perValidOutcome: 1_050
      },
      totalWallClockMs: {
        coverage: 'complete',
        measuredAttempts: 2,
        total: 2_300,
        perValidOutcome: 1_150
      }
    }
  });

  const failedAttemptRuns = balancedRuns();
  failedAttemptRuns.find(({ runId }) => runId === '004-baseline').eligibility = {
    eligible: false,
    exclusionReasons: ['fixture-failure'],
    contaminationFlags: []
  };
  const failedAttempt = summarizeExperiment(experimentFixture(), failedAttemptRuns);
  assert.equal(
    failedAttempt.arms.baseline.observedCostPerValidOutcome.resources.totalTokens.perValidOutcome,
    2_000
  );
  assert.equal(
    failedAttempt.arms.baseline.observedCostPerValidOutcome.resources.productWallClockMs.perValidOutcome,
    2_100
  );

  const incompleteCostRuns = balancedRuns();
  incompleteCostRuns.find(({ runId }) => runId === '004-baseline').context.usageComplete = false;
  const incompleteCost = summarizeExperiment(experimentFixture(), incompleteCostRuns);
  assert.deepEqual(
    incompleteCost.arms.baseline.observedCostPerValidOutcome.resources.totalTokens,
    {
      coverage: 'partial',
      measuredAttempts: 1,
      total: null,
      perValidOutcome: null
    }
  );
  assert.equal(incompleteCost.efficiency.tokenCoverageComplete, false);
  assert.equal(incompleteCost.efficiency.tokenDecision, 'not-measured');
  assert.equal(incompleteCost.efficiency.tokenImprovementPercent, null);

  const noTokenCoverageRuns = balancedRuns();
  for (const run of noTokenCoverageRuns.filter(({ order }) => order.armId === 'baseline')) {
    run.context.usageComplete = false;
  }
  const noTokenCoverage = summarizeExperiment(experimentFixture(), noTokenCoverageRuns);
  assert.deepEqual(
    noTokenCoverage.arms.baseline.observedCostPerValidOutcome.resources.totalTokens,
    {
      coverage: 'none',
      measuredAttempts: 0,
      total: null,
      perValidOutcome: null
    }
  );

  const noValidOutcomeRuns = balancedRuns();
  for (const run of noValidOutcomeRuns.filter(({ order }) => order.armId === 'candidate')) {
    run.eligibility = {
      eligible: false,
      exclusionReasons: ['fixture-failure'],
      contaminationFlags: []
    };
  }
  const noValidOutcome = summarizeExperiment(experimentFixture(), noValidOutcomeRuns);
  assert.equal(noValidOutcome.arms.candidate.observedCostPerValidOutcome.validOutcomes, 0);
  assert.equal(
    noValidOutcome.arms.candidate.observedCostPerValidOutcome.resources.totalTokens.coverage,
    'complete'
  );
  assert.equal(
    noValidOutcome.arms.candidate.observedCostPerValidOutcome.resources.totalTokens.perValidOutcome,
    null
  );

  const missingToolOutputRuns = balancedRuns();
  missingToolOutputRuns.find(({ runId }) => runId === '003-candidate').context.coverage = 'partial';
  const missingToolOutput = summarizeExperiment(experimentFixture(), missingToolOutputRuns);
  assert.equal(missingToolOutput.efficiency.toolOutputCoverageComplete, false);
  assert.equal(missingToolOutput.efficiency.toolOutputDecision, 'not-measured');
  assert.equal(missingToolOutput.efficiency.toolOutputImprovementPercent, null);
  assert.equal(
    missingToolOutput.arms.candidate.observedCostPerValidOutcome.resources.toolOutputBytes.coverage,
    'partial'
  );
  assert.equal(
    missingToolOutput.arms.candidate.observedCostPerValidOutcome.resources.totalTokens.coverage,
    'partial'
  );
  assert.equal(
    missingToolOutput.arms.candidate.observedCostPerValidOutcome.resources.totalTokens.perValidOutcome,
    null
  );

  const contaminatedTimingRuns = balancedRuns();
  contaminatedTimingRuns.find(({ runId }) => runId === '003-candidate')
    .eligibility.contaminationFlags.push('fixture-contamination');
  const contaminatedTiming = summarizeExperiment(experimentFixture(), contaminatedTimingRuns);
  assert.equal(
    contaminatedTiming.arms.candidate.observedCostPerValidOutcome.resources.productWallClockMs.coverage,
    'partial'
  );
  assert.equal(
    contaminatedTiming.arms.candidate.observedCostPerValidOutcome.resources.totalWallClockMs.perValidOutcome,
    null
  );

  const qualityMismatch = summarizeExperiment(
    experimentFixture(),
    balancedRuns({ candidateFingerprint: 'sha256:different-quality' })
  );
  assert.equal(qualityMismatch.decision, 'quality-not-equivalent');
  assert.deepEqual(qualityMismatch.reasons, ['quality-outcome-fingerprints-differ']);
  assert.equal(qualityMismatch.efficiency.tokenDecision, 'not-eligible');
  assert.equal(qualityMismatch.efficiency.toolOutputDecision, 'not-eligible');

  const insufficient = summarizeExperiment(
    experimentFixture({ minimumValidRunsPerArm: 3 }),
    balancedRuns()
  );
  assert.equal(insufficient.decision, 'insufficient-evidence');
  assert.deepEqual(insufficient.reasons, ['minimum-valid-runs-not-met']);
  assert.equal(insufficient.efficiency.anyImprovement, false);

  const efficiencyOnly = summarizeExperiment(
    experimentFixture({
      thresholds: {
        minimumMedianImprovementPercent: 20,
        minimumMedianImprovementMs: 500,
        minimumTokenImprovementPercent: 40,
        minimumToolOutputImprovementPercent: 40,
        requireEveryPairFaster: true
      }
    }),
    balancedRuns({
      baselineMs: [1_000, 1_000],
      candidateMs: [950, 950],
      baselineTokens: 1_000,
      candidateTokens: 500,
      baselineToolBytes: 2_000,
      candidateToolBytes: 1_000
    })
  );
  assert.equal(efficiencyOnly.decision, 'efficiency-improved');
  assert.deepEqual(efficiencyOnly.reasons, ['speed-thresholds-not-met']);
  assert.equal(efficiencyOnly.efficiency.tokenDecision, 'improved');
  assert.equal(efficiencyOnly.efficiency.tokenImprovementPercent, 50);
  assert.equal(efficiencyOnly.efficiency.toolOutputDecision, 'improved');
  assert.equal(efficiencyOnly.efficiency.toolOutputImprovementPercent, 50);
  assert.equal(efficiencyOnly.efficiency.anyImprovement, true);
  assert.equal(efficiencyOnly.productTimeNonRegressionMet, true);
  assert.equal(efficiencyOnly.outcomeTimeNonRegressionMet, true);
  assert.equal(efficiencyOnly.speedNonRegressionMet, true);

  const outcomeTradeoff = summarizeExperiment(
    experimentFixture(),
    balancedRuns({
      baselineMs: [1_000, 1_000],
      candidateMs: [950, 950],
      baselineOutcomeMs: [1_100, 1_100],
      candidateOutcomeMs: [1_400, 1_400],
      baselineTokens: 1_000,
      candidateTokens: 500
    })
  );
  assert.equal(outcomeTradeoff.decision, 'tradeoff');
  assert.equal(outcomeTradeoff.productTimeNonRegressionMet, true);
  assert.equal(outcomeTradeoff.outcomeTimeNonRegressionMet, false);
  assert.equal(outcomeTradeoff.speedNonRegressionMet, false);
  assert.equal(outcomeTradeoff.productMedianImprovementMs, 50);
  assert.equal(outcomeTradeoff.outcomeMedianImprovementMs, -300);
  assert.equal(outcomeTradeoff.outcomeMedianRegressionMs, 300);
  assert.deepEqual(
    outcomeTradeoff.reasons,
    ['outcome-time-regressed-beyond-efficiency-tolerance']
  );

  const speedThresholdCannotHideOutcomeRegression = summarizeExperiment(
    experimentFixture(),
    balancedRuns({
      baselineMs: [2_000, 2_000],
      candidateMs: [1_000, 1_000],
      baselineOutcomeMs: [2_100, 2_100],
      candidateOutcomeMs: [2_600, 2_600],
      baselineTokens: 1_000,
      candidateTokens: 1_000,
      baselineToolBytes: 2_000,
      candidateToolBytes: 2_000
    })
  );
  assert.equal(speedThresholdCannotHideOutcomeRegression.thresholdsMet, true);
  assert.equal(speedThresholdCannotHideOutcomeRegression.decision, 'regressed');
  assert.deepEqual(
    speedThresholdCannotHideOutcomeRegression.reasons,
    ['outcome-time-regressed-beyond-tolerance']
  );

  const missingOutcomeRuns = balancedRuns({
    baselineMs: [1_000, 1_000],
    candidateMs: [1_000, 1_000],
    baselineTokens: 1_000,
    candidateTokens: 500
  });
  for (const run of missingOutcomeRuns.filter(({ order }) => order.armId === 'candidate')) {
    delete run.timing.measuredOutcomeWallClockMs;
  }
  const missingOutcome = summarizeExperiment(experimentFixture(), missingOutcomeRuns);
  assert.equal(missingOutcome.decision, 'tradeoff');
  assert.equal(missingOutcome.outcomeTimingCoverageComplete, false);
  assert.equal(missingOutcome.outcomeTimeNonRegressionMet, false);
  assert.deepEqual(
    missingOutcome.reasons,
    ['outcome-time-non-regression-not-measured']
  );

  const pairRegression = summarizeExperiment(
    experimentFixture(),
    balancedRuns({
      baselineMs: [1_000, 2_000],
      candidateMs: [1_100, 500]
    })
  );
  assert.equal(pairRegression.medianImprovementMs, 700);
  assert.equal(pairRegression.pairedDeltas.some(({ improvementMs }) => improvementMs < 0), true);
  assert.equal(pairRegression.thresholdsMet, false);
  assert.equal(pairRegression.decision, 'efficiency-improved');

  const speedTradeoff = summarizeExperiment(
    experimentFixture(),
    balancedRuns({
      baselineMs: [1_000, 1_000],
      candidateMs: [1_300, 1_300],
      baselineTokens: 1_000,
      candidateTokens: 500
    })
  );
  assert.equal(speedTradeoff.decision, 'tradeoff');
  assert.equal(speedTradeoff.speedNonRegressionMet, false);
  assert.deepEqual(speedTradeoff.reasons, [
    'product-time-regressed-beyond-efficiency-tolerance',
    'outcome-time-regressed-beyond-efficiency-tolerance'
  ]);

  const speedRegression = summarizeExperiment(
    experimentFixture(),
    balancedRuns({
      baselineMs: [1_000, 1_000],
      candidateMs: [1_300, 1_300],
      baselineTokens: 1_000,
      candidateTokens: 1_200,
      baselineToolBytes: 2_000,
      candidateToolBytes: 2_500
    })
  );
  assert.equal(speedRegression.decision, 'regressed');
  assert.equal(speedRegression.speedNonRegressionMet, false);
  assert.equal(speedRegression.efficiency.anyImprovement, false);
  assert.deepEqual(speedRegression.reasons, [
    'product-time-regressed-beyond-tolerance',
    'outcome-time-regressed-beyond-tolerance'
  ]);

  const equalEfficiency = summarizeExperiment(
    experimentFixture({
      thresholds: {
        minimumTokenImprovementPercent: 0,
        minimumToolOutputImprovementPercent: 0
      }
    }),
    balancedRuns({
      baselineMs: [1_000, 1_000],
      candidateMs: [1_000, 1_000],
      baselineTokens: 1_000,
      candidateTokens: 1_000,
      baselineToolBytes: 2_000,
      candidateToolBytes: 2_000
    })
  );
  assert.equal(equalEfficiency.efficiency.anyImprovement, false);
  assert.equal(equalEfficiency.decision, 'not-improved');
});

test('CLI runs a reusable two-arm experiment with fake lifecycle commands', { timeout: 60_000 }, () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-benchmark-test-'));
  const scenarioRoot = resolve(temporaryRoot, 'scenario');
  const preparePath = resolve(scenarioRoot, 'prepare.mjs');
  const buildPath = resolve(scenarioRoot, 'build.mjs');
  const evaluatorPath = resolve(scenarioRoot, 'evaluate.mjs');
  const cleanupPath = resolve(scenarioRoot, 'cleanup.mjs');
  const scenarioPath = resolve(scenarioRoot, 'scenario.json');
  const experimentDir = resolve(temporaryRoot, 'experiment');
  const kitPath = resolve(temporaryRoot, 'kit');
  const localRunnerPath = resolve(temporaryRoot, 'runner-repo', 'scripts', 'benchmark-builds.mjs');

  try {
    mkdirSync(scenarioRoot);
    mkdirSync(kitPath);
    mkdirSync(dirname(localRunnerPath), { recursive: true });
    writeFileSync(localRunnerPath, readFileSync(runnerPath));
    writeFileSync(resolve(kitPath, 'README.md'), '# Clean benchmark kit fixture\n');
    execFileSync('git', ['init', '-b', 'main'], { cwd: kitPath });
    execFileSync('git', ['add', 'README.md'], { cwd: kitPath });
    execFileSync('git', [
      '-c', 'user.name=Benchmark Test',
      '-c', 'user.email=benchmark-test@example.invalid',
      'commit', '-m', 'fixture'
    ], { cwd: kitPath });
    writeFileSync(preparePath, [
      "import { writeFileSync } from 'node:fs';",
      "import { resolve } from 'node:path';",
      'const [workspace, armId] = process.argv.slice(2);',
      "writeFileSync(resolve(workspace, 'prepared.txt'), `${armId}\\n`);"
    ].join('\n'));
    writeFileSync(buildPath, [
      "import { existsSync } from 'node:fs';",
      "import { resolve } from 'node:path';",
      'const workspace = process.cwd();',
      "if (!existsSync(resolve(workspace, 'prepared.txt'))) process.exit(3);",
      "for (const name of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLOUDFLARE_API_TOKEN', 'AZURE_CLIENT_SECRET', 'PGPASSWORD', 'MYSQL_PWD', 'DEPLOY_KEY', 'DATABASE_URL']) {",
      '  if (process.env[name] !== undefined) process.exit(5);',
      '}',
      "if (process.env.NO_COLOR !== 'benchmark-safe-marker') process.exit(6);",
      'const events = [',
      "  { type: 'thread.started', thread_id: 'fresh-opaque' },",
      "  { type: 'turn.started' },",
      "  { type: 'item.completed', item: { type: 'agent_message', text: 'built opaque ✓' } },",
      "  { type: 'item.completed', item: { type: 'command_execution', command: ['node', 'verify.mjs'], aggregated_output: 'verified ✓', exit_code: 0, status: 'completed' } },",
      "  { type: 'turn.completed', usage: { input_tokens: 100, cached_input_tokens: 20, output_tokens: 25, reasoning_output_tokens: 5 } }",
      '];',
      "process.stdout.write(`${events.map((event) => JSON.stringify(event)).join('\\n')}\\n`);"
    ].join('\n'));
    writeFileSync(evaluatorPath, [
      "const [armId] = process.argv.slice(2);",
      'const quality = {',
      "  schemaVersion: 'public-kit.build-benchmark-quality.1',",
      '  valid: true,',
      '  outcomes: { functionalPass: true, visualPass: true },',
      '  blockers: []',
      '};',
      "if (!armId) process.exit(4);",
      "process.stdout.write(`${JSON.stringify(quality)}\\n`);"
    ].join('\n'));
    writeFileSync(cleanupPath, [
      "import { writeFileSync } from 'node:fs';",
      "import { resolve } from 'node:path';",
      'const [runDir] = process.argv.slice(2);',
      "writeFileSync(resolve(runDir, 'cleanup-ran.txt'), 'yes\\n');"
    ].join('\n'));

    const scenario = scenarioFixture({
      id: 'cli-smoke',
      description: 'Run a lightweight reusable CLI benchmark smoke workload.',
      minimumValidRunsPerArm: 1,
      thresholds: {
        minimumMedianImprovementPercent: 0,
        minimumMedianImprovementMs: 0,
        minimumTokenImprovementPercent: 0,
        minimumToolOutputImprovementPercent: 0,
        maximumMedianRegressionPercent: 100_000,
        maximumMedianRegressionMs: 60_000,
        requireEveryPairFaster: false
      },
      commands: {
        prepare: [{
          argv: [process.execPath, preparePath, '{workspace}', '{armId}'],
          cwd: '{runDir}'
        }],
        build: [{
          argv: [process.execPath, buildPath],
          cwd: '{workspace}',
          adapter: 'codex-jsonl-v1'
        }],
        evaluate: [{
          argv: [process.execPath, evaluatorPath, '{armId}'],
          cwd: '{workspace}'
        }],
        cleanup: [{
          argv: [process.execPath, cleanupPath, '{runDir}'],
          cwd: '{runDir}'
        }]
      }
    });
    writeFileSync(scenarioPath, `${JSON.stringify(scenario, null, 2)}\n`);

    const stdout = execFileSync(process.execPath, [
      localRunnerPath,
      'run',
      '--scenario', scenarioPath,
      '--baseline-kit', kitPath,
      '--candidate-kit', kitPath,
      '--evaluator-kit', kitPath,
      '--output', experimentDir,
      '--sequence', 'ABBA',
      '--warmups-per-arm', '0'
    ], {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 60_000,
      env: {
        ...process.env,
        OPENAI_API_KEY: 'ambient-openai-credential',
        ANTHROPIC_API_KEY: 'ambient-anthropic-credential',
        CLOUDFLARE_API_TOKEN: 'ambient-cloudflare-credential',
        AZURE_CLIENT_SECRET: 'ambient-azure-credential',
        PGPASSWORD: 'ambient-postgres-credential',
        MYSQL_PWD: 'ambient-mysql-credential',
        DEPLOY_KEY: 'ambient-deploy-credential',
        DATABASE_URL: 'postgresql://user:password@example.invalid/database',
        NO_COLOR: 'benchmark-safe-marker'
      }
    });

    assert.match(stdout, /Starting 1\/4: baseline/);
    assert.match(stdout, /Starting 4\/4: baseline/);
    const experiment = JSON.parse(readFileSync(resolve(experimentDir, 'experiment.json'), 'utf8'));
    const comparison = JSON.parse(readFileSync(resolve(experimentDir, 'comparison.json'), 'utf8'));
    assert.equal(experiment.status, 'completed');
    assert.equal(experiment.schedule.length, 4);
    assert.deepEqual(experiment.schedulerMonitor, {
      mode: 'built-in',
      heartbeatIntervalMs: 5_000,
      thresholdMs: 60_000
    });
    assert.deepEqual(experiment.scenario.identityInputs[0], {
      id: 'benchmark-runner',
      bytes: readFileSync(localRunnerPath).length,
      sha256: sha256(readFileSync(localRunnerPath))
    });
    assert.equal(comparison.minimumSampleMet, true);
    assert.equal(comparison.qualityComparable, true);
    assert.ok(['improved', 'not-improved'].includes(comparison.decision));

    for (const runId of ['001-trial', '002-trial', '003-trial', '004-trial']) {
      const runDir = resolve(experimentDir, 'runs', runId);
      const run = JSON.parse(readFileSync(resolve(runDir, 'run.json'), 'utf8'));
      assert.equal(run.eligibility.eligible, true);
      assert.equal(run.context.threadStartedCount, 1);
      assert.equal(run.context.turnCompletedCount, 1);
      assert.equal(run.context.verifierInvocationCount, 1);
      assert.equal(run.quality.valid, true);
      assert.equal(existsSync(resolve(runDir, 'cleanup-ran.txt')), true);
    }

    const validReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.equal(validReport.status, 0);

    const experimentPath = resolve(experimentDir, 'experiment.json');
    const originalExperiment = readFileSync(experimentPath);
    const interruptedExperiment = JSON.parse(originalExperiment);
    interruptedExperiment.status = 'interrupted';
    writeFileSync(experimentPath, `${JSON.stringify(interruptedExperiment, null, 2)}\n`);
    const interruptedReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.notEqual(interruptedReport.status, 0);
    assert.match(interruptedReport.stderr, /Only a completed experiment/);
    writeFileSync(experimentPath, originalExperiment);

    const runPath = resolve(experimentDir, 'runs', '001-trial', 'run.json');
    const originalRun = readFileSync(runPath);
    const projectionTamper = JSON.parse(originalRun);
    projectionTamper.context.usage.totalTokens += 1;
    projectionTamper.resultFingerprint = recomputeRunFingerprint(projectionTamper);
    writeFileSync(runPath, `${JSON.stringify(projectionTamper, null, 2)}\n`);
    const projectionReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.notEqual(projectionReport.status, 0);
    assert.match(projectionReport.stderr, /context projection does not match raw Codex evidence/);
    writeFileSync(runPath, originalRun);

    const schedulerGapTamper = JSON.parse(originalRun);
    schedulerGapTamper.timing.schedulerGap = {
      detectedAt: new Date().toISOString(),
      phaseId: 'evaluate-01',
      heartbeatIntervalMs: 5_000,
      thresholdMs: 60_000,
      observedWallClockIntervalMs: 61_000,
      observedMonotonicIntervalMs: 61_000
    };
    schedulerGapTamper.resultFingerprint = recomputeRunFingerprint(schedulerGapTamper);
    writeFileSync(runPath, `${JSON.stringify(schedulerGapTamper, null, 2)}\n`);
    const schedulerGapReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.notEqual(schedulerGapReport.status, 0);
    assert.match(schedulerGapReport.stderr, /contains a scheduler gap/);
    writeFileSync(runPath, originalRun);

    const originalRunValue = JSON.parse(originalRun);
    const codexRecord = originalRunValue.timing.phases.find(
      ({ command }) => command.adapter === 'codex-jsonl-v1'
    );
    const codexStdoutPath = resolve(experimentDir, 'runs', '001-trial', codexRecord.artifacts.stdout);
    const originalCodexStdout = readFileSync(codexStdoutPath);
    writeFileSync(codexStdoutPath, Buffer.concat([originalCodexStdout, Buffer.from('tamper\n')]));
    const artifactReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.notEqual(artifactReport.status, 0);
    assert.match(artifactReport.stderr, /artifact does not match/);
    writeFileSync(codexStdoutPath, originalCodexStdout);

    const outsideArtifact = resolve(temporaryRoot, 'outside-evidence.log');
    writeFileSync(outsideArtifact, originalCodexStdout);
    rmSync(codexStdoutPath);
    symlinkSync(outsideArtifact, codexStdoutPath);
    const symlinkReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.notEqual(symlinkReport.status, 0);
    assert.match(symlinkReport.stderr, /missing, unsafe, or outside/);
    rmSync(codexStdoutPath);
    writeFileSync(codexStdoutPath, originalCodexStdout);

    const originalRunner = readFileSync(localRunnerPath);
    writeFileSync(localRunnerPath, Buffer.concat([originalRunner, Buffer.from('\n// tampered\n')]));
    const runnerMismatchReport = spawnSync(process.execPath, [
      localRunnerPath,
      'report',
      '--experiment', experimentDir
    ], { cwd: repoRoot, encoding: 'utf8' });
    assert.notEqual(runnerMismatchReport.status, 0);
    assert.match(runnerMismatchReport.stderr, /does not match the experiment runner identity/);
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('scheduler gap aborts the measured interval after cleanup without a comparison', { timeout: 30_000 }, () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-benchmark-gap-test-'));
  const scenarioRoot = resolve(temporaryRoot, 'scenario');
  const agentPath = resolve(scenarioRoot, 'agent.mjs');
  const evaluatorPath = resolve(scenarioRoot, 'evaluate.mjs');
  const cleanupPath = resolve(scenarioRoot, 'cleanup.mjs');
  const helperPath = resolve(temporaryRoot, 'run-with-gap.mjs');
  const boundaryHelperPath = resolve(temporaryRoot, 'run-with-boundary-gap.mjs');
  const scenarioPath = resolve(scenarioRoot, 'scenario.json');
  const experimentDir = resolve(temporaryRoot, 'experiment');
  const boundaryExperimentDir = resolve(temporaryRoot, 'boundary-experiment');
  const kitPath = resolve(temporaryRoot, 'kit');
  try {
    mkdirSync(scenarioRoot);
    mkdirSync(kitPath);
    writeFileSync(resolve(kitPath, 'README.md'), '# Scheduler gap fixture\n');
    execFileSync('git', ['init', '-b', 'main'], { cwd: kitPath });
    execFileSync('git', ['add', 'README.md'], { cwd: kitPath });
    execFileSync('git', [
      '-c', 'user.name=Benchmark Test',
      '-c', 'user.email=benchmark-test@example.invalid',
      'commit', '-m', 'fixture'
    ], { cwd: kitPath });
    writeFileSync(agentPath, [
      'const events = [',
      "  { type: 'thread.started', thread_id: 'fresh-gap' },",
      "  { type: 'turn.started' },",
      "  { type: 'turn.completed', usage: { input_tokens: 100, cached_input_tokens: 20, output_tokens: 25, reasoning_output_tokens: 5 } }",
      '];',
      "process.stdout.write(`${events.map(JSON.stringify).join('\\n')}\\n`);"
    ].join('\n'));
    writeFileSync(evaluatorPath, [
      'setTimeout(() => process.stdout.write(JSON.stringify({',
      "  schemaVersion: 'public-kit.build-benchmark-quality.1',",
      '  valid: true,',
      '  outcomes: { functionalPass: true },',
      '  blockers: []',
      '})), 5_000);'
    ].join('\n'));
    writeFileSync(cleanupPath, [
      "import { writeFileSync } from 'node:fs';",
      "import { resolve } from 'node:path';",
      "writeFileSync(resolve(process.argv[2], 'cleanup-ran.txt'), 'yes\\n');",
      'process.exitCode = 7;'
    ].join('\n'));
    const scenario = scenarioFixture({
      id: 'scheduler-gap-abort',
      description: 'Prove scheduler contamination aborts after cleanup without a comparison.',
      minimumValidRunsPerArm: 1,
      commands: {
        prepare: [],
        build: [{
          argv: [process.execPath, agentPath],
          cwd: '{workspace}',
          adapter: 'codex-jsonl-v1'
        }],
        evaluate: [{
          argv: [process.execPath, evaluatorPath],
          cwd: '{workspace}'
        }],
        cleanup: [{
          argv: [process.execPath, cleanupPath, '{runDir}'],
          cwd: '{runDir}'
        }]
      }
    });
    writeFileSync(scenarioPath, `${JSON.stringify(scenario, null, 2)}\n`);
    const runOptions = {
      scenario: scenarioPath,
      'baseline-kit': kitPath,
      'candidate-kit': kitPath,
      'evaluator-kit': kitPath,
      output: experimentDir,
      sequence: 'ABBA',
      'warmups-per-arm': '0',
      vars: {}
    };
    writeFileSync(helperPath, [
      `import { runCommand } from ${JSON.stringify(pathToFileURL(runnerPath).href)};`,
      `const options = ${JSON.stringify(runOptions)};`,
      'const status = await runCommand(options, {',
      '  schedulerGapMonitorFactory: ({ activePhaseId, onGap }) => {',
      '    let stopped = false;',
      '    const timer = setInterval(() => {',
      "      if (stopped || activePhaseId() !== 'evaluate-01') return;",
      '      stopped = true;',
      '      clearInterval(timer);',
      '      onGap({',
      '        heartbeatIntervalMs: 5000,',
      '        thresholdMs: 60000,',
      '        observedWallClockIntervalMs: 61000,',
      '        observedMonotonicIntervalMs: 61000',
      '      });',
      '    }, 1);',
      '    return () => {',
      '      if (stopped) return;',
      '      stopped = true;',
      '      clearInterval(timer);',
      '    };',
      '  }',
      '});',
      'process.exitCode = status;'
    ].join('\n'));

    const result = spawnSync(process.execPath, [helperPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 30_000
    });
    assert.equal(result.status, 2, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /aborted after a scheduler gap/);
    assert.match(result.stderr, /Cleanup also failed/);
    const runDir = resolve(experimentDir, 'runs', '001-trial');
    const run = JSON.parse(readFileSync(resolve(runDir, 'run.json'), 'utf8'));
    const evaluator = run.timing.phases.find(({ id }) => id === 'evaluate-01');
    assert.equal(evaluator.status, 'scheduler_gap');
    assert.equal(evaluator.process.timedOut, false);
    assert.equal(typeof evaluator.process.schedulerGap.detectedAt, 'string');
    assert.deepEqual(
      { ...evaluator.process.schedulerGap, detectedAt: '<dynamic>' },
      {
        detectedAt: '<dynamic>',
        heartbeatIntervalMs: 5_000,
        thresholdMs: 60_000,
        observedWallClockIntervalMs: 61_000,
        observedMonotonicIntervalMs: 61_000
      }
    );
    assert.deepEqual(run.eligibility.exclusionReasons, [
      'evaluation-process-failed',
      'cleanup-failed',
      'scheduler-gap-detected'
    ]);
    assert.deepEqual(run.eligibility.contaminationFlags, [
      'scheduler-gap-detected:evaluate-01'
    ]);
    assert.equal(run.resultFingerprint, recomputeRunFingerprint(run));
    assert.equal(existsSync(resolve(runDir, 'cleanup-ran.txt')), true);
    const experiment = JSON.parse(readFileSync(resolve(experimentDir, 'experiment.json'), 'utf8'));
    assert.equal(experiment.status, 'aborted');
    assert.equal(experiment.schedulerMonitor.mode, 'injected-test-only');
    assert.equal(experiment.termination.reason, 'scheduler-gap-detected');
    assert.equal(experiment.termination.runId, '001-trial');
    assert.equal(experiment.termination.phaseId, 'evaluate-01');
    assert.deepEqual(experiment.termination.cleanupFailureReasons, ['cleanup-failed']);
    assert.equal(existsSync(resolve(experimentDir, 'comparison.json')), false);
    assert.equal(existsSync(resolve(experimentDir, 'runs', '002-trial')), false);

    writeFileSync(evaluatorPath, [
      'process.stdout.write(JSON.stringify({',
      "  schemaVersion: 'public-kit.build-benchmark-quality.1',",
      '  valid: true,',
      '  outcomes: { functionalPass: true },',
      '  blockers: []',
      '}));'
    ].join('\n'));
    writeFileSync(cleanupPath, [
      "import { writeFileSync } from 'node:fs';",
      "import { resolve } from 'node:path';",
      "writeFileSync(resolve(process.argv[2], 'cleanup-ran.txt'), 'yes\\n');"
    ].join('\n'));
    const boundaryOptions = { ...runOptions, output: boundaryExperimentDir };
    writeFileSync(boundaryHelperPath, [
      `import { runCommand } from ${JSON.stringify(pathToFileURL(runnerPath).href)};`,
      `const options = ${JSON.stringify(boundaryOptions)};`,
      'const status = await runCommand(options, {',
      '  schedulerGapMonitorFactory: ({ activePhaseId, onGap }) => {',
      '    let stopped = false;',
      '    return () => {',
      '      if (stopped) return;',
      '      stopped = true;',
      "      if (activePhaseId() !== null) throw new Error('Expected a measurement-boundary stop.');",
      '      onGap({',
      '        heartbeatIntervalMs: 5000,',
      '        thresholdMs: 60000,',
      '        observedWallClockIntervalMs: 61000,',
      '        observedMonotonicIntervalMs: 61000',
      '      });',
      '    };',
      '  }',
      '});',
      'process.exitCode = status;'
    ].join('\n'));
    const boundaryResult = spawnSync(process.execPath, [boundaryHelperPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 30_000
    });
    assert.equal(
      boundaryResult.status,
      2,
      `${boundaryResult.stdout}\n${boundaryResult.stderr}`
    );
    const boundaryRunDir = resolve(boundaryExperimentDir, 'runs', '001-trial');
    const boundaryRun = JSON.parse(
      readFileSync(resolve(boundaryRunDir, 'run.json'), 'utf8')
    );
    const completedEvaluator = boundaryRun.timing.phases.find(
      ({ id }) => id === 'evaluate-01'
    );
    assert.equal(completedEvaluator.status, 'completed');
    assert.equal(completedEvaluator.process.schedulerGap, undefined);
    assert.equal(boundaryRun.timing.schedulerGap.phaseId, 'measurement-boundary');
    assert.equal(boundaryRun.timing.schedulerGap.previousPhaseId, 'evaluate-01');
    assert.deepEqual(boundaryRun.eligibility.exclusionReasons, [
      'scheduler-gap-detected'
    ]);
    assert.deepEqual(boundaryRun.eligibility.contaminationFlags, [
      'scheduler-gap-detected:measurement-boundary'
    ]);
    assert.equal(existsSync(resolve(boundaryRunDir, 'cleanup-ran.txt')), true);
    const boundaryExperiment = JSON.parse(
      readFileSync(resolve(boundaryExperimentDir, 'experiment.json'), 'utf8')
    );
    assert.equal(boundaryExperiment.status, 'aborted');
    assert.equal(
      boundaryExperiment.termination.phaseId,
      'measurement-boundary'
    );
    assert.equal(
      boundaryExperiment.termination.previousPhaseId,
      'evaluate-01'
    );
    assert.deepEqual(boundaryExperiment.termination.cleanupFailureReasons, []);
    assert.equal(existsSync(resolve(boundaryExperimentDir, 'comparison.json')), false);
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('CLI preserves an invalid warm-up and aborts before measured runs', { timeout: 30_000 }, () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'build-benchmark-warmup-test-'));
  const scenarioRoot = resolve(temporaryRoot, 'scenario');
  const agentPath = resolve(scenarioRoot, 'agent.mjs');
  const evaluatorPath = resolve(scenarioRoot, 'evaluate.mjs');
  const scenarioPath = resolve(scenarioRoot, 'scenario.json');
  const experimentDir = resolve(temporaryRoot, 'experiment');
  const kitPath = resolve(temporaryRoot, 'kit');
  try {
    mkdirSync(scenarioRoot);
    mkdirSync(kitPath);
    writeFileSync(resolve(kitPath, 'README.md'), '# Warm-up fixture\n');
    execFileSync('git', ['init', '-b', 'main'], { cwd: kitPath });
    execFileSync('git', ['add', 'README.md'], { cwd: kitPath });
    execFileSync('git', [
      '-c', 'user.name=Benchmark Test',
      '-c', 'user.email=benchmark-test@example.invalid',
      'commit', '-m', 'fixture'
    ], { cwd: kitPath });
    writeFileSync(agentPath, [
      'const events = [',
      "  { type: 'thread.started', thread_id: 'fresh-warmup' },",
      "  { type: 'turn.completed', usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 } }",
      '];',
      "process.stdout.write(`${events.map(JSON.stringify).join('\\n')}\\n`);"
    ].join('\n'));
    writeFileSync(evaluatorPath, [
      'process.stdout.write(JSON.stringify({',
      "  schemaVersion: 'public-kit.build-benchmark-quality.1',",
      '  valid: false,',
      '  outcomes: { functionalPass: false },',
      "  blockers: ['intentional warm-up failure']",
      '}));'
    ].join('\n'));
    const scenario = scenarioFixture({
      id: 'warmup-abort',
      description: 'Prove that an invalid warm-up aborts measured benchmark execution.',
      minimumValidRunsPerArm: 1,
      commands: {
        prepare: [],
        build: [{
          argv: [process.execPath, agentPath],
          cwd: '{workspace}',
          adapter: 'codex-jsonl-v1'
        }],
        evaluate: [{
          argv: [process.execPath, evaluatorPath],
          cwd: '{workspace}'
        }],
        cleanup: []
      }
    });
    writeFileSync(scenarioPath, `${JSON.stringify(scenario, null, 2)}\n`);

    const result = spawnSync(process.execPath, [
      runnerPath,
      'run',
      '--scenario', scenarioPath,
      '--baseline-kit', kitPath,
      '--candidate-kit', kitPath,
      '--evaluator-kit', kitPath,
      '--output', experimentDir,
      '--sequence', 'ABBA',
      '--warmups-per-arm', '1'
    ], { cwd: repoRoot, encoding: 'utf8', timeout: 30_000 });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /aborted after an ineligible warm-up/);
    const experiment = JSON.parse(readFileSync(resolve(experimentDir, 'experiment.json'), 'utf8'));
    assert.equal(experiment.status, 'aborted');
    assert.equal(existsSync(resolve(experimentDir, 'runs', '001-trial', 'run.json')), true);
    assert.equal(existsSync(resolve(experimentDir, 'runs', '002-trial')), false);
    assert.equal(existsSync(resolve(experimentDir, 'comparison.json')), false);
  }
  finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
