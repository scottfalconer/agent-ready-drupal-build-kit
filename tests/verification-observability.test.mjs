import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync
} from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, parse } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';

import {
  buildVerificationWorkload,
  createPhaseRecorder,
  observabilityFingerprint,
  recordVerificationObservability,
  summarizeVerificationRuns
} from '../bin/verification-observability.mjs';
import { recordObservabilitySafely } from '../bin/verify.mjs';

const repoRoot = join(import.meta.dirname, '..');

function copyTemplatePacket(projectRoot) {
  const packetDir = join(projectRoot, 'review-packet');
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  mkdirSync(join(projectRoot, '.ddev'), { recursive: true });
  writeFileSync(join(projectRoot, '.ddev', 'config.yaml'), 'type: drupal11\n');
  mkdirSync(packetDir, { recursive: true });
  for (const packetFile of gates.reviewPacketFiles) {
    const parsed = parse(packetFile);
    cpSync(
      join(repoRoot, 'templates', `${parsed.name}.template${parsed.ext}`),
      join(packetDir, packetFile)
    );
  }
  return packetDir;
}

function verifierClaimProjection(report) {
  return {
    valid: report.valid,
    verdict: report.verdict,
    completeLocalRebuildClaimAllowed: report.completeLocalRebuildClaimAllowed,
    completeLocalBuildFromBriefClaimAllowed: report.completeLocalBuildFromBriefClaimAllowed,
    currentSiteClaimAllowed: report.currentSiteClaimAllowed,
    stateFingerprint: report.buildState?.fingerprint ?? ''
  };
}

function reportFixture(overrides = {}) {
  const targetOrigin = 'https://private-fixture.ddev.site';
  return {
    buildMode: 'brief',
    target: {
      declaredSourceBaseUrl: '',
      resolvedBaseUrl: targetOrigin
    },
    buildState: {
      fingerprint: observabilityFingerprint('site-state'),
      evidenceBindings: {
        verifierFingerprint: observabilityFingerprint('verifier'),
        packetFingerprint: observabilityFingerprint('packet'),
        machineLocalEnvironment: { fingerprint: observabilityFingerprint('machine-environment') },
        runtimeEnvironment: { fingerprint: observabilityFingerprint('runtime-environment') }
      }
    },
    evidenceBinding: {
      routeMatrixSha256: observabilityFingerprint('route-matrix')
    },
    routeChecks: [{ targetPath: '/', requestTarget: '/', finalUrl: `${targetOrigin}/` }],
    targetRequiredRouteChecks: [],
    browserRepresentativeRouteChecks: [],
    globalChromeCapture: {
      contract: { fingerprint: observabilityFingerprint('contract') },
      runtime: { backend: 'fixture', product: 'Fixture/1', ready: true },
      routes: [{ path: '/', viewport: { name: 'desktop' } }]
    },
    liveHttpBudget: { requestCount: 3, taskCount: 2 },
    agentContinuation: { requiredAction: 'repair' },
    completionBlockedReasons: ['One fixture blocker.'],
    currentStateBlockedReasons: [],
    errors: [],
    completeLocalRebuildClaimAllowed: false,
    completeLocalBuildFromBriefClaimAllowed: false,
    currentSiteClaimAllowed: false,
    verdict: 'machine-incomplete',
    valid: true,
    ...overrides
  };
}

function timingFixture(totalWallClockMs = 42) {
  return {
    schemaVersion: 'public-kit.verification-phase-timing.1',
    startedAt: '2026-07-15T12:00:00.000Z',
    finishedAt: '2026-07-15T12:00:00.042Z',
    totalWallClockMs,
    status: 'completed',
    overlapAware: true,
    phases: [
      {
        id: 'target-route-http',
        startOffsetMs: 0,
        endOffsetMs: 20,
        durationMs: 20,
        status: 'completed',
        details: {}
      },
      {
        id: 'source-census',
        startOffsetMs: 5,
        endOffsetMs: 35,
        durationMs: 30,
        status: 'completed',
        details: {}
      }
    ]
  };
}

test('phase recorder preserves overlapping spans and failed operations', async () => {
  let elapsed = 100;
  let wall = Date.parse('2026-07-15T12:00:00.000Z');
  const recorder = createPhaseRecorder({
    clock: () => elapsed,
    now: () => new Date(wall)
  });
  const outer = recorder.start('source-census', { concurrent: true });
  elapsed += 10;
  const inner = recorder.start('target-route-http');
  elapsed += 5;
  outer.end();
  elapsed += 10;
  inner.end();
  await assert.rejects(
    recorder.measure('browser', async () => {
      elapsed += 3;
      throw new TypeError('fixture failure');
    }),
    TypeError
  );
  wall += 28;
  const timing = recorder.finish({ status: 'failed' });
  assert.equal(timing.totalWallClockMs, 28);
  assert.equal(timing.status, 'failed');
  assert.equal(timing.overlapAware, true);
  assert.deepEqual(timing.phases.map(({ id, durationMs, status }) => ({ id, durationMs, status })), [
    { id: 'source-census', durationMs: 15, status: 'completed' },
    { id: 'target-route-http', durationMs: 15, status: 'completed' },
    { id: 'browser', durationMs: 3, status: 'failed' }
  ]);
  assert.equal(timing.phases[2].details.errorClass, 'TypeError');
  assert.throws(() => recorder.start('late'), /after the recorder is finished/);

  const interrupted = createPhaseRecorder({ clock: () => 1, now: () => new Date(0) });
  let release;
  const pending = interrupted.measure('unfinished', () => new Promise((resolve) => {
    release = resolve;
  }));
  const interruptedTiming = interrupted.finish({ status: 'failed' });
  assert.equal(interruptedTiming.phases[0].status, 'aborted');
  release('finished-late');
  assert.equal(await pending, 'finished-late');
});

test('metrics recorder failures cannot escape into verifier control flow', async () => {
  const report = reportFixture();
  const original = structuredClone(report);
  let warning = '';
  const stderr = { write: (value) => { warning += value; } };
  const finishFailure = await recordObservabilitySafely({
    recorder: { finish: () => { throw new Error('finish failed'); } },
    report,
    projectRoot: mkdtempSync(join(tmpdir(), 'verification-performance-safe-finish-')),
    stderr
  });
  assert.equal(finishFailure, null);
  assert.match(warning, /metrics could not be recorded/);
  assert.deepEqual(report, original);

  warning = '';
  const writeFailure = await recordObservabilitySafely({
    recorder: { finish: () => timingFixture() },
    report,
    projectRoot: mkdtempSync(join(tmpdir(), 'verification-performance-safe-write-')),
    recordObservability: async () => { throw new Error('write failed'); },
    stderr
  });
  assert.equal(writeFailure, null);
  assert.match(warning, /metrics could not be recorded/);
  assert.deepEqual(report, original);

  let finishedWithoutRoot = false;
  let recordedWithoutRoot = false;
  const missingRoot = await recordObservabilitySafely({
    recorder: { finish: () => { finishedWithoutRoot = true; } },
    report,
    projectRoot: null,
    recordObservability: async () => { recordedWithoutRoot = true; }
  });
  assert.equal(missingRoot, null);
  assert.equal(finishedWithoutRoot, false);
  assert.equal(recordedWithoutRoot, false);
});

test('default verifier binds metrics to report bytes and storage failure preserves authority', () => {
  const verifyScript = join(repoRoot, 'bin', 'verify.mjs');
  const run = (projectRoot) => spawnSync(
    process.execPath,
    [verifyScript, '--packet', 'review-packet'],
    { cwd: projectRoot, encoding: 'utf8' }
  );

  const controlRoot = mkdtempSync(join(tmpdir(), 'verification-performance-cli-control-'));
  const controlPacket = copyTemplatePacket(controlRoot);
  const control = run(controlRoot);
  assert.equal(control.status, 1, control.stderr);
  const controlReportPath = join(controlPacket, 'evidence', 'live-verification.json');
  const controlReportText = readFileSync(controlReportPath, 'utf8');
  const controlReport = JSON.parse(controlReportText);
  const runDirectory = join(controlRoot, '.agent-ready-drupal', 'verification-metrics', 'runs');
  const runFiles = readdirSync(runDirectory).filter((name) => name.endsWith('.json'));
  assert.equal(runFiles.length, 1);
  const metric = JSON.parse(readFileSync(join(runDirectory, runFiles[0]), 'utf8'));
  assert.equal(metric.authority.evidenceAuthority, 'none');
  assert.equal(metric.observedReport.persisted, true);
  assert.equal(metric.observedReport.path, 'review-packet/evidence/live-verification.json');
  assert.equal(metric.observedReport.bytes, Buffer.byteLength(controlReportText));
  assert.equal(
    metric.observedReport.sha256,
    `sha256:${createHash('sha256').update(controlReportText).digest('hex')}`
  );
  assert.deepEqual(metric.observedReportOutcome, {
    valid: controlReport.valid,
    verdict: controlReport.verdict,
    completeLocalRebuildClaimAllowed: controlReport.completeLocalRebuildClaimAllowed,
    completeLocalBuildFromBriefClaimAllowed: controlReport.completeLocalBuildFromBriefClaimAllowed,
    currentSiteClaimAllowed: controlReport.currentSiteClaimAllowed,
    stateFingerprint: controlReport.buildState?.fingerprint ?? ''
  });
  assert.equal(
    metric.timing.phases.some((phase) => phase.id === 'report-write' && phase.status === 'completed'),
    true
  );

  const failureRoot = mkdtempSync(join(tmpdir(), 'verification-performance-cli-failure-'));
  const outside = mkdtempSync(join(tmpdir(), 'verification-performance-cli-outside-'));
  const failurePacket = copyTemplatePacket(failureRoot);
  symlinkSync(outside, join(failureRoot, '.agent-ready-drupal'));
  const failure = run(failureRoot);
  assert.equal(failure.status, control.status, failure.stderr);
  const failureReport = JSON.parse(
    readFileSync(join(failurePacket, 'evidence', 'live-verification.json'), 'utf8')
  );
  assert.deepEqual(verifierClaimProjection(failureReport), verifierClaimProjection(controlReport));
  assert.match(failure.stderr, /Verification metrics could not be recorded/);
  const withoutMetricsWarning = (value) => value
    .split('\n')
    .filter((line) => !line.startsWith('Verification metrics could not be recorded'))
    .join('\n');
  assert.equal(withoutMetricsWarning(failure.stderr), withoutMetricsWarning(control.stderr));
  assert.deepEqual(readdirSync(outside), []);
});

test('brief workloads remain comparable without inventing a source site', () => {
  const brief = buildVerificationWorkload(reportFixture());
  assert.equal(brief.comparable, true);
  assert.equal(brief.inputs.buildMode, 'brief');
  assert.equal(brief.inputs.source, '');
  assert.match(brief.inputs.routeSet, /^sha256:[a-f0-9]{64}$/);
  assert.equal(Object.hasOwn(brief.inputs, 'routePaths'), false);

  const optimized = buildVerificationWorkload(reportFixture({
    buildState: {
      ...reportFixture().buildState,
      evidenceBindings: {
        ...reportFixture().buildState.evidenceBindings,
        verifierFingerprint: observabilityFingerprint('optimized-verifier')
      }
    }
  }));
  assert.equal(optimized.inputs.verifier, observabilityFingerprint('optimized-verifier'));
  assert.equal(optimized.fingerprint, brief.fingerprint);

  const sourceSite = buildVerificationWorkload(reportFixture({ buildMode: 'source_site' }));
  assert.equal(sourceSite.comparable, false);
  assert.ok(sourceSite.missing.includes('source'));
  assert.ok(sourceSite.missing.includes('sourceSurface'));

  const sourceReport = reportFixture({
    buildMode: 'source_site',
    target: {
      declaredSourceBaseUrl: 'https://source.example',
      resolvedBaseUrl: 'https://private-fixture.ddev.site'
    },
    evidenceBinding: {
      ...reportFixture().evidenceBinding,
      sourceSurfaceSha256: observabilityFingerprint('source-surface-a')
    }
  });
  const sourceA = buildVerificationWorkload(sourceReport);
  const sourceB = buildVerificationWorkload({
    ...sourceReport,
    evidenceBinding: {
      ...sourceReport.evidenceBinding,
      sourceSurfaceSha256: observabilityFingerprint('source-surface-b')
    }
  });
  assert.equal(sourceA.comparable, true);
  assert.notEqual(sourceA.fingerprint, sourceB.fingerprint);

  const movedRoute = buildVerificationWorkload(reportFixture({
    routeChecks: [],
    targetRequiredRouteChecks: reportFixture().routeChecks
  }));
  assert.notEqual(movedRoute.fingerprint, brief.fingerprint);

  const changedEnvironment = buildVerificationWorkload(reportFixture({
    buildState: {
      ...reportFixture().buildState,
      evidenceBindings: {
        ...reportFixture().buildState.evidenceBindings,
        runtimeEnvironment: { fingerprint: observabilityFingerprint('different-runtime-environment') }
      }
    }
  }));
  assert.notEqual(changedEnvironment.fingerprint, brief.fingerprint);
});

test('performance records stay local, self-ignore, redact workload identities, and do not mutate reports', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-'));
  const report = reportFixture();
  const original = structuredClone(report);
  const reportPath = join(projectRoot, 'review-packet', 'evidence', 'live-verification.json');
  mkdirSync(join(projectRoot, 'review-packet', 'evidence'), { recursive: true });
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  const result = await recordVerificationObservability({
    projectRoot,
    report,
    reportPath,
    reportPersisted: true,
    timing: timingFixture(),
    verificationPreObservabilityMs: 45,
    runId: '11111111-1111-4111-8111-111111111111',
    now: () => new Date('2026-07-15T12:00:01.000Z')
  });
  assert.deepEqual(report, original);
  assert.equal(readFileSync(join(projectRoot, '.agent-ready-drupal', '.gitignore'), 'utf8'), '*\n');
  assert.equal(result.paths.agentNext, '.agent-ready-drupal/agent-next.json');
  const runText = await readFile(join(projectRoot, result.paths.run), 'utf8');
  const run = JSON.parse(runText);
  assert.equal(run.verificationPreObservabilityMs, 45);
  assert.equal(
    run.verificationTimingBoundary,
    'before-observability-preparation-and-persistence'
  );
  assert.equal(run.authority.evidenceAuthority, 'none');
  assert.equal(run.authority.canAuthorizeCompletion, false);
  assert.equal(run.command.status, 'completed');
  assert.equal(run.observedReport.persisted, true);
  assert.equal(run.observedReport.path, 'review-packet/evidence/live-verification.json');
  const reportText = `${JSON.stringify(report, null, 2)}\n`;
  assert.equal(
    run.observedReport.sha256,
    `sha256:${createHash('sha256').update(reportText).digest('hex')}`
  );
  assert.equal(run.workload.comparable, true);
  assert.equal(run.counters.liveHttpRequests, 3);
  assert.ok(Number.isFinite(run.instrumentationPrePersistenceMs));
  assert.equal(run.instrumentationBoundary, 'after-agent-next-before-metric-record-persistence');
  assert.doesNotMatch(runText, /private-fixture\.ddev\.site/);
  const agentNext = JSON.parse(await readFile(join(projectRoot, result.paths.agentNext), 'utf8'));
  assert.equal(agentNext.authority.evidenceAuthority, 'none');
  assert.equal(agentNext.observedReportVerdict, 'machine-incomplete');
  assert.equal(agentNext.blockers.length, 1);
  assert.ok(run.agentReadReduction.fullReportBytes > run.agentReadReduction.agentNextBytes);
  const history = await readFile(join(projectRoot, result.paths.history), 'utf8');
  assert.equal(history.trim().split('\n').length, 1);
});

test('persisted instrumentation timing is independent of metric file mtime', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-mtime-'));
  const runId = '66666666-6666-4666-8666-666666666666';
  const result = await recordVerificationObservability({
    projectRoot,
    report: reportFixture(),
    timing: timingFixture(),
    verificationPreObservabilityMs: 45,
    runId
  });
  const script = join(import.meta.dirname, '..', 'bin', 'verification-observability.mjs');
  const readSummary = () => JSON.parse(execFileSync(
    process.execPath,
    [script, 'report', '--json'],
    { cwd: projectRoot, encoding: 'utf8' }
  ));
  const before = readSummary().verification;
  utimesSync(
    join(projectRoot, result.paths.run),
    new Date('2035-01-01T00:00:00.000Z'),
    new Date('2035-01-01T00:00:00.000Z')
  );
  const after = readSummary().verification;
  assert.equal(
    after.medianInstrumentationPrePersistenceMs,
    before.medianInstrumentationPrePersistenceMs
  );
  assert.equal(
    after.medianVerificationPreObservabilityMs,
    before.medianVerificationPreObservabilityMs
  );
});

test('failed verifier commands still emit bounded failure-class metrics', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-failed-'));
  const result = await recordVerificationObservability({
    projectRoot,
    report: null,
    timing: { ...timingFixture(7), status: 'failed' },
    verificationPreObservabilityMs: 7,
    failureClass: 'UsageError',
    runId: '22222222-2222-4222-8222-222222222222',
    now: () => new Date('2026-07-15T12:00:02.000Z')
  });
  assert.equal(result.record.command.status, 'failed');
  assert.equal(result.record.command.failureClass, 'UsageError');
  assert.equal(result.record.workload.comparable, false);
  const agentNext = JSON.parse(
    await readFile(join(projectRoot, '.agent-ready-drupal', 'agent-next.json'), 'utf8')
  );
  assert.equal(agentNext.requiredAction, 'repair-verification-command');
  assert.match(agentNext.blockers[0].message, /UsageError/);
  assert.equal(agentNext.delta.resolutionUnknown, true);
});

test('an unevaluated verifier failure preserves known site blockers', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-blockers-'));
  await recordVerificationObservability({
    projectRoot,
    report: reportFixture(),
    timing: timingFixture(),
    runId: '44444444-4444-4444-8444-444444444444'
  });
  await recordVerificationObservability({
    projectRoot,
    report: null,
    timing: { ...timingFixture(7), status: 'failed' },
    failureClass: 'UsageError',
    runId: '55555555-5555-4555-8555-555555555555'
  });
  const agentNext = JSON.parse(
    await readFile(join(projectRoot, '.agent-ready-drupal', 'agent-next.json'), 'utf8')
  );
  assert.equal(agentNext.stateFingerprint, observabilityFingerprint('site-state'));
  assert.equal(agentNext.blockers.some((blocker) => blocker.message === 'One fixture blocker.'), true);
  assert.equal(agentNext.blockers.some((blocker) => /UsageError/.test(blocker.message)), true);
  assert.deepEqual(agentNext.delta.resolved, []);
  assert.equal(agentNext.delta.resolutionUnknown, true);
});

test('agent-next bounds blocker count and message bytes while retaining totals', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-bounds-'));
  const errors = Array.from({ length: 100 }, (_, index) => (
    `Blocker ${String(index).padStart(3, '0')} ${'x'.repeat(1_000)}`
  ));
  await recordVerificationObservability({
    projectRoot,
    report: reportFixture({ completionBlockedReasons: [], errors }),
    timing: timingFixture(),
    runId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  });
  const agentNext = JSON.parse(
    readFileSync(join(projectRoot, '.agent-ready-drupal', 'agent-next.json'), 'utf8')
  );
  assert.equal(agentNext.totalBlockerCount, 100);
  assert.equal(agentNext.blockers.length, 32);
  assert.equal(agentNext.omittedBlockerCount, 68);
  assert.equal(
    agentNext.blockers.every((blocker) => Buffer.byteLength(blocker.message) <= 512),
    true
  );
});

test('project-local metrics reject a symlinked state root', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-link-'));
  const outside = mkdtempSync(join(tmpdir(), 'verification-performance-outside-'));
  symlinkSync(outside, join(projectRoot, '.agent-ready-drupal'));
  await assert.rejects(
    recordVerificationObservability({
      projectRoot,
      report: reportFixture(),
      timing: timingFixture(),
      runId: '33333333-3333-4333-8333-333333333333'
    }),
    /state root must be a real directory/
  );
});

test('project-local metrics claim a new namespace but never overwrite existing ignore policy', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-ignore-'));
  const stateRoot = join(projectRoot, '.agent-ready-drupal');
  execFileSync('git', ['init', '-q'], { cwd: projectRoot, stdio: 'pipe' });
  await recordVerificationObservability({
    projectRoot,
    report: reportFixture(),
    timing: timingFixture(),
    runId: '77777777-7777-4777-8777-777777777770'
  });
  assert.equal(readFileSync(join(stateRoot, '.gitignore'), 'utf8'), '*\n');
  assert.equal(execFileSync('git', ['status', '--short'], {
    cwd: projectRoot,
    encoding: 'utf8'
  }), '');

  writeFileSync(join(stateRoot, '.gitignore'), '!agent-next.json\n');
  await assert.rejects(
    recordVerificationObservability({
      projectRoot,
      report: reportFixture(),
      timing: timingFixture(),
      runId: '77777777-7777-4777-8777-777777777771'
    }),
    /ignore marker is non-canonical/
  );
  assert.equal(readFileSync(join(stateRoot, '.gitignore'), 'utf8'), '!agent-next.json\n');

  const unownedProjectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-unowned-'));
  const unownedStateRoot = join(unownedProjectRoot, '.agent-ready-drupal');
  mkdirSync(unownedStateRoot);
  writeFileSync(join(unownedStateRoot, '.gitignore'), '*\n');
  await assert.rejects(
    recordVerificationObservability({
      projectRoot: unownedProjectRoot,
      report: reportFixture(),
      timing: timingFixture(),
      runId: '77777777-7777-4777-8777-777777777772'
    }),
    /is not owned by the build kit/
  );
});

test('performance run ids cannot escape the local state directory', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-run-id-'));
  await assert.rejects(
    recordVerificationObservability({
      projectRoot,
      report: reportFixture(),
      timing: timingFixture(),
      runId: '../escaped'
    }),
    /Run id must use/
  );
  assert.equal(existsSync(join(projectRoot, 'escaped.json')), false);
});

test('metrics history and per-run files retain only the newest bounded window', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-retention-'));
  for (let index = 0; index < 257; index += 1) {
    await recordVerificationObservability({
      projectRoot,
      report: reportFixture(),
      timing: timingFixture(1),
      verificationPreObservabilityMs: 1,
      runId: `retention-${String(index).padStart(3, '0')}`,
      now: () => new Date(1_700_000_000_000 + index)
    });
  }
  const metricsRoot = join(projectRoot, '.agent-ready-drupal', 'verification-metrics');
  assert.equal(
    readFileSync(join(metricsRoot, 'runs.jsonl'), 'utf8').trim().split('\n').length,
    256
  );
  assert.equal(
    readdirSync(join(metricsRoot, 'runs')).filter((name) => name.endsWith('.json')).length,
    256
  );
});

test('performance report rejects symlinked and oversized local metric inputs', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-read-guard-'));
  const result = await recordVerificationObservability({
    projectRoot,
    report: reportFixture(),
    timing: timingFixture(),
    runId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
  });
  const script = join(import.meta.dirname, '..', 'bin', 'verification-observability.mjs');
  const runPath = join(projectRoot, result.paths.run);
  const outside = join(projectRoot, 'outside.json');
  writeFileSync(outside, '{}\n');
  unlinkSync(runPath);
  symlinkSync(outside, runPath);
  const linked = spawnSync(process.execPath, [script, 'report', '--json'], {
    cwd: projectRoot,
    encoding: 'utf8'
  });
  assert.equal(linked.status, 1);
  assert.match(linked.stderr, /single-link regular files/);

  unlinkSync(runPath);
  writeFileSync(runPath, '{}\n');
  writeFileSync(
    join(projectRoot, '.agent-ready-drupal', 'verification-metrics', 'runs.jsonl'),
    'x'.repeat(2 * 1024 * 1024 + 1)
  );
  const oversized = spawnSync(process.execPath, [script, 'report', '--json'], {
    cwd: projectRoot,
    encoding: 'utf8'
  });
  assert.equal(oversized.status, 1);
  assert.match(oversized.stderr, /read limit/);
});

test('summaries compare like workloads and retain overlap-aware phase medians', () => {
  const report = reportFixture();
  const workload = buildVerificationWorkload(report);
  const optimizedWorkload = buildVerificationWorkload(reportFixture({
    buildState: {
      ...report.buildState,
      evidenceBindings: {
        ...report.buildState.evidenceBindings,
        verifierFingerprint: observabilityFingerprint('optimized-verifier')
      }
    }
  }));
  const records = [20, 40, 100].map((verificationPreObservabilityMs, index) => ({
    runId: `run-${index}`,
    verificationPreObservabilityMs,
    workload: index === 1 ? optimizedWorkload : workload,
    outcome: {
      commandStatus: index === 2 ? 'failed' : 'completed',
      valid: index === 0
    },
    timing: index === 2
      ? {
          ...timingFixture(verificationPreObservabilityMs),
          phases: [{
            id: 'failed-outlier',
            startOffsetMs: 0,
            endOffsetMs: 10_000,
            durationMs: 10_000,
            status: 'completed',
            details: {}
          }]
        }
      : {
          ...timingFixture(verificationPreObservabilityMs),
          phases: [
            ...timingFixture(verificationPreObservabilityMs).phases,
            {
              id: 'aborted-outlier',
              startOffsetMs: 0,
              endOffsetMs: 10_000,
              durationMs: 10_000,
              status: 'aborted',
              details: {}
            },
            {
              id: 'source-census-not-run',
              startOffsetMs: 0,
              endOffsetMs: 0,
              durationMs: 0,
              status: 'completed',
              details: { attempted: false }
            }
          ]
        }
  }));
  const summary = summarizeVerificationRuns(records);
  assert.equal(summary.runCount, 3);
  assert.equal(summary.completedRunCount, 2);
  assert.equal(summary.failedCommandRunCount, 1);
  assert.equal(summary.validRunCount, 1);
  assert.equal(summary.invalidRunCount, 1);
  assert.equal(summary.medianVerificationPreObservabilityMs, 30);
  assert.equal(summary.comparableWorkloads[workload.fingerprint].runCount, 3);
  assert.equal(summary.comparableWorkloads[workload.fingerprint].completedRunCount, 2);
  assert.equal(
    summary.comparableWorkloads[workload.fingerprint].medianVerificationPreObservabilityMs,
    30
  );
  assert.equal(
    summary.comparableWorkloads[workload.fingerprint].implementations[workload.inputs.verifier].runCount,
    2
  );
  assert.equal(
    summary.comparableWorkloads[workload.fingerprint]
      .implementations[optimizedWorkload.inputs.verifier].medianVerificationPreObservabilityMs,
    40
  );
  assert.equal(summary.phases['source-census'].medianDurationMs, 30);
  assert.equal(summary.phases['failed-outlier'].measuredRunCount, 0);
  assert.equal(summary.phases['failed-outlier'].discardedRunCount, 1);
  assert.equal(summary.phases['aborted-outlier'].measuredRunCount, 0);
  assert.equal(summary.phases['aborted-outlier'].abortedRunCount, 2);
  assert.equal(summary.phases['source-census-not-run'].measuredRunCount, 0);
  assert.equal(summary.phases['source-census-not-run'].skippedRunCount, 2);
  assert.equal(
    summary.comparableWorkloads[workload.fingerprint]
      .implementations[optimizedWorkload.inputs.verifier]
      .phases['source-census'].medianDurationMs,
    30
  );
});

test('plain observability report labels global data and shows matched implementation cohorts', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-cohorts-'));
  const reportA = reportFixture();
  const reportB = reportFixture({
    buildState: {
      ...reportA.buildState,
      evidenceBindings: {
        ...reportA.buildState.evidenceBindings,
        verifierFingerprint: observabilityFingerprint('second-implementation')
      }
    }
  });
  await recordVerificationObservability({
    projectRoot,
    report: reportA,
    timing: timingFixture(20),
    verificationPreObservabilityMs: 20,
    runId: '88888888-8888-4888-8888-888888888888'
  });
  await recordVerificationObservability({
    projectRoot,
    report: reportB,
    timing: timingFixture(10),
    verificationPreObservabilityMs: 10,
    runId: '99999999-9999-4999-8999-999999999999'
  });
  const script = join(import.meta.dirname, '..', 'bin', 'verification-observability.mjs');
  const output = execFileSync(process.execPath, [script, 'report'], {
    cwd: projectRoot,
    encoding: 'utf8'
  });
  assert.match(output, /coarse inventory; not comparable across workloads/);
  assert.match(output, /Matched workload cohorts/);
  assert.equal((output.match(/implementation sha256:/g) ?? []).length, 2);
});

test('observability CLI anchors nested invocations to the Drupal DDEV project root', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'verification-performance-root-'));
  const nested = join(projectRoot, 'web', 'modules', 'custom');
  mkdirSync(join(projectRoot, '.ddev'), { recursive: true });
  mkdirSync(nested, { recursive: true });
  writeFileSync(join(projectRoot, '.ddev', 'config.yaml'), 'name: fixture\ntype: drupal11\n');
  await recordVerificationObservability({
    projectRoot,
    report: reportFixture(),
    timing: timingFixture(),
    runId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  });
  const script = join(import.meta.dirname, '..', 'bin', 'verification-observability.mjs');
  const result = spawnSync(process.execPath, [script, 'report', '--json'], {
    cwd: nested,
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).verification.runCount, 1);
  assert.equal(existsSync(join(nested, '.agent-ready-drupal')), false);
});
