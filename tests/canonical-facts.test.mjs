import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  CanonicalFactContradictionError,
  collectCanonicalFacts,
  generateCanonicalFactStore,
  storeEvidenceObject,
  verifyCanonicalFactStore
} from '../bin/canonical-facts.mjs';

const checkedAt = new Date().toISOString();

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function actor(kind, overrides = {}) {
  const base = {
    kind,
    id: `${kind}-fixture`,
    name: `${kind} fixture`,
    identityBasis: `Recorded ${kind} test identity`
  };
  if (kind === 'subagent') base.parentActorId = 'agent-fixture';
  if (kind === 'tool') base.tool = 'fixture-verifier --check';
  return { ...base, ...overrides };
}

function factFixture() {
  const root = mkdtempSync(join(tmpdir(), 'canonical-facts-'));
  const packetDir = join(root, 'review-packet');
  mkdirSync(join(packetDir, 'evidence'), { recursive: true });
  writeJson(join(packetDir, 'source-audit.json'), {
    site: { baseUrl: 'https://source.example/' }
  });
  writeJson(join(packetDir, 'pattern-map.json'), {
    sourceSite: 'https://source.example',
    pageCompositionOwnership: [{ sourceRoute: '/', selectedOwner: 'node' }],
    compositionModel: { flexibleLandingRoutes: [] },
    sectionOwnershipMatrix: []
  });
  writeJson(join(packetDir, 'route-matrix.json'), {
    sourceBaseUrl: 'https://source.example',
    targetBaseUrl: 'https://target.example/',
    homepageParity: {
      targetPath: '/',
      targetStatus: 200,
      targetFinalPath: '/',
      targetDrupalRouteOwner: 'node',
      accepted: true
    },
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }],
    routes: [{ sourcePath: '/', targetPath: '/', targetStatus: 200, targetFinalPath: '/', accepted: true }],
    targetRequiredRoutes: [{ targetPath: '/', targetStatus: 200, targetFinalPath: '/', drupalOwner: 'node', accepted: true }]
  });
  writeJson(join(packetDir, 'parity-report.json'), { targetUrl: 'https://target.example' });
  writeJson(join(packetDir, 'browser-evidence.json'), { site: 'https://target.example/' });
  writeJson(join(packetDir, 'independent-verification.json'), {
    target: { baseUrl: 'https://target.example' },
    completionClaims: [{ status: 'pass' }],
    compositionModelFidelityChecks: [],
    summary: { failedClaimCount: 0, blockedClaimCount: 0, verdict: 'pass' }
  });
  writeJson(join(packetDir, 'blind-adversarial-review.json'), {
    site: 'https://target.example',
    productDefects: [],
    summary: {
      verdict: 'good',
      completionState: 'parity_reviewed',
      openBlockerIssueCount: 0,
      openCriticalIssueCount: 0,
      openHighIssueCount: 0,
      acceptedOutOfScopeIssueCount: 0,
      externalBlockerIssueCount: 0
    }
  });
  writeJson(join(packetDir, 'drupal-readback.json'), {
    site: 'https://target.example',
    drupal: {
      siteUuid: '11111111-1111-4111-8111-111111111111',
      configSyncDirectory: '../config/sync',
      trackedConfigDirectory: 'config/sync',
      configSyncDirectoryMatchesTrackedDirectory: true,
      configStatus: 'No differences',
      configStatusClean: true,
      frontPage: '/'
    }
  });
  writeJson(join(packetDir, 'field-output-matrix.json'), { site: 'https://target.example' });
  const originalEvidence = Buffer.from('{"observation":"same bytes"}\n');
  writeFileSync(join(packetDir, 'evidence', 'shared.json'), originalEvidence);
  writeJson(join(packetDir, 'fact-provenance.json'), {
    schemaVersion: 'public-kit.fact-provenance.1',
    humanGateAcceptanceRecordedHere: false,
    run: {
      id: 'canonical-fixture',
      startedAt: checkedAt,
      finishedAt: checkedAt,
      actor: actor('agent')
    },
    claims: [
      {
        claimId: 'agent-observation',
        gate: 'G-ROUTE-01',
        authority: 'evidence_observation',
        status: 'observed',
        checkedAt,
        reviewer: actor('agent'),
        factKeys: ['site.target.origin', 'route:/:status'],
        evidence: ['evidence/shared.json']
      },
      {
        claimId: 'subagent-observation',
        gate: 'G-CONFIG-01',
        authority: 'evidence_observation',
        status: 'observed',
        checkedAt,
        reviewer: actor('subagent'),
        factKeys: ['config.status.clean', 'ownership:/:pageOwner', 'completion.independent.verdict'],
        evidence: ['evidence/shared.json']
      }
    ]
  });
  return { packetDir, originalEvidence };
}

test('canonical fact generation is deterministic and deduplicates evidence without deleting originals', () => {
  const { packetDir, originalEvidence } = factFixture();
  const first = generateCanonicalFactStore({ packetDir });
  const generatedNames = ['canonical-facts.json', 'claims.json', 'object-index.json', 'summary.md', 'manifest.json'];
  const firstBytes = new Map(generatedNames.map((name) => [name, readFileSync(join(packetDir, 'evidence', 'facts', name))]));
  const objectFiles = readdirSync(join(packetDir, 'evidence', 'objects', 'sha256'));

  assert.equal(objectFiles.length, 1, 'two claims with identical bytes must share one object');
  assert.deepEqual(readFileSync(join(packetDir, 'evidence', 'shared.json')), originalEvidence);
  const objectBytes = readFileSync(join(packetDir, 'evidence', 'objects', 'sha256', objectFiles[0]));
  assert.deepEqual(objectBytes, originalEvidence);
  assert.doesNotMatch(objectBytes.toString('utf8'), /reviewer|agent-fixture|run/);

  const index = JSON.parse(readFileSync(join(packetDir, 'evidence', 'facts', 'object-index.json'), 'utf8'));
  assert.deepEqual(index.objects[0].claimIds, ['agent-observation', 'subagent-observation']);
  assert.deepEqual(index.objects[0].originalPaths, ['evidence/shared.json']);
  const claims = JSON.parse(readFileSync(join(packetDir, 'evidence', 'facts', 'claims.json'), 'utf8'));
  assert.equal(claims.humanGateAcceptanceRecordedHere, false);
  assert.deepEqual(claims.claims.map((claim) => claim.reviewer.kind), ['agent', 'subagent']);
  const summary = readFileSync(join(packetDir, 'evidence', 'facts', 'summary.md'), 'utf8');
  assert.match(summary, /Human-gate acceptance: not recorded here/);
  assert.match(summary, /## Site Facts/);
  assert.match(summary, /## Completion Facts/);

  const legacySnapshot = join(packetDir, 'evidence', 'lifecycle', 'changes', 'legacy', 'evidence', 'old-proof.txt');
  mkdirSync(join(legacySnapshot, '..'), { recursive: true });
  writeFileSync(legacySnapshot, 'legacy snapshot path\n');

  const second = generateCanonicalFactStore({ packetDir });
  assert.deepEqual(second, first);
  for (const name of generatedNames) {
    assert.deepEqual(readFileSync(join(packetDir, 'evidence', 'facts', name)), firstBytes.get(name), name);
  }
  assert.equal(readFileSync(legacySnapshot, 'utf8'), 'legacy snapshot path\n');
  assert.equal(verifyCanonicalFactStore({ packetDir }).ready, true);
});

test('all provenance kinds are truthful metadata observations, never implicit human acceptance', () => {
  const { packetDir } = factFixture();
  const provenancePath = join(packetDir, 'fact-provenance.json');
  const provenance = JSON.parse(readFileSync(provenancePath, 'utf8'));
  provenance.claims = ['agent', 'subagent', 'tool', 'named_human'].map((kind) => ({
    claimId: `${kind}-observation`,
    gate: kind === 'named_human' ? 'G-MAINTAINER-01' : 'G-VERIFY-01',
    authority: 'evidence_observation',
    status: 'observed',
    checkedAt,
    reviewer: actor(kind),
    factKeys: ['site.target.origin'],
    evidence: ['evidence/shared.json']
  }));
  writeJson(provenancePath, provenance);
  generateCanonicalFactStore({ packetDir });
  const claims = JSON.parse(readFileSync(join(packetDir, 'evidence', 'facts', 'claims.json'), 'utf8'));

  assert.deepEqual(claims.claims.map((claim) => claim.reviewer.kind), ['agent', 'named_human', 'subagent', 'tool']);
  assert.equal(claims.humanGateAcceptanceRecordedHere, false);
  assert.ok(claims.claims.every((claim) => claim.authority === 'evidence_observation'));

  provenance.claims = provenance.claims.filter((claim) => claim.reviewer.kind !== 'named_human');
  writeJson(provenancePath, provenance);
  assert.doesNotThrow(() => generateCanonicalFactStore({ packetDir }), 'an agent-only run must never be forced to pretend a human participated');
});

test('invalid provenance and stale or tampered generated output fail closed', () => {
  const { packetDir } = factFixture();
  const provenancePath = join(packetDir, 'fact-provenance.json');
  const provenance = JSON.parse(readFileSync(provenancePath, 'utf8'));
  provenance.claims[1].reviewer = actor('subagent', { parentActorId: '' });
  writeJson(provenancePath, provenance);
  assert.throws(() => generateCanonicalFactStore({ packetDir }), /subagent requires parentActorId/i);

  provenance.claims[1].reviewer = actor('subagent');
  provenance.humanGateAcceptanceRecordedHere = true;
  writeJson(provenancePath, provenance);
  assert.throws(() => generateCanonicalFactStore({ packetDir }), /must not record human-gate acceptance/i);

  provenance.humanGateAcceptanceRecordedHere = false;
  provenance.claims[0].gate = 'NOT-A-CANONICAL-GATE';
  writeJson(provenancePath, provenance);
  assert.throws(() => generateCanonicalFactStore({ packetDir }), /canonical gates\.json ID/i);

  provenance.claims[0].gate = 'G-ROUTE-01';
  writeJson(provenancePath, provenance);
  generateCanonicalFactStore({ packetDir });
  writeFileSync(join(packetDir, 'evidence', 'facts', 'summary.md'), '# Edited summary\n');
  const stale = verifyCanonicalFactStore({ packetDir });
  assert.equal(stale.valid, true);
  assert.equal(stale.ready, false);
  assert.match(stale.reasons.join('\n'), /stale or non-deterministic.*summary\.md/i);

  const object = readdirSync(join(packetDir, 'evidence', 'objects', 'sha256'))[0];
  writeFileSync(join(packetDir, 'evidence', 'objects', 'sha256', object), 'tampered\n');
  const tampered = verifyCanonicalFactStore({ packetDir });
  assert.equal(tampered.ready, false);
  assert.match(tampered.reasons.join('\n'), /Evidence object bytes do not match/i);
});

test('query-aware routes remain distinct canonical facts', () => {
  const { packetDir } = factFixture();
  const routePath = join(packetDir, 'route-matrix.json');
  const routeMatrix = JSON.parse(readFileSync(routePath, 'utf8'));
  routeMatrix.routes.push(
    { sourcePath: '/search?q=alpha', targetPath: '/search?q=alpha', targetStatus: 200, targetFinalPath: '/search?q=alpha', accepted: true },
    { sourcePath: '/search?q=beta', targetPath: '/search?q=beta', targetStatus: 200, targetFinalPath: '/search?q=beta', accepted: true }
  );
  writeJson(routePath, routeMatrix);

  const facts = collectCanonicalFacts({ packetDir }).facts.map((fact) => fact.key);
  assert.ok(facts.includes('route:/search?q=alpha:status'));
  assert.ok(facts.includes('route:/search?q=beta:status'));
});

test('evidence-object storage rejects symlink ancestors before creating outside directories', () => {
  const root = mkdtempSync(join(tmpdir(), 'canonical-facts-symlink-'));
  const packetDir = join(root, 'review-packet');
  const outside = join(root, 'outside');
  mkdirSync(packetDir, { recursive: true });
  mkdirSync(outside, { recursive: true });
  symlinkSync(outside, join(packetDir, 'evidence'));

  assert.throws(
    () => storeEvidenceObject({ packetDir, bytes: Buffer.from('proof') }),
    /unsafe ancestor|symbolic link/i
  );
  assert.equal(existsSync(join(outside, 'objects')), false);
});

test('contradictory duplicated site, route, config, ownership, and completion facts fail closed', () => {
  const { packetDir: canonicalPacket } = factFixture();
  const cases = [
    ['site', (packetDir) => {
      writeJson(join(packetDir, 'browser-evidence.json'), { site: 'https://different.example' });
    }],
    ['route', (packetDir) => {
      const route = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8'));
      route.targetRequiredRoutes[0].targetStatus = 404;
      writeJson(join(packetDir, 'route-matrix.json'), route);
    }],
    ['config', (packetDir) => {
      const readback = JSON.parse(readFileSync(join(packetDir, 'drupal-readback.json'), 'utf8'));
      readback.drupal.configStatusClean = false;
      writeJson(join(packetDir, 'drupal-readback.json'), readback);
    }],
    ['ownership', (packetDir) => {
      const route = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8'));
      route.targetRequiredRoutes[0].drupalOwner = 'view';
      writeJson(join(packetDir, 'route-matrix.json'), route);
    }],
    ['completion', (packetDir) => {
      const independent = JSON.parse(readFileSync(join(packetDir, 'independent-verification.json'), 'utf8'));
      independent.completionClaims[0].status = 'fail';
      writeJson(join(packetDir, 'independent-verification.json'), independent);
    }]
  ];

  for (const [name, mutate] of cases) {
    const packetDir = join(dirnameForPacket(canonicalPacket), `contradiction-${name}`);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);
    assert.throws(
      () => collectCanonicalFacts({ packetDir }),
      (error) => error instanceof CanonicalFactContradictionError && error.message.includes(name === 'ownership' ? 'ownership:' : name),
      name
    );
  }
});

function dirnameForPacket(packetDir) {
  return join(packetDir, '..');
}

test('unconfigured provenance is a completion boundary rather than a destructive migration', () => {
  const { packetDir } = factFixture();
  writeJson(join(packetDir, 'fact-provenance.json'), {
    schemaVersion: 'public-kit.fact-provenance.1',
    humanGateAcceptanceRecordedHere: false,
    run: { id: '', startedAt: '', finishedAt: '', actor: {} },
    claims: []
  });
  const legacy = join(packetDir, 'evidence', 'legacy-proof.txt');
  writeFileSync(legacy, 'legacy proof remains\n');
  const result = verifyCanonicalFactStore({ packetDir });

  assert.equal(result.valid, true);
  assert.equal(result.ready, false);
  assert.match(result.reasons.join('\n'), /unconfigured stub/i);
  assert.equal(existsSync(legacy), true);
  assert.equal(readFileSync(legacy, 'utf8'), 'legacy proof remains\n');
});
