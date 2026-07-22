import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  createLiveVerificationReport,
  LIVE_VERIFICATION_MODE,
  LIVE_VERIFICATION_SCHEMA
} from '../bin/live-verification-contract.mjs';
import {
  reviewHandoffManifestErrors,
  reviewHandoffInputFileBindings,
  reviewHandoffPreliminaryPacketFingerprint,
  reviewHandoffProjectionDigest,
  reviewHandoffProjectionErrors,
  reviewHandoffReference,
  reviewHandoffReviewerErrors,
  reviewHandoffStateErrors,
  sealReviewHandoff,
  sealReviewHandoffBundle,
  writeReviewHandoff
} from '../bin/review-handoff.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const templatesDir = join(repoRoot, 'templates');
const handoffScript = join(repoRoot, 'bin', 'review-handoff.mjs');
const siteUuid = '11111111-1111-4111-8111-111111111111';
const stateFingerprint = `sha256:${'1'.repeat(64)}`;
const identityFingerprint = `sha256:${'2'.repeat(64)}`;

function templateName(packetFile) {
  const parsed = parse(packetFile);
  return `${parsed.name}.template${parsed.ext}`;
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function refreshPreliminaryPacketFingerprint(packetDir) {
  const path = join(packetDir, 'evidence', 'live-verification.json');
  const report = JSON.parse(readFileSync(path, 'utf8'));
  report.buildState.evidenceBindings.packetFingerprint = reviewHandoffPreliminaryPacketFingerprint(packetDir);
  writeJson(path, report);
}

function fixtureProject() {
  const projectRoot = mkdtempSync(join(tmpdir(), 'review-handoff-'));
  const packetDir = join(projectRoot, 'review-packet');
  mkdirSync(packetDir, { recursive: true });
  writeFileSync(join(projectRoot, 'AGENTS.md'), '# Target instructions\n');
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  for (const file of gates.reviewPacketFiles) {
    cpSync(join(templatesDir, templateName(file)), join(packetDir, file));
  }
  writeJson(join(packetDir, 'build-input.json'), {
    schemaVersion: 'public-kit.build-input.1',
    mode: 'source_site',
    sourceUrl: 'https://source.example/',
    brief: null
  });
  const routeMatrix = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8'));
  routeMatrix.sourceBaseUrl = 'https://source.example/';
  routeMatrix.targetBaseUrl = 'https://target.ddev.site/';
  routeMatrix.primaryRoutes = [{
    sourcePath: '/',
    targetPath: '/',
    briefRequirementIds: [],
    routeRole: 'homepage',
    sourceIntent: 'Source homepage',
    targetIntent: 'Rebuilt homepage',
    matchesBrowserRenderedSource: true,
    accepted: true,
    notes: 'Builder rationale must not enter the blind handoff.'
  }];
  writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  blind.reviewInputs = {
    originalBrief: 'Rebuild the supplied public source site as Drupal CMS.',
    acceptanceCriteria: ['Match the public homepage on desktop and mobile.'],
    targetUrlsOrArtifacts: [],
    sourceOfTruthMaterials: [{
      type: 'source_site',
      reference: 'https://source.example/',
      notes: 'Builder note deliberately omitted from the generated handoff.'
    }],
    credentialsUsed: [],
    excludedInputs: []
  };
  writeJson(blindPath, blind);
  const liveVerificationPath = join(packetDir, 'evidence', 'live-verification.json');
  const liveVerification = createLiveVerificationReport({
    verificationMode: LIVE_VERIFICATION_MODE,
    buildMode: 'source_site',
    liveTargetValid: true,
    target: { resolvedBaseUrl: 'https://target.ddev.site/' },
    buildState: {
      schemaVersion: 'public-kit.site-state.1',
      complete: true,
      fingerprint: stateFingerprint,
      componentFingerprints: { targetIdentity: identityFingerprint },
      targetIdentity: {
        configSyncDirectory: '../config/sync',
        frontPage: '/',
        siteUuid
      },
      evidenceBindings: { packetFingerprint: '' }
    },
    drupalRuntime: {
      authoritativeForCompletion: true,
      confirmed: true,
      siteUuidMatchesPacket: true,
      configStatusClean: true,
      configSyncMatchesHead: true
    }
  });
  writeJson(liveVerificationPath, liveVerification);
  liveVerification.buildState.evidenceBindings.packetFingerprint = reviewHandoffPreliminaryPacketFingerprint(packetDir);
  writeJson(liveVerificationPath, liveVerification);
  return { packetDir, projectRoot };
}

function reviewerRecords(manifest, projections) {
  const independent = {
    reviewHandoff: reviewHandoffReference(manifest.handoffDigest),
    artifactsReviewed: projections.independent.allowedInputs.files.map((binding) => binding.path),
    target: {
      baseUrl: 'https://target.ddev.site/',
      adminUrl: 'https://target.ddev.site/admin'
    }
  };
  const allowed = projections.blind.allowedInputs;
  const blind = {
    reviewHandoff: reviewHandoffReference(manifest.handoffDigest),
    reviewInputs: {
      originalBrief: allowed.brief.reference,
      acceptanceCriteria: [...allowed.acceptanceCriteria],
      targetUrlsOrArtifacts: [...allowed.targetUrlsOrArtifacts],
      sourceOfTruthMaterials: structuredClone(allowed.sourceOfTruthMaterials),
      credentialsUsed: [...allowed.credentialLabels],
      excludedInputs: [...projections.blind.excludedInputs]
    },
    routeViewportReviews: allowed.primaryRoutes.map((route) => ({
      route: route.targetPath,
      targetUrlOrArtifact: route.targetUrl,
      sourceTruthReference: route.sourceTruthReference,
      briefRequirementIds: route.briefRequirementIds
    }))
  };
  return { blind, independent };
}

function resealProjectionBundle(bundle, kind) {
  const projections = structuredClone(bundle.projections);
  let manifest = structuredClone(bundle.manifest);
  projections[kind].projectionDigest = reviewHandoffProjectionDigest(projections[kind]);
  manifest.reviewerProjections[kind].digest = projections[kind].projectionDigest;
  manifest = sealReviewHandoff(manifest);
  for (const projection of Object.values(projections)) {
    projection.handoff = reviewHandoffReference(manifest.handoffDigest);
  }
  return { manifest, projections };
}

function allKeys(value, result = []) {
  if (!value || typeof value !== 'object') return result;
  if (Array.isArray(value)) {
    for (const child of value) allKeys(child, result);
    return result;
  }
  for (const [key, child] of Object.entries(value)) {
    result.push(key);
    allKeys(child, result);
  }
  return result;
}

test('review handoff is byte-stable, sanitized, state-bound, and never writes reviewer artifacts', () => {
  const { packetDir, projectRoot } = fixtureProject();
  const independentPath = join(packetDir, 'independent-verification.json');
  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const independentBefore = readFileSync(independentPath);
  const blindBefore = readFileSync(blindPath);

  const first = writeReviewHandoff({
    project: projectRoot,
    packet: 'review-packet',
    blindCredentialLabelValues: ['content-editor'],
    independentCredentialLabelValues: ['verification-editor']
  });
  const firstBytes = readFileSync(first.outputPath);
  const firstBlindBytes = readFileSync(first.projectionPaths.blind);
  const firstIndependentBytes = readFileSync(first.projectionPaths.independent);
  const second = writeReviewHandoff({
    project: projectRoot,
    packet: 'review-packet',
    blindCredentialLabelValues: ['content-editor'],
    independentCredentialLabelValues: ['verification-editor']
  });

  assert.deepEqual(readFileSync(second.outputPath), firstBytes);
  assert.deepEqual(readFileSync(second.projectionPaths.blind), firstBlindBytes);
  assert.deepEqual(readFileSync(second.projectionPaths.independent), firstIndependentBytes);
  assert.deepEqual(readFileSync(independentPath), independentBefore);
  assert.deepEqual(readFileSync(blindPath), blindBefore);
  assert.deepEqual(reviewHandoffManifestErrors(first.manifest), []);
  assert.equal(first.manifest.binding.siteStateFingerprint, stateFingerprint);
  assert.equal(first.manifest.binding.targetOrigin, 'https://target.ddev.site');
  assert.equal(first.manifest.authority.completionAuthority, false);
  assert.equal(first.manifest.authority.reviewerIdentityAuthority, false);
  assert.equal(first.manifest.authority.writesReviewerArtifacts, false);
  assert.equal(first.projections.blind.allowedInputs.primaryRoutes[0].notes, undefined);
  assert.deepEqual(first.projections.blind.allowedInputs.credentialLabels, ['content-editor']);
  assert.deepEqual(first.projections.independent.allowedInputs.credentialLabels, ['verification-editor']);
  assert.equal(first.projections.independent.allowedInputs.files.some((binding) => binding.path === 'AGENTS.md'), true);
  assert.equal(
    first.projections.independent.allowedInputs.files.some((binding) =>
      /(?:independent-verification|blind-adversarial-review)/.test(binding.path)
    ),
    false
  );
  assert.equal(first.manifest.reviewers, undefined);
  assert.equal(first.projections.blind.allowedInputs.files, undefined);
  assert.deepEqual(reviewHandoffProjectionErrors(first.projections.blind, 'blind', first.manifest), []);
  assert.deepEqual(reviewHandoffProjectionErrors(first.projections.independent, 'independent', first.manifest), []);
  for (const forbidden of ['completionClaim', 'completionClaims', 'readbackComplete', 'reviewerArtifact', 'reviewerIdentity', 'verdict']) {
    assert.equal(allKeys({ manifest: first.manifest, projections: first.projections }).includes(forbidden), false, forbidden);
  }
});

test('review handoff consumes the current verifier report contract and rejects legacy schema v1', () => {
  const current = fixtureProject();
  const currentReportPath = join(current.packetDir, 'evidence', 'live-verification.json');
  const currentReport = JSON.parse(readFileSync(currentReportPath, 'utf8'));

  assert.equal(currentReport.schemaVersion, LIVE_VERIFICATION_SCHEMA);
  assert.doesNotThrow(() => writeReviewHandoff({ project: current.projectRoot }));

  const legacy = fixtureProject();
  const legacyReportPath = join(legacy.packetDir, 'evidence', 'live-verification.json');
  const legacyReport = JSON.parse(readFileSync(legacyReportPath, 'utf8'));
  legacyReport.schemaVersion = 'public-kit.live-verification.1';
  writeJson(legacyReportPath, legacyReport);

  assert.throws(
    () => writeReviewHandoff({ project: legacy.projectRoot }),
    /Run the live-target verifier before creating a review handoff/
  );
});

test('reviewer references reject stale digests and inputs outside the generated boundary', () => {
  const { packetDir, projectRoot } = fixtureProject();
  const { manifest, projections } = writeReviewHandoff({ project: projectRoot });
  const { blind, independent } = reviewerRecords(manifest, projections);
  const declaredPacketFiles = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8')).reviewPacketFiles;

  assert.deepEqual(reviewHandoffReviewerErrors({
    manifest,
    projections,
    independentVerification: independent,
    blindReview: blind,
    packetDir,
    declaredPacketFiles
  }), {
    blind: [],
    common: [],
    independent: []
  });

  independent.artifactsReviewed.push('web/modules/custom/private_builder_notes.txt');
  blind.reviewInputs.targetUrlsOrArtifacts.push('https://wrong.example/');
  blind.reviewHandoff.digest = `sha256:${'f'.repeat(64)}`;
  const errors = reviewHandoffReviewerErrors({
    manifest,
    projections,
    independentVerification: independent,
    blindReview: blind,
    packetDir,
    declaredPacketFiles
  });
  assert.match(errors.independent.join('\n'), /disallowed input/);
  assert.match(errors.blind.join('\n'), /exact review-handoff.*digest|target inputs do not match/i);
});

test('reviewer input byte drift invalidates the exact handed-off packet files', () => {
  const { packetDir, projectRoot } = fixtureProject();
  const { manifest, projections } = writeReviewHandoff({ project: projectRoot });
  const { blind, independent } = reviewerRecords(manifest, projections);
  const declaredPacketFiles = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8')).reviewPacketFiles;

  writeFileSync(join(packetDir, 'route-matrix.json'), '{"changed":true}\n');
  const errors = reviewHandoffReviewerErrors({
    manifest,
    projections,
    independentVerification: independent,
    blindReview: blind,
    packetDir,
    declaredPacketFiles
  });

  assert.match(errors.independent.join('\n'), /size and sha256|reviewerInputFingerprint/i);
});

test('final reviewer validation rediscovers the complete input membership as well as bytes', () => {
  const addedFixture = fixtureProject();
  const addedBundle = writeReviewHandoff({ project: addedFixture.projectRoot });
  const addedRecords = reviewerRecords(addedBundle.manifest, addedBundle.projections);
  const declaredPacketFiles = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8')).reviewPacketFiles;
  writeJson(join(addedFixture.packetDir, 'evidence', 'new-builder-claim.json'), { claim: 'added after handoff' });
  const addedErrors = reviewHandoffReviewerErrors({
    manifest: addedBundle.manifest,
    projections: addedBundle.projections,
    independentVerification: addedRecords.independent,
    blindReview: addedRecords.blind,
    packetDir: addedFixture.packetDir,
    declaredPacketFiles
  });
  assert.match(addedErrors.independent.join('\n'), /input added after handoff.*new-builder-claim\.json/i);

  const omittedFixture = fixtureProject();
  const complete = writeReviewHandoff({ project: omittedFixture.projectRoot });
  const omittedPath = complete.projections.independent.allowedInputs.files
    .find((binding) => binding.path.endsWith('/route-matrix.json')).path;
  const omitted = sealReviewHandoffBundle({
    binding: complete.manifest.binding,
    blind: {
      allowedInputs: complete.projections.blind.allowedInputs,
      excludedInputs: complete.projections.blind.excludedInputs
    },
    independent: {
      allowedInputs: {
        ...complete.projections.independent.allowedInputs,
        files: complete.projections.independent.allowedInputs.files.filter((binding) => binding.path !== omittedPath)
      },
      excludedInputs: complete.projections.independent.excludedInputs
    }
  });
  const omittedRecords = reviewerRecords(omitted.manifest, omitted.projections);
  const omittedErrors = reviewHandoffReviewerErrors({
    manifest: omitted.manifest,
    projections: omitted.projections,
    independentVerification: omittedRecords.independent,
    blindReview: omittedRecords.blind,
    packetDir: omittedFixture.packetDir,
    declaredPacketFiles
  });
  assert.match(omittedErrors.independent.join('\n'), new RegExp(`input added after handoff.*${omittedPath.replaceAll('.', '\\.')}`, 'i'));
});

test('independent handoff rejects duplicate bindings, widened URLs, and incomplete reviewed membership', () => {
  const duplicateFixture = fixtureProject();
  const duplicateComplete = writeReviewHandoff({ project: duplicateFixture.projectRoot });
  const duplicateBinding = duplicateComplete.projections.independent.allowedInputs.files[0];
  duplicateComplete.projections.independent.allowedInputs.files.unshift({
    ...duplicateBinding,
    size: duplicateBinding.size + 1,
    sha256: `sha256:${'f'.repeat(64)}`
  });
  const duplicate = resealProjectionBundle(duplicateComplete, 'independent');
  const duplicateRecords = reviewerRecords(duplicate.manifest, duplicate.projections);
  const declaredPacketFiles = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8')).reviewPacketFiles;
  const duplicateErrors = reviewHandoffReviewerErrors({
    manifest: duplicate.manifest,
    projections: duplicate.projections,
    independentVerification: duplicateRecords.independent,
    blindReview: duplicateRecords.blind,
    packetDir: duplicateFixture.packetDir,
    declaredPacketFiles
  });
  assert.match(duplicateErrors.independent.join('\n'), /unique paths|reviewerInputFingerprint|canonical allowed input list/i);

  const widenedFixture = fixtureProject();
  const widenedComplete = writeReviewHandoff({ project: widenedFixture.projectRoot });
  widenedComplete.projections.independent.allowedInputs.urls = [
    ...widenedComplete.projections.independent.allowedInputs.urls,
    'https://builder-summary.example/'
  ].sort();
  const widened = resealProjectionBundle(widenedComplete, 'independent');
  const widenedRecords = reviewerRecords(widened.manifest, widened.projections);
  const widenedErrors = reviewHandoffReviewerErrors({
    manifest: widened.manifest,
    projections: widened.projections,
    independentVerification: widenedRecords.independent,
    blindReview: widenedRecords.blind,
    packetDir: widenedFixture.packetDir,
    declaredPacketFiles
  });
  assert.match(widenedErrors.independent.join('\n'), /URLs do not exactly match/i);

  const incompleteFixture = fixtureProject();
  const incomplete = writeReviewHandoff({ project: incompleteFixture.projectRoot });
  const incompleteRecords = reviewerRecords(incomplete.manifest, incomplete.projections);
  incompleteRecords.independent.artifactsReviewed = [];
  const incompleteErrors = reviewHandoffReviewerErrors({
    manifest: incomplete.manifest,
    projections: incomplete.projections,
    independentVerification: incompleteRecords.independent,
    blindReview: incompleteRecords.blind,
    packetDir: incompleteFixture.packetDir,
    declaredPacketFiles
  });
  assert.match(incompleteErrors.independent.join('\n'), /artifactsReviewed must exactly match every file/i);
});

test('reviewer target and primary-route URLs stay bound to the root target origin', () => {
  const { projectRoot } = fixtureProject();
  const complete = writeReviewHandoff({ project: projectRoot });
  const decoy = sealReviewHandoffBundle({
    binding: complete.manifest.binding,
    blind: {
      allowedInputs: {
        ...complete.projections.blind.allowedInputs,
        primaryRoutes: complete.projections.blind.allowedInputs.primaryRoutes.map((route) => ({
          ...route,
          targetUrl: 'https://decoy.example/'
        })),
        targetUrlsOrArtifacts: ['https://decoy.example/']
      },
      excludedInputs: complete.projections.blind.excludedInputs
    },
    independent: {
      allowedInputs: {
        ...complete.projections.independent.allowedInputs,
        urls: complete.projections.independent.allowedInputs.urls
          .filter((url) => !url.startsWith('https://target.ddev.site'))
          .concat(['https://decoy.example/', 'https://decoy.example/admin'])
      },
      excludedInputs: complete.projections.independent.excludedInputs
    }
  });

  assert.match(
    reviewHandoffProjectionErrors(decoy.projections.independent, 'independent', decoy.manifest).join('\n'),
    /root-bound target URL/i
  );
  assert.match(
    reviewHandoffProjectionErrors(decoy.projections.blind, 'blind', decoy.manifest).join('\n'),
    /root-bound target origin/i
  );
});

test('reviewer inputs reject secret-like evidence and local references through symlink ancestors', () => {
  const secretFixture = fixtureProject();
  writeFileSync(join(secretFixture.packetDir, '.env'), 'IGNORED_ROOT_SECRET=true\n');
  refreshPreliminaryPacketFingerprint(secretFixture.packetDir);
  const clean = writeReviewHandoff({ project: secretFixture.projectRoot });
  assert.equal(clean.projections.independent.allowedInputs.files.some((binding) => binding.path.endsWith('/.env')), false);

  mkdirSync(join(secretFixture.packetDir, 'evidence', 'private'), { recursive: true });
  writeFileSync(join(secretFixture.packetDir, 'evidence', 'private', 'credentials.json'), '{"token":"secret"}\n');
  refreshPreliminaryPacketFingerprint(secretFixture.packetDir);
  assert.throws(
    () => writeReviewHandoff({ project: secretFixture.projectRoot }),
    /secret-like path/i
  );

  const symlinkFixture = fixtureProject();
  const outside = mkdtempSync(join(tmpdir(), 'review-handoff-outside-'));
  writeFileSync(join(outside, 'private.txt'), 'outside-private-data\n');
  symlinkSync(outside, join(symlinkFixture.projectRoot, 'external'));
  const blindPath = join(symlinkFixture.packetDir, 'blind-adversarial-review.json');
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  blind.reviewInputs.sourceOfTruthMaterials.push({ type: 'written_spec', reference: 'external/private.txt' });
  writeJson(blindPath, blind);
  refreshPreliminaryPacketFingerprint(symlinkFixture.packetDir);
  assert.throws(
    () => writeReviewHandoff({ project: symlinkFixture.projectRoot }),
    /symbolic link|inside the review packet/i
  );
});

test('reviewer input discovery rejects common secret basenames', () => {
  for (const name of [
    'client-secret.json',
    'api-key.txt',
    'service-account.json',
    'private_key.txt',
    'oauth-client-secret.json',
    'stripe-api-key.txt',
    'google-service-account.json',
    'github-token.txt',
    'aws-access-key-id.txt',
    'database-password.txt',
    'ssh_host_rsa_key',
    'github-token-backup.txt',
    'id_rsa.bak',
    '.npmrc.backup',
    'service-account-key.json',
    'database-passphrase.txt',
    'kubeconfig'
  ]) {
    const fixture = fixtureProject();
    writeFileSync(join(fixture.packetDir, 'evidence', name), 'must-not-be-reviewed\n');
    refreshPreliminaryPacketFingerprint(fixture.packetDir);
    assert.throws(
      () => writeReviewHandoff({ project: fixture.projectRoot }),
      new RegExp(`secret-like path.*${name.replaceAll('.', '\\.')}`, 'i')
    );
  }
});

test('reviewer input discovery permits benign documentation and design basenames', () => {
  const fixture = fixtureProject();
  const flatNames = [
    'cookie-policy.md',
    'privacy-cookie-policy.json',
    'auth-flow.png',
    'service-account-architecture.md',
    'api-key-rotation-guide.md',
    'private-key-design-notes.md'
  ];
  for (const name of flatNames) {
    writeFileSync(join(fixture.packetDir, 'evidence', name), 'reviewable evidence\n');
  }
  for (const path of [
    ['auth', 'flow.png'],
    ['cookies', 'policy.md'],
    ['api-key', 'rotation-guide.md']
  ]) {
    mkdirSync(join(fixture.packetDir, 'evidence', path[0]), { recursive: true });
    writeFileSync(join(fixture.packetDir, 'evidence', ...path), 'reviewable evidence\n');
  }
  refreshPreliminaryPacketFingerprint(fixture.packetDir);
  const handoff = writeReviewHandoff({ project: fixture.projectRoot });
  const reviewed = handoff.projections.independent.allowedInputs.files.map((binding) => binding.path);
  for (const name of flatNames) {
    assert.equal(reviewed.some((path) => path.endsWith(`/evidence/${name}`)), true, name);
  }
  for (const path of ['auth/flow.png', 'cookies/policy.md', 'api-key/rotation-guide.md']) {
    assert.equal(reviewed.some((candidate) => candidate.endsWith(`/evidence/${path}`)), true, path);
  }
});

test('reviewer input discovery enforces pre-read byte, file, depth, and directory-entry budgets', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));

  const oversized = fixtureProject();
  const oversizedPath = join(oversized.packetDir, 'evidence', 'oversized.bin');
  writeFileSync(oversizedPath, '');
  truncateSync(oversizedPath, 25 * 1024 * 1024 + 1);
  assert.throws(
    () => reviewHandoffInputFileBindings(oversized.projectRoot, oversized.packetDir, gates.reviewPacketFiles),
    /file limit/i
  );

  const aggregate = fixtureProject();
  for (let index = 0; index < 21; index += 1) {
    const aggregatePath = join(aggregate.packetDir, 'evidence', `aggregate-${index}.bin`);
    writeFileSync(aggregatePath, '');
    truncateSync(aggregatePath, 25 * 1024 * 1024);
  }
  assert.throws(
    () => reviewHandoffInputFileBindings(aggregate.projectRoot, aggregate.packetDir, gates.reviewPacketFiles),
    /aggregate input limit before file bytes are read/i
  );

  const tooManyFiles = fixtureProject();
  for (let index = 0; index < 2050; index += 1) {
    writeFileSync(join(tooManyFiles.packetDir, 'evidence', `empty-${index}.txt`), '');
  }
  assert.throws(
    () => reviewHandoffInputFileBindings(tooManyFiles.projectRoot, tooManyFiles.packetDir, gates.reviewPacketFiles),
    /file input limit before file bytes are read/i
  );

  const tooDeep = fixtureProject();
  let deepPath = join(tooDeep.packetDir, 'evidence');
  for (let index = 0; index < 13; index += 1) deepPath = join(deepPath, `level-${index}`);
  mkdirSync(deepPath, { recursive: true });
  writeFileSync(join(deepPath, 'proof.txt'), 'too deep\n');
  assert.throws(
    () => reviewHandoffInputFileBindings(tooDeep.projectRoot, tooDeep.packetDir, gates.reviewPacketFiles),
    /directory limit/i
  );

  const tooWide = fixtureProject();
  for (let index = 0; index < 4100; index += 1) {
    mkdirSync(join(tooWide.packetDir, 'evidence', `empty-dir-${index}`));
  }
  assert.throws(
    () => reviewHandoffInputFileBindings(tooWide.projectRoot, tooWide.packetDir, gates.reviewPacketFiles),
    /entry traversal limit/i
  );
});

test('strict reviewer projections reject unknown keys and malformed shapes without throwing', () => {
  const { packetDir, projectRoot } = fixtureProject();
  const { manifest, projections } = writeReviewHandoff({ project: projectRoot });
  const { blind, independent } = reviewerRecords(manifest, projections);
  const declaredPacketFiles = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8')).reviewPacketFiles;
  const contaminated = structuredClone(projections);
  contaminated.blind.allowedInputs.builderSummary = 'Confirm the builder says this is complete.';

  assert.match(
    reviewHandoffProjectionErrors(contaminated.blind, 'blind', manifest).join('\n'),
    /builderSummary is not allowed/
  );

  const malformed = structuredClone(projections);
  malformed.blind.allowedInputs = 'truthy-but-not-an-object';
  const errors = reviewHandoffReviewerErrors({
    manifest,
    projections: malformed,
    independentVerification: independent,
    blindReview: blind,
    packetDir,
    declaredPacketFiles
  });
  assert.match(errors.blind.join('\n'), /allowedInputs must be a JSON object/);

  let deeplyNested = null;
  for (let depth = 0; depth < 20000; depth += 1) deeplyNested = { nested: deeplyNested };
  const deepProjection = structuredClone(projections.blind);
  deepProjection.unexpectedDeepValue = deeplyNested;
  assert.doesNotThrow(() => reviewHandoffProjectionErrors(deepProjection, 'blind', manifest));
  assert.match(
    reviewHandoffProjectionErrors(deepProjection, 'blind', manifest).join('\n'),
    /validation depth limit|canonically hashed/i
  );
});

test('current live origin and state invalidate stale or wrong-target review handoffs', () => {
  const { projectRoot } = fixtureProject();
  const { manifest } = writeReviewHandoff({ project: projectRoot });
  const buildState = {
    fingerprint: stateFingerprint,
    componentFingerprints: { targetIdentity: identityFingerprint },
    targetIdentity: {
      configSyncDirectory: '../config/sync',
      frontPage: '/',
      siteUuid
    }
  };

  assert.deepEqual(reviewHandoffStateErrors({
    manifest,
    buildMode: 'source_site',
    buildState,
    targetOrigin: 'https://target.ddev.site'
  }), []);

  const stale = reviewHandoffStateErrors({
    manifest,
    buildMode: 'source_site',
    buildState: { ...buildState, fingerprint: `sha256:${'9'.repeat(64)}` },
    targetOrigin: 'https://target.ddev.site'
  });
  assert.match(stale.join('\n'), /site state fingerprint no longer matches/);

  const wrongTarget = reviewHandoffStateErrors({
    manifest,
    buildMode: 'source_site',
    buildState,
    targetOrigin: 'https://other.ddev.site'
  });
  assert.match(wrongTarget.join('\n'), /target origin no longer matches/);
});

test('review handoff CLI exposes only non-authoritative output metadata', () => {
  const { projectRoot } = fixtureProject();
  const result = spawnSync(process.execPath, [
    handoffScript,
    '--project', projectRoot,
    '--packet', 'review-packet',
    '--blind-credential-label', 'content-editor'
  ], { encoding: 'utf8' });

  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.schemaVersion, 'public-kit.review-handoff.1');
  assert.equal(output.authority.completionAuthority, false);
  assert.equal(output.authority.writesReviewerArtifacts, false);
  assert.match(output.handoffDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(output.projections.blind.digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(output.projections.independent.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(output.verdict, undefined);
  assert.equal(output.reviewerIdentity, undefined);
});
