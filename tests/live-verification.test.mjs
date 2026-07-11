import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { deflateSync } from 'node:zlib';

import { exportedSeoUrlPortabilityFindings, verifyLive } from '../bin/verify.mjs';
import { MACHINE_GATE_EVALUATORS, validatePacket } from '../bin/verify-packet.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const templatesDir = join(repoRoot, 'templates');
const testSiteUuid = '11111111-1111-4111-8111-111111111111';
const testCheckedAt = new Date().toISOString();

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
  assert.deepEqual([...new Set(gates.gates.map((gate) => gate.blocking))].sort(), ['handoff', 'launch']);
  assert.equal(gates.gates.find((gate) => gate.id === 'G-SEO-01')?.evidenceFile, 'browser-evidence.json');
});

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function mutateJson(path, mutate) {
  const value = JSON.parse(readFileSync(path, 'utf8'));
  mutate(value);
  writeJson(path, value);
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

async function withHttpServer(handler, callback) {
  const server = createServer(handler);
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
      candidateRoutesFromRenderedLinks: [],
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
    configSyncDirectory: '../config/sync',
    configSyncTracked: true,
    frontPage: '/',
    mode: 'test-injected',
    project: 'fixture',
    reason: '',
    siteUuid: testSiteUuid,
    trackedConfigDirectory: 'config/sync',
    trackedConfigYamlFiles: ['config/sync/system.site.yml', 'config/sync/system.theme.yml'],
    ...overrides
  };
}

function addQualifyingMarkdownEvidence(packetDir, sourceBaseUrl, targetBaseUrl) {
  writeFileSync(join(packetDir, 'operator-run.md'), `# Independent Operator Run Record

## Operator

- Name: Fixture Operator
- Role: Independent operator
- Environment: DDEV Drupal fixture
- Environment provisioning (manual, One Line Installer, other): One Line Installer-equivalent fixture
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
evidence_scope: "No durable intent records apply to this fixture."
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
    'drupal-readback.json',
    'field-output-matrix.json',
    'parity-report.json',
    'pattern-map.json'
  ].map((artifact) => ({
    artifact,
    claim: `${artifact} reflects the inspected target.`,
    liveSiteEvidence: 'claim-evidence.json',
    staleOrMissingEvidence: false,
    status: 'pass'
  }));
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
      section: 'intro',
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
      sourceScreenshot: `evidence/blind-adversarial-review/source-${viewport}.png`,
      targetScreenshot: `evidence/blind-adversarial-review/target-${viewport}.png`,
      visualComparison: { method: 'human_review', diffImage: '', diffScore: null, status: 'pass', acceptedExceptions: [] },
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
    'drush config:get system.site --field=uuid',
    'drush config:get system.site --field=page.front',
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
  readback.rolesAndPermissionsNotes = ['Content editor can create and edit Page content.'];
  readback.readbackComplete = true;
  readback.blockers = [];
  writeJson(readbackPath, readback);

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
  });
  mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
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
      accepted: true,
      notes: 'Anonymous contact form route.'
    });
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
  });

  const browserPath = join(packetDir, 'browser-evidence.json');
  const browser = JSON.parse(readFileSync(browserPath, 'utf8'));
  const contact = structuredClone(browser.publicRouteChecks[0]);
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
  contact.accessibilityCheck.report = 'evidence/browser/axe-contact.json';
  contact.accessibilityCheck.manualChecks.formLabelsErrorsAndFocus = 'pass';
  contact.accessibilityCheck.manualChecks.formLabelsErrorsAndFocusNotApplicableRationale = '';
  browser.publicRouteChecks.push(contact);
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

  const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
  writeJson(join(browserEvidenceDir, 'axe-contact.json'), {
    testEngine: { name: 'axe-core', version: '4.10.2' },
    toolOptions: { runOnly: null, rules: {} },
    testEnvironment: { userAgent: 'Fixture Browser/1.0', windowWidth: 1280, windowHeight: 800 },
    timestamp: testCheckedAt,
    url: `${targetBaseUrl}/contact`,
    passes: [],
    violations: [],
    incomplete: [],
    inapplicable: [{ id: 'fixture-rule', tags: ['wcag2a'], nodes: [] }]
  });
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
        cwd: repoRoot,
        environment: { DDEV_PRIMARY_URL: baseUrl }
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.liveTargetValid, true);
      assert.equal(report.routeChecks.length, 1);
      assert.equal(report.routeChecks[0].passed, true, report.routeChecks[0].errors.join('\n'));
      assert.match(report.routeChecks[0].bodySha256, /^sha256:[a-f0-9]{64}$/);
      assert.match(report.target.targetFingerprint, /^sha256:[a-f0-9]{64}$/);
      assert.equal(report.target.resolutionSource, 'ddev-environment');
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.packetVerification.completionEvidence.packetCompletionReady, false);
      assert.match(
        report.packetVerification.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /unchanged from the shipped template/
      );
      assert.match(report.completionBlockedReasons.join(' '), /Independent verification/);
    }
  );
  assert.equal(requestCount, 2, 'primary and target-required route checks should both fetch the declared target');
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

      const packetOnlyReport = await validatePacket({ packetDir });
      assert.equal(packetOnlyReport.valid, true, packetOnlyReport.errors.join('\n'));
      assert.equal(
        packetOnlyReport.completionEvidence.packetSupportsCompletion,
        true,
        JSON.stringify(packetOnlyReport.completionEvidence, null, 2)
      );
      assert.equal(packetOnlyReport.completeLocalRebuildClaimAllowed, false);
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

test('CLI discovers the DDEV Drupal runtime and requires clean status plus real Git-tracked config YAML', async () => {
  let liveBaseUrl = '';
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head>
        <title>Target site</title>
        <link rel="canonical" href="${liveBaseUrl}/">
        <meta name="description" content="Fixture homepage description.">
      </head><body><h1>Target home</h1></body></html>`);
    },
    async (baseUrl) => {
      liveBaseUrl = baseUrl;
      const targetRoot = mkdtempSync(join(tmpdir(), 'live-fake-ddev-'));
      mkdirSync(join(targetRoot, '.ddev'), { recursive: true });
      mkdirSync(join(targetRoot, 'web'), { recursive: true });
      mkdirSync(join(targetRoot, 'config', 'sync'), { recursive: true });
      writeFileSync(join(targetRoot, '.ddev', 'config.yaml'), 'name: fake-runtime\ntype: drupal11\ndocroot: web\n');
      writeFileSync(join(targetRoot, 'config', 'sync', 'system.site.yml'), `uuid: ${testSiteUuid}\n`);
      writeFileSync(join(targetRoot, 'config', 'sync', 'system.theme.yml'), 'default: fixture_theme\nadmin: claro\n');

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
const command = args.slice(1).join(' ');
const outputs = new Map([
  ['status --field=bootstrap', 'Successful'],
  ['status --field=root', 'web'],
  ['config:get system.site --field=uuid', '${testSiteUuid}'],
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
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

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
      execFileSync('git', ['add', 'config/sync/system.site.yml', 'config/sync/system.theme.yml'], { cwd: targetRoot });

      const cleanResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(cleanResult.status, 0, cleanResult.stderr);
      assert.match(cleanResult.stdout, /complete local rebuild claim authorized/);
      const cleanReport = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(cleanReport.target.resolutionSource, 'ddev-describe');
      assert.equal(cleanReport.drupalRuntime.mode, 'ddev-host');
      assert.equal(cleanReport.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(cleanReport.drupalRuntime.configStatusClean, true);
      assert.equal(cleanReport.drupalRuntime.configSyncTracked, true);
      assert.equal(cleanReport.drupalRuntime.trackedConfigYamlPresent, true);
      assert.equal(cleanReport.completeLocalRebuildClaimAllowed, true);

      const dirtyResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: { ...cleanEnvironment, FAKE_DDEV_CONFIG_DIRTY: '1' }
      });
      assert.equal(dirtyResult.status, 2, dirtyResult.stderr);
      const dirtyReport = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(dirtyReport.valid, true, dirtyReport.errors.join('\n'));
      assert.equal(dirtyReport.drupalRuntime.configStatusClean, false);
      assert.equal(dirtyReport.completeLocalRebuildClaimAllowed, false);
      assert.match(dirtyReport.completionBlockedReasons.join('\n'), /config status is not clean/i);
    }
  );
});

test('completion fails closed when structured gate evidence or applicability dispositions are missing', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'structured-gate-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

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
      mutate: (value) => { value.browserFirstRouteExpansion.candidateRoutesFromRenderedLinks = ['/legacy']; }
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
          value.browserFirstRouteExpansion.candidateRoutesFromRenderedLinks = ['/legacy'];
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

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
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
    'independent-verification.json',
    'blind-adversarial-review.json',
    'drupal-readback.json',
    'field-output-matrix.json'
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

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, true);
  assert.equal(report.completionEvidence.packetCompletionReady, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /source-audit\.json/);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /maintainer-review\.md/);
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
  const staleReport = await validatePacket({ packetDir });
  assert.equal(staleReport.valid, true, staleReport.errors.join('\n'));
  assert.equal(staleReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(staleReport.completionEvidence.packetCompletionBlockedReasons.join('\n'), /durable-intent\.yml/);
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
  assert.match(report.errors.join('\n'), /bound to its claimId, gate, target, checkedAt time, and concrete passing checks/);
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
    /external.blocker.*(?:cannot support|blocks).*completion|completion.*blocked.*external/i
  );
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
          expectedRedirect: false, accepted: true, notes: 'Query-state fixture.'
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
      assert.match(
        report.browserRepresentativeRouteChecks.find((check) => check.requestTarget.endsWith('state=drop')).errors.join('\n'),
        /expected exact representative state \/search\?state=drop/i
      );
      assert.deepEqual([...seen].sort(), ['/search?state=a', '/search?state=b', '/search?state=drop']);
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

test('default CLI exits 2 when live checks pass but completion evidence is incomplete', async () => {
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

      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stderr, /completion remains blocked/);
      const report = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(report.valid, true);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
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
