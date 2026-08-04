import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  collectionOwnershipRouteReasons,
  compositionOwnerMachinePasses,
  identityChangeDispositionReasons,
  independentCollectionOwnershipCheckShapePasses,
  navigationParityDispositionReasons,
  recordConfigIdentities,
  utilityExceptionHasRouteBoundBrowserEvidence
} from '../bin/verify-packet.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;

function evidencePacket() {
  const packetDir = mkdtempSync(join(tmpdir(), 'packet-contract-'));
  mkdirSync(join(packetDir, 'evidence'), { recursive: true });
  writeFileSync(join(packetDir, 'evidence', 'disposition.json'), '{}\n');
  return packetDir;
}

test('composition owner deviations never machine-pass', () => {
  assert.equal(compositionOwnerMachinePasses({
    declaredOwner: 'canvas_page',
    actualOwner: 'canvas_page',
    selectedOwner: 'canvas_page'
  }), true);
  assert.equal(compositionOwnerMachinePasses({
    declaredOwner: 'canvas_page',
    actualOwner: 'layout_builder',
    selectedOwner: 'canvas_page',
    deviationRecordPresent: true,
    deviationEvidence: 'evidence/disposition.json'
  }), false);
});

test('utility exceptions require browser evidence for their exact route and role', () => {
  const exception = {
    sourceRoute: '/about',
    targetRoute: '/about-us',
    routeRole: 'landing',
    browserEvidence: 'evidence/target-about.png'
  };
  const routeCheck = {
    sourceUrl: 'https://source.example/about',
    targetUrl: 'https://target.example/about-us',
    routeRole: 'landing',
    captureState: { id: 'default' },
    sourceScreenshot: 'evidence/source-about.png',
    targetScreenshot: 'evidence/target-about.png',
    visualComparison: { status: 'pass' },
    accepted: true
  };
  assert.equal(utilityExceptionHasRouteBoundBrowserEvidence(exception, {
    publicRouteChecks: [routeCheck]
  }), true);
  assert.equal(utilityExceptionHasRouteBoundBrowserEvidence(exception, {
    publicRouteChecks: [{ ...routeCheck, targetUrl: 'https://target.example/contact' }]
  }), false);
  assert.equal(utilityExceptionHasRouteBoundBrowserEvidence({
    ...exception,
    browserEvidence: 'evidence/unrelated-review.json'
  }, {
    publicRouteChecks: [routeCheck]
  }), false);
});

test('View readback identities include canonical config and direct display fields', () => {
  const identities = recordConfigIdentities({
    viewId: 'events',
    displayId: 'page_1',
    configName: 'views.view.events'
  }, 'view_row');
  assert.equal(identities.includes('views.view.events'), true);
  assert.equal(identities.includes('views.view.events:page_1'), true);
  assert.equal(recordConfigIdentities('events:page_1', 'view_row').includes('views.view.events:page_1'), true);
});

test('collection routes bind to coherent live Views and exact representative detail routes', () => {
  const ledger = {
    sourceRoute: '/events',
    sourceObject: 'Event',
    collectionOwner: 'view',
    collectionSelection: 'query_backed',
    viewDisplayOrConfig: 'views.view.events:page_1',
    detailRouteMode: 'separate_public_route',
    representativeDetailSourcePath: '/events/summer-day',
    representativeDetailTargetPath: '/events/summer-day',
    pagination: { liveViewDisplay: 'views.view.events:page_1' },
    accepted: true
  };
  const routeMatrix = {
    routes: [
      { sourcePath: '/events', targetPath: '/events', routeRole: 'listing', accepted: true },
      {
        sourcePath: '/events/summer-day',
        targetPath: '/events/summer-day',
        routeRole: 'detail',
        accepted: true
      }
    ]
  };
  const drupalReadback = {
    views: [{
      viewId: 'events',
      displayId: 'page_1',
      configName: 'views.view.events',
      path: '/events'
    }]
  };
  assert.deepEqual(collectionOwnershipRouteReasons({
    patternMap: { structuredContentModel: { collectionOwnershipLedger: [ledger] } },
    routeMatrix,
    drupalReadback
  }), []);

  const wrongPath = structuredClone(drupalReadback);
  wrongPath.views[0].path = '/news';
  assert.match(collectionOwnershipRouteReasons({
    patternMap: { structuredContentModel: { collectionOwnershipLedger: [ledger] } },
    routeMatrix,
    drupalReadback: wrongPath
  }).join('\n'), /path coherent with its exact declared target route/i);
});

test('curated entity references require evidence and cannot stand in for listing Views', () => {
  const curated = {
    sourceRoute: '/featured',
    sourceObject: 'Featured item',
    collectionOwner: 'entity_reference',
    collectionSelection: 'curated_reference',
    curationRationale: 'Editors deliberately hand-pick and order the highlighted items.',
    curationEvidence: 'evidence/source-audit/featured-selection.json',
    detailRouteMode: 'no_detail',
    pagination: {
      sourceMode: 'none',
      targetMode: 'none',
      sourceContinuationKind: 'none',
      targetContinuationKind: 'none',
      liveViewDisplay: ''
    },
    accepted: true
  };
  const landingRoutes = {
    routes: [{ sourcePath: '/featured', targetPath: '/featured', routeRole: 'landing', accepted: true }]
  };
  assert.deepEqual(collectionOwnershipRouteReasons({
    patternMap: { structuredContentModel: { collectionOwnershipLedger: [curated] } },
    routeMatrix: landingRoutes,
    drupalReadback: { views: [] }
  }), []);

  const noRationale = { ...curated, curationRationale: '' };
  assert.match(collectionOwnershipRouteReasons({
    patternMap: { structuredContentModel: { collectionOwnershipLedger: [noRationale] } },
    routeMatrix: landingRoutes,
    drupalReadback: { views: [] }
  }).join('\n'), /curationRationale/i);

  const listingRoutes = structuredClone(landingRoutes);
  listingRoutes.routes[0].routeRole = 'listing';
  assert.match(collectionOwnershipRouteReasons({
    patternMap: { structuredContentModel: { collectionOwnershipLedger: [curated] } },
    routeMatrix: listingRoutes,
    drupalReadback: { views: [] }
  }).join('\n'), /curated reference cannot satisfy a dynamic listing route/i);

  const independentCuratedCheck = {
    sourceRoute: '/featured',
    drupalOwner: 'entity_reference_curated',
    collectionSelection: 'curated_reference',
    viewOrCollectionConfig: '',
    curationRationale: curated.curationRationale,
    curationEvidence: curated.curationEvidence,
    editorAddRowEvidence: 'evidence/independent-verification/curated-editor-task.json',
    evidence: 'evidence/independent-verification/curated-ownership.json',
    status: 'pass'
  };
  assert.equal(independentCollectionOwnershipCheckShapePasses(independentCuratedCheck), true);
  assert.equal(independentCollectionOwnershipCheckShapePasses({
    ...independentCuratedCheck,
    viewOrCollectionConfig: 'views.view.fabricated:page_1'
  }), false);
});

test('identity dispositions bind exact current route values to one independent passing check', async () => {
  const packetDir = evidencePacket();
  const route = {
    sourcePath: '/program',
    targetPath: '/program',
    sourceTitle: 'Old title',
    sourceH1: 'Old heading',
    targetTitle: 'New title',
    targetH1: 'New heading',
    identityChangeDisposition: {
      applies: true,
      sourceTitle: 'Old title',
      sourceH1: 'Old heading',
      targetTitle: 'New title',
      targetH1: 'New heading',
      acceptedBy: 'Site owner',
      rationale: 'The clearer identity was approved.',
      evidence: 'evidence/disposition.json'
    }
  };
  const check = {
    sourcePath: '/program',
    targetPath: '/program',
    sourceTitle: 'Old title',
    sourceH1: 'Old heading',
    targetTitle: 'New title',
    targetH1: 'New heading',
    dispositionEvidence: 'evidence/disposition.json',
    status: 'pass'
  };
  assert.deepEqual(await identityChangeDispositionReasons(
    packetDir,
    { routes: [route] },
    { identityChangeDispositionChecks: [check] }
  ), []);

  const staleCheck = { ...check, targetH1: 'Previous heading' };
  assert.match((await identityChangeDispositionReasons(
    packetDir,
    { routes: [route] },
    { identityChangeDispositionChecks: [staleCheck] }
  )).join('\n'), /exactly one passing.*counterpart/i);

  const noDifference = structuredClone(route);
  noDifference.sourceTitle = noDifference.targetTitle;
  noDifference.sourceH1 = noDifference.targetH1;
  Object.assign(noDifference.identityChangeDisposition, {
    sourceTitle: noDifference.sourceTitle,
    sourceH1: noDifference.sourceH1
  });
  assert.match((await identityChangeDispositionReasons(
    packetDir,
    { routes: [noDifference] },
    { identityChangeDispositionChecks: [] }
  )).join('\n'), /applies=true is stale.*no source\/target difference/i);
});

test('navigation dispositions require strict acceptance and exactly one independent counterpart', async () => {
  const packetDir = evidencePacket();
  const disposition = {
    schemaVersion: 'public-kit.navigation-parity-disposition.1',
    viewport: 'desktop',
    expectedSourceTreeFingerprint: digest('a'),
    targetTreeFingerprint: digest('b'),
    differenceKinds: ['href', 'label'],
    accepted: true,
    acceptedBy: 'Site owner',
    rationale: 'The navigation labels were intentionally clarified.',
    evidence: 'evidence/disposition.json'
  };
  const check = {
    viewport: 'desktop',
    expectedSourceTreeFingerprint: digest('a'),
    targetTreeFingerprint: digest('b'),
    differenceKinds: ['href', 'label'],
    dispositionEvidence: 'evidence/disposition.json',
    status: 'pass'
  };
  assert.deepEqual(await navigationParityDispositionReasons(
    packetDir,
    { primaryNavigationParityDispositions: [disposition] },
    { primaryNavigationParityDispositionChecks: [check] }
  ), []);
  assert.match((await navigationParityDispositionReasons(
    packetDir,
    { primaryNavigationParityDispositions: [disposition] },
    { primaryNavigationParityDispositionChecks: [] }
  )).join('\n'), /exactly one passing.*counterpart/i);
  assert.match((await navigationParityDispositionReasons(
    packetDir,
    { primaryNavigationParityDispositions: [{ ...disposition, accepted: 'true' }] },
    { primaryNavigationParityDispositionChecks: [check] }
  )).join('\n'), /accepted=true/i);
});
