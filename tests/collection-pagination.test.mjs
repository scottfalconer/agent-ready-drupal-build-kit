import assert from 'node:assert/strict';
import test from 'node:test';

import {
  collectionPaginationReconciliationErrors,
  DRUPAL_LIVE_SURFACE_EVAL,
  effectiveViewPager
} from '../bin/verify.mjs';
import { collectionPaginationRecordReasons } from '../bin/verify-packet.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;

function acceptedLedger(overrides = {}) {
  return {
    sourceRoute: '/events',
    sourceObject: 'Event',
    accepted: true,
    pagination: {
      sourceMode: 'paged',
      sourcePageSize: 12,
      targetMode: 'paged',
      targetPageSize: 8,
      liveViewDisplay: 'views.view.events:page_1',
      targetContinuationRequest: '/events?page=1',
      sourceContinuationEquivalent: true,
      evidence: 'evidence/browser/events-pagination.json',
      accepted: true,
      ...overrides
    }
  };
}

function passingBrowserCheck(overrides = {}) {
  return {
    sourceRoute: '/events',
    targetRoute: '/events',
    sourceObject: 'Event',
    initialTargetRequest: '/events',
    targetContinuationRequest: '/events?page=1',
    initialStatus: 200,
    continuationStatus: 200,
    initialItemIdentitySha256: digest('a'),
    continuationItemIdentitySha256: digest('b'),
    continuationStateDistinct: true,
    sourceContinuationEquivalent: true,
    status: 'pass',
    evidence: 'events-pagination.json',
    ...overrides
  };
}

function capturedContinuationRoute(overrides = {}) {
  return {
    targetUrl: 'https://target.example/events?page=1',
    targetFinalUrl: 'https://target.example/events?page=1',
    targetScreenshot: 'evidence/browser/events-page-2.png',
    captureState: {
      id: 'default',
      evidenceBindings: { targetScreenshotSha256: digest('c') }
    },
    accepted: true,
    ...overrides
  };
}

function liveInventory(pager) {
  return {
    confirmed: true,
    items: [{
      key: 'view_display:events:page_1',
      kind: 'view_display',
      publicSurface: true,
      pager
    }]
  };
}

test('effective View pager readback resolves inherited and overridden display options', () => {
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'inheritedFromDefault' => \$pager_inherited/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'itemsPerPage' => \$pager_items_per_page/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'offset' => \$pager_offset/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /'type' => \$pager_type/);
  const view = {
    display: {
      default: {
        display_options: {
          pager: { type: 'full', options: { items_per_page: 10, offset: 0 } }
        }
      },
      inherited_page: { display_options: { path: 'events' } },
      overridden_page: {
        display_options: {
          defaults: { pager: false },
          pager: { type: 'mini', options: { items_per_page: 6, offset: 2 } }
        }
      }
    }
  };

  assert.deepEqual(effectiveViewPager(view, 'inherited_page'), {
    inheritedFromDefault: true,
    itemsPerPage: 10,
    offset: 0,
    type: 'full'
  });
  assert.deepEqual(effectiveViewPager(view, 'overridden_page'), {
    inheritedFromDefault: false,
    itemsPerPage: 6,
    offset: 2,
    type: 'mini'
  });
});

test('collection pagination accepts unequal source and target page sizes with a distinct page-two state', () => {
  assert.deepEqual(
    collectionPaginationRecordReasons(
      acceptedLedger(),
      passingBrowserCheck(),
      '/events',
      [capturedContinuationRoute()]
    ),
    []
  );

  const repeatedState = collectionPaginationRecordReasons(
    acceptedLedger(),
    passingBrowserCheck({ continuationItemIdentitySha256: digest('a') }),
    '/events',
    [capturedContinuationRoute()]
  );
  assert.match(repeatedState.join('\n'), /item-distinct page-two state/i);

  const uncapturedState = collectionPaginationRecordReasons(
    acceptedLedger(),
    passingBrowserCheck(),
    '/events',
    []
  );
  assert.match(uncapturedState.join('\n'), /captured publicRouteChecks row.*exact page-two request/i);

  const laundering = collectionPaginationRecordReasons(
    acceptedLedger({ targetMode: 'none', targetPageSize: null, targetContinuationRequest: '' }),
    null,
    '/events',
    []
  );
  assert.match(laundering.join('\n'), /cannot launder source pagination mode paged into target mode none/i);
});

test('live collection pagination rejects fixed limits and offsets and accepts a real pager', () => {
  const patternMap = {
    structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] }
  };
  assert.deepEqual(
    collectionPaginationReconciliationErrors(patternMap, liveInventory({
      inheritedFromDefault: true,
      itemsPerPage: 8,
      offset: 0,
      type: 'full'
    })),
    []
  );

  const fixedLimit = collectionPaginationReconciliationErrors(patternMap, liveInventory({
    inheritedFromDefault: false,
    itemsPerPage: 24,
    offset: 24,
    type: 'some'
  }));
  assert.match(fixedLimit.join('\n'), /fixed offset 24/i);
  assert.match(fixedLimit.join('\n'), /fixed-limit pager type some/i);

  const abstractModeMismatch = collectionPaginationReconciliationErrors(
    { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger({ sourceMode: 'load_more', targetMode: 'load_more' })] } },
    liveInventory({ inheritedFromDefault: true, itemsPerPage: 8, offset: 0, type: 'full' })
  );
  assert.match(abstractModeMismatch.join('\n'), /live View pager type full resolves to paged/i);
});

test('genuine single-page collections require explicit none backed by a live no-pager display', () => {
  const ledger = acceptedLedger({
    sourceMode: 'none',
    sourcePageSize: null,
    targetMode: 'none',
    targetPageSize: null,
    targetContinuationRequest: '',
    sourceContinuationEquivalent: false
  });
  assert.deepEqual(collectionPaginationRecordReasons(ledger, null, '/events', []), []);
  assert.deepEqual(
    collectionPaginationReconciliationErrors(
      { structuredContentModel: { collectionOwnershipLedger: [ledger] } },
      liveInventory({ inheritedFromDefault: true, itemsPerPage: 0, offset: 0, type: 'none' })
    ),
    []
  );

  const documentedException = {
    ...ledger,
    collectionOwner: 'documented_exception',
    exceptionRationale: 'The source contains one fixed, non-repeating item.',
    pagination: { ...ledger.pagination, liveViewDisplay: '' }
  };
  assert.deepEqual(collectionPaginationRecordReasons(documentedException, null, '/events', []), []);
  assert.deepEqual(
    collectionPaginationReconciliationErrors(
      { structuredContentModel: { collectionOwnershipLedger: [documentedException] } },
      { confirmed: true, items: [] }
    ),
    []
  );
});
