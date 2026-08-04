import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import {
  collectionPaginationLiveResponseChecks,
  collectionPaginationReconciliationErrors,
  collectionPaginationTargetRoutePlan,
  DRUPAL_LIVE_SURFACE_EVAL,
  effectiveViewPager,
  inspectSourceSurface,
  scheduleLiveRouteChecks
} from '../bin/verify.mjs';
import {
  collectionPaginationRecordReasons,
  collectionRecordMatchesLedger
} from '../bin/verify-packet.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;

async function withHttpServer(handler, callback) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  try {
    return await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

function acceptedLedger(overrides = {}) {
  return {
    sourceRoute: '/events',
    sourceObject: 'Event',
    accepted: true,
    pagination: {
      sourceMode: 'paged',
      sourcePageSize: 12,
      sourceContinuationKind: 'request',
      sourceContinuationRequest: '/events?page=1',
      sourceContinuationStateId: '',
      targetMode: 'paged',
      targetPageSize: 8,
      liveViewDisplay: 'views.view.events:page_1',
      targetContinuationKind: 'request',
      targetContinuationRequest: '/events?page=1',
      targetContinuationStateId: '',
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
    sourceInitialRequest: '/events',
    sourceContinuationRequest: '/events?page=1',
    sourceContinuationStateId: '',
    initialTargetRequest: '/events',
    targetContinuationRequest: '/events?page=1',
    targetContinuationStateId: '',
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
    sourceUrl: 'https://source.example/events?page=1',
    sourceFinalUrl: 'https://source.example/events?page=1',
    targetUrl: 'https://target.example/events?page=1',
    targetFinalUrl: 'https://target.example/events?page=1',
    sourceScreenshot: 'evidence/browser/source-events-page-2.png',
    targetScreenshot: 'evidence/browser/events-page-2.png',
    captureState: {
      id: 'default',
      interactionSteps: [],
      evidenceBindings: {
        sourceScreenshotSha256: digest('c'),
        targetScreenshotSha256: digest('d')
      }
    },
    visualComparison: { status: 'pass' },
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
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /listAll\('core\.entity_view_display\.'\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\(\$display_config\['status'\] \?\? FALSE\) !== TRUE/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\$layout_display_count > \$surface_limit/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\$component\['configuration'\]\['id'\]/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /str_starts_with\(\$plugin, 'views_block:'\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /hasField\('layout_builder__layout'\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /getFieldDefinitions\(\$entity_type_id, \$bundle\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /->exists\('layout_builder__layout'\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /->accessCheck\(TRUE\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /access\('view', \$anonymous_user, TRUE\)->isAllowed\(\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\$layout_field->getSections\(\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\$component->getPluginId\(\)/);
  assert.match(DRUPAL_LIVE_SURFACE_EVAL, /\$layout_override_entity_count/);
  assert.doesNotMatch(DRUPAL_LIVE_SURFACE_EVAL, /->toArray\(\)/);
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
  assert.match(repeatedState.join('\n'), /item-distinct continuation state/i);

  const uncapturedState = collectionPaginationRecordReasons(
    acceptedLedger(),
    passingBrowserCheck(),
    '/events',
    []
  );
  assert.match(uncapturedState.join('\n'), /source screenshot evidence.*exact declared source continuation/i);
  assert.match(uncapturedState.join('\n'), /target screenshot evidence.*exact declared target continuation/i);

  const laundering = collectionPaginationRecordReasons(
    acceptedLedger({ targetMode: 'none', targetPageSize: null, targetContinuationRequest: '' }),
    null,
    '/events',
    []
  );
  assert.match(laundering.join('\n'), /cannot launder source pagination mode paged into target mode none/i);
});

test('continuation mode changes require one narrow exact accessible replacement disposition', () => {
  const replacement = acceptedLedger({
    sourceMode: 'infinite_scroll',
    targetMode: 'paged',
    modeChangeDisposition: {
      kind: 'accessible_continuation_replacement',
      sourceMode: 'infinite_scroll',
      targetMode: 'paged',
      acceptedBy: 'Site owner',
      rationale: 'Explicit pagination preserves continuation while exposing stable keyboard controls.',
      evidence: 'evidence/browser/pagination-accessibility.json',
      accepted: true
    }
  });
  assert.deepEqual(
    collectionPaginationRecordReasons(replacement, passingBrowserCheck(), '/events', [capturedContinuationRoute()]),
    []
  );

  const unbound = structuredClone(replacement);
  unbound.pagination.modeChangeDisposition.targetMode = 'load_more';
  assert.match(
    collectionPaginationRecordReasons(unbound, passingBrowserCheck(), '/events', [capturedContinuationRoute()]).join('\n'),
    /exact named-acceptance.*accessible_continuation_replacement/i
  );

  const unnamed = structuredClone(replacement);
  unnamed.pagination.modeChangeDisposition.acceptedBy = '';
  assert.match(
    collectionPaginationRecordReasons(unnamed, passingBrowserCheck(), '/events', [capturedContinuationRoute()]).join('\n'),
    /exact named-acceptance.*accessible_continuation_replacement/i
  );

  const fabricated = acceptedLedger({
    sourceMode: 'none',
    sourcePageSize: null,
    sourceContinuationKind: 'none',
    sourceContinuationRequest: '',
    targetMode: 'paged'
  });
  assert.match(
    collectionPaginationRecordReasons(fabricated, passingBrowserCheck(), '/events', [capturedContinuationRoute()]).join('\n'),
    /target continuation cannot be fabricated/i
  );
});

test('continuing sources require a positive observed batch size and none declarations are exact', () => {
  assert.match(
    collectionPaginationRecordReasons(
      acceptedLedger({ sourcePageSize: null }),
      passingBrowserCheck(),
      '/events',
      [capturedContinuationRoute()]
    ).join('\n'),
    /valid observable page sizes/i
  );

  const inexactNone = acceptedLedger({
    sourceMode: 'none',
    sourcePageSize: 1,
    sourceContinuationKind: 'none',
    sourceContinuationRequest: '',
    targetMode: 'none',
    targetPageSize: null,
    targetContinuationKind: 'none',
    targetContinuationRequest: '',
    sourceContinuationEquivalent: false
  });
  assert.match(
    collectionPaginationRecordReasons(inexactNone, null, '/events', []).join('\n'),
    /valid observable page sizes/i
  );
});

test('JS-only source continuation must bind an interaction-bearing capture state', () => {
  const ledger = acceptedLedger({
    sourceContinuationKind: 'browser_interaction',
    sourceContinuationRequest: '',
    sourceContinuationStateId: 'source-load-more'
  });
  const browserCheck = passingBrowserCheck({
    sourceContinuationRequest: '',
    sourceContinuationStateId: 'source-load-more'
  });
  const inertSourceState = capturedContinuationRoute({
    sourceUrl: 'https://source.example/events',
    sourceFinalUrl: 'https://source.example/events',
    targetUrl: 'https://target.example/events',
    targetFinalUrl: 'https://target.example/events',
    captureState: {
      id: 'source-load-more',
      interactionSteps: [],
      evidenceBindings: {
        sourceScreenshotSha256: digest('e'),
        targetScreenshotSha256: digest('f')
      }
    }
  });
  const reasons = collectionPaginationRecordReasons(
    ledger,
    browserCheck,
    '/events',
    [inertSourceState, capturedContinuationRoute()]
  );
  assert.match(reasons.join('\n'), /source screenshot evidence.*JS-only state/i);

  inertSourceState.captureState.interactionSteps = [{
    action: 'click',
    target: '.load-more',
    value: '',
    expectedState: 'Additional items are visible.'
  }];
  assert.deepEqual(
    collectionPaginationRecordReasons(
      ledger,
      browserCheck,
      '/events',
      [inertSourceState, capturedContinuationRoute()]
    ),
    []
  );
});

test('target request continuation must be verifier-owned and semantically distinct', () => {
  const routeMatrix = {
    routes: [{ sourcePath: '/events', targetPath: '/events' }]
  };
  const liveResponse = (requestTarget, character, semanticCharacter = character, finalUrl = requestTarget) => ({
    requestTarget,
    finalRequest: finalUrl,
    finalUrl: `https://target.example${finalUrl}`,
    finalStatus: 200,
    passed: true,
    bodySha256: digest(character),
    intrinsicSemantics: {
      visibleTextSha256: digest(semanticCharacter),
      mediaTargetsSha256: digest('f')
    }
  });
  const distinct = collectionPaginationLiveResponseChecks(
    { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } },
    routeMatrix,
    [liveResponse('/events', 'a'), liveResponse('/events?page=1', 'b')]
  );
  assert.deepEqual(distinct.errors, []);
  assert.equal(distinct.checks[0].authority, 'verifier-owned-target-http');
  assert.equal(distinct.checks[0].semanticallyDistinct, true);

  const cosmeticOnly = collectionPaginationLiveResponseChecks(
    { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } },
    routeMatrix,
    [liveResponse('/events', 'a'), liveResponse('/events?page=1', 'b', 'a')]
  );
  assert.match(cosmeticOnly.errors.join('\n'), /distinct visible-text or media semantics/i);

  const redirectedBack = collectionPaginationLiveResponseChecks(
    { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } },
    routeMatrix,
    [liveResponse('/events', 'a'), liveResponse('/events?page=1', 'b', 'b', '/events')]
  );
  assert.match(redirectedBack.errors.join('\n'), /resolve to distinct final requests/i);
  assert.match(redirectedBack.errors.join('\n'), /exact declared continuation binding/i);

  const omitted = collectionPaginationLiveResponseChecks(
    { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } },
    routeMatrix,
    []
  );
  assert.match(omitted.errors.join('\n'), /successful verifier-owned live responses/i);

  const privateContinuation = collectionPaginationLiveResponseChecks(
    { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } },
    routeMatrix,
    [
      liveResponse('/events', 'a'),
      liveResponse('/events?page=1', 'b', 'b', '/events?page=1')
    ].map((check, index) => index === 1 ? { ...check, finalStatus: 403, passed: true } : check)
  );
  assert.match(privateContinuation.errors.join('\n'), /successful verifier-owned live responses/i);

  const jsOnlyLedger = acceptedLedger({
    targetContinuationKind: 'browser_interaction',
    targetContinuationRequest: '',
    targetContinuationStateId: 'load-more'
  });
  const jsOnly = collectionPaginationLiveResponseChecks(
    { structuredContentModel: { collectionOwnershipLedger: [jsOnlyLedger] } },
    routeMatrix,
    []
  );
  assert.deepEqual(jsOnly.errors, []);
  assert.equal(jsOnly.checks[0].authority, 'self_attested_capture_evidence');
  assert.equal(jsOnly.checks[0].status, 'packet_authored_js_only');
});

test('a valid non-primary collection schedules both exact target states in the shared bounded route plan', () => {
  const patternMap = { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } };
  const routeMatrix = {
    primaryRoutes: [{ sourcePath: '/', targetPath: '/' }],
    routes: [
      { sourcePath: '/', targetPath: '/', accepted: true },
      { sourcePath: '/events', targetPath: '/events', targetStatus: 200, accepted: true }
    ]
  };
  assert.deepEqual(
    collectionPaginationTargetRoutePlan(patternMap, routeMatrix, ['/']),
    {
      contractCount: 1,
      errors: [],
      requests: ['/events', '/events?page=1'],
      withinLimit: true
    }
  );
  assert.deepEqual(
    collectionPaginationTargetRoutePlan(patternMap, routeMatrix, ['/', '/events?page=1']).requests,
    ['/events']
  );

  const ambiguousRouteMatrix = structuredClone(routeMatrix);
  ambiguousRouteMatrix.routes.push({
    sourcePath: '/events',
    targetPath: '/alternate-events',
    targetStatus: 200,
    accepted: true
  });
  const ambiguousPlan = collectionPaginationTargetRoutePlan(patternMap, ambiguousRouteMatrix, ['/']);
  assert.deepEqual(ambiguousPlan.requests, []);
  assert.match(ambiguousPlan.errors.join('\n'), /must map to exactly one target request.*found 2/i);

  const ambiguousChecks = collectionPaginationLiveResponseChecks(
    patternMap,
    ambiguousRouteMatrix,
    []
  );
  assert.deepEqual(ambiguousChecks.checks, []);
  assert.match(ambiguousChecks.errors.join('\n'), /must map to exactly one target request.*found 2/i);
});

test('collection packet records bind to exact same-path query variants', () => {
  const firstLedger = {
    sourceRoute: '/catalog?segment=first',
    sourceObject: 'Listing',
    accepted: true
  };
  const secondLedger = {
    sourceRoute: '/catalog?segment=second',
    sourceObject: 'Listing',
    accepted: true
  };
  const ledgers = [firstLedger, secondLedger];
  const routeMatrix = {
    routes: [
      {
        sourcePath: '/catalog?segment=first',
        targetPath: '/offers?segment=first'
      },
      {
        sourcePath: '/catalog?segment=second',
        targetPath: '/offers?segment=second'
      }
    ]
  };
  const firstRecord = {
    sourceRoute: 'https://source.example/catalog?segment=first',
    targetRoute: 'https://target.example/offers?segment=first',
    sourceObject: 'Listing'
  };
  const secondRecord = {
    sourceRoute: 'https://source.example/catalog?segment=second',
    targetRoute: 'https://target.example/offers?segment=second',
    sourceObject: 'Listing'
  };

  assert.equal(collectionRecordMatchesLedger(firstRecord, firstLedger, routeMatrix, ledgers), true);
  assert.equal(collectionRecordMatchesLedger(firstRecord, secondLedger, routeMatrix, ledgers), false);
  assert.equal(collectionRecordMatchesLedger(secondRecord, firstLedger, routeMatrix, ledgers), false);
  assert.equal(collectionRecordMatchesLedger(secondRecord, secondLedger, routeMatrix, ledgers), true);

  const ambiguousRouteMatrix = structuredClone(routeMatrix);
  ambiguousRouteMatrix.routes.push({
    sourcePath: '/catalog?segment=first',
    targetPath: '/alternate-offers?segment=first'
  });
  assert.equal(
    collectionRecordMatchesLedger(firstRecord, firstLedger, ambiguousRouteMatrix, ledgers),
    false,
    'An ambiguous exact source request must not bind to the first route-matrix target by order.'
  );
});

test('query-bound collection failures redact private request values', () => {
  const ledger = acceptedLedger();
  ledger.sourceObject = '';
  ledger.sourceRoute = '/events?private-state=owner-only';
  ledger.pagination.sourceContinuationRequest = '/events?private-state=owner-only&page=2';

  const reasons = collectionPaginationRecordReasons(
    ledger,
    null,
    '/events?private-state=owner-only',
    []
  ).join('\n');

  assert.match(reasons, /\/events\?query-sha256=[a-f0-9]{64}/);
  assert.doesNotMatch(reasons, /owner-only|private-state/);
});

test('target continuation keeps an exact private final-request binding after public query redaction', async () => {
  await withHttpServer((request, response) => {
    const continuation = request.url === '/events?page=1';
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<html><title>Events</title><h1>Events</h1><article>${continuation ? 'Second batch' : 'First batch'}</article></html>`);
  }, async (baseUrl) => {
    const task = (requestTarget) => ({
      bucket: 'browser-representative',
      expected: {
        accepted: true,
        expectedBehavior: 'public_200',
        expectedFinalPath: '/events',
        expectedFinalRequest: requestTarget,
        expectedH1: 'Events',
        expectedStatus: 200,
        expectedTitle: 'Events',
        identityRequired: true,
        matchesBrowserRenderedSource: true,
        renderedSeo: null,
        requestTarget,
        routeKind: 'browser-representative',
        statusUsesInitialResponse: false,
        targetPath: '/events'
      }
    });
    const scheduled = await scheduleLiveRouteChecks({
      baseUrl: new URL(baseUrl),
      concurrency: 2,
      deadlineMs: 2_000,
      maxRequests: 10,
      maxRoutes: 10,
      tasks: [task('/events'), task('/events?page=1')]
    });
    assert.deepEqual(scheduled.errors, []);
    const liveChecks = scheduled.checks.map(({ check }) => check);
    assert.equal(liveChecks.every((check) => check.passed), true);
    assert.doesNotMatch(liveChecks[1].finalUrl, /page=1/);

    const result = collectionPaginationLiveResponseChecks(
      { structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] } },
      { routes: [{ sourcePath: '/events', targetPath: '/events' }] },
      liveChecks
    );
    assert.deepEqual(result.errors, []);
    assert.equal(result.checks[0].passed, true);
    assert.doesNotMatch(result.checks[0].continuationFinalRequest, /page=1/);
  });
});

test('source request continuation is fetched live, exact-final-bound, and semantically distinct', async () => {
  let distinctContinuation = true;
  let redirectContinuation = false;
  const baseUrl = 'https://source.example';
  const liveHttpContext = {
    errors: [],
    async request(url) {
      const request = `${url.pathname}${url.search}`;
      if (request === '/events?page=1' && redirectContinuation) {
        return {
          body: 'Redirecting',
          headers: { location: '/events', 'content-type': 'text/html; charset=utf-8' },
          localTlsVerificationBypassed: false,
          status: 302
        };
      }
      const body = request === '/events?page=1'
        ? `<html><body><h1>Events</h1><article>${distinctContinuation ? 'Second batch' : 'First batch'}</article></body></html>`
        : request === '/events'
          ? '<html><body><h1>Events</h1><article>First batch</article></body></html>'
          : request === '/'
            ? '<html><body><h1>Home</h1></body></html>'
            : 'Not found';
      return {
        body,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        localTlsVerificationBypassed: false,
        status: ['/robots.txt', '/sitemap.xml'].includes(request) ? 404 : 200
      };
    },
    async runTask(_kind, task) {
      return task();
    },
    async runTasks(_kind, values, mapper) {
      return Promise.all(values.map(mapper));
    },
    metrics() {
      return {
        attempted: true,
        deadlineAt: new Date(Date.now() + 5_000).toISOString(),
        deadlineExceeded: false,
        deadlineMs: 5_000,
        elapsedMs: 1,
        maxConcurrency: 2,
        maxRequests: 40,
        maxTasks: 40,
        peakConcurrency: 1,
        requestCapExhausted: false,
        requestCount: 8,
        taskCapExhausted: false,
        taskCount: 8,
        taskRejectedCount: 0,
        completedTaskCount: 8,
        tasksByKind: {}
      };
    }
  };
  const routeMatrix = {
    sourceBaseUrl: baseUrl,
    primaryRoutes: [
      { sourcePath: '/', targetPath: '/' },
      { sourcePath: '/events', targetPath: '/events' }
    ],
    routes: [
      { sourcePath: '/', targetPath: '/', accepted: true },
      { sourcePath: '/events', targetPath: '/events', accepted: true }
    ]
  };
  const patternMap = {
    structuredContentModel: { collectionOwnershipLedger: [acceptedLedger()] }
  };
  const limits = {
    concurrency: 2,
    deadlineMs: 5_000,
    maxBodyBytes: 1024 * 1024,
    maxRequests: 40,
    maxRoutes: 10,
    maxSitemapLocs: 20,
    maxSitemaps: 2,
    maxTasks: 40
  };

  const distinct = await inspectSourceSurface({ limits, liveHttpContext, patternMap, routeMatrix });
  assert.equal(distinct.collectionPaginationChecks[0].authority, 'verifier-owned-source-http');
  assert.equal(distinct.collectionPaginationChecks[0].passed, true);

  distinctContinuation = false;
  const repeated = await inspectSourceSurface({ limits, liveHttpContext, patternMap, routeMatrix });
  assert.equal(repeated.status, 'blocked');
  assert.match(repeated.errors.join('\n'), /exact continuation request.*distinct visible-text or media semantics/i);

  distinctContinuation = true;
  redirectContinuation = true;
  const redirectedBack = await inspectSourceSurface({ limits, liveHttpContext, patternMap, routeMatrix });
  assert.match(redirectedBack.errors.join('\n'), /resolve to distinct final requests/i);
  assert.match(redirectedBack.errors.join('\n'), /exact declared continuation binding/i);
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
    sourceContinuationKind: 'none',
    sourceContinuationRequest: '',
    sourceContinuationStateId: '',
    targetMode: 'none',
    targetPageSize: null,
    targetContinuationKind: 'none',
    targetContinuationRequest: '',
    targetContinuationStateId: '',
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
