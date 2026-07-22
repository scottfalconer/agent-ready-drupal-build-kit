import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  ddevProjectWebUrls,
  exportedSeoUrlPortabilityFindings,
  isLocalEnvironmentHost,
  liveTargetBudgetCompletionBlocker,
  liveTargetLimitsForRouteCount,
  localOnlyFormExceptionsBoundToRuntime,
  scheduleLiveRouteChecks
} from '../bin/verify.mjs';

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

function routeTask(bucket, targetPath) {
  return {
    bucket,
    expected: {
      accepted: true,
      expectedBehavior: 'public_200',
      expectedFinalPath: targetPath,
      expectedH1: 'Fixture',
      expectedStatus: 200,
      expectedTitle: '',
      identityRequired: true,
      matchesBrowserRenderedSource: true,
      renderedSeo: null,
      routeKind: bucket === 'primary' ? 'primary' : bucket,
      statusUsesInitialResponse: false,
      targetPath
    }
  };
}

test('local environment classifier covers supported development-only hosts', () => {
  for (const host of [
    'localhost',
    'app.localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    'host.docker.internal',
    'project.ddev.site',
    'project.test'
  ]) {
    assert.equal(isLocalEnvironmentHost(host), true, host);
  }
  for (const host of ['example.com', 'test.example.com', 'contest.example']) {
    assert.equal(isLocalEnvironmentHost(host), false, host);
  }
});

test('SEO portability scans effective YAML scalar values without treating comments or a public target origin as defects', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'seo-scalar-values-'));
  const configDirectory = join(projectRoot, 'config', 'sync');
  mkdirSync(configDirectory, { recursive: true });
  const file = 'config/sync/metatag.metatag_defaults.front.yml';
  writeFileSync(join(projectRoot, file), `# old canonical: https://comment-only.ddev.site/
tags:
  canonical_url: 'https://www.example.com/' # https://inline-comment.test/
  og_image: 'https://host.docker.internal/media/hero.jpg'
  twitter_image: http://0.0.0.0:8080/media/card.jpg
  alternate: >
    https://preview.example.test/page
  external_media: 'https://cdn.example.com/hero.jpg'
`);

  const findings = exportedSeoUrlPortabilityFindings(
    projectRoot,
    [file],
    'https://www.example.com'
  );
  assert.deepEqual(
    findings.map(({ host, key }) => ({ host, key })),
    [
      { host: 'host.docker.internal', key: 'og_image' },
      { host: '0.0.0.0:8080', key: 'twitter_image' },
      { host: 'preview.example.test', key: 'alternate' }
    ]
  );

  const authoritativeCustomDdevFindings = exportedSeoUrlPortabilityFindings(
    projectRoot,
    [file],
    'https://www.example.com',
    true,
    ['https://www.example.com', 'https://alternate.example.com']
  );
  assert.equal(
    authoritativeCustomDdevFindings.some((finding) => finding.host === 'www.example.com'),
    true
  );
});

test('DDEV 1.25 custom web origins include singular URL fields, exclude service URLs, and bind local-only form exceptions', () => {
  const description = {
    raw: {
      primary_url: 'https://project.ddev.site',
      urls: ['https://project.ddev.site', 'https://preview.example.com'],
      httpURLs: ['http://project.ddev.site'],
      httpsURLs: null,
      httpurl: 'http://project.ddev.site',
      httpsurl: 'https://project.ddev.site:8443'
    },
    services: {
      mailpit: {
        primary_url: 'https://project.ddev.site:8026',
        urls: ['https://project.ddev.site:8026']
      }
    }
  };
  const origins = ddevProjectWebUrls(description);
  assert.deepEqual(origins.sort(), [
    'http://project.ddev.site',
    'https://preview.example.com',
    'https://project.ddev.site',
    'https://project.ddev.site:8443'
  ]);
  const browserEvidence = {
    anonymousFormChecks: [{
      targetUrl: 'https://preview.example.com/contact',
      abuseProtection: { mode: 'local_only_exception' }
    }]
  };
  assert.equal(
    localOnlyFormExceptionsBoundToRuntime(browserEvidence, 'https://preview.example.com', origins),
    true
  );
  assert.equal(
    localOnlyFormExceptionsBoundToRuntime(browserEvidence, 'https://public.example.org', origins),
    false
  );
  assert.equal(
    localOnlyFormExceptionsBoundToRuntime(browserEvidence, 'https://project.ddev.site:8026', origins),
    false
  );
});

test('one scheduler caps concurrency across every live route class', async () => {
  let active = 0;
  let maximumActive = 0;
  await withHttpServer((request, response) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    setTimeout(() => {
      active -= 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Fixture</title><h1>Fixture</h1>');
    }, 25);
  }, async (baseUrl) => {
    const result = await scheduleLiveRouteChecks({
      baseUrl: new URL(baseUrl),
      concurrency: 2,
      deadlineMs: 1_000,
      maxRequests: 10,
      maxRoutes: 10,
      tasks: [
        routeTask('primary', '/primary'),
        routeTask('target-required', '/required'),
        routeTask('browser-representative', '/representative')
      ]
    });
    assert.deepEqual(result.errors, []);
    assert.equal(result.checks.length, 3);
    assert.equal(result.checks.every(({ check }) => check.passed), true);
    assert.ok(maximumActive > 1, `expected concurrent requests, observed ${maximumActive}`);
    assert.ok(maximumActive <= 2, `expected at most 2 concurrent requests, observed ${maximumActive}`);
  });
});

test('scheduler fails closed before fetching when its route limit is exceeded', async () => {
  const result = await scheduleLiveRouteChecks({
    baseUrl: new URL('http://127.0.0.1:1'),
    maxRoutes: 2,
    tasks: [routeTask('primary', '/a'), routeTask('target-required', '/b'), routeTask('browser-representative', '/c')]
  });
  assert.equal(result.budget.attempted, false);
  assert.equal(result.budget.requestCount, 0);
  assert.equal(result.checks.length, 0);
  assert.match(result.errors.join('\n'), /3 checks, exceeding the 2 route limit; no routes were fetched/i);
});

test('scheduler deadline destroys in-flight requests and returns failed checks promptly', async () => {
  await withHttpServer((_request, response) => {
    setTimeout(() => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Fixture</title><h1>Fixture</h1>');
    }, 250);
  }, async (baseUrl) => {
    const startedAt = Date.now();
    const result = await scheduleLiveRouteChecks({
      baseUrl: new URL(baseUrl),
      concurrency: 1,
      deadlineMs: 30,
      maxRequests: 10,
      maxRoutes: 10,
      tasks: [routeTask('primary', '/slow'), routeTask('target-required', '/queued')]
    });
    assert.ok(Date.now() - startedAt < 500, 'deadline should not wait for the slow response');
    assert.equal(result.checks.length, 2);
    assert.equal(result.checks.every(({ check }) => !check.passed), true);
    assert.match(
      result.checks.flatMap(({ check }) => check.errors).join('\n'),
      /exceeded its total wall-clock deadline/i
    );
  });
});

test('scheduler enforces one HTTP request budget across redirects and route classes', async () => {
  let requests = 0;
  await withHttpServer((_request, response) => {
    requests += 1;
    response.writeHead(302, { location: '/final' });
    response.end();
  }, async (baseUrl) => {
    const result = await scheduleLiveRouteChecks({
      baseUrl: new URL(baseUrl),
      concurrency: 2,
      deadlineMs: 1_000,
      maxRequests: 1,
      maxRoutes: 10,
      tasks: [routeTask('primary', '/redirect'), routeTask('target-required', '/another')]
    });
    assert.equal(result.budget.requestCount, 1);
    assert.equal(requests, 1);
    assert.equal(result.checks.every(({ check }) => !check.passed), true);
    assert.match(
      result.checks.flatMap(({ check }) => check.errors).join('\n'),
      /exhausted its 1 HTTP request budget/i
    );
  });
});

test('live target limits default to the exact bounded constants', () => {
  assert.deepEqual(liveTargetLimitsForRouteCount(), {
    concurrency: 12,
    deadlineMs: 90_000,
    maxRequests: 2_000,
    maxRoutes: 1_000,
    maxTasks: 20_000
  });
});

test('live target limits scale coupled budgets with the authorized route ceiling', () => {
  const limits = liveTargetLimitsForRouteCount(4_096);
  assert.equal(limits.maxRoutes, 4_096);
  assert.equal(limits.maxRequests, 10_000);
  assert.equal(limits.maxTasks, 100_000);
  assert.equal(limits.deadlineMs, 450_000);
  assert.equal(limits.concurrency, 12, 'concurrency stays fixed for politeness');
});

test('live target limits reject counts outside the supported range', () => {
  assert.throws(() => liveTargetLimitsForRouteCount(999), /from 1000 through 8192/);
  assert.throws(() => liveTargetLimitsForRouteCount(8_193), /from 1000 through 8192/);
  assert.throws(() => liveTargetLimitsForRouteCount(1.5), /from 1000 through 8192/);
});

test('live target budget blocker recommends a sufficient one-run route ceiling', () => {
  const blocker = liveTargetBudgetCompletionBlocker(
    { requestCount: 2_000, maxRequests: 2_000 },
    { routeCount: 3_132 },
    1_000,
    499
  );
  assert.match(blocker.missingInput, /3132-route ceiling/);
  assert.match(blocker.nextAction, /--target-max-routes 3132\b/);
});

test('live target budget blocker does not recommend a known-insufficient supported ceiling', () => {
  const blocker = liveTargetBudgetCompletionBlocker(
    { requestCount: 0, maxRequests: 2_000 },
    { routeCount: 8_193 },
    1_000
  );
  assert.doesNotMatch(blocker.nextAction, /--target-max-routes/);
  assert.match(blocker.nextAction, /build-kit maintainer/);
});

test('scheduler route ceiling honors an authorized larger maxRoutes without fetching on overflow', async () => {
  const tasks = Array.from({ length: 1_500 }, (_value, index) => routeTask('primary', `/route-${index}`));
  const defaultResult = await scheduleLiveRouteChecks({
    baseUrl: new URL('http://127.0.0.1:1'),
    tasks
  });
  assert.equal(defaultResult.budget.attempted, false);
  assert.match(
    defaultResult.errors.join('\n'),
    /1500 checks, exceeding the 1000 route limit; no routes were fetched/i
  );
  const raisedOverflow = await scheduleLiveRouteChecks({
    baseUrl: new URL('http://127.0.0.1:1'),
    maxRoutes: 1_200,
    tasks
  });
  assert.equal(raisedOverflow.budget.attempted, false);
  assert.equal(raisedOverflow.budget.maxRoutes, 1_200);
  assert.match(
    raisedOverflow.errors.join('\n'),
    /1500 checks, exceeding the 1200 route limit; no routes were fetched/i
  );
});
