import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { createLiveHttpContext } from '../bin/verify.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const delay = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

async function withServer(handler, callback) {
  const server = createServer(handler);
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const { port } = server.address();
  try {
    return await callback(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
}

// The mechanism behind the bug: a liveHttpContext fixes its wall-clock deadline
// at creation (deadlineAt = startedAt + deadlineMs). If a slow source census is
// awaited BEFORE the target context is used, that fixed deadline elapses while
// the target context sits idle, so every subsequent target-side check fails with
// "exceeded its total wall-clock deadline" even though the target is fast and
// healthy. This test locks that property so the isolation fix stays meaningful.
test('a liveHttpContext whose wall-clock elapses before first use fails even when idle (source-census starvation mechanism)', async () => {
  await withServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><body><h1>fast target</h1></body></html>');
    },
    async (baseUrl) => {
      // Stand-in for "target context created, then a slow source census awaited first".
      const starved = createLiveHttpContext({ deadlineMs: 60 });
      await delay(180);
      await assert.rejects(
        () => starved.request(baseUrl),
        /exceeded its total wall-clock deadline/,
        'a context whose fixed deadline elapsed before use must fail even though it did no work'
      );

      // The fix keeps target checks on a context whose deadline has not been
      // pre-consumed by the source census, so the same fast target succeeds.
      const fresh = createLiveHttpContext({ deadlineMs: 5000 });
      const response = await fresh.request(baseUrl);
      assert.equal(response.status, 200, 'a fresh-deadline context reaches the same fast target');
    }
  );
});

// Structural guard on verifyLive's scheduling: the verifier-owned source census
// (which crawls a slow / large / CDN-gated SOURCE origin and has its own budget)
// must be awaited only AFTER every target-side liveHttpContext check has run, so
// its cost cannot consume the target context's wall-clock and produce false
// target-side "deadline exceeded" failures. bin/ and skills/ copies are kept
// byte-identical by the skill-package sync test, so checking bin/ suffices.
test('verifyLive awaits the source census after every target-side check so source cost cannot starve the target wall-clock', () => {
  const source = readFileSync(join(repoRoot, 'bin', 'verify.mjs'), 'utf8');
  const start = source.indexOf('export async function verifyLive');
  assert.ok(start >= 0, 'verifyLive must exist');
  const body = source.slice(start);

  const contextCreation = body.indexOf('const liveHttpContext = createLiveHttpContext({');
  const accessWallCheck = body.indexOf('Access-wall verification could not complete');
  const legalPrivacyCheck = body.indexOf('Legal/privacy-link verification could not complete');
  const censusAwait = body.indexOf('await sourceSurfaceCensusPromise');

  assert.ok(contextCreation >= 0, 'target liveHttpContext creation must exist in verifyLive');
  assert.ok(accessWallCheck >= 0, 'access-wall target-side check must exist');
  assert.ok(legalPrivacyCheck >= 0, 'legal/privacy target-side check must exist');
  assert.ok(censusAwait >= 0, 'source census must be awaited');

  assert.ok(
    censusAwait > contextCreation,
    'source census must be awaited after the target liveHttpContext is created'
  );
  assert.ok(
    censusAwait > accessWallCheck,
    'source census must be awaited after the access-wall target-side check'
  );
  assert.ok(
    censusAwait > legalPrivacyCheck,
    'source census must be awaited after the legal/privacy target-side check (the last one)'
  );

  const awaitCount = body.split('await sourceSurfaceCensusPromise').length - 1;
  assert.equal(
    awaitCount,
    1,
    'the source census must be awaited exactly once, after all target-side checks (no earlier serialization point)'
  );
});
