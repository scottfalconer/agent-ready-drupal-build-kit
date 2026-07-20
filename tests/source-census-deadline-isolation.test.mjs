import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  browserRuntimePreflightUnavailable,
  createLiveHttpContext,
  verifierFingerprint
} from '../bin/verify.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const delay = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

test('verifier fingerprint binds handoff validation and the executable vendored WebSocket transport', () => {
  const kitRoot = mkdtempSync(join(tmpdir(), 'verifier-fingerprint-'));
  const scriptPath = join(kitRoot, 'bin', 'verify.mjs');
  const vendorRoot = join(kitRoot, 'vendor', 'ws', '8.21.0');
  mkdirSync(dirname(scriptPath), { recursive: true });
  mkdirSync(vendorRoot, { recursive: true });
  writeFileSync(scriptPath, 'fixture verifier');
  writeFileSync(join(dirname(scriptPath), 'review-handoff.mjs'), 'export const handoff = "first";\n');
  writeFileSync(join(vendorRoot, 'INTEGRITY.json'), '{"fixture":true}\n');
  writeFileSync(join(vendorRoot, 'ws.mjs'), 'export default "first";\n');

  const before = verifierFingerprint({ kitRoot, scriptPath });
  writeFileSync(join(dirname(scriptPath), 'review-handoff.mjs'), 'export const handoff = "second";\n');
  const afterHandoffChange = verifierFingerprint({ kitRoot, scriptPath });
  assert.notEqual(afterHandoffChange, before);

  writeFileSync(join(vendorRoot, 'ws.mjs'), 'export default "second";\n');
  const afterBundleChange = verifierFingerprint({ kitRoot, scriptPath });
  assert.notEqual(afterBundleChange, afterHandoffChange);

  writeFileSync(join(vendorRoot, 'INTEGRITY.json'), '{"fixture":false}\n');
  assert.notEqual(verifierFingerprint({ kitRoot, scriptPath }), afterBundleChange);
});

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

test('browser preflight distinguishes runtime failure from route/site capture failure', () => {
  assert.equal(browserRuntimePreflightUnavailable({
    status: 'unavailable',
    budget: { attempted: true },
    runtime: { ready: false }
  }, { attempted: true }), true);
  assert.equal(browserRuntimePreflightUnavailable({
    status: 'blocked',
    budget: { attempted: true },
    runtime: { ready: false }
  }, { attempted: true }), true, 'an attempted CDP/axe preflight that never becomes ready is a runtime failure');
  assert.equal(browserRuntimePreflightUnavailable({
    status: 'blocked',
    budget: { attempted: true },
    runtime: { ready: true }
  }, { attempted: true }), false, 'site capture errors after a ready preflight must not suppress source/HTTP evidence');
  assert.equal(browserRuntimePreflightUnavailable({
    status: 'blocked',
    budget: { attempted: false },
    runtime: { ready: false }
  }, { attempted: true }), false, 'route/input bounds that prevent launch are not a broken browser runtime');
  assert.equal(browserRuntimePreflightUnavailable(null, { attempted: false }), false);
});

// Structural guard on verifyLive's delivery order: browser/CDP/axe capture is
// the early runtime preflight, target routes and editor/runtime evidence finish
// next, and only then may the expensive source crawl start. bin/ and skills/
// copies are kept byte-identical by the skill-package sync test, so checking
// bin/ suffices.
test('verifyLive preflights the browser and completes target delivery checks before starting source census', () => {
  const source = readFileSync(join(repoRoot, 'bin', 'verify.mjs'), 'utf8');
  const start = source.indexOf('export async function verifyLive');
  assert.ok(start >= 0, 'verifyLive must exist');
  const body = source.slice(start);

  const browserCapture = body.indexOf('const rawGlobalChromeCapture = browserCaptureAttempted');
  const censusDefinition = body.indexOf('const runSourceSurfaceCensus = async () => briefMode');
  const contextCreation = body.indexOf('const liveHttpContext = createLiveHttpContext({');
  const accessWallCheck = body.indexOf('Access-wall verification could not complete');
  const legalPrivacyCheck = body.indexOf('Legal/privacy-link verification could not complete');
  const consentReconciliation = body.indexOf('const consentReconciliation = verifyConsentReconciliation(');
  const axeEvaluation = body.indexOf('const verifierOwnedAxeErrors = verifierAxeCompletionErrors(');
  const censusEligibility = body.indexOf('const lateSourceCensusEligible =');
  const censusStart = body.indexOf('await runSourceSurfaceCensus()');
  const targetVerdict = body.indexOf('const liveTargetValid = Boolean(target)');

  assert.ok(browserCapture >= 0, 'verifier-owned browser preflight must exist');
  assert.ok(censusDefinition >= 0, 'deferred source census definition must exist');
  assert.ok(contextCreation >= 0, 'target liveHttpContext creation must exist in verifyLive');
  assert.ok(accessWallCheck >= 0, 'access-wall target-side check must exist');
  assert.ok(legalPrivacyCheck >= 0, 'legal/privacy target-side check must exist');
  assert.ok(consentReconciliation >= 0, 'target consent reconciliation must exist');
  assert.ok(axeEvaluation >= 0, 'verifier-owned accessibility evaluation must exist');
  assert.ok(censusEligibility >= 0, 'late source-census eligibility gate must exist');
  assert.ok(censusStart >= 0, 'source census must be invoked');
  assert.ok(targetVerdict >= 0, 'target verdict must exist');

  assert.ok(
    browserCapture < censusDefinition,
    'browser capture must finish before defining the deferred source census'
  );
  assert.ok(
    censusDefinition < contextCreation,
    'the deferred source census must be available before target work without starting it'
  );
  assert.ok(
    censusStart > contextCreation,
    'source census must start after the target liveHttpContext work'
  );
  assert.ok(
    censusStart > accessWallCheck,
    'source census must start after the access-wall target-side check'
  );
  assert.ok(
    censusStart > legalPrivacyCheck,
    'source census must start after the legal/privacy target-side check'
  );
  assert.ok(
    censusStart > consentReconciliation,
    'source census must start after browser/consent reconciliation'
  );
  assert.ok(censusStart > axeEvaluation, 'source census must start after verifier-owned accessibility evaluation');
  assert.ok(censusStart > censusEligibility, 'source census must start only through its late eligibility gate');
  assert.ok(
    censusStart > targetVerdict,
    'the core target verdict must be established before the late source census starts'
  );

  const awaitCount = body.split('await runSourceSurfaceCensus()').length - 1;
  assert.equal(
    awaitCount,
    1,
    'the source census must start exactly once, after all target delivery checks'
  );
  assert.equal(body.includes('liveErrors.push(...sourceSurfaceCensus.errors)'), false);
});
