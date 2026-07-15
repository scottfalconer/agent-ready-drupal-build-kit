import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildPortableReproductionState,
  comparePortableReproductionStates,
  normalizeRouteResponse
} from '../bin/reproduction-state.mjs';
import { sha256 } from '../bin/state-fingerprint.mjs';

function state(overrides = {}) {
  return buildPortableReproductionState({
    confirmed: true,
    errors: [],
    siteUuid: '11111111-1111-4111-8111-111111111111',
    configSyncDirectory: '/var/www/html/config/sync',
    configStatusClean: true,
    config: {
      items: [
        { name: 'system.site', sha256: sha256({ name: 'Fixture' }) },
        { name: 'system.theme', sha256: sha256({ default: 'olivero' }) }
      ]
    },
    entities: {
      types: {
        node: {
          items: [{
            stableId: 'uuid:22222222-2222-4222-8222-222222222222',
            bundle: 'page',
            sha256: sha256({ title: 'Home' })
          }]
        }
      }
    },
    managedFiles: {
      items: [{
        stableId: 'uuid:33333333-3333-4333-8333-333333333333',
        scheme: 'public',
        uriSha256: sha256('public://hero.jpg'),
        bytesSha256: sha256(Buffer.from('hero bytes')),
        size: 10
      }]
    },
    routes: [{
      path: '/',
      status: 200,
      finalPath: '/',
      titleSha256: sha256('Fixture'),
      h1Sha256: sha256('Welcome'),
      bodyTextSha256: sha256('Fixture Welcome'),
      bodyTextLength: 15
    }],
    ...overrides
  });
}

test('portable reproduction state normalizes the DDEV container config path and compares exact stable facts', () => {
  const expected = state();
  const actual = state();

  assert.equal(expected.configSyncDirectory, 'config/sync');
  assert.equal(comparePortableReproductionStates(expected, actual).match, true);
  assert.equal(expected.entities.types.node.items[0].stableId.startsWith('uuid:'), true);
});

test('portable reproduction state resolves a Drupal-root-relative sync directory', () => {
  const value = state({
    configSyncDirectory: '../config/sync',
    drupalRoot: '/var/www/html/web'
  });

  assert.equal(value.configSyncDirectory, 'config/sync');
});

test('portable comparison reports stable-entity and managed-file byte changes without raw values', () => {
  const expected = state();
  const changed = state({
    entities: {
      types: {
        node: {
          items: [{
            stableId: 'uuid:22222222-2222-4222-8222-222222222222',
            bundle: 'page',
            sha256: sha256({ title: 'Changed' })
          }]
        }
      }
    },
    managedFiles: {
      items: [{
        stableId: 'uuid:33333333-3333-4333-8333-333333333333',
        scheme: 'public',
        uriSha256: sha256('public://hero.jpg'),
        bytesSha256: sha256(Buffer.from('different bytes')),
        size: 15
      }]
    }
  });

  const comparison = comparePortableReproductionStates(expected, changed);

  assert.equal(comparison.match, false);
  assert.deepEqual(comparison.mismatches.map((item) => item.component).sort(), [
    'managedFileBytes',
    'stableEntities'
  ]);
  assert.doesNotMatch(JSON.stringify(comparison), /Changed|different bytes/);
});

test('route normalization removes the machine-local origin but preserves visitor-visible semantics', () => {
  const working = normalizeRouteResponse({
    body: '<html><head><title>Example</title></head><body><h1>Hello</h1><a href="https://working.ddev.site/about">About</a></body></html>',
    effectiveUrl: 'https://working.ddev.site/',
    origin: 'https://working.ddev.site',
    path: '/',
    status: 200
  });
  const disposable = normalizeRouteResponse({
    body: '<html><head><title>Example</title></head><body><h1>Hello</h1><a href="https://disposable.ddev.site/about">About</a></body></html>',
    effectiveUrl: 'https://disposable.ddev.site/',
    origin: 'https://disposable.ddev.site',
    path: '/',
    status: 200
  });

  assert.deepEqual(disposable, working);
  assert.equal(working.h1Sha256, sha256('Hello'));
});

test('route normalization refuses cross-origin final responses', () => {
  assert.throws(() => normalizeRouteResponse({
    body: '<h1>Elsewhere</h1>',
    effectiveUrl: 'https://external.example/',
    origin: 'https://working.ddev.site',
    path: '/',
    status: 200
  }), /left the DDEV target origin/);
});

test('unconfirmed Drupal facts can never compare as a valid reproduction', () => {
  const expected = state();
  const unconfirmed = state({ confirmed: false, errors: ['Managed bytes unavailable.'] });

  const comparison = comparePortableReproductionStates(expected, unconfirmed);

  assert.equal(comparison.match, false);
  assert.equal(comparison.mismatches.some((item) => item.component === 'actualReadback'), true);
});
