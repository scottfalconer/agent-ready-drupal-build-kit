import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { inspectRecipeManifest, runDoctor } from '../bin/doctor.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function fixtureProject({ coreVersion = '11.4.3', docroot = 'web', vendorRunner = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'kit-doctor-'));
  mkdirSync(join(root, '.ddev'), { recursive: true });
  if (vendorRunner) mkdirSync(join(root, 'vendor', 'bin'), { recursive: true });
  mkdirSync(join(root, docroot, 'core', 'scripts'), { recursive: true });
  mkdirSync(join(root, 'recipes', 'example', 'config', 'install'), { recursive: true });
  writeFileSync(join(root, '.ddev', 'config.yaml'), `name: doctor-test\ntype: drupal11\ndocroot: ${docroot}\n`);
  if (vendorRunner) writeFileSync(join(root, 'vendor', 'bin', 'dr'), '#!/usr/bin/env php\n');
  writeFileSync(join(root, docroot, 'core', 'scripts', 'drupal'), '#!/usr/bin/env php\n');
  writeJson(join(root, 'composer.json'), {
    name: 'drupal/cms',
    type: 'project',
    require: { 'drupal/core-recommended': '^11' }
  });
  writeJson(join(root, 'composer.lock'), {
    packages: [
      { name: 'drupal/core', version: coreVersion, type: 'drupal-core', require: {} },
      { name: 'drupal/example', version: '1.2.3', type: 'drupal-recipe', require: { 'drupal/core': '^11' } }
    ],
    'packages-dev': []
  });
  writeFileSync(join(root, 'recipes', 'example', 'recipe.yml'), `name: Example
description: 'Example Recipe'
type: Site
recipes:
  - drupal_cms_content_type_base
install:
  - node
config:
  import:
    canvas: '*'
    system:
      - system.site
      - system.theme
  actions:
    system.site:
      simpleConfigUpdate:
        page.front: /home
`);
  writeFileSync(join(root, 'recipes', 'example', 'config', 'install', 'node.type.article.yml'), 'type: article\nname: Article\n');
  return root;
}

test('Recipe inspection extracts bounded executable touch points without pretending to validate YAML', () => {
  const manifest = inspectRecipeManifest(`name: Example
type: Site
recipes:
  - base_recipe
install:
  - node
config:
  import:
    canvas: '*'
    system:
      - system.site
  actions:
    system.site:
      simpleConfigUpdate:
        page.front: /home
`);

  assert.equal(manifest.name, 'Example');
  assert.equal(manifest.type, 'Site');
  assert.deepEqual(manifest.includedRecipes, ['base_recipe']);
  assert.deepEqual(manifest.installExtensions, ['node']);
  assert.deepEqual(manifest.configImports, ['canvas', 'system']);
  assert.deepEqual(manifest.configImportTargets, ['system.site']);
  assert.deepEqual(manifest.wildcardConfigImports, ['canvas']);
  assert.equal(manifest.configImportInspectionIncomplete, true);
  assert.deepEqual(manifest.configActionTargets, ['system.site']);
  assert.throws(() => inspectRecipeManifest(''), /must be nonempty/);
});

test('doctor records machine-owned substrate, route, browser, Recipe, and upstream facts without applying anything', async () => {
  const root = fixtureProject();
  const commands = [];
  const commandRunner = ({ args, command }) => {
    commands.push([command, ...args]);
    if (command.endsWith('/vendor/bin/dr')) return { status: 0, stdout: 'Recipe commands\n', stderr: '' };
    if (command === 'drush' && args[0] === 'status') {
      return {
        status: 0,
        stdout: JSON.stringify({ bootstrap: 'Successful', 'db-status': 'Connected', 'drupal-version': '11.4.3', root: 'web' }),
        stderr: ''
      };
    }
    if (command === 'drush' && args[0] === 'config:get') {
      return ['system.site', 'system.theme'].includes(args[1])
        ? { status: 0, stdout: '{"page":{"front":"/"}}', stderr: '' }
        : { status: 1, stdout: '', stderr: 'private diagnostic detail' };
    }
    if (command === 'composer') {
      return {
        status: 0,
        stdout: JSON.stringify({
          name: 'drupal/example',
          type: 'drupal-recipe',
          versions: ['1.2.3'],
          requires: { 'drupal/core': '^11' },
          dist: { url: 'https://secret.invalid/token' }
        }),
        stderr: ''
      };
    }
    return { status: 1, stdout: '', stderr: 'unexpected command' };
  };

  const report = await runDoctor({
    baseUrl: 'https://doctor-test.ddev.site',
    browserSmokeRunner: async () => ({
      ready: true,
      axeRouteViewportCount: 2,
      browserVersion: 'Chrome/140',
      executionBoundary: 'ddev-add-on-sidecar'
    }),
    checkedAt: '2026-07-14T20:00:00.000Z',
    commandRunner,
    environment: {
      IS_DDEV_PROJECT: 'true',
      DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site'
    },
    fetchImpl: async () => new Response(
      '<!doctype html><html><head><title>Doctor route</title></head><body><h1>Ready</h1></body></html>',
      { status: 200, headers: { 'content-type': 'text/html' } }
    ),
    packages: ['drupal/example'],
    projectRoot: root,
    recipes: ['recipes/example'],
    route: '/search?email=person@example.com&token=super-secret'
  });

  assert.equal(report.schemaVersion, 'public-kit.doctor.1');
  assert.equal(report.completionAuthority, false);
  assert.deepEqual(report.mutationPolicy, {
    appliesRecipes: false,
    changesDrupalContentOrConfig: false,
    writesReviewerVerdicts: false
  });
  assert.equal(report.stages.find((stage) => stage.id === 'substrate').status, 'pass');
  assert.equal(report.stages.find((stage) => stage.id === 'substrate').facts.recipeRunnerPath, 'vendor/bin/dr');
  assert.equal(report.stages.find((stage) => stage.id === 'runtime').status, 'pass');
  assert.equal(report.stages.find((stage) => stage.id === 'route').status, 'pass');
  assert.equal(report.stages.find((stage) => stage.id === 'browser-runtime').status, 'pass');
  assert.equal(report.recipes[0].status, 'warning');
  assert.deepEqual(report.recipes[0].activeConfigTargets, ['system.site', 'system.theme']);
  assert.equal(report.recipes[0].applyReadiness, 'manual_review_required');
  assert.equal(report.recipes[0].includedRecipeInspectionIncomplete, true);
  assert.match(report.recipes[0].warnings.join('\n'), /Included Recipes were not recursively inspected/);
  assert.equal(report.upstreamPackages[0].available, true);
  assert.match(report.upstreamPackages[0].command.stdoutSha256, /^sha256:[a-f0-9]{64}$/);
  assert.equal(
    report.project.route,
    '/search?query-sha256=b2e0ca042a075485ba8be095e1605d03536c460f1f09f9f4d97ef0085866aee4'
  );
  assert.equal(report.stages.find((stage) => stage.id === 'route').facts.finalPath, report.project.route);
  assert.doesNotMatch(
    JSON.stringify(report),
    /private diagnostic detail|secret\.invalid|person@example\.com|super-secret/
  );
  assert.equal(
    commands.some((command) => command.includes('recipe') && !command.includes('--help')),
    false,
    'doctor must never apply a Recipe'
  );
  assert.equal(report.summary.status, 'warning');
  assert.equal(report.summary.failed, 0);
});

test('doctor fails diagnostics when no current local route can be identified and can explicitly skip browser smoke', async () => {
  const root = fixtureProject();
  const commandRunner = ({ args, command }) => {
    if (command.endsWith('/vendor/bin/dr')) return { status: 0, stdout: '', stderr: '' };
    if (command === 'drush' && args[0] === 'status') {
      return { status: 0, stdout: JSON.stringify({ bootstrap: 'Successful', root: 'web' }), stderr: '' };
    }
    return { status: 1, stdout: '', stderr: '' };
  };
  const report = await runDoctor({
    baseUrl: '',
    browser: false,
    commandRunner,
    environment: { IS_DDEV_PROJECT: 'true' },
    fetchImpl: async () => { throw new Error('must not fetch'); },
    projectRoot: root,
    recipes: ['recipes/example']
  });

  assert.equal(report.stages.find((stage) => stage.id === 'route').status, 'fail');
  assert.equal(report.stages.find((stage) => stage.id === 'browser-runtime').status, 'skipped');
  assert.equal(report.summary.status, 'fail');
  assert.equal(report.summary.readyForFullVerification, false);
});

test('doctor CLI exposes diagnostic-only options without touching a project', () => {
  const result = spawnSync(process.execPath, [join(repoRoot, 'bin', 'doctor.mjs'), '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /diagnostic-only/);
  assert.match(result.stdout, /--package/);
  assert.match(result.stdout, /--skip-browser/);
});

test('doctor CLI runs through an npm-style bin symlink', () => {
  const binDirectory = mkdtempSync(join(tmpdir(), 'kit-doctor-bin-'));
  const binPath = join(binDirectory, 'agent-ready-drupal-doctor');
  symlinkSync(join(repoRoot, 'bin', 'doctor.mjs'), binPath);
  const result = spawnSync(process.execPath, [binPath, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /diagnostic-only/);
});

test('doctor rejects Recipe and report paths that traverse symbolic links', async () => {
  const root = fixtureProject();
  const linkedRecipe = join(root, 'linked-recipe');
  symlinkSync(join(root, 'recipes', 'example'), linkedRecipe);
  await assert.rejects(
    runDoctor({
      browser: false,
      commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
      environment: { IS_DDEV_PROJECT: 'true' },
      fetchImpl: async () => { throw new Error('route unavailable'); },
      projectRoot: root,
      recipes: ['linked-recipe']
    }),
    /Recipe path must not traverse a symbolic link/
  );

  const realEvidence = join(root, 'real-evidence');
  mkdirSync(realEvidence);
  symlinkSync(realEvidence, join(root, 'linked-evidence'));
  const result = spawnSync(process.execPath, [
    join(repoRoot, 'bin', 'doctor.mjs'),
    '--project', root,
    '--out', 'linked-evidence/doctor.json',
    '--skip-browser'
  ], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--out must not traverse a symbolic link/);
});

test('doctor rejects a symlinked automatic Recipe root', async () => {
  const root = fixtureProject();
  const outside = mkdtempSync(join(tmpdir(), 'kit-doctor-outside-recipes-'));
  writeFileSync(join(outside, 'recipe.yml'), 'name: Outside\ntype: Site\n');
  symlinkSync(outside, join(root, 'web', 'core', 'recipes'));
  await assert.rejects(
    runDoctor({
      browser: false,
      commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
      environment: { IS_DDEV_PROJECT: 'true' },
      fetchImpl: async () => { throw new Error('route unavailable'); },
      projectRoot: root
    }),
    /Automatic Recipe discovery root must not traverse a symbolic link/
  );
});

test('doctor warns when automatic Recipe discovery skips a nested symlink', async () => {
  const root = fixtureProject();
  const outside = mkdtempSync(join(tmpdir(), 'kit-doctor-linked-auto-recipe-'));
  writeFileSync(join(outside, 'recipe.yml'), 'name: Linked automatic Recipe\n');
  symlinkSync(outside, join(root, 'recipes', 'linked-automatic'));
  const report = await runDoctor({
    browser: false,
    commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root
  });
  const discovery = report.stages.find((stage) => stage.id === 'recipe-discovery');
  assert.equal(discovery.status, 'warning');
  assert.equal(discovery.facts.skippedSymlink, true);
  assert.match(discovery.warnings.join('\n'), /skipped one or more symbolic links/);
  assert.doesNotMatch(JSON.stringify(report), /Linked automatic Recipe/);
});

test('doctor refuses ambiguous routes before fetch', async () => {
  const root = fixtureProject();
  let fetched = false;
  const report = await runDoctor({
    browser: false,
    commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => {
      fetched = true;
      throw new Error('must not fetch');
    },
    projectRoot: root,
    route: '/https://169.254.169.254/latest/meta-data'
  });
  assert.equal(fetched, false);
  assert.equal(report.project.route, 'invalid-route');
  assert.equal(report.stages.find((stage) => stage.id === 'route').status, 'fail');
  assert.doesNotMatch(JSON.stringify(report), /169\.254\.169\.254/);
});

test('doctor binds an explicit base URL to the current DDEV project origin', async () => {
  const root = fixtureProject();
  const fetched = [];
  const report = await runDoctor({
    baseUrl: 'https://project-b.ddev.site',
    browser: false,
    commandRunner: ({ args, command }) => {
      if (command === 'ddev' && args[0] === 'describe') {
        return {
          status: 0,
          stdout: JSON.stringify({ raw: { primary_url: 'https://project-a.ddev.site' } }),
          stderr: ''
        };
      }
      return { status: 1, stdout: '', stderr: '' };
    },
    environment: {},
    fetchImpl: async (url) => {
      fetched.push(new URL(url).origin);
      return new Response('<title>Ready</title>', { status: 200 });
    },
    projectRoot: root,
    recipes: ['recipes/example']
  });
  const binding = report.stages.find((stage) => stage.id === 'target-origin-binding');
  assert.equal(binding.status, 'fail');
  assert.deepEqual(fetched, ['https://project-a.ddev.site']);
  assert.doesNotMatch(JSON.stringify(report), /project-[ab]\.ddev\.site/);
});

test('doctor hashes a raw query-sha256 parameter instead of trusting its value', async () => {
  const root = fixtureProject();
  const rawValue = 'a'.repeat(64);
  const report = await runDoctor({
    browser: false,
    commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/example'],
    route: `/search?query-sha256=${rawValue}`
  });
  assert.match(report.project.route, /^\/search\?query-sha256=[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(report).includes(rawValue), false);
});

test('doctor cannot pass runtime diagnostics on parseable but empty Drush status', async () => {
  const root = fixtureProject();
  const report = await runDoctor({
    browserSmokeRunner: async () => ({
      ready: true,
      axeRouteViewportCount: 1,
      executionBoundary: 'ddev-add-on-sidecar'
    }),
    commandRunner: ({ args, command }) => {
      if (command.endsWith('/vendor/bin/dr')) return { status: 0, stdout: '', stderr: '' };
      if (command === 'drush' && args[0] === 'status') return { status: 0, stdout: '{}', stderr: '' };
      return { status: 1, stdout: '', stderr: '' };
    },
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/example']
  });
  assert.equal(report.stages.find((stage) => stage.id === 'runtime').status, 'fail');
  assert.equal(report.summary.status, 'fail');
  assert.equal(report.summary.readyForFullVerification, false);
});

test('doctor binds the Drupal runtime to locked core and the configured docroot', async () => {
  const root = fixtureProject();
  const report = await runDoctor({
    browser: false,
    commandRunner: ({ args, command }) => {
      if (command.endsWith('/vendor/bin/dr')) return { status: 0, stdout: '', stderr: '' };
      if (command === 'drush' && args[0] === 'status') {
        return {
          status: 0,
          stdout: JSON.stringify({
            bootstrap: 'Successful',
            'db-status': 'Connected',
            'drupal-version': '11.3.11',
            root: 'elsewhere'
          }),
          stderr: ''
        };
      }
      return { status: 1, stdout: '', stderr: '' };
    },
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/example']
  });
  const runtime = report.stages.find((stage) => stage.id === 'runtime');
  assert.equal(runtime.status, 'fail');
  assert.equal(runtime.facts.coreVersionMatchesLock, false);
  assert.equal(runtime.facts.rootMatchesDdevDocroot, false);
  assert.equal('root' in runtime.facts, false);
});

test('doctor rejects a symlinked configured DDEV docroot', async () => {
  const root = fixtureProject();
  const outside = mkdtempSync(join(tmpdir(), 'kit-doctor-outside-docroot-'));
  mkdirSync(join(outside, 'core', 'scripts'), { recursive: true });
  writeFileSync(join(outside, 'core', 'scripts', 'drupal'), '#!/usr/bin/env php\n');
  symlinkSync(outside, join(root, 'linked-docroot'));
  writeFileSync(
    join(root, '.ddev', 'config.yaml'),
    'name: doctor-test\ntype: drupal11\ndocroot: linked-docroot\n'
  );
  const report = await runDoctor({
    browser: false,
    commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/example']
  });
  const substrate = report.stages.find((stage) => stage.id === 'substrate');
  assert.equal(substrate.status, 'fail');
  assert.match(substrate.errors.join('\n'), /DDEV docroot must not traverse a symbolic link/);
  assert.doesNotMatch(JSON.stringify(report), new RegExp(outside.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('doctor discovers the legacy Recipe runner from the configured DDEV docroot', async () => {
  const root = fixtureProject({ coreVersion: '11.3.11', docroot: 'htdocs', vendorRunner: false });
  mkdirSync(join(root, 'htdocs', 'core', 'recipes', 'core-example'), { recursive: true });
  writeFileSync(
    join(root, 'htdocs', 'core', 'recipes', 'core-example', 'recipe.yml'),
    'name: Core example\n'
  );
  const commands = [];
  const report = await runDoctor({
    browser: false,
    commandRunner: ({ args, command, cwd }) => {
      commands.push({ args, command, cwd });
      if (command === 'php') return { status: 0, stdout: '', stderr: '' };
      if (command === 'drush' && args[0] === 'status') {
        return {
          status: 0,
          stdout: JSON.stringify({
            bootstrap: 'Successful',
            'db-status': 'Connected',
            'drupal-version': '11.3.11',
            root: 'htdocs'
          }),
          stderr: ''
        };
      }
      return { status: 1, stdout: '', stderr: '' };
    },
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root
  });
  const substrate = report.stages.find((stage) => stage.id === 'substrate');
  assert.equal(substrate.status, 'pass');
  assert.equal(substrate.facts.ddevDocroot, 'htdocs');
  assert.equal(substrate.facts.recipeRunnerPath, 'htdocs/core/scripts/drupal');
  assert.equal(report.stages.find((stage) => stage.id === 'runtime').status, 'pass');
  assert.equal(commands[0].command, 'php');
  assert.equal(commands[0].cwd.split('/').pop(), 'htdocs');
  assert.equal(
    report.recipes.some((recipe) => recipe.path === 'htdocs/core/recipes/core-example/recipe.yml'),
    true
  );
});

test('doctor accepts a current minimal Recipe without optional type metadata', async () => {
  const root = fixtureProject();
  mkdirSync(join(root, 'recipes', 'minimal'));
  writeFileSync(join(root, 'recipes', 'minimal', 'recipe.yml'), 'name: Minimal\n');
  const report = await runDoctor({
    browser: false,
    commandRunner: ({ args, command }) => {
      if (command.endsWith('/vendor/bin/dr')) return { status: 0, stdout: '', stderr: '' };
      if (command === 'drush' && args[0] === 'status') {
        return {
          status: 0,
          stdout: JSON.stringify({
            bootstrap: 'Successful',
            'db-status': 'Connected',
            'drupal-version': '11.4.3',
            root: 'web'
          }),
          stderr: ''
        };
      }
      return { status: 1, stdout: '', stderr: '' };
    },
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/minimal']
  });
  assert.equal(report.recipes[0].manifest.type, '');
  assert.equal(report.recipes[0].status, 'pass');
  assert.deepEqual(report.recipes[0].errors, []);
});

test('doctor marks symlinked Recipe config inventory incomplete without reading it', async () => {
  const root = fixtureProject();
  const recipeRoot = join(root, 'recipes', 'linked-config');
  const outside = mkdtempSync(join(tmpdir(), 'kit-doctor-outside-config-'));
  mkdirSync(recipeRoot);
  writeFileSync(join(recipeRoot, 'recipe.yml'), 'name: Linked config\n');
  writeFileSync(join(outside, 'secret.outside.yml'), 'value: hidden\n');
  symlinkSync(outside, join(recipeRoot, 'config'));
  const report = await runDoctor({
    browser: false,
    commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/linked-config']
  });
  assert.equal(report.recipes[0].status, 'warning');
  assert.equal(report.recipes[0].configInstallInspectionIncomplete, true);
  assert.deepEqual(report.recipes[0].configInstallNames, []);
  assert.doesNotMatch(JSON.stringify(report), /secret\.outside/);
});

test('doctor exposes bounded manifest and automatic discovery truncation', async () => {
  const root = fixtureProject();
  const actionLines = Array.from({ length: 65 }, (_, index) =>
    `    system.test_${String(index).padStart(2, '0')}:\n      simpleConfigUpdate:\n        value: true`
  ).join('\n');
  writeFileSync(join(root, 'recipes', 'example', 'recipe.yml'), `name: Bounded\nconfig:\n  actions:\n${actionLines}\n`);
  const bounded = await runDoctor({
    browser: false,
    commandRunner: ({ args, command }) => {
      if (command.endsWith('/vendor/bin/dr')) return { status: 0, stdout: '', stderr: '' };
      if (command === 'drush' && args[0] === 'status') {
        return {
          status: 0,
          stdout: JSON.stringify({
            bootstrap: 'Successful',
            'db-status': 'Connected',
            'drupal-version': '11.4.3',
            root: 'web'
          }),
          stderr: ''
        };
      }
      return { status: 1, stdout: '', stderr: '' };
    },
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: root,
    recipes: ['recipes/example']
  });
  assert.equal(bounded.recipes[0].manifest.declaredCounts.configActionTargets, 65);
  assert.equal(bounded.recipes[0].manifest.configActionTargets.length, 64);
  assert.equal(bounded.recipes[0].activeConfigInspectionTruncated, true);
  assert.equal(bounded.recipes[0].status, 'warning');

  const discoveryRoot = fixtureProject();
  for (let index = 0; index < 65; index += 1) {
    const directory = join(discoveryRoot, 'recipes', `extra-${String(index).padStart(2, '0')}`);
    mkdirSync(directory);
    writeFileSync(join(directory, 'recipe.yml'), `name: Extra ${index}\n`);
  }
  const discovered = await runDoctor({
    browser: false,
    commandRunner: () => ({ status: 1, stdout: '', stderr: '' }),
    environment: { IS_DDEV_PROJECT: 'true', DDEV_PRIMARY_URL: 'https://doctor-test.ddev.site' },
    fetchImpl: async () => new Response('<title>Ready</title>', { status: 200 }),
    projectRoot: discoveryRoot
  });
  const discoveryStage = discovered.stages.find((stage) => stage.id === 'recipe-discovery');
  assert.equal(discoveryStage.status, 'warning');
  assert.equal(discoveryStage.facts.recipeCount, 64);
  assert.equal(discoveryStage.facts.truncated, true);
});
