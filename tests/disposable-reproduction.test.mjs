import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  cleanupDisposable,
  createDisposableClone,
  createRecordedExecutor,
  loadValidatedReproductionInputs,
  parseReproductionPlan,
  provisioningSteps
} from '../bin/disposable-ddev.mjs';
import { buildPortableReproductionState } from '../bin/reproduction-state.mjs';
import { collectFileManifest, sha256 } from '../bin/state-fingerprint.mjs';
import { runDisposableReproduction } from '../bin/verify-reproduction.mjs';

const DIGEST = `sha256:${'a'.repeat(64)}`;

function git(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'disposable-reproduction-fixture-'));
  mkdirSync(join(root, '.ddev'), { recursive: true });
  mkdirSync(join(root, 'config', 'sync'), { recursive: true });
  mkdirSync(join(root, 'review-packet'), { recursive: true });
  mkdirSync(join(root, 'web'), { recursive: true });
  writeFileSync(join(root, 'web', 'index.php'), '<?php\n');
  writeFileSync(join(root, '.ddev', 'config.yaml'), [
    'name: working-fixture',
    'type: drupal11',
    'docroot: web',
    'php_version: "8.4"',
    'webserver_type: nginx-fpm',
    'xdebug_enabled: false',
    'additional_hostnames: []',
    'additional_fqdns: []',
    'database:',
    '    type: mariadb',
    '    version: "11.8"',
    'use_dns_when_possible: true',
    'composer_version: "2"',
    'web_environment: []',
    'corepack_enable: true',
    ''
  ].join('\n'));
  writeFileSync(join(root, 'composer.json'), '{"name":"fixture/site"}\n');
  writeFileSync(join(root, 'composer.lock'), '{"packages":[]}\n');
  writeFileSync(join(root, 'config', 'sync', 'system.site.yml'), 'uuid: 11111111-1111-4111-8111-111111111111\n');
  writeFileSync(join(root, 'review-packet', 'route-matrix.json'), `${JSON.stringify({
    schemaVersion: 'public-kit.route-matrix.1',
    primaryRoutes: [{ targetPath: '/', accepted: true }],
    routes: [],
    targetRequiredRoutes: []
  }, null, 2)}\n`);
  const plan = {
    schemaVersion: 'public-kit.reproduction-plan.1',
    mode: 'clean_install_config_import',
    dependencies: {
      adapter: 'ddev_composer_install',
      lockFile: { path: 'composer.lock', sha256: sha256(readFileSync(join(root, 'composer.lock'))) }
    },
    trackedConfig: {
      path: 'config/sync',
      sha256: collectFileManifest(root, ['config/sync']).fingerprint
    },
    content: { adapter: 'none', expectedEntityCount: 0 },
    files: { adapter: 'none', expectedManagedFileCount: 0 }
  };
  writeFileSync(join(root, 'reproduction-plan.json'), `${JSON.stringify(plan, null, 2)}\n`);
  git(root, ['init', '--quiet']);
  git(root, ['add', '.']);
  git(root, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'fixture']);
  return { plan, root };
}

function generatedDdevName(projectRoot) {
  const config = readFileSync(join(projectRoot, '.ddev', 'config.yaml'), 'utf8');
  return config.match(/^name:\s*"([^"]+)"$/m)?.[1] ?? '';
}

function realExecutor(commandLog = []) {
  const execute = createRecordedExecutor({ commandLog });
  execute.commandLog = commandLog;
  return execute;
}

function emptyState() {
  return buildPortableReproductionState({
    confirmed: true,
    errors: [],
    siteUuid: '11111111-1111-4111-8111-111111111111',
    configSyncDirectory: 'config/sync',
    configStatusClean: true,
    config: { items: [{ name: 'system.site', sha256: sha256({ uuid: 'fixture' }) }] },
    entities: { types: {} },
    managedFiles: { items: [] },
    routes: [{
      path: '/', status: 200, finalPath: '/',
      titleSha256: sha256('Fixture'), h1Sha256: sha256('Fixture'),
      bodyTextSha256: sha256('Fixture'), bodyTextLength: 7
    }]
  });
}

test('typed plan validation accepts only exact-HEAD digest-bound inputs and primary routes', () => {
  const { root } = fixture();
  try {
    const loaded = loadValidatedReproductionInputs({ execute: realExecutor(), projectRoot: root });

    assert.equal(loaded.plan.mode, 'clean_install_config_import');
    assert.deepEqual(loaded.routes, ['/']);
    assert.equal(loaded.inputs.every((input) => input.declaredSha256 === input.actualSha256), true);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('typed plans reject command surfaces and mode-confused snapshot adapters', () => {
  assert.throws(() => parseReproductionPlan({
    schemaVersion: 'public-kit.reproduction-plan.1',
    mode: 'clean_install_config_import',
    dependencies: { adapter: 'ddev_composer_install', lockFile: { path: 'composer.lock', sha256: DIGEST } },
    trackedConfig: { path: 'config/sync', sha256: DIGEST },
    content: { adapter: 'none', expectedEntityCount: 0 },
    files: { adapter: 'none', expectedManagedFileCount: 0 },
    commands: ['sh -c "anything"']
  }), /unsupported field.*commands/i);

  assert.throws(() => parseReproductionPlan({
    schemaVersion: 'public-kit.reproduction-plan.1',
    mode: 'snapshot_restore',
    dependencies: { adapter: 'ddev_composer_install', lockFile: { path: 'composer.lock', sha256: DIGEST } },
    trackedConfig: { path: 'config/sync', sha256: DIGEST },
    content: { adapter: 'drush_php_script', source: { path: 'scripts/import.php', sha256: DIGEST } },
    files: { adapter: 'none', expectedManagedFileCount: 0 },
    databaseSnapshot: { adapter: 'ddev_import_db_archive', source: { path: 'artifacts/db.sql.gz', sha256: DIGEST } }
  }), /content\.adapter must be database_snapshot/);
});

test('fixed provisioning registry distinguishes clean import from snapshot restore', () => {
  const clean = parseReproductionPlan({
    schemaVersion: 'public-kit.reproduction-plan.1',
    mode: 'clean_install_config_import',
    dependencies: { adapter: 'ddev_composer_install', lockFile: { path: 'composer.lock', sha256: DIGEST } },
    trackedConfig: { path: 'config/sync', sha256: DIGEST },
    content: { adapter: 'drush_php_script', source: { path: 'scripts/import.php', sha256: DIGEST } },
    files: { adapter: 'ddev_import_files_archive', source: { path: 'artifacts/files.tar.gz', sha256: DIGEST } }
  });
  const snapshot = parseReproductionPlan({
    schemaVersion: 'public-kit.reproduction-plan.1',
    mode: 'snapshot_restore',
    dependencies: { adapter: 'ddev_composer_install', lockFile: { path: 'composer.lock', sha256: DIGEST } },
    trackedConfig: { path: 'config/sync', sha256: DIGEST },
    content: { adapter: 'database_snapshot' },
    files: { adapter: 'none', expectedManagedFileCount: 0 },
    databaseSnapshot: { adapter: 'ddev_import_db_archive', source: { path: 'artifacts/db.sql.gz', sha256: DIGEST } }
  });

  const cleanAdapters = provisioningSteps(clean).map((step) => step.adapter);
  const snapshotAdapters = provisioningSteps(snapshot).map((step) => step.adapter);
  assert.equal(cleanAdapters.includes('drush_site_install_existing_config'), true);
  assert.equal(cleanAdapters.includes('ddev_import_db_archive'), false);
  assert.equal(snapshotAdapters.includes('ddev_import_db_archive'), true);
  assert.equal(snapshotAdapters.includes('drush_site_install_existing_config'), false);
  assert.equal(provisioningSteps(clean).every((step) => Array.isArray(step.args) && !Object.hasOwn(step, 'shell')), true);
});

test('recorded executor always disables shell interpretation', () => {
  const calls = [];
  const execute = createRecordedExecutor({
    commandLog: [],
    spawn(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: 'ok', stderr: '', signal: null };
    }
  });

  const result = execute('tool', ['literal;not-shell'], { cwd: process.cwd(), phase: 'test', target: 'fixture' });

  assert.equal(result.status, 0);
  assert.equal(calls[0].options.shell, false);
  assert.deepEqual(calls[0].args, ['literal;not-shell']);
});

test('independent clone replaces project DDEV config with a minimal typed runtime and isolated global home', () => {
  const { root } = fixture();
  let disposable;
  try {
    const execute = realExecutor();
    disposable = createDisposableClone({ execute, head: git(root, ['rev-parse', 'HEAD']), projectRoot: root });

    const generatedConfig = readFileSync(join(disposable.root, '.ddev', 'config.yaml'), 'utf8');
    assert.equal(generatedDdevName(disposable.root), disposable.name);
    assert.match(generatedConfig, /^type: "drupal11"$/m);
    assert.match(generatedConfig, /^docroot: "web"$/m);
    assert.match(generatedConfig, /^php_version: "8\.4"$/m);
    assert.match(generatedConfig, /^webserver_type: "nginx-fpm"$/m);
    assert.match(generatedConfig, /^database:\n  type: "mariadb"\n  version: "11\.8"$/m);
    assert.doesNotMatch(generatedConfig, /web_environment|corepack_enable|use_dns_when_possible|webimage/);
    assert.deepEqual(readdirSync(join(disposable.root, '.ddev')), ['config.yaml']);
    assert.equal(disposable.ddevXdgConfigHome.startsWith(`${disposable.root}/`), false);
    assert.equal(existsSync(disposable.ddevXdgConfigHome), true);
    assert.doesNotMatch(readFileSync(join(root, '.ddev', 'config.yaml'), 'utf8'), /agent-ready-repro/);
    const cleanup = cleanupDisposable({ ddevStartAttempted: false, disposable, execute });
    assert.deepEqual(cleanup, { deletedDdevProject: false, removedClone: true });
    assert.equal(existsSync(disposable.root), false);
    assert.equal(existsSync(disposable.ownerRoot), false);
    disposable = null;
  } finally {
    if (disposable?.ownerRoot) rmSync(disposable.ownerRoot, { force: true, recursive: true });
    rmSync(root, { force: true, recursive: true });
  }
});

test('typed DDEV projection rejects PATH injection, extra daemons, custom images, and escaped keys', () => {
  for (const [mutate, expected] of [
    [
      (config) => config.replace('web_environment: []', 'web_environment:\n  - PATH=/tmp/project-controlled'),
      /web_environment must be an explicit empty list/
    ],
    [
      (config) => `${config}web_extra_daemons:\n  - name: forged\n    command: /tmp/project-controlled\n`,
      /unsupported field web_extra_daemons/
    ],
    [
      (config) => `${config}webimage: attacker.example.invalid/forged:latest\n`,
      /unsupported field webimage/
    ],
    [
      (config) => `${config}"web_\\u0065nvironment": ["PATH=/tmp/project-controlled"]\n`,
      /escaped or control key material/
    ]
  ]) {
    const { root } = fixture();
    try {
      const configPath = join(root, '.ddev', 'config.yaml');
      writeFileSync(configPath, mutate(readFileSync(configPath, 'utf8')));
      git(root, ['add', '.']);
      git(root, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'unsafe ddev config']);
      assert.throws(
        () => createDisposableClone({ execute: realExecutor(), head: git(root, ['rev-parse', 'HEAD']), projectRoot: root }),
        expected
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test('disposable clone rejects every project .ddev file or directory beyond config.yaml', () => {
  for (const [path, contents] of [
    ['.ddev/config.hooks.yaml', 'hooks:\n  pre-start:\n    - exec-host: "touch /tmp/owned"\n'],
    ['.ddev/commands/host/pwn', '#!/usr/bin/env bash\ntouch /tmp/owned\n'],
    ['.ddev/docker-compose.forged.yaml', 'services:\n  web:\n    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n'],
    ['.ddev/.env', 'COMPOSE_FILE=/tmp/project-controlled\n'],
    ['.ddev/web-build/Dockerfile', 'RUN touch /tmp/owned\n'],
    ['.ddev/db-build/Dockerfile', 'RUN touch /tmp/owned\n'],
    ['.ddev/web-entrypoint.d/pwn.sh', '#!/usr/bin/env bash\ntouch /tmp/owned\n'],
    ['.ddev/db-entrypoint.d/pwn.sh', '#!/usr/bin/env bash\ntouch /tmp/owned\n']
  ]) {
    const { root } = fixture();
    try {
      mkdirSync(join(root, path, '..'), { recursive: true });
      writeFileSync(join(root, path), contents);
      git(root, ['add', '-f', path]);
      git(root, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'extra ddev surface']);
      assert.throws(
        () => createDisposableClone({ execute: realExecutor(), head: git(root, ['rev-parse', 'HEAD']), projectRoot: root }),
        /rejects every project \.ddev file or directory except \.ddev\/config\.yaml/
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test('cleanup retains the owned clone when live DDEV identity cannot be reconfirmed', () => {
  const { root } = fixture();
  let disposable;
  try {
    const execute = realExecutor();
    disposable = createDisposableClone({ execute, head: git(root, ['rev-parse', 'HEAD']), projectRoot: root });
    const calls = [];
    const unsafeExecute = (command, args, options) => {
      calls.push({ command, args, options });
      if (command === 'ddev' && args[0] === 'describe') {
        return { status: 0, stdout: JSON.stringify({ raw: { name: 'another-project', approot: disposable.root } }), stderr: '', signal: null };
      }
      throw new Error(`Unexpected cleanup command: ${command} ${args.join(' ')}`);
    };

    assert.throws(
      () => cleanupDisposable({ ddevStartAttempted: true, disposable, execute: unsafeExecute }),
      /did not confirm the verifier-owned disposable project name and real app root/
    );
    assert.equal(calls.some(({ args }) => args[0] === 'delete'), false);
    assert.equal(existsSync(disposable.root), true);
  } finally {
    if (disposable?.ownerRoot) rmSync(disposable.ownerRoot, { force: true, recursive: true });
    rmSync(root, { force: true, recursive: true });
  }
});

test('cleanup refuses a same-name DDEV project whose real app root is not the owned clone', () => {
  const { root } = fixture();
  const wrongRoot = mkdtempSync(join(tmpdir(), 'wrong-disposable-root-'));
  let disposable;
  try {
    disposable = createDisposableClone({ execute: realExecutor(), head: git(root, ['rev-parse', 'HEAD']), projectRoot: root });
    const calls = [];
    const unsafeExecute = (command, args, options) => {
      calls.push({ command, args, options });
      if (command === 'ddev' && args[0] === 'describe') {
        return {
          status: 0,
          stdout: JSON.stringify({ raw: { name: disposable.name, approot: wrongRoot } }),
          stderr: '',
          signal: null
        };
      }
      throw new Error(`Unexpected cleanup command: ${command} ${args.join(' ')}`);
    };
    assert.throws(
      () => cleanupDisposable({ ddevStartAttempted: true, disposable, execute: unsafeExecute }),
      /name and real app root/
    );
    assert.equal(calls.some(({ args }) => args[0] === 'delete'), false);
    assert.equal(existsSync(disposable.root), true);
  } finally {
    if (disposable?.ownerRoot) rmSync(disposable.ownerRoot, { force: true, recursive: true });
    rmSync(wrongRoot, { force: true, recursive: true });
    rmSync(root, { force: true, recursive: true });
  }
});

test('a partial failed DDEV start still uses isolated state and identity-checks cleanup', () => {
  const { root } = fixture();
  const commandLog = [];
  const spawnCalls = [];
  const spawn = (command, args, options) => {
    spawnCalls.push({ command, args, options });
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'start') {
      return { status: 1, stdout: '', stderr: 'simulated partial start', signal: null };
    }
    if (command === 'ddev' && args[0] === 'describe') {
      const name = generatedDdevName(options.cwd);
      return {
        status: 0,
        stdout: JSON.stringify({ raw: { name, approot: options.cwd, primary_url: `https://${name}.ddev.site` } }),
        stderr: '',
        signal: null
      };
    }
    if (command === 'ddev' && args[0] === 'delete') {
      return { status: 0, stdout: 'deleted', stderr: '', signal: null };
    }
    throw new Error(`Unexpected mocked command: ${command} ${args.join(' ')}`);
  };
  const execute = createRecordedExecutor({
    commandLog,
    environment: {
      ...process.env,
      COMPOSE_FILE: '/tmp/ambient-compose.yaml',
      DDEV_XDG_CONFIG_HOME: '/tmp/ambient-ddev-home'
    },
    spawn
  });
  execute.commandLog = commandLog;
  try {
    const report = runDisposableReproduction({
      captureState: () => emptyState(),
      execute,
      projectRoot: root
    });

    assert.equal(report.valid, false);
    assert.match(report.errors.join('\n'), /Typed adapter ddev_start failed: simulated partial start/);
    assert.deepEqual(report.disposable.cleanup, { deletedDdevProject: true, removedClone: true });
    assert.equal(commandLog.some((record) => record.phase === 'confirm-disposable-ddev-identity-before-delete'), true);
    assert.equal(commandLog.some((record) => record.phase === 'delete-owned-disposable-ddev'), true);
    const ddevCalls = spawnCalls.filter((call) => call.command === 'ddev');
    assert.equal(new Set(ddevCalls.map((call) => call.options.env.DDEV_XDG_CONFIG_HOME)).size, 1);
    assert.equal(ddevCalls.every((call) => !Object.hasOwn(call.options.env, 'COMPOSE_FILE')), true);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('mocked end-to-end run proves exact-HEAD reproduction and working-target before/after equality', () => {
  const { root } = fixture();
  const commandLog = [];
  const spawnCalls = [];
  const spawn = (command, args, options) => {
    spawnCalls.push({ command, args, options });
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'describe') {
      const name = generatedDdevName(options.cwd);
      return { status: 0, stdout: JSON.stringify({ raw: { name, approot: options.cwd, primary_url: `https://${name}.ddev.site` } }), stderr: '', signal: null };
    }
    if (command === 'ddev') return { status: 0, stdout: 'ok', stderr: '', signal: null };
    throw new Error(`Unexpected mocked command: ${command}`);
  };
  const execute = createRecordedExecutor({
    commandLog,
    environment: {
      ...process.env,
      COMPOSE_FILE: '/tmp/ambient-compose.yaml',
      COMPOSE_PROJECT_NAME: 'ambient-project',
      DDEV_NO_TUI: 'false',
      DDEV_XDG_CONFIG_HOME: '/tmp/ambient-ddev-home'
    },
    spawn
  });
  execute.commandLog = commandLog;
  try {
    const report = runDisposableReproduction({
      captureState: () => emptyState(),
      execute,
      projectRoot: root
    });

    assert.equal(report.valid, true, JSON.stringify(report.errors));
    assert.equal(report.gateId, 'G-REPRO-01');
    assert.equal(report.source.exactHeadClone, true);
    assert.equal(report.reproductionComparison.match, true);
    assert.equal(report.workingTargetProof.untouched, true);
    assert.equal(report.disposable.cleanup.removedClone, true);
    assert.equal(report.evidenceScope.authoritativeForDefaultHandoff, false);
    assert.equal(report.commands.every((command) => !command.argv.includes('sh') && !command.argv.includes('bash')), true);
    const ddevCalls = spawnCalls.filter((call) => call.command === 'ddev');
    assert.ok(ddevCalls.length > 0);
    assert.equal(new Set(ddevCalls.map((call) => call.options.env.DDEV_XDG_CONFIG_HOME)).size, 1);
    assert.equal(ddevCalls[0].options.env.DDEV_XDG_CONFIG_HOME.endsWith('/xdg'), true);
    assert.notEqual(ddevCalls[0].options.env.DDEV_XDG_CONFIG_HOME, '/tmp/ambient-ddev-home');
    assert.equal(ddevCalls.every((call) => Object.keys(call.options.env).filter((key) => /^(?:DDEV|COMPOSE)_/i.test(key)).join(',') === 'DDEV_XDG_CONFIG_HOME'), true);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('generated working DDEV runtime stays outside exact HEAD but inside untouched proof', () => {
  const { root } = fixture();
  const generated = join(root, 'web', 'sites', 'default', 'settings.ddev.php');
  mkdirSync(join(generated, '..'), { recursive: true });
  writeFileSync(generated, '<?php // generated locally\n');
  const spawn = (command, args, options) => {
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'describe') {
      const name = generatedDdevName(options.cwd);
      return { status: 0, stdout: JSON.stringify({ raw: { name, approot: options.cwd } }), stderr: '', signal: null };
    }
    if (command === 'ddev') return { status: 0, stdout: 'ok', stderr: '', signal: null };
    throw new Error(`Unexpected mocked command: ${command}`);
  };
  try {
    const stable = runDisposableReproduction({
      captureState: () => emptyState(),
      execute: createRecordedExecutor({ commandLog: [], spawn }),
      projectRoot: root
    });
    assert.equal(stable.valid, true, JSON.stringify(stable.errors));
    assert.equal(stable.source.exactHeadClone, true);
    assert.equal(stable.source.head, git(root, ['rev-parse', 'HEAD']));
    assert.equal(stable.source.tree, git(root, ['rev-parse', 'HEAD^{tree}']));

    const changed = runDisposableReproduction({
      captureState({ target }) {
        if (target === 'disposable' && existsSync(generated)) rmSync(generated);
        return emptyState();
      },
      execute: createRecordedExecutor({ commandLog: [], spawn }),
      projectRoot: root
    });
    assert.equal(changed.valid, false);
    assert.equal(changed.source.exactHeadClone, true);
    assert.equal(changed.workingTargetProof.sourceUnchanged, false);
    assert.equal(changed.workingTargetProof.untouched, false);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('working-target proof binds dirty file bytes even when porcelain status text is unchanged', () => {
  const { root } = fixture();
  const note = join(root, 'maintainer-notes.txt');
  writeFileSync(note, 'committed\n');
  git(root, ['add', 'maintainer-notes.txt']);
  git(root, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '--quiet', '-m', 'notes']);
  writeFileSync(note, 'dirty before\n');
  const commandLog = [];
  const spawn = (command, args, options) => {
    if (command === 'git') return spawnSync(command, args, options);
    if (command === 'ddev' && args[0] === 'describe') {
      const name = generatedDdevName(options.cwd);
      return { status: 0, stdout: JSON.stringify({ raw: { name, approot: options.cwd, primary_url: `https://${name}.ddev.site` } }), stderr: '', signal: null };
    }
    if (command === 'ddev') return { status: 0, stdout: 'ok', stderr: '', signal: null };
    throw new Error(`Unexpected mocked command: ${command}`);
  };
  const execute = createRecordedExecutor({ commandLog, spawn });
  try {
    const report = runDisposableReproduction({
      captureState({ target }) {
        if (target === 'disposable') writeFileSync(note, 'dirty after\n');
        return emptyState();
      },
      execute,
      projectRoot: root
    });

    assert.equal(report.valid, false);
    assert.equal(report.workingTargetProof.sourceUnchanged, false);
    assert.equal(report.workingTargetProof.untouched, false);
    assert.equal(report.workingTargetProof.gitStatusBeforeSha256, report.workingTargetProof.gitStatusAfterSha256);
    assert.notEqual(
      report.workingTargetProof.trackedWorktreeBeforeSha256,
      report.workingTargetProof.trackedWorktreeAfterSha256
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
