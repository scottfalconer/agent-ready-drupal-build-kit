import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, parse, resolve } from 'node:path';
import test from 'node:test';

import {
  createCustomCodeDdevExecutor,
  createCustomCodeExecutionRunner,
  createDisposableCustomCodeWorkspace,
  cleanupDisposableCustomCodeWorkspace,
  customCodeDdevTreeSnapshot,
  customTestMethodId,
  inspectCustomCodeFilesystem,
  inspectCustomCodeQuality
} from '../bin/verify.mjs';
import { PACKET_JSON_LIMITS, parseBoundedJsonText, validatePacket } from '../bin/verify-packet.mjs';

function writeFixture(root, path, contents = '') {
  const absolute = join(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, contents);
}

const TOOL_PACKAGES = [
  { key: 'phpcs', name: 'squizlabs/php_codesniffer', binary: 'bin/phpcs' },
  { key: 'coder', name: 'drupal/coder', binary: '' },
  { key: 'phpstan', name: 'phpstan/phpstan', binary: 'phpstan' },
  { key: 'phpunit', name: 'phpunit/phpunit', binary: 'phpunit' }
];
const TRANSITIVE_TOOL_PACKAGE = { name: 'fixture/tool-runtime', version: '1.0.0', type: 'library' };

function writeComposerToolchain(root, {
  phpcsBinary = true,
  phpstanBinary = true,
  writeComposerJson = true,
  writeLock = true
} = {}) {
  const included = TOOL_PACKAGES.filter((tool) =>
    !((tool.key === 'phpcs' || tool.key === 'coder') && !phpcsBinary) && !(tool.key === 'phpstan' && !phpstanBinary)
  );
  const locked = [];
  const installed = [];
  const repositories = {
    phpcs: ['https://github.com/PHPCSStandards/PHP_CodeSniffer.git', 'https://api.github.com/repos/PHPCSStandards/PHP_CodeSniffer/zipball/'],
    coder: ['https://github.com/pfrenssen/coder.git', 'https://api.github.com/repos/pfrenssen/coder/zipball/'],
    phpstan: ['', 'https://api.github.com/repos/phpstan/phpstan/zipball/'],
    phpunit: ['https://github.com/sebastianbergmann/phpunit.git', 'https://api.github.com/repos/sebastianbergmann/phpunit/zipball/']
  };
  for (const [index, tool] of included.entries()) {
    const reference = String(index + 1).repeat(40).slice(0, 40);
    const [sourceUrl, distPrefix] = repositories[tool.key];
    const dist = { type: 'zip', url: `${distPrefix}${reference}`, reference };
    const record = { name: tool.name, version: '1.0.0', type: tool.key === 'coder' ? 'phpcodesniffer-standard' : 'library', dist };
    if (sourceUrl) record.source = { type: 'git', url: sourceUrl, reference };
    if (tool.binary) record.bin = [tool.binary];
    if (tool.key === 'phpunit') record.require = { [TRANSITIVE_TOOL_PACKAGE.name]: TRANSITIVE_TOOL_PACKAGE.version };
    locked.push(record);
    installed.push({ ...record, 'installation-source': 'dist', 'install-path': `../${tool.name}` });
    writeFixture(root, `vendor/${tool.name}/README.md`, `${tool.name}\n`);
    if (tool.binary) {
      const binaryPath = `vendor/${tool.name}/${tool.binary}`;
      writeFixture(root, binaryPath, `#!/usr/bin/env php\n<?php // ${tool.name}\n`);
      chmodSync(join(root, binaryPath), 0o755);
    }
  }
  const transitiveReference = 'e'.repeat(40);
  const transitive = {
    ...TRANSITIVE_TOOL_PACKAGE,
    dist: {
      type: 'zip',
      url: `https://api.github.com/repos/example/tool-runtime/zipball/${transitiveReference}`,
      reference: transitiveReference
    },
    source: {
      type: 'git',
      url: 'https://github.com/example/tool-runtime.git',
      reference: transitiveReference
    },
    autoload: { 'psr-4': { 'Fixture\\ToolRuntime\\': 'src/' } }
  };
  locked.push(transitive);
  installed.push({ ...structuredClone(transitive), 'installation-source': 'dist', 'install-path': `../${transitive.name}` });
  writeFixture(root, `vendor/${transitive.name}/src/Runtime.php`, '<?php\nnamespace Fixture\\ToolRuntime;\nfinal class Runtime {}\n');
  if (writeComposerJson) {
    writeFixture(root, 'composer.json', `${JSON.stringify({
      name: 'fixture/custom-code-quality',
      type: 'project',
      'require-dev': Object.fromEntries(included.map((record) => [record.name, '1.0.0']))
    })}\n`);
  }
  if (writeLock) writeFixture(root, 'composer.lock', `${JSON.stringify({ 'content-hash': 'a'.repeat(32), packages: [], 'packages-dev': locked })}\n`);
  writeFixture(root, 'vendor/composer/installed.json', `${JSON.stringify({ packages: installed })}\n`);
  writeFixture(root, 'vendor/autoload.php', '<?php\n// generated Composer root autoloader\n');
  // These wrappers are intentionally untrusted and must never be executed.
  writeFixture(root, 'vendor/bin/phpcs', '#!/bin/sh\nexit 99\n');
  writeFixture(root, 'vendor/bin/phpstan', '#!/bin/sh\nexit 99\n');
  writeFixture(root, 'vendor/bin/phpunit', '#!/bin/sh\nexit 99\n');
}

function materializeInstalledToolchain(root, lock, { rootAutoload = 'regular' } = {}) {
  const packages = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])];
  const installed = [];
  for (const record of packages) {
    const tool = TOOL_PACKAGES.find((candidate) => candidate.name === record.name);
    installed.push({ ...structuredClone(record), 'installation-source': 'dist', 'install-path': `../${record.name}` });
    writeFixture(root, `vendor/${record.name}/README.md`, `fresh ${record.name}\n`);
    if (tool?.binary) {
      const binaryPath = `vendor/${record.name}/${tool.binary}`;
      writeFixture(root, binaryPath, `#!/usr/bin/env php\n<?php // freshly installed ${record.name}\n`);
      chmodSync(join(root, binaryPath), 0o755);
    }
  }
  writeFixture(root, 'vendor/composer/installed.json', `${JSON.stringify({ packages: installed })}\n`);
  if (rootAutoload === 'regular') {
    writeFixture(root, 'vendor/autoload.php', '<?php\n// freshly generated Composer root autoloader\n');
  } else if (rootAutoload === 'symlink') {
    symlinkSync('composer/installed.json', join(root, 'vendor/autoload.php'));
  } else if (rootAutoload !== 'missing') {
    throw new Error(`Unsupported root autoload fixture mode: ${rootAutoload}`);
  }
  for (const binary of ['phpcs', 'phpstan', 'phpunit']) writeFixture(root, `vendor/bin/${binary}`, '#!/bin/sh\nexit 99\n');
}

function composerLockForNames(lock, names) {
  const selected = new Set(names);
  return {
    ...structuredClone(lock),
    packages: (lock.packages ?? []).filter((record) => selected.has(record.name)),
    'packages-dev': (lock['packages-dev'] ?? []).filter((record) => selected.has(record.name))
  };
}

function qualityFixture({
  executableSource = false,
  phpcsBinary = true,
  phpstanBinary = true,
  phpstanConfig = true
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'custom-code-quality-'));
  writeFixture(root, '.ddev/config.yaml', 'name: custom-quality\ntype: drupal11\ndocroot: web\n');
  writeFixture(root, 'web/modules/custom/catalog/catalog.info.yml', 'name: Catalog\ntype: module\n');
  writeFixture(
    root,
    executableSource
      ? 'web/modules/custom/catalog/src/Controller/CatalogController.php'
      : 'web/modules/custom/catalog/src/CatalogService.php',
    executableSource
      ? '<?php\nnamespace Drupal\\catalog\\Controller;\nfinal class CatalogController {}\n'
      : '<?php\nnamespace Drupal\\catalog;\nfinal class CatalogService {}\n'
  );
  writeFixture(
    root,
    'web/modules/custom/catalog/tests/src/Kernel/CatalogTest.php',
    '<?php\nnamespace Drupal\\Tests\\catalog\\Kernel;\nfinal class CatalogTest {\n  public function testCatalogRoute() {}\n}\n'
  );
  writeFixture(root, 'phpunit.xml', '<phpunit/>\n');
  writeComposerToolchain(root, { phpcsBinary, phpstanBinary });
  if (phpstanConfig) writeFixture(root, 'phpstan.neon', 'parameters:\n  level: 6\n');
  const inventory = inspectCustomCodeFilesystem(root);
  assert.equal(inventory.completed, true, inventory.errors.join('\n'));
  assert.equal(inventory.schemaVersion, 'public-kit.custom-code-inventory.2');
  const testFile = inventory.tests.find((candidate) => candidate.path.endsWith('CatalogTest.php'));
  const method = testFile.testMethods.find((candidate) => candidate.methodName === 'testCatalogRoute');
  const review = {
    capabilities: [{
      extension: 'catalog',
      loadBearing: true,
      sourceSurfaceIds: inventory.sourceFiles
        .filter((source) => source.extension === 'catalog')
        .flatMap((source) => source.surfaces.map((surface) => surface.id)),
      acceptanceCriteria: [
        { id: 'AC-CATALOG-01', criterion: 'Route works.' },
        { id: 'AC-CATALOG-02', criterion: 'Route remains accessible.' }
      ]
    }],
    testCoverage: ['AC-CATALOG-01', 'AC-CATALOG-02'].map((acceptanceCriterionId) => ({
      acceptanceCriterionId,
      runner: 'phpunit',
      testFileId: testFile.id,
      className: method.className,
      methodName: method.methodName,
      testMethodId: method.id
    }))
  };
  return { inventory, method, review, root, testFile };
}

function rawResult(stdout = '', exitCode = 0, stderr = '') {
  return { ok: exitCode === 0, exitCode, stdout, stderr, spawnError: false, timedOut: false };
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function initializeGitFixture(root) {
  for (const args of [
    ['init', '-q'],
    ['config', 'user.email', 'fixture@example.com'],
    ['config', 'user.name', 'Fixture'],
    ['add', '.'],
    ['commit', '-qm', 'fixture']
  ]) {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  }
}

function disposableWorkspaceHostSpawn({ ddevCalls, hostCalls, validateExitCode = 0 }) {
  return (command, args, options) => {
    hostCalls.push({ command, args: [...args], cwd: options.cwd });
    if (command !== 'ddev') return spawnSync(command, args, options);
    ddevCalls.push({ args: [...args], cwd: options.cwd, env: options.env });
    if (args[0] === 'start') {
      writeFixture(options.cwd, '.ddev/web-entrypoint.d/README.txt', 'DDEV-generated runtime scaffold.\n');
      return { status: 0, stdout: '', stderr: '' };
    }
    if (args[0] === 'delete') return { status: 0, stdout: '', stderr: '' };
    if (args[0] === 'describe') {
      const config = readFileSync(join(options.cwd, '.ddev/config.yaml'), 'utf8');
      const projectName = JSON.parse(config.match(/^name:\s*(.+)$/m)[1]);
      return { status: 0, stdout: JSON.stringify({ raw: {
        name: projectName,
        approot: options.cwd,
        primary_url: `http://${projectName}.ddev.site:8800`
      } }), stderr: '' };
    }
    if (args[0] === 'exec') {
      const separator = args.indexOf('--');
      const inner = args.slice(separator + 1);
      if (inner[0] !== 'composer') return { status: 1, stdout: '', stderr: 'unexpected fake ddev exec command' };
      const workingDirectory = inner.find((argument) => argument.startsWith('--working-dir='))?.slice('--working-dir='.length) ?? '';
      const composerCommand = inner.find((argument) => ['install', 'update', 'validate'].includes(argument));
      if (!workingDirectory && composerCommand === 'validate') {
        return {
          status: validateExitCode,
          stdout: validateExitCode === 0 ? 'composer inputs are synchronized' : '',
          stderr: validateExitCode === 0 ? '' : 'composer.lock is not up to date with composer.json'
        };
      }
      if (!workingDirectory && composerCommand === 'install') {
        materializeInstalledToolchain(options.cwd, JSON.parse(readFileSync(join(options.cwd, 'composer.lock'), 'utf8')));
        return { status: 0, stdout: 'project dependencies installed', stderr: '' };
      }
      const auditRoot = join(options.cwd, workingDirectory);
      if (composerCommand === 'update' && inner.includes('--no-install')) {
        const sourceLock = JSON.parse(readFileSync(join(options.cwd, 'composer.lock'), 'utf8'));
        const auditComposer = JSON.parse(readFileSync(join(auditRoot, 'composer.json'), 'utf8'));
        writeFixture(auditRoot, 'composer.lock', `${JSON.stringify(composerLockForNames(sourceLock, Object.keys(auditComposer.require ?? {})))}\n`);
        return { status: 0, stdout: 'audit lock resolved', stderr: '' };
      }
      if (composerCommand === 'install') {
        materializeInstalledToolchain(auditRoot, JSON.parse(readFileSync(join(auditRoot, 'composer.lock'), 'utf8')));
        return { status: 0, stdout: 'audit dependencies installed', stderr: '' };
      }
    }
    return { status: 1, stdout: '', stderr: 'unexpected fake ddev command' };
  };
}

function fakeQualityExecutor(root, options = {}) {
  const calls = [];
  const listFormat = options.listFormat ?? 'phpunit9';
  const junitMode = options.junitMode ?? 'pass';
  const standardOutput = options.standardOutput ?? 'The installed coding standards are Drupal and DrupalPractice';
  const makeExecutor = (executionRoot, workspace) => ({ argv, env, timeoutMs, outputLimitBytes }) => {
    calls.push({ argv: [...argv], env: { ...env }, timeoutMs, outputLimitBytes, workspace });
    const isBinary = (path) => argv[0] === path || argv[0].endsWith(`/${path}`);
    const auditPrefix = (path) => argv[0].slice(0, -path.length);
    if (argv[0] === 'php' && argv[1] === '--version') return rawResult('PHP 8.3.9\n');
    if (argv[0] === 'php' && argv[1] === '-l') return rawResult(`No syntax errors detected in ${argv[2]}\n`);
    if (isBinary('vendor/squizlabs/php_codesniffer/bin/phpcs') && argv.includes('--version')) {
      if (options.mutatePackageTree && workspace === 'disposable') {
        writeFixture(executionRoot, `${auditPrefix('vendor/squizlabs/php_codesniffer/bin/phpcs')}vendor/squizlabs/php_codesniffer/README.md`, 'mutated during execution\n');
      }
      if (options.mutateClosureTree && workspace === 'disposable') {
        writeFixture(executionRoot, `${auditPrefix('vendor/squizlabs/php_codesniffer/bin/phpcs')}vendor/${TRANSITIVE_TOOL_PACKAGE.name}/README.md`, 'mutated transitive dependency\n');
      }
      if (options.mutateRootAutoload && workspace === 'disposable') {
        writeFixture(executionRoot, `${auditPrefix('vendor/squizlabs/php_codesniffer/bin/phpcs')}vendor/autoload.php`, '<?php\n// mutated Composer root autoloader\n');
      }
      return rawResult('PHP_CodeSniffer version 3.11.0\n');
    }
    if (isBinary('vendor/squizlabs/php_codesniffer/bin/phpcs') && argv.includes('-i')) return rawResult(`${standardOutput}\n`);
    if (isBinary('vendor/squizlabs/php_codesniffer/bin/phpcs') && argv.includes('--report=json')) {
      if (options.phpcsInvalidReport) return rawResult(JSON.stringify(options.phpcsInvalidReport));
      if (options.phpcsCleanOmitFiles) {
        return rawResult(JSON.stringify({ totals: { errors: 0, warnings: 0, fixable: 0 }, files: {} }));
      }
      const paths = argv.slice(argv.indexOf('--report=json') + 1);
      const files = Object.fromEntries(paths.map((path) => [path, { errors: 0, warnings: 0, messages: [] }]));
      if (options.phpcsNegativeTotals) {
        return rawResult(JSON.stringify({ totals: { errors: -1, warnings: 0, fixable: 0 }, files }));
      }
      const violationPath = paths.find((path) => path.endsWith('CatalogService.php')) ?? paths[0];
      if (options.phpcsViolation && violationPath) {
        files[violationPath] = { errors: 1, warnings: 0, messages: [{ line: 3, column: 1, type: 'ERROR', severity: 5, source: 'Drupal.Commenting.DocComment.Missing', message: 'Missing doc comment.', fixable: false }] };
        return rawResult(JSON.stringify({ totals: { errors: 1, warnings: 0, fixable: 0 }, files }), 1);
      }
      return rawResult(JSON.stringify({ totals: { errors: 0, warnings: 0, fixable: 0 }, files }));
    }
    if (isBinary('vendor/phpstan/phpstan/phpstan') && argv.includes('--version')) return rawResult('PHPStan - PHP Static Analysis Tool 2.1\n');
    if (isBinary('vendor/phpstan/phpstan/phpstan') && argv.includes('analyse')) {
      if (options.mutateAnalyzerSource) {
        writeFixture(executionRoot, 'web/modules/custom/catalog/src/CatalogService.php', '<?php\n// analyzer mutation\n');
      }
      if (options.mutateWorkingTarget) {
        writeFixture(root, 'web/modules/custom/catalog/src/CatalogService.php', '<?php\n// working target mutation\n');
      }
      if (options.phpstanInvalidReport) return rawResult(JSON.stringify(options.phpstanInvalidReport));
      if (options.phpstanNegativeTotals) return rawResult(JSON.stringify({ totals: { errors: -1, file_errors: 0 }, files: {}, errors: [] }));
      return rawResult(JSON.stringify({ totals: { errors: 0, file_errors: 0 }, files: {}, errors: [] }));
    }
    if (isBinary('vendor/phpunit/phpunit/phpunit') && argv.includes('--version')) return rawResult('PHPUnit 11.5.0\n');
    if (argv[0] === 'printenv') return rawResult('mysql\n');
    if (argv.includes('--list-tests-xml')) {
      const outputPath = argv[argv.indexOf('--list-tests-xml') + 1];
      const xml = options.malformedListXml
        ? '<tests><test name="broken"></testsuites>'
        : listFormat === 'phpunit9'
        ? '<tests><testCaseClass name="Drupal\\Tests\\catalog\\Kernel\\CatalogTest"><testCaseMethod name="testCatalogRoute"/></testCaseClass></tests>'
        : listFormat === 'phpunit10'
          ? '<testsuites><testsuite><testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute"/></testsuite></testsuites>'
          : '<tests><test name="Drupal\\Tests\\catalog\\Kernel\\CatalogTest::testCatalogRoute"/></tests>';
      writeFixture(executionRoot, outputPath, xml);
      return rawResult('');
    }
    if (argv.includes('--log-junit')) {
      const outputPath = argv[argv.indexOf('--log-junit') + 1];
      let cases = listFormat === 'phpunit9'
        ? '<testcase class="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute" assertions="1"/>'
        : listFormat === 'phpunit10'
          ? '<testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute" assertions="1"/>'
          : '<testcase name="Drupal\\Tests\\catalog\\Kernel\\CatalogTest::testCatalogRoute" assertions="1"/>';
      let attributes = 'tests="1" assertions="1" failures="0" errors="0" skipped="0"';
      let status = 0;
      if (junitMode === 'fail') {
        cases = '<testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute" assertions="1"><failure/></testcase>';
        attributes = 'tests="1" assertions="1" failures="1" errors="0" skipped="0"';
        status = 1;
      } else if (junitMode === 'skip') {
        cases = '<testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute" assertions="0"><skipped/></testcase>';
        attributes = 'tests="1" assertions="0" failures="0" errors="0" skipped="1"';
        status = 1;
      } else if (junitMode === 'no-assertions') {
        cases = '<testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute" assertions="0"/>';
        attributes = 'tests="1" assertions="0" failures="0" errors="0" skipped="0"';
      } else if (junitMode === 'extra') {
        cases += '<testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testOther" assertions="1"/>';
        attributes = 'tests="2" assertions="2" failures="0" errors="0" skipped="0"';
      } else if (junitMode === 'zero') {
        cases = '';
        attributes = 'tests="0" assertions="0" failures="0" errors="0" skipped="0"';
      } else if (junitMode === 'data-overflow') {
        cases = Array.from({ length: 257 }, (_, index) => `<testcase classname="Drupal\\Tests\\catalog\\Kernel\\CatalogTest" name="testCatalogRoute with data set #${index}" assertions="1"/>`).join('');
        attributes = 'tests="257" assertions="257" failures="0" errors="0" skipped="0"';
      } else if (junitMode === 'missing-totals') {
        attributes = 'tests="1" assertions="1" failures="0" errors="0"';
      } else if (junitMode === 'negative-totals') {
        attributes = 'tests="1" assertions="1" failures="0" errors="0" skipped="-1"';
      } else if (junitMode === 'inconsistent-totals') {
        attributes = 'tests="2" assertions="1" failures="0" errors="0" skipped="0"';
      }
      const junit = junitMode === 'malformed-xml'
        ? `<testsuites><testsuite ${attributes}>${cases}</testsuites>`
        : `<testsuites><testsuite ${attributes}>${cases}</testsuite></testsuites>`;
      writeFixture(executionRoot, outputPath, junit);
      if (options.mutateDisposablePhpunit && workspace === 'disposable') {
        writeFixture(executionRoot, `${auditPrefix('vendor/phpunit/phpunit/phpunit')}vendor/phpunit/phpunit/README.md`, 'mutated during focused execution\n');
      }
      return rawResult('', status);
    }
    throw new Error(`Unexpected fake command: ${argv.join(' ')}`);
  };
  const executor = makeExecutor(root, 'working-target');
  const disposableWorkspaceFactory = ({ requirements } = {}) => {
    const ownerRoot = mkdtempSync(join(tmpdir(), 'custom-code-disposable-fixture-'));
    const projectRoot = join(ownerRoot, 'project');
    cpSync(root, projectRoot, { recursive: true });
    const auditRoot = join(projectRoot, '.agent-ready-audit-fixture');
    mkdirSync(auditRoot);
    cpSync(join(root, 'composer.json'), join(auditRoot, 'composer.json'));
    const sourceLock = JSON.parse(readFileSync(join(root, 'composer.lock'), 'utf8'));
    const auditLock = composerLockForNames(sourceLock, requirements.closure.map((record) => record.name));
    writeFixture(auditRoot, 'composer.lock', `${JSON.stringify(auditLock)}\n`);
    materializeInstalledToolchain(auditRoot, auditLock, { rootAutoload: options.rootAutoload ?? 'regular' });
    const runtimeConfig = readFileSync(join(projectRoot, '.ddev/config.yaml'));
    const cloneExecutor = makeExecutor(projectRoot, 'disposable');
    return {
      failures: [],
      workspace: {
        auditRoot,
        baseUrl: 'https://custom-quality-disposable.ddev.site',
        exactHead: true,
        executor: cloneExecutor,
        freshDatabase: true,
        identity: { head: 'a'.repeat(40), projectName: 'custom-quality-disposable', workspaceId: 'DISPOSABLE-fixture' },
        projectRoot,
        runtimeProvenance: {
          configSha256: digest(runtimeConfig),
          databaseFamily: 'mysql',
          ddevTreeFingerprint: customCodeDdevTreeSnapshot(projectRoot).fingerprint,
          specSha256: `sha256:${'4'.repeat(64)}`
        },
        setupCommandResultHashes: [`sha256:${'1'.repeat(64)}`],
        cleanup() {
          rmSync(ownerRoot, { force: true, recursive: true });
          return options.cleanupMismatch
            ? { completed: false, commandResultHashes: [], failures: [{ code: 'stale_test_binding', check: 'phpunit-isolation-cleanup', subjectId: 'DISPOSABLE-fixture', message: 'Identity mismatch.' }] }
            : { completed: true, commandResultHashes: [`sha256:${'2'.repeat(64)}`, `sha256:${'3'.repeat(64)}`], failures: [] };
        }
      }
    };
  };
  executor.disposableWorkspaceFactory = disposableWorkspaceFactory;
  return { calls, disposableWorkspaceFactory, executor };
}

test('TESTMETHOD identity is class-aware and stable', () => {
  const { inventory, method, root, testFile } = qualityFixture();
  assert.equal(method.id, customTestMethodId('catalog', testFile.path, method.className, method.methodName));
  assert.match(method.id, /^TESTMETHOD-[a-f0-9]{16}$/);
  assert.notEqual(method.id, customTestMethodId('catalog', testFile.path, `${method.className}Other`, method.methodName));
  assert.equal(inventory.tests[0].testMethods.length, 1);
  rmSync(root, { recursive: true, force: true });
});

test('DDEV executor uses direct host/container argv and never enables a shell', () => {
  const { root } = qualityFixture();
  const hostCalls = [];
  const host = createCustomCodeDdevExecutor(root, {
    PATH: process.env.PATH,
    COMPOSE_FILE: '/tmp/ambient-compose.yaml',
    DDEV_PROJECT: 'ambient-project',
    IS_DDEV_PROJECT: 'false'
  }, {
    containerMarker: false,
    spawnSync(command, args, options) {
      hostCalls.push({ command, args, options });
      return { status: 0, stdout: 'ok', stderr: '' };
    }
  });
  assert.equal(host({ argv: ['php', '-v'], env: { SIMPLETEST_DB: 'secret-dsn' }, timeoutMs: 1000, outputLimitBytes: 1024 }).ok, true);
  assert.equal(hostCalls[0].command, 'ddev');
  assert.deepEqual(hostCalls[0].args.slice(0, 6), ['exec', '--raw', '--dir', '/var/www/html', '--', 'env']);
  assert.ok(hostCalls[0].args.includes('SIMPLETEST_DB=secret-dsn'));
  assert.equal(hostCalls[0].options.shell, false);
  assert.equal(Object.hasOwn(hostCalls[0].options.env, 'DDEV_PROJECT'), false);
  assert.equal(Object.hasOwn(hostCalls[0].options.env, 'IS_DDEV_PROJECT'), false);
  assert.equal(Object.hasOwn(hostCalls[0].options.env, 'COMPOSE_FILE'), false);

  const containerCalls = [];
  const containerEnv = {
    PATH: process.env.PATH,
    IS_DDEV_PROJECT: 'true',
    DDEV_APPROOT: root,
    DDEV_PROJECT: 'custom-quality',
    DDEV_DOCROOT: 'web'
  };
  const forgedHostCalls = [];
  const forgedHost = createCustomCodeDdevExecutor(root, containerEnv, {
    containerMarker: false,
    spawnSync(command, args, options) {
      forgedHostCalls.push({ command, args, options });
      return { status: 0, stdout: 'ok', stderr: '' };
    }
  });
  forgedHost({ argv: ['php', '-v'], env: {}, timeoutMs: 1000, outputLimitBytes: 1024 });
  assert.equal(forgedHostCalls[0].command, 'ddev');
  assert.deepEqual(forgedHostCalls[0].args.slice(0, 5), ['exec', '--raw', '--dir', '/var/www/html', '--']);

  const container = createCustomCodeDdevExecutor(root, containerEnv, {
    containerMarker: true,
    spawnSync(command, args, options) {
      containerCalls.push({ command, args, options });
      return { status: 0, stdout: 'ok', stderr: '' };
    }
  });
  container({ argv: ['php', '-v'], env: {}, timeoutMs: 1000, outputLimitBytes: 1024 });
  assert.equal(containerCalls[0].command, 'php');
  assert.deepEqual(containerCalls[0].args, ['-v']);
  assert.equal(containerCalls[0].options.shell, false);
  rmSync(root, { recursive: true, force: true });
});

test('shared execution runner clamps deadlines, caps output, and reports env keys without values or temp paths', () => {
  let current = 0;
  let observedTimeout = 0;
  const runner = createCustomCodeExecutionRunner(({ timeoutMs }) => {
    observedTimeout = timeoutMs;
    return rawResult('small');
  }, { now: () => current, deadlineMs: 900_000, outputLimit: 8 });
  current = 850_000;
  const result = runner.run({
    argv: ['/private/project/.ddev/.agent-ready-custom-code-random/junit.xml'],
    env: { SIMPLETEST_DB: 'do-not-report' },
    timeoutMs: 180_000,
    outputLimitBytes: 8
  });
  assert.equal(observedTimeout, 20_000);
  assert.deepEqual(result.record.envKeys, ['SIMPLETEST_DB']);
  assert.equal(JSON.stringify(result.record).includes('do-not-report'), false);
  assert.equal(result.record.argv[0], '.ddev/<custom-code-audit>/junit.xml');
  const over = runner.run({ argv: ['php'], env: {}, timeoutMs: 1, outputLimitBytes: 3 });
  assert.equal(over.failureCode, 'invalid_output');
  const commandBound = createCustomCodeExecutionRunner(() => rawResult(''), { now: () => 0, commandLimit: 1 });
  assert.equal(commandBound.run({ argv: ['php'], env: {}, timeoutMs: 1, outputLimitBytes: 1 }).ok, true);
  assert.equal(commandBound.run({ argv: ['php'], env: {}, timeoutMs: 1, outputLimitBytes: 1 }).failureCode, 'input_limit_exceeded');
});

test('packet JSON parser rejects bytes, nesting, collection fanout, and oversized strings at verifier caps', () => {
  assert.throws(
    () => parseBoundedJsonText(`"${'x'.repeat(PACKET_JSON_LIMITS.fileBytes)}"`, 'oversized'),
    /limit/
  );
  let nested = 'null';
  for (let index = 0; index < PACKET_JSON_LIMITS.depth + 2; index += 1) nested = `{"x":${nested}}`;
  assert.throws(() => parseBoundedJsonText(nested, 'nested'), /nested/);
  assert.throws(
    () => parseBoundedJsonText(JSON.stringify(Array(PACKET_JSON_LIMITS.collectionEntries + 1).fill(0)), 'fanout'),
    /array/
  );
  assert.throws(
    () => parseBoundedJsonText(JSON.stringify('x'.repeat(PACKET_JSON_LIMITS.stringBytes + 1)), 'string'),
    /string/
  );
});

test('packet verifier rejects an oversized JSON file before semantic processing', async () => {
  const root = mkdtempSync(join(tmpdir(), 'bounded-packet-'));
  const packetDir = join(root, 'review-packet');
  const gates = JSON.parse(readFileSync(resolve('gates.json'), 'utf8'));
  mkdirSync(packetDir);
  for (const file of gates.reviewPacketFiles) {
    const parsed = parse(file);
    cpSync(resolve('templates', `${parsed.name}.template${parsed.ext}`), join(packetDir, file));
  }
  writeFileSync(join(packetDir, 'route-matrix.json'), `"${'x'.repeat(PACKET_JSON_LIMITS.fileBytes)}"`);
  const report = await validatePacket({ packetDir });
  assert.ok(report.errors.some((error) => /route-matrix\.json.*bounded regular JSON file|route-matrix\.json.*exceeds/.test(error)));
  rmSync(root, { recursive: true, force: true });
});

test('packet evidence JSON shares one aggregate budget while repeated references use the cache', async () => {
  const root = mkdtempSync(join(tmpdir(), 'bounded-packet-evidence-'));
  const packetDir = join(root, 'review-packet');
  const evidenceDir = join(packetDir, 'evidence', 'independent-verification');
  const gates = JSON.parse(readFileSync(resolve('gates.json'), 'utf8'));
  mkdirSync(packetDir);
  mkdirSync(evidenceDir, { recursive: true });
  for (const file of gates.reviewPacketFiles) {
    const parsed = parse(file);
    cpSync(resolve('templates', `${parsed.name}.template${parsed.ext}`), join(packetDir, file));
  }

  const checkedAt = new Date().toISOString();
  const targetBaseUrl = 'https://packet-evidence-budget.example';
  const gateIds = {
    accessibility: 'G-A11Y-01',
    architecture: 'G-COMPOSITION-01',
    behavior: 'G-BROWSER-01',
    content: 'G-CONTENT-01',
    editor: 'G-EDITOR-01',
    media: 'G-PARITY-01',
    packet: 'G-VERIFY-01',
    route: 'G-ROUTE-01',
    security_privacy: 'G-PRIVACY-01',
    seo: 'G-SEO-01',
    visual: 'G-BROWSER-02'
  };
  const claims = Object.entries(gateIds).map(([gate, gateId]) => ({
    claimId: `${gate}-checked`,
    claim: `${gate} evidence was independently checked.`,
    gate,
    gateId,
    builderEvidence: [],
    falsificationChecks: [`Falsified ${gate} against the target.`],
    verifierEvidence: ['shared.json'],
    status: 'pass',
    failureEvidence: [],
    nextFix: ''
  }));
  const independentPath = join(packetDir, 'independent-verification.json');
  const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
  independent.checkedAt = checkedAt;
  independent.site = targetBaseUrl;
  independent.target = { ...independent.target, baseUrl: targetBaseUrl };
  independent.verifier = {
    ...independent.verifier,
    nameOrRole: 'fresh independent verifier',
    runtimeOrTool: 'bounded evidence test',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    builderSummaryExcluded: true,
    liveSiteInspected: true,
    packetInspected: true,
    independenceDegradedReason: ''
  };
  independent.completionClaims = claims;
  independent.summary = {
    failedClaimCount: 0,
    blockedClaimCount: 0,
    highestRiskFailures: [],
    verdict: 'pass',
    notes: ''
  };
  writeFileSync(independentPath, `${JSON.stringify(independent)}\n`);

  const largeEvidence = {
    schemaVersion: 'public-kit.independent-claim-evidence.1',
    targetBaseUrl,
    checkedAt,
    claims: claims.map((claim) => ({
      claimId: claim.claimId,
      gate: claim.gate,
      gateId: claim.gateId,
      checks: [{
        name: `${claim.gate} falsification`,
        method: 'live target and packet inspection',
        result: 'pass',
        observation: `${claim.gate} matched the inspected target.`
      }]
    })),
    padding: Array.from({ length: 6_500 }, () => 'x'.repeat(950))
  };
  const largeEvidenceText = `${JSON.stringify(largeEvidence)}\n`;
  assert.ok(Buffer.byteLength(largeEvidenceText) < PACKET_JSON_LIMITS.fileBytes);
  writeFileSync(join(evidenceDir, 'shared.json'), largeEvidenceText);

  const cachedReport = await validatePacket({ packetDir });
  assert.equal(cachedReport.errors.some((error) => /aggregate limit/.test(error)), false);

  for (const [index, claim] of claims.entries()) {
    const reference = `unique-${index}.json`;
    claim.verifierEvidence = [reference];
    writeFileSync(join(evidenceDir, reference), largeEvidenceText);
  }
  writeFileSync(independentPath, `${JSON.stringify(independent)}\n`);
  const overBudgetReport = await validatePacket({ packetDir });
  assert.ok(overBudgetReport.errors.some((error) => /packet JSON exceeds the .*aggregate limit/.test(error)));
  rmSync(root, { recursive: true, force: true });
});

test('cleanup refuses a disposable DDEV identity mismatch before delete', () => {
  const ownerRoot = mkdtempSync(join(tmpdir(), 'agent-ready-custom-code-'));
  const projectRoot = join(ownerRoot, 'project');
  mkdirSync(join(projectRoot, '.ddev'), { recursive: true });
  const verifierConfig = 'name: "owned-project"\ntype: "drupal11"\ndocroot: "web"\n';
  writeFixture(projectRoot, '.ddev/config.yaml', verifierConfig);
  const identity = {
    head: 'a'.repeat(40),
    projectName: 'owned-project',
    schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
    tokenSha256: `sha256:${'b'.repeat(64)}`,
    workspaceId: 'DISPOSABLE-owned'
  };
  const markerPath = join(ownerRoot, 'identity.json');
  writeFileSync(markerPath, JSON.stringify(identity));
  const calls = [];
  const hostExecutor = ({ argv }) => {
    calls.push(argv);
    return rawResult(JSON.stringify({ raw: { name: 'different-project', approot: projectRoot, primary_url: 'https://different-project.ddev.site' } }));
  };
  const runner = createCustomCodeExecutionRunner(hostExecutor);
  const result = cleanupDisposableCustomCodeWorkspace({
    hostExecutor,
    identity,
    markerPath,
    ownerRoot,
    projectRoot,
    runtimeProvenance: { configSha256: digest(verifierConfig) },
    tempParent: tmpdir()
  }, runner);
  assert.equal(result.completed, false);
  assert.equal(calls.length, 1);
  assert.equal(calls.some((argv) => argv.includes('delete')), false);
  assert.equal(existsSync(ownerRoot), true);
  rmSync(ownerRoot, { recursive: true, force: true });
});

test('cleanup rejects unsafe DDEV configuration before describe or delete', () => {
  const ownerRoot = mkdtempSync(join(tmpdir(), 'agent-ready-custom-code-'));
  const projectRoot = join(ownerRoot, 'project');
  const verifierConfig = 'name: "owned-project"\ntype: "drupal11"\ndocroot: "web"\n';
  writeFixture(projectRoot, '.ddev/config.yaml', verifierConfig);
  writeFixture(projectRoot, '.ddev/config.hooks.yaml', 'hooks:\n  pre-delete:\n    - exec-host: "touch /tmp/unsafe"\n');
  const identity = {
    head: 'a'.repeat(40),
    projectName: 'owned-project',
    schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
    tokenSha256: `sha256:${'b'.repeat(64)}`,
    workspaceId: 'DISPOSABLE-unsafe-cleanup'
  };
  const markerPath = join(ownerRoot, 'identity.json');
  writeFileSync(markerPath, JSON.stringify(identity));
  const calls = [];
  const hostExecutor = ({ argv }) => { calls.push(argv); return rawResult(''); };
  const runner = createCustomCodeExecutionRunner(hostExecutor);
  const result = cleanupDisposableCustomCodeWorkspace({
    hostExecutor,
    identity,
    markerPath,
    ownerRoot,
    projectRoot,
    runtimeProvenance: { configSha256: digest(verifierConfig) },
    tempParent: tmpdir()
  }, runner);
  assert.equal(result.completed, false);
  assert.equal(calls.length, 0);
  assert.equal(existsSync(ownerRoot), true);
  rmSync(ownerRoot, { recursive: true, force: true });
});

test('cleanup refuses verifier-owned config drift before describe or delete', () => {
  const ownerRoot = mkdtempSync(join(tmpdir(), 'agent-ready-custom-code-'));
  const projectRoot = join(ownerRoot, 'project');
  const verifierConfig = 'name: "owned-project"\ntype: "drupal11"\ndocroot: "web"\nproject_tld: "ddev.site"\nxdebug_enabled: false\n';
  writeFixture(projectRoot, '.ddev/config.yaml', verifierConfig);
  writeFixture(projectRoot, 'web/index.php', '<?php\n');
  const identity = {
    head: 'a'.repeat(40),
    projectName: 'owned-project',
    schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
    tokenSha256: `sha256:${'b'.repeat(64)}`,
    workspaceId: 'DISPOSABLE-config-changed'
  };
  const markerPath = join(ownerRoot, 'identity.json');
  writeFileSync(markerPath, JSON.stringify(identity));
  writeFileSync(join(projectRoot, '.ddev/config.yaml'), verifierConfig.replace('owned-project', 'ambiguous-user-project'));
  const calls = [];
  const hostExecutor = ({ argv }) => {
    calls.push(argv);
    return rawResult('', 1, 'project state unavailable');
  };
  const runner = createCustomCodeExecutionRunner(hostExecutor);
  const result = cleanupDisposableCustomCodeWorkspace({
    hostExecutor,
    identity,
    markerPath,
    ownerRoot,
    projectRoot,
    runtimeProvenance: { configSha256: digest(verifierConfig) },
    tempParent: tmpdir()
  }, runner);
  assert.equal(result.completed, false);
  assert.deepEqual(calls, []);
  assert.equal(existsSync(ownerRoot), true);
  rmSync(ownerRoot, { recursive: true, force: true });
});

test('cleanup rejects a DDEV runtime-tree mutation before describe or delete', () => {
  const ownerRoot = mkdtempSync(join(tmpdir(), 'agent-ready-custom-code-'));
  const projectRoot = join(ownerRoot, 'project');
  const verifierConfig = 'name: "owned-project"\ntype: "drupal11"\ndocroot: "web"\n';
  writeFixture(projectRoot, '.ddev/config.yaml', verifierConfig);
  writeFixture(projectRoot, '.ddev/web-entrypoint.d/README.txt', 'DDEV-generated runtime scaffold.\n');
  const identity = {
    head: 'a'.repeat(40),
    projectName: 'owned-project',
    schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
    tokenSha256: `sha256:${'b'.repeat(64)}`,
    workspaceId: 'DISPOSABLE-runtime-tree-drift'
  };
  const markerPath = join(ownerRoot, 'identity.json');
  writeFileSync(markerPath, JSON.stringify(identity));
  const runtimeTree = customCodeDdevTreeSnapshot(projectRoot);
  const calls = [];
  const hostExecutor = ({ argv }) => {
    calls.push(argv);
    return rawResult('');
  };
  const runner = createCustomCodeExecutionRunner(hostExecutor);
  writeFixture(projectRoot, '.ddev/web-entrypoint.d/10-active.sh', '#!/bin/sh\nexit 0\n');
  const result = cleanupDisposableCustomCodeWorkspace({
    hostExecutor,
    identity,
    markerPath,
    ownerRoot,
    projectRoot,
    runtimeProvenance: {
      configSha256: digest(verifierConfig),
      ddevTreeFingerprint: runtimeTree.fingerprint
    },
    tempParent: tmpdir()
  }, runner);
  assert.equal(result.completed, false);
  assert.match(result.failures[0]?.message ?? '', /runtime tree changed before cleanup/i);
  assert.deepEqual(calls, []);
  assert.equal(existsSync(ownerRoot), true);
  rmSync(ownerRoot, { recursive: true, force: true });
});

test('disposable workspace factory clones exact HEAD, owns a distinct DDEV identity, and cleans only that identity', () => {
  const fixture = qualityFixture();
  writeFixture(fixture.root, '.ddev/config.yaml', [
    'name: custom-quality',
    'type: drupal11',
    'docroot: web',
    'webimage: attacker/example:latest',
    'web_environment: ["PATH=/tmp/attacker"]',
    'web_extra_daemons: [{name: attacker, command: "touch /tmp/owned", directory: /tmp}]',
    ''
  ].join('\n'));
  for (const path of [
    'vendor/squizlabs/php_codesniffer/bin/phpcs',
    'vendor/phpstan/phpstan/phpstan',
    'vendor/phpunit/phpunit/phpunit'
  ]) {
    writeFixture(fixture.root, path, '#!/bin/sh\necho hostile-direct-package-stub\nexit 97\n');
    chmodSync(join(fixture.root, path), 0o755);
  }
  initializeGitFixture(fixture.root);
  const ddevCalls = [];
  const hostCalls = [];
  const hostSpawnSync = disposableWorkspaceHostSpawn({ ddevCalls, hostCalls });
  const runner = createCustomCodeExecutionRunner(() => { throw new Error('working target executor must not run'); });
  const created = createDisposableCustomCodeWorkspace(fixture.root, fixture.inventory, runner, {
    ...process.env,
    COMPOSE_FILE: '/tmp/ambient-compose.yaml',
    DDEV_PROJECT: 'working-target',
    IS_DDEV_PROJECT: 'false'
  }, { containerMarker: false, hostSpawnSync });
  assert.deepEqual(created.failures, []);
  assert.notEqual(created.workspace.projectRoot, fixture.root);
  assert.equal(created.workspace.exactHead, true);
  assert.equal(created.workspace.freshDatabase, true);
  assert.equal(created.workspace.baseUrl, `http://${created.workspace.identity.projectName}.ddev.site:8800`);
  assert.match(created.workspace.runtimeProvenance.ddevTreeFingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(created.workspace.auditRoot, created.workspace.projectRoot);
  const verifierConfig = readFileSync(join(created.workspace.projectRoot, '.ddev/config.yaml'), 'utf8');
  assert.doesNotMatch(verifierConfig, /webimage|web_environment|web_extra_daemons|attacker/);
  assert.equal(digest(verifierConfig), created.workspace.runtimeProvenance.configSha256);
  const auditComposer = JSON.parse(readFileSync(join(created.workspace.auditRoot, 'composer.json'), 'utf8'));
  assert.equal(auditComposer.require[TRANSITIVE_TOOL_PACKAGE.name], TRANSITIVE_TOOL_PACKAGE.version);
  assert.doesNotMatch(readFileSync(join(created.workspace.auditRoot, 'vendor/phpunit/phpunit/phpunit'), 'utf8'), /hostile-direct-package-stub/);
  assert.match(readFileSync(join(fixture.root, 'vendor/phpunit/phpunit/phpunit'), 'utf8'), /hostile-direct-package-stub/);
  assert.equal(hostCalls.some((call) => call.command === 'cp'), false);
  assert.ok(ddevCalls.some((call) =>
    call.args.includes('composer') && call.args.includes('validate') && call.args.includes('--check-lock') &&
    call.args.includes('--no-check-publish') && call.args.includes('--no-plugins') && call.args.includes('--no-scripts')
  ));
  assert.ok(ddevCalls.some((call) => call.args.includes('composer') && call.args.includes('update') && call.args.includes('--no-install') && call.args.includes('--no-plugins') && call.args.includes('--no-scripts') && call.args.includes('--prefer-dist')));
  assert.ok(ddevCalls.some((call) => call.args.includes('composer') && call.args.includes('install') && call.args.includes('--no-plugins') && call.args.includes('--no-scripts') && call.args.includes('--prefer-dist')));
  assert.ok(ddevCalls.every((call) => !Object.hasOwn(call.env, 'DDEV_PROJECT') && !Object.hasOwn(call.env, 'IS_DDEV_PROJECT') && !Object.hasOwn(call.env, 'COMPOSE_FILE')));
  assert.ok(ddevCalls.some((call) => call.args[0] === 'start' && call.cwd === created.workspace.projectRoot));
  assert.equal(
    customCodeDdevTreeSnapshot(created.workspace.projectRoot).fingerprint,
    created.workspace.runtimeProvenance.ddevTreeFingerprint
  );
  const ownerRoot = created.workspace.ownerRoot;
  const cleanup = cleanupDisposableCustomCodeWorkspace(created.workspace, runner);
  assert.equal(cleanup.completed, true, JSON.stringify(cleanup.failures));
  assert.equal(existsSync(ownerRoot), false);
  assert.ok(ddevCalls.some((call) => call.args[0] === 'delete' && call.cwd !== fixture.root));
  assert.ok(ddevCalls.filter((call) => ['start', 'describe', 'delete'].includes(call.args[0])).every((call) => call.args.includes('--skip-hooks')));
  assert.equal(ddevCalls.some((call) => call.cwd === fixture.root), false);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('stale project Composer lock blocks before dependency installation or analyzers', () => {
  const fixture = qualityFixture();
  initializeGitFixture(fixture.root);
  const ddevCalls = [];
  const hostCalls = [];
  const hostSpawnSync = disposableWorkspaceHostSpawn({
    ddevCalls,
    hostCalls,
    validateExitCode: 2
  });
  const runner = createCustomCodeExecutionRunner(() => {
    throw new Error('working target executor must not run');
  });
  const created = createDisposableCustomCodeWorkspace(
    fixture.root,
    fixture.inventory,
    runner,
    process.env,
    { containerMarker: false, hostSpawnSync }
  );
  const composerCalls = ddevCalls
    .filter((call) => call.args[0] === 'exec')
    .map((call) => call.args.slice(call.args.indexOf('--') + 1));
  assert.equal(created.workspace, null);
  assert.ok(created.failures.some((failure) => failure.check === 'phpunit-isolation'));
  assert.ok(composerCalls.some((argv) => argv.includes('validate') && argv.includes('--check-lock')));
  assert.equal(composerCalls.some((argv) => argv.includes('install') || argv.includes('update')), false);
  assert.ok(ddevCalls.some((call) => call.args[0] === 'delete'));
  rmSync(fixture.root, { recursive: true, force: true });
});

test('disposable workspace rejects unsafe hooks, compose, commands, remote config, aliases, and symlinks before DDEV start', () => {
  for (const candidate of [
    { path: '.ddev/config.hooks.yaml', contents: 'hooks:\n  pre-start:\n    - exec-host: "touch /tmp/unsafe"\n' },
    { path: '.ddev/docker-compose.override.yaml', contents: 'services:\n  web:\n    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n' },
    { path: '.ddev/commands/host/start', contents: '#!/bin/sh\nexit 0\n' },
    { path: '.ddev/config.remote.yaml', contents: 'remote_config: https://example.invalid/unsafe.yaml\n' },
    { path: '.ddev/config.alias.yaml', contents: 'shared: &danger { web_environment: ["X=1"] }\ncopy: *danger\n' },
    { path: '.ddev/config.unicode.yaml', contents: '"h\\U0000006Foks": { pre-start: [{exec-host: "touch /tmp/unsafe"}] }\n' },
    { path: '.ddev/web-build/Dockerfile', contents: 'FROM attacker/example\n' },
    { path: '.ddev/db-build/Dockerfile', contents: 'FROM attacker/example\n' },
    { path: '.ddev/web-entrypoint.d/10-unsafe.sh', contents: '#!/bin/sh\ntouch /tmp/unsafe\n' },
    { path: '.ddev/config.link.yaml', symlink: 'config.yaml' }
  ]) {
    const fixture = qualityFixture();
    if (candidate.symlink) symlinkSync(candidate.symlink, join(fixture.root, candidate.path));
    else writeFixture(fixture.root, candidate.path, candidate.contents);
    initializeGitFixture(fixture.root);
    const ddevCalls = [];
    const hostSpawnSync = (command, args, options) => {
      if (command !== 'ddev') return spawnSync(command, args, options);
      ddevCalls.push([...args]);
      return { status: 1, stdout: '', stderr: 'DDEV must not run for unsafe config' };
    };
    const runner = createCustomCodeExecutionRunner(() => { throw new Error('working target executor must not run'); });
    const created = createDisposableCustomCodeWorkspace(fixture.root, fixture.inventory, runner, process.env, {
      containerMarker: false,
      hostSpawnSync
    });
    assert.equal(created.workspace, null, candidate.path);
    assert.ok(created.failures.length > 0, candidate.path);
    assert.equal(ddevCalls.some((argv) => argv[0] === 'start'), false, candidate.path);
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('a partial failed DDEV start still identity-checks and deletes the owned disposable project', () => {
  const fixture = qualityFixture();
  initializeGitFixture(fixture.root);
  const ddevCalls = [];
  const hostSpawnSync = (command, args, options) => {
    if (command !== 'ddev') return spawnSync(command, args, options);
    ddevCalls.push({ args: [...args], cwd: options.cwd });
    if (args[0] === 'start') return { status: 1, stdout: '', stderr: 'partial start' };
    if (args[0] === 'describe') {
      const config = readFileSync(join(options.cwd, '.ddev/config.yaml'), 'utf8');
      const projectName = JSON.parse(config.match(/^name:\s*(.+)$/m)[1]);
      return { status: 0, stdout: JSON.stringify({ raw: {
        name: projectName,
        approot: options.cwd,
        primary_url: `https://${projectName}.ddev.site`
      } }), stderr: '' };
    }
    if (args[0] === 'delete') return { status: 0, stdout: '', stderr: '' };
    return { status: 1, stdout: '', stderr: 'unexpected command' };
  };
  const runner = createCustomCodeExecutionRunner(() => { throw new Error('working target executor must not run'); });
  const created = createDisposableCustomCodeWorkspace(fixture.root, fixture.inventory, runner, process.env, {
    containerMarker: false,
    hostSpawnSync
  });
  assert.equal(created.workspace, null);
  assert.ok(created.failures.length > 0);
  assert.ok(ddevCalls.some((call) => call.args[0] === 'delete'));
  const disposableRoot = ddevCalls.find((call) => call.args[0] === 'start').cwd;
  assert.equal(existsSync(dirname(disposableRoot)), false);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('a partial failed DDEV start still deletes the verifier-owned project when describe fails', () => {
  const fixture = qualityFixture();
  initializeGitFixture(fixture.root);
  const ddevCalls = [];
  const hostSpawnSync = (command, args, options) => {
    if (command !== 'ddev') return spawnSync(command, args, options);
    ddevCalls.push({ args: [...args], cwd: options.cwd });
    if (args[0] === 'start') return { status: 1, stdout: '', stderr: 'partial start' };
    if (args[0] === 'describe') return { status: 1, stdout: '', stderr: 'project state unavailable' };
    if (args[0] === 'delete') return { status: 0, stdout: '', stderr: '' };
    return { status: 1, stdout: '', stderr: 'unexpected command' };
  };
  const runner = createCustomCodeExecutionRunner(() => { throw new Error('working target executor must not run'); });
  const created = createDisposableCustomCodeWorkspace(fixture.root, fixture.inventory, runner, process.env, {
    containerMarker: false,
    hostSpawnSync
  });
  assert.equal(created.workspace, null);
  assert.ok(created.failures.length > 0);
  assert.deepEqual(ddevCalls.map((call) => call.args[0]), ['start', 'describe', 'delete']);
  const disposableRoot = ddevCalls[0].cwd;
  assert.notEqual(disposableRoot, fixture.root);
  assert.equal(ddevCalls[2].cwd, disposableRoot);
  assert.equal(existsSync(dirname(disposableRoot)), false);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('disposable focused tests fail closed inside the working DDEV container', () => {
  const fixture = qualityFixture();
  let called = false;
  const runner = createCustomCodeExecutionRunner(() => { called = true; return rawResult(''); });
  const result = createDisposableCustomCodeWorkspace(fixture.root, fixture.inventory, runner, {
    IS_DDEV_PROJECT: 'true',
    DDEV_APPROOT: fixture.root,
    DDEV_PROJECT: 'custom-quality',
    DDEV_DOCROOT: 'web'
  }, { containerMarker: true });
  assert.equal(result.workspace, null);
  assert.ok(result.failures.some((failure) => /host-side DDEV orchestration/.test(failure.message)));
  assert.equal(called, false);
  rmSync(fixture.root, { recursive: true, force: true });
});

for (const listFormat of ['phpunit9', 'phpunit10', 'phpunit11']) {
  test(`quality audit and exact focused execution pass with ${listFormat} discovery and dedupe reused AC coverage`, () => {
    const fixture = qualityFixture();
    const fake = fakeQualityExecutor(fixture.root, { listFormat });
    fixture.review.untrustedCommand = 'rm -rf /';
    fixture.review.untrustedEnv = { TOKEN: 'packet-secret' };
    const result = inspectCustomCodeQuality(
      fixture.root,
      {},
      fixture.inventory,
      fixture.review,
      { executor: fake.executor, baseUrl: 'https://custom-quality.ddev.site' }
    );
    assert.equal(result.qualityAudit.status, 'pass', JSON.stringify(result.qualityAudit.failures));
    assert.equal(result.qualityAudit.checks.phpstan.status, 'pass');
    assert.deepEqual(result.qualityAudit.checks.phpstan.requestedFileIds, result.qualityAudit.checks.phpstan.expectedFileIds);
    assert.deepEqual(result.qualityAudit.checks.phpstan.reportedFileIds, []);
    const reportedProvenance = result.qualityAudit.tools.phpcs.provenance;
    for (const field of [
      'composerJsonSha256', 'sourceComposerLockSha256', 'composerLockSha256', 'installedMetadataSha256',
      'closureIdentitySha256', 'closurePackageTreeSha256', 'autoloadTreeSha256', 'rootAutoloadSha256'
    ]) assert.match(reportedProvenance[field], /^sha256:[a-f0-9]{64}$/, field);
    assert.ok(reportedProvenance.rootAutoloadBytes > 0);
    assert.equal(reportedProvenance.closurePackageCount, TOOL_PACKAGES.length + 1);
    assert.equal(result.focusedTestExecution.status, 'pass', JSON.stringify(result.focusedTestExecution.failures));
    assert.equal(result.focusedTestExecution.expectedTestMethodIds.length, 1);
    assert.equal(result.focusedTestExecution.runs.length, 1);
    assert.equal(result.focusedTestExecution.isolation.status, 'cleaned');
    assert.ok(fake.calls.every((call) => call.workspace === 'disposable'));
    assert.equal(fake.calls.some((call) => call.argv[0].startsWith('vendor/bin/')), false);
    assert.deepEqual(result.qualityAudit.executionBudget, result.focusedTestExecution.executionBudget);
    const phpstan = fake.calls.find((call) => call.argv.includes('analyse'));
    assert.ok(phpstan.argv.includes('--memory-limit=512M'));
    const phpcs = fake.calls.find((call) => call.argv.includes('--report=json'));
    assert.deepEqual(phpcs.argv.slice(1, 4), ['--runtime-set', 'installed_paths', '.agent-ready-audit-fixture/vendor/drupal/coder/coder_sniffer']);
    assert.ok(phpcs.argv[0].startsWith('.agent-ready-audit-fixture/vendor/'));
    assert.ok(phpstan.argv[0].startsWith('.agent-ready-audit-fixture/vendor/'));
    const discovery = fake.calls.find((call) => call.argv.includes('--list-tests-xml'));
    const execution = fake.calls.find((call) => call.argv.includes('--log-junit'));
    for (const call of [discovery, execution]) {
      assert.ok(call.argv.includes('--colors=never'));
      assert.ok(call.argv.includes('--do-not-cache-result'));
      assert.deepEqual(Object.keys(call.env).sort(), ['SIMPLETEST_BASE_URL', 'SIMPLETEST_DB']);
    }
    assert.match(execution.argv[execution.argv.indexOf('--filter') + 1], /^\/\^.*\$\/$/);
    assert.equal(JSON.stringify(fake.calls).includes('packet-secret'), false);
    rmSync(fixture.root, { recursive: true, force: true });
  });
}

test('clean PHPCS JSON may omit requested files while exact argv remains completed evidence', () => {
  const fixture = qualityFixture();
  const fake = fakeQualityExecutor(fixture.root, { phpcsCleanOmitFiles: true });
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    executor: fake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(result.qualityAudit.status, 'pass', JSON.stringify(result.qualityAudit.failures));
  assert.deepEqual(
    result.qualityAudit.checks.phpcs.completedFileIds,
    result.qualityAudit.checks.phpcs.expectedFileIds
  );
  assert.deepEqual(result.qualityAudit.checks.phpcs.findings, []);
  rmSync(fixture.root, { recursive: true, force: true });
});

for (const [name, invalidate] of [
  ['provenance', (workspace) => { workspace.runtimeProvenance.specSha256 = 'invalid'; }],
  ['runtime config', (workspace) => { workspace.runtimeProvenance.configSha256 = `sha256:${'f'.repeat(64)}`; }],
  ['base origin', (workspace) => { workspace.baseUrl = 'https://custom-quality.ddev.site'; }]
]) {
  test(`invalid disposable ${name} still cleans the verifier-owned workspace exactly once`, () => {
    const fixture = qualityFixture();
    const fake = fakeQualityExecutor(fixture.root);
    let cleanupCalls = 0;
    const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
      baseUrl: 'https://custom-quality.ddev.site',
      executor: fake.executor,
      disposableWorkspaceFactory(args) {
        const created = fake.disposableWorkspaceFactory(args);
        const cleanup = created.workspace.cleanup;
        created.workspace.cleanup = (...cleanupArgs) => {
          cleanupCalls += 1;
          return cleanup(...cleanupArgs);
        };
        invalidate(created.workspace);
        return created;
      }
    });
    assert.equal(cleanupCalls, 1);
    assert.equal(result.qualityAudit.status, 'blocked');
    assert.equal(result.focusedTestExecution.status, 'blocked');
    assert.ok(result.qualityAudit.failures.some((failure) => failure.check === 'custom-code-isolation'));
    assert.deepEqual(fake.calls, []);
    rmSync(fixture.root, { recursive: true, force: true });
  });
}

test('an unexpected post-validation audit failure still cleans and returns blocked evidence', () => {
  const fixture = qualityFixture();
  const fake = fakeQualityExecutor(fixture.root);
  let cleanupCalls = 0;
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    baseUrl: 'https://custom-quality.ddev.site',
    executor: fake.executor,
    disposableWorkspaceFactory(args) {
      const created = fake.disposableWorkspaceFactory(args);
      const auditRoot = created.workspace.auditRoot;
      const cleanup = created.workspace.cleanup;
      let auditRootReads = 0;
      Object.defineProperty(created.workspace, 'auditRoot', {
        configurable: true,
        get() {
          auditRootReads += 1;
          if (auditRootReads > 1) throw new Error('synthetic audit access failure');
          return auditRoot;
        }
      });
      created.workspace.cleanup = (...cleanupArgs) => {
        cleanupCalls += 1;
        return cleanup(...cleanupArgs);
      };
      return created;
    }
  });
  assert.equal(cleanupCalls, 1);
  assert.equal(result.qualityAudit.status, 'blocked');
  assert.ok(result.qualityAudit.failures.some((failure) =>
    failure.code === 'spawn_failed' && failure.check === 'custom-code-isolation'
  ));
  rmSync(fixture.root, { recursive: true, force: true });
});

test('PHPCS is mandatory, both standards are required, and violations fail without raw output', () => {
  const missing = qualityFixture({ phpcsBinary: false });
  const missingFake = fakeQualityExecutor(missing.root);
  const missingResult = inspectCustomCodeQuality(missing.root, {}, missing.inventory, missing.review, { executor: missingFake.executor, baseUrl: 'https://custom-quality.ddev.site' });
  assert.equal(missingResult.qualityAudit.status, 'blocked');
  assert.ok(missingResult.qualityAudit.failures.some((failure) => failure.code === 'tool_missing'));
  assert.equal(missingFake.calls.some((call) => ['php', 'vendor/squizlabs/php_codesniffer/bin/phpcs', 'vendor/phpstan/phpstan/phpstan'].includes(call.argv[0])), false);
  rmSync(missing.root, { recursive: true, force: true });

  const standards = qualityFixture();
  const standardsFake = fakeQualityExecutor(standards.root, { standardOutput: 'The installed coding standards are Drupal' });
  const standardsResult = inspectCustomCodeQuality(standards.root, {}, standards.inventory, standards.review, { executor: standardsFake.executor, baseUrl: 'https://custom-quality.ddev.site' });
  assert.equal(standardsResult.qualityAudit.status, 'blocked');
  assert.ok(standardsResult.qualityAudit.failures.some((failure) => failure.code === 'required_standard_missing'));
  rmSync(standards.root, { recursive: true, force: true });

  const violation = qualityFixture();
  const violationFake = fakeQualityExecutor(violation.root, { phpcsViolation: true });
  const violationResult = inspectCustomCodeQuality(violation.root, {}, violation.inventory, violation.review, { executor: violationFake.executor, baseUrl: 'https://custom-quality.ddev.site' });
  assert.equal(violationResult.qualityAudit.status, 'fail');
  assert.ok(violationResult.qualityAudit.failures.some((failure) => failure.code === 'violations_found'));
  assert.equal(JSON.stringify(violationResult.qualityAudit).includes('Missing doc comment.'), false);
  assert.match(violationResult.qualityAudit.checks.phpcs.findings[0].messageSha256, /^sha256:[a-f0-9]{64}$/);
  rmSync(violation.root, { recursive: true, force: true });
});

test('analyzer JSON schemas reject malformed or inconsistent reports instead of inferring completion', () => {
  const phpcsFixture = qualityFixture();
  const phpcsFake = fakeQualityExecutor(phpcsFixture.root, {
    phpcsInvalidReport: {
      totals: { errors: 0, warnings: 0, fixable: 0 },
      files: { 'web/modules/custom/unknown.php': { errors: 0, warnings: 0, messages: [] } }
    }
  });
  const phpcsResult = inspectCustomCodeQuality(phpcsFixture.root, {}, phpcsFixture.inventory, phpcsFixture.review, {
    executor: phpcsFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(phpcsResult.qualityAudit.status, 'blocked');
  assert.ok(phpcsResult.qualityAudit.failures.some((failure) => failure.code === 'invalid_output' && failure.check === 'phpcs'));
  rmSync(phpcsFixture.root, { recursive: true, force: true });

  const phpstanFixture = qualityFixture();
  const phpstanFake = fakeQualityExecutor(phpstanFixture.root, { phpstanInvalidReport: { files: {} } });
  const phpstanResult = inspectCustomCodeQuality(phpstanFixture.root, {}, phpstanFixture.inventory, phpstanFixture.review, {
    executor: phpstanFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(phpstanResult.qualityAudit.status, 'blocked');
  assert.ok(phpstanResult.qualityAudit.failures.some((failure) => failure.code === 'invalid_output' && failure.check === 'phpstan'));
  rmSync(phpstanFixture.root, { recursive: true, force: true });

  for (const [option, check] of [['phpcsNegativeTotals', 'phpcs'], ['phpstanNegativeTotals', 'phpstan']]) {
    const fixture = qualityFixture();
    const fake = fakeQualityExecutor(fixture.root, { [option]: true });
    const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
      executor: fake.executor,
      baseUrl: 'https://custom-quality.ddev.site'
    });
    assert.equal(result.qualityAudit.status, 'blocked');
    assert.ok(result.qualityAudit.failures.some((failure) => failure.code === 'invalid_output' && failure.check === check));
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('analyzer and working-target mutations fail measured disposable and source/runtime postflights', () => {
  const analyzerMutation = qualityFixture();
  const originalAnalyzerTarget = readFileSync(join(analyzerMutation.root, 'web/modules/custom/catalog/src/CatalogService.php'), 'utf8');
  const analyzerFake = fakeQualityExecutor(analyzerMutation.root, { mutateAnalyzerSource: true });
  const analyzerResult = inspectCustomCodeQuality(analyzerMutation.root, {}, analyzerMutation.inventory, analyzerMutation.review, {
    executor: analyzerFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(analyzerResult.qualityAudit.status, 'blocked');
  assert.ok(analyzerResult.qualityAudit.failures.some((failure) => failure.code === 'stale_test_binding'));
  assert.equal(readFileSync(join(analyzerMutation.root, 'web/modules/custom/catalog/src/CatalogService.php'), 'utf8'), originalAnalyzerTarget);
  assert.ok(analyzerFake.calls.every((call) => call.workspace === 'disposable'));
  rmSync(analyzerMutation.root, { recursive: true, force: true });

  const workingMutation = qualityFixture();
  const workingFake = fakeQualityExecutor(workingMutation.root, { mutateWorkingTarget: true });
  const workingResult = inspectCustomCodeQuality(workingMutation.root, {}, workingMutation.inventory, workingMutation.review, {
    executor: workingFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(workingResult.qualityAudit.status, 'blocked');
  assert.ok(workingResult.qualityAudit.failures.some((failure) => failure.check === 'working-target-snapshot'));
  assert.notEqual(
    workingResult.qualityAudit.isolation.workingTargetSnapshotBeforeSha256,
    workingResult.qualityAudit.isolation.workingTargetSnapshotAfterSha256
  );
  assert.ok(workingFake.calls.every((call) => call.workspace === 'disposable'));
  rmSync(workingMutation.root, { recursive: true, force: true });
});

test('Composer provenance ignores hostile wrappers and blocks a package tree altered during execution', () => {
  const passing = qualityFixture();
  const passingFake = fakeQualityExecutor(passing.root);
  const passingResult = inspectCustomCodeQuality(passing.root, {}, passing.inventory, passing.review, {
    executor: passingFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(passingResult.qualityAudit.status, 'pass', JSON.stringify(passingResult.qualityAudit.failures));
  assert.equal(passingFake.calls.some((call) => call.argv[0].startsWith('vendor/bin/')), false);
  assert.ok(passingFake.calls.some((call) => call.argv[0].endsWith('/vendor/squizlabs/php_codesniffer/bin/phpcs')));
  assert.ok(passingFake.calls.every((call) => call.workspace === 'disposable'));
  rmSync(passing.root, { recursive: true, force: true });

  for (const mutation of [
    ({ installed }) => { installed.packages.find((entry) => entry.name === 'squizlabs/php_codesniffer')['installation-source'] = 'source'; },
    ({ installed }) => { installed.packages.find((entry) => entry.name === 'squizlabs/php_codesniffer')['install-path'] = '../custom/phpcs'; }
  ]) {
    const ignored = qualityFixture();
    const installed = JSON.parse(readFileSync(join(ignored.root, 'vendor/composer/installed.json'), 'utf8'));
    mutation({ installed });
    writeFixture(ignored.root, 'vendor/composer/installed.json', JSON.stringify(installed));
    const ignoredFake = fakeQualityExecutor(ignored.root);
    const ignoredResult = inspectCustomCodeQuality(ignored.root, {}, ignored.inventory, ignored.review, {
      executor: ignoredFake.executor,
      baseUrl: 'https://custom-quality.ddev.site'
    });
    assert.equal(ignoredResult.qualityAudit.status, 'pass', JSON.stringify(ignoredResult.qualityAudit.failures));
    rmSync(ignored.root, { recursive: true, force: true });
  }

  const rejected = qualityFixture();
  const locked = JSON.parse(readFileSync(join(rejected.root, 'composer.lock'), 'utf8'));
  locked['packages-dev'].find((entry) => entry.name === 'squizlabs/php_codesniffer').dist.url = 'https://artifacts.example.invalid/phpcs.zip';
  writeFixture(rejected.root, 'composer.lock', JSON.stringify(locked));
  const rejectedFake = fakeQualityExecutor(rejected.root);
  const rejectedResult = inspectCustomCodeQuality(rejected.root, {}, rejected.inventory, rejected.review, {
    executor: rejectedFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(rejectedResult.qualityAudit.status, 'blocked');
  assert.ok(rejectedResult.qualityAudit.failures.some((failure) => failure.check === 'tool-provenance'));
  assert.equal(rejectedFake.calls.length, 0);
  rmSync(rejected.root, { recursive: true, force: true });

  const altered = qualityFixture();
  const alteredFake = fakeQualityExecutor(altered.root, { mutatePackageTree: true });
  const alteredResult = inspectCustomCodeQuality(altered.root, {}, altered.inventory, altered.review, {
    executor: alteredFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(alteredResult.qualityAudit.status, 'blocked');
  assert.ok(alteredResult.qualityAudit.failures.some((failure) => failure.code === 'stale_test_binding' && failure.check === 'tool-provenance'));
  rmSync(altered.root, { recursive: true, force: true });

  const alteredClone = qualityFixture();
  const alteredCloneFake = fakeQualityExecutor(alteredClone.root, { mutateDisposablePhpunit: true });
  const alteredCloneResult = inspectCustomCodeQuality(alteredClone.root, {}, alteredClone.inventory, alteredClone.review, {
    executor: alteredCloneFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(alteredCloneResult.focusedTestExecution.status, 'blocked');
  assert.ok(alteredCloneResult.focusedTestExecution.failures.some((failure) => failure.code === 'stale_test_binding' && failure.check === 'tool-provenance'));
  rmSync(alteredClone.root, { recursive: true, force: true });

  const alteredClosure = qualityFixture();
  const alteredClosureFake = fakeQualityExecutor(alteredClosure.root, { mutateClosureTree: true });
  const alteredClosureResult = inspectCustomCodeQuality(alteredClosure.root, {}, alteredClosure.inventory, alteredClosure.review, {
    executor: alteredClosureFake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(alteredClosureResult.qualityAudit.status, 'blocked');
  assert.ok(alteredClosureResult.qualityAudit.failures.some((failure) => failure.code === 'stale_test_binding' && failure.check === 'tool-provenance'));
  rmSync(alteredClosure.root, { recursive: true, force: true });
});

test('Composer provenance rejects a missing root vendor autoloader', () => {
  const fixture = qualityFixture();
  const fake = fakeQualityExecutor(fixture.root, { rootAutoload: 'missing' });
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    executor: fake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(result.qualityAudit.status, 'blocked');
  assert.ok(result.qualityAudit.failures.length > 0);
  assert.equal(fake.calls.length, 0);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('Composer provenance rejects a symlinked root vendor autoloader', () => {
  const fixture = qualityFixture();
  const fake = fakeQualityExecutor(fixture.root, { rootAutoload: 'symlink' });
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    executor: fake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(result.qualityAudit.status, 'blocked');
  assert.ok(result.qualityAudit.failures.length > 0);
  assert.equal(fake.calls.length, 0);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('Composer provenance postflight rejects a mutated root vendor autoloader', () => {
  const fixture = qualityFixture();
  const fake = fakeQualityExecutor(fixture.root, { mutateRootAutoload: true });
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    executor: fake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(result.qualityAudit.status, 'blocked');
  assert.ok(result.qualityAudit.failures.some((failure) =>
    failure.code === 'stale_test_binding' && failure.check === 'tool-provenance'
  ));
  rmSync(fixture.root, { recursive: true, force: true });
});

test('PHPStan is not_supported without config and blocked when config lacks its binary', () => {
  const unsupported = qualityFixture({ phpstanConfig: false });
  const unsupportedFake = fakeQualityExecutor(unsupported.root);
  const unsupportedResult = inspectCustomCodeQuality(unsupported.root, {}, unsupported.inventory, unsupported.review, { executor: unsupportedFake.executor, baseUrl: 'https://custom-quality.ddev.site' });
  assert.equal(unsupportedResult.qualityAudit.status, 'pass');
  assert.equal(unsupportedResult.qualityAudit.checks.phpstan.status, 'not_supported');
  rmSync(unsupported.root, { recursive: true, force: true });

  const blocked = qualityFixture({ phpstanBinary: false, phpstanConfig: true });
  const blockedFake = fakeQualityExecutor(blocked.root);
  const blockedResult = inspectCustomCodeQuality(blocked.root, {}, blocked.inventory, blocked.review, { executor: blockedFake.executor, baseUrl: 'https://custom-quality.ddev.site' });
  assert.equal(blockedResult.qualityAudit.status, 'blocked');
  assert.ok(blockedResult.qualityAudit.failures.some((failure) => failure.code === 'tool_missing'));
  assert.equal(blockedFake.calls.some((call) => ['php', 'vendor/squizlabs/php_codesniffer/bin/phpcs', 'vendor/phpstan/phpstan/phpstan'].includes(call.argv[0])), false);
  rmSync(blocked.root, { recursive: true, force: true });
});

test('coverage rejects unsupported, stale, foreign, and uncovered rows before PHPUnit execution', () => {
  for (const mutation of [
    (fixture) => { fixture.review.testCoverage[0].runner = 'shell'; },
    (fixture) => { fixture.review.testCoverage[0].testMethodId = 'TESTMETHOD-0000000000000000'; },
    (fixture) => { fixture.review.testCoverage[0].className = 'Drupal\\Tests\\other\\Kernel\\CatalogTest'; },
    (fixture) => {
      fixture.testFile.extension = 'other';
      fixture.method.id = customTestMethodId('other', fixture.testFile.path, fixture.method.className, fixture.method.methodName);
      fixture.review.testCoverage[0].testMethodId = fixture.method.id;
    },
    (fixture) => { fixture.review.testCoverage = []; }
  ]) {
    const fixture = qualityFixture();
    mutation(fixture);
    const fake = fakeQualityExecutor(fixture.root);
    const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, { executor: fake.executor, baseUrl: 'https://custom-quality.ddev.site' });
    assert.equal(result.focusedTestExecution.status, 'blocked');
    assert.equal(fake.calls.some((call) => call.workspace === 'working-target' && call.argv[0] === 'vendor/phpunit/phpunit/phpunit'), false);
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('an executable custom surface cannot opt out of focused tests with loadBearing false', () => {
  const fixture = qualityFixture({ executableSource: true });
  fixture.review.capabilities[0].loadBearing = false;
  fixture.review.testCoverage = [];
  const fake = fakeQualityExecutor(fixture.root);
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    executor: fake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(result.focusedTestExecution.applies, true);
  assert.equal(result.focusedTestExecution.status, 'blocked');
  assert.ok(result.focusedTestExecution.failures.some((failure) =>
    failure.code === 'uncovered_acceptance_criterion'
  ));
  assert.equal(fake.calls.some((call) => call.argv.some((value) => String(value).includes('phpunit'))), false);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('coverage row and focused method bounds are preflighted before PHPUnit commands', () => {
  const fixture = qualityFixture();
  const criteria = Array.from({ length: 129 }, (_, index) => ({
    id: `AC-CATALOG-${String(index).padStart(3, '0')}`,
    criterion: `Bounded criterion ${index}.`
  }));
  fixture.review.capabilities[0].acceptanceCriteria = criteria;
  fixture.review.testCoverage = criteria.map((criterion) => ({
    ...fixture.review.testCoverage[0],
    acceptanceCriterionId: criterion.id
  }));
  const fake = fakeQualityExecutor(fixture.root);
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, { executor: fake.executor, baseUrl: 'https://custom-quality.ddev.site' });
  assert.equal(result.focusedTestExecution.status, 'blocked');
  assert.ok(result.focusedTestExecution.failures.some((failure) => failure.code === 'input_limit_exceeded'));
  assert.equal(fake.calls.some((call) => call.workspace === 'working-target' && call.argv[0] === 'vendor/phpunit/phpunit/phpunit'), false);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('PHP file-count and aggregate path-argv bounds block before any tool command', () => {
  for (const [count, longNames, expectedMessage] of [
    [257, false, /256 files/],
    [200, true, /aggregate argv limit/]
  ]) {
    const root = mkdtempSync(join(tmpdir(), 'custom-code-quality-file-bound-'));
    writeFixture(root, '.ddev/config.yaml', 'name: quality-bound\ntype: drupal11\ndocroot: web\n');
    writeFixture(root, 'web/modules/custom/many/many.info.yml', 'name: Many\ntype: module\n');
    for (let index = 0; index < count; index += 1) {
      const suffix = longNames ? `-${'x'.repeat(100)}` : '';
      writeFixture(root, `web/modules/custom/many/src/Class${index}${suffix}.php`, `<?php\nfinal class Class${index} {}\n`);
    }
    const inventory = inspectCustomCodeFilesystem(root);
    assert.equal(inventory.completed, true, inventory.errors.join('\n'));
    let called = false;
    const result = inspectCustomCodeQuality(root, {}, inventory, { capabilities: [], testCoverage: [] }, {
      executor() { called = true; return rawResult(''); },
      baseUrl: ''
    });
    assert.equal(result.qualityAudit.status, 'blocked');
    assert.ok(result.qualityAudit.failures.some((failure) => expectedMessage.test(failure.message)));
    assert.equal(called, false);
    rmSync(root, { recursive: true, force: true });
  }
});

for (const [junitMode, expectedStatus, expectedCode] of [
  ['fail', 'fail', 'test_failed'],
  ['skip', 'fail', 'test_skipped'],
  ['no-assertions', 'fail', 'no_assertions_executed'],
  ['extra', 'blocked', 'unexpected_test_executed'],
  ['zero', 'blocked', 'no_tests_executed'],
  ['data-overflow', 'blocked', 'input_limit_exceeded'],
  ['malformed-xml', 'blocked', 'invalid_output'],
  ['missing-totals', 'blocked', 'invalid_output'],
  ['negative-totals', 'blocked', 'invalid_output'],
  ['inconsistent-totals', 'blocked', 'invalid_output']
]) {
  test(`focused JUnit ${junitMode} result fails closed`, () => {
    const fixture = qualityFixture();
    const fake = fakeQualityExecutor(fixture.root, { junitMode });
    const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, { executor: fake.executor, baseUrl: 'https://custom-quality.ddev.site' });
    assert.equal(result.focusedTestExecution.status, expectedStatus);
    assert.ok(result.focusedTestExecution.failures.some((failure) => failure.code === expectedCode));
    rmSync(fixture.root, { recursive: true, force: true });
  });
}

test('focused discovery rejects malformed XML before method execution', () => {
  const fixture = qualityFixture();
  const fake = fakeQualityExecutor(fixture.root, { malformedListXml: true });
  const result = inspectCustomCodeQuality(fixture.root, {}, fixture.inventory, fixture.review, {
    executor: fake.executor,
    baseUrl: 'https://custom-quality.ddev.site'
  });
  assert.equal(result.focusedTestExecution.status, 'blocked');
  assert.ok(result.focusedTestExecution.failures.some((failure) => failure.code === 'invalid_output' && failure.check === 'phpunit-discovery'));
  assert.equal(fake.calls.some((call) => call.argv.includes('--log-junit')), false);
  rmSync(fixture.root, { recursive: true, force: true });
});

test('quality and focused execution are typed not_applicable when no custom PHP or load-bearing AC exists', () => {
  const root = mkdtempSync(join(tmpdir(), 'custom-code-quality-na-'));
  writeFixture(root, '.ddev/config.yaml', 'name: custom-quality-na\ntype: drupal11\ndocroot: web\n');
  writeFixture(root, 'web/themes/custom/plain/plain.info.yml', 'name: Plain\ntype: theme\n');
  writeFixture(root, 'web/themes/custom/plain/css/plain.css', 'body { color: black; }\n');
  const inventory = inspectCustomCodeFilesystem(root);
  const result = inspectCustomCodeQuality(root, {}, inventory, { capabilities: [], testCoverage: [] }, { executor() { throw new Error('must not execute'); }, baseUrl: '' });
  assert.equal(result.qualityAudit.status, 'not_applicable');
  assert.equal(result.focusedTestExecution.status, 'not_applicable');
  assert.equal(result.executionBudget.commandsExecuted, 0);
  rmSync(root, { recursive: true, force: true });
});
