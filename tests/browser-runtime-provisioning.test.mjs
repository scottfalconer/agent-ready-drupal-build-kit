import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  DEFAULT_SELENIUM_GRID_URL,
  SELENIUM_ADD_ON_RELEASE,
  SELENIUM_CHROMIUM_IMAGE,
  SELENIUM_CHROMIUM_MAJOR
} from '../bin/global-chrome.mjs';
import { validateBrowserRuntimeSmoke } from '../scripts/browser-runtime-smoke.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const assetRoot = join(repoRoot, 'assets', 'browser-runtime');
const commonScript = join(repoRoot, 'scripts', 'browser-runtime-common.sh');
const manifestPath = join(assetRoot, 'runtime.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

function runBash(script, args = [], options = {}) {
  return spawnSync('bash', ['-c', script, 'browser-runtime-test', ...args], {
    encoding: 'utf8',
    ...options
  });
}

function renderOverride() {
  const result = runBash(
    'source "$1" && browser_runtime_load_manifest "$2" && browser_runtime_render_override "$3"',
    [commonScript, manifestPath, join(assetRoot, 'docker-compose.zz-agent-ready-verifier.yaml')]
  );
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

function effectiveCompose({ maxSessions = '1' } = {}) {
  return `name: ddev-browser-runtime-test
services:
  selenium-chrome:
    container_name: ddev-browser-runtime-test-selenium-chrome
    environment:
      SE_NODE_GRID_URL: http://selenium-chrome:4444
      SE_NODE_MAX_SESSIONS: "${maxSessions}"
      SE_NODE_OVERRIDE_MAX_SESSIONS: "false"
    healthcheck:
      test:
        - CMD-SHELL
        - curl -fsS http://localhost:4444/status | grep -Eq '\"ready\"[[:space:]]*:[[:space:]]*true'
      timeout: 5s
      interval: 2s
      retries: 30
      start_period: 10s
    image: ${manifest.browserImage}
    shm_size: "2147483648"
  web:
    container_name: ddev-browser-runtime-test-web
    image: ddev/ddev-webserver:test
`;
}

function makeScript(path, content) {
  writeFileSync(path, content);
  chmodSync(path, 0o755);
}

function makeProvisioningFixture() {
  const project = mkdtempSync(join(tmpdir(), 'browser-runtime-project-'));
  const ddevDirectory = join(project, '.ddev');
  const nestedCwd = join(project, 'web', 'modules', 'custom');
  const skillRoot = join(project, '.agents', 'skills', 'agent-ready-drupal-build-kit');
  const scriptRoot = join(skillRoot, 'scripts');
  const fixtureAssetRoot = join(skillRoot, 'assets', 'browser-runtime');
  const fakeBin = join(project, '.fake-bin');
  mkdirSync(ddevDirectory, { recursive: true });
  mkdirSync(nestedCwd, { recursive: true });
  mkdirSync(scriptRoot, { recursive: true });
  mkdirSync(fixtureAssetRoot, { recursive: true });
  mkdirSync(fakeBin, { recursive: true });
  writeFileSync(join(ddevDirectory, 'config.yaml'), 'name: browser-runtime-test\ntype: drupal11\ndocroot: web\n');
  cpSync(assetRoot, fixtureAssetRoot, { recursive: true });
  for (const name of [
    'browser-runtime-common.sh',
    'browser-runtime-smoke.mjs',
    'repair-browser-runtime.sh',
    'setup-browser-runtime.sh'
  ]) {
    cpSync(join(repoRoot, 'scripts', name), join(scriptRoot, name));
  }

  const composePath = join(project, '.fake-compose.yaml');
  const logPath = join(project, '.fake-ddev.log');
  const runningPath = join(project, '.fake-running');
  writeFileSync(composePath, effectiveCompose());
  writeFileSync(logPath, '');

  makeScript(join(fakeBin, 'sha256sum'), `#!/usr/bin/env bash
case "$(basename "$1")" in
  docker-compose.selenium-chrome.yaml) hash="$FAKE_ADDON_COMPOSE_SHA256" ;;
  config.selenium-standalone-chrome.yaml) hash="$FAKE_ADDON_CONFIG_SHA256" ;;
  *) exit 1 ;;
esac
printf '%s  %s\\n' "$hash" "$1"
`);
  makeScript(join(fakeBin, 'ddev'), `#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FAKE_DDEV_LOG"
case "\${1:-}:\${2:-}" in
  utility:match-constraint)
    [ "\${FAKE_DDEV_UNSUPPORTED:-}" != "1" ]
    exit
    ;;
  utility:dockercheck) exit 0 ;;
  utility:compose-config) cat "$FAKE_COMPOSE"; exit 0 ;;
  utility:rebuild) touch "$FAKE_RUNNING"; exit 0 ;;
  add-on:get)
    mkdir -p "$FAKE_PROJECT/.ddev/addon-metadata/ddev-selenium-standalone-chrome"
    printf '#ddev-generated\\nfixture compose\\n' > "$FAKE_PROJECT/.ddev/docker-compose.selenium-chrome.yaml"
    printf '#ddev-generated\\nfixture config\\n' > "$FAKE_PROJECT/.ddev/config.selenium-standalone-chrome.yaml"
    printf 'name: ddev-selenium-standalone-chrome\\nrepository: ddev/ddev-selenium-standalone-chrome\\nversion: 2.2.1\\n' > "$FAKE_PROJECT/.ddev/addon-metadata/ddev-selenium-standalone-chrome/manifest.yaml"
    exit 0
    ;;
  restart:-y) touch "$FAKE_RUNNING"; exit 0 ;;
  exec:--service) printf '{"ready":true,"fixture":true}\\n'; exit 0 ;;
esac
printf 'Unexpected fake ddev command: %s\\n' "$*" >&2
exit 1
`);
  makeScript(join(fakeBin, 'docker'), `#!/usr/bin/env bash
set -eu
[ "\${1:-}" = inspect ] || exit 1
format=\${3:-}
container=\${4:-}
if [ "$format" = '{{.Id}}' ] && [ "$container" = ddev-browser-runtime-test-web ]; then
  [ -f "$FAKE_RUNNING" ] || exit 1
  printf 'stable-web-container-id\\n'
  exit 0
fi
[ "$container" = ddev-browser-runtime-test-selenium-chrome ] || exit 1
[ -f "$FAKE_RUNNING" ] || exit 1
printf '%s|running|healthy|2147483648|["SE_NODE_GRID_URL=http://selenium-chrome:4444","SE_NODE_MAX_SESSIONS=1","SE_NODE_OVERRIDE_MAX_SESSIONS=false"]|["CMD-SHELL","curl -fsS http://localhost:4444/status and ready"]\\n' "$FAKE_BROWSER_IMAGE"
`);

  const environment = {
    ...process.env,
    PATH: `${fakeBin}:${process.env.PATH}`,
    FAKE_ADDON_COMPOSE_SHA256: manifest.addOnComposeSha256,
    FAKE_ADDON_CONFIG_SHA256: manifest.addOnConfigSha256,
    FAKE_BROWSER_IMAGE: manifest.browserImage,
    FAKE_COMPOSE: composePath,
    FAKE_DDEV_LOG: logPath,
    FAKE_PROJECT: project,
    FAKE_RUNNING: runningPath
  };
  return {
    composePath,
    environment,
    logPath,
    nestedCwd,
    overridePath: join(ddevDirectory, 'docker-compose.zz-agent-ready-verifier.yaml'),
    project,
    repairScript: join(scriptRoot, 'repair-browser-runtime.sh'),
    runningPath,
    setupScript: join(scriptRoot, 'setup-browser-runtime.sh')
  };
}

test('runtime manifest pins one multi-arch add-on boundary without a floating browser image', () => {
  assert.equal(manifest.schemaVersion, '1');
  assert.equal(manifest.ddevMinimumVersion, '1.25.3');
  assert.equal(manifest.addOnRepository, 'ddev/ddev-selenium-standalone-chrome');
  assert.equal(manifest.addOnRelease, '2.2.1');
  assert.equal(manifest.addOnCommit, '2719f44bd16128629c2c77d93b71b7a10c32f73f');
  assert.equal(
    manifest.browserImage,
    'selenium/standalone-chromium:149.0@sha256:9b10a9ccf68e3a18153a68a0705577157e20665d88d00bd4393a42e5839aa3d3'
  );
  assert.deepEqual(manifest.supportedPlatforms, ['linux/amd64', 'linux/arm64']);
  assert.equal(manifest.gridUrl, 'http://selenium-chrome:4444');
  assert.equal(manifest.gridUrl, DEFAULT_SELENIUM_GRID_URL);
  assert.equal(manifest.addOnRelease, SELENIUM_ADD_ON_RELEASE);
  assert.equal(manifest.browserImage, SELENIUM_CHROMIUM_IMAGE);
  assert.equal(manifest.browserTag.split('.')[0], SELENIUM_CHROMIUM_MAJOR);
  assert.equal(manifest.maxSessions, '1');
  assert.equal(manifest.sharedMemoryBytes, String(2 * 1024 * 1024 * 1024));
  assert.equal(manifest.smokeTimeoutMs, '90000');
});

test('override rendering is complete and refuses an unmarked destination', () => {
  const rendered = renderOverride();
  assert.match(rendered, /^#ddev-silent-no-warn$/m);
  assert.match(rendered, /browser-runtime-schema: 1/);
  assert.match(rendered, new RegExp(manifest.browserManifestDigest));
  assert.match(rendered, /SE_NODE_GRID_URL: http:\/\/selenium-chrome:4444/);
  assert.match(rendered, /SE_NODE_MAX_SESSIONS: "1"/);
  assert.match(rendered, /shm_size: 2gb/);
  assert.match(rendered, /value\.ready|\\"ready\\"/);
  assert.doesNotMatch(rendered, /@@/);

  const root = mkdtempSync(join(tmpdir(), 'browser-runtime-unmarked-'));
  const destination = join(root, 'docker-compose.zz-agent-ready-verifier.yaml');
  writeFileSync(destination, 'services: {}\n');
  const result = runBash(
    'source "$1" && browser_runtime_validate_override_ownership "$2"',
    [commonScript, destination]
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not marker-owned/);
  assert.equal(readFileSync(destination, 'utf8'), 'services: {}\n');
});

test('effective Compose validation accepts the pinned service and rejects session drift', () => {
  const root = mkdtempSync(join(tmpdir(), 'browser-runtime-compose-'));
  const fakeDdev = join(root, 'ddev');
  const composePath = join(root, 'compose.yaml');
  makeScript(fakeDdev, '#!/usr/bin/env bash\ncat "$FAKE_COMPOSE"\n');
  const command = 'source "$1" && browser_runtime_load_manifest "$2" && BROWSER_RUNTIME_DDEV_BIN="$3" && browser_runtime_validate_effective_compose';

  writeFileSync(composePath, effectiveCompose());
  const accepted = runBash(command, [commonScript, manifestPath, fakeDdev], {
    env: { ...process.env, FAKE_COMPOSE: composePath }
  });
  assert.equal(accepted.status, 0, accepted.stderr);

  writeFileSync(composePath, effectiveCompose({ maxSessions: '12' }));
  const rejected = runBash(command, [commonScript, manifestPath, fakeDdev], {
    env: { ...process.env, FAKE_COMPOSE: composePath }
  });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /SE_NODE_MAX_SESSIONS/);
});

test('host setup installs once, writes atomically, and becomes a smoke-only no-op', () => {
  const fixture = makeProvisioningFixture();
  const first = spawnSync('bash', [fixture.setupScript], {
    cwd: fixture.nestedCwd,
    encoding: 'utf8',
    env: fixture.environment
  });
  assert.equal(first.status, 0, first.stderr);
  const firstLog = readFileSync(fixture.logPath, 'utf8');
  assert.match(firstLog, /add-on get ddev\/ddev-selenium-standalone-chrome --version 2\.2\.1/);
  assert.match(firstLog, /^restart -y$/m);
  assert.match(firstLog, /^exec --service web --dir \/var\/www\/html env /m);
  assert.equal(readFileSync(fixture.overridePath, 'utf8'), renderOverride());

  writeFileSync(fixture.logPath, '');
  const second = spawnSync('bash', [fixture.setupScript], {
    cwd: fixture.project,
    encoding: 'utf8',
    env: fixture.environment
  });
  assert.equal(second.status, 0, second.stderr);
  const secondLog = readFileSync(fixture.logPath, 'utf8');
  assert.doesNotMatch(secondLog, /add-on get/);
  assert.doesNotMatch(secondLog, /^restart /m);
  assert.match(secondLog, /^exec --service web /m);
});

test('host setup rejects DDEV older than the service-rebuild boundary before changing the project', () => {
  const fixture = makeProvisioningFixture();
  const result = spawnSync('bash', [fixture.setupScript], {
    cwd: fixture.project,
    encoding: 'utf8',
    env: { ...fixture.environment, FAKE_DDEV_UNSUPPORTED: '1' }
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /DDEV 1\.25\.3 or newer is required/);
  assert.equal(readFileSync(fixture.logPath, 'utf8'), 'utility match-constraint >= 1.25.3\n');
  assert.equal(existsSync(fixture.overridePath), false);
  assert.equal(existsSync(join(fixture.project, '.ddev', 'docker-compose.selenium-chrome.yaml')), false);
});

test('repair uses the supported service-only rebuild and preserves the web boundary', () => {
  const fixture = makeProvisioningFixture();
  const setup = spawnSync('bash', [fixture.setupScript], {
    cwd: fixture.project,
    encoding: 'utf8',
    env: fixture.environment
  });
  assert.equal(setup.status, 0, setup.stderr);
  writeFileSync(fixture.logPath, '');

  const repaired = spawnSync('bash', [fixture.repairScript], {
    cwd: fixture.project,
    encoding: 'utf8',
    env: fixture.environment
  });
  assert.equal(repaired.status, 0, repaired.stderr);
  const log = readFileSync(fixture.logPath, 'utf8');
  assert.match(log, /^utility rebuild --service selenium-chrome --cache$/m);
  assert.doesNotMatch(log, /^restart /m);
  assert.match(log, /^exec --service web /m);
  assert.doesNotMatch(readFileSync(fixture.repairScript, 'utf8'), /browser_runtime_ddev restart/);
});

test('host repair refuses in-container execution before invoking DDEV', () => {
  const fixture = makeProvisioningFixture();
  const result = spawnSync('bash', [fixture.repairScript], {
    cwd: fixture.project,
    encoding: 'utf8',
    env: { ...fixture.environment, IS_DDEV_PROJECT: 'true' }
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /host-only command/);
  assert.equal(readFileSync(fixture.logPath, 'utf8'), '');
});

test('smoke result validation requires pinned axe, PNG, target network, and fresh context evidence', () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('fixture')]);
  const globalCapture = {
    authoritative: true,
    browser: { product: 'Chrome/149.0.7827.155' },
    routes: [{
      axe: { report: { violations: [] }, status: 'executed' },
      path: '/',
      screenshot: { base64: png.toString('base64') },
      signals: { finalUrl: 'https://fixture.ddev.site/' },
      viewport: { name: 'desktop' }
    }],
    runtime: { backend: 'selenium-grid-cdp', ready: true },
    status: 'captured'
  };
  const networkCapture = {
    authoritative: true,
    routes: [{
      isolation: { browserContextFresh: true },
      requests: [{ method: 'GET', url: 'https://fixture.ddev.site/' }]
    }],
    runtime: { backend: 'selenium-grid-cdp', ready: true },
    status: 'captured'
  };
  const validated = validateBrowserRuntimeSmoke({
    globalCapture,
    networkCapture,
    targetUrl: 'https://fixture.ddev.site/'
  });
  assert.equal(validated.axeRouteViewportCount, 1);
  assert.equal(validated.networkRequestCount, 1);
  assert.equal(validated.screenshotBytes, png.length);

  assert.throws(
    () => validateBrowserRuntimeSmoke({
      globalCapture,
      networkCapture: { ...networkCapture, routes: [{ isolation: { browserContextFresh: true }, requests: [] }] },
      targetUrl: 'https://fixture.ddev.site/'
    }),
    /no request for the DDEV target host/
  );
});
