import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const verifyScript = join(repoRoot, 'bin', 'verify-packet.mjs');
const templatesDir = join(repoRoot, 'templates');

function runVerifier(args, options = {}) {
  return spawnSync(process.execPath, [verifyScript, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    ...options
  });
}

function requiredTemplateName(packetFile) {
  const parsed = parse(packetFile);
  return `${parsed.name}.template${parsed.ext}`;
}

function copyTemplatePacket(packetDir) {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  mkdirSync(packetDir, { recursive: true });
  for (const file of gates.reviewPacketFiles) {
    cpSync(join(templatesDir, requiredTemplateName(file)), join(packetDir, file));
  }
}

function textPromptAfter(content, heading) {
  const section = content.split(heading)[1] ?? '';
  return section.match(/```text\n([\s\S]*?)\n```/)?.[1] ?? '';
}

function assertCanonicalBrowserBootstrap(content, surface) {
  const skillInstall = content.indexOf('ddev exec npx --yes skills add');
  const runtimeSetup = content.indexOf(
    'bash .agents/skills/agent-ready-drupal-build-kit/scripts/setup-browser-runtime.sh'
  );
  const agentLaunches = ['ddev codex', 'ddev claude', 'ddev opencode']
    .map((command) => content.indexOf(command))
    .filter((index) => index >= 0);

  assert.notEqual(skillInstall, -1, `${surface} must install the copied skill`);
  assert.notEqual(runtimeSetup, -1, `${surface} must run the supported browser setup`);
  assert.ok(skillInstall < runtimeSetup, `${surface} must install the skill before browser setup`);
  assert.ok(agentLaunches.length > 0, `${surface} must name a canonical DDEV agent launch`);
  assert.ok(
    agentLaunches.every((index) => runtimeSetup < index),
    `${surface} must finish browser setup before any DDEV agent launch`
  );
  assert.doesNotMatch(content, /(?:export\s+CHROME_PATH|CHROME_PATH\s*=)/);
  for (const line of content.split('\n').filter((candidate) => candidate.includes('CHROME_PATH'))) {
    assert.match(line, /\b(?:do not|not)\b/i, `${surface} must not recommend CHROME_PATH as a runtime path`);
  }
}

test('each required review packet file has a matching template', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const missing = gates.reviewPacketFiles.filter((file) => !existsSync(join(templatesDir, requiredTemplateName(file))));

  assert.deepEqual(missing, []);
});

test('post-baseline impact profiles reference one canonical check catalog and known state components', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const knownComponents = new Set([
    'targetIdentity',
    'configTree',
    'runtimeCodeTree',
    'runtimeFacts',
    'entityInventory',
    'routeManifest'
  ]);

  assert.ok(gates.changeChecks && typeof gates.changeChecks === 'object');
  assert.ok(gates.changeImpactProfiles && typeof gates.changeImpactProfiles === 'object');
  for (const [profileId, profile] of Object.entries(gates.changeImpactProfiles)) {
    assert.ok(Array.isArray(profile.checks), `${profileId} must declare checks`);
    assert.ok(Array.isArray(profile.components), `${profileId} must declare state components`);
    for (const checkId of profile.checks) {
      assert.equal(typeof gates.changeChecks[checkId], 'string', `${profileId} references unknown check ${checkId}`);
      assert.notEqual(gates.changeChecks[checkId].trim(), '', `${checkId} must have a description`);
    }
    for (const component of profile.components) {
      assert.equal(knownComponents.has(component), true, `${profileId} references unknown component ${component}`);
    }
  }
  for (const requiredProfile of ['universal', 'repair', 'extension', 'unknown']) {
    assert.ok(gates.changeImpactProfiles[requiredProfile], `${requiredProfile} impact profile is required`);
  }
});

test('template directory contains only packet templates named by gates.json', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const requiredFiles = new Set(gates.reviewPacketFiles);
  const templateFiles = new Set(gates.reviewPacketFiles.map(requiredTemplateName));
  const listed = new Set(
    spawnSync('find', [templatesDir, '-maxdepth', '1', '-type', 'f'], { encoding: 'utf8' })
      .stdout.trim()
      .split('\n')
      .filter(Boolean)
      .map((file) => basename(file))
  );

  const unexpected = [...listed].filter((file) => !templateFiles.has(file));
  const derived = [...listed]
    .filter((file) => file.includes('.template.'))
    .map((file) => file.replace('.template.', '.'));
  const orphaned = derived.filter((file) => !requiredFiles.has(file));

  assert.deepEqual(unexpected, []);
  assert.deepEqual(orphaned, []);
});

test('verifier CLI runs when invoked through an npm-style bin symlink', () => {
  const temp = mkdtempSync(join(tmpdir(), 'packet-bin-'));
  const link = join(temp, 'agent-ready-drupal-verify-packet');
  symlinkSync(verifyScript, link);

  const result = spawnSync(link, ['--help'], { encoding: 'utf8' });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage: node .*verify-packet\.mjs/);
});

test('verifier rejects --packet without a value cleanly', () => {
  const result = runVerifier(['--packet']);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /--packet requires a value/);
  assert.doesNotMatch(result.stderr, /TypeError|at .*verify-packet/);
});

test('verifier qualifies structural success when no complete rebuild claim is made', () => {
  const temp = mkdtempSync(join(tmpdir(), 'packet-stub-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);

  const result = runVerifier(['--packet', packetDir, '--out', join(packetDir, 'evidence', 'packet-verification.json')]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Packet structure valid/);
  assert.doesNotMatch(result.stdout, /Packet verification passed/);
});

test('verifier accepts --packet=value form for explicit packet paths', () => {
  const temp = mkdtempSync(join(tmpdir(), 'packet-equals-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);

  const result = runVerifier([`--packet=${packetDir}`, '--out', join(packetDir, 'evidence', 'packet-verification.json')]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Packet structure valid/);
});

test('npm package excludes local agent state and keeps verifier bins executable', () => {
  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.equal(result.status, 0, result.stderr);
  const [pack] = JSON.parse(result.stdout);
  const files = new Map(pack.files.map((file) => [file.path, file]));
  for (const path of files.keys()) {
    assert.doesNotMatch(path, /^(?:\.agents|\.claude)(?:\/|$)/);
    assert.notEqual(path, 'skills-lock.json');
    assert.doesNotMatch(path, /\.tgz$/);
  }
  for (const path of ['bin/verify.mjs', 'bin/verify-packet.mjs', 'bin/lifecycle.mjs']) {
    assert.equal(files.has(path), true, `${path} missing from npm package`);
    assert.notEqual(files.get(path).mode & 0o111, 0, `${path} should remain executable`);
  }
});

test('PACKAGE-MANIFEST.json includedPaths matches the npm pack surface exactly', () => {
  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.equal(result.status, 0, result.stderr);
  const [pack] = JSON.parse(result.stdout);
  const packedTopLevelPaths = [...new Set(
    pack.files.map((file) => (file.path.includes('/') ? `${file.path.split('/')[0]}/` : file.path))
  )].sort();
  const manifest = JSON.parse(readFileSync(join(repoRoot, 'PACKAGE-MANIFEST.json'), 'utf8'));

  assert.deepEqual(
    [...manifest.includedPaths].sort(),
    packedTopLevelPaths,
    'PACKAGE-MANIFEST.json includedPaths drifted from npm pack --dry-run --json; update the manifest to match the shipped surface'
  );
});

test('public repository surface includes conventional license, CI, and contribution metadata', () => {
  const license = readFileSync(join(repoRoot, 'LICENSE'), 'utf8');
  const workflow = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8');
  const contributing = readFileSync(join(repoRoot, 'CONTRIBUTING.md'), 'utf8');
  const security = readFileSync(join(repoRoot, 'SECURITY.md'), 'utf8');
  const packageJson = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));

  assert.match(license, /^MIT License\n/);
  assert.equal(existsSync(join(repoRoot, 'LICENSE.md')), false);
  assert.match(workflow, /node-version: 20/);
  assert.match(workflow, /npm test/);
  assert.match(workflow, /sync-skill-package\.mjs --check/);
  assert.match(workflow, /npm pack --dry-run --json/);
  assert.match(workflow, /browser-runtime:[\s\S]*runs-on: ubuntu-24\.04/);
  assert.match(workflow, /ddev\/github-action-setup-ddev@v1[\s\S]*autostart: false[\s\S]*version: 1\.25\.3/);
  assert.match(workflow, /setup-browser-runtime\.sh/);
  assert.match(workflow, /browser-runtime-smoke\.mjs/);
  assert.match(contributing, /sync-skill-package\.mjs --write/);
  assert.match(security, /private vulnerability reporting/);
  assert.equal(packageJson.homepage, 'https://github.com/scottfalconer/agent-ready-drupal-build-kit#readme');
  assert.equal(packageJson.bugs.url, 'https://github.com/scottfalconer/agent-ready-drupal-build-kit/issues');
  assert.ok(packageJson.keywords.includes('drupal-cms'));
});

test('README leads with the same concise bootstrap prompt as USAGE', () => {
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  const usage = readFileSync(join(repoRoot, 'USAGE.md'), 'utf8');
  const start = readFileSync(join(repoRoot, 'START.md'), 'utf8');
  const readmePrompt = textPromptAfter(readme, '## Copy This Prompt');
  const usagePrompt = textPromptAfter(usage, '## Canonical Prompt');
  const readmeBriefPrompt = textPromptAfter(readme, '### No source site? Use a brief');
  const usageBriefPrompt = textPromptAfter(usage, '## Brief-Only Prompt');

  assert.equal(usagePrompt, readmePrompt);
  assert.match(usagePrompt, /Source site: \[SOURCE_URL\]/);
  assert.match(usagePrompt, /handle all setup yourself/);
  assert.match(usagePrompt, /Work in exactly one Drupal project/);
  assert.match(usagePrompt, /first meaningful source-shaped route/);
  assert.match(usagePrompt, /real Drupal site passes the kit's verification/);
  assert.ok(usagePrompt.split('\n').length <= 12, 'canonical prompt should stay concise');
  assert.equal(usageBriefPrompt, readmeBriefPrompt);
  assert.match(usageBriefPrompt, /Brief: \[BRIEF_FILE\]/);
  assert.match(usageBriefPrompt, /initialize the kit in brief mode/);
  assert.match(usageBriefPrompt, /do not claim source-site parity/);
  assert.doesNotMatch(usageBriefPrompt, /Source site: \[SOURCE_URL\]/);
  assert.ok(readme.indexOf('## Copy This Prompt') < readme.indexOf('### No source site? Use a brief'));
  assert.match(readme, /if the project starts from requirements instead/i);
  assert.ok(readme.indexOf('```text') < readme.indexOf('bash <('), 'copy-paste prompt should precede manual setup');
  assert.match(start, /on macOS, Docker Desktop or OrbStack installed and running/);
  assert.doesNotMatch(start, /supplies the rest: Docker/);
  assertCanonicalBrowserBootstrap(readme, 'README.md');
  assertCanonicalBrowserBootstrap(start, 'START.md');
  assertCanonicalBrowserBootstrap(usage, 'USAGE.md');
});

test('cookbook stays executable, Drush 13 compatible, and referenced from skill surfaces', () => {
  const cookbook = readFileSync(join(repoRoot, 'docs', 'cookbook.md'), 'utf8');
  const skill = readFileSync(join(repoRoot, 'skills', 'agent-ready-drupal-build-kit', 'SKILL.md'), 'utf8');
  const playbook = readFileSync(join(repoRoot, 'docs', 'build-playbook.md'), 'utf8');
  const gapList = readFileSync(join(templatesDir, 'scoped-gap-list.template.md'), 'utf8');

  assert.match(skill, /references\/cookbook\.md/);
  assert.match(playbook, /references\/cookbook\.md/);

  for (const move of [
    /role:create/,
    /role:perm:add/,
    /user:create/,
    /uli --name=/,
    /user:information/,
    /'format' => 'basic_html'/,
    /pathauto\.pattern\./,
    /system_messages_block/,
    /local_tasks_block/,
    /title_prefix/,
    /CacheableResponse/,
    /\['#cache'\]\['contexts'\]\[\]\s*=\s*'route'/,
    /results_lifespan/,
    /node_preview/,
    /metatag_views/,
    /system\.menu\./
  ]) {
    assert.match(cookbook, move);
  }

  assert.doesNotMatch(cookbook, /drush (?:role-create|role-add-perm|user-create|user-add-role|pm-enable)\b/);
  assert.doesNotMatch(cookbook, /role:perm:add[^\n]*full_html/);
  assert.doesNotMatch(cookbook, /'format' => 'full_html'/);
  assert.doesNotMatch(cookbook, /user_load_by_name\s*\(/);
  assert.doesNotMatch(cookbook, /ddev composer require[^\n]*(?:\s-W\b|--with-all-dependencies)/);
  assert.doesNotMatch(cookbook, /str_starts_with\(\\Drupal::service\('path\.current'\)/);
  assert.match(cookbook, /get the human owner's approval before running `composer require`/);
  assert.match(cookbook, /<TARGET_COMPATIBLE_CONSTRAINT>/);
  assert.doesNotMatch(cookbook, /\/Users\/|\/home\/[a-z]/i);

  for (const stance of [
    'Multilingual stance',
    'Caching and performance budget stance',
    'Update strategy stance',
    '404-page quality stance'
  ]) {
    assert.match(gapList, new RegExp(stance));
  }
});

test('post-install assembly uses bounded Recipes and the available core runner', () => {
  const contract = readFileSync(join(repoRoot, 'AGENTS.md.template'), 'utf8');
  const decision = readFileSync(join(repoRoot, 'templates', 'recipe-start-point.template.md'), 'utf8');
  const playbook = readFileSync(join(repoRoot, 'docs', 'build-playbook.md'), 'utf8');

  for (const content of [contract, decision, playbook]) {
    assert.doesNotMatch(content, /ddev exec dr\b/);
    assert.doesNotMatch(content, /High-fit Drupal CMS template or site template/);
    assert.match(content, /php core\/scripts\/drupal recipe/);
  }
  assert.doesNotMatch(contract, /Fresh `drupal\/cms` installs currently resolve/);
  assert.doesNotMatch(contract, /Drupal core `dr` CLI/);
  assert.match(contract, /derive the exact Drupal CMS package, Drupal core minor, Drush version/);
  assert.match(contract, /do not layer a different full site template|Do not treat a different full site template/);
  assert.match(decision, /selected before installation/);
});
