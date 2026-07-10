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

test('each required review packet file has a matching template', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const missing = gates.reviewPacketFiles.filter((file) => !existsSync(join(templatesDir, requiredTemplateName(file))));

  assert.deepEqual(missing, []);
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
  for (const path of ['bin/verify.mjs', 'bin/verify-packet.mjs']) {
    assert.equal(files.has(path), true, `${path} missing from npm package`);
    assert.notEqual(files.get(path).mode & 0o111, 0, `${path} should remain executable`);
  }
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
  assert.match(contributing, /sync-skill-package\.mjs --write/);
  assert.match(security, /private vulnerability reporting/);
  assert.equal(packageJson.homepage, 'https://github.com/scottfalconer/agent-ready-drupal-build-kit#readme');
  assert.equal(packageJson.bugs.url, 'https://github.com/scottfalconer/agent-ready-drupal-build-kit/issues');
  assert.ok(packageJson.keywords.includes('drupal-cms'));
});

test('README and USAGE expose one concise canonical prompt with real-site progress', () => {
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  const usage = readFileSync(join(repoRoot, 'USAGE.md'), 'utf8');
  const start = readFileSync(join(repoRoot, 'START.md'), 'utf8');
  const readmePrompt = textPromptAfter(readme, 'Then replace `[SOURCE_URL]` and give the selected agent this prompt:');
  const usagePrompt = textPromptAfter(usage, '## Canonical Prompt');

  assert.equal(usagePrompt, readmePrompt);
  assert.match(usagePrompt, /Source site: \[SOURCE_URL\]/);
  assert.match(usagePrompt, /first meaningful source-shaped route/);
  assert.match(usagePrompt, /continue the full rebuild and verification loop/);
  assert.ok(usagePrompt.split('\n').length <= 12, 'canonical prompt should stay concise');
  assert.match(start, /on macOS, Docker Desktop or OrbStack installed and running/);
  assert.doesNotMatch(start, /supplies the rest: Docker/);
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
