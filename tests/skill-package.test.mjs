import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const skillRoot = join(repoRoot, 'skills', 'agent-ready-drupal-build-kit');
const initializer = join(skillRoot, 'scripts', 'init-kit.mjs');
const syncScript = join(repoRoot, 'scripts', 'sync-skill-package.mjs');
const startMarker = '<!-- agent-ready-drupal-build-kit:start -->';
const endMarker = '<!-- agent-ready-drupal-build-kit:end -->';

function runInitializer(script, cwd, extraArgs = []) {
  return spawnSync(process.execPath, [
    script,
    '--source-url',
    'https://source.example/site',
    ...extraArgs
  ], {
    cwd,
    encoding: 'utf8'
  });
}

function runBriefInitializer(script, cwd, briefFile, extraArgs = []) {
  return spawnSync(process.execPath, [
    script,
    '--brief-file',
    briefFile,
    ...extraArgs
  ], {
    cwd,
    encoding: 'utf8'
  });
}

function makeDrupalTarget(prefix = 'skill-target-') {
  const root = mkdtempSync(join(tmpdir(), prefix));
  mkdirSync(join(root, '.ddev'), { recursive: true });
  writeFileSync(join(root, '.ddev', 'config.yaml'), 'name: kit-test\ntype: drupal11\ndocroot: web\n');
  return root;
}

function occurrenceCount(content, needle) {
  return content.split(needle).length - 1;
}

test('installable skill describes an in-place target and only installed runtime paths', () => {
  const content = readFileSync(join(skillRoot, 'SKILL.md'), 'utf8');
  const projectBlock = readFileSync(join(skillRoot, 'assets', 'AGENTS.block.md'), 'utf8');

  assert.equal(existsSync(join(repoRoot, 'skill.md')), false, 'root skill.md would shadow the self-contained nested skill');
  assert.match(content, /^name: agent-ready-drupal-build-kit$/m);
  assert.match(content, /current project is the target/);
  assert.match(content, /scripts\/init-kit\.mjs/);
  assert.match(content, /scripts\/verify\.mjs/);
  assert.match(content, /references\/build-contract\.md/);
  assert.match(content, /references\/output-inventory\.md/);
  assert.match(content, /references\/USAGE\.md/);
  assert.doesNotMatch(content, /git clone/);
  assert.doesNotMatch(content, /\.\.\/agent-ready-drupal-build-kit/);
  assert.doesNotMatch(content, /Create a clean Drupal CMS project workspace alongside/);
  assert.match(projectBlock, /non-empty tracked sync directory/);
  assert.match(projectBlock, /active configuration has no drift/);
  assert.match(projectBlock, /perform live inspection and must run inside DDEV/);
  assert.match(projectBlock, /plain `node` live commands below assume the\s+active DDEV agent/);
  assert.doesNotMatch(projectBlock, /Commands below use host `node`/);
  assert.doesNotMatch(projectBlock, /survives clean import/);
});

test('initializer refuses to write outside an existing Drupal/DDEV target', () => {
  const root = mkdtempSync(join(tmpdir(), 'skill-not-drupal-'));
  const agentsPath = join(root, 'AGENTS.md');
  writeFileSync(agentsPath, '# User instructions\n');

  const result = runInitializer(initializer, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /No existing Drupal\/DDEV target found/);
  assert.equal(readFileSync(agentsPath, 'utf8'), '# User instructions\n');
  assert.equal(existsSync(join(root, 'review-packet')), false);
});

test('initializer does not mistake a Drupal extension package for a site target', () => {
  const root = mkdtempSync(join(tmpdir(), 'skill-contrib-module-'));
  writeFileSync(join(root, 'composer.json'), `${JSON.stringify({
    name: 'drupal/example',
    type: 'drupal-module',
    'require-dev': { 'drupal/core': '^11' }
  }, null, 2)}\n`);

  const result = runInitializer(initializer, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /No existing Drupal\/DDEV target found/);
  assert.equal(existsSync(join(root, 'AGENTS.md')), false);
  assert.equal(existsSync(join(root, 'review-packet')), false);
});

test('initializer does not treat Drupal Composer tooling alone as a site runtime', () => {
  const root = mkdtempSync(join(tmpdir(), 'skill-composer-tooling-'));
  writeFileSync(join(root, 'composer.json'), `${JSON.stringify({
    name: 'example/scaffold-only',
    type: 'project',
    require: { 'drupal/core-composer-scaffold': '^11' }
  }, null, 2)}\n`);

  const result = runInitializer(initializer, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /No existing Drupal\/DDEV target found/);
  assert.equal(existsSync(join(root, 'AGENTS.md')), false);
});

test('initializer rejects credential-bearing source URLs and unsafe packet destinations before writing', () => {
  const root = makeDrupalTarget('skill-unsafe-input-');

  const credentialResult = runInitializer(initializer, root, [
    '--source-url=https://user:secret@source.example/'
  ]);
  assert.notEqual(credentialResult.status, 0);
  assert.match(credentialResult.stderr, /must not contain embedded credentials/);

  const rootPacketResult = runInitializer(initializer, root, ['--packet=.']);
  assert.notEqual(rootPacketResult.status, 0);
  assert.match(rootPacketResult.stderr, /not the target root/);

  assert.equal(existsSync(join(root, 'AGENTS.md')), false);
  assert.equal(existsSync(join(root, 'review-packet')), false);
});

test('initializer dry-run honors an explicit project and nested packet without writing', () => {
  const root = makeDrupalTarget('skill-explicit-project-');
  const outside = mkdtempSync(join(tmpdir(), 'skill-explicit-cwd-'));

  const result = runInitializer(initializer, outside, [
    '--project',
    root,
    '--packet=evidence/review',
    '--dry-run'
  ]);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Dry run valid:/);
  assert.match(result.stdout, /AGENTS\.md: would update kit block/);
  assert.match(result.stdout, /Review packet: 22 missing, 0 preserved/);
  assert.equal(existsSync(join(root, 'AGENTS.md')), false);
  assert.equal(existsSync(join(root, 'evidence')), false);
});

test('initializer rejects packet traversal, file destinations, and ancestor symlink escapes', () => {
  const traversalRoot = makeDrupalTarget('skill-packet-traversal-');
  const traversalResult = runInitializer(initializer, traversalRoot, ['--packet=../escape']);
  assert.notEqual(traversalResult.status, 0);
  assert.match(traversalResult.stderr, /directory inside the Drupal target/);
  assert.equal(existsSync(join(traversalRoot, 'AGENTS.md')), false);

  const fileRoot = makeDrupalTarget('skill-packet-file-');
  writeFileSync(join(fileRoot, 'review-packet'), 'not a directory\n');
  const fileResult = runInitializer(initializer, fileRoot);
  assert.notEqual(fileResult.status, 0);
  assert.match(fileResult.stderr, /must name a directory/);
  assert.equal(existsSync(join(fileRoot, 'AGENTS.md')), false);

  const linkedRoot = makeDrupalTarget('skill-packet-ancestor-link-');
  const outside = mkdtempSync(join(tmpdir(), 'skill-packet-ancestor-outside-'));
  symlinkSync(outside, join(linkedRoot, 'linked'));
  const linkedResult = runInitializer(initializer, linkedRoot, ['--packet=linked/review-packet']);
  assert.notEqual(linkedResult.status, 0);
  assert.match(linkedResult.stderr, /must not escape the Drupal target through a symbolic link/);
  assert.equal(existsSync(join(linkedRoot, 'AGENTS.md')), false);
  assert.equal(existsSync(join(outside, 'review-packet')), false);
});

test('initializer rejects AGENTS and packet symlinks before any project write', () => {
  const agentsRoot = makeDrupalTarget('skill-agents-link-');
  const agentsOutside = mkdtempSync(join(tmpdir(), 'skill-agents-outside-'));
  const outsideAgentsPath = join(agentsOutside, 'AGENTS.md');
  symlinkSync(outsideAgentsPath, join(agentsRoot, 'AGENTS.md'));

  const agentsResult = runInitializer(initializer, agentsRoot);
  assert.notEqual(agentsResult.status, 0);
  assert.match(agentsResult.stderr, /AGENTS\.md is a symbolic link/);
  assert.equal(existsSync(outsideAgentsPath), false);
  assert.equal(existsSync(join(agentsRoot, 'review-packet')), false);

  const packetRoot = makeDrupalTarget('skill-packet-link-');
  const packetOutside = mkdtempSync(join(tmpdir(), 'skill-packet-outside-'));
  const outsideEvidence = join(packetOutside, 'source-audit.json');
  writeFileSync(outsideEvidence, '{"outside":true}\n');
  mkdirSync(join(packetRoot, 'review-packet'));
  symlinkSync(outsideEvidence, join(packetRoot, 'review-packet', 'source-audit.json'));

  const packetResult = runInitializer(initializer, packetRoot);
  assert.notEqual(packetResult.status, 0);
  assert.match(packetResult.stderr, /Review packet paths must be regular non-symlink files: source-audit\.json/);
  assert.equal(readFileSync(outsideEvidence, 'utf8'), '{"outside":true}\n');
  assert.equal(existsSync(join(packetRoot, 'AGENTS.md')), false);
});

test('initializer recognizes normal quoted or whitespace-padded DDEV Drupal types', () => {
  const root = mkdtempSync(join(tmpdir(), 'skill-ddev-type-'));
  mkdirSync(join(root, '.ddev'), { recursive: true });
  writeFileSync(join(root, '.ddev', 'config.yaml'), "name: kit-test\ntype: 'drupal11'   \n");

  const result = runInitializer(initializer, root);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(join(root, 'review-packet', 'source-audit.json')), true);
});

test('initializer accepts a Composer project that explicitly requires Drupal core', () => {
  const root = mkdtempSync(join(tmpdir(), 'skill-composer-project-'));
  writeFileSync(join(root, 'composer.json'), `${JSON.stringify({
    name: 'example/site',
    type: 'project',
    require: { 'drupal/core-recommended': '^11' }
  }, null, 2)}\n`);

  const result = runInitializer(initializer, root);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(join(root, 'review-packet', 'source-audit.json')), true);
});

test('initializer climbs past a Drupal docroot and writes only at the project root', () => {
  const root = makeDrupalTarget('skill-nested-docroot-');
  const nestedModule = join(root, 'web', 'modules', 'custom', 'example');
  mkdirSync(join(root, 'web', 'core', 'lib'), { recursive: true });
  writeFileSync(join(root, 'web', 'core', 'lib', 'Drupal.php'), '<?php\n');
  mkdirSync(nestedModule, { recursive: true });

  const result = runInitializer(initializer, nestedModule);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Kit initialized:/);
  assert.equal(existsSync(join(root, 'AGENTS.md')), true);
  assert.equal(existsSync(join(root, 'review-packet', 'source-audit.json')), true);
  assert.equal(existsSync(join(root, 'web', 'AGENTS.md')), false);
  assert.equal(existsSync(join(root, 'web', 'review-packet')), false);
});

test('initializer preserves OLI and user instructions and is idempotent', () => {
  const root = makeDrupalTarget();
  const agentsPath = join(root, 'AGENTS.md');
  const original = `# Existing project instructions

<!-- one-line-installer:start -->
OLI managed content
<!-- one-line-installer:end -->

User-authored tail.
`;
  writeFileSync(agentsPath, original);

  const first = runInitializer(initializer, root);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /Kit initialized/);

  const firstAgents = readFileSync(agentsPath, 'utf8');
  assert.ok(firstAgents.startsWith(original));
  assert.match(firstAgents, /OLI managed content/);
  assert.match(firstAgents, /User-authored tail\./);
  assert.equal(occurrenceCount(firstAgents, startMarker), 1);
  assert.equal(occurrenceCount(firstAgents, endMarker), 1);
  assert.match(firstAgents, /https:\/\/source\.example\/site/);

  const gates = JSON.parse(readFileSync(join(skillRoot, 'gates.json'), 'utf8'));
  for (const packetFile of gates.reviewPacketFiles) {
    assert.equal(existsSync(join(root, 'review-packet', packetFile)), true, packetFile);
  }

  const sourceAudit = join(root, 'review-packet', 'source-audit.json');
  writeFileSync(sourceAudit, '{"preserve":"user evidence"}\n');

  const second = runInitializer(initializer, root);
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /AGENTS\.md: unchanged/);
  assert.match(second.stdout, /0 created, 22 preserved/);
  assert.equal(readFileSync(agentsPath, 'utf8'), firstAgents);
  assert.equal(readFileSync(sourceAudit, 'utf8'), '{"preserve":"user evidence"}\n');

  const changedSource = runInitializer(initializer, root, ['--source-url=https://changed.example/']);
  assert.equal(changedSource.status, 0, changedSource.stderr);
  const changedAgents = readFileSync(agentsPath, 'utf8');
  assert.ok(changedAgents.startsWith(original));
  assert.match(changedAgents, /https:\/\/changed\.example\//);
  assert.doesNotMatch(changedAgents, /https:\/\/source\.example\/site/);
  assert.equal(occurrenceCount(changedAgents, startMarker), 1);
  assert.equal(occurrenceCount(changedAgents, endMarker), 1);
  assert.equal(readFileSync(sourceAudit, 'utf8'), '{"preserve":"user evidence"}\n');
  assert.deepEqual(
    JSON.parse(readFileSync(join(root, 'review-packet', 'build-input.json'), 'utf8')),
    {
      schemaVersion: 'public-kit.build-input.1',
      mode: 'source_site',
      sourceUrl: 'https://changed.example/',
      brief: null
    }
  );
});

test('initializer creates a hash-bound brief packet without inventing a source site', () => {
  const root = makeDrupalTarget('skill-brief-mode-');
  const briefPath = join(root, 'site-brief.md');
  const brief = '# Site brief\n\nBuild a public homepage and an editable event listing.\n';
  writeFileSync(briefPath, brief);

  const result = runBriefInitializer(initializer, root, 'site-brief.md');

  assert.equal(result.status, 0, result.stderr);
  const expectedHash = `sha256:${createHash('sha256').update(brief).digest('hex')}`;
  assert.equal(readFileSync(join(root, 'review-packet', 'original-brief.md'), 'utf8'), brief);
  assert.deepEqual(
    JSON.parse(readFileSync(join(root, 'review-packet', 'build-input.json'), 'utf8')),
    {
      schemaVersion: 'public-kit.build-input.1',
      mode: 'brief',
      sourceUrl: '',
      brief: {
        path: 'review-packet/original-brief.md',
        sha256: expectedHash
      }
    }
  );
  assert.equal(
    JSON.parse(readFileSync(join(root, 'review-packet', 'brief-acceptance.json'), 'utf8')).briefSha256,
    expectedHash
  );
  const agents = readFileSync(join(root, 'AGENTS.md'), 'utf8');
  assert.match(agents, /Build basis: `brief`/);
  assert.match(agents, /Source-site parity is not claimed/);
  assert.doesNotMatch(agents, /https:\/\/source\.example/);

  const repeated = runBriefInitializer(initializer, root, 'site-brief.md');
  assert.equal(repeated.status, 0, repeated.stderr);
  assert.match(repeated.stdout, /AGENTS\.md: unchanged/);
  assert.match(repeated.stdout, /0 created, 22 preserved/);

  const packetOnly = spawnSync(process.execPath, [
    join(skillRoot, 'scripts', 'verify.mjs'),
    '--packet',
    'review-packet',
    '--packet-only'
  ], { cwd: root, encoding: 'utf8' });
  assert.equal(packetOnly.status, 0, packetOnly.stderr);
  const packetReport = JSON.parse(
    readFileSync(join(root, 'review-packet', 'evidence', 'packet-verification.json'), 'utf8')
  );
  assert.equal(packetReport.valid, true);
  assert.equal(packetReport.buildMode, 'brief');
  assert.equal(packetReport.claimScope, 'complete-local-build-from-brief');
  assert.equal(packetReport.completeLocalBuildFromBriefClaimAllowed, false);
});

test('initializer requires exactly one source or brief and keeps packet modes separate', () => {
  const root = makeDrupalTarget('skill-build-input-choice-');
  writeFileSync(join(root, 'brief.md'), '# Brief\n');

  const missing = spawnSync(process.execPath, [initializer], { cwd: root, encoding: 'utf8' });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /exactly one of --source-url or --brief-file is required/);

  const conflicting = runInitializer(initializer, root, ['--brief-file=brief.md']);
  assert.notEqual(conflicting.status, 0);
  assert.match(conflicting.stderr, /mutually exclusive starting points/);

  const source = runInitializer(initializer, root);
  assert.equal(source.status, 0, source.stderr);
  const switchToBrief = runBriefInitializer(initializer, root, 'brief.md');
  assert.notEqual(switchToBrief.status, 0);
  assert.match(switchToBrief.stderr, /different build basis/);
  assert.equal(existsSync(join(root, 'review-packet', 'original-brief.md')), false);
});

test('initializer fails closed on malformed markers before changing the target', () => {
  const root = makeDrupalTarget('skill-bad-marker-');
  const agentsPath = join(root, 'AGENTS.md');
  const malformed = `# Existing\n\n${startMarker}\nunterminated\n`;
  writeFileSync(agentsPath, malformed);

  const result = runInitializer(initializer, root);

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /malformed or duplicate/);
  assert.equal(readFileSync(agentsPath, 'utf8'), malformed);
  assert.equal(existsSync(join(root, 'review-packet')), false);
});

test('initializer leaves existing AGENTS.md unchanged when packet creation fails', () => {
  const root = makeDrupalTarget('skill-unwritable-packet-');
  const agentsPath = join(root, 'AGENTS.md');
  const packetPath = join(root, 'review-packet');
  const original = '# Existing project instructions\n\nDo not alter this file on a failed initialization.\n';
  writeFileSync(agentsPath, original);
  mkdirSync(packetPath);
  chmodSync(packetPath, 0o555);

  try {
    const result = runInitializer(initializer, root);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Initializer failed:/);
    assert.equal(readFileSync(agentsPath, 'utf8'), original);
    assert.equal(existsSync(join(packetPath, 'source-audit.json')), false);
  } finally {
    chmodSync(packetPath, 0o755);
  }
});

test('initializer runs from a copy containing only the installed skill directory', () => {
  const root = mkdtempSync('/tmp/skill-isolated-');
  mkdirSync(join(root, '.ddev'), { recursive: true });
  writeFileSync(join(root, '.ddev', 'config.yaml'), 'name: kit-test\ntype: drupal11\ndocroot: web\n');
  const installedSkill = join(root, '.agents', 'skills', 'agent-ready-drupal-build-kit');
  mkdirSync(dirname(installedSkill), { recursive: true });
  cpSync(skillRoot, installedSkill, { recursive: true });

  const result = runInitializer(join(installedSkill, 'scripts', 'init-kit.mjs'), root);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(join(root, 'review-packet', 'source-audit.json')), true);
  const agents = readFileSync(join(root, 'AGENTS.md'), 'utf8');
  assert.match(agents, /\.agents\/skills\/agent-ready-drupal-build-kit\/SKILL\.md/);
  assert.match(agents, /Canonical workflow:.*\(\.agents\/skills\/agent-ready-drupal-build-kit\/SKILL\.md\)/);
  assert.doesNotMatch(agents, /\.\.\/.*(?:private\/)?tmp\/.*\.agents\/skills/);
  assert.doesNotMatch(agents, /\/Users\//);

  for (const verifier of ['verify.mjs', 'verify-packet.mjs']) {
    const verifierPath = join(installedSkill, 'scripts', verifier);
    assert.equal(existsSync(verifierPath), true, verifier);
    assert.notEqual(statSync(verifierPath).mode & 0o111, 0, `${verifier} should be executable`);
    const help = spawnSync(process.execPath, [verifierPath, '--help'], { cwd: root, encoding: 'utf8' });
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /<path-to-skill>\/scripts\/verify/);
    assert.doesNotMatch(help.stdout, /node bin\/verify/);
  }

  const lifecyclePath = join(installedSkill, 'scripts', 'lifecycle.mjs');
  assert.equal(existsSync(lifecyclePath), true);
  assert.notEqual(statSync(lifecyclePath).mode & 0o111, 0, 'lifecycle.mjs should be executable');
  const lifecycleHelp = spawnSync(process.execPath, [lifecyclePath, '--help'], {
    cwd: root,
    encoding: 'utf8'
  });
  assert.equal(lifecycleHelp.status, 0, lifecycleHelp.stderr);
  assert.match(lifecycleHelp.stdout, /lifecycle\.mjs/);

  const packetOnly = spawnSync(process.execPath, [
    join(installedSkill, 'scripts', 'verify.mjs'),
    '--packet',
    'review-packet',
    '--packet-only'
  ], { cwd: root, encoding: 'utf8' });
  assert.equal(packetOnly.status, 0, packetOnly.stderr);
  assert.match(packetOnly.stdout, /packet-only verification never authorizes completion/);
  const packetReport = JSON.parse(
    readFileSync(join(root, 'review-packet', 'evidence', 'packet-verification.json'), 'utf8')
  );
  assert.equal(packetReport.verificationMode, 'packet-only');
  assert.equal(packetReport.completeLocalRebuildClaimAllowed, false);
});

test('installed skill runtime matches canonical root assets and verifiers', () => {
  const result = spawnSync(process.execPath, [syncScript, '--check'], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /is in sync \(49 files\)/);
  assert.ok(readFileSync(
    join(repoRoot, 'assets', 'vendor', 'axe-core', '4.10.3', 'axe.min.js')
  ).equals(readFileSync(
    join(repoRoot, 'skills', 'agent-ready-drupal-build-kit', 'assets', 'vendor', 'axe-core', '4.10.3', 'axe.min.js')
  )));
  for (const relativePath of [
    ['assets', 'browser-runtime', 'runtime.json'],
    ['assets', 'browser-runtime', 'docker-compose.zz-agent-ready-verifier.yaml'],
    ['scripts', 'browser-runtime-common.sh'],
    ['scripts', 'browser-runtime-smoke.mjs'],
    ['scripts', 'setup-browser-runtime.sh'],
    ['scripts', 'repair-browser-runtime.sh'],
    ['vendor', 'ws', '8.21.0', 'ws.mjs'],
    ['vendor', 'ws', '8.21.0', 'LICENSE'],
    ['vendor', 'ws', '8.21.0', 'INTEGRITY.json']
  ]) {
    assert.ok(readFileSync(
      join(repoRoot, ...relativePath)
    ).equals(readFileSync(
      join(skillRoot, ...relativePath)
    )), `${relativePath.join('/')} drifted from the canonical runtime`);
  }
  assert.ok(readFileSync(
    join(repoRoot, 'bin', 'review-handoff.mjs')
  ).equals(readFileSync(
    join(skillRoot, 'scripts', 'review-handoff.mjs')
  )), 'scripts/review-handoff.mjs drifted from the canonical runtime');
  for (const relativePath of [
    ['scripts', 'browser-runtime-smoke.mjs'],
    ['scripts', 'setup-browser-runtime.sh'],
    ['scripts', 'repair-browser-runtime.sh'],
    ['scripts', 'review-handoff.mjs']
  ]) {
    assert.notEqual(
      statSync(join(skillRoot, ...relativePath)).mode & 0o111,
      0,
      `${relativePath.join('/')} should be executable in the installed skill`
    );
  }
});

test('sync checker reports drift and write mode repairs bytes and executable bits', () => {
  const parent = mkdtempSync(join(tmpdir(), 'skill-sync-repo-'));
  const isolatedRepo = join(parent, 'repo');
  const excluded = new Set([
    join(repoRoot, '.git'),
    join(repoRoot, 'node_modules')
  ]);
  cpSync(repoRoot, isolatedRepo, {
    recursive: true,
    filter(source) {
      return ![...excluded].some((path) => source === path || source.startsWith(`${path}/`));
    }
  });

  const isolatedSync = join(isolatedRepo, 'scripts', 'sync-skill-package.mjs');
  const copiedGates = join(isolatedRepo, 'skills', 'agent-ready-drupal-build-kit', 'gates.json');
  const copiedVerifier = join(isolatedRepo, 'skills', 'agent-ready-drupal-build-kit', 'scripts', 'verify.mjs');
  writeFileSync(copiedGates, '{"drift":true}\n');
  chmodSync(copiedVerifier, 0o644);

  const drift = spawnSync(process.execPath, [isolatedSync, '--check'], {
    cwd: isolatedRepo,
    encoding: 'utf8'
  });
  assert.notEqual(drift.status, 0);
  assert.match(drift.stderr, /Installable skill package is out of sync/);
  assert.match(drift.stderr, /gates\.json/);
  assert.match(drift.stderr, /verify\.mjs/);

  const repair = spawnSync(process.execPath, [isolatedSync, '--write'], {
    cwd: isolatedRepo,
    encoding: 'utf8'
  });
  assert.equal(repair.status, 0, repair.stderr);
  assert.match(repair.stdout, /Skill package synced \(49 files\)/);
  assert.equal(readFileSync(copiedGates, 'utf8'), readFileSync(join(isolatedRepo, 'gates.json'), 'utf8'));
  assert.notEqual(statSync(copiedVerifier).mode & 0o111, 0);
});
