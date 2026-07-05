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
