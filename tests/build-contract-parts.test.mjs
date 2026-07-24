import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contractRoot = join(repoRoot, 'contract');
const manifest = JSON.parse(readFileSync(join(contractRoot, 'manifest.json'), 'utf8'));

test('the generated contract is the exact concatenation of its parts', () => {
  const composed = manifest.parts
    .map(({ file }) => readFileSync(join(contractRoot, file), 'utf8'))
    .join('\n');
  const generated = readFileSync(join(repoRoot, manifest.generated), 'utf8');
  assert.equal(
    composed,
    generated,
    'AGENTS.md.template drifted from contract/. Run: node scripts/build-contract.mjs --write'
  );
});

test('build-contract --check passes on the committed tree', () => {
  const output = execFileSync(process.execPath, [join(repoRoot, 'scripts', 'build-contract.mjs'), '--check'], {
    cwd: repoRoot,
    encoding: 'utf8'
  });
  assert.match(output, /Build contract is in sync/);
});

test('every part starts with its manifest heading and carries a summary', () => {
  for (const part of manifest.parts) {
    const body = readFileSync(join(contractRoot, part.file), 'utf8');
    assert.equal(body.split('\n', 1)[0], part.heading, `${part.file} must start with its manifest heading`);
    assert.ok(part.summary && part.summary.length > 10, `${part.file} needs a manifest summary for phase routing`);
    assert.equal(part.bytes, Buffer.byteLength(body), `${part.file} manifest byte count is stale`);
  }
});

test('no part is large enough to defeat progressive disclosure', () => {
  // The whole point of splitting is that a phase read stays small. The largest
  // section of the original contract is ~19 KB; anything beyond 32 KB means a
  // part needs splitting again rather than growing unbounded.
  for (const part of manifest.parts) {
    assert.ok(
      part.bytes <= 32_768,
      `contract/${part.file} is ${part.bytes} bytes; split it so a phase read stays small`
    );
  }
});

test('manifest lists every markdown part on disk exactly once', () => {
  const onDisk = readdirSync(contractRoot).filter((name) => name.endsWith('.md')).sort();
  const listed = manifest.parts.map(({ file }) => file).sort();
  assert.deepEqual(listed, onDisk, 'contract/manifest.json must list every contract part');
  assert.equal(new Set(listed).size, listed.length, 'contract/manifest.json must not list a part twice');
});

test('the installed skill package ships the parts and the manifest index', () => {
  const skillContract = join(repoRoot, 'skills', 'agent-ready-drupal-build-kit', 'references', 'contract');
  for (const part of [...manifest.parts.map(({ file }) => file), 'manifest.json']) {
    assert.deepEqual(
      readFileSync(join(skillContract, part)),
      readFileSync(join(contractRoot, part)),
      `installed references/contract/${part} is out of sync`
    );
  }
});

test('SKILL.md routes agents to the phase part rather than the whole contract', () => {
  const skill = readFileSync(
    join(repoRoot, 'skills', 'agent-ready-drupal-build-kit', 'SKILL.md'),
    'utf8'
  );
  assert.match(skill, /references\/contract\/00-orientation\.md/);
  assert.match(skill, /references\/contract\/manifest\.json/);
  // The complete document must stay discoverable for search and human review.
  assert.match(skill, /references\/build-contract\.md/);
});
