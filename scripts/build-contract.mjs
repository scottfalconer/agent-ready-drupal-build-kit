#!/usr/bin/env node

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contractRoot = join(repoRoot, 'contract');

function usage() {
  return `Usage: node scripts/build-contract.mjs [--check|--write] [--quiet]

Concatenate the canonical per-phase contract parts in contract/ into the full
AGENTS.md.template contract. The parts are the source of truth; the combined
file is generated so existing readers and the installed skill package keep a
single complete document.

  --check   Report drift without writing (default)
  --write   Regenerate AGENTS.md.template from contract/manifest.json
  --quiet   Suppress success output
  --help    Show this help
`;
}

function parseArgs(argv) {
  const options = { mode: 'check', quiet: false };
  for (const argument of argv) {
    if (argument === '--help') {
      process.stdout.write(usage());
      process.exit(0);
    } else if (argument === '--check') {
      options.mode = 'check';
    } else if (argument === '--write') {
      options.mode = 'write';
    } else if (argument === '--quiet') {
      options.quiet = true;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options;
}

export function readManifest() {
  const manifest = JSON.parse(readFileSync(join(contractRoot, 'manifest.json'), 'utf8'));
  if (manifest.schemaVersion !== 'public-kit.build-contract-parts.1') {
    throw new Error(`Unsupported contract manifest schemaVersion: ${manifest.schemaVersion}`);
  }
  if (!Array.isArray(manifest.parts) || manifest.parts.length === 0) {
    throw new Error('contract/manifest.json must list at least one part.');
  }
  return manifest;
}

// A part on disk that no manifest entry references would be shipped by
// `npm pack` while contributing nothing to the generated contract. `npm test`
// catches it; check for it here too so `prepack` refuses to publish one.
function assertNoOrphanParts(manifest) {
  const listed = new Set(manifest.parts.map(({ file }) => file));
  const orphans = readdirSync(contractRoot)
    .filter((name) => name.endsWith('.md') && !listed.has(name))
    .sort();
  if (orphans.length > 0) {
    throw new Error(
      `contract/ has parts that contract/manifest.json does not list:\n${orphans.map((name) => `- ${name}`).join('\n')}`
    );
  }
}

export function composeContract() {
  const manifest = readManifest();
  assertNoOrphanParts(manifest);
  const bodies = manifest.parts.map(({ file, heading }) => {
    const body = readFileSync(join(contractRoot, file), 'utf8');
    if (body.includes('\r\n')) {
      throw new Error(
        `contract/${file} has CRLF line endings. The contract is joined byte-for-byte, so parts must use LF. ` +
        'Re-save the file with LF endings (the repository .gitattributes keeps contract/*.md as LF).'
      );
    }
    const firstLine = body.split('\n', 1)[0];
    if (firstLine !== heading) {
      throw new Error(`contract/${file} must start with its manifest heading "${heading}" but starts with "${firstLine}".`);
    }
    return body;
  });
  // Parts are split on line boundaries, so a single newline restores the original document.
  return bodies.join('\n');
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const composed = composeContract();
  const generatedPath = join(repoRoot, readManifest().generated);

  if (options.mode === 'write') {
    writeFileSync(generatedPath, composed);
    // Keep the manifest's recorded byte counts current. Without this, editing a
    // part leaves a stale count that --check accepts but `npm test` rejects,
    // so the documented fix command would not actually fix the tree.
    const manifest = readManifest();
    let manifestChanged = false;
    for (const part of manifest.parts) {
      const bytes = Buffer.byteLength(readFileSync(join(contractRoot, part.file)));
      if (part.bytes !== bytes) {
        part.bytes = bytes;
        manifestChanged = true;
      }
    }
    if (manifestChanged) {
      writeFileSync(join(contractRoot, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    }
  }

  const current = readFileSync(generatedPath, 'utf8');
  if (current !== composed) {
    throw new Error(
      'AGENTS.md.template is out of sync with contract/. Edit the part under contract/ and run: node scripts/build-contract.mjs --write'
    );
  }

  if (!options.quiet) {
    const manifest = readManifest();
    process.stdout.write(
      `Build contract ${options.mode === 'write' ? 'regenerated' : 'is in sync'} (${manifest.parts.length} parts).\n`
    );
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
