#!/usr/bin/env node

import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifierSelfEvidence } from '../bin/verify-packet.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const skillRoot = join(repoRoot, 'skills', 'agent-ready-drupal-build-kit');
const VERIFIER_HASHES_FILE = 'VERIFIER-HASHES.json';

function usage() {
  return `Usage: node scripts/sync-skill-package.mjs [--check|--write] [--assets-only] [--quiet]

Keep canonical root gates/templates/references and verifier entrypoints byte-for-byte aligned
with the self-contained installable Agent Skill, and publish the verifier hashes manifest
both copies report provenance against.

  --check        Report drift without writing (default)
  --write        Copy canonical files into the skill package
  --assets-only  Check/copy gates, templates, and references but defer verifier entrypoints
  --quiet        Suppress success output (useful for package lifecycle hooks)
  --help         Show this help
`;
}

function templateName(packetFile) {
  const parsed = parse(packetFile);
  return `${parsed.name}.template${parsed.ext}`;
}

function parseArgs(argv) {
  const options = { assetsOnly: false, mode: 'check', quiet: false };
  for (const argument of argv) {
    if (argument === '--help') {
      process.stdout.write(usage());
      process.exit(0);
    }
    if (argument === '--assets-only') {
      options.assetsOnly = true;
    } else if (argument === '--quiet') {
      options.quiet = true;
    } else if (argument === '--check') {
      options.mode = 'check';
    } else if (argument === '--write') {
      options.mode = 'write';
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options;
}

function copyPlan(assetsOnly) {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const plan = [
    { source: join(repoRoot, 'gates.json'), destination: join(skillRoot, 'gates.json') },
    { source: join(repoRoot, 'AGENTS.md.template'), destination: join(skillRoot, 'references', 'build-contract.md') },
    { source: join(repoRoot, 'USAGE.md'), destination: join(skillRoot, 'references', 'USAGE.md') },
    { source: join(repoRoot, 'docs', 'output-inventory.md'), destination: join(skillRoot, 'references', 'output-inventory.md') },
    { source: join(repoRoot, 'docs', 'recommended-agent-skills.md'), destination: join(skillRoot, 'references', 'recommended-agent-skills.md') },
    { source: join(repoRoot, 'docs', 'parity-spec.md'), destination: join(skillRoot, 'references', 'parity-spec.md') },
    { source: join(repoRoot, 'docs', 'build-playbook.md'), destination: join(skillRoot, 'references', 'build-playbook.md') },
    ...gates.reviewPacketFiles.map((packetFile) => {
      const name = templateName(packetFile);
      return {
        source: join(repoRoot, 'templates', name),
        destination: join(skillRoot, 'assets', 'templates', name)
      };
    })
  ];

  if (!assetsOnly) {
    const manifest = verifierHashesManifest();
    plan.push(
      {
        source: join(repoRoot, 'bin', 'verify.mjs'),
        destination: join(skillRoot, 'scripts', 'verify.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'verify-packet.mjs'),
        destination: join(skillRoot, 'scripts', 'verify-packet.mjs'),
        executable: true
      },
      { content: manifest, destination: join(repoRoot, VERIFIER_HASHES_FILE) },
      { content: manifest, destination: join(skillRoot, VERIFIER_HASHES_FILE) }
    );
  }
  return plan;
}

// The published tamper-evident manifest is derived from the canonical root sources;
// the synced skill copy is byte-identical, so one manifest covers both layouts.
function verifierHashesManifest() {
  const { version } = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
  const { files, verifierSelfHash } = verifierSelfEvidence(repoRoot, join(repoRoot, 'bin'));
  return `${JSON.stringify({
    schemaVersion: 'public-kit.verifier-hashes.1',
    kitVersion: version,
    verifierSelfHash,
    files
  }, null, 2)}\n`;
}

function sameBytes(left, right) {
  return existsSync(left) && existsSync(right) && readFileSync(left).equals(readFileSync(right));
}

function planEntryInSync({ content, destination, executable, source }) {
  if (content !== undefined) {
    return existsSync(destination) && readFileSync(destination, 'utf8') === content;
  }
  return sameBytes(source, destination) && (!executable || (statSync(destination).mode & 0o111) !== 0);
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const plan = copyPlan(options.assetsOnly);
  const missingSources = plan.filter(({ source }) => source && !existsSync(source));
  if (missingSources.length > 0) {
    throw new Error(`Missing canonical source files:\n${missingSources.map(({ source }) => `- ${source}`).join('\n')}`);
  }

  if (options.mode === 'write') {
    for (const { content, destination, executable, source } of plan) {
      mkdirSync(dirname(destination), { recursive: true });
      if (content !== undefined) {
        writeFileSync(destination, content);
      } else {
        copyFileSync(source, destination);
      }
      if (executable) {
        chmodSync(destination, 0o755);
      }
    }
  }

  const drift = plan.filter((entry) => !planEntryInSync(entry));
  if (drift.length > 0) {
    throw new Error(`Installable skill package is out of sync:\n${drift.map(({ destination }) => `- ${destination}`).join('\n')}`);
  }

  if (!options.quiet) {
    process.stdout.write(`Skill package ${options.mode === 'write' ? 'synced' : 'is in sync'} (${plan.length} files).\n`);
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
