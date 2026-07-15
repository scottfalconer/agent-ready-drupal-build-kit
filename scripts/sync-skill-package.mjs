#!/usr/bin/env node

import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync
} from 'node:fs';
import { dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const skillRoot = join(repoRoot, 'skills', 'agent-ready-drupal-build-kit');

function usage() {
  return `Usage: node scripts/sync-skill-package.mjs [--check|--write] [--assets-only] [--quiet]

Keep canonical root gates/templates/references and verifier entrypoints byte-for-byte aligned
with the self-contained installable Agent Skill.

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
    { source: join(repoRoot, 'docs', 'site-lifecycle.md'), destination: join(skillRoot, 'references', 'site-lifecycle.md') },
    { source: join(repoRoot, 'docs', 'disposable-assembly.md'), destination: join(skillRoot, 'references', 'disposable-assembly.md') },
    { source: join(repoRoot, 'docs', 'verification-reuse.md'), destination: join(skillRoot, 'references', 'verification-reuse.md') },
    { source: join(repoRoot, 'docs', 'disposable-reproduction.md'), destination: join(skillRoot, 'references', 'disposable-reproduction.md') },
    { source: join(repoRoot, 'docs', 'cookbook.md'), destination: join(skillRoot, 'references', 'cookbook.md') },
    ...['runtime.json', 'docker-compose.zz-agent-ready-verifier.yaml'].map((name) => ({
      source: join(repoRoot, 'assets', 'browser-runtime', name),
      destination: join(skillRoot, 'assets', 'browser-runtime', name)
    })),
    ...['axe.min.js', 'LICENSE', 'LICENSE-3RD-PARTY.txt'].map((name) => ({
      source: join(repoRoot, 'assets', 'vendor', 'axe-core', '4.10.3', name),
      destination: join(skillRoot, 'assets', 'vendor', 'axe-core', '4.10.3', name)
    })),
    ...gates.reviewPacketFiles.map((packetFile) => {
      const name = templateName(packetFile);
      return {
        source: join(repoRoot, 'templates', name),
        destination: join(skillRoot, 'assets', 'templates', name)
      };
    })
  ];

  if (!assetsOnly) {
    plan.push(
      {
        source: join(repoRoot, 'bin', 'doctor.mjs'),
        destination: join(skillRoot, 'scripts', 'doctor.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'verify.mjs'),
        destination: join(skillRoot, 'scripts', 'verify.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'reconcile.mjs'),
        destination: join(skillRoot, 'scripts', 'reconcile.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'verify-packet.mjs'),
        destination: join(skillRoot, 'scripts', 'verify-packet.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'review-handoff.mjs'),
        destination: join(skillRoot, 'scripts', 'review-handoff.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'verify-assembly.mjs'),
        destination: join(skillRoot, 'scripts', 'verify-assembly.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'verify-reproduction.mjs'),
        destination: join(skillRoot, 'scripts', 'verify-reproduction.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'assembly-contract.mjs'),
        destination: join(skillRoot, 'scripts', 'assembly-contract.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'assembly-fixtures.mjs'),
        destination: join(skillRoot, 'scripts', 'assembly-fixtures.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'assembly-persistence.mjs'),
        destination: join(skillRoot, 'scripts', 'assembly-persistence.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'verification-observability.mjs'),
        destination: join(skillRoot, 'scripts', 'verification-observability.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'verification-reuse.mjs'),
        destination: join(skillRoot, 'scripts', 'verification-reuse.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'disposable-ddev.mjs'),
        destination: join(skillRoot, 'scripts', 'disposable-ddev.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'reproduction-state.mjs'),
        destination: join(skillRoot, 'scripts', 'reproduction-state.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'state-fingerprint.mjs'),
        destination: join(skillRoot, 'scripts', 'state-fingerprint.mjs')
      },
      {
        source: join(repoRoot, 'bin', 'lifecycle.mjs'),
        destination: join(skillRoot, 'scripts', 'lifecycle.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'bin', 'global-chrome.mjs'),
        destination: join(skillRoot, 'scripts', 'global-chrome.mjs')
      },
      {
        source: join(repoRoot, 'scripts', 'browser-runtime-common.sh'),
        destination: join(skillRoot, 'scripts', 'browser-runtime-common.sh')
      },
      {
        source: join(repoRoot, 'scripts', 'browser-runtime-smoke.mjs'),
        destination: join(skillRoot, 'scripts', 'browser-runtime-smoke.mjs'),
        executable: true
      },
      {
        source: join(repoRoot, 'scripts', 'setup-browser-runtime.sh'),
        destination: join(skillRoot, 'scripts', 'setup-browser-runtime.sh'),
        executable: true
      },
      {
        source: join(repoRoot, 'scripts', 'repair-browser-runtime.sh'),
        destination: join(skillRoot, 'scripts', 'repair-browser-runtime.sh'),
        executable: true
      },
      ...['ws.mjs', 'LICENSE', 'INTEGRITY.json'].map((name) => ({
        source: join(repoRoot, 'vendor', 'ws', '8.21.0', name),
        destination: join(skillRoot, 'vendor', 'ws', '8.21.0', name)
      }))
    );
  }
  return plan;
}

function sameBytes(left, right) {
  return existsSync(left) && existsSync(right) && readFileSync(left).equals(readFileSync(right));
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const plan = copyPlan(options.assetsOnly);
  const missingSources = plan.filter(({ source }) => !existsSync(source));
  if (missingSources.length > 0) {
    throw new Error(`Missing canonical source files:\n${missingSources.map(({ source }) => `- ${source}`).join('\n')}`);
  }

  if (options.mode === 'write') {
    for (const { destination, executable, source } of plan) {
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(source, destination);
      if (executable) {
        chmodSync(destination, 0o755);
      }
    }
  }

  const drift = plan.filter(({ destination, executable, source }) => (
    !sameBytes(source, destination) ||
    (executable && (statSync(destination).mode & 0o111) === 0)
  ));
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
