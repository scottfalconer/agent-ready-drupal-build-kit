#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const KIT_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HASH_RE = /^sha256:[a-f0-9]{64}$/;

function parseArgs(argv) {
  const args = {
    packet: 'review-packet',
    out: ''
  };

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--packet') {
      args.packet = argv[index + 1];
      index += 1;
    } else if (arg === '--out') {
      args.out = argv[index + 1];
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    }
  }

  if (!args.out) {
    args.out = join(args.packet, 'evidence', 'packet-verification.json');
  }

  return args;
}

async function readJson(path, errors) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    errors.push(`${path} must be valid JSON: ${error.message}`);
    return null;
  }
}

async function hasFiles(path) {
  try {
    return (await readdir(path)).length > 0;
  } catch {
    return false;
  }
}

function validateGateVocabulary(gates, errors) {
  if (gates?.schemaVersion !== 'public-kit.gates.1') {
    errors.push('gates.json must use schemaVersion public-kit.gates.1.');
  }

  const ids = new Set();
  for (const gate of gates?.gates ?? []) {
    if (!gate.id || ids.has(gate.id)) {
      errors.push(`gates.json has missing or duplicate gate id: ${gate.id || '(missing)'}.`);
    }
    ids.add(gate.id);

    for (const field of ['title', 'phase', 'evidenceFile', 'checkedBy', 'blocking']) {
      if (gate[field] === undefined || gate[field] === '') {
        errors.push(`gate ${gate.id || '(missing)'} is missing ${field}.`);
      }
    }

    if (!gates.reviewPacketFiles.includes(gate.evidenceFile)) {
      errors.push(`gate ${gate.id} evidenceFile ${gate.evidenceFile} is not listed in reviewPacketFiles.`);
    }
  }
}

async function validateRequiredFiles(packetDir, gates, errors) {
  for (const file of gates.reviewPacketFiles ?? []) {
    const path = join(packetDir, file);
    if (!existsSync(path)) {
      errors.push(`review packet is missing required file: ${file}.`);
      continue;
    }

    if (file.endsWith('.json')) {
      await readJson(path, errors);
    }
  }
}

function validateIndependentVerification(packetDir, independentVerification, errors) {
  if (!independentVerification) {
    return;
  }

  const verifier = independentVerification.verifier ?? {};
  const summary = independentVerification.summary ?? {};
  const degraded =
    verifier.sameContextAsBuilder === true ||
    Boolean(verifier.independenceDegradedReason) ||
    verifier.freshContextUsed === false;

  if (degraded && summary.completeLocalRebuildClaimAllowed !== false) {
    errors.push(
      'independent-verification.json must set summary.completeLocalRebuildClaimAllowed=false when verifier independence is degraded.'
    );
  }

  if (
    summary.completeLocalRebuildClaimAllowed === true &&
    (summary.verdict !== 'pass' || Number(summary.failedClaimCount) > 0 || Number(summary.blockedClaimCount) > 0)
  ) {
    errors.push('independent-verification.json cannot allow a complete rebuild claim with failed or blocked verifier claims.');
  }

  if (summary.completeLocalRebuildClaimAllowed === true) {
    const evidenceDir = join(packetDir, 'evidence', 'independent-verification');
    if (!existsSync(evidenceDir)) {
      errors.push('complete rebuild claims require raw verifier evidence under review-packet/evidence/independent-verification/.');
    }
  }
}

async function validateDurableIntent(packetDir, errors) {
  const path = join(packetDir, 'durable-intent.yml');
  if (!existsSync(path)) {
    return;
  }

  const text = await readFile(path, 'utf8');
  const statusBlocks = text.split(/\n(?=\s*-\s+id:)/);

  for (const block of statusBlocks) {
    const id = block.match(/\bid:\s*"?([^"\n]+)"?/)?.[1] ?? '(unknown intent)';
    const status = block.match(/\bstatus:\s*"?([^"\n]+)"?/)?.[1] ?? '';
    const configHash = block.match(/\bconfig_hash:\s*"?([^"\n]*)"?/)?.[1] ?? '';

    if ((status === 'hash-valid' || status === 'accepted') && !HASH_RE.test(configHash) && configHash !== 'not-applicable') {
      errors.push(`${id} has status ${status} but config_hash is not sha256:<64 hex chars> or not-applicable.`);
    }

    if ((status === 'hash-valid' || status === 'accepted') && (configHash === 'UNKNOWN' || configHash === '')) {
      errors.push(`${id} has status ${status} but config_hash is blank or UNKNOWN.`);
    }
  }
}

async function validateRecipeStartPoint(packetDir, errors) {
  const path = join(packetDir, 'recipe-start-point.md');
  if (!existsSync(path)) {
    return;
  }

  const text = await readFile(path, 'utf8');
  if (!/ddev exec dr list recipe/.test(text)) {
    errors.push('recipe-start-point.md must record recipe discovery with ddev exec dr list recipe.');
  }
  if (!/default owner|default-owner|recipe.*default/i.test(text)) {
    errors.push('recipe-start-point.md must record the recipe default-owner decision before custom content-type overlays.');
  }
}

export async function validatePacket({ packetDir = 'review-packet' } = {}) {
  const errors = [];
  const warnings = [];
  const gates = await readJson(join(KIT_ROOT, 'gates.json'), errors);

  if (gates) {
    validateGateVocabulary(gates, errors);
    await validateRequiredFiles(packetDir, gates, errors);
  }

  const independentVerification = await readJson(join(packetDir, 'independent-verification.json'), []);
  validateIndependentVerification(packetDir, independentVerification, errors);
  await validateDurableIntent(packetDir, errors);
  await validateRecipeStartPoint(packetDir, errors);

  return {
    schemaVersion: 'public-kit.packet-verification.1',
    checkedAt: new Date().toISOString(),
    packetDir,
    gatesSchemaVersion: gates?.schemaVersion ?? '',
    gateCount: gates?.gates?.length ?? 0,
    requiredFileCount: gates?.reviewPacketFiles?.length ?? 0,
    valid: errors.length === 0,
    errors,
    warnings
  };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write('Usage: node bin/verify-packet.mjs --packet review-packet --out review-packet/evidence/packet-verification.json\n');
    return;
  }

  const report = await validatePacket({ packetDir: args.packet });
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, `${JSON.stringify(report, null, 2)}\n`);

  if (!report.valid) {
    process.stderr.write(`Packet verification failed. Report: ${args.out}\n`);
    for (const error of report.errors) {
      process.stderr.write(`- ${error}\n`);
    }
    process.exit(1);
  }

  process.stdout.write(`Packet verification passed. Report: ${args.out}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exit(1);
  });
}
