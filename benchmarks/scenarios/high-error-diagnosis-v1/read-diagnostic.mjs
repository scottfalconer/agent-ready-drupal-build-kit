#!/usr/bin/env node

import { appendFileSync, existsSync, lstatSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve, sep } from 'node:path';

const MAX_BYTES = 64 * 1024 * 1024;
const ALLOWED = new Set([
  '.benchmark-runtime/arm/live-verification.json',
  '.benchmark-runtime/arm/live-verification.summary.json'
]);

function normalizedRelative(path) {
  return path.replaceAll('\\', '/').replace(/^\.\//, '');
}

function within(path, parent) {
  const rel = relative(resolve(parent), resolve(path));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`));
}

function fail(message) {
  process.stderr.write(`Diagnostic read rejected: ${message}\n`);
  process.exit(1);
}

const requested = normalizedRelative(process.argv[2] ?? '');
if (process.argv.length !== 3 || !ALLOWED.has(requested)) {
  fail(`expected exactly one announced path (${[...ALLOWED].join(' or ')})`);
}

const workspace = process.cwd();
const path = resolve(workspace, requested);
if (!within(path, workspace) || !existsSync(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) {
  fail('path is missing, unsafe, or not a regular file');
}

const bytes = readFileSync(path);
if (bytes.length > MAX_BYTES) fail(`file exceeds ${MAX_BYTES} bytes`);

const eventPath = resolve(workspace, '.benchmark-runtime', 'read-events.jsonl');
if (!within(eventPath, workspace) || dirname(eventPath) !== resolve(workspace, '.benchmark-runtime')) {
  fail('telemetry path escaped the workspace');
}
const event = {
  schemaVersion: 'public-kit.high-error-diagnostic-read.1',
  path: requested,
  bytes: bytes.length,
  sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`
};
appendFileSync(eventPath, `${JSON.stringify(event)}\n`, { encoding: 'utf8', mode: 0o600 });
process.stdout.write(bytes);
