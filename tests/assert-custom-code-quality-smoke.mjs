#!/usr/bin/env node

import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  inspectCustomCodeFilesystem,
  inspectCustomCodeQuality
} from '../bin/verify.mjs';

if (!process.argv[2]) {
  throw new Error('Usage: node tests/assert-custom-code-quality-smoke.mjs <project-root>');
}

const projectRoot = resolve(process.argv[2]);
const inventory = inspectCustomCodeFilesystem(projectRoot);
assert.equal(inventory.completed, true, JSON.stringify(inventory.errors));
assert.ok(inventory.sourceFiles.some((file) => file.path.endsWith('/quality_smoke.module')));

const result = inspectCustomCodeQuality(
  projectRoot,
  process.env,
  inventory,
  { capabilities: [], testCoverage: [] }
);

assert.equal(result.qualityAudit.status, 'pass', JSON.stringify(result.qualityAudit.failures));
assert.equal(result.qualityAudit.completed, true);
assert.equal(result.qualityAudit.isolation?.status, 'cleaned');
assert.equal(result.focusedTestExecution.status, 'not_applicable');
assert.equal(result.focusedTestExecution.applies, false);
assert.equal(result.focusedTestExecution.completed, true);

process.stdout.write('Real disposable custom-code quality evidence passed and cleaned its isolated runtime.\n');
