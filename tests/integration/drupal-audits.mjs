#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  inspectCustomCode,
  inspectCustomConfigSchema,
  inspectCustomRouteRuntime
} from '../../bin/verify.mjs';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : '';
}

const projectRoot = resolve(option('--project') || process.cwd());
const packetDir = option('--packet') ? resolve(option('--packet')) : '';
let packetRoutes = [];
let sourceIdentity = {};
if (packetDir) {
  const readbackPath = resolve(packetDir, 'drupal-readback.json');
  const routeMatrixPath = resolve(packetDir, 'route-matrix.json');
  const sourceAuditPath = resolve(packetDir, 'source-audit.json');
  if (existsSync(readbackPath)) {
    const readback = JSON.parse(readFileSync(readbackPath, 'utf8'));
    packetRoutes = Array.isArray(readback?.implementationQuality?.customCodeInventory?.routes)
      ? readback.implementationQuality.customCodeInventory.routes
      : [];
  }
  if (existsSync(routeMatrixPath)) {
    sourceIdentity.sourceBaseUrl = JSON.parse(readFileSync(routeMatrixPath, 'utf8'))?.sourceBaseUrl;
  }
  if (existsSync(sourceAuditPath)) {
    sourceIdentity.sourceSiteName = JSON.parse(readFileSync(sourceAuditPath, 'utf8'))?.site?.name;
  }
}

const inventory = inspectCustomCode(projectRoot, sourceIdentity);
const bindings = inventory.routes.map((route) => {
  const packetRoute = packetRoutes.find((candidate) => candidate?.name === route.name) ?? {};
  return {
    name: route.name,
    requestMethod: String(packetRoute.requestMethod || 'GET').toUpperCase(),
    routeParameters: packetRoute.routeParameters && typeof packetRoute.routeParameters === 'object'
      ? packetRoute.routeParameters
      : {}
  };
});
const audit = inspectCustomRouteRuntime(
  projectRoot,
  process.env,
  inventory.routes,
  inventory.extensions,
  bindings
);
const configSchemaAudit = inspectCustomConfigSchema(projectRoot, process.env, inventory.extensions);

const result = {
  projectRoot,
  inventoryCompleted: inventory.completed,
  inventoryErrors: inventory.errors,
  extensionCount: inventory.extensions.length,
  behaviorFindingCount: inventory.behaviorFindings.length,
  behaviorFindings: inventory.behaviorFindings,
  configSchemaAuditCompleted: configSchemaAudit.completed,
  configSchemaViolations: configSchemaAudit.violations,
  filesystemRouteCount: inventory.routes.length,
  routeAuditCompleted: audit.completed,
  auditedRouteCount: audit.routes.length,
  routeAuditViolations: audit.violations
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (
  !inventory.completed ||
  !audit.completed ||
  audit.violations.length > 0 ||
  !configSchemaAudit.completed ||
  configSchemaAudit.violations.length > 0
) {
  process.exitCode = 1;
}
