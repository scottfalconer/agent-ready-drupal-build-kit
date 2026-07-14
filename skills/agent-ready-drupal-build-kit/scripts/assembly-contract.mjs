import { readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  loadValidatedReproductionInputs,
  safeProjectRelativePath,
  validateBoundInput
} from './disposable-ddev.mjs';
import { canonicalJson, sha256 } from './state-fingerprint.mjs';

export const ASSEMBLY_PLAN_SCHEMA = 'public-kit.assembly-plan.1';
export const ASSEMBLY_PROVENANCE_SCHEMA = 'public-kit.assembly-provenance.1';
export const ASSEMBLY_DRY_RUN_SCHEMA = 'public-kit.assembly-dry-run.1';

const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const MACHINE_NAME_RE = /^[a-z][a-z0-9_]{0,127}$/;
const CONFIG_NAME_RE = /^[a-z0-9_][a-z0-9_.:-]{0,254}$/;
const SOURCE_KEY_RE = /^[a-z][a-z0-9_.-]{0,63}:[a-z0-9][a-z0-9_.:/-]{0,254}$/;
const MAX_OPERATIONS = 5_000;

const SURFACES = new Set([
  'node', 'canvas_page', 'canvas_component', 'menu', 'alias', 'view', 'sitemap',
  'config', 'entity', 'managed_file', 'route'
]);
const ACTIONS = ['create', 'update', 'delete', 'unchanged'];

function comparePortable(left, right) {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function assertExactKeys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const unsupported = Object.keys(value).filter((key) => !allowed.includes(key)).sort(comparePortable);
  if (unsupported.length > 0) throw new Error(`${label} contains unsupported field(s): ${unsupported.join(', ')}.`);
}

function normalizedString(value, label) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${label} must not be empty.`);
  return text;
}

function normalizedHash(value, label) {
  const text = String(value ?? '').trim().toLowerCase();
  const digest = /^[a-f0-9]{64}$/.test(text) ? `sha256:${text}` : text;
  if (!HASH_RE.test(digest)) throw new Error(`${label} must be a SHA-256 digest.`);
  return digest;
}

function boundSource(value, label) {
  assertExactKeys(value, ['path', 'sha256'], label);
  return {
    path: safeProjectRelativePath(value.path, `${label}.path`),
    sha256: normalizedHash(value.sha256, `${label}.sha256`)
  };
}

function machineName(value, label) {
  const text = normalizedString(value, label);
  if (!MACHINE_NAME_RE.test(text)) throw new Error(`${label} must be a Drupal machine name.`);
  return text;
}

function normalizedNamespace(value, label) {
  const text = normalizedString(value, label);
  if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(text)) {
    throw new Error(`${label} must be a stable lowercase provenance namespace.`);
  }
  return text;
}

function normalizedSourceKey(value, namespace, label) {
  const text = normalizedString(value, label);
  if (!SOURCE_KEY_RE.test(text) || !text.startsWith(`${namespace}:`)) {
    throw new Error(`${label} must be a stable key inside provenance namespace ${namespace}: (no titles, numeric-only IDs, wildcards, or bulk selectors).`);
  }
  if (/[*?\[\]{}]/.test(text) || /(^|[:/])\d+(?:$|[:/])/.test(text)) {
    throw new Error(`${label} must not contain wildcards, bulk selectors, or numeric-only identity segments.`);
  }
  return text;
}

function normalizedRoute(value, label) {
  const text = normalizedString(value, label);
  if (!text.startsWith('/')) throw new Error(`${label} must be a target-relative route.`);
  const url = new URL(text, 'https://agent-ready.invalid/');
  if (url.origin !== 'https://agent-ready.invalid' || url.pathname.includes('*')) {
    throw new Error(`${label} must be one exact target-relative route without wildcards.`);
  }
  url.hash = '';
  return `${url.pathname}${url.search}`;
}

function stableEntityId(value, label) {
  const text = normalizedString(value, label).toLowerCase();
  if (text.startsWith('uuid:') && UUID_RE.test(text.slice(5))) return text;
  if (text.startsWith('id:')) {
    const id = text.slice(3);
    if (/^[a-z][a-z0-9_.-]{0,127}$/.test(id)) return text;
  }
  throw new Error(`${label} must be uuid:<UUID> or id:<non-numeric-machine-id>; titles and numeric IDs are forbidden.`);
}

export function parseAssemblyTarget(value, label = 'Assembly target') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const kind = normalizedString(value.kind, `${label}.kind`);
  if (kind === 'config') {
    assertExactKeys(value, ['kind', 'name'], label);
    const name = normalizedString(value.name, `${label}.name`);
    if (!CONFIG_NAME_RE.test(name) || /[*?\[\]{}]/.test(name)) throw new Error(`${label}.name must be one exact configuration name.`);
    return { kind, name };
  }
  if (kind === 'entity') {
    assertExactKeys(value, ['kind', 'entityType', 'stableId'], label);
    return {
      kind,
      entityType: machineName(value.entityType, `${label}.entityType`),
      stableId: stableEntityId(value.stableId, `${label}.stableId`)
    };
  }
  if (kind === 'managed_file') {
    assertExactKeys(value, ['kind', 'stableId'], label);
    return { kind, stableId: stableEntityId(value.stableId, `${label}.stableId`) };
  }
  if (kind === 'route') {
    assertExactKeys(value, ['kind', 'path'], label);
    return { kind, path: normalizedRoute(value.path, `${label}.path`) };
  }
  throw new Error(`${label}.kind must be config, entity, managed_file, or route.`);
}

export function assemblyTargetKey(target) {
  if (target.kind === 'config') return `config:${target.name}`;
  if (target.kind === 'entity') return `entity:${target.entityType}:${target.stableId}`;
  if (target.kind === 'managed_file') return `managed_file:${target.stableId}`;
  if (target.kind === 'route') return `route:${target.path}`;
  throw new Error(`Unsupported assembly target kind: ${target?.kind ?? '(missing)'}.`);
}

function normalizeSurface(value, target, label) {
  const surface = normalizedString(value, label);
  if (!SURFACES.has(surface)) throw new Error(`${label} is not a supported bounded surface.`);
  const expected = {
    node: target.kind === 'entity' && target.entityType === 'node',
    canvas_page: target.kind === 'entity',
    canvas_component: target.kind === 'config',
    menu: target.kind === 'entity' && target.entityType === 'menu_link_content',
    alias: target.kind === 'entity' && target.entityType === 'path_alias',
    view: target.kind === 'config' && target.name.startsWith('views.view.'),
    sitemap: target.kind === 'config',
    config: target.kind === 'config',
    entity: target.kind === 'entity',
    managed_file: target.kind === 'managed_file',
    route: target.kind === 'route'
  }[surface];
  if (!expected) throw new Error(`${label} ${surface} is incompatible with target ${assemblyTargetKey(target)}.`);
  return surface;
}

function fixtureDisposition(value, requiredFields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const status = normalizedString(value.status, `${label}.status`);
  if (status === 'not_applicable') {
    assertExactKeys(value, ['status'], label);
    return { status };
  }
  if (status !== 'required') throw new Error(`${label}.status must be required or not_applicable.`);
  assertExactKeys(value, ['status', ...requiredFields], label);
  return { status };
}

function parseFixtures(value) {
  assertExactKeys(value, ['node', 'menu', 'alias', 'view', 'canvas', 'sitemap'], 'Assembly plan extensionFixtures');

  const nodeDisposition = fixtureDisposition(value.node, ['bundle'], 'Assembly plan extensionFixtures.node');
  const node = nodeDisposition.status === 'required'
    ? { status: 'required', bundle: machineName(value.node.bundle, 'Assembly plan extensionFixtures.node.bundle') }
    : nodeDisposition;

  const menuDisposition = fixtureDisposition(value.menu, ['menuName'], 'Assembly plan extensionFixtures.menu');
  const menu = menuDisposition.status === 'required'
    ? { status: 'required', menuName: machineName(value.menu.menuName, 'Assembly plan extensionFixtures.menu.menuName') }
    : menuDisposition;

  const alias = fixtureDisposition(value.alias, [], 'Assembly plan extensionFixtures.alias');
  const view = fixtureDisposition(value.view, [], 'Assembly plan extensionFixtures.view');

  const canvasDisposition = fixtureDisposition(
    value.canvas,
    ['pageEntityType', 'pageBundle', 'componentConfigName'],
    'Assembly plan extensionFixtures.canvas'
  );
  let canvas = canvasDisposition;
  if (canvasDisposition.status === 'required') {
    const componentConfigName = normalizedString(
      value.canvas.componentConfigName,
      'Assembly plan extensionFixtures.canvas.componentConfigName'
    );
    if (!CONFIG_NAME_RE.test(componentConfigName)) throw new Error('Canvas componentConfigName must be one exact config name.');
    const pageBundle = String(value.canvas.pageBundle ?? '').trim();
    if (pageBundle && !MACHINE_NAME_RE.test(pageBundle)) throw new Error('Canvas pageBundle must be empty or a Drupal machine name.');
    canvas = {
      status: 'required',
      pageEntityType: machineName(value.canvas.pageEntityType, 'Assembly plan extensionFixtures.canvas.pageEntityType'),
      pageBundle,
      componentConfigName
    };
  }

  const sitemapDisposition = fixtureDisposition(
    value.sitemap,
    ['configName'],
    'Assembly plan extensionFixtures.sitemap'
  );
  let sitemap = sitemapDisposition;
  if (sitemapDisposition.status === 'required') {
    const configName = normalizedString(value.sitemap.configName, 'Assembly plan extensionFixtures.sitemap.configName');
    if (!CONFIG_NAME_RE.test(configName)) throw new Error('Sitemap configName must be one exact config name.');
    sitemap = { status: 'required', configName };
  }
  return { node, menu, alias, view, canvas, sitemap };
}

/** Parse the exact typed contract. There is no command or arbitrary argv surface. */
export function parseAssemblyPlan(value) {
  assertExactKeys(value, [
    'schemaVersion', 'assemblyId', 'substratePlan', 'provenance', 'deletion', 'adapter', 'extensionFixtures'
  ], 'Assembly plan');
  if (value.schemaVersion !== ASSEMBLY_PLAN_SCHEMA) {
    throw new Error(`Assembly plan schemaVersion must be ${ASSEMBLY_PLAN_SCHEMA}.`);
  }
  const assemblyId = machineName(value.assemblyId, 'Assembly plan assemblyId');
  const substratePlan = boundSource(value.substratePlan, 'Assembly plan substratePlan');
  const provenanceSource = boundSource(value.provenance, 'Assembly plan provenance');
  assertExactKeys(value.deletion, ['policy'], 'Assembly plan deletion');
  if (value.deletion.policy !== 'provenance_owned_only') {
    throw new Error('Assembly plan deletion.policy must be provenance_owned_only.');
  }
  assertExactKeys(value.adapter, ['protocol', 'source', 'failureProof'], 'Assembly plan adapter');
  if (value.adapter.protocol !== 'drush_assembly_contract_v1') {
    throw new Error('Assembly plan adapter.protocol must be drush_assembly_contract_v1.');
  }
  if (value.adapter.failureProof !== 'tested_restoration') {
    throw new Error('Assembly plan adapter.failureProof must be tested_restoration; unobserved transactional claims are not accepted.');
  }
  const source = boundSource(value.adapter.source, 'Assembly plan adapter.source');
  if (!source.path.endsWith('.php')) throw new Error('Assembly adapter source must be a .php file.');
  if (source.path === substratePlan.path) throw new Error('Assembly adapter and substrate plan must be separate inputs.');
  return {
    schemaVersion: ASSEMBLY_PLAN_SCHEMA,
    assemblyId,
    substratePlan,
    provenance: provenanceSource,
    deletion: { policy: 'provenance_owned_only' },
    adapter: {
      protocol: 'drush_assembly_contract_v1',
      source,
      failureProof: 'tested_restoration'
    },
    extensionFixtures: parseFixtures(value.extensionFixtures)
  };
}

function parseResource(value, namespace, label) {
  assertExactKeys(value, ['sourceKey', 'surface', 'target'], label);
  const target = parseAssemblyTarget(value.target, `${label}.target`);
  return {
    sourceKey: normalizedSourceKey(value.sourceKey, namespace, `${label}.sourceKey`),
    surface: normalizeSurface(value.surface, target, `${label}.surface`),
    target
  };
}

function resourceKey(resource) {
  return `${resource.sourceKey}|${assemblyTargetKey(resource.target)}`;
}

export function parseAssemblyProvenance(value, expectedAssemblyId = '') {
  assertExactKeys(value, ['schemaVersion', 'assemblyId', 'namespace', 'resources'], 'Assembly provenance');
  if (value.schemaVersion !== ASSEMBLY_PROVENANCE_SCHEMA) {
    throw new Error(`Assembly provenance schemaVersion must be ${ASSEMBLY_PROVENANCE_SCHEMA}.`);
  }
  const assemblyId = machineName(value.assemblyId, 'Assembly provenance assemblyId');
  if (expectedAssemblyId && assemblyId !== expectedAssemblyId) throw new Error('Assembly provenance assemblyId does not match the plan.');
  const namespace = normalizedNamespace(value.namespace, 'Assembly provenance namespace');
  if (!Array.isArray(value.resources) || value.resources.length === 0 || value.resources.length > MAX_OPERATIONS) {
    throw new Error(`Assembly provenance resources must contain 1-${MAX_OPERATIONS} bounded rows.`);
  }
  const keys = new Set();
  const targets = new Set();
  const resources = value.resources.map((resource, index) => {
    const parsed = parseResource(resource, namespace, `Assembly provenance resources[${index}]`);
    const key = resourceKey(parsed);
    const targetKey = assemblyTargetKey(parsed.target);
    if (keys.has(key)) throw new Error(`Assembly provenance contains duplicate resource ${key}.`);
    if (targets.has(targetKey)) throw new Error(`Assembly provenance assigns target ${targetKey} more than once.`);
    keys.add(key);
    targets.add(targetKey);
    return parsed;
  }).sort((left, right) => comparePortable(resourceKey(left), resourceKey(right)));
  return { schemaVersion: ASSEMBLY_PROVENANCE_SCHEMA, assemblyId, namespace, resources };
}

export function parseAssemblyDryRun(value, provenance) {
  assertExactKeys(value, ['schemaVersion', 'assemblyId', 'operations', 'summary'], 'Assembly dry-run output');
  if (value.schemaVersion !== ASSEMBLY_DRY_RUN_SCHEMA) {
    throw new Error(`Assembly dry-run schemaVersion must be ${ASSEMBLY_DRY_RUN_SCHEMA}.`);
  }
  if (value.assemblyId !== provenance.assemblyId) throw new Error('Assembly dry-run assemblyId does not match exact-HEAD provenance.');
  if (!Array.isArray(value.operations) || value.operations.length !== provenance.resources.length) {
    throw new Error('Assembly dry-run must return exactly one operation for every provenance resource.');
  }
  const operationKeys = new Set();
  const operations = value.operations.map((operation, index) => {
    assertExactKeys(operation, ['action', 'sourceKey', 'surface', 'target'], `Assembly dry-run operations[${index}]`);
    const resource = parseResource({
      sourceKey: operation.sourceKey,
      surface: operation.surface,
      target: operation.target
    }, provenance.namespace, `Assembly dry-run operations[${index}]`);
    const action = normalizedString(operation.action, `Assembly dry-run operations[${index}].action`);
    if (!ACTIONS.includes(action)) throw new Error(`Assembly dry-run operations[${index}].action is unsupported.`);
    const parsed = { action, ...resource };
    const key = resourceKey(parsed);
    if (operationKeys.has(key)) throw new Error(`Assembly dry-run contains duplicate operation ${key}.`);
    operationKeys.add(key);
    return parsed;
  }).sort((left, right) => comparePortable(resourceKey(left), resourceKey(right)));
  const provenanceKeys = provenance.resources.map(resourceKey);
  const dryKeys = operations.map(resourceKey);
  if (canonicalJson(provenanceKeys) !== canonicalJson(dryKeys)) {
    throw new Error('Assembly dry-run operations are not exactly bound to the provenance ledger.');
  }
  assertExactKeys(value.summary, [...ACTIONS, 'total'], 'Assembly dry-run summary');
  const counts = Object.fromEntries(ACTIONS.map((action) => [action, operations.filter((row) => row.action === action).length]));
  for (const key of [...ACTIONS, 'total']) {
    const expected = key === 'total' ? operations.length : counts[key];
    if (value.summary[key] !== expected) throw new Error(`Assembly dry-run summary.${key} must equal ${expected}.`);
  }
  return {
    schemaVersion: ASSEMBLY_DRY_RUN_SCHEMA,
    assemblyId: provenance.assemblyId,
    operations,
    summary: { ...counts, total: operations.length },
    fingerprint: sha256(operations)
  };
}

function parseJsonFile(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`${label} must contain valid JSON.`);
  }
}

/** Validate the plan, provenance, adapter, and full reproduction substrate at exact HEAD. */
export function loadValidatedAssemblyInputs({ execute, planPath = 'assembly-plan.json', projectRoot }) {
  const root = realpathSync(resolve(projectRoot));
  const normalizedPlanPath = safeProjectRelativePath(planPath, 'Assembly plan path');
  const planBytes = readFileSync(resolve(root, normalizedPlanPath));
  const planInput = validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Assembly plan',
    projectRoot: root,
    source: { path: normalizedPlanPath, sha256: sha256(planBytes) }
  });
  const plan = parseAssemblyPlan(parseJsonFile(resolve(root, normalizedPlanPath), 'Assembly plan'));
  const substrateInput = validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Assembly substrate plan',
    projectRoot: root,
    source: plan.substratePlan
  });
  const provenanceInput = validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Assembly provenance ledger',
    projectRoot: root,
    source: plan.provenance
  });
  const adapterInput = validateBoundInput({
    execute,
    expectedKind: 'file',
    label: 'Assembly adapter source',
    projectRoot: root,
    source: plan.adapter.source
  });
  const provenance = parseAssemblyProvenance(
    parseJsonFile(resolve(root, plan.provenance.path), 'Assembly provenance ledger'),
    plan.assemblyId
  );
  const substrate = loadValidatedReproductionInputs({
    execute,
    planPath: plan.substratePlan.path,
    projectRoot: root
  });
  if (substrate.plan.mode === 'clean_install_config_import' && substrate.plan.content.adapter !== 'none') {
    throw new Error('A clean-install assembly substrate must use content.adapter none; executable content importers would make the pre-assembly barrier unobservable. Use a pre-assembly snapshot for seeded substrate data.');
  }
  return {
    plan,
    planPath: normalizedPlanPath,
    provenance,
    routes: substrate.routes,
    substrate,
    inputs: [planInput, substrateInput, provenanceInput, adapterInput, ...substrate.inputs]
  };
}

/** Index only independently read back portable rows, never adapter claims. */
export function portableAssemblyIndex(state) {
  const rows = new Map();
  for (const row of state.config.items) rows.set(`config:${row.name}`, row.sha256);
  for (const [entityType, type] of Object.entries(state.entities.types)) {
    for (const row of type.items) rows.set(`entity:${entityType}:${row.stableId}`, row.sha256);
  }
  for (const row of state.managedFiles.items) rows.set(`managed_file:${row.stableId}`, sha256(row));
  for (const row of state.routes) rows.set(`route:${row.path}`, sha256(row));
  return rows;
}

function independentlyDerivedAction(before, after, key) {
  const hadBefore = before.has(key);
  const hasAfter = after.has(key);
  if (!hadBefore && hasAfter) return 'create';
  if (hadBefore && !hasAfter) return 'delete';
  if (hadBefore && hasAfter && before.get(key) !== after.get(key)) return 'update';
  return 'unchanged';
}

export function deriveAssemblyChanges(beforeState, afterState) {
  const before = portableAssemblyIndex(beforeState);
  const after = portableAssemblyIndex(afterState);
  return [...new Set([...before.keys(), ...after.keys()])].sort(comparePortable).map((key) => ({
    key,
    action: independentlyDerivedAction(before, after, key),
    beforeSha256: before.get(key) ?? '',
    afterSha256: after.get(key) ?? ''
  })).filter((row) => row.action !== 'unchanged');
}

/** Reconcile untrusted adapter output against verifier-owned before/after state. */
export function reconcileDryRun(dryRun, beforeState, afterState) {
  const before = portableAssemblyIndex(beforeState);
  const after = portableAssemblyIndex(afterState);
  const mismatches = [];
  const declaredTargets = new Set();
  for (const operation of dryRun.operations) {
    const key = assemblyTargetKey(operation.target);
    declaredTargets.add(key);
    const derived = independentlyDerivedAction(before, after, key);
    if (derived !== operation.action) {
      mismatches.push({ key, declaredAction: operation.action, derivedAction: derived });
    }
  }
  for (const change of deriveAssemblyChanges(beforeState, afterState)) {
    if (!declaredTargets.has(change.key)) mismatches.push({ key: change.key, declaredAction: 'missing', derivedAction: change.action });
  }
  return {
    valid: mismatches.length === 0,
    beforeFingerprint: beforeState.fingerprint,
    afterFingerprint: afterState.fingerprint,
    derivedChangeCount: deriveAssemblyChanges(beforeState, afterState).length,
    mismatches
  };
}

export function assertStateMetadataStable(beforeState, afterState, label) {
  if (!beforeState?.confirmed || !afterState?.confirmed) throw new Error(`${label} readback must be independently confirmed.`);
  if (beforeState.siteUuid !== afterState.siteUuid) throw new Error(`${label} changed the Drupal site UUID.`);
  if (beforeState.configSyncDirectory !== afterState.configSyncDirectory) throw new Error(`${label} changed the config sync directory.`);
}

export function assertNoOpDryRun(dryRun, label) {
  const mutations = dryRun.operations.filter((operation) => operation.action !== 'unchanged');
  if (mutations.length > 0) throw new Error(`${label} must contain only unchanged rows; found ${mutations.length} mutation(s).`);
}

export function assertInitialMutation(dryRun) {
  if (dryRun.operations.every((operation) => operation.action === 'unchanged')) {
    throw new Error('First assembly dry-run must declare at least one independently verifiable create, update, or delete.');
  }
}

export function assertDeletesAuthorized(dryRun, allowOwnedDeletes) {
  const deletes = dryRun.operations.filter((operation) => operation.action === 'delete');
  if (deletes.length > 0 && allowOwnedDeletes !== true) {
    throw new Error(`Assembly dry-run contains ${deletes.length} provenance-owned delete(s); rerun with explicit --allow-owned-deletes authorization.`);
  }
  return deletes.length;
}

export function assertChangesWithinProvenance(changes, provenance, label) {
  const allowed = new Set(provenance.resources.map((resource) => assemblyTargetKey(resource.target)));
  const outside = changes.filter((change) => !allowed.has(change.key));
  if (outside.length > 0) throw new Error(`${label} touched ${outside.length} target(s) outside the exact provenance ledger: ${outside[0].key}.`);
}

export function fixtureTargetsSurvived(targets, beforeState, afterState) {
  const before = portableAssemblyIndex(beforeState);
  const after = portableAssemblyIndex(afterState);
  const rows = targets.map(({ surface, target }) => {
    const key = assemblyTargetKey(target);
    return {
      surface,
      key,
      presentBefore: before.has(key),
      presentAfter: after.has(key),
      unchanged: before.has(key) && after.has(key) && before.get(key) === after.get(key)
    };
  });
  return { valid: rows.length > 0 && rows.every((row) => row.unchanged), rows };
}
