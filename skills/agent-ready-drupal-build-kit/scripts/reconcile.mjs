#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { basename, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findDrupalDdevRoot,
  inspectDrupalLiveSurface,
  liveSurfaceReconciliationErrors
} from './verify.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DRAFT_SCHEMA = 'public-kit.live-surface-reconciliation-draft.1';
const LIVE_SCHEMA = 'public-kit.drupal-live-surface.1';
const RECONCILIATION_SCHEMA = 'public-kit.live-surface-reconciliation.1';
const MAX_LIVE_ITEMS = 5_000;
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const DRAFT_FILENAME = 'live-surface-reconciliation-draft.json';
const USAGE = `Usage: node <path-to-skill>/scripts/reconcile.mjs [options]

Refresh or materialize the verifier-owned live Drupal surface worksheet.

Options:
  --packet <path>   Review packet directory inside the current Drupal project (default: review-packet)
  --draft           Refresh the non-passing worksheet without changing drupal-readback.json
  --materialize     Refresh the worksheet, then write only a fully resolved reconciliation block
  --help            Show this help`;

class UsageError extends Error {}

function comparePortable(left, right) {
  const leftValue = String(left);
  const rightValue = String(right);
  if (leftValue === rightValue) return 0;
  return leftValue < rightValue ? -1 : 1;
}

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => comparePortable(left, right))
        .map(([key, child]) => [key, canonicalValue(child)])
    );
  }
  return value;
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalValue(value))).digest('hex')}`;
}

function sameJson(left, right) {
  return JSON.stringify(canonicalValue(left)) === JSON.stringify(canonicalValue(right));
}

function pathIsInside(parent, candidate) {
  const relation = relative(parent, candidate);
  return relation !== '' && relation !== '..' && !relation.startsWith(`..${sep}`) && !isAbsolute(relation);
}

function pathEntryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function assertRealDirectory(path, label) {
  if (!existsSync(path)) {
    throw new Error(`${label} does not exist: ${path}`);
  }
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a file or symbolic link.`);
  }
  if (realpathSync(path) !== resolve(path)) {
    throw new Error(`${label} must not traverse a symbolic link.`);
  }
}

function assertPacketFile(path, packetDir, { allowMissing = false } = {}) {
  const packetRoot = realpathSync(packetDir);
  const resolvedPath = resolve(path);
  if (!pathIsInside(packetRoot, resolvedPath)) {
    throw new Error(`Reconciliation files must stay inside ${basename(packetDir)}.`);
  }
  if (!pathEntryExists(resolvedPath)) {
    if (allowMissing) return;
    throw new Error(`Required reconciliation file does not exist: ${basename(resolvedPath)}.`);
  }
  const metadata = lstatSync(resolvedPath);
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`Reconciliation paths must be regular non-symlink files: ${basename(resolvedPath)}.`);
  }
  if (!pathIsInside(packetRoot, realpathSync(resolvedPath))) {
    throw new Error(`Reconciliation files must not escape ${basename(packetDir)} through a symbolic link.`);
  }
  if (metadata.size > MAX_JSON_BYTES) {
    throw new Error(`${basename(resolvedPath)} exceeds the ${MAX_JSON_BYTES}-byte reconciliation input limit.`);
  }
}

function readJson(path, packetDir, { optional = false } = {}) {
  if (optional && !pathEntryExists(path)) return null;
  assertPacketFile(path, packetDir);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`${basename(path)} must contain valid JSON.`);
  }
}

function writeJsonAtomic(path, value, packetDir) {
  assertPacketFile(path, packetDir, { allowMissing: true });
  const content = `${JSON.stringify(value, null, 2)}\n`;
  if (pathEntryExists(path) && readFileSync(path, 'utf8') === content) {
    return false;
  }
  const mode = pathEntryExists(path) ? statSync(path).mode & 0o777 : 0o644;
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  try {
    writeFileSync(temporary, content, { encoding: 'utf8', mode, flag: 'wx' });
    renameSync(temporary, path);
  } catch (error) {
    if (existsSync(temporary)) unlinkSync(temporary);
    throw error;
  }
  return true;
}

export function parseReconcileArgs(argv) {
  const options = { help: false, mode: '', packet: 'review-packet' };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }
    if (argument === '--draft' || argument === '--materialize') {
      const mode = argument.slice(2);
      if (options.mode && options.mode !== mode) {
        throw new UsageError('--draft and --materialize are mutually exclusive.');
      }
      options.mode = mode;
      continue;
    }
    const equalsIndex = argument.indexOf('=');
    const option = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    if (option !== '--packet') {
      throw new UsageError(
        argument.startsWith('-') ? `Unknown option: ${argument}.` : `Unexpected positional argument: ${argument}.`
      );
    }
    const value = equalsIndex === -1 ? argv[index + 1] : argument.slice(equalsIndex + 1);
    if (!value || (equalsIndex === -1 && value.startsWith('--'))) {
      throw new UsageError('--packet requires a value.');
    }
    if (equalsIndex === -1) index += 1;
    options.packet = value;
  }
  if (!options.help && !options.mode) {
    throw new UsageError('Choose exactly one of --draft or --materialize.');
  }
  return options;
}

function normalizedDisposition(value = {}) {
  return {
    status: ['declare', 'exclude'].includes(value?.status) ? value.status : 'unresolved',
    packetReferences: Array.isArray(value?.packetReferences)
      ? [...new Set(value.packetReferences.map((entry) => String(entry).trim()).filter(Boolean))].sort(comparePortable)
      : [],
    owner: String(value?.owner ?? '').trim(),
    rationale: String(value?.rationale ?? '').trim(),
    evidence: Array.isArray(value?.evidence)
      ? [...new Set(value.evidence.map((entry) => String(entry).trim()).filter(Boolean))].sort(comparePortable)
      : []
  };
}

function readbackDispositions(reconciliation) {
  if (!reconciliation || typeof reconciliation !== 'object' || Array.isArray(reconciliation)) {
    return new Map();
  }
  const declarations = Array.isArray(reconciliation.declarations) ? reconciliation.declarations : [];
  const exclusions = Array.isArray(reconciliation.exclusions) ? reconciliation.exclusions : [];
  if (declarations.length > MAX_LIVE_ITEMS || exclusions.length > MAX_LIVE_ITEMS) {
    throw new Error('drupal-readback.json liveSurfaceReconciliation exceeds the bounded live-surface row limit.');
  }
  const dispositions = new Map();
  for (const declaration of declarations) {
    const key = String(declaration?.key ?? '').trim();
    if (!key || dispositions.has(key)) {
      throw new Error('drupal-readback.json liveSurfaceReconciliation contains a missing or duplicate key.');
    }
    dispositions.set(key, {
      kind: String(declaration?.kind ?? '').trim(),
      disposition: normalizedDisposition({
        status: 'declare',
        packetReferences: declaration?.packetReferences
      })
    });
  }
  for (const exclusion of exclusions) {
    const key = String(exclusion?.key ?? '').trim();
    if (!key || dispositions.has(key)) {
      throw new Error('drupal-readback.json liveSurfaceReconciliation contains a missing or duplicate key.');
    }
    dispositions.set(key, {
      kind: String(exclusion?.kind ?? '').trim(),
      disposition: normalizedDisposition({
        status: 'exclude',
        owner: exclusion?.owner,
        rationale: exclusion?.rationale,
        evidence: exclusion?.evidence
      })
    });
  }
  return dispositions;
}

function assertInventory(inventory) {
  if (
    inventory?.schemaVersion !== LIVE_SCHEMA ||
    inventory?.confirmed !== true ||
    !/^sha256:[a-f0-9]{64}$/.test(String(inventory?.fingerprint ?? '')) ||
    !inventory?.countsByKind ||
    typeof inventory.countsByKind !== 'object' ||
    Array.isArray(inventory.countsByKind) ||
    inventory?.bounded !== true ||
    inventory?.truncated !== false ||
    Number(inventory?.limit) !== MAX_LIVE_ITEMS ||
    !Array.isArray(inventory?.items) ||
    Number(inventory?.itemCount) !== inventory.items.length ||
    inventory.items.length > MAX_LIVE_ITEMS
  ) {
    throw new Error(inventory?.reason || 'The bounded live Drupal surface census is unavailable or malformed.');
  }
  const keys = new Set();
  const actualCounts = {};
  for (const item of inventory.items) {
    const key = String(item?.key ?? '').trim();
    const kind = String(item?.kind ?? '').trim();
    if (!key || !kind || !key.startsWith(`${kind}:`) || keys.has(key)) {
      throw new Error('The live Drupal surface census contains a missing, malformed, or duplicate key.');
    }
    keys.add(key);
    actualCounts[kind] = (actualCounts[kind] ?? 0) + 1;
  }
  if (!sameJson(actualCounts, inventory.countsByKind)) {
    throw new Error('The live Drupal surface census counts do not match its bounded items.');
  }
}

function observedFacts(item) {
  return canonicalValue(Object.fromEntries(
    Object.entries(item).filter(([key]) => !['key', 'kind'].includes(key))
  ));
}

function dispositionBasis(item) {
  return canonicalValue(Object.fromEntries(
    Object.entries(item).filter(([key]) => key !== 'publishedCount')
  ));
}

function candidatePacketReferences(item) {
  const kind = String(item?.kind ?? '');
  if (kind === 'bundle') {
    return ({
      node: ['pattern-map.json#contentTypes'],
      media: ['pattern-map.json#media'],
      taxonomy_term: ['pattern-map.json#vocabularies']
    })[String(item?.entityType ?? '')] ?? ['pattern-map.json#structuredContentModel'];
  }
  return ({
    alias: ['route-matrix.json#routes'],
    canvas_component: ['pattern-map.json#compositionModel.canvasComponentModel'],
    canvas_page: ['pattern-map.json#pageCompositionOwnership', 'route-matrix.json#routes'],
    canvas_template: ['pattern-map.json#compositionModel.flexibleLandingRoutes'],
    custom_extension: ['off-road-inventory.md#Inventory'],
    custom_route: ['off-road-inventory.md#Inventory', 'route-matrix.json#targetRequiredRoutes'],
    menu: ['pattern-map.json#menus'],
    menu_link: ['pattern-map.json#menus'],
    redirect: ['pattern-map.json#redirectsAndSeo', 'route-matrix.json#routes'],
    sitemap: ['route-matrix.json#targetRequiredRoutes'],
    sitemap_route: ['route-matrix.json#targetRequiredRoutes'],
    view: ['pattern-map.json#views'],
    view_display: ['pattern-map.json#views']
  })[kind] ?? [];
}

function recommendedDisposition(item) {
  return item?.publicSurface === false || item?.publicEditorialRoot === false ? 'exclude' : 'declare';
}

function normalizePriorDraft(draft) {
  if (!draft) return { active: new Map(), stale: new Map() };
  if (draft?.schemaVersion !== DRAFT_SCHEMA) {
    throw new Error(`${DRAFT_FILENAME} must use schemaVersion ${DRAFT_SCHEMA}.`);
  }
  const items = Array.isArray(draft.items) ? draft.items : [];
  const staleItems = Array.isArray(draft.staleItems) ? draft.staleItems : [];
  if (items.length > MAX_LIVE_ITEMS || staleItems.length > MAX_LIVE_ITEMS) {
    throw new Error(`${DRAFT_FILENAME} exceeds the bounded worksheet row limit.`);
  }
  const active = new Map();
  const stale = new Map();
  for (const row of items) {
    const key = String(row?.key ?? '').trim();
    if (!key || active.has(key) || stale.has(key)) {
      throw new Error(`${DRAFT_FILENAME} contains a missing or duplicate key.`);
    }
    active.set(key, row);
  }
  for (const row of staleItems) {
    const key = String(row?.key ?? '').trim();
    if (!key || active.has(key) || stale.has(key)) {
      throw new Error(`${DRAFT_FILENAME} contains a missing or duplicate key.`);
    }
    stale.set(key, row);
  }
  return { active, stale };
}

function invalidationRecord(disposition, reason) {
  const normalized = normalizedDisposition(disposition);
  if (normalized.status === 'unresolved' && normalized.packetReferences.length === 0 &&
      !normalized.owner && !normalized.rationale && normalized.evidence.length === 0) {
    return null;
  }
  return { reason, disposition: normalized };
}

function unresolvedReasons(row) {
  const reasons = [];
  if (row.invalidatedDisposition) reasons.push('disposition_invalidated');
  if (row.disposition.status === 'unresolved') reasons.push('disposition_required');
  if (row.disposition.status === 'declare' && row.disposition.packetReferences.length === 0) {
    reasons.push('packet_reference_required');
  }
  if (row.disposition.status === 'exclude') {
    if (!row.disposition.owner) reasons.push('exclusion_owner_required');
    if (!row.disposition.rationale) reasons.push('exclusion_rationale_required');
    if (row.disposition.evidence.length === 0) reasons.push('exclusion_evidence_required');
  }
  return reasons;
}

export function refreshLiveSurfaceDraft(inventory, {
  priorDraft = null,
  readbackReconciliation = null
} = {}) {
  assertInventory(inventory);
  const prior = normalizePriorDraft(priorDraft);
  const readback = readbackDispositions(readbackReconciliation);
  const readbackMatchesCurrent =
    String(readbackReconciliation?.inventoryFingerprint ?? '') === String(inventory.fingerprint);
  const liveKeys = new Set(inventory.items.map((item) => String(item.key)));
  const items = inventory.items
    .slice()
    .sort((left, right) => comparePortable(left.key, right.key))
    .map((item) => {
      const key = String(item.key);
      const kind = String(item.kind);
      const observed = observedFacts(item);
      const observedFingerprint = sha256(item);
      const dispositionBasisFingerprint = sha256(dispositionBasis(item));
      const priorRow = prior.active.get(key);
      const readbackRow = readback.get(key);
      let disposition = normalizedDisposition();
      let invalidatedDisposition = null;

      if (
        priorRow &&
        String(priorRow.kind ?? '') === kind &&
        String(priorRow.dispositionBasisFingerprint ?? '') === dispositionBasisFingerprint
      ) {
        disposition = normalizedDisposition(priorRow.disposition);
        if (disposition.status === 'unresolved' && priorRow.invalidatedDisposition) {
          invalidatedDisposition = canonicalValue(priorRow.invalidatedDisposition);
        }
      } else if (priorRow) {
        invalidatedDisposition = invalidationRecord(priorRow.disposition, 'observed_disposition_basis_changed');
      } else if (readbackRow && readbackMatchesCurrent && readbackRow.kind === kind) {
        disposition = normalizedDisposition(readbackRow.disposition);
      } else if (readbackRow) {
        invalidatedDisposition = invalidationRecord(readbackRow.disposition, 'readback_inventory_is_not_current');
      }

      return {
        key,
        kind,
        observedFingerprint,
        dispositionBasisFingerprint,
        observed,
        recommendedDisposition: recommendedDisposition(item),
        candidatePacketReferences: candidatePacketReferences(item),
        disposition,
        invalidatedDisposition
      };
    });

  const staleSources = new Map();
  for (const [key, row] of prior.active) {
    if (!liveKeys.has(key)) staleSources.set(key, row);
  }
  for (const [key, row] of readback) {
    if (!liveKeys.has(key) && !staleSources.has(key)) {
      const priorStale = prior.stale.get(key);
      staleSources.set(key, priorStale?.acknowledgedRemoved === true
        ? priorStale
        : {
            key,
            kind: row.kind,
            observedFingerprint: '',
            observed: {},
            disposition: row.disposition,
            acknowledgedRemoved: false
          });
    }
  }
  for (const [key, row] of prior.stale) {
    if (
      !liveKeys.has(key) &&
      !staleSources.has(key) &&
      (row?.acknowledgedRemoved !== true || readback.has(key))
    ) {
      staleSources.set(key, row);
    }
  }
  const staleItems = [...staleSources]
    .sort(([left], [right]) => comparePortable(left, right))
    .map(([key, row]) => ({
      key,
      kind: String(row?.kind ?? ''),
      observedFingerprint: String(row?.observedFingerprint ?? ''),
      observed: canonicalValue(row?.observed && typeof row.observed === 'object' ? row.observed : {}),
      previousDisposition: normalizedDisposition(row?.disposition ?? row?.previousDisposition),
      acknowledgedRemoved: row?.acknowledgedRemoved === true
    }));

  const unresolved = [];
  for (const row of items) {
    const reasons = unresolvedReasons(row);
    if (reasons.length > 0) unresolved.push({ key: row.key, reasons });
  }
  for (const row of staleItems) {
    if (row.acknowledgedRemoved !== true) {
      unresolved.push({ key: row.key, reasons: ['stale_surface_acknowledgment_required'] });
    }
  }
  return {
    schemaVersion: DRAFT_SCHEMA,
    scope: 'live_surface',
    authority: 'non_passing_work_queue',
    inventoryFingerprint: String(inventory.fingerprint),
    countsByKind: canonicalValue(inventory.countsByKind),
    items,
    staleItems,
    unresolved,
    summary: {
      live: items.length,
      unresolved: unresolved.length,
      invalidated: items.filter((row) => row.invalidatedDisposition !== null).length,
      stale: staleItems.length
    }
  };
}

function assertDraftMatchesInventory(inventory, draft) {
  if (draft?.schemaVersion !== DRAFT_SCHEMA) {
    throw new Error(`${DRAFT_FILENAME} must use schemaVersion ${DRAFT_SCHEMA}.`);
  }
  if (draft.inventoryFingerprint !== inventory.fingerprint || !sameJson(draft.countsByKind, inventory.countsByKind)) {
    throw new Error('The live-surface worksheet is not bound to the current Drupal census.');
  }
  const liveByKey = new Map(inventory.items.map((item) => [String(item.key), item]));
  if (!Array.isArray(draft.items) || draft.items.length !== liveByKey.size) {
    throw new Error('The live-surface worksheet does not contain every current Drupal surface exactly once.');
  }
  const seen = new Set();
  for (const row of draft.items) {
    const item = liveByKey.get(String(row?.key ?? ''));
    if (!item || seen.has(row.key) || row.kind !== item.kind ||
        row.observedFingerprint !== sha256(item) ||
        row.dispositionBasisFingerprint !== sha256(dispositionBasis(item))) {
      throw new Error('The live-surface worksheet contains stale or altered verifier-owned facts.');
    }
    seen.add(row.key);
  }
}

export function materializeLiveSurfaceReconciliation(inventory, draft, packetDir) {
  assertInventory(inventory);
  assertDraftMatchesInventory(inventory, draft);
  const errors = [];
  for (const row of draft.items) {
    const reasons = unresolvedReasons({
      ...row,
      disposition: normalizedDisposition(row.disposition)
    });
    if (reasons.length > 0) {
      errors.push(`Unresolved live surface ${row.key}: ${reasons.join(', ')}.`);
    }
  }
  if (Array.isArray(draft.staleItems) && draft.staleItems.length > 0) {
    for (const row of draft.staleItems) {
      if (row?.acknowledgedRemoved !== true && !errors.some((error) => error.includes(` ${row.key}:`))) {
        errors.push(`Unresolved live surface ${row.key}: stale surface acknowledgment required.`);
      }
    }
  }
  if (errors.length > 0) return { errors, reconciliation: null };

  const declarations = [];
  const exclusions = [];
  for (const row of draft.items) {
    const disposition = normalizedDisposition(row.disposition);
    if (disposition.status === 'declare') {
      declarations.push({
        key: row.key,
        kind: row.kind,
        packetReferences: disposition.packetReferences
      });
    } else if (disposition.status === 'exclude') {
      exclusions.push({
        key: row.key,
        kind: row.kind,
        owner: disposition.owner,
        rationale: disposition.rationale,
        evidence: disposition.evidence
      });
    } else {
      errors.push(`Unresolved live surface ${row.key}: disposition required.`);
    }
  }
  if (errors.length > 0) return { errors, reconciliation: null };
  declarations.sort((left, right) => comparePortable(left.key, right.key));
  exclusions.sort((left, right) => comparePortable(left.key, right.key));
  const reconciliation = {
    schemaVersion: RECONCILIATION_SCHEMA,
    inventoryFingerprint: inventory.fingerprint,
    countsByKind: canonicalValue(inventory.countsByKind),
    declarations,
    exclusions,
    reconciliationComplete: true,
    blockers: []
  };
  errors.push(...liveSurfaceReconciliationErrors(inventory, reconciliation, packetDir));
  return { errors, reconciliation: errors.length === 0 ? reconciliation : null };
}

export function readbackWithLiveSurfaceReconciliation(readback, reconciliation) {
  if (!readback || typeof readback !== 'object' || Array.isArray(readback) ||
      readback.schemaVersion !== 'public-kit.drupal-readback.1') {
    throw new Error('drupal-readback.json must use schemaVersion public-kit.drupal-readback.1.');
  }
  return { ...readback, liveSurfaceReconciliation: reconciliation };
}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

function main() {
  const options = parseReconcileArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  const projectRoot = findDrupalDdevRoot(process.cwd());
  if (!projectRoot) {
    throw new Error('Run reconciliation from inside the current DDEV Drupal project.');
  }
  const packetDir = isAbsolute(options.packet)
    ? resolve(options.packet)
    : resolve(projectRoot, options.packet);
  if (!pathIsInside(projectRoot, packetDir)) {
    throw new Error('The review packet must be a directory inside the current Drupal project.');
  }
  assertRealDirectory(packetDir, 'Review packet');
  const draftPath = resolve(packetDir, DRAFT_FILENAME);
  const readbackPath = resolve(packetDir, 'drupal-readback.json');
  const priorDraft = readJson(draftPath, packetDir, { optional: true });
  const readback = readJson(readbackPath, packetDir);
  if (!readback || typeof readback !== 'object' || Array.isArray(readback) ||
      readback.schemaVersion !== 'public-kit.drupal-readback.1') {
    throw new Error('drupal-readback.json must use schemaVersion public-kit.drupal-readback.1.');
  }
  const inventory = inspectDrupalLiveSurface(projectRoot, process.env);
  assertInventory(inventory);
  const draft = refreshLiveSurfaceDraft(inventory, {
    priorDraft,
    readbackReconciliation: readback.liveSurfaceReconciliation
  });
  const draftChanged = writeJsonAtomic(draftPath, draft, packetDir);
  if (options.mode === 'draft') {
    const verb = draftChanged ? 'refreshed' : 'unchanged';
    process.stdout.write(
      `Live-surface worksheet ${verb}: ${draft.summary.live} live, ${draft.summary.unresolved} unresolved, ${draft.summary.stale} stale. ${draftPath}\n`
    );
    return;
  }
  const result = materializeLiveSurfaceReconciliation(inventory, draft, packetDir);
  if (result.errors.length > 0) {
    process.stderr.write(`Live-surface reconciliation remains unresolved. Worksheet: ${draftPath}\n`);
    for (const error of result.errors.slice(0, 200)) {
      process.stderr.write(`- ${error}\n`);
    }
    process.exitCode = 2;
    return;
  }
  writeJsonAtomic(
    readbackPath,
    readbackWithLiveSurfaceReconciliation(readback, result.reconciliation),
    packetDir
  );
  process.stdout.write(
    `Materialized ${result.reconciliation.declarations.length} declarations and ${result.reconciliation.exclusions.length} exclusions into ${readbackPath}. Run the default live verifier next.\n`
  );
}

if (isDirectRun()) {
  try {
    main();
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n${USAGE}\n`);
    } else {
      process.stderr.write(`${error.stack || error.message}\n`);
    }
    process.exitCode = 1;
  }
}
