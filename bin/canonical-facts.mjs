#!/usr/bin/env node

import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, sha256 } from './state-fingerprint.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const FACTS_SCHEMA = 'public-kit.canonical-facts.1';
const PROVENANCE_SCHEMA = 'public-kit.fact-provenance.1';
const CLAIMS_SCHEMA = 'public-kit.fact-claims.1';
const OBJECT_INDEX_SCHEMA = 'public-kit.evidence-object-index.1';
const MANIFEST_SCHEMA = 'public-kit.fact-store-manifest.1';
const ACTOR_KINDS = new Set(['agent', 'subagent', 'tool', 'named_human']);
const CLAIM_STATUSES = new Set(['observed', 'falsified', 'blocked']);
const FACT_CATEGORIES = ['site', 'route', 'config', 'ownership', 'completion'];
const GENERATED_FILES = Object.freeze({
  canonicalFacts: 'canonical-facts.json',
  claims: 'claims.json',
  objectIndex: 'object-index.json',
  summary: 'summary.md',
  manifest: 'manifest.json'
});

class UsageError extends Error {}

export class CanonicalFactContradictionError extends Error {
  constructor(contradictions) {
    const detail = contradictions
      .map((entry) => `${entry.key}: ${entry.observations.map((observation) => `${observation.artifact}${observation.path}=${canonicalJson(observation.value)}`).join(' versus ')}`)
      .join('; ');
    super(`Canonical fact contradictions detected: ${detail}`);
    this.name = 'CanonicalFactContradictionError';
    this.contradictions = contradictions;
  }
}

function comparePortable(left, right) {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function prettyJson(value) {
  return `${JSON.stringify(JSON.parse(canonicalJson(value)), null, 2)}\n`;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function portablePath(value) {
  return String(value).replaceAll('\\', '/').split(sep).join('/');
}

function isInside(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (
    pathFromParent !== '..' &&
    !pathFromParent.startsWith(`..${sep}`) &&
    !isAbsolute(pathFromParent)
  );
}

function assertDirectory(path, label) {
  if (!existsSync(path) || !statSync(path).isDirectory()) {
    throw new Error(`${label} is not a directory: ${path}`);
  }
  if (lstatSync(path).isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link.`);
  }
}

function ensureDirectory(path, root, label) {
  mkdirSync(path, { recursive: true });
  const realRoot = realpathSync(root);
  let current = resolve(path);
  while (current !== resolve(root)) {
    if (!existsSync(current) || !statSync(current).isDirectory() || lstatSync(current).isSymbolicLink()) {
      throw new Error(`${label} must contain only real directories inside the packet.`);
    }
    const parent = dirname(current);
    if (!isInside(resolve(root), parent)) {
      throw new Error(`${label} escaped the packet.`);
    }
    current = parent;
  }
  if (!isInside(realRoot, realpathSync(path))) {
    throw new Error(`${label} escaped the packet.`);
  }
}

function normalizeRoute(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  try {
    const url = new URL(text);
    return url.pathname || '/';
  } catch {
    const path = text.split(/[?#]/)[0] || '/';
    return path.startsWith('/') ? path : `/${path}`;
  }
}

function normalizeOrigin(value) {
  try {
    const url = new URL(String(value ?? '').trim());
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.origin : '';
  } catch {
    return '';
  }
}

function normalizeDirectory(value) {
  const text = portablePath(String(value ?? '').trim());
  return text.replace(/^(?:(?:\.\.?)\/)*/, '').replace(/\/$/, '');
}

function nonEmpty(value) {
  if (typeof value === 'string') return value.trim() !== '';
  if (typeof value === 'number') return Number.isFinite(value);
  return typeof value === 'boolean';
}

function readJsonIfPresent(packetDir, name) {
  const path = join(packetDir, name);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${name} is not valid JSON: ${error.message}`);
  }
}

function routeTargetMap(routeMatrix) {
  const result = new Map();
  for (const record of [
    ...arrayOrEmpty(routeMatrix?.primaryRoutes),
    ...arrayOrEmpty(routeMatrix?.routes)
  ]) {
    const source = normalizeRoute(record?.sourcePath);
    const target = normalizeRoute(record?.targetPath);
    if (source && target) result.set(source, target);
  }
  return result;
}

function countClaims(claims, status) {
  return arrayOrEmpty(claims).filter((claim) => claim?.status === status).length;
}

function collectObservations(packetDir) {
  const artifacts = {
    sourceAudit: readJsonIfPresent(packetDir, 'source-audit.json'),
    patternMap: readJsonIfPresent(packetDir, 'pattern-map.json'),
    routeMatrix: readJsonIfPresent(packetDir, 'route-matrix.json'),
    parityReport: readJsonIfPresent(packetDir, 'parity-report.json'),
    browserEvidence: readJsonIfPresent(packetDir, 'browser-evidence.json'),
    independentVerification: readJsonIfPresent(packetDir, 'independent-verification.json'),
    blindReview: readJsonIfPresent(packetDir, 'blind-adversarial-review.json'),
    drupalReadback: readJsonIfPresent(packetDir, 'drupal-readback.json'),
    fieldOutput: readJsonIfPresent(packetDir, 'field-output-matrix.json')
  };
  const observations = [];
  const add = (key, category, value, artifact, path, normalize = (input) => input) => {
    if (!nonEmpty(value)) return;
    if (typeof value === 'string' && value.includes('|')) return;
    const normalized = normalize(value);
    if (!nonEmpty(normalized)) return;
    observations.push({ key, category, value: normalized, artifact, path });
  };

  add('site.source.origin', 'site', artifacts.sourceAudit?.site?.baseUrl, 'source-audit.json', '$.site.baseUrl', normalizeOrigin);
  add('site.source.origin', 'site', artifacts.patternMap?.sourceSite, 'pattern-map.json', '$.sourceSite', normalizeOrigin);
  add('site.source.origin', 'site', artifacts.routeMatrix?.sourceBaseUrl, 'route-matrix.json', '$.sourceBaseUrl', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.routeMatrix?.targetBaseUrl, 'route-matrix.json', '$.targetBaseUrl', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.parityReport?.targetUrl, 'parity-report.json', '$.targetUrl', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.browserEvidence?.site, 'browser-evidence.json', '$.site', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.independentVerification?.target?.baseUrl, 'independent-verification.json', '$.target.baseUrl', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.blindReview?.site, 'blind-adversarial-review.json', '$.site', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.drupalReadback?.site, 'drupal-readback.json', '$.site', normalizeOrigin);
  add('site.target.origin', 'site', artifacts.fieldOutput?.site, 'field-output-matrix.json', '$.site', normalizeOrigin);
  add('site.drupal.uuid', 'site', artifacts.drupalReadback?.drupal?.siteUuid, 'drupal-readback.json', '$.drupal.siteUuid', (value) => String(value).trim());

  const addRoute = (record, artifact, path, statusField, finalField, acceptedField = 'accepted') => {
    const route = normalizeRoute(record?.targetPath ?? record?.path);
    if (!route) return;
    add(`route:${route}:status`, 'route', record?.[statusField], artifact, `${path}.${statusField}`, Number);
    add(`route:${route}:finalPath`, 'route', record?.[finalField], artifact, `${path}.${finalField}`, normalizeRoute);
    add(`route:${route}:accepted`, 'route', record?.[acceptedField], artifact, `${path}.${acceptedField}`);
  };
  arrayOrEmpty(artifacts.routeMatrix?.routes).forEach((record, index) =>
    addRoute(record, 'route-matrix.json', `$.routes[${index}]`, 'targetStatus', 'targetFinalPath'));
  arrayOrEmpty(artifacts.routeMatrix?.targetRequiredRoutes).forEach((record, index) =>
    addRoute(record, 'route-matrix.json', `$.targetRequiredRoutes[${index}]`, 'targetStatus', 'targetFinalPath'));
  addRoute(artifacts.routeMatrix?.homepageParity, 'route-matrix.json', '$.homepageParity', 'targetStatus', 'targetFinalPath');
  add('config.active.syncDirectory', 'config', artifacts.drupalReadback?.drupal?.configSyncDirectory, 'drupal-readback.json', '$.drupal.configSyncDirectory', normalizeDirectory);
  add('config.tracked.directory', 'config', artifacts.drupalReadback?.drupal?.trackedConfigDirectory, 'drupal-readback.json', '$.drupal.trackedConfigDirectory', normalizeDirectory);
  if (artifacts.drupalReadback?.drupal?.configSyncDirectoryMatchesTrackedDirectory === true) {
    add('config.canonical.directory', 'config', artifacts.drupalReadback?.drupal?.configSyncDirectory, 'drupal-readback.json', '$.drupal.configSyncDirectory', normalizeDirectory);
    add('config.canonical.directory', 'config', artifacts.drupalReadback?.drupal?.trackedConfigDirectory, 'drupal-readback.json', '$.drupal.trackedConfigDirectory', normalizeDirectory);
  }
  add('config.status.clean', 'config', artifacts.drupalReadback?.drupal?.configStatusClean, 'drupal-readback.json', '$.drupal.configStatusClean');
  const configStatus = String(artifacts.drupalReadback?.drupal?.configStatus ?? '').trim();
  if (/no\s+(?:differences|changes)/i.test(configStatus)) {
    add('config.status.clean', 'config', true, 'drupal-readback.json', '$.drupal.configStatus');
  } else if (configStatus && /different|changed|only\s+in|missing|modified/i.test(configStatus)) {
    add('config.status.clean', 'config', false, 'drupal-readback.json', '$.drupal.configStatus');
  }
  add('config.frontPage', 'config', artifacts.drupalReadback?.drupal?.frontPage, 'drupal-readback.json', '$.drupal.frontPage', normalizeRoute);

  const targetMap = routeTargetMap(artifacts.routeMatrix);
  const targetForSource = (source) => targetMap.get(normalizeRoute(source)) || normalizeRoute(source);
  arrayOrEmpty(artifacts.patternMap?.pageCompositionOwnership).forEach((record, index) => {
    const route = targetForSource(record?.sourceRoute);
    if (route) add(`ownership:${route}:pageOwner`, 'ownership', record?.selectedOwner, 'pattern-map.json', `$.pageCompositionOwnership[${index}].selectedOwner`, (value) => String(value).trim());
  });
  arrayOrEmpty(artifacts.routeMatrix?.targetRequiredRoutes).forEach((record, index) => {
    const route = normalizeRoute(record?.targetPath);
    if (route) add(`ownership:${route}:pageOwner`, 'ownership', record?.drupalOwner, 'route-matrix.json', `$.targetRequiredRoutes[${index}].drupalOwner`, (value) => String(value).trim());
  });
  add('ownership:/:pageOwner', 'ownership', artifacts.routeMatrix?.homepageParity?.targetDrupalRouteOwner, 'route-matrix.json', '$.homepageParity.targetDrupalRouteOwner', (value) => String(value).trim());
  arrayOrEmpty(artifacts.patternMap?.compositionModel?.flexibleLandingRoutes).forEach((record, index) => {
    const route = normalizeRoute(record?.targetRoute) || targetForSource(record?.sourceRoute);
    if (route) add(`ownership:${route}:compositionOwner`, 'ownership', record?.compositionOwner, 'pattern-map.json', `$.compositionModel.flexibleLandingRoutes[${index}].compositionOwner`, (value) => String(value).trim());
  });
  arrayOrEmpty(artifacts.independentVerification?.compositionModelFidelityChecks).forEach((record, index) => {
    const route = normalizeRoute(record?.targetRoute) || targetForSource(record?.sourceRoute);
    if (route) add(`ownership:${route}:compositionOwner`, 'ownership', record?.actualCompositionOwner, 'independent-verification.json', `$.compositionModelFidelityChecks[${index}].actualCompositionOwner`, (value) => String(value).trim());
  });
  arrayOrEmpty(artifacts.patternMap?.sectionOwnershipMatrix).forEach((record, index) => {
    const route = targetForSource(record?.sourceRoute);
    const section = String(record?.section ?? '').trim();
    if (route && section) {
      add(`ownership:${route}:section:${section}`, 'ownership', record?.drupalOwner || record?.editorOwnedBy, 'pattern-map.json', `$.sectionOwnershipMatrix[${index}]`, (value) => String(value).trim());
    }
  });

  const independentClaims = artifacts.independentVerification?.completionClaims;
  add('completion.independent.failedClaimCount', 'completion', artifacts.independentVerification?.summary?.failedClaimCount, 'independent-verification.json', '$.summary.failedClaimCount', Number);
  add('completion.independent.failedClaimCount', 'completion', countClaims(independentClaims, 'fail'), 'independent-verification.json', '$.completionClaims[status=fail]', Number);
  add('completion.independent.blockedClaimCount', 'completion', artifacts.independentVerification?.summary?.blockedClaimCount, 'independent-verification.json', '$.summary.blockedClaimCount', Number);
  add('completion.independent.blockedClaimCount', 'completion', countClaims(independentClaims, 'blocked'), 'independent-verification.json', '$.completionClaims[status=blocked]', Number);
  add('completion.independent.verdict', 'completion', artifacts.independentVerification?.summary?.verdict, 'independent-verification.json', '$.summary.verdict', (value) => String(value).trim());

  const defects = arrayOrEmpty(artifacts.blindReview?.productDefects);
  const openSeverity = (severity) => defects.filter((defect) => defect?.severity === severity && defect?.status === 'open').length;
  const blindCounts = [
    ['openBlockerIssueCount', openSeverity('blocker')],
    ['openCriticalIssueCount', openSeverity('critical')],
    ['openHighIssueCount', openSeverity('high')],
    ['acceptedOutOfScopeIssueCount', defects.filter((defect) => defect?.status === 'accepted_out_of_scope').length],
    ['externalBlockerIssueCount', defects.filter((defect) => defect?.status === 'external_blocker').length]
  ];
  for (const [name, computed] of blindCounts) {
    add(`completion.blind.${name}`, 'completion', artifacts.blindReview?.summary?.[name], 'blind-adversarial-review.json', `$.summary.${name}`, Number);
    add(`completion.blind.${name}`, 'completion', computed, 'blind-adversarial-review.json', '$.productDefects', Number);
  }
  add('completion.blind.verdict', 'completion', artifacts.blindReview?.summary?.verdict, 'blind-adversarial-review.json', '$.summary.verdict', (value) => String(value).trim());
  add('completion.blind.state', 'completion', artifacts.blindReview?.summary?.completionState, 'blind-adversarial-review.json', '$.summary.completionState', (value) => String(value).trim());
  return observations;
}

export function collectCanonicalFacts({ packetDir = 'review-packet' } = {}) {
  const absolutePacket = resolve(packetDir);
  assertDirectory(absolutePacket, 'Review packet');
  const byKey = new Map();
  for (const observation of collectObservations(absolutePacket)) {
    const records = byKey.get(observation.key) ?? [];
    records.push(observation);
    byKey.set(observation.key, records);
  }
  const contradictions = [];
  const facts = [];
  for (const [key, observations] of [...byKey.entries()].sort(([left], [right]) => comparePortable(left, right))) {
    const distinct = new Map(observations.map((observation) => [canonicalJson(observation.value), observation.value]));
    if (distinct.size > 1) {
      contradictions.push({ key, observations });
      continue;
    }
    const category = observations[0].category;
    facts.push({ key, category, value: [...distinct.values()][0] });
  }
  if (contradictions.length > 0) throw new CanonicalFactContradictionError(contradictions);
  const document = {
    schemaVersion: FACTS_SCHEMA,
    facts,
    fingerprint: sha256(facts)
  };
  return document;
}

function safeEvidencePath(packetDir, reference) {
  let text = portablePath(String(reference ?? '').trim()).replace(/^\.\//, '');
  const packetName = basename(packetDir);
  if (text.startsWith(`${packetName}/`)) text = text.slice(packetName.length + 1);
  if (
    !text ||
    isAbsolute(text) ||
    text.startsWith('/') ||
    /^[a-z]:\//i.test(text) ||
    text.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error(`Fact evidence reference must be a non-traversing packet-relative path: ${String(reference)}`);
  }
  const candidate = resolve(packetDir, text);
  if (!isInside(packetDir, candidate) || !existsSync(candidate) || !statSync(candidate).isFile()) {
    throw new Error(`Fact evidence reference is missing or not a file: ${text}`);
  }
  if (lstatSync(candidate).isSymbolicLink() || !isInside(realpathSync(packetDir), realpathSync(candidate))) {
    throw new Error(`Fact evidence reference must not traverse a symbolic link: ${text}`);
  }
  let current = candidate;
  while (current !== packetDir) {
    if (lstatSync(current).isSymbolicLink()) {
      throw new Error(`Fact evidence reference must not traverse a symbolic link: ${text}`);
    }
    current = dirname(current);
    if (!isInside(packetDir, current)) {
      throw new Error(`Fact evidence reference escaped the packet: ${text}`);
    }
  }
  return { absolutePath: realpathSync(candidate), packetPath: text };
}

function normalizeActor(actor, label) {
  if (!isObject(actor) || !ACTOR_KINDS.has(actor.kind)) {
    throw new Error(`${label}.kind must be agent, subagent, tool, or named_human.`);
  }
  const id = String(actor.id ?? '').trim();
  const name = String(actor.name ?? '').trim();
  const identityBasis = String(actor.identityBasis ?? '').trim();
  if (!id || !name || !identityBasis) {
    throw new Error(`${label} requires id, name, and identityBasis.`);
  }
  const normalized = { kind: actor.kind, id, name, identityBasis };
  if (actor.kind === 'subagent') {
    const parentActorId = String(actor.parentActorId ?? '').trim();
    if (!parentActorId) throw new Error(`${label} subagent requires parentActorId.`);
    normalized.parentActorId = parentActorId;
  }
  if (actor.kind === 'tool') {
    const tool = String(actor.tool ?? '').trim();
    if (!tool) throw new Error(`${label} tool requires tool.`);
    normalized.tool = tool;
  }
  return normalized;
}

function isoTimestamp(value, label) {
  const text = String(value ?? '').trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(text) || !Number.isFinite(Date.parse(text))) {
    throw new Error(`${label} must be a UTC ISO timestamp.`);
  }
  return text;
}

function loadProvenance(packetDir) {
  const path = join(packetDir, 'fact-provenance.json');
  if (!existsSync(path)) return { configured: false, reason: 'fact-provenance.json is missing.' };
  const provenance = readJsonIfPresent(packetDir, 'fact-provenance.json');
  const claims = arrayOrEmpty(provenance?.claims);
  if (!String(provenance?.run?.id ?? '').trim() && claims.length === 0) {
    return { configured: false, reason: 'fact-provenance.json is still an unconfigured stub.' };
  }
  if (provenance?.schemaVersion !== PROVENANCE_SCHEMA) {
    throw new Error(`fact-provenance.json must use schemaVersion ${PROVENANCE_SCHEMA}.`);
  }
  if (provenance.humanGateAcceptanceRecordedHere !== false) {
    throw new Error('fact-provenance.json is evidence metadata only and must not record human-gate acceptance.');
  }
  const runId = String(provenance.run?.id ?? '').trim();
  if (!runId || !/^[a-z0-9][a-z0-9._-]*$/i.test(runId)) {
    throw new Error('fact-provenance.json run.id must be a stable slug.');
  }
  const startedAt = isoTimestamp(provenance.run?.startedAt, 'fact-provenance.json run.startedAt');
  const finishedAt = isoTimestamp(provenance.run?.finishedAt, 'fact-provenance.json run.finishedAt');
  if (Date.parse(finishedAt) < Date.parse(startedAt)) {
    throw new Error('fact-provenance.json run.finishedAt must not precede run.startedAt.');
  }
  const run = {
    id: runId,
    startedAt,
    finishedAt,
    actor: normalizeActor(provenance.run?.actor, 'fact-provenance.json run.actor')
  };
  if (claims.length === 0) throw new Error('fact-provenance.json requires at least one claim.');
  const seen = new Set();
  const normalizedClaims = claims.map((claim, index) => {
    const claimId = String(claim?.claimId ?? '').trim();
    if (!claimId || seen.has(claimId)) throw new Error(`fact-provenance.json claim ${index} has a missing or duplicate claimId.`);
    seen.add(claimId);
    const factKeys = [...new Set(arrayOrEmpty(claim.factKeys).map((value) => String(value).trim()).filter(Boolean))].sort(comparePortable);
    const evidence = [...new Set(arrayOrEmpty(claim.evidence).map((value) => String(value).trim()).filter(Boolean))].sort(comparePortable);
    const status = String(claim.status ?? '').trim();
    if (claim.authority !== 'evidence_observation') throw new Error(`Fact claim ${claimId} authority must be evidence_observation.`);
    if (!CLAIM_STATUSES.has(status)) throw new Error(`Fact claim ${claimId} status must be observed, falsified, or blocked.`);
    if (factKeys.length === 0 || evidence.length === 0) throw new Error(`Fact claim ${claimId} requires factKeys and evidence.`);
    return {
      claimId,
      gate: String(claim.gate ?? '').trim(),
      authority: 'evidence_observation',
      status,
      checkedAt: isoTimestamp(claim.checkedAt, `Fact claim ${claimId} checkedAt`),
      reviewer: normalizeActor(claim.reviewer, `Fact claim ${claimId} reviewer`),
      factKeys,
      evidence
    };
  }).sort((left, right) => comparePortable(left.claimId, right.claimId));
  return { configured: true, run, claims: normalizedClaims };
}

export function storeEvidenceObject({ packetDir, bytes = null, sourcePath = '', projectRoot = dirname(resolve(packetDir)) }) {
  const absolutePacket = resolve(packetDir);
  assertDirectory(absolutePacket, 'Review packet');
  let content = bytes;
  if (content === null) {
    if (!sourcePath || !existsSync(sourcePath) || !statSync(sourcePath).isFile() || lstatSync(sourcePath).isSymbolicLink()) {
      throw new Error('Evidence object source must be a regular non-symlink file.');
    }
    content = readFileSync(sourcePath);
  }
  const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const digest = sha256(buffer);
  const hex = digest.slice('sha256:'.length);
  const objectDirectory = join(absolutePacket, 'evidence', 'objects', 'sha256');
  ensureDirectory(objectDirectory, absolutePacket, 'Evidence object store');
  const objectPath = join(objectDirectory, hex);
  if (existsSync(objectPath)) {
    if (!statSync(objectPath).isFile() || lstatSync(objectPath).isSymbolicLink() || sha256(readFileSync(objectPath)) !== digest) {
      throw new Error(`Evidence object ${digest} exists with different or unsafe bytes.`);
    }
  } else {
    writeFileSync(objectPath, buffer, { flag: 'wx' });
  }
  return {
    sha256: digest,
    size: buffer.length,
    packetPath: portablePath(relative(absolutePacket, objectPath)),
    projectPath: portablePath(relative(resolve(projectRoot), objectPath))
  };
}

function buildFactArtifacts(packetDir) {
  const canonicalFacts = collectCanonicalFacts({ packetDir });
  const provenance = loadProvenance(packetDir);
  if (!provenance.configured) return { configured: false, reason: provenance.reason, canonicalFacts };
  const factKeys = new Set(canonicalFacts.facts.map((fact) => fact.key));
  const objects = new Map();
  const claims = provenance.claims.map((claim) => {
    const missingFactKeys = claim.factKeys.filter((key) => !factKeys.has(key));
    if (missingFactKeys.length > 0) throw new Error(`Fact claim ${claim.claimId} references unknown facts: ${missingFactKeys.join(', ')}.`);
    const objectDigests = [];
    for (const reference of claim.evidence) {
      const evidence = safeEvidencePath(packetDir, reference);
      const bytes = readFileSync(evidence.absolutePath);
      const digest = sha256(bytes);
      objectDigests.push(digest);
      const object = objects.get(digest) ?? { sha256: digest, size: bytes.length, originalPaths: new Set(), claimIds: new Set(), bytes };
      if (object.size !== bytes.length || sha256(object.bytes) !== digest) throw new Error(`Evidence digest collision for ${digest}.`);
      object.originalPaths.add(evidence.packetPath);
      object.claimIds.add(claim.claimId);
      objects.set(digest, object);
    }
    return {
      claimId: claim.claimId,
      gate: claim.gate,
      authority: claim.authority,
      status: claim.status,
      checkedAt: claim.checkedAt,
      reviewer: claim.reviewer,
      factKeys: claim.factKeys,
      evidenceObjects: [...new Set(objectDigests)].sort(comparePortable)
    };
  });
  const objectRecords = [...objects.values()].sort((left, right) => comparePortable(left.sha256, right.sha256)).map((object) => ({
    sha256: object.sha256,
    size: object.size,
    path: `evidence/objects/sha256/${object.sha256.slice('sha256:'.length)}`,
    originalPaths: [...object.originalPaths].sort(comparePortable),
    claimIds: [...object.claimIds].sort(comparePortable)
  }));
  const claimDocument = {
    schemaVersion: CLAIMS_SCHEMA,
    humanGateAcceptanceRecordedHere: false,
    run: provenance.run,
    claims,
    fingerprint: sha256({ run: provenance.run, claims })
  };
  const objectIndex = {
    schemaVersion: OBJECT_INDEX_SCHEMA,
    objects: objectRecords,
    fingerprint: sha256(objectRecords)
  };
  const summary = deterministicSummary(canonicalFacts, claimDocument, objectIndex);
  const contents = {
    [GENERATED_FILES.canonicalFacts]: prettyJson(canonicalFacts),
    [GENERATED_FILES.claims]: prettyJson(claimDocument),
    [GENERATED_FILES.objectIndex]: prettyJson(objectIndex),
    [GENERATED_FILES.summary]: summary
  };
  const manifestEntries = Object.entries(contents).sort(([left], [right]) => comparePortable(left, right)).map(([path, content]) => ({
    path,
    sha256: sha256(content),
    size: Buffer.byteLength(content)
  }));
  const manifest = {
    schemaVersion: MANIFEST_SCHEMA,
    factFingerprint: canonicalFacts.fingerprint,
    claimFingerprint: claimDocument.fingerprint,
    objectFingerprint: objectIndex.fingerprint,
    generatedFiles: manifestEntries,
    fingerprint: sha256(manifestEntries)
  };
  contents[GENERATED_FILES.manifest] = prettyJson(manifest);
  return { configured: true, canonicalFacts, claimDocument, objectIndex, objects, contents, manifest };
}

function displayValue(value) {
  return typeof value === 'string' ? JSON.stringify(value) : canonicalJson(value);
}

export function deterministicSummary(canonicalFacts, claimDocument, objectIndex) {
  const lines = [
    '# Canonical Fact Summary',
    '',
    `- Fact fingerprint: ${canonicalFacts.fingerprint}`,
    `- Run: ${claimDocument.run.id}`,
    `- Run actor: ${claimDocument.run.actor.kind} — ${claimDocument.run.actor.name} (${claimDocument.run.actor.id})`,
    `- Evidence objects: ${objectIndex.objects.length}`,
    '- Human-gate acceptance: not recorded here; dedicated human-gate records remain authoritative.',
    ''
  ];
  for (const category of FACT_CATEGORIES) {
    lines.push(`## ${category[0].toUpperCase()}${category.slice(1)} Facts`, '');
    const facts = canonicalFacts.facts.filter((fact) => fact.category === category);
    if (facts.length === 0) {
      lines.push('- None recorded.', '');
    } else {
      for (const fact of facts) lines.push(`- ${fact.key}: ${displayValue(fact.value)}`);
      lines.push('');
    }
  }
  lines.push('## Claim Provenance', '');
  for (const claim of claimDocument.claims) {
    lines.push(`- ${claim.claimId}: ${claim.status}; reviewer ${claim.reviewer.kind} — ${claim.reviewer.name} (${claim.reviewer.id}); ${claim.evidenceObjects.length} evidence object(s).`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

export function generateCanonicalFactStore({ packetDir = 'review-packet' } = {}) {
  const absolutePacket = resolve(packetDir);
  const built = buildFactArtifacts(absolutePacket);
  if (!built.configured) throw new Error(built.reason);
  for (const object of built.objects.values()) {
    storeEvidenceObject({ packetDir: absolutePacket, bytes: object.bytes, projectRoot: dirname(absolutePacket) });
  }
  const factsDirectory = join(absolutePacket, 'evidence', 'facts');
  ensureDirectory(factsDirectory, absolutePacket, 'Canonical fact output directory');
  for (const [name, content] of Object.entries(built.contents)) {
    const path = join(factsDirectory, name);
    if (existsSync(path) && (!statSync(path).isFile() || lstatSync(path).isSymbolicLink())) {
      throw new Error(`Canonical fact output must be a regular non-symlink file: ${name}.`);
    }
    writeFileSync(path, content);
  }
  return {
    packetDir: absolutePacket,
    factFingerprint: built.canonicalFacts.fingerprint,
    claimFingerprint: built.claimDocument.fingerprint,
    objectFingerprint: built.objectIndex.fingerprint,
    objectCount: built.objectIndex.objects.length,
    manifestFingerprint: built.manifest.fingerprint
  };
}

export function verifyCanonicalFactStore({ packetDir = 'review-packet' } = {}) {
  const absolutePacket = resolve(packetDir);
  try {
    const built = buildFactArtifacts(absolutePacket);
    if (!built.configured) {
      return { valid: true, ready: false, errors: [], reasons: [built.reason], factFingerprint: built.canonicalFacts.fingerprint };
    }
    const reasons = [];
    const factsDirectory = join(absolutePacket, 'evidence', 'facts');
    for (const [name, expected] of Object.entries(built.contents)) {
      const path = join(factsDirectory, name);
      if (!existsSync(path) || !statSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
        reasons.push(`Canonical fact output is missing or unsafe: evidence/facts/${name}.`);
      } else if (!readFileSync(path).equals(Buffer.from(expected))) {
        reasons.push(`Canonical fact output is stale or non-deterministic: evidence/facts/${name}.`);
      }
    }
    for (const object of built.objectIndex.objects) {
      const path = join(absolutePacket, object.path);
      if (!existsSync(path) || !statSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
        reasons.push(`Evidence object is missing or unsafe: ${object.path}.`);
      } else {
        const bytes = readFileSync(path);
        if (bytes.length !== object.size || sha256(bytes) !== object.sha256) {
          reasons.push(`Evidence object bytes do not match ${object.sha256}.`);
        }
      }
    }
    const categorySet = new Set(built.canonicalFacts.facts.map((fact) => fact.category));
    for (const category of FACT_CATEGORIES) {
      if (!categorySet.has(category)) reasons.push(`Canonical fact store has no ${category} facts.`);
    }
    return {
      valid: true,
      ready: reasons.length === 0,
      errors: [],
      reasons,
      factFingerprint: built.canonicalFacts.fingerprint,
      claimFingerprint: built.claimDocument.fingerprint,
      objectFingerprint: built.objectIndex.fingerprint,
      objectCount: built.objectIndex.objects.length
    };
  } catch (error) {
    return {
      valid: false,
      ready: false,
      errors: [error.message],
      reasons: ['Canonical fact generation or contradiction checking failed.']
    };
  }
}

function usage() {
  return `Usage: node <path-to-skill>/scripts/canonical-facts.mjs <generate|check> [--packet review-packet]\n\n` +
    'generate  Build canonical facts, deterministic summary, claim metadata, and SHA-256 evidence objects.\n' +
    'check     Recompute without writing; fail when generated output is missing, stale, contradictory, or tampered.\n';
}

function parseArgs(argv) {
  const args = { command: '', packetDir: 'review-packet' };
  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index];
    if (!args.command && ['generate', 'check'].includes(value)) {
      args.command = value;
    } else if (value === '--packet') {
      const next = argv[index + 1];
      if (!next || next.startsWith('-')) throw new UsageError('--packet requires a value.');
      args.packetDir = next;
      index += 1;
    } else if (value.startsWith('--packet=')) {
      args.packetDir = value.slice('--packet='.length);
    } else if (value === '--help' || value === '-h') {
      args.help = true;
    } else {
      throw new UsageError(`Unknown argument: ${value}`);
    }
  }
  if (!args.help && !args.command) throw new UsageError('generate or check is required.');
  return args;
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
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(usage());
    return;
  }
  if (args.command === 'generate') {
    const result = generateCanonicalFactStore({ packetDir: args.packetDir });
    process.stdout.write(`Canonical fact store generated: ${result.factFingerprint}; ${result.objectCount} evidence object(s).\n`);
    return;
  }
  const result = verifyCanonicalFactStore({ packetDir: args.packetDir });
  if (!result.valid || !result.ready) {
    for (const message of [...result.errors, ...result.reasons]) process.stderr.write(`- ${message}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`Canonical fact store verified: ${result.factFingerprint}; ${result.objectCount} evidence object(s).\n`);
}

if (isDirectRun()) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = error instanceof UsageError ? 2 : 1;
  }
}
