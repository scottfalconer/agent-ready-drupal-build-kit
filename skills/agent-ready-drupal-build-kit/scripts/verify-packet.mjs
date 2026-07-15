#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';

const KIT_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const USAGE = 'Usage: node <path-to-skill>/scripts/verify-packet.mjs --packet review-packet --out review-packet/evidence/packet-verification.json';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const BLIND_COMPLETE_VERDICTS = new Set(['good', 'good_enough']);
const GATE_CHECKED_BY = new Set(['human', 'verify-script', 'verifier', 'blind-verifier']);
const GATE_BLOCKING = new Set(['handoff', 'launch']);
const VISUAL_COMPARISON_METHODS = new Set([
  'agent_review',
  'human_review',
  'other',
  'pixel_diff',
  'structural_review'
]);
const COMPLETION_VISUAL_COMPARISON_METHODS = new Set(['agent_review', 'human_review', 'pixel_diff']);
const BLIND_DEFECT_SEVERITIES = new Set(['blocker', 'critical', 'high', 'medium', 'low']);
const BLIND_DEFECT_STATUSES = new Set(['open', 'fixed', 'accepted_out_of_scope', 'external_blocker']);
const BLIND_ROUTE_CHECKS = [
  'actualRequestedOutcome',
  'firstFoldVisualParity',
  'navigationBehavior',
  'contentHierarchyCompleteness',
  'mediaArtworkFidelity',
  'interactionParity',
  'editorialQuality',
  'accessibilitySeoConsoleObviousDefects'
];
const REQUIRED_BLIND_ROUTE_PASSES = new Set([
  'actualRequestedOutcome',
  'firstFoldVisualParity',
  'navigationBehavior',
  'contentHierarchyCompleteness',
  'mediaArtworkFidelity',
  'interactionParity',
  'editorialQuality',
  'accessibilitySeoConsoleObviousDefects'
]);
const MIN_SCREENSHOT_BYTES = 1024;
const MIN_SCREENSHOT_DIMENSION = 200;
const MAX_SCREENSHOT_BYTES = 25 * 1024 * 1024;
const MAX_SCREENSHOT_DIMENSION = 12_000;
const MAX_SCREENSHOT_PIXELS = 50_000_000;
const MAX_PNG_INFLATED_BYTES = 200 * 1024 * 1024;
const LOCAL_COMPLETION_NON_AUTHORITY_FILES = new Set([
  'launch-checklist.md',
  'maintainer-review.md',
  'operator-run.md',
  'production-target.md'
]);
const COMPLETION_CLAIM_GATES = new Set([
  'content',
  'media',
  'visual',
  'behavior',
  'editor',
  'route',
  'seo',
  'accessibility',
  'security_privacy',
  'architecture',
  'packet'
]);
const MAX_COMPLETION_EVIDENCE_SPAN_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_TIMESTAMP_SKEW_MS = 5 * 60 * 1000;
const ROUTE_ROLES = new Set([
  'homepage',
  'landing',
  'listing',
  'detail',
  'taxonomy',
  'search',
  'form',
  'legal',
  'media',
  'other'
]);
const SAME_ORIGIN_LINK_DISPOSITIONS = new Set([
  'intentional_unlisted_route',
  'dynamic_endpoint',
  'other'
]);
const EXTERNAL_REDIRECT_FINAL_MATCHES = new Set(['exact_url', 'origin']);
const FREEFORM_TEMPLATE_PIPE_FIELDS = new Set(['nameOrRole', 'task']);
const PACKET_EXECUTED_GATE_IDS = new Set([
  'G-ROUTE-01',
  'G-COMPOSITION-01',
  'G-RECIPE-01',
  'G-INTENT-01',
  'G-VERIFY-01',
  'G-HANDOFF-01',
  'G-BLIND-01'
]);
const COMPLETION_GATE_IDS = Object.freeze({
  accessibility: 'G-A11Y-01',
  architecture: 'G-COMPOSITION-01',
  behavior: 'G-BROWSER-01',
  content: 'G-CONTENT-01',
  editor: 'G-EDITOR-01',
  media: 'G-PARITY-01',
  packet: 'G-VERIFY-01',
  route: 'G-ROUTE-01',
  security_privacy: 'G-PRIVACY-01',
  seo: 'G-SEO-01',
  visual: 'G-BROWSER-02'
});

// Keep this map explicit. A non-human gate without a named evaluator is a prose-only
// promise and must make the gate vocabulary invalid.
export const MACHINE_GATE_EVALUATORS = Object.freeze({
  'G-ROUTE-01': 'routeInventory',
  'G-ROUTE-02': 'browserFirstRouteExpansion',
  'G-ROUTE-03': 'perRouteItemReconciliation',
  'G-ROUTE-04': 'sourceRouteDrift',
  'G-ROUTE-05': 'targetRequiredRoutes',
  'G-ROUTE-06': 'homepageAndAlias',
  'G-BROWSER-01': 'publicBrowserEvidence',
  'G-BROWSER-02': 'firstFoldBrandParity',
  'G-DETAIL-01': 'detailRouteContent',
  'G-A11Y-01': 'realBrowserAccessibility',
  'G-FORM-01': 'anonymousFormReadiness',
  'G-PARITY-01': 'addressableSurfaceParity',
  'G-CONTENT-01': 'structuredContentOwnership',
  'G-CONTENT-02': 'collectionOwnership',
  'G-COMPOSITION-01': 'compositionDeclaration',
  'G-COMPOSITION-02': 'compositionFidelity',
  'G-CANVAS-01': 'canvasComponentFidelity',
  'G-RECIPE-01': 'recipeStartPoint',
  'G-CONFIG-01': 'trackedConfigSync',
  'G-SURFACE-01': 'liveDrupalSurfaceReconciliation',
  'G-INTENT-01': 'durableIntent',
  'G-FIELD-01': 'fieldOutput',
  'G-OFFROAD-01': 'offRoadAndRawMarkup',
  'G-HANDOFF-01': 'humanDecisionPresentation',
  'G-VERIFY-01': 'independentVerification',
  'G-VERIFY-02': 'liveVerification',
  'G-BLIND-01': 'blindAdversarialReview',
  'G-EDITOR-01': 'editorWorkflow',
  'G-SEO-01': 'renderedSeo',
  'G-EDITOR-02': 'nextCycleEditorWorkflow',
  'G-PRIVACY-01': 'negativeRouteConsent',
  'G-REPRO-01': 'disposableReproduction'
});

function collectTemplateEnumRules(value, path = [], rules = new Map()) {
  if (Array.isArray(value)) {
    for (const child of value) {
      collectTemplateEnumRules(child, [...path, '*'], rules);
    }
    return rules;
  }
  if (!isJsonObject(value)) {
    return rules;
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = [...path, key];
    if (
      typeof child === 'string' &&
      child.includes(' | ') &&
      !FREEFORM_TEMPLATE_PIPE_FIELDS.has(key)
    ) {
      const allowed = child.split(/\s*\|\s*/).map((item) => item.trim()).filter(Boolean);
      if (allowed.length > 1) {
        rules.set(JSON.stringify(childPath), { allowed, path: childPath });
      }
    } else {
      collectTemplateEnumRules(child, childPath, rules);
    }
  }
  return rules;
}

function structuredEnumRules(gates, errors) {
  const byFile = new Map();
  for (const file of arrayOrEmpty(gates?.reviewPacketFiles).filter((name) => name.endsWith('.json'))) {
    const templatePath = installedTemplatePath(file);
    if (!templatePath) {
      errors.push(`${file} has no installed JSON template for structured enum validation.`);
      continue;
    }
    try {
      const template = JSON.parse(readFileSync(templatePath, 'utf8'));
      byFile.set(file, [...collectTemplateEnumRules(template).values()]);
    } catch {
      errors.push(`${file} installed template must be readable valid JSON for structured enum validation.`);
    }
  }
  return byFile;
}

function valuesAtStructuredPath(value, path, index = 0, display = '') {
  if (index >= path.length) {
    return [{ display, value }];
  }
  const segment = path[index];
  if (segment === '*') {
    if (!Array.isArray(value)) {
      return [];
    }
    return value.flatMap((child, childIndex) =>
      valuesAtStructuredPath(child, path, index + 1, `${display}[${childIndex}]`)
    );
  }
  if (!isJsonObject(value) || !Object.hasOwn(value, segment)) {
    return [];
  }
  const nextDisplay = display ? `${display}.${segment}` : segment;
  return valuesAtStructuredPath(value[segment], path, index + 1, nextDisplay);
}

function validateStructuredEnums(gates, records, errors) {
  for (const [file, rules] of structuredEnumRules(gates, errors)) {
    const record = records[file];
    if (!isJsonObject(record)) {
      continue;
    }
    for (const rule of rules) {
      for (const candidate of valuesAtStructuredPath(record, rule.path)) {
        if (candidate.value === rule.allowed.join(' | ')) {
          // The shipped template sentinel is a valid blocked-stub placeholder. It
          // never supports completion and is rejected separately when unresolved.
          continue;
        }
        if (typeof candidate.value !== 'string' || !rule.allowed.includes(candidate.value)) {
          errors.push(
            `${file} ${candidate.display} must be one of: ${rule.allowed.join(', ')}.`
          );
        }
      }
    }
  }
}

function visitArtifactGateIds(value, visit, path = '') {
  if (Array.isArray(value)) {
    value.forEach((child, index) => visitArtifactGateIds(child, visit, `${path}[${index}]`));
    return;
  }
  if (!isJsonObject(value)) {
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (key === 'gateId') {
      visit(child, childPath, false);
    } else if (key === 'gateIds') {
      if (!Array.isArray(child)) {
        visit(child, childPath, true);
      } else {
        child.forEach((gateId, index) => visit(gateId, `${childPath}[${index}]`, false));
      }
    } else {
      visitArtifactGateIds(child, visit, childPath);
    }
  }
}

function validateArtifactGateIds(gates, records, errors) {
  const knownGateIds = new Set(arrayOrEmpty(gates?.gates).map((gate) => gate?.id).filter(Boolean));
  for (const [file, record] of Object.entries(records)) {
    visitArtifactGateIds(record, (value, path, requiresArray) => {
      if (requiresArray) {
        errors.push(`${file} ${path} must be an array of canonical gate ids from gates.json.`);
        return;
      }
      if (typeof value === 'string' && value.trim() === '') {
        return;
      }
      if (typeof value !== 'string' || !knownGateIds.has(value)) {
        errors.push(`${file} ${path} must reference a canonical gate id from gates.json.`);
      }
    });
  }
}

function gateFindingMap(gates, messages) {
  const findings = new Map();
  const attach = (gateId, message) => {
    if (!findings.has(gateId)) {
      findings.set(gateId, []);
    }
    if (!findings.get(gateId).includes(message)) {
      findings.get(gateId).push(message);
    }
  };
  for (const rawMessage of messages) {
    const message = String(rawMessage ?? '').trim();
    if (!message) {
      continue;
    }
    let attributed = false;
    for (const gateId of message.match(/\bG-[A-Z]+-\d{2}\b/g) ?? []) {
      if (arrayOrEmpty(gates?.gates).some((gate) => gate?.id === gateId)) {
        attach(gateId, message);
        attributed = true;
      }
    }
    for (const gate of arrayOrEmpty(gates?.gates)) {
      const evidenceFile = String(gate?.evidenceFile ?? '');
      const evidenceName = basename(evidenceFile);
      if (evidenceName && message.includes(evidenceName)) {
        attach(gate.id, message);
        attributed = true;
      }
    }
    if (!attributed) {
      attach('G-VERIFY-01', message);
    }
  }
  return findings;
}

export function perGateResults(gates, messages, { mode = 'packet' } = {}) {
  const findings = gateFindingMap(gates, messages);
  const liveRunErrors = mode === 'live' ? (findings.get('G-VERIFY-02') ?? []) : [];
  return arrayOrEmpty(gates?.gates)
    .filter((gate) => isJsonObject(gate) && String(gate.id ?? '').trim())
    .map((gate) => {
      const gateErrors = findings.get(gate.id) ?? [];
      const errors = gate.checkedBy === 'human' || liveRunErrors.length === 0
        ? gateErrors
        : [...new Set([...gateErrors, ...liveRunErrors])];
      const evaluated = mode === 'live'
        ? gate.checkedBy !== 'human'
        : PACKET_EXECUTED_GATE_IDS.has(gate.id);
      const status = gate.checkedBy === 'human'
        ? 'human_review'
        : errors.length > 0
          ? 'fail'
          : evaluated
            ? 'pass'
            : 'not_evaluated';
      return {
        gateId: gate.id,
        evaluator: MACHINE_GATE_EVALUATORS[gate.id] ?? 'human-record',
        evaluatorCompleted: evaluated,
        status,
        errors
      };
    });
}

class UsageError extends Error {}

function parseArgs(argv) {
  const args = {
    packet: 'review-packet',
    out: ''
  };

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--packet' || arg === '--out') {
      const next = argv[index + 1];
      if (!next || next.startsWith('--')) {
        throw new UsageError(`${arg} requires a value.`);
      }
      if (arg === '--packet') {
        args.packet = next;
      } else {
        args.out = next;
      }
      index += 1;
    } else if (arg.startsWith('--packet=')) {
      const value = arg.slice('--packet='.length);
      if (!value) {
        throw new UsageError('--packet requires a value.');
      }
      args.packet = value;
    } else if (arg.startsWith('--out=')) {
      const value = arg.slice('--out='.length);
      if (!value) {
        throw new UsageError('--out requires a value.');
      }
      args.out = value;
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg.startsWith('-')) {
      throw new UsageError(`Unknown option: ${arg}.`);
    } else {
      throw new UsageError(`Unexpected positional argument: ${arg}.`);
    }
  }

  if (!args.out) {
    args.out = join(args.packet, 'evidence', 'packet-verification.json');
  }

  return args;
}

function isDirectRun() {
  if (!process.argv[1]) {
    return false;
  }

  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
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

function isJsonObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function isoTimestamp(value) {
  const text = String(value ?? '').trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(text)) {
    return null;
  }
  const timestamp = Date.parse(text);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function dateOrTimestamp(value) {
  const text = String(value ?? '').trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    const timestamp = Date.parse(`${text}T00:00:00Z`);
    return Number.isFinite(timestamp) ? timestamp : null;
  }
  return isoTimestamp(text);
}

function timestampIsFresh(value, now = Date.now()) {
  const timestamp = isoTimestamp(value);
  return timestamp !== null &&
    timestamp <= now + MAX_FUTURE_TIMESTAMP_SKEW_MS &&
    timestamp >= now - MAX_COMPLETION_EVIDENCE_SPAN_MS;
}

function substantiveObject(value) {
  if (!isJsonObject(value)) {
    return false;
  }
  return Object.values(value).some((child) => {
    if (typeof child === 'string') {
      return child.trim().length > 0;
    }
    if (typeof child === 'number') {
      return Number.isFinite(child);
    }
    if (typeof child === 'boolean') {
      return child;
    }
    return Array.isArray(child) ? child.length > 0 : isJsonObject(child) && substantiveObject(child);
  });
}

function substantiveObjects(values) {
  return arrayOrEmpty(values).filter(substantiveObject);
}

function routeLikeValue(value) {
  if (typeof value === 'string') {
    return normalizeRouteRequestKey(value);
  }
  if (!isJsonObject(value)) {
    return '';
  }
  return normalizeRouteRequestKey(value.sourcePath || value.path || value.route || value.url || value.href);
}

function allPassingRecords(values, { allowNotApplicable = false } = {}) {
  const records = substantiveObjects(values);
  const acceptedStatuses = allowNotApplicable ? new Set(['pass', 'not_applicable']) : new Set(['pass']);
  return records.length > 0 && records.every((record) => acceptedStatuses.has(record.status));
}

function finiteNumberValue(value) {
  return value !== null && value !== '' && Number.isFinite(Number(value));
}

function numericValue(value) {
  return finiteNumberValue(value) ? Number(value) : null;
}

function successfulStatus(value) {
  const status = numericValue(value);
  return status !== null && status >= 200 && status < 300;
}

function redirectStatus(value) {
  const status = numericValue(value);
  return status !== null && status >= 300 && status < 400;
}

function expectedPublicBehaviorMatches(behavior, status, finalPath, requestedPath) {
  const normalizedFinalPath = normalizeRouteKey(finalPath);
  const normalizedRequestedPath = normalizeRouteKey(requestedPath);
  if (behavior === 'public_200') {
    return numericValue(status) === 200 && normalizedFinalPath === normalizedRequestedPath;
  }
  if (behavior === 'redirect') {
    return redirectStatus(status) && Boolean(normalizedFinalPath) && normalizedFinalPath !== normalizedRequestedPath;
  }
  if (behavior === 'private_403') {
    return numericValue(status) === 403 && normalizedFinalPath === normalizedRequestedPath;
  }
  if (behavior === 'noindex') {
    return successfulStatus(status) && normalizedFinalPath === normalizedRequestedPath;
  }
  return false;
}

function privilegedEditorIdentity(value) {
  const identity = String(value ?? '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ');
  return /(?:^|\s)(?:admin(?:istrator)?|root|superuser|uid\s*1)(?:\s|$)/.test(identity);
}

function identityKey(value) {
  return String(value ?? '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function identitiesMatch(left, right) {
  const leftKey = identityKey(left);
  const rightKey = identityKey(right);
  return Boolean(leftKey && rightKey && (leftKey === rightKey || leftKey.includes(rightKey) || rightKey.includes(leftKey)));
}

function exactIdentityMatch(left, right) {
  const leftKey = identityKey(left);
  const rightKey = identityKey(right);
  return Boolean(leftKey && rightKey && leftKey === rightKey);
}

function compositionOwnersMatch(declared, actual) {
  return exactIdentityMatch(declared, actual);
}

function authoredCompletionClaim(record) {
  return isJsonObject(record?.summary) && (
    record.summary.completeLocalRebuildClaimAllowed === true ||
    record.summary.completeLocalBuildFromBriefClaimAllowed === true
  );
}

function normalizeRouteKey(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }

  try {
    return new URL(text).pathname || '/';
  } catch {
    return text.split(/[?#]/)[0] || '/';
  }
}

function normalizeRouteRequestKey(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  try {
    const url = new URL(text, 'https://route-key.invalid/');
    const pathname = url.pathname !== '/' ? url.pathname.replace(/\/+$/, '') : '/';
    return `${pathname || '/'}${url.search}`;
  } catch {
    return '';
  }
}

function httpUrl(value) {
  try {
    const url = new URL(String(value ?? '').trim());
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

function isWithin(root, path) {
  const pathFromRoot = relative(root, path);
  return pathFromRoot === '' || (!pathFromRoot.startsWith('..') && !isAbsolute(pathFromRoot));
}

function resolveReviewEvidencePath(packetDir, evidenceDir, value) {
  const path = String(value ?? '').trim();
  if (!path) {
    return '';
  }

  const packetRoot = resolve(packetDir);
  const candidates = [
    isAbsolute(path) ? resolve(path) : '',
    resolve(evidenceDir, path),
    resolve(packetDir, path),
    resolve(dirname(packetDir), path)
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (!isWithin(packetRoot, candidate) || !existsSync(candidate)) {
      continue;
    }

    try {
      const realCandidate = realpathSync(candidate);
      if (isWithin(realpathSync(packetRoot), realCandidate)) {
        return realCandidate;
      }
    } catch {
      // Treat unreadable or broken evidence paths as missing.
    }
  }

  return '';
}

async function nonEmptyPacketEvidence(packetDir, reference, evidenceDir = join(packetDir, 'evidence')) {
  const evidencePath = resolveReviewEvidencePath(packetDir, evidenceDir, reference);
  if (!evidencePath) {
    return false;
  }
  try {
    const evidenceStat = await stat(evidencePath);
    return evidenceStat.isFile() && evidenceStat.size > 0;
  } catch {
    return false;
  }
}

async function fileSha256(path) {
  return `sha256:${createHash('sha256').update(await readFile(path)).digest('hex')}`;
}

async function validateBuildInput(packetDir, buildInput, routeMatrix, errors) {
  const context = {
    briefPath: '',
    briefSha256: '',
    mode: 'source_site'
  };
  if (!isJsonObject(buildInput)) {
    errors.push('build-input.json must be a JSON object.');
    return context;
  }
  if (buildInput.schemaVersion !== 'public-kit.build-input.1') {
    errors.push('build-input.json must use schemaVersion public-kit.build-input.1.');
  }
  if (!['source_site', 'brief'].includes(buildInput.mode)) {
    errors.push('build-input.json mode must be source_site or brief.');
    return context;
  }
  context.mode = buildInput.mode;

  if (buildInput.mode === 'source_site') {
    const inputSource = String(buildInput.sourceUrl ?? '').trim();
    if (inputSource && !httpUrl(inputSource)) {
      errors.push('build-input.json sourceUrl must be a valid credential-free HTTP(S) URL when present.');
    }
    const routeSource = String(routeMatrix?.sourceBaseUrl ?? '').trim();
    if (inputSource && routeSource && httpUrl(inputSource)?.origin !== httpUrl(routeSource)?.origin) {
      errors.push('build-input.json sourceUrl must match route-matrix.json sourceBaseUrl.');
    }
    if (buildInput.brief !== null) {
      errors.push('build-input.json source_site mode must set brief to null.');
    }
    return context;
  }

  if (String(buildInput.sourceUrl ?? '').trim()) {
    errors.push('build-input.json brief mode must not declare sourceUrl.');
  }
  const brief = buildInput.brief;
  if (!isJsonObject(brief) || !String(brief.path ?? '').trim() || !HASH_RE.test(String(brief.sha256 ?? ''))) {
    errors.push('build-input.json brief mode requires brief.path and a sha256 brief.sha256 value.');
    return context;
  }
  const briefPath = resolveReviewEvidencePath(packetDir, packetDir, brief.path);
  if (!briefPath || basename(briefPath) !== 'original-brief.md') {
    errors.push('build-input.json brief.path must reference packet-local original-brief.md.');
    return context;
  }
  const briefStat = await stat(briefPath);
  if (!briefStat.isFile() || briefStat.size === 0) {
    errors.push('The preserved original brief must be a non-empty regular file.');
    return context;
  }
  const actualSha256 = await fileSha256(briefPath);
  if (actualSha256 !== brief.sha256) {
    errors.push('build-input.json brief.sha256 does not match the preserved original brief bytes.');
  }
  context.briefPath = briefPath;
  context.briefSha256 = actualSha256;
  return context;
}

async function packetEvidenceJson(packetDir, reference, evidenceDir = join(packetDir, 'evidence')) {
  const evidencePath = resolveReviewEvidencePath(packetDir, evidenceDir, reference);
  if (!evidencePath || extname(evidencePath).toLowerCase() !== '.json') {
    return null;
  }
  try {
    const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
    return isJsonObject(evidence) ? evidence : null;
  } catch {
    return null;
  }
}

async function packetJsonEvidence(packetDir, reference, evidenceDir = join(packetDir, 'evidence')) {
  const evidencePath = resolveReviewEvidencePath(packetDir, evidenceDir, reference);
  if (!evidencePath || extname(evidencePath).toLowerCase() !== '.json') {
    return null;
  }
  try {
    const evidenceStat = await stat(evidencePath);
    if (!evidenceStat.isFile() || evidenceStat.size === 0) {
      return null;
    }
    const value = JSON.parse(await readFile(evidencePath, 'utf8'));
    return isJsonObject(value) ? value : null;
  } catch {
    return null;
  }
}

function safeImageDimensions(width, height) {
  return (
    Number.isSafeInteger(width) &&
    Number.isSafeInteger(height) &&
    width > 0 &&
    height > 0 &&
    width <= MAX_SCREENSHOT_DIMENSION &&
    height <= MAX_SCREENSHOT_DIMENSION &&
    Number.isSafeInteger(width * height) &&
    width * height <= MAX_SCREENSHOT_PIXELS
  );
}

async function evidenceBindsClaim(evidencePath, claim, independentTargetUrl) {
  if (extname(evidencePath).toLowerCase() !== '.json' || !independentTargetUrl) {
    return false;
  }
  try {
    const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
    const candidates = Array.isArray(evidence?.claims) ? evidence.claims : [evidence];
    return candidates.some((candidate) => {
      const evidenceTargetUrl = httpUrl(candidate?.targetBaseUrl ?? evidence?.targetBaseUrl);
      const checkedAt = String(candidate?.checkedAt ?? evidence?.checkedAt ?? '').trim();
      const checks = arrayOrEmpty(candidate?.checks);
      return (
        evidence?.schemaVersion === 'public-kit.independent-claim-evidence.1' &&
        candidate?.claimId === claim.claimId &&
        candidate?.gate === claim.gate &&
        candidate?.gateId === claim.gateId &&
        evidenceTargetUrl?.origin === independentTargetUrl.origin &&
        timestampIsFresh(checkedAt) &&
        checks.length > 0 &&
        checks.every(
          (check) =>
            isJsonObject(check) &&
            String(check.name ?? '').trim() &&
            String(check.method ?? '').trim() &&
            check.result === 'pass' &&
            String(check.observation ?? '').trim()
        )
      );
    });
  } catch {
    return false;
  }
}

async function evidenceImageMetadata(path) {
  try {
    const fileStat = await stat(path);
    if (!fileStat.isFile() || fileStat.size < 10 || fileStat.size > MAX_SCREENSHOT_BYTES) {
      return null;
    }
    const bytes = await readFile(path);
    if (bytes.length < 10) {
      return null;
    }

    const contentSha256 = createHash('sha256').update(bytes).digest('hex');

    if (
      bytes.length >= 24 &&
      bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    ) {
      let offset = 8;
      let width = 0;
      let height = 0;
      let bitDepth = 0;
      let colorType = -1;
      let interlace = -1;
      let ended = false;
      const imageData = [];
      while (offset + 12 <= bytes.length) {
        const chunkLength = bytes.readUInt32BE(offset);
        const chunkEnd = offset + 12 + chunkLength;
        if (chunkEnd > bytes.length) {
          break;
        }
        const chunkType = bytes.subarray(offset + 4, offset + 8).toString('ascii');
        const chunkData = bytes.subarray(offset + 8, offset + 8 + chunkLength);
        if (chunkType === 'IHDR' && chunkLength === 13) {
          width = chunkData.readUInt32BE(0);
          height = chunkData.readUInt32BE(4);
          bitDepth = chunkData[8];
          colorType = chunkData[9];
          interlace = chunkData[12];
        } else if (chunkType === 'IDAT') {
          imageData.push(chunkData);
        } else if (chunkType === 'IEND') {
          ended = true;
          break;
        }
        offset = chunkEnd;
      }
      const channels = new Map([[0, 1], [2, 3], [3, 1], [4, 2], [6, 4]]).get(colorType) ?? 0;
      if (!safeImageDimensions(width, height) || channels === 0 || ![1, 2, 4, 8, 16].includes(bitDepth)) {
        return null;
      }
      try {
        const declaredMaximum = Math.min(
          MAX_PNG_INFLATED_BYTES,
          Math.max(height, width * height * 8 + height * 8 + 1024)
        );
        const inflated = inflateSync(Buffer.concat(imageData), { maxOutputLength: declaredMaximum });
        const minimumBytes = interlace === 0 && channels > 0
          ? height * (1 + Math.ceil((width * channels * bitDepth) / 8))
          : height;
        if (ended && imageData.length > 0 && inflated.length >= minimumBytes) {
          return { contentSha256, format: 'png', height, size: bytes.length, width };
        }
      } catch {
        return null;
      }
      return null;
    }

    if (
      bytes.length >= 10 &&
      ['GIF87a', 'GIF89a'].includes(bytes.subarray(0, 6).toString('ascii')) &&
      bytes.at(-1) === 0x3b
    ) {
      const width = bytes.readUInt16LE(6);
      const height = bytes.readUInt16LE(8);
      if (!safeImageDimensions(width, height)) {
        return null;
      }
      return {
        contentSha256,
        format: 'gif',
        height,
        size: bytes.length,
        width
      };
    }

    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes.at(-2) === 0xff && bytes.at(-1) === 0xd9) {
      const startOfFrameMarkers = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
      let offset = 2;
      while (offset + 8 < bytes.length) {
        if (bytes[offset] !== 0xff) {
          offset += 1;
          continue;
        }
        const marker = bytes[offset + 1];
        if (startOfFrameMarkers.has(marker)) {
          const height = bytes.readUInt16BE(offset + 5);
          const width = bytes.readUInt16BE(offset + 7);
          if (!safeImageDimensions(width, height)) {
            return null;
          }
          return {
            contentSha256,
            format: 'jpeg',
            height,
            size: bytes.length,
            width
          };
        }
        if (marker === 0xd8 || marker === 0xd9) {
          offset += 2;
          continue;
        }
        const segmentLength = bytes.readUInt16BE(offset + 2);
        if (segmentLength < 2) {
          break;
        }
        offset += segmentLength + 2;
      }
    }

    if (
      bytes.length >= 30 &&
      bytes.subarray(0, 4).toString('ascii') === 'RIFF' &&
      bytes.subarray(8, 12).toString('ascii') === 'WEBP' &&
      bytes.readUInt32LE(4) + 8 <= bytes.length
    ) {
      const format = bytes.subarray(12, 16).toString('ascii');
      if (format === 'VP8X') {
        const height = bytes.readUIntLE(27, 3) + 1;
        const width = bytes.readUIntLE(24, 3) + 1;
        if (!safeImageDimensions(width, height)) {
          return null;
        }
        return {
          contentSha256,
          format: 'webp',
          height,
          size: bytes.length,
          width
        };
      }
      if (format === 'VP8L' && bytes[20] === 0x2f) {
        const dimensions = bytes.readUInt32LE(21);
        const height = ((dimensions >>> 14) & 0x3fff) + 1;
        const width = (dimensions & 0x3fff) + 1;
        if (!safeImageDimensions(width, height)) {
          return null;
        }
        return {
          contentSha256,
          format: 'webp',
          height,
          size: bytes.length,
          width
        };
      }
      if (
        format === 'VP8 ' &&
        bytes[23] === 0x9d &&
        bytes[24] === 0x01 &&
        bytes[25] === 0x2a
      ) {
        const height = bytes.readUInt16LE(28) & 0x3fff;
        const width = bytes.readUInt16LE(26) & 0x3fff;
        if (!safeImageDimensions(width, height)) {
          return null;
        }
        return {
          contentSha256,
          format: 'webp',
          height,
          size: bytes.length,
          width
        };
      }
    }

    return null;
  } catch {
    return null;
  }
}

function validateGateVocabulary(gates, errors) {
  if (gates?.schemaVersion !== 'public-kit.gates.1') {
    errors.push('gates.json must use schemaVersion public-kit.gates.1.');
  }

  for (const checker of new Set(arrayOrEmpty(gates?.gates).map((gate) => gate?.checkedBy).filter(Boolean))) {
    if (GATE_CHECKED_BY.has(checker) && !String(gates?.checkedBySemantics?.[checker] ?? '').trim()) {
      errors.push(`gates.json checkedBySemantics must define what checkedBy ${checker} means.`);
    }
  }

  const ids = new Set();
  const knownEvidenceFiles = new Set([
    ...arrayOrEmpty(gates?.reviewPacketFiles),
    ...arrayOrEmpty(gates?.generatedEvidenceFiles)
  ]);
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

    if (!knownEvidenceFiles.has(gate.evidenceFile)) {
      errors.push(
        `gate ${gate.id} evidenceFile ${gate.evidenceFile} is not listed in reviewPacketFiles or generatedEvidenceFiles.`
      );
    }

    if (!GATE_CHECKED_BY.has(gate.checkedBy)) {
      errors.push(`gate ${gate.id} checkedBy ${gate.checkedBy} is not an allowed gate checker.`);
    }
    if (!GATE_BLOCKING.has(gate.blocking)) {
      errors.push(`gate ${gate.id} blocking ${gate.blocking} must be handoff or launch.`);
    }
    if (gate.checkedBy !== 'human' && !Object.hasOwn(MACHINE_GATE_EVALUATORS, gate.id)) {
      errors.push(`gate ${gate.id} is non-human but has no machine evaluator.`);
    }
  }

  for (const gateId of Object.keys(MACHINE_GATE_EVALUATORS)) {
    if (!ids.has(gateId)) {
      errors.push(`machine evaluator ${gateId} does not correspond to a gate in gates.json.`);
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

function recordMatchesRoute(record, sourcePath, targetPath) {
  const recordSource = normalizeRouteRequestKey(record?.sourceRoute || record?.sourcePath);
  const recordTarget = normalizeRouteRequestKey(record?.targetRoute || record?.targetPath || record?.publicRoute);
  return (!sourcePath || recordSource === sourcePath) && (!targetPath || recordTarget === targetPath);
}

function targetRouteForSource(routeMatrix, sourcePath) {
  const source = normalizeRouteKey(sourcePath);
  const primary = arrayOrEmpty(routeMatrix?.primaryRoutes).find(
    (route) => normalizeRouteKey(route?.sourcePath) === source
  );
  return normalizeRouteKey(primary?.targetPath);
}

function recordMatchesCollection(record, ledger, routeMatrix, ledgerRows) {
  const source = normalizeRouteKey(ledger?.sourceRoute);
  const target = targetRouteForSource(routeMatrix, source);
  const recordSource = normalizeRouteKey(record?.sourceRoute || record?.sourcePath);
  const recordTarget = normalizeRouteKey(
    record?.targetRoute || record?.targetPath || record?.publicRoute || record?.publicRouteExpectedToChange
  );
  if (recordSource && recordSource !== source) {
    return false;
  }
  if (recordTarget && target && recordTarget !== target) {
    return false;
  }
  if (!recordSource && !recordTarget) {
    return false;
  }

  const ledgerIdentities = [ledger?.sourceObject, ledger?.contentTypeOrBundle, ledger?.collectionPattern].filter(Boolean);
  const recordIdentities = [
    record?.sourceObject,
    record?.objectType,
    record?.itemType,
    record?.contentTypeOrBundle,
    record?.bundle,
    record?.collectionPattern
  ].filter(Boolean);
  if (String(record?.sourceObject ?? '').trim()) {
    return exactIdentityMatch(record.sourceObject, ledger.sourceObject);
  }
  if (recordIdentities.length > 0) {
    const exactMatch = recordIdentities.some((candidate) =>
      ledgerIdentities.some((expected) => exactIdentityMatch(candidate, expected))
    );
    if (exactMatch) {
      return true;
    }
  }
  return ledgerRows.filter((candidate) => normalizeRouteKey(candidate?.sourceRoute) === source).length === 1;
}

function editorWorkflowMatchesBundle(check, bundle) {
  if (privilegedEditorIdentity(check?.editorUser) || privilegedEditorIdentity(check?.editorRole)) {
    return false;
  }
  const entityType = String(bundle?.entityType ?? '').trim();
  const bundleName = String(bundle?.bundle ?? '').trim();
  return exactIdentityMatch(check?.bundle, bundleName) && exactIdentityMatch(check?.entityType, entityType);
}

function recurringModelEntityType(owner) {
  const normalized = String(owner ?? '').trim().toLowerCase();
  return {
    content_type: 'node',
    taxonomy: 'taxonomy_term',
    media: 'media'
  }[normalized] ?? normalized;
}

function recurringModelRequirements(patternMap) {
  const requirements = [];
  for (const record of substantiveObjects(patternMap?.structuredContentModel?.recurringSourceObjects)) {
    if (record?.accepted !== true || !String(record?.bundleOrConfigName ?? '').trim()) {
      continue;
    }
    requirements.push({
      bundle: String(record.bundleOrConfigName).trim(),
      entityType: recurringModelEntityType(record.drupalOwner),
      label: String(record.sourceObject || record.bundleOrConfigName).trim()
    });
  }
  for (const record of substantiveObjects(patternMap?.structuredContentModel?.collectionOwnershipLedger)) {
    if (record?.accepted !== true || !String(record?.contentTypeOrBundle ?? '').trim()) {
      continue;
    }
    requirements.push({
      bundle: String(record.contentTypeOrBundle).trim(),
      entityType: String(record.drupalEntityType || '').trim(),
      label: String(record.sourceObject || record.contentTypeOrBundle).trim()
    });
  }
  return requirements.filter((record, index) => requirements.findIndex((candidate) =>
    exactIdentityMatch(candidate.entityType, record.entityType) && exactIdentityMatch(candidate.bundle, record.bundle)
  ) === index);
}

function temporalFieldCandidate(field) {
  const type = String(field?.fieldType ?? '').trim().toLowerCase();
  const targetType = String(field?.targetEntityType ?? '').trim().toLowerCase();
  const identity = `${field?.machineName ?? ''} ${field?.editorLabel ?? ''}`.toLowerCase();
  return (
    /(?:^|_)(?:date|datetime|daterange|timestamp)(?:_|$)/.test(type) ||
    /\b(?:date|day|year|season|period|cycle|edition|taxonomy|term)\b/.test(identity.replaceAll('_', ' ')) ||
    targetType === 'taxonomy_term'
  );
}

async function nextCycleStructuredGateReasons({
  browserEvidence,
  fieldOutputMatrix,
  nextCycleVerification,
  packetDir,
  patternMap
}) {
  const reasons = [];
  const record = nextCycleVerification;
  const applicability = record?.applicability ?? {};
  const discovery = record?.discovery ?? {};
  const models = substantiveObjects(discovery?.recurringPublicModels);
  const evidenceDir = join(packetDir, 'evidence', 'next-cycle');
  const evidencePresent = (reference) => nonEmptyPacketEvidence(packetDir, reference, evidenceDir);

  if (record?.schemaVersion !== 'public-kit.next-cycle-verification.1') {
    reasons.push('next-cycle-verification.json must use schemaVersion public-kit.next-cycle-verification.1.');
  }
  if (!httpUrl(record?.site) || isoTimestamp(record?.checkedAt) === null) {
    reasons.push('next-cycle-verification.json must name the target site and use a UTC ISO checkedAt timestamp.');
  }
  if (
    applicability.reviewed !== true ||
    typeof applicability.applies !== 'boolean' ||
    !String(applicability.reason ?? '').trim()
  ) {
    reasons.push('next-cycle-verification.json must contain a reviewed applies true/false disposition with a reason.');
  }
  if (
    !hasMeaningfulEntry(discovery?.commands) ||
    discovery.fieldDefinitionsInspected !== true ||
    discovery.taxonomyVocabulariesInspected !== true ||
    discovery.workflowsInspected !== true ||
    !(await evidencePresent(discovery.evidence))
  ) {
    reasons.push('next-cycle-verification.json discovery must inspect fields, taxonomy vocabularies, and workflows with commands and packet-local machine evidence.');
  }

  const requirements = recurringModelRequirements(patternMap);
  for (const requirement of requirements) {
    if (!models.some((model) =>
      exactIdentityMatch(model?.entityType, requirement.entityType) &&
      exactIdentityMatch(model?.bundle, requirement.bundle)
    )) {
      reasons.push(`next-cycle-verification.json discovery must review recurring public model ${requirement.entityType}.${requirement.bundle}.`);
    }
  }

  const dimensionRecords = [];
  for (const [modelIndex, model] of models.entries()) {
    const modelDimensions = substantiveObjects(model?.dimensions);
    if (
      model.reviewed !== true ||
      !String(model?.entityType ?? '').trim() ||
      !String(model?.bundle ?? '').trim() ||
      !hasMeaningfulEntry(model?.publicRoutes) ||
      (modelDimensions.length === 0 && !String(model?.noTemporalCycleDimensionRationale ?? '').trim())
    ) {
      reasons.push(`next-cycle-verification.json discovery.recurringPublicModels[${modelIndex}] must identify a reviewed public model and either its dimensions or a model-specific N/A rationale.`);
    }
    for (const [dimensionIndex, dimension] of modelDimensions.entries()) {
      if (
        !String(dimension?.id ?? '').trim() ||
        !['date', 'datetime', 'year', 'season', 'period', 'taxonomy'].includes(dimension?.kind) ||
        !String(dimension?.machineName ?? '').trim() ||
        !String(dimension?.configName ?? '').trim() ||
        !String(dimension?.latestCurrentValue ?? '').trim() ||
        !finiteNumberValue(dimension?.latestCurrentComparable)
      ) {
        reasons.push(`next-cycle-verification.json discovery.recurringPublicModels[${modelIndex}].dimensions[${dimensionIndex}] must identify a comparable date, season, year, period, or taxonomy dimension.`);
      }
      dimensionRecords.push({ dimension, model });
    }
  }
  const discoveryEvidence = await packetJsonEvidence(packetDir, discovery?.evidence, evidenceDir);
  const recordSite = httpUrl(record?.site);
  const discoveryTarget = httpUrl(discoveryEvidence?.targetBaseUrl);
  if (
    !discoveryEvidence ||
    !recordSite ||
    !discoveryTarget ||
    discoveryTarget.origin !== recordSite.origin ||
    isoTimestamp(discoveryEvidence?.checkedAt) !== isoTimestamp(record?.checkedAt) ||
    !hasMeaningfulEntry(discoveryEvidence?.commands) ||
    numericValue(discoveryEvidence?.temporalCycleDimensionsFound) !== dimensionRecords.length
  ) {
    reasons.push('next-cycle-verification.json discovery evidence must be structured JSON bound to the target, commands, timestamp, and exact discovered-dimension count.');
  }

  for (const bundle of substantiveObjects(fieldOutputMatrix?.bundles)) {
    const isRecurring = requirements.some((requirement) =>
      exactIdentityMatch(requirement.entityType, bundle?.entityType) && exactIdentityMatch(requirement.bundle, bundle?.bundle)
    );
    if (!isRecurring) {
      continue;
    }
    for (const field of substantiveObjects(bundle?.fields).filter(temporalFieldCandidate)) {
      const model = models.find((candidate) =>
        exactIdentityMatch(candidate?.entityType, bundle?.entityType) && exactIdentityMatch(candidate?.bundle, bundle?.bundle)
      );
      if (!substantiveObjects(model?.dimensions).some((dimension) =>
        exactIdentityMatch(dimension?.machineName, field?.machineName)
      )) {
        reasons.push(`next-cycle-verification.json discovery must identify temporal/cycle field ${bundle.entityType}.${bundle.bundle}.${field.machineName}.`);
      }
    }
  }

  if (dimensionRecords.length > 0 && applicability.applies !== true) {
    reasons.push('next-cycle-verification.json cannot use N/A when discovery found a temporal, cycle, or taxonomy dimension.');
  }
  if (applicability.applies === false) {
    if (dimensionRecords.length > 0) {
      reasons.push('next-cycle-verification.json structured N/A requires zero discovered temporal/cycle dimensions.');
    }
    if (arrayOrEmpty(record?.blockers).length > 0) {
      reasons.push('next-cycle-verification.json structured N/A cannot contain unresolved blockers.');
    }
    return reasons;
  }
  if (applicability.applies !== true) {
    return reasons;
  }
  if (dimensionRecords.length === 0) {
    reasons.push('next-cycle-verification.json applies=true requires at least one discovered temporal/cycle dimension.');
  }

  const editor = record?.leastPrivilegeEditor ?? {};
  const passingBrowserEditor = substantiveObjects(browserEvidence?.editorWorkflowChecks).some((check) =>
    check?.accepted === true &&
    check?.status === 'pass' &&
    exactIdentityMatch(check?.editorUser, editor.editorUser) &&
    exactIdentityMatch(check?.editorRole, editor.editorRole)
  );
  if (
    !String(editor?.editorUser ?? '').trim() ||
    !String(editor?.editorRole ?? '').trim() ||
    privilegedEditorIdentity(editor?.editorUser) ||
    privilegedEditorIdentity(editor?.editorRole) ||
    editor.leastPrivilegeRoleConfirmed !== true ||
    !passingBrowserEditor
  ) {
    reasons.push('next-cycle-verification.json must use the same proven least-privilege non-admin editor identity as browser-evidence.json.');
  }

  const permissionChecks = substantiveObjects(editor?.permissionChecks);
  for (const [index, check] of permissionChecks.entries()) {
    if (
      !['create_cycle_value', 'select_cycle_value', 'create_taxonomy_term', 'use_taxonomy_term', 'publish_content'].includes(check?.capability) ||
      !String(check?.permission ?? '').trim() ||
      check?.granted !== true ||
      check?.status !== 'pass' ||
      !(await evidencePresent(check?.evidence))
    ) {
      reasons.push(`next-cycle-verification.json leastPrivilegeEditor.permissionChecks[${index}] must contain an evidence-backed granted permission.`);
    }
  }
  const permissionCapabilities = new Set(permissionChecks
    .filter((check) => check?.granted === true && check?.status === 'pass')
    .map((check) => check.capability));
  if (!permissionCapabilities.has('publish_content')) {
    reasons.push('next-cycle-verification.json must verify the non-admin publish permission.');
  }

  const periodProbe = record?.futurePeriodOrTermProbe ?? {};
  const matchedDimension = dimensionRecords.find(({ dimension }) =>
    exactIdentityMatch(dimension?.id, periodProbe?.dimensionId)
  );
  if (
    !matchedDimension ||
    !['created', 'selected_existing'].includes(periodProbe?.operation) ||
    !String(periodProbe?.value ?? '').trim() ||
    !finiteNumberValue(periodProbe?.comparable) ||
    !finiteNumberValue(matchedDimension?.dimension?.latestCurrentComparable) ||
    Number(periodProbe.comparable) <= Number(matchedDimension.dimension.latestCurrentComparable) ||
    !exactIdentityMatch(periodProbe?.editorUser, editor?.editorUser) ||
    !exactIdentityMatch(periodProbe?.editorRole, editor?.editorRole) ||
    periodProbe?.status !== 'pass' ||
    !(await evidencePresent(periodProbe?.evidence))
  ) {
    reasons.push('next-cycle-verification.json must prove a non-admin created or selected future period/term beyond the latest current comparable value.');
  }
  const taxonomyDimension = matchedDimension?.dimension?.kind === 'taxonomy';
  const requiredPeriodCapability = taxonomyDimension
    ? (periodProbe?.operation === 'created' ? 'create_taxonomy_term' : 'use_taxonomy_term')
    : (periodProbe?.operation === 'created' ? 'create_cycle_value' : 'select_cycle_value');
  if (requiredPeriodCapability && !permissionCapabilities.has(requiredPeriodCapability)) {
    reasons.push(`next-cycle-verification.json must verify ${requiredPeriodCapability} for the future period/term probe.`);
  }

  const contentProbe = record?.futureContentProbe ?? {};
  const createdAt = isoTimestamp(contentProbe?.createdAt);
  const futureDate = dateOrTimestamp(contentProbe?.futureDate);
  const transition = contentProbe?.workflowTransition ?? {};
  const publicUrl = httpUrl(contentProbe?.publicUrl);
  if (
    !String(contentProbe?.probeId ?? '').trim() ||
    !String(contentProbe?.entityType ?? '').trim() ||
    !String(contentProbe?.bundle ?? '').trim() ||
    !exactIdentityMatch(contentProbe?.editorUser, editor?.editorUser) ||
    !exactIdentityMatch(contentProbe?.editorRole, editor?.editorRole) ||
    createdAt === null ||
    futureDate === null ||
    futureDate <= createdAt ||
    contentProbe?.published !== true ||
    !['moderation', 'publication_status'].includes(transition?.type) ||
    !String(transition?.fromState ?? '').trim() ||
    !String(transition?.toState ?? '').trim() ||
    exactIdentityMatch(transition?.fromState, transition?.toState) ||
    transition?.status !== 'pass' ||
    !(await evidencePresent(transition?.evidence)) ||
    !publicUrl ||
    !successfulStatus(contentProbe?.anonymousStatus) ||
    !String(contentProbe?.outputMarker ?? '').trim() ||
    contentProbe?.outputObserved !== true ||
    contentProbe?.status !== 'pass' ||
    !(await evidencePresent(contentProbe?.evidence))
  ) {
    reasons.push('next-cycle-verification.json must prove a future-dated non-admin publish transition and anonymous public output.');
  }
  if (matchedDimension && !(
    exactIdentityMatch(contentProbe?.entityType, matchedDimension.model?.entityType) &&
    exactIdentityMatch(contentProbe?.bundle, matchedDimension.model?.bundle)
  )) {
    reasons.push('next-cycle-verification.json future content probe must use the recurring model that owns the selected dimension.');
  }
  const passingModelBrowserEditor = substantiveObjects(browserEvidence?.editorWorkflowChecks).some((check) =>
    check?.accepted === true &&
    check?.status === 'pass' &&
    exactIdentityMatch(check?.editorUser, editor?.editorUser) &&
    exactIdentityMatch(check?.editorRole, editor?.editorRole) &&
    exactIdentityMatch(check?.entityType, contentProbe?.entityType) &&
    exactIdentityMatch(check?.bundle, contentProbe?.bundle)
  );
  if (!passingModelBrowserEditor) {
    reasons.push('browser-evidence.json must prove the next-cycle editor identity on the same recurring entity type and bundle.');
  }
  const probeEvidence = await packetJsonEvidence(packetDir, contentProbe?.evidence, evidenceDir);
  const evidenceTarget = httpUrl(probeEvidence?.targetBaseUrl);
  const evidencePublicUrl = httpUrl(probeEvidence?.publicUrl);
  if (
    !probeEvidence ||
    !recordSite ||
    !evidenceTarget ||
    evidenceTarget.origin !== recordSite.origin ||
    isoTimestamp(probeEvidence?.checkedAt) !== isoTimestamp(record?.checkedAt) ||
    !exactIdentityMatch(probeEvidence?.editorUser, editor?.editorUser) ||
    !exactIdentityMatch(probeEvidence?.editorRole, editor?.editorRole) ||
    !exactIdentityMatch(probeEvidence?.probeId, contentProbe?.probeId) ||
    String(probeEvidence?.futureValue ?? '').trim() !== String(periodProbe?.value ?? '').trim() ||
    dateOrTimestamp(probeEvidence?.futureDate) !== futureDate ||
    !publicUrl ||
    !evidencePublicUrl ||
    evidencePublicUrl.href !== publicUrl.href ||
    numericValue(probeEvidence?.anonymousStatus) !== numericValue(contentProbe?.anonymousStatus) ||
    String(probeEvidence?.outputMarker ?? '').trim() !== String(contentProbe?.outputMarker ?? '').trim() ||
    probeEvidence?.result !== 'pass'
  ) {
    reasons.push('next-cycle-verification.json future probe evidence must be structured JSON bound to the target, editor, future value/date, probe entity, and anonymous output marker.');
  }

  const cleanup = record?.cleanup ?? {};
  const cleanupCheckedAt = isoTimestamp(cleanup?.checkedAt);
  const expectedPeriodCleanup = periodProbe?.operation === 'created' ? 'deleted' : 'not_created';
  if (
    !exactIdentityMatch(cleanup?.probeId, contentProbe?.probeId) ||
    cleanupCheckedAt === null ||
    (createdAt !== null && cleanupCheckedAt < createdAt) ||
    cleanup?.probeContentDeleted !== true ||
    cleanup?.periodOrTermCleanup !== expectedPeriodCleanup ||
    numericValue(cleanup?.contentResidueCount) !== 0 ||
    numericValue(cleanup?.revisionResidueCount) !== 0 ||
    numericValue(cleanup?.aliasResidueCount) !== 0 ||
    numericValue(cleanup?.periodOrTermResidueCount) !== 0 ||
    ![404, 410].includes(numericValue(cleanup?.publicUrlStatusAfterCleanup)) ||
    cleanup?.status !== 'pass' ||
    !(await evidencePresent(cleanup?.evidence))
  ) {
    reasons.push('next-cycle-verification.json cleanup must prove zero content, revision, alias, and period/term residue and a 404/410 probe URL.');
  }
  const cleanupEvidence = await packetJsonEvidence(packetDir, cleanup?.evidence, evidenceDir);
  const cleanupTarget = httpUrl(cleanupEvidence?.targetBaseUrl);
  if (
    !cleanupEvidence ||
    !recordSite ||
    !cleanupTarget ||
    cleanupTarget.origin !== recordSite.origin ||
    isoTimestamp(cleanupEvidence?.checkedAt) !== isoTimestamp(record?.checkedAt) ||
    !exactIdentityMatch(cleanupEvidence?.probeId, cleanup?.probeId) ||
    numericValue(cleanupEvidence?.contentResidueCount) !== 0 ||
    numericValue(cleanupEvidence?.revisionResidueCount) !== 0 ||
    numericValue(cleanupEvidence?.aliasResidueCount) !== 0 ||
    numericValue(cleanupEvidence?.periodOrTermResidueCount) !== 0 ||
    numericValue(cleanupEvidence?.publicUrlStatusAfterCleanup) !== numericValue(cleanup?.publicUrlStatusAfterCleanup) ||
    cleanupEvidence?.result !== 'pass'
  ) {
    reasons.push('next-cycle-verification.json cleanup evidence must be structured JSON bound to the target, probe identity, zero residue counts, and final public URL status.');
  }
  if (arrayOrEmpty(record?.blockers).length > 0) {
    reasons.push('next-cycle-verification.json cannot pass with unresolved blockers.');
  }
  return reasons;
}

async function independentStructuredGateReasons({
  browserEvidence,
  drupalReadback,
  fieldOutputMatrix,
  independentVerification,
  nextCycleVerification,
  packetDir,
  patternMap,
  routeMatrix,
  sourceAudit
}) {
  const reasons = [];
  reasons.push(...await nextCycleStructuredGateReasons({
    browserEvidence,
    fieldOutputMatrix,
    nextCycleVerification,
    packetDir,
    patternMap
  }));
  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes)
    .map((route) => ({
      source: normalizeRouteRequestKey(route?.sourcePath),
      target: normalizeRouteRequestKey(route?.targetPath)
    }))
    .filter((route) => route.source && route.target);
  const collectionLedger = substantiveObjects(patternMap?.structuredContentModel?.collectionOwnershipLedger);
  const recurringObjects = substantiveObjects(patternMap?.structuredContentModel?.recurringSourceObjects);
  const browserItemCounts = arrayOrEmpty(browserEvidence?.publicRouteChecks)
    .flatMap((check) => substantiveObjects(check?.renderedItemCounts).map((count) => ({
      ...count,
      sourceRoute: normalizeRouteKey(httpUrl(check?.sourceUrl)?.pathname),
      targetRoute: routeRecordPath(check)
    })));
  const collectionScope = patternMap?.structuredContentModel?.collectionScope ?? {};
  const discoveredCollectionEvidence = collectionLedger.length > 0 || recurringObjects.some(
    (record) => String(record.collectionOwner ?? '').trim()
  ) || browserItemCounts.length > 0;
  const collectionEvidenceRequired = collectionScope.applies === true;
  if (
    collectionScope.reviewed !== true ||
    typeof collectionScope.applies !== 'boolean' ||
    !String(collectionScope.reason ?? '').trim() ||
    (discoveredCollectionEvidence && collectionScope.applies !== true)
  ) {
    reasons.push('pattern-map.json must explicitly review whether collection ownership applies and keep that disposition consistent with discovered collection evidence.');
  }
  const driftRecords = substantiveObjects(routeMatrix?.sourceRouteDriftClassification);
  const targetRequiredRoutes = substantiveObjects(routeMatrix?.targetRequiredRoutes);
  const canvasBuild = /canvas|experience_builder/.test(String(patternMap?.buildTypeDeclaration?.type ?? '')) &&
    !/canvas_unused/.test(String(patternMap?.buildTypeDeclaration?.type ?? ''));
  const publicCanvasOwner = arrayOrEmpty(patternMap?.pageCompositionOwnership).some((owner) =>
    owner?.accepted === true && /canvas|experience_builder/.test(String(owner?.selectedOwner ?? ''))
  );
  const canvasEvidenceRequired = canvasBuild || publicCanvasOwner;
  if (
    privilegedEditorIdentity(independentVerification?.target?.editorUser) ||
    privilegedEditorIdentity(independentVerification?.target?.editorRole)
  ) {
    reasons.push('independent-verification.json target editor identity must not be an administrator, root, superuser, or uid 1 account.');
  }

  const reconciliationRecords = substantiveObjects(routeMatrix?.perRouteItemReconciliation);
  const perRouteItemCounts = substantiveObjects(independentVerification?.perRouteItemCounts);
  if (
    collectionEvidenceRequired &&
    (perRouteItemCounts.length === 0 || perRouteItemCounts.some((record) =>
      record.status !== 'pass' ||
      !normalizeRouteKey(record.sourceRoute) ||
      !normalizeRouteKey(record.targetRoute) ||
      !finiteNumberValue(record.expectedSourceItemCount) ||
      !finiteNumberValue(record.targetRenderedItemCount) ||
      !finiteNumberValue(record.targetDrupalEntityCount) ||
      !String(record.evidence ?? '').trim()
    ))
  ) {
    reasons.push('independent-verification.json must contain passing, evidence-backed per-route item counts for in-scope collections.');
  }

  const collectionChecks = substantiveObjects(independentVerification?.collectionOwnershipChecks);
  if (
    collectionEvidenceRequired &&
    (collectionChecks.length === 0 || collectionChecks.some((record) =>
      record.status !== 'pass' ||
      !normalizeRouteKey(record.sourceRoute) ||
      !String(record.drupalOwner ?? '').trim() ||
      record.drupalOwner === 'body_markup_or_blob' ||
      !String(record.viewOrCollectionConfig ?? '').trim() ||
      !String(record.editorAddRowEvidence ?? '').trim() ||
      !String(record.evidence ?? '').trim()
    ))
  ) {
    reasons.push('independent-verification.json must contain passing collection ownership and editor-add-row checks for in-scope collections.');
  }

  const addRowChecks = substantiveObjects(independentVerification?.editorAddRowChecks);
  const independentEvidenceDir = join(packetDir, 'evidence', 'independent-verification');
  for (const record of reconciliationRecords) {
    const sourceCount = numericValue(record.sourceCount);
    const renderedCount = numericValue(record.targetRenderedCount);
    const entityCount = numericValue(record.targetDrupalEntityCount);
    const mismatch = sourceCount !== renderedCount || renderedCount !== entityCount;
    if (record.mismatchDisposition === 'none' && mismatch) {
      reasons.push('route-matrix.json mismatchDisposition none requires equal source, target-rendered, and target-Drupal-entity counts.');
    }
    if (record.mismatchDisposition === 'owner_approved_exclusion') {
      const evidencePresent = await nonEmptyPacketEvidence(packetDir, record.dispositionEvidence);
      if (!String(record.acceptedBy ?? '').trim() || !String(record.rationale || record.notes || '').trim() || !evidencePresent) {
        reasons.push('route-matrix.json owner_approved_exclusion requires acceptedBy, rationale or notes, and packet-local dispositionEvidence.');
      }
    }
    if (record.mismatchDisposition === 'private_unreachable') {
      const evidencePresent = await nonEmptyPacketEvidence(packetDir, record.dispositionEvidence);
      if (!String(record.rationale || record.notes || '').trim() || !evidencePresent) {
        reasons.push('route-matrix.json private_unreachable requires a rationale and concrete packet-local dispositionEvidence.');
      }
    }
  }
  for (const count of perRouteItemCounts.filter((record) => record.status === 'pass')) {
    const sourceCount = numericValue(count.expectedSourceItemCount);
    const renderedCount = numericValue(count.targetRenderedItemCount);
    const entityCount = numericValue(count.targetDrupalEntityCount);
    if (sourceCount === renderedCount && renderedCount === entityCount) {
      continue;
    }
    const reconciliation = reconciliationRecords.find((record) =>
      normalizeRouteKey(record.sourcePath) === normalizeRouteKey(count.sourceRoute) &&
      normalizeRouteKey(record.targetPath) === normalizeRouteKey(count.targetRoute) &&
      numericValue(record.sourceCount) === sourceCount &&
      numericValue(record.targetRenderedCount) === renderedCount &&
      numericValue(record.targetDrupalEntityCount) === entityCount &&
      ['owner_approved_exclusion', 'private_unreachable'].includes(record.mismatchDisposition) &&
      record.accepted === true
    );
    if (!reconciliation) {
      reasons.push('independent-verification.json passing per-route item counts with a count shortfall must match and reconcile to an accepted evidence-backed route-matrix disposition.');
    }
  }
  if (collectionEvidenceRequired && collectionLedger.filter((record) => record?.accepted === true).length === 0) {
    reasons.push('pattern-map.json collection ownership applies but has no accepted collectionOwnershipLedger rows.');
  }
  const acceptedCollectionKeys = new Set();
  for (const ledger of collectionLedger.filter((record) => record?.accepted === true)) {
    const sourcePath = normalizeRouteKey(ledger.sourceRoute);
    const targetPath = targetRouteForSource(routeMatrix, sourcePath);
    const collectionKey = `${sourcePath}:${identityKey(ledger.sourceObject)}`;
    if (acceptedCollectionKeys.has(collectionKey)) {
      reasons.push(`pattern-map.json collectionOwnershipLedger has a duplicate accepted route/object key for ${ledger.sourceObject || sourcePath}.`);
    }
    acceptedCollectionKeys.add(collectionKey);
    const reconciliation = reconciliationRecords.find((record) =>
      recordMatchesCollection(record, ledger, routeMatrix, collectionLedger)
    );
    const countCheck = perRouteItemCounts.find((record) =>
      recordMatchesCollection(record, ledger, routeMatrix, collectionLedger)
    );
    const ownershipCheck = collectionChecks.find((record) =>
      recordMatchesCollection(record, ledger, routeMatrix, collectionLedger)
    );
    const addRowCheck = addRowChecks.find((record) =>
      recordMatchesCollection(record, ledger, routeMatrix, collectionLedger)
    );
    const browserCount = browserItemCounts.find((record) =>
      recordMatchesCollection(record, ledger, routeMatrix, collectionLedger)
    );
    const ledgerSourceCount = numericValue(ledger.sourceItemCount);
    const sourceCount = numericValue(reconciliation?.sourceCount);
    const renderedCount = numericValue(reconciliation?.targetRenderedCount);
    const entityCount = numericValue(reconciliation?.targetDrupalEntityCount);
    const disposition = reconciliation?.mismatchDisposition;
    const countMismatch = sourceCount !== renderedCount || renderedCount !== entityCount;
    const dispositionEvidencePresent = reconciliation && await nonEmptyPacketEvidence(
      packetDir,
      reconciliation.dispositionEvidence
    );
    const ledgerEditorEvidencePresent = await nonEmptyPacketEvidence(packetDir, ledger.editorAddRowEvidence);
    const countEvidencePresent = countCheck && await nonEmptyPacketEvidence(packetDir, countCheck.evidence, independentEvidenceDir);
    const ownershipEvidencePresent = ownershipCheck && await nonEmptyPacketEvidence(packetDir, ownershipCheck.evidence, independentEvidenceDir);
    const ownershipAddEvidencePresent = ownershipCheck && await nonEmptyPacketEvidence(
      packetDir,
      ownershipCheck.editorAddRowEvidence,
      independentEvidenceDir
    );
    const addRowEvidencePresent = addRowCheck && await nonEmptyPacketEvidence(packetDir, addRowCheck.evidence, independentEvidenceDir);

    if (
      !sourcePath ||
      !targetPath ||
      !reconciliation ||
      ledgerSourceCount === null ||
      sourceCount !== ledgerSourceCount ||
      renderedCount === null ||
      entityCount === null ||
      reconciliation.accepted !== true ||
      !['none', 'owner_approved_exclusion', 'private_unreachable'].includes(disposition) ||
      (disposition === 'none' && countMismatch) ||
      (disposition !== 'none' && !countMismatch) ||
      (disposition === 'owner_approved_exclusion' && (
        !String(reconciliation.acceptedBy ?? '').trim() ||
        !String(reconciliation.rationale || reconciliation.notes || '').trim() ||
        !dispositionEvidencePresent
      )) ||
      (disposition === 'private_unreachable' && (
        !String(reconciliation.rationale || reconciliation.notes || '').trim() ||
        !dispositionEvidencePresent
      ))
    ) {
      reasons.push(`route-matrix.json must account for every count delta in accepted collection ${ledger.sourceObject || sourcePath} with matching counts and packet-local disposition evidence.`);
    }
    if (
      !countCheck ||
      countCheck.status !== 'pass' ||
      numericValue(countCheck.expectedSourceItemCount) !== sourceCount ||
      numericValue(countCheck.targetRenderedItemCount) !== renderedCount ||
      numericValue(countCheck.targetDrupalEntityCount) !== entityCount ||
      (disposition === 'none' && (
        arrayOrEmpty(countCheck.missingItems).length > 0 ||
        arrayOrEmpty(countCheck.extraItems).length > 0
      )) ||
      !countEvidencePresent
    ) {
      reasons.push(`independent-verification.json needs an independently evidenced perRouteItemCounts row for collection ${ledger.sourceObject || sourcePath}.`);
    }
    if (
      !ownershipCheck ||
      ownershipCheck.status !== 'pass' ||
      !String(ownershipCheck.drupalOwner ?? '').trim() ||
      ownershipCheck.drupalOwner === 'body_markup_or_blob' ||
      !exactIdentityMatch(ownershipCheck.viewOrCollectionConfig, ledger.viewDisplayOrConfig) ||
      !ownershipEvidencePresent ||
      !ownershipAddEvidencePresent
    ) {
      reasons.push(`independent-verification.json needs an evidence-backed collectionOwnershipChecks row mapped to collection ${ledger.sourceObject || sourcePath}.`);
    }
    if (
      !addRowCheck ||
      addRowCheck.status !== 'pass' ||
      privilegedEditorIdentity(addRowCheck.editorUser) ||
      privilegedEditorIdentity(addRowCheck.editorRole) ||
      !String(addRowCheck.editorUser ?? '').trim() ||
      addRowCheck.publicOutputChanged !== true ||
      addRowCheck.listingOrDetailUpdatedWithoutCode !== true ||
      !addRowEvidencePresent ||
      !ledgerEditorEvidencePresent
    ) {
      reasons.push(`independent-verification.json needs a non-admin, packet-evidenced editorAddRowChecks row mapped to collection ${ledger.sourceObject || sourcePath}.`);
    }
    if (browserCount && (
      numericValue(browserCount.sourceCount) !== sourceCount ||
      numericValue(browserCount.targetCount) !== renderedCount ||
      browserCount.accepted !== true
    )) {
      reasons.push(`browser-evidence.json rendered item counts disagree with the accepted reconciliation for collection ${ledger.sourceObject || sourcePath}.`);
    }
  }

  const sourceHasEmbeds = hasMeaningfulEntry(sourceAudit?.mediaSignals) || hasMeaningfulEntry(sourceAudit?.formsAndIntegrations);
  const embedChecks = substantiveObjects(independentVerification?.renderedEmbedChecks);
  if (
    sourceHasEmbeds &&
    (embedChecks.length === 0 || embedChecks.some((record) =>
      record.status !== 'pass' || !normalizeRouteKey(record.route) || !String(record.evidence ?? '').trim()
    ))
  ) {
    reasons.push('independent-verification.json must contain passing rendered embed/media checks when the source audit identifies embeds or integrations.');
  }

  const independentDetailChecks = substantiveObjects(independentVerification?.detailRouteChecks);
  for (const ledger of collectionLedger.filter((record) =>
    record?.accepted === true && record?.detailRouteMode === 'separate_public_route'
  )) {
    const expectedFields = detailExpectedFields(ledger, fieldOutputMatrix, recurringObjects);
    const browserDetail = arrayOrEmpty(browserEvidence?.publicRouteChecks).find((candidate) =>
      candidate?.routeRole === 'detail' &&
      normalizeRouteKey(candidate?.sourceUrl) === normalizeRouteKey(ledger?.representativeDetailSourcePath) &&
      routeRecordPath(candidate) === normalizeRouteKey(ledger?.representativeDetailTargetPath)
    );
    const browserSignals = browserDetail?.detailContentSignals ?? {};
    const deviation = browserSignals?.ownerDeviation ?? {};
    const check = independentDetailChecks.find((candidate) =>
      normalizeRouteKey(candidate?.sourceRoute) === normalizeRouteKey(ledger?.representativeDetailSourcePath) &&
      normalizeRouteKey(candidate?.targetRoute) === normalizeRouteKey(ledger?.representativeDetailTargetPath)
    );
    const evidencePresent = check && await nonEmptyPacketEvidence(
      packetDir,
      check?.evidence,
      independentEvidenceDir
    );
    const deviationEvidencePresent = deviation?.applies === true && await nonEmptyPacketEvidence(
      packetDir,
      check?.ownerDeviationEvidence
    );
    const verifiedFields = new Set(arrayOrEmpty(check?.loadBearingFieldsVerified).map((field) =>
      identityKey(isJsonObject(field) ? field.field : field)
    ));
    if (
      !check ||
      check?.status !== 'pass' ||
      !exactIdentityMatch(check?.contentTypeOrBundle, ledger?.contentTypeOrBundle) ||
      !exactIdentityMatch(check?.declaredDetailOwner, ledger?.detailRouteOwner) ||
      !exactIdentityMatch(check?.observedDetailOwner, browserSignals?.drupalOwner) ||
      !exactIdentityMatch(check?.drupalOwnerConfigId, browserSignals?.drupalOwnerConfigId) ||
      (deviation?.applies === true && (
        check?.ownerDeviationEvidence !== deviation?.evidence || !deviationEvidencePresent
      )) ||
      (deviation?.applies !== true && (
        !exactIdentityMatch(browserSignals?.drupalOwner, ledger?.detailRouteOwner) ||
        !exactIdentityMatch(browserSignals?.drupalOwnerConfigId, ledger?.drupalOwnerConfigId)
      )) ||
      expectedFields.length === 0 ||
      expectedFields.some((field) => !verifiedFields.has(identityKey(field))) ||
      !evidencePresent
    ) {
      reasons.push(`independent-verification.json needs an owner/config-bound passing detailRouteChecks row covering every required public field for ${ledger.sourceObject || ledger.sourceRoute || '(unnamed)'}.`);
    }
  }

  const modeledForms = substantiveObjects(patternMap?.forms);
  const independentFormChecks = substantiveObjects(independentVerification?.anonymousFormChecks);
  if (
    (modeledForms.length > 0 || independentFormChecks.length > 0) &&
    (!uniqueRecordKeys(modeledForms, 'formKey') || !uniqueRecordKeys(independentFormChecks, 'formKey'))
  ) {
    reasons.push('pattern-map.json forms and independent-verification.json anonymousFormChecks must use unique, non-empty formKey values.');
  }
  for (const form of modeledForms) {
    const browserCheck = substantiveObjects(browserEvidence?.anonymousFormChecks).find((candidate) =>
      String(candidate?.formKey ?? '').trim() === String(form?.formKey ?? '').trim()
    );
    const check = independentFormChecks.find((candidate) =>
      String(candidate?.formKey ?? '').trim() === String(form?.formKey ?? '').trim()
    );
    const evidencePresent = check && await nonEmptyPacketEvidence(
      packetDir,
      check?.evidence,
      independentEvidenceDir
    );
    if (
      !check ||
      !browserCheck ||
      check?.status !== 'pass' ||
      normalizeRouteKey(check?.sourceRoute) !== normalizeRouteKey(form?.sourceRoute) ||
      normalizeRouteKey(check?.targetRoute) !== normalizeRouteKey(form?.targetRoute) ||
      !exactIdentityMatch(check?.purpose, form?.purpose) ||
      !exactIdentityMatch(check?.modeledOwner, form?.drupalOwner) ||
      !exactIdentityMatch(check?.browserOwner, browserCheck?.drupalOwner) ||
      check?.expectedOutcome !== form?.expectedOutcome ||
      check?.browserOutcome !== browserCheck?.outcome?.mode ||
      check?.anonymousInvalidAndValidSubmissionVerified !== true ||
      check?.outcomeEvidence !== browserCheck?.outcome?.evidence ||
      check?.abuseProtectionDisposition !== browserCheck?.abuseProtection?.mode ||
      check?.abuseProtectionEvidence !== browserCheck?.abuseProtection?.evidence ||
      !evidencePresent
    ) {
      reasons.push(`independent-verification.json needs a passing formKey-bound anonymousFormChecks row matching model, browser outcome, and abuse evidence for ${form?.formKey || '(missing formKey)'}.`);
    }
  }

  const rawScan = independentVerification?.rawEmbedAndMarkupScan ?? {};
  if (
    rawScan.status !== 'pass' ||
    !hasMeaningfulEntry(rawScan.fieldsScanned) ||
    !hasMeaningfulEntry(rawScan.patternsChecked) ||
    rawScan.offRoadInventoryUpdated !== true
  ) {
    reasons.push('independent-verification.json raw embed and markup scan must pass, name scanned fields/patterns, and confirm the off-road inventory was updated.');
  }

  const targetRequiredChecks = substantiveObjects(independentVerification?.targetRequiredRouteChecks);
  for (const route of targetRequiredRoutes) {
    const behavior = String(route.expectedPublicBehavior ?? '').trim();
    const routePath = normalizeRouteKey(route.targetPath);
    const routeFinalPath = normalizeRouteKey(route.targetFinalPath || route.targetPath);
    const check = targetRequiredChecks.find((candidate) =>
      normalizeRouteKey(candidate.targetPath) === routePath
    );
    const checkFinalUrl = httpUrl(check?.targetFinalUrl);
    const independentTargetUrl = httpUrl(independentVerification?.target?.baseUrl);
    const checkEvidencePresent = check && await nonEmptyPacketEvidence(
      packetDir,
      check.evidence,
      join(packetDir, 'evidence', 'independent-verification')
    );
    if (
      !check ||
      behavior === 'blocked' ||
      check.expectedPublicBehavior === 'blocked' ||
      check.status !== 'pass' ||
      check.expectedPublicBehavior !== behavior ||
      numericValue(check.targetStatus) !== numericValue(route.targetStatus) ||
      !independentTargetUrl ||
      checkFinalUrl?.origin !== independentTargetUrl.origin ||
      normalizeRouteKey(checkFinalUrl?.pathname) !== routeFinalPath ||
      !expectedPublicBehaviorMatches(behavior, route.targetStatus, routeFinalPath, routePath) ||
      !checkEvidencePresent
    ) {
      reasons.push(`independent-verification.json must pass target-required route ${routePath || '(missing)'} with status/final-path behavior matching route-matrix.json and packet-local evidence.`);
    }
  }

  const driftChecks = substantiveObjects(independentVerification?.routeDriftDispositionChecks);
  if (
    driftRecords.length > 0 &&
    driftRecords.some((route) => !driftChecks.some((check) =>
      normalizeRouteRequestKey(check.sourcePath) === normalizeRouteRequestKey(route.sourcePath) &&
      check.status === 'pass' &&
      String(check.dispositionEvidence ?? '').trim()
    ))
  ) {
    reasons.push('independent-verification.json must pass every source-route drift disposition check with evidence.');
  }

  const placeholderScan = independentVerification?.placeholderTextScan ?? {};
  const scannedPlaceholderRoutes = new Set(arrayOrEmpty(placeholderScan.scannedRoutes).map(normalizeRouteRequestKey));
  if (
    placeholderScan.status !== 'pass' ||
    arrayOrEmpty(placeholderScan.findings).length > 0 ||
    primaryRoutes.some((route) => !scannedPlaceholderRoutes.has(route.target))
  ) {
    reasons.push('independent-verification.json placeholder scan must pass every primary target route with no unresolved findings.');
  }

  const starterChecks = independentVerification?.starterRouteAndLeakChecks ?? {};
  if (
    starterChecks.status !== 'pass' ||
    arrayOrEmpty(starterChecks.unexpectedPublic200s).length > 0 ||
    arrayOrEmpty(starterChecks.duplicateAliases).length > 0 ||
    arrayOrEmpty(starterChecks.disconnectedCanvasStarterPages).length > 0
  ) {
    reasons.push('independent-verification.json starter-route and leak checks must pass with no unexpected routes, duplicate aliases, or disconnected Canvas pages.');
  }

  const canvasPlaceholderChecks = independentVerification?.canvasPlaceholderChecks ?? {};
  if (
    canvasPlaceholderChecks.status !== 'pass' ||
    arrayOrEmpty(canvasPlaceholderChecks.publicCanvasPlaceholderFindings).length > 0 ||
    arrayOrEmpty(canvasPlaceholderChecks.disconnectedCanvasEditorRoutes).length > 0 ||
    (!canvasEvidenceRequired && canvasPlaceholderChecks.canvasIntentionallyUnusedAndDocumented !== true)
  ) {
    reasons.push('independent-verification.json Canvas placeholder checks must pass and explicitly document intentional non-use when Canvas is not part of the build.');
  }

  const firstFoldChecks = substantiveObjects(independentVerification?.firstFoldBrandAssetChecks);
  for (const route of primaryRoutes) {
    for (const viewport of ['desktop', 'mobile']) {
      const check = firstFoldChecks.find((candidate) =>
        recordMatchesRoute(candidate, route.source, route.target) && candidate.viewport === viewport
      );
      if (
        !check ||
        ['heroArtworkStatus', 'logoOrLockupStatus', 'signatureGraphicStatus', 'primaryCtaTreatmentStatus']
          .some((field) => !['pass', 'not_applicable'].includes(check[field])) ||
        arrayOrEmpty(check.reachableSourceAssetsMissingOrApproximated).length > 0 ||
        !String(check.evidence ?? '').trim()
      ) {
        reasons.push(`independent-verification.json needs a passing first-fold brand check for ${route.target} at ${viewport}.`);
      }
    }
  }

  const compositionChecks = substantiveObjects(independentVerification?.compositionModelFidelityChecks);
  for (const route of primaryRoutes) {
    const check = compositionChecks.find((candidate) => recordMatchesRoute(candidate, route.source, route.target));
    const ownerMatches = compositionOwnersMatch(check?.declaredCompositionOwner, check?.actualCompositionOwner);
    const independentTargetUrl = httpUrl(independentVerification?.target?.baseUrl);
    const deviationTargetUrl = httpUrl(check?.deviationTargetUrl);
    const deviationEvidencePresent = check && await nonEmptyPacketEvidence(
      packetDir,
      check.deviationEvidence,
      join(packetDir, 'evidence', 'independent-verification')
    );
    const evidencedDeviation =
      !ownerMatches &&
      check?.deviationRecordRequired === true &&
      check?.deviationRecordPresent === true &&
      independentTargetUrl &&
      deviationTargetUrl?.origin === independentTargetUrl.origin &&
      normalizeRouteRequestKey(deviationTargetUrl.href) === route.target &&
      String(check?.deviationRationale ?? '').trim() &&
      deviationEvidencePresent;
    if (
      !check ||
      check.status !== 'pass' ||
      !String(check.declaredCompositionOwner ?? '').trim() ||
      !String(check.actualCompositionOwner ?? '').trim() ||
      (!ownerMatches && !evidencedDeviation) ||
      check.routeRationalePresent !== true ||
      check.sectionOwnershipDeclared !== true ||
      check.expectedEditorActionsVerified !== true ||
      !String(check.nonAdminEditorPublicOutputProof ?? '').trim() ||
      !String(check.evidence ?? '').trim()
    ) {
      reasons.push(`independent-verification.json needs a passing composition-fidelity check for ${route.target}.`);
    }
  }

  if (canvasEvidenceRequired) {
    const canvasChecks = substantiveObjects(independentVerification?.canvasComponentModelChecks);
    if (
      canvasChecks.length === 0 ||
      canvasChecks.some((check) =>
        check.status !== 'pass' ||
        check.canvasPagePublicOrPartOfRebuild !== true ||
        check.componentInventoryMatchesDeclaration !== true ||
        check.singleMonolithComponentDetected !== false ||
        check.declaredSlotsActuallySlots !== true ||
        check.entityReferencePropsActuallyReferences !== true ||
        check.declaredRepeatableSectionsBackedByDrupalData !== true ||
        check.sectionOrderEditableWhenCanvasOwnsComposition !== true ||
        arrayOrEmpty(check.stringBlobProps).length > 0 ||
        arrayOrEmpty(check.jsonPropsDetected).length > 0 ||
        arrayOrEmpty(check.newlineUrlListPropsDetected).length > 0 ||
        arrayOrEmpty(check.multiUrlStringPropsDetected).length > 0 ||
        arrayOrEmpty(check.hardcodedTwigLiteralFindings).length > 0 ||
        !String(check.evidence ?? '').trim()
      )
    ) {
      reasons.push('independent-verification.json Canvas component-model checks must pass when Canvas owns rebuild output.');
    }
  }

  if (collectionEvidenceRequired) {
    const addRowChecks = substantiveObjects(independentVerification?.editorAddRowChecks);
    if (
      addRowChecks.length === 0 ||
      addRowChecks.some((check) =>
        check.status !== 'pass' ||
        check.publicOutputChanged !== true ||
        check.listingOrDetailUpdatedWithoutCode !== true ||
        !String(check.editorUser ?? '').trim() ||
        privilegedEditorIdentity(check.editorUser) ||
        privilegedEditorIdentity(check.editorRole) ||
        !String(check.evidence ?? '').trim()
      )
    ) {
      reasons.push('independent-verification.json must contain passing editor-add-row checks for in-scope collections.');
    }
  }

  const fieldChecks = substantiveObjects(independentVerification?.fieldOutputFalsification);
  const fieldBundles = substantiveObjects(fieldOutputMatrix?.bundles);
  const declaredContentTypes = substantiveObjects(patternMap?.contentTypes);
  const editorWorkflowChecks = substantiveObjects(browserEvidence?.editorWorkflowChecks).filter(
    (check) => check?.accepted === true && check?.status === 'pass'
  );
  const requiredNodeBundles = new Set([
    ...declaredContentTypes.map((record) => String(record?.machineName || record?.bundle || '').trim()),
    ...recurringObjects
      .filter((record) => record?.accepted === true && record?.drupalOwner === 'content_type')
      .map((record) => String(record?.bundleOrConfigName ?? '').trim()),
    ...substantiveObjects(drupalReadback?.content?.nodes)
      .map((record) => String(record?.type || record?.bundle || '').trim())
  ].filter(Boolean));
  if (
    declaredContentTypes.length === 0 ||
    declaredContentTypes.some((record) =>
      !String(record?.machineName || record?.bundle || '').trim() || !String(record?.label ?? '').trim()
    )
  ) {
    reasons.push('pattern-map.json contentTypes must contain structured machine-name and label records for the rebuild-owned node bundles.');
  }
  for (const bundleName of requiredNodeBundles) {
    const declared = declaredContentTypes.some((record) =>
      exactIdentityMatch(record?.machineName || record?.bundle, bundleName)
    );
    const fieldBundle = fieldBundles.find((record) =>
      exactIdentityMatch(record?.entityType, 'node') && exactIdentityMatch(record?.bundle, bundleName)
    );
    const editorWorkflow = editorWorkflowChecks.find((check) =>
      exactIdentityMatch(check?.entityType, 'node') && exactIdentityMatch(check?.bundle, bundleName)
    );
    if (!declared) {
      reasons.push(`pattern-map.json must declare the used node bundle ${bundleName}.`);
    }
    if (!fieldBundle) {
      reasons.push(`field-output-matrix.json must include the used node bundle node.${bundleName}.`);
    }
    if (!editorWorkflow) {
      reasons.push(`browser-evidence.json needs a passing non-admin editor workflow mapped to node.${bundleName}.`);
    }
  }
  if (fieldBundles.length === 0 || fieldChecks.length === 0) {
    reasons.push('independent-verification.json must contain passing field-output falsification evidence.');
  }
  for (const bundle of fieldBundles) {
    if (!editorWorkflowChecks.some((check) =>
      editorWorkflowMatchesBundle(check, bundle)
    )) {
      reasons.push(`browser-evidence.json needs a passing non-admin editor workflow mapped to ${bundle.entityType || '(entity)'}.${bundle.bundle || '(bundle)'}.`);
    }
    for (const field of arrayOrEmpty(bundle.fields).filter(
      (candidate) => candidate?.required === true || candidate?.affectsAnonymousOutput === true
    )) {
      const check = fieldChecks.find((candidate) =>
        exactIdentityMatch(candidate?.entityType, bundle.entityType) &&
        exactIdentityMatch(candidate?.bundle, bundle.bundle) &&
        exactIdentityMatch(candidate?.field, field.machineName)
      );
      const fieldEvidencePresent = check && await nonEmptyPacketEvidence(
        packetDir,
        check.evidence,
        join(packetDir, 'evidence', 'independent-verification')
      );
      if (
        !check ||
        check.status !== 'pass' ||
        !String(check.actualEditorSurface ?? '').trim() ||
        (field.affectsAnonymousOutput === true && !String(check.actualPublicOutput ?? '').trim()) ||
        !fieldEvidencePresent
      ) {
        reasons.push(`independent-verification.json needs a passing field-output falsification check for ${bundle.entityType}.${bundle.bundle}.${field.machineName}.`);
      }
    }
  }

  const labelChecks = substantiveObjects(independentVerification?.coldReaderLabelChecks);
  if (
    labelChecks.length === 0 ||
    labelChecks.some((check) =>
      check.status !== 'pass' ||
      check.wouldMakeSenseIfBrandChanged !== true ||
      check.siteBrandingExposedToEditor !== false ||
      !String(check.evidence ?? '').trim()
    )
  ) {
    reasons.push('independent-verification.json must contain passing cold-reader label checks.');
  }

  const databaseCleanupChecks = substantiveObjects(independentVerification?.directDatabaseCleanupChecks);
  if (databaseCleanupChecks.some((check) =>
    check.status !== 'pass' ||
    check.localCleanRebuildOnly !== true ||
    check.recordedInOffRoadInventory !== true ||
    !String(check.productionSafeAlternative ?? '').trim() ||
    !String(check.evidence ?? '').trim()
  )) {
    reasons.push('independent-verification.json direct-database cleanup checks must be local-only, recorded, passing, and name a production-safe alternative.');
  }

  const freshnessChecks = substantiveObjects(independentVerification?.packetFreshnessChecks);
  const freshnessArtifacts = new Set(freshnessChecks.filter((check) =>
    check.status === 'pass' &&
    check.staleOrMissingEvidence === false &&
    String(check.liveSiteEvidence ?? '').trim()
  ).map((check) => String(check.artifact ?? '').replace(/^review-packet\//, '')));
  for (const artifact of [
    'route-matrix.json',
    'browser-evidence.json',
    'drupal-readback.json',
    'field-output-matrix.json',
    'negative-route-consent.json',
    'parity-report.json',
    'pattern-map.json'
  ]) {
    if (!freshnessArtifacts.has(artifact)) {
      reasons.push(`independent-verification.json packet freshness checks must pass ${artifact}.`);
    }
  }

  return reasons;
}

async function validateIndependentVerification(
  packetDir,
  independentVerification,
  relatedRecords,
  errors,
  { briefAcceptance = null, briefMode = false } = {}
) {
  if (!isJsonObject(independentVerification)) {
    errors.push('independent-verification.json must be a JSON object (blocked stub at minimum).');
    return false;
  }

  const startingErrorCount = errors.length;
  if (independentVerification.schemaVersion !== 'public-kit.independent-verification.1') {
    errors.push('independent-verification.json must use schemaVersion public-kit.independent-verification.1.');
  }

  const verifier = independentVerification.verifier ?? {};
  const summary = independentVerification.summary ?? {};
  const completionClaims = arrayOrEmpty(independentVerification.completionClaims);
  const strictCompletionReview =
    summary.verdict === 'pass' &&
    Number(summary.failedClaimCount) === 0 &&
    Number(summary.blockedClaimCount) === 0;

  if (!strictCompletionReview) {
    return false;
  }

  if (isoTimestamp(independentVerification.checkedAt) === null) {
    errors.push('independent-verification.json pass verdict requires checkedAt as a UTC ISO timestamp.');
  }

  const degraded =
    verifier.freshContextUsed !== true ||
    verifier.sameContextAsBuilder !== false ||
    verifier.builderSummaryExcluded !== true ||
    verifier.liveSiteInspected !== true ||
    verifier.packetInspected !== true ||
    Boolean(verifier.independenceDegradedReason) ||
    !String(verifier.nameOrRole ?? '').trim() ||
    !String(verifier.runtimeOrTool ?? '').trim();

  if (degraded) {
    errors.push(
      'independent-verification.json cannot support completion unless a named fresh verifier used a recorded runtime, excluded the builder summary, inspected the live site and packet, and declared no degraded independence.'
    );
  }

  if (completionClaims.length === 0) {
    errors.push('independent-verification.json pass verdict requires at least one completionClaims entry.');
  }

  const evidenceDir = join(packetDir, 'evidence', 'independent-verification');
  const independentTargetUrl = httpUrl(independentVerification?.target?.baseUrl);
  for (const [index, claim] of completionClaims.entries()) {
    if (!isJsonObject(claim)) {
      errors.push(`independent-verification.json completionClaims[${index}] must be an object.`);
      continue;
    }
    if (
      !String(claim.claimId ?? '').trim() ||
      !String(claim.claim ?? '').trim() ||
      !String(claim.gate ?? '').trim() ||
      !String(claim.gateId ?? '').trim()
    ) {
      errors.push(`independent-verification.json completionClaims[${index}] requires claimId, claim, gate, and gateId.`);
    }
    if (COMPLETION_GATE_IDS[claim.gate] && claim.gateId !== COMPLETION_GATE_IDS[claim.gate]) {
      errors.push(
        `independent-verification.json completionClaims[${index}] gateId must be ${COMPLETION_GATE_IDS[claim.gate]} for the ${claim.gate} completion gate.`
      );
    }
    if (claim.status !== 'pass') {
      errors.push(`independent-verification.json completionClaims[${index}] must pass before completion can be supported.`);
    }
    if (arrayOrEmpty(claim.falsificationChecks).length === 0) {
      errors.push(`independent-verification.json completionClaims[${index}] requires at least one falsification check.`);
    }
    const verifierEvidence = arrayOrEmpty(claim.verifierEvidence);
    let semanticallyBoundEvidence = false;
    if (verifierEvidence.length === 0) {
      errors.push(`independent-verification.json completionClaims[${index}] requires packet-local verifierEvidence.`);
    }
    for (const [evidenceIndex, evidenceReference] of verifierEvidence.entries()) {
      const evidencePath = resolveReviewEvidencePath(packetDir, evidenceDir, evidenceReference);
      if (!evidencePath) {
        errors.push(
          `independent-verification.json completionClaims[${index}].verifierEvidence[${evidenceIndex}] must reference packet-local evidence.`
        );
        continue;
      }
      const evidenceStat = await stat(evidencePath);
      if (!evidenceStat.isFile() || evidenceStat.size === 0) {
        errors.push(
          `independent-verification.json completionClaims[${index}].verifierEvidence[${evidenceIndex}] must not be empty.`
        );
      }
      if (evidenceStat.isFile() && await evidenceBindsClaim(evidencePath, claim, independentTargetUrl)) {
        semanticallyBoundEvidence = true;
      }
    }
    if (!semanticallyBoundEvidence) {
      errors.push(
        `independent-verification.json completionClaims[${index}] requires JSON verifier evidence bound to its claimId, gate, gateId, target, checkedAt time, and concrete passing checks.`
      );
    }
  }

  const coveredClaimGates = new Set(completionClaims.map((claim) => claim?.gate).filter(Boolean));
  for (const gate of COMPLETION_CLAIM_GATES) {
    if (!coveredClaimGates.has(gate)) {
      errors.push(`independent-verification.json pass verdict requires a passing completion claim for the ${gate} gate.`);
    }
  }

  const failedClaimCount = completionClaims.filter((claim) => claim?.status === 'fail').length;
  const blockedClaimCount = completionClaims.filter((claim) => claim?.status === 'blocked').length;
  if (Number(summary.failedClaimCount) !== failedClaimCount) {
    errors.push('independent-verification.json summary.failedClaimCount must match failed completion claims.');
  }
  if (Number(summary.blockedClaimCount) !== blockedClaimCount) {
    errors.push('independent-verification.json summary.blockedClaimCount must match blocked completion claims.');
  }

  if (!(await hasFiles(evidenceDir))) {
    errors.push('independent-verification.json pass verdict requires raw verifier evidence under review-packet/evidence/independent-verification/.');
  }

  const structuredGateReasons = [];
  if (briefMode) {
    const requirementIds = new Set(
      arrayOrEmpty(briefAcceptance?.requirements)
        .map((requirement) => String(requirement?.id ?? '').trim())
        .filter(Boolean)
    );
    const seenRequirementIds = new Set();
    const checks = arrayOrEmpty(independentVerification.briefRequirementChecks)
      .filter((check) => String(check?.requirementId ?? '').trim());
    for (const [index, check] of checks.entries()) {
      const requirementId = String(check.requirementId).trim();
      if (!requirementIds.has(requirementId)) {
        errors.push(`independent-verification.json briefRequirementChecks[${index}] references unknown requirement ${requirementId}.`);
      }
      if (seenRequirementIds.has(requirementId)) {
        errors.push(`independent-verification.json repeats brief requirement ${requirementId}.`);
      }
      seenRequirementIds.add(requirementId);
      if (check.status !== 'pass' || arrayOrEmpty(check.falsificationChecks).length === 0) {
        errors.push(`independent-verification.json brief requirement ${requirementId} needs passing falsification checks.`);
      }
      const evidenceResults = await Promise.all(
        arrayOrEmpty(check.evidence).map((reference) => nonEmptyPacketEvidence(packetDir, reference))
      );
      if (evidenceResults.length === 0 || !evidenceResults.every(Boolean)) {
        errors.push(`independent-verification.json brief requirement ${requirementId} needs non-empty packet-local evidence.`);
      }
    }
    for (const requirementId of requirementIds) {
      if (!seenRequirementIds.has(requirementId)) {
        errors.push(`independent-verification.json must independently check brief requirement ${requirementId}.`);
      }
    }
  } else {
    structuredGateReasons.push(...await independentStructuredGateReasons({
      ...relatedRecords,
      independentVerification,
      packetDir
    }));
  }

  return errors.length === startingErrorCount && structuredGateReasons.length === 0;
}

function rejectAuthoredCompletionClaims(independentVerification, blindReview, errors) {
  for (const [file, record] of [
    ['independent-verification.json', independentVerification],
    ['blind-adversarial-review.json', blindReview]
  ]) {
    if (authoredCompletionClaim(record)) {
      errors.push(
        `${file} cannot self-authorize a completion claim; completion authority belongs only to the live verifier.`
      );
    }
  }
}

async function validateBlindAdversarialReview(
  packetDir,
  blindReview,
  routeMatrix,
  errors,
  { briefAcceptance = null, briefContext = null, briefMode = false } = {}
) {
  if (!isJsonObject(blindReview)) {
    errors.push('blind-adversarial-review.json must be a JSON object (blocked stub at minimum).');
    return {
      externalBlockers: [],
      externalBlockersOnly: false,
      supportsCompletion: false
    };
  }

  const startingErrorCount = errors.length;
  if (blindReview.schemaVersion !== 'public-kit.blind-adversarial-review.1') {
    errors.push('blind-adversarial-review.json must use schemaVersion public-kit.blind-adversarial-review.1.');
  }

  const reviewer = blindReview.reviewer ?? {};
  const summary = blindReview.summary ?? {};
  const defects = arrayOrEmpty(blindReview.productDefects);
  const routeReviews = arrayOrEmpty(blindReview.routeViewportReviews);
  const reviewPasses = arrayOrEmpty(blindReview.reviewPasses);
  const reviewInputs = blindReview.reviewInputs ?? {};
  const omittedPrimaryRoutes = substantiveObjects(blindReview.routeCoverage?.omittedPrimaryRoutes).filter(
    (route) => normalizeRouteKey(route?.route || route?.targetPath || route?.sourcePath || route?.path)
  );
  const evidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  const strictCompletionReview =
    BLIND_COMPLETE_VERDICTS.has(summary.verdict) &&
    ['parity_reviewed', 'human_accepted', 'complete'].includes(summary.completionState);
  const externalPauseReview =
    summary.verdict === 'blocked' &&
    summary.completionState === 'blocked' &&
    (
      defects.some((defect) => defect?.status === 'external_blocker') ||
      omittedPrimaryRoutes.some((omission) => omission?.disposition === 'external_blocker')
    );
  const externalBlockers = [];

  if (!strictCompletionReview && !externalPauseReview) {
    return {
      externalBlockers,
      externalBlockersOnly: false,
      supportsCompletion: false
    };
  }

  if (isoTimestamp(blindReview.checkedAt) === null) {
    errors.push('blind-adversarial-review.json completion evidence requires checkedAt as a UTC ISO timestamp.');
  }

  const declaredSourceUrl = httpUrl(routeMatrix?.sourceBaseUrl);
  const declaredTargetUrl = httpUrl(routeMatrix?.targetBaseUrl);
  if ((!briefMode && !declaredSourceUrl) || !declaredTargetUrl) {
    errors.push('blind-adversarial-review.json completion evidence requires valid route-matrix sourceBaseUrl and targetBaseUrl values.');
  }

  const degraded =
    !String(reviewer.nameOrRole ?? '').trim() ||
    !String(reviewer.runtimeOrTool ?? '').trim() ||
    reviewer.freshContextUsed !== true ||
    reviewer.sameContextAsBuilder !== false ||
    reviewer.didNotBuildTarget !== true ||
    reviewer.inputsRestrictedToBriefTargetAndSourceTruth !== true ||
    reviewer.implementationFilesReadBeforePublicReview !== false ||
    reviewer.reviewPacketReadBeforePublicReview !== false ||
    reviewer.priorBuildConversationRead !== false ||
    reviewer.builderSummaryExcluded !== true;

  if (degraded) {
    errors.push(
      'blind-adversarial-review.json cannot allow a complete rebuild claim unless the reviewer is fresh, did not build the target, used only brief/target/source-truth inputs before public review, and excluded builder claims.'
    );
  }

  if (strictCompletionReview && !BLIND_COMPLETE_VERDICTS.has(summary.verdict)) {
    errors.push('blind-adversarial-review.json can allow completion only with summary.verdict good or good_enough.');
  }

  const requiredCountFields = [
    'openBlockerIssueCount',
    'openCriticalIssueCount',
    'openHighIssueCount',
    'acceptedOutOfScopeIssueCount',
    'externalBlockerIssueCount'
  ];
  for (const field of requiredCountFields) {
    if (summary[field] === undefined || !Number.isFinite(Number(summary[field]))) {
      errors.push(`blind-adversarial-review.json complete claims require numeric summary.${field}.`);
    }
  }

  const reviewPassIds = new Set();
  for (const [index, pass] of reviewPasses.entries()) {
    if (!isJsonObject(pass)) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] must be an object.`);
      continue;
    }
    if (!String(pass.id ?? '').trim()) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] is missing id.`);
    } else {
      reviewPassIds.add(pass.id);
    }
    if (isoTimestamp(pass.checkedAt) === null) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] needs checkedAt as a UTC ISO timestamp.`);
    }
    if (!String(pass.reviewer ?? '').trim()) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] is missing reviewer.`);
    }
    if (!BLIND_COMPLETE_VERDICTS.has(pass.verdict)) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] must record a good or good_enough verdict for completion.`);
    }
  }

  if (reviewPasses.length === 0) {
    errors.push('blind-adversarial-review.json complete claims require at least one reviewPasses entry.');
  }

  for (const [index, defect] of defects.entries()) {
    if (!isJsonObject(defect)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] must be an object.`);
      continue;
    }

    if (!BLIND_DEFECT_SEVERITIES.has(defect.severity)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] must have severity blocker, critical, high, medium, or low.`);
    }

    if (defect.status === undefined) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] is missing status; missing status is treated as open.`);
    } else if (!BLIND_DEFECT_STATUSES.has(defect.status)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] has invalid status ${defect.status}.`);
    }

    if (defect.status === 'fixed' && !reviewPassIds.has(defect.resolvedByReviewPassId)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] marked fixed must name resolvedByReviewPassId from reviewPasses.`);
    }
    if (['accepted_out_of_scope', 'external_blocker'].includes(defect.status)) {
      const evidenceResults = await Promise.all(
        arrayOrEmpty(defect.evidence).map((reference) => nonEmptyPacketEvidence(packetDir, reference, evidenceDir))
      );
      const reason = String(defect.acceptedReason || defect.reason || defect.rationale || '').trim();
      const defectId = String(defect.id ?? '').trim();
      const missingInput = String(defect.missingInput ?? '').trim();
      const nextAction = String(defect.nextAction ?? defect.recommendedFix ?? '').trim();
      if (
        (defect.status === 'accepted_out_of_scope' && !String(defect.acceptedBy ?? '').trim()) ||
        !reason ||
        !evidenceResults.some(Boolean)
      ) {
        errors.push(
          `blind-adversarial-review.json productDefects[${index}] ${defect.status} requires a reason${defect.status === 'accepted_out_of_scope' ? ', acceptedBy,' : ','} and concrete packet-local evidence.`
        );
      }
      if (defect.status === 'external_blocker') {
        if (!/^[A-Za-z0-9._-]+$/.test(defectId)) {
          errors.push(
            `blind-adversarial-review.json productDefects[${index}] external_blocker requires a stable alphanumeric id.`
          );
        } else if (!missingInput || !nextAction) {
          errors.push(
            `blind-adversarial-review.json productDefects[${index}] external_blocker requires missingInput and nextAction.`
          );
        } else if (reason && evidenceResults.some(Boolean)) {
          externalBlockers.push({
            attemptedEvidence: arrayOrEmpty(defect.evidence).map((reference) => String(reference).trim()).filter(Boolean),
            code: `blind.defect.${defectId}`,
            message: String(defect.title || reason).trim(),
            missingInput,
            nextAction,
            origin: `packet-verifier:blind-adversarial-review.productDefects[${index}]`,
            resolutionClass: 'external',
            verifierConfirmedExternal: true
          });
        }
      }
    }
  }

  for (const [index, omission] of omittedPrimaryRoutes.entries()) {
    if (!isJsonObject(omission) || !['accepted_out_of_scope', 'external_blocker'].includes(omission.disposition)) {
      errors.push(`blind-adversarial-review.json routeCoverage.omittedPrimaryRoutes[${index}] must declare accepted_out_of_scope or external_blocker.`);
      continue;
    }
    const evidenceResults = await Promise.all(
      arrayOrEmpty(omission.evidence).map((reference) => nonEmptyPacketEvidence(packetDir, reference, evidenceDir))
    );
    const rationale = String(omission.reason || omission.rationale || '').trim();
    const missingInput = String(omission.missingInput ?? '').trim();
    const nextAction = String(omission.nextAction ?? '').trim();
    if (
      (omission.disposition === 'accepted_out_of_scope' && !String(omission.acceptedBy ?? '').trim()) ||
      !rationale ||
      !evidenceResults.some(Boolean)
    ) {
      errors.push(
        `blind-adversarial-review.json routeCoverage.omittedPrimaryRoutes[${index}] ${omission.disposition} requires a rationale${omission.disposition === 'accepted_out_of_scope' ? ', acceptedBy,' : ','} and concrete packet-local evidence.`
      );
    }
    if (omission.disposition === 'external_blocker') {
      if (!missingInput || !nextAction) {
        errors.push(
          `blind-adversarial-review.json routeCoverage.omittedPrimaryRoutes[${index}] external_blocker requires missingInput and nextAction.`
        );
      } else if (rationale && evidenceResults.some(Boolean)) {
        const route = normalizeRouteKey(omission.route || omission.targetPath || omission.sourcePath || omission.path);
        externalBlockers.push({
          attemptedEvidence: arrayOrEmpty(omission.evidence).map((reference) => String(reference).trim()).filter(Boolean),
          code: `blind.route.${route || index}`,
          message: `Primary route ${route || `(row ${index})`} is externally blocked: ${rationale}`,
          missingInput,
          nextAction,
          origin: `packet-verifier:blind-adversarial-review.routeCoverage.omittedPrimaryRoutes[${index}]`,
          resolutionClass: 'external',
          verifierConfirmedExternal: true
        });
      }
    }
  }

  const openSevereDefects = defects.filter((defect) =>
    ['blocker', 'critical', 'high'].includes(defect.severity) && (defect.status ?? 'open') === 'open'
  );
  const openBlockerCount = defects.filter((defect) => defect.severity === 'blocker' && (defect.status ?? 'open') === 'open').length;
  const openCriticalCount = defects.filter((defect) => defect.severity === 'critical' && (defect.status ?? 'open') === 'open').length;
  const openHighCount = defects.filter((defect) => defect.severity === 'high' && (defect.status ?? 'open') === 'open').length;
  const acceptedOutOfScopeCount = defects.filter((defect) => defect.status === 'accepted_out_of_scope').length;
  const externalBlockerCount = defects.filter((defect) => defect.status === 'external_blocker').length;

  if (Number(summary.openBlockerIssueCount) !== openBlockerCount) {
    errors.push('blind-adversarial-review.json summary.openBlockerIssueCount must match open blocker defects.');
  }
  if (Number(summary.openCriticalIssueCount) !== openCriticalCount) {
    errors.push('blind-adversarial-review.json summary.openCriticalIssueCount must match open critical defects.');
  }
  if (Number(summary.openHighIssueCount) !== openHighCount) {
    errors.push('blind-adversarial-review.json summary.openHighIssueCount must match open high defects.');
  }
  if (Number(summary.acceptedOutOfScopeIssueCount) !== acceptedOutOfScopeCount) {
    errors.push('blind-adversarial-review.json summary.acceptedOutOfScopeIssueCount must match accepted-out-of-scope defects.');
  }
  if (Number(summary.externalBlockerIssueCount) !== externalBlockerCount) {
    errors.push('blind-adversarial-review.json summary.externalBlockerIssueCount must match external-blocker defects.');
  }

  if (
    openSevereDefects.length > 0 ||
    Number(summary.openBlockerIssueCount) > 0 ||
    Number(summary.openCriticalIssueCount) > 0 ||
    Number(summary.openHighIssueCount) > 0
  ) {
    errors.push('blind-adversarial-review.json cannot allow completion with open blocker, critical, or high product defects.');
  }

  const hasDesktop = routeReviews.some((review) => review.viewport === 'desktop');
  const hasMobile = routeReviews.some((review) => review.viewport === 'mobile');
  const hasRouteNotes = routeReviews.length > 0 && routeReviews.every((review) => String(review.routeNotes ?? '').trim().length > 0);
  if (summary.desktopMobileReviewed !== true || !hasDesktop || !hasMobile) {
    errors.push('blind-adversarial-review.json complete claims require desktop and mobile route reviews.');
  }

  if (summary.routeNotesPresent !== true || !hasRouteNotes) {
    errors.push('blind-adversarial-review.json complete claims require route notes from the blind review.');
  }

  if (summary.rawEvidencePresent !== true || !(await hasFiles(evidenceDir))) {
    errors.push('complete rebuild claims require raw blind review evidence under review-packet/evidence/blind-adversarial-review/.');
  }

  const usedScreenshotPaths = new Set();
  const usedScreenshotHashes = new Set();
  for (const [index, review] of routeReviews.entries()) {
    if (!isJsonObject(review)) {
      errors.push(`blind-adversarial-review.json routeViewportReviews[${index}] must be an object.`);
      continue;
    }
    if (!BLIND_COMPLETE_VERDICTS.has(review.verdict)) {
      errors.push(
        `blind-adversarial-review.json routeViewportReviews[${index}] must have verdict good or good_enough for completion.`
      );
    }
    const reviewTargetUrl = httpUrl(review.targetUrlOrArtifact);
    if (briefMode) {
      const briefReference = resolveReviewEvidencePath(packetDir, packetDir, review.sourceTruthReference);
      if (!briefReference || briefReference !== briefContext?.briefPath) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].sourceTruthReference must reference the preserved original brief.`
        );
      }
      const requirementIds = new Set(
        arrayOrEmpty(briefAcceptance?.requirements).map((requirement) => String(requirement?.id ?? '').trim()).filter(Boolean)
      );
      const reviewedRequirementIds = arrayOrEmpty(review.briefRequirementIds).map((id) => String(id).trim()).filter(Boolean);
      if (reviewedRequirementIds.length === 0 || reviewedRequirementIds.some((id) => !requirementIds.has(id))) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}] must name valid briefRequirementIds.`
        );
      }
    } else {
      const reviewSourceUrl = httpUrl(review.sourceTruthReference);
      if (!reviewSourceUrl || (declaredSourceUrl && reviewSourceUrl.origin !== declaredSourceUrl.origin)) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].sourceTruthReference must use the declared source origin.`
        );
      }
    }
    if (!reviewTargetUrl || (declaredTargetUrl && reviewTargetUrl.origin !== declaredTargetUrl.origin)) {
      errors.push(
        `blind-adversarial-review.json routeViewportReviews[${index}].targetUrlOrArtifact must use the declared target origin.`
      );
    }
    for (const check of BLIND_ROUTE_CHECKS) {
      const acceptedStatuses = REQUIRED_BLIND_ROUTE_PASSES.has(check) ? ['pass'] : ['pass', 'not_applicable'];
      if (!acceptedStatuses.includes(review.checks?.[check])) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].checks.${check} must be ${acceptedStatuses.join(' or ')} for completion.`
        );
      }
    }

    const reviewScreenshotPaths = {};
    const requiredScreenshotFields = briefMode ? ['targetScreenshot'] : ['sourceScreenshot', 'targetScreenshot'];
    for (const screenshotField of requiredScreenshotFields) {
      const screenshotPath = resolveReviewEvidencePath(packetDir, evidenceDir, review[screenshotField]);
      if (!screenshotPath) {
        errors.push(`blind-adversarial-review.json routeViewportReviews[${index}].${screenshotField} must reference an existing evidence file.`);
        continue;
      }
      reviewScreenshotPaths[screenshotField] = screenshotPath;
      const metadata = await evidenceImageMetadata(screenshotPath);
      if (
        !metadata ||
        metadata.size < MIN_SCREENSHOT_BYTES ||
        metadata.width < MIN_SCREENSHOT_DIMENSION ||
        metadata.height < MIN_SCREENSHOT_DIMENSION
      ) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].${screenshotField} must be a credible packet-local PNG, JPEG, WebP, or GIF capture at least ${MIN_SCREENSHOT_DIMENSION}x${MIN_SCREENSHOT_DIMENSION} and ${MIN_SCREENSHOT_BYTES} bytes.`
        );
      }
      if (
        metadata &&
        ((review.viewport === 'desktop' && (metadata.width < 1024 || metadata.height < 600)) ||
          (review.viewport === 'mobile' &&
            (metadata.width < 280 || metadata.width > 767 || metadata.height < 480)))
      ) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].${screenshotField} dimensions do not match its ${review.viewport} viewport.`
        );
      }
      if (usedScreenshotPaths.has(screenshotPath)) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].${screenshotField} must use a distinct capture, not a screenshot reused by another source/target viewport.`
        );
      }
      usedScreenshotPaths.add(screenshotPath);
      if (metadata?.contentSha256 && usedScreenshotHashes.has(metadata.contentSha256)) {
        errors.push(
          `blind-adversarial-review.json routeViewportReviews[${index}].${screenshotField} duplicates the bytes of another source/target viewport capture.`
        );
      }
      if (metadata?.contentSha256) {
        usedScreenshotHashes.add(metadata.contentSha256);
      }
    }
    if (
      !briefMode &&
      reviewScreenshotPaths.sourceScreenshot &&
      reviewScreenshotPaths.sourceScreenshot === reviewScreenshotPaths.targetScreenshot
    ) {
      errors.push(
        `blind-adversarial-review.json routeViewportReviews[${index}] must use distinct source and target screenshot files.`
      );
    }
  }

  const editorExperienceReviews = arrayOrEmpty(blindReview.editorExperienceReviews);
  if (editorExperienceReviews.length === 0) {
    errors.push('blind-adversarial-review.json complete claims require at least one non-admin editor experience review.');
  }
  for (const [index, review] of editorExperienceReviews.entries()) {
    if (
      !isJsonObject(review) ||
      !String(review.task ?? '').trim() ||
      !String(review.targetAdminUrl ?? '').trim() ||
      !String(review.editorRole ?? '').trim() ||
      privilegedEditorIdentity(review.editorUser) ||
      privilegedEditorIdentity(review.editorRole) ||
      !BLIND_COMPLETE_VERDICTS.has(review.verdict) ||
      review.publicOutputChanged !== true
    ) {
      errors.push(
        `blind-adversarial-review.json editorExperienceReviews[${index}] must record a named non-admin task and role, target admin URL, changed public output, and a good or good_enough verdict.`
      );
    }
    if (arrayOrEmpty(review.evidence).length === 0) {
      errors.push(`blind-adversarial-review.json editorExperienceReviews[${index}] requires packet-local evidence.`);
    }
    let credibleEditorCaptureCount = 0;
    let structuredEditorEvidencePresent = false;
    for (const [evidenceIndex, reference] of arrayOrEmpty(review.evidence).entries()) {
      const evidencePath = resolveReviewEvidencePath(packetDir, evidenceDir, reference);
      if (!evidencePath || !(await stat(evidencePath)).isFile() || (await stat(evidencePath)).size === 0) {
        errors.push(
          `blind-adversarial-review.json editorExperienceReviews[${index}].evidence[${evidenceIndex}] must reference non-empty packet-local evidence.`
        );
        continue;
      }
      const metadata = await evidenceImageMetadata(evidencePath);
      if (
        metadata &&
        metadata.size >= MIN_SCREENSHOT_BYTES &&
        metadata.width >= MIN_SCREENSHOT_DIMENSION &&
        metadata.height >= MIN_SCREENSHOT_DIMENSION
      ) {
        credibleEditorCaptureCount += 1;
      }
      if (extname(evidencePath).toLowerCase() === '.json') {
        try {
          const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
          const adminUrl = httpUrl(evidence?.targetAdminUrl);
          const publicUrl = httpUrl(evidence?.resultingPublicUrl);
          if (
            adminUrl &&
            publicUrl &&
            declaredTargetUrl &&
            adminUrl.origin === declaredTargetUrl.origin &&
            publicUrl.origin === declaredTargetUrl.origin &&
            String(evidence?.editorRole ?? '').trim() === String(review?.editorRole ?? '').trim() &&
            String(evidence?.action ?? '').trim() &&
            String(evidence?.checkedAt ?? '').trim() &&
            evidence?.publicOutputChanged === true
          ) {
            structuredEditorEvidencePresent = true;
          }
        } catch {
          // A non-JSON or malformed evidence file may still qualify as an image capture above.
        }
      }
    }
    if (credibleEditorCaptureCount < 2 && !structuredEditorEvidencePresent) {
      errors.push(
        `blind-adversarial-review.json editorExperienceReviews[${index}] requires credible before/after captures or structured target-bound editor action evidence.`
      );
    }
  }

  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes)
    .map((route) => ({
      source: normalizeRouteRequestKey(route.sourcePath || route.route || route.path),
      target: normalizeRouteRequestKey(route.targetPath || route.sourcePath || route.route || route.path)
    }))
    .filter((route) => route.target);
  const acceptedOmissions = new Map(
    omittedPrimaryRoutes
      .filter((route) =>
        ['accepted_out_of_scope', 'external_blocker'].includes(route.disposition) &&
        (route.disposition === 'external_blocker' || String(route.acceptedBy ?? '').trim()) &&
        String(route.rationale ?? '').trim() &&
        arrayOrEmpty(route.evidence).length > 0 &&
        (route.disposition !== 'external_blocker' || (
          String(route.missingInput ?? '').trim() && String(route.nextAction ?? '').trim()
        ))
      )
      .map((route) => [normalizeRouteRequestKey(route.route || route.targetPath || route.sourcePath || route.path), route])
  );

  for (const primaryRoute of primaryRoutes) {
    const matchingReviews = routeReviews.filter((review) => {
      const routeKey = normalizeRouteRequestKey(review.route);
      const targetKey = normalizeRouteRequestKey(review.targetUrlOrArtifact);
      const sourceKey = briefMode ? primaryRoute.source : normalizeRouteRequestKey(review.sourceTruthReference);
      return (
        routeKey === primaryRoute.target &&
        targetKey === primaryRoute.target &&
        (briefMode || sourceKey === primaryRoute.source)
      );
    });
    const coveredDesktop = matchingReviews.some((review) => review.viewport === 'desktop');
    const coveredMobile = matchingReviews.some((review) => review.viewport === 'mobile');

    if ((!coveredDesktop || !coveredMobile) && !acceptedOmissions.has(primaryRoute.target)) {
      errors.push(`blind-adversarial-review.json complete claims require path-consistent desktop and mobile blind review coverage for primary route ${primaryRoute.target}.`);
    }
  }

  if (!String(reviewInputs.originalBrief ?? '').trim() && (reviewInputs.acceptanceCriteria ?? []).length === 0) {
    errors.push('blind-adversarial-review.json complete claims require the original brief or acceptance criteria.');
  }

  if ((reviewInputs.targetUrlsOrArtifacts ?? []).length === 0) {
    errors.push('blind-adversarial-review.json complete claims require target URLs or artifacts.');
  }

  const reviewedTargetUrls = arrayOrEmpty(reviewInputs.targetUrlsOrArtifacts).map(httpUrl).filter(Boolean);
  if (
    reviewedTargetUrls.length === 0 ||
    (declaredTargetUrl && reviewedTargetUrls.some((url) => url.origin !== declaredTargetUrl.origin))
  ) {
    errors.push('blind-adversarial-review.json reviewInputs.targetUrlsOrArtifacts must bind its live URLs to the declared target origin.');
  }

  if ((reviewInputs.sourceOfTruthMaterials ?? []).length === 0) {
    errors.push('blind-adversarial-review.json complete claims require source-of-truth materials from the brief.');
  }
  if (briefMode) {
    const briefMaterials = arrayOrEmpty(reviewInputs.sourceOfTruthMaterials).filter((material) => {
      if (!['written_spec', 'design_file', 'screenshot', 'content_inventory', 'brand_guide', 'other'].includes(material?.type)) {
        return false;
      }
      return resolveReviewEvidencePath(packetDir, packetDir, material?.reference) === briefContext?.briefPath;
    });
    if (briefMaterials.length === 0) {
      errors.push('blind-adversarial-review.json brief mode must include the preserved original brief as a written source-of-truth material.');
    }
    const requiredIds = new Set(
      arrayOrEmpty(briefAcceptance?.requirements).map((requirement) => String(requirement?.id ?? '').trim()).filter(Boolean)
    );
    const acceptedCriteria = new Set(
      arrayOrEmpty(reviewInputs.acceptanceCriteria).map((criterion) =>
        typeof criterion === 'string' ? criterion.trim().split(/\s+/, 1)[0] : String(criterion?.id ?? '').trim()
      ).filter(Boolean)
    );
    for (const requirementId of requiredIds) {
      if (!acceptedCriteria.has(requirementId)) {
        errors.push(`blind-adversarial-review.json acceptanceCriteria must include brief requirement ${requirementId}.`);
      }
    }
  } else {
    const reviewedSourceUrls = arrayOrEmpty(reviewInputs.sourceOfTruthMaterials)
      .filter((material) => material?.type === 'source_site')
      .map((material) => httpUrl(material?.reference))
      .filter(Boolean);
    if (
      reviewedSourceUrls.length === 0 ||
      (declaredSourceUrl && reviewedSourceUrls.some((url) => url.origin !== declaredSourceUrl.origin))
    ) {
      errors.push('blind-adversarial-review.json reviewInputs.sourceOfTruthMaterials must include the declared source-site origin.');
    }
  }

  const structurallyValidForRequestedState = errors.length === startingErrorCount;
  return {
    externalBlockers,
    externalBlockersOnly:
      externalPauseReview &&
      externalBlockers.length > 0 &&
      structurallyValidForRequestedState,
    supportsCompletion:
      strictCompletionReview &&
      externalBlockers.length === 0 &&
      structurallyValidForRequestedState
  };
}

async function validateDurableIntent(packetDir, errors) {
  const path = join(packetDir, 'durable-intent.yml');
  if (!existsSync(path)) {
    return;
  }

  const text = await readFile(path, 'utf8');
  const statusBlocks = [...text.matchAll(/^\s*-\s+id:\s*["']?([^"'\n]*)["']?\s*$([\s\S]*?)(?=^\s*-\s+id:|(?![\s\S]))/gm)];
  const allowedStatuses = new Set(['draft', 'hash-valid', 'accepted', 'superseded']);

  for (const match of statusBlocks) {
    const block = match[0];
    const id = match[1]?.trim() || '(unknown intent)';
    const status = block.match(/^\s*status:\s*["']?([^"'\n]+)["']?\s*(?:#.*)?$/m)?.[1]?.trim() ?? '';
    const configHash = block.match(/^\s*config_hash:\s*["']?([^"'\n]*)["']?\s*(?:#.*)?$/m)?.[1]?.trim() ?? '';

    if (!allowedStatuses.has(status)) {
      errors.push(`${id} has invalid durable intent status ${status || '(blank)'}; expected draft, hash-valid, accepted, or superseded.`);
    }

    if ((status === 'hash-valid' || status === 'accepted') && !HASH_RE.test(configHash) && configHash !== 'not-applicable') {
      errors.push(`${id} has status ${status} but config_hash is not sha256:<64 hex chars> or not-applicable.`);
    }

    if ((status === 'hash-valid' || status === 'accepted') && (configHash === 'UNKNOWN' || configHash === '')) {
      errors.push(`${id} has status ${status} but config_hash is blank or UNKNOWN.`);
    }
  }
}

function durableEmptyIntentAcceptance(text) {
  const section = text.match(/^empty_intent_acceptance:\s*$([\s\S]*?)(?=^[^\s#][^\n]*:|(?![\s\S]))/m)?.[1] ?? '';
  const field = (name) => section.match(
    new RegExp(`^\\s+${name}:\\s*["']?([^"'\\n#]+)["']?\\s*(?:#.*)?$`, 'm')
  )?.[1]?.trim() ?? '';
  const evidenceBlock = section.match(/^\s+evidence:\s*$([\s\S]*?)(?=^\s+[a-zA-Z_][\w-]*:|(?![\s\S]))/m)?.[1] ?? '';
  const evidence = [...evidenceBlock.matchAll(/^\s+-\s*["']?([^"'\n#]+)["']?\s*(?:#.*)?$/gm)]
    .map((match) => match[1].trim())
    .filter(Boolean);
  return {
    acceptedBy: field('accepted_by'),
    disposition: field('disposition'),
    evidence,
    rationale: field('rationale')
  };
}

async function validateRecipeStartPoint(packetDir, errors) {
  const path = join(packetDir, 'recipe-start-point.md');
  if (!existsSync(path)) {
    return;
  }

  const text = await readFile(path, 'utf8');
  if (!/(?:ddev\s+)?composer\s+show\s+['"]drupal\/drupal_cms_\*['"]/.test(text)) {
    errors.push("recipe-start-point.md must record installed Drupal CMS package discovery with composer show 'drupal/drupal_cms_*'.");
  }
  if (!/find\s+recipes\s+web\/core\/recipes\s+-name\s+recipe\.yml/.test(text)) {
    errors.push('recipe-start-point.md must record filesystem Recipe discovery under recipes and web/core/recipes.');
  }
  if (!/default owner|default-owner|recipe.*default/i.test(text)) {
    errors.push('recipe-start-point.md must record the recipe default-owner decision before custom content-type overlays.');
  }
}

function packetTemplateName(packetFile) {
  const finalDot = packetFile.lastIndexOf('.');
  return finalDot === -1
    ? `${packetFile}.template`
    : `${packetFile.slice(0, finalDot)}.template${packetFile.slice(finalDot)}`;
}

function installedTemplatePath(packetFile) {
  const name = packetTemplateName(packetFile);
  return [
    join(KIT_ROOT, 'templates', name),
    join(KIT_ROOT, 'assets', 'templates', name)
  ].find((candidate) => existsSync(candidate)) ?? '';
}

function templateEnumSentinels(value, results = new Set()) {
  if (typeof value === 'string' && value.includes('|')) {
    results.add(value.trim());
  } else if (Array.isArray(value)) {
    value.forEach((child) => templateEnumSentinels(child, results));
  } else if (isJsonObject(value)) {
    Object.values(value).forEach((child) => templateEnumSentinels(child, results));
  }
  return results;
}

function unresolvedEnumSentinels(value, sentinels, path = '$', results = []) {
  if (typeof value === 'string' && sentinels.has(value.trim())) {
    results.push(path);
    return results;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) => unresolvedEnumSentinels(child, sentinels, `${path}[${index}]`, results));
  } else if (isJsonObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      unresolvedEnumSentinels(child, sentinels, `${path}.${key}`, results);
    }
  }
  return results;
}

function hasMeaningfulEntry(values) {
  return arrayOrEmpty(values).some((value) => {
    if (typeof value === 'string') {
      return value.trim().length > 0;
    }
    if (!isJsonObject(value)) {
      return value !== null && value !== undefined;
    }
    return Object.values(value).some((child) => {
      if (typeof child === 'string') {
        return child.trim().length > 0;
      }
      if (typeof child === 'number') {
        return Number.isFinite(child);
      }
      return Array.isArray(child) && child.length > 0;
    });
  });
}

function routeRecordPath(record) {
  return normalizeRouteKey(record?.route || record?.targetPath || record?.targetUrl || record?.targetFinalUrl);
}

function routeRecordRequestKey(record) {
  return normalizeRouteRequestKey(record?.route || record?.targetPath || record?.targetUrl || record?.targetFinalUrl);
}

function routeHasViewport(checks, route, viewport) {
  return checks.some((check) => {
    const viewportName = String(check?.viewport?.name ?? check?.viewport ?? '').trim();
    return routeRecordRequestKey(check) === route && viewportName === viewport;
  });
}

const AXE_WCAG_TAG_RE = /^wcag(?:2|21|22)(?:a|aa)$/i;
const REQUIRED_AXE_WCAG_TAGS = new Set([
  'wcag2a',
  'wcag2aa',
  'wcag21a',
  'wcag21aa',
  'wcag22aa'
]);

function sameHttpRoute(left, right) {
  const leftUrl = httpUrl(left);
  const rightUrl = httpUrl(right);
  return Boolean(
    leftUrl &&
    rightUrl &&
    leftUrl.origin === rightUrl.origin &&
    leftUrl.pathname === rightUrl.pathname &&
    leftUrl.search === rightUrl.search
  );
}

function axeRuleScopeReasons(accessibility, report, prefix) {
  const reasons = [];
  const declared = accessibility?.ruleScope ?? {};
  const mode = String(declared?.mode ?? '');
  const declaredTags = new Set(arrayOrEmpty(declared?.tags).map((tag) => String(tag).toLowerCase()));
  const toolOptions = isJsonObject(report?.toolOptions) ? report.toolOptions : {};
  const runOnly = toolOptions.runOnly;
  const disabledRules = Object.entries(isJsonObject(toolOptions.rules) ? toolOptions.rules : {})
    .filter(([, value]) => isJsonObject(value) && value.enabled === false)
    .map(([rule]) => rule);
  const resultCount = ['passes', 'incomplete', 'inapplicable', 'violations']
    .reduce((count, key) => count + arrayOrEmpty(report?.[key]).length, 0);

  if (declared?.accepted !== true || !['full_default', 'wcag_tags'].includes(mode)) {
    reasons.push(`${prefix}.ruleScope must declare and accept full_default or wcag_tags coverage.`);
    return reasons;
  }
  if (disabledRules.length > 0) {
    reasons.push(`${prefix}.report disables axe rules (${disabledRules.join(', ')}), so it is not a complete declared WCAG run.`);
  }
  if (resultCount === 0) {
    reasons.push(`${prefix}.report has no evaluated axe rules; empty result arrays cannot prove accessibility coverage.`);
  }
  if (mode === 'full_default') {
    if (runOnly !== undefined && runOnly !== null && runOnly !== false) {
      reasons.push(`${prefix}.report toolOptions.runOnly must be absent for declared full_default coverage.`);
    }
    if (declaredTags.size > 0) {
      reasons.push(`${prefix}.ruleScope.tags must be empty for full_default coverage.`);
    }
    return reasons;
  }

  const normalizedRunOnly = Array.isArray(runOnly)
    ? { type: 'tag', values: runOnly }
    : runOnly;
  const actualTags = new Set(arrayOrEmpty(normalizedRunOnly?.values).map((tag) => String(tag).toLowerCase()));
  if (!isJsonObject(normalizedRunOnly) || normalizedRunOnly.type !== 'tag') {
    reasons.push(`${prefix}.report toolOptions.runOnly must use tag mode for declared wcag_tags coverage.`);
  }
  for (const requiredTag of REQUIRED_AXE_WCAG_TAGS) {
    if (!declaredTags.has(requiredTag) || !actualTags.has(requiredTag)) {
      reasons.push(`${prefix}.ruleScope and report toolOptions.runOnly must include ${requiredTag}.`);
    }
  }
  if (
    declaredTags.size !== actualTags.size ||
    [...declaredTags].some((tag) => !actualTags.has(tag))
  ) {
    reasons.push(`${prefix}.ruleScope.tags must exactly match report toolOptions.runOnly.values.`);
  }
  return reasons;
}

async function axeIncompleteEvidenceMatches({
  browserEvidenceDir,
  disposition,
  incomplete,
  nodeTarget,
  packetDir,
  report
}) {
  const evidence = await packetEvidenceJson(packetDir, disposition?.evidence, browserEvidenceDir);
  const reportTimestamp = isoTimestamp(report?.timestamp);
  const evidenceTimestamp = isoTimestamp(evidence?.checkedAt);
  return Boolean(
    evidence?.schemaVersion === 'public-kit.axe-incomplete-disposition.1' &&
    sameHttpRoute(evidence?.targetUrl, report?.url) &&
    String(evidence?.ruleId ?? '') === String(incomplete?.id ?? '') &&
    JSON.stringify(arrayOrEmpty(evidence?.target)) === JSON.stringify(nodeTarget) &&
    evidence?.disposition === disposition?.disposition &&
    evidence?.result === 'pass' &&
    String(evidence?.observation ?? '').trim() &&
    timestampIsFresh(evidence?.checkedAt) &&
    reportTimestamp !== null &&
    evidenceTimestamp !== null &&
    evidenceTimestamp >= reportTimestamp &&
    evidenceTimestamp - reportTimestamp <= MAX_COMPLETION_EVIDENCE_SPAN_MS
  );
}

async function accessibilityCheckReasons(packetDir, browserEvidenceDir, check, index) {
  const reasons = [];
  const accessibility = check?.accessibilityCheck ?? {};
  const prefix = `browser-evidence.json publicRouteChecks[${index}].accessibilityCheck`;
  if (
    accessibility.standard !== 'WCAG 2.2 AA' ||
    accessibility.engine !== 'axe-core' ||
    !String(accessibility.engineVersion ?? '').trim() ||
    accessibility.executedInBrowser !== true ||
    accessibility.incompleteReviewed !== true ||
    accessibility.status !== 'pass' ||
    arrayOrEmpty(accessibility.blockers).length > 0
  ) {
    reasons.push(`${prefix} must record a passing in-browser axe-core WCAG 2.2 AA check with reviewed incomplete results and no blockers.`);
  }

  const reportPath = resolveReviewEvidencePath(packetDir, browserEvidenceDir, accessibility.report);
  let report = null;
  if (reportPath) {
    try {
      report = JSON.parse(await readFile(reportPath, 'utf8'));
    } catch {
      // The message below covers missing and malformed reports without leaking local paths.
    }
  }
  if (!isJsonObject(report)) {
    reasons.push(`${prefix}.report must reference packet-local raw axe-core JSON.`);
  } else {
    const environment = report.testEnvironment ?? {};
    const engine = report.testEngine ?? {};
    if (
      String(engine.name ?? '').toLowerCase() !== 'axe-core' ||
      String(engine.version ?? '').trim() !== String(accessibility.engineVersion ?? '').trim() ||
      !String(environment.userAgent ?? '').trim() ||
      !finiteNumberValue(environment.windowWidth) ||
      !finiteNumberValue(environment.windowHeight) ||
      Number(environment.windowWidth) !== Number(check?.viewport?.width) ||
      Number(environment.windowHeight) !== Number(check?.viewport?.height) ||
      !timestampIsFresh(report.timestamp) ||
      !Array.isArray(report.passes) ||
      !Array.isArray(report.incomplete) ||
      !Array.isArray(report.inapplicable) ||
      !Array.isArray(report.violations) ||
      !sameHttpRoute(report.url, check?.targetFinalUrl || check?.targetUrl)
    ) {
      reasons.push(`${prefix}.report must bind the reviewed target route to a real browser environment and the declared axe-core version.`);
    }
    reasons.push(...axeRuleScopeReasons(accessibility, report, prefix));
    const violations = arrayOrEmpty(report.violations);
    const unresolvedWcag = violations.filter((violation) =>
      arrayOrEmpty(violation?.tags).some((tag) => AXE_WCAG_TAG_RE.test(String(tag))) &&
      arrayOrEmpty(violation?.nodes).length > 0
    );
    if (unresolvedWcag.length > 0) {
      reasons.push(`${prefix}.report contains unresolved WCAG A/AA violations: ${unresolvedWcag.map((violation) => violation.id || 'unknown-rule').join(', ')}.`);
    }
    const incompleteDispositions = substantiveObjects(accessibility.incompleteDispositions);
    const usedIncompleteDispositions = new Set();
    for (const incomplete of arrayOrEmpty(report.incomplete).filter((record) =>
      arrayOrEmpty(record?.tags).some((tag) => AXE_WCAG_TAG_RE.test(String(tag)))
    )) {
      for (const node of arrayOrEmpty(incomplete?.nodes)) {
        const target = arrayOrEmpty(node?.target);
        const dispositionIndex = incompleteDispositions.findIndex((record, index) =>
          !usedIncompleteDispositions.has(index) &&
          String(record?.ruleId ?? '') === String(incomplete?.id ?? '') &&
          JSON.stringify(arrayOrEmpty(record?.target)) === JSON.stringify(target)
        );
        const disposition = dispositionIndex >= 0 ? incompleteDispositions[dispositionIndex] : null;
        const evidenceMatches = disposition && await axeIncompleteEvidenceMatches({
          browserEvidenceDir,
          disposition,
          incomplete,
          nodeTarget: target,
          packetDir,
          report
        });
        if (
          !disposition ||
          !['manual_pass', 'false_positive', 'not_applicable'].includes(disposition.disposition) ||
          !String(disposition.rationale ?? '').trim() ||
          !evidenceMatches
        ) {
          reasons.push(`${prefix}.report incomplete WCAG result ${incomplete?.id || 'unknown-rule'} at ${JSON.stringify(target)} needs a matching rationale and packet-local disposition evidence.`);
        } else {
          usedIncompleteDispositions.add(dispositionIndex);
        }
      }
    }
  }

  const manual = accessibility.manualChecks ?? {};
  for (const name of ['keyboardNavigation', 'visibleFocus', 'accessibleNamesAndLabels', 'formLabelsErrorsAndFocus']) {
    const result = String(manual[name] ?? '');
    const rationale = String(manual[`${name}NotApplicableRationale`] ?? '').trim();
    if (result !== 'pass' && !(result === 'not_applicable' && rationale)) {
      reasons.push(`${prefix}.manualChecks.${name} must pass or include a not-applicable rationale.`);
    }
  }
  return reasons;
}

function formOutcomeMatches(expected, actual) {
  const allowed = {
    message_delivery: new Set(['local_mail_capture', 'provider_delivery']),
    submission_storage: new Set(['drupal_submission_storage']),
    account_creation: new Set(['account_created']),
    provider_handoff: new Set(['provider_handoff']),
    other: new Set(['other'])
  };
  return allowed[expected]?.has(actual) === true;
}

function uniqueRecordKeys(records, keyName) {
  const keys = records.map((record) => String(record?.[keyName] ?? '').trim()).filter(Boolean);
  return keys.length === records.length && new Set(keys).size === keys.length;
}

async function formOutcomeEvidenceMatches(packetDir, browserEvidenceDir, check) {
  const evidence = await packetEvidenceJson(packetDir, check?.outcome?.evidence, browserEvidenceDir);
  const mode = String(check?.outcome?.mode ?? '');
  const providerRequired = ['provider_delivery', 'provider_handoff'].includes(mode);
  return Boolean(
    evidence?.schemaVersion === 'public-kit.form-outcome-evidence.1' &&
    String(evidence?.formKey ?? '').trim() === String(check?.formKey ?? '').trim() &&
    sameHttpRoute(evidence?.targetUrl, check?.targetUrl) &&
    evidence?.mode === mode &&
    evidence?.result === 'pass' &&
    timestampIsFresh(evidence?.checkedAt) &&
    String(evidence?.handlerOwner ?? '').trim() &&
    String(evidence?.resultReference ?? '').trim() &&
    String(evidence?.observation ?? '').trim() &&
    (!providerRequired || String(evidence?.provider ?? '').trim()) &&
    (mode !== 'other' || String(evidence?.rationale ?? '').trim())
  );
}

async function formAbuseEvidenceMatches(packetDir, browserEvidenceDir, check) {
  const evidence = await packetEvidenceJson(packetDir, check?.abuseProtection?.evidence, browserEvidenceDir);
  const mode = String(check?.abuseProtection?.mode ?? '');
  const localException = mode === 'local_only_exception';
  const modeSpecific =
    (['rendered_honeypot', 'rendered_challenge'].includes(mode) &&
      String(evidence?.renderedSelector ?? '').trim() && evidence?.enforcementVerified === true) ||
    (mode === 'configured_rate_limiting' &&
      String(evidence?.configurationOwner ?? '').trim() && evidence?.enforcementVerified === true) ||
    (mode === 'provider_managed' &&
      String(evidence?.provider ?? '').trim() && evidence?.enforcementVerified === true) ||
    (localException &&
      evidence?.localTargetVerified === true &&
      String(evidence?.rationale ?? '').trim());
  return Boolean(
    evidence?.schemaVersion === 'public-kit.form-abuse-evidence.1' &&
    String(evidence?.formKey ?? '').trim() === String(check?.formKey ?? '').trim() &&
    sameHttpRoute(evidence?.targetUrl, check?.targetUrl) &&
    evidence?.mode === mode &&
    evidence?.result === (localException ? 'accepted_gap' : 'pass') &&
    timestampIsFresh(evidence?.checkedAt) &&
    String(evidence?.observation ?? '').trim() &&
    modeSpecific
  );
}

function detailFieldVisible(record) {
  const visibility = record?.computedVisibility ?? {};
  const selector = String(record?.selector ?? '').trim();
  const documentWideSelector = /^(?:\*|:root|html|body|main|#page|\[role=["']?main["']?\])$/i.test(selector);
  const opacity = Number(visibility?.opacity);
  const width = Number(visibility?.boundingWidth);
  const height = Number(visibility?.boundingHeight);
  const visibleText = String(visibility?.text ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
  const expectedText = String(record?.targetSignal ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
  return Boolean(
    selector &&
    !documentWideSelector &&
    Number(visibility?.matchedElementCount) === 1 &&
    String(visibility?.display ?? '').toLowerCase() !== 'none' &&
    !['hidden', 'collapse'].includes(String(visibility?.visibility ?? '').toLowerCase()) &&
    Number.isFinite(opacity) && opacity > 0 &&
    visibility?.hiddenAttribute === false &&
    visibility?.ariaHidden === false &&
    Number.isFinite(width) && width > 0 &&
    Number.isFinite(height) && height > 0 &&
    expectedText && visibleText.includes(expectedText)
  );
}

function recordConfigIdentities(record, owner) {
  if (typeof record === 'string') {
    const value = record.trim();
    if (!value) {
      return [];
    }
    return owner === 'view_row' && !value.startsWith('views.view.')
      ? [value, `views.view.${value}`]
      : [value];
  }
  if (!isJsonObject(record)) {
    return [];
  }
  const identities = new Set([
    record?.configId,
    record?.id,
    record?.config,
    record?.name,
    record?.displayConfig
  ].map((value) => String(value ?? '').trim()).filter(Boolean));
  if (owner === 'entity_view_display' && record?.bundle && record?.mode) {
    identities.add(`core.entity_view_display.${record.entityType || 'node'}.${record.bundle}.${record.mode}`);
  }
  if (owner === 'view_row' && record?.id) {
    identities.add(`views.view.${record.id}`);
    for (const display of arrayOrEmpty(record?.displays)) {
      const displayId = String(isJsonObject(display) ? display.id || display.displayId : display).trim();
      if (displayId) {
        identities.add(`views.view.${record.id}:${displayId}`);
      }
    }
  }
  return [...identities];
}

function drupalOwnerConfigExists(drupalReadback, owner, configId) {
  const recordsByOwner = {
    entity_view_display: drupalReadback?.content?.viewDisplays,
    canvas_composition: drupalReadback?.content?.canvasPages,
    view_row: drupalReadback?.views
  };
  if (owner === 'documented_exception') {
    return true;
  }
  return arrayOrEmpty(recordsByOwner[owner]).some((record) =>
    recordConfigIdentities(record, owner).some((identity) => exactIdentityMatch(identity, configId))
  );
}

function detailExpectedFields(ledger, fieldOutputMatrix, recurringSourceObjects = []) {
  const expected = new Set(
    arrayOrEmpty(ledger?.requiredFields).map((field) => String(field).trim()).filter(Boolean)
  );
  for (const field of arrayOrEmpty(ledger?.detailLoadBearingFields)) {
    if (String(field).trim()) {
      expected.add(String(field).trim());
    }
  }
  for (const recurring of recurringSourceObjects) {
    if (exactIdentityMatch(recurring?.bundleOrConfigName, ledger?.contentTypeOrBundle)) {
      for (const field of arrayOrEmpty(recurring?.requiredFields)) {
        if (String(field).trim()) {
          expected.add(String(field).trim());
        }
      }
    }
  }
  const matchingFieldBundles = arrayOrEmpty(fieldOutputMatrix?.bundles).filter((bundle) =>
    exactIdentityMatch(bundle?.entityType, ledger?.drupalEntityType) &&
    exactIdentityMatch(bundle?.bundle, ledger?.contentTypeOrBundle)
  );
  for (const field of matchingFieldBundles.flatMap((bundle) => arrayOrEmpty(bundle?.fields))) {
    const locations = arrayOrEmpty(field?.publicRenderLocations).map((location) => String(location).trim()).filter(Boolean);
    const appliesToDetail = locations.some((location) =>
      normalizeRouteKey(location) === normalizeRouteKey(ledger?.representativeDetailTargetPath) ||
      exactIdentityMatch(location, ledger?.drupalOwnerConfigId) ||
      ['detail', 'full', 'canonicaldetail'].includes(identityKey(location))
    ) || (locations.length === 0 && arrayOrEmpty(ledger?.detailLoadBearingFields).some((declared) =>
      exactIdentityMatch(declared, field?.machineName)
    ));
    if (
      (field?.required === true || field?.affectsAnonymousOutput === true) &&
      appliesToDetail &&
      String(field?.machineName ?? '').trim()
    ) {
      expected.add(String(field.machineName).trim());
    }
  }
  return [...expected];
}

function escapedRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function markdownField(text, label) {
  return text.match(new RegExp(`^[ \\t]*-[ \\t]*${escapedRegex(label)}:[ \\t]*([^\\r\\n]+?)[ \\t]*$`, 'mi'))?.[1]?.trim() ?? '';
}

function markdownPlainField(text, label) {
  return text.match(new RegExp(`^[ \\t]*${escapedRegex(label)}:[ \\t]*([^\\r\\n]+?)[ \\t]*$`, 'mi'))?.[1]?.trim() ?? '';
}

function resolvedMarkdownField(text, label) {
  const value = markdownField(text, label);
  return Boolean(value) && !/^`?UNKNOWN`?$/i.test(value);
}

function checkedStatement(text, statement) {
  return new RegExp(`^\\s*-\\s*\\[[xX]\\]\\s*${escapedRegex(statement)}\\s*$`, 'm').test(text);
}

function blockedTableRow(text) {
  return /^\|[^\n]*\|\s*blocked\s*\|\s*$/im.test(text);
}

function unresolvedMarkdownUnknown(text) {
  return /:\s*`?UNKNOWN`?\s*$/im.test(text) || /\|\s*UNKNOWN\s*\|/i.test(text);
}

function markdownDecisionRows(text) {
  return String(text)
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith('|') || !trimmed.endsWith('|')) {
        return null;
      }
      const cells = trimmed.slice(1, -1).split('|').map((cell) => cell.trim());
      if (!/^DEC-[A-Za-z0-9._-]+$/.test(cells[0] ?? '')) {
        return null;
      }
      return { cells, currentEvidence: cells[3] ?? '', raw: trimmed };
    })
    .filter(Boolean);
}

function completeDecisionRow(row) {
  return row?.cells?.length === 9 && row.cells.every((cell) => Boolean(cell));
}

function decisionRowStatus(row) {
  return String(row?.cells?.[8] ?? '').replaceAll('`', '').trim().toLowerCase();
}

function currentEvidenceReferenceSet(rows) {
  return new Set(
    rows.flatMap((row) =>
      String(row.currentEvidence)
        .toLowerCase()
        .replaceAll('`', '')
        .split(/[\s,;()[\]{}]+/)
        .map((token) => token.replace(/^["'<>]+|["'<>.!?]+$/g, ''))
        .filter(Boolean)
    )
  );
}

function stableDeviationIdentity(value) {
  const identity = typeof value === 'string'
    ? value.trim()
    : isJsonObject(value)
      ? String(value.id || value.route || value.sourcePath || value.targetPath || value.path || '').trim()
      : '';
  return /^[A-Za-z0-9._~:/?&=%+-]+$/.test(identity) ? identity : '';
}

function referenceSlug(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function humanDecisionPresentationAssessment({ briefMode = false, decisions, offRoad, records }) {
  const structuralReasons = [];
  const contradictionReasons = [];
  const decisionRows = markdownDecisionRows(decisions);
  const openDecisionSummary = markdownField(decisions, 'Decisions still open').replaceAll('`', '').trim();
  const noOpenDecisions = /^None$/i.test(openDecisionSummary);
  const summaryFields = [
    'Decisions still open',
    'Decisions accepted',
    'Decisions blocked by missing external input',
    'Agent-resolvable work deliberately excluded from this file'
  ];
  const allowedDecisionStatuses = new Set([
    'accepted',
    'blocked',
    'deferred',
    'not_applicable',
    'open',
    'pending',
    'rejected',
    'resolved'
  ]);
  const openDecisionStatuses = new Set(['blocked', 'deferred', 'open', 'pending']);
  const identityFields = briefMode
    ? ['Build basis', 'Brief file', 'Target site name', 'Target workspace', 'Date']
    : ['Source URL', 'Target site name', 'Target workspace', 'Date'];
  const identityComplete = identityFields.every((field) =>
    resolvedMarkdownField(decisions, field)
  );
  const summariesComplete = summaryFields.every((field) => resolvedMarkdownField(decisions, field));
  const rowsComplete = decisionRows.every(completeDecisionRow);
  const rowStatusesValid = decisionRows.every((row) => allowedDecisionStatuses.has(decisionRowStatus(row)));
  if (
    !identityComplete ||
    !summariesComplete ||
    unresolvedMarkdownUnknown(decisions) ||
    (!noOpenDecisions && decisionRows.length === 0) ||
    !rowsComplete ||
    !rowStatusesValid
  ) {
    structuralReasons.push(
      'open-decisions.md must contain run identity, exact handoff summaries, and substantive DEC rows with nine populated cells and a supported status, or an exact Decisions still open: None declaration.'
    );
  }
  if (noOpenDecisions && decisionRows.some((row) => openDecisionStatuses.has(decisionRowStatus(row)))) {
    contradictionReasons.push(
      'open-decisions.md cannot declare "Decisions still open: None" while a DEC row remains open, pending, blocked, or deferred.'
    );
  }
  const requiredReferences = [];
  const sourceDescriptions = new Set();
  const missingStableIdentities = [];

  for (const match of offRoad.matchAll(/^\|\s*(OR-[A-Za-z0-9._-]+)\s*\|[^\n]*$/gim)) {
    requiredReferences.push(match[1]);
    sourceDescriptions.add('off-road-inventory.md OR- exception rows');
  }
  for (const [index, defect] of arrayOrEmpty(records.blindAdversarialReview?.productDefects).entries()) {
    if (defect?.status !== 'accepted_out_of_scope') {
      continue;
    }
    const identity = stableDeviationIdentity(String(defect.id ?? ''));
    if (!identity) {
      missingStableIdentities.push(`blind-adversarial-review.json productDefects[${index}]`);
      continue;
    }
    requiredReferences.push(identity);
    sourceDescriptions.add('blind-adversarial-review.json accepted_out_of_scope defects');
  }
  for (const [index, route] of arrayOrEmpty(
    records.blindAdversarialReview?.routeCoverage?.omittedPrimaryRoutes
  ).entries()) {
    if (route?.disposition !== 'accepted_out_of_scope') {
      continue;
    }
    const identity = normalizeRouteKey(route.route || route.targetPath || route.sourcePath || route.path);
    if (!identity) {
      missingStableIdentities.push(`blind-adversarial-review.json routeCoverage.omittedPrimaryRoutes[${index}]`);
      continue;
    }
    requiredReferences.push(`omitted-route:${identity}`);
    sourceDescriptions.add('blind-adversarial-review.json accepted primary-route omissions');
  }
  for (const [index, exclusion] of arrayOrEmpty(records.parityReport?.addressableSurface?.exclusions).entries()) {
    if (!hasMeaningfulEntry([exclusion])) {
      continue;
    }
    const identity = stableDeviationIdentity(exclusion);
    if (!identity) {
      missingStableIdentities.push(`parity-report.json addressableSurface.exclusions[${index}]`);
      continue;
    }
    requiredReferences.push(`parity-exclusion:${identity}`);
    sourceDescriptions.add('parity-report.json addressable-surface exclusions');
  }
  for (const [index, reconciliation] of arrayOrEmpty(records.routeMatrix?.perRouteItemReconciliation).entries()) {
    if (reconciliation?.mismatchDisposition !== 'owner_approved_exclusion') {
      continue;
    }
    const sourcePath = normalizeRouteKey(reconciliation.sourcePath);
    const targetPath = normalizeRouteKey(reconciliation.targetPath);
    const itemType = String(reconciliation.itemType ?? '').trim();
    const itemTypeSlug = referenceSlug(itemType);
    if (!sourcePath || !targetPath || !itemTypeSlug || /\s/.test(sourcePath) || /\s/.test(targetPath)) {
      missingStableIdentities.push(`route-matrix.json perRouteItemReconciliation[${index}]`);
      continue;
    }
    requiredReferences.push(`count-exclusion:${sourcePath}->${targetPath}:${itemTypeSlug}`);
    sourceDescriptions.add('route-matrix.json owner_approved_exclusion count dispositions');
  }
  for (const [index, check] of arrayOrEmpty(
    records.independentVerification?.compositionModelFidelityChecks
  ).entries()) {
    if (
      compositionOwnersMatch(check?.declaredCompositionOwner, check?.actualCompositionOwner) ||
      check?.deviationRecordRequired !== true ||
      check?.deviationRecordPresent !== true
    ) {
      continue;
    }
    const targetRoute = normalizeRouteKey(check.targetRoute || check.publicRoute || check.targetPath);
    if (!targetRoute || /\s/.test(targetRoute)) {
      missingStableIdentities.push(`independent-verification.json compositionModelFidelityChecks[${index}]`);
      continue;
    }
    requiredReferences.push(`composition-deviation:${targetRoute}`);
    sourceDescriptions.add('independent-verification.json accepted composition-owner deviations');
  }

  if (missingStableIdentities.length > 0) {
    contradictionReasons.push(
      `Accepted deviations need stable IDs or route/item identities before handoff presentation can be checked: ${missingStableIdentities.join(', ')}.`
    );
  }
  const presentedReferences = currentEvidenceReferenceSet(decisionRows);
  const missingReferences = requiredReferences.filter((reference) =>
    !presentedReferences.has(reference.toLowerCase())
  );
  if (noOpenDecisions && requiredReferences.length > 0) {
    contradictionReasons.push(
      `open-decisions.md cannot declare "Decisions still open: None" while ${[...sourceDescriptions].join(', ')} require presented ratification decisions; the local verifier does not authenticate their approvers.`
    );
  } else if (missingReferences.length > 0) {
    contradictionReasons.push(
      `open-decisions.md must reference every accepted deviation in a substantive DEC row Current evidence cell; missing ${missingReferences.join(', ')}.`
    );
  }

  return {
    decisionRows,
    noOpenDecisions,
    reasons: [...structuralReasons, ...contradictionReasons],
    status:
      contradictionReasons.length > 0
        ? 'contradictory'
        : structuralReasons.length > 0
          ? 'incomplete'
          : 'presented-consistently'
  };
}

function recordedDecision(text, choices) {
  const selected = choices.filter(({ statement }) => checkedStatement(text, statement));
  if (selected.length === 0) {
    return 'pending';
  }
  if (selected.length > 1) {
    return 'conflicting-record';
  }
  return selected[0].status;
}

function recordedAttribution(text, recordedByLabel) {
  const recordedBy = markdownField(text, recordedByLabel);
  const builderIdentity = markdownField(text, 'Builder identity');
  return {
    recordedBy,
    builderIdentity,
    identityStringComparison:
      !recordedBy || !builderIdentity
        ? 'not-comparable'
        : identitiesMatch(recordedBy, builderIdentity)
          ? 'same-string'
          : 'different-string'
  };
}

function recordedHumanGateAssessment(texts) {
  const operator = texts['operator-run.md'];
  const maintainer = texts['maintainer-review.md'];
  const productionTarget = texts['production-target.md'];
  const launchChecklist = texts['launch-checklist.md'];

  const operatorStatus = recordedDecision(operator, [
    { statement: 'Repeatability not reviewed', status: 'pending' },
    { statement: 'Repeatability blocked', status: 'recorded-not-accepted' },
    { statement: 'Repeatability accepted', status: 'recorded-accepted' },
    { statement: 'Repeatability accepted with restrictions', status: 'recorded-accepted-with-restrictions' }
  ]);
  const maintainerStatus = recordedDecision(maintainer, [
    {
      statement: 'I would stake my name on this as a complete local Drupal CMS rebuild.',
      status: 'recorded-accepted'
    },
    {
      statement: 'I would not stake my name on this as a complete local Drupal CMS rebuild.',
      status: 'recorded-not-accepted'
    }
  ]);
  const productionTargetStatus = recordedDecision(productionTarget, [
    { statement: 'Production target accepted', status: 'recorded-accepted' },
    { statement: 'Production target not accepted', status: 'recorded-not-accepted' }
  ]);
  const launchStatus = recordedDecision(launchChecklist, [
    { statement: 'Launch approved', status: 'recorded-accepted' },
    { statement: 'Launch not approved', status: 'recorded-not-accepted' }
  ]);
  const operatorRecordComplete = [
    'Name',
    'Role',
    'Environment',
    'Environment provisioning (manual, One Line Installer, other)',
    'Date',
    'Builder identity',
    'DDEV project URL',
    '`ddev drush status`',
    'Config export location',
    'Anonymous route checks',
    'Browser-rendered evidence',
    'Command transcript',
    'Reviewer'
  ].every((field) => resolvedMarkdownField(operator, field)) && !unresolvedMarkdownUnknown(operator);
  const maintainerQuestions = [
    'Is the build on Drupal CMS best practices using Drupal-native primitives?',
    "Is the architecture sound for the source site's real shape?",
    'Does it contain the public content and media needed to review the site as a rebuild?',
    "Does it match the source site's visual language and public behavior?",
    'Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?',
    'Are the load-bearing decisions captured and usable by later agents?',
    'Are the remaining business, legal, integration, production, and launch gaps named?',
    'Would a Drupal maintainer put their name on this as a complete local starting point?'
  ];
  const maintainerRecordComplete =
    ['Site', 'Target', 'Reviewer', 'Date', 'Builder identity'].every((field) => resolvedMarkdownField(maintainer, field)) &&
    maintainerQuestions.every((question) => checkedStatement(maintainer, question)) &&
    resolvedMarkdownField(maintainer, 'Reasons to accept') &&
    !unresolvedMarkdownUnknown(maintainer);
  const productionTargetRecordComplete = ['Approver', 'Builder identity', 'Reviewed at'].every((field) =>
    resolvedMarkdownField(productionTarget, field)
  ) && !unresolvedMarkdownUnknown(productionTarget);
  const launchRecordComplete = ['Approver', 'Builder identity', 'Reviewed at'].every((field) =>
    resolvedMarkdownField(launchChecklist, field)
  ) && !unresolvedMarkdownUnknown(launchChecklist);
  const localRecords = [
    { recordComplete: operatorRecordComplete, status: operatorStatus },
    { recordComplete: maintainerRecordComplete, status: maintainerStatus }
  ];
  const localRebuildStatus = localRecords.some(({ status }) =>
    ['recorded-not-accepted', 'conflicting-record'].includes(status)
  )
    ? 'recorded-not-accepted'
    : localRecords.some(({ recordComplete, status }) => !recordComplete || status === 'pending')
      ? 'pending'
      : localRecords.some(({ status }) => status === 'recorded-accepted-with-restrictions')
        ? 'recorded-accepted-with-restrictions'
        : 'recorded-accepted';

  return {
    authentication: 'self-attested-record-only',
    affectsMachineCompletion: false,
    localRebuildStatus,
    gates: {
      'G-OPERATOR-01': {
        status: operatorStatus,
        recordComplete: operatorRecordComplete,
        ...recordedAttribution(operator, 'Name')
      },
      'G-TARGET-01': {
        status: productionTargetStatus,
        recordComplete: productionTargetRecordComplete,
        ...recordedAttribution(productionTarget, 'Approver')
      },
      'G-LAUNCH-01': {
        status: launchStatus,
        recordComplete: launchRecordComplete,
        ...recordedAttribution(launchChecklist, 'Approver')
      },
      'G-MAINTAINER-01': {
        status: maintainerStatus,
        recordComplete: maintainerRecordComplete,
        ...recordedAttribution(maintainer, 'Reviewer')
      }
    },
    note: 'These packet fields are builder-writable. The verifier reports the recorded strings and choices but does not authenticate a person or infer human independence.'
  };
}

async function markdownCompletionReadiness(packetDir, records = {}, { briefMode = false } = {}) {
  const reasons = [];
  const texts = Object.fromEntries(
    await Promise.all(
      [
        'operator-run.md',
        'maintainer-review.md',
        'production-target.md',
        'launch-checklist.md',
        'recipe-start-point.md',
        'scoped-gap-list.md',
        'open-decisions.md',
        'off-road-inventory.md',
        'durable-intent.yml'
      ].map(async (file) => [file, existsSync(join(packetDir, file)) ? await readFile(join(packetDir, file), 'utf8') : ''])
    )
  );

  const recipe = texts['recipe-start-point.md'];
  const selectedStartPoints = [
    'Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.',
    'Retain a site template selected before installation plus bounded source-fit Recipes and overlays.',
    'Retain another existing Drupal CMS substrate and extend it without replacing it.',
    'Use bounded custom overlays because maintained Recipes do not fit the audited source patterns.'
  ].filter((choice) => checkedStatement(recipe, choice));
  const recipeIdentityFields = briefMode
    ? ['Build basis', 'Brief file', 'Target site name', 'Target workspace', 'Decision date', 'Decision owner']
    : ['Source URL', 'Target site name', 'Target workspace', 'Decision date', 'Decision owner'];
  if (
    recipeIdentityFields.some(
      (field) => !markdownField(recipe, field)
    ) ||
    selectedStartPoints.length !== 1 ||
    !markdownPlainField(recipe, 'Decision') ||
    !markdownPlainField(recipe, 'Rationale') ||
    unresolvedMarkdownUnknown(recipe) ||
    /Recipe discovery \/ apply evidence:[\s\S]{0,160}?```(?:text)?\s*UNKNOWN\s*```/i.test(recipe)
  ) {
    reasons.push('recipe-start-point.md must record one selected start point, owner/date, rationale, and resolved recipe evidence.');
  }

  const gaps = texts['scoped-gap-list.md'];
  const gapIdentityFields = briefMode
    ? ['Build basis', 'Brief file', 'Target site name', 'Target workspace', 'Date']
    : ['Source URL', 'Target site name', 'Target workspace', 'Date'];
  const expectedGapStatus = briefMode
    ? /^Overall status:\s*`?(?:complete-local-build-from-brief|local-complete)`?\s*$/mi
    : /^Overall status:\s*`?(?:complete-local-rebuild|local-complete)`?\s*$/mi;
  if (
    gapIdentityFields.some((field) => !markdownField(gaps, field)) ||
    !expectedGapStatus.test(gaps) ||
    unresolvedMarkdownUnknown(gaps) ||
    blockedTableRow(gaps)
  ) {
    reasons.push('scoped-gap-list.md must identify the run, declare complete-local-rebuild status, and disposition every gap without UNKNOWN or blocked rows.');
  }

  const decisions = texts['open-decisions.md'];
  const offRoad = texts['off-road-inventory.md'];
  const decisionPresentation = humanDecisionPresentationAssessment({ briefMode, decisions, offRoad, records });
  reasons.push(...decisionPresentation.reasons);

  if (
    ['Site', 'Checked at', 'Reviewer'].some((field) => !markdownField(offRoad, field)) ||
    !/^\s*-\s*Overall status:\s*`?accepted`?\s*$/mi.test(offRoad) ||
    unresolvedMarkdownUnknown(offRoad) ||
    blockedTableRow(offRoad) ||
    !(/no off-road moves/i.test(offRoad) || /^\|\s*OR-[^\n]+\|\s*$/im.test(offRoad))
  ) {
    reasons.push('off-road-inventory.md must contain a recorded review and disposition every paved-path exception without UNKNOWN or blocked rows; reviewer attribution is self-attested.');
  }

  const durableIntent = texts['durable-intent.yml'];
  const explicitEmptyIntent = /^\s*intent_records:\s*\[\s*\]\s*$/m.test(durableIntent);
  const emptyIntentAcceptance = durableEmptyIntentAcceptance(durableIntent);
  const emptyIntentEvidenceResults = await Promise.all(
    emptyIntentAcceptance.evidence.map((reference) => nonEmptyPacketEvidence(packetDir, reference))
  );
  const acceptedEmptyIntent =
    explicitEmptyIntent &&
    emptyIntentAcceptance.disposition === 'accepted_no_durable_intent' &&
    Boolean(emptyIntentAcceptance.acceptedBy) &&
    Boolean(emptyIntentAcceptance.rationale) &&
    emptyIntentEvidenceResults.length > 0 &&
    emptyIntentEvidenceResults.every(Boolean);
  const intentBlocks = [...durableIntent.matchAll(/^\s*-\s+id:\s*["']?([^"'\n]*)["']?\s*$([\s\S]*?)(?=^\s*-\s+id:|(?![\s\S]))/gm)];
  const allIntentRecordsCurrent =
    intentBlocks.length > 0 &&
    intentBlocks.every((match) => {
      const block = match[0];
      const status = block.match(/^\s*status:\s*["']?([^"'\n]+)["']?\s*$/m)?.[1]?.trim();
      const hash = block.match(/^\s*config_hash:\s*["']?([^"'\s]+)["']?\s*(?:#.*)?$/m)?.[1]?.trim();
      return (
        match[1].trim() &&
        /^\s*target_config:\s*["']?\S.+?["']?\s*$/m.test(block) &&
        /^\s*rationale:\s*["']?\S.+?["']?\s*$/m.test(block) &&
        /^\s*asserted_by:\s*["']?\S.+?["']?\s*$/m.test(block) &&
        /^\s*last_reviewed:\s*["']?\S.+?["']?\s*$/m.test(block) &&
        ['hash-valid', 'accepted'].includes(status) &&
        (HASH_RE.test(hash) || hash === 'not-applicable')
      );
    });
  if (
    !/^site:\s*["']?\S.+?["']?\s*$/m.test(durableIntent) ||
    (!acceptedEmptyIntent && !allIntentRecordsCurrent)
  ) {
    reasons.push(
      'durable-intent.yml must name the site and contain current accepted/hash-valid intent, or an empty record list with a named accepted_no_durable_intent disposition, rationale, and non-empty packet evidence.'
    );
  }

  return {
    reasons,
    humanDecisionPresentationStatus: decisionPresentation.status,
    recordedHumanGateStatus: recordedHumanGateAssessment(texts)
  };
}

async function dispositionReady(packetDir, disposition) {
  return Boolean(
    String(disposition?.acceptedBy ?? '').trim() &&
    String(disposition?.rationale ?? '').trim() &&
    arrayOrEmpty(disposition?.evidence).length > 0 &&
    (await Promise.all(arrayOrEmpty(disposition?.evidence).map((reference) =>
      nonEmptyPacketEvidence(packetDir, reference)
    ))).every(Boolean)
  );
}

async function negativeRouteConsentReasons(packetDir, record, routeMatrix) {
  const reasons = [];
  if (!isJsonObject(record) || record.schemaVersion !== 'public-kit.negative-route-consent.1') {
    return ['negative-route-consent.json must use schemaVersion public-kit.negative-route-consent.1.'];
  }
  if (!String(record.site ?? '').trim() || !String(record.toolOrMethod ?? '').trim() || !isoTimestamp(record.checkedAt)) {
    reasons.push('negative-route-consent.json must identify the site, UTC check time, and tool or method.');
  }
  if (record.runSpecificEvidenceRecorded !== true) {
    reasons.push('negative-route-consent.json must affirm that run-specific evidence was recorded.');
  }

  const missingRoute = record.missingRoute;
  if (!isJsonObject(missingRoute) || missingRoute.canonicalPolicy !== 'absent_or_self') {
    reasons.push('negative-route-consent.json must require absent-or-self canonical behavior for the generated missing route.');
  }
  if (!['required', 'status_only_with_disposition'].includes(missingRoute?.noindexPolicy)) {
    reasons.push('negative-route-consent.json must select a supported missing-route noindex policy.');
  } else if (
    missingRoute.noindexPolicy === 'status_only_with_disposition' &&
    !(await dispositionReady(packetDir, missingRoute.statusOnlyDisposition))
  ) {
    reasons.push('A status-only missing-route noindex policy requires a named, evidenced disposition.');
  }

  const accessWallRoutes = arrayOrEmpty(record.accessWallRoutes);
  if (
    accessWallRoutes.length === 0 ||
    accessWallRoutes.some((route) =>
      !normalizeRouteKey(route?.path) ||
      route?.canonicalPolicy !== 'absent_or_self' ||
      !['available', 'denied', 'disabled', 'external_auth'].includes(route?.expectedBehavior)
    )
  ) {
    reasons.push('negative-route-consent.json must declare at least one valid access-wall route with absent-or-self canonical policy.');
  }
  for (const route of accessWallRoutes.filter((candidate) => candidate?.expectedBehavior === 'external_auth')) {
    const disposition = route.externalAuthDisposition;
    if (!httpUrl(disposition?.expectedOrigin) || !(await dispositionReady(packetDir, disposition))) {
      reasons.push(`${normalizeRouteKey(route?.path) || 'An external-auth access wall'} needs an expected origin and named, evidenced disposition.`);
    }
  }

  const legalScope = record.legalPrivacyScope;
  const requirements = arrayOrEmpty(legalScope?.requirements);
  if (legalScope?.reviewed !== true) {
    reasons.push('negative-route-consent.json legal/privacy scope must be reviewed.');
  }
  if (requirements.length === 0 && !String(legalScope?.noRoutesReason ?? '').trim()) {
    reasons.push('An empty legal/privacy requirement list needs a reason.');
  }
  for (const requirement of requirements) {
    if (!normalizeRouteKey(requirement?.path) || !['active', 'production_only'].includes(requirement?.status)) {
      reasons.push('Every legal/privacy requirement needs a route and active or production_only status.');
      continue;
    }
    if (requirement.status === 'production_only' && !(await dispositionReady(packetDir, requirement))) {
      reasons.push(`${normalizeRouteKey(requirement.path)} is production-only and needs a named, evidenced disposition.`);
    }
  }

  const consent = record.consent;
  if (!['installed', 'not_installed'].includes(consent?.discoveryStatus)) {
    reasons.push('negative-route-consent.json must record whether a consent manager is installed.');
    return reasons;
  }
  const managers = arrayOrEmpty(consent.managers);
  const applications = arrayOrEmpty(consent.applications);
  const beforeChecks = arrayOrEmpty(consent.beforeConsentChecks);
  if (consent.discoveryStatus === 'not_installed') {
    if (!String(consent.notInstalledReason ?? '').trim() || managers.length || applications.length || beforeChecks.length) {
      reasons.push('A not-installed consent result needs a reason and must not declare managers, applications, or before-consent checks.');
    }
    return reasons;
  }
  if (
    managers.length === 0 ||
    managers.some((manager) => !String(manager?.id ?? '').trim() || !String(manager?.module ?? '').trim())
  ) {
    reasons.push('Installed consent must enumerate each manager with an id and Drupal module.');
  }
  const managerIds = new Set(managers.map((manager) => String(manager?.id ?? '').trim()).filter(Boolean));
  for (const application of applications) {
    const resources = arrayOrEmpty(application?.controlledResources);
    if (
      !String(application?.id ?? '').trim() ||
      !managerIds.has(String(application?.managerId ?? '').trim()) ||
      !String(application?.configName ?? '').trim() ||
      typeof application?.enabled !== 'boolean' ||
      typeof application?.required !== 'boolean'
    ) {
      reasons.push('Every consent application needs an id, known manager, config name, and boolean enabled/required state.');
    }
    const essentialEvidence = arrayOrEmpty(application?.essentialServiceEvidence);
    if (application?.required === true) {
      const essentialEvidenceReady = essentialEvidence.length > 0 &&
        (await Promise.all(essentialEvidence.map((reference) =>
          nonEmptyPacketEvidence(packetDir, reference)
        ))).every(Boolean);
      if (
        application?.essentialWithoutConsent !== true ||
        !String(application?.essentialServiceRationale ?? '').trim() ||
        !essentialEvidenceReady
      ) {
        reasons.push(`Required consent application ${application?.id || '(missing id)'} needs an explicit essential-without-consent classification, rationale, and packet-local evidence; required=true alone cannot authorize pre-consent loading.`);
      }
    } else if (application?.essentialWithoutConsent === true) {
      reasons.push(`Optional consent application ${application?.id || '(missing id)'} cannot declare essentialWithoutConsent.`);
    }
    if (resources.some((resource) =>
      !['script', 'iframe', 'image', 'style', 'resource', 'selector', 'attachment'].includes(resource?.kind) ||
      !String(resource?.pattern ?? '').trim()
    )) {
      reasons.push(`Consent application ${application?.id || '(missing id)'} has an invalid controlled-resource declaration.`);
    }
    if (resources.length === 0 && !(await dispositionReady(packetDir, application?.resourceDiscoveryDisposition))) {
      reasons.push(`Consent application ${application?.id || '(missing id)'} needs controlled resources or a named, evidenced discovery disposition.`);
    }
  }

  const primaryRoutes = new Set(
    arrayOrEmpty(routeMatrix?.primaryRoutes).map((route) => normalizeRouteKey(route?.targetPath)).filter(Boolean)
  );
  const checksByRoute = new Map(beforeChecks.map((check) => [normalizeRouteKey(check?.route), check]));
  for (const route of primaryRoutes) {
    const check = checksByRoute.get(route);
    if (!check || check.status !== 'pass' || check.browserContextFresh !== true || check.consentStorageCleared !== true) {
      reasons.push(`Installed consent needs a passing fresh before-consent browser check with storage cleared for ${route}.`);
      continue;
    }
    const evidencePath = resolveReviewEvidencePath(packetDir, join(packetDir, 'evidence'), check.evidence);
    if (!evidencePath) {
      reasons.push(`Before-consent check for ${route} needs packet-local evidence.`);
      continue;
    }
    try {
      const evidence = JSON.parse(await readFile(evidencePath, 'utf8'));
      const target = httpUrl(evidence?.targetBaseUrl);
      const declaredTarget = httpUrl(routeMatrix?.targetBaseUrl);
      if (
        evidence?.schemaVersion !== 'public-kit.before-consent-evidence.1' ||
        target?.origin !== declaredTarget?.origin ||
        normalizeRouteKey(evidence?.route) !== route ||
        evidence?.browserContextFresh !== true ||
        evidence?.consentStorageCleared !== true ||
        !timestampIsFresh(evidence?.checkedAt) ||
        JSON.stringify(arrayOrEmpty(evidence?.observedResourceUrls)) !== JSON.stringify(arrayOrEmpty(check.observedResourceUrls)) ||
        JSON.stringify(arrayOrEmpty(evidence?.blockedApplicationIds)) !== JSON.stringify(arrayOrEmpty(check.blockedApplicationIds))
      ) {
        reasons.push(`Before-consent evidence for ${route} is stale, target-mismatched, or inconsistent with its packet record.`);
      }
    } catch {
      reasons.push(`Before-consent evidence for ${route} must be valid JSON.`);
    }
  }
  return reasons;
}

async function packetCompletionReadiness(packetDir, gates, records) {
  const reasons = [];
  const markdownAssessment = await markdownCompletionReadiness(packetDir, records);
  if (!gates) {
    return {
      packetCompletionReady: false,
      reasons: ['Gate vocabulary could not be loaded.'],
      humanDecisionPresentationStatus: markdownAssessment.humanDecisionPresentationStatus,
      recordedHumanGateStatus: markdownAssessment.recordedHumanGateStatus
    };
  }

  for (const packetFile of arrayOrEmpty(gates.reviewPacketFiles)) {
    const packetPath = join(packetDir, packetFile);
    const templatePath = installedTemplatePath(packetFile);
    if (templatePath && existsSync(packetPath) && !LOCAL_COMPLETION_NON_AUTHORITY_FILES.has(packetFile)) {
      const [packetBytes, templateBytes] = await Promise.all([readFile(packetPath), readFile(templatePath)]);
      if (packetBytes.equals(templateBytes)) {
        reasons.push(`${packetFile} is unchanged from the shipped template.`);
      }
    }

    if (packetFile.endsWith('.json') && existsSync(packetPath)) {
      try {
        const shippedSentinels = templatePath
          ? templateEnumSentinels(JSON.parse(await readFile(templatePath, 'utf8')))
          : new Set();
        const unresolved = unresolvedEnumSentinels(
          JSON.parse(await readFile(packetPath, 'utf8')),
          shippedSentinels
        );
        if (unresolved.length > 0) {
          reasons.push(`${packetFile} still contains unresolved enum sentinels at ${unresolved.slice(0, 3).join(', ')}${unresolved.length > 3 ? ', ...' : ''}.`);
        }
      } catch {
        // Structural packet validation reports invalid JSON separately.
      }
    }
  }

  reasons.push(...markdownAssessment.reasons);

  const {
    blindAdversarialReview,
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    negativeRouteConsent,
    nextCycleVerification,
    parityReport,
    patternMap,
    routeMatrix,
    sourceAudit
  } = records;
  reasons.push(...await negativeRouteConsentReasons(packetDir, negativeRouteConsent, routeMatrix));
  reasons.push(...await independentStructuredGateReasons({
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    nextCycleVerification,
    packetDir,
    patternMap,
    routeMatrix,
    sourceAudit
  }));
  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes);
  const primaryRoutePaths = primaryRoutes.map((route) => normalizeRouteRequestKey(route?.targetPath)).filter(Boolean);
  const primarySourceRoutePaths = primaryRoutes.map((route) => normalizeRouteRequestKey(route?.sourcePath)).filter(Boolean);
  const primaryRouteRoles = new Map(
    primaryRoutes.map((route) => [normalizeRouteRequestKey(route?.targetPath), String(route?.routeRole ?? '').trim()])
  );
  const routeRows = arrayOrEmpty(routeMatrix?.routes);
  if (!String(routeMatrix?.sourceBaseUrl ?? '').trim() || !String(routeMatrix?.targetBaseUrl ?? '').trim()) {
    reasons.push('route-matrix.json must declare both sourceBaseUrl and targetBaseUrl.');
  }
  if (routeMatrix?.browserFirstRouteExpansion?.expansionComplete !== true) {
    reasons.push('route-matrix.json browser-first route expansion is not complete.');
  }
  if (routeMatrix?.homepageParity?.accepted !== true) {
    reasons.push('route-matrix.json homepage parity is not accepted.');
  }
  if (routeMatrix?.frontPageAliasDecision?.accepted !== true) {
    reasons.push('route-matrix.json front-page alias decision is not accepted.');
  }
  if (routeMatrix?.starterRouteCleanup?.accepted !== true) {
    reasons.push('route-matrix.json starter-route cleanup is not accepted.');
  }
  if (routeMatrix?.canvasPlaceholderDetection?.accepted !== true) {
    reasons.push('route-matrix.json Canvas placeholder disposition is not accepted.');
  }
  if (
    primaryRoutes.length === 0 ||
    primaryRoutes.some((route) =>
      !normalizeRouteRequestKey(route?.sourcePath) ||
      !normalizeRouteRequestKey(route?.targetPath) ||
      !ROUTE_ROLES.has(String(route?.routeRole ?? '').trim()) ||
      numericValue(route?.sourceStatus) >= 500 ||
      numericValue(route?.targetStatus) >= 500 ||
      route?.matchesBrowserRenderedSource !== true ||
      route?.accepted !== true ||
      !routeRows.some((row) =>
        normalizeRouteRequestKey(row?.sourcePath) === normalizeRouteRequestKey(route?.sourcePath) &&
        normalizeRouteRequestKey(row?.targetPath) === normalizeRouteRequestKey(route?.targetPath) &&
        String(row?.routeRole ?? '').trim() === String(route?.routeRole ?? '').trim()
      )
    )
  ) {
    reasons.push('Every primary route must have source/target paths, a valid routeRole matching its route row, browser-rendered source binding, and acceptance.');
  }
  if (
    routeMatrix?.homepageParity?.accepted === true &&
    (numericValue(routeMatrix.homepageParity.sourceStatus) >= 500 || numericValue(routeMatrix.homepageParity.targetStatus) >= 500)
  ) {
    reasons.push('route-matrix.json homepageParity cannot accept a declared 5xx source or target response.');
  }
  if (
    routeRows.length === 0 ||
    routeRows.some((route) => {
      const targetPath = normalizeRouteRequestKey(route?.targetPath);
      const targetFinalPath = normalizeRouteRequestKey(route?.targetFinalPath);
      const declaredServerError = numericValue(route?.sourceStatus) >= 500 || numericValue(route?.targetStatus) >= 500;
      const redirectContractValid = route?.expectedRedirect === true &&
        redirectStatus(route?.targetStatus) &&
        Boolean(targetFinalPath) &&
        targetFinalPath !== targetPath;
      const directContractValid = route?.expectedRedirect === false &&
        successfulStatus(route?.targetStatus) &&
        targetFinalPath === targetPath;
      return route?.accepted !== true ||
        !normalizeRouteRequestKey(route?.sourcePath) ||
        !targetPath ||
        !ROUTE_ROLES.has(String(route?.routeRole ?? '').trim()) ||
        declaredServerError ||
        (!redirectContractValid && !directContractValid);
    })
  ) {
    reasons.push('route-matrix.json route rows must declare a valid routeRole, be accepted, reject declared 5xx responses, and declare either a direct final 2xx path or an intentional initial 3xx redirect with its expected final path.');
  }
  const mappingContracts = [];
  for (const [index, route] of routeRows.entries()) {
    const sourceRequest = normalizeRouteRequestKey(route?.sourcePath);
    const targetRequest = normalizeRouteRequestKey(route?.targetPath);
    const expectedFinalRequest = normalizeRouteRequestKey(route?.targetFinalPath || route?.targetPath);
    if (sourceRequest && targetRequest && expectedFinalRequest && sourceRequest !== targetRequest) {
      mappingContracts.push({
        declaredIn: `routes[${index}]`,
        expectedFinalRequest,
        noRedirectDisposition: route?.noRedirectDisposition,
        sourceRequest
      });
    }
  }
  for (const [index, record] of substantiveObjects(routeMatrix?.sourceRouteDriftClassification).entries()) {
    const sourceRequest = normalizeRouteRequestKey(record?.sourcePath);
    const targetRequest = normalizeRouteRequestKey(record?.targetPath);
    if (record?.targetDisposition === 'redirect' && sourceRequest && targetRequest && sourceRequest !== targetRequest) {
      mappingContracts.push({
        declaredIn: `sourceRouteDriftClassification[${index}]`,
        expectedFinalRequest: targetRequest,
        noRedirectDisposition: record?.noRedirectDisposition,
        sourceRequest
      });
    }
  }
  let invalidNoRedirectDisposition = false;
  let conflictingMappingContract = false;
  const mappingContractsBySource = new Map();
  for (const contract of mappingContracts) {
    const rawDisposition = contract.noRedirectDisposition;
    const disposition = rawDisposition && typeof rawDisposition === 'object' && !Array.isArray(rawDisposition)
      ? {
          accepted: rawDisposition.accepted === true,
          acceptedBy: String(rawDisposition.acceptedBy ?? '').trim(),
          evidence: String(rawDisposition.evidence ?? '').trim(),
          rationale: String(rawDisposition.rationale ?? '').trim()
        }
      : null;
    if (rawDisposition !== undefined && rawDisposition !== null) {
      const evidencePresent = disposition
        ? await nonEmptyPacketEvidence(packetDir, disposition.evidence)
        : false;
      if (
        !disposition ||
        disposition.accepted !== true ||
        !disposition.acceptedBy ||
        !disposition.rationale ||
        !evidencePresent
      ) {
        invalidNoRedirectDisposition = true;
      }
    }
    const signature = JSON.stringify({
      expectedFinalRequest: contract.expectedFinalRequest,
      noRedirectDisposition: disposition
    });
    const existing = mappingContractsBySource.get(contract.sourceRequest);
    if (existing && existing.signature !== signature) {
      conflictingMappingContract = true;
    } else if (!existing) {
      mappingContractsBySource.set(contract.sourceRequest, {
        declaredIn: contract.declaredIn,
        signature
      });
    }
  }
  if (invalidNoRedirectDisposition) {
    reasons.push('route-matrix.json noRedirectDisposition exceptions must set accepted true, name acceptedBy, explain the rationale, and reference non-empty packet-local evidence.');
  }
  if (conflictingMappingContract) {
    reasons.push('route-matrix.json duplicate source path+query redirect mappings must fully agree on target path+query and noRedirectDisposition.');
  }
  const representedRouteRoles = new Set(primaryRouteRoles.values());
  const uncoveredRouteRoles = [...new Set(routeRows.map((route) => String(route?.routeRole ?? '').trim()))]
    .filter((role) => ROUTE_ROLES.has(role) && !representedRouteRoles.has(role));
  if (uncoveredRouteRoles.length > 0) {
    reasons.push(`route-matrix.json primaryRoutes must include a representative of every discovered routeRole; missing ${uncoveredRouteRoles.join(', ')}.`);
  }
  const frontPageRoute = routeRows.find((route) => normalizeRouteRequestKey(route?.targetPath) === '/');
  if (frontPageRoute && String(frontPageRoute.routeRole ?? '').trim() !== 'homepage') {
    reasons.push('route-matrix.json must classify the target front page with routeRole homepage.');
  }
  const rawSourceOriginLinkExceptions = arrayOrEmpty(routeMatrix?.sourceOriginLinkExceptions);
  const sourceOriginLinkExceptions = substantiveObjects(rawSourceOriginLinkExceptions);
  const declaredSourceUrl = httpUrl(routeMatrix?.sourceBaseUrl);
  const declaredTargetUrl = httpUrl(routeMatrix?.targetBaseUrl);
  const acceptedLinkReferrerRequests = new Set([
    ...routeRows.filter((route) => route?.accepted === true),
    ...substantiveObjects(routeMatrix?.targetRequiredRoutes).filter((route) => route?.accepted === true)
  ].flatMap((route) => [route?.targetPath, route?.targetFinalPath])
    .map(normalizeRouteRequestKey)
    .filter(Boolean));
  const exceptionPairs = new Set();
  let sourceOriginExceptionInvalid = rawSourceOriginLinkExceptions.some((exception) => !isJsonObject(exception));
  for (const exception of sourceOriginLinkExceptions) {
    let referrerUrl = null;
    try {
      referrerUrl = declaredTargetUrl
        ? new URL(String(exception?.referrer ?? ''), declaredTargetUrl)
        : null;
    } catch {
      // The aggregate completion reason below reports malformed exception URLs.
    }
    const exceptionTargetUrl = httpUrl(exception?.target);
    if (referrerUrl) {
      referrerUrl.hash = '';
    }
    if (exceptionTargetUrl) {
      exceptionTargetUrl.hash = '';
    }
    const pairKey = referrerUrl && exceptionTargetUrl
      ? `${referrerUrl.href}\n${exceptionTargetUrl.href}`
      : '';
    const referrerMatchesAcceptedRoute = Boolean(referrerUrl) &&
      acceptedLinkReferrerRequests.has(normalizeRouteRequestKey(referrerUrl?.href));
    const evidencePresent = await nonEmptyPacketEvidence(packetDir, exception?.evidence);
    if (
      exception?.accepted !== true ||
      !declaredSourceUrl ||
      !declaredTargetUrl ||
      !referrerUrl ||
      referrerUrl.origin !== declaredTargetUrl.origin ||
      !referrerMatchesAcceptedRoute ||
      !exceptionTargetUrl ||
      exceptionTargetUrl.origin !== declaredSourceUrl.origin ||
      !String(exception?.rationale ?? '').trim() ||
      !String(exception?.accepter ?? '').trim() ||
      !evidencePresent ||
      !pairKey ||
      exceptionPairs.has(pairKey)
    ) {
      sourceOriginExceptionInvalid = true;
    }
    if (pairKey) {
      exceptionPairs.add(pairKey);
    }
  }
  if (sourceOriginExceptionInvalid) {
    reasons.push('route-matrix.json sourceOriginLinkExceptions must uniquely bind an accepted target-route referrer to an absolute source-origin target with rationale, named accepter, non-empty packet-local evidence, and accepted true.');
  }
  const rawSameOriginLinkExceptions = arrayOrEmpty(routeMatrix?.sameOriginLinkExceptions);
  const sameOriginLinkExceptions = substantiveObjects(rawSameOriginLinkExceptions);
  const sameOriginExceptionPairs = new Set();
  let sameOriginExceptionInvalid = rawSameOriginLinkExceptions.some((exception) => !isJsonObject(exception));
  for (const exception of sameOriginLinkExceptions) {
    let referrerUrl = null;
    let exceptionTargetUrl = null;
    try {
      referrerUrl = declaredTargetUrl
        ? new URL(String(exception?.referrer ?? ''), declaredTargetUrl)
        : null;
      exceptionTargetUrl = declaredTargetUrl
        ? new URL(String(exception?.target ?? ''), declaredTargetUrl)
        : null;
    } catch {
      // The aggregate completion reason below reports malformed exception URLs.
    }
    if (referrerUrl) {
      referrerUrl.hash = '';
    }
    if (exceptionTargetUrl) {
      exceptionTargetUrl.hash = '';
    }
    const pairKey = referrerUrl && exceptionTargetUrl
      ? `${referrerUrl.href}\n${exceptionTargetUrl.href}`
      : '';
    const referrerMatchesAcceptedRoute = Boolean(referrerUrl) &&
      acceptedLinkReferrerRequests.has(normalizeRouteRequestKey(referrerUrl?.href));
    const evidencePresent = await nonEmptyPacketEvidence(packetDir, exception?.evidence);
    if (
      exception?.accepted !== true ||
      !declaredTargetUrl ||
      !referrerUrl ||
      referrerUrl.origin !== declaredTargetUrl.origin ||
      !referrerMatchesAcceptedRoute ||
      !exceptionTargetUrl ||
      exceptionTargetUrl.origin !== declaredTargetUrl.origin ||
      !SAME_ORIGIN_LINK_DISPOSITIONS.has(String(exception?.disposition ?? '').trim()) ||
      !String(exception?.rationale ?? '').trim() ||
      !String(exception?.accepter ?? '').trim() ||
      !evidencePresent ||
      !pairKey ||
      sameOriginExceptionPairs.has(pairKey)
    ) {
      sameOriginExceptionInvalid = true;
    }
    if (pairKey) {
      sameOriginExceptionPairs.add(pairKey);
    }
  }
  if (sameOriginExceptionInvalid) {
    reasons.push('route-matrix.json sameOriginLinkExceptions must uniquely bind an accepted target-route referrer to an exact same-origin target with an allowed disposition, rationale, named accepter, non-empty packet-local evidence, and accepted true.');
  }

  const rawExpectedExternalRedirects = arrayOrEmpty(routeMatrix?.expectedExternalLinkRedirects);
  const expectedExternalRedirects = substantiveObjects(rawExpectedExternalRedirects);
  const expectedExternalRedirectKeys = new Set();
  let expectedExternalRedirectInvalid = rawExpectedExternalRedirects.some((record) => !isJsonObject(record));
  for (const record of expectedExternalRedirects) {
    let referrerUrl = null;
    let startUrl = null;
    const finalUrl = httpUrl(record?.final);
    try {
      referrerUrl = declaredTargetUrl
        ? new URL(String(record?.referrer ?? ''), declaredTargetUrl)
        : null;
      startUrl = declaredTargetUrl
        ? new URL(String(record?.start ?? ''), declaredTargetUrl)
        : null;
    } catch {
      // The aggregate completion reason below reports malformed expectation URLs.
    }
    if (referrerUrl) {
      referrerUrl.hash = '';
    }
    if (startUrl) {
      startUrl.hash = '';
    }
    if (finalUrl) {
      finalUrl.hash = '';
    }
    const finalMatch = String(record?.finalMatch ?? '').trim();
    const expectationKey = referrerUrl && startUrl && finalUrl
      ? `${referrerUrl.href}\n${startUrl.href}\n${finalMatch}\n${finalUrl.href}`
      : '';
    const referrerMatchesAcceptedRoute = Boolean(referrerUrl) &&
      acceptedLinkReferrerRequests.has(normalizeRouteRequestKey(referrerUrl?.href));
    const originMatchUsesOriginOnly = finalMatch !== 'origin' || (
      finalUrl?.pathname === '/' && !finalUrl.search && !finalUrl.hash
    );
    const evidencePresent = await nonEmptyPacketEvidence(packetDir, record?.evidence);
    if (
      record?.accepted !== true ||
      !declaredTargetUrl ||
      !referrerUrl ||
      referrerUrl.origin !== declaredTargetUrl.origin ||
      !referrerMatchesAcceptedRoute ||
      !startUrl ||
      startUrl.origin !== declaredTargetUrl.origin ||
      !finalUrl ||
      finalUrl.origin === declaredTargetUrl.origin ||
      !EXTERNAL_REDIRECT_FINAL_MATCHES.has(finalMatch) ||
      !originMatchUsesOriginOnly ||
      !String(record?.rationale ?? '').trim() ||
      !String(record?.accepter ?? '').trim() ||
      !evidencePresent ||
      !expectationKey ||
      expectedExternalRedirectKeys.has(expectationKey)
    ) {
      expectedExternalRedirectInvalid = true;
    }
    if (expectationKey) {
      expectedExternalRedirectKeys.add(expectationKey);
    }
  }
  if (expectedExternalRedirectInvalid) {
    reasons.push('route-matrix.json expectedExternalLinkRedirects must uniquely bind an accepted target-route referrer and exact same-origin start URL to an external final origin or exact URL with rationale, named accepter, non-empty packet-local evidence, and accepted true.');
  }
  if (
    arrayOrEmpty(routeMatrix?.blockedRoutes).length > 0 ||
    arrayOrEmpty(routeMatrix?.missingSourceRoutes).length > 0 ||
    arrayOrEmpty(routeMatrix?.wrongPatternRoutes).length > 0
  ) {
    reasons.push('route-matrix.json still records blocked, missing, or wrong-pattern routes.');
  }

  const expansion = routeMatrix?.browserFirstRouteExpansion ?? {};
  const legacyRenderedLinkRoutes = [...new Set(arrayOrEmpty(expansion.candidateRoutesFromRenderedLinks)
    .map(routeLikeValue)
    .filter(Boolean))];
  const browserRenderedLinkRoutes = [...new Set(arrayOrEmpty(expansion.candidateRoutesFromBrowserRenderedLinks)
    .map(routeLikeValue)
    .filter(Boolean))];
  if (
    Object.hasOwn(expansion, 'candidateRoutesFromRenderedLinks') &&
    Object.hasOwn(expansion, 'candidateRoutesFromBrowserRenderedLinks') &&
    (
      legacyRenderedLinkRoutes.length !== browserRenderedLinkRoutes.length ||
      [...legacyRenderedLinkRoutes].sort().join('\n') !==
        [...browserRenderedLinkRoutes].sort().join('\n')
    )
  ) {
    reasons.push('route-matrix.json legacy candidateRoutesFromRenderedLinks and candidateRoutesFromBrowserRenderedLinks declarations must describe the same discovered routes when both are present.');
  }
  const discoveredSourceRoutes = new Set([
    ...arrayOrEmpty(expansion.browserRenderedSeedRoutes),
    ...legacyRenderedLinkRoutes,
    ...browserRenderedLinkRoutes,
    ...arrayOrEmpty(expansion.candidateRoutesFromBundles),
    ...arrayOrEmpty(expansion.candidateRoutesFromMetadata),
    ...arrayOrEmpty(expansion.candidateRoutesFromAssets),
    ...arrayOrEmpty(expansion.candidateRoutesFromSitemapsOrRobots),
    ...arrayOrEmpty(expansion.candidateRoutesFromImportedContentBodies),
    ...arrayOrEmpty(expansion.candidateRoutesFromNamingPatterns)
  ].map(routeLikeValue).filter(Boolean));
  const driftRecords = substantiveObjects(routeMatrix?.sourceRouteDriftClassification);
  const acceptedDriftRoutes = new Set(driftRecords.filter((record) =>
    record?.accepted === true &&
    normalizeRouteRequestKey(record.sourcePath) &&
    !['unknown'].includes(record.classification) &&
    !['blocked', 'owner_decision_required'].includes(record.targetDisposition) &&
    String(record.notes ?? '').trim()
  ).map((record) => normalizeRouteRequestKey(record.sourcePath)));
  if (
    driftRecords.some((record) => !acceptedDriftRoutes.has(normalizeRouteRequestKey(record.sourcePath))) ||
    [...discoveredSourceRoutes].some((route) =>
      !primarySourceRoutePaths.includes(route) && !acceptedDriftRoutes.has(route)
    )
  ) {
    reasons.push('route-matrix.json must classify and accept every discovered source route not included in the primary rebuild surface.');
  }

  const targetRequiredRoutes = substantiveObjects(routeMatrix?.targetRequiredRoutes);
  if (
    targetRequiredRoutes.length === 0 ||
    !targetRequiredRoutes.some((record) => normalizeRouteKey(record.targetPath) === '/') ||
    targetRequiredRoutes.some((record) =>
      !normalizeRouteKey(record.targetPath) ||
      !String(record.reasonRequired ?? '').trim() ||
      !finiteNumberValue(record.targetStatus) ||
      !normalizeRouteKey(record.targetFinalPath || record.targetPath) ||
      !String(record.drupalOwner ?? '').trim() ||
      record.accepted !== true ||
      record.expectedPublicBehavior === 'blocked' ||
      !expectedPublicBehaviorMatches(
        record.expectedPublicBehavior,
        record.targetStatus,
        record.targetFinalPath || record.targetPath,
        record.targetPath
      ) ||
      (record.expectedPublicBehavior === 'private_403' ? record.shouldBePublic !== false : record.shouldBePublic !== true)
    )
  ) {
    reasons.push('route-matrix.json must contain accepted target-required route records, including the front page, with consistent expectedPublicBehavior, non-5xx status, final path, visibility, and Drupal owner; blocked behavior cannot complete.');
  }

  const collectionLedger = substantiveObjects(patternMap?.structuredContentModel?.collectionOwnershipLedger);
  const recurringSourceObjects = substantiveObjects(patternMap?.structuredContentModel?.recurringSourceObjects);
  const publicRouteItemCounts = arrayOrEmpty(browserEvidence?.publicRouteChecks)
    .flatMap((check) => substantiveObjects(check?.renderedItemCounts));
  const collectionScope = patternMap?.structuredContentModel?.collectionScope ?? {};
  const discoveredCollectionEvidence = collectionLedger.length > 0 || recurringSourceObjects.some(
    (record) => String(record.collectionOwner ?? '').trim()
  ) || publicRouteItemCounts.length > 0;
  const collectionEvidenceRequired = collectionScope.applies === true;
  if (
    collectionScope.reviewed !== true ||
    typeof collectionScope.applies !== 'boolean' ||
    !String(collectionScope.reason ?? '').trim() ||
    (discoveredCollectionEvidence && collectionScope.applies !== true)
  ) {
    reasons.push('pattern-map.json must explicitly review collection applicability and align it with the discovered recurring-content evidence.');
  }
  const reconciliationRecords = substantiveObjects(routeMatrix?.perRouteItemReconciliation);
  if (
    (collectionEvidenceRequired && reconciliationRecords.length === 0) ||
    reconciliationRecords.some((record) =>
      !normalizeRouteKey(record.sourcePath) ||
      !normalizeRouteKey(record.targetPath) ||
      !String(record.itemType ?? '').trim() ||
      !finiteNumberValue(record.sourceCount) ||
      !finiteNumberValue(record.targetRenderedCount) ||
      !finiteNumberValue(record.targetDrupalEntityCount) ||
      !['none', 'owner_approved_exclusion', 'private_unreachable'].includes(record.mismatchDisposition) ||
      record.accepted !== true ||
      !String(record.notes ?? '').trim()
    ) ||
    publicRouteItemCounts.some((record) =>
      !finiteNumberValue(record.sourceCount) ||
      !finiteNumberValue(record.targetCount) ||
      record.accepted !== true
    )
  ) {
    reasons.push('route-matrix.json and browser-evidence.json must reconcile every in-scope repeated-item count with an accepted disposition.');
  }

  const firstFoldRecords = substantiveObjects(routeMatrix?.firstFoldBrandAssetParity);
  for (const route of primaryRoutes) {
    for (const viewport of ['desktop', 'mobile']) {
      if (!firstFoldRecords.some((record) =>
        recordMatchesRoute(record, normalizeRouteRequestKey(route.sourcePath), normalizeRouteRequestKey(route.targetPath)) &&
        record.viewport === viewport &&
        record.heroArtworkMatchesOrDispositioned === true &&
        record.logoOrLockupMatchesOrDispositioned === true &&
        record.signatureGraphicsMatchOrDispositioned === true &&
        record.primaryCtaTreatmentMatchesOrDispositioned === true &&
        record.accepted === true &&
        String(record.notes ?? '').trim()
      )) {
        reasons.push(`route-matrix.json needs accepted first-fold brand parity for ${normalizeRouteRequestKey(route.targetPath)} at ${viewport}.`);
      }
    }
  }

  const sourceRouteSummary = sourceAudit?.routeInventorySummary ?? {};
  if (
    isoTimestamp(sourceAudit?.checkedAt) === null ||
    !String(sourceAudit?.site?.name ?? '').trim() ||
    !httpUrl(sourceAudit?.site?.baseUrl) ||
    !hasMeaningfulEntry(sourceAudit?.representativeUrls) ||
    !hasMeaningfulEntry(sourceAudit?.evidencePoints) ||
    !hasMeaningfulEntry(sourceAudit?.contentInventory) ||
    !hasMeaningfulEntry(sourceAudit?.designSignals) ||
    Number(sourceRouteSummary.attemptedRoutes) < primaryRoutes.length ||
    Number(sourceRouteSummary.successfulRoutes) < primaryRoutes.length ||
    Number(sourceRouteSummary.successfulRoutes) > Number(sourceRouteSummary.attemptedRoutes)
  ) {
    reasons.push('source-audit.json must identify the source and record substantive URL, evidence, content, design, and successful-route capture.');
  }

  const acceptedPageOwners = arrayOrEmpty(patternMap?.pageCompositionOwnership).filter(
    (owner) =>
      owner?.accepted === true &&
      normalizeRouteRequestKey(owner?.sourceRoute) &&
      String(owner?.selectedOwner ?? '').trim() &&
      String(owner?.ownerRationale ?? '').trim() &&
      String(owner?.editorVerificationEvidence ?? '').trim()
  );
  const acceptedCollectionOwners = collectionLedger.filter((record) =>
    record?.accepted === true &&
    normalizeRouteKey(record?.sourceRoute) &&
    String(record?.sourceObject ?? '').trim() &&
    finiteNumberValue(record?.sourceItemCount) &&
    String(record?.drupalEntityType ?? '').trim() &&
    String(record?.contentTypeOrBundle ?? '').trim() &&
    hasMeaningfulEntry(record?.requiredFields) &&
    String(record?.collectionOwner ?? '').trim() &&
    String(record?.viewDisplayOrConfig ?? '').trim() &&
    String(record?.detailRouteOwner ?? '').trim() &&
    String(record?.editorAddRowEvidence ?? '').trim()
  );
  const acceptedRecurringObjects = recurringSourceObjects.filter((record) =>
    record?.accepted === true &&
    String(record?.sourceObject ?? '').trim() &&
    String(record?.drupalOwner ?? '').trim() &&
    String(record?.bundleOrConfigName ?? '').trim() &&
    hasMeaningfulEntry(record?.requiredFields) &&
    record?.editorVerification?.nonAdminEditorCanCreate === true &&
    record?.editorVerification?.appearsInPublicListingOrDetailWithoutCodeChange === true &&
    String(record?.editorVerification?.evidence ?? '').trim()
  );
  const buildType = String(patternMap?.buildTypeDeclaration?.type ?? '');
  const canvasEvidenceRequired = /canvas|experience_builder/.test(buildType) && !/canvas_unused/.test(buildType);
  const canvasModels = substantiveObjects(patternMap?.compositionModel?.canvasComponentModel);
  if (
    isoTimestamp(patternMap?.checkedAt) === null ||
    !String(patternMap?.sourceSite ?? '').trim() ||
    !hasMeaningfulEntry(patternMap?.contentTypes) ||
    !hasMeaningfulEntry(patternMap?.fields) ||
    patternMap?.buildTypeDeclaration?.accepted !== true ||
    !String(patternMap?.buildTypeDeclaration?.type ?? '').trim() ||
    patternMap?.compositionModel?.completedBeforeImplementation !== true ||
    patternMap?.contentTypeLabelPolicy?.accepted !== true ||
    patternMap?.reviewStatus !== 'reviewed' ||
    arrayOrEmpty(patternMap?.structuredContentModel?.blockers).length > 0 ||
    recurringSourceObjects.length !== acceptedRecurringObjects.length ||
    (collectionEvidenceRequired && (
      acceptedCollectionOwners.length === 0 || acceptedCollectionOwners.length !== collectionLedger.length
    )) ||
    !String(patternMap?.seoMetadata?.strategy ?? '').trim() ||
    !hasMeaningfulEntry(patternMap?.seoMetadata?.canonicalDecisions) ||
    arrayOrEmpty(patternMap?.seoMetadata?.blockedEvidence).length > 0 ||
    (canvasEvidenceRequired && (
      canvasModels.length === 0 ||
      canvasModels.some((model) =>
        model?.accepted !== true ||
        model?.canvasOwnerDeclared !== true ||
        !hasMeaningfulEntry(model?.componentList) ||
        model?.repeatableSectionsUseDrupalOwnedData !== true ||
        model?.oneMonolithicComponentRejected !== true ||
        model?.jsonOrNewlineBlobPropsRejected !== true ||
        model?.hardcodedPublicCopyRejected !== true ||
        model?.componentInventoryMatchesDeclaration !== true
      )
    )) ||
    primaryRoutes.some(
      (route) => !acceptedPageOwners.some((owner) =>
        normalizeRouteRequestKey(owner.sourceRoute) === normalizeRouteRequestKey(route.sourcePath)
      )
    ) ||
    !arrayOrEmpty(patternMap?.sectionOwnershipMatrix).some(
      (section) =>
        section?.accepted === true &&
        normalizeRouteKey(section?.sourceRoute) &&
        String(section?.section ?? '').trim() &&
        String(section?.drupalOwner ?? '').trim() &&
        String(section?.expectedEditorAction ?? '').trim() &&
        String(section?.acceptanceProof ?? '').trim()
    )
  ) {
    reasons.push('pattern-map.json must record reviewed Drupal structures plus accepted route composition and section ownership with editor proof.');
  }

  const fieldBundles = arrayOrEmpty(fieldOutputMatrix?.bundles);
  const fieldRecords = fieldBundles.flatMap((bundle) => arrayOrEmpty(bundle?.fields));
  if (
    !String(fieldOutputMatrix?.site ?? '').trim() ||
    isoTimestamp(fieldOutputMatrix?.checkedAt) === null ||
    fieldBundles.length === 0 ||
    fieldBundles.some(
      (bundle) =>
        !String(bundle?.entityType ?? '').trim() ||
        !String(bundle?.bundle ?? '').trim() ||
        arrayOrEmpty(bundle?.fields).length === 0
    ) ||
    fieldRecords.some(
      (field) =>
        !String(field?.machineName ?? '').trim() ||
        !String(field?.editorLabel ?? '').trim() ||
        !String(field?.fieldType ?? '').trim() ||
        !String(field?.widget ?? '').trim() ||
        !String(field?.formatter ?? '').trim() ||
        !String(field?.presentationBoundary ?? '').trim() ||
        field?.accepted !== true
    ) ||
    !fieldRecords.some((field) => field?.affectsAnonymousOutput === true) ||
    arrayOrEmpty(fieldOutputMatrix?.blockedFields).length > 0
  ) {
    reasons.push('field-output-matrix.json must contain checked, accepted bundle fields and at least one field proven to affect anonymous output.');
  }

  const parityRouteChecks = arrayOrEmpty(parityReport?.routeChecks);
  const parityContentChecks = substantiveObjects(parityReport?.contentChecks);
  const parityVisualChecks = substantiveObjects(parityReport?.visualChecks);
  const parityFunctionalChecks = substantiveObjects(parityReport?.functionalChecks);
  const functionalScope = parityReport?.functionalScope ?? {};
  const discoveredFunctionalEvidence = hasMeaningfulEntry(sourceAudit?.functionalSignals) ||
    hasMeaningfulEntry(sourceAudit?.formsAndIntegrations);
  const functionalParityRequired = functionalScope.applies === true;
  if (
    isoTimestamp(parityReport?.checkedAt) === null ||
    functionalScope.reviewed !== true ||
    typeof functionalScope.applies !== 'boolean' ||
    !String(functionalScope.reason ?? '').trim() ||
    (discoveredFunctionalEvidence && functionalScope.applies !== true) ||
    parityReport?.verdict !== 'pass' ||
    Number(parityReport?.addressableSurface?.routesInScope) < primaryRoutes.length ||
    parityRouteChecks.length === 0 ||
    primaryRoutePaths.some(
      (route) => !parityRouteChecks.some((check) =>
        routeRecordRequestKey(check) === route && check?.status === 'pass' && String(check?.evidence ?? '').trim()
      )
    ) ||
    parityContentChecks.length === 0 ||
    parityContentChecks.some((check) =>
      check?.status !== 'pass' || !String(check?.sourceExpectation ?? '').trim() ||
      !String(check?.targetObservation ?? '').trim() || !String(check?.evidence ?? '').trim()
    ) ||
    parityVisualChecks.length === 0 ||
    parityVisualChecks.some((check) =>
      check?.status !== 'pass' || !String(check?.sourceExpectation ?? '').trim() ||
      !String(check?.targetObservation ?? '').trim() || !String(check?.evidence ?? '').trim()
    ) ||
    (functionalParityRequired && parityFunctionalChecks.length === 0) ||
    parityFunctionalChecks.some((check) =>
      !['pass', 'not_applicable'].includes(check?.status) ||
      !String(check?.sourceExpectation ?? '').trim() ||
      !String(check?.targetObservation ?? '').trim() ||
      !String(check?.evidence ?? '').trim()
    ) ||
    !hasMeaningfulEntry(parityReport?.browserEvidence) ||
    arrayOrEmpty(parityReport?.blockedEvidence).length > 0
  ) {
    reasons.push('parity-report.json must pass with populated route checks, complete scope, and no blocked evidence.');
  }

  const publicRouteChecks = arrayOrEmpty(browserEvidence?.publicRouteChecks);
  if (publicRouteChecks.some((check) => !VISUAL_COMPARISON_METHODS.has(check?.visualComparison?.method))) {
    reasons.push('browser-evidence.json visualComparison.method must be agent_review, human_review, pixel_diff, structural_review, or other for every public route check.');
  }
  if (publicRouteChecks.some((check) =>
    VISUAL_COMPARISON_METHODS.has(check?.visualComparison?.method) &&
    !COMPLETION_VISUAL_COMPARISON_METHODS.has(check.visualComparison.method)
  )) {
    reasons.push('browser-evidence.json completion-bearing visualComparison.method must be agent_review, human_review, or pixel_diff; structural_review and other are diagnostic-only classifications.');
  }
  if (publicRouteChecks.some((check) =>
    check?.visualComparison?.method === 'human_review' &&
    !String(check?.visualComparison?.reviewer ?? '').trim()
  )) {
    reasons.push('browser-evidence.json visualComparison method human_review requires a recorded reviewer label; the local verifier reports that label as self-attested and does not authenticate it. Record agent_review for agent-performed structural comparison.');
  }
  if (publicRouteChecks.some((check) =>
    check?.visualComparison?.method === 'pixel_diff' &&
    (!String(check?.visualComparison?.diffImage ?? '').trim() || !finiteNumberValue(check?.visualComparison?.diffScore))
  )) {
    reasons.push('browser-evidence.json visualComparison method pixel_diff requires a diffImage and numeric diffScore.');
  }
  let browserScreenshotsCredible = true;
  let visualMethodEvidenceCredible = true;
  const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
  for (const [index, check] of publicRouteChecks.entries()) {
    const screenshotMetadata = {};
    for (const field of ['sourceScreenshot', 'targetScreenshot']) {
      const screenshotPath = resolveReviewEvidencePath(packetDir, browserEvidenceDir, check?.[field]);
      const metadata = screenshotPath ? await evidenceImageMetadata(screenshotPath) : null;
      screenshotMetadata[field] = metadata;
      if (
        !metadata ||
        metadata.size < MIN_SCREENSHOT_BYTES ||
        metadata.width < MIN_SCREENSHOT_DIMENSION ||
        metadata.height < MIN_SCREENSHOT_DIMENSION
      ) {
        browserScreenshotsCredible = false;
      }
    }
    reasons.push(...await accessibilityCheckReasons(packetDir, browserEvidenceDir, check, index));
    if (check?.visualComparison?.method === 'pixel_diff') {
      const diffPath = resolveReviewEvidencePath(
        packetDir,
        browserEvidenceDir,
        check.visualComparison.diffImage
      );
      const diffMetadata = diffPath ? await evidenceImageMetadata(diffPath) : null;
      if (
        !diffMetadata ||
        diffMetadata.size < MIN_SCREENSHOT_BYTES ||
        diffMetadata.width < MIN_SCREENSHOT_DIMENSION ||
        diffMetadata.height < MIN_SCREENSHOT_DIMENSION ||
        diffMetadata.contentSha256 === screenshotMetadata.sourceScreenshot?.contentSha256 ||
        diffMetadata.contentSha256 === screenshotMetadata.targetScreenshot?.contentSha256 ||
        diffMetadata.width !== screenshotMetadata.sourceScreenshot?.width ||
        diffMetadata.height !== screenshotMetadata.sourceScreenshot?.height ||
        diffMetadata.width !== screenshotMetadata.targetScreenshot?.width ||
        diffMetadata.height !== screenshotMetadata.targetScreenshot?.height
      ) {
        visualMethodEvidenceCredible = false;
      }
    }
  }
  if (!visualMethodEvidenceCredible) {
    reasons.push('browser-evidence.json pixel_diff visual comparisons require a distinct real bounded packet-local diff image with source/target dimensions.');
  }
  if (
    isoTimestamp(browserEvidence?.checkedAt) === null ||
    browserEvidence?.browserEvidenceComplete !== true ||
    arrayOrEmpty(browserEvidence?.missingBrowserEvidence).length > 0 ||
    publicRouteChecks.length === 0 ||
    !browserScreenshotsCredible ||
    !visualMethodEvidenceCredible ||
    publicRouteChecks.some((check) =>
      check?.accepted !== true ||
      !ROUTE_ROLES.has(String(check?.routeRole ?? '').trim()) ||
      (primaryRouteRoles.has(routeRecordRequestKey(check)) &&
        primaryRouteRoles.get(routeRecordRequestKey(check)) !== String(check?.routeRole ?? '').trim()) ||
      !COMPLETION_VISUAL_COMPARISON_METHODS.has(check?.visualComparison?.method) ||
      check?.visualComparison?.status !== 'pass' ||
      !httpUrl(check?.sourceUrl) ||
      !httpUrl(check?.sourceFinalUrl) ||
      !httpUrl(check?.targetUrl) ||
      !httpUrl(check?.targetFinalUrl) ||
      !String(check?.sourceScreenshot ?? '').trim() ||
      !String(check?.targetScreenshot ?? '').trim() ||
      !(String(check?.renderedSignals?.sourceTitle ?? '').trim() || String(check?.renderedSignals?.sourceH1 ?? '').trim()) ||
      !(String(check?.renderedSignals?.targetTitle ?? '').trim() || String(check?.renderedSignals?.targetH1 ?? '').trim()) ||
      check?.renderedSignals?.sectionOrderMatches !== true ||
      check?.renderedSignals?.headerFooterTreatmentMatches !== true ||
      check?.renderedSignals?.typographySpacingMatches !== true ||
      check?.renderedSignals?.mediaPlacementMatches !== true ||
      check?.renderedSignals?.sourceLikeBehaviorMatches !== true ||
      !String(check?.firstFoldBrandAssetSignals?.sourceHeroArtwork ?? '').trim() ||
      !String(check?.firstFoldBrandAssetSignals?.targetHeroArtwork ?? '').trim() ||
      !String(check?.firstFoldBrandAssetSignals?.sourceLogoOrLockup ?? '').trim() ||
      !String(check?.firstFoldBrandAssetSignals?.targetLogoOrLockup ?? '').trim() ||
      check?.firstFoldBrandAssetSignals?.primaryCtaTreatmentMatches !== true ||
      arrayOrEmpty(check?.firstFoldBrandAssetSignals?.brandDefiningAssetsMissingOrApproximated).length > 0 ||
      arrayOrEmpty(check?.blockers).length > 0
    ) ||
    primaryRoutePaths.some(
      (route) => !routeHasViewport(publicRouteChecks, route, 'desktop') || !routeHasViewport(publicRouteChecks, route, 'mobile')
    )
  ) {
    reasons.push('browser-evidence.json must cover every primary route at desktop and mobile with accepted source/target visual and rendered-signal evidence.');
  }
  const renderedSeoRoutes = new Set();
  const renderedSeoRoutePaths = new Set();
  for (const check of publicRouteChecks) {
    const seo = check?.renderedSeoSignals ?? {};
    if (
      seo.accepted === true &&
      httpUrl(seo.targetCanonicalUrl) &&
      ['present', 'not_applicable'].includes(seo.metaDescriptionStatus) &&
      ['present', 'not_applicable'].includes(seo.openGraphImageStatus) &&
      (seo.metaDescriptionStatus !== 'present' || String(seo.targetMetaDescription ?? '').trim()) &&
      (seo.openGraphImageStatus !== 'present' || httpUrl(seo.targetOpenGraphImage)) &&
      (seo.metaDescriptionStatus !== 'not_applicable' || (
        seo.metaDescriptionApplicabilityReviewed === true &&
        String(seo.metaDescriptionNotApplicableRationale ?? '').trim()
      )) &&
      (seo.openGraphImageStatus !== 'not_applicable' || (
        seo.openGraphImageApplicabilityReviewed === true &&
        String(seo.openGraphImageNotApplicableRationale ?? '').trim()
      )) &&
      String(seo.evidence ?? '').trim()
    ) {
      renderedSeoRoutes.add(routeRecordRequestKey(check));
      renderedSeoRoutePaths.add(routeRecordPath(check));
    }
  }
  if (primaryRoutePaths.some((route) => !renderedSeoRoutes.has(route))) {
    reasons.push('browser-evidence.json must contain accepted rendered canonical, description, and social-image dispositions for every primary route.');
  }

  const acceptedCollections = collectionLedger.filter((record) => record?.accepted === true);
  for (const ledger of acceptedCollections) {
    const mode = String(ledger?.detailRouteMode ?? '');
    if (!['separate_public_route', 'inline_in_collection', 'external_provider', 'no_detail'].includes(mode)) {
      reasons.push(`pattern-map.json collection ${ledger.sourceObject || ledger.sourceRoute || '(unnamed)'} must declare detailRouteMode.`);
      continue;
    }
    if (mode !== 'separate_public_route') {
      if (!String(ledger?.detailRouteRationale ?? '').trim()) {
        reasons.push(`pattern-map.json collection ${ledger.sourceObject || ledger.sourceRoute || '(unnamed)'} needs a rationale for detailRouteMode ${mode}.`);
      }
      continue;
    }
    const sourceDetail = normalizeRouteKey(ledger?.representativeDetailSourcePath);
    const targetDetail = normalizeRouteKey(ledger?.representativeDetailTargetPath);
    const expectedFields = detailExpectedFields(ledger, fieldOutputMatrix, recurringSourceObjects);
    const declaredDetailFields = new Set(
      arrayOrEmpty(ledger?.detailLoadBearingFields).map((field) => identityKey(field)).filter(Boolean)
    );
    const matchingRoute = routeRows.find((route) =>
      normalizeRouteKey(route?.sourcePath) === sourceDetail &&
      normalizeRouteKey(route?.targetPath) === targetDetail &&
      route?.accepted === true
    );
    const detailCheck = publicRouteChecks.find((check) =>
      check?.routeRole === 'detail' &&
      normalizeRouteKey(httpUrl(check?.sourceUrl)?.pathname) === sourceDetail &&
      routeRecordPath(check) === targetDetail &&
      check?.accepted === true
    );
    const detailSignals = detailCheck?.detailContentSignals ?? {};
    const actualFields = arrayOrEmpty(detailSignals?.loadBearingFields);
    const fieldsDeclared = expectedFields.length > 0 && expectedFields.every((field) =>
      declaredDetailFields.has(identityKey(field))
    );
    const verifiedFieldRecords = expectedFields.map((field) =>
      actualFields.find((record) =>
        exactIdentityMatch(record?.field, field) &&
        record?.visible === true &&
        String(record?.sourceSignal ?? '').trim() &&
        String(record?.targetSignal ?? '').trim() &&
        detailFieldVisible(record)
      )
    );
    const verifiedSelectors = verifiedFieldRecords
      .map((record) => String(record?.selector ?? '').trim())
      .filter(Boolean);
    const fieldsVerified = fieldsDeclared &&
      verifiedFieldRecords.every(Boolean) &&
      new Set(verifiedSelectors).size === expectedFields.length;
    const ownerDeviation = detailSignals?.ownerDeviation ?? {};
    const ownerDeviationEvidencePresent = ownerDeviation?.applies === true && await nonEmptyPacketEvidence(
      packetDir,
      ownerDeviation?.evidence,
      browserEvidenceDir
    );
    const detailOwnerMatches = exactIdentityMatch(detailSignals?.drupalOwner, ledger?.detailRouteOwner);
    const detailOwnerConfigMatches = exactIdentityMatch(
      detailSignals?.drupalOwnerConfigId,
      ledger?.drupalOwnerConfigId
    ) && drupalOwnerConfigExists(
      drupalReadback,
      ledger?.detailRouteOwner,
      ledger?.drupalOwnerConfigId
    );
    const detailOwnerDeviationAccepted = Boolean(
      String(detailSignals?.drupalOwner ?? '').trim() &&
      ownerDeviation?.applies === true &&
      String(ownerDeviation?.rationale ?? '').trim() &&
      ownerDeviationEvidencePresent
    );
    if (detailCheck && (!detailOwnerMatches || !detailOwnerConfigMatches) && !detailOwnerDeviationAccepted) {
      reasons.push(`browser-evidence.json detail owner/config must match Drupal readback and collection ${ledger.sourceObject || ledger.sourceRoute || '(unnamed)'} owner ${ledger.detailRouteOwner || '(missing)'}, or record an evidenced owner deviation.`);
    }
    if (
      !sourceDetail ||
      !targetDetail ||
      !matchingRoute ||
      !detailCheck ||
      detailSignals?.accepted !== true ||
      !exactIdentityMatch(detailSignals?.contentTypeOrBundle, ledger?.contentTypeOrBundle) ||
      (!detailOwnerMatches && !detailOwnerDeviationAccepted) ||
      (!detailOwnerConfigMatches && !detailOwnerDeviationAccepted) ||
      !fieldsVerified ||
      !renderedSeoRoutePaths.has(targetDetail)
    ) {
      reasons.push(`browser-evidence.json must prove an accepted representative detail route with visible load-bearing fields and rendered SEO for collection ${ledger.sourceObject || ledger.sourceRoute || '(unnamed)'}.`);
    }
  }

  const sourcePublicForms = substantiveObjects(sourceAudit?.formsAndIntegrations).filter((record) =>
    record?.kind === 'public_submission_form' && record?.anonymousPublicUse === true
  );
  const modeledForms = substantiveObjects(patternMap?.forms);
  const anonymousFormChecks = substantiveObjects(browserEvidence?.anonymousFormChecks);
  if (
    (sourcePublicForms.length > 0 || modeledForms.length > 0 || anonymousFormChecks.length > 0) &&
    (!uniqueRecordKeys(sourcePublicForms, 'formKey') ||
      !uniqueRecordKeys(modeledForms, 'formKey') ||
      !uniqueRecordKeys(anonymousFormChecks, 'formKey'))
  ) {
    reasons.push('Anonymous public forms must use unique, non-empty formKey values in source-audit.json, pattern-map.json, and browser-evidence.json.');
  }
  if (sourcePublicForms.some((sourceForm) => {
    const form = modeledForms.find((candidate) =>
      String(candidate?.formKey ?? '').trim() === String(sourceForm?.formKey ?? '').trim()
    );
    return !form ||
      form?.accepted !== true ||
      normalizeRouteKey(form?.sourceRoute) !== normalizeRouteKey(sourceForm?.sourceRoute) ||
      !exactIdentityMatch(form?.purpose, sourceForm?.purpose) ||
      String(form?.expectedOutcome ?? '') !== String(sourceForm?.expectedOutcome ?? '') ||
      !String(form?.drupalOwner ?? '').trim();
  })) {
    reasons.push('pattern-map.json must map every audited anonymous public submission form without changing its source purpose or expectedOutcome, and must name its accepted Drupal/provider owner.');
  }
  for (const form of modeledForms) {
    const formKey = String(form?.formKey ?? '').trim();
    const sourceRoute = normalizeRouteKey(form?.sourceRoute);
    const targetRoute = normalizeRouteKey(form?.targetRoute);
    const expectedOutcome = String(form?.expectedOutcome ?? '');
    const sourceForm = sourcePublicForms.find((candidate) =>
      String(candidate?.formKey ?? '').trim() === formKey
    );
    const check = anonymousFormChecks.find((candidate) =>
      String(candidate?.formKey ?? '').trim() === formKey
    );
    const routeRecord = routeRows.find((candidate) =>
      normalizeRouteKey(candidate?.targetPath) === targetRoute && candidate?.accepted === true
    );
    const browserFormCheck = publicRouteChecks.find((candidate) =>
      candidate?.routeRole === 'form' && routeRecordPath(candidate) === targetRoute && candidate?.accepted === true
    );
    const outcomeEvidenceMatches = check && await formOutcomeEvidenceMatches(
      packetDir,
      browserEvidenceDir,
      check
    );
    const abuseProtectionMode = String(check?.abuseProtection?.mode ?? '');
    const abuseProtectionEvidenceMatches = check && await formAbuseEvidenceMatches(
      packetDir,
      browserEvidenceDir,
      check
    );
    if (check && (
      !exactIdentityMatch(check?.purpose, form?.purpose) ||
      !exactIdentityMatch(check?.drupalOwner, form?.drupalOwner)
    )) {
      reasons.push(`browser-evidence.json anonymous form ${form.sourceRoute || form.targetRoute || '(unnamed)'} must preserve the modeled purpose and Drupal/provider owner.`);
    }
    if (
      form?.accepted !== true ||
      !formKey ||
      !sourceForm ||
      !sourceRoute ||
      !targetRoute ||
      !String(form?.purpose ?? '').trim() ||
      !String(form?.drupalOwner ?? '').trim() ||
      !['message_delivery', 'submission_storage', 'account_creation', 'provider_handoff', 'other'].includes(expectedOutcome) ||
      !routeRecord ||
      !browserFormCheck ||
      !check ||
      normalizeRouteKey(check?.sourceRoute) !== sourceRoute ||
      routeRecordPath(check) !== targetRoute ||
      check?.accepted !== true ||
      check?.status !== 'pass' ||
      check?.anonymousSession !== true ||
      check?.syntheticTestData !== true ||
      check?.invalidSubmission?.performed !== true ||
      check?.invalidSubmission?.errorsVisible !== true ||
      check?.invalidSubmission?.focusOrSummaryVerified !== true ||
      check?.validSubmission?.performed !== true ||
      check?.validSubmission?.successStateVisible !== true ||
      !formOutcomeMatches(expectedOutcome, check?.outcome?.mode) ||
      !outcomeEvidenceMatches ||
      !['rendered_honeypot', 'rendered_challenge', 'configured_rate_limiting', 'provider_managed', 'local_only_exception'].includes(abuseProtectionMode) ||
      check?.abuseProtection?.dispositionVerified !== true ||
      !abuseProtectionEvidenceMatches ||
      (abuseProtectionMode === 'local_only_exception' && !String(check?.abuseProtection?.rationale ?? '').trim()) ||
      arrayOrEmpty(check?.blockers).length > 0
    ) {
      reasons.push(`browser-evidence.json must prove anonymous invalid and valid submissions plus an outcome-appropriate handler for form ${form.sourceRoute || form.targetRoute || '(unnamed)'}; it must also record a vendor-neutral abuse-protection disposition with evidence.`);
    }
  }
  if (anonymousFormChecks.some((check) => !modeledForms.some((form) =>
    String(form?.formKey ?? '').trim() === String(check?.formKey ?? '').trim() &&
    normalizeRouteKey(form?.sourceRoute) === normalizeRouteKey(check?.sourceRoute) &&
    normalizeRouteKey(form?.targetRoute) === routeRecordPath(check)
  ))) {
    reasons.push('browser-evidence.json anonymousFormChecks must map to pattern-map.json forms.');
  }
  const editorWorkflowChecks = arrayOrEmpty(browserEvidence?.editorWorkflowChecks);
  let editorScreenshotsCredible = true;
  for (const check of editorWorkflowChecks) {
    for (const field of ['formScreenshot', 'resultScreenshot']) {
      const screenshotPath = resolveReviewEvidencePath(packetDir, browserEvidenceDir, check?.[field]);
      const metadata = screenshotPath ? await evidenceImageMetadata(screenshotPath) : null;
      if (
        !metadata ||
        metadata.size < MIN_SCREENSHOT_BYTES ||
        metadata.width < MIN_SCREENSHOT_DIMENSION ||
        metadata.height < MIN_SCREENSHOT_DIMENSION
      ) {
        editorScreenshotsCredible = false;
      }
    }
  }
  if (
    editorWorkflowChecks.length === 0 ||
    !editorScreenshotsCredible ||
    editorWorkflowChecks.some((check) =>
      check?.accepted !== true ||
      check?.status !== 'pass' ||
      !String(check?.editorUser ?? '').trim() ||
      privilegedEditorIdentity(check?.editorUser) ||
      !String(check?.editorRole ?? '').trim() ||
      privilegedEditorIdentity(check?.editorRole) ||
      !String(check?.drupalRoute ?? '').trim() ||
      !String(check?.taskPerformed ?? '').trim() ||
      !String(check?.formScreenshot ?? '').trim() ||
      !String(check?.resultScreenshot ?? '').trim() ||
      !hasMeaningfulEntry(check?.fieldsAndWidgetsVerified) ||
      !String(check?.publicOutputAffected ?? '').trim() ||
      !String(check?.visualOrBehaviorResult ?? '').trim() ||
      arrayOrEmpty(check?.blockers).length > 0
    )
  ) {
    reasons.push('browser-evidence.json must include an accepted passing non-admin editor workflow with no blockers.');
  }

  const surfaceReconciliation = drupalReadback?.liveSurfaceReconciliation ?? {};
  const surfaceDeclarations = arrayOrEmpty(surfaceReconciliation.declarations);
  const surfaceExclusions = arrayOrEmpty(surfaceReconciliation.exclusions);
  const surfaceKeys = [...surfaceDeclarations, ...surfaceExclusions]
    .map((record) => String(record?.key ?? '').trim())
    .filter(Boolean);
  let surfaceReconciliationReady =
    surfaceReconciliation.schemaVersion === 'public-kit.live-surface-reconciliation.1' &&
    HASH_RE.test(String(surfaceReconciliation.inventoryFingerprint ?? '')) &&
    isJsonObject(surfaceReconciliation.countsByKind) &&
    Object.keys(surfaceReconciliation.countsByKind).length > 0 &&
    Object.entries(surfaceReconciliation.countsByKind).every(([kind, count]) =>
      /^[a-z][a-z0-9_]*$/.test(kind) && Number.isSafeInteger(Number(count)) && Number(count) >= 0
    ) &&
    surfaceReconciliation.reconciliationComplete === true &&
    arrayOrEmpty(surfaceReconciliation.blockers).length === 0 &&
    surfaceKeys.length > 0 &&
    surfaceKeys.length === new Set(surfaceKeys).size;
  for (const declaration of surfaceDeclarations) {
    const references = arrayOrEmpty(declaration?.packetReferences);
    if (
      !String(declaration?.key ?? '').trim() ||
      !String(declaration?.kind ?? '').trim() ||
      references.length === 0
    ) {
      surfaceReconciliationReady = false;
      continue;
    }
    for (const reference of references) {
      const text = String(reference ?? '').trim();
      const hashIndex = text.indexOf('#');
      const artifact = hashIndex === -1 ? '' : text.slice(0, hashIndex);
      const fragment = hashIndex === -1 ? '' : text.slice(hashIndex + 1);
      const artifactPath = artifact
        ? resolveReviewEvidencePath(packetDir, packetDir, artifact)
        : '';
      if (
        !fragment ||
        (artifact === 'drupal-readback.json' && fragment.startsWith('liveSurfaceReconciliation')) ||
        !artifactPath ||
        !(await nonEmptyPacketEvidence(packetDir, artifact, packetDir))
      ) {
        surfaceReconciliationReady = false;
      }
    }
  }
  for (const exclusion of surfaceExclusions) {
    const evidence = arrayOrEmpty(exclusion?.evidence);
    if (
      !String(exclusion?.key ?? '').trim() ||
      !String(exclusion?.kind ?? '').trim() ||
      !String(exclusion?.owner ?? '').trim() ||
      !String(exclusion?.rationale ?? '').trim() ||
      evidence.length === 0
    ) {
      surfaceReconciliationReady = false;
      continue;
    }
    for (const reference of evidence) {
      if (!String(reference ?? '').startsWith('evidence/') || !(await nonEmptyPacketEvidence(packetDir, reference))) {
        surfaceReconciliationReady = false;
      }
    }
  }
  if (!surfaceReconciliationReady) {
    reasons.push('drupal-readback.json liveSurfaceReconciliation must contain a fingerprint-bound exact census with unique declarations or named evidence-backed exclusions.');
  }

  const drupalCommands = arrayOrEmpty(drupalReadback?.commands).map((command) => String(command));
  const drupalContent = drupalReadback?.content ?? {};
  const drupalRouting = drupalReadback?.routing ?? {};
  if (
    drupalReadback?.readbackComplete !== true ||
    arrayOrEmpty(drupalReadback?.blockers).length > 0 ||
    !String(drupalReadback?.site ?? '').trim() ||
    isoTimestamp(drupalReadback?.checkedAt) === null ||
    !drupalCommands.some((command) => /(?:^|\s)(?:drush\s+)?status(?:\s|$)/i.test(command)) ||
    !drupalCommands.some((command) => /system\.site.*uuid|config:get\s+system\.site/i.test(command)) ||
    !drupalCommands.some((command) => /config:status|config\s+status/i.test(command)) ||
    !drupalCommands.some((command) => /git\s+ls-files/i.test(command)) ||
    !String(drupalReadback?.drupal?.siteUuid ?? '').trim() ||
    !isJsonObject(drupalReadback?.drupal?.status) ||
    Object.keys(drupalReadback.drupal.status).length === 0 ||
    !hasMeaningfulEntry(drupalReadback?.drupal?.enabledModules) ||
    !String(drupalReadback?.drupal?.defaultTheme ?? '').trim() ||
    !String(drupalReadback?.drupal?.adminTheme ?? '').trim() ||
    !String(drupalReadback?.drupal?.frontPage ?? '').trim() ||
    !String(drupalReadback?.drupal?.configSyncDirectory ?? '').trim() ||
    !String(drupalReadback?.drupal?.trackedConfigDirectory ?? '').trim() ||
    !hasMeaningfulEntry(drupalReadback?.drupal?.trackedConfigYamlFiles) ||
    arrayOrEmpty(drupalReadback?.drupal?.trackedConfigYamlFiles).some((path) =>
      !/\.ya?ml$/i.test(String(path ?? '').trim())
    ) ||
    drupalReadback?.drupal?.configSyncDirectoryMatchesTrackedDirectory !== true ||
    !String(drupalReadback?.drupal?.configStatus ?? '').trim() ||
    drupalReadback?.drupal?.configStatusClean !== true ||
    !hasMeaningfulEntry(drupalContent.contentTypes) ||
    !hasMeaningfulEntry(drupalContent.fieldStorage) ||
    !hasMeaningfulEntry(drupalContent.formDisplays) ||
    !hasMeaningfulEntry(drupalContent.viewDisplays) ||
    (!hasMeaningfulEntry(drupalContent.nodes) && !hasMeaningfulEntry(drupalContent.canvasPages)) ||
    arrayOrEmpty(drupalContent.defaultOrDemoContent).length > 0 ||
    (collectionEvidenceRequired && !hasMeaningfulEntry(drupalReadback?.views)) ||
    ((hasMeaningfulEntry(sourceAudit?.mediaSignals) || hasMeaningfulEntry(patternMap?.media)) &&
      (!hasMeaningfulEntry(drupalReadback?.media?.items) ||
        !isJsonObject(drupalReadback?.media?.countsByType) ||
        Object.keys(drupalReadback.media.countsByType).length === 0)) ||
    !hasMeaningfulEntry(drupalRouting.menus) ||
    !hasMeaningfulEntry(drupalRouting.menuLinks) ||
    arrayOrEmpty(drupalRouting.duplicateAliases).length > 0 ||
    arrayOrEmpty(drupalRouting.unexpectedPublicRoutes).length > 0 ||
    !hasMeaningfulEntry(drupalReadback?.rolesAndPermissionsNotes)
  ) {
    reasons.push('drupal-readback.json must substantively identify the bootstrapped site, config, Drupal structures, public content, menus, and editor permissions with no blockers.');
  }

  const completionTimestamps = [
    ['source-audit.json', sourceAudit?.checkedAt],
    ['pattern-map.json', patternMap?.checkedAt],
    ['route-matrix.json', routeMatrix?.checkedAt],
    ['parity-report.json', parityReport?.checkedAt],
    ['browser-evidence.json', browserEvidence?.checkedAt],
    ['next-cycle-verification.json', nextCycleVerification?.checkedAt],
    ['independent-verification.json', independentVerification?.checkedAt],
    ['blind-adversarial-review.json', blindAdversarialReview?.checkedAt],
    ['drupal-readback.json', drupalReadback?.checkedAt],
    ['field-output-matrix.json', fieldOutputMatrix?.checkedAt],
    ['negative-route-consent.json', negativeRouteConsent?.checkedAt]
  ];
  const invalidTimestampFiles = completionTimestamps.filter(([, value]) => isoTimestamp(value) === null).map(([file]) => file);
  const parsedTimestamps = completionTimestamps.map(([, value]) => isoTimestamp(value)).filter((value) => value !== null);
  if (invalidTimestampFiles.length > 0) {
    reasons.push(`Completion evidence must use UTC ISO timestamps in ${invalidTimestampFiles.join(', ')}.`);
  } else if (Math.max(...parsedTimestamps) - Math.min(...parsedTimestamps) > MAX_COMPLETION_EVIDENCE_SPAN_MS) {
    reasons.push('Completion evidence timestamps span more than seven days and do not describe one coherent verification run.');
  } else if (Math.max(...parsedTimestamps) > Date.now() + MAX_FUTURE_TIMESTAMP_SKEW_MS) {
    reasons.push('Completion evidence contains a future timestamp beyond the five-minute clock-skew allowance.');
  } else if (Date.now() - Math.max(...parsedTimestamps) > MAX_COMPLETION_EVIDENCE_SPAN_MS) {
    reasons.push('The newest completion evidence is older than seven days and must be refreshed against the current target.');
  }

  return {
    packetCompletionReady: reasons.length === 0,
    reasons,
    humanDecisionPresentationStatus: markdownAssessment.humanDecisionPresentationStatus,
    recordedHumanGateStatus: markdownAssessment.recordedHumanGateStatus
  };
}

async function briefPacketCompletionReadiness(
  packetDir,
  gates,
  records,
  briefContext,
  { blindAdversarialReviewSupportsCompletion = false, independentVerificationSupportsCompletion = false } = {}
) {
  const reasons = [];
  const markdownAssessment = await markdownCompletionReadiness(packetDir, records, { briefMode: true });
  if (!gates) {
    return {
      packetCompletionReady: false,
      reasons: ['gates.json is unavailable.'],
      humanDecisionPresentationStatus: markdownAssessment.humanDecisionPresentationStatus,
      recordedHumanGateStatus: markdownAssessment.recordedHumanGateStatus
    };
  }

  const {
    blindAdversarialReview,
    briefAcceptance,
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    negativeRouteConsent,
    nextCycleVerification,
    patternMap,
    routeMatrix
  } = records;
  reasons.push(...markdownAssessment.reasons);
  reasons.push(...await negativeRouteConsentReasons(packetDir, negativeRouteConsent, routeMatrix));

  if (briefContext?.mode !== 'brief' || !briefContext?.briefPath || !briefContext?.briefSha256) {
    reasons.push('build-input.json must bind brief mode to a preserved packet-local original brief.');
  }
  const requirements = arrayOrEmpty(briefAcceptance?.requirements)
    .filter((requirement) => String(requirement?.id ?? '').trim());
  const requirementIds = new Set();
  const declaredTargetRoutes = new Set(
    arrayOrEmpty(routeMatrix?.routes).map((route) => normalizeRouteRequestKey(route?.targetPath)).filter(Boolean)
  );
  if (
    briefAcceptance?.schemaVersion !== 'public-kit.brief-acceptance.1' ||
    briefAcceptance?.briefSha256 !== briefContext?.briefSha256 ||
    isoTimestamp(briefAcceptance?.checkedAt) === null ||
    requirements.length === 0 ||
    arrayOrEmpty(briefAcceptance?.blockers).length > 0
  ) {
    reasons.push('brief-acceptance.json must bind the preserved brief, include a UTC check time and requirements, and have no blockers.');
  }
  const requirementCategories = new Set([
    'route', 'content', 'design', 'functionality', 'editorial', 'integration', 'accessibility', 'seo', 'other'
  ]);
  for (const [index, requirement] of requirements.entries()) {
    const id = String(requirement.id).trim();
    if (!/^BR-[A-Z0-9][A-Z0-9._-]*$/.test(id) || requirementIds.has(id)) {
      reasons.push(`brief-acceptance.json requirements[${index}] needs a unique stable BR- identifier.`);
    }
    requirementIds.add(id);
    const targetRoutes = arrayOrEmpty(requirement.targetRoutes).map(normalizeRouteRequestKey).filter(Boolean);
    const evidenceResults = await Promise.all(
      arrayOrEmpty(requirement.evidence).map((reference) => nonEmptyPacketEvidence(packetDir, reference))
    );
    if (
      !String(requirement.requirement ?? '').trim() ||
      !requirementCategories.has(requirement.category) ||
      arrayOrEmpty(requirement.acceptanceChecks).length === 0 ||
      requirement.status !== 'pass' ||
      evidenceResults.length === 0 ||
      !evidenceResults.every(Boolean) ||
      (targetRoutes.length === 0 && !['integration', 'other'].includes(requirement.category)) ||
      targetRoutes.some((route) => !declaredTargetRoutes.has(route))
    ) {
      reasons.push(`Brief requirement ${id || `(row ${index})`} must be explicit, passed, route-bound where applicable, and backed by packet-local evidence.`);
    }
  }
  if (arrayOrEmpty(briefAcceptance?.assumptions).some((assumption) =>
    assumption?.status === 'owner_decision_required' || !String(assumption?.id ?? '').trim() || !String(assumption?.assumption ?? '').trim()
  )) {
    reasons.push('brief-acceptance.json assumptions must be identified and resolved or recorded without owner-decision blockers.');
  }

  const targetBaseUrl = httpUrl(routeMatrix?.targetBaseUrl);
  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes);
  const routeRows = arrayOrEmpty(routeMatrix?.routes);
  if (!targetBaseUrl || String(routeMatrix?.sourceBaseUrl ?? '').trim()) {
    reasons.push('Brief mode route-matrix.json must declare targetBaseUrl and leave sourceBaseUrl empty.');
  }
  if (primaryRoutes.length === 0) {
    reasons.push('Brief mode route-matrix.json must declare at least one primary target route.');
  }
  const primaryRouteRequirements = new Map();
  for (const [index, route] of primaryRoutes.entries()) {
    const targetPath = normalizeRouteRequestKey(route?.targetPath);
    const routeRequirementIds = arrayOrEmpty(route?.briefRequirementIds).map((id) => String(id).trim()).filter(Boolean);
    const routeRow = routeRows.find((row) => normalizeRouteRequestKey(row?.targetPath) === targetPath);
    if (
      !targetPath ||
      !ROUTE_ROLES.has(route?.routeRole) ||
      route?.accepted !== true ||
      routeRequirementIds.length === 0 ||
      routeRequirementIds.some((id) => !requirementIds.has(id)) ||
      !routeRow ||
      routeRow.accepted !== true ||
      (!successfulStatus(routeRow.targetStatus) && !(routeRow.expectedRedirect === true && redirectStatus(routeRow.targetStatus))) ||
      !(String(routeRow.targetH1 ?? '').trim() || String(routeRow.targetTitle ?? '').trim())
    ) {
      reasons.push(`Brief primary route ${targetPath || `(row ${index})`} must be accepted, requirement-bound, and mapped to an accepted target route with identity evidence.`);
    }
    primaryRouteRequirements.set(targetPath, new Set(routeRequirementIds));
  }
  for (const requirement of requirements) {
    for (const route of arrayOrEmpty(requirement.targetRoutes).map(normalizeRouteRequestKey).filter(Boolean)) {
      const primaryIds = primaryRouteRequirements.get(route);
      if (primaryIds && !primaryIds.has(requirement.id)) {
        reasons.push(`Brief primary route ${route} must name requirement ${requirement.id}.`);
      }
    }
  }
  if (
    primaryRouteRequirements.has('/') &&
    (
      routeMatrix?.homepageTargetAcceptance?.accepted !== true ||
      !successfulStatus(routeMatrix?.homepageTargetAcceptance?.targetStatus) ||
      !(String(routeMatrix?.homepageTargetAcceptance?.targetH1 ?? '').trim() ||
        String(routeMatrix?.homepageTargetAcceptance?.targetTitle ?? '').trim())
    )
  ) {
    reasons.push('Brief mode route-matrix.json must accept the target homepage with a successful status and target H1 or title.');
  }
  if (routeMatrix?.starterRouteCleanup?.accepted !== true || routeMatrix?.canvasPlaceholderDetection?.accepted !== true) {
    reasons.push('Brief mode still requires accepted starter-route cleanup and Canvas placeholder disposition.');
  }

  const browserChecks = arrayOrEmpty(browserEvidence?.publicRouteChecks);
  if (!httpUrl(browserEvidence?.site) || isoTimestamp(browserEvidence?.checkedAt) === null || !String(browserEvidence?.toolOrMethod ?? '').trim()) {
    reasons.push('browser-evidence.json must identify the brief target, UTC check time, and browser method.');
  }
  for (const [targetPath, expectedRequirementIds] of primaryRouteRequirements) {
    for (const viewport of ['desktop', 'mobile']) {
      const check = browserChecks.find((candidate) =>
        normalizeRouteRequestKey(candidate?.targetUrl) === targetPath && candidate?.viewport?.name === viewport
      );
      const checkedIds = new Set(arrayOrEmpty(check?.briefRequirementIds).map((id) => String(id).trim()).filter(Boolean));
      const screenshotPath = resolveReviewEvidencePath(packetDir, join(packetDir, 'evidence', 'browser'), check?.targetScreenshot);
      const screenshot = screenshotPath ? await evidenceImageMetadata(screenshotPath) : null;
      const dimensionsMatch = Boolean(screenshot) && (
        viewport === 'desktop'
          ? screenshot.width >= 1024 && screenshot.height >= 600
          : screenshot.width >= 280 && screenshot.width <= 767 && screenshot.height >= 480
      );
      if (
        !check ||
        check.accepted !== true ||
        arrayOrEmpty(check.blockers).length > 0 ||
        !httpUrl(check.targetUrl) ||
        !httpUrl(check.targetFinalUrl) ||
        check.visualComparison?.status !== 'pass' ||
        !(String(check.renderedSignals?.targetTitle ?? '').trim() || String(check.renderedSignals?.targetH1 ?? '').trim()) ||
        check.renderedSeoSignals?.accepted !== true ||
        check.accessibilityCheck?.status !== 'pass' ||
        !dimensionsMatch ||
        [...expectedRequirementIds].some((id) => !checkedIds.has(id))
      ) {
        reasons.push(`browser-evidence.json must provide accepted ${viewport} target evidence for brief route ${targetPath}, bound to its requirements.`);
      }
    }
  }
  const editorChecks = arrayOrEmpty(browserEvidence?.editorWorkflowChecks);
  if (!editorChecks.some((check) =>
    check?.status === 'pass' &&
    check?.accepted === true &&
    !privilegedEditorIdentity(check?.editorUser) &&
    !privilegedEditorIdentity(check?.editorRole) &&
    String(check?.drupalRoute ?? '').trim() &&
    String(check?.publicOutputAffected ?? '').trim()
  )) {
    reasons.push('Brief mode requires at least one passing, accepted non-admin editor workflow that changes public output.');
  }

  const pageOwners = arrayOrEmpty(patternMap?.pageCompositionOwnership);
  if (
    isoTimestamp(patternMap?.checkedAt) === null ||
    patternMap?.buildTypeDeclaration?.accepted !== true ||
    patternMap?.compositionModel?.completedBeforeImplementation !== true ||
    arrayOrEmpty(patternMap?.structuredContentModel?.blockers).length > 0
  ) {
    reasons.push('pattern-map.json must contain a reviewed Drupal-native build type and pre-implementation composition model without blockers.');
  }
  for (const targetPath of primaryRouteRequirements.keys()) {
    if (!pageOwners.some((owner) =>
      normalizeRouteRequestKey(owner?.targetRoute || owner?.sourceRoute) === targetPath &&
      owner?.accepted === true &&
      String(owner?.selectedOwner ?? '').trim() &&
      String(owner?.ownerRationale ?? '').trim() &&
      String(owner?.editorVerificationEvidence ?? '').trim()
    )) {
      reasons.push(`pattern-map.json must declare accepted composition and editor ownership for brief route ${targetPath}.`);
    }
  }

  if (
    isoTimestamp(drupalReadback?.checkedAt) === null ||
    !httpUrl(drupalReadback?.site) ||
    drupalReadback?.readbackComplete !== true ||
    arrayOrEmpty(drupalReadback?.blockers).length > 0 ||
    !String(drupalReadback?.drupal?.siteUuid ?? '').trim() ||
    !String(drupalReadback?.drupal?.configSyncDirectory ?? '').trim() ||
    drupalReadback?.drupal?.configStatusClean !== true ||
    arrayOrEmpty(drupalReadback?.drupal?.trackedConfigYamlFiles).length === 0
  ) {
    reasons.push('drupal-readback.json must record a complete target-bound Drupal readback with clean tracked config and no blockers.');
  }
  const publicFieldRows = arrayOrEmpty(fieldOutputMatrix?.bundles).flatMap((bundle) =>
    arrayOrEmpty(bundle?.fields).filter((field) => field?.affectsAnonymousOutput === true)
  );
  if (
    isoTimestamp(fieldOutputMatrix?.checkedAt) === null ||
    !httpUrl(fieldOutputMatrix?.site) ||
    publicFieldRows.length === 0 ||
    publicFieldRows.some((field) => field?.accepted !== true || field?.containsRawPresentationImplementation === true) ||
    arrayOrEmpty(fieldOutputMatrix?.blockedFields).length > 0 ||
    arrayOrEmpty(fieldOutputMatrix?.rawPresentationImplementationFields).length > 0
  ) {
    reasons.push('field-output-matrix.json must accept public-output fields, reject raw presentation implementation, and have no blockers.');
  }

  if (
    nextCycleVerification?.applicability?.reviewed !== true ||
    typeof nextCycleVerification?.applicability?.applies !== 'boolean' ||
    (nextCycleVerification?.applicability?.applies === false && !String(nextCycleVerification?.applicability?.reason ?? '').trim()) ||
    arrayOrEmpty(nextCycleVerification?.blockers).length > 0
  ) {
    reasons.push('next-cycle-verification.json must record a reviewed applicable or reasoned-not-applicable target disposition without blockers.');
  }
  if (!independentVerificationSupportsCompletion) {
    reasons.push('Independent verification does not cover every brief requirement and shared completion gate.');
  }
  if (!blindAdversarialReviewSupportsCompletion) {
    reasons.push('Blind review does not cover every primary target route and brief requirement.');
  }

  const timestampPairs = [
    ['brief-acceptance.json', briefAcceptance?.checkedAt],
    ['browser-evidence.json', browserEvidence?.checkedAt],
    ['drupal-readback.json', drupalReadback?.checkedAt],
    ['field-output-matrix.json', fieldOutputMatrix?.checkedAt],
    ['pattern-map.json', patternMap?.checkedAt],
    ['next-cycle-verification.json', nextCycleVerification?.checkedAt],
    ['negative-route-consent.json', negativeRouteConsent?.checkedAt],
    ['independent-verification.json', independentVerification?.checkedAt],
    ['blind-adversarial-review.json', blindAdversarialReview?.checkedAt]
  ];
  const parsedTimestamps = timestampPairs.map(([, value]) => isoTimestamp(value)).filter((value) => value !== null);
  if (parsedTimestamps.length !== timestampPairs.length) {
    reasons.push('Every brief completion artifact must include a UTC ISO checkedAt timestamp.');
  } else if (Math.max(...parsedTimestamps) - Math.min(...parsedTimestamps) > MAX_COMPLETION_EVIDENCE_SPAN_MS) {
    reasons.push('Brief completion evidence timestamps span more than seven days and must be refreshed as one coherent run.');
  }

  return {
    packetCompletionReady: reasons.length === 0,
    reasons,
    humanDecisionPresentationStatus: markdownAssessment.humanDecisionPresentationStatus,
    recordedHumanGateStatus: markdownAssessment.recordedHumanGateStatus
  };
}

// Independence declarations live in builder-writable packet JSON, so the strongest
// honest machine label is self-attested; subagent independence is allowed, not proven.
function independenceAttestation(actor) {
  if (!isJsonObject(actor) || !String(actor.nameOrRole ?? '').trim()) {
    return 'not-declared';
  }
  if (
    String(actor.independenceDegradedReason ?? '').trim() ||
    actor.freshContextUsed !== true ||
    actor.sameContextAsBuilder !== false ||
    actor.builderSummaryExcluded !== true
  ) {
    return 'degraded';
  }
  return 'self-attested';
}

function sharedPacketDir(packetDir) {
  return basename(resolve(packetDir));
}

function sharedPacketMessage(value, packetDir) {
  return String(value).replaceAll(resolve(packetDir), sharedPacketDir(packetDir));
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
  const blindAdversarialReview = await readJson(join(packetDir, 'blind-adversarial-review.json'), []);
  const buildInput = await readJson(join(packetDir, 'build-input.json'), []);
  const briefAcceptance = await readJson(join(packetDir, 'brief-acceptance.json'), []);
  const routeMatrix = await readJson(join(packetDir, 'route-matrix.json'), []);
  const parityReport = await readJson(join(packetDir, 'parity-report.json'), []);
  const browserEvidence = await readJson(join(packetDir, 'browser-evidence.json'), []);
  const drupalReadback = await readJson(join(packetDir, 'drupal-readback.json'), []);
  const fieldOutputMatrix = await readJson(join(packetDir, 'field-output-matrix.json'), []);
  const nextCycleVerification = await readJson(join(packetDir, 'next-cycle-verification.json'), []);
  const patternMap = await readJson(join(packetDir, 'pattern-map.json'), []);
  const sourceAudit = await readJson(join(packetDir, 'source-audit.json'), []);
  const negativeRouteConsent = await readJson(join(packetDir, 'negative-route-consent.json'), []);
  const structuredRecords = {
    'blind-adversarial-review.json': blindAdversarialReview,
    'brief-acceptance.json': briefAcceptance,
    'browser-evidence.json': browserEvidence,
    'build-input.json': buildInput,
    'drupal-readback.json': drupalReadback,
    'field-output-matrix.json': fieldOutputMatrix,
    'independent-verification.json': independentVerification,
    'negative-route-consent.json': negativeRouteConsent,
    'next-cycle-verification.json': nextCycleVerification,
    'parity-report.json': parityReport,
    'pattern-map.json': patternMap,
    'route-matrix.json': routeMatrix,
    'source-audit.json': sourceAudit
  };
  validateStructuredEnums(gates, structuredRecords, errors);
  validateArtifactGateIds(gates, structuredRecords, errors);
  const briefContext = await validateBuildInput(packetDir, buildInput, routeMatrix, errors);
  const briefMode = briefContext.mode === 'brief';
  rejectAuthoredCompletionClaims(independentVerification, blindAdversarialReview, errors);
  const independentVerificationSupportsCompletion = await validateIndependentVerification(
    packetDir,
    independentVerification,
    {
      browserEvidence,
      drupalReadback,
      fieldOutputMatrix,
      nextCycleVerification,
      patternMap,
      routeMatrix,
      sourceAudit
    },
    errors,
    { briefAcceptance, briefMode }
  );
  const blindAdversarialReviewValidation = await validateBlindAdversarialReview(
    packetDir,
    blindAdversarialReview,
    routeMatrix,
    errors,
    { briefAcceptance, briefContext, briefMode }
  );
  const blindAdversarialReviewSupportsCompletion =
    blindAdversarialReviewValidation.supportsCompletion === true;
  await validateDurableIntent(packetDir, errors);
  await validateRecipeStartPoint(packetDir, errors);
  const completionRecords = {
    blindAdversarialReview,
    briefAcceptance,
    buildInput,
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    negativeRouteConsent,
    nextCycleVerification,
    parityReport,
    patternMap,
    routeMatrix,
    sourceAudit
  };
  const completionReadiness = briefMode
    ? await briefPacketCompletionReadiness(packetDir, gates, completionRecords, briefContext, {
        blindAdversarialReviewSupportsCompletion,
        independentVerificationSupportsCompletion
      })
    : await packetCompletionReadiness(packetDir, gates, completionRecords);
  const sharedErrors = errors.map((error) => sharedPacketMessage(error, packetDir));
  const sharedCompletionBlockedReasons = completionReadiness.reasons.map((reason) =>
    sharedPacketMessage(reason, packetDir)
  );
  const gateFindings = [...sharedErrors, ...sharedCompletionBlockedReasons];
  if (!independentVerificationSupportsCompletion) {
    gateFindings.push('G-VERIFY-01 independent verification did not support completion.');
  }
  if (!blindAdversarialReviewSupportsCompletion) {
    gateFindings.push('G-BLIND-01 blind adversarial review did not support completion.');
  }

  return {
    schemaVersion: 'public-kit.packet-verification.2',
    checkedAt: new Date().toISOString(),
    buildMode: briefMode ? 'brief' : 'source_site',
    claimScope: briefMode ? 'complete-local-build-from-brief' : 'complete-local-rebuild',
    productionReadinessEvaluated: false,
    launchReady: false,
    packetDir: sharedPacketDir(packetDir),
    gatesSchemaVersion: gates?.schemaVersion ?? '',
    gateCount: gates?.gates?.length ?? 0,
    requiredFileCount: gates?.reviewPacketFiles?.length ?? 0,
    verificationMode: 'packet-only',
    gateResults: perGateResults(gates, gateFindings, { mode: 'packet' }),
    recordedHumanGateStatus: completionReadiness.recordedHumanGateStatus,
    completionEvidence: {
      independentVerificationSupportsCompletion,
      blindAdversarialReviewSupportsCompletion,
      externalBlockers: blindAdversarialReviewValidation.externalBlockers,
      externalBlockersOnly: blindAdversarialReviewValidation.externalBlockersOnly,
      scopeDispositionAttribution: 'builder-writable-self-attested',
      humanDecisionPresentationStatus: completionReadiness.humanDecisionPresentationStatus,
      independence: {
        independentVerification: independenceAttestation(independentVerification?.verifier),
        blindAdversarialReview: independenceAttestation(blindAdversarialReview?.reviewer)
      },
      packetCompletionReady: completionReadiness.packetCompletionReady,
      packetCompletionBlockedReasons: sharedCompletionBlockedReasons,
      packetSupportsCompletion:
        independentVerificationSupportsCompletion &&
        blindAdversarialReviewSupportsCompletion &&
        completionReadiness.packetCompletionReady
    },
    completeLocalRebuildClaimAllowed: false,
    completeLocalBuildFromBriefClaimAllowed: false,
    valid: errors.length === 0,
    errors: sharedErrors,
    warnings: warnings.map((warning) => sharedPacketMessage(warning, packetDir))
  };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }

  if (!existsSync(args.packet)) {
    throw new UsageError(`Packet directory does not exist: ${args.packet}.`);
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

  process.stdout.write(
    `Packet structure valid; packet-only verification never authorizes a complete local rebuild claim. Report: ${args.out}\n`
  );
}

if (isDirectRun()) {
  main().catch((error) => {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n${USAGE}\n`);
    } else {
      process.stderr.write(`${error.stack || error.message}\n`);
    }
    process.exit(1);
  });
}
