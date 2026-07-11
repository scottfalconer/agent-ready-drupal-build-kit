#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
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
const BLIND_DEFECT_SEVERITIES = new Set(['blocker', 'critical', 'high', 'medium', 'low']);
const BLIND_DEFECT_STATUSES = new Set(['open', 'fixed', 'accepted_out_of_scope', 'external_blocker']);
const STARTER_CONFIG_ENTITY_KINDS = new Set([
  'webform',
  'view_page',
  'canvas_content_template',
  'canvas_page_template',
  'other'
]);
const STARTER_CONFIG_ENTITY_DISPOSITIONS = new Set(['keep', 'close', 'delete']);
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
const LOCAL_COMPLETION_NON_AUTHORITY_FILES = new Set(['launch-checklist.md', 'production-target.md']);
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
  'G-PARITY-01': 'addressableSurfaceParity',
  'G-CONTENT-01': 'structuredContentOwnership',
  'G-CONTENT-02': 'collectionOwnership',
  'G-COMPOSITION-01': 'compositionDeclaration',
  'G-COMPOSITION-02': 'compositionFidelity',
  'G-CANVAS-01': 'canvasComponentFidelity',
  'G-RECIPE-01': 'recipeStartPoint',
  'G-CONFIG-01': 'trackedConfigSync',
  'G-INTENT-01': 'durableIntent',
  'G-FIELD-01': 'fieldOutput',
  'G-OFFROAD-01': 'offRoadAndRawMarkup',
  'G-VERIFY-01': 'independentVerification',
  'G-VERIFY-02': 'liveVerification',
  'G-BLIND-01': 'blindAdversarialReview',
  'G-EDITOR-01': 'editorWorkflow',
  'G-SEO-01': 'renderedSeo'
});

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
    return normalizeRouteKey(value);
  }
  if (!isJsonObject(value)) {
    return '';
  }
  return normalizeRouteKey(value.sourcePath || value.path || value.route || value.url || value.href);
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
  return isJsonObject(record?.summary) && record.summary.completeLocalRebuildClaimAllowed === true;
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
  const recordSource = normalizeRouteKey(record?.sourceRoute || record?.sourcePath);
  const recordTarget = normalizeRouteKey(record?.targetRoute || record?.targetPath || record?.publicRoute);
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

// Drupal Canvas / Experience Builder template config entities silently supersede theme
// node--*.html.twig output for their bundle/view-mode, so an enabled one falsifies any
// "Canvas intentionally unused" declaration.
export const CANVAS_TEMPLATE_CONFIG_RE =
  /(?:^|[\\/])(?:canvas|experience_builder)\.(?:content_template|page_template)\.[^\\/]*\.ya?ml$/i;

export function canvasNonUseClaimed(patternMap, independentVerification) {
  return /canvas_unused/.test(String(patternMap?.buildTypeDeclaration?.type ?? '')) ||
    independentVerification?.canvasPlaceholderChecks?.canvasIntentionallyUnusedAndDocumented === true;
}

export function canvasTemplateConfigTargetsRebuildBundle(configPath, patternMap, drupalReadback) {
  const configName = basename(String(configPath ?? '').trim()).replace(/\.ya?ml$/i, '');
  const [, templateKind, entityType = '', bundle = ''] = configName.split('.');
  if (templateKind !== 'content_template') {
    return true;
  }
  if (entityType !== 'node' || !bundle) {
    return true;
  }
  const rebuildNodeBundles = new Set([
    ...substantiveObjects(patternMap?.contentTypes)
      .map((record) => String(record?.machineName || record?.bundle || '').trim()),
    ...substantiveObjects(drupalReadback?.content?.nodes)
      .map((record) => String(record?.type || record?.bundle || '').trim())
  ].filter(Boolean));
  return rebuildNodeBundles.has(bundle);
}

async function trackedConfigEntityConfirmedDisabled(projectRoot, configPath) {
  const candidate = resolve(projectRoot, configPath);
  if (isAbsolute(configPath) || relative(projectRoot, candidate).startsWith('..')) {
    return false;
  }
  try {
    return /^status:\s*false\b/m.test(await readFile(candidate, 'utf8'));
  } catch {
    return false;
  }
}

function editorWorkflowMatchesBundle(check, bundle) {
  if (privilegedEditorIdentity(check?.editorUser) || privilegedEditorIdentity(check?.editorRole)) {
    return false;
  }
  const entityType = String(bundle?.entityType ?? '').trim();
  const bundleName = String(bundle?.bundle ?? '').trim();
  return exactIdentityMatch(check?.bundle, bundleName) && exactIdentityMatch(check?.entityType, entityType);
}

async function independentStructuredGateReasons({
  browserEvidence,
  drupalReadback,
  fieldOutputMatrix,
  independentVerification,
  packetDir,
  patternMap,
  routeMatrix,
  sourceAudit
}) {
  const reasons = [];
  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes)
    .map((route) => ({
      source: normalizeRouteKey(route?.sourcePath),
      target: normalizeRouteKey(route?.targetPath)
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
      normalizeRouteKey(check.sourcePath) === normalizeRouteKey(route.sourcePath) &&
      check.status === 'pass' &&
      String(check.dispositionEvidence ?? '').trim()
    ))
  ) {
    reasons.push('independent-verification.json must pass every source-route drift disposition check with evidence.');
  }

  const placeholderScan = independentVerification?.placeholderTextScan ?? {};
  const scannedPlaceholderRoutes = new Set(arrayOrEmpty(placeholderScan.scannedRoutes).map(normalizeRouteKey));
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

  if (canvasNonUseClaimed(patternMap, independentVerification)) {
    const projectRoot = dirname(resolve(packetDir));
    const trackedCanvasTemplateConfigs = arrayOrEmpty(drupalReadback?.drupal?.trackedConfigYamlFiles)
      .map((path) => String(path ?? '').trim().replaceAll('\\', '/'))
      .filter((path) => CANVAS_TEMPLATE_CONFIG_RE.test(path))
      .filter((path) => canvasTemplateConfigTargetsRebuildBundle(path, patternMap, drupalReadback));
    for (const configPath of trackedCanvasTemplateConfigs) {
      if (!await trackedConfigEntityConfirmedDisabled(projectRoot, configPath)) {
        reasons.push(`Tracked Canvas template config ${configPath} is not confirmed disabled while the packet claims Canvas is unused; disable or delete the template or declare Canvas the composition owner.`);
      }
    }
  }

  const starterConfigSweep = independentVerification?.starterConfigEntitySweep ?? {};
  const starterConfigDispositions = substantiveObjects(starterConfigSweep.openUnreferencedEntities);
  if (
    starterConfigSweep.status !== 'pass' ||
    starterConfigSweep.webformsReviewed !== true ||
    starterConfigSweep.viewsPagesReviewed !== true ||
    starterConfigSweep.canvasTemplatesReviewed !== true ||
    starterConfigDispositions.some((record) =>
      !String(record.configName ?? '').trim() ||
      !STARTER_CONFIG_ENTITY_KINDS.has(record.kind) ||
      !STARTER_CONFIG_ENTITY_DISPOSITIONS.has(record.disposition) ||
      !String(record.dispositionOwner ?? '').trim() ||
      !String(record.rationale ?? '').trim()
    )
  ) {
    reasons.push('independent-verification.json must review starter config entities (webforms, Views pages, Canvas templates) and record a keep, close, or delete disposition with a named owner and rationale for every open-but-unreferenced entity.');
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
      normalizeRouteKey(deviationTargetUrl.pathname) === route.target &&
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
    'parity-report.json',
    'pattern-map.json'
  ]) {
    if (!freshnessArtifacts.has(artifact)) {
      reasons.push(`independent-verification.json packet freshness checks must pass ${artifact}.`);
    }
  }

  return reasons;
}

async function validateIndependentVerification(packetDir, independentVerification, relatedRecords, errors) {
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
    if (!String(claim.claimId ?? '').trim() || !String(claim.claim ?? '').trim() || !String(claim.gate ?? '').trim()) {
      errors.push(`independent-verification.json completionClaims[${index}] requires claimId, claim, and gate.`);
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
        `independent-verification.json completionClaims[${index}] requires JSON verifier evidence bound to its claimId, gate, target, checkedAt time, and concrete passing checks.`
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

  const structuredGateReasons = await independentStructuredGateReasons({
    ...relatedRecords,
    independentVerification,
    packetDir
  });

  return errors.length === startingErrorCount && structuredGateReasons.length === 0;
}

function rejectAuthoredCompletionClaims(independentVerification, blindReview, errors) {
  for (const [file, record] of [
    ['independent-verification.json', independentVerification],
    ['blind-adversarial-review.json', blindReview]
  ]) {
    if (authoredCompletionClaim(record)) {
      errors.push(
        `${file} cannot set summary.completeLocalRebuildClaimAllowed=true; completion authority belongs only to the live verifier.`
      );
    }
  }
}

async function validateBlindAdversarialReview(packetDir, blindReview, routeMatrix, errors) {
  if (!isJsonObject(blindReview)) {
    errors.push('blind-adversarial-review.json must be a JSON object (blocked stub at minimum).');
    return false;
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

  if (!strictCompletionReview) {
    return false;
  }

  if (isoTimestamp(blindReview.checkedAt) === null) {
    errors.push('blind-adversarial-review.json completion evidence requires checkedAt as a UTC ISO timestamp.');
  }

  const declaredSourceUrl = httpUrl(routeMatrix?.sourceBaseUrl);
  const declaredTargetUrl = httpUrl(routeMatrix?.targetBaseUrl);
  if (!declaredSourceUrl || !declaredTargetUrl) {
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

  if (!BLIND_COMPLETE_VERDICTS.has(summary.verdict)) {
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
      if (
        (defect.status === 'accepted_out_of_scope' && !String(defect.acceptedBy ?? '').trim()) ||
        !String(defect.acceptedReason || defect.reason || defect.rationale || '').trim() ||
        !evidenceResults.some(Boolean)
      ) {
        errors.push(
          `blind-adversarial-review.json productDefects[${index}] ${defect.status} requires a reason${defect.status === 'accepted_out_of_scope' ? ', acceptedBy,' : ','} and concrete packet-local evidence.`
        );
      }
    }
    if (defect.status === 'external_blocker') {
      errors.push(`blind-adversarial-review.json productDefects[${index}] external blocker blocks completion.`);
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
    if (
      (omission.disposition === 'accepted_out_of_scope' && !String(omission.acceptedBy ?? '').trim()) ||
      !String(omission.reason || omission.rationale || '').trim() ||
      !evidenceResults.some(Boolean)
    ) {
      errors.push(
        `blind-adversarial-review.json routeCoverage.omittedPrimaryRoutes[${index}] ${omission.disposition} requires a rationale${omission.disposition === 'accepted_out_of_scope' ? ', acceptedBy,' : ','} and concrete packet-local evidence.`
      );
    }
    if (omission.disposition === 'external_blocker') {
      errors.push(`blind-adversarial-review.json routeCoverage.omittedPrimaryRoutes[${index}] external blocker blocks completion.`);
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
    const reviewSourceUrl = httpUrl(review.sourceTruthReference);
    const reviewTargetUrl = httpUrl(review.targetUrlOrArtifact);
    if (!reviewSourceUrl || (declaredSourceUrl && reviewSourceUrl.origin !== declaredSourceUrl.origin)) {
      errors.push(
        `blind-adversarial-review.json routeViewportReviews[${index}].sourceTruthReference must use the declared source origin.`
      );
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
    for (const screenshotField of ['sourceScreenshot', 'targetScreenshot']) {
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
      source: normalizeRouteKey(route.sourcePath || route.route || route.path),
      target: normalizeRouteKey(route.targetPath || route.sourcePath || route.route || route.path)
    }))
    .filter((route) => route.target);
  const acceptedOmissions = new Map(
    omittedPrimaryRoutes
      .filter((route) =>
        route.disposition === 'accepted_out_of_scope' &&
        String(route.acceptedBy ?? '').trim() &&
        String(route.rationale ?? '').trim() &&
        arrayOrEmpty(route.evidence).length > 0
      )
      .map((route) => [normalizeRouteKey(route.route || route.targetPath || route.sourcePath || route.path), route])
  );

  for (const primaryRoute of primaryRoutes) {
    const matchingReviews = routeReviews.filter((review) => {
      const routeKey = normalizeRouteKey(review.route);
      const targetKey = normalizeRouteKey(review.targetUrlOrArtifact);
      const sourceKey = normalizeRouteKey(review.sourceTruthReference);
      return (
        routeKey === primaryRoute.target &&
        targetKey === primaryRoute.target &&
        sourceKey === primaryRoute.source
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

  return errors.length === startingErrorCount;
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

function routeHasViewport(checks, route, viewport) {
  return checks.some((check) => {
    const viewportName = String(check?.viewport?.name ?? check?.viewport ?? '').trim();
    return routeRecordPath(check) === route && viewportName === viewport;
  });
}

function escapedRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function markdownField(text, label) {
  return text.match(new RegExp(`^\\s*-\\s*${escapedRegex(label)}:\\s*(.+?)\\s*$`, 'mi'))?.[1]?.trim() ?? '';
}

function markdownPlainField(text, label) {
  return text.match(new RegExp(`^\\s*${escapedRegex(label)}:\\s*(.+?)\\s*$`, 'mi'))?.[1]?.trim() ?? '';
}

function checkedStatement(text, statement) {
  return new RegExp(`^\\s*-\\s*\\[[xX]\\]\\s*${escapedRegex(statement)}\\s*$`, 'm').test(text);
}

function uncheckedStatement(text, statement) {
  return new RegExp(`^\\s*-\\s*\\[ \\]\\s*${escapedRegex(statement)}\\s*$`, 'm').test(text);
}

function blockedTableRow(text) {
  return /^\|[^\n]*\|\s*blocked\s*\|\s*$/im.test(text);
}

function unresolvedMarkdownUnknown(text) {
  return /:\s*`?UNKNOWN`?\s*$/im.test(text) || /\|\s*UNKNOWN\s*\|/i.test(text);
}

async function markdownCompletionReadiness(packetDir) {
  const reasons = [];
  const texts = Object.fromEntries(
    await Promise.all(
      [
        'operator-run.md',
        'maintainer-review.md',
        'recipe-start-point.md',
        'scoped-gap-list.md',
        'open-decisions.md',
        'off-road-inventory.md',
        'durable-intent.yml'
      ].map(async (file) => [file, existsSync(join(packetDir, file)) ? await readFile(join(packetDir, file), 'utf8') : ''])
    )
  );

  const operator = texts['operator-run.md'];
  const operatorFields = [
    'Name',
    'Role',
    'Environment',
    'Environment provisioning (manual, One Line Installer, other)',
    'Date',
    'DDEV project URL',
    '`ddev drush status`',
    'Config export location',
    'Anonymous route checks',
    'Browser-rendered evidence',
    'Command transcript',
    'Reviewer'
  ];
  const acceptedOperatorDecisions = [
    'Repeatability accepted',
    'Repeatability accepted with restrictions'
  ].filter((decision) => checkedStatement(operator, decision));
  if (
    operatorFields.some((field) => !markdownField(operator, field)) ||
    acceptedOperatorDecisions.length !== 1 ||
    !uncheckedStatement(operator, 'Repeatability not reviewed') ||
    !uncheckedStatement(operator, 'Repeatability blocked')
  ) {
    reasons.push('operator-run.md must identify the operator/runtime, point to concrete run evidence, and record an accepted repeatability decision.');
  }

  const maintainer = texts['maintainer-review.md'];
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
  if (
    ['Site', 'Target', 'Reviewer', 'Date'].some((field) => !markdownField(maintainer, field)) ||
    maintainerQuestions.some((question) => !checkedStatement(maintainer, question)) ||
    !checkedStatement(maintainer, 'I would stake my name on this as a complete local Drupal CMS rebuild.') ||
    !uncheckedStatement(maintainer, 'I would not stake my name on this as a complete local Drupal CMS rebuild.') ||
    !markdownField(maintainer, 'Reasons to accept')
  ) {
    reasons.push('maintainer-review.md must contain a named, dated positive stake-my-name review with all local-rebuild questions answered.');
  }

  const recipe = texts['recipe-start-point.md'];
  const selectedStartPoints = [
    'Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.',
    'Retain a site template selected before installation plus bounded source-fit Recipes and overlays.',
    'Retain another existing Drupal CMS substrate and extend it without replacing it.',
    'Use bounded custom overlays because maintained Recipes do not fit the audited source patterns.'
  ].filter((choice) => checkedStatement(recipe, choice));
  if (
    ['Source URL', 'Target site name', 'Target workspace', 'Decision date', 'Decision owner'].some(
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
  if (
    ['Source URL', 'Target site name', 'Target workspace', 'Date'].some((field) => !markdownField(gaps, field)) ||
    !/^Overall status:\s*`?(?:complete-local-rebuild|local-complete)`?\s*$/mi.test(gaps) ||
    unresolvedMarkdownUnknown(gaps) ||
    blockedTableRow(gaps)
  ) {
    reasons.push('scoped-gap-list.md must identify the run, declare complete-local-rebuild status, and disposition every gap without UNKNOWN or blocked rows.');
  }

  const decisions = texts['open-decisions.md'];
  const noOpenDecisions = /^\s*-\s*Decisions still open:\s*None\b/im.test(decisions);
  if (
    ['Source URL', 'Target site name', 'Target workspace', 'Date'].some((field) => !markdownField(decisions, field)) ||
    unresolvedMarkdownUnknown(decisions) ||
    (!noOpenDecisions && !/^\|\s*DEC-[^\n]+\|\s*$/im.test(decisions)) ||
    ['Decisions still open', 'Decisions accepted', 'Decisions blocked by missing external input', 'Agent-resolvable work deliberately excluded from this file']
      .some((field) => !markdownField(decisions, field))
  ) {
    reasons.push('open-decisions.md must contain run identity, only evidence-backed human decisions (or an explicit none declaration), and a complete handoff summary.');
  }

  const offRoad = texts['off-road-inventory.md'];
  if (
    ['Site', 'Checked at', 'Reviewer'].some((field) => !markdownField(offRoad, field)) ||
    !/^\s*-\s*Overall status:\s*`?accepted`?\s*$/mi.test(offRoad) ||
    unresolvedMarkdownUnknown(offRoad) ||
    blockedTableRow(offRoad) ||
    !(/no off-road moves/i.test(offRoad) || /^\|\s*OR-[^\n]+\|\s*$/im.test(offRoad))
  ) {
    reasons.push('off-road-inventory.md must contain a named accepted review and disposition every paved-path exception without UNKNOWN or blocked rows.');
  }

  const durableIntent = texts['durable-intent.yml'];
  const explicitEmptyIntent = /^\s*intent_records:\s*\[\s*\]\s*$/m.test(durableIntent);
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
    (!explicitEmptyIntent && !allIntentRecordsCurrent)
  ) {
    reasons.push('durable-intent.yml must name the site and contain current accepted/hash-valid intent or an explicit empty intent record list.');
  }

  return reasons;
}

async function packetCompletionReadiness(packetDir, gates, records) {
  const reasons = [];
  if (!gates) {
    return { packetCompletionReady: false, reasons: ['Gate vocabulary could not be loaded.'] };
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

  reasons.push(...await markdownCompletionReadiness(packetDir));

  const {
    blindAdversarialReview,
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    parityReport,
    patternMap,
    routeMatrix,
    sourceAudit
  } = records;
  reasons.push(...await independentStructuredGateReasons({
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    packetDir,
    patternMap,
    routeMatrix,
    sourceAudit
  }));
  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes);
  const primaryRoutePaths = primaryRoutes.map((route) => normalizeRouteKey(route?.targetPath)).filter(Boolean);
  const primarySourceRoutePaths = primaryRoutes.map((route) => normalizeRouteKey(route?.sourcePath)).filter(Boolean);
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
      !normalizeRouteKey(route?.sourcePath) ||
      !normalizeRouteKey(route?.targetPath) ||
      numericValue(route?.sourceStatus) >= 500 ||
      numericValue(route?.targetStatus) >= 500 ||
      route?.matchesBrowserRenderedSource !== true ||
      route?.accepted !== true ||
      !routeRows.some((row) =>
        normalizeRouteKey(row?.sourcePath) === normalizeRouteKey(route?.sourcePath) &&
        normalizeRouteKey(row?.targetPath) === normalizeRouteKey(route?.targetPath)
      )
    )
  ) {
    reasons.push('Every primary route must have source/target paths, a matching route row, browser-rendered source binding, and acceptance.');
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
      const targetPath = normalizeRouteKey(route?.targetPath);
      const targetFinalPath = normalizeRouteKey(route?.targetFinalPath);
      const declaredServerError = numericValue(route?.sourceStatus) >= 500 || numericValue(route?.targetStatus) >= 500;
      const redirectContractValid = route?.expectedRedirect === true &&
        redirectStatus(route?.targetStatus) &&
        Boolean(targetFinalPath) &&
        targetFinalPath !== targetPath;
      const directContractValid = route?.expectedRedirect === false &&
        successfulStatus(route?.targetStatus) &&
        targetFinalPath === targetPath;
      return route?.accepted !== true || declaredServerError || (!redirectContractValid && !directContractValid);
    })
  ) {
    reasons.push('route-matrix.json route rows must be accepted, reject declared 5xx responses, and declare either a direct final 2xx path or an intentional initial 3xx redirect with its expected final path.');
  }
  if (
    arrayOrEmpty(routeMatrix?.blockedRoutes).length > 0 ||
    arrayOrEmpty(routeMatrix?.missingSourceRoutes).length > 0 ||
    arrayOrEmpty(routeMatrix?.wrongPatternRoutes).length > 0
  ) {
    reasons.push('route-matrix.json still records blocked, missing, or wrong-pattern routes.');
  }

  const expansion = routeMatrix?.browserFirstRouteExpansion ?? {};
  const discoveredSourceRoutes = new Set([
    ...arrayOrEmpty(expansion.browserRenderedSeedRoutes),
    ...arrayOrEmpty(expansion.candidateRoutesFromRenderedLinks),
    ...arrayOrEmpty(expansion.candidateRoutesFromBundles),
    ...arrayOrEmpty(expansion.candidateRoutesFromMetadata),
    ...arrayOrEmpty(expansion.candidateRoutesFromAssets),
    ...arrayOrEmpty(expansion.candidateRoutesFromSitemapsOrRobots),
    ...arrayOrEmpty(expansion.candidateRoutesFromNamingPatterns)
  ].map(routeLikeValue).filter(Boolean));
  const driftRecords = substantiveObjects(routeMatrix?.sourceRouteDriftClassification);
  const acceptedDriftRoutes = new Set(driftRecords.filter((record) =>
    record?.accepted === true &&
    normalizeRouteKey(record.sourcePath) &&
    !['unknown'].includes(record.classification) &&
    !['blocked', 'owner_decision_required'].includes(record.targetDisposition) &&
    String(record.notes ?? '').trim()
  ).map((record) => normalizeRouteKey(record.sourcePath)));
  if (
    driftRecords.some((record) => !acceptedDriftRoutes.has(normalizeRouteKey(record.sourcePath))) ||
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
        recordMatchesRoute(record, normalizeRouteKey(route.sourcePath), normalizeRouteKey(route.targetPath)) &&
        record.viewport === viewport &&
        record.heroArtworkMatchesOrDispositioned === true &&
        record.logoOrLockupMatchesOrDispositioned === true &&
        record.signatureGraphicsMatchOrDispositioned === true &&
        record.primaryCtaTreatmentMatchesOrDispositioned === true &&
        record.accepted === true &&
        String(record.notes ?? '').trim()
      )) {
        reasons.push(`route-matrix.json needs accepted first-fold brand parity for ${normalizeRouteKey(route.targetPath)} at ${viewport}.`);
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
      normalizeRouteKey(owner?.sourceRoute) &&
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
      (route) => !acceptedPageOwners.some((owner) => normalizeRouteKey(owner.sourceRoute) === normalizeRouteKey(route.sourcePath))
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
        routeRecordPath(check) === route && check?.status === 'pass' && String(check?.evidence ?? '').trim()
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
  let browserScreenshotsCredible = true;
  const browserEvidenceDir = join(packetDir, 'evidence', 'browser');
  for (const check of publicRouteChecks) {
    for (const field of ['sourceScreenshot', 'targetScreenshot']) {
      const screenshotPath = resolveReviewEvidencePath(packetDir, browserEvidenceDir, check?.[field]);
      const metadata = screenshotPath ? await evidenceImageMetadata(screenshotPath) : null;
      if (
        !metadata ||
        metadata.size < MIN_SCREENSHOT_BYTES ||
        metadata.width < MIN_SCREENSHOT_DIMENSION ||
        metadata.height < MIN_SCREENSHOT_DIMENSION
      ) {
        browserScreenshotsCredible = false;
      }
    }
  }
  if (
    isoTimestamp(browserEvidence?.checkedAt) === null ||
    browserEvidence?.browserEvidenceComplete !== true ||
    arrayOrEmpty(browserEvidence?.missingBrowserEvidence).length > 0 ||
    publicRouteChecks.length === 0 ||
    !browserScreenshotsCredible ||
    publicRouteChecks.some((check) =>
      check?.accepted !== true ||
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
      renderedSeoRoutes.add(routeRecordPath(check));
    }
  }
  if (primaryRoutePaths.some((route) => !renderedSeoRoutes.has(route))) {
    reasons.push('browser-evidence.json must contain accepted rendered canonical, description, and social-image dispositions for every primary route.');
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
    ['independent-verification.json', independentVerification?.checkedAt],
    ['blind-adversarial-review.json', blindAdversarialReview?.checkedAt],
    ['drupal-readback.json', drupalReadback?.checkedAt],
    ['field-output-matrix.json', fieldOutputMatrix?.checkedAt]
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

  return { packetCompletionReady: reasons.length === 0, reasons };
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
  const routeMatrix = await readJson(join(packetDir, 'route-matrix.json'), []);
  const parityReport = await readJson(join(packetDir, 'parity-report.json'), []);
  const browserEvidence = await readJson(join(packetDir, 'browser-evidence.json'), []);
  const drupalReadback = await readJson(join(packetDir, 'drupal-readback.json'), []);
  const fieldOutputMatrix = await readJson(join(packetDir, 'field-output-matrix.json'), []);
  const patternMap = await readJson(join(packetDir, 'pattern-map.json'), []);
  const sourceAudit = await readJson(join(packetDir, 'source-audit.json'), []);
  rejectAuthoredCompletionClaims(independentVerification, blindAdversarialReview, errors);
  const independentVerificationSupportsCompletion = await validateIndependentVerification(
    packetDir,
    independentVerification,
    {
      browserEvidence,
      drupalReadback,
      fieldOutputMatrix,
      patternMap,
      routeMatrix,
      sourceAudit
    },
    errors
  );
  const blindAdversarialReviewSupportsCompletion = await validateBlindAdversarialReview(
    packetDir,
    blindAdversarialReview,
    routeMatrix,
    errors
  );
  await validateDurableIntent(packetDir, errors);
  await validateRecipeStartPoint(packetDir, errors);
  const completionReadiness = await packetCompletionReadiness(packetDir, gates, {
    blindAdversarialReview,
    browserEvidence,
    drupalReadback,
    fieldOutputMatrix,
    independentVerification,
    parityReport,
    patternMap,
    routeMatrix,
    sourceAudit
  });

  return {
    schemaVersion: 'public-kit.packet-verification.1',
    checkedAt: new Date().toISOString(),
    claimScope: 'complete-local-rebuild',
    productionReadinessEvaluated: false,
    launchReady: false,
    packetDir: sharedPacketDir(packetDir),
    gatesSchemaVersion: gates?.schemaVersion ?? '',
    gateCount: gates?.gates?.length ?? 0,
    requiredFileCount: gates?.reviewPacketFiles?.length ?? 0,
    verificationMode: 'packet-only',
    completionEvidence: {
      independentVerificationSupportsCompletion,
      blindAdversarialReviewSupportsCompletion,
      packetCompletionReady: completionReadiness.packetCompletionReady,
      packetCompletionBlockedReasons: completionReadiness.reasons,
      packetSupportsCompletion:
        independentVerificationSupportsCompletion &&
        blindAdversarialReviewSupportsCompletion &&
        completionReadiness.packetCompletionReady
    },
    completeLocalRebuildClaimAllowed: false,
    valid: errors.length === 0,
    errors: errors.map((error) => sharedPacketMessage(error, packetDir)),
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
