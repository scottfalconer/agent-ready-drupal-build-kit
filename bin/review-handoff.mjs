#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  opendirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, hashManifest, sha256 } from './state-fingerprint.mjs';
import { isCurrentLiveVerificationReport } from './live-verification-contract.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = resolve(dirname(SCRIPT_PATH), '..');
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HANDOFF_PATH = 'evidence/review-handoff.json';
const HANDOFF_SCHEMA = 'public-kit.review-handoff.1';
const HANDOFF_REFERENCE_SCHEMA = 'public-kit.review-handoff-reference.1';
const PROJECTION_SCHEMA = 'public-kit.review-handoff-projection.1';
const PROJECTION_REFERENCE_SCHEMA = 'public-kit.review-handoff-projection-reference.1';
const PROJECTION_PATHS = Object.freeze({
  blind: 'evidence/review-handoff-blind.json',
  independent: 'evidence/review-handoff-independent.json'
});
const MAX_HANDOFF_FILES = 2048;
const MAX_HANDOFF_ENTRIES = 4096;
const MAX_HANDOFF_FILE_BYTES = 25 * 1024 * 1024;
const MAX_HANDOFF_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_HANDOFF_DEPTH = 12;
const MAX_HANDOFF_JSON_DEPTH = 64;
const MAX_HANDOFF_JSON_NODES = 10000;
const SECRET_PATH_PATTERNS = [
  /(?:^|\/)\.env(?:\.|$)/i,
  /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|\.netrc|\.npmrc)(?:[._-](?:bak|backup|copy|old|temp|tmp))?$/i,
  /\.(?:key|p12|pfx|pem)$/i
];
const SECRET_BASENAME_SUFFIX_PATTERN = /(?:^|[-_.])(?:auth|cookies?|credentials?|kubeconfigs?|passphrases?|passwords?|passwd|secrets?|storage[-_.]?state|tokens?|api[-_.]?keys?|access[-_.]?keys?(?:[-_.]?ids?)?|client[-_.]?secrets?|private[-_.]?keys?|service[-_.]?accounts?(?:[-_.](?:credentials?|keys?))?|ssh(?:[-_.]?host)?[-_.]?(?:rsa|dsa|ecdsa|ed25519)[-_.]?keys?)(?:[-_.](?:bak|backup|ci|copy|dev|development|local|old|prod|production|stage|staging|temp|test|testing|tmp)){0,2}$/i;
const FORBIDDEN_AUTHORITY_KEYS = new Set([
  'completionClaim',
  'completionClaims',
  'readbackComplete',
  'reviewerArtifact',
  'reviewerIdentity',
  'verdict'
]);
const REVIEW_OUTPUT_PREFIXES = [
  'independent-verification.json',
  'blind-adversarial-review.json',
  'evidence/independent-verification/',
  'evidence/blind-adversarial-review/',
  'evidence/lifecycle/',
  'evidence/live-verification.json',
  'evidence/packet-verification.json',
  PROJECTION_PATHS.independent,
  PROJECTION_PATHS.blind,
  `${HANDOFF_PATH}`
];
const BLIND_INPUT_KEYS = new Set([
  'acceptanceCriteria',
  'credentialsUsed',
  'excludedInputs',
  'originalBrief',
  'sourceOfTruthMaterials',
  'targetUrlsOrArtifacts'
]);
const SOURCE_MATERIAL_TYPES = new Set([
  'source_site',
  'screenshot',
  'design_file',
  'content_inventory',
  'brand_guide',
  'written_spec',
  'other'
]);

const INDEPENDENT_EXCLUDED_INPUTS = Object.freeze([
  'builder final summary',
  'prior build conversation',
  'independent-verification.json from an earlier run',
  'blind-adversarial-review.json from an earlier run'
]);
const BLIND_EXCLUDED_INPUTS = Object.freeze([
  'implementation files',
  'review packet before public or artifact review',
  'builder notes and scripts',
  'prior build conversation',
  'self-authored completion claims',
  'builder final summary'
]);

class UsageError extends Error {}

function usage() {
  return `Usage: node <path-to-skill>/scripts/review-handoff.mjs [options]

Create the self-attested, non-authoritative input manifest used to hand an exact
Drupal target state to independent and blind reviewers.

Options:
  --project <path>             Drupal project root (default: current directory)
  --packet <path>              Packet directory inside the project (default: review-packet)
  --independent-credential-label <id>
                               Out-of-band independent-review credential label
  --blind-credential-label <id>
                               Out-of-band blind-review credential label
  --help                       Show this help

Run the live verifier once before this command. The handoff binds that inspected
target state and exact reviewer input bytes, then writes separate independent and
blind input projections. It never writes reviewer artifacts, identities, verdicts,
completion claims, or drupal-readback.json.
`;
}

function parseArgs(argv) {
  const options = {
    blindCredentialLabels: [],
    independentCredentialLabels: [],
    packet: 'review-packet',
    project: process.cwd()
  };
  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }
    const equalsIndex = argument.indexOf('=');
    const option = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    if (![
      '--project',
      '--packet',
      '--independent-credential-label',
      '--blind-credential-label'
    ].includes(option)) {
      throw new UsageError(
        argument.startsWith('-') ? `Unknown option: ${argument}.` : `Unexpected positional argument: ${argument}.`
      );
    }
    const value = equalsIndex === -1 ? argv[index + 1] : argument.slice(equalsIndex + 1);
    if (!value || (equalsIndex === -1 && value.startsWith('--'))) {
      throw new UsageError(`${option} requires a value.`);
    }
    if (equalsIndex === -1) index += 1;
    if (option === '--independent-credential-label') options.independentCredentialLabels.push(value);
    if (option === '--blind-credential-label') options.blindCredentialLabels.push(value);
    if (option === '--packet') options.packet = value;
    if (option === '--project') options.project = value;
  }
  return options;
}

function portablePath(path) {
  return String(path).split(sep).join('/');
}

function comparePortable(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function pathIsInside(parent, child) {
  const fromParent = relative(parent, child);
  return fromParent === '' || (
    fromParent !== '..' &&
    !fromParent.startsWith(`..${sep}`) &&
    !isAbsolute(fromParent)
  );
}

function isJsonObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeRelativePath(value, label = 'Path') {
  const path = portablePath(String(value ?? '').trim()).replace(/^\.\//, '');
  if (
    !path ||
    path === '.' ||
    isAbsolute(path) ||
    path.startsWith('/') ||
    /^[a-z]:\//i.test(path) ||
    path.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error(`${label} must be a non-empty project-relative path without traversal.`);
  }
  return path;
}

function safeProjectPath(projectRoot, value, label) {
  const text = String(value ?? '').trim();
  if (!text || isAbsolute(text) || /^[a-z]:[\\/]/i.test(text)) {
    throw new Error(`${label} must be a project-relative path.`);
  }
  const path = resolve(projectRoot, text);
  if (!pathIsInside(projectRoot, path)) {
    throw new Error(`${label} must stay inside the Drupal project.`);
  }
  return path;
}

function regularFile(path, label) {
  if (!existsSync(path)) throw new Error(`${label} does not exist.`);
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file.`);
  }
}

function assertNoSymlinkAncestors(root, path, label) {
  const absoluteRoot = resolve(root);
  const absolutePath = resolve(path);
  if (!pathIsInside(absoluteRoot, absolutePath)) {
    throw new Error(`${label} must stay inside its declared root.`);
  }
  const segments = relative(absoluteRoot, absolutePath).split(sep).filter(Boolean);
  let current = absoluteRoot;
  for (const segment of segments) {
    current = join(current, segment);
    if (lstatSync(current).isSymbolicLink()) {
      throw new Error(`${label} must not traverse a symbolic link.`);
    }
  }
  const realRoot = realpathSync(absoluteRoot);
  const realPath = realpathSync(absolutePath);
  if (!pathIsInside(realRoot, realPath)) {
    throw new Error(`${label} must not escape its declared root through a symbolic link.`);
  }
}

function secretLikePath(path) {
  const portable = portablePath(path);
  if (SECRET_PATH_PATTERNS.some((pattern) => pattern.test(portable))) return true;
  const basename = portable.split('/').filter(Boolean).at(-1) ?? '';
  const stem = basename.replace(/\.[^.]+$/, '');
  return SECRET_BASENAME_SUFFIX_PATTERN.test(stem);
}

function boundedFileMetadata(projectRoot, path, label, { rejectSecrets = true } = {}) {
  regularFile(path, label);
  assertNoSymlinkAncestors(projectRoot, path, label);
  const projectPath = safeRelativePath(relative(projectRoot, path), label);
  if (rejectSecrets && secretLikePath(projectPath)) {
    throw new Error(`${label} uses a secret-like path and cannot be handed to a reviewer: ${projectPath}`);
  }
  const metadata = statSync(path);
  if (metadata.size > MAX_HANDOFF_FILE_BYTES) {
    throw new Error(`${label} exceeds the ${MAX_HANDOFF_FILE_BYTES}-byte review-handoff file limit.`);
  }
  return { path: portablePath(projectPath), size: metadata.size };
}

function boundedFileBinding(projectRoot, path, label, options = {}) {
  const metadata = boundedFileMetadata(projectRoot, path, label, options);
  const bytes = readFileSync(path);
  if (bytes.length !== metadata.size) {
    throw new Error(`${label} changed while its review-handoff bytes were being bound.`);
  }
  return {
    path: metadata.path,
    size: bytes.length,
    sha256: sha256(bytes)
  };
}

function boundedCollector(root, { label = 'Review handoff', rejectSecrets = true } = {}) {
  const candidates = new Map();
  const entries = new Set();
  let totalBytes = 0;
  const reserveEntry = (path, pathLabel, { rejectSecret = rejectSecrets } = {}) => {
    const relativePath = safeRelativePath(relative(root, path), pathLabel);
    if (rejectSecret && secretLikePath(relativePath)) {
      throw new Error(`${pathLabel} uses a secret-like path and cannot be handed to a reviewer: ${relativePath}`);
    }
    if (entries.has(relativePath)) return;
    if (entries.size + 1 > MAX_HANDOFF_ENTRIES) {
      throw new Error(`${label} exceeds the ${MAX_HANDOFF_ENTRIES}-entry traversal limit.`);
    }
    entries.add(relativePath);
  };
  const add = (path, pathLabel) => {
    reserveEntry(path, pathLabel);
    const metadata = boundedFileMetadata(root, path, pathLabel, { rejectSecrets });
    if (candidates.has(metadata.path)) return;
    if (candidates.size + 1 > MAX_HANDOFF_FILES) {
      throw new Error(`${label} exceeds the ${MAX_HANDOFF_FILES}-file input limit before file bytes are read.`);
    }
    if (totalBytes + metadata.size > MAX_HANDOFF_TOTAL_BYTES) {
      throw new Error(`${label} exceeds the ${MAX_HANDOFF_TOTAL_BYTES}-byte aggregate input limit before file bytes are read.`);
    }
    totalBytes += metadata.size;
    candidates.set(metadata.path, { absolutePath: path, label: pathLabel, reservedSize: metadata.size });
  };
  const bindings = () => [...candidates.values()]
    .map((candidate) => {
      const binding = boundedFileBinding(root, candidate.absolutePath, candidate.label, { rejectSecrets });
      if (binding.size !== candidate.reservedSize) {
        throw new Error(`${candidate.label} changed after the review-handoff byte budget was reserved.`);
      }
      return binding;
    })
    .sort((left, right) => comparePortable(left.path, right.path));
  return { add, bindings, reserveEntry };
}

function readJson(path, label) {
  regularFile(path, label);
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${label} must contain valid JSON: ${error.message}`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must contain a JSON object.`);
  }
  return value;
}

function credentialLabels(values) {
  const labels = [...new Set(values.map((value) => String(value).trim()))].sort(comparePortable);
  for (const label of labels) {
    if (!/^[a-z][a-z0-9._-]{0,63}$/.test(label)) {
      throw new Error(`Credential label must be a lowercase identifier, not a credential value: ${label}`);
    }
  }
  return labels;
}

function credentialFreeUrl(value, label) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error(`${label} must be an absolute HTTP(S) URL.`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error(`${label} must be a credential-free HTTP(S) URL.`);
  }
  url.hash = '';
  return url;
}

function normalizedUrl(value, label = 'URL') {
  return credentialFreeUrl(value, label).href;
}

function exactOrigin(value, label) {
  const url = credentialFreeUrl(value, label);
  return url.origin;
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value).trim()).filter(Boolean))].sort(comparePortable);
}

function uniqueObjects(values) {
  const byJson = new Map();
  for (const value of values) byJson.set(canonicalJson(value), value);
  return [...byJson.entries()].sort(([left], [right]) => comparePortable(left, right)).map(([, value]) => value);
}

function primaryRouteRows(routeMatrix, targetOrigin, buildMode, briefReference) {
  const rows = Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : [];
  if (rows.length === 0) throw new Error('route-matrix.json must contain at least one primary route.');
  const sourceOrigin = buildMode === 'source_site'
    ? exactOrigin(routeMatrix.sourceBaseUrl, 'route-matrix.json sourceBaseUrl')
    : '';
  return rows.map((route, index) => {
    const targetPath = String(route?.targetPath ?? '').trim();
    if (!targetPath.startsWith('/')) {
      throw new Error(`route-matrix.json primaryRoutes[${index}].targetPath must start with /.`);
    }
    const targetUrl = new URL(targetPath, targetOrigin).href;
    const sourceTruthReference = buildMode === 'source_site'
      ? new URL(String(route?.sourcePath ?? '/'), sourceOrigin).href
      : briefReference;
    return {
      briefRequirementIds: uniqueStrings(Array.isArray(route?.briefRequirementIds) ? route.briefRequirementIds : []),
      sourceTruthReference,
      targetPath,
      targetUrl
    };
  }).sort((left, right) => comparePortable(
    `${left.targetPath}\u0000${left.sourceTruthReference}`,
    `${right.targetPath}\u0000${right.sourceTruthReference}`
  ));
}

function reviewOutputPath(packetPath) {
  return REVIEW_OUTPUT_PREFIXES.some((prefix) => (
    prefix.endsWith('/') ? packetPath.startsWith(prefix) : packetPath === prefix
  ));
}

export function reviewHandoffInputFileBindings(projectRoot, packetDir, declaredPacketFiles, extraPacketPaths = []) {
  const collector = boundedCollector(projectRoot, { label: 'Review handoff' });
  const packetDepth = (packetPath, label) => {
    const directoryDepth = safeRelativePath(packetPath, label).split('/').length - 1;
    if (directoryDepth > MAX_HANDOFF_DEPTH) {
      throw new Error(`${label} exceeds the ${MAX_HANDOFF_DEPTH}-level review-handoff directory limit.`);
    }
  };
  const addPacketFile = (packetPath, label) => {
    const safe = safeRelativePath(packetPath, label);
    if (reviewOutputPath(safe)) return;
    packetDepth(safe, label);
    const path = resolve(packetDir, safe);
    if (!pathIsInside(packetDir, path)) throw new Error(`${label} must stay inside the packet.`);
    collector.add(path, label);
  };
  for (const packetFile of declaredPacketFiles) addPacketFile(packetFile, 'gates.json review packet file');
  for (const packetPath of extraPacketPaths) {
    const absolute = resolve(projectRoot, packetPath);
    if (!pathIsInside(packetDir, absolute)) {
      throw new Error(`Reviewer file input must stay inside the packet: ${packetPath}`);
    }
    addPacketFile(relative(packetDir, absolute), 'Reviewer packet file');
  }

  const evidenceRoot = join(packetDir, 'evidence');
  const visitEvidence = (directory, depth = 0) => {
    if (depth > MAX_HANDOFF_DEPTH) {
      throw new Error(`Review handoff evidence exceeds the ${MAX_HANDOFF_DEPTH}-level directory limit.`);
    }
    const entries = opendirSync(directory);
    try {
      let entry;
      while ((entry = entries.readSync()) !== null) {
        const path = join(directory, entry.name);
        const packetPath = portablePath(relative(packetDir, path));
        if (reviewOutputPath(entry.isDirectory() ? `${packetPath}/` : packetPath)) continue;
        collector.reserveEntry(path, `Review handoff evidence entry ${packetPath}`, { rejectSecret: false });
        const metadata = lstatSync(path);
        if (metadata.isSymbolicLink()) {
          throw new Error(`Review handoff inputs must not contain symlinks: ${packetPath}`);
        }
        if (metadata.isDirectory()) {
          visitEvidence(path, depth + 1);
        } else if (metadata.isFile()) {
          addPacketFile(packetPath, `Review handoff evidence file ${packetPath}`);
        } else {
          throw new Error(`Review handoff inputs must contain only regular files and directories: ${packetPath}`);
        }
      }
    } finally {
      entries.closeSync();
    }
  };
  if (existsSync(evidenceRoot)) {
    assertNoSymlinkAncestors(packetDir, evidenceRoot, 'Review handoff evidence root');
    visitEvidence(evidenceRoot);
  }

  const agentsPath = join(projectRoot, 'AGENTS.md');
  collector.add(agentsPath, 'AGENTS.md');
  return collector.bindings();
}

export function reviewHandoffPreliminaryPacketFingerprint(packetDir) {
  const absolutePacketDir = resolve(packetDir);
  const collector = boundedCollector(absolutePacketDir, {
    label: 'Preliminary review-packet fingerprint',
    rejectSecrets: false
  });
  const visit = (directory, depth = 0) => {
    if (depth > MAX_HANDOFF_DEPTH) {
      throw new Error(`Preliminary review-packet fingerprint exceeds the ${MAX_HANDOFF_DEPTH}-level directory limit.`);
    }
    const entries = opendirSync(directory);
    try {
      let entry;
      while ((entry = entries.readSync()) !== null) {
        const path = join(directory, entry.name);
        const packetPath = portablePath(relative(absolutePacketDir, path));
        const metadata = lstatSync(path);
        if (metadata.isSymbolicLink()) throw new Error(`Review packet evidence must not contain symbolic links: ${packetPath}`);
        if (metadata.isDirectory()) {
          if (packetPath === 'evidence/lifecycle' || packetPath.startsWith('evidence/lifecycle/')) continue;
          collector.reserveEntry(path, `Review packet directory ${packetPath}`);
          visit(path, depth + 1);
        } else if (metadata.isFile()) {
          if (![
            'evidence/live-verification.json',
            'evidence/packet-verification.json',
            HANDOFF_PATH,
            PROJECTION_PATHS.independent,
            PROJECTION_PATHS.blind
          ].includes(packetPath)) collector.add(path, `Review packet file ${packetPath}`);
        } else {
          throw new Error(`Review packet evidence must contain only regular files and directories: ${packetPath}`);
        }
      }
    } finally {
      entries.closeSync();
    }
  };
  visit(absolutePacketDir);
  return hashManifest(collector.bindings()).fingerprint;
}

function packetLocalReference(projectRoot, packetDir, reference, label) {
  const path = safeProjectPath(projectRoot, reference, label);
  regularFile(path, label);
  assertNoSymlinkAncestors(projectRoot, path, label);
  if (!pathIsInside(packetDir, path)) {
    throw new Error(`${label} must stay inside the review packet.`);
  }
  boundedFileBinding(projectRoot, path, label);
  return portablePath(relative(projectRoot, path));
}

function packetReferenceBinding(projectRoot, reference, label) {
  const path = resolve(projectRoot, reference);
  const binding = boundedFileBinding(projectRoot, path, label);
  return { kind: 'packet_file', reference: binding.path, sha256: binding.sha256, size: binding.size };
}

function briefInput(projectRoot, packetDir, buildInput, blindInputs) {
  if (buildInput.mode === 'brief') {
    const reference = packetLocalReference(projectRoot, packetDir, buildInput?.brief?.path, 'build-input.json brief.path');
    const binding = packetReferenceBinding(projectRoot, reference, 'Preserved original brief');
    const digest = binding.sha256;
    if (digest !== buildInput?.brief?.sha256) {
      throw new Error('build-input.json brief.sha256 does not match the preserved original brief.');
    }
    return binding;
  }
  const original = String(blindInputs?.originalBrief ?? '').trim();
  if (!original) {
    throw new Error('blind-adversarial-review.json reviewInputs.originalBrief must be seeded before creating a source-site review handoff.');
  }
  if (/^(?:\.\/)?review-packet\//.test(original)) {
    const reference = packetLocalReference(projectRoot, packetDir, original.replace(/^\.\//, ''), 'Blind original brief');
    return packetReferenceBinding(projectRoot, reference, 'Blind original brief');
  }
  return { kind: 'literal', reference: original, sha256: sha256(original), size: Buffer.byteLength(original) };
}

function acceptanceCriteria(buildInput, briefAcceptance, blindInputs) {
  if (buildInput.mode === 'brief') {
    const requirements = Array.isArray(briefAcceptance?.requirements) ? briefAcceptance.requirements : [];
    if (requirements.length === 0) throw new Error('brief-acceptance.json must contain requirements.');
    return requirements.map((requirement, index) => {
      const id = String(requirement?.id ?? '').trim();
      const text = String(requirement?.requirement ?? '').trim();
      if (!id || !text) throw new Error(`brief-acceptance.json requirements[${index}] needs id and requirement.`);
      return `${id} ${text}`;
    });
  }
  return uniqueStrings(Array.isArray(blindInputs?.acceptanceCriteria) ? blindInputs.acceptanceCriteria : []);
}

function sourceTruthMaterials(projectRoot, packetDir, buildInput, routeMatrix, blindInputs, brief) {
  const seeded = Array.isArray(blindInputs?.sourceOfTruthMaterials)
    ? blindInputs.sourceOfTruthMaterials
    : [];
  const materials = [];
  for (const [index, material] of seeded.entries()) {
    const type = String(material?.type ?? '').trim();
    const rawReference = String(material?.reference ?? '').trim();
    if (!SOURCE_MATERIAL_TYPES.has(type) || !rawReference) {
      throw new Error(`blind-adversarial-review.json sourceOfTruthMaterials[${index}] needs a supported type and reference.`);
    }
    if (/^https?:\/\//i.test(rawReference)) {
      materials.push({ kind: 'url', reference: normalizedUrl(rawReference, `sourceOfTruthMaterials[${index}].reference`), type });
    } else {
      const reference = packetLocalReference(projectRoot, packetDir, rawReference, `sourceOfTruthMaterials[${index}].reference`);
      const binding = packetReferenceBinding(projectRoot, reference, `sourceOfTruthMaterials[${index}].reference`);
      materials.push({ ...binding, type });
    }
  }
  if (buildInput.mode === 'brief') {
    materials.push({ ...brief, type: 'written_spec' });
  } else {
    const sourceOrigin = exactOrigin(routeMatrix.sourceBaseUrl, 'route-matrix.json sourceBaseUrl');
    materials.push({ kind: 'url', reference: `${sourceOrigin}/`, type: 'source_site' });
    for (const material of materials.filter((value) => value.type === 'source_site')) {
      if (exactOrigin(material.reference, 'Source-site material') !== sourceOrigin) {
        throw new Error('Every source_site material must use route-matrix.json sourceBaseUrl.');
      }
    }
  }
  return uniqueObjects(materials);
}

function stateBinding(report, buildMode, projectRoot, packetDir) {
  if (!isCurrentLiveVerificationReport(report)) {
    throw new Error('Run the live-target verifier before creating a review handoff.');
  }
  if (
    report.liveTargetValid !== true ||
    report?.buildState?.complete !== true ||
    report?.drupalRuntime?.authoritativeForCompletion !== true ||
    report?.drupalRuntime?.confirmed !== true ||
    report?.drupalRuntime?.siteUuidMatchesPacket !== true ||
    report?.drupalRuntime?.configStatusClean !== true ||
    report?.drupalRuntime?.configSyncMatchesHead !== true
  ) {
    throw new Error('The latest live verification must confirm a clean, authoritative target state before reviewer handoff.');
  }
  const targetOrigin = exactOrigin(report?.target?.resolvedBaseUrl, 'live-verification target.resolvedBaseUrl');
  const siteUuid = String(report?.buildState?.targetIdentity?.siteUuid ?? '').trim().toLowerCase();
  const fingerprint = String(report?.buildState?.fingerprint ?? '').trim();
  const targetIdentityFingerprint = String(report?.buildState?.componentFingerprints?.targetIdentity ?? '').trim();
  const preliminaryPacketEvidenceFingerprint = String(
    report?.buildState?.evidenceBindings?.packetFingerprint ?? ''
  ).trim();
  if (
    !UUID_RE.test(siteUuid) ||
    !HASH_RE.test(fingerprint) ||
    !HASH_RE.test(targetIdentityFingerprint) ||
    !HASH_RE.test(preliminaryPacketEvidenceFingerprint)
  ) {
    throw new Error('The latest live verification is missing its site UUID, state fingerprints, or packet-evidence fingerprint.');
  }
  if (report.buildMode !== buildMode) {
    throw new Error('The latest live verification build mode does not match build-input.json.');
  }
  const currentPreliminaryFingerprint = reviewHandoffPreliminaryPacketFingerprint(packetDir);
  if (currentPreliminaryFingerprint !== preliminaryPacketEvidenceFingerprint) {
    throw new Error('The packet changed after the preliminary live verification; rerun live verification before reviewer handoff.');
  }
  return {
    buildMode,
    configSyncDirectory: String(report.buildState.targetIdentity.configSyncDirectory ?? ''),
    frontPage: String(report.buildState.targetIdentity.frontPage ?? ''),
    packetPath: portablePath(relative(projectRoot, packetDir)),
    preliminaryPacketEvidenceFingerprint,
    siteStateFingerprint: fingerprint,
    siteUuid,
    targetIdentityFingerprint,
    targetOrigin
  };
}

function forbiddenAuthorityKeyErrors(value, path = '$') {
  const errors = [];
  const stack = [{ value, path, depth: 0 }];
  let inspectedNodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current.value || typeof current.value !== 'object') continue;
    inspectedNodes += 1;
    if (inspectedNodes > MAX_HANDOFF_JSON_NODES) {
      errors.push(`Review handoff JSON exceeds the ${MAX_HANDOFF_JSON_NODES}-node validation limit.`);
      break;
    }
    if (current.depth > MAX_HANDOFF_JSON_DEPTH) {
      errors.push(`${current.path} exceeds the ${MAX_HANDOFF_JSON_DEPTH}-level validation depth limit.`);
      continue;
    }
    if (Array.isArray(current.value)) {
      if (inspectedNodes + stack.length + current.value.length > MAX_HANDOFF_JSON_NODES) {
        errors.push(`Review handoff JSON exceeds the ${MAX_HANDOFF_JSON_NODES}-node validation limit.`);
        return uniqueStrings(errors);
      }
      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        stack.push({ value: current.value[index], path: `${current.path}[${index}]`, depth: current.depth + 1 });
      }
      continue;
    }
    const entries = Object.entries(current.value);
    if (inspectedNodes + stack.length + entries.length > MAX_HANDOFF_JSON_NODES) {
      errors.push(`Review handoff JSON exceeds the ${MAX_HANDOFF_JSON_NODES}-node validation limit.`);
      return uniqueStrings(errors);
    }
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const [key, child] = entries[index];
      if (FORBIDDEN_AUTHORITY_KEYS.has(key)) {
        errors.push(`${current.path}.${key} is forbidden in a review handoff.`);
      }
      stack.push({ value: child, path: `${current.path}.${key}`, depth: current.depth + 1 });
    }
  }
  return uniqueStrings(errors);
}

export function reviewHandoffDigest(manifest) {
  const copy = structuredClone(manifest);
  delete copy.handoffDigest;
  return sha256(copy);
}

export function reviewHandoffProjectionDigest(projection) {
  const copy = structuredClone(projection);
  delete copy.handoff;
  delete copy.projectionDigest;
  return sha256(copy);
}

function authorityRecord() {
  return {
    completionAuthority: false,
    reviewerIdentityAuthority: false,
    selfAttested: true,
    writesReviewerArtifacts: false
  };
}

function projectionReference(kind, digest) {
  return {
    schemaVersion: PROJECTION_REFERENCE_SCHEMA,
    reviewerKind: kind,
    path: PROJECTION_PATHS[kind],
    digest
  };
}

function reviewerInputFingerprint(files) {
  return sha256({
    schemaVersion: 'public-kit.review-handoff-input-files.1',
    files: [...files].sort((left, right) => comparePortable(left.path, right.path))
  });
}

export function sealReviewHandoffBundle({ binding, blind, independent }) {
  const cores = {
    blind: {
      schemaVersion: PROJECTION_SCHEMA,
      reviewerKind: 'blind',
      authority: authorityRecord(),
      allowedInputs: structuredClone(blind.allowedInputs),
      excludedInputs: [...blind.excludedInputs]
    },
    independent: {
      schemaVersion: PROJECTION_SCHEMA,
      reviewerKind: 'independent',
      authority: authorityRecord(),
      allowedInputs: structuredClone(independent.allowedInputs),
      excludedInputs: [...independent.excludedInputs]
    }
  };
  const projectionDigests = Object.fromEntries(
    Object.entries(cores).map(([kind, core]) => [kind, reviewHandoffProjectionDigest(core)])
  );
  const manifest = sealReviewHandoff({
    schemaVersion: HANDOFF_SCHEMA,
    authority: authorityRecord(),
    binding: {
      ...binding,
      reviewerInputFingerprint: reviewerInputFingerprint(independent.allowedInputs.files)
    },
    reviewerProjections: {
      blind: projectionReference('blind', projectionDigests.blind),
      independent: projectionReference('independent', projectionDigests.independent)
    }
  });
  const projections = Object.fromEntries(Object.entries(cores).map(([kind, core]) => [kind, {
    ...core,
    handoff: reviewHandoffReference(manifest.handoffDigest),
    projectionDigest: projectionDigests[kind]
  }]));
  return { manifest, projections };
}

export function sealReviewHandoff(manifest) {
  const sealed = structuredClone(manifest);
  delete sealed.handoffDigest;
  const authorityErrors = forbiddenAuthorityKeyErrors(sealed);
  if (authorityErrors.length > 0) throw new Error(authorityErrors.join('\n'));
  sealed.handoffDigest = reviewHandoffDigest(sealed);
  return sealed;
}

export function reviewHandoffReference(digest) {
  if (!HASH_RE.test(String(digest ?? ''))) throw new Error('Review handoff digest must be sha256:<64 hex>.');
  return {
    schemaVersion: HANDOFF_REFERENCE_SCHEMA,
    manifest: HANDOFF_PATH,
    digest
  };
}

function unknownKeyErrors(value, allowed, path) {
  if (!isJsonObject(value)) return [];
  return Object.keys(value)
    .filter((key) => !allowed.has(key))
    .map((key) => `${path}.${key} is not allowed.`);
}

function objectAt(value, path, errors) {
  if (!isJsonObject(value)) {
    errors.push(`${path} must be a JSON object.`);
    return null;
  }
  return value;
}

function stringArrayErrors(value, path) {
  if (!Array.isArray(value)) return [`${path} must be an array.`];
  if (value.some((entry) => typeof entry !== 'string' || !entry.trim())) {
    return [`${path} must contain only non-empty strings.`];
  }
  return [];
}

function authorityErrors(value, path) {
  const errors = [];
  const authority = objectAt(value, path, errors);
  if (!authority) return errors;
  errors.push(...unknownKeyErrors(authority, new Set([
    'completionAuthority',
    'reviewerIdentityAuthority',
    'selfAttested',
    'writesReviewerArtifacts'
  ]), path));
  if (
    authority.selfAttested !== true ||
    authority.completionAuthority !== false ||
    authority.reviewerIdentityAuthority !== false ||
    authority.writesReviewerArtifacts !== false
  ) {
    errors.push(`${path} must remain self-attested and explicitly non-authoritative.`);
  }
  return errors;
}

function projectionReferenceErrors(value, kind, path) {
  const errors = [];
  const reference = objectAt(value, path, errors);
  if (!reference) return errors;
  errors.push(...unknownKeyErrors(reference, new Set(['schemaVersion', 'reviewerKind', 'path', 'digest']), path));
  if (
    reference.schemaVersion !== PROJECTION_REFERENCE_SCHEMA ||
    reference.reviewerKind !== kind ||
    reference.path !== PROJECTION_PATHS[kind] ||
    !HASH_RE.test(String(reference.digest ?? ''))
  ) {
    errors.push(`${path} must reference the exact ${kind} review-handoff projection.`);
  }
  return errors;
}

export function reviewHandoffManifestErrors(manifest) {
  const errors = [];
  if (!isJsonObject(manifest)) {
    return ['review-handoff.json must contain a JSON object.'];
  }
  errors.push(...unknownKeyErrors(manifest, new Set([
    'schemaVersion',
    'authority',
    'binding',
    'reviewerProjections',
    'handoffDigest'
  ]), 'review-handoff.json'));
  if (manifest.schemaVersion !== HANDOFF_SCHEMA) errors.push(`review-handoff.json must use ${HANDOFF_SCHEMA}.`);
  errors.push(...authorityErrors(manifest.authority, 'review-handoff.json.authority'));
  errors.push(...forbiddenAuthorityKeyErrors(manifest));
  let computedDigest = '';
  try {
    computedDigest = reviewHandoffDigest(manifest);
  } catch (error) {
    errors.push(`review-handoff.json cannot be canonically hashed: ${error.message}`);
  }
  if (!HASH_RE.test(String(manifest.handoffDigest ?? '')) || manifest.handoffDigest !== computedDigest) {
    errors.push('review-handoff.json handoffDigest does not match its canonical content.');
  }
  const binding = objectAt(manifest.binding, 'review-handoff.json.binding', errors) ?? {};
  errors.push(...unknownKeyErrors(binding, new Set([
    'buildMode',
    'configSyncDirectory',
    'frontPage',
    'packetPath',
    'preliminaryPacketEvidenceFingerprint',
    'reviewerInputFingerprint',
    'siteStateFingerprint',
    'siteUuid',
    'targetIdentityFingerprint',
    'targetOrigin'
  ]), 'review-handoff.json.binding'));
  if (
    !['brief', 'source_site'].includes(binding.buildMode) ||
    !HASH_RE.test(String(binding.preliminaryPacketEvidenceFingerprint ?? '')) ||
    !HASH_RE.test(String(binding.reviewerInputFingerprint ?? '')) ||
    !HASH_RE.test(String(binding.siteStateFingerprint ?? '')) ||
    !HASH_RE.test(String(binding.targetIdentityFingerprint ?? '')) ||
    !UUID_RE.test(String(binding.siteUuid ?? ''))
  ) {
    errors.push('review-handoff.json binding must identify one build mode, site UUID, target identity, and exact site state.');
  }
  try {
    if (exactOrigin(binding.targetOrigin, 'review-handoff targetOrigin') !== binding.targetOrigin) {
      errors.push('review-handoff.json binding.targetOrigin must be an exact HTTP(S) origin.');
    }
  } catch (error) {
    errors.push(error.message);
  }
  try {
    safeRelativePath(binding.packetPath, 'review-handoff.json binding.packetPath');
  } catch (error) {
    errors.push(error.message);
  }
  if (typeof binding.configSyncDirectory !== 'string' || typeof binding.frontPage !== 'string') {
    errors.push('review-handoff.json binding frontPage and configSyncDirectory must be strings.');
  }
  const reviewerProjections = objectAt(
    manifest.reviewerProjections,
    'review-handoff.json.reviewerProjections',
    errors
  );
  if (reviewerProjections) {
    errors.push(...unknownKeyErrors(reviewerProjections, new Set(['blind', 'independent']), 'review-handoff.json.reviewerProjections'));
  }
  for (const kind of ['independent', 'blind']) {
    errors.push(...projectionReferenceErrors(reviewerProjections?.[kind], kind, `review-handoff.json.reviewerProjections.${kind}`));
  }
  return uniqueStrings(errors);
}

function fileBindingErrors(value, path) {
  const errors = [];
  const binding = objectAt(value, path, errors);
  if (!binding) return errors;
  errors.push(...unknownKeyErrors(binding, new Set(['path', 'size', 'sha256']), path));
  try {
    const safe = safeRelativePath(binding.path, `${path}.path`);
    if (secretLikePath(safe)) errors.push(`${path}.path must not identify a secret-like file.`);
  } catch (error) {
    errors.push(error.message);
  }
  if (!Number.isSafeInteger(binding.size) || binding.size < 0 || binding.size > MAX_HANDOFF_FILE_BYTES) {
    errors.push(`${path}.size must be an integer from 0 through ${MAX_HANDOFF_FILE_BYTES}.`);
  }
  if (!HASH_RE.test(String(binding.sha256 ?? ''))) errors.push(`${path}.sha256 must be sha256:<64 hex>.`);
  return errors;
}

function briefBindingErrors(value, path) {
  const errors = [];
  const brief = objectAt(value, path, errors);
  if (!brief) return errors;
  errors.push(...unknownKeyErrors(brief, new Set(['kind', 'reference', 'size', 'sha256']), path));
  if (!['literal', 'packet_file'].includes(brief.kind)) errors.push(`${path}.kind must be literal or packet_file.`);
  if (typeof brief.reference !== 'string' || !brief.reference.trim()) errors.push(`${path}.reference must be a non-empty string.`);
  if (brief.kind === 'packet_file') {
    errors.push(...fileBindingErrors({ path: brief.reference, size: brief.size, sha256: brief.sha256 }, path));
  } else {
    if (!Number.isSafeInteger(brief.size) || brief.size < 0 || brief.size > MAX_HANDOFF_FILE_BYTES) {
      errors.push(`${path}.size must be a bounded non-negative integer.`);
    }
    if (!HASH_RE.test(String(brief.sha256 ?? ''))) errors.push(`${path}.sha256 must be sha256:<64 hex>.`);
  }
  return errors;
}

function materialBindingErrors(value, path) {
  const errors = [];
  const material = objectAt(value, path, errors);
  if (!material) return errors;
  const packetFile = material.kind === 'packet_file';
  errors.push(...unknownKeyErrors(
    material,
    packetFile ? new Set(['kind', 'reference', 'size', 'sha256', 'type']) : new Set(['kind', 'reference', 'type']),
    path
  ));
  if (!SOURCE_MATERIAL_TYPES.has(material.type)) errors.push(`${path}.type is unsupported.`);
  if (packetFile) {
    errors.push(...fileBindingErrors({ path: material.reference, size: material.size, sha256: material.sha256 }, path));
  } else if (material.kind === 'url') {
    try {
      if (normalizedUrl(material.reference, `${path}.reference`) !== material.reference) {
        errors.push(`${path}.reference must be a canonical credential-free URL.`);
      }
    } catch (error) {
      errors.push(error.message);
    }
  } else {
    errors.push(`${path}.kind must be url or packet_file.`);
  }
  return errors;
}

function routeBindingErrors(value, path) {
  const errors = [];
  const route = objectAt(value, path, errors);
  if (!route) return errors;
  errors.push(...unknownKeyErrors(route, new Set([
    'briefRequirementIds',
    'sourceTruthReference',
    'targetPath',
    'targetUrl'
  ]), path));
  errors.push(...stringArrayErrors(route.briefRequirementIds, `${path}.briefRequirementIds`));
  if (typeof route.sourceTruthReference !== 'string' || !route.sourceTruthReference.trim()) {
    errors.push(`${path}.sourceTruthReference must be a non-empty string.`);
  }
  if (typeof route.targetPath !== 'string' || !route.targetPath.startsWith('/')) {
    errors.push(`${path}.targetPath must start with /.`);
  }
  try {
    normalizedUrl(route.targetUrl, `${path}.targetUrl`);
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}

function allowedInputErrors(value, kind, path, manifest) {
  const errors = [];
  const allowed = objectAt(value, path, errors);
  if (!allowed) return errors;
  const boundTargetOrigin = String(manifest?.binding?.targetOrigin ?? '');
  if (kind === 'independent') {
    errors.push(...unknownKeyErrors(allowed, new Set(['credentialLabels', 'files', 'urls']), path));
    errors.push(...stringArrayErrors(allowed.credentialLabels, `${path}.credentialLabels`));
    if (!Array.isArray(allowed.files)) {
      errors.push(`${path}.files must be an array.`);
    } else {
      allowed.files.forEach((binding, index) => errors.push(...fileBindingErrors(binding, `${path}.files[${index}]`)));
      const filePaths = allowed.files.map((binding) => String(binding?.path ?? ''));
      if (new Set(filePaths).size !== filePaths.length) {
        errors.push(`${path}.files must use unique paths.`);
      }
      const sortedFiles = [...allowed.files].sort((left, right) => comparePortable(left?.path, right?.path));
      try {
        if (canonicalJson(allowed.files) !== canonicalJson(sortedFiles)) {
          errors.push(`${path}.files must use canonical path order.`);
        }
      } catch (error) {
        errors.push(`${path}.files cannot be canonically validated: ${error.message}`);
      }
      if (allowed.files.length > MAX_HANDOFF_FILES) errors.push(`${path}.files exceeds the ${MAX_HANDOFF_FILES}-file limit.`);
      const total = allowed.files.reduce((sum, binding) => sum + (Number.isSafeInteger(binding?.size) ? binding.size : 0), 0);
      if (total > MAX_HANDOFF_TOTAL_BYTES) errors.push(`${path}.files exceeds the ${MAX_HANDOFF_TOTAL_BYTES}-byte aggregate limit.`);
    }
    if (!Array.isArray(allowed.urls)) {
      errors.push(`${path}.urls must be an array.`);
    } else {
      const normalized = new Set();
      for (const [index, url] of allowed.urls.entries()) {
        try { normalized.add(normalizedUrl(url, `${path}.urls[${index}]`)); } catch (error) { errors.push(error.message); }
      }
      if (
        normalized.size !== allowed.urls.length ||
        canonicalJson(allowed.urls) !== canonicalJson([...normalized].sort(comparePortable))
      ) {
        errors.push(`${path}.urls must be unique canonical URLs in stable order.`);
      }
      if (boundTargetOrigin) {
        for (const required of [`${boundTargetOrigin}/`, `${boundTargetOrigin}/admin`]) {
          if (!normalized.has(required)) {
            errors.push(`${path}.urls must include the root-bound target URL ${required}.`);
          }
        }
      }
    }
  } else {
    errors.push(...unknownKeyErrors(allowed, new Set([
      'acceptanceCriteria',
      'brief',
      'credentialLabels',
      'primaryRoutes',
      'sourceOfTruthMaterials',
      'targetUrlsOrArtifacts'
    ]), path));
    errors.push(...stringArrayErrors(allowed.acceptanceCriteria, `${path}.acceptanceCriteria`));
    errors.push(...stringArrayErrors(allowed.credentialLabels, `${path}.credentialLabels`));
    errors.push(...briefBindingErrors(allowed.brief, `${path}.brief`));
    if (!Array.isArray(allowed.primaryRoutes)) errors.push(`${path}.primaryRoutes must be an array.`);
    else allowed.primaryRoutes.forEach((route, index) => {
      errors.push(...routeBindingErrors(route, `${path}.primaryRoutes[${index}]`));
      try {
        if (boundTargetOrigin && exactOrigin(route?.targetUrl, `${path}.primaryRoutes[${index}].targetUrl`) !== boundTargetOrigin) {
          errors.push(`${path}.primaryRoutes[${index}].targetUrl must use the root-bound target origin.`);
        }
      } catch (error) {
        errors.push(error.message);
      }
    });
    if (!Array.isArray(allowed.sourceOfTruthMaterials)) errors.push(`${path}.sourceOfTruthMaterials must be an array.`);
    else allowed.sourceOfTruthMaterials.forEach((material, index) => errors.push(...materialBindingErrors(material, `${path}.sourceOfTruthMaterials[${index}]`)));
    if (!Array.isArray(allowed.targetUrlsOrArtifacts)) errors.push(`${path}.targetUrlsOrArtifacts must be an array.`);
    else for (const [index, url] of allowed.targetUrlsOrArtifacts.entries()) {
      try {
        normalizedUrl(url, `${path}.targetUrlsOrArtifacts[${index}]`);
        if (boundTargetOrigin && exactOrigin(url, `${path}.targetUrlsOrArtifacts[${index}]`) !== boundTargetOrigin) {
          errors.push(`${path}.targetUrlsOrArtifacts[${index}] must use the root-bound target origin.`);
        }
      } catch (error) {
        errors.push(error.message);
      }
    }
  }
  try {
    credentialLabels(Array.isArray(allowed.credentialLabels) ? allowed.credentialLabels : []);
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}

export function reviewHandoffProjectionErrors(projection, kind, manifest) {
  const path = `${PROJECTION_PATHS[kind]}`;
  const errors = [];
  if (!isJsonObject(projection)) return [`${path} must contain a JSON object.`];
  errors.push(...unknownKeyErrors(projection, new Set([
    'schemaVersion',
    'reviewerKind',
    'authority',
    'allowedInputs',
    'excludedInputs',
    'handoff',
    'projectionDigest'
  ]), path));
  if (projection.schemaVersion !== PROJECTION_SCHEMA || projection.reviewerKind !== kind) {
    errors.push(`${path} must use ${PROJECTION_SCHEMA} for the ${kind} reviewer.`);
  }
  errors.push(...authorityErrors(projection.authority, `${path}.authority`));
  errors.push(...allowedInputErrors(projection.allowedInputs, kind, `${path}.allowedInputs`, manifest));
  errors.push(...stringArrayErrors(projection.excludedInputs, `${path}.excludedInputs`));
  const expectedExcluded = kind === 'blind' ? BLIND_EXCLUDED_INPUTS : INDEPENDENT_EXCLUDED_INPUTS;
  if (
    Array.isArray(projection.excludedInputs) &&
    canonicalJson(uniqueStrings(projection.excludedInputs)) !== canonicalJson(uniqueStrings(expectedExcluded))
  ) {
    errors.push(`${path}.excludedInputs must preserve the canonical ${kind} reviewer boundary.`);
  }
  errors.push(...forbiddenAuthorityKeyErrors(projection));
  let digest = '';
  try { digest = reviewHandoffProjectionDigest(projection); } catch (error) {
    errors.push(`${path} cannot be canonically hashed: ${error.message}`);
  }
  if (!HASH_RE.test(String(projection.projectionDigest ?? '')) || projection.projectionDigest !== digest) {
    errors.push(`${path} projectionDigest does not match its canonical allowed-input content.`);
  }
  const rootReferenceErrors = referenceErrors(projection, manifest, path, 'handoff');
  errors.push(...rootReferenceErrors);
  const manifestReference = manifest?.reviewerProjections?.[kind];
  if (
    manifestReference?.digest !== projection.projectionDigest ||
    manifestReference?.path !== PROJECTION_PATHS[kind]
  ) {
    errors.push(`${path} does not match its review-handoff.json projection reference.`);
  }
  if (kind === 'independent' && Array.isArray(projection?.allowedInputs?.files)) {
    try {
      if (reviewerInputFingerprint(projection.allowedInputs.files) !== manifest?.binding?.reviewerInputFingerprint) {
        errors.push(`${path}.allowedInputs.files reviewerInputFingerprint does not match review-handoff.json.`);
      }
    } catch (error) {
      errors.push(`${path}.allowedInputs.files reviewerInputFingerprint cannot be validated: ${error.message}`);
    }
  }
  return uniqueStrings(errors);
}

function referenceErrors(record, manifest, label, field = 'reviewHandoff') {
  const errors = [];
  const reference = record?.[field];
  if (!isJsonObject(reference)) {
    return [`${label} must contain an exact review-handoff reference.`];
  }
  errors.push(...unknownKeyErrors(reference, new Set(['schemaVersion', 'manifest', 'digest']), `${label}.${field}`));
  if (
    reference?.schemaVersion !== HANDOFF_REFERENCE_SCHEMA ||
    reference?.manifest !== HANDOFF_PATH ||
    reference?.digest !== manifest?.handoffDigest
  ) {
    errors.push(`${label} must reference the exact review-handoff.json digest.`);
  }
  return errors;
}

function sameStringSet(left, right) {
  return canonicalJson(uniqueStrings(Array.isArray(left) ? left : [])) === canonicalJson(uniqueStrings(Array.isArray(right) ? right : []));
}

function sameMaterialSet(left, right) {
  const project = (values) => uniqueObjects((Array.isArray(values) ? values : []).map((material) => structuredClone(material)));
  return canonicalJson(project(left)) === canonicalJson(project(right));
}

function projectRootForPacket(manifest, packetDir) {
  const absolutePacketDir = resolve(packetDir);
  const packetPath = safeRelativePath(manifest.binding.packetPath, 'review-handoff.json binding.packetPath');
  const projectRoot = resolve(absolutePacketDir, ...packetPath.split('/').map(() => '..'));
  if (resolve(projectRoot, packetPath) !== absolutePacketDir) {
    throw new Error('review-handoff.json binding.packetPath does not identify the current packet directory.');
  }
  assertNoSymlinkAncestors(projectRoot, absolutePacketDir, 'Current review packet');
  return { absolutePacketDir, projectRoot };
}

function revalidateIndependentFiles({ manifest, projections, packetDir, declaredPacketFiles }) {
  const errors = [];
  let roots;
  try {
    roots = projectRootForPacket(manifest, packetDir);
  } catch (error) {
    return [error.message];
  }
  const { absolutePacketDir, projectRoot } = roots;
  const localBlindInputs = [
    projections?.blind?.allowedInputs?.brief,
    ...(Array.isArray(projections?.blind?.allowedInputs?.sourceOfTruthMaterials)
      ? projections.blind.allowedInputs.sourceOfTruthMaterials
      : [])
  ].filter((input) => input?.kind === 'packet_file').map((input) => input.reference);
  const files = projections?.independent?.allowedInputs?.files;
  if (!Array.isArray(files)) return ['Independent review-handoff projection files must be an array.'];
  let current = [];
  try {
    current = reviewHandoffInputFileBindings(
      projectRoot,
      absolutePacketDir,
      Array.isArray(declaredPacketFiles) ? declaredPacketFiles : [],
      localBlindInputs
    );
  } catch (error) {
    return [error.message];
  }
  const expectedByPath = new Map(files.map((binding) => [binding.path, binding]));
  const currentByPath = new Map(current.map((binding) => [binding.path, binding]));
  for (const binding of current) {
    const expected = expectedByPath.get(binding.path);
    if (!expected) {
      errors.push(`Current review packet contains an independent input added after handoff: ${binding.path}.`);
    } else if (canonicalJson(binding) !== canonicalJson(expected)) {
      errors.push(`Independent review-handoff input ${binding.path} no longer matches its handed-off size and sha256.`);
    }
  }
  for (const binding of files) {
    if (!currentByPath.has(binding.path)) {
      errors.push(`Independent review-handoff projection contains an input no longer present in the declared roots: ${binding.path}.`);
    }
  }
  if (canonicalJson(files) !== canonicalJson(current)) {
    errors.push('Independent review-handoff projection files do not exactly match the current canonical allowed input list.');
  }
  const currentFingerprint = reviewerInputFingerprint(current);
  if (currentFingerprint !== manifest.binding.reviewerInputFingerprint) {
    errors.push('Review handoff reviewerInputFingerprint no longer matches the current complete allowed input set and bytes.');
  }
  return uniqueStrings(errors);
}

function revalidateIndependentUrls({ manifest, projection, packetDir }) {
  const errors = [];
  let roots;
  try {
    roots = projectRootForPacket(manifest, packetDir);
  } catch (error) {
    return [error.message];
  }
  try {
    const routeMatrix = readJson(join(roots.absolutePacketDir, 'route-matrix.json'), 'route-matrix.json');
    const targetOrigin = exactOrigin(routeMatrix.targetBaseUrl, 'route-matrix.json targetBaseUrl');
    if (targetOrigin !== manifest.binding.targetOrigin) {
      errors.push('route-matrix.json targetBaseUrl no longer matches the review-handoff target origin.');
    }
    const targetUrls = (Array.isArray(routeMatrix.primaryRoutes) ? routeMatrix.primaryRoutes : [])
      .map((route, index) => {
        const targetPath = String(route?.targetPath ?? '').trim();
        if (!targetPath.startsWith('/')) {
          throw new Error(`route-matrix.json primaryRoutes[${index}].targetPath must start with /.`);
        }
        return new URL(targetPath, targetOrigin).href;
      });
    const expected = uniqueStrings([
      `${targetOrigin}/`,
      ...targetUrls,
      `${targetOrigin}/admin`,
      ...(manifest.binding.buildMode === 'source_site'
        ? [`${exactOrigin(routeMatrix.sourceBaseUrl, 'route-matrix.json sourceBaseUrl')}/`]
        : [])
    ]);
    if (canonicalJson(projection?.allowedInputs?.urls) !== canonicalJson(expected)) {
      errors.push('Independent review-handoff projection URLs do not exactly match the current target, admin, primary-route, and source input set.');
    }
  } catch (error) {
    errors.push(error.message);
  }
  return uniqueStrings(errors);
}

function revalidateBlindFiles({ manifest, projection, packetDir }) {
  let roots;
  try {
    roots = projectRootForPacket(manifest, packetDir);
  } catch (error) {
    return [error.message];
  }
  const inputs = [
    projection?.allowedInputs?.brief,
    ...(Array.isArray(projection?.allowedInputs?.sourceOfTruthMaterials)
      ? projection.allowedInputs.sourceOfTruthMaterials
      : [])
  ].filter((input) => input?.kind === 'packet_file');
  const errors = [];
  for (const [index, expected] of inputs.entries()) {
    try {
      const path = resolve(roots.projectRoot, safeRelativePath(expected.reference, `Blind file input[${index}].reference`));
      if (!pathIsInside(roots.absolutePacketDir, path)) {
        throw new Error(`Blind file input[${index}] must stay inside the review packet.`);
      }
      const actual = boundedFileBinding(roots.projectRoot, path, `Blind file input[${index}]`);
      const expectedBinding = { path: expected.reference, size: expected.size, sha256: expected.sha256 };
      if (canonicalJson(actual) !== canonicalJson(expectedBinding)) {
        errors.push(`Blind file input[${index}] no longer matches its handed-off size and sha256.`);
      }
    } catch (error) {
      errors.push(error.message);
    }
  }
  return uniqueStrings(errors);
}

export function reviewHandoffReviewerErrors({
  manifest,
  projections = {},
  independentVerification,
  blindReview,
  packetDir = '',
  declaredPacketFiles = []
} = {}) {
  const common = reviewHandoffManifestErrors(manifest);
  const independent = [];
  const blind = [];
  if (common.length > 0) return { blind: [...common], common, independent: [...common] };

  independent.push(...reviewHandoffProjectionErrors(projections.independent, 'independent', manifest));
  blind.push(...reviewHandoffProjectionErrors(projections.blind, 'blind', manifest));
  if (independent.length === 0) {
    independent.push(...revalidateIndependentFiles({
      manifest,
      projections,
      packetDir,
      declaredPacketFiles
    }));
  }
  if (independent.length === 0) {
    independent.push(...revalidateIndependentUrls({
      manifest,
      projection: projections.independent,
      packetDir
    }));
  }
  if (blind.length === 0) {
    blind.push(...revalidateBlindFiles({
      manifest,
      projection: projections.blind,
      packetDir
    }));
  }

  if (independent.length === 0) {
    independent.push(...referenceErrors(independentVerification, manifest, 'independent-verification.json'));
    const independentInputs = projections.independent.allowedInputs;
    const allowedIndependentFiles = new Set(independentInputs.files.map((binding) => binding.path));
    const artifactsReviewed = Array.isArray(independentVerification?.artifactsReviewed)
      ? independentVerification.artifactsReviewed.map((file) => String(file).trim())
      : null;
    for (const file of artifactsReviewed ?? []) {
      if (!allowedIndependentFiles.has(file)) {
        independent.push(`independent-verification.json reviewed disallowed input ${file}.`);
      }
    }
    if (
      !artifactsReviewed ||
      artifactsReviewed.length !== allowedIndependentFiles.size ||
      !sameStringSet(artifactsReviewed, [...allowedIndependentFiles])
    ) {
      independent.push('independent-verification.json artifactsReviewed must exactly match every file in the independent review-handoff projection.');
    }
    const allowedIndependentUrls = new Set();
    for (const url of independentInputs.urls) {
      try {
        allowedIndependentUrls.add(normalizedUrl(url, 'Independent handoff URL'));
      } catch (error) {
        independent.push(error.message);
      }
    }
    for (const [label, value] of [
      ['target.baseUrl', independentVerification?.target?.baseUrl],
      ['target.adminUrl', independentVerification?.target?.adminUrl]
    ]) {
      try {
        const normalized = normalizedUrl(value, `independent-verification.json ${label}`);
        if (!allowedIndependentUrls.has(normalized)) {
          independent.push(`independent-verification.json ${label} is not an allowed handoff URL.`);
        }
        const required = label === 'target.baseUrl'
          ? `${manifest.binding.targetOrigin}/`
          : `${manifest.binding.targetOrigin}/admin`;
        if (normalized !== required) {
          independent.push(`independent-verification.json ${label} must use the root-bound target ${required}.`);
        }
      } catch (error) {
        independent.push(error.message);
      }
    }
  }

  if (blind.length === 0) blind.push(...referenceErrors(blindReview, manifest, 'blind-adversarial-review.json'));
  const blindInputs = blindReview?.reviewInputs ?? {};
  const allowedBlind = projections.blind?.allowedInputs;
  if (blind.length > 0 || !isJsonObject(allowedBlind)) {
    return { blind: uniqueStrings(blind), common, independent: uniqueStrings(independent) };
  }
  for (const key of Object.keys(blindInputs)) {
    if (!BLIND_INPUT_KEYS.has(key)) blind.push(`blind-adversarial-review.json reviewInputs.${key} is not allowed by the handoff.`);
  }
  if (String(blindInputs.originalBrief ?? '').trim() !== allowedBlind.brief.reference) {
    blind.push('blind-adversarial-review.json originalBrief does not match the handoff.');
  }
  if (!sameStringSet(blindInputs.acceptanceCriteria, allowedBlind.acceptanceCriteria)) {
    blind.push('blind-adversarial-review.json acceptanceCriteria do not match the handoff.');
  }
  const normalizeUrls = (values, label) => uniqueStrings((Array.isArray(values) ? values : []).map((value) => normalizedUrl(value, label)));
  try {
    if (canonicalJson(normalizeUrls(blindInputs.targetUrlsOrArtifacts, 'Blind target input')) !==
      canonicalJson(normalizeUrls(allowedBlind.targetUrlsOrArtifacts, 'Handoff target input'))) {
      blind.push('blind-adversarial-review.json target inputs do not match the handoff.');
    }
  } catch (error) {
    blind.push(error.message);
  }
  if (!sameMaterialSet(blindInputs.sourceOfTruthMaterials, allowedBlind.sourceOfTruthMaterials)) {
    blind.push('blind-adversarial-review.json source-of-truth inputs do not match the handoff.');
  }
  if (!sameStringSet(blindInputs.credentialsUsed, allowedBlind.credentialLabels)) {
    blind.push('blind-adversarial-review.json credential labels do not match the handoff.');
  }
  if (!sameStringSet(blindInputs.excludedInputs, projections.blind.excludedInputs)) {
    blind.push('blind-adversarial-review.json excludedInputs do not match the handoff boundary.');
  }

  const routeByPath = new Map((allowedBlind.primaryRoutes ?? []).map((route) => [route.targetPath, route]));
  for (const [index, review] of (Array.isArray(blindReview?.routeViewportReviews)
    ? blindReview.routeViewportReviews
    : []).entries()) {
    const allowed = routeByPath.get(String(review?.route ?? '').trim());
    if (!allowed) {
      blind.push(`blind-adversarial-review.json routeViewportReviews[${index}] uses a route outside the handoff.`);
      continue;
    }
    try {
      if (normalizedUrl(review?.targetUrlOrArtifact, 'Blind route target') !== normalizedUrl(allowed.targetUrl)) {
        blind.push(`blind-adversarial-review.json routeViewportReviews[${index}] uses a target outside the handoff.`);
      }
    } catch (error) {
      blind.push(error.message);
    }
    const sourceReference = String(review?.sourceTruthReference ?? '').trim();
    const expectedSource = String(allowed.sourceTruthReference ?? '').trim();
    const sourceMatches = /^https?:\/\//i.test(expectedSource)
      ? (() => {
          try { return normalizedUrl(sourceReference) === normalizedUrl(expectedSource); } catch { return false; }
        })()
      : sourceReference === expectedSource;
    if (!sourceMatches) {
      blind.push(`blind-adversarial-review.json routeViewportReviews[${index}] uses source truth outside the handoff.`);
    }
    const allowedRequirementIds = new Set(allowed.briefRequirementIds ?? []);
    if ((Array.isArray(review?.briefRequirementIds) ? review.briefRequirementIds : [])
      .some((id) => !allowedRequirementIds.has(String(id)))) {
      blind.push(`blind-adversarial-review.json routeViewportReviews[${index}] uses a brief requirement outside the handoff.`);
    }
  }
  return { blind: uniqueStrings(blind), common, independent: uniqueStrings(independent) };
}

export function reviewHandoffStateErrors({ manifest, buildMode, buildState, targetOrigin } = {}) {
  const errors = reviewHandoffManifestErrors(manifest);
  if (errors.length > 0) return errors;
  const binding = manifest.binding;
  let currentOrigin = '';
  try {
    currentOrigin = exactOrigin(targetOrigin, 'Current live target origin');
  } catch (error) {
    errors.push(error.message);
  }
  const comparisons = [
    ['build mode', binding.buildMode, buildMode],
    ['target origin', binding.targetOrigin, currentOrigin],
    ['site UUID', binding.siteUuid, String(buildState?.targetIdentity?.siteUuid ?? '').trim().toLowerCase()],
    ['front page', binding.frontPage, String(buildState?.targetIdentity?.frontPage ?? '')],
    ['config sync directory', binding.configSyncDirectory, String(buildState?.targetIdentity?.configSyncDirectory ?? '')],
    ['target identity fingerprint', binding.targetIdentityFingerprint, buildState?.componentFingerprints?.targetIdentity],
    ['site state fingerprint', binding.siteStateFingerprint, buildState?.fingerprint]
  ];
  for (const [label, expected, actual] of comparisons) {
    if (expected !== actual) errors.push(`Review handoff ${label} no longer matches the current live target state.`);
  }
  return uniqueStrings(errors);
}

export function buildReviewHandoff({
  projectRoot,
  packetDir,
  gates,
  buildInput,
  briefAcceptance,
  routeMatrix,
  blindReview,
  liveVerification,
  independentCredentialLabelValues = [],
  blindCredentialLabelValues = []
}) {
  if (!Array.isArray(gates?.reviewPacketFiles)) throw new Error('gates.json must declare reviewPacketFiles.');
  if (!['brief', 'source_site'].includes(buildInput?.mode)) throw new Error('build-input.json must declare brief or source_site mode.');
  if (routeMatrix?.schemaVersion !== 'public-kit.route-matrix.1') throw new Error('route-matrix.json has an unsupported schemaVersion.');
  const independentLabels = credentialLabels(independentCredentialLabelValues);
  const blindLabels = credentialLabels(blindCredentialLabelValues);
  const binding = stateBinding(liveVerification, buildInput.mode, projectRoot, packetDir);
  const routeTargetOrigin = exactOrigin(routeMatrix.targetBaseUrl, 'route-matrix.json targetBaseUrl');
  if (routeTargetOrigin !== binding.targetOrigin) {
    throw new Error('route-matrix.json targetBaseUrl does not match the inspected live target.');
  }
  const brief = briefInput(projectRoot, packetDir, buildInput, blindReview?.reviewInputs);
  const routes = primaryRouteRows(routeMatrix, binding.targetOrigin, buildInput.mode, brief.reference);
  const targetUrls = uniqueStrings(routes.map((route) => route.targetUrl));
  const materials = sourceTruthMaterials(projectRoot, packetDir, buildInput, routeMatrix, blindReview?.reviewInputs, brief);
  const independentUrls = uniqueStrings([
    `${binding.targetOrigin}/`,
    ...targetUrls,
    `${binding.targetOrigin}/admin`,
    ...(buildInput.mode === 'source_site' ? [`${exactOrigin(routeMatrix.sourceBaseUrl, 'sourceBaseUrl')}/`] : [])
  ]);

  const extraPacketPaths = [
    brief.kind === 'packet_file' ? brief.reference : '',
    ...materials.filter((material) => material.kind === 'packet_file').map((material) => material.reference)
  ].filter(Boolean);
  return sealReviewHandoffBundle({
    binding,
    blind: {
      allowedInputs: {
        acceptanceCriteria: acceptanceCriteria(buildInput, briefAcceptance, blindReview?.reviewInputs),
        brief,
        credentialLabels: blindLabels,
        primaryRoutes: routes,
        sourceOfTruthMaterials: materials,
        targetUrlsOrArtifacts: targetUrls
      },
      excludedInputs: [...BLIND_EXCLUDED_INPUTS]
    },
    independent: {
      allowedInputs: {
        credentialLabels: independentLabels,
        files: reviewHandoffInputFileBindings(projectRoot, packetDir, gates.reviewPacketFiles, extraPacketPaths),
        urls: independentUrls
      },
      excludedInputs: [...INDEPENDENT_EXCLUDED_INPUTS]
    }
  });
}

export function writeReviewHandoff({
  project = process.cwd(),
  packet = 'review-packet',
  independentCredentialLabelValues = [],
  blindCredentialLabelValues = []
} = {}) {
  const requestedProject = resolve(project);
  if (!existsSync(requestedProject) || lstatSync(requestedProject).isSymbolicLink() || !statSync(requestedProject).isDirectory()) {
    throw new Error('Project root must be an existing non-symlink directory.');
  }
  const projectRoot = realpathSync(requestedProject);
  const packetDir = safeProjectPath(projectRoot, packet, 'Packet directory');
  if (!existsSync(packetDir) || lstatSync(packetDir).isSymbolicLink() || !statSync(packetDir).isDirectory()) {
    throw new Error('Packet directory must be an existing non-symlink directory inside the Drupal project.');
  }
  if (!pathIsInside(projectRoot, realpathSync(packetDir))) {
    throw new Error('Packet directory must not escape the Drupal project through a symbolic link.');
  }
  const gates = readJson(join(PACKAGE_ROOT, 'gates.json'), 'gates.json');
  const buildInput = readJson(join(packetDir, 'build-input.json'), 'build-input.json');
  const briefAcceptance = readJson(join(packetDir, 'brief-acceptance.json'), 'brief-acceptance.json');
  const routeMatrix = readJson(join(packetDir, 'route-matrix.json'), 'route-matrix.json');
  const blindReview = readJson(join(packetDir, 'blind-adversarial-review.json'), 'blind-adversarial-review.json');
  const liveVerification = readJson(
    join(packetDir, 'evidence', 'live-verification.json'),
    'evidence/live-verification.json'
  );
  const bundle = buildReviewHandoff({
    projectRoot,
    packetDir,
    gates,
    buildInput,
    briefAcceptance,
    routeMatrix,
    blindReview,
    liveVerification,
    independentCredentialLabelValues,
    blindCredentialLabelValues
  });
  const outputs = [
    { path: join(packetDir, PROJECTION_PATHS.independent), value: bundle.projections.independent },
    { path: join(packetDir, PROJECTION_PATHS.blind), value: bundle.projections.blind },
    { path: join(packetDir, HANDOFF_PATH), value: bundle.manifest }
  ];
  for (const output of outputs) {
    mkdirSync(dirname(output.path), { recursive: true });
    if (existsSync(output.path) && (lstatSync(output.path).isSymbolicLink() || !lstatSync(output.path).isFile())) {
      throw new Error(`${portablePath(relative(packetDir, output.path))} must be a regular non-symlink file when it exists.`);
    }
    assertNoSymlinkAncestors(packetDir, dirname(output.path), 'Review handoff output directory');
  }
  const temporary = outputs.map((output) => ({
    ...output,
    temporaryPath: join(dirname(output.path), `.${basename(output.path)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`)
  }));
  try {
    for (const output of temporary) {
      writeFileSync(
        output.temporaryPath,
        `${JSON.stringify(JSON.parse(canonicalJson(output.value)), null, 2)}\n`,
        { flag: 'wx', mode: 0o600 }
      );
    }
    for (const output of temporary) renameSync(output.temporaryPath, output.path);
  } finally {
    for (const output of temporary) if (existsSync(output.temporaryPath)) unlinkSync(output.temporaryPath);
  }
  return {
    manifest: bundle.manifest,
    projections: bundle.projections,
    outputPath: join(packetDir, HANDOFF_PATH),
    projectionPaths: {
      blind: join(packetDir, PROJECTION_PATHS.blind),
      independent: join(packetDir, PROJECTION_PATHS.independent)
    }
  };
}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  try {
    const options = parseArgs(process.argv);
    if (options.help) {
      process.stdout.write(usage());
    } else {
      const result = writeReviewHandoff({
        project: options.project,
        packet: options.packet,
        independentCredentialLabelValues: options.independentCredentialLabels,
        blindCredentialLabelValues: options.blindCredentialLabels
      });
      process.stdout.write(`${JSON.stringify({
        schemaVersion: HANDOFF_SCHEMA,
        authority: result.manifest.authority,
        handoffDigest: result.manifest.handoffDigest,
        output: portablePath(relative(resolve(options.project), result.outputPath)),
        projections: Object.fromEntries(Object.entries(result.projectionPaths).map(([kind, path]) => [kind, {
          path: portablePath(relative(resolve(options.project), path)),
          digest: result.projections[kind].projectionDigest
        }]))
      }, null, 2)}\n`);
    }
  } catch (error) {
    process.stderr.write(`${error instanceof UsageError ? `${error.message}\n\n${usage()}` : `${error.message}\n`}`);
    process.exitCode = 1;
  }
}
