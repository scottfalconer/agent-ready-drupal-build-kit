import { createHash } from 'node:crypto';
import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync
} from 'node:fs';
import { isAbsolute, posix, relative, resolve, sep } from 'node:path';

export const MUTABLE_IDENTITY_DRUPAL_INPUT_SCHEMA = 'public-kit.mutable-identity-drupal-input.1';
export const MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA = 'public-kit.mutable-identity-drupal-ast.1';
export const MUTABLE_IDENTITY_DRUPAL_INPUT_BYTES = 4 * 1024 * 1024;

export const MUTABLE_IDENTITY_DRUPAL_LIMITS = Object.freeze({
  files: 5_000,
  surfacesPerFile: 5_000,
  surfacesTotal: 50_000,
  sourceBytesPerFile: 1024 * 1024,
  sourceBytesTotal: 64 * 1024 * 1024,
  astNodesPerFile: 100_000,
  astNodesTotal: 500_000,
  astDepth: 256,
  findings: 200,
  deadlineMs: 30_000,
  outputBytes: 1024 * 1024
});

const LIMIT_MINIMUMS = Object.freeze({
  files: 1,
  surfacesPerFile: 1,
  surfacesTotal: 1,
  sourceBytesPerFile: 1,
  sourceBytesTotal: 1,
  astNodesPerFile: 1,
  astNodesTotal: 1,
  astDepth: 1,
  findings: 1,
  deadlineMs: 10,
  outputBytes: 4_096
});

const SOURCE_KINDS = new Set(['procedural_php', 'php_class', 'twig_template']);
const PROCEDURAL_PHP_EXTENSION_RE = /\.(?:module|theme|install|inc|test|profile)$/i;
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const SOURCE_ID_RE = /^SOURCE-[a-f0-9]{16}$/;
const SURFACE_ID_RE = /^SURFACE-[a-f0-9]{16}$/;
const SAFE_NODE_TYPE_RE = /^(?:PhpParser|Twig|Verifier)\\[A-Za-z0-9_\\]+$/;
const IDENTITY_KINDS = new Set(['alias_or_path', 'title_or_label', 'media_name']);
const SINK_KINDS = new Set(['behavior_branch', 'computed_lookup', 'presentation_selector', 'entity_selector']);
const ENTITY_KINDS = new Set(['file', 'media', 'node']);
const ENTITY_OUTPUT_SINK_KINDS = new Set(['entity_render_call', 'entity_view_builder', 'render_array', 'twig_print']);
const SEMANTIC_BLOCKERS = new Set([
  'ambiguous_identity_receiver',
  'ambiguous_media_receiver',
  'indirect_identity_flow',
  'indirect_identity_operand',
  'unsupported_dynamic_call',
  'unsupported_dynamic_identity'
]);
const BLOCKER_CODES = new Set([
  ...SEMANTIC_BLOCKERS,
  'ast_depth_limit',
  'ast_node_limit',
  'deadline_exceeded',
  'docroot_invalid',
  'docroot_mismatch',
  'duplicate_source_id',
  'file_limit',
  'finding_limit',
  'input_fingerprint_invalid',
  'input_invalid',
  'input_limit',
  'invalid_output',
  'missing_ast_span',
  'output_limit',
  'parse_error',
  'parser_process_failed',
  'parser_runtime_failed',
  'php_parse_incomplete',
  'php_parser_unavailable',
  'project_root_unavailable',
  'runner_unavailable',
  'source_bytes_invalid',
  'source_encoding_invalid',
  'source_hash_mismatch',
  'source_kind_invalid',
  'source_record_invalid',
  'source_unavailable',
  'spawn_failed',
  'surface_limit',
  'twig_parse_incomplete',
  'twig_parser_unavailable',
  'unsupported_ast_child',
  'unsupported_ast_node',
  'unsupported_async_runner',
  'unsupported_entity_output',
  'unsupported_traversal'
]);

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function comparePortable(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function normalizedRelativePath(value, label, { allowDot = false } = {}) {
  const text = String(value ?? '');
  if (
    !text || text.includes('\\') || text.includes('\0') || isAbsolute(text) || text.startsWith('/') ||
    text.length > 1_024 || text.split('/').some((segment) => segment === '' || segment === '..')
  ) {
    throw new Error(`${label} must be a normalized project-relative POSIX path.`);
  }
  const normalized = posix.normalize(text.replace(/^\.\//, ''));
  if ((!allowDot && normalized === '.') || normalized !== text.replace(/^\.\//, '')) {
    throw new Error(`${label} must be a normalized project-relative POSIX path.`);
  }
  return normalized;
}

function normalizedDigest(value, label) {
  const digest = String(value ?? '').trim().toLowerCase();
  if (!HASH_RE.test(digest)) throw new Error(`${label} must be a SHA-256 digest.`);
  return digest;
}

function resolvedLimits(options = {}) {
  const requested = plainObject(options?.limits) ? options.limits : options;
  const limits = {};
  for (const [key, ceiling] of Object.entries(MUTABLE_IDENTITY_DRUPAL_LIMITS)) {
    const value = requested?.[key] ?? ceiling;
    if (!Number.isSafeInteger(value) || value < LIMIT_MINIMUMS[key] || value > ceiling) {
      throw new Error(`Mutable-identity Drupal limit ${key} must be an integer between ${LIMIT_MINIMUMS[key]} and ${ceiling}.`);
    }
    limits[key] = value;
  }
  if (limits.astNodesPerFile > limits.astNodesTotal) {
    throw new Error('Mutable-identity Drupal astNodesPerFile cannot exceed astNodesTotal.');
  }
  if (limits.sourceBytesPerFile > limits.sourceBytesTotal) {
    throw new Error('Mutable-identity Drupal sourceBytesPerFile cannot exceed sourceBytesTotal.');
  }
  if (limits.surfacesPerFile > limits.surfacesTotal) {
    throw new Error('Mutable-identity Drupal surfacesPerFile cannot exceed surfacesTotal.');
  }
  return limits;
}

function pathInside(root, candidate) {
  const relation = relative(root, candidate);
  return relation === '' || (!relation.startsWith(`..${sep}`) && relation !== '..' && !isAbsolute(relation));
}

function normalizedSources(projectRoot, sourceFiles, limits) {
  if (!Array.isArray(sourceFiles)) throw new Error('Mutable-identity Drupal sourceFiles must be an array.');
  const selected = sourceFiles.filter((source) => SOURCE_KINDS.has(source?.kind));
  if (selected.length > limits.files) {
    throw new Error(`Mutable-identity Drupal input exceeds its ${limits.files} file limit.`);
  }
  const projectRealPath = realpathSync(projectRoot);
  if (!statSync(projectRealPath).isDirectory()) throw new Error('Mutable-identity Drupal projectRoot must be a directory.');
  const ids = new Set();
  const paths = new Set();
  let totalBytes = 0;
  let totalSurfaces = 0;
  const sources = selected.map((source, index) => {
    const id = String(source?.id ?? '');
    if (!SOURCE_ID_RE.test(id)) throw new Error(`sourceFiles[${index}].id must be a verifier-owned SOURCE identity.`);
    if (ids.has(id)) throw new Error(`Mutable-identity Drupal input contains duplicate source id ${id}.`);
    ids.add(id);
    const kind = String(source.kind);
    const path = normalizedRelativePath(source.path, `sourceFiles[${index}].path`);
    if (paths.has(path)) throw new Error(`Mutable-identity Drupal input contains duplicate source path ${path}.`);
    paths.add(path);
    const extensionMatches = kind === 'twig_template'
      ? /\.twig$/i.test(path)
      : kind === 'procedural_php' ? PROCEDURAL_PHP_EXTENSION_RE.test(path) : /\.php$/i.test(path);
    if (!extensionMatches) {
      throw new Error(`sourceFiles[${index}] kind ${kind} does not match its file extension.`);
    }
    const logicalPath = resolve(projectRealPath, ...path.split('/'));
    if (lstatSync(logicalPath).isSymbolicLink()) {
      const target = realpathSync(logicalPath);
      if (!pathInside(projectRealPath, target)) throw new Error(`sourceFiles[${index}] resolves outside projectRoot.`);
    }
    const realPath = realpathSync(logicalPath);
    if (!pathInside(projectRealPath, realPath) || !statSync(realPath).isFile()) {
      throw new Error(`sourceFiles[${index}] is not a regular project file.`);
    }
    const bytes = readFileSync(realPath);
    if (bytes.length > limits.sourceBytesPerFile) {
      throw new Error(`sourceFiles[${index}] exceeds the per-file byte limit.`);
    }
    totalBytes += bytes.length;
    if (totalBytes > limits.sourceBytesTotal) throw new Error('Mutable-identity Drupal input exceeds the aggregate source-byte limit.');
    const digest = normalizedDigest(source.sha256, `sourceFiles[${index}].sha256`);
    if (sha256(bytes) !== digest) throw new Error(`sourceFiles[${index}] is not bound to its current bytes.`);
    const rawSurfaces = source.surfaces ?? [];
    if (!Array.isArray(rawSurfaces)) throw new Error(`sourceFiles[${index}].surfaces must be an array.`);
    if (rawSurfaces.length > limits.surfacesPerFile) {
      throw new Error(`sourceFiles[${index}] exceeds the per-file surface limit.`);
    }
    const surfaceIds = rawSurfaces.map((surface, surfaceIndex) => {
      const surfaceId = String(surface?.id ?? '');
      if (!SURFACE_ID_RE.test(surfaceId)) {
        throw new Error(`sourceFiles[${index}].surfaces[${surfaceIndex}].id must be a verifier-owned SURFACE identity.`);
      }
      return surfaceId;
    }).sort(comparePortable);
    if (new Set(surfaceIds).size !== surfaceIds.length) {
      throw new Error(`sourceFiles[${index}] contains duplicate surface identities.`);
    }
    totalSurfaces += surfaceIds.length;
    if (totalSurfaces > limits.surfacesTotal) {
      throw new Error('Mutable-identity Drupal input exceeds the aggregate surface limit.');
    }
    return { id, path, kind, sha256: digest, bytes: bytes.length, surfaceIds };
  }).sort((left, right) => comparePortable(left.path, right.path));
  return { sources, totalBytes };
}

export function createMutableIdentityDrupalInput(projectRoot, sourceFiles, options = {}) {
  const limits = resolvedLimits(options);
  const docroot = normalizedRelativePath(options.docroot ?? 'web', 'Mutable-identity Drupal docroot', { allowDot: true });
  const { sources, totalBytes } = normalizedSources(projectRoot, sourceFiles, limits);
  const unsigned = {
    schemaVersion: MUTABLE_IDENTITY_DRUPAL_INPUT_SCHEMA,
    docroot,
    limits,
    expectedTotalBytes: totalBytes,
    sources
  };
  const value = { ...unsigned, inputFingerprint: sha256(JSON.stringify(unsigned)) };
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json, 'utf8') > MUTABLE_IDENTITY_DRUPAL_INPUT_BYTES) {
    throw new Error('Mutable-identity Drupal input exceeds its serialized byte limit.');
  }
  if (Buffer.byteLength(JSON.stringify(blockedTransportResult({ value }, 'output_limit')), 'utf8') + 512 > limits.outputBytes) {
    throw new Error('Mutable-identity Drupal output limit cannot represent exact file coverage.');
  }
  return Object.freeze({ value: Object.freeze(value), json });
}

export function mutableIdentityDrupalResultFingerprint(result) {
  const unsigned = { ...result };
  delete unsigned.resultFingerprint;
  return sha256(JSON.stringify(unsigned));
}

function syntheticEvidence() {
  return {
    sourceNodeType: 'Verifier\\Transport',
    sourceStartLine: 0,
    sourceEndLine: 0,
    sourceStartFilePos: null,
    sourceEndFilePos: null,
    sinkNodeType: '',
    sinkStartLine: 0,
    sinkEndLine: 0,
    sinkStartFilePos: null,
    sinkEndFilePos: null
  };
}

function blockedTransportResult(input, code) {
  const value = input.value;
  const result = {
    schemaVersion: MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA,
    analyzer: 'nikic-php-parser+drupal-twig-parser',
    inputFingerprint: value.inputFingerprint,
    parser: {
      php: { name: 'nikic/php-parser', version: '', ast: true },
      twig: { name: 'drupal/twig', version: '', ast: true }
    },
    limits: value.limits,
    applies: value.sources.length > 0,
    completed: false,
    status: 'blocked',
    expectedFileIds: value.sources.map(({ id }) => id).sort(comparePortable),
    completedFileIds: [],
    sourceBytes: 0,
    astNodes: 0,
    maxDepth: 0,
    durationMs: 0,
    deadlineExceeded: code === 'deadline_exceeded',
    findings: [],
    entityOutputCandidates: [],
    blockers: [{
      code,
      fileId: '',
      language: '',
      ruleId: `mutable_identity.${code}`,
      evidence: syntheticEvidence()
    }]
  };
  return { ...result, resultFingerprint: mutableIdentityDrupalResultFingerprint(result) };
}

function notApplicableResult(input) {
  const value = input.value;
  const result = {
    schemaVersion: MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA,
    analyzer: 'nikic-php-parser+drupal-twig-parser',
    inputFingerprint: value.inputFingerprint,
    parser: {
      php: { name: 'nikic/php-parser', version: '', ast: true },
      twig: { name: 'drupal/twig', version: '', ast: true }
    },
    limits: value.limits,
    applies: false,
    completed: true,
    status: 'not_applicable',
    expectedFileIds: [],
    completedFileIds: [],
    sourceBytes: 0,
    astNodes: 0,
    maxDepth: 0,
    durationMs: 0,
    deadlineExceeded: false,
    findings: [],
    entityOutputCandidates: [],
    blockers: []
  };
  return { ...result, resultFingerprint: mutableIdentityDrupalResultFingerprint(result) };
}

function exactKeys(value, keys) {
  return plainObject(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function assertInputEnvelope(input) {
  const valueKeys = ['schemaVersion', 'docroot', 'limits', 'expectedTotalBytes', 'sources', 'inputFingerprint'];
  if (!input || !exactKeys(input.value, valueKeys) || typeof input.json !== 'string' ||
      input.value.schemaVersion !== MUTABLE_IDENTITY_DRUPAL_INPUT_SCHEMA ||
      input.json !== JSON.stringify(input.value) ||
      Buffer.byteLength(input.json, 'utf8') > MUTABLE_IDENTITY_DRUPAL_INPUT_BYTES) {
    throw new Error('Mutable-identity Drupal input envelope is invalid.');
  }
  const unsigned = { ...input.value };
  delete unsigned.inputFingerprint;
  if (input.value.inputFingerprint !== sha256(JSON.stringify(unsigned))) {
    throw new Error('Mutable-identity Drupal input fingerprint is invalid.');
  }
  if (!Array.isArray(input.value.sources) || input.value.sources.some((source) =>
    !exactKeys(source, ['id', 'path', 'kind', 'sha256', 'bytes', 'surfaceIds']) ||
    !SOURCE_ID_RE.test(source.id) || !SOURCE_KINDS.has(source.kind) || !HASH_RE.test(source.sha256) ||
    !Number.isSafeInteger(source.bytes) || source.bytes < 0 || !Array.isArray(source.surfaceIds) ||
    source.surfaceIds.some((id, index, values) => !SURFACE_ID_RE.test(id) || values.indexOf(id) !== index)
  )) {
    throw new Error('Mutable-identity Drupal input source records are invalid.');
  }
  const expectedLimits = resolvedLimits({ limits: input.value.limits });
  if (JSON.stringify(expectedLimits) !== JSON.stringify(input.value.limits)) {
    throw new Error('Mutable-identity Drupal input limits are invalid.');
  }
  normalizedRelativePath(input.value.docroot, 'Mutable-identity Drupal docroot', { allowDot: true });
  const ids = new Set();
  const paths = new Set();
  let bytes = 0;
  let surfaces = 0;
  let previousPath = '';
  for (const source of input.value.sources) {
    const extensionMatches = source.kind === 'twig_template'
      ? /\.twig$/i.test(source.path)
      : source.kind === 'procedural_php' ? PROCEDURAL_PHP_EXTENSION_RE.test(source.path) : /\.php$/i.test(source.path);
    normalizedRelativePath(source.path, 'Mutable-identity Drupal source path');
    if (!extensionMatches || ids.has(source.id) || paths.has(source.path) ||
        (previousPath && comparePortable(previousPath, source.path) >= 0) ||
        source.bytes > input.value.limits.sourceBytesPerFile ||
        source.surfaceIds.length > input.value.limits.surfacesPerFile ||
        JSON.stringify([...source.surfaceIds].sort(comparePortable)) !== JSON.stringify(source.surfaceIds)) {
      throw new Error('Mutable-identity Drupal input source records are invalid.');
    }
    ids.add(source.id);
    paths.add(source.path);
    previousPath = source.path;
    bytes += source.bytes;
    surfaces += source.surfaceIds.length;
  }
  if (input.value.sources.length > input.value.limits.files || bytes !== input.value.expectedTotalBytes ||
      bytes > input.value.limits.sourceBytesTotal || surfaces > input.value.limits.surfacesTotal) {
    throw new Error('Mutable-identity Drupal input aggregate bounds are invalid.');
  }
}

function integerInRange(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function validEvidence(evidence, language, { structural = false, transport = false } = {}) {
  const keys = [
    'sourceNodeType', 'sourceStartLine', 'sourceEndLine', 'sourceStartFilePos', 'sourceEndFilePos',
    'sinkNodeType', 'sinkStartLine', 'sinkEndLine', 'sinkStartFilePos', 'sinkEndFilePos'
  ];
  if (!exactKeys(evidence, keys) || !SAFE_NODE_TYPE_RE.test(evidence.sourceNodeType)) return false;
  if (transport) {
    return evidence.sourceNodeType === 'Verifier\\Transport' && evidence.sourceStartLine === 0 &&
      evidence.sourceEndLine === 0 && evidence.sourceStartFilePos === null && evidence.sourceEndFilePos === null &&
      evidence.sinkNodeType === '' && evidence.sinkStartLine === 0 && evidence.sinkEndLine === 0 &&
      evidence.sinkStartFilePos === null && evidence.sinkEndFilePos === null;
  }
  if (structural) {
    return integerInRange(evidence.sourceStartLine, 0, Number.MAX_SAFE_INTEGER) &&
      integerInRange(evidence.sourceEndLine, evidence.sourceStartLine, Number.MAX_SAFE_INTEGER) &&
      evidence.sourceStartFilePos === null && evidence.sourceEndFilePos === null &&
      evidence.sinkNodeType === '' && evidence.sinkStartLine === 0 && evidence.sinkEndLine === 0 &&
      evidence.sinkStartFilePos === null && evidence.sinkEndFilePos === null;
  }
  if (!integerInRange(evidence.sourceStartLine, 1, Number.MAX_SAFE_INTEGER) ||
      !integerInRange(evidence.sourceEndLine, evidence.sourceStartLine, Number.MAX_SAFE_INTEGER)) return false;
  if (language === 'php') {
    if (!integerInRange(evidence.sourceStartFilePos, 0, Number.MAX_SAFE_INTEGER) ||
        !integerInRange(evidence.sourceEndFilePos, evidence.sourceStartFilePos, Number.MAX_SAFE_INTEGER)) return false;
  } else if (evidence.sourceStartFilePos !== null || evidence.sourceEndFilePos !== null) return false;
  if (evidence.sinkNodeType) {
    if (!SAFE_NODE_TYPE_RE.test(evidence.sinkNodeType) ||
        !integerInRange(evidence.sinkStartLine, 1, Number.MAX_SAFE_INTEGER) ||
        !integerInRange(evidence.sinkEndLine, evidence.sinkStartLine, Number.MAX_SAFE_INTEGER)) return false;
    if (language === 'php') {
      if (!integerInRange(evidence.sinkStartFilePos, 0, Number.MAX_SAFE_INTEGER) ||
          !integerInRange(evidence.sinkEndFilePos, evidence.sinkStartFilePos, Number.MAX_SAFE_INTEGER)) return false;
    } else if (evidence.sinkStartFilePos !== null || evidence.sinkEndFilePos !== null) return false;
  } else if (
    evidence.sinkStartLine !== 0 || evidence.sinkEndLine !== 0 ||
    evidence.sinkStartFilePos !== null || evidence.sinkEndFilePos !== null
  ) return false;
  return true;
}

function parsedExecutionOutput(raw) {
  if (typeof raw === 'string' || Buffer.isBuffer(raw)) return { exitCode: 0, stdout: raw, timedOut: false };
  if (!plainObject(raw)) throw new Error('Mutable-identity Drupal runner returned an invalid result envelope.');
  return {
    exitCode: Number(raw.exitCode ?? raw.status ?? 0),
    stdout: raw.stdout ?? raw.output ?? '',
    timedOut: raw.timedOut === true
  };
}

export function parseMutableIdentityDrupalResult(raw, input) {
  assertInputEnvelope(input);
  const output = parsedExecutionOutput(raw);
  if (output.timedOut || output.exitCode !== 0) throw new Error('Mutable-identity Drupal parser execution did not complete successfully.');
  const stdout = Buffer.isBuffer(output.stdout) ? output.stdout.toString('utf8') : String(output.stdout ?? '');
  if (Buffer.byteLength(stdout, 'utf8') > input.value.limits.outputBytes) {
    throw new Error('Mutable-identity Drupal parser output exceeds its byte limit.');
  }
  let result;
  try { result = JSON.parse(stdout); }
  catch { throw new Error('Mutable-identity Drupal parser output is not strict JSON.'); }
  const topKeys = [
    'schemaVersion', 'analyzer', 'inputFingerprint', 'parser', 'limits', 'applies', 'completed', 'status',
    'expectedFileIds', 'completedFileIds', 'sourceBytes', 'astNodes', 'maxDepth', 'durationMs',
    'deadlineExceeded', 'findings', 'entityOutputCandidates', 'blockers', 'resultFingerprint'
  ];
  if (!exactKeys(result, topKeys) || result.schemaVersion !== MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA ||
      result.analyzer !== 'nikic-php-parser+drupal-twig-parser' ||
      result.inputFingerprint !== input.value.inputFingerprint ||
      JSON.stringify(result.limits) !== JSON.stringify(input.value.limits)) {
    throw new Error('Mutable-identity Drupal parser output is not bound to the exact verifier input and limits.');
  }
  if (result.resultFingerprint !== mutableIdentityDrupalResultFingerprint(result)) {
    throw new Error('Mutable-identity Drupal parser result fingerprint is invalid.');
  }
  if (!exactKeys(result.parser, ['php', 'twig']) ||
      !exactKeys(result.parser.php, ['name', 'version', 'ast']) ||
      !exactKeys(result.parser.twig, ['name', 'version', 'ast']) ||
      result.parser.php.name !== 'nikic/php-parser' || result.parser.twig.name !== 'drupal/twig' ||
      result.parser.php.ast !== true || result.parser.twig.ast !== true ||
      typeof result.parser.php.version !== 'string' || result.parser.php.version.length > 100 ||
      typeof result.parser.twig.version !== 'string' || result.parser.twig.version.length > 100 ||
      (result.parser.php.version !== '' && !/^[0-9A-Za-z.+_-]+$/.test(result.parser.php.version)) ||
      (result.parser.twig.version !== '' && !/^[0-9A-Za-z.+_-]+$/.test(result.parser.twig.version))) {
    throw new Error('Mutable-identity Drupal parser provenance is invalid.');
  }
  const expectedIds = input.value.sources.map(({ id }) => id).sort(comparePortable);
  if (JSON.stringify(result.expectedFileIds) !== JSON.stringify(expectedIds) ||
      !Array.isArray(result.completedFileIds) ||
      result.completedFileIds.some((id, index, values) => !expectedIds.includes(id) || values.indexOf(id) !== index) ||
      JSON.stringify([...result.completedFileIds].sort(comparePortable)) !== JSON.stringify(result.completedFileIds)) {
    throw new Error('Mutable-identity Drupal parser file coverage is invalid.');
  }
  if (result.applies !== (expectedIds.length > 0) || typeof result.completed !== 'boolean' ||
      !['pass', 'fail', 'blocked', 'not_applicable'].includes(result.status) ||
      !integerInRange(result.sourceBytes, 0, input.value.expectedTotalBytes) ||
      !integerInRange(result.astNodes, 0, input.value.limits.astNodesTotal) ||
      !integerInRange(result.maxDepth, 0, input.value.limits.astDepth) ||
      !integerInRange(result.durationMs, 0, input.value.limits.deadlineMs) ||
      typeof result.deadlineExceeded !== 'boolean') {
    throw new Error('Mutable-identity Drupal parser completion metrics are invalid.');
  }
  if (!Array.isArray(result.findings) || !Array.isArray(result.entityOutputCandidates) || !Array.isArray(result.blockers) ||
      result.findings.length + result.entityOutputCandidates.length + result.blockers.length > input.value.limits.findings) {
    throw new Error('Mutable-identity Drupal parser findings exceed their aggregate limit.');
  }
  const seen = new Set();
  for (const finding of result.findings) {
    const keys = ['id', 'fileId', 'language', 'identityKind', 'sinkKind', 'ruleId', 'evidence'];
    const source = input.value.sources.find(({ id }) => id === finding.fileId);
    const identityKey = `${finding.fileId}\0${finding.ruleId}\0${JSON.stringify(finding.evidence)}`;
    if (!exactKeys(finding, keys) || finding.id !== `MUTABLE-${sha256(identityKey).slice(7, 23)}` || seen.has(finding.id) ||
        !source || !['php', 'twig'].includes(finding.language) ||
        finding.language !== (source.kind === 'twig_template' ? 'twig' : 'php') ||
        !IDENTITY_KINDS.has(finding.identityKind) || !SINK_KINDS.has(finding.sinkKind) ||
        finding.ruleId !== `mutable_identity.${finding.identityKind}.${finding.sinkKind}` ||
        !validEvidence(finding.evidence, finding.language)) {
      throw new Error('Mutable-identity Drupal parser emitted an invalid or unredacted finding.');
    }
    seen.add(finding.id);
  }
  const sourcesById = new Map(input.value.sources.map((source) => [source.id, source]));
  for (const candidate of result.entityOutputCandidates) {
    const keys = ['id', 'fileId', 'language', 'entityKinds', 'sinkKind', 'ruleId', 'sourceSurfaceIds', 'evidence'];
    const source = sourcesById.get(candidate.fileId);
    const candidateKey = `${candidate.fileId}\0${candidate.ruleId}\0${Array.isArray(candidate.entityKinds) ? candidate.entityKinds.join(',') : ''}\0${JSON.stringify(candidate.sourceSurfaceIds)}\0${JSON.stringify(candidate.evidence)}`;
    if (!exactKeys(candidate, keys) || candidate.id !== `ENTITYOUT-${sha256(candidateKey).slice(7, 23)}` || seen.has(candidate.id) ||
        !source || !['php', 'twig'].includes(candidate.language) ||
        candidate.language !== (source.kind === 'twig_template' ? 'twig' : 'php') || !Array.isArray(candidate.entityKinds) ||
        candidate.entityKinds.length === 0 || candidate.entityKinds.some((kind, index, values) =>
          !ENTITY_KINDS.has(kind) || values.indexOf(kind) !== index || (index > 0 && comparePortable(values[index - 1], kind) >= 0)
        ) || !ENTITY_OUTPUT_SINK_KINDS.has(candidate.sinkKind) ||
        candidate.ruleId !== `entity_output.${candidate.sinkKind}` ||
        JSON.stringify(candidate.sourceSurfaceIds) !== JSON.stringify(source.surfaceIds) ||
        !validEvidence(candidate.evidence, candidate.language)) {
      throw new Error('Mutable-identity Drupal parser emitted an invalid or unbound entity-output candidate.');
    }
    seen.add(candidate.id);
  }
  let incompleteBlocker = false;
  for (const blocker of result.blockers) {
    const keys = ['code', 'fileId', 'language', 'ruleId', 'evidence'];
    const transport = blocker.evidence?.sourceNodeType === 'Verifier\\Transport';
    const structural = !SEMANTIC_BLOCKERS.has(blocker.code);
    const blockerSource = sourcesById.get(blocker.fileId);
    if (!exactKeys(blocker, keys) || !BLOCKER_CODES.has(blocker.code) ||
        (blocker.fileId !== '' && !expectedIds.includes(blocker.fileId)) ||
        !['', 'php', 'twig'].includes(blocker.language) ||
        (blocker.fileId === '' ? blocker.language !== '' : blocker.language !== (blockerSource?.kind === 'twig_template' ? 'twig' : 'php')) ||
        blocker.ruleId !== `mutable_identity.${blocker.code}` ||
        !validEvidence(blocker.evidence, blocker.language || 'php', { structural, transport })) {
      throw new Error('Mutable-identity Drupal parser emitted an invalid or unredacted blocker.');
    }
    if (!SEMANTIC_BLOCKERS.has(blocker.code)) incompleteBlocker = true;
  }
  const completeCoverage = JSON.stringify([...result.completedFileIds].sort(comparePortable)) === JSON.stringify(expectedIds);
  const expectedStatus = expectedIds.length === 0
    ? 'not_applicable'
    : result.blockers.length > 0 ? 'blocked' : result.findings.length > 0 ? 'fail' : 'pass';
  if (result.status !== expectedStatus || result.completed !== (!incompleteBlocker && completeCoverage) ||
      result.sourceBytes !== (completeCoverage ? input.value.expectedTotalBytes : result.sourceBytes) ||
      result.deadlineExceeded !== result.blockers.some(({ code }) => code === 'deadline_exceeded')) {
    throw new Error('Mutable-identity Drupal parser status does not match its findings, blockers, and coverage.');
  }
  const needsPhp = input.value.sources.some(({ kind }) => kind !== 'twig_template');
  const needsTwig = input.value.sources.some(({ kind }) => kind === 'twig_template');
  if (['pass', 'fail'].includes(result.status) &&
      ((needsPhp && !result.parser.php.version) || (needsTwig && !result.parser.twig.version))) {
    throw new Error('Mutable-identity Drupal successful analysis lacks exact parser versions.');
  }
  return result;
}

export function mutableIdentityDrupalEntityOutputBindings(result) {
  if (!plainObject(result) || result.schemaVersion !== MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA ||
      result.completed !== true || !Array.isArray(result.entityOutputCandidates)) return [];
  return result.entityOutputCandidates.map(({ id, fileId, sourceSurfaceIds, entityKinds, sinkKind }) => ({
    id,
    fileId,
    sourceSurfaceIds: [...sourceSurfaceIds],
    entityKinds: [...entityKinds],
    sinkKind
  }));
}

export function runMutableIdentityDrupalAudit(input, runDrush, options = {}) {
  assertInputEnvelope(input);
  if (input.value.sources.length === 0) return notApplicableResult(input);
  if (typeof runDrush !== 'function') return blockedTransportResult(input, 'runner_unavailable');
  const now = typeof options.now === 'function' ? options.now : Date.now;
  const startedAt = now();
  let raw;
  try {
    raw = runDrush({
      args: ['php:eval', DRUPAL_MUTABLE_IDENTITY_AST_EVAL],
      stdin: input.json,
      timeoutMs: input.value.limits.deadlineMs,
      maxOutputBytes: input.value.limits.outputBytes
    });
  } catch {
    return blockedTransportResult(input, 'spawn_failed');
  }
  if (raw && typeof raw.then === 'function') return blockedTransportResult(input, 'unsupported_async_runner');
  const elapsed = now() - startedAt;
  if (!Number.isFinite(elapsed) || elapsed > input.value.limits.deadlineMs) {
    return blockedTransportResult(input, 'deadline_exceeded');
  }
  let execution;
  try { execution = parsedExecutionOutput(raw); }
  catch { return blockedTransportResult(input, 'invalid_output'); }
  if (execution.timedOut) return blockedTransportResult(input, 'deadline_exceeded');
  if (execution.exitCode !== 0) return blockedTransportResult(input, 'parser_process_failed');
  try { return parseMutableIdentityDrupalResult(raw, input); }
  catch { return blockedTransportResult(input, 'invalid_output'); }
}

export function inspectMutableIdentityDrupal(projectRoot, sourceFiles, runDrush, options = {}) {
  const input = createMutableIdentityDrupalInput(projectRoot, sourceFiles, options);
  return runMutableIdentityDrupalAudit(input, runDrush, options);
}

export const DRUPAL_MUTABLE_IDENTITY_AST_EVAL = String.raw`
$schema_input = 'public-kit.mutable-identity-drupal-input.1';
$schema_result = 'public-kit.mutable-identity-drupal-ast.1';
$analyzer = 'nikic-php-parser+drupal-twig-parser';
$started_ns = hrtime(TRUE);
$input = NULL;
$limits = [];
$input_fingerprint = '';
$expected_file_ids = [];
$completed_file_ids = [];
$source_bytes = 0;
$ast_nodes = 0;
$max_depth = 0;
$findings = [];
$entity_output_candidates = [];
$blockers = [];
$finding_keys = [];
$entity_output_keys = [];
$blocker_keys = [];
$incomplete = FALSE;
$deadline_exceeded = FALSE;

$strict_json = static function (mixed $value): string {
  return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
};
$digest = static function (string $value): string {
  return 'sha256:' . hash('sha256', $value);
};
$portable_compare = static function (string $left, string $right): int {
  return $left <=> $right;
};
$valid_relative_path = static function (mixed $value, bool $allow_dot = FALSE): bool {
  if (!is_string($value) || $value === '' || strlen($value) > 1024 || str_contains($value, "\\") || str_contains($value, "\0") || str_starts_with($value, '/')) return FALSE;
  if (!$allow_dot && $value === '.') return FALSE;
  foreach (explode('/', $value) as $segment) if ($segment === '' || $segment === '..') return FALSE;
  return !str_starts_with($value, './');
};
$span = static function (object $node, string $language): array {
  if ($language === 'php') {
    $start_line = (int) $node->getStartLine();
    $end_line = (int) $node->getEndLine();
    $start_pos = $node->getAttribute('startFilePos', -1);
    $end_pos = $node->getAttribute('endFilePos', -1);
    return [
      'nodeType' => get_class($node),
      'startLine' => $start_line,
      'endLine' => $end_line,
      'startFilePos' => is_int($start_pos) && $start_pos >= 0 ? $start_pos : NULL,
      'endFilePos' => is_int($end_pos) && $end_pos >= 0 ? $end_pos : NULL,
    ];
  }
  $line = method_exists($node, 'getTemplateLine') ? (int) $node->getTemplateLine() : 0;
  return ['nodeType' => get_class($node), 'startLine' => $line, 'endLine' => $line, 'startFilePos' => NULL, 'endFilePos' => NULL];
};
$evidence = static function (object $source, ?object $sink, string $language) use ($span): array {
  $source_span = $span($source, $language);
  $sink_span = $sink ? $span($sink, $language) : ['nodeType' => '', 'startLine' => 0, 'endLine' => 0, 'startFilePos' => NULL, 'endFilePos' => NULL];
  return [
    'sourceNodeType' => $source_span['nodeType'],
    'sourceStartLine' => $source_span['startLine'],
    'sourceEndLine' => $source_span['endLine'],
    'sourceStartFilePos' => $source_span['startFilePos'],
    'sourceEndFilePos' => $source_span['endFilePos'],
    'sinkNodeType' => $sink_span['nodeType'],
    'sinkStartLine' => $sink_span['startLine'],
    'sinkEndLine' => $sink_span['endLine'],
    'sinkStartFilePos' => $sink_span['startFilePos'],
    'sinkEndFilePos' => $sink_span['endFilePos'],
  ];
};
$synthetic_evidence = static function (string $node_type, int $line = 0): array {
  return [
    'sourceNodeType' => $node_type,
    'sourceStartLine' => $line,
    'sourceEndLine' => $line,
    'sourceStartFilePos' => NULL,
    'sourceEndFilePos' => NULL,
    'sinkNodeType' => '',
    'sinkStartLine' => 0,
    'sinkEndLine' => 0,
    'sinkStartFilePos' => NULL,
    'sinkEndFilePos' => NULL,
  ];
};

try {
  $raw_input = stream_get_contents(STDIN);
  if (!is_string($raw_input) || strlen($raw_input) > 4 * 1024 * 1024) throw new RuntimeException('input_limit');
  $input = json_decode($raw_input, TRUE, 64, JSON_THROW_ON_ERROR);
  if (!is_array($input) || array_keys($input) !== ['schemaVersion', 'docroot', 'limits', 'expectedTotalBytes', 'sources', 'inputFingerprint'] || ($input['schemaVersion'] ?? '') !== $schema_input || !is_array($input['limits'] ?? NULL) || !is_array($input['sources'] ?? NULL) || !is_int($input['expectedTotalBytes'] ?? NULL) || $input['expectedTotalBytes'] < 0) throw new RuntimeException('input_invalid');
  $input_fingerprint = (string) ($input['inputFingerprint'] ?? '');
  if (strlen($input_fingerprint) !== 71 || !str_starts_with($input_fingerprint, 'sha256:') || substr($input_fingerprint, 7) !== strtolower(substr($input_fingerprint, 7)) || !ctype_xdigit(substr($input_fingerprint, 7))) throw new RuntimeException('input_fingerprint_invalid');
  $unsigned_input = $input;
  unset($unsigned_input['inputFingerprint']);
  if (!hash_equals($digest($strict_json($unsigned_input)), $input_fingerprint)) throw new RuntimeException('input_fingerprint_invalid');
  $limits = $input['limits'];
  $ceilings = [
    'files' => 5000,
    'surfacesPerFile' => 5000,
    'surfacesTotal' => 50000,
    'sourceBytesPerFile' => 1048576,
    'sourceBytesTotal' => 67108864,
    'astNodesPerFile' => 100000,
    'astNodesTotal' => 500000,
    'astDepth' => 256,
    'findings' => 200,
    'deadlineMs' => 30000,
    'outputBytes' => 1048576,
  ];
  $minimums = ['files' => 1, 'surfacesPerFile' => 1, 'surfacesTotal' => 1, 'sourceBytesPerFile' => 1, 'sourceBytesTotal' => 1, 'astNodesPerFile' => 1, 'astNodesTotal' => 1, 'astDepth' => 1, 'findings' => 1, 'deadlineMs' => 10, 'outputBytes' => 4096];
  if (array_keys($limits) !== array_keys($ceilings)) throw new RuntimeException('limits_invalid');
  foreach ($ceilings as $key => $ceiling) {
    if (!is_int($limits[$key]) || $limits[$key] < $minimums[$key] || $limits[$key] > $ceiling) throw new RuntimeException('limits_invalid');
  }
  if ($limits['astNodesPerFile'] > $limits['astNodesTotal'] || $limits['sourceBytesPerFile'] > $limits['sourceBytesTotal'] || $limits['surfacesPerFile'] > $limits['surfacesTotal']) throw new RuntimeException('limits_invalid');
  if (count($input['sources']) > $limits['files']) throw new RuntimeException('file_limit');
  $deadline_ns = $started_ns + ($limits['deadlineMs'] * 1000000);
  $check_deadline = static function () use ($deadline_ns, &$deadline_exceeded): void {
    if (hrtime(TRUE) > $deadline_ns) {
      $deadline_exceeded = TRUE;
      throw new RuntimeException('deadline_exceeded');
    }
  };
  $record_blocker = static function (string $code, string $file_id, string $language, array $event_evidence, bool $structural = FALSE) use (&$blockers, &$blocker_keys, &$findings, &$entity_output_candidates, &$incomplete, $limits, $strict_json): void {
    $key = $code . "\0" . $file_id . "\0" . $language . "\0" . $strict_json($event_evidence);
    if (isset($blocker_keys[$key])) return;
    if (count($blockers) + count($findings) + count($entity_output_candidates) >= $limits['findings']) {
      if ($code !== 'finding_limit') throw new RuntimeException('finding_limit');
      if (count($findings) > 0) array_pop($findings);
      elseif (count($entity_output_candidates) > 0) array_pop($entity_output_candidates);
      elseif (count($blockers) > 0) array_pop($blockers);
    }
    $blocker_keys[$key] = TRUE;
    $blockers[] = ['code' => $code, 'fileId' => $file_id, 'language' => $language, 'ruleId' => 'mutable_identity.' . $code, 'evidence' => $event_evidence];
    if ($structural) $incomplete = TRUE;
  };
  $record_finding = static function (string $file_id, string $language, string $identity_kind, string $sink_kind, object $source, object $sink) use (&$findings, &$finding_keys, &$blockers, &$entity_output_candidates, $limits, $evidence, $strict_json, $digest, $record_blocker): void {
    $event_evidence = $evidence($source, $sink, $language);
    if ($event_evidence['sourceStartLine'] < 1 || $event_evidence['sinkStartLine'] < 1 || ($language === 'php' && ($event_evidence['sourceStartFilePos'] === NULL || $event_evidence['sourceEndFilePos'] === NULL || $event_evidence['sinkStartFilePos'] === NULL || $event_evidence['sinkEndFilePos'] === NULL))) {
      $record_blocker('missing_ast_span', $file_id, $language, $event_evidence, TRUE);
      return;
    }
    $rule_id = 'mutable_identity.' . $identity_kind . '.' . $sink_kind;
    $key = $file_id . "\0" . $rule_id . "\0" . $strict_json($event_evidence);
    if (isset($finding_keys[$key])) return;
    if (count($findings) + count($entity_output_candidates) + count($blockers) >= $limits['findings']) throw new RuntimeException('finding_limit');
    $finding_keys[$key] = TRUE;
    $findings[] = [
      'id' => 'MUTABLE-' . substr($digest($key), 7, 16),
      'fileId' => $file_id,
      'language' => $language,
      'identityKind' => $identity_kind,
      'sinkKind' => $sink_kind,
      'ruleId' => $rule_id,
      'evidence' => $event_evidence,
    ];
  };
  $record_entity_output = static function (string $file_id, string $language, array $entity_kinds, string $sink_kind, array $source_surface_ids, object $source, ?object $sink = NULL) use (&$entity_output_candidates, &$entity_output_keys, &$findings, &$blockers, $limits, $evidence, $strict_json, $digest, $record_blocker): void {
    $entity_kinds = array_values(array_unique($entity_kinds));
    sort($entity_kinds, SORT_STRING);
    if (count($entity_kinds) === 0 || count(array_diff($entity_kinds, ['file', 'media', 'node'])) > 0 || !in_array($sink_kind, ['entity_render_call', 'entity_view_builder', 'render_array', 'twig_print'], TRUE)) {
      $record_blocker('unsupported_entity_output', $file_id, $language, $evidence($source, $sink, $language), TRUE);
      return;
    }
    $event_evidence = $evidence($source, $sink, $language);
    $source_span_missing = $event_evidence['sourceStartLine'] < 1 || ($language === 'php' && ($event_evidence['sourceStartFilePos'] === NULL || $event_evidence['sourceEndFilePos'] === NULL));
    $sink_span_missing = $sink !== NULL && ($event_evidence['sinkStartLine'] < 1 || ($language === 'php' && ($event_evidence['sinkStartFilePos'] === NULL || $event_evidence['sinkEndFilePos'] === NULL)));
    if ($source_span_missing || $sink_span_missing) {
      $record_blocker('missing_ast_span', $file_id, $language, $event_evidence, TRUE);
      return;
    }
    $rule_id = 'entity_output.' . $sink_kind;
    $key = $file_id . "\0" . $rule_id . "\0" . implode(',', $entity_kinds) . "\0" . $strict_json($source_surface_ids) . "\0" . $strict_json($event_evidence);
    if (isset($entity_output_keys[$key])) return;
    if (count($findings) + count($entity_output_candidates) + count($blockers) >= $limits['findings']) throw new RuntimeException('finding_limit');
    $entity_output_keys[$key] = TRUE;
    $entity_output_candidates[] = [
      'id' => 'ENTITYOUT-' . substr($digest($key), 7, 16),
      'fileId' => $file_id,
      'language' => $language,
      'entityKinds' => $entity_kinds,
      'sinkKind' => $sink_kind,
      'ruleId' => $rule_id,
      'sourceSurfaceIds' => $source_surface_ids,
      'evidence' => $event_evidence,
    ];
  };

  $docroot = (string) ($input['docroot'] ?? '');
  if (!$valid_relative_path($docroot, TRUE)) throw new RuntimeException('docroot_invalid');
  $drupal_root = realpath(\Drupal::root());
  if (!is_string($drupal_root)) throw new RuntimeException('drupal_root_unavailable');
  $normalized_drupal_root = str_replace("\\", '/', $drupal_root);
  if ($docroot === '.') {
    $project_root = $drupal_root;
  }
  else {
    $suffix = '/' . $docroot;
    if (!str_ends_with($normalized_drupal_root, $suffix)) throw new RuntimeException('docroot_mismatch');
    $project_root = substr($drupal_root, 0, strlen($drupal_root) - strlen($suffix));
  }
  $project_root = realpath($project_root);
  if (!is_string($project_root)) throw new RuntimeException('project_root_unavailable');
  $project_prefix = rtrim(str_replace("\\", '/', $project_root), '/') . '/';

  $source_paths = [];
  $surface_count = 0;
  $declared_source_bytes = 0;
  $needs_php = FALSE;
  $needs_twig = FALSE;
  foreach ($input['sources'] as $source) {
    if (!is_array($source) || array_keys($source) !== ['id', 'path', 'kind', 'sha256', 'bytes', 'surfaceIds']) throw new RuntimeException('source_record_invalid');
    $file_id = (string) $source['id'];
    $path = (string) $source['path'];
    $kind = (string) $source['kind'];
    $source_hash = (string) $source['sha256'];
    if (!str_starts_with($file_id, 'SOURCE-') || strlen($file_id) !== 23 || substr($file_id, 7) !== strtolower(substr($file_id, 7)) || !ctype_xdigit(substr($file_id, 7)) || in_array($file_id, $expected_file_ids, TRUE) || !$valid_relative_path($path) || isset($source_paths[$path]) || !in_array($kind, ['procedural_php', 'php_class', 'twig_template'], TRUE) || !is_int($source['bytes']) || $source['bytes'] < 0 || $source['bytes'] > $limits['sourceBytesPerFile'] || strlen($source_hash) !== 71 || !str_starts_with($source_hash, 'sha256:') || substr($source_hash, 7) !== strtolower(substr($source_hash, 7)) || !ctype_xdigit(substr($source_hash, 7)) || !is_array($source['surfaceIds']) || count($source['surfaceIds']) > $limits['surfacesPerFile']) throw new RuntimeException('source_record_invalid');
    if (($kind === 'twig_template' && !str_ends_with(strtolower($path), '.twig')) || ($kind === 'php_class' && !str_ends_with(strtolower($path), '.php')) || ($kind === 'procedural_php' && preg_match('/\.(?:module|theme|install|inc|test|profile)$/i', $path) !== 1)) throw new RuntimeException('source_kind_invalid');
    $previous_surface_id = '';
    foreach ($source['surfaceIds'] as $surface_id) {
      if (!is_string($surface_id) || !str_starts_with($surface_id, 'SURFACE-') || strlen($surface_id) !== 24 || substr($surface_id, 8) !== strtolower(substr($surface_id, 8)) || !ctype_xdigit(substr($surface_id, 8)) || ($previous_surface_id !== '' && $surface_id <= $previous_surface_id)) throw new RuntimeException('source_record_invalid');
      $previous_surface_id = $surface_id;
      $surface_count++;
      if ($surface_count > $limits['surfacesTotal']) throw new RuntimeException('surface_limit');
    }
    $source_paths[$path] = TRUE;
    $declared_source_bytes += $source['bytes'];
    if ($declared_source_bytes > $limits['sourceBytesTotal']) throw new RuntimeException('source_bytes_invalid');
    $needs_twig = $needs_twig || $kind === 'twig_template';
    $needs_php = $needs_php || $kind !== 'twig_template';
    $expected_file_ids[] = $file_id;
  }
  if ($declared_source_bytes !== $input['expectedTotalBytes']) throw new RuntimeException('source_bytes_invalid');
  sort($expected_file_ids, SORT_STRING);

  $php_version = '';
  $twig_version = '';
  if (class_exists('Composer\\InstalledVersions')) {
    try { $php_version = (string) (\Composer\InstalledVersions::getPrettyVersion('nikic/php-parser') ?? ''); } catch (Throwable) {}
    try { $twig_version = (string) (\Composer\InstalledVersions::getPrettyVersion('twig/twig') ?? ''); } catch (Throwable) {}
  }
  $php_parser = NULL;
  if ($needs_php) {
    if (!class_exists('PhpParser\\ParserFactory') || !interface_exists('PhpParser\\Node')) throw new RuntimeException('php_parser_unavailable');
    $factory = new \PhpParser\ParserFactory();
    if (method_exists($factory, 'createForNewestSupportedVersion')) {
      $php_parser = $factory->createForNewestSupportedVersion();
    }
    else {
      $lexer = new \PhpParser\Lexer\Emulative(['usedAttributes' => ['startLine', 'endLine', 'startFilePos', 'endFilePos']]);
      $php_parser = $factory->create(\PhpParser\ParserFactory::PREFER_PHP7, $lexer);
    }
  }
  $twig = NULL;
  if ($needs_twig) {
    $twig = \Drupal::service('twig');
    if (!$twig instanceof \Twig\Environment || !class_exists('Twig\\Source') || !class_exists('Twig\\Node\\Node')) throw new RuntimeException('twig_parser_unavailable');
  }

  $name_string = static function (mixed $value): string {
    if ($value instanceof \PhpParser\Node\Identifier || $value instanceof \PhpParser\Node\Name) return strtolower((string) $value->toString());
    if ($value instanceof \PhpParser\Node\Scalar\String_) return strtolower((string) $value->value);
    if (is_string($value)) return strtolower($value);
    return '';
  };
  $receiver_hint = NULL;
  $receiver_hint = static function (mixed $node) use (&$receiver_hint, $name_string): string {
    if ($node instanceof \PhpParser\Node\Expr\Variable && is_string($node->name)) return strtolower($node->name);
    if ($node instanceof \PhpParser\Node\Expr\PropertyFetch || $node instanceof \PhpParser\Node\Expr\NullsafePropertyFetch) return $receiver_hint($node->var) . '.' . $name_string($node->name);
    if ($node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) return $receiver_hint($node->var) . '.' . $name_string($node->name);
    if ($node instanceof \PhpParser\Node\Expr\StaticCall) return $name_string($node->class) . '.' . $name_string($node->name);
    return '';
  };
  $scalar_string = static function (mixed $node): string {
    return $node instanceof \PhpParser\Node\Scalar\String_ ? strtolower($node->value) : '';
  };
  $contains_call_argument = NULL;
  $contains_call_argument = static function (mixed $node, string $needle) use (&$contains_call_argument, $scalar_string): bool {
    if ($scalar_string($node) === $needle) return TRUE;
    if (!$node instanceof \PhpParser\Node) return FALSE;
    foreach ($node->getSubNodeNames() as $name) {
      $child = $node->$name;
      if (is_array($child)) foreach ($child as $item) { if ($contains_call_argument($item, $needle)) return TRUE; }
      elseif ($contains_call_argument($child, $needle)) return TRUE;
    }
    return FALSE;
  };
  $php_source = static function (\PhpParser\Node $node) use ($name_string, $receiver_hint, $scalar_string): array {
    $method = '';
    $receiver = '';
    if ($node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) {
      $method = $name_string($node->name);
      $receiver = $receiver_hint($node->var);
      if (in_array($method, ['getaliasbypath', 'getpathbyalias', 'getpathinfo', 'getrequesturi', 'geturi', 'lookupbyalias', 'tourl'], TRUE) || ($method === 'getpath' && (str_contains($receiver, 'path') || str_contains($receiver, 'request')))) return ['alias_or_path', ''];
      if ($method === 'gettitle') {
        if (str_contains($receiver, 'node') || str_contains($receiver, 'entity') || str_contains($receiver, 'content')) return ['title_or_label', ''];
        return ['', 'ambiguous_identity_receiver'];
      }
      if ($method === 'label') {
        if (str_contains($receiver, 'media') || str_contains($receiver, 'asset')) return ['media_name', ''];
        if (str_contains($receiver, 'node') || str_contains($receiver, 'entity') || str_contains($receiver, 'content') || str_contains($receiver, 'item')) return ['title_or_label', ''];
        return ['', 'ambiguous_identity_receiver'];
      }
      if ($method === 'getname') {
        if (str_contains($receiver, 'media') || str_contains($receiver, 'asset')) return ['media_name', ''];
        return ['', 'ambiguous_media_receiver'];
      }
      if (in_array($method, ['getinternalpath', 'tostring'], TRUE) && str_contains($receiver, 'tourl')) return ['alias_or_path', ''];
      if ($method === 'get') {
        if (!isset($node->args[0]) || $scalar_string($node->args[0]->value) === '') {
          return str_contains($receiver, 'node') || str_contains($receiver, 'entity') || str_contains($receiver, 'media')
            ? ['', 'unsupported_dynamic_identity']
            : ['', ''];
        }
        $field = $scalar_string($node->args[0]->value);
        if ($field === 'title' && (str_contains($receiver, 'node') || str_contains($receiver, 'entity'))) return ['title_or_label', ''];
        if ($field === 'name' && (str_contains($receiver, 'media') || str_contains($receiver, 'asset'))) return ['media_name', ''];
        if ($field === 'alias' && str_contains($receiver, 'alias')) return ['alias_or_path', ''];
        if (in_array($field, ['title', 'name', 'alias'], TRUE)) return ['', 'ambiguous_identity_receiver'];
      }
    }
    if ($node instanceof \PhpParser\Node\Expr\PropertyFetch || $node instanceof \PhpParser\Node\Expr\NullsafePropertyFetch) {
      $property = $name_string($node->name);
      $receiver = $receiver_hint($node->var);
      if ($property === '' && (str_contains($receiver, 'node') || str_contains($receiver, 'entity') || str_contains($receiver, 'media'))) return ['', 'unsupported_dynamic_identity'];
      if (in_array($property, ['pathinfo', 'requesturi', 'pathname'], TRUE) && (str_contains($receiver, 'request') || str_contains($receiver, 'location'))) return ['alias_or_path', ''];
      if (in_array($property, ['title', 'label'], TRUE)) {
        if (str_contains($receiver, 'media') || str_contains($receiver, 'asset')) return ['media_name', ''];
        if (str_contains($receiver, 'node') || str_contains($receiver, 'entity') || str_contains($receiver, 'content') || str_contains($receiver, 'item')) return ['title_or_label', ''];
        return ['', 'ambiguous_identity_receiver'];
      }
      if ($property === 'name') return str_contains($receiver, 'media') || str_contains($receiver, 'asset') ? ['media_name', ''] : ['', 'ambiguous_media_receiver'];
    }
    if ($node instanceof \PhpParser\Node\Expr\ArrayDimFetch && $node->dim instanceof \PhpParser\Node\Scalar\String_) {
      $field = strtolower($node->dim->value);
      $receiver = $receiver_hint($node->var);
      if ($field === 'title' && (str_contains($receiver, 'node') || str_contains($receiver, 'entity'))) return ['title_or_label', ''];
      if ($field === 'name' && (str_contains($receiver, 'media') || str_contains($receiver, 'asset'))) return ['media_name', ''];
      if ($field === 'alias' && str_contains($receiver, 'alias')) return ['alias_or_path', ''];
    }
    return ['', ''];
  };
  $php_entity_lookup = static function (\PhpParser\Node $node) use ($name_string, $receiver_hint, $scalar_string, $contains_call_argument): array {
    if (!$node instanceof \PhpParser\Node\Expr\MethodCall && !$node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) return ['', ''];
    $method = $name_string($node->name);
    $receiver = $receiver_hint($node->var);
    if ($method === 'lookupbyalias') return ['alias_or_path', ''];
    $entity_receiver = str_contains($receiver, 'query') || str_contains($receiver, 'storage') || str_contains($receiver, 'entity') || str_contains($receiver, 'node') || str_contains($receiver, 'media') || $contains_call_argument($node->var, 'node') || $contains_call_argument($node->var, 'media') || $contains_call_argument($node->var, 'file');
    if ($method === 'condition') {
      if (!isset($node->args[0])) return ['', 'unsupported_dynamic_identity'];
      $field = $scalar_string($node->args[0]->value);
      if ($field === '') return ['', 'unsupported_dynamic_identity'];
      if ($field === 'title') return $entity_receiver ? ['title_or_label', ''] : ['', 'ambiguous_identity_receiver'];
      if ($field === 'alias') return (str_contains($receiver, 'alias') || $entity_receiver) ? ['alias_or_path', ''] : ['', 'ambiguous_identity_receiver'];
      if ($field === 'name') return (str_contains($receiver, 'media') || $contains_call_argument($node->var, 'media')) ? ['media_name', ''] : ['', 'ambiguous_media_receiver'];
    }
    if ($method === 'loadbyproperties') {
      if (!isset($node->args[0]) || !$node->args[0]->value instanceof \PhpParser\Node\Expr\Array_) return ['', 'unsupported_dynamic_identity'];
      foreach ($node->args[0]->value->items as $item) {
        if (!$item instanceof \PhpParser\Node\ArrayItem || !$item->key instanceof \PhpParser\Node\Scalar\String_) return ['', 'unsupported_dynamic_identity'];
        $field = $scalar_string($item->key);
        if ($field === 'title') return $entity_receiver ? ['title_or_label', ''] : ['', 'ambiguous_identity_receiver'];
        if ($field === 'alias') return (str_contains($receiver, 'alias') || $entity_receiver) ? ['alias_or_path', ''] : ['', 'ambiguous_identity_receiver'];
        if ($field === 'name') return (str_contains($receiver, 'media') || $contains_call_argument($node->var, 'media')) ? ['media_name', ''] : ['', 'ambiguous_media_receiver'];
      }
    }
    return ['', ''];
  };
  $entity_kinds_for_hint = static function (string $hint): array {
    $compact = strtolower(str_replace(['_', '-', '.', '\\'], '', $hint));
    $kinds = [];
    foreach (['file', 'media', 'node'] as $kind) {
      if (in_array($compact, [$kind, $kind . 's', $kind . 'entity', $kind . 'entities', $kind . 'view', $kind . 'views', $kind . 'viewbuilder', $kind . 'entityviewbuilder'], TRUE) || str_contains($compact, $kind . 'viewbuilder') || str_contains($compact, $kind . 'entityview')) $kinds[] = $kind;
    }
    return $kinds;
  };
  $view_builder_kind = static function (mixed $node) use ($name_string, $scalar_string): string {
    if (($node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) && $name_string($node->name) === 'getviewbuilder' && isset($node->args[0])) {
      $kind = $scalar_string($node->args[0]->value);
      return in_array($kind, ['file', 'media', 'node'], TRUE) ? $kind : '';
    }
    return '';
  };
  $php_entity_output = static function (\PhpParser\Node $node) use ($name_string, $receiver_hint, $scalar_string, $entity_kinds_for_hint, $view_builder_kind): array {
    if ($node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) {
      $method = $name_string($node->name);
      $receiver = $receiver_hint($node->var);
      if (in_array($method, ['view', 'viewmultiple', 'build', 'buildmultiple'], TRUE) && (str_contains(strtolower(str_replace(['_', '-', '.'], '', $receiver)), 'viewbuilder') || $view_builder_kind($node->var) !== '')) {
        $kinds = $entity_kinds_for_hint($receiver);
        $builder_kind = $view_builder_kind($node->var);
        if ($builder_kind !== '') $kinds[] = $builder_kind;
        foreach ($node->args as $argument) $kinds = [...$kinds, ...$entity_kinds_for_hint($receiver_hint($argument->value))];
        $kinds = array_values(array_unique($kinds));
        if (count($kinds) > 0) return [$kinds, 'entity_view_builder'];
      }
      if (in_array($method, ['render', 'renderplain', 'renderroot'], TRUE) && str_contains(strtolower($receiver), 'renderer')) {
        $kinds = [];
        foreach ($node->args as $argument) $kinds = [...$kinds, ...$entity_kinds_for_hint($receiver_hint($argument->value))];
        $kinds = array_values(array_unique($kinds));
        if (count($kinds) > 0) return [$kinds, 'entity_render_call'];
      }
    }
    if ($node instanceof \PhpParser\Node\Expr\FuncCall) {
      $function = $name_string($node->name);
      if (in_array($function, ['node_view', 'media_view', 'file_view'], TRUE)) return [[substr($function, 0, strpos($function, '_'))], 'entity_render_call'];
    }
    if ($node instanceof \PhpParser\Node\Expr\Array_) {
      $theme_kind = '';
      $type = '';
      $kinds = [];
      foreach ($node->items as $item) {
        if (!$item instanceof \PhpParser\Node\ArrayItem || !$item->key instanceof \PhpParser\Node\Scalar\String_) continue;
        $key = strtolower($item->key->value);
        if ($key === '#theme') $theme_kind = $scalar_string($item->value);
        if ($key === '#type') $type = $scalar_string($item->value);
        if (in_array($key, ['#file', '#media', '#node'], TRUE)) $kinds[] = substr($key, 1);
        if ($key === '#entity') $kinds = [...$kinds, ...$entity_kinds_for_hint($receiver_hint($item->value))];
      }
      if (in_array($theme_kind, ['file', 'media', 'node'], TRUE)) $kinds[] = $theme_kind;
      $kinds = array_values(array_unique($kinds));
      if (count($kinds) > 0 && ($theme_kind !== '' || in_array($type, ['entity_view', 'view'], TRUE))) return [$kinds, 'render_array'];
    }
    return [[], ''];
  };
  $php_array_key = static function (mixed $node) use ($scalar_string): string {
    return $node instanceof \PhpParser\Node\Scalar\String_ ? $scalar_string($node) : '';
  };
  $contexts_for_php_child = static function (\PhpParser\Node $node, string $name, mixed $child, array $contexts) use ($name_string, $php_array_key, $receiver_hint): array {
    $append = static function (array $list, string $type, string $sink_kind, object $sink): array { $list[] = ['type' => $type, 'sinkKind' => $sink_kind, 'sink' => $sink]; return $list; };
    if ((($node instanceof \PhpParser\Node\Stmt\If_ || $node instanceof \PhpParser\Node\Stmt\ElseIf_ || $node instanceof \PhpParser\Node\Stmt\While_ || $node instanceof \PhpParser\Node\Stmt\Do_) && $name === 'cond') ||
        (($node instanceof \PhpParser\Node\Expr\Ternary || $node instanceof \PhpParser\Node\Stmt\Switch_ || $node instanceof \PhpParser\Node\Expr\Match_ || $node instanceof \PhpParser\Node\Stmt\Case_) && $name === 'cond') ||
        ($node instanceof \PhpParser\Node\Stmt\For_ && $name === 'cond')) return $append($contexts, 'sink', 'behavior_branch', $node);
    if ($node instanceof \PhpParser\Node\Expr\ArrayDimFetch && $name === 'dim' && !($child instanceof \PhpParser\Node\Scalar)) return $append($contexts, 'sink', 'computed_lookup', $node);
    if ($node instanceof \PhpParser\Node\ArrayItem && $name === 'value') {
      $key = $php_array_key($node->key);
      if (in_array($key, ['#markup', '#plain_text', '#title', '#alt'], TRUE)) return $append($contexts, 'display', '', $node);
      if (in_array($key, ['#theme', '#theme_wrappers'], TRUE)) return $append($contexts, 'sink', 'presentation_selector', $node);
    }
    if ($node instanceof \PhpParser\Node\Expr\Assign && $name === 'expr') {
      if ($node->var instanceof \PhpParser\Node\Expr\ArrayDimFetch) {
        $key = $php_array_key($node->var->dim);
        if (in_array($key, ['#markup', '#plain_text', '#title', '#alt'], TRUE)) return $append($contexts, 'display', '', $node);
        if (in_array($key, ['#theme', '#theme_wrappers'], TRUE)) return $append($contexts, 'sink', 'presentation_selector', $node);
      }
      $hint = $receiver_hint($node->var);
      if (str_contains($hint, 'template') || str_contains($hint, 'component') || str_contains($hint, 'variant') || str_contains($hint, 'viewmode') || str_contains($hint, 'classname') || str_contains($hint, 'suggestion')) return $append($contexts, 'sink', 'presentation_selector', $node);
    }
    if ($node instanceof \PhpParser\Node\Expr\Include_ && $name === 'expr') return $append($contexts, 'sink', 'presentation_selector', $node);
    if (($node instanceof \PhpParser\Node\Expr\FuncCall || $node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) && $name === 'args') {
      $call_name = $name_string($node->name);
      if (in_array($call_name, ['theme', 'rendertemplate', 'settheme', 'settemplate', 'addclass'], TRUE)) return $append($contexts, 'sink', 'presentation_selector', $node);
    }
    return $contexts;
  };

  $twig_chain = NULL;
  $twig_chain = static function (mixed $node) use (&$twig_chain): array {
    if ($node instanceof \Twig\Node\Expression\NameExpression) return [strtolower((string) $node->getAttribute('name'))];
    if ($node instanceof \Twig\Node\Expression\GetAttrExpression && $node->hasNode('node') && $node->hasNode('attribute')) {
      $attribute = $node->getNode('attribute');
      if (!$attribute instanceof \Twig\Node\Expression\ConstantExpression) return [];
      return [...$twig_chain($node->getNode('node')), strtolower((string) $attribute->getAttribute('value'))];
    }
    return [];
  };
  $twig_source = static function (\Twig\Node\Node $node) use ($twig_chain): array {
    if (!$node instanceof \Twig\Node\Expression\GetAttrExpression) return ['', ''];
    $chain = $twig_chain($node);
    if (count($chain) < 2) return ['', ''];
    $last = $chain[count($chain) - 1];
    $root = $chain[0];
    if ($last === 'tourl' ||
        (in_array($last, ['pathinfo', 'requesturi', 'pathname', 'getpathinfo', 'getrequesturi', 'geturi'], TRUE) && (in_array('request', $chain, TRUE) || in_array('location', $chain, TRUE))) ||
        (in_array($last, ['getinternalpath', 'tostring'], TRUE) && in_array('tourl', $chain, TRUE))) return ['alias_or_path', ''];
    if (in_array($last, ['title', 'label', 'gettitle', 'getlabel'], TRUE)) {
      if (str_contains($root, 'media') || str_contains($root, 'asset')) return ['media_name', ''];
      if (in_array($root, ['node', 'entity'], TRUE)) return ['title_or_label', ''];
      return ['', 'ambiguous_identity_receiver'];
    }
    if (in_array($last, ['name', 'getname'], TRUE)) return str_contains($root, 'media') || str_contains($root, 'asset') ? ['media_name', ''] : ['', 'ambiguous_media_receiver'];
    return ['', ''];
  };
  $twig_entity_output = static function (\Twig\Node\Node $node, string $template_entity_kind): array {
    if (!str_ends_with(get_class($node), '\\PrintNode') || !$node->hasNode('expr')) return [[], NULL];
    $expression = $node->getNode('expr');
    if (!$expression instanceof \Twig\Node\Expression\NameExpression) return [[], NULL];
    $name = strtolower((string) $expression->getAttribute('name'));
    if (in_array($name, ['file', 'media', 'node'], TRUE)) return [[$name], $expression];
    if ($name === 'content' && in_array($template_entity_kind, ['file', 'media', 'node'], TRUE)) return [[$template_entity_kind], $expression];
    return [[], NULL];
  };
  $suspicious_name = static function (string $name): bool {
    $name = strtolower(str_replace(['_', '-'], '', $name));
    return in_array($name, ['alias', 'pathalias', 'currentpath', 'requestpath', 'title', 'label', 'medianame', 'medialabel'], TRUE);
  };
  $twig_call_name = static function (\Twig\Node\Node $node): string {
    if ($node instanceof \Twig\Node\Expression\GetAttrExpression && $node->hasNode('attribute')) {
      $attribute = $node->getNode('attribute');
      if ($attribute instanceof \Twig\Node\Expression\ConstantExpression) return strtolower((string) $attribute->getAttribute('value'));
    }
    if (str_ends_with(get_class($node), '\\FilterExpression') && $node->hasNode('filter')) {
      $filter = $node->getNode('filter');
      if ($filter instanceof \Twig\Node\Expression\ConstantExpression) return strtolower((string) $filter->getAttribute('value'));
    }
    if ($node->hasAttribute('name') && is_string($node->getAttribute('name'))) return strtolower((string) $node->getAttribute('name'));
    return '';
  };
  $twig_output_contexts = static function (string $source): array {
    $contexts = [];
    $line = 1;
    $in_tag = FALSE;
    $quote = '';
    $attribute = '';
    $tag_name = '';
    $closing_tag = FALSE;
    $raw_element = '';
    $length = strlen($source);
    $record = static function (array &$items, int $line_number, string $context): void {
      $rank = ['display' => 1, 'presentation' => 2];
      if (!isset($items[$line_number]) || $rank[$context] > $rank[$items[$line_number]]) $items[$line_number] = $context;
    };
    for ($index = 0; $index < $length; $index++) {
      $character = $source[$index];
      if ($character === '{' && $index + 1 < $length && $source[$index + 1] === '{') {
        $context = 'display';
        if ($in_tag || in_array($raw_element, ['script', 'style'], TRUE)) {
          $safe_attribute = $quote !== '' && in_array($attribute, ['alt', 'aria-label', 'title'], TRUE);
          $context = $safe_attribute && !in_array($raw_element, ['script', 'style'], TRUE) ? 'display' : 'presentation';
        }
        $record($contexts, $line, $context);
        $end = strpos($source, '}}', $index + 2);
        if ($end === FALSE) break;
        while ($index < $end + 1) {
          if ($source[$index] === "\n") $line++;
          $index++;
        }
        continue;
      }
      if ($character === "\n") {
        $line++;
        continue;
      }
      if (!$in_tag) {
        if ($character !== '<') continue;
        $cursor = $index + 1;
        while ($cursor < $length && ctype_space($source[$cursor])) $cursor++;
        $closing_tag = $cursor < $length && $source[$cursor] === '/';
        if ($closing_tag) $cursor++;
        $start = $cursor;
        while ($cursor < $length && (ctype_alnum($source[$cursor]) || in_array($source[$cursor], ['-', ':'], TRUE))) $cursor++;
        $tag_name = $cursor === $start ? '' : strtolower(substr($source, $start, $cursor - $start));
        $in_tag = TRUE;
        $quote = '';
        $attribute = '';
        continue;
      }
      if ($quote !== '') {
        if ($character === $quote) {
          $quote = '';
          $attribute = '';
        }
        continue;
      }
      if ($character === '"' || $character === "'") {
        $cursor = $index - 1;
        while ($cursor >= 0 && ctype_space($source[$cursor])) $cursor--;
        if ($cursor >= 0 && $source[$cursor] === '=') {
          $cursor--;
          while ($cursor >= 0 && ctype_space($source[$cursor])) $cursor--;
          $end = $cursor;
          while ($cursor >= 0 && (ctype_alnum($source[$cursor]) || in_array($source[$cursor], ['-', '_', ':'], TRUE))) $cursor--;
          $attribute = strtolower(substr($source, $cursor + 1, $end - $cursor));
        }
        else $attribute = '';
        $quote = $character;
        continue;
      }
      if ($character === '>') {
        if ($closing_tag && $tag_name === $raw_element) $raw_element = '';
        elseif (!$closing_tag && in_array($tag_name, ['script', 'style'], TRUE)) $raw_element = $tag_name;
        $in_tag = FALSE;
        $tag_name = '';
        $closing_tag = FALSE;
        $attribute = '';
      }
    }
    return $contexts;
  };

  foreach ($input['sources'] as $index => $source) {
    $check_deadline();
    if (!is_array($source) || array_keys($source) !== ['id', 'path', 'kind', 'sha256', 'bytes', 'surfaceIds']) throw new RuntimeException('source_record_invalid');
    $file_id = (string) $source['id'];
    $path = (string) $source['path'];
    $kind = (string) $source['kind'];
    $source_surface_ids = $source['surfaceIds'];
    if (!str_starts_with($file_id, 'SOURCE-') || strlen($file_id) !== 23 || substr($file_id, 7) !== strtolower(substr($file_id, 7)) || !ctype_xdigit(substr($file_id, 7)) || !$valid_relative_path($path) || !in_array($kind, ['procedural_php', 'php_class', 'twig_template'], TRUE) || !is_int($source['bytes']) || $source['bytes'] < 0 || $source['bytes'] > $limits['sourceBytesPerFile'] || !is_array($source_surface_ids)) throw new RuntimeException('source_record_invalid');
    if (($kind === 'twig_template' && !str_ends_with(strtolower($path), '.twig')) || ($kind === 'php_class' && !str_ends_with(strtolower($path), '.php')) || ($kind === 'procedural_php' && preg_match('/\.(?:module|theme|install|inc|test|profile)$/i', $path) !== 1)) throw new RuntimeException('source_kind_invalid');
    $candidate = realpath($project_root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $path));
    if (!is_string($candidate) || !is_file($candidate) || !str_starts_with(str_replace("\\", '/', $candidate), $project_prefix)) {
      $record_blocker('source_unavailable', $file_id, $kind === 'twig_template' ? 'twig' : 'php', $synthetic_evidence($kind === 'twig_template' ? 'Twig\\Error\\LoaderError' : 'PhpParser\\Error'), TRUE);
      continue;
    }
    $bytes = filesize($candidate);
    if (!is_int($bytes) || $bytes !== $source['bytes'] || $bytes > $limits['sourceBytesPerFile'] || $source_bytes + $bytes > $limits['sourceBytesTotal']) {
      $record_blocker('source_bytes_invalid', $file_id, $kind === 'twig_template' ? 'twig' : 'php', $synthetic_evidence($kind === 'twig_template' ? 'Twig\\Error\\SyntaxError' : 'PhpParser\\Error'), TRUE);
      continue;
    }
    $text = file_get_contents($candidate);
    if (!is_string($text) || strlen($text) !== $bytes || !mb_check_encoding($text, 'UTF-8')) {
      $record_blocker('source_encoding_invalid', $file_id, $kind === 'twig_template' ? 'twig' : 'php', $synthetic_evidence($kind === 'twig_template' ? 'Twig\\Error\\SyntaxError' : 'PhpParser\\Error'), TRUE);
      continue;
    }
    if (!hash_equals((string) $source['sha256'], 'sha256:' . hash('sha256', $text))) {
      $record_blocker('source_hash_mismatch', $file_id, $kind === 'twig_template' ? 'twig' : 'php', $synthetic_evidence($kind === 'twig_template' ? 'Twig\\Error\\SyntaxError' : 'PhpParser\\Error'), TRUE);
      continue;
    }
    $source_bytes += $bytes;
    $file_nodes = 0;

    try {
      if ($kind !== 'twig_template') {
        $ast = $php_parser->parse($text);
        if (!is_array($ast)) throw new RuntimeException('php_parse_incomplete');
        $walk_php = NULL;
        $walk_php = static function (mixed $node, int $depth, array $contexts) use (&$walk_php, &$file_nodes, &$ast_nodes, &$max_depth, $limits, $check_deadline, $php_source, $php_entity_lookup, $php_entity_output, $contexts_for_php_child, $suspicious_name, $record_blocker, $record_finding, $record_entity_output, $evidence, $synthetic_evidence, $file_id, $source_surface_ids): void {
          if (!$node instanceof \PhpParser\Node) {
            if (is_object($node)) $record_blocker('unsupported_ast_child', $file_id, 'php', $synthetic_evidence('PhpParser\\Node\\Unknown'), TRUE);
            return;
          }
          $check_deadline();
          $file_nodes++;
          $ast_nodes++;
          $max_depth = max($max_depth, $depth);
          if ($file_nodes > $limits['astNodesPerFile'] || $ast_nodes > $limits['astNodesTotal']) throw new RuntimeException('ast_node_limit');
          if ($depth > $limits['astDepth']) throw new RuntimeException('ast_depth_limit');
          if ($node instanceof \PhpParser\Node\Expr\Error) $record_blocker('unsupported_ast_node', $file_id, 'php', $evidence($node, NULL, 'php'), TRUE);
          if ($node instanceof \PhpParser\Node\Expr\Eval_) $record_blocker('unsupported_dynamic_call', $file_id, 'php', $evidence($node, NULL, 'php'));
          [$entity_kinds, $entity_sink_kind] = $php_entity_output($node);
          if ($entity_sink_kind !== '') $record_entity_output($file_id, 'php', $entity_kinds, $entity_sink_kind, $source_surface_ids, $node);
          [$lookup_kind, $lookup_ambiguity] = $php_entity_lookup($node);
          if ($lookup_ambiguity !== '') $record_blocker($lookup_ambiguity, $file_id, 'php', $evidence($node, $node, 'php'));
          elseif ($lookup_kind !== '') $record_finding($file_id, 'php', $lookup_kind, 'entity_selector', $node, $node);
          [$identity_kind, $ambiguity] = $php_source($node);
          $sink_contexts = array_values(array_filter($contexts, static fn (array $context): bool => $context['type'] === 'sink'));
          $display_context = count(array_filter($contexts, static fn (array $context): bool => $context['type'] === 'display')) > 0;
          if ($ambiguity !== '' && count($sink_contexts) > 0) $record_blocker($ambiguity, $file_id, 'php', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'php'));
          elseif ($ambiguity !== '' && !$display_context) $record_blocker($ambiguity, $file_id, 'php', $evidence($node, NULL, 'php'));
          if ($identity_kind !== '') {
            if (count($sink_contexts) > 0) foreach ($sink_contexts as $context) $record_finding($file_id, 'php', $identity_kind, $context['sinkKind'], $node, $context['sink']);
            elseif (!$display_context) $record_blocker('indirect_identity_flow', $file_id, 'php', $evidence($node, NULL, 'php'));
          }
          if ($node instanceof \PhpParser\Node\Expr\Variable && count($sink_contexts) > 0) {
            $computed_context = count(array_filter($sink_contexts, static fn (array $context): bool => $context['sinkKind'] === 'computed_lookup')) > 0;
            if (!is_string($node->name)) $record_blocker('unsupported_dynamic_identity', $file_id, 'php', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'php'));
            elseif ($computed_context) $record_blocker('unsupported_dynamic_identity', $file_id, 'php', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'php'));
            elseif ($suspicious_name($node->name)) $record_blocker('indirect_identity_operand', $file_id, 'php', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'php'));
          }
          if (($node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall || $node instanceof \PhpParser\Node\Expr\FuncCall) && count($sink_contexts) > 0 && !($node->name instanceof \PhpParser\Node\Identifier) && !($node->name instanceof \PhpParser\Node\Name)) {
            $record_blocker('unsupported_dynamic_call', $file_id, 'php', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'php'));
          }
          foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            $child_contexts = $contexts_for_php_child($node, $name, $child, $contexts);
            if (is_array($child)) foreach ($child as $item) $walk_php($item, $depth + 1, $child_contexts);
            else $walk_php($child, $depth + 1, $child_contexts);
          }
        };
        foreach ($ast as $node) $walk_php($node, 1, []);
      }
      else {
        $module = $twig->parse($twig->tokenize(new \Twig\Source($text, 'verifier-source')));
        if (!$module instanceof \Twig\Node\ModuleNode) throw new RuntimeException('twig_parse_incomplete');
        $twig_print_contexts = $twig_output_contexts($text);
        $template_name = strtolower(basename($path));
        $template_entity_kind = str_starts_with($template_name, 'node') ? 'node' : (str_starts_with($template_name, 'media') ? 'media' : (str_starts_with($template_name, 'file') ? 'file' : ''));
        $walk_twig = NULL;
        $walk_twig = static function (mixed $node, int $depth, array $contexts, string $mode = '') use (&$walk_twig, &$file_nodes, &$ast_nodes, &$max_depth, $limits, $check_deadline, $twig_source, $twig_entity_output, $twig_call_name, $twig_print_contexts, $suspicious_name, $record_blocker, $record_finding, $record_entity_output, $evidence, $synthetic_evidence, $file_id, $source_surface_ids, $template_entity_kind): void {
          if (!$node instanceof \Twig\Node\Node) {
            if (is_object($node)) $record_blocker('unsupported_ast_child', $file_id, 'twig', $synthetic_evidence('Twig\\Node\\Unknown'), TRUE);
            return;
          }
          $check_deadline();
          $file_nodes++;
          $ast_nodes++;
          $max_depth = max($max_depth, $depth);
          if ($file_nodes > $limits['astNodesPerFile'] || $ast_nodes > $limits['astNodesTotal']) throw new RuntimeException('ast_node_limit');
          if ($depth > $limits['astDepth']) throw new RuntimeException('ast_depth_limit');
          [$entity_kinds, $entity_source] = $twig_entity_output($node, $template_entity_kind);
          if ($entity_source instanceof \Twig\Node\Node) $record_entity_output($file_id, 'twig', $entity_kinds, 'twig_print', $source_surface_ids, $entity_source, $node);
          [$identity_kind, $ambiguity] = $twig_source($node);
          $sink_contexts = array_values(array_filter($contexts, static fn (array $context): bool => $context['type'] === 'sink'));
          $deferred_output_context = count(array_filter($contexts, static fn (array $context): bool => $context['type'] === 'deferred_output')) > 0;
          $display_context = !$deferred_output_context && count(array_filter($contexts, static fn (array $context): bool => $context['type'] === 'display')) > 0;
          if ($ambiguity !== '' && count($sink_contexts) > 0) $record_blocker($ambiguity, $file_id, 'twig', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'twig'));
          elseif ($ambiguity !== '' && !$display_context) $record_blocker($ambiguity, $file_id, 'twig', $evidence($node, NULL, 'twig'));
          if ($identity_kind !== '') {
            if (count($sink_contexts) > 0) foreach ($sink_contexts as $context) $record_finding($file_id, 'twig', $identity_kind, $context['sinkKind'], $node, $context['sink']);
            elseif (!$display_context) $record_blocker('indirect_identity_flow', $file_id, 'twig', $evidence($node, NULL, 'twig'));
          }
          if ($node instanceof \Twig\Node\Expression\NameExpression && count($sink_contexts) > 0) {
            $computed_context = count(array_filter($sink_contexts, static fn (array $context): bool => $context['sinkKind'] === 'computed_lookup')) > 0;
            if ($computed_context) $record_blocker('unsupported_dynamic_identity', $file_id, 'twig', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'twig'));
            elseif ($suspicious_name((string) $node->getAttribute('name'))) $record_blocker('indirect_identity_operand', $file_id, 'twig', $evidence($node, $sink_contexts[count($sink_contexts) - 1]['sink'], 'twig'));
          }
          $class = get_class($node);
          $node_call_name = $twig_call_name($node);
          $call_arguments = $node->hasNode('arguments') ? $node->getNode('arguments') : NULL;
          $has_call_arguments = $call_arguments instanceof \Twig\Node\Node && count($call_arguments) > 0;
          $position = 0;
          foreach ($node as $name => $child) {
            $child_contexts = $contexts;
            $child_mode = '';
            if ($mode === 'if_tests' && $position % 2 === 0) $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'behavior_branch', 'sink' => $node];
            if (str_ends_with($class, '\\IfNode') && (string) $name === 'tests') $child_mode = 'if_tests';
            if ((str_ends_with($class, '\\ConditionalTernary') || str_ends_with($class, '\\ConditionalExpression')) && in_array((string) $name, ['test', 'expr1'], TRUE)) $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'behavior_branch', 'sink' => $node];
            if ($node instanceof \Twig\Node\Expression\GetAttrExpression && (string) $name === 'attribute' && !($child instanceof \Twig\Node\Expression\ConstantExpression)) $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'computed_lookup', 'sink' => $node];
            if ($node_call_name === 'attribute' && (string) $name === 'arguments') $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'computed_lookup', 'sink' => $node];
            elseif ($has_call_arguments && (string) $name === 'arguments') $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'presentation_selector', 'sink' => $node];
            if (in_array($node_call_name, ['addclass', 'setattribute', 'theme', 'component', 'template', 'variant', 'viewmode'], TRUE) &&
                ((str_ends_with($class, '\\FilterExpression') && (string) $name === 'node') || !in_array((string) $name, ['node', 'attribute', 'filter'], TRUE))) $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'presentation_selector', 'sink' => $node];
            if ((str_ends_with($class, '\\MacroNode') || str_ends_with($class, '\\CaptureNode'))) $child_contexts[] = ['type' => 'deferred_output', 'sinkKind' => '', 'sink' => $node];
            if (str_ends_with($class, '\\PrintNode') && (string) $name === 'expr' && !$deferred_output_context) {
              $print_context = $twig_print_contexts[(int) $node->getTemplateLine()] ?? 'presentation';
              $child_contexts[] = $print_context === 'display'
                ? ['type' => 'display', 'sinkKind' => '', 'sink' => $node]
                : ['type' => 'sink', 'sinkKind' => 'presentation_selector', 'sink' => $node];
            }
            if ((str_ends_with($class, '\\IncludeNode') || str_ends_with($class, '\\EmbedNode') || str_ends_with($class, '\\ExtendsNode') || str_ends_with($class, '\\ImportNode') || str_ends_with($class, '\\FromNode')) && (string) $name === 'expr') $child_contexts[] = ['type' => 'sink', 'sinkKind' => 'presentation_selector', 'sink' => $node];
            $walk_twig($child, $depth + 1, $child_contexts, $child_mode);
            $position++;
          }
        };
        $walk_twig($module, 1, []);
      }
      $completed_file_ids[] = $file_id;
    }
    catch (\PhpParser\Error $error) {
      $line = method_exists($error, 'getStartLine') ? (int) $error->getStartLine() : 0;
      $record_blocker('parse_error', $file_id, 'php', $synthetic_evidence('PhpParser\\Error', $line), TRUE);
    }
    catch (\Twig\Error\Error $error) {
      $record_blocker('parse_error', $file_id, 'twig', $synthetic_evidence('Twig\\Error\\SyntaxError', (int) $error->getTemplateLine()), TRUE);
    }
    catch (RuntimeException $error) {
      $code = $error->getMessage();
      if (!in_array($code, ['deadline_exceeded', 'ast_node_limit', 'ast_depth_limit', 'finding_limit', 'php_parse_incomplete', 'twig_parse_incomplete'], TRUE)) $code = 'unsupported_traversal';
      if ($code === 'deadline_exceeded') $deadline_exceeded = TRUE;
      $record_blocker($code, $file_id, $kind === 'twig_template' ? 'twig' : 'php', $synthetic_evidence($kind === 'twig_template' ? 'Twig\\Node\\Node' : 'PhpParser\\Node'), TRUE);
      if (in_array($code, ['deadline_exceeded', 'ast_node_limit', 'finding_limit'], TRUE)) break;
    }
  }
  sort($expected_file_ids, SORT_STRING);
  sort($completed_file_ids, SORT_STRING);
  if ($source_bytes !== (int) ($input['expectedTotalBytes'] ?? -1) && count($completed_file_ids) === count($expected_file_ids)) {
    $record_blocker('source_bytes_invalid', '', '', $synthetic_evidence('Verifier\\Input'), TRUE);
  }
  $check_deadline();
}
catch (Throwable $fatal) {
  $code = $fatal->getMessage();
  $allowed = ['input_limit', 'input_invalid', 'input_fingerprint_invalid', 'limits_invalid', 'file_limit', 'surface_limit', 'source_bytes_invalid', 'docroot_invalid', 'drupal_root_unavailable', 'docroot_mismatch', 'project_root_unavailable', 'php_parser_unavailable', 'twig_parser_unavailable', 'source_record_invalid', 'source_kind_invalid', 'duplicate_source_id', 'deadline_exceeded'];
  if (!in_array($code, $allowed, TRUE)) $code = 'parser_runtime_failed';
  if ($code === 'deadline_exceeded') $deadline_exceeded = TRUE;
  $incomplete = TRUE;
  if (is_array($limits) && isset($limits['findings']) && count($blockers) + count($findings) + count($entity_output_candidates) < $limits['findings']) {
    $blockers[] = ['code' => $code, 'fileId' => '', 'language' => '', 'ruleId' => 'mutable_identity.' . $code, 'evidence' => $synthetic_evidence('Verifier\\Runtime')];
  }
}

$duration_ms = (int) ceil((hrtime(TRUE) - $started_ns) / 1000000);
if (isset($limits['deadlineMs']) && $duration_ms > $limits['deadlineMs']) {
  $duration_ms = $limits['deadlineMs'];
  $deadline_exceeded = TRUE;
  $incomplete = TRUE;
  if (count($blockers) + count($findings) + count($entity_output_candidates) < ($limits['findings'] ?? 1)) $blockers[] = ['code' => 'deadline_exceeded', 'fileId' => '', 'language' => '', 'ruleId' => 'mutable_identity.deadline_exceeded', 'evidence' => $synthetic_evidence('Verifier\\Runtime')];
}
$limits += ['files' => 1, 'surfacesPerFile' => 1, 'surfacesTotal' => 1, 'sourceBytesPerFile' => 1, 'sourceBytesTotal' => 1, 'astNodesPerFile' => 1, 'astNodesTotal' => 1, 'astDepth' => 1, 'findings' => 1, 'deadlineMs' => 10, 'outputBytes' => 4096];
sort($expected_file_ids, SORT_STRING);
sort($completed_file_ids, SORT_STRING);
$applies = count($expected_file_ids) > 0;
$complete_coverage = $completed_file_ids === $expected_file_ids;
$completed = !$incomplete && $complete_coverage;
$status = !$applies && count($blockers) === 0 ? 'not_applicable' : (count($blockers) > 0 ? 'blocked' : (count($findings) > 0 ? 'fail' : 'pass'));
$result = [
  'schemaVersion' => $schema_result,
  'analyzer' => $analyzer,
  'inputFingerprint' => $input_fingerprint,
  'parser' => [
    'php' => ['name' => 'nikic/php-parser', 'version' => $php_version ?? '', 'ast' => TRUE],
    'twig' => ['name' => 'drupal/twig', 'version' => $twig_version ?? '', 'ast' => TRUE],
  ],
  'limits' => $limits,
  'applies' => $applies,
  'completed' => $completed,
  'status' => $status,
  'expectedFileIds' => $expected_file_ids,
  'completedFileIds' => $completed_file_ids,
  'sourceBytes' => $source_bytes,
  'astNodes' => $ast_nodes,
  'maxDepth' => $max_depth,
  'durationMs' => $duration_ms,
  'deadlineExceeded' => $deadline_exceeded,
  'findings' => $findings,
  'entityOutputCandidates' => $entity_output_candidates,
  'blockers' => $blockers,
];
$result['resultFingerprint'] = $digest($strict_json($result));
$encoded = $strict_json($result);
if (strlen($encoded) > $limits['outputBytes']) {
  $result['completed'] = FALSE;
  $result['status'] = 'blocked';
  $result['findings'] = [];
  $result['entityOutputCandidates'] = [];
  $result['blockers'] = [['code' => 'output_limit', 'fileId' => '', 'language' => '', 'ruleId' => 'mutable_identity.output_limit', 'evidence' => $synthetic_evidence('Verifier\\Runtime')]];
  unset($result['resultFingerprint']);
  $result['resultFingerprint'] = $digest($strict_json($result));
  $encoded = $strict_json($result);
}
print $encoded;
`;
