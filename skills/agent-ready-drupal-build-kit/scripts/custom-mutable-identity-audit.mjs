import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync
} from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  inspectMutableIdentityDrupal,
  mutableIdentityDrupalEntityOutputBindings,
  MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA
} from './mutable-identity-drupal.mjs';
import {
  MUTABLE_IDENTITY_WORKER_LIMITS,
  MUTABLE_IDENTITY_WORKER_REQUEST_SCHEMA,
  MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA
} from './mutable-identity-worker.mjs';
import { sha256 } from './state-fingerprint.mjs';

export const CUSTOM_MUTABLE_IDENTITY_AUDIT_SCHEMA = 'public-kit.custom-mutable-identity-audit.1';
export const CUSTOM_MUTABLE_IDENTITY_LIMITS = Object.freeze({
  workerTimeoutMs: 30_000,
  workerOutputBytes: 1024 * 1024,
  workerInputBytes: 140 * 1024 * 1024
});

const WORKER_PATH = fileURLToPath(new URL('./mutable-identity-worker.mjs', import.meta.url));
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const SOURCE_ID_RE = /^SOURCE-[a-f0-9]{16}$/;
const JS_SOURCE_KINDS = new Set(['javascript']);
const DRUPAL_SOURCE_KINDS = new Set(['procedural_php', 'php_class', 'twig_template']);
const IDENTITY_KINDS = new Set(['alias_or_path', 'title_or_label', 'media_name']);
const JS_SINK_KINDS = new Set(['branch', 'computed_lookup', 'presentation_selection', 'entity_selection']);

function testOnlySource(source) {
  const path = String(source?.path ?? '').replaceAll('\\', '/').toLowerCase();
  return /(?:^|\/)tests?(?:\/|$)/.test(path) ||
    (source?.kind === 'procedural_php' && /\.test$/.test(path));
}

function runtimeTypeScriptBoundary(sourceInventory) {
  const sourceFiles = Array.isArray(sourceInventory?.sourceFiles) ? sourceInventory.sourceFiles : [];
  const extensions = new Map((Array.isArray(sourceInventory?.extensions) ? sourceInventory.extensions : [])
    .map((extension) => [String(extension?.machineName ?? ''), String(extension?.path ?? '').replaceAll('\\', '/')]))
  const typescriptByPath = new Map(sourceFiles
    .filter((source) => source?.kind === 'typescript_source')
    .map((source) => [String(source.path ?? '').replaceAll('\\', '/'), source]));
  const javascriptByPath = new Map(sourceFiles
    .filter((source) => source?.kind === 'javascript')
    .map((source) => [String(source.path ?? '').replaceAll('\\', '/'), source]));
  const runtimeSources = new Map();
  const runtimeJavascriptSources = new Map();
  const surfaceIds = [];
  const unboundSurfaceIds = [];
  const javascriptSurfaceIds = [];
  const unboundJavascriptSurfaceIds = [];
  for (const registration of sourceFiles.filter((source) => source?.kind === 'drupal_registration')) {
    for (const surface of Array.isArray(registration?.surfaces) ? registration.surfaces : []) {
      if (!['runtime_typescript_asset', 'runtime_javascript_asset'].includes(surface?.kind)) continue;
      const surfaceId = String(surface.id ?? '');
      if (surface.kind === 'runtime_typescript_asset') surfaceIds.push(surfaceId);
      else javascriptSurfaceIds.push(surfaceId);
      const asset = String(surface.name ?? '').replaceAll('\\', '/');
      const root = extensions.get(String(registration.extension ?? '')) ?? '';
      const segments = asset.split('/');
      if (!root || !asset || asset.startsWith('/') || /^[a-z][a-z0-9+.-]*:/i.test(asset) ||
        segments.some((segment) => !segment || segment === '..')) {
        if (surface.kind === 'runtime_typescript_asset') unboundSurfaceIds.push(surfaceId);
        else unboundJavascriptSurfaceIds.push(surfaceId);
        continue;
      }
      const sourcePath = `${root.replace(/\/$/, '')}/${asset}`;
      const source = surface.kind === 'runtime_typescript_asset'
        ? typescriptByPath.get(sourcePath)
        : javascriptByPath.get(sourcePath);
      if (!source) {
        if (surface.kind === 'runtime_typescript_asset') unboundSurfaceIds.push(surfaceId);
        else unboundJavascriptSurfaceIds.push(surfaceId);
      } else if (surface.kind === 'runtime_typescript_asset') {
        runtimeSources.set(source.id, source);
      } else {
        runtimeJavascriptSources.set(source.id, source);
      }
    }
  }
  return {
    runtimeSources: [...runtimeSources.values()].sort((left, right) => comparePortable(left.id, right.id)),
    runtimeJavascriptSources: [...runtimeJavascriptSources.values()].sort((left, right) => comparePortable(left.id, right.id)),
    surfaceIds: [...new Set(surfaceIds)].sort(comparePortable),
    unboundSurfaceIds: [...new Set(unboundSurfaceIds)].sort(comparePortable),
    javascriptSurfaceIds: [...new Set(javascriptSurfaceIds)].sort(comparePortable),
    unboundJavascriptSurfaceIds: [...new Set(unboundJavascriptSurfaceIds)].sort(comparePortable)
  };
}

function comparePortable(left, right) {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function rawSha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort(comparePortable)) === JSON.stringify([...keys].sort(comparePortable));
}

function pathInside(root, candidate) {
  const relation = relative(root, candidate);
  return relation === '' || (!relation.startsWith(`..${sep}`) && relation !== '..' && !isAbsolute(relation));
}

function sourceBytes(projectRoot, source) {
  const sharedPath = String(source?.path ?? '');
  if (
    !SOURCE_ID_RE.test(String(source?.id ?? '')) || !HASH_RE.test(String(source?.sha256 ?? '')) ||
    !sharedPath || sharedPath.includes('\\') || sharedPath.includes('\0') || isAbsolute(sharedPath) ||
    sharedPath.split('/').some((segment) => !segment || segment === '..')
  ) {
    throw new Error('invalid_source_record');
  }
  const projectReal = realpathSync(projectRoot);
  const candidate = resolve(projectReal, ...sharedPath.split('/'));
  const target = lstatSync(candidate).isSymbolicLink() ? realpathSync(candidate) : candidate;
  const realTarget = realpathSync(target);
  if (!pathInside(projectReal, realTarget) || !statSync(realTarget).isFile()) throw new Error('source_path_escape');
  const bytes = readFileSync(realTarget);
  if (rawSha256(bytes) !== source.sha256) throw new Error('source_hash_mismatch');
  return bytes;
}

function jsWorkerRequest(projectRoot, sourceFiles, limits = MUTABLE_IDENTITY_WORKER_LIMITS) {
  const files = sourceFiles.map((source) => {
    const bytes = sourceBytes(projectRoot, source);
    return {
      fileId: source.id,
      language: /\.ts$/i.test(String(source.path ?? '')) ? 'typescript' : 'javascript',
      sourceSha256: source.sha256,
      sourceBase64: bytes.toString('base64')
    };
  });
  const request = {
    schemaVersion: MUTABLE_IDENTITY_WORKER_REQUEST_SCHEMA,
    limits: { ...limits },
    files
  };
  const input = JSON.stringify(request);
  if (Buffer.byteLength(input, 'utf8') > CUSTOM_MUTABLE_IDENTITY_LIMITS.workerInputBytes) {
    throw new Error('worker_input_limit');
  }
  return { input, request };
}

function blockedJavascriptResult(sourceFiles, code) {
  return {
    schemaVersion: MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA,
    parser: {
      name: 'acorn',
      version: '8.15.0',
      sourceSha256: 'sha256:b4c8c70200e72bae33cf1085e0ecb1e792c1b6924ed50cab817caf14f51bb249'
    },
    bounded: true,
    limits: { ...MUTABLE_IDENTITY_WORKER_LIMITS },
    completed: false,
    status: 'blocked',
    files: sourceFiles.map((source) => ({
      fileId: source.id,
      sourceSha256: source.sha256,
      sourceBytes: 0,
      parserSourceType: '',
      completed: false,
      status: 'blocked',
      nodeCount: 0,
      maxDepth: 0,
      findingCount: 0
    })),
    findings: [],
    blockers: [{ code, fileId: '' }]
  };
}

function validNodeSpan(node) {
  return exactKeys(node, ['type', 'start', 'end', 'startLine', 'startColumn', 'endLine', 'endColumn']) &&
    typeof node.type === 'string' && node.type.length > 0 && node.type.length <= 128 &&
    ['start', 'end', 'startLine', 'startColumn', 'endLine', 'endColumn']
      .every((key) => Number.isSafeInteger(node[key]) && node[key] >= 0) &&
    node.end >= node.start && node.endLine >= node.startLine;
}

function parseJavascriptResult(raw, expectedSources) {
  if (Buffer.byteLength(String(raw ?? ''), 'utf8') > CUSTOM_MUTABLE_IDENTITY_LIMITS.workerOutputBytes) {
    throw new Error('worker_output_limit');
  }
  let result;
  try {
    result = JSON.parse(String(raw ?? ''));
  } catch {
    throw new Error('worker_invalid_json');
  }
  if (!exactKeys(result, [
    'schemaVersion', 'parser', 'bounded', 'limits', 'completed', 'status', 'files', 'findings', 'blockers'
  ]) || result.schemaVersion !== MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA || result.bounded !== true ||
    JSON.stringify(result.limits) !== JSON.stringify(MUTABLE_IDENTITY_WORKER_LIMITS) ||
    !exactKeys(result.parser, ['name', 'version', 'sourceSha256']) || result.parser.name !== 'acorn' ||
    result.parser.version !== '8.15.0' ||
    result.parser.sourceSha256 !== 'sha256:b4c8c70200e72bae33cf1085e0ecb1e792c1b6924ed50cab817caf14f51bb249' ||
    !['pass', 'fail', 'blocked'].includes(result.status) || typeof result.completed !== 'boolean' ||
    !Array.isArray(result.files) || !Array.isArray(result.findings) || !Array.isArray(result.blockers)
  ) {
    throw new Error('worker_invalid_schema');
  }
  if (result.findings.length > MUTABLE_IDENTITY_WORKER_LIMITS.findings ||
    result.blockers.length > MUTABLE_IDENTITY_WORKER_LIMITS.findings) {
    throw new Error('worker_result_limit');
  }
  const expectedById = new Map(expectedSources.map((source) => [source.id, source]));
  if (result.files.length !== expectedById.size || new Set(result.files.map((file) => file.fileId)).size !== result.files.length) {
    throw new Error('worker_file_coverage');
  }
  let sourceBytesTotal = 0;
  for (const file of result.files) {
    const expected = expectedById.get(file?.fileId);
    if (!exactKeys(file, [
      'fileId', 'sourceSha256', 'sourceBytes', 'parserSourceType', 'completed', 'status',
      'nodeCount', 'maxDepth', 'findingCount'
    ]) || !expected || file.sourceSha256 !== expected.sha256 || typeof file.completed !== 'boolean' ||
      !['pass', 'fail', 'blocked'].includes(file.status) ||
      !['sourceBytes', 'nodeCount', 'maxDepth', 'findingCount'].every((key) =>
        Number.isSafeInteger(file[key]) && file[key] >= 0
      ) || file.sourceBytes > MUTABLE_IDENTITY_WORKER_LIMITS.sourceBytesPerFile ||
      file.nodeCount > MUTABLE_IDENTITY_WORKER_LIMITS.nodesPerFile ||
      file.maxDepth > MUTABLE_IDENTITY_WORKER_LIMITS.depth ||
      file.findingCount > MUTABLE_IDENTITY_WORKER_LIMITS.findings ||
      !['', 'module', 'script'].includes(file.parserSourceType) ||
      (file.completed && !['module', 'script'].includes(file.parserSourceType))) {
      throw new Error('worker_file_record');
    }
    sourceBytesTotal += file.sourceBytes;
  }
  if (sourceBytesTotal > MUTABLE_IDENTITY_WORKER_LIMITS.sourceBytesTotal) throw new Error('worker_source_bytes_total');
  for (const finding of result.findings) {
    if (!exactKeys(finding, ['id', 'fileId', 'identityKind', 'sinkKind', 'ruleId', 'node', 'evidenceSha256']) ||
      !/^AST-[a-f0-9]{16}$/.test(finding.id) || !expectedById.has(finding.fileId) ||
      !IDENTITY_KINDS.has(finding.identityKind) || !JS_SINK_KINDS.has(finding.sinkKind) ||
      finding.ruleId !== `mutable_identity.${finding.identityKind}.${finding.sinkKind}` ||
      !validNodeSpan(finding.node) || !HASH_RE.test(finding.evidenceSha256)) {
      throw new Error('worker_finding_record');
    }
  }
  for (const blocker of result.blockers) {
    if (!plainObject(blocker) || typeof blocker.code !== 'string' || !/^[a-z0-9_]+$/.test(blocker.code) ||
      !['', ...expectedById.keys()].includes(String(blocker.fileId ?? '')) ||
      Object.keys(blocker).some((key) => !['code', 'fileId', 'node'].includes(key)) ||
      (blocker.node !== undefined && !validNodeSpan(blocker.node))) {
      throw new Error('worker_blocker_record');
    }
  }
  for (const file of result.files) {
    const findingCount = result.findings.filter((finding) => finding.fileId === file.fileId).length;
    const blocked = result.blockers.some((blocker) => blocker.fileId === file.fileId || blocker.code === 'finding_limit');
    const expectedFileStatus = blocked ? 'blocked' : findingCount > 0 ? 'fail' : 'pass';
    if (file.findingCount !== findingCount || file.completed !== !blocked || file.status !== expectedFileStatus) {
      throw new Error('worker_file_state_mismatch');
    }
  }
  const expectedStatus = result.blockers.length > 0 ? 'blocked' : result.findings.length > 0 ? 'fail' : 'pass';
  const completeCoverage = result.files.every((file) => file.completed === true);
  if (result.status !== expectedStatus || result.completed !== (result.blockers.length === 0 && completeCoverage)) {
    throw new Error('worker_status_mismatch');
  }
  return result;
}

function inspectJavascript(projectRoot, sourceFiles, options = {}) {
  let envelope;
  try {
    envelope = jsWorkerRequest(projectRoot, sourceFiles);
  } catch (error) {
    return blockedJavascriptResult(sourceFiles, error?.message || 'worker_input_invalid');
  }
  const runner = typeof options.javascriptRunner === 'function'
    ? options.javascriptRunner
    : ({ input }) => spawnSync(process.execPath, [WORKER_PATH], {
      encoding: 'utf8',
      input,
      maxBuffer: CUSTOM_MUTABLE_IDENTITY_LIMITS.workerOutputBytes,
      timeout: CUSTOM_MUTABLE_IDENTITY_LIMITS.workerTimeoutMs,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  let execution;
  try {
    execution = runner({
      input: envelope.input,
      timeoutMs: CUSTOM_MUTABLE_IDENTITY_LIMITS.workerTimeoutMs,
      outputBytes: CUSTOM_MUTABLE_IDENTITY_LIMITS.workerOutputBytes
    });
  } catch {
    return blockedJavascriptResult(sourceFiles, 'worker_spawn_failed');
  }
  if (execution && typeof execution.then === 'function') {
    return blockedJavascriptResult(sourceFiles, 'worker_async_unsupported');
  }
  if (execution?.error?.code === 'ETIMEDOUT' || execution?.timedOut === true) {
    return blockedJavascriptResult(sourceFiles, 'worker_timeout');
  }
  if (execution?.error?.code === 'ENOBUFS' || execution?.outputExceeded === true) {
    return blockedJavascriptResult(sourceFiles, 'worker_output_limit');
  }
  const status = Number(execution?.status ?? execution?.exitCode ?? 0);
  const stdout = execution?.stdout ?? execution?.output ?? '';
  if (![0, 2].includes(status)) return blockedJavascriptResult(sourceFiles, 'worker_process_failed');
  try {
    return parseJavascriptResult(stdout, sourceFiles);
  } catch {
    return blockedJavascriptResult(sourceFiles, 'worker_invalid_output');
  }
}

function ddevContainer(projectRoot, environment) {
  if (!/^(?:1|true|yes)$/i.test(String(environment?.IS_DDEV_PROJECT ?? ''))) return false;
  const appRoot = String(environment?.DDEV_APPROOT ?? '');
  if (!appRoot || !isAbsolute(appRoot)) return false;
  try {
    return realpathSync(appRoot) === realpathSync(projectRoot);
  } catch {
    return false;
  }
}

function drupalRunner(projectRoot, environment) {
  return ({ args, stdin, timeoutMs, maxOutputBytes }) => {
    const inContainer = ddevContainer(projectRoot, environment);
    const commands = inContainer
      ? [['drush', args], [resolve(projectRoot, 'vendor/bin/drush'), args]]
      : [['ddev', ['drush', ...args]]];
    let latest = null;
    for (const [command, commandArgs] of commands) {
      const result = spawnSync(command, commandArgs, {
        cwd: projectRoot,
        encoding: 'utf8',
        input: stdin,
        maxBuffer: maxOutputBytes,
        timeout: timeoutMs,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      latest = result;
      if (!result.error && result.status === 0) {
        return { exitCode: 0, stdout: result.stdout, timedOut: false };
      }
    }
    return {
      exitCode: Number.isInteger(latest?.status) ? latest.status : 1,
      stdout: latest?.stdout ?? '',
      timedOut: latest?.error?.code === 'ETIMEDOUT'
    };
  };
}

export function customMutableIdentityResultFingerprint(result) {
  const unsigned = { ...result };
  delete unsigned.resultFingerprint;
  return sha256(unsigned);
}

function finalizedResult(result) {
  return { ...result, resultFingerprint: customMutableIdentityResultFingerprint(result) };
}

export function inspectCustomMutableIdentity(projectRoot, sourceInventory, environment = process.env, options = {}) {
  const inventoryFingerprint = String(sourceInventory?.fingerprint ?? '');
  const sourceFiles = Array.isArray(sourceInventory?.sourceFiles) ? sourceInventory.sourceFiles : [];
  const typescriptBoundary = runtimeTypeScriptBoundary(sourceInventory);
  const auditable = [...new Map([
    ...sourceFiles.filter((source) => JS_SOURCE_KINDS.has(source?.kind) || DRUPAL_SOURCE_KINDS.has(source?.kind)),
    ...typescriptBoundary.runtimeSources
  ].map((source) => [source.id, source])).values()];
  const runtimeAssetFileIds = new Set([
    ...typescriptBoundary.runtimeSources,
    ...typescriptBoundary.runtimeJavascriptSources
  ].map((source) => source.id));
  const excludedFromRuntime = (source) => testOnlySource(source) && !runtimeAssetFileIds.has(source.id);
  const excludedTestFileIds = auditable.filter(excludedFromRuntime).map((source) => source.id).sort(comparePortable);
  const relevant = auditable.filter((source) => !excludedFromRuntime(source));
  if (sourceInventory?.completed !== true || !HASH_RE.test(inventoryFingerprint)) {
    return finalizedResult({
      schemaVersion: CUSTOM_MUTABLE_IDENTITY_AUDIT_SCHEMA,
      inputInventoryFingerprint: inventoryFingerprint,
      applies: relevant.length > 0 || typescriptBoundary.unboundSurfaceIds.length > 0 ||
        typescriptBoundary.unboundJavascriptSurfaceIds.length > 0,
      completed: false,
      status: 'blocked',
      excludedTestFileIds,
      runtimeTypeScriptSurfaceIds: typescriptBoundary.surfaceIds,
      unboundRuntimeTypeScriptSurfaceIds: typescriptBoundary.unboundSurfaceIds,
      runtimeJavascriptSurfaceIds: typescriptBoundary.javascriptSurfaceIds,
      unboundRuntimeJavascriptSurfaceIds: typescriptBoundary.unboundJavascriptSurfaceIds,
      expectedFileIds: relevant.map((source) => source.id).sort(comparePortable),
      completedFileIds: [],
      findingCount: 0,
      blockerCount: 1,
      entityOutputCandidates: [],
      javascript: blockedJavascriptResult([], 'inventory_incomplete'),
      drupal: null
    });
  }
  const javascriptSources = relevant.filter((source) =>
    JS_SOURCE_KINDS.has(source.kind) || source.kind === 'typescript_source'
  );
  const drupalSources = relevant.filter((source) => DRUPAL_SOURCE_KINDS.has(source.kind));
  const unboundRuntimeScript = typescriptBoundary.unboundSurfaceIds.length > 0 ||
    typescriptBoundary.unboundJavascriptSurfaceIds.length > 0;
  const javascript = unboundRuntimeScript
    ? blockedJavascriptResult(javascriptSources, 'runtime_script_asset_unbound')
    : inspectJavascript(projectRoot, javascriptSources, options);
  let drupal;
  try {
    drupal = inspectMutableIdentityDrupal(
      projectRoot,
      drupalSources,
      options.drupalRunner ?? drupalRunner(projectRoot, environment),
      options.drupal ?? {}
    );
  } catch {
    drupal = null;
  }
  const expectedFileIds = relevant.map((source) => source.id).sort(comparePortable);
  const completedFileIds = [
    ...javascript.files.filter((file) => file.completed).map((file) => file.fileId),
    ...(Array.isArray(drupal?.completedFileIds) ? drupal.completedFileIds : [])
  ].sort(comparePortable);
  const findingCount = javascript.findings.length + (Array.isArray(drupal?.findings) ? drupal.findings.length : 0);
  const blockerCount = javascript.blockers.length + (Array.isArray(drupal?.blockers) ? drupal.blockers.length : drupal ? 0 : 1);
  const completeCoverage = JSON.stringify(completedFileIds) === JSON.stringify(expectedFileIds);
  const completed = blockerCount === 0 && completeCoverage && javascript.completed === true &&
    drupal?.completed === true;
  const status = unboundRuntimeScript
    ? 'blocked'
    : relevant.length === 0
    ? 'not_applicable'
    : blockerCount > 0 ? 'blocked' : findingCount > 0 ? 'fail' : 'pass';
  return finalizedResult({
    schemaVersion: CUSTOM_MUTABLE_IDENTITY_AUDIT_SCHEMA,
    inputInventoryFingerprint: inventoryFingerprint,
    applies: relevant.length > 0 || unboundRuntimeScript,
    completed,
    status,
    excludedTestFileIds,
    runtimeTypeScriptSurfaceIds: typescriptBoundary.surfaceIds,
    unboundRuntimeTypeScriptSurfaceIds: typescriptBoundary.unboundSurfaceIds,
    runtimeJavascriptSurfaceIds: typescriptBoundary.javascriptSurfaceIds,
    unboundRuntimeJavascriptSurfaceIds: typescriptBoundary.unboundJavascriptSurfaceIds,
    expectedFileIds,
    completedFileIds,
    findingCount,
    blockerCount,
    entityOutputCandidates: mutableIdentityDrupalEntityOutputBindings(drupal),
    javascript,
    drupal
  });
}

export function customMutableIdentityAuditErrors(sourceInventory, audit = sourceInventory?.mutableIdentityAudit) {
  const errors = [];
  const sourceFiles = Array.isArray(sourceInventory?.sourceFiles) ? sourceInventory.sourceFiles : [];
  const typescriptBoundary = runtimeTypeScriptBoundary(sourceInventory);
  const auditable = [...new Map([
    ...sourceFiles.filter((source) => JS_SOURCE_KINDS.has(source?.kind) || DRUPAL_SOURCE_KINDS.has(source?.kind)),
    ...typescriptBoundary.runtimeSources
  ].map((source) => [source.id, source])).values()];
  const runtimeAssetFileIds = new Set([
    ...typescriptBoundary.runtimeSources,
    ...typescriptBoundary.runtimeJavascriptSources
  ].map((source) => source.id));
  const excludedFromRuntime = (source) => testOnlySource(source) && !runtimeAssetFileIds.has(source.id);
  const excludedTestFileIds = auditable.filter(excludedFromRuntime).map((source) => source.id).sort(comparePortable);
  const relevantIds = auditable
    .filter((source) => !excludedFromRuntime(source))
    .map((source) => source.id)
    .sort(comparePortable);
  if (!audit || audit.schemaVersion !== CUSTOM_MUTABLE_IDENTITY_AUDIT_SCHEMA) {
    return [`Verifier-owned mutable-identity audit must use schemaVersion ${CUSTOM_MUTABLE_IDENTITY_AUDIT_SCHEMA}.`];
  }
  if (audit.resultFingerprint !== customMutableIdentityResultFingerprint(audit)) {
    errors.push('Verifier-owned mutable-identity audit result fingerprint is invalid.');
  }
  if (audit.inputInventoryFingerprint !== sourceInventory?.filesystemFingerprint) {
    errors.push('Verifier-owned mutable-identity audit is not bound to the current filesystem inventory fingerprint.');
  }
  if (JSON.stringify(audit.excludedTestFileIds) !== JSON.stringify(excludedTestFileIds)) {
    errors.push('Verifier-owned mutable-identity audit did not bind the exact test-only source exclusion boundary.');
  }
  if (JSON.stringify(audit.runtimeTypeScriptSurfaceIds) !== JSON.stringify(typescriptBoundary.surfaceIds)) {
    errors.push('Verifier-owned mutable-identity audit did not bind exact runtime TypeScript asset surfaces.');
  }
  if (JSON.stringify(audit.unboundRuntimeTypeScriptSurfaceIds) !== JSON.stringify(typescriptBoundary.unboundSurfaceIds)) {
    errors.push('Verifier-owned mutable-identity audit did not bind unresolvable runtime TypeScript asset surfaces.');
  }
  if (JSON.stringify(audit.runtimeJavascriptSurfaceIds) !== JSON.stringify(typescriptBoundary.javascriptSurfaceIds)) {
    errors.push('Verifier-owned mutable-identity audit did not bind exact runtime JavaScript asset surfaces.');
  }
  if (JSON.stringify(audit.unboundRuntimeJavascriptSurfaceIds) !== JSON.stringify(typescriptBoundary.unboundJavascriptSurfaceIds)) {
    errors.push('Verifier-owned mutable-identity audit did not bind unresolvable runtime JavaScript asset surfaces.');
  }
  if (JSON.stringify(audit.expectedFileIds) !== JSON.stringify(relevantIds) ||
    !Array.isArray(audit.completedFileIds) || audit.completedFileIds.some((id) => !relevantIds.includes(id))) {
    errors.push('Verifier-owned mutable-identity audit did not bind exact PHP, Twig, and JavaScript source identities.');
  }
  const expectedStatus = relevantIds.length === 0 && typescriptBoundary.unboundSurfaceIds.length === 0 &&
    typescriptBoundary.unboundJavascriptSurfaceIds.length === 0
    ? 'not_applicable'
    : 'pass';
  if (audit.applies !== (relevantIds.length > 0 || typescriptBoundary.unboundSurfaceIds.length > 0 ||
    typescriptBoundary.unboundJavascriptSurfaceIds.length > 0) ||
    audit.completed !== true || audit.status !== expectedStatus) {
    errors.push(`Verifier-owned mutable-identity audit must complete with status ${expectedStatus}.`);
  }
  if (audit.findingCount !== 0 || audit.blockerCount !== 0) {
    errors.push('Verifier-owned mutable-identity AST analysis found forbidden identity control or could not complete safely.');
  }
  if (audit.javascript?.schemaVersion !== MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA ||
    !['pass'].includes(audit.javascript?.status)) {
    if (relevantIds.some((id) => audit.javascript?.files?.some((file) => file.fileId === id))) {
      errors.push('Verifier-owned Acorn JavaScript identity analysis did not pass.');
    }
  }
  if (audit.drupal?.schemaVersion !== MUTABLE_IDENTITY_DRUPAL_RESULT_SCHEMA ||
    !['pass', 'not_applicable'].includes(audit.drupal?.status)) {
    errors.push('Verifier-owned PHP/Twig AST identity analysis did not pass or report exact N/A.');
  }
  return errors;
}
