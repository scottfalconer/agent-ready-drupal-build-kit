#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const QUALITY_SCHEMA = 'public-kit.build-benchmark-quality.1';
const OWNER_SCHEMA = 'public-kit.high-error-diagnosis-owner.1';
const SEED_SCHEMA = 'public-kit.high-error-diagnosis-seed.1';
const INPUT_MANIFEST_SCHEMA = 'public-kit.high-error-diagnosis-input-manifest.1';
const EVIDENCE_SCHEMA = 'public-kit.high-error-diagnosis-evidence.1';
const DIAGNOSIS_SCHEMA = 'public-kit.high-error-diagnosis.1';
const READ_EVENT_SCHEMA = 'public-kit.high-error-diagnostic-read.1';
const ROUTE_COUNT = 300;
const MAX_DIAGNOSIS_BYTES = 4 * 1024;
const MAX_JSON_BYTES = 128 * 1024 * 1024;
const MAX_VERIFIER_BUFFER = 160 * 1024 * 1024;
const OWNER_FILE = 'high-error-diagnosis-owner.json';
const SEED_FILE = 'high-error-diagnosis-seed.json';
const INPUT_MANIFEST_FILE = 'high-error-diagnosis-input-manifest.json';
const EVIDENCE_FILE = 'high-error-diagnosis-evidence.json';
const ARM_REPORT = '.benchmark-runtime/arm/live-verification.json';
const ARM_SUMMARY = '.benchmark-runtime/arm/live-verification.summary.json';
const ARM_STDOUT = '.benchmark-runtime/arm/verifier.stdout';
const ARM_STDERR = '.benchmark-runtime/arm/verifier.stderr';
const READ_EVENTS = '.benchmark-runtime/read-events.jsonl';
const DIAGNOSIS_FILE = 'diagnosis.json';
const PRISTINE_DIRECTORY = 'pristine-input';
const EVALUATOR_DIRECTORY = 'fixed-evaluator';
const OUTCOME_NAMES = Object.freeze([
  'seedContractPass',
  'highErrorMechanismPass',
  'gateFanoutMechanismPass',
  'fixedSummaryMechanismPass',
  'packetInputImmutablePass',
  'installedSkillImmutablePass',
  'workspaceMutationBoundedPass',
  'singleArmVerifierInvocationPass',
  'packetOnlyInvocationPass',
  'armReportProducedPass',
  'fixedEvaluatorReportProducedPass',
  'authoritativeValidFingerprintPass',
  'authoritativeVerdictFingerprintPass',
  'authoritativeErrorFingerprintPass',
  'authoritativeGateFingerprintPass',
  'armGateAccountingPass',
  'armDiagnosticContractPass',
  'terminalErrorAccountingPass',
  'diagnosisSchemaPass',
  'diagnosisCountsPass',
  'diagnosisEvidencePass',
  'diagnosisAuthorityPass',
  'documentedReadOrderPass',
  'diagnosticReadTelemetryPass',
  'stderrMetricsCapturedPass',
  'reportMetricsCapturedPass',
  'summaryMetricsCapturedPass',
  'armBlindnessPass',
  'codexEvidenceCompletePass'
]);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function atomicJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

function readJson(path, label = basename(path)) {
  const bytes = readFileSync(path);
  if (bytes.length > MAX_JSON_BYTES) throw new Error(`${label} exceeds ${MAX_JSON_BYTES} bytes.`);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function pathExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function within(path, parent) {
  const rel = relative(resolve(parent), resolve(path));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function regularFile(path, label) {
  if (!pathExists(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) {
    throw new Error(`${label} is missing, symbolic, or not a regular file.`);
  }
  return path;
}

function directory(path, label) {
  if (!pathExists(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isDirectory()) {
    throw new Error(`${label} is missing, symbolic, or not a directory.`);
  }
  return realpathSync(path);
}

function assertOwnedWorkspace(workspace, runDir) {
  const realRunDir = directory(runDir, 'run directory');
  const realWorkspace = directory(workspace, 'workspace');
  if (!within(realWorkspace, realRunDir) || basename(realWorkspace) !== 'workspace') {
    throw new Error('Workspace must be the runner-owned workspace inside its run directory.');
  }
  return { realRunDir, realWorkspace };
}

function parseArgs(argv) {
  const [command, ...remaining] = argv;
  const options = {};
  for (let index = 0; index < remaining.length; index += 1) {
    const option = remaining[index];
    if (!/^--[a-z][a-z-]*$/.test(option)) throw new Error(`Unexpected argument: ${option}`);
    const value = remaining[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${option} requires a value.`);
    options[option.slice(2)] = value;
    index += 1;
  }
  return { command, options };
}

function requireOptions(options, names) {
  for (const name of names) {
    if (!options[name]) throw new Error(`--${name} is required.`);
  }
}

function walkTree(root) {
  const realRoot = directory(root, 'tree root');
  const files = [];
  const visit = (directoryPath) => {
    for (const name of readdirSync(directoryPath).sort()) {
      const path = join(directoryPath, name);
      const stat = lstatSync(path);
      const relativePath = relative(realRoot, path).split(sep).join('/');
      if (stat.isSymbolicLink()) throw new Error(`Symbolic links are not allowed in benchmark inputs: ${relativePath}`);
      if (stat.isDirectory()) {
        visit(path);
        continue;
      }
      if (!stat.isFile()) throw new Error(`Unsupported benchmark input type: ${relativePath}`);
      const bytes = readFileSync(path);
      files.push({
        path: relativePath,
        bytes: bytes.length,
        sha256: sha256(bytes)
      });
    }
  };
  visit(realRoot);
  return {
    files,
    fingerprint: sha256(canonicalJson(files))
  };
}

function copyTree(source, destination) {
  walkTree(source);
  if (pathExists(destination)) {
    if (lstatSync(destination).isSymbolicLink() || !lstatSync(destination).isDirectory()) {
      throw new Error(`Copy destination is unsafe: ${destination}`);
    }
    if (readdirSync(destination).length > 0) throw new Error(`Copy destination must be empty: ${destination}`);
  } else {
    mkdirSync(destination, { recursive: true, mode: 0o700 });
  }
  cpSync(source, destination, {
    recursive: true,
    errorOnExist: true,
    force: false,
    preserveTimestamps: false
  });
  walkTree(destination);
}

function writeProjectScaffold(projectRoot) {
  mkdirSync(projectRoot, { recursive: true, mode: 0o700 });
  atomicJson(join(projectRoot, 'composer.json'), {
    name: 'benchmark/high-error-diagnosis',
    type: 'project',
    require: {
      'drupal/core-recommended': '11.2.0'
    },
    extra: {
      'drupal-scaffold': {
        locations: {
          'web-root': 'web/'
        }
      }
    }
  });
  writeFileSync(join(projectRoot, 'benchmark-brief.md'), [
    '# High-error packet diagnosis benchmark',
    '',
    'BR-DIAG-001: Preserve a complete accepted route inventory before any completion claim.',
    'This packet is intentionally invalid and exists only to measure diagnosis behavior.',
    ''
  ].join('\n'), { encoding: 'utf8', mode: 0o600 });
}

function deterministicPrimaryRoutes() {
  return Array.from({ length: ROUTE_COUNT }, (_, index) => {
    const suffix = String(index + 1).padStart(3, '0');
    return {
      sourcePath: `/catalog/source-item-${suffix}`,
      targetPath: `/content/target-item-${suffix}`,
      briefRequirementIds: ['BR-DIAG-001'],
      // Deliberately outside the emitted enum. This produces one real,
      // index-addressed structural error per primary route in every revision,
      // which is the repeated family exercised by terminal grouping.
      routeRole: 'benchmark_invalid_role',
      sourceIntent: `Benchmark source item ${suffix}`,
      targetIntent: '',
      matchesBrowserRenderedSource: false,
      accepted: false,
      notes: ''
    };
  });
}

function initializePacket(projectRoot, evaluatorKit, initEvidenceDirectory) {
  writeProjectScaffold(projectRoot);
  const initPath = regularFile(
    join(evaluatorKit, 'skills', 'agent-ready-drupal-build-kit', 'scripts', 'init-kit.mjs'),
    'fixed evaluator init-kit'
  );
  mkdirSync(initEvidenceDirectory, { recursive: true, mode: 0o700 });
  const result = spawnSync(process.execPath, [
    initPath,
    '--brief-file', 'benchmark-brief.md',
    '--project', projectRoot,
    '--packet', 'review-packet'
  ], {
    cwd: projectRoot,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 8 * 1024 * 1024
  });
  writeFileSync(join(initEvidenceDirectory, 'init.stdout'), result.stdout ?? '', { encoding: 'utf8', mode: 0o600 });
  writeFileSync(join(initEvidenceDirectory, 'init.stderr'), result.stderr ?? '', { encoding: 'utf8', mode: 0o600 });
  if (result.status !== 0) {
    throw new Error(`Fixed evaluator init-kit failed with exit ${String(result.status)}.`);
  }

  // init-kit legitimately points AGENTS.md at its own checkout. Replace that
  // generated guidance before any arm is installed so the measured agent sees
  // no evaluator path or revision.
  writeFileSync(
    join(projectRoot, 'AGENTS.md'),
    '# Diagnosis benchmark\n\nThe selected benchmark skill has not been installed yet.\n',
    { encoding: 'utf8', mode: 0o600 }
  );

  const matrixPath = regularFile(join(projectRoot, 'review-packet', 'route-matrix.json'), 'route matrix');
  const matrix = readJson(matrixPath, 'route matrix');
  matrix.site = 'High-error diagnosis benchmark';
  matrix.checkedAt = '2026-07-28T00:00:00.000Z';
  matrix.sourceBaseUrl = 'https://source.example.invalid/';
  matrix.targetBaseUrl = 'https://target.example.invalid/';
  matrix.primaryRoutes = deterministicPrimaryRoutes();
  atomicJson(matrixPath, matrix);
}

function seedProjection(projectRoot) {
  const packetRoot = directory(join(projectRoot, 'review-packet'), 'seed packet');
  const matrix = readJson(join(packetRoot, 'route-matrix.json'), 'seed route matrix');
  const primaryRoutes = Array.isArray(matrix.primaryRoutes) ? matrix.primaryRoutes : [];
  const routeRowsPass =
    primaryRoutes.length === ROUTE_COUNT &&
    primaryRoutes.every((row, index) => {
      const suffix = String(index + 1).padStart(3, '0');
      return row?.sourcePath === `/catalog/source-item-${suffix}` &&
        row?.targetPath === `/content/target-item-${suffix}` &&
        row?.routeRole === 'benchmark_invalid_role' &&
        row?.accepted === false &&
        row?.matchesBrowserRenderedSource === false &&
        row?.targetIntent === '';
    });
  const packet = walkTree(packetRoot);
  return {
    primaryRouteCount: primaryRoutes.length,
    routeRowsPass,
    packetFingerprint: packet.fingerprint,
    packetFiles: packet.files.length
  };
}

function ownerRecord(options, realWorkspace) {
  return {
    schemaVersion: OWNER_SCHEMA,
    experimentId: options['experiment-id'],
    runId: options['run-id'],
    workspace: realWorkspace
  };
}

function assertCodexVersion(expectedVersion) {
  if (!/^\d+\.\d+\.\d+$/.test(expectedVersion)) {
    throw new Error('--codex-version must be an exact semantic version.');
  }
  const result = spawnSync('codex', ['--version'], {
    encoding: 'utf8',
    timeout: 60_000
  });
  if (result.error || result.status !== 0) {
    throw new Error(`Unable to verify Codex CLI version: ${result.error?.message ?? result.stderr?.trim() ?? `exit ${result.status}`}`);
  }
  const actual = result.stdout.trim();
  if (actual !== `codex-cli ${expectedVersion}`) {
    throw new Error(`Codex CLI version mismatch: expected ${expectedVersion}, got ${actual || '<empty>'}.`);
  }
}

function prepare(options) {
  requireOptions(options, ['workspace', 'run-dir', 'evaluator-kit', 'codex-version', 'experiment-id', 'run-id']);
  const { realRunDir, realWorkspace } = assertOwnedWorkspace(options.workspace, options['run-dir']);
  const evaluatorKit = directory(options['evaluator-kit'], 'fixed evaluator kit');
  if (readdirSync(realWorkspace).length > 0) throw new Error('Prepare requires a fresh empty workspace.');
  assertCodexVersion(options['codex-version']);

  const pristineRoot = resolve(realRunDir, PRISTINE_DIRECTORY);
  if (!within(pristineRoot, realRunDir) || pathExists(pristineRoot)) {
    throw new Error('Pristine input destination must be new and run-owned.');
  }
  initializePacket(pristineRoot, evaluatorKit, join(realRunDir, 'prepare-init-evidence'));
  const seed = seedProjection(pristineRoot);
  if (!seed.routeRowsPass) throw new Error('Generated seed does not contain the exact 300 invalid primary-route rows.');
  copyTree(pristineRoot, realWorkspace);
  const copiedSeed = seedProjection(realWorkspace);
  if (canonicalJson(copiedSeed) !== canonicalJson(seed)) {
    throw new Error('Workspace seed differs from the pristine initialized input.');
  }

  atomicJson(join(realRunDir, OWNER_FILE), ownerRecord(options, realWorkspace));
  atomicJson(join(realRunDir, SEED_FILE), {
    schemaVersion: SEED_SCHEMA,
    codexCliVersion: options['codex-version'],
    routeCount: ROUTE_COUNT,
    ...seed
  });
  process.stdout.write(`Prepared deterministic ${ROUTE_COUNT}-primary-route diagnosis packet.\n`);
}

function benchmarkAgentsText() {
  return `# High-error diagnosis benchmark

This is a disposable, diagnosis-only benchmark. Work only in this directory.
Use \`.agents/skills/agent-ready-drupal-build-kit/SKILL.md\`.

- The review packet and all installed inputs are immutable.
- Run only the packet-only verifier command in the benchmark prompt.
- Do not inspect parent directories, Git metadata, credentials, host paths,
  benchmark scheduling, or external network resources.
- Write only verifier-owned runtime output and the requested \`diagnosis.json\`.
`;
}

function install(options) {
  requireOptions(options, ['workspace', 'run-dir', 'arm-kit', 'reader']);
  const { realRunDir, realWorkspace } = assertOwnedWorkspace(options.workspace, options['run-dir']);
  const armKit = directory(options['arm-kit'], 'arm kit');
  const reader = regularFile(options.reader, 'diagnostic reader');
  const owner = readJson(join(realRunDir, OWNER_FILE), 'owner record');
  if (owner.schemaVersion !== OWNER_SCHEMA || owner.workspace !== realWorkspace) {
    throw new Error('Run ownership does not match the install workspace.');
  }
  const seed = readJson(join(realRunDir, SEED_FILE), 'seed record');
  const before = seedProjection(realWorkspace);
  if (before.packetFingerprint !== seed.packetFingerprint || !before.routeRowsPass) {
    throw new Error('Packet changed before arm installation.');
  }

  const installedSkill = resolve(realWorkspace, '.agents', 'skills', 'agent-ready-drupal-build-kit');
  const armSkill = directory(
    join(armKit, 'skills', 'agent-ready-drupal-build-kit'),
    'arm skill'
  );
  mkdirSync(dirname(installedSkill), { recursive: true, mode: 0o700 });
  copyTree(armSkill, installedSkill);
  writeFileSync(join(realWorkspace, 'AGENTS.md'), benchmarkAgentsText(), { encoding: 'utf8', mode: 0o600 });
  const runtimeRoot = resolve(realWorkspace, '.benchmark-runtime');
  const armRuntime = resolve(runtimeRoot, 'arm');
  mkdirSync(armRuntime, { recursive: true, mode: 0o700 });
  cpSync(reader, join(runtimeRoot, 'read-diagnostic.mjs'), {
    errorOnExist: true,
    force: false,
    preserveTimestamps: false
  });
  chmodSync(join(runtimeRoot, 'read-diagnostic.mjs'), 0o700);

  const manifest = walkTree(realWorkspace);
  atomicJson(join(realRunDir, INPUT_MANIFEST_FILE), {
    schemaVersion: INPUT_MANIFEST_SCHEMA,
    fingerprint: manifest.fingerprint,
    files: manifest.files,
    packetFingerprint: seed.packetFingerprint,
    installedSkillFingerprint: walkTree(installedSkill).fingerprint
  });
  process.stdout.write('Installed one arm skill and sealed agent-visible inputs.\n');
}

function fileMetric(path) {
  if (!pathExists(path)) return { present: false, bytes: 0, lines: 0, sha256: null };
  regularFile(path, basename(path));
  const bytes = readFileSync(path);
  return {
    present: true,
    bytes: bytes.length,
    lines: bytes.length === 0 ? 0 : bytes.toString('utf8').split('\n').length - (bytes.at(-1) === 10 ? 1 : 0),
    sha256: sha256(bytes)
  };
}

function parseJsonl(path) {
  const events = [];
  for (const [index, line] of readFileSync(path, 'utf8').split('\n').entries()) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line));
    } catch (error) {
      throw new Error(`Codex JSONL line ${index + 1} is malformed: ${error.message}`);
    }
  }
  return events;
}

function commandRecords(events) {
  return events
    .filter((event) => event?.type === 'item.completed' && event?.item?.type === 'command_execution')
    .map((event, index) => {
      const raw = event.item.command ?? event.item.argv ?? '';
      const argv = Array.isArray(raw) ? raw.map(String) : null;
      const text = argv ? argv.join(' ') : String(raw);
      const output = event.item.aggregated_output ?? event.item.output ?? '';
      return {
        index,
        argv,
        text: text.replaceAll('\\', '/'),
        output: typeof output === 'string' ? output : canonicalJson(output),
        exitCode: event.item.exit_code,
        status: event.item.status
      };
    });
}

function parseReadEvents(path) {
  if (!pathExists(path)) return [];
  regularFile(path, 'diagnostic read telemetry');
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map((line, index) => {
    let event;
    try {
      event = JSON.parse(line);
    } catch (error) {
      throw new Error(`Diagnostic read event ${index + 1} is malformed: ${error.message}`);
    }
    if (
      event?.schemaVersion !== READ_EVENT_SCHEMA ||
      ![ARM_REPORT, ARM_SUMMARY].includes(event.path) ||
      !Number.isSafeInteger(event.bytes) ||
      event.bytes < 0 ||
      !/^sha256:[0-9a-f]{64}$/.test(event.sha256 ?? '')
    ) {
      throw new Error(`Diagnostic read event ${index + 1} violates its contract.`);
    }
    return event;
  });
}

function reportProjection(report) {
  const gateRows = Array.isArray(report?.gateResults)
    ? report.gateResults
    : Array.isArray(report?.packetVerification?.gateResults)
      ? report.packetVerification.gateResults
      : [];
  const errors = Array.isArray(report?.errors) ? report.errors.map(String).sort() : [];
  const gates = gateRows.map((row) => ({
    gateId: String(row?.gateId ?? ''),
    evaluator: String(row?.evaluator ?? ''),
    status: String(row?.status ?? ''),
    errorCount: Number.isSafeInteger(row?.errorCount)
      ? row.errorCount
      : Array.isArray(row?.errors)
        ? row.errors.length
        : -1
  })).sort((left, right) => left.gateId.localeCompare(right.gateId));
  return {
    valid: report?.valid === true,
    verdict: String(report?.verdict ?? ''),
    errors,
    gates,
    fingerprints: {
      valid: sha256(canonicalJson(report?.valid === true)),
      verdict: sha256(canonicalJson(String(report?.verdict ?? ''))),
      errors: sha256(canonicalJson(errors)),
      gates: sha256(canonicalJson(gates))
    }
  };
}

function gateAccountingPass(report) {
  const rows = Array.isArray(report?.gateResults)
    ? report.gateResults
    : Array.isArray(report?.packetVerification?.gateResults)
      ? report.packetVerification.gateResults
      : [];
  return rows.length > 0 && rows.every((row) => {
    if (!Array.isArray(row?.errors)) return false;
    if (!Number.isSafeInteger(row.errorCount)) return true;
    const omitted = Number.isSafeInteger(row.omittedErrorCount) ? row.omittedErrorCount : 0;
    return omitted >= 0 && row.errorCount === row.errors.length + omitted;
  });
}

function verifierRun({ kitRoot, projectRoot, outputRoot }) {
  mkdirSync(outputRoot, { recursive: true, mode: 0o700 });
  const verifier = regularFile(
    join(kitRoot, 'skills', 'agent-ready-drupal-build-kit', 'scripts', 'verify.mjs'),
    'fixed evaluator verifier'
  );
  const reportPath = join(outputRoot, 'live-verification.json');
  const result = spawnSync(process.execPath, [
    verifier,
    '--packet', join(projectRoot, 'review-packet'),
    '--packet-only',
    '--out', reportPath
  ], {
    cwd: projectRoot,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: MAX_VERIFIER_BUFFER
  });
  writeFileSync(join(outputRoot, 'verifier.stdout'), result.stdout ?? '', { encoding: 'utf8', mode: 0o600 });
  writeFileSync(join(outputRoot, 'verifier.stderr'), result.stderr ?? '', { encoding: 'utf8', mode: 0o600 });
  return {
    exitCode: result.status,
    signal: result.signal,
    error: result.error?.message ?? '',
    reportPath,
    summaryPath: reportPath.replace(/\.json$/i, '.summary.json'),
    stdoutPath: join(outputRoot, 'verifier.stdout'),
    stderrPath: join(outputRoot, 'verifier.stderr')
  };
}

function dominantEvidenceFile(errors, packetRoot) {
  const packetFiles = readdirSync(packetRoot)
    .filter((name) => pathExists(join(packetRoot, name)) && lstatSync(join(packetRoot, name)).isFile())
    .sort();
  const counts = packetFiles.map((name) => ({
    name,
    count: errors.filter((error) => String(error).includes(name)).length
  })).sort((left, right) => right.count - left.count || left.name.localeCompare(right.name));
  return {
    name: counts[0]?.name ?? '',
    count: counts[0]?.count ?? 0,
    counts
  };
}

function normalizedFamily(message) {
  return String(message ?? '')
    .replace(/\[\s*\d+\s*\]/g, '[]')
    .replace(/\bhttps?:\/\/[^\s,;)'"]+/gi, '<url>')
    .replace(/(?<=\s|^)\/[^\s,;:)'"]*/g, '<path>')
    .replace(/\s+/g, ' ')
    .trim();
}

function mechanismProjection(report) {
  const errors = Array.isArray(report?.errors) ? report.errors.map(String) : [];
  const families = new Map();
  for (const error of errors) {
    const key = normalizedFamily(error);
    families.set(key, (families.get(key) ?? 0) + 1);
  }
  const largestFamilyCount = Math.max(0, ...families.values());
  const gates = reportProjection(report).gates;
  const highVolumeGates = gates.filter(({ errorCount }) => errorCount > 20);
  return {
    errorCount: errors.length,
    familyCount: families.size,
    largestFamilyCount,
    highVolumeGateCount: highVolumeGates.length,
    maximumGateErrorCount: Math.max(0, ...gates.map(({ errorCount }) => errorCount))
  };
}

function summaryContract(summary, report, expectedReportPath) {
  if (!summary) return { recognized: true, present: false };
  const projection = reportProjection(report);
  const gateRows = Array.isArray(summary.gateResults) ? summary.gateResults : [];
  const summaryErrors = summary?.errors;
  const pass =
    summary.schemaVersion === 'public-kit.live-verification-summary.1' &&
    summary.authority === 'diagnostic_only' &&
    summary.fullReport === expectedReportPath &&
    summary.valid === projection.valid &&
    summary.verdict === projection.verdict &&
    Number.isSafeInteger(summaryErrors?.total) &&
    Number.isSafeInteger(summaryErrors?.shown) &&
    Number.isSafeInteger(summaryErrors?.omitted) &&
    summaryErrors.total === projection.errors.length &&
    summaryErrors.total === summaryErrors.shown + summaryErrors.omitted &&
    gateRows.length === projection.gates.length &&
    gateRows.every((row) => {
      const expected = projection.gates.find(({ gateId }) => gateId === row.gateId);
      return expected &&
        row.status === expected.status &&
        row.errorCount === expected.errorCount &&
        !Object.hasOwn(row, 'errors');
    });
  return {
    recognized: pass,
    present: true,
    omittedErrors: Number.isSafeInteger(summaryErrors?.omitted) ? summaryErrors.omitted : -1
  };
}

function compareInputManifest(workspace, manifest) {
  const current = walkTree(workspace);
  const expected = new Map(manifest.files.map((row) => [row.path, row]));
  const mutableExact = new Set([
    DIAGNOSIS_FILE,
    ARM_REPORT,
    ARM_SUMMARY,
    ARM_STDOUT,
    ARM_STDERR,
    READ_EVENTS
  ]);
  const mutablePrefixes = ['.agent-ready-drupal/'];
  const originalUnchanged = manifest.files.every((row) => {
    const currentRow = current.files.find(({ path }) => path === row.path);
    return currentRow &&
      currentRow.bytes === row.bytes &&
      currentRow.sha256 === row.sha256;
  });
  const additionsBounded = current.files.every((row) => (
    expected.has(row.path) ||
    mutableExact.has(row.path) ||
    mutablePrefixes.some((prefix) => row.path.startsWith(prefix))
  ));
  const packet = walkTree(join(workspace, 'review-packet'));
  const skill = walkTree(join(workspace, '.agents', 'skills', 'agent-ready-drupal-build-kit'));
  return {
    originalUnchanged,
    additionsBounded,
    packetUnchanged: packet.fingerprint === manifest.packetFingerprint,
    installedSkillUnchanged: skill.fingerprint === manifest.installedSkillFingerprint,
    currentFingerprint: current.fingerprint
  };
}

function exactDiagnosisShape(value) {
  const expectedKeys = [
    'authority',
    'dominantEvidenceFile',
    'errorCount',
    'failingGateCount',
    'firstDiagnosticArtifact',
    'recommendedAction',
    'schemaVersion',
    'valid',
    'verdict'
  ].sort();
  return value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort()) === canonicalJson(expectedKeys) &&
    value.schemaVersion === DIAGNOSIS_SCHEMA &&
    value.authority === 'diagnostic_only' &&
    typeof value.valid === 'boolean' &&
    typeof value.verdict === 'string' &&
    Number.isSafeInteger(value.errorCount) &&
    Number.isSafeInteger(value.failingGateCount) &&
    typeof value.dominantEvidenceFile === 'string' &&
    typeof value.firstDiagnosticArtifact === 'string' &&
    value.recommendedAction === 'repair-packet-and-reverify';
}

function emittedCommandText(record) {
  return record.text.toLowerCase();
}

function evaluateCommandEvidence(commands, codexEvents, armStderrMetric) {
  const verifierCommands = commands.filter((record) => (
    /\bnode\b/.test(record.text) &&
    /\.agents\/skills\/agent-ready-drupal-build-kit\/scripts\/verify\.mjs\b/.test(record.text) &&
    /--packet-only\b/.test(record.text)
  ));
  const verifier = verifierCommands[0];
  const invocationContractPass = Boolean(verifier) &&
    /--packet\s+review-packet\b/.test(verifier.text) &&
    /--out\s+\.benchmark-runtime\/arm\/live-verification\.json\b/.test(verifier.text) &&
    /\.benchmark-runtime\/arm\/verifier\.stdout/.test(verifier.text) &&
    /\.benchmark-runtime\/arm\/verifier\.stderr/.test(verifier.text) &&
    Number(verifier.exitCode) === 1;
  const stderrReads = commands.filter((record) => (
    emittedCommandText(record).includes(ARM_STDERR.toLowerCase()) &&
    !record.text.includes('verify.mjs')
  ));
  const surfacedStderrBytes = stderrReads.reduce(
    (total, { output }) => total + Buffer.byteLength(output),
    0
  );
  const completeStderrRead = surfacedStderrBytes >= armStderrMetric.bytes;
  const threadStartedCount = codexEvents.filter(({ type }) => type === 'thread.started').length;
  const turnCompletedCount = codexEvents.filter(({ type }) => type === 'turn.completed').length;
  const turnFailedCount = codexEvents.filter(({ type }) => type === 'turn.failed').length;
  const unsupportedCommandCount = commands.filter(({ text }) => !text.trim()).length;
  const forbidden = [
    /(?:^|\s)\.\.(?:\/|\s|$)/,
    /(?:^|\s)(?:git|gh|curl|wget|ssh|scp)(?:\s|$)/i,
    /(?:^|\s)(?:pwd|printenv|env)(?:\s|$)/i,
    /\/users\//i,
    /\/private\/tmp\//i,
    /(?:^|\/)\.git(?:\/|\s|$)/i,
    /(?:^|\/|~)\.codex(?:\/|\s|$)/i,
    /(?:auth\.json|ssh_auth_sock|credential|api[_-]?key|access[_-]?token)/i,
    /(?:https?:\/\/|fetch\s*\(|net\.connect\s*\()/i,
    /(?:run-owner|pristine-input|fixed-evaluator|experiment\.json|run\.json)/i
  ];
  const forbiddenCommands = commands.filter(({ text }) => forbidden.some((pattern) => pattern.test(text)));
  return {
    verifierInvocationCount: verifierCommands.length,
    invocationContractPass,
    completeStderrRead,
    threadStartedCount,
    turnCompletedCount,
    turnFailedCount,
    unsupportedCommandCount,
    surfacedStderrBytes,
    forbiddenCommands: forbiddenCommands.map(({ index, text }) => ({ index, text: text.slice(0, 300) }))
  };
}

function qualityFromOutcomes(outcomes) {
  const blockers = Object.entries(outcomes)
    .filter(([, value]) => value !== true)
    .map(([name]) => name)
    .sort();
  return {
    schemaVersion: QUALITY_SCHEMA,
    valid: blockers.length === 0,
    outcomes,
    blockers
  };
}

function emptyOutcomes() {
  return Object.fromEntries(OUTCOME_NAMES.map((name) => [name, false]));
}

function evaluate(options) {
  requireOptions(options, ['workspace', 'run-dir', 'evaluator-kit', 'codex-log']);
  const outcomes = emptyOutcomes();
  const blockers = [];
  let evidence = {
    schemaVersion: EVIDENCE_SCHEMA,
    completed: false
  };
  let realRunDir = resolve(options['run-dir']);
  try {
    const owned = assertOwnedWorkspace(options.workspace, options['run-dir']);
    realRunDir = owned.realRunDir;
    const realWorkspace = owned.realWorkspace;
    const evaluatorKit = directory(options['evaluator-kit'], 'fixed evaluator kit');
    const codexLog = regularFile(options['codex-log'], 'Codex JSONL');
    if (!within(codexLog, realRunDir)) throw new Error('Codex evidence must stay inside the run directory.');

    const owner = readJson(join(realRunDir, OWNER_FILE), 'owner record');
    if (owner.schemaVersion !== OWNER_SCHEMA || owner.workspace !== realWorkspace) {
      throw new Error('Run ownership does not match evaluation.');
    }
    const seed = readJson(join(realRunDir, SEED_FILE), 'seed record');
    const manifest = readJson(join(realRunDir, INPUT_MANIFEST_FILE), 'input manifest');
    if (manifest.schemaVersion !== INPUT_MANIFEST_SCHEMA) throw new Error('Input manifest schema is invalid.');
    const pristineRoot = directory(join(realRunDir, PRISTINE_DIRECTORY), 'pristine input');
    const pristineSeed = seedProjection(pristineRoot);
    outcomes.seedContractPass =
      seed.schemaVersion === SEED_SCHEMA &&
      seed.routeCount === ROUTE_COUNT &&
      seed.primaryRouteCount === ROUTE_COUNT &&
      seed.routeRowsPass === true &&
      pristineSeed.routeRowsPass &&
      pristineSeed.packetFingerprint === seed.packetFingerprint;

    const inputCheck = compareInputManifest(realWorkspace, manifest);
    outcomes.packetInputImmutablePass = inputCheck.packetUnchanged && inputCheck.originalUnchanged;
    outcomes.installedSkillImmutablePass = inputCheck.installedSkillUnchanged;
    outcomes.workspaceMutationBoundedPass = inputCheck.additionsBounded;

    const armPaths = {
      report: join(realWorkspace, ARM_REPORT),
      summary: join(realWorkspace, ARM_SUMMARY),
      stdout: join(realWorkspace, ARM_STDOUT),
      stderr: join(realWorkspace, ARM_STDERR)
    };
    const armMetrics = {
      report: fileMetric(armPaths.report),
      summary: fileMetric(armPaths.summary),
      stdout: fileMetric(armPaths.stdout),
      stderr: fileMetric(armPaths.stderr)
    };
    outcomes.armReportProducedPass = armMetrics.report.present && armMetrics.report.bytes > 0;
    outcomes.stderrMetricsCapturedPass = armMetrics.stderr.present && armMetrics.stderr.bytes > 0;
    outcomes.reportMetricsCapturedPass = armMetrics.report.present && armMetrics.report.bytes > 0;
    outcomes.summaryMetricsCapturedPass =
      Number.isSafeInteger(armMetrics.summary.bytes) &&
      typeof armMetrics.summary.present === 'boolean';
    if (!outcomes.armReportProducedPass) throw new Error('Arm report was not produced.');

    const armReport = readJson(armPaths.report, 'arm report');
    const armSummary = armMetrics.summary.present ? readJson(armPaths.summary, 'arm summary') : null;
    const armProjection = reportProjection(armReport);
    const armSummaryContract = summaryContract(armSummary, armReport, ARM_REPORT);
    const armMechanisms = mechanismProjection(armReport);
    outcomes.armGateAccountingPass = gateAccountingPass(armReport);
    outcomes.armDiagnosticContractPass = armSummaryContract.recognized;
    const armStderrText = readFileSync(armPaths.stderr, 'utf8');
    const groupedCount = Number(
      armStderrText.match(/(?:^|\n)(\d+) errors? in \d+ groups?\b/)?.[1] ?? NaN
    );
    const legacyLineCount = armStderrText
      .split('\n')
      .filter((line) => line.startsWith('- ')).length;
    outcomes.terminalErrorAccountingPass =
      groupedCount === armProjection.errors.length ||
      legacyLineCount === armProjection.errors.length;

    const evaluatorProject = resolve(realRunDir, EVALUATOR_DIRECTORY, 'project');
    if (pathExists(resolve(realRunDir, EVALUATOR_DIRECTORY))) {
      throw new Error('Fixed evaluator destination must be new.');
    }
    mkdirSync(dirname(evaluatorProject), { recursive: true, mode: 0o700 });
    copyTree(pristineRoot, evaluatorProject);
    const fixedOutput = resolve(realRunDir, EVALUATOR_DIRECTORY, 'output');
    const fixedRun = verifierRun({
      kitRoot: evaluatorKit,
      projectRoot: evaluatorProject,
      outputRoot: fixedOutput
    });
    const fixedMetrics = {
      report: fileMetric(fixedRun.reportPath),
      summary: fileMetric(fixedRun.summaryPath),
      stdout: fileMetric(fixedRun.stdoutPath),
      stderr: fileMetric(fixedRun.stderrPath)
    };
    outcomes.fixedEvaluatorReportProducedPass =
      fixedRun.exitCode === 1 &&
      fixedMetrics.report.present &&
      fixedMetrics.report.bytes > 0;
    if (!outcomes.fixedEvaluatorReportProducedPass) {
      throw new Error(`Fixed evaluator did not produce the expected invalid report (exit ${String(fixedRun.exitCode)}).`);
    }
    const fixedReport = readJson(fixedRun.reportPath, 'fixed evaluator report');
    const fixedSummary = fixedMetrics.summary.present ? readJson(fixedRun.summaryPath, 'fixed evaluator summary') : null;
    const fixedProjection = reportProjection(fixedReport);
    const fixedMechanisms = mechanismProjection(fixedReport);
    const fixedSummaryContract = summaryContract(
      fixedSummary,
      fixedReport,
      fixedRun.reportPath
    );
    const pristineAfter = seedProjection(pristineRoot);
    outcomes.seedContractPass &&= pristineAfter.packetFingerprint === seed.packetFingerprint;

    outcomes.highErrorMechanismPass =
      fixedMechanisms.errorCount >= ROUTE_COUNT &&
      fixedMechanisms.largestFamilyCount >= ROUTE_COUNT - 5;
    outcomes.gateFanoutMechanismPass =
      fixedMechanisms.highVolumeGateCount >= 2 &&
      fixedMechanisms.maximumGateErrorCount >= ROUTE_COUNT;
    outcomes.fixedSummaryMechanismPass =
      fixedSummaryContract.recognized &&
      fixedSummaryContract.present &&
      fixedSummaryContract.omittedErrors > 0 &&
      fixedMetrics.summary.bytes > 0 &&
      fixedMetrics.summary.bytes < fixedMetrics.report.bytes;

    outcomes.authoritativeValidFingerprintPass =
      armProjection.fingerprints.valid === fixedProjection.fingerprints.valid;
    outcomes.authoritativeVerdictFingerprintPass =
      armProjection.fingerprints.verdict === fixedProjection.fingerprints.verdict;
    outcomes.authoritativeErrorFingerprintPass =
      armProjection.fingerprints.errors === fixedProjection.fingerprints.errors;
    outcomes.authoritativeGateFingerprintPass =
      armProjection.fingerprints.gates === fixedProjection.fingerprints.gates;

    const codexEvents = parseJsonl(codexLog);
    const commands = commandRecords(codexEvents);
    const commandEvidence = evaluateCommandEvidence(commands, codexEvents, armMetrics.stderr);
    outcomes.singleArmVerifierInvocationPass = commandEvidence.verifierInvocationCount === 1;
    outcomes.packetOnlyInvocationPass = commandEvidence.invocationContractPass;
    outcomes.armBlindnessPass = commandEvidence.forbiddenCommands.length === 0;
    outcomes.codexEvidenceCompletePass =
      commandEvidence.threadStartedCount === 1 &&
      commandEvidence.turnCompletedCount === 1 &&
      commandEvidence.turnFailedCount === 0 &&
      commandEvidence.unsupportedCommandCount === 0 &&
      commandEvidence.completeStderrRead;

    const readEvents = parseReadEvents(join(realWorkspace, READ_EVENTS));
    const helperCommands = commands.filter(({ text }) => (
      /\.benchmark-runtime\/read-diagnostic\.mjs\b/.test(text)
    ));
    const helperSequencePass =
      helperCommands.length === readEvents.length &&
      helperCommands.every((command, index) => command.text.includes(readEvents[index]?.path ?? '\0'));
    const unauthorizedDiagnosticCommands = commands.filter(({ text }) => {
      const namesDiagnosticArtifact = text.includes(ARM_REPORT) || text.includes(ARM_SUMMARY);
      const isVerifier = text.includes(
        '.agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs'
      );
      const isReader = text.includes('.benchmark-runtime/read-diagnostic.mjs');
      return namesDiagnosticArtifact && !isVerifier && !isReader;
    });
    const readMetricsPass =
      readEvents.length >= 1 &&
      helperSequencePass &&
      unauthorizedDiagnosticCommands.length === 0 &&
      readEvents.every((event) => {
        const path = join(realWorkspace, event.path);
        const metric = fileMetric(path);
        return metric.present && metric.bytes === event.bytes && metric.sha256 === event.sha256;
      });
    outcomes.diagnosticReadTelemetryPass = readMetricsPass;

    const expectedFirst = armMetrics.summary.present ? ARM_SUMMARY : ARM_REPORT;
    const stderrText = armStderrText;
    const summaryAnnouncementIndex = stderrText.indexOf('Bounded diagnostic summary (read this first):');
    const reportAnnouncementIndex = Math.max(
      stderrText.indexOf('Authoritative full report:'),
      stderrText.indexOf('Report:')
    );
    const announcementPass = armMetrics.summary.present
      ? summaryAnnouncementIndex >= 0 && reportAnnouncementIndex > summaryAnnouncementIndex
      : summaryAnnouncementIndex === -1 && reportAnnouncementIndex >= 0;
    outcomes.documentedReadOrderPass =
      announcementPass &&
      readEvents[0]?.path === expectedFirst &&
      (!armMetrics.summary.present || readEvents.findIndex(({ path }) => path === ARM_REPORT) <= 0 ||
        readEvents.findIndex(({ path }) => path === ARM_SUMMARY) <
          readEvents.findIndex(({ path }) => path === ARM_REPORT));

    const diagnosisPath = regularFile(join(realWorkspace, DIAGNOSIS_FILE), 'diagnosis');
    const diagnosisMetric = fileMetric(diagnosisPath);
    const diagnosis = readJson(diagnosisPath, 'diagnosis');
    const diagnosisShapePass = diagnosisMetric.bytes <= MAX_DIAGNOSIS_BYTES && exactDiagnosisShape(diagnosis);
    const dominant = dominantEvidenceFile(fixedProjection.errors, join(pristineRoot, 'review-packet'));
    const failingGateCount = fixedProjection.gates.filter(({ status }) => status === 'fail').length;
    outcomes.diagnosisSchemaPass = diagnosisShapePass;
    outcomes.diagnosisCountsPass =
      diagnosis.valid === fixedProjection.valid &&
      diagnosis.verdict === fixedProjection.verdict &&
      diagnosis.errorCount === fixedProjection.errors.length &&
      diagnosis.failingGateCount === failingGateCount;
    outcomes.diagnosisEvidencePass =
      diagnosis.dominantEvidenceFile === dominant.name &&
      diagnosis.firstDiagnosticArtifact === expectedFirst;
    outcomes.diagnosisAuthorityPass =
      diagnosis.authority === 'diagnostic_only' &&
      diagnosis.recommendedAction === 'repair-packet-and-reverify' &&
      diagnosis.valid === false;

    const packetAfterEvaluator = seedProjection(pristineRoot);
    outcomes.packetInputImmutablePass &&=
      packetAfterEvaluator.packetFingerprint === seed.packetFingerprint;

    evidence = {
      schemaVersion: EVIDENCE_SCHEMA,
      completed: true,
      seed: {
        routeCount: seed.primaryRouteCount,
        packetFingerprint: seed.packetFingerprint
      },
      arm: {
        metrics: armMetrics,
        projection: armProjection,
        mechanisms: armMechanisms,
        summaryContract: armSummaryContract
      },
      fixedEvaluator: {
        exitCode: fixedRun.exitCode,
        metrics: fixedMetrics,
        projection: fixedProjection,
        mechanisms: fixedMechanisms,
        summaryContract: fixedSummaryContract
      },
      diagnosis: {
        bytes: diagnosisMetric.bytes,
        value: diagnosis,
        expected: {
          errorCount: fixedProjection.errors.length,
          failingGateCount,
          dominantEvidenceFile: dominant.name,
          firstDiagnosticArtifact: expectedFirst
        }
      },
      reads: {
        events: readEvents,
        attributableBytes: readEvents.reduce((total, event) => total + event.bytes, 0)
      },
      commandEvidence,
      inputCheck,
      outcomes
    };
  } catch (error) {
    blockers.push(error.message);
    evidence = {
      ...evidence,
      error: error.message,
      outcomes
    };
  }

  try {
    atomicJson(join(realRunDir, EVIDENCE_FILE), evidence);
  } catch (error) {
    blockers.push(`Evidence persistence failed: ${error.message}`);
  }
  const quality = qualityFromOutcomes(outcomes);
  quality.blockers = [...new Set([...quality.blockers, ...blockers])].sort();
  quality.valid =
    Object.values(quality.outcomes).every((value) => value === true) &&
    quality.blockers.length === 0;
  process.stderr.write(`Detailed same-state metrics: ${EVIDENCE_FILE}\n`);
  process.stdout.write(`${JSON.stringify(quality)}\n`);
}

function cleanup(options) {
  requireOptions(options, ['workspace', 'run-dir', 'experiment-id', 'run-id']);
  const { realRunDir, realWorkspace } = assertOwnedWorkspace(options.workspace, options['run-dir']);
  const owner = readJson(join(realRunDir, OWNER_FILE), 'owner record');
  const expected = ownerRecord(options, realWorkspace);
  if (canonicalJson(owner) !== canonicalJson(expected)) {
    throw new Error('Cleanup ownership mismatch; no cleanup action was taken.');
  }
  // This host-only scenario allocates no service, credential copy, or external
  // resource. Retain all local evidence and record the verified no-op cleanup.
  atomicJson(join(realRunDir, 'high-error-diagnosis-cleanup.json'), {
    schemaVersion: 'public-kit.high-error-diagnosis-cleanup.1',
    ownerVerified: true,
    externalResourcesAllocated: false,
    evidenceRetained: true
  });
  process.stdout.write('Cleanup complete: ownership verified; no external resources were allocated.\n');
}

function usage() {
  return `Usage:
  node adapter.mjs prepare --workspace <path> --run-dir <path> --evaluator-kit <path> --codex-version <version> --experiment-id <id> --run-id <id>
  node adapter.mjs install --workspace <path> --run-dir <path> --arm-kit <path> --reader <path>
  node adapter.mjs evaluate --workspace <path> --run-dir <path> --evaluator-kit <path> --codex-log <path>
  node adapter.mjs cleanup --workspace <path> --run-dir <path> --experiment-id <id> --run-id <id>
`;
}

try {
  const { command, options } = parseArgs(process.argv.slice(2));
  if (command === 'prepare') prepare(options);
  else if (command === 'install') install(options);
  else if (command === 'evaluate') evaluate(options);
  else if (command === 'cleanup') cleanup(options);
  else {
    process.stderr.write(usage());
    throw new Error(`Unknown adapter command: ${String(command ?? '')}`);
  }
} catch (error) {
  process.stderr.write(`High-error diagnosis adapter failed: ${error.message}\n`);
  process.exitCode = 1;
}
