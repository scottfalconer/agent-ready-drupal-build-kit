#!/usr/bin/env node

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  createReadStream,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCENARIO_SCHEMA = 'public-kit.build-benchmark-scenario.1';
const EXPERIMENT_SCHEMA = 'public-kit.build-benchmark-experiment.1';
const RUN_SCHEMA = 'public-kit.build-benchmark-run.1';
const QUALITY_SCHEMA = 'public-kit.build-benchmark-quality.1';
const COMPARISON_SCHEMA = 'public-kit.build-benchmark-comparison.1';
const AUTHORITY = Object.freeze({
  evidenceAuthority: 'none',
  diagnosticOnly: true,
  canAuthorizeCompletion: false
});
const ALLOWED_PLACEHOLDERS = new Set([
  'armId',
  'armKit',
  'evaluatorKit',
  'experimentDir',
  'experimentId',
  'repoRoot',
  'runDir',
  'runId',
  'runOrdinal',
  'scenarioDir',
  'scenarioId',
  'workspace'
]);
const SHELL_EXECUTABLES = new Set([
  'bash', 'cmd', 'dash', 'fish', 'ksh', 'powershell', 'pwsh', 'sh', 'zsh'
]);
const AGENT_FORBIDDEN_PLACEHOLDERS = new Set([
  'armId',
  'armKit',
  'evaluatorKit',
  'experimentDir',
  'experimentId',
  'repoRoot',
  'runDir',
  'runId',
  'runOrdinal',
  'workspace'
]);
let activeChild = null;
let interruptionSignal = null;

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function now() {
  return new Date().toISOString();
}

function atomicJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function safeId(value, field) {
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(value ?? '')) {
    throw new Error(`${field} must be a lowercase kebab identifier.`);
  }
  return value;
}

function finiteNonNegative(value, field) {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${field} must be a finite non-negative number.`);
  return value;
}

function within(path, parent) {
  const child = resolve(path);
  const root = resolve(parent);
  const rel = relative(root, child);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function lstatIfPresent(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

export function newOutputProjection(path) {
  const target = resolve(path);
  if (lstatIfPresent(target)) {
    throw new Error('Output must be a new directory so stale or unrelated evidence cannot be mixed into the experiment.');
  }
  let ancestor = dirname(target);
  while (true) {
    const entry = lstatIfPresent(ancestor);
    if (entry) {
      if (entry.isSymbolicLink() || !entry.isDirectory()) {
        throw new Error('Output must not traverse a symbolic-link or non-directory ancestor.');
      }
      const realAncestor = realpathSync(ancestor);
      return resolve(realAncestor, relative(ancestor, target));
    }
    const parent = dirname(ancestor);
    if (parent === ancestor) {
      throw new Error('Output has no safe existing directory ancestor.');
    }
    ancestor = parent;
  }
}

function assertOutputDisjoint(projectedOutput, protectedRoots) {
  const realProtectedRoots = protectedRoots.map((root) => realpathSync(root));
  if (realProtectedRoots.some((root) => (
    within(projectedOutput, root) ||
    within(root, projectedOutput)
  ))) {
    throw new Error('Output must be disjoint from the repository, scenario, kit checkouts, and directory inputs.');
  }
}

function parseCommand(command, phase, index) {
  if (!command || typeof command !== 'object' || Array.isArray(command)) {
    throw new Error(`commands.${phase}[${index}] must be an object.`);
  }
  if (!Array.isArray(command.argv) || command.argv.length === 0 || command.argv.some((value) => typeof value !== 'string' || value === '')) {
    throw new Error(`commands.${phase}[${index}].argv must be a non-empty string array.`);
  }
  const executable = command.argv[0].split(/[\\/]/).at(-1)?.toLowerCase();
  if (SHELL_EXECUTABLES.has(executable)) {
    throw new Error(`commands.${phase}[${index}] must not invoke a shell; use an argv array with the target executable.`);
  }
  if (command.env !== undefined && (
    !command.env ||
    typeof command.env !== 'object' ||
    Array.isArray(command.env) ||
    Object.entries(command.env).some(([key, value]) => !/^[A-Z_][A-Z0-9_]*$/.test(key) || typeof value !== 'string')
  )) {
    throw new Error(`commands.${phase}[${index}].env must map uppercase environment names to strings.`);
  }
  for (const value of [
    ...command.argv,
    command.cwd ?? '',
    command.stdinFile ?? '',
    ...Object.values(command.env ?? {})
  ]) {
    for (const match of value.matchAll(/\{([^}]+)\}/g)) {
      const placeholder = match[1];
      if (!ALLOWED_PLACEHOLDERS.has(placeholder) && !placeholder.startsWith('var:')) {
        throw new Error(`commands.${phase}[${index}] uses unknown placeholder {${placeholder}}.`);
      }
    }
  }
  if (command.timeoutMs !== undefined) finiteNonNegative(command.timeoutMs, `commands.${phase}[${index}].timeoutMs`);
  if (
    command.measurementRole !== undefined &&
    (phase !== 'build' || !['product', 'harness'].includes(command.measurementRole))
  ) {
    throw new Error(`commands.${phase}[${index}].measurementRole must be product or harness on a build command.`);
  }
  if (command.adapter !== undefined && command.adapter !== 'codex-jsonl-v1') {
    throw new Error(`commands.${phase}[${index}].adapter is unsupported.`);
  }
  if (command.adapter === 'codex-jsonl-v1') {
    if ((command.cwd ?? '{workspace}') !== '{workspace}') {
      throw new Error(`commands.${phase}[${index}] agent cwd must be the opaque trial workspace.`);
    }
    for (const value of [
      ...command.argv,
      command.stdinFile ?? '',
      ...Object.values(command.env ?? {})
    ]) {
      for (const match of value.matchAll(/\{([^}]+)\}/g)) {
        if (AGENT_FORBIDDEN_PLACEHOLDERS.has(match[1])) {
          throw new Error(
            `commands.${phase}[${index}] must not expose {${match[1]}} to the measured agent.`
          );
        }
      }
    }
  }
  return {
    argv: [...command.argv],
    cwd: command.cwd,
    stdinFile: command.stdinFile,
    timeoutMs: command.timeoutMs ?? 6 * 60 * 60 * 1000,
    adapter: command.adapter ?? null,
    measurementRole: phase === 'build' ? command.measurementRole ?? 'product' : 'harness',
    env: { ...(command.env ?? {}) }
  };
}

export function validateScenario(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Scenario must be an object.');
  if (value.schemaVersion !== SCENARIO_SCHEMA) throw new Error(`Scenario schemaVersion must be ${SCENARIO_SCHEMA}.`);
  safeId(value.id, 'scenario.id');
  if (typeof value.description !== 'string' || value.description.trim().length < 20) {
    throw new Error('scenario.description must explain the workload.');
  }
  if (!value.measurementBoundary || typeof value.measurementBoundary.start !== 'string' || typeof value.measurementBoundary.end !== 'string') {
    throw new Error('scenario.measurementBoundary must declare start and end.');
  }
  if (!value.quality || value.quality.mode !== 'exact') {
    throw new Error('scenario.quality.mode must be exact; normalize volatile fresh-build identity in the evaluator.');
  }
  const minimum = value.minimumValidRunsPerArm ?? 2;
  if (!Number.isSafeInteger(minimum) || minimum < 1) throw new Error('scenario.minimumValidRunsPerArm must be a positive integer.');
  const thresholds = {
    minimumMedianImprovementPercent: value.thresholds?.minimumMedianImprovementPercent ?? 10,
    minimumMedianImprovementMs: value.thresholds?.minimumMedianImprovementMs ?? 5000,
    minimumTokenImprovementPercent: value.thresholds?.minimumTokenImprovementPercent ?? 10,
    minimumToolOutputImprovementPercent: value.thresholds?.minimumToolOutputImprovementPercent ?? 10,
    maximumMedianRegressionPercent: value.thresholds?.maximumMedianRegressionPercent ?? 5,
    maximumMedianRegressionMs: value.thresholds?.maximumMedianRegressionMs ?? 30_000,
    requireEveryPairFaster: value.thresholds?.requireEveryPairFaster ?? true
  };
  finiteNonNegative(thresholds.minimumMedianImprovementPercent, 'scenario.thresholds.minimumMedianImprovementPercent');
  finiteNonNegative(thresholds.minimumMedianImprovementMs, 'scenario.thresholds.minimumMedianImprovementMs');
  finiteNonNegative(thresholds.minimumTokenImprovementPercent, 'scenario.thresholds.minimumTokenImprovementPercent');
  finiteNonNegative(thresholds.minimumToolOutputImprovementPercent, 'scenario.thresholds.minimumToolOutputImprovementPercent');
  finiteNonNegative(thresholds.maximumMedianRegressionPercent, 'scenario.thresholds.maximumMedianRegressionPercent');
  finiteNonNegative(thresholds.maximumMedianRegressionMs, 'scenario.thresholds.maximumMedianRegressionMs');
  if (typeof thresholds.requireEveryPairFaster !== 'boolean') throw new Error('scenario.thresholds.requireEveryPairFaster must be boolean.');

  const variables = value.variables ?? {};
  if (!variables || typeof variables !== 'object' || Array.isArray(variables)) throw new Error('scenario.variables must be an object.');
  for (const [key, variable] of Object.entries(variables)) {
    if (!/^[a-z][a-zA-Z0-9]*$/.test(key) || ALLOWED_PLACEHOLDERS.has(key)) throw new Error(`Invalid or reserved scenario variable: ${key}.`);
    if (typeof variable !== 'string' && variable !== null) throw new Error(`scenario.variables.${key} must be a string or null.`);
  }
  const identityFiles = value.identityFiles ?? [];
  if (!Array.isArray(identityFiles)) throw new Error('scenario.identityFiles must be an array.');
  const identityIds = new Set();
  for (const [index, item] of identityFiles.entries()) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`scenario.identityFiles[${index}] must be an object.`);
    safeId(item.id, `scenario.identityFiles[${index}].id`);
    if (identityIds.has(item.id)) throw new Error(`Duplicate scenario identity file id: ${item.id}.`);
    identityIds.add(item.id);
    if (typeof item.path !== 'string' || !item.path) throw new Error(`scenario.identityFiles[${index}].path must be a string.`);
    for (const match of item.path.matchAll(/\{([^}]+)\}/g)) {
      const placeholder = match[1];
      if (!['repoRoot', 'scenarioDir'].includes(placeholder) && !placeholder.startsWith('var:')) {
        throw new Error(`scenario.identityFiles[${index}] uses unsupported placeholder {${placeholder}}.`);
      }
    }
  }
  const runtime = value.runtime ?? {};
  if (!runtime || typeof runtime !== 'object' || Array.isArray(runtime)) throw new Error('scenario.runtime must be an object.');
  for (const [key, item] of Object.entries(runtime)) {
    if (!/^[a-z][a-zA-Z0-9]*$/.test(key) || typeof item !== 'string' || item.length > 200) {
      throw new Error(`scenario.runtime.${key} must be a short string.`);
    }
    for (const match of item.matchAll(/\{([^}]+)\}/g)) {
      if (!match[1].startsWith('var:')) throw new Error(`scenario.runtime.${key} may only use scenario variables.`);
    }
  }

  const commands = {};
  for (const phase of ['prepare', 'build', 'evaluate', 'cleanup']) {
    const list = value.commands?.[phase] ?? [];
    if (!Array.isArray(list)) throw new Error(`scenario.commands.${phase} must be an array.`);
    commands[phase] = list.map((command, index) => parseCommand(command, phase, index));
  }
  if (commands.build.length === 0) throw new Error('scenario.commands.build requires at least one command.');
  if (commands.evaluate.length !== 1) throw new Error('scenario.commands.evaluate requires exactly one quality command.');
  if (commands.build.filter(({ adapter }) => adapter === 'codex-jsonl-v1').length > 1) {
    throw new Error('Only one build command may use the codex-jsonl-v1 adapter.');
  }
  return {
    schemaVersion: SCENARIO_SCHEMA,
    id: value.id,
    description: value.description,
    measurementBoundary: structuredClone(value.measurementBoundary),
    minimumValidRunsPerArm: minimum,
    thresholds,
    quality: structuredClone(value.quality),
    variables: structuredClone(variables),
    identityFiles: structuredClone(identityFiles),
    runtime: structuredClone(runtime),
    commands
  };
}

export function parseSequence(value = 'ABBA') {
  const compact = String(value).toUpperCase().replace(/[\s_-]+/g, '');
  if (!/^[AB]+$/.test(compact) || !compact.includes('A') || !compact.includes('B') || compact.length % 2 !== 0) {
    throw new Error('Sequence must be an even ordering containing both A and B, such as ABBA or ABBA-BAAB.');
  }
  const a = [...compact].filter((item) => item === 'A').length;
  if (a * 2 !== compact.length) throw new Error('Sequence must contain equal A and B runs.');
  for (let index = 0; index < compact.length; index += 2) {
    if (new Set(compact.slice(index, index + 2)).size !== 2) {
      throw new Error('Every adjacent pair in the sequence must contain one A and one B.');
    }
  }
  const pairOrientations = [];
  for (let index = 0; index < compact.length; index += 2) {
    pairOrientations.push(compact.slice(index, index + 2));
  }
  if (
    pairOrientations.filter((pair) => pair === 'AB').length !==
    pairOrientations.filter((pair) => pair === 'BA').length
  ) {
    throw new Error('Sequence must balance AB and BA pair orientations.');
  }
  return [...compact];
}

export function buildSchedule(sequence, warmupsPerArm = 0) {
  if (!Number.isSafeInteger(warmupsPerArm) || warmupsPerArm < 0 || warmupsPerArm > 3) {
    throw new Error('warmupsPerArm must be 0 through 3.');
  }
  const measured = Array.isArray(sequence) ? sequence : parseSequence(sequence);
  const schedule = [];
  const firstWarmupPair = measured[0] === 'A' ? ['B', 'A'] : ['A', 'B'];
  for (let index = 0; index < warmupsPerArm; index += 1) {
    const warmupPair = index % 2 === 0 ? firstWarmupPair : [...firstWarmupPair].reverse();
    for (const [position, symbol] of warmupPair.entries()) {
      schedule.push({
        ordinal: schedule.length + 1,
        block: 0,
        position: index * 2 + position + 1,
        armId: symbol === 'A' ? 'baseline' : 'candidate',
        warmup: true
      });
    }
  }
  measured.forEach((symbol, index) => {
    schedule.push({
      ordinal: schedule.length + 1,
      block: Math.floor(index / 4) + 1,
      position: (index % 4) + 1,
      armId: symbol === 'A' ? 'baseline' : 'candidate',
      warmup: false
    });
  });
  return schedule;
}

function resolveTemplate(value, context) {
  return value.replace(/\{([^}]+)\}/g, (_, placeholder) => {
    if (placeholder.startsWith('var:')) {
      const key = placeholder.slice(4);
      if (!Object.hasOwn(context.variables, key) || context.variables[key] === null) {
        throw new Error(`Required scenario variable ${key} was not supplied.`);
      }
      return context.variables[key];
    }
    if (!Object.hasOwn(context, placeholder)) throw new Error(`Unknown placeholder {${placeholder}}.`);
    return String(context[placeholder]);
  });
}

function sanitize(value, context) {
  let safe = String(value);
  const replacements = [
    ['<trial-workspace>', context.workspace],
    ['<run-dir>', context.runDir],
    ['<experiment-dir>', context.experimentDir],
    ['<scenario-dir>', context.scenarioDir],
    ['<arm-kit>', context.armKit],
    ['<evaluator-kit>', context.evaluatorKit],
    ['<repo-root>', context.repoRoot],
    ...Object.entries(context.variables).filter(([, item]) => typeof item === 'string' && isAbsolute(item)).map(([key, item]) => [`<var:${key}>`, item])
  ].sort((left, right) => right[1].length - left[1].length);
  for (const [replacement, original] of replacements) {
    if (original) safe = safe.split(original).join(replacement);
  }
  return safe;
}

function resolvedCommand(spec, context, phase) {
  const argv = spec.argv.map((value) => resolveTemplate(value, context));
  const cwd = resolveTemplate(spec.cwd ?? (phase === 'prepare' ? '{runDir}' : '{workspace}'), context);
  if (!within(cwd, context.runDir) && !within(cwd, context.scenarioDir)) {
    throw new Error(`Resolved ${phase} cwd must stay inside the run or scenario directory.`);
  }
  const stdinFile = spec.stdinFile ? resolveTemplate(spec.stdinFile, context) : null;
  if (stdinFile && !within(stdinFile, context.runDir) && !within(stdinFile, context.scenarioDir)) {
    throw new Error(`Resolved ${phase} stdinFile must stay inside the run or scenario directory.`);
  }
  const env = Object.fromEntries(Object.entries(spec.env).map(([key, value]) => [key, resolveTemplate(value, context)]));
  return {
    argv,
    cwd,
    stdinFile,
    timeoutMs: spec.timeoutMs,
    adapter: spec.adapter,
    measurementRole: spec.measurementRole,
    env
  };
}

function killProcessGroup(child, signal) {
  if (!child.pid) return;
  try {
    if (process.platform === 'win32') child.kill(signal);
    else process.kill(-child.pid, signal);
  }
  catch {}
}

async function runProcess(spec, { phase, index, context }) {
  const command = resolvedCommand(spec, context, phase);
  mkdirSync(command.cwd, { recursive: true });
  const prefix = `${phase}-${String(index + 1).padStart(2, '0')}`;
  const stdoutPath = resolve(context.runDir, 'logs', `${prefix}.stdout.log`);
  const stderrPath = resolve(context.runDir, 'logs', `${prefix}.stderr.log`);
  mkdirSync(dirname(stdoutPath), { recursive: true });
  const stdoutFd = openSync(stdoutPath, 'w', 0o600);
  const stderrFd = openSync(stderrPath, 'w', 0o600);
  const startedAt = now();
  const started = performance.now();

  let infrastructureError;
  let outputsClosed = false;
  const closeOutputs = () => {
    if (outputsClosed) return;
    outputsClosed = true;
    for (const descriptor of [stdoutFd, stderrFd]) {
      try {
        closeSync(descriptor);
      }
      catch {}
    }
  };
  const result = await new Promise((resolveProcess) => {
    let child;
    try {
      child = spawn(command.argv[0], command.argv.slice(1), {
        cwd: command.cwd,
        detached: process.platform !== 'win32',
        env: { ...process.env, ...command.env, PWD: command.cwd },
        stdio: ['pipe', stdoutFd, stderrFd]
      });
      activeChild = child;
    }
    catch (error) {
      infrastructureError = error;
      closeOutputs();
      resolveProcess({ code: 1, signal: '', timedOut: false });
      return;
    }
    let timedOut = false;
    let hardKill;
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessGroup(child, 'SIGTERM');
      hardKill = setTimeout(() => killProcessGroup(child, 'SIGKILL'), 10_000);
    }, command.timeoutMs);
    child.on('error', (error) => {
      infrastructureError ??= error;
    });
    child.stdin.on('error', (error) => {
      if (error.code !== 'EPIPE') infrastructureError ??= error;
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      clearTimeout(hardKill);
      closeOutputs();
      if (activeChild === child) activeChild = null;
      resolveProcess({ code: code ?? (timedOut ? 124 : 1), signal: signal ?? '', timedOut });
    });
    if (command.stdinFile) {
      const input = createReadStream(command.stdinFile);
      input.on('error', (error) => {
        infrastructureError ??= error;
        killProcessGroup(child, 'SIGTERM');
      });
      input.pipe(child.stdin);
    } else child.stdin.end();
  });
  if (infrastructureError) throw infrastructureError;
  const fileHash = (path) => new Promise((resolveHash, rejectHash) => {
    const hash = createHash('sha256');
    const input = createReadStream(path);
    input.on('data', (chunk) => hash.update(chunk));
    input.on('error', rejectHash);
    input.on('end', () => resolveHash(`sha256:${hash.digest('hex')}`));
  });
  const [stdoutSha256, stderrSha256] = await Promise.all([fileHash(stdoutPath), fileHash(stderrPath)]);
  const stdoutBytes = statSync(stdoutPath).size;
  const stderrBytes = statSync(stderrPath).size;
  const finishedAt = now();
  const durationMs = performance.now() - started;
  return {
    id: prefix,
    phase,
    startedAt,
    finishedAt,
    durationMs: Math.round(durationMs * 1000) / 1000,
    status: result.timedOut ? 'timed_out' : result.code === 0 ? 'completed' : 'failed',
    process: {
      exitCode: result.code,
      signal: result.signal,
      timedOut: result.timedOut,
      stdoutBytes,
      stderrBytes,
      stdoutSha256,
      stderrSha256
    },
    command: {
      argv: spec.argv.map((value) => sanitize(value, context)),
      cwd: sanitize(spec.cwd ?? (phase === 'prepare' ? '{runDir}' : '{workspace}'), context),
      adapter: command.adapter,
      measurementRole: command.measurementRole
    },
    artifacts: {
      stdout: relative(context.runDir, stdoutPath),
      stderr: relative(context.runDir, stderrPath)
    }
  };
}

function textBytes(value) {
  return Buffer.byteLength(typeof value === 'string' ? value : '');
}

function structuredCommandArgv(item) {
  if (Array.isArray(item?.argv) && item.argv.every((value) => typeof value === 'string')) return item.argv;
  if (Array.isArray(item?.command) && item.command.every((value) => typeof value === 'string')) return item.command;
  return null;
}

function commandAttribution(item) {
  const argv = structuredCommandArgv(item);
  if (argv) {
    return {
      coverage: 'exact',
      values: argv.map((argument) => argument.replaceAll('\\', '/'))
    };
  }
  const rendered = typeof item?.command === 'string'
    ? item.command
    : typeof item?.argv === 'string'
      ? item.argv
      : null;
  if (rendered) {
    return {
      coverage: 'heuristic',
      values: [rendered.replaceAll('\\', '/')]
    };
  }
  return { coverage: 'partial', values: [] };
}

export function parseCodexJsonl(value) {
  const metrics = {
    adapterId: 'codex-jsonl-v1',
    coverage: 'complete',
    rawEventBytes: Buffer.byteLength(value),
    rawEventSha256: sha256(value),
    eventCount: 0,
    unsupportedEventCount: 0,
    threadStartedCount: 0,
    turnCompletedCount: 0,
    turnFailedCount: 0,
    agentMessageBytes: 0,
    toolOutputBytes: 0,
    toolCallCount: 0,
    failedToolCallCount: 0,
    commandAttributionCoverage: 'complete',
    unstructuredCommandCount: 0,
    heuristicCommandCount: 0,
    verifierInvocationCount: 0,
    summaryReadCount: 0,
    fullReportReadCount: 0,
    usage: {
      inputTokens: null,
      cachedInputTokens: null,
      outputTokens: null,
      reasoningOutputTokens: null,
      totalTokens: null
    },
    usageComplete: false
  };
  const supported = new Set([
    'thread.started', 'turn.started', 'turn.completed', 'turn.failed',
    'item.started', 'item.updated', 'item.completed', 'error'
  ]);
  const supportedCompletedItems = new Set([
    'agent_message',
    'reasoning',
    'file_change',
    'todo_list',
    'error',
    'command_execution',
    'mcp_tool_call',
    'web_search'
  ]);
  const usageEvents = [];
  for (const line of value.split('\n')) {
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
    }
    catch {
      metrics.coverage = 'partial';
      metrics.unsupportedEventCount += 1;
      continue;
    }
    metrics.eventCount += 1;
    if (!supported.has(event.type)) metrics.unsupportedEventCount += 1;
    if (event.type === 'thread.started') metrics.threadStartedCount += 1;
    if (event.type === 'turn.failed') metrics.turnFailedCount += 1;
    if (event.type === 'turn.completed') {
      metrics.turnCompletedCount += 1;
      const usage = event.usage ?? {};
      const inputTokens = usage.input_tokens ?? usage.inputTokens;
      const cachedInputTokens = usage.cached_input_tokens ?? usage.cachedInputTokens;
      const outputTokens = usage.output_tokens ?? usage.outputTokens;
      const reasoningOutputTokens = usage.reasoning_output_tokens ?? usage.reasoningOutputTokens;
      usageEvents.push({
        inputTokens: Number.isFinite(inputTokens) ? inputTokens : null,
        cachedInputTokens: Number.isFinite(cachedInputTokens) ? cachedInputTokens : null,
        outputTokens: Number.isFinite(outputTokens) ? outputTokens : null,
        reasoningOutputTokens: Number.isFinite(reasoningOutputTokens) ? reasoningOutputTokens : null,
        totalTokens: Number.isFinite(inputTokens) && Number.isFinite(outputTokens) ? inputTokens + outputTokens : null
      });
    }
    const item = event.item;
    if (!item || event.type !== 'item.completed') continue;
    if (!supportedCompletedItems.has(item.type)) {
      metrics.unsupportedEventCount += 1;
      continue;
    }
    if (item.type === 'agent_message') metrics.agentMessageBytes += textBytes(item.text ?? item.content);
    if (['command_execution', 'mcp_tool_call', 'web_search'].includes(item.type)) {
      metrics.toolCallCount += 1;
      const output = item.aggregated_output ?? item.output ?? item.result ?? '';
      metrics.toolOutputBytes += textBytes(typeof output === 'string' ? output : canonicalJson(output));
      if (item.status === 'failed' || (Number.isFinite(item.exit_code) && item.exit_code !== 0)) metrics.failedToolCallCount += 1;
      if (item.type === 'command_execution') {
        const attribution = commandAttribution(item);
        if (attribution.coverage === 'partial') {
          metrics.commandAttributionCoverage = 'partial';
          metrics.unstructuredCommandCount += 1;
        } else {
          if (
            attribution.coverage === 'heuristic' &&
            metrics.commandAttributionCoverage === 'complete'
          ) {
            metrics.commandAttributionCoverage = 'heuristic';
            metrics.heuristicCommandCount += 1;
          } else if (attribution.coverage === 'heuristic') {
            metrics.heuristicCommandCount += 1;
          }
          const normalized = attribution.values;
          if (normalized.some((argument) => /(?:^|[/\s"'=])verify\.mjs(?:$|[\s"'])/.test(argument))) metrics.verifierInvocationCount += 1;
          if (normalized.some((argument) => /(?:^|[/\s"'=])live-verification\.summary\.json(?:$|[\s"'])/.test(argument))) metrics.summaryReadCount += 1;
          if (normalized.some((argument) => /(?:^|[/\s"'=])live-verification\.json(?:$|[\s"'])/.test(argument))) metrics.fullReportReadCount += 1;
        }
      }
    }
  }
  if (usageEvents.length === 1) {
    metrics.usage = usageEvents[0];
    metrics.usageComplete = Number.isFinite(metrics.usage.inputTokens) && Number.isFinite(metrics.usage.outputTokens);
  }
  if (metrics.commandAttributionCoverage === 'partial') {
    metrics.verifierInvocationCount = null;
    metrics.summaryReadCount = null;
    metrics.fullReportReadCount = null;
  }
  if (metrics.unsupportedEventCount > 0) metrics.coverage = 'partial';
  return metrics;
}

export function parseQuality(path) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  }
  catch (error) {
    throw new Error(`Quality evaluator must write one JSON object to stdout: ${error.message}`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Quality evaluator output must be an object.');
  if (value.schemaVersion !== QUALITY_SCHEMA) throw new Error(`Quality schemaVersion must be ${QUALITY_SCHEMA}.`);
  if (typeof value.valid !== 'boolean') throw new Error('Quality valid must be boolean.');
  if (!value.outcomes || typeof value.outcomes !== 'object' || Array.isArray(value.outcomes)) {
    throw new Error('Quality outcomes must be an object.');
  }
  const outcomeEntries = Object.entries(value.outcomes);
  if (outcomeEntries.length === 0) {
    throw new Error('Quality outcomes must contain at least one evaluated outcome.');
  }
  for (const [name, outcome] of outcomeEntries) {
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name)) {
      throw new Error(`Quality outcome name is invalid: ${name}.`);
    }
    if (typeof outcome !== 'boolean') {
      throw new Error(`Quality outcome ${name} must be boolean.`);
    }
  }
  if (!Array.isArray(value.blockers)) {
    throw new Error('Quality blockers must be an array.');
  }
  const projected = {
    schemaVersion: QUALITY_SCHEMA,
    valid: value.valid,
    outcomes: value.outcomes,
    blockers: value.blockers.map(String).sort()
  };
  const derivedValid =
    outcomeEntries.every(([, outcome]) => outcome === true) &&
    projected.blockers.length === 0;
  if (projected.valid !== derivedValid) {
    throw new Error('Quality valid must exactly match boolean outcomes and blockers.');
  }
  return {
    ...projected,
    outcomeFingerprint: sha256(canonicalJson(projected.outcomes))
  };
}

function gitIdentity(path) {
  const run = (args) => spawnSync('git', ['-C', path, ...args], { encoding: 'utf8' });
  const commit = run(['rev-parse', 'HEAD']);
  const tree = run(['rev-parse', 'HEAD^{tree}']);
  const status = run(['status', '--porcelain=v1', '--untracked-files=all']);
  const ignored = run(['ls-files', '--others', '--ignored', '--exclude-standard']);
  if (commit.status !== 0 || tree.status !== 0 || status.status !== 0 || ignored.status !== 0) {
    throw new Error(`Kit path is not a readable Git checkout: ${path}`);
  }
  if (status.stdout.trim()) throw new Error(`Kit checkout must be clean so its recorded commit identifies the exact bytes: ${path}`);
  if (ignored.stdout.trim()) throw new Error(`Kit checkout must not contain ignored files outside its recorded commit: ${path}`);
  return {
    commit: commit.stdout.trim(),
    treeFingerprint: sha256(tree.stdout.trim())
  };
}

function commandVersion(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 15_000 });
  if (result.status !== 0) return null;
  return (result.stdout || result.stderr).trim().split('\n')[0].slice(0, 200) || null;
}

function currentDdevVersion() {
  const result = spawnSync('ddev', ['version', '-j'], {
    encoding: 'utf8',
    timeout: 15_000
  });
  if (result.status !== 0) return null;
  for (const line of result.stdout.trim().split('\n').reverse()) {
    try {
      const parsed = JSON.parse(line);
      const version = parsed?.raw?.['DDEV version'];
      if (typeof version === 'string' && version !== '') {
        return version.replace(/^v/, '');
      }
    } catch {}
  }
  return null;
}

function environmentProjection() {
  const value = {
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
    codex: commandVersion('codex', ['--version']),
    ddev: currentDdevVersion(),
    git: commandVersion('git', ['--version'])
  };
  return { ...value, fingerprint: sha256(canonicalJson(value)) };
}

async function runPhase(phase, specs, context, state) {
  const phaseStarted = performance.now();
  const records = [];
  for (let index = 0; index < specs.length; index += 1) {
    if (interruptionSignal && phase !== 'cleanup') throw new Error(`Benchmark interrupted by ${interruptionSignal}.`);
    const record = await runProcess(specs[index], { phase, index, context });
    records.push(record);
    state.timing.phases.push(record);
    atomicJson(resolve(context.runDir, 'run.json'), state);
    if (record.status !== 'completed') break;
  }
  return {
    phase,
    durationMs: Math.round((performance.now() - phaseStarted) * 1000) / 1000,
    records,
    passed: records.length === specs.length && records.every(({ status }) => status === 'completed')
  };
}

function variableValues(scenario, supplied) {
  const values = { ...scenario.variables };
  for (const [key, value] of Object.entries(supplied)) {
    if (!Object.hasOwn(values, key)) throw new Error(`Unknown scenario variable: ${key}.`);
    values[key] = value;
  }
  for (const [key, value] of Object.entries(values)) {
    if (value === null) throw new Error(`Required scenario variable ${key} was not supplied.`);
  }
  return values;
}

function runFingerprint(run) {
  return sha256(canonicalJson({
    schemaVersion: run.schemaVersion,
    authority: run.authority,
    experimentFingerprint: run.experimentFingerprint,
    runId: run.runId,
    order: run.order,
    identity: run.identity,
    eligibility: run.eligibility,
    timing: run.timing,
    context: run.context,
    quality: run.quality,
    artifacts: run.artifacts
  }));
}

function experimentFingerprint(experiment) {
  const identity = structuredClone(experiment);
  delete identity.createdAt;
  delete identity.completedAt;
  delete identity.status;
  delete identity.fingerprint;
  return sha256(canonicalJson(identity));
}

function evidenceFile(path, root, label) {
  if (
    !within(path, root) ||
    !existsSync(path) ||
    lstatSync(path).isSymbolicLink() ||
    !lstatSync(path).isFile()
  ) {
    throw new Error(`${label} is missing, unsafe, or outside its run directory.`);
  }
  const realRoot = realpathSync(root);
  const realFile = realpathSync(path);
  if (!within(realFile, realRoot)) {
    throw new Error(`${label} resolves outside its run directory.`);
  }
  return path;
}

function verifyRecordedArtifacts(experimentDir, run) {
  const runDir = resolve(
    experimentDir,
    'runs',
    `${String(run.order.ordinal).padStart(3, '0')}-trial`
  );
  for (const phase of run.timing.phases) {
    for (const [stream, expectedBytes, expectedSha256] of [
      ['stdout', phase.process.stdoutBytes, phase.process.stdoutSha256],
      ['stderr', phase.process.stderrBytes, phase.process.stderrSha256]
    ]) {
      const relativePath = phase.artifacts?.[stream];
      if (typeof relativePath !== 'string') {
        throw new Error(`Run ${run.runId} has no ${stream} artifact path for ${phase.id}.`);
      }
      const artifactPath = evidenceFile(
        resolve(runDir, relativePath),
        runDir,
        `Run ${run.runId} ${stream} artifact`
      );
      const bytes = readFileSync(artifactPath);
      if (bytes.length !== expectedBytes || sha256(bytes) !== expectedSha256) {
        throw new Error(`Run ${run.runId} ${stream} artifact does not match its recorded bytes and hash.`);
      }
    }
  }
  for (const artifact of run.artifacts ?? []) {
    if (typeof artifact.path !== 'string') {
      throw new Error(`Run ${run.runId} recorded artifact path is invalid.`);
    }
    const artifactPath = evidenceFile(
      resolve(runDir, artifact.path),
      runDir,
      `Run ${run.runId} recorded artifact`
    );
    const bytes = readFileSync(artifactPath);
    if (bytes.length !== artifact.bytes || sha256(bytes) !== artifact.sha256) {
      throw new Error(`Run ${run.runId} recorded artifact does not match its preserved bytes and hash.`);
    }
  }

  const codexRecord = run.timing.phases.find(({ command }) => command.adapter === 'codex-jsonl-v1');
  if (codexRecord) {
    const stdoutPath = evidenceFile(
      resolve(runDir, codexRecord.artifacts.stdout),
      runDir,
      `Run ${run.runId} Codex stdout`
    );
    const derivedContext = parseCodexJsonl(readFileSync(stdoutPath, 'utf8'));
    if (canonicalJson(derivedContext) !== canonicalJson(run.context)) {
      throw new Error(`Run ${run.runId} context projection does not match raw Codex evidence.`);
    }
  } else if (run.context !== null) {
    throw new Error(`Run ${run.runId} has context without a Codex evidence record.`);
  }

  const evaluateRecord = run.timing.phases.find(({ phase }) => phase === 'evaluate');
  if (evaluateRecord?.status === 'completed') {
    const stdoutPath = evidenceFile(
      resolve(runDir, evaluateRecord.artifacts.stdout),
      runDir,
      `Run ${run.runId} evaluator stdout`
    );
    let derivedQuality;
    try {
      derivedQuality = parseQuality(stdoutPath);
    } catch (error) {
      derivedQuality = { valid: false, error: error.message };
    }
    if (canonicalJson(derivedQuality) !== canonicalJson(run.quality)) {
      throw new Error(`Run ${run.runId} quality projection does not match raw evaluator evidence.`);
    }
  } else if (run.quality !== null) {
    throw new Error(`Run ${run.runId} has quality without completed evaluator evidence.`);
  }

  const qualityArtifact = (run.artifacts ?? []).find(({ id }) => id === 'quality-projection');
  if (qualityArtifact) {
    const projected = readJson(resolve(runDir, qualityArtifact.path));
    if (canonicalJson(projected) !== canonicalJson(run.quality)) {
      throw new Error(`Run ${run.runId} quality artifact does not match its recorded projection.`);
    }
  }
}

function validateExperimentEvidence(experiment, runs, { experimentDir = null } = {}) {
  if (experiment.schemaVersion !== EXPERIMENT_SCHEMA) throw new Error('Unsupported experiment schema.');
  if (canonicalJson(experiment.authority) !== canonicalJson(AUTHORITY)) throw new Error('Experiment authority contract changed.');
  if (experiment.fingerprint !== experimentFingerprint(experiment)) throw new Error('Experiment fingerprint does not match the preserved identity.');
  if (!Array.isArray(experiment.schedule) || experiment.schedule.length !== runs.length) {
    throw new Error('Experiment schedule and preserved runs differ.');
  }
  const ordinals = new Set();
  runs.forEach((run, index) => {
    const expected = experiment.schedule[index];
    if (run.schemaVersion !== RUN_SCHEMA) throw new Error(`Unsupported run schema at schedule position ${index + 1}.`);
    if (canonicalJson(run.authority) !== canonicalJson(AUTHORITY)) throw new Error(`Run ${run.runId} authority contract changed.`);
    const expectedRunId = `${String(expected.ordinal).padStart(3, '0')}-trial`;
    if (run.runId !== expectedRunId) throw new Error(`Run ${run.runId} does not match its scheduled identifier.`);
    if (run.experimentFingerprint !== experiment.fingerprint) throw new Error(`Run ${run.runId} belongs to a different experiment.`);
    if (canonicalJson(run.order) !== canonicalJson(expected)) throw new Error(`Run ${run.runId} does not match its scheduled order.`);
    if (ordinals.has(run.order.ordinal)) throw new Error(`Duplicate run ordinal ${run.order.ordinal}.`);
    ordinals.add(run.order.ordinal);
    if (run.resultFingerprint !== runFingerprint(run)) throw new Error(`Run ${run.runId} fingerprint does not match its preserved evidence.`);
    if (experimentDir) verifyRecordedArtifacts(experimentDir, run);
  });
}

function identitySourceChanged(source) {
  if (
    !existsSync(source.path) ||
    lstatSync(source.path).isSymbolicLink() ||
    !lstatSync(source.path).isFile()
  ) return true;
  const bytes = readFileSync(source.path);
  return bytes.length !== source.bytes || sha256(bytes) !== source.sha256;
}

async function executeRun({ experiment, scenario, scenarioDir, experimentDir, order, arm, evaluatorKit, variables, identitySources }) {
  const runId = `${String(order.ordinal).padStart(3, '0')}-trial`;
  const runDir = resolve(experimentDir, 'runs', runId);
  const workspace = resolve(runDir, 'workspace');
  mkdirSync(resolve(runDir, 'logs'), { recursive: true });
  mkdirSync(workspace, { recursive: true });
  const context = {
    armId: order.armId,
    armKit: arm.path,
    evaluatorKit,
    experimentDir,
    experimentId: experiment.experimentId,
    repoRoot,
    runDir,
    runId,
    runOrdinal: String(order.ordinal),
    scenarioDir,
    scenarioId: scenario.id,
    variables,
    workspace
  };
  const state = {
    schemaVersion: RUN_SCHEMA,
    authority: AUTHORITY,
    experimentFingerprint: experiment.fingerprint,
    runId,
    order,
    identity: {
      scenarioFingerprint: experiment.scenario.fingerprint,
      identityInputs: experiment.scenario.identityInputs,
      armFingerprint: arm.fingerprint,
      kitCommit: arm.commit,
      environmentFingerprint: experiment.environment.fingerprint
    },
    eligibility: {
      eligible: false,
      exclusionReasons: [],
      contaminationFlags: []
    },
    timing: {
      startedAt: now(),
      finishedAt: null,
      totalWallClockMs: null,
      measurementBoundary: scenario.measurementBoundary,
      measuredBuildWallClockMs: null,
      measuredProductWallClockMs: null,
      measuredHarnessWallClockMs: null,
      measuredOutcomeWallClockMs: null,
      phases: []
    },
    context: null,
    quality: null,
    artifacts: [],
    resultFingerprint: null
  };
  atomicJson(resolve(runDir, 'run.json'), state);
  const runStarted = performance.now();
  let prepare;
  let build;
  let evaluate;
  let cleanup;
  let unexpected;
  let measuredStarted;
  try {
    if (identitySources.some(identitySourceChanged)) throw new Error('A scenario identity input changed before the run.');
    const beforeIdentity = gitIdentity(arm.path);
    if (beforeIdentity.commit !== arm.commit || beforeIdentity.treeFingerprint !== arm.treeFingerprint) {
      throw new Error('Arm checkout identity changed before the run.');
    }
    const evaluatorBeforeIdentity = gitIdentity(evaluatorKit);
    if (
      evaluatorBeforeIdentity.commit !== experiment.evaluator.kitCommit ||
      evaluatorBeforeIdentity.treeFingerprint !== experiment.evaluator.kitTreeFingerprint
    ) {
      throw new Error('Evaluator checkout identity changed before the run.');
    }
    prepare = await runPhase('prepare', scenario.commands.prepare, context, state);
    if (!prepare.passed) state.eligibility.exclusionReasons.push('prepare-failed');
    if (prepare.passed) {
      measuredStarted = performance.now();
      build = await runPhase('build', scenario.commands.build, context, state);
      state.timing.measuredBuildWallClockMs = build.durationMs;
      state.timing.measuredProductWallClockMs = Math.round(
        build.records
          .filter(({ command }) => command.measurementRole === 'product')
          .reduce((total, record) => total + record.durationMs, 0) * 1000
      ) / 1000;
      state.timing.measuredHarnessWallClockMs = Math.round(
        build.records
          .filter(({ command }) => command.measurementRole === 'harness')
          .reduce((total, record) => total + record.durationMs, 0) * 1000
      ) / 1000;
      if (!build.passed) state.eligibility.exclusionReasons.push('build-failed');
    }
    if (build?.passed) {
      evaluate = await runPhase('evaluate', scenario.commands.evaluate, context, state);
      if (!evaluate.passed) state.eligibility.exclusionReasons.push('evaluation-process-failed');
      else {
        state.timing.measuredOutcomeWallClockMs = Math.round((performance.now() - measuredStarted) * 1000) / 1000;
        try {
          const stdoutPath = resolve(runDir, evaluate.records[0].artifacts.stdout);
          state.quality = parseQuality(stdoutPath);
          const qualityPath = resolve(runDir, 'quality-projection.json');
          atomicJson(qualityPath, state.quality);
          const qualityBytes = readFileSync(qualityPath);
          state.artifacts.push({
            id: 'quality-projection',
            path: relative(runDir, qualityPath),
            bytes: qualityBytes.length,
            sha256: sha256(qualityBytes)
          });
          if (!state.quality.valid) state.eligibility.exclusionReasons.push('quality-contract-failed');
        }
        catch (error) {
          state.eligibility.exclusionReasons.push('quality-output-invalid');
          state.quality = { valid: false, error: error.message };
        }
      }
    }
  }
  catch (error) {
    unexpected = error;
    state.eligibility.exclusionReasons.push('runner-error');
    state.eligibility.contaminationFlags.push(error.message);
  }
  finally {
    try {
      cleanup = await runPhase('cleanup', scenario.commands.cleanup, context, state);
      if (!cleanup.passed) state.eligibility.exclusionReasons.push('cleanup-failed');
    }
    catch (error) {
      state.eligibility.exclusionReasons.push('cleanup-runner-error');
      state.eligibility.contaminationFlags.push(error.message);
    }
  }

  const codexRecord = state.timing.phases.find(({ command }) => command.adapter === 'codex-jsonl-v1');
  if (codexRecord) {
    state.context = parseCodexJsonl(readFileSync(resolve(runDir, codexRecord.artifacts.stdout), 'utf8'));
    if (state.context.threadStartedCount !== 1) state.eligibility.exclusionReasons.push('codex-thread-not-fresh');
    if (state.context.turnCompletedCount !== 1) state.eligibility.exclusionReasons.push('codex-turn-count-invalid');
    if (state.context.turnFailedCount > 0) state.eligibility.exclusionReasons.push('codex-turn-failed');
    if (state.context.coverage !== 'complete') state.eligibility.exclusionReasons.push('codex-event-coverage-partial');
  }
  try {
    const afterIdentity = gitIdentity(arm.path);
    if (afterIdentity.commit !== arm.commit || afterIdentity.treeFingerprint !== arm.treeFingerprint) {
      state.eligibility.exclusionReasons.push('arm-checkout-mutated');
    }
  }
  catch (error) {
    state.eligibility.exclusionReasons.push('arm-checkout-mutated');
    state.eligibility.contaminationFlags.push(error.message);
  }
  if (identitySources.some(identitySourceChanged)) {
    state.eligibility.exclusionReasons.push('scenario-identity-input-mutated');
  }
  try {
    const evaluatorAfterIdentity = gitIdentity(evaluatorKit);
    if (
      evaluatorAfterIdentity.commit !== experiment.evaluator.kitCommit ||
      evaluatorAfterIdentity.treeFingerprint !== experiment.evaluator.kitTreeFingerprint
    ) {
      state.eligibility.exclusionReasons.push('evaluator-checkout-mutated');
    }
  }
  catch (error) {
    state.eligibility.exclusionReasons.push('evaluator-checkout-mutated');
    state.eligibility.contaminationFlags.push(error.message);
  }
  state.eligibility.exclusionReasons = [...new Set(state.eligibility.exclusionReasons)];
  state.eligibility.eligible = state.eligibility.exclusionReasons.length === 0;
  state.timing.finishedAt = now();
  state.timing.totalWallClockMs = Math.round((performance.now() - runStarted) * 1000) / 1000;
  state.resultFingerprint = runFingerprint(state);
  atomicJson(resolve(runDir, 'run.json'), state);
  if (unexpected) process.stderr.write(`Run ${runId} retained runner error: ${unexpected.message}\n`);
  return state;
}

export function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function medianAbsoluteDeviation(values) {
  const center = median(values);
  return center === null ? null : median(values.map((value) => Math.abs(value - center)));
}

function armSummary(runs, armId) {
  const selected = runs.filter((run) => !run.order.warmup && run.order.armId === armId);
  const eligible = selected.filter((run) => run.eligibility.eligible);
  const productValues = eligible.map((run) => run.timing.measuredProductWallClockMs);
  const outcomeValues = eligible.map((run) => run.timing.measuredOutcomeWallClockMs);
  const buildValues = eligible.map((run) => run.timing.measuredBuildWallClockMs);
  const harnessValues = eligible.map((run) => run.timing.measuredHarnessWallClockMs);
  const contextRows = eligible.map((run) => ({
    inputTokens: run.context?.usage?.inputTokens,
    cachedInputTokens: run.context?.usage?.cachedInputTokens,
    outputTokens: run.context?.usage?.outputTokens,
    totalTokens: run.context?.usage?.totalTokens,
    uncachedInputTokens: Number.isFinite(run.context?.usage?.inputTokens) && Number.isFinite(run.context?.usage?.cachedInputTokens)
      ? run.context.usage.inputTokens - run.context.usage.cachedInputTokens
      : null,
    toolOutputBytes: run.context?.toolOutputBytes,
    toolCallCount: run.context?.toolCallCount,
    verifierInvocationCount: run.context?.verifierInvocationCount,
    summaryReadCount: run.context?.summaryReadCount,
    fullReportReadCount: run.context?.fullReportReadCount,
    commandAttributionCoverage: run.context?.commandAttributionCoverage
  }));
  return {
    scheduledRuns: selected.length,
    eligibleRuns: eligible.length,
    successRate: selected.length ? eligible.length / selected.length : 0,
    medianProductWallClockMs: median(productValues),
    medianOutcomeWallClockMs: median(outcomeValues),
    medianBuildWallClockMs: median(buildValues),
    medianHarnessWallClockMs: median(harnessValues),
    medianAbsoluteDeviationMs: medianAbsoluteDeviation(productValues),
    context: {
      measuredRuns: contextRows.filter(({ totalTokens }) => Number.isFinite(totalTokens)).length,
      medianInputTokens: median(contextRows.map(({ inputTokens }) => inputTokens).filter(Number.isFinite)),
      medianCachedInputTokens: median(contextRows.map(({ cachedInputTokens }) => cachedInputTokens).filter(Number.isFinite)),
      medianUncachedInputTokens: median(contextRows.map(({ uncachedInputTokens }) => uncachedInputTokens).filter(Number.isFinite)),
      medianOutputTokens: median(contextRows.map(({ outputTokens }) => outputTokens).filter(Number.isFinite)),
      medianTotalTokens: median(contextRows.map(({ totalTokens }) => totalTokens).filter(Number.isFinite)),
      medianToolOutputBytes: median(contextRows.map(({ toolOutputBytes }) => toolOutputBytes).filter(Number.isFinite)),
      medianToolCallCount: median(contextRows.map(({ toolCallCount }) => toolCallCount).filter(Number.isFinite)),
      medianVerifierInvocationCount: median(contextRows.map(({ verifierInvocationCount }) => verifierInvocationCount).filter(Number.isFinite)),
      medianSummaryReadCount: median(contextRows.map(({ summaryReadCount }) => summaryReadCount).filter(Number.isFinite)),
      medianFullReportReadCount: median(contextRows.map(({ fullReportReadCount }) => fullReportReadCount).filter(Number.isFinite)),
      commandAttributionCoverage: [...new Set(
        contextRows.map(({ commandAttributionCoverage }) => commandAttributionCoverage).filter(Boolean)
      )].sort()
    },
    outcomeFingerprints: [...new Set(eligible.map((run) => run.quality?.outcomeFingerprint).filter(Boolean))],
    exclusionReasons: selected.flatMap((run) => run.eligibility.exclusionReasons.map((reason) => ({ runId: run.runId, reason })))
  };
}

function pairedDeltas(runs) {
  const measured = runs.filter((run) => !run.order.warmup).sort((left, right) => left.order.ordinal - right.order.ordinal);
  const pairs = [];
  for (let index = 0; index < measured.length; index += 2) {
    const pair = measured.slice(index, index + 2);
    const baseline = pair.find((run) => run.order.armId === 'baseline');
    const candidate = pair.find((run) => run.order.armId === 'candidate');
    if (!baseline || !candidate) {
      pairs.push({ pair: index / 2 + 1, eligible: false, reason: 'adjacent-pair-is-not-balanced' });
      continue;
    }
    if (!baseline.eligibility.eligible || !candidate.eligibility.eligible) {
      pairs.push({ pair: index / 2 + 1, eligible: false, baselineRunId: baseline.runId, candidateRunId: candidate.runId, reason: 'run-ineligible' });
      continue;
    }
    const improvementMs = baseline.timing.measuredProductWallClockMs - candidate.timing.measuredProductWallClockMs;
    pairs.push({
      pair: index / 2 + 1,
      eligible: true,
      baselineRunId: baseline.runId,
      candidateRunId: candidate.runId,
      improvementMs,
      improvementPercent: baseline.timing.measuredProductWallClockMs > 0
        ? improvementMs / baseline.timing.measuredProductWallClockMs * 100
        : null
    });
  }
  return pairs;
}

export function summarizeExperiment(experiment, runs) {
  const baseline = armSummary(runs, 'baseline');
  const candidate = armSummary(runs, 'candidate');
  const pairs = pairedDeltas(runs);
  const eligiblePairs = pairs.filter(({ eligible }) => eligible);
  const comparableQuality = (
    baseline.outcomeFingerprints.length === 1 &&
    candidate.outcomeFingerprints.length === 1 &&
    baseline.outcomeFingerprints[0] === candidate.outcomeFingerprints[0]
  );
  const minimumMet = baseline.eligibleRuns >= experiment.minimumValidRunsPerArm &&
    candidate.eligibleRuns >= experiment.minimumValidRunsPerArm;
  const improvementMs = baseline.medianProductWallClockMs !== null && candidate.medianProductWallClockMs !== null
    ? baseline.medianProductWallClockMs - candidate.medianProductWallClockMs
    : null;
  const improvementPercent = improvementMs !== null && baseline.medianProductWallClockMs > 0
    ? improvementMs / baseline.medianProductWallClockMs * 100
    : null;
  const thresholdsMet = improvementMs !== null &&
    improvementMs >= experiment.thresholds.minimumMedianImprovementMs &&
    improvementPercent >= experiment.thresholds.minimumMedianImprovementPercent &&
    (!experiment.thresholds.requireEveryPairFaster || (
      eligiblePairs.length > 0 && eligiblePairs.every((pair) => pair.improvementMs > 0)
    ));
  const percentReduction = (baselineValue, candidateValue) => (
    Number.isFinite(baselineValue) && baselineValue > 0 && Number.isFinite(candidateValue)
      ? (baselineValue - candidateValue) / baselineValue * 100
      : null
  );
  const tokenImprovementPercent = percentReduction(
    baseline.context.medianTotalTokens,
    candidate.context.medianTotalTokens
  );
  const toolOutputImprovementPercent = percentReduction(
    baseline.context.medianToolOutputBytes,
    candidate.context.medianToolOutputBytes
  );
  const qualityAndSampleGate = comparableQuality && minimumMet &&
    baseline.successRate === 1 && candidate.successRate === 1;
  const tokenCoverageComplete = baseline.context.measuredRuns === baseline.eligibleRuns &&
    candidate.context.measuredRuns === candidate.eligibleRuns;
  const tokenDecision = !qualityAndSampleGate
    ? 'not-eligible'
    : !tokenCoverageComplete
      ? 'not-measured'
    : tokenImprovementPercent === null
      ? 'not-measured'
      : tokenImprovementPercent > 0 &&
          tokenImprovementPercent >= experiment.thresholds.minimumTokenImprovementPercent
        ? 'improved'
        : 'not-improved';
  const toolOutputDecision = !qualityAndSampleGate
    ? 'not-eligible'
    : toolOutputImprovementPercent === null
      ? 'not-measured'
      : toolOutputImprovementPercent > 0 &&
          toolOutputImprovementPercent >= experiment.thresholds.minimumToolOutputImprovementPercent
        ? 'improved'
        : 'not-improved';
  const efficiencyImproved =
    tokenDecision === 'improved' ||
    toolOutputDecision === 'improved';
  const medianRegressionMs = improvementMs === null ? null : Math.max(0, -improvementMs);
  const medianRegressionPercent = improvementPercent === null
    ? null
    : Math.max(0, -improvementPercent);
  const speedRegressed =
    medianRegressionMs === null ||
    medianRegressionPercent === null ||
    medianRegressionMs > experiment.thresholds.maximumMedianRegressionMs ||
    medianRegressionPercent > experiment.thresholds.maximumMedianRegressionPercent;
  let decision = 'not-improved';
  const reasons = [];
  if (!minimumMet) {
    decision = 'insufficient-evidence';
    reasons.push('minimum-valid-runs-not-met');
  } else if (!comparableQuality) {
    decision = 'quality-not-equivalent';
    reasons.push('quality-outcome-fingerprints-differ');
  } else if (baseline.successRate !== 1 || candidate.successRate !== 1) {
    decision = 'quality-or-execution-failures';
    reasons.push('not-all-measured-runs-eligible');
  } else if (thresholdsMet) {
    decision = 'improved';
  } else if (speedRegressed) {
    if (efficiencyImproved) {
      decision = 'tradeoff';
      reasons.push('speed-regressed-beyond-efficiency-tolerance');
    } else {
      decision = 'regressed';
      reasons.push('speed-regressed-beyond-tolerance');
    }
  } else if (efficiencyImproved) {
    decision = 'efficiency-improved';
    reasons.push('speed-thresholds-not-met');
  } else {
    reasons.push('speed-thresholds-not-met');
  }
  const comparison = {
    schemaVersion: COMPARISON_SCHEMA,
    authority: AUTHORITY,
    experimentFingerprint: experiment.fingerprint,
    generatedAt: now(),
    decision,
    reasons,
    qualityComparable: comparableQuality,
    minimumSampleMet: minimumMet,
    thresholdsMet,
    speedNonRegressionMet: !speedRegressed,
    medianRegressionMs,
    medianRegressionPercent,
    efficiency: {
      tokenDecision,
      tokenCoverageComplete,
      tokenImprovementPercent,
      toolOutputDecision,
      toolOutputImprovementPercent,
      anyImprovement: efficiencyImproved
    },
    arms: { baseline, candidate },
    medianImprovementMs: improvementMs,
    medianImprovementPercent: improvementPercent,
    pairedDeltas: pairs,
    warmups: runs.filter((run) => run.order.warmup).map((run) => ({
      runId: run.runId,
      armId: run.order.armId,
      eligible: run.eligibility.eligible,
      exclusionReasons: run.eligibility.exclusionReasons,
      measuredBuildWallClockMs: run.timing.measuredBuildWallClockMs,
      measuredProductWallClockMs: run.timing.measuredProductWallClockMs,
      measuredHarnessWallClockMs: run.timing.measuredHarnessWallClockMs,
      measuredOutcomeWallClockMs: run.timing.measuredOutcomeWallClockMs,
      totalTokens: run.context?.usage?.totalTokens ?? null,
      toolOutputBytes: run.context?.toolOutputBytes ?? null
    })),
    evidenceRunFingerprints: runs.map(({ runId, resultFingerprint }) => ({ runId, resultFingerprint })),
    limitation: 'This decision is scenario-specific. General build-kit speed claims require multiple representative workloads.',
    fingerprint: null
  };
  const identity = structuredClone(comparison);
  delete identity.generatedAt;
  delete identity.fingerprint;
  comparison.fingerprint = sha256(canonicalJson(identity));
  return comparison;
}

function parseOptions(argv) {
  const command = argv.shift() ?? '';
  const options = { vars: {} };
  while (argv.length) {
    const key = argv.shift();
    if (!key?.startsWith('--')) throw new Error(`Unexpected argument: ${key}`);
    if (key === '--var') {
      const assignment = argv.shift() ?? '';
      const separator = assignment.indexOf('=');
      if (separator < 1) throw new Error('--var expects name=value.');
      options.vars[assignment.slice(0, separator)] = assignment.slice(separator + 1);
      continue;
    }
    const name = key.slice(2);
    if (name === 'help') options.help = true;
    else {
      const value = argv.shift();
      if (value === undefined) throw new Error(`Missing value for ${key}.`);
      options[name] = value;
    }
  }
  return { command, options };
}

function usage() {
  return `Usage:
  node scripts/benchmark-builds.mjs run --scenario <scenario.json> \\
    --baseline-kit <checkout> --candidate-kit <checkout> --evaluator-kit <checkout> \\
    --output <new-experiment-dir> [--sequence ABBA] [--warmups-per-arm 0] [--var name=value]

  node scripts/benchmark-builds.mjs report --experiment <experiment-dir>

The benchmark is diagnostic evidence only. It cannot authorize a Drupal build or
replace the authoritative verifier and independent quality evaluator.
`;
}

async function runCommand(options) {
  for (const required of ['scenario', 'baseline-kit', 'candidate-kit', 'evaluator-kit', 'output']) {
    if (!options[required]) throw new Error(`--${required} is required.`);
  }
  const scenarioPath = resolve(options.scenario);
  const scenarioDir = dirname(scenarioPath);
  const scenario = validateScenario(readJson(scenarioPath));
  const experimentDir = resolve(options.output);
  const variables = variableValues(scenario, options.vars);
  const armPaths = {
    baseline: resolve(options['baseline-kit']),
    candidate: resolve(options['candidate-kit'])
  };
  const evaluatorKit = resolve(options['evaluator-kit']);
  const protectedRoots = [
    repoRoot,
    scenarioDir,
    armPaths.baseline,
    armPaths.candidate,
    evaluatorKit,
    ...Object.values(variables).filter((value) => isAbsolute(value) && existsSync(value) && statSync(value).isDirectory())
  ];
  const projectedOutput = newOutputProjection(experimentDir);
  assertOutputDisjoint(projectedOutput, protectedRoots);
  mkdirSync(experimentDir, { recursive: true, mode: 0o700 });
  chmodSync(experimentDir, 0o700);
  const createdOutput = realpathSync(experimentDir);
  if (createdOutput !== projectedOutput) {
    throw new Error('Output resolution changed while the experiment directory was created.');
  }
  assertOutputDisjoint(createdOutput, protectedRoots);
  const identityContext = { repoRoot, scenarioDir, variables };
  const runnerPath = fileURLToPath(import.meta.url);
  const runnerBytes = readFileSync(runnerPath);
  const scenarioIdentitySources = scenario.identityFiles.map(({ id, path }) => {
    const resolvedPath = resolve(resolveTemplate(path, identityContext));
    if (
      !existsSync(resolvedPath) ||
      lstatSync(resolvedPath).isSymbolicLink() ||
      !lstatSync(resolvedPath).isFile()
    ) {
      throw new Error(`Scenario identity file ${id} is missing, unsafe, or not a regular file.`);
    }
    const bytes = readFileSync(resolvedPath);
    return { id, path: resolvedPath, bytes: bytes.length, sha256: sha256(bytes) };
  });
  if (scenarioIdentitySources.some(({ id }) => id === 'benchmark-runner')) {
    throw new Error('Scenario identity file id benchmark-runner is reserved for the mandatory runner identity.');
  }
  const identitySources = [
    {
      id: 'benchmark-runner',
      path: runnerPath,
      bytes: runnerBytes.length,
      sha256: sha256(runnerBytes)
    },
    ...scenarioIdentitySources
  ];
  const identityInputs = identitySources.map(({ id, bytes, sha256: fingerprint }) => ({ id, bytes, sha256: fingerprint }));
  const runtime = Object.fromEntries(Object.entries(scenario.runtime).map(([key, value]) => {
    const resolvedValue = resolveTemplate(value, identityContext);
    if (/[/\\]|:\/\/|@/.test(resolvedValue)) throw new Error(`scenario.runtime.${key} must be safe metadata, not a path, URL, or credential.`);
    return [key, resolvedValue];
  }));
  const arms = {
    baseline: { path: armPaths.baseline, ...gitIdentity(armPaths.baseline) },
    candidate: { path: armPaths.candidate, ...gitIdentity(armPaths.candidate) }
  };
  for (const [id, arm] of Object.entries(arms)) {
    arm.fingerprint = sha256(canonicalJson({ id, commit: arm.commit, treeFingerprint: arm.treeFingerprint }));
  }
  const evaluator = gitIdentity(evaluatorKit);
  const sequence = parseSequence(options.sequence ?? 'ABBA');
  const warmupsPerArm = Number(options['warmups-per-arm'] ?? 0);
  const schedule = buildSchedule(sequence, warmupsPerArm);
  const environment = environmentProjection();
  const scenarioFingerprint = sha256(canonicalJson({
    scenario,
    variableNames: Object.keys(variables).sort(),
    variableFingerprints: Object.fromEntries(Object.entries(variables).map(([key, value]) => [key, sha256(value)])),
    identityInputs,
    runtime
  }));
  const experiment = {
    schemaVersion: EXPERIMENT_SCHEMA,
    authority: AUTHORITY,
    experimentId: safeId(`${scenario.id.slice(0, 48)}-${Date.now().toString(36)}`, 'experimentId'),
    createdAt: now(),
    status: 'running',
    scenario: {
      id: scenario.id,
      description: scenario.description,
      fingerprint: scenarioFingerprint,
      measurementBoundary: scenario.measurementBoundary,
      identityInputs
    },
    variants: Object.entries(arms).map(([id, arm]) => ({
      id,
      kitCommit: arm.commit,
      kitTreeFingerprint: arm.treeFingerprint,
      fingerprint: arm.fingerprint
    })),
    evaluator: {
      kitCommit: evaluator.commit,
      kitTreeFingerprint: evaluator.treeFingerprint
    },
    environment,
    runtime,
    schedule,
    quality: scenario.quality,
    minimumValidRunsPerArm: scenario.minimumValidRunsPerArm,
    thresholds: scenario.thresholds,
    fingerprint: null
  };
  experiment.fingerprint = experimentFingerprint(experiment);
  atomicJson(resolve(experimentDir, 'experiment.json'), experiment);
  const runs = [];
  for (const order of schedule) {
    process.stdout.write(`Starting ${order.ordinal}/${schedule.length}: ${order.armId}${order.warmup ? ' warm-up' : ''}\n`);
    const run = await executeRun({
      experiment,
      scenario,
      scenarioDir,
      experimentDir,
      order,
      arm: arms[order.armId],
      evaluatorKit,
      variables,
      identitySources
    });
    runs.push(run);
    const outcome = run.eligibility.eligible ? 'eligible' : `ineligible (${run.eligibility.exclusionReasons.join(', ')})`;
    process.stdout.write(`Finished ${run.runId}: ${outcome}, measured ${run.timing.measuredBuildWallClockMs ?? 'n/a'} ms\n`);
    if (interruptionSignal) {
      experiment.status = 'interrupted';
      experiment.completedAt = now();
      atomicJson(resolve(experimentDir, 'experiment.json'), experiment);
      process.stderr.write(`Benchmark stopped after ${interruptionSignal}; preserved runs remain local and no comparison was issued.\n`);
      return interruptionSignal === 'SIGINT' ? 130 : 143;
    }
    if (order.warmup && !run.eligibility.eligible) {
      experiment.status = 'aborted';
      experiment.completedAt = now();
      atomicJson(resolve(experimentDir, 'experiment.json'), experiment);
      process.stderr.write(
        'Benchmark aborted after an ineligible warm-up; measured runs were not started and no comparison was issued.\n'
      );
      return 2;
    }
    if (
      run.eligibility.exclusionReasons.includes('cleanup-failed') ||
      run.eligibility.exclusionReasons.includes('cleanup-runner-error')
    ) {
      experiment.status = 'aborted';
      experiment.completedAt = now();
      atomicJson(resolve(experimentDir, 'experiment.json'), experiment);
      process.stderr.write(
        'Benchmark aborted after cleanup failure; later runs were not started and no comparison was issued.\n'
      );
      return 2;
    }
  }
  experiment.status = 'completed';
  experiment.completedAt = now();
  atomicJson(resolve(experimentDir, 'experiment.json'), experiment);
  validateExperimentEvidence(experiment, runs, { experimentDir });
  const comparison = summarizeExperiment(experiment, runs);
  atomicJson(resolve(experimentDir, 'comparison.json'), comparison);
  process.stdout.write(`${JSON.stringify(comparison, null, 2)}\n`);
  return ['improved', 'efficiency-improved', 'not-improved'].includes(comparison.decision) ? 0 : 2;
}

function reportCommand(options) {
  if (!options.experiment) throw new Error('--experiment is required.');
  const experimentDir = resolve(options.experiment);
  const experiment = readJson(resolve(experimentDir, 'experiment.json'));
  if (
    experiment.status !== 'completed' ||
    typeof experiment.completedAt !== 'string' ||
    !Number.isFinite(Date.parse(experiment.completedAt))
  ) {
    throw new Error('Only a completed experiment can produce a comparison report.');
  }
  const runnerIdentity = experiment.scenario?.identityInputs?.find(({ id }) => id === 'benchmark-runner');
  const currentRunnerBytes = readFileSync(fileURLToPath(import.meta.url));
  if (
    !runnerIdentity ||
    runnerIdentity.bytes !== currentRunnerBytes.length ||
    runnerIdentity.sha256 !== sha256(currentRunnerBytes)
  ) {
    throw new Error('The current benchmark runner does not match the experiment runner identity.');
  }
  const runs = experiment.schedule.map(({ ordinal, armId }) => (
    readJson(resolve(experimentDir, 'runs', `${String(ordinal).padStart(3, '0')}-trial`, 'run.json'))
  ));
  validateExperimentEvidence(experiment, runs, { experimentDir });
  const comparison = summarizeExperiment(experiment, runs);
  atomicJson(resolve(experimentDir, 'comparison.json'), comparison);
  process.stdout.write(`${JSON.stringify(comparison, null, 2)}\n`);
  return ['improved', 'efficiency-improved', 'not-improved'].includes(comparison.decision) ? 0 : 2;
}

async function main() {
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      interruptionSignal = signal;
      if (activeChild) killProcessGroup(activeChild, 'SIGTERM');
    });
  }
  const { command, options } = parseOptions(process.argv.slice(2));
  if (options.help || !command || command === '--help' || command === '-h') {
    process.stdout.write(usage());
    return 0;
  }
  if (command === 'run') return runCommand(options);
  if (command === 'report') return reportCommand(options);
  throw new Error(`Unknown command: ${command}\n\n${usage()}`);
}

if (
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  main().then((status) => {
    process.exitCode = status;
  }).catch((error) => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
