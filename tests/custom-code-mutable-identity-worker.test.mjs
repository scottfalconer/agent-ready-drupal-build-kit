import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  MUTABLE_IDENTITY_WORKER_REQUEST_SCHEMA,
  MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA
} from '../bin/mutable-identity-worker.mjs';

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const worker = join(repoRoot, 'bin', 'mutable-identity-worker.mjs');
const packagedWorker = join(
  repoRoot,
  'skills',
  'agent-ready-drupal-build-kit',
  'scripts',
  'mutable-identity-worker.mjs'
);
const defaultLimits = Object.freeze({
  files: 8,
  sourceBytesPerFile: 64 * 1024,
  sourceBytesTotal: 256 * 1024,
  nodesPerFile: 10_000,
  depth: 128,
  findings: 64
});

function hashBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function fileRecord(source, {
  fileId = 'SOURCE-0123456789abcdef',
  language = 'javascript',
  sourceBytes = Buffer.from(source, 'utf8'),
  sourceSha256 = hashBytes(sourceBytes)
} = {}) {
  return {
    fileId,
    language,
    sourceSha256,
    sourceBase64: sourceBytes.toString('base64')
  };
}

function workerRequest(files, limits = defaultLimits) {
  return {
    schemaVersion: MUTABLE_IDENTITY_WORKER_REQUEST_SCHEMA,
    limits: { ...limits },
    files
  };
}

function runWorker(request, { timeout = 5_000, workerPath = worker } = {}) {
  const result = spawnSync(process.execPath, [workerPath], {
    cwd: repoRoot,
    encoding: 'utf8',
    input: JSON.stringify(request),
    maxBuffer: 2 * 1024 * 1024,
    timeout
  });
  const output = result.stdout ? JSON.parse(result.stdout) : null;
  return { ...result, output };
}

function findingPairs(output) {
  return new Set(output.findings.map((finding) => `${finding.identityKind}:${finding.sinkKind}`));
}

test('worker uses the pinned Acorn bytes and a redacted subprocess result contract', () => {
  const vendorRoot = join(repoRoot, 'vendor', 'acorn', '8.15.0');
  const integrity = JSON.parse(readFileSync(join(vendorRoot, 'INTEGRITY.json'), 'utf8'));
  const source = readFileSync(join(vendorRoot, 'acorn.mjs'));
  const license = readFileSync(join(vendorRoot, 'LICENSE'));
  assert.equal(integrity.package, 'acorn');
  assert.equal(integrity.version, '8.15.0');
  assert.equal(hashBytes(source), `sha256:${integrity.files['acorn.mjs'].sha256}`);
  assert.equal(hashBytes(license), `sha256:${integrity.files.LICENSE.sha256}`);

  const secret = '/private-preview-never-emit';
  const code = `if (window.location.pathname === '${secret}') document.body.className = 'private';`;
  const first = runWorker(workerRequest([fileRecord(code)]));
  const second = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.output.schemaVersion, MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA);
  assert.equal(first.output.parser.name, 'acorn');
  assert.equal(first.output.parser.version, '8.15.0');
  assert.equal(first.output.completed, true);
  assert.equal(first.output.status, 'fail');
  assert.deepEqual(first.output, second.output);
  assert.equal(first.stdout.includes(secret), false);
  assert.equal(first.stdout.includes(fileRecord(code).sourceBase64), false);
  for (const finding of first.output.findings) {
    assert.deepEqual(Object.keys(finding).sort(), [
      'evidenceSha256', 'fileId', 'id', 'identityKind', 'node', 'ruleId', 'sinkKind'
    ]);
    assert.match(finding.id, /^AST-[a-f0-9]{16}$/);
    assert.match(finding.evidenceSha256, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Number.isSafeInteger(finding.node.start), true);
    assert.equal(Number.isSafeInteger(finding.node.end), true);
    assert.equal(typeof finding.node.type, 'string');
  }
});

test('the installable skill mirror runs against its mirrored Acorn package', () => {
  const result = runWorker(workerRequest([
    fileRecord("if (document.title === 'Hero') choose();")
  ]), { workerPath: packagedWorker });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.completed, true);
  assert.equal(result.output.status, 'fail');
  assert.ok(findingPairs(result.output).has('title_or_label:branch'));
});

test('direct and bracket-property path predicates fail without lexical masking', () => {
  const code = `
const currentPath = window['location']['pathname'];
if (currentPath === '/news') showNews();
if (settings.path.currentPath.startsWith('/catalog')) showCatalog();
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  const pathBranches = result.output.findings.filter((finding) =>
    finding.identityKind === 'alias_or_path' && finding.sinkKind === 'branch'
  );
  assert.equal(pathBranches.length, 2, JSON.stringify(result.output.findings));
  assert.ok(pathBranches.every((finding) => ['BinaryExpression', 'CallExpression'].includes(finding.node.type)));
});

test('computed lookups catch injected aliases, titles, and Media names', () => {
  const code = `
function choose(pathAlias, title) {
  const mediaName = settings['media']['name'];
  return [templates[pathAlias], variants[title], components[mediaName]];
}
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('alias_or_path:computed_lookup'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('title_or_label:computed_lookup'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:computed_lookup'), JSON.stringify(result.output.findings));
});

test('dynamic selectors, class variants, imports, and entity selectors are rejected', () => {
  const code = `
const title = document.title;
document.querySelector(\`.card--\${title}\`);
const mediaName = drupalSettings.media.name;
document.body.dataset.variant = mediaName;
import(\`./variants/\${title}.js\`);
entityStore.condition('title', 'News');
mediaStorage.loadByProperties({ name: 'Hero' });
entities[title];
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('title_or_label:presentation_selection'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:presentation_selection'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('title_or_label:entity_selection'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:entity_selection'), JSON.stringify(result.output.findings));
});

test('direct display and existence-only checks remain allowed', () => {
  const code = `
heading.textContent = document.title;
image.alt = drupalSettings.media.name;
image.setAttribute('aria-label', drupalSettings.media.name);
if (document.title) heading.hidden = false;
if (!drupalSettings.media.name) image.hidden = true;
function show(value) { heading.textContent = value; }
show(document.title);
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.completed, true);
  assert.equal(result.output.status, 'pass', JSON.stringify(result.output.findings));
  assert.deepEqual(result.output.findings, []);
  assert.deepEqual(result.output.blockers, []);
});

test('bounded fixed-point propagation catches reverse aliases, destructuring, and local returns', () => {
  const code = `
const first = second;
const second = third;
const third = document.title;
if (first === 'Hero') chooseHero();

const readMediaName = () => {
  const { ['name']: renamed } = drupalSettings.media;
  return renamed;
};
components[readMediaName()];

function readTitle() {
  const { title: renamedTitle } = content;
  return renamedTitle;
}
document.querySelector(\`.card--\${readTitle()}\`);

const helpers = { readPath: () => window.location.pathname };
variants[helpers.readPath()];
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('title_or_label:branch'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:computed_lookup'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('alias_or_path:computed_lookup'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('title_or_label:presentation_selection'), JSON.stringify(result.output.findings));
});

test('local function call arguments propagate into parameters before sink analysis', () => {
  const code = `
function choose(value) {
  if (value === 'Hero') chooseHero();
}
choose(document.title);
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  assert.ok(findingPairs(result.output).has('title_or_label:branch'), JSON.stringify(result.output.findings));
});

test('call propagation resolves arrows, function expressions, and local aliases', () => {
  const code = `
const choosePath = (value) => templates[value];
const aliasedChooser = choosePath;
aliasedChooser(window.location.pathname);

const chooseMedia = function (value) {
  return variants[value];
};
chooseMedia(drupalSettings.media.name);
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('alias_or_path:computed_lookup'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:computed_lookup'), JSON.stringify(result.output.findings));
});

test('call propagation projects object arguments through destructured parameters', () => {
  const code = `
const chooseTitle = ({ renamed }) => components[renamed];
chooseTitle({ renamed: document.title });

function chooseMedia({ ['renamed']: value }) {
  if (value === 'Hero') chooseHero();
}
chooseMedia({ renamed: drupalSettings.media.name });
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('title_or_label:computed_lookup'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:branch'), JSON.stringify(result.output.findings));
});

test('dynamic call targets and dynamic parameter destructuring fail closed', () => {
  const dynamicTarget = runWorker(workerRequest([fileRecord(`
const handlers = { hero(value) { return value; } };
handlers[mode](document.title);
`)]));
  assert.equal(dynamicTarget.status, 2, dynamicTarget.stderr);
  assert.ok(dynamicTarget.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_call_target'
  ), JSON.stringify(dynamicTarget.output.blockers));

  const dynamicParameter = runWorker(workerRequest([fileRecord(`
function choose({ [field]: value }) {
  if (value === 'Hero') chooseHero();
}
choose(record);
`)]));
  assert.equal(dynamicParameter.status, 2, dynamicParameter.stderr);
  assert.ok(dynamicParameter.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_branch'
  ), JSON.stringify(dynamicParameter.output.blockers));
});

test('unknown global and member call targets cannot consume mutable identity without a modeled sink', () => {
  const result = runWorker(workerRequest([fileRecord(`
Drupal.theme(document.title);
selector.chooseTemplate(node.title);
external.choose(document.title);
const choose = window.external.choose;
choose(document.title);
`)]));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.status, 'blocked');
  assert.ok(result.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_call_target'
  ), JSON.stringify(result.output.blockers));
  assert.ok(findingPairs(result.output).has('title_or_label:presentation_selection'),
    JSON.stringify(result.output.findings));
});

test('identity assigned through a static member remains tainted at later selection sinks', () => {
  const result = runWorker(workerRequest([fileRecord(`
const state = {};
state.selector = node.title;
if (state.selector === 'Hero') chooseHero();
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  assert.ok(findingPairs(result.output).has('title_or_label:branch'),
    JSON.stringify(result.output.findings));
});

test('computed destructuring keys cannot use mutable identity even when the selected value is display-only', () => {
  const result = runWorker(workerRequest([fileRecord(`
const { [document.title]: selected } = variants;
heading.textContent = selected;
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  assert.ok(findingPairs(result.output).has('title_or_label:computed_lookup'),
    JSON.stringify(result.output.findings));
});

test('dynamic entity field keys fail closed even when their variable names look innocuous', () => {
  const result = runWorker(workerRequest([fileRecord(`
const field = 'title';
entityStore.condition(field, 'Hero');
const mediaField = 'name';
mediaStorage.loadByProperties({ [mediaField]: 'Hero' });
`)]));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.status, 'blocked');
  assert.ok(result.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_entity_selection'
  ), JSON.stringify(result.output.blockers));
});

test('object aliases and parameter mutations preserve member taint', () => {
  const result = runWorker(workerRequest([fileRecord(`
const first = {};
const second = first;
second.selector = node.title;
if (first.selector === 'Hero') pick();

function setSelector(state, value) { state.variant = value; }
const state = {};
setSelector(state, node.title);
if (state.variant === 'Hero') pickVariant();
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  assert.ok(result.output.findings.filter(({ identityKind, sinkKind }) =>
    identityKind === 'title_or_label' && sinkKind === 'branch'
  ).length >= 2, JSON.stringify(result.output.findings));
});

test('for-of bindings and the implicit arguments object propagate identity into branches', () => {
  const result = runWorker(workerRequest([fileRecord(`
for (const value of [node.title]) {
  if (value === 'Hero') pick();
}
function choose() {
  if (arguments[0] === 'Hero') pickArgument();
}
choose(node.title);
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  assert.ok(result.output.findings.filter(({ identityKind, sinkKind }) =>
    identityKind === 'title_or_label' && sinkKind === 'branch'
  ).length >= 2, JSON.stringify(result.output.findings));
});

test('class member flow is shared across methods and unresolved class returns block at a sink', () => {
  const result = runWorker(workerRequest([fileRecord(`
class Selector {
  set() { this.selector = node.title; }
  choose() { if (this.selector === 'Hero') pick(); }
  read() { return node.title; }
}
if (new Selector().read() === 'Hero') pickRead();
`)]));
  assert.equal(result.status, 2, result.stderr);
  assert.ok(findingPairs(result.output).has('title_or_label:branch'),
    JSON.stringify(result.output.findings));
  assert.ok(result.output.blockers.some(({ code }) => code === 'unresolved_identity_branch'),
    JSON.stringify(result.output.blockers));
});

test('tagged templates, visibility assignments, and common URL forms are selection sinks', () => {
  const result = runWorker(workerRequest([fileRecord(`
theme\`card-\${node.title}\`;
card.hidden = node.title === 'Hero';
card.style.display = node.title === 'Hero' ? 'block' : 'none';
card.setAttribute('aria-hidden', node.title === 'Hero');
if (document.URL.endsWith('/news')) showNews();
if (window.location.toString().includes('/events')) showEvents();
components[window.location];
if (location === 'https://example.com/news') showLocation();
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('title_or_label:presentation_selection'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('alias_or_path:branch'), JSON.stringify(result.output.findings));
});

test('object getters, catch bindings, and destructuring member targets preserve identity flow', () => {
  const result = runWorker(workerRequest([fileRecord(`
const getterState = { get selector() { return node.title; } };
if (getterState.selector === 'Hero') pickGetter();
try { throw node.title; } catch (value) {
  if (value === 'Hero') pickCatch();
}
const state = {};
({ selector: state.selector } = { selector: node.title });
if (state.selector === 'Hero') pickDestructured();
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  assert.ok(result.output.findings.filter(({ identityKind, sinkKind }) =>
    identityKind === 'title_or_label' && sinkKind === 'branch'
  ).length >= 3, JSON.stringify(result.output.findings));
});

test('identity-bearing call spreads and prototype writes fail closed', () => {
  const result = runWorker(workerRequest([fileRecord(`
function setSelector(state, value) { state.selector = value; }
const state = {};
setSelector(...[state, node.title]);
if (state.selector === 'Hero') pickSpread();
function Constructor() {}
Constructor.prototype.selector = node.title;
`)]));
  assert.equal(result.status, 2, result.stderr);
  assert.ok(result.output.blockers.some(({ code }) => code === 'unresolved_identity_call_spread'),
    JSON.stringify(result.output.blockers));
  assert.ok(findingPairs(result.output).has('title_or_label:presentation_selection'),
    JSON.stringify(result.output.findings));
});

test('mutable identity cannot control navigation or resource-bearing properties', () => {
  const result = runWorker(workerRequest([fileRecord(`
link.href = node.title;
window.location.href = node.title;
form.action = node.title;
image.src = drupalSettings.media.name;
`)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.status, 'fail');
  const pairs = findingPairs(result.output);
  assert.ok(pairs.has('title_or_label:presentation_selection'), JSON.stringify(result.output.findings));
  assert.ok(pairs.has('media_name:presentation_selection'), JSON.stringify(result.output.findings));
});

test('dynamic execution blocks and identity-bearing class fields cannot bypass analysis', () => {
  const result = runWorker(workerRequest([fileRecord(`
eval('if (node.title === "Hero") pick()');
class StaticSelector { static selector = node.title; }
class PrivateSelector {
  #selector = node.title;
  choose() { if (this.#selector === 'Hero') pickPrivate(); }
}
`)]));
  assert.equal(result.status, 2, result.stderr);
  assert.ok(result.output.blockers.some(({ code }) => code === 'unsupported_dynamic_execution'),
    JSON.stringify(result.output.blockers));
  assert.ok(findingPairs(result.output).has('title_or_label:presentation_selection'),
    JSON.stringify(result.output.findings));
});

test('shared shorthand import identifiers remain valid for unused or direct display data', () => {
  const code = `
import { safeValue } from './identity.js';
heading.textContent = safeValue;
`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.output.completed, true);
  assert.equal(result.output.status, 'pass', JSON.stringify(result.output));
  assert.deepEqual(result.output.blockers, []);
  assert.deepEqual(result.output.findings, []);
});

test('named aliases, default imports, and namespace imports block across a two-file request', () => {
  const namedAndDefaultId = 'SOURCE-aaaaaaaaaaaaaaaa';
  const namespaceId = 'SOURCE-bbbbbbbbbbbbbbbb';
  const result = runWorker(workerRequest([
    fileRecord(`
import defaultIdentity, { mutableIdentity as safeAlias } from './identity.js';
if (safeAlias === 'Hero') chooseHero();
templates[defaultIdentity];
`, { fileId: namedAndDefaultId }),
    fileRecord(`
import * as identityBag from './identity.js';
document.querySelector(identityBag.selector);
entityStore.condition('id', identityBag.value);
`, { fileId: namespaceId })
  ]));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.status, 'blocked');
  assert.ok(result.output.blockers.some((entry) =>
    entry.fileId === namedAndDefaultId && entry.code === 'unresolved_identity_branch'
  ), JSON.stringify(result.output.blockers));
  assert.ok(result.output.blockers.some((entry) =>
    entry.fileId === namedAndDefaultId && entry.code === 'unresolved_identity_computed_lookup'
  ), JSON.stringify(result.output.blockers));
  assert.ok(result.output.blockers.some((entry) =>
    entry.fileId === namespaceId && entry.code === 'unresolved_identity_presentation_selection'
  ), JSON.stringify(result.output.blockers));
  assert.ok(result.output.blockers.some((entry) =>
    entry.fileId === namespaceId && entry.code === 'unresolved_identity_entity_selection'
  ), JSON.stringify(result.output.blockers));
});

test('unresolved dynamic destructuring and bracket aliases block only when they reach selection', () => {
  const destructured = runWorker(workerRequest([fileRecord(`
const { [field]: selected } = record;
templates[selected];
`)]));
  assert.equal(destructured.status, 2, destructured.stderr);
  assert.ok(destructured.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_computed_lookup'
  ), JSON.stringify(destructured.output.blockers));

  const bracketed = runWorker(workerRequest([fileRecord(`
const selected = record[field];
document.querySelector(selected);
`)]));
  assert.equal(bracketed.status, 2, bracketed.stderr);
  assert.ok(bracketed.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_presentation_selection'
  ), JSON.stringify(bracketed.output.blockers));

  const destructuredCallable = runWorker(workerRequest([fileRecord(`
const helpers = { read: () => document.title };
const { read: selected } = helpers;
templates[selected()];
`)]));
  assert.equal(destructuredCallable.status, 2, destructuredCallable.stderr);
  assert.ok(destructuredCallable.output.blockers.some((entry) =>
    entry.code === 'unresolved_identity_computed_lookup'
  ), JSON.stringify(destructuredCallable.output.blockers));

  const displayOnly = runWorker(workerRequest([fileRecord(`
const { [field]: selected } = record;
heading.textContent = selected;
`)]));
  assert.equal(displayOnly.status, 0, displayOnly.stderr);
  assert.equal(displayOnly.output.status, 'pass', JSON.stringify(displayOnly.output));
});

test('the propagation ceiling blocks instead of returning a partial pass', () => {
  const aliases = Array.from({ length: 70 }, (_, index) =>
    index === 69
      ? `const value${index} = document.title;`
      : `const value${index} = value${index + 1};`
  );
  aliases.push("if (value0 === 'Hero') chooseHero();");
  const result = runWorker(workerRequest([fileRecord(aliases.join('\n'))]));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.status, 'blocked');
  assert.ok(result.output.blockers.some((entry) => entry.code === 'propagation_limit'));
  assert.deepEqual(result.output.findings, []);
});

test('deep local call propagation also blocks at the fixed-point ceiling', () => {
  const functions = [];
  for (let index = 69; index >= 0; index -= 1) {
    functions.push(index === 69
      ? `function choose${index}(value) { if (value === 'Hero') chooseHero(); }`
      : `function choose${index}(value) { choose${index + 1}(value); }`);
  }
  functions.push('choose0(document.title);');
  const result = runWorker(workerRequest([fileRecord(functions.join('\n'))]));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.status, 'blocked');
  assert.ok(result.output.blockers.some((entry) => entry.code === 'propagation_limit'),
    JSON.stringify(result.output.blockers));
  assert.deepEqual(result.output.findings, []);
});

test('object alias facts have a hard ceiling and block before partial analysis', () => {
  const lines = Array.from({ length: 162 }, (_, index) => `const object${index} = {};`);
  for (let index = 0; index < 160; index += 1) {
    const previous = index === 0 ? 'object0' : `alias${index - 1}`;
    lines.push(`const alias${index} = condition ? ${previous} : object${index + 1};`);
  }
  lines.push('alias159.selector = document.title;');
  const result = runWorker(workerRequest([fileRecord(lines.join('\n'))]));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.status, 'blocked');
  assert.ok(result.output.blockers.some(({ code }) => code === 'object_alias_limit'),
    JSON.stringify(result.output.blockers));
  assert.deepEqual(result.output.findings, []);
});

test('AST positions remain exact across astral UTF-16 characters', () => {
  const code = `const marker = '😀';\nif (document.title === 'Hero') select();\n`;
  const result = runWorker(workerRequest([fileRecord(code)]));
  assert.equal(result.status, 0, result.stderr);
  const finding = result.output.findings.find((candidate) => candidate.sinkKind === 'branch');
  assert.ok(finding, JSON.stringify(result.output.findings));
  assert.equal(code.slice(finding.node.start, finding.node.end), "document.title === 'Hero'");
  assert.equal(finding.node.startLine, 2);
});

test('malformed comments and malformed JavaScript fail closed with redacted parse spans', () => {
  for (const code of [
    "/* unterminated comment if (window.location.pathname === '/secret') {}",
    "if (window.location.pathname === '/secret' { choose(); }"
  ]) {
    const result = runWorker(workerRequest([fileRecord(code)]));
    assert.equal(result.status, 2, result.stderr);
    assert.equal(result.output.completed, false);
    assert.equal(result.output.status, 'blocked');
    const parseBlocker = result.output.blockers.find((entry) => entry.code === 'parse_error');
    assert.ok(parseBlocker, JSON.stringify(result.output.blockers));
    assert.equal(parseBlocker.node.type, 'ParseError');
    assert.equal(result.stdout.includes('/secret'), false);
  }
});

test('TypeScript input is unsupported and TypeScript syntax cannot fall through as JavaScript', () => {
  const declared = runWorker(workerRequest([
    fileRecord('const title = document.title;', { language: 'typescript' })
  ]));
  assert.equal(declared.status, 2, declared.stderr);
  assert.ok(declared.output.blockers.some((entry) => entry.code === 'unsupported_typescript'));

  const disguised = runWorker(workerRequest([
    fileRecord("const title: string = document.title;")
  ]));
  assert.equal(disguised.status, 2, disguised.stderr);
  assert.ok(disguised.output.blockers.some((entry) => entry.code === 'parse_error'));
});

test('exact source hashes, strict base64, and UTF-8 decoding fail closed', () => {
  const hashMismatch = runWorker(workerRequest([
    fileRecord('const title = document.title;', { sourceSha256: `sha256:${'0'.repeat(64)}` })
  ]));
  assert.equal(hashMismatch.status, 2, hashMismatch.stderr);
  assert.ok(hashMismatch.output.blockers.some((entry) => entry.code === 'source_hash_mismatch'));

  const invalidBase64 = fileRecord('safe');
  invalidBase64.sourceBase64 = '!!!!';
  const base64Result = runWorker(workerRequest([invalidBase64]));
  assert.equal(base64Result.status, 2, base64Result.stderr);
  assert.ok(base64Result.output.blockers.some((entry) => entry.code === 'invalid_base64'));

  const invalidUtf8Bytes = Buffer.from([0xc3, 0x28]);
  const utf8Result = runWorker(workerRequest([
    fileRecord('', { sourceBytes: invalidUtf8Bytes })
  ]));
  assert.equal(utf8Result.status, 2, utf8Result.stderr);
  assert.ok(utf8Result.output.blockers.some((entry) => entry.code === 'invalid_utf8'));
});

test('file and source-byte ceilings block before partial analysis', () => {
  const twoFiles = [
    fileRecord('const a = 1;', { fileId: 'SOURCE-aaaaaaaaaaaaaaaa' }),
    fileRecord('const b = 2;', { fileId: 'SOURCE-bbbbbbbbbbbbbbbb' })
  ];
  const fileLimited = runWorker(workerRequest(twoFiles, { ...defaultLimits, files: 1 }));
  assert.equal(fileLimited.status, 2, fileLimited.stderr);
  assert.ok(fileLimited.output.blockers.some((entry) => entry.code === 'file_limit'));
  assert.deepEqual(fileLimited.output.files, []);

  const perFileLimited = runWorker(workerRequest([
    fileRecord('const title = document.title;')
  ], { ...defaultLimits, sourceBytesPerFile: 8 }));
  assert.equal(perFileLimited.status, 2, perFileLimited.stderr);
  assert.ok(perFileLimited.output.blockers.some((entry) => entry.code === 'source_bytes_per_file'));

  const totalLimited = runWorker(workerRequest(twoFiles, {
    ...defaultLimits,
    sourceBytesPerFile: 32,
    sourceBytesTotal: 20
  }));
  assert.equal(totalLimited.status, 2, totalLimited.stderr);
  assert.ok(totalLimited.output.blockers.some((entry) => entry.code === 'source_bytes_total'));
});

test('node and AST-depth ceilings fail closed with a typed span', () => {
  const nodeLimited = runWorker(workerRequest([
    fileRecord('const title = document.title; templates[title];')
  ], { ...defaultLimits, nodesPerFile: 5 }));
  assert.equal(nodeLimited.status, 2, nodeLimited.stderr);
  const nodeBlocker = nodeLimited.output.blockers.find((entry) => entry.code === 'node_limit');
  assert.ok(nodeBlocker, JSON.stringify(nodeLimited.output.blockers));
  assert.equal(typeof nodeBlocker.node.type, 'string');

  const deep = `const value = [[[[[[document.title]]]]]]; templates[value];`;
  const depthLimited = runWorker(workerRequest([
    fileRecord(deep)
  ], { ...defaultLimits, depth: 6 }));
  assert.equal(depthLimited.status, 2, depthLimited.stderr);
  const depthBlocker = depthLimited.output.blockers.find((entry) => entry.code === 'depth_limit');
  assert.ok(depthBlocker, JSON.stringify(depthLimited.output.blockers));
  assert.equal(typeof depthBlocker.node.type, 'string');
});

test('finding and stdout budgets block deterministically without raw output', () => {
  const code = `
templates[document.title];
variants[document.title];
components[document.title];
classes[document.title];
`;
  const result = runWorker(workerRequest([
    fileRecord(code)
  ], { ...defaultLimits, findings: 2 }));
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.output.findings.length, 2);
  assert.ok(result.output.blockers.some((entry) => entry.code === 'finding_limit'));
  assert.ok(Buffer.byteLength(result.stdout) < 16 * 1024, `unexpected stdout bytes: ${Buffer.byteLength(result.stdout)}`);
  assert.equal(result.stdout.includes('templates'), false);
  assert.equal(result.stdout.includes('components'), false);
});

test('the subprocess boundary supports a hard parent deadline', () => {
  const code = `const values = [${Array.from({ length: 20_000 }, (_, index) => index).join(',')}];`;
  const request = workerRequest([fileRecord(code)], {
    ...defaultLimits,
    sourceBytesPerFile: 256 * 1024,
    sourceBytesTotal: 256 * 1024,
    nodesPerFile: 100_000
  });
  const result = spawnSync(process.execPath, [worker], {
    cwd: repoRoot,
    encoding: 'utf8',
    input: JSON.stringify(request),
    maxBuffer: 2 * 1024 * 1024,
    timeout: 1
  });
  assert.equal(result.status, null);
  assert.equal(result.error?.code, 'ETIMEDOUT');
});
