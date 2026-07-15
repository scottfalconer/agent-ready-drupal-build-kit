#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MUTABLE_IDENTITY_WORKER_REQUEST_SCHEMA = 'public-kit.mutable-identity-worker-request.1';
export const MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA = 'public-kit.mutable-identity-worker-result.1';
export const MUTABLE_IDENTITY_WORKER_LIMITS = Object.freeze({
  files: 256,
  sourceBytesPerFile: 5 * 1024 * 1024,
  sourceBytesTotal: 100 * 1024 * 1024,
  nodesPerFile: 250_000,
  depth: 512,
  findings: 200
});

const MAX_STDIN_BYTES = 140 * 1024 * 1024;
const MAX_PROPAGATION_ROUNDS = 64;
const MAX_LOCAL_FUNCTION_TARGET_FACTS = 1_000_000;
const MAX_LOCAL_CALL_BINDING_APPLICATIONS = 2_000_000;
const MAX_OBJECT_ALIAS_FACTS = 1_000_000;
const ACORN_VERSION = '8.15.0';
const ACORN_SOURCE_SHA256 = 'b4c8c70200e72bae33cf1085e0ecb1e792c1b6924ed50cab817caf14f51bb249';
const ACORN_LICENSE_SHA256 = '76a876cf886ff9be2a8b5e2e86514fed06223c8c9f0c1e9ee9606e93841e00b7';
const FILE_ID_PATTERN = /^SOURCE-[a-f0-9]{16}$/;
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const IDENTITY_KINDS = new Set(['alias_or_path', 'title_or_label', 'media_name']);
const SINK_KINDS = new Set([
  'branch',
  'computed_lookup',
  'presentation_selection',
  'entity_selection'
]);
const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression'
]);
const IMPORT_SPECIFIER_TYPES = new Set([
  'ImportSpecifier',
  'ImportDefaultSpecifier',
  'ImportNamespaceSpecifier'
]);
const BRANCH_TYPES = new Set([
  'IfStatement',
  'ConditionalExpression',
  'WhileStatement',
  'DoWhileStatement',
  'ForStatement'
]);
const PRESENTATION_PROPERTIES = new Set([
  '#theme',
  'action',
  'ariahidden',
  'class',
  'classname',
  'component',
  'display',
  'hidden',
  'href',
  'id',
  'pluginid',
  'src',
  'template',
  'theme',
  'variant',
  'visibility',
  'viewmode'
]);
const DISPLAY_PROPERTIES = new Set([
  'alt',
  'arialabel',
  'innertext',
  'textcontent',
  'title'
]);
const SELECTING_CALLS = new Set([
  'endswith',
  'includes',
  'indexof',
  'match',
  'search',
  'startswith',
  'test'
]);
const ENTITY_CALLS = new Set([
  'condition',
  'findentity',
  'getentity',
  'loadbyproperties',
  'loadentity',
  'queryentity',
  'selectentity'
]);
const ENTITY_COLLECTION_CALLS = new Set(['filter', 'find', 'findindex']);
const PRESENTATION_CALLS = new Set([
  'closest',
  'getelementbyid',
  'matches',
  'queryselector',
  'queryselectorall'
]);
const PRESENTATION_SELECTION_CALLS = new Set([
  'choosecomponent',
  'choosetemplate',
  'choosetheme',
  'choosevariant',
  'chooseviewmode',
  'rendertemplate',
  'selectcomponent',
  'selecttemplate',
  'selecttheme',
  'selectvariant',
  'selectviewmode',
  'setcomponent',
  'settemplate',
  'settheme',
  'setvariant',
  'setviewmode',
  'theme'
]);
const CLASS_LIST_CALLS = new Set(['add', 'remove', 'replace', 'toggle']);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function isAstNode(value) {
  return Boolean(value) && typeof value === 'object' && typeof value.type === 'string' &&
    Number.isSafeInteger(value.start) && Number.isSafeInteger(value.end);
}

function nodeSpan(node, type = '') {
  if (!node || !Number.isSafeInteger(node.start) || !Number.isSafeInteger(node.end)) return null;
  const startLine = Number(node.loc?.start?.line ?? 0);
  const startColumn = Number(node.loc?.start?.column ?? 0);
  const endLine = Number(node.loc?.end?.line ?? startLine);
  const endColumn = Number(node.loc?.end?.column ?? startColumn);
  return {
    type: type || String(node.type ?? 'Unknown'),
    start: node.start,
    end: node.end,
    startLine: Number.isSafeInteger(startLine) && startLine >= 0 ? startLine : 0,
    startColumn: Number.isSafeInteger(startColumn) && startColumn >= 0 ? startColumn : 0,
    endLine: Number.isSafeInteger(endLine) && endLine >= 0 ? endLine : 0,
    endColumn: Number.isSafeInteger(endColumn) && endColumn >= 0 ? endColumn : 0
  };
}

function parseErrorSpan(error) {
  const position = Number.isSafeInteger(error?.pos) && error.pos >= 0 ? error.pos : 0;
  const line = Number.isSafeInteger(error?.loc?.line) && error.loc.line >= 0 ? error.loc.line : 0;
  const column = Number.isSafeInteger(error?.loc?.column) && error.loc.column >= 0
    ? error.loc.column
    : 0;
  return {
    type: 'ParseError',
    start: position,
    end: position,
    startLine: line,
    startColumn: column,
    endLine: line,
    endColumn: column
  };
}

function safeFileId(value) {
  const normalized = String(value ?? '');
  return FILE_ID_PATTERN.test(normalized) ? normalized : '';
}

function blocker(code, fileId = '', node = null) {
  const record = { code: String(code), fileId: safeFileId(fileId) };
  if (node && Number.isSafeInteger(node.startLine) && Number.isSafeInteger(node.endLine)) {
    record.node = {
      type: String(node.type ?? 'Unknown'),
      start: Number(node.start ?? 0),
      end: Number(node.end ?? 0),
      startLine: node.startLine,
      startColumn: Number(node.startColumn ?? 0),
      endLine: node.endLine,
      endColumn: Number(node.endColumn ?? 0)
    };
  } else if (node) {
    record.node = isAstNode(node) ? nodeSpan(node) : node;
  }
  return record;
}

function resultTemplate(limits = MUTABLE_IDENTITY_WORKER_LIMITS) {
  return {
    schemaVersion: MUTABLE_IDENTITY_WORKER_RESULT_SCHEMA,
    parser: {
      name: 'acorn',
      version: ACORN_VERSION,
      sourceSha256: `sha256:${ACORN_SOURCE_SHA256}`
    },
    bounded: true,
    limits: { ...limits },
    completed: false,
    status: 'blocked',
    files: [],
    findings: [],
    blockers: []
  };
}

function finalResult(result) {
  result.findings.sort((left, right) =>
    left.fileId.localeCompare(right.fileId) ||
    left.node.start - right.node.start ||
    left.node.end - right.node.end ||
    left.identityKind.localeCompare(right.identityKind) ||
    left.sinkKind.localeCompare(right.sinkKind)
  );
  result.blockers.sort((left, right) =>
    left.fileId.localeCompare(right.fileId) ||
    left.code.localeCompare(right.code) ||
    Number(left.node?.start ?? 0) - Number(right.node?.start ?? 0)
  );
  result.files.sort((left, right) => left.fileId.localeCompare(right.fileId));
  result.completed = result.blockers.length === 0 && result.files.every((file) => file.completed === true);
  result.status = result.blockers.length > 0
    ? 'blocked'
    : result.findings.length > 0
      ? 'fail'
      : 'pass';
  return result;
}

function resolvedLimits(value) {
  if (value === undefined) return { limits: { ...MUTABLE_IDENTITY_WORKER_LIMITS }, error: '' };
  if (!plainObject(value)) return { limits: { ...MUTABLE_IDENTITY_WORKER_LIMITS }, error: 'invalid_limits' };
  const allowed = new Set(Object.keys(MUTABLE_IDENTITY_WORKER_LIMITS));
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    return { limits: { ...MUTABLE_IDENTITY_WORKER_LIMITS }, error: 'invalid_limits' };
  }
  const limits = {};
  for (const [key, maximum] of Object.entries(MUTABLE_IDENTITY_WORKER_LIMITS)) {
    const requested = value[key] ?? maximum;
    if (!Number.isSafeInteger(requested) || requested <= 0 || requested > maximum) {
      return { limits: { ...MUTABLE_IDENTITY_WORKER_LIMITS }, error: 'invalid_limits' };
    }
    limits[key] = requested;
  }
  return { limits, error: '' };
}

function decodeBase64(value) {
  if (typeof value !== 'string' || value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return null;
  }
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value ? bytes : null;
}

async function loadPinnedAcorn() {
  const root = new URL(`../vendor/acorn/${ACORN_VERSION}/`, import.meta.url);
  const sourceUrl = new URL('acorn.mjs', root);
  const licenseUrl = new URL('LICENSE', root);
  const integrityUrl = new URL('INTEGRITY.json', root);
  if (
    statSync(sourceUrl).size !== 229_792 ||
    statSync(licenseUrl).size !== 1_099 ||
    statSync(integrityUrl).size > 16 * 1024
  ) {
    throw new Error('parser_integrity');
  }
  const source = readFileSync(sourceUrl);
  const license = readFileSync(licenseUrl);
  let integrity;
  try {
    integrity = JSON.parse(readFileSync(integrityUrl, 'utf8'));
  } catch {
    throw new Error('parser_integrity');
  }
  if (
    integrity?.package !== 'acorn' || integrity?.version !== ACORN_VERSION ||
    integrity?.files?.['acorn.mjs']?.bytes !== source.length ||
    integrity?.files?.['acorn.mjs']?.sha256 !== ACORN_SOURCE_SHA256 ||
    integrity?.files?.LICENSE?.bytes !== license.length ||
    integrity?.files?.LICENSE?.sha256 !== ACORN_LICENSE_SHA256 ||
    sha256(source) !== ACORN_SOURCE_SHA256 || sha256(license) !== ACORN_LICENSE_SHA256
  ) {
    throw new Error('parser_integrity');
  }
  const acorn = await import(`data:text/javascript;base64,${source.toString('base64')}`);
  if (acorn.version !== ACORN_VERSION || typeof acorn.parse !== 'function') {
    throw new Error('parser_integrity');
  }
  return acorn;
}

function parseJavaScript(acorn, source) {
  const options = {
    allowHashBang: true,
    ecmaVersion: 'latest',
    locations: true,
    preserveParens: true
  };
  let moduleError;
  try {
    return { ast: acorn.parse(source, { ...options, sourceType: 'module' }), sourceType: 'module' };
  } catch (error) {
    moduleError = error;
  }
  try {
    return { ast: acorn.parse(source, { ...options, sourceType: 'script' }), sourceType: 'script' };
  } catch (error) {
    return { ast: null, sourceType: '', error: error?.pos >= moduleError?.pos ? error : moduleError };
  }
}

function astChildren(node) {
  const children = [];
  for (const [key, value] of Object.entries(node)) {
    if (['type', 'start', 'end', 'loc', 'raw', 'regex', 'directive'].includes(key)) continue;
    if (isAstNode(value)) {
      children.push(value);
    } else if (Array.isArray(value)) {
      for (const child of value) if (isAstNode(child)) children.push(child);
    }
  }
  return children;
}

function indexAst(ast, limits) {
  const nodes = [];
  const parentByNode = new WeakMap();
  const depthByNode = new WeakMap();
  const states = new WeakMap();
  const stack = [{ node: ast, parent: null, depth: 1, exiting: false }];
  let maxDepth = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current.exiting) {
      states.set(current.node, 2);
      continue;
    }
    const state = states.get(current.node) ?? 0;
    if (state === 1) {
      return { nodes, parentByNode, depthByNode, maxDepth, blocker: blocker('ast_cycle', '', current.node) };
    }
    maxDepth = Math.max(maxDepth, current.depth);
    if (current.depth > limits.depth) {
      return { nodes, parentByNode, depthByNode, maxDepth, blocker: blocker('depth_limit', '', current.node) };
    }
    if (state === 2) continue;
    states.set(current.node, 1);
    parentByNode.set(current.node, current.parent);
    depthByNode.set(current.node, current.depth);
    nodes.push(current.node);
    if (nodes.length > limits.nodesPerFile) {
      return { nodes, parentByNode, depthByNode, maxDepth, blocker: blocker('node_limit', '', current.node) };
    }
    const children = astChildren(current.node);
    stack.push({ ...current, exiting: true });
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: children[index], parent: current.node, depth: current.depth + 1, exiting: false });
    }
  }
  nodes.sort((left, right) => left.start - right.start || right.end - left.end || left.type.localeCompare(right.type));
  return { nodes, parentByNode, depthByNode, maxDepth, blocker: null };
}

function patternIdentifiers(pattern) {
  const names = [];
  const stack = [pattern];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node) continue;
    if (node.type === 'Identifier') {
      names.push(node.name);
    } else if (node.type === 'RestElement') {
      stack.push(node.argument);
    } else if (node.type === 'AssignmentPattern') {
      stack.push(node.left);
    } else if (node.type === 'ArrayPattern') {
      stack.push(...node.elements);
    } else if (node.type === 'ObjectPattern') {
      for (const property of node.properties) stack.push(property.type === 'Property' ? property.value : property.argument);
    }
  }
  return names;
}

function staticPatternPropertyName(property) {
  if (!property || property.type !== 'Property') return '';
  if (!property.computed && property.key?.type === 'Identifier') return property.key.name;
  const key = unwrapExpression(property.key);
  if (key?.type === 'Literal' && ['string', 'number'].includes(typeof key.value)) {
    return String(key.value);
  }
  if (key?.type === 'TemplateLiteral' && key.expressions.length === 0) {
    return key.quasis[0]?.value?.cooked ?? '';
  }
  return '';
}

function projectedObjectSource(sourceNode, propertyName) {
  const source = unwrapExpression(sourceNode);
  if (source?.type !== 'ObjectExpression') return sourceNode;
  for (const property of source.properties) {
    if (property.type === 'Property' && staticPatternPropertyName(property) === propertyName) {
      return property.value;
    }
  }
  return sourceNode;
}

function projectedArraySource(sourceNode, index) {
  const source = unwrapExpression(sourceNode);
  return source?.type === 'ArrayExpression' ? source.elements[index] ?? null : sourceNode;
}

function propertyPathKinds(path, sourceNode) {
  const kinds = new Set();
  const normalizedPath = path.map(normalizedName);
  const last = normalizedPath.at(-1) ?? '';
  if (['title', 'label'].includes(last)) kinds.add('title_or_label');
  if (
    ['alias', 'canonicalpath', 'currentpath', 'currenturi', 'pathalias', 'pathname', 'pathinfo',
      'requestpath', 'requesturi'].includes(last)
  ) {
    kinds.add('alias_or_path');
  }
  const sourceContext = memberPath(sourceNode).map(normalizedName);
  if (last === 'name' && [...normalizedPath.slice(0, -1), ...sourceContext].some((part) =>
    /(?:media|asset)/.test(part)
  )) {
    kinds.add('media_name');
  }
  return kinds;
}

function sourceHasDynamicBracket(node) {
  let current = unwrapExpression(node);
  while (current?.type === 'MemberExpression') {
    if (current.computed && !staticComputedPropertyName(current.property)) return true;
    current = unwrapExpression(current.object);
  }
  return false;
}

function patternBindingSpecs(pattern, sourceNode, path = [], inheritedUnresolved = false) {
  const specs = [];
  const visit = (current, source, propertyPath, unresolved) => {
    if (!current) return;
    if (current.type === 'MemberExpression') {
      specs.push({
        member: current,
        sourceNode: source,
        kinds: propertyPathKinds(propertyPath, source),
        unresolved: unresolved || sourceHasDynamicBracket(current) || sourceHasDynamicBracket(source),
        callableUnresolved: false
      });
      return;
    }
    if (current.type === 'Identifier') {
      const kinds = propertyPathKinds(propertyPath, source);
      specs.push({
        name: current.name,
        sourceNode: source,
        kinds,
        unresolved: unresolved || sourceHasDynamicBracket(source) ||
          (normalizedName(propertyPath.at(-1)) === 'name' && !kinds.has('media_name')),
        callableUnresolved: propertyPath.length > 0 && !FUNCTION_TYPES.has(unwrapExpression(source)?.type)
      });
      return;
    }
    if (current.type === 'AssignmentPattern') {
      visit(current.left, source, propertyPath, unresolved);
      visit(current.left, current.right, [], unresolved);
      return;
    }
    if (current.type === 'RestElement') {
      visit(current.argument, source, propertyPath, true);
      return;
    }
    if (current.type === 'ObjectPattern') {
      for (const property of current.properties) {
        if (property.type === 'RestElement') {
          visit(property.argument, source, propertyPath, true);
          continue;
        }
        const propertyName = staticPatternPropertyName(property);
        if (!propertyName) {
          visit(property.value, source, propertyPath, true);
          continue;
        }
        visit(
          property.value,
          projectedObjectSource(source, propertyName),
          [...propertyPath, propertyName],
          unresolved
        );
      }
      return;
    }
    if (current.type === 'ArrayPattern') {
      for (let index = 0; index < current.elements.length; index += 1) {
        const element = current.elements[index];
        if (!element) continue;
        const projected = projectedArraySource(source, index);
        visit(element, projected, propertyPath, unresolved || projected === source);
      }
    }
  };
  visit(pattern, sourceNode, path, inheritedUnresolved);
  return specs;
}

function buildScopes(astIndex) {
  let nextScopeId = 0;
  const programScope = { id: nextScopeId++, parent: null, bindings: new Set(), parameters: new Set() };
  const scopeByNode = new WeakMap([[astIndex.nodes[0], programScope]]);
  const orderedByDepth = [...astIndex.nodes].sort((left, right) =>
    astIndex.depthByNode.get(left) - astIndex.depthByNode.get(right) || left.start - right.start
  );
  for (const node of orderedByDepth) {
    if (node.type === 'Program') {
      scopeByNode.set(node, programScope);
      continue;
    }
    const parent = astIndex.parentByNode.get(node);
    const parentScope = scopeByNode.get(parent) ?? programScope;
    if (FUNCTION_TYPES.has(node.type) || node.type === 'CatchClause') {
      scopeByNode.set(node, { id: nextScopeId++, parent: parentScope, bindings: new Set(), parameters: new Set() });
    } else {
      scopeByNode.set(node, parentScope);
    }
  }
  for (const node of astIndex.nodes) {
    const scope = scopeByNode.get(node) ?? programScope;
    if (node.type === 'FunctionDeclaration' && node.id) {
      const parentScope = scope.parent ?? programScope;
      parentScope.bindings.add(node.id.name);
    }
    if (FUNCTION_TYPES.has(node.type)) {
      if (node.type === 'FunctionExpression' && node.id) scope.bindings.add(node.id.name);
      if (node.type !== 'ArrowFunctionExpression') scope.bindings.add('arguments');
      for (const parameter of node.params) {
        for (const name of patternIdentifiers(parameter)) {
          scope.bindings.add(name);
          scope.parameters.add(name);
        }
      }
    } else if (node.type === 'CatchClause' && node.param) {
      for (const name of patternIdentifiers(node.param)) scope.bindings.add(name);
    } else if (node.type === 'VariableDeclarator') {
      for (const name of patternIdentifiers(node.id)) scope.bindings.add(name);
    } else if (node.type === 'ClassDeclaration' && node.id) {
      scope.bindings.add(node.id.name);
    } else if (IMPORT_SPECIFIER_TYPES.has(node.type) && node.local?.type === 'Identifier') {
      scope.bindings.add(node.local.name);
    }
  }
  return { programScope, scopeByNode };
}

function buildFunctionReturns(astIndex) {
  const returnsByFunction = new WeakMap();
  for (const node of astIndex.nodes) {
    if (FUNCTION_TYPES.has(node.type)) returnsByFunction.set(node, []);
  }
  for (const node of astIndex.nodes) {
    if (node.type !== 'ReturnStatement' || !node.argument) continue;
    for (let parent = astIndex.parentByNode.get(node); parent; parent = astIndex.parentByNode.get(parent)) {
      if (!FUNCTION_TYPES.has(parent.type)) continue;
      returnsByFunction.get(parent)?.push(node.argument);
      break;
    }
  }
  for (const node of astIndex.nodes) {
    if (node.type === 'ArrowFunctionExpression' && node.body.type !== 'BlockStatement') {
      returnsByFunction.get(node)?.push(node.body);
    }
  }
  return returnsByFunction;
}

function buildLocalObjectMembers(astIndex, scopes) {
  const objects = new Set();
  const members = new Map();
  const record = (pattern, value, scope) => {
    const object = unwrapExpression(value);
    if (pattern?.type !== 'Identifier' || object?.type !== 'ObjectExpression') return;
    const objectKey = bindingKey(scope, pattern.name);
    objects.add(objectKey);
    for (const property of object.properties) {
      if (property.type !== 'Property') continue;
      const propertyName = staticPatternPropertyName(property);
      if (!propertyName) continue;
      const memberKey = `${objectKey}\u0000${normalizedName(propertyName)}`;
      const values = members.get(memberKey) ?? [];
      values.push(property.value);
      members.set(memberKey, values);
    }
  };
  for (const node of astIndex.nodes) {
    const scope = scopes.scopeByNode.get(node) ?? scopes.programScope;
    if (node.type === 'VariableDeclarator') record(node.id, node.init, scope);
    if (node.type === 'AssignmentExpression' && node.operator === '=') record(node.left, node.right, scope);
  }
  return { objects, members };
}

function bindingKey(scope, name) {
  for (let current = scope; current; current = current.parent) {
    if (current.bindings.has(name)) return `${current.id}:${name}`;
  }
  return `global:${name}`;
}

function normalizedName(value) {
  return String(value ?? '').replace(/[^A-Za-z0-9]+/g, '').toLowerCase();
}

function identityKindFromName(value) {
  const name = normalizedName(value);
  if (/media(?:name|label)$/.test(name)) return 'media_name';
  if (/^(?:alias|canonicalpath|currentpath|currenturi|location|pathalias|requestpath|requesturi)$/.test(name)) {
    return 'alias_or_path';
  }
  if (/^(?:title|label)$/.test(name) || /(?:entity|node|item)(?:title|label)$/.test(name)) {
    return 'title_or_label';
  }
  return '';
}

function unwrapExpression(node) {
  let current = node;
  while (current && ['ChainExpression', 'ParenthesizedExpression'].includes(current.type)) {
    current = current.expression;
  }
  return current;
}

function staticPropertyName(node) {
  const current = unwrapExpression(node);
  if (!current) return '';
  if (current.type === 'Identifier') return current.name;
  if (current.type === 'Literal' && typeof current.value === 'string') return current.value;
  if (current.type === 'TemplateLiteral' && current.expressions.length === 0) {
    return current.quasis[0]?.value?.cooked ?? '';
  }
  return '';
}

function staticComputedPropertyName(node) {
  const current = unwrapExpression(node);
  if (current?.type === 'Literal' && ['string', 'number'].includes(typeof current.value)) {
    return String(current.value);
  }
  if (current?.type === 'TemplateLiteral' && current.expressions.length === 0) {
    return current.quasis[0]?.value?.cooked ?? '';
  }
  return '';
}

function memberPath(node) {
  const parts = [];
  let current = unwrapExpression(node);
  while (current?.type === 'MemberExpression') {
    const property = current.computed
      ? staticComputedPropertyName(current.property)
      : current.property?.type === 'Identifier'
        ? current.property.name
        : '';
    if (!property) return [];
    parts.unshift(property);
    current = unwrapExpression(current.object);
  }
  if (current?.type === 'Identifier') parts.unshift(current.name);
  else if (current?.type === 'ThisExpression') parts.unshift('this');
  else return [];
  return parts;
}

function thisBindingKey(node, context) {
  let owner = node;
  while ((owner = context.astIndex.parentByNode.get(owner))) {
    if (!FUNCTION_TYPES.has(owner.type) || owner.type === 'ArrowFunctionExpression') continue;
    const parent = context.astIndex.parentByNode.get(owner);
    if (parent?.type === 'MethodDefinition') {
      const classBody = context.astIndex.parentByNode.get(parent);
      const classNode = context.astIndex.parentByNode.get(classBody);
      return `this:class:${classNode?.start ?? classBody?.start}:${classNode?.end ?? classBody?.end}`;
    }
    if (parent?.type === 'Property') {
      const object = context.astIndex.parentByNode.get(parent);
      if (object?.type === 'ObjectExpression') return `this:object:${object.start}:${object.end}`;
    }
    return `this:function:${owner.start}:${owner.end}`;
  }
  return 'this:global';
}

function objectIdentityKeys(node, context) {
  const current = unwrapExpression(node);
  if (!current) return new Set();
  if (current.type === 'Identifier') {
    const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
    const binding = bindingKey(scope, current.name);
    return new Set(context.objectAliases.get(binding) ?? []);
  }
  if (current.type === 'ThisExpression') return new Set([thisBindingKey(current, context)]);
  if (['ObjectExpression', 'ArrayExpression', 'NewExpression'].includes(current.type)) {
    return new Set([`object:${current.type}:${current.start}:${current.end}`]);
  }
  if (current.type === 'ConditionalExpression') {
    return new Set([
      ...objectIdentityKeys(current.consequent, context),
      ...objectIdentityKeys(current.alternate, context)
    ]);
  }
  if (current.type === 'LogicalExpression') {
    return new Set([
      ...objectIdentityKeys(current.left, context),
      ...objectIdentityKeys(current.right, context)
    ]);
  }
  return new Set();
}

function staticMemberBindingKeys(node, context) {
  const properties = [];
  let current = unwrapExpression(node);
  while (current?.type === 'MemberExpression') {
    const property = current.computed
      ? staticComputedPropertyName(current.property)
      : current.property?.type === 'Identifier'
        ? current.property.name
        : '';
    if (!property) return [];
    properties.unshift(normalizedName(property));
    current = unwrapExpression(current.object);
  }
  if (properties.length === 0) return [];
  const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
  let roots = new Set();
  if (current?.type === 'Identifier') {
    const binding = bindingKey(scope, current.name);
    roots = new Set([binding, ...(context.objectAliases.get(binding) ?? [])]);
  } else if (current?.type === 'ThisExpression') {
    roots.add(thisBindingKey(current, context));
  }
  return [...roots].map((root) => `${root}\u0000${properties.join('\u0000')}`);
}

function callName(node) {
  const current = unwrapExpression(node);
  if (!current) return '';
  if (current.type === 'Identifier') return normalizedName(current.name);
  if (current.type === 'MemberExpression') {
    return normalizedName(current.computed ? staticComputedPropertyName(current.property) : current.property?.name);
  }
  return '';
}

function directIdentityKinds(node) {
  const kinds = new Set();
  const current = unwrapExpression(node);
  if (!current) return kinds;
  if (current.type === 'MemberExpression') {
    const path = memberPath(current).map(normalizedName);
    const last = path.at(-1) ?? '';
    const context = path.slice(0, -1);
    const mediaContext = context.some((part) => /(?:media|asset)/.test(part));
    if (mediaContext && ['label', 'name'].includes(last)) {
      kinds.add('media_name');
    } else if (['label', 'title'].includes(last)) {
      kinds.add('title_or_label');
    }
    if (
      ['alias', 'canonicalpath', 'currentpath', 'currenturi', 'pathalias', 'pathname', 'pathinfo', 'requesturi'].includes(last) ||
      (last === 'href' && context.includes('location')) ||
      (last === 'location' && context.some((part) => ['document', 'window'].includes(part))) ||
      (['documenturi', 'url'].includes(last) && context.includes('document'))
    ) {
      kinds.add('alias_or_path');
    }
  } else if (current.type === 'CallExpression') {
    const name = callName(current.callee);
    if (['getalias', 'getaliasbypath', 'getpath', 'getpathbyalias', 'getpathinfo', 'getrequesturi'].includes(name)) {
      kinds.add('alias_or_path');
    }
    if (['tostring', 'valueof'].includes(name)) {
      const path = memberPath(unwrapExpression(current.callee)?.object).map(normalizedName);
      if (path.includes('location')) kinds.add('alias_or_path');
    }
    if (['getname', 'label'].includes(name)) {
      const path = memberPath(unwrapExpression(current.callee)?.object).map(normalizedName);
      if (path.some((part) => /(?:media|asset)/.test(part))) kinds.add('media_name');
      else kinds.add('title_or_label');
    }
    if (['gettitle'].includes(name)) kinds.add('title_or_label');
  }
  return kinds;
}

function expressionChildren(node, descendFunctions = false) {
  const current = unwrapExpression(node);
  if (!current) return [];
  if (FUNCTION_TYPES.has(current.type) && !descendFunctions) return [];
  if (current.type === 'MemberExpression') {
    return [current.object, ...(current.computed ? [current.property] : [])].filter(Boolean);
  }
  if (current.type === 'Property') {
    return [...(current.computed ? [current.key] : []), current.value].filter(Boolean);
  }
  if (current.type === 'MethodDefinition' || current.type === 'PropertyDefinition') {
    return [...(current.computed ? [current.key] : []), current.value].filter(Boolean);
  }
  return astChildren(current);
}

function localObjectMember(node, context) {
  const member = unwrapExpression(node);
  const object = unwrapExpression(member?.object);
  if (member?.type !== 'MemberExpression' || object?.type !== 'Identifier') {
    return { knownObject: false, values: [] };
  }
  const scope = context.scopes.scopeByNode.get(object) ?? context.scopes.programScope;
  const objectKey = bindingKey(scope, object.name);
  if (!context.localObjectMembers.objects.has(objectKey)) return { knownObject: false, values: [] };
  const propertyName = member.computed
    ? staticComputedPropertyName(member.property)
    : member.property?.name ?? '';
  if (!propertyName) return { knownObject: true, values: [] };
  return {
    knownObject: true,
    values: context.localObjectMembers.members.get(`${objectKey}\u0000${normalizedName(propertyName)}`) ?? []
  };
}

function resolveLocalFunctionTargets(node, context) {
  const targets = new Set();
  const stack = [node];
  const seen = new WeakSet();
  let unresolved = false;
  let pending = false;
  while (stack.length > 0) {
    const current = unwrapExpression(stack.pop());
    if (!isAstNode(current) || seen.has(current)) continue;
    seen.add(current);
    if (FUNCTION_TYPES.has(current.type)) {
      targets.add(current);
      continue;
    }
    if (current.type === 'Identifier') {
      const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
      const key = bindingKey(scope, current.name);
      const resolved = context.functionTargets.get(key);
      for (const target of resolved ?? []) targets.add(target);
      if (context.functionTargetUnresolved.has(key)) unresolved = true;
      if (!resolved || resolved.size === 0) {
        if (key.startsWith('global:')) unresolved = true;
        else pending = true;
      }
      continue;
    }
    if (current.type === 'MemberExpression') {
      const local = localObjectMember(current, context);
      if (sourceHasDynamicBracket(current)) unresolved = true;
      if (local.knownObject) {
        if (local.values.length === 0) unresolved = true;
        else stack.push(...local.values);
      } else unresolved = true;
      continue;
    }
    if (current.type === 'ConditionalExpression') {
      stack.push(current.consequent, current.alternate);
      continue;
    }
    if (current.type === 'LogicalExpression') {
      stack.push(current.left, current.right);
      continue;
    }
    if (current.type === 'SequenceExpression') {
      if (current.expressions.length > 0) stack.push(current.expressions.at(-1));
      continue;
    }
    if (current.type === 'AssignmentExpression') {
      stack.push(current.right);
      continue;
    }
    if (current.type === 'CallExpression' || current.type === 'NewExpression') {
      unresolved = true;
    }
  }
  return { targets, unresolved, pending };
}

function mergeLocalFunctionTargets(context, key, targets, node) {
  if (targets.size === 0) return false;
  const current = context.functionTargets.get(key) ?? new Set();
  let changed = false;
  for (const target of targets) {
    if (current.has(target)) continue;
    if (context.functionTargetFactCount >= context.functionTargetFactLimit) {
      context.functionTargetLimitNode ??= node;
      break;
    }
    current.add(target);
    context.functionTargetFactCount += 1;
    changed = true;
  }
  if (changed) context.functionTargets.set(key, current);
  return changed;
}

function callableKinds(node, context) {
  const kinds = new Set();
  const stack = [node];
  const seen = new WeakSet();
  while (stack.length > 0) {
    const current = unwrapExpression(stack.pop());
    if (!isAstNode(current) || seen.has(current)) continue;
    seen.add(current);
    if (current.type === 'Identifier') {
      const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
      for (const kind of context.callableTaints.get(bindingKey(scope, current.name)) ?? []) kinds.add(kind);
      continue;
    }
    if (FUNCTION_TYPES.has(current.type)) {
      for (const returned of context.returnsByFunction.get(current) ?? []) {
        for (const kind of identityKinds(returned, context)) kinds.add(kind);
      }
      continue;
    }
    if (current.type === 'MemberExpression') {
      const local = localObjectMember(current, context);
      for (const value of local.values) {
        const target = unwrapExpression(value);
        if (FUNCTION_TYPES.has(target?.type)) {
          for (const returned of context.returnsByFunction.get(target) ?? []) {
            for (const kind of identityKinds(returned, context)) kinds.add(kind);
          }
        } else if (target?.type === 'Identifier') {
          const scope = context.scopes.scopeByNode.get(target) ?? context.scopes.programScope;
          for (const kind of context.callableTaints.get(bindingKey(scope, target.name)) ?? []) kinds.add(kind);
        }
      }
      continue;
    }
    if (current.type === 'CallExpression') continue;
    for (const child of expressionChildren(current)) stack.push(child);
  }
  return kinds;
}

function callableIsUnresolved(node, context) {
  const stack = [node];
  const seen = new WeakSet();
  while (stack.length > 0) {
    const current = unwrapExpression(stack.pop());
    if (!isAstNode(current) || seen.has(current)) continue;
    seen.add(current);
    if (current.type === 'Identifier') {
      const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
      if (context.callableUnresolved.has(bindingKey(scope, current.name))) return true;
      continue;
    }
    if (FUNCTION_TYPES.has(current.type)) {
      for (const returned of context.returnsByFunction.get(current) ?? []) {
        if (expressionIsUnresolved(returned, context)) return true;
      }
      continue;
    }
    if (current.type === 'CallExpression') return true;
    if (current.type === 'MemberExpression') {
      const local = localObjectMember(current, context);
      if (!local.knownObject) return true;
      if (local.knownObject && local.values.length === 0) return true;
      for (const value of local.values) {
        const target = unwrapExpression(value);
        if (FUNCTION_TYPES.has(target?.type)) {
          for (const returned of context.returnsByFunction.get(target) ?? []) {
            if (expressionIsUnresolved(returned, context)) return true;
          }
        } else if (target?.type === 'Identifier') {
          const scope = context.scopes.scopeByNode.get(target) ?? context.scopes.programScope;
          if (context.callableUnresolved.has(bindingKey(scope, target.name))) return true;
        } else {
          return true;
        }
      }
      return sourceHasDynamicBracket(current);
    }
    for (const child of expressionChildren(current)) stack.push(child);
  }
  return false;
}

function expressionIsUnresolved(node, context, { descendFunctions = false } = {}) {
  const stack = [node];
  const seen = new WeakSet();
  while (stack.length > 0) {
    const current = unwrapExpression(stack.pop());
    if (!isAstNode(current) || seen.has(current)) continue;
    seen.add(current);
    if (current.type === 'Identifier') {
      const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
      if (context.unresolvedValues.has(bindingKey(scope, current.name))) return true;
      continue;
    }
    if (current.type === 'CallExpression' && !callTargetIsModeled(current) &&
      callableIsUnresolved(current.callee, context)) return true;
    if (current.type === 'MemberExpression') {
      if (sourceHasDynamicBracket(current)) return true;
      if (staticMemberBindingKeys(current, context).some((key) => context.unresolvedMembers.has(key))) return true;
      const local = localObjectMember(current, context);
      const resolutionKey = staticMemberBindingKeys(current, context)[0] ?? '';
      if (!resolutionKey || !context.activeUnresolvedMemberResolutions.has(resolutionKey)) {
        if (resolutionKey) context.activeUnresolvedMemberResolutions.add(resolutionKey);
        let localUnresolved = false;
        for (const value of local.values) {
          const target = unwrapExpression(value);
          if (FUNCTION_TYPES.has(target?.type)) {
            for (const returned of context.returnsByFunction.get(target) ?? []) {
              if (expressionIsUnresolved(returned, context)) {
                localUnresolved = true;
                break;
              }
            }
          } else if (expressionIsUnresolved(target, context)) localUnresolved = true;
          if (localUnresolved) break;
        }
        if (resolutionKey) context.activeUnresolvedMemberResolutions.delete(resolutionKey);
        if (localUnresolved) return true;
      }
    }
    for (const child of expressionChildren(current, descendFunctions)) stack.push(child);
  }
  return false;
}

function identityKinds(node, context, { descendFunctions = false } = {}) {
  const kinds = new Set();
  const stack = [node];
  const seen = new WeakSet();
  while (stack.length > 0) {
    const current = unwrapExpression(stack.pop());
    if (!isAstNode(current) || seen.has(current)) continue;
    seen.add(current);
    for (const kind of directIdentityKinds(current)) kinds.add(kind);
    if (current.type === 'CallExpression') {
      for (const kind of callableKinds(current.callee, context)) kinds.add(kind);
    }
    if (current.type === 'MemberExpression') {
      for (const memberKey of staticMemberBindingKeys(current, context)) {
        for (const kind of context.memberTaints.get(memberKey) ?? []) kinds.add(kind);
      }
      const local = localObjectMember(current, context);
      const resolutionKey = staticMemberBindingKeys(current, context)[0] ?? '';
      if (!resolutionKey || !context.activeMemberResolutions.has(resolutionKey)) {
        if (resolutionKey) context.activeMemberResolutions.add(resolutionKey);
        for (const value of local.values) {
          const target = unwrapExpression(value);
          if (FUNCTION_TYPES.has(target?.type)) {
            for (const returned of context.returnsByFunction.get(target) ?? []) {
              for (const kind of identityKinds(returned, context)) kinds.add(kind);
            }
          } else {
            for (const kind of identityKinds(target, context)) kinds.add(kind);
          }
        }
        if (resolutionKey) context.activeMemberResolutions.delete(resolutionKey);
      }
    }
    if (current.type === 'Identifier') {
      const scope = context.scopes.scopeByNode.get(current) ?? context.scopes.programScope;
      const key = bindingKey(scope, current.name);
      for (const kind of context.taints.get(key) ?? []) kinds.add(kind);
      if (key.startsWith('global:')) {
        const named = identityKindFromName(current.name);
        if (named) kinds.add(named);
      }
      continue;
    }
    for (const child of expressionChildren(current, descendFunctions)) stack.push(child);
  }
  return kinds;
}

function mergeBindingKinds(map, key, kinds) {
  if (kinds.size === 0) return false;
  const current = map.get(key) ?? new Set();
  let changed = false;
  for (const kind of kinds) {
    if (current.has(kind)) continue;
    current.add(kind);
    changed = true;
  }
  if (changed) map.set(key, current);
  return changed;
}

function markBindingUnresolved(set, key, unresolved) {
  if (!unresolved || set.has(key)) return false;
  set.add(key);
  return true;
}

function mergeObjectAliases(context, key, aliases, node) {
  if (aliases.size === 0) return false;
  const current = context.objectAliases.get(key) ?? new Set();
  let changed = false;
  for (const alias of aliases) {
    if (current.has(alias)) continue;
    if (context.objectAliasFactCount >= context.objectAliasFactLimit) {
      context.objectAliasLimitNode ??= node;
      break;
    }
    current.add(alias);
    context.objectAliasFactCount += 1;
    changed = true;
  }
  if (changed) context.objectAliases.set(key, current);
  return changed;
}

function applyBindingSpecs(
  pattern,
  sourceNode,
  scope,
  context,
  { seedNames = false, forceUnresolved = false } = {}
) {
  let changed = false;
  for (const spec of patternBindingSpecs(pattern, sourceNode, [], forceUnresolved)) {
    if (spec.member) {
      const valueKinds = new Set(spec.kinds);
      if (spec.sourceNode) {
        for (const kind of identityKinds(spec.sourceNode, context)) valueKinds.add(kind);
      }
      for (const memberKey of staticMemberBindingKeys(spec.member, context)) {
        changed = mergeBindingKinds(context.memberTaints, memberKey, valueKinds) || changed;
        changed = markBindingUnresolved(
          context.unresolvedMembers,
          memberKey,
          spec.unresolved || (spec.sourceNode && expressionIsUnresolved(spec.sourceNode, context))
        ) || changed;
      }
      continue;
    }
    const key = bindingKey(scope, spec.name);
    const valueKinds = new Set(spec.kinds);
    if (seedNames) {
      const named = identityKindFromName(spec.name);
      if (named) valueKinds.add(named);
    }
    if (spec.sourceNode) {
      for (const kind of identityKinds(spec.sourceNode, context)) valueKinds.add(kind);
      changed = mergeObjectAliases(context, key, objectIdentityKeys(spec.sourceNode, context), spec.sourceNode) || changed;
    }
    changed = mergeBindingKinds(context.taints, key, valueKinds) || changed;
    changed = markBindingUnresolved(
      context.unresolvedValues,
      key,
      spec.unresolved || (spec.sourceNode && expressionIsUnresolved(spec.sourceNode, context))
    ) || changed;
    if (spec.sourceNode) {
      changed = mergeBindingKinds(context.callableTaints, key, callableKinds(spec.sourceNode, context)) || changed;
      const functionResolution = resolveLocalFunctionTargets(spec.sourceNode, context);
      changed = mergeLocalFunctionTargets(context, key, functionResolution.targets, spec.sourceNode) || changed;
      changed = markBindingUnresolved(
        context.functionTargetUnresolved,
        key,
        forceUnresolved || spec.callableUnresolved || functionResolution.unresolved
      ) || changed;
    }
    changed = markBindingUnresolved(
      context.callableUnresolved,
      key,
      spec.callableUnresolved || (spec.sourceNode && callableIsUnresolved(spec.sourceNode, context))
    ) || changed;
  }
  return changed;
}

function applyAssignment(node, context) {
  const scope = context.scopes.scopeByNode.get(node) ?? context.scopes.programScope;
  if (node.type === 'VariableDeclarator') {
    return applyBindingSpecs(node.id, node.init, scope, context);
  }
  if (node.type === 'AssignmentExpression') {
    if (node.left?.type === 'MemberExpression') {
      const keys = staticMemberBindingKeys(node.left, context);
      let changed = false;
      for (const key of keys) {
        changed = mergeBindingKinds(context.memberTaints, key, identityKinds(node.right, context)) || changed;
        changed = markBindingUnresolved(
          context.unresolvedMembers,
          key,
          expressionIsUnresolved(node.right, context)
        ) || changed;
      }
      return changed;
    }
    return applyBindingSpecs(node.left, node.right, scope, context);
  }
  if (node.type === 'ForOfStatement' || node.type === 'ForInStatement') {
    const target = node.left?.type === 'VariableDeclaration'
      ? node.left.declarations[0]?.id
      : node.left;
    if (!target) return false;
    return applyBindingSpecs(target, node.right, scope, context, {
      forceUnresolved: node.type === 'ForInStatement'
    });
  }
  return false;
}

function applyCatchBinding(node, context) {
  if (node.type !== 'CatchClause' || !node.param) return false;
  const tryStatement = context.astIndex.parentByNode.get(node);
  const scope = context.scopes.scopeByNode.get(node) ?? context.scopes.programScope;
  const sources = [];
  if (tryStatement?.type === 'TryStatement') {
    for (const candidate of context.astIndex.nodes) {
      if (candidate.type !== 'ThrowStatement' || !candidate.argument) continue;
      let parent = candidate;
      while ((parent = context.astIndex.parentByNode.get(parent))) {
        if (parent === tryStatement.block) {
          sources.push(candidate.argument);
          break;
        }
        if (FUNCTION_TYPES.has(parent.type)) break;
      }
    }
  }
  if (sources.length === 0) {
    return applyBindingSpecs(node.param, null, scope, context, { forceUnresolved: true });
  }
  let changed = false;
  for (const source of sources) {
    changed = applyBindingSpecs(node.param, source, scope, context) || changed;
  }
  return changed;
}

function applyFunctionBinding(node, context) {
  if (node.type === 'FunctionDeclaration' && node.id) {
    const functionScope = context.scopes.scopeByNode.get(node) ?? context.scopes.programScope;
    const targetScope = functionScope.parent ?? context.scopes.programScope;
    const key = bindingKey(targetScope, node.id.name);
    const kindsChanged = mergeBindingKinds(context.callableTaints, key, callableKinds(node, context));
    const unresolvedChanged = markBindingUnresolved(
      context.callableUnresolved,
      key,
      callableIsUnresolved(node, context)
    );
    const targetChanged = mergeLocalFunctionTargets(context, key, new Set([node]), node);
    return kindsChanged || unresolvedChanged || targetChanged;
  }
  if (node.type === 'FunctionExpression' && node.id) {
    const scope = context.scopes.scopeByNode.get(node) ?? context.scopes.programScope;
    const key = bindingKey(scope, node.id.name);
    const kindsChanged = mergeBindingKinds(context.callableTaints, key, callableKinds(node, context));
    const unresolvedChanged = markBindingUnresolved(
      context.callableUnresolved,
      key,
      callableIsUnresolved(node, context)
    );
    const targetChanged = mergeLocalFunctionTargets(context, key, new Set([node]), node);
    return kindsChanged || unresolvedChanged || targetChanged;
  }
  return false;
}

function applyParameterBindings(node, context) {
  if (!FUNCTION_TYPES.has(node.type)) return false;
  const scope = context.scopes.scopeByNode.get(node) ?? context.scopes.programScope;
  let changed = false;
  for (const parameter of node.params) {
    changed = applyBindingSpecs(parameter, null, scope, context, { seedNames: true }) || changed;
  }
  return changed;
}

function applyImportBinding(node, context) {
  if (!IMPORT_SPECIFIER_TYPES.has(node.type) || node.local?.type !== 'Identifier') return false;
  const scope = context.scopes.scopeByNode.get(node) ?? context.scopes.programScope;
  const key = bindingKey(scope, node.local.name);
  const valueChanged = markBindingUnresolved(context.unresolvedValues, key, true);
  const callableChanged = markBindingUnresolved(context.callableUnresolved, key, true);
  const targetChanged = markBindingUnresolved(context.functionTargetUnresolved, key, true);
  return valueChanged || callableChanged || targetChanged;
}

function applyLocalCallArguments(node, context) {
  if (!['CallExpression', 'NewExpression'].includes(node.type)) return false;
  const resolution = resolveLocalFunctionTargets(node.callee, context);
  let changed = false;
  const apply = (pattern, source, scope, forceUnresolved = false) => {
    if (context.localCallBindingApplicationCount >= context.localCallBindingApplicationLimit) {
      context.localCallBindingLimitNode ??= node;
      return;
    }
    context.localCallBindingApplicationCount += 1;
    changed = applyBindingSpecs(pattern, source, scope, context, { forceUnresolved }) || changed;
  };
  for (const target of resolution.targets) {
    const scope = context.scopes.scopeByNode.get(target) ?? context.scopes.programScope;
    if (target.type !== 'ArrowFunctionExpression') {
      const argumentsRoot = bindingKey(scope, 'arguments');
      for (let index = 0; index < node.arguments.length; index += 1) {
        const argument = node.arguments[index];
        const expression = argument.type === 'SpreadElement' ? argument.argument : argument;
        const key = `${argumentsRoot}\u0000${index}`;
        changed = mergeBindingKinds(context.memberTaints, key, identityKinds(expression, context)) || changed;
        changed = markBindingUnresolved(
          context.unresolvedMembers,
          key,
          argument.type === 'SpreadElement' || expressionIsUnresolved(expression, context)
        ) || changed;
      }
    }
    let argumentIndex = 0;
    for (let parameterIndex = 0; parameterIndex < target.params.length; parameterIndex += 1) {
      const parameter = target.params[parameterIndex];
      if (parameter.type === 'RestElement') {
        for (; argumentIndex < node.arguments.length; argumentIndex += 1) {
          const argument = node.arguments[argumentIndex];
          apply(
            parameter.argument,
            argument.type === 'SpreadElement' ? argument.argument : argument,
            scope,
            argument.type === 'SpreadElement'
          );
          if (context.localCallBindingLimitNode) return changed;
        }
        break;
      }
      const argument = node.arguments[argumentIndex];
      if (!argument) continue;
      if (argument.type === 'SpreadElement') {
        for (let remaining = parameterIndex; remaining < target.params.length; remaining += 1) {
          const remainingParameter = target.params[remaining];
          apply(
            remainingParameter.type === 'RestElement' ? remainingParameter.argument : remainingParameter,
            argument.argument,
            scope,
            true
          );
          if (context.localCallBindingLimitNode) return changed;
        }
        break;
      }
      apply(parameter, argument, scope);
      if (context.localCallBindingLimitNode) return changed;
      argumentIndex += 1;
    }
  }
  return changed;
}

function containsSelectingOperation(node) {
  const stack = [node];
  const seen = new WeakSet();
  while (stack.length > 0) {
    const current = unwrapExpression(stack.pop());
    if (!isAstNode(current) || seen.has(current)) continue;
    seen.add(current);
    if (current.type === 'BinaryExpression' &&
      ['==', '!=', '===', '!==', '<', '<=', '>', '>=', 'in', 'instanceof'].includes(current.operator)) {
      return true;
    }
    if (current.type === 'CallExpression' && SELECTING_CALLS.has(callName(current.callee))) return true;
    for (const child of expressionChildren(current)) stack.push(child);
  }
  return false;
}

function objectHasEntitySemantics(node) {
  return memberPath(node).map(normalizedName).some((part) =>
    /^(?:entities|entity|media|node|nodes)$/.test(part)
  );
}

function objectHasClassList(node) {
  return memberPath(node).map(normalizedName).includes('classlist');
}

function staticLiteralValue(node) {
  const current = unwrapExpression(node);
  if (current?.type === 'Literal' && typeof current.value === 'string') return normalizedName(current.value);
  if (current?.type === 'TemplateLiteral' && current.expressions.length === 0) {
    return normalizedName(current.quasis[0]?.value?.cooked ?? '');
  }
  return '';
}

function entityFieldKinds(call) {
  const kinds = new Set();
  const calleeName = callName(call.callee);
  const calleePath = memberPath(unwrapExpression(call.callee)?.object).map(normalizedName);
  const mediaContext = calleePath.some((part) => /(?:media|asset)/.test(part));
  if (calleeName === 'condition') {
    const field = staticLiteralValue(call.arguments[0]);
    if (['label', 'title'].includes(field)) kinds.add('title_or_label');
    if (field === 'name' && mediaContext) kinds.add('media_name');
  }
  if (calleeName === 'loadbyproperties') {
    for (const argument of call.arguments) {
      if (argument?.type !== 'ObjectExpression') continue;
      for (const property of argument.properties) {
        if (property.type !== 'Property') continue;
        const field = property.computed ? staticPropertyName(property.key) : staticPropertyName(property.key);
        const normalized = normalizedName(field);
        if (['label', 'title'].includes(normalized)) kinds.add('title_or_label');
        if (normalized === 'name' && mediaContext) kinds.add('media_name');
      }
    }
  }
  return kinds;
}

function entityFieldSelectionIsUnresolved(call) {
  const calleeName = callName(call.callee);
  if (calleeName === 'condition') {
    return !staticLiteralValue(call.arguments[0]);
  }
  if (calleeName !== 'loadbyproperties') return false;
  const object = unwrapExpression(call.arguments[0]);
  if (object?.type !== 'ObjectExpression') return true;
  return object.properties.some((property) =>
    property.type !== 'Property' || (property.computed && !staticComputedPropertyName(property.key))
  );
}

function analyzeSinks(node, context, addFinding, addUnresolved) {
  const inspect = (expression, sinkKind, findingNode = expression, options = {}) => {
    if (!expression) return;
    if (expressionIsUnresolved(expression, context, options)) addUnresolved(sinkKind, findingNode);
    for (const kind of identityKinds(expression, context, options)) addFinding(kind, sinkKind, findingNode);
  };

  if (BRANCH_TYPES.has(node.type)) {
    const test = node.test;
    if (test && containsSelectingOperation(test)) {
      inspect(test, 'branch');
    }
  } else if (node.type === 'SwitchStatement') {
    inspect(node.discriminant, 'branch');
  }

  if (node.type === 'MemberExpression' && node.computed) {
    inspect(node.property, 'computed_lookup', node);
    if (objectHasEntitySemantics(node.object)) inspect(node.property, 'entity_selection', node);
  }

  if (['Property', 'MethodDefinition', 'PropertyDefinition'].includes(node.type) && node.computed) {
    inspect(node.key, 'computed_lookup', node);
  }

  if (node.type === 'PropertyDefinition' && node.value) {
    inspect(node.value, 'presentation_selection', node);
  }

  if (node.type === 'AssignmentExpression' && node.left?.type === 'MemberExpression') {
    const property = normalizedName(node.left.computed
      ? staticPropertyName(node.left.property)
      : node.left.property?.name);
    const objectPath = memberPath(node.left.object).map(normalizedName);
    const presentationProperty = PRESENTATION_PROPERTIES.has(property) || objectPath.includes('prototype') ||
      (objectPath.includes('dataset') && ['component', 'theme', 'variant', 'viewmode'].includes(property));
    if (presentationProperty && !DISPLAY_PROPERTIES.has(property)) {
      inspect(node.right, 'presentation_selection', node);
    }
  }

  if (node.type === 'Property') {
    const property = normalizedName(node.computed ? staticPropertyName(node.key) : staticPropertyName(node.key));
    if (PRESENTATION_PROPERTIES.has(property) && !DISPLAY_PROPERTIES.has(property)) {
      inspect(node.value, 'presentation_selection', node);
    }
  }

  if (node.type === 'ImportExpression') {
    inspect(node.source, 'presentation_selection', node);
  }

  if (node.type === 'TaggedTemplateExpression') {
    inspect(node.quasi, 'presentation_selection', node);
  }

  if (node.type !== 'CallExpression') return;
  const name = callName(node.callee);
  const callee = unwrapExpression(node.callee);
  const callObject = callee?.type === 'MemberExpression' ? callee.object : null;
  if (PRESENTATION_CALLS.has(name) || PRESENTATION_SELECTION_CALLS.has(name)) {
    for (const argument of node.arguments) inspect(argument, 'presentation_selection', node);
  }
  if (CLASS_LIST_CALLS.has(name) && objectHasClassList(callObject)) {
    for (const argument of node.arguments) inspect(argument, 'presentation_selection', node);
  }
  if (name === 'setattribute') {
    const attribute = staticLiteralValue(node.arguments[0]);
    if (PRESENTATION_PROPERTIES.has(attribute) || /^(?:data)?(?:component|theme|variant|viewmode)$/.test(attribute)) {
      inspect(node.arguments[1], 'presentation_selection', node);
    }
  }
  if (ENTITY_CALLS.has(name)) {
    const kinds = entityFieldKinds(node);
    if (entityFieldSelectionIsUnresolved(node)) addUnresolved('entity_selection', node);
    for (const argument of node.arguments) {
      if (expressionIsUnresolved(argument, context, { descendFunctions: true })) {
        addUnresolved('entity_selection', node);
      }
      for (const kind of identityKinds(argument, context, { descendFunctions: true })) kinds.add(kind);
    }
    for (const kind of kinds) addFinding(kind, 'entity_selection', node);
  } else if (ENTITY_COLLECTION_CALLS.has(name) && objectHasEntitySemantics(callObject)) {
    for (const argument of node.arguments) {
      inspect(argument, 'entity_selection', node, { descendFunctions: true });
    }
  }
}

function callTargetIsModeled(node) {
  const name = callName(node.callee);
  const callee = unwrapExpression(node.callee);
  const callObject = callee?.type === 'MemberExpression' ? callee.object : null;
  if (directIdentityKinds(node).size > 0) return true;
  if (PRESENTATION_CALLS.has(name) || PRESENTATION_SELECTION_CALLS.has(name) ||
    SELECTING_CALLS.has(name) || ENTITY_CALLS.has(name)) {
    return true;
  }
  if (ENTITY_COLLECTION_CALLS.has(name) && objectHasEntitySemantics(callObject)) return true;
  if (CLASS_LIST_CALLS.has(name) && objectHasClassList(callObject)) return true;
  if (name !== 'setattribute') return false;
  const attribute = staticLiteralValue(node.arguments[0]);
  return ['alt', 'arialabel', 'title'].includes(attribute) ||
    PRESENTATION_PROPERTIES.has(attribute) ||
    /^(?:data)?(?:component|theme|variant|viewmode)$/.test(attribute);
}

function analyzeAst(file, source, ast, sourceType, limits, aggregate) {
  const astIndex = indexAst(ast, limits);
  const fileResult = {
    fileId: file.fileId,
    sourceSha256: file.sourceSha256,
    sourceBytes: Buffer.byteLength(source, 'utf8'),
    parserSourceType: sourceType,
    completed: false,
    status: 'blocked',
    nodeCount: astIndex.nodes.length,
    maxDepth: astIndex.maxDepth,
    findingCount: 0
  };
  if (astIndex.blocker) {
    aggregate.blockers.push({ ...astIndex.blocker, fileId: file.fileId });
    return fileResult;
  }
  const scopes = buildScopes(astIndex);
  const localObjectMembers = buildLocalObjectMembers(astIndex, scopes);
  const context = {
    astIndex,
    scopes,
    taints: new Map(),
    objectAliases: new Map(),
    objectAliasFactCount: 0,
    objectAliasFactLimit: Math.max(
      64,
      Math.min(MAX_OBJECT_ALIAS_FACTS, astIndex.nodes.length * 4)
    ),
    objectAliasLimitNode: null,
    memberTaints: new Map(),
    activeMemberResolutions: new Set(),
    activeUnresolvedMemberResolutions: new Set(),
    callableTaints: new Map(),
    unresolvedValues: new Set(),
    unresolvedMembers: new Set(),
    callableUnresolved: new Set(),
    functionTargets: new Map(),
    functionTargetUnresolved: new Set(),
    functionTargetFactCount: 0,
    functionTargetFactLimit: Math.max(
      64,
      Math.min(MAX_LOCAL_FUNCTION_TARGET_FACTS, astIndex.nodes.length * 4)
    ),
    functionTargetLimitNode: null,
    localCallBindingApplicationCount: 0,
    localCallBindingApplicationLimit: Math.max(
      64,
      Math.min(MAX_LOCAL_CALL_BINDING_APPLICATIONS, astIndex.nodes.length * 16)
    ),
    localCallBindingLimitNode: null,
    returnsByFunction: buildFunctionReturns(astIndex),
    localObjectMembers
  };
  const propagationNodes = astIndex.nodes.filter((node) =>
    node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression' ||
    node.type === 'ForOfStatement' || node.type === 'ForInStatement' ||
    node.type === 'CatchClause' ||
    node.type === 'CallExpression' || node.type === 'NewExpression' || FUNCTION_TYPES.has(node.type) ||
    IMPORT_SPECIFIER_TYPES.has(node.type)
  );
  let propagationStable = false;
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round += 1) {
    let changed = false;
    for (const node of propagationNodes) {
      if (IMPORT_SPECIFIER_TYPES.has(node.type)) {
        changed = applyImportBinding(node, context) || changed;
      } else if (FUNCTION_TYPES.has(node.type)) {
        changed = applyParameterBindings(node, context) || changed;
        changed = applyFunctionBinding(node, context) || changed;
      } else if (node.type === 'CatchClause') {
        changed = applyCatchBinding(node, context) || changed;
      } else if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression' ||
        node.type === 'ForOfStatement' || node.type === 'ForInStatement') {
        changed = applyAssignment(node, context) || changed;
      } else {
        changed = applyLocalCallArguments(node, context) || changed;
      }
      if (context.functionTargetLimitNode || context.localCallBindingLimitNode || context.objectAliasLimitNode) break;
    }
    if (context.functionTargetLimitNode || context.localCallBindingLimitNode || context.objectAliasLimitNode) break;
    if (!changed) {
      propagationStable = true;
      break;
    }
  }
  if (context.functionTargetLimitNode) {
    aggregate.blockers.push(blocker('call_target_limit', file.fileId, context.functionTargetLimitNode));
    return fileResult;
  }
  if (context.localCallBindingLimitNode) {
    aggregate.blockers.push(blocker('call_propagation_limit', file.fileId, context.localCallBindingLimitNode));
    return fileResult;
  }
  if (context.objectAliasLimitNode) {
    aggregate.blockers.push(blocker('object_alias_limit', file.fileId, context.objectAliasLimitNode));
    return fileResult;
  }
  if (!propagationStable) {
    aggregate.blockers.push(blocker(
      'propagation_limit',
      file.fileId,
      propagationNodes.at(-1) ?? ast
    ));
    return fileResult;
  }
  const findingKeys = new Set();
  const unresolvedKeys = new Set();
  const addFinding = (identityKind, sinkKind, node) => {
    if (!IDENTITY_KINDS.has(identityKind) || !SINK_KINDS.has(sinkKind) || !isAstNode(node)) return;
    const key = `${file.fileId}\u0000${identityKind}\u0000${sinkKind}\u0000${node.type}\u0000${node.start}\u0000${node.end}`;
    if (findingKeys.has(key)) return;
    if (aggregate.findings.length >= limits.findings) {
      if (!aggregate.blockers.some((entry) => entry.code === 'finding_limit')) {
        aggregate.blockers.push(blocker('finding_limit', file.fileId, node));
      }
      return;
    }
    findingKeys.add(key);
    const evidenceSha256 = `sha256:${sha256(JSON.stringify({
      type: node.type,
      start: node.start,
      end: node.end,
      identityKind,
      sinkKind
    }))}`;
    aggregate.findings.push({
      id: `AST-${sha256(key).slice(0, 16)}`,
      fileId: file.fileId,
      identityKind,
      sinkKind,
      ruleId: `mutable_identity.${identityKind}.${sinkKind}`,
      node: nodeSpan(node),
      evidenceSha256
    });
  };
  const addFlowBlocker = (code, node) => {
    if (!isAstNode(node)) return;
    const key = `${file.fileId}\u0000${code}\u0000${node.type}\u0000${node.start}\u0000${node.end}`;
    if (unresolvedKeys.has(key)) return;
    if (unresolvedKeys.size >= limits.findings) {
      if (!aggregate.blockers.some((entry) => entry.code === 'blocker_limit' && entry.fileId === file.fileId)) {
        aggregate.blockers.push(blocker('blocker_limit', file.fileId, node));
      }
      return;
    }
    unresolvedKeys.add(key);
    aggregate.blockers.push(blocker(code, file.fileId, node));
  };
  const addUnresolved = (sinkKind, node) => {
    if (!SINK_KINDS.has(sinkKind)) return;
    addFlowBlocker(`unresolved_identity_${sinkKind}`, node);
  };

  for (const node of astIndex.nodes) {
    if (['CallExpression', 'NewExpression'].includes(node.type)) {
      if (['eval', 'function'].includes(callName(node.callee))) {
        addFlowBlocker('unsupported_dynamic_execution', node);
      }
      const resolution = resolveLocalFunctionTargets(node.callee, context);
      if ((resolution.unresolved || resolution.pending) && !callTargetIsModeled(node) &&
        node.arguments.some((argument) => {
        const expression = argument.type === 'SpreadElement' ? argument.argument : argument;
        return identityKinds(expression, context).size > 0 || expressionIsUnresolved(expression, context);
      })) {
        addFlowBlocker('unresolved_identity_call_target', node);
      }
      if (node.arguments.some((argument) => argument.type === 'SpreadElement' &&
        (identityKinds(argument.argument, context).size > 0 ||
          expressionIsUnresolved(argument.argument, context)))) {
        addFlowBlocker('unresolved_identity_call_spread', node);
      }
    }
    analyzeSinks(node, context, addFinding, addUnresolved);
  }

  fileResult.findingCount = aggregate.findings.filter((finding) => finding.fileId === file.fileId).length;
  fileResult.completed = !aggregate.blockers.some((entry) => entry.fileId === file.fileId || entry.code === 'finding_limit');
  fileResult.status = fileResult.completed
    ? fileResult.findingCount > 0 ? 'fail' : 'pass'
    : 'blocked';
  return fileResult;
}

export async function analyzeMutableIdentityRequest(request, options = {}) {
  const limitResolution = resolvedLimits(request?.limits);
  const result = resultTemplate(limitResolution.limits);
  if (limitResolution.error) {
    result.blockers.push(blocker(limitResolution.error));
    return finalResult(result);
  }
  if (
    !plainObject(request) || request.schemaVersion !== MUTABLE_IDENTITY_WORKER_REQUEST_SCHEMA ||
    !Array.isArray(request.files) ||
    Object.keys(request).some((key) => !['schemaVersion', 'limits', 'files'].includes(key))
  ) {
    result.blockers.push(blocker('invalid_request'));
    return finalResult(result);
  }
  if (request.files.length > result.limits.files) {
    result.blockers.push(blocker('file_limit'));
    return finalResult(result);
  }
  let acorn;
  try {
    acorn = options.acorn ?? await loadPinnedAcorn();
  } catch {
    result.blockers.push(blocker('parser_integrity'));
    return finalResult(result);
  }
  const aggregate = { findings: result.findings, blockers: result.blockers };
  const fileIds = new Set();
  let sourceBytesTotal = 0;
  for (const candidate of request.files) {
    const fileId = safeFileId(candidate?.fileId);
    const sourceSha256 = String(candidate?.sourceSha256 ?? '');
    const fileResult = {
      fileId,
      sourceSha256: HASH_PATTERN.test(sourceSha256) ? sourceSha256 : '',
      sourceBytes: 0,
      parserSourceType: '',
      completed: false,
      status: 'blocked',
      nodeCount: 0,
      maxDepth: 0,
      findingCount: 0
    };
    result.files.push(fileResult);
    if (
      !plainObject(candidate) ||
      Object.keys(candidate).some((key) => !['fileId', 'language', 'sourceSha256', 'sourceBase64'].includes(key)) ||
      !fileId || !HASH_PATTERN.test(sourceSha256)
    ) {
      result.blockers.push(blocker('invalid_file_record', fileId));
      continue;
    }
    if (fileIds.has(fileId)) {
      result.blockers.push(blocker('duplicate_file_id', fileId));
      continue;
    }
    fileIds.add(fileId);
    if (candidate.language !== 'javascript') {
      result.blockers.push(blocker(
        String(candidate.language ?? '').toLowerCase().includes('typescript')
          ? 'unsupported_typescript'
          : 'unsupported_language',
        fileId
      ));
      continue;
    }
    const bytes = decodeBase64(candidate.sourceBase64);
    if (!bytes) {
      result.blockers.push(blocker('invalid_base64', fileId));
      continue;
    }
    fileResult.sourceBytes = bytes.length;
    if (bytes.length > result.limits.sourceBytesPerFile) {
      result.blockers.push(blocker('source_bytes_per_file', fileId));
      continue;
    }
    if (sourceBytesTotal + bytes.length > result.limits.sourceBytesTotal) {
      result.blockers.push(blocker('source_bytes_total', fileId));
      continue;
    }
    sourceBytesTotal += bytes.length;
    if (`sha256:${sha256(bytes)}` !== sourceSha256) {
      result.blockers.push(blocker('source_hash_mismatch', fileId));
      continue;
    }
    let source;
    try {
      source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      result.blockers.push(blocker('invalid_utf8', fileId));
      continue;
    }
    const parsed = parseJavaScript(acorn, source);
    if (!parsed.ast) {
      result.blockers.push(blocker('parse_error', fileId, parseErrorSpan(parsed.error)));
      continue;
    }
    const analyzed = analyzeAst(candidate, source, parsed.ast, parsed.sourceType, result.limits, aggregate);
    Object.assign(fileResult, analyzed);
  }
  return finalResult(result);
}

async function readStdinBounded() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_STDIN_BYTES) throw new Error('input_bytes');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, bytes);
}

async function main() {
  let request;
  try {
    const bytes = await readStdinBounded();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    request = JSON.parse(text);
  } catch (error) {
    const result = resultTemplate();
    result.blockers.push(blocker(error?.message === 'input_bytes' ? 'input_bytes' : 'invalid_request_json'));
    process.stdout.write(`${JSON.stringify(finalResult(result))}\n`);
    process.exitCode = 2;
    return;
  }
  const result = await analyzeMutableIdentityRequest(request);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.status === 'blocked' ? 2 : 0;
}

const directRun = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (directRun) {
  main().catch(() => {
    const result = resultTemplate();
    result.blockers.push(blocker('internal_error'));
    process.stdout.write(`${JSON.stringify(finalResult(result))}\n`);
    process.exitCode = 1;
  });
}
