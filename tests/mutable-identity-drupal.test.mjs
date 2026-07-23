import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  createMutableIdentityDrupalInput,
  DRUPAL_MUTABLE_IDENTITY_AST_EVAL,
  inspectMutableIdentityDrupal,
  mutableIdentityDrupalEntityOutputBindings,
  mutableIdentityDrupalResultFingerprint,
  parseMutableIdentityDrupalResult,
  runMutableIdentityDrupalAudit
} from '../bin/mutable-identity-drupal.mjs';

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'mutable-identity-drupal-'));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  return root;
}

function runEmbeddedTwigWalker(t, text) {
  const root = fixture(t);
  const source = writeSource(
    root,
    'web/themes/custom/catalog/templates/node--catalog.html.twig',
    text,
    { kind: 'twig_template' }
  );
  const input = createMutableIdentityDrupalInput(root, [source], { docroot: '.' });
  const harness = join(root, 'twig-walker-harness.php');
  writeFileSync(harness, String.raw`<?php
namespace Composer {
  final class InstalledVersions {
    public static function getPrettyVersion(string $package): ?string {
      return $package === 'twig/twig' ? '3.21.1' : NULL;
    }
  }
}
namespace Twig {
  final class Source {
    public function __construct(private string $code, private string $name) {}
    public function getCode(): string { return $this->code; }
  }
  class Environment {
    public function tokenize(Source $source): Source { return $source; }
    public function parse(Source $source): \Twig\Node\ModuleNode { return \FixtureAst::forSource($source->getCode()); }
  }
}
namespace Twig\Node {
  class Node implements \IteratorAggregate, \Countable {
    public function __construct(private array $nodes = [], private array $attributes = [], private int $line = 1) {}
    public function getIterator(): \Traversable { return new \ArrayIterator($this->nodes); }
    public function count(): int { return count($this->nodes); }
    public function hasNode(string $name): bool { return array_key_exists($name, $this->nodes); }
    public function getNode(string $name): Node { return $this->nodes[$name]; }
    public function hasAttribute(string $name): bool { return array_key_exists($name, $this->attributes); }
    public function getAttribute(string $name): mixed { return $this->attributes[$name]; }
    public function getTemplateLine(): int { return $this->line; }
  }
  class BodyNode extends Node {}
  class CaptureNode extends Node {}
  class IfNode extends Node {}
  class MacroNode extends Node {}
  class ModuleNode extends Node {}
  class PrintNode extends Node {}
  class SetNode extends Node {}
  class TextNode extends Node {}
}
namespace Twig\Node\Expression {
  class ConstantExpression extends \Twig\Node\Node {}
  class FunctionExpression extends \Twig\Node\Node {}
  class GetAttrExpression extends \Twig\Node\Node {}
  class NameExpression extends \Twig\Node\Node {}
}
namespace {
  final class Drupal {
    public static function root(): string { return (string) getenv('FAKE_DRUPAL_ROOT'); }
    public static function service(string $name): object {
      if ($name !== 'twig') throw new \RuntimeException('unsupported_service');
      return new \Twig\Environment();
    }
  }
  final class FixtureAst {
    private static function titleExpression(int $line = 1): \Twig\Node\Expression\GetAttrExpression {
      return new \Twig\Node\Expression\GetAttrExpression([
        'node' => new \Twig\Node\Expression\NameExpression([], ['name' => 'node'], $line),
        'attribute' => new \Twig\Node\Expression\ConstantExpression([], ['value' => 'title'], $line),
      ], [], $line);
    }
    private static function printedTitle(): \Twig\Node\PrintNode {
      return new \Twig\Node\PrintNode(['expr' => self::titleExpression()]);
    }
    private static function printedDynamicAttribute(): \Twig\Node\PrintNode {
      return new \Twig\Node\PrintNode(['expr' => new \Twig\Node\Expression\GetAttrExpression([
        'node' => new \Twig\Node\Expression\NameExpression([], ['name' => 'node']),
        'attribute' => new \Twig\Node\Expression\NameExpression([], ['name' => 'field']),
      ])]);
    }
    private static function printedAddClass(): \Twig\Node\PrintNode {
      return new \Twig\Node\PrintNode(['expr' => new \Twig\Node\Expression\GetAttrExpression([
        'node' => new \Twig\Node\Expression\NameExpression([], ['name' => 'attributes']),
        'attribute' => new \Twig\Node\Expression\ConstantExpression([], ['value' => 'addClass']),
        'arguments' => new \Twig\Node\Node([self::titleExpression()]),
      ])]);
    }
    private static function functionIdentityExpression(string $attribute): \Twig\Node\Expression\GetAttrExpression {
      return new \Twig\Node\Expression\GetAttrExpression([
        'node' => new \Twig\Node\Expression\FunctionExpression([
          'arguments' => new \Twig\Node\Node([
            new \Twig\Node\Expression\ConstantExpression([], ['value' => $attribute === 'name' ? 'media' : 'node']),
            new \Twig\Node\Expression\ConstantExpression([], ['value' => 1]),
          ]),
        ], ['name' => 'drupal_entity']),
        'attribute' => new \Twig\Node\Expression\ConstantExpression([], ['value' => $attribute]),
      ]);
    }
    public static function forSource(string $source): \Twig\Node\ModuleNode {
      $print = self::printedTitle();
      if (str_contains($source, '<script') || str_contains($source, 'onclick=') || str_contains($source, 'javascript:')) {
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([
          new \Twig\Node\TextNode([], ['data' => $source]),
        ])]);
      }
      if (str_contains($source, "path('entity.node.canonical'")) {
        $expression = new \Twig\Node\Expression\FunctionExpression([
          'arguments' => new \Twig\Node\Node(),
        ], ['name' => 'path']);
        if (str_contains($source, '{% if')) {
          $if = new \Twig\Node\IfNode(['tests' => new \Twig\Node\Node([$expression, new \Twig\Node\BodyNode()])]);
          return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$if])]);
        }
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([new \Twig\Node\PrintNode(['expr' => $expression])])]);
      }
      if (str_contains($source, 'drupal_entity')) {
        $attribute = str_contains($source, ').name') ? 'name' : 'label';
        $expression = self::functionIdentityExpression($attribute);
        if (str_contains($source, '{% if')) {
          $if = new \Twig\Node\IfNode(['tests' => new \Twig\Node\Node([$expression, new \Twig\Node\BodyNode()])]);
          return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$if])]);
        }
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([new \Twig\Node\PrintNode(['expr' => $expression])])]);
      }
      if (str_contains($source, 'node[field]')) return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([self::printedDynamicAttribute()])]);
      if (str_contains($source, 'attributes.addClass')) return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([self::printedAddClass()])]);
      if (str_contains($source, 'node.getTitle()')) {
        $getter = new \Twig\Node\Expression\GetAttrExpression([
          'node' => new \Twig\Node\Expression\NameExpression([], ['name' => 'node']),
          'attribute' => new \Twig\Node\Expression\ConstantExpression([], ['value' => 'getTitle']),
          'arguments' => new \Twig\Node\Node(),
        ]);
        $if_line = str_contains($source, 'missing-sink-span') ? 0 : 1;
        $if = new \Twig\Node\IfNode(
          ['tests' => new \Twig\Node\Node([$getter, new \Twig\Node\BodyNode()], [], 0)],
          [],
          $if_line,
        );
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$if])]);
      }
      if (str_contains($source, 'node.toUrl()')) {
        $getter = new \Twig\Node\Expression\GetAttrExpression([
          'node' => new \Twig\Node\Expression\NameExpression([], ['name' => 'node']),
          'attribute' => new \Twig\Node\Expression\ConstantExpression([], ['value' => 'toUrl']),
          'arguments' => new \Twig\Node\Node(),
        ]);
        $if = new \Twig\Node\IfNode(['tests' => new \Twig\Node\Node([$getter, new \Twig\Node\BodyNode()])]);
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$if])]);
      }
      if (str_contains($source, '{% macro read(node) %}')) {
        $macro = new \Twig\Node\MacroNode([
          'body' => new \Twig\Node\BodyNode([$print]),
          'arguments' => new \Twig\Node\Node(),
        ], ['name' => 'read']);
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$macro])]);
      }
      if (str_contains($source, '{% set value %}')) {
        $capture = new \Twig\Node\CaptureNode(['body' => new \Twig\Node\Node([$print])]);
        $set = new \Twig\Node\SetNode([
          'names' => new \Twig\Node\Node([new \Twig\Node\Expression\NameExpression([], ['name' => 'value'])]),
          'values' => $capture,
        ], ['capture' => TRUE]);
        return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$set])]);
      }
      return new \Twig\Node\ModuleNode(['body' => new \Twig\Node\Node([$print])]);
    }
  }
${DRUPAL_MUTABLE_IDENTITY_AST_EVAL}
}
`);
  const execution = spawnSync('php', [harness], {
    encoding: 'utf8',
    env: { ...process.env, FAKE_DRUPAL_ROOT: root },
    input: input.json,
    maxBuffer: input.value.limits.outputBytes
  });
  assert.equal(execution.status, 0, `${execution.stdout}\n${execution.stderr}`);
  return parseMutableIdentityDrupalResult(execution.stdout, input);
}

function writeSource(root, path, text, {
  id = 'SOURCE-0123456789abcdef',
  kind = 'php_class',
  surfaceIds = ['SURFACE-0123456789abcdef']
} = {}) {
  const absolute = join(root, ...path.split('/'));
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, text);
  return {
    id,
    kind,
    path,
    sha256: digest(readFileSync(absolute)),
    surfaces: surfaceIds.map((surfaceId) => ({ id: surfaceId }))
  };
}

function phpEvidence({ sink = false } = {}) {
  return {
    sourceNodeType: 'PhpParser\\Node\\Expr\\MethodCall',
    sourceStartLine: 3,
    sourceEndLine: 3,
    sourceStartFilePos: 24,
    sourceEndFilePos: 41,
    sinkNodeType: sink ? 'PhpParser\\Node\\Stmt\\If_' : '',
    sinkStartLine: sink ? 3 : 0,
    sinkEndLine: sink ? 5 : 0,
    sinkStartFilePos: sink ? 20 : null,
    sinkEndFilePos: sink ? 66 : null
  };
}

function twigEvidence() {
  return {
    sourceNodeType: 'Twig\\Node\\Expression\\NameExpression',
    sourceStartLine: 1,
    sourceEndLine: 1,
    sourceStartFilePos: null,
    sourceEndFilePos: null,
    sinkNodeType: 'Twig\\Node\\PrintNode',
    sinkStartLine: 1,
    sinkEndLine: 1,
    sinkStartFilePos: null,
    sinkEndFilePos: null
  };
}

function structuralEvidence(nodeType, line = 0) {
  return {
    sourceNodeType: nodeType,
    sourceStartLine: line,
    sourceEndLine: line,
    sourceStartFilePos: null,
    sourceEndFilePos: null,
    sinkNodeType: '',
    sinkStartLine: 0,
    sinkEndLine: 0,
    sinkStartFilePos: null,
    sinkEndFilePos: null
  };
}

function finding({
  fileId = 'SOURCE-0123456789abcdef',
  identityKind = 'title_or_label',
  sinkKind = 'behavior_branch',
  language = 'php',
  evidence = phpEvidence({ sink: true })
} = {}) {
  const ruleId = `mutable_identity.${identityKind}.${sinkKind}`;
  const key = `${fileId}\0${ruleId}\0${JSON.stringify(evidence)}`;
  return {
    id: `MUTABLE-${digest(key).slice(7, 23)}`,
    fileId,
    language,
    identityKind,
    sinkKind,
    ruleId,
    evidence
  };
}

function entityCandidate({
  fileId = 'SOURCE-0123456789abcdef',
  language = 'php',
  entityKinds = ['node'],
  sinkKind = 'entity_view_builder',
  sourceSurfaceIds = ['SURFACE-0123456789abcdef'],
  evidence = phpEvidence()
} = {}) {
  const ruleId = `entity_output.${sinkKind}`;
  const key = `${fileId}\0${ruleId}\0${entityKinds.join(',')}\0${JSON.stringify(sourceSurfaceIds)}\0${JSON.stringify(evidence)}`;
  return {
    id: `ENTITYOUT-${digest(key).slice(7, 23)}`,
    fileId,
    language,
    entityKinds,
    sinkKind,
    ruleId,
    sourceSurfaceIds,
    evidence
  };
}

const semanticBlockers = new Set([
  'ambiguous_identity_receiver',
  'ambiguous_media_receiver',
  'indirect_identity_flow',
  'indirect_identity_operand',
  'unsupported_dynamic_call',
  'unsupported_dynamic_identity'
]);

function resultFor(input, {
  findings = [],
  entityOutputCandidates = [],
  blockers = [],
  completedFileIds,
  sourceBytes,
  astNodes = 8,
  maxDepth = 4,
  durationMs = 2,
  parser
} = {}) {
  const expectedFileIds = input.value.sources.map(({ id }) => id).sort();
  const completedIds = completedFileIds ?? [...expectedFileIds];
  const applies = expectedFileIds.length > 0;
  const completeCoverage = JSON.stringify([...completedIds].sort()) === JSON.stringify(expectedFileIds);
  const incomplete = blockers.some(({ code }) => !semanticBlockers.has(code));
  const status = !applies ? 'not_applicable' : blockers.length > 0 ? 'blocked' : findings.length > 0 ? 'fail' : 'pass';
  const result = {
    schemaVersion: 'public-kit.mutable-identity-drupal-ast.1',
    analyzer: 'nikic-php-parser+drupal-twig-parser',
    inputFingerprint: input.value.inputFingerprint,
    parser: parser ?? {
      php: {
        name: 'nikic/php-parser',
        version: input.value.sources.some(({ kind }) => kind !== 'twig_template') ? '5.6.1' : '',
        ast: true
      },
      twig: {
        name: 'drupal/twig',
        version: input.value.sources.some(({ kind }) => kind === 'twig_template') ? '3.21.1' : '',
        ast: true
      }
    },
    limits: input.value.limits,
    applies,
    completed: !incomplete && completeCoverage,
    status,
    expectedFileIds,
    completedFileIds: completedIds,
    sourceBytes: sourceBytes ?? (completeCoverage ? input.value.expectedTotalBytes : 0),
    astNodes: applies ? astNodes : 0,
    maxDepth: applies ? maxDepth : 0,
    durationMs,
    deadlineExceeded: blockers.some(({ code }) => code === 'deadline_exceeded'),
    findings,
    entityOutputCandidates,
    blockers
  };
  return { ...result, resultFingerprint: mutableIdentityDrupalResultFingerprint(result) };
}

function resign(result) {
  const unsigned = structuredClone(result);
  delete unsigned.resultFingerprint;
  return { ...unsigned, resultFingerprint: mutableIdentityDrupalResultFingerprint(unsigned) };
}

test('input creation accepts every inventoried procedural PHP extension and binds exact source and surface identities', (t) => {
  const root = fixture(t);
  const proceduralExtensions = ['module', 'theme', 'install', 'inc', 'test', 'profile'];
  const sources = proceduralExtensions.map((extension, index) => writeSource(
    root,
    `web/modules/custom/catalog/catalog.${extension}`,
    `<?php\nfunction catalog_${extension}_${index}() {}\n`,
    {
      id: `SOURCE-${String(index + 1).padStart(16, '0')}`,
      kind: 'procedural_php',
      surfaceIds: [`SURFACE-${String(index + 1).padStart(16, '0')}`]
    }
  ));
  sources.push(writeSource(
    root,
    'web/modules/custom/catalog/src/Catalog.php',
    '<?php\nfinal class Catalog {}\n',
    { id: 'SOURCE-0000000000000007', surfaceIds: ['SURFACE-0000000000000007'] }
  ));
  sources.push(writeSource(
    root,
    'web/themes/custom/catalog/templates/node--catalog.html.twig',
    '{{ content }}\n',
    { id: 'SOURCE-0000000000000008', kind: 'twig_template', surfaceIds: ['SURFACE-0000000000000008'] }
  ));

  const input = createMutableIdentityDrupalInput(root, sources, { docroot: 'web' });
  assert.equal(input.value.sources.length, 8);
  assert.equal(input.value.expectedTotalBytes, sources.reduce((total, source) => total + readFileSync(join(root, source.path)).length, 0));
  assert.deepEqual(input.value.sources.flatMap(({ surfaceIds }) => surfaceIds).sort(), [
    'SURFACE-0000000000000001',
    'SURFACE-0000000000000002',
    'SURFACE-0000000000000003',
    'SURFACE-0000000000000004',
    'SURFACE-0000000000000005',
    'SURFACE-0000000000000006',
    'SURFACE-0000000000000007',
    'SURFACE-0000000000000008'
  ]);
  assert.equal(input.value.inputFingerprint, digest(JSON.stringify({
    schemaVersion: input.value.schemaVersion,
    docroot: input.value.docroot,
    limits: input.value.limits,
    expectedTotalBytes: input.value.expectedTotalBytes,
    sources: input.value.sources
  })));

  assert.throws(() => createMutableIdentityDrupalInput(root, [{ ...sources[0], sha256: digest('stale') }]), /current bytes/);
  assert.throws(() => createMutableIdentityDrupalInput(root, [{ ...sources[0], path: '../catalog.module' }]), /normalized project-relative/);
  assert.throws(() => createMutableIdentityDrupalInput(root, [{ ...sources[0], kind: 'php_class' }]), /does not match/);
  assert.throws(() => createMutableIdentityDrupalInput(root, [{ ...sources[0], surfaces: [{ id: 'authored-opt-out' }] }]), /verifier-owned SURFACE/);
});

test('the fake Drush boundary receives only the fixed AST program and exact bounded input', (t) => {
  const root = fixture(t);
  const source = writeSource(
    root,
    'web/modules/custom/catalog/src/Controller/CatalogController.php',
    '<?php\nfinal class CatalogController {}\n'
  );
  const input = createMutableIdentityDrupalInput(root, [source], { docroot: 'web' });
  let request;
  const result = runMutableIdentityDrupalAudit(input, (value) => {
    request = value;
    return { exitCode: 0, stdout: JSON.stringify(resultFor(input)) };
  });
  assert.equal(result.status, 'pass');
  assert.deepEqual(request.args, ['php:eval', DRUPAL_MUTABLE_IDENTITY_AST_EVAL]);
  assert.equal(request.stdin, input.json);
  assert.equal(request.timeoutMs, input.value.limits.deadlineMs);
  assert.equal(request.maxOutputBytes, input.value.limits.outputBytes);
  assert.equal(request.stdin.includes('<?php\nfinal class CatalogController'), false);

  const tamperedValue = { ...input.value, expectedTotalBytes: input.value.expectedTotalBytes + 1 };
  assert.throws(
    () => runMutableIdentityDrupalAudit({ value: tamperedValue, json: JSON.stringify(tamperedValue) }, () => ''),
    /fingerprint|aggregate bounds/
  );
});

test('zero PHP or Twig inputs are locally not applicable and do not require Drupal transport', (t) => {
  const root = fixture(t);
  let calls = 0;
  const result = inspectMutableIdentityDrupal(root, [], () => {
    calls += 1;
    throw new Error('must not run');
  }, { docroot: 'web' });
  assert.equal(calls, 0);
  assert.equal(result.status, 'not_applicable');
  assert.equal(result.completed, true);
  assert.equal(result.applies, false);
  assert.deepEqual(result.expectedFileIds, []);
  assert.deepEqual(result.entityOutputCandidates, []);
});

test('valid AST findings and entity-output candidates retain only exact node spans and inventory bindings', (t) => {
  const root = fixture(t);
  const php = writeSource(root, 'web/modules/custom/catalog/src/Catalog.php', '<?php\nfinal class Catalog {}\n');
  const twig = writeSource(
    root,
    'web/themes/custom/catalog/templates/node--catalog.html.twig',
    '{{ content }}\n',
    {
      id: 'SOURCE-fedcba9876543210',
      kind: 'twig_template',
      surfaceIds: ['SURFACE-fedcba9876543210']
    }
  );
  const input = createMutableIdentityDrupalInput(root, [php, twig]);
  const phpFinding = finding();
  const phpCandidate = entityCandidate();
  const twigCandidate = entityCandidate({
    fileId: twig.id,
    language: 'twig',
    entityKinds: ['node'],
    sinkKind: 'twig_print',
    sourceSurfaceIds: ['SURFACE-fedcba9876543210'],
    evidence: twigEvidence()
  });
  const parsed = parseMutableIdentityDrupalResult(JSON.stringify(resultFor(input, {
    findings: [phpFinding],
    entityOutputCandidates: [phpCandidate, twigCandidate]
  })), input);
  assert.equal(parsed.status, 'fail');
  assert.equal(parsed.completed, true);
  assert.deepEqual(mutableIdentityDrupalEntityOutputBindings(parsed), [
    {
      id: phpCandidate.id,
      fileId: php.id,
      sourceSurfaceIds: ['SURFACE-0123456789abcdef'],
      entityKinds: ['node'],
      sinkKind: 'entity_view_builder'
    },
    {
      id: twigCandidate.id,
      fileId: twig.id,
      sourceSurfaceIds: ['SURFACE-fedcba9876543210'],
      entityKinds: ['node'],
      sinkKind: 'twig_print'
    }
  ]);
  assert.equal(JSON.stringify(parsed).includes('Catalog'), false);
});

test('semantic ambiguity blocks but records complete traversal; parse failures block incomplete traversal', (t) => {
  const root = fixture(t);
  const source = writeSource(root, 'web/modules/custom/catalog/catalog.module', '<?php\nfunction catalog_help() {}\n', { kind: 'procedural_php' });
  const input = createMutableIdentityDrupalInput(root, [source]);
  const semantic = {
    code: 'indirect_identity_flow',
    fileId: source.id,
    language: 'php',
    ruleId: 'mutable_identity.indirect_identity_flow',
    evidence: phpEvidence()
  };
  const semanticResult = parseMutableIdentityDrupalResult(JSON.stringify(resultFor(input, { blockers: [semantic] })), input);
  assert.equal(semanticResult.status, 'blocked');
  assert.equal(semanticResult.completed, true);

  const structural = {
    code: 'parse_error',
    fileId: source.id,
    language: 'php',
    ruleId: 'mutable_identity.parse_error',
    evidence: structuralEvidence('PhpParser\\Error', 2)
  };
  const structuralResult = parseMutableIdentityDrupalResult(JSON.stringify(resultFor(input, {
    blockers: [structural],
    completedFileIds: [],
    sourceBytes: input.value.expectedTotalBytes,
    astNodes: 0,
    maxDepth: 0
  })), input);
  assert.equal(structuralResult.status, 'blocked');
  assert.equal(structuralResult.completed, false);
  assert.deepEqual(mutableIdentityDrupalEntityOutputBindings(structuralResult), []);
});

test('malformed, forged, unredacted, incomplete, and oversized parser outputs fail closed', (t) => {
  const root = fixture(t);
  const source = writeSource(root, 'web/modules/custom/catalog/src/Catalog.php', '<?php\nfinal class Catalog {}\n');
  const input = createMutableIdentityDrupalInput(root, [source], { outputBytes: 4096 });
  const candidate = entityCandidate();
  const baseline = resultFor(input, { entityOutputCandidates: [candidate] });
  const cases = [];

  cases.push('{not-json');
  cases.push(JSON.stringify(resign({ ...baseline, unexpected: true })));
  cases.push(JSON.stringify(resign({ ...baseline, inputFingerprint: digest('wrong input') })));
  cases.push(JSON.stringify(resign({
    ...baseline,
    parser: { ...baseline.parser, php: { ...baseline.parser.php, version: '5.6.1\n/private/secret' } }
  })));
  cases.push(JSON.stringify(resign({
    ...baseline,
    entityOutputCandidates: [{ ...candidate, id: 'ENTITYOUT-0000000000000000' }]
  })));
  const unredactedEvidence = { ...candidate.evidence, sourceNodeType: '/private/customer/Catalog.php' };
  cases.push(JSON.stringify(resign({
    ...baseline,
    entityOutputCandidates: [entityCandidate({ evidence: unredactedEvidence })]
  })));
  cases.push(JSON.stringify(resign({
    ...baseline,
    entityOutputCandidates: [entityCandidate({ sourceSurfaceIds: ['SURFACE-fedcba9876543210'] })]
  })));
  cases.push(JSON.stringify(resign({ ...baseline, completedFileIds: [], completed: true })));
  cases.push(`${JSON.stringify(baseline)}${' '.repeat(5000)}`);

  for (const raw of cases) {
    assert.throws(() => parseMutableIdentityDrupalResult(raw, input));
    const blocked = runMutableIdentityDrupalAudit(input, () => ({ exitCode: 0, stdout: raw }));
    assert.equal(blocked.status, 'blocked');
    assert.equal(blocked.completed, false);
    assert.equal(blocked.blockers[0].code, 'invalid_output');
  }
});

test('runner errors, nonzero exits, timeouts, and async adapters are typed transport blockers', (t) => {
  const root = fixture(t);
  const source = writeSource(root, 'web/modules/custom/catalog/src/Catalog.php', '<?php\nfinal class Catalog {}\n');
  const input = createMutableIdentityDrupalInput(root, [source]);
  const cases = [
    [undefined, 'runner_unavailable'],
    [() => { throw new Error('private spawn details'); }, 'spawn_failed'],
    [() => Promise.resolve('{}'), 'unsupported_async_runner'],
    [() => ({ exitCode: 2, stdout: '', stderr: '/private/parser/error' }), 'parser_process_failed'],
    [() => ({ exitCode: 0, stdout: '', timedOut: true }), 'deadline_exceeded']
  ];
  for (const [runner, code] of cases) {
    const result = runMutableIdentityDrupalAudit(input, runner);
    assert.equal(result.status, 'blocked');
    assert.equal(result.blockers[0].code, code);
    assert.equal(JSON.stringify(result).includes('/private/'), false);
  }
});

test('Twig macro and capture output cannot launder mutable identity into later selectors', (t) => {
  const available = spawnSync('php', ['-v'], { encoding: 'utf8' });
  if (available.error?.code === 'ENOENT') {
    t.skip('PHP is not installed in this test environment.');
    return;
  }

  const directDisplay = runEmbeddedTwigWalker(t, '{{ node.title }}\n');
  assert.equal(directDisplay.status, 'pass');
  assert.deepEqual(directDisplay.blockers, []);

  const deferredCases = [
    `{% macro read(node) %}{{ node.title }}{% endmacro %}
{% if _self.read(node) == 'Hero' %}chosen{% endif %}
`,
    `{% set value %}{{ node.title }}{% endset %}
{% if value == 'Hero' %}chosen{% endif %}
`
  ];
  for (const source of deferredCases) {
    const result = runEmbeddedTwigWalker(t, source);
    assert.equal(result.status, 'blocked');
    assert.equal(result.completed, true);
    assert.deepEqual(result.blockers.map(({ code }) => code), ['indirect_identity_flow']);
    assert.equal(result.blockers[0].evidence.sourceNodeType, 'Twig\\Node\\Expression\\GetAttrExpression');
  }
});

test('Twig computed attributes, presentation output, calls, and getter branches fail closed', (t) => {
  const available = spawnSync('php', ['-v'], { encoding: 'utf8' });
  if (available.error?.code === 'ENOENT') {
    t.skip('PHP is not installed in this test environment.');
    return;
  }

  const dynamic = runEmbeddedTwigWalker(t, '{{ node[field] }}\n');
  assert.equal(dynamic.status, 'blocked');
  assert.ok(dynamic.blockers.some(({ code }) => code === 'unsupported_dynamic_identity'),
    JSON.stringify(dynamic.blockers));

  const attribute = runEmbeddedTwigWalker(t, '<div class="{{ node.title }}">safe</div>\n');
  assert.equal(attribute.status, 'fail');
  assert.ok(attribute.findings.some(({ sinkKind }) => sinkKind === 'presentation_selector'),
    JSON.stringify(attribute.findings));

  const dynamicTag = runEmbeddedTwigWalker(t, '<{{ node.title }}>safe</{{ node.title }}>\n');
  assert.equal(dynamicTag.status, 'fail');
  assert.ok(dynamicTag.findings.some(({ sinkKind }) => sinkKind === 'presentation_selector'),
    JSON.stringify(dynamicTag.findings));

  const call = runEmbeddedTwigWalker(t, '{{ attributes.addClass(node.title) }}\n');
  assert.equal(call.status, 'fail');
  assert.ok(call.findings.some(({ sinkKind }) => sinkKind === 'presentation_selector'),
    JSON.stringify(call.findings));

  const getter = runEmbeddedTwigWalker(t, "{% if node.getTitle() == 'Hero' %}chosen{% endif %}\n");
  assert.equal(getter.status, 'fail');
  assert.ok(getter.findings.some(({ identityKind, sinkKind }) =>
    identityKind === 'title_or_label' && sinkKind === 'behavior_branch'
  ), JSON.stringify(getter.findings));

  const url = runEmbeddedTwigWalker(t, "{% if node.toUrl() == '/hero' %}chosen{% endif %}\n");
  assert.equal(url.status, 'fail');
  assert.ok(url.findings.some(({ identityKind, sinkKind }) =>
    identityKind === 'alias_or_path' && sinkKind === 'behavior_branch'
  ), JSON.stringify(url.findings));

  const missingSinkSpan = runEmbeddedTwigWalker(
    t,
    "{# missing-sink-span #}{% if node.getTitle() == 'Hero' %}chosen{% endif %}\n"
  );
  assert.equal(missingSinkSpan.status, 'blocked');
  assert.equal(missingSinkSpan.completed, false);
  const structural = missingSinkSpan.blockers.find(({ code }) => code === 'missing_ast_span');
  assert.ok(structural, JSON.stringify(missingSinkSpan));
  assert.equal(structural.evidence.sourceNodeType, 'Twig\\Node\\Expression\\GetAttrExpression');
  assert.equal(structural.evidence.sourceStartLine, 1);
  assert.equal(structural.evidence.sinkNodeType, '');
});

test('Twig function-rooted entity identities fail closed in selectors but remain valid display output', (t) => {
  const available = spawnSync('php', ['-v'], { encoding: 'utf8' });
  if (available.error?.code === 'ENOENT') {
    t.skip('PHP is not installed in this test environment.');
    return;
  }

  for (const source of [
    "{% if drupal_entity('node', 1).label == 'Hero' %}chosen{% endif %}\n",
    "{% if drupal_entity('media', 1).name == 'Hero' %}chosen{% endif %}\n"
  ]) {
    const result = runEmbeddedTwigWalker(t, source);
    assert.equal(result.status, 'blocked');
    assert.equal(result.completed, true);
    assert.ok(result.blockers.some(({ code }) => code.startsWith('ambiguous_')), JSON.stringify(result.blockers));
  }

  for (const source of [
    "{{ drupal_entity('node', 1).label }}\n",
    "{{ drupal_entity('media', 1).name }}\n"
  ]) {
    const result = runEmbeddedTwigWalker(t, source);
    assert.equal(result.status, 'pass');
    assert.deepEqual(result.blockers, []);
  }
});

test('Twig route URL functions cannot control behavior but remain valid display output', (t) => {
  const available = spawnSync('php', ['-v'], { encoding: 'utf8' });
  if (available.error?.code === 'ENOENT') {
    t.skip('PHP is not installed in this test environment.');
    return;
  }

  const branch = runEmbeddedTwigWalker(
    t,
    "{% if path('entity.node.canonical', {'node': node.id}) == '/hero' %}chosen{% endif %}\n"
  );
  assert.equal(branch.status, 'fail');
  assert.ok(branch.findings.some(({ identityKind, sinkKind }) =>
    identityKind === 'alias_or_path' && sinkKind === 'behavior_branch'
  ), JSON.stringify(branch));

  const display = runEmbeddedTwigWalker(
    t,
    "{{ path('entity.node.canonical', {'node': node.id}) }}\n"
  );
  assert.equal(display.status, 'pass');
  assert.deepEqual(display.blockers, []);
});

test('custom Twig inline executable HTML is fail-closed for separate JavaScript analysis', (t) => {
  const available = spawnSync('php', ['-v'], { encoding: 'utf8' });
  if (available.error?.code === 'ENOENT') {
    t.skip('PHP is not installed in this test environment.');
    return;
  }

  for (const source of [
    "<script>if (window.location.pathname === '/hero') chooseTheme()</script>\n",
    '<button onclick="if(window.location.pathname === \'/hero\') chooseTheme()">Choose</button>\n',
    '<a href="javascript:if(document.title) chooseTheme()">Choose</a>\n'
  ]) {
    const result = runEmbeddedTwigWalker(t, source);
    assert.equal(result.status, 'blocked');
    assert.ok(result.blockers.some(({ code }) => code === 'unsupported_inline_script'), JSON.stringify(result));
  }
});

test('embedded Drupal program is syntax-valid when PHP is available and names both real AST parsers', (t) => {
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /PhpParser\\ParserFactory/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /interface_exists\('PhpParser\\\\Node'\)/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /getSubNodeNames/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /Drupal::service\('twig'\)/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /Twig\\Node\\ModuleNode/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /hash\('sha256', \$text\)/);
  assert.doesNotMatch(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /hash_file\('sha256'/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /entityOutputCandidates/);
  assert.match(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /PhpParser\\Node\\Expr\\Eval_/);
  assert.doesNotMatch(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /loadBearing|load_bearing/);
  assert.doesNotMatch(DRUPAL_MUTABLE_IDENTITY_AST_EVAL, /preg_match\([^\n]*\$text/);

  const available = spawnSync('php', ['-v'], { encoding: 'utf8' });
  if (available.error?.code === 'ENOENT') {
    t.skip('PHP is not installed in this test environment.');
    return;
  }
  const syntax = spawnSync('php', ['-l'], {
    encoding: 'utf8',
    input: `<?php\n${DRUPAL_MUTABLE_IDENTITY_AST_EVAL}`
  });
  assert.equal(syntax.status, 0, `${syntax.stdout}\n${syntax.stderr}`);
  assert.match(syntax.stdout, /No syntax errors detected/);
});
