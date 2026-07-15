#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { inspectCustomMutableIdentity } from '../bin/custom-mutable-identity-audit.mjs';
import { inspectCustomEntityOutputAudit } from '../bin/custom-entity-output-audit.mjs';
import { inspectCustomCodeFilesystem } from '../bin/verify.mjs';

if (!process.argv[2]) {
  throw new Error('Usage: node tests/assert-custom-entity-output-smoke.mjs <project-root>');
}

const projectRoot = resolve(process.argv[2]);

function drush(args) {
  return execFileSync('ddev', ['drush', ...args], {
    cwd: projectRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 120_000
  }).trim();
}

let fixture;
let setupAttempted = false;
try {
  setupAttempted = true;
  fixture = JSON.parse(drush(['php:script', 'scripts/setup-custom-entity-output-smoke.php']));
  assert.equal(fixture.schemaVersion, 'public-kit.custom-entity-output-smoke-fixture.1');
  assert.equal(fixture.defaultTheme, 'quality_smoke_child');
  assert.equal(fixture.baseTheme, 'quality_smoke_base');
  assert.match(fixture.routePath, /^\/quality-smoke\/\d+$/);
  assert.match(fixture.entityViewRoutePath, /^\/quality-smoke-entity-view\/\d+$/);
  const missingBubblingRoutePath = fixture.routePath.replace(
    /^\/quality-smoke\//,
    '/quality-smoke-missing-bubbling/'
  );
  assert.match(missingBubblingRoutePath, /^\/quality-smoke-missing-bubbling\/\d+$/);

  const inventory = inspectCustomCodeFilesystem(projectRoot);
  assert.equal(inventory.completed, true, JSON.stringify(inventory.errors));
  assert.ok(inventory.sourceFiles.some((source) =>
    source.path.endsWith('/quality_smoke/src/Controller/EntityOutputController.php')
  ));

  const regressionPaths = [
    resolve(projectRoot, 'web/modules/custom/quality_smoke/phase_c_identity_regression.inc'),
    resolve(projectRoot, 'web/modules/custom/quality_smoke/phase_c_identity_regression.html.twig')
  ];
  try {
    writeFileSync(regressionPaths[0], String.raw`<?php
function quality_smoke_identity_regression(\Drupal\node\NodeInterface $node): string {
  $title = $node->label();
  return $title === 'Hero' ? 'hero' : 'default';
}
function quality_smoke_dynamic_field_regression(\Drupal\node\NodeInterface $node): string {
  $field = 'title';
  return $node->get($field)->value === 'Hero' ? 'hero' : 'default';
}
function quality_smoke_url_regression(\Drupal\node\NodeInterface $node): string {
  return $node->toUrl()->toString() === '/hero' ? 'hero' : 'default';
}
function quality_smoke_eval_regression(): void {
  eval('return;');
}
function quality_smoke_inline_script_regression(): array {
  return ['#markup' => '<button onclick="if(document.title) chooseTheme()">Choose</button>'];
}
`);
    writeFileSync(regressionPaths[1], String.raw`{% macro read(n) %}{{ n.title }}{% endmacro %}
{% set captured %}{{ node.title }}{% endset %}
{% if _self.read(node) == 'Hero' or captured == 'Hero' %}hero{% endif %}
{{ node[field] }}
<div class="{{ node.title }}">safe</div>
{{ attributes.addClass(node.title) }}
{% if node.getTitle() == 'Hero' %}hero{% endif %}
{% set url = node.toUrl() %}
{% if url.toString() == '/hero' %}hero{% endif %}
<a href="javascript:if(document.title) chooseTheme()">Choose</a>
`);
    const regressionInventory = inspectCustomCodeFilesystem(projectRoot);
    assert.equal(regressionInventory.completed, true, JSON.stringify(regressionInventory.errors));
    const regressionAudit = inspectCustomMutableIdentity(projectRoot, regressionInventory, process.env);
    assert.equal(regressionAudit.status, 'blocked', JSON.stringify(regressionAudit));
    for (const suffix of ['phase_c_identity_regression.inc', 'phase_c_identity_regression.html.twig']) {
      const source = regressionInventory.sourceFiles.find((candidate) => candidate.path.endsWith(`/${suffix}`));
      assert.ok(source, `Missing real parser regression source ${suffix}.`);
      assert.ok(regressionAudit.drupal.blockers.some((blocker) =>
        blocker.fileId === source.id && blocker.code === 'indirect_identity_flow'
      ), JSON.stringify(regressionAudit.drupal.blockers));
    }
    const phpSource = regressionInventory.sourceFiles.find((candidate) =>
      candidate.path.endsWith('/phase_c_identity_regression.inc')
    );
    const twigSource = regressionInventory.sourceFiles.find((candidate) =>
      candidate.path.endsWith('/phase_c_identity_regression.html.twig')
    );
    assert.ok(regressionAudit.drupal.blockers.some((blocker) =>
      blocker.fileId === phpSource.id && blocker.code === 'unsupported_dynamic_identity'
    ), JSON.stringify(regressionAudit.drupal.blockers));
    assert.ok(regressionAudit.drupal.blockers.some((blocker) =>
      blocker.fileId === phpSource.id && blocker.code === 'unsupported_dynamic_call'
    ), JSON.stringify(regressionAudit.drupal.blockers));
    assert.ok(regressionAudit.drupal.blockers.some((blocker) =>
      blocker.fileId === twigSource.id && blocker.code === 'unsupported_dynamic_identity'
    ), JSON.stringify(regressionAudit.drupal.blockers));
    for (const source of [phpSource, twigSource]) {
      assert.ok(regressionAudit.drupal.blockers.some((blocker) =>
        blocker.fileId === source.id && blocker.code === 'unsupported_inline_script'
      ), JSON.stringify(regressionAudit.drupal.blockers));
    }
    assert.ok(regressionAudit.drupal.findings.some((finding) =>
      finding.fileId === phpSource.id && finding.identityKind === 'alias_or_path' &&
      finding.sinkKind === 'behavior_branch'
    ), JSON.stringify(regressionAudit.drupal.findings));
    assert.ok(regressionAudit.drupal.findings.some((finding) =>
      finding.fileId === twigSource.id && finding.identityKind === 'title_or_label' &&
      ['behavior_branch', 'presentation_selector'].includes(finding.sinkKind)
    ), JSON.stringify(regressionAudit.drupal.findings));
  } finally {
    for (const path of regressionPaths) rmSync(path, { force: true });
  }

  const mutableIdentityAudit = inspectCustomMutableIdentity(projectRoot, inventory, process.env);
  assert.equal(mutableIdentityAudit.completed, true, JSON.stringify(mutableIdentityAudit));
  assert.equal(mutableIdentityAudit.status, 'pass', JSON.stringify(mutableIdentityAudit));
  assert.ok(mutableIdentityAudit.entityOutputCandidates.length > 0, JSON.stringify(mutableIdentityAudit));

  const fieldOutputMatrix = {
    bundles: [{
      entityType: 'node',
      bundle: fixture.nodeBundle,
      fields: [{
        machineName: fixture.nodeField,
        fieldType: 'entity_reference',
        targetEntityType: 'media',
        affectsAnonymousOutput: true,
        publicRenderLocations: [fixture.routePath, fixture.entityViewRoutePath]
      }]
    }]
  };
  const routeMatrix = {
    routes: [
      { targetPath: fixture.routePath, accepted: true },
      { targetPath: fixture.entityViewRoutePath, accepted: true }
    ]
  };

  const missingBubbling = inspectCustomEntityOutputAudit({
    projectRoot,
    environment: process.env,
    sourceInventory: inventory,
    staticAudit: mutableIdentityAudit,
    fieldOutputMatrix: {
      bundles: [{
        entityType: 'node',
        bundle: fixture.nodeBundle,
        fields: [{
          machineName: fixture.nodeField,
          fieldType: 'entity_reference',
          targetEntityType: 'media',
          affectsAnonymousOutput: true,
          publicRenderLocations: [missingBubblingRoutePath]
        }]
      }]
    },
    routeMatrix: {
      routes: [{ targetPath: missingBubblingRoutePath, accepted: true }]
    }
  });
  assert.equal(missingBubbling.completed, true, JSON.stringify(missingBubbling));
  assert.equal(missingBubbling.status, 'fail', JSON.stringify(missingBubbling));
  assert.equal(missingBubbling.noExplicitVerifierMutation, true);
  assert.equal(missingBubbling.runtime.invalidation.status, 'not_run');
  assert.equal(missingBubbling.runtime.routes.length, 1, JSON.stringify(missingBubbling.runtime.routes));
  const missingBubblingRoute = missingBubbling.runtime.routes[0];
  assert.equal(missingBubblingRoute.matched, true, JSON.stringify(missingBubblingRoute));
  assert.equal(missingBubblingRoute.rendered, true, JSON.stringify(missingBubblingRoute));
  assert.equal(missingBubblingRoute.outputHandlerKind, 'candidate_controller');
  const missingBubblingDependencies = new Map(
    missingBubblingRoute.dependencies.map((dependency) => [dependency.entityType, dependency])
  );
  assert.deepEqual([...missingBubblingDependencies.keys()].sort(), ['file', 'media', 'node']);
  for (const entityType of ['media', 'file']) {
    const dependency = missingBubblingDependencies.get(entityType);
    assert.ok(dependency, `Missing ${entityType} dependency from the negative runtime evidence.`);
    for (const code of ['render_missing_entity_cache_tags', 'render_missing_invalidation_cache_tags']) {
      assert.ok(missingBubbling.runtime.violations.some((violation) =>
        violation.code === code &&
        violation.routeSha256 === missingBubblingRoute.routeSha256 &&
        violation.subjectSha256 === dependency.entitySha256
      ), `Missing ${code} for the exact ${entityType} dependency: ${JSON.stringify(missingBubbling.runtime)}`);
    }
  }

  const defaultProbe = inspectCustomEntityOutputAudit({
    projectRoot,
    environment: process.env,
    sourceInventory: inventory,
    staticAudit: mutableIdentityAudit,
    fieldOutputMatrix,
    routeMatrix
  });
  assert.equal(defaultProbe.completed, true, JSON.stringify(defaultProbe));
  assert.equal(defaultProbe.status, 'pass', JSON.stringify(defaultProbe));
  assert.equal(defaultProbe.noExplicitVerifierMutation, true);
  assert.equal(defaultProbe.runtime.invalidation.status, 'not_run');
  assert.deepEqual(
    [...new Set(defaultProbe.runtime.routes.map((route) => route.outputHandlerKind))].sort(),
    ['candidate_controller', 'entity_view']
  );
  assert.deepEqual(
    [...new Set(defaultProbe.runtime.routes.flatMap((route) => route.dependencies.map((dependency) => dependency.entityType)))].sort(),
    ['file', 'media', 'node']
  );
  assert.ok(defaultProbe.runtime.routes.flatMap((route) => route.dependencies).every((dependency) =>
    dependency.access === 'allowed' && dependency.invalidationTagCount > 0 && dependency.renderedTagIntersectionCount > 0
  ));

  const isolated = inspectCustomEntityOutputAudit({
    projectRoot,
    environment: process.env,
    sourceInventory: inventory,
    staticAudit: mutableIdentityAudit,
    fieldOutputMatrix,
    routeMatrix,
    allowOwnedCacheInvalidation: true,
    isolation: {
      executionBoundary: 'verifier-owned-disposable-ddev',
      workspaceId: 'DISPOSABLE-phase-c-ci',
      exactHead: true,
      freshDatabase: true
    }
  });
  assert.equal(isolated.completed, true, JSON.stringify(isolated));
  assert.equal(isolated.status, 'pass', JSON.stringify(isolated));
  assert.equal(isolated.runtime.invalidation.status, 'pass');
  assert.equal(isolated.runtime.invalidation.cleanupCompleted, true);
  assert.ok(isolated.runtime.invalidation.seededCount >= 3);
  assert.equal(isolated.runtime.invalidation.seededCount, isolated.runtime.invalidation.invalidatedCount);
} finally {
  if (setupAttempted) {
    const cleanup = JSON.parse(drush(['php:script', 'scripts/cleanup-custom-entity-output-smoke.php']));
    assert.equal(cleanup.schemaVersion, 'public-kit.custom-entity-output-smoke-cleanup.1');
    assert.equal(cleanup.cleaned, true);
    assert.equal(cleanup.fixtureFileRemoved, true);
    assert.equal(cleanup.fixtureDirectoryRemoved, true);
    assert.equal(cleanup.themesRemoved, true);
    const residue = JSON.parse(drush(['php:eval', String.raw`
$repository = \Drupal::service('entity.repository');
print json_encode([
  'moduleEnabled' => \Drupal::moduleHandler()->moduleExists('quality_smoke'),
  'node' => (bool) $repository->loadEntityByUuid('node', 'f039a4de-ccf5-4f54-ab6e-32bf7812b387'),
  'media' => (bool) $repository->loadEntityByUuid('media', 'ed363033-e645-42f7-a940-5df63e7ed0f9'),
  'file' => (bool) $repository->loadEntityByUuid('file', '0869d341-f0ba-4a2d-b09c-d01baf35d3da'),
  'nodeType' => (bool) \Drupal\node\Entity\NodeType::load('phase_c_output'),
  'mediaType' => (bool) \Drupal\media\Entity\MediaType::load('phase_c_file'),
  'nodeFieldStorage' => (bool) \Drupal\field\Entity\FieldStorageConfig::loadByName('node', 'field_phase_c_media'),
  'mediaFieldStorage' => (bool) \Drupal\field\Entity\FieldStorageConfig::loadByName('media', 'field_phase_c_file'),
  'nodeField' => (bool) \Drupal\field\Entity\FieldConfig::loadByName('node', 'phase_c_output', 'field_phase_c_media'),
  'mediaField' => (bool) \Drupal\field\Entity\FieldConfig::loadByName('media', 'phase_c_file', 'field_phase_c_file'),
  'nodeViewDisplay' => (bool) \Drupal\Core\Entity\Entity\EntityViewDisplay::load('node.phase_c_output.default'),
  'mediaViewDisplay' => (bool) \Drupal\Core\Entity\Entity\EntityViewDisplay::load('media.phase_c_file.default'),
  'defaultTheme' => (string) \Drupal::config('system.theme')->get('default'),
  'baseThemeEnabled' => array_key_exists('quality_smoke_base', (array) \Drupal::config('core.extension')->get('theme')),
  'childThemeEnabled' => array_key_exists('quality_smoke_child', (array) \Drupal::config('core.extension')->get('theme')),
  'fixtureFile' => file_exists('public://phase-c/entity-output.txt'),
  'fixtureDirectory' => is_dir('public://phase-c'),
]);
`]));
    assert.deepEqual(residue, {
      moduleEnabled: false,
      node: false,
      media: false,
      file: false,
      nodeType: false,
      mediaType: false,
      nodeFieldStorage: false,
      mediaFieldStorage: false,
      nodeField: false,
      mediaField: false,
      nodeViewDisplay: false,
      mediaViewDisplay: false,
      defaultTheme: 'stark',
      baseThemeEnabled: false,
      childThemeEnabled: false,
      fixtureFile: false,
      fixtureDirectory: false
    });
  }
}

process.stdout.write('Real custom entity-output access, bubbling, invalidation, and cleanup evidence passed.\n');
