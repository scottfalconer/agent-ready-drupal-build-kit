import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { deflateSync } from 'node:zlib';

import {
  canvasAssetRuntimeErrors,
  CUSTOM_ROUTE_AUDIT_PHP,
  DISPLAY_PLUGIN_AUDIT_PHP,
  inspectCustomCode,
  inspectCustomPhpQuality,
  inspectTrackedCanvasTemplates,
  verifyLive
} from '../bin/verify.mjs';
import {
  canvasProviderAssetGateReasons,
  canvasTemplateTargetsPublicOutput,
  MACHINE_GATE_EVALUATORS,
  validatePacket
} from '../bin/verify-packet.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const templatesDir = join(repoRoot, 'templates');
const testSiteUuid = '11111111-1111-4111-8111-111111111111';
const testCheckedAt = new Date().toISOString();

function templateName(packetFile) {
  const parsed = parse(packetFile);
  return `${parsed.name}.template${parsed.ext}`;
}

function copyTemplatePacket(packetDir) {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  mkdirSync(packetDir, { recursive: true });
  for (const file of gates.reviewPacketFiles) {
    cpSync(join(templatesDir, templateName(file)), join(packetDir, file));
  }
}

function acceptedSolutionLadder(
  need = 'Expose a standards-compliant calendar capability.',
  capabilityId = 'calendar_feed.export'
) {
  const evidence = 'evidence/independent-verification/claim-evidence.json';
  return {
    capabilityId,
    need,
    acceptanceCriteria: [{
      id: 'stable_output',
      criterion: 'Anonymous consumers receive the required stable capability output.'
    }],
    core: {
      reviewed: true,
      noCandidateFound: false,
      candidates: [{
        name: 'Drupal core Views and entity displays',
        fit: 'rejected',
        unmetCriteria: [],
        reason: 'They do not produce the required interchange format.',
        evidence
      }],
      conclusion: 'Core cannot satisfy the required interchange contract.',
      evidence
    },
    installedDrupalCms: {
      reviewed: true,
      disabledCapabilitiesChecked: true,
      noCandidateFound: false,
      capabilities: [{
        name: 'Example disabled feed submodule',
        type: 'submodule',
        enabled: false,
        fit: 'partial',
        unmetCriteria: ['stable_output'],
        reason: 'It exposes a feed but not the required format.',
        evidence
      }],
      conclusion: 'Installed and disabled capabilities do not meet the format criterion.',
      evidence
    },
    currentRecipes: {
      reviewed: true,
      checkedAt: testCheckedAt,
      noCandidateFound: false,
      candidates: [{
        package: 'drupal/example_events',
        version: '2.0.0',
        drupalCompatibility: '^11.4 || ^12',
        supportStatus: 'supported',
        securityAdvisoryCoverage: true,
        fit: 'rejected',
        unmetCriteria: [],
        reason: 'The recipe models events but does not expose the required feed contract.',
        maintenanceEvidence: evidence,
        evidence
      }],
      conclusion: 'The current compatible Recipe does not own the required output.',
      evidence
    },
    maintainedContrib: {
      reviewed: true,
      checkedAt: testCheckedAt,
      noCandidateFound: false,
      candidates: [{
        project: 'drupal/example_feed',
        version: '4.0.0',
        drupalCompatibility: '^10 || ^11',
        maintenanceStatus: 'maintained',
        securityAdvisoryCoverage: true,
        fit: 'partial',
        unmetCriteria: ['stable_output'],
        reason: 'It lacks the required cache invalidation contract.',
        maintenanceEvidence: evidence,
        adoptionEvidence: evidence,
        evidence
      }],
      conclusion: 'The maintained compatible project misses one required acceptance criterion.',
      evidence
    },
    customDecision: {
      whyCustomRemains: 'Only the narrow interchange adapter remains unmet.',
      narrowestScope: 'Serialize the existing Drupal event View into the required format.',
      revisitTrigger: 'Remove the adapter when a compatible maintained owner meets every criterion.',
      acceptedBy: 'Fixture Maintainer',
      acceptedAt: testCheckedAt,
      evidence,
      accepted: true
    }
  };
}

function acceptedSourceFile({
  capabilityId = 'calendar_feed.export',
  extension = 'calendar_adapter',
  hex = '1',
  kind = 'php_class',
  path = 'web/modules/custom/calendar_adapter/src/Adapter.php',
  surfaceKind = 'class',
  surfaceName = 'Adapter'
} = {}) {
  const digit = /^[a-f0-9]$/i.test(hex) ? hex.toLowerCase() : '1';
  const surfaceId = `SURFACE-${digit.repeat(16)}`;
  return {
    id: `SOURCE-${digit.repeat(16)}`,
    extension,
    path,
    kind,
    sha256: `sha256:${digit.repeat(64)}`,
    surfaces: [{ id: surfaceId, kind: surfaceKind, name: surfaceName, line: 1 }],
    capabilityBindings: [{
      capabilityId,
      surfaceIds: [surfaceId],
      responsibility: 'Implements the reviewed custom capability.'
    }],
    reviewed: true
  };
}

function acceptedScannedSourceFiles(sourceFiles, capabilityId, responsibility = 'Implements the reviewed capability.') {
  return sourceFiles.map((sourceFile) => ({
    ...sourceFile,
    capabilityBindings: [{
      capabilityId,
      surfaceIds: sourceFile.surfaces.map((surface) => surface.id),
      responsibility
    }],
    reviewed: true
  }));
}

function owningSurfaceIds(sourceFiles, path, line = 1) {
  const sourceFile = sourceFiles.find((candidate) => candidate.path === path);
  if (!sourceFile) {
    return [];
  }
  const nearest = [...sourceFile.surfaces]
    .filter((surface) => surface.line <= line)
    .sort((left, right) => right.line - left.line)[0] ?? sourceFile.surfaces[0];
  return nearest ? [nearest.id] : [];
}

test('every non-human gate has an explicit machine evaluator and a supported blocking scope', () => {
  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  const expected = gates.gates.filter((gate) => gate.checkedBy !== 'human').map((gate) => gate.id).sort();

  assert.deepEqual(Object.keys(MACHINE_GATE_EVALUATORS).sort(), expected);
  assert.deepEqual([...new Set(gates.gates.map((gate) => gate.blocking))].sort(), ['handoff', 'launch']);
  assert.equal(gates.gates.find((gate) => gate.id === 'G-SEO-01')?.evidenceFile, 'browser-evidence.json');
});

test('custom-code inventory discovers extensions, routes, controllers, and tests', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'custom-code-inventory-'));
  const moduleRoot = join(projectRoot, 'web', 'modules', 'custom', 'calendar_feed');
  const themeRoot = join(projectRoot, 'web', 'themes', 'custom', 'public_theme');
  mkdirSync(join(moduleRoot, 'src', 'Controller'), { recursive: true });
  mkdirSync(join(moduleRoot, 'src', 'EventSubscriber'), { recursive: true });
  mkdirSync(join(moduleRoot, 'src', 'Plugin', 'Block'), { recursive: true });
  mkdirSync(join(moduleRoot, 'config', 'schema'), { recursive: true });
  mkdirSync(join(moduleRoot, 'scripts'), { recursive: true });
  mkdirSync(join(moduleRoot, 'tests', 'src', 'Functional'), { recursive: true });
  mkdirSync(join(themeRoot, 'css'), { recursive: true });
  mkdirSync(join(themeRoot, 'js'), { recursive: true });
  mkdirSync(join(themeRoot, 'templates'), { recursive: true });
  writeFileSync(join(moduleRoot, 'calendar_feed.info.yml'), 'name: Calendar feed\ntype: module\n');
  writeFileSync(join(themeRoot, 'public_theme.info.yml'), 'name: Public theme\ntype: theme\n');
  writeFileSync(join(moduleRoot, 'calendar_feed.module'), `<?php
function calendar_feed_node_insert($node): void {}
function calendar_feed_cron(): void {}
`);
  writeFileSync(join(moduleRoot, 'calendar_feed.services.yml'), `services:
    calendar_feed.subscriber:
        class: Drupal\\calendar_feed\\EventSubscriber\\CalendarSubscriber
    'calendar_feed.renderer':
        class: Drupal\\calendar_feed\\CalendarRenderer
`);
  writeFileSync(join(moduleRoot, 'config', 'schema', 'calendar_feed.schema.yml'), 'calendar_feed.settings:\n  type: config_object\n');
  writeFileSync(join(moduleRoot, 'scripts', 'build.mjs'), 'export default {};\n');
  writeFileSync(join(moduleRoot, 'src', 'EventSubscriber', 'CalendarSubscriber.php'), '<?php\nfinal class CalendarSubscriber {}\n');
  writeFileSync(join(moduleRoot, 'src', 'Plugin', 'Block', 'CalendarBlock.php'), '<?php\nfinal class CalendarBlock {}\n');
  writeFileSync(join(themeRoot, 'js', 'site.js'), 'Drupal.behaviors.publicThemeMenu = {};\nDrupal.behaviors.publicThemeSearch = {};\n');
  writeFileSync(join(themeRoot, 'js', 'module.mjs'), 'Drupal.behaviors.publicThemeModule = {};\n');
  writeFileSync(join(themeRoot, 'css', 'style.css'), '.site-header { display: block; }\n');
  writeFileSync(join(themeRoot, 'css', 'tokens.sass'), '$brand: #005a70\n');
  writeFileSync(join(themeRoot, 'public_theme.theme'), `<?php
function public_theme_page_attachments_alter(array &$attachments): void {
  $attachments['#attached']['html_head'][] = [['#tag' => 'meta', '#attributes' => ['name' => 'description', 'content' => 'Example']], 'example_description'];
}
`);
  writeFileSync(join(themeRoot, 'templates', 'page.html.twig'), `<a href="/section/example">Example</a>
<form action="/search" role="search"><input name="keywords" type="search"><button>Search</button></form>
`);
  writeFileSync(join(themeRoot, 'templates', 'views-view-unformatted.html.twig'), '{{ rows }}\n');
  writeFileSync(join(themeRoot, 'templates', 'views-mini-pager.html.twig'), '{{ items }}\n');
  writeFileSync(join(themeRoot, 'templates', 'views-view-unformatted--news.html.twig'), '{{ rows }}\n');
  const commonSearchNames = ['keys', 'keywords', 'query', 'q', 'search', 'search_api_fulltext'];
  writeFileSync(
    join(themeRoot, 'templates', 'search-forms.html.twig'),
    `${commonSearchNames.map((name, index) => `<form action="{{ path('view.site_search.page_${index + 1}') }}"><input name="${name}" type="text"><button>Go</button></form>`).join('\n')}
<form class="directory-search" action="{{ path('view.search_directory.page_1') }}"><label>Search directory</label><input name="term" type="text"><button>Go</button></form>\n`
  );
  const excludedThemeDirectories = [
    'test', 'tests', 'fixture', 'fixtures', 'test-data', 'test_data', 'testdata', 'tools', 'tooling'
  ];
  for (const excludedDirectory of excludedThemeDirectories) {
    const excludedRoot = join(themeRoot, excludedDirectory);
    mkdirSync(excludedRoot, { recursive: true });
    writeFileSync(
      join(excludedRoot, 'views-view-table.html.twig'),
      '<a href="/should-not-scan">Ignored</a><form action="/search"><input name="q" type="text"></form>\n'
    );
  }
  writeFileSync(join(moduleRoot, 'calendar_feed.routing.yml'), `calendar_feed.permission:\n  path: '/calendar.ics'\n  defaults:\n    _controller: '\\Drupal\\calendar_feed\\Controller\\CalendarController::feed'\n  requirements:\n    _permission: 'access calendar feed'\ncalendar_feed.anonymous_role:\n  path: '/calendar/public'\n  defaults:\n    _controller: '\\Drupal\\calendar_feed\\Controller\\CalendarController::feed'\n  requirements:\n    _role: 'anonymous'\ncalendar_feed.custom_access:\n  path: '/calendar/{calendar}'\n  defaults:\n    _controller: '\\Drupal\\calendar_feed\\Controller\\CalendarController::feed'\n  requirements:\n    _custom_access: '\\Drupal\\calendar_feed\\Access\\CalendarAccess::access'\n`);
  writeFileSync(join(moduleRoot, 'src', 'Controller', 'CalendarController.php'), '<?php\n');
  writeFileSync(join(moduleRoot, 'tests', 'src', 'Functional', 'CalendarFeedTest.php'), '<?php\n');

  const inventory = inspectCustomCode(projectRoot);

  assert.deepEqual(inventory.extensions.map((extension) => extension.machineName), ['calendar_feed', 'public_theme']);
  assert.deepEqual(inventory.routes.map((route) => route.name), [
    'calendar_feed.anonymous_role',
    'calendar_feed.custom_access',
    'calendar_feed.permission'
  ]);
  assert.equal(inventory.routes.find((route) => route.name === 'calendar_feed.custom_access').path, '/calendar/{calendar}');
  assert.equal(Object.hasOwn(inventory.routes[0], 'public'), false, 'filesystem YAML must not guess anonymous access');
  assert.equal(inventory.extensions.find((extension) => extension.machineName === 'calendar_feed').phpFileCount, 5);
  assert.match(inventory.controllers[0].path, /CalendarController\.php$/);
  assert.equal(inventory.controllers[0].extension, 'calendar_feed');
  assert.match(inventory.tests[0], /CalendarFeedTest\.php$/);
  assert.ok(inventory.sourceFiles.some((sourceFile) =>
    sourceFile.path.endsWith('calendar_feed.module') &&
    sourceFile.surfaces.some((surface) => surface.name === 'calendar_feed_node_insert') &&
    sourceFile.surfaces.some((surface) => surface.name === 'calendar_feed_cron')
  ));
  assert.ok(inventory.sourceFiles.some((sourceFile) =>
    sourceFile.path.endsWith('CalendarSubscriber.php') &&
    sourceFile.surfaces.some((surface) => surface.name === 'CalendarSubscriber')
  ));
  assert.ok(inventory.sourceFiles.some((sourceFile) =>
    sourceFile.path.endsWith('CalendarBlock.php') &&
    sourceFile.surfaces.some((surface) => surface.name === 'CalendarBlock')
  ));
  assert.ok(inventory.sourceFiles.some((sourceFile) =>
    sourceFile.path.endsWith('calendar_feed.services.yml') &&
    sourceFile.surfaces.some((surface) => surface.name === 'calendar_feed.subscriber') &&
    sourceFile.surfaces.some((surface) => surface.name === 'calendar_feed.renderer')
  ));
  assert.ok(inventory.sourceFiles.some((sourceFile) =>
    sourceFile.path.endsWith('config/schema/calendar_feed.schema.yml') &&
    sourceFile.surfaces.some((surface) => surface.name === 'calendar_feed.settings')
  ));
  assert.ok(inventory.sourceFiles.some((sourceFile) =>
    sourceFile.path.endsWith('site.js') && sourceFile.surfaces.length === 2
  ));
  assert.ok(inventory.sourceFiles.some((sourceFile) => sourceFile.path.endsWith('module.mjs')));
  assert.ok(inventory.sourceFiles.some((sourceFile) => sourceFile.path.endsWith('tokens.sass')));
  assert.ok(inventory.sourceFiles.every((sourceFile) => !sourceFile.path.endsWith('scripts/build.mjs')));
  assert.ok(inventory.sourceFiles.every((sourceFile) =>
    !/(?:^|\/)(?:scripts|test|tests|fixture|fixtures|test-data|test_data|testdata|tools|tooling|vendor|dist|build)(?:\/|$)/.test(sourceFile.path)
  ));
  assert.deepEqual([...new Set(inventory.themeOwnershipFindings.map((finding) => finding.kind))].sort(), [
    'global_views_template_override',
    'handwritten_search_form',
    'hardcoded_internal_path',
    'theme_meta_injection'
  ]);
  assert.ok(inventory.themeOwnershipFindings.every((finding) => /^THEME-[a-f0-9]{16}$/.test(finding.id)));
  assert.ok(inventory.themeOwnershipFindings.every((finding) => /^sha256:[a-f0-9]{64}$/.test(finding.matchHash)));
  assert.equal(
    inventory.themeOwnershipFindings.filter((finding) => finding.kind === 'theme_meta_injection').length,
    1,
    "the scanner must recognize Drupal render arrays shaped as ['#tag' => 'meta']"
  );
  assert.equal(
    inventory.themeOwnershipFindings.filter((finding) => finding.kind === 'global_views_template_override').length,
    2,
    'all unsuffixed Views base templates are findings while suggested templates are excluded'
  );
  assert.equal(
    inventory.themeOwnershipFindings.filter((finding) => finding.kind === 'handwritten_search_form').length,
    8,
    'common text search names plus search-like Twig path(), class, and label signals are detected'
  );
  assert.ok(
    inventory.themeOwnershipFindings.every((finding) =>
      !/(?:^|\/)(?:test|tests|fixture|fixtures|test-data|test_data|testdata|tools|tooling)(?:\/|$)/.test(finding.file)
    ),
    'theme test and fixture directories are excluded from runtime ownership findings'
  );
  assert.ok(
    inventory.themeOwnershipFindings.every((finding) =>
      !finding.file.endsWith('views-view-unformatted--news.html.twig')
    ),
    'a Views template suggestion is not treated as a global base override'
  );
});

test('embedded Drupal audits cover live callback routes, real Requests, and registered extra fields', () => {
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /getAllRoutes\(\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /live_callback/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /matchRequest\(\$request\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /\$param_converter->convert\(\$matched\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /checkRequest\(\$request, \$anonymous, TRUE\)/);
  assert.match(CUSTOM_ROUTE_AUDIT_PHP, /neutral_access_result/);
  assert.match(DISPLAY_PLUGIN_AUDIT_PHP, /getExtraFields\(\$entity_type, \$bundle\)/);
  assert.match(DISPLAY_PLUGIN_AUDIT_PHP, /registeredExtraField' => TRUE/);
  assert.ok(
    DISPLAY_PLUGIN_AUDIT_PHP.indexOf("isset($extra_fields[$field_name])") <
      DISPLAY_PLUGIN_AUDIT_PHP.indexOf("'missing_field_definition'")
  );
});

test('custom PHP quality uses verifier-owned canonical tools and reports unsupported checks', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'custom-php-quality-'));
  const binRoot = join(projectRoot, 'vendor', 'bin');
  const extensionPath = 'web/modules/custom/calendar_feed';
  mkdirSync(join(projectRoot, extensionPath), { recursive: true });
  mkdirSync(binRoot, { recursive: true });
  const phpcs = join(binRoot, 'phpcs');
  const phpstan = join(binRoot, 'phpstan');
  writeFileSync(phpcs, `#!/bin/sh
if [ "$1" = "-i" ]; then
  echo "The installed coding standards are Drupal and DrupalPractice"
else
  printf '%s' '{"totals":{"errors":0,"warnings":0,"files":1},"files":{}}'
fi
`);
  writeFileSync(phpstan, `#!/bin/sh
printf '%s' '{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}'
`);
  chmodSync(phpcs, 0o755);
  chmodSync(phpstan, 0o755);
  writeFileSync(join(projectRoot, 'phpstan.neon'), 'parameters:\n  level: 1\n');
  const extension = {
    machineName: 'calendar_feed', type: 'module', path: extensionPath, phpFileCount: 1
  };

  const [result] = inspectCustomPhpQuality(projectRoot, [extension]);

  assert.deepEqual(result.checks.map((check) => [check.kind, check.supported, check.status]), [
    ['coding_standards', true, 'pass'],
    ['static_analysis', true, 'pass']
  ]);
  assert.match(result.checks[0].command.join(' '), /vendor\/bin\/phpcs --standard=Drupal,DrupalPractice/);
  assert.match(result.checks[1].command.join(' '), /vendor\/bin\/phpstan analyse --configuration=phpstan\.neon/);

  const withoutConfig = mkdtempSync(join(tmpdir(), 'custom-php-quality-no-config-'));
  mkdirSync(join(withoutConfig, 'vendor', 'bin'), { recursive: true });
  mkdirSync(join(withoutConfig, extensionPath), { recursive: true });
  cpSync(phpcs, join(withoutConfig, 'vendor', 'bin', 'phpcs'));
  cpSync(phpstan, join(withoutConfig, 'vendor', 'bin', 'phpstan'));
  chmodSync(join(withoutConfig, 'vendor', 'bin', 'phpcs'), 0o755);
  chmodSync(join(withoutConfig, 'vendor', 'bin', 'phpstan'), 0o755);
  const [unsupported] = inspectCustomPhpQuality(withoutConfig, [extension]);
  assert.deepEqual(
    unsupported.checks.map((check) => [check.kind, check.supported, check.status]),
    [['coding_standards', true, 'pass'], ['static_analysis', false, 'unsupported']]
  );
});

test('tracked config Canvas audit reads active content templates and ignores translation overrides', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'canvas-template-config-'));
  const configRoot = join(projectRoot, 'config', 'sync');
  mkdirSync(join(configRoot, 'language', 'fr'), { recursive: true });
  writeFileSync(join(configRoot, 'system.site.yml'), 'name: Fixture\n');
  writeFileSync(join(configRoot, 'canvas.content_template.node.page.full.yml'), `status: true
id: node.page.full
content_entity_type_id: node
content_entity_type_bundle: page
content_entity_type_view_mode: full
`);
  writeFileSync(join(configRoot, 'canvas.content_template.node.article.full.yml'), `status: false
id: node.article.full
content_entity_type_id: node
content_entity_type_bundle: article
content_entity_type_view_mode: full
`);
  writeFileSync(
    join(configRoot, 'language', 'fr', 'canvas.content_template.node.page.full.yml'),
    'label: Page française\n'
  );

  const audit = inspectTrackedCanvasTemplates(projectRoot, [
    'config/sync/system.site.yml',
    'config/sync/canvas.content_template.node.page.full.yml',
    'config/sync/canvas.content_template.node.article.full.yml',
    'config/sync/language/fr/canvas.content_template.node.page.full.yml'
  ], 'config/sync');

  assert.equal(audit.completed, true, audit.errors.join('\n'));
  assert.equal(audit.trackedConfigFileCount, 4);
  assert.equal(audit.matchingConfigCount, 2);
  assert.deepEqual(audit.templates.map((template) => ({
    configName: template.configName,
    enabled: template.enabled,
    target: `${template.entityType}.${template.bundle}.${template.viewMode}`
  })), [
    { configName: 'canvas.content_template.node.page.full', enabled: true, target: 'node.page.full' },
    { configName: 'canvas.content_template.node.article.full', enabled: false, target: 'node.article.full' }
  ]);
});

test('Canvas public targets honor row-only bundles and include public embedded non-node displays', () => {
  const rowOnlyPattern = {
    contentTypes: [{ machineName: 'topic' }],
    structuredContentModel: {
      collectionOwnershipLedger: [{
        accepted: true,
        drupalEntityType: 'node',
        contentTypeOrBundle: 'topic',
        detailRouteOwner: 'view_row'
      }]
    }
  };
  const rowOnlyReadback = {
    content: { nodes: [{ type: 'topic', published: true }], viewDisplays: [] },
    routing: { publicBundleAliasPolicies: [] }
  };
  assert.equal(canvasTemplateTargetsPublicOutput(
    { entityType: 'node', bundle: 'topic', viewMode: 'full' },
    rowOnlyReadback,
    rowOnlyPattern
  ), false);

  const embeddedReadback = {
    content: {
      nodes: [],
      viewDisplays: [{
        entityType: 'media', bundle: 'image', viewMode: 'card', embeddedOnPublicOutput: true
      }]
    },
    routing: { publicBundleAliasPolicies: [] }
  };
  assert.equal(canvasTemplateTargetsPublicOutput(
    { entityType: 'media', bundle: 'image', viewMode: 'card' },
    embeddedReadback,
    { contentTypes: [], structuredContentModel: { collectionOwnershipLedger: [] } }
  ), true);
});

test('Canvas provider assets require target-bound loaded libraries and browser effectiveness', () => {
  const patternMap = {
    compositionModel: {
      canvasComponentModel: [{
        accepted: true,
        canvasOwnerDeclared: true,
        publicRoute: '/landing',
        componentList: ['sdc.example.hero', 'sdc.example.cta']
      }]
    }
  };
  const drupalReadback = { drupal: { defaultTheme: 'public_theme' } };
  const browserEvidence = {
    publicRouteChecks: ['desktop', 'mobile'].map((name) => ({
      accepted: true,
      targetFinalUrl: 'https://target.example/landing',
      viewport: { name }
    })),
    canvasAuthoringChecks: [{
      publicRoute: '/landing',
      canvasOwnsPublicRoute: true,
      activePublicTheme: 'public_theme',
      providerAssetChecks: [{
        provider: 'example_components',
        componentIds: ['sdc.example.hero', 'sdc.example.cta'],
        assetContractReviewed: true,
        requiredLibraries: [{
          name: 'example_components/global',
          assetTypes: ['css', 'js'],
          disposition: 'loaded_directly',
          contractEvidence: 'The provider library definition requires CSS and JavaScript.',
          equivalenceEvidence: ''
        }],
        loadedAssets: [
          {
            url: 'https://target.example/themes/example/global.css',
            type: 'css',
            satisfiesLibraries: ['example_components/global'],
            observedBy: 'link_stylesheet',
            mappingEvidence: 'The browser stylesheet link maps to the declared provider library.'
          },
          {
            url: 'https://target.example/themes/example/global.js',
            type: 'js',
            satisfiesLibraries: ['example_components/global'],
            observedBy: 'script_src',
            mappingEvidence: 'The browser script source maps to the declared provider library.'
          }
        ],
        effectivenessChecks: [
          {
            method: 'computed_style', selector: '.example-hero', expectation: 'Grid layout is active.',
            observedResult: 'display: grid', status: 'pass', evidence: 'evidence/browser/canvas-style.json'
          },
          {
            method: 'interaction', selector: '.example-cta', expectation: 'CTA behavior responds.',
            observedResult: 'The interaction completed.', status: 'pass', evidence: 'evidence/browser/canvas-interaction.json'
          }
        ],
        noLibrariesRequiredRationale: '',
        status: 'pass',
        accepted: true,
        blockers: []
      }],
      status: 'pass',
      accepted: true
    }]
  };

  assert.deepEqual(canvasProviderAssetGateReasons({ browserEvidence, drupalReadback, patternMap }), []);

  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].loadedAssets[0].observedBy = 'network';
  assert.match(
    canvasProviderAssetGateReasons({ browserEvidence, drupalReadback, patternMap }).join('\n'),
    /provider asset contract/
  );
  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].loadedAssets[0].observedBy = 'link_stylesheet';

  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].effectivenessChecks =
    browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].effectivenessChecks
      .filter((check) => check.method !== 'computed_style');
  assert.match(
    canvasProviderAssetGateReasons({ browserEvidence, drupalReadback, patternMap }).join('\n'),
    /provider asset contract/
  );

  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].effectivenessChecks.push({
    method: 'computed_style', selector: '.example-hero', expectation: 'Grid layout is active.',
    observedResult: 'display: grid', status: 'pass', evidence: 'evidence/browser/canvas-style.json'
  });
  browserEvidence.canvasAuthoringChecks[0].activePublicTheme = 'other_theme';
  assert.match(
    canvasProviderAssetGateReasons({ browserEvidence, drupalReadback, patternMap }).join('\n'),
    /provider asset contract/
  );
});

test('live Canvas asset evidence rejects fake assets, stale themes, and missing artifacts', () => {
  const packetDir = mkdtempSync(join(tmpdir(), 'canvas-runtime-assets-'));
  mkdirSync(join(packetDir, 'evidence', 'browser'), { recursive: true });
  writeFileSync(
    join(packetDir, 'evidence', 'browser', 'canvas-style.json'),
    '{"publicRoute":"/landing","method":"computed_style","selector":".example-hero","observedResult":"display: grid"}\n'
  );
  const browserEvidence = {
    canvasAuthoringChecks: [{
      publicRoute: '/landing',
      canvasOwnsPublicRoute: true,
      activePublicTheme: 'public_theme',
      providerAssetChecks: [{
        provider: 'example_components',
        loadedAssets: [{
          url: 'https://target.example/themes/example/global.css',
          type: 'css',
          observedBy: 'link_stylesheet'
        }],
        effectivenessChecks: [{
          method: 'computed_style',
          selector: '.example-hero',
          observedResult: 'display: grid',
          evidence: 'evidence/browser/canvas-style.json'
        }]
      }],
      accepted: true
    }]
  };
  const routeChecks = [{
    finalUrl: 'https://target.example/landing',
    loadedAssets: [{
      url: 'https://target.example/themes/example/global.css',
      type: 'css',
      observedBy: 'link_stylesheet'
    }]
  }];

  assert.deepEqual(canvasAssetRuntimeErrors({
    browserEvidence, packetDir, routeChecks, runtimeDefaultTheme: 'public_theme'
  }), []);

  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].loadedAssets[0].url =
    'https://target.example/themes/example/fake.css';
  assert.match(canvasAssetRuntimeErrors({
    browserEvidence, packetDir, routeChecks, runtimeDefaultTheme: 'public_theme'
  }).join('\n'), /was not present in the live HTML/);

  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].loadedAssets[0].url =
    'https://target.example/themes/example/global.css';
  assert.match(canvasAssetRuntimeErrors({
    browserEvidence, packetDir, routeChecks, runtimeDefaultTheme: 'other_theme'
  }).join('\n'), /does not match live system\.theme:default/);

  browserEvidence.canvasAuthoringChecks[0].providerAssetChecks[0].effectivenessChecks[0].evidence =
    'evidence/browser/missing.json';
  assert.match(canvasAssetRuntimeErrors({
    browserEvidence, packetDir, routeChecks, runtimeDefaultTheme: 'public_theme'
  }).join('\n'), /not a non-empty packet-local browser artifact/);
});

test('packet completion blocks Canvas output without provider asset evidence', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'canvas-provider-assets-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    patternMap.buildTypeDeclaration.type = 'structured_drupal_native_canvas';
    patternMap.compositionModel.canvasComponentModel = [{
      sourceRoute: '/',
      publicRoute: '/',
      canvasOwnerDeclared: true,
      componentList: ['sdc.example.hero'],
      slotList: [],
      props: [],
      repeatableSectionsUseDrupalOwnedData: true,
      oneMonolithicComponentRejected: true,
      jsonOrNewlineBlobPropsRejected: true,
      hardcodedPublicCopyRejected: true,
      componentInventoryMatchesDeclaration: true,
      accepted: true,
      notes: ''
    }];
    patternMap.pageCompositionOwnership[0].selectedOwner = 'canvas_page';
    patternMap.pageCompositionOwnership[0].canvasOwnsPublicRoute = true;
  });
  mutateJson(join(packetDir, 'browser-evidence.json'), (browserEvidence) => {
    browserEvidence.canvasAuthoringChecks = [{
      publicRoute: '/',
      canvasOwnsPublicRoute: true,
      activePublicTheme: 'fixture_theme',
      providerAssetChecks: [],
      status: 'pass',
      accepted: true
    }];
  });

  const report = await validatePacket({ packetDir });
  assert.match(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /Canvas\/component provider asset contract/
  );
});

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function mutateJson(path, mutate) {
  const value = JSON.parse(readFileSync(path, 'utf8'));
  mutate(value);
  writeJson(path, value);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])));
  return Buffer.concat([length, typeBytes, data, checksum]);
}

function screenshotPng(seed, width = 320, height = 240) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const scanlines = Buffer.alloc(height * (1 + width * 3));
  for (let row = 0; row < height; row += 1) {
    const offset = row * (1 + width * 3);
    scanlines[offset] = 0;
    scanlines[offset + 1] = seed;
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('tEXt', Buffer.alloc(1200, seed)),
    pngChunk('IDAT', deflateSync(scanlines)),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

function resolveEnumSentinels(value) {
  if (typeof value === 'string' && /^[a-z0-9_ -]+(?:\s*\|\s*[a-z0-9_ -]+)+$/i.test(value.trim())) {
    return value.split('|')[0].trim();
  }
  if (Array.isArray(value)) {
    return value.map(resolveEnumSentinels);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, resolveEnumSentinels(child)]));
  }
  return value;
}

async function withHttpServer(handler, callback) {
  const server = createServer(handler);
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    return await callback(baseUrl);
  } finally {
    await new Promise((resolveClose, rejectClose) =>
      server.close((error) => (error ? rejectClose(error) : resolveClose()))
    );
  }
}

function fixtureTargetHtml(request) {
  const origin = `http://${request.headers.host}`;
  return `<!doctype html><html><head>
    <title>Target site</title>
    <link rel="canonical" href="${origin}/">
    <meta name="description" content="Fixture homepage description.">
  </head><body><h1>Target home</h1></body></html>`;
}

function runProcess(command, args, cwd, options = {}) {
  return new Promise((resolveProcess) => {
    const child = spawn(command, args, { cwd, ...options });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolveProcess({ status, stderr, stdout }));
  });
}

function liveRouteMatrix(baseUrl) {
  return {
    ...JSON.parse(readFileSync(join(templatesDir, 'route-matrix.template.json'), 'utf8')),
    site: 'Fixture rebuild',
    checkedAt: testCheckedAt,
    sourceBaseUrl: 'https://source.example',
    targetBaseUrl: baseUrl,
    browserFirstRouteExpansion: {
      browserRenderedSeedRoutes: ['/'],
      candidateRoutesFromRenderedLinks: [],
      candidateRoutesFromBundles: [],
      candidateRoutesFromMetadata: [],
      candidateRoutesFromAssets: [],
      candidateRoutesFromSitemapsOrRobots: [],
      candidateRoutesFromNamingPatterns: [],
      curlOnlyRoutesRejected: [],
      expansionComplete: true,
      notes: 'Browser-rendered homepage inspected.'
    },
    homepageParity: {
      sourcePath: '/',
      targetPath: '/',
      targetStatus: 200,
      targetFinalPath: '/',
      targetH1: 'Target home',
      targetTitle: 'Target site',
      accepted: true
    },
    frontPageAliasDecision: {
      sourceHasSeparateHomeAndAlias: false,
      targetDecision: 'not_applicable',
      finalUrlChecks: ['/'],
      noFollowRedirectChecks: ['/'],
      accepted: true,
      rationale: 'No separate source alias.'
    },
    sourceRouteDriftClassification: [],
    targetRequiredRoutes: [
      {
        targetPath: '/',
        reasonRequired: 'front_page',
        targetStatus: 200,
        targetFinalPath: '/',
        expectedPublicBehavior: 'public_200',
        drupalOwner: 'node',
        shouldBePublic: true,
        accepted: true,
        notes: 'The configured front page is public.'
      }
    ],
    perRouteItemReconciliation: [],
    firstFoldBrandAssetParity: ['desktop', 'mobile'].map((viewport) => ({
      sourcePath: '/',
      targetPath: '/',
      viewport,
      heroArtworkMatchesOrDispositioned: true,
      logoOrLockupMatchesOrDispositioned: true,
      signatureGraphicsMatchOrDispositioned: true,
      primaryCtaTreatmentMatchesOrDispositioned: true,
      sourceAssetsReachable: [],
      targetAssetsUsed: [],
      exceptions: [],
      accepted: true,
      notes: 'The fixture has a text lockup and no separate hero artwork.'
    })),
    primaryRoutes: [
      {
        sourcePath: '/',
        targetPath: '/',
        sourceIntent: 'Source homepage',
        targetIntent: 'Target homepage',
        matchesBrowserRenderedSource: true,
        accepted: true,
        notes: ''
      }
    ],
    routes: [
      {
        sourcePath: '/',
        targetPath: '/',
        targetStatus: 200,
        targetFinalPath: '/',
        targetTitle: 'Target site',
        targetH1: 'Target home',
        expectedRedirect: false,
        accepted: true,
        notes: ''
      }
    ],
    starterRouteCleanup: {
      checkedPaths: ['/home', '/page/1', '/privacy-policy'],
      rawNodeRoutesChecked: [],
      starterCanvasPages: [],
      starterCanvasPlaceholderChecks: [],
      staleMenuOrFooterLinks: [],
      duplicateAliases: [],
      unexpectedStarterPublic200s: [],
      accepted: true,
      notes: 'No starter routes leaked.'
    },
    canvasPlaceholderDetection: {
      canvasEnabled: false,
      starterCanvasRoutesChecked: [],
      placeholderTextFindings: [],
      disconnectedCanvasEditorRoutes: [],
      canvasIntentionallyUnused: true,
      documentedReasonIfUnused: 'Not required by this fixture.',
      hardFailIfPublicPlaceholderExists: true,
      accepted: true,
      notes: ''
    },
    unexpectedPublic200s: [],
    missingSourceRoutes: [],
    wrongPatternRoutes: [],
    blockedRoutes: []
  };
}

function injectedDrupalRuntime(baseUrl, overrides = {}) {
  return {
    aliasPolicyAudit: {
      completed: true,
      records: [],
      violations: []
    },
    baseUrl,
    confirmed: true,
    canvasTemplateAudit: {
      completed: true,
      trackedConfigFileCount: 2,
      matchingConfigCount: 0,
      templates: [],
      errors: []
    },
    configStatusClean: true,
    configSyncDirectory: '../config/sync',
    configSyncTracked: true,
    defaultTheme: 'fixture_theme',
    customCodeInventory: {
      completed: true,
      controllers: [],
      extensions: [],
      routes: [],
      sourceFiles: [],
      tests: []
    },
    displayPluginAudit: {
      completed: true,
      formComponentCount: 1,
      formComponents: [{
        displayConfig: 'core.entity_form_display.node.page.default',
        fieldName: 'body',
        fieldDefinitionPresent: true,
        fieldType: 'text_with_summary',
        configuredPlugin: 'text_textarea_with_summary',
        resolvedPlugin: 'text_textarea_with_summary',
        supportsFieldType: true,
        classApplicable: true,
        applicable: true
      }],
      viewComponents: [{
        displayConfig: 'core.entity_view_display.node.page.default',
        fieldName: 'body',
        fieldDefinitionPresent: true,
        fieldType: 'text_with_summary',
        configuredPlugin: 'text_default',
        resolvedPlugin: 'text_default',
        supportsFieldType: true,
        classApplicable: true,
        applicable: true
      }],
      viewComponentCount: 1,
      violations: []
    },
    frontPage: '/',
    mode: 'test-injected',
    project: 'fixture',
    reason: '',
    siteUuid: testSiteUuid,
    trackedConfigDirectory: 'config/sync',
    trackedConfigYamlFiles: ['config/sync/system.site.yml', 'config/sync/system.theme.yml'],
    ...overrides
  };
}

function addQualifyingMarkdownEvidence(packetDir, sourceBaseUrl, targetBaseUrl) {
  writeFileSync(join(packetDir, 'operator-run.md'), `# Independent Operator Run Record

## Operator

- Name: Fixture Operator
- Role: Independent operator
- Environment: DDEV Drupal fixture
- Environment provisioning (manual, One Line Installer, other): One Line Installer-equivalent fixture
- Date: 2026-07-09

## Run Evidence

- DDEV project URL: ${targetBaseUrl}
- \`ddev drush status\`: Successful bootstrap recorded in drupal-readback.json
- Config export location: config/sync
- Anonymous route checks: browser-evidence.json
- Browser-rendered evidence: evidence/blind-adversarial-review/
- Command transcript: drupal-readback.json commands
- Reviewer: Fixture Reviewer

## Decision

- [ ] Repeatability not reviewed
- [ ] Repeatability blocked
- [x] Repeatability accepted
- [ ] Repeatability accepted with restrictions
`);

  writeFileSync(join(packetDir, 'maintainer-review.md'), `# Maintainer Review Packet

## Review Scope

- Site: Fixture rebuild
- Target: ${targetBaseUrl}
- Reviewer: Fixture Maintainer
- Date: 2026-07-09

## Stake-My-Name Verdict

- [x] Is the build on Drupal CMS best practices using Drupal-native primitives?
- [x] Is the architecture sound for the source site's real shape?
- [x] Does it contain the public content and media needed to review the site as a rebuild?
- [x] Does it match the source site's visual language and public behavior?
- [x] Can editors maintain the site through Drupal forms, menus, media, Views, and workflow?
- [x] Are the load-bearing decisions captured and usable by later agents?
- [x] Are the remaining business, legal, integration, production, and launch gaps named?
- [x] Would a Drupal maintainer put their name on this as a complete local starting point?

## Binary Verdict

- [x] I would stake my name on this as a complete local Drupal CMS rebuild.
- [ ] I would not stake my name on this as a complete local Drupal CMS rebuild.

## Required Rationale

- Reasons to accept: The live, editor, packet, config, and parity evidence is complete for the fixture.
- Reasons to reject or revise: None for the local rebuild claim.
`);

  writeFileSync(join(packetDir, 'recipe-start-point.md'), `# Installed Baseline And Recipe Fit Decision

## Site

- Source URL: ${sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Source-use boundary: Authorized public rebuild
- Decision date: 2026-07-09
- Decision owner: Fixture Maintainer

## Installed Substrate And Assembly Decision

- [x] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.
- [ ] Retain a site template selected before installation plus bounded source-fit Recipes and overlays.
- [ ] Retain another existing Drupal CMS substrate and extend it without replacing it.
- [ ] Use bounded custom overlays because maintained Recipes do not fit the audited source patterns.

Decision: Retain the installed Drupal CMS Starter.

Rationale: The source has one structured route and no higher-fit template.

Installed substrate evidence (installed Recipe/template, Drupal CMS/core versions, public theme, front page, and starter content): drupal-readback.json

## Recipe Candidate Review

The recipe default owner was checked before custom overlays.

ddev composer show 'drupal/drupal_cms_*'
ddev exec bash -lc 'find recipes web/core/recipes -name recipe.yml -print 2>/dev/null | sort'

All available recipe candidates were reviewed and dispositioned as not_applicable for this fixture.
`);

  writeFileSync(join(packetDir, 'scoped-gap-list.md'), `# Scoped Gap List

## Site

- Source URL: ${sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Date: 2026-07-09

## Summary

Overall status: \`complete-local-rebuild\`

## Gaps

No unresolved local-rebuild gaps remain. Launch-only production evidence is outside this fixture claim.
`);

  writeFileSync(join(packetDir, 'open-decisions.md'), `# Open Decisions

## Site

- Source URL: ${sourceBaseUrl}
- Target site name: Fixture rebuild
- Target workspace: DDEV fixture
- Date: 2026-07-09

## Decisions

No human-only decisions remain for the complete local rebuild.

## Handoff Summary

- Decisions still open: None
- Decisions accepted: Local rebuild architecture and evidence
- Decisions blocked by missing external input: None
- Agent-resolvable work deliberately excluded from this file: None
`);

  writeFileSync(join(packetDir, 'off-road-inventory.md'), `# Off-Road Inventory

## Summary

- Site: Fixture rebuild
- Checked at: 2026-07-09
- Reviewer: Fixture Maintainer
- Overall status: \`accepted\`

## Inventory

No off-road moves were used in this fixture.
`);

  writeFileSync(join(packetDir, 'durable-intent.yml'), `schema_version: public-kit.1
site: "${targetBaseUrl}"
intent_records: []
evidence_scope: "No durable intent records apply to this fixture."
`);
}

function addQualifyingReviewEvidence(packetDir, targetBaseUrl) {
  const sourceBaseUrl = JSON.parse(readFileSync(join(packetDir, 'route-matrix.json'), 'utf8')).sourceBaseUrl;
  const independentPath = join(packetDir, 'independent-verification.json');
  const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
  independent.site = targetBaseUrl;
  independent.checkedAt = testCheckedAt;
  independent.verifier = {
    nameOrRole: 'fresh independent verifier',
    runtimeOrTool: 'browser and Drupal CLI',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    builderSummaryExcluded: true,
    independenceDegradedReason: '',
    liveSiteInspected: true,
    packetInspected: true,
    notes: ''
  };
  independent.target = {
    baseUrl: targetBaseUrl,
    ddevProject: 'test-target',
    adminUrl: `${targetBaseUrl}/admin`,
    editorUser: 'editor',
    editorRole: 'content editor'
  };
  independent.perRouteItemCounts = [];
  independent.collectionOwnershipChecks = [];
  independent.renderedEmbedChecks = [];
  independent.rawEmbedAndMarkupScan = {
    fieldsScanned: ['node fields', 'theme templates'],
    patternsChecked: ['<iframe', '<script', 'onload=', 'onclick=', 'javascript:', 'style=', 'raw source HTML'],
    findings: [],
    offRoadInventoryUpdated: true,
    status: 'pass'
  };
  independent.footerAndMenuLinkChecks = [];
  independent.targetRequiredRouteChecks = [
    {
      targetPath: '/',
      reasonRequired: 'front_page',
      targetStatus: 200,
      targetFinalUrl: `${targetBaseUrl}/`,
      expectedPublicBehavior: 'public_200',
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.routeDriftDispositionChecks = [];
  independent.placeholderTextScan = {
    scannedRoutes: ['/'],
    scannedAdminSurfaces: ['/admin/content'],
    termsChecked: ['lorem ipsum', 'placeholder', 'sample', 'starter', 'TODO', 'test page'],
    findings: [],
    status: 'pass'
  };
  independent.starterRouteAndLeakChecks = {
    pathsChecked: ['/', '/home', '/page/1', '/privacy-policy'],
    rawNodeRoutesChecked: [],
    unexpectedPublic200s: [],
    duplicateAliases: [],
    disconnectedCanvasStarterPages: [],
    status: 'pass'
  };
  independent.canvasPlaceholderChecks = {
    canvasEnabled: false,
    starterCanvasPagesChecked: [],
    publicCanvasPlaceholderFindings: [],
    disconnectedCanvasEditorRoutes: [],
    canvasIntentionallyUnusedAndDocumented: true,
    status: 'pass'
  };
  independent.firstFoldBrandAssetChecks = ['desktop', 'mobile'].map((viewport) => ({
    sourceRoute: '/',
    targetRoute: '/',
    viewport,
    heroArtworkStatus: 'not_applicable',
    logoOrLockupStatus: 'pass',
    signatureGraphicStatus: 'not_applicable',
    primaryCtaTreatmentStatus: 'pass',
    reachableSourceAssetsMissingOrApproximated: [],
    evidence: 'claim-evidence.json'
  }));
  independent.compositionModelFidelityChecks = [
    {
      sourceRoute: '/',
      targetRoute: '/',
      declaredCompositionOwner: 'entity_display',
      actualCompositionOwner: 'entity_display',
      routeRationalePresent: true,
      sectionOwnershipDeclared: true,
      sectionsChecked: ['Introduction'],
      expectedEditorActionsVerified: true,
      nonAdminEditorPublicOutputProof: 'evidence/blind-adversarial-review/editor-task.json',
      deviationRecordRequired: false,
      deviationRecordPresent: false,
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.canvasComponentModelChecks = [];
  independent.editorAddRowChecks = [];
  independent.fieldOutputFalsification = [
    {
      entityType: 'node',
      bundle: 'page',
      field: 'body',
      claim: 'Body affects anonymous output.',
      actualEditorSurface: '/node/1/edit',
      actualPublicOutput: '/',
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.drupalImplementationChecks = [
    {
      kind: 'display_plugin_audit',
      identity: 'all_configured_components',
      liveReadback: 'drupal-readback.json implementationQuality.displayPluginAudit',
      falsificationAttempt: 'Compared configured and resolved plugins against live field applicability.',
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.coldReaderLabelChecks = [
    {
      bundle: 'page',
      editorFacingLabel: 'Page',
      wouldMakeSenseIfBrandChanged: true,
      siteBrandingExposedToEditor: false,
      status: 'pass',
      evidence: 'claim-evidence.json'
    }
  ];
  independent.directDatabaseCleanupChecks = [];
  independent.packetFreshnessChecks = [
    'route-matrix.json',
    'browser-evidence.json',
    'drupal-readback.json',
    'field-output-matrix.json',
    'parity-report.json',
    'pattern-map.json'
  ].map((artifact) => ({
    artifact,
    claim: `${artifact} reflects the inspected target.`,
    liveSiteEvidence: 'claim-evidence.json',
    staleOrMissingEvidence: false,
    status: 'pass'
  }));
  independent.completionClaims = [
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
  ].map((gate) => ({
    claimId: `${gate}-checked`,
    claim: `The ${gate} completion evidence was independently checked.`,
    gate,
    builderEvidence: [],
    falsificationChecks: [`Attempted to falsify the ${gate} evidence against the target and packet.`],
    verifierEvidence: ['claim-evidence.json'],
    status: 'pass',
    failureEvidence: [],
    nextFix: ''
  }));
  independent.summary = {
    failedClaimCount: 0,
    blockedClaimCount: 0,
    highestRiskFailures: [],
    verdict: 'pass',
    notes: ''
  };
  writeJson(independentPath, independent);
  const independentEvidenceDir = join(packetDir, 'evidence', 'independent-verification');
  mkdirSync(independentEvidenceDir, { recursive: true });
  writeJson(join(independentEvidenceDir, 'claim-evidence.json'), {
    schemaVersion: 'public-kit.independent-claim-evidence.1',
    targetBaseUrl,
    checkedAt: testCheckedAt,
    claims: independent.completionClaims.map((claim) => ({
      claimId: claim.claimId,
      gate: claim.gate,
      checks: [
        {
          name: `${claim.gate} falsification`,
          method: 'live target and packet inspection',
          result: 'pass',
          observation: `The ${claim.gate} evidence matched the inspected target and packet.`
        }
      ]
    }))
  });

  const blindEvidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  mkdirSync(blindEvidenceDir, { recursive: true });
  for (const [index, [name, width, height]] of [
    ['source-desktop.png', 1280, 800],
    ['target-desktop.png', 1280, 800],
    ['source-mobile.png', 390, 844],
    ['target-mobile.png', 390, 844]
  ].entries()) {
    writeFileSync(join(blindEvidenceDir, name), screenshotPng(index + 1, width, height));
  }
  writeJson(join(blindEvidenceDir, 'editor-task.json'), {
    targetAdminUrl: `${targetBaseUrl}/admin/content`,
    editorRole: 'content editor',
    action: 'Created representative Page content as the non-admin editor.',
    resultingPublicUrl: `${targetBaseUrl}/`,
    publicOutputChanged: true,
    checkedAt: testCheckedAt
  });

  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  blind.site = targetBaseUrl;
  blind.checkedAt = testCheckedAt;
  blind.reviewer = {
    nameOrRole: 'fresh blind reviewer',
    runtimeOrTool: 'browser',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    didNotBuildTarget: true,
    inputsRestrictedToBriefTargetAndSourceTruth: true,
    implementationFilesReadBeforePublicReview: false,
    reviewPacketReadBeforePublicReview: false,
    priorBuildConversationRead: false,
    builderSummaryExcluded: true,
    notes: ''
  };
  blind.reviewInputs = {
    originalBrief: 'Rebuild the source site.',
    acceptanceCriteria: [],
    targetUrlsOrArtifacts: [`${targetBaseUrl}/`],
    sourceOfTruthMaterials: [{ type: 'source_site', reference: sourceBaseUrl, notes: '' }],
    credentialsUsed: [],
    excludedInputs: []
  };
  blind.routeViewportReviews = ['desktop', 'mobile'].map((viewport) => ({
    route: '/',
    sourceTruthReference: sourceBaseUrl,
    targetUrlOrArtifact: `${targetBaseUrl}/`,
    viewport,
    sourceScreenshot: `source-${viewport}.png`,
    targetScreenshot: `target-${viewport}.png`,
    routeNotes: `${viewport} checked`,
    checks: {
      actualRequestedOutcome: 'pass',
      firstFoldVisualParity: 'pass',
      navigationBehavior: 'pass',
      contentHierarchyCompleteness: 'pass',
      mediaArtworkFidelity: 'pass',
      interactionParity: 'pass',
      editorialQuality: 'pass',
      accessibilitySeoConsoleObviousDefects: 'pass'
    },
    verdict: 'good',
    evidence: []
  }));
  blind.routeCoverage = {
    strategy: 'all_primary_routes',
    primaryRoutesReviewed: ['/'],
    omittedPrimaryRoutes: [],
    notes: ''
  };
  blind.editorExperienceReviews = [
    {
      task: 'create representative content',
      briefExpectation: 'A non-admin editor can update public output.',
      targetAdminUrl: `${targetBaseUrl}/admin/content`,
      editorRole: 'content editor',
      publicOutputExpectedToChange: '/',
      publicOutputChanged: true,
      notInspectedReason: '',
      verdict: 'good',
      evidence: ['editor-task.json']
    }
  ];
  blind.productDefects = [];
  blind.reviewPasses = [
    { id: 'pass-1', checkedAt: testCheckedAt, reviewer: 'fresh reviewer', verdict: 'good', notes: '' }
  ];
  blind.summary = {
    verdict: 'good',
    completionState: 'parity_reviewed',
    desktopMobileReviewed: true,
    routeNotesPresent: true,
    rawEvidencePresent: true,
    openBlockerIssueCount: 0,
    openCriticalIssueCount: 0,
    openHighIssueCount: 0,
    acceptedOutOfScopeIssueCount: 0,
    externalBlockerIssueCount: 0,
    notes: ''
  };
  writeJson(blindPath, blind);

  const sourceAuditPath = join(packetDir, 'source-audit.json');
  const sourceAudit = JSON.parse(readFileSync(sourceAuditPath, 'utf8'));
  sourceAudit.checkedAt = testCheckedAt;
  sourceAudit.site = { name: 'Source fixture', baseUrl: sourceBaseUrl };
  sourceAudit.representativeUrls = [`${sourceBaseUrl}/`];
  sourceAudit.evidencePoints = [
    { claim: 'The source homepage was captured.', url: `${sourceBaseUrl}/`, method: 'browser', result: 'observed' }
  ];
  sourceAudit.observedPatterns = [{ pattern: 'homepage', evidence: `${sourceBaseUrl}/` }];
  sourceAudit.contentInventory = [{ route: '/', type: 'homepage', title: 'Source home' }];
  sourceAudit.designSignals = [{ route: '/', signal: 'hero, navigation, and content hierarchy captured' }];
  sourceAudit.routeInventorySummary = {
    attemptedRoutes: 1,
    successfulRoutes: 1,
    failedRoutes: 0,
    unfetchedCandidates: 0
  };
  writeJson(sourceAuditPath, sourceAudit);

  const patternMapPath = join(packetDir, 'pattern-map.json');
  const patternMap = JSON.parse(readFileSync(patternMapPath, 'utf8'));
  patternMap.checkedAt = testCheckedAt;
  patternMap.sourceSite = sourceBaseUrl;
  patternMap.contentTypes = [{ machineName: 'page', label: 'Page', sourceObjects: ['homepage'] }];
  patternMap.fields = [{ bundle: 'page', machineName: 'body', sourceFact: 'homepage copy' }];
  patternMap.structuredContentModel.collectionScope = {
    reviewed: true,
    applies: false,
    reason: 'The one-route fixture has no repeatable collection surface.'
  };
  patternMap.structuredContentModel.recurringSourceObjects = [];
  patternMap.structuredContentModel.collectionOwnershipLedger = [];
  patternMap.buildTypeDeclaration = {
    type: 'structured_drupal_native_canvas_unused',
    canvasAvailabilityEvidence: 'Canvas was inspected and is not needed for this one-route fixture.',
    whyThisTypeFitsSource: 'The fixture is a structured homepage.',
    editorOwnershipImplications: 'Editors maintain the page through fields.',
    accepted: true,
    notes: ''
  };
  patternMap.compositionModel.completedBeforeImplementation = true;
  patternMap.pageCompositionOwnership = [
    {
      sourceRoute: '/',
      routeRole: 'homepage',
      selectedOwner: 'node',
      ownerRationale: 'A structured Page entity owns the homepage.',
      canvasOrExperienceBuilderAvailable: true,
      canvasOwnsPublicRoute: false,
      editorCanOpenSelectedOwner: true,
      themeOwnsOnlyPresentation: true,
      starterCanvasPlaceholderDisconnected: true,
      editorVerificationEvidence: 'evidence/blind-adversarial-review/editor-task.json',
      accepted: true,
      notes: ''
    }
  ];
  patternMap.sectionOwnershipMatrix = [
    {
      sourceRoute: '/',
      section: 'intro',
      editorFacingName: 'Introduction',
      editorOwnedBy: 'field',
      repeatability: 'singleton',
      dataSource: 'node.page.body',
      expectedEditorAction: 'Edit the Introduction field.',
      acceptanceProof: 'evidence/blind-adversarial-review/editor-task.json',
      drupalOwner: 'node.page.body',
      publicOutputLocation: '/',
      nonAdminEditorCanChange: true,
      themeOwnsOnlyPresentation: true,
      exceptionRationale: '',
      accepted: true,
      notes: ''
    }
  ];
  patternMap.contentTypeLabelPolicy = {
    editorFacingLabelsUsePortableNouns: true,
    coldReaderLabelTestPassed: true,
    siteBrandedEditorLabels: [],
    machineNamePrefixPolicy: 'Portable bundle and field names.',
    accepted: true,
    notes: ''
  };
  patternMap.seoMetadata = {
    strategy: 'Rendered canonical URL and description are verified on the public route.',
    metatagConfig: ['metatag.metatag_defaults.node'],
    editorFields: ['node.page.body'],
    canonicalDecisions: [{ route: '/', decision: 'self canonical', accepted: true }],
    blockedEvidence: []
  };
  patternMap.reviewStatus = 'reviewed';
  writeJson(patternMapPath, patternMap);

  const fieldOutputPath = join(packetDir, 'field-output-matrix.json');
  const fieldOutput = JSON.parse(readFileSync(fieldOutputPath, 'utf8'));
  fieldOutput.site = targetBaseUrl;
  fieldOutput.checkedAt = testCheckedAt;
  fieldOutput.bundles = [
    {
      entityType: 'node',
      bundle: 'page',
      fields: [
        {
          machineName: 'body',
          editorLabel: 'Introduction',
          required: true,
          fieldType: 'text_long',
          widget: 'text_textarea',
          formatter: 'text_default',
          publicRenderLocations: ['/'],
          affectsAnonymousOutput: true,
          containsRawPresentationImplementation: false,
          presentationBoundary: 'content_fact',
          editorOnlyRationale: '',
          accepted: true,
          notes: 'The editor task changed this output.'
        }
      ]
    }
  ];
  fieldOutput.blockedFields = [];
  writeJson(fieldOutputPath, fieldOutput);

  const parityPath = join(packetDir, 'parity-report.json');
  const parity = JSON.parse(readFileSync(parityPath, 'utf8'));
  parity.checkedAt = testCheckedAt;
  parity.targetUrl = targetBaseUrl;
  parity.addressableSurface = { routesInScope: 1, routesExcluded: 0, exclusions: [] };
  parity.routeChecks = [{ route: '/', status: 'pass', evidence: 'route-check.json' }];
  parity.functionalScope = {
    reviewed: true,
    applies: false,
    reason: 'The source fixture has no interactive behavior beyond navigation.'
  };
  parity.contentChecks = [{
    route: '/',
    sourceExpectation: 'Source homepage intent is present.',
    targetObservation: 'Target homepage carries the rebuilt intent.',
    status: 'pass',
    evidence: 'browser-evidence.json',
    notes: ''
  }];
  parity.visualChecks = [{
    route: '/',
    sourceExpectation: 'Text lockup and hierarchy match.',
    targetObservation: 'Target text lockup and hierarchy were compared.',
    status: 'pass',
    evidence: 'browser-evidence.json',
    notes: ''
  }];
  parity.functionalChecks = [];
  parity.browserEvidence = ['browser-evidence.json'];
  parity.blockedEvidence = [];
  parity.verdict = 'pass';
  writeJson(parityPath, parity);

  const browserPath = join(packetDir, 'browser-evidence.json');
  const browser = JSON.parse(readFileSync(browserPath, 'utf8'));
  browser.site = targetBaseUrl;
  browser.checkedAt = testCheckedAt;
  browser.toolOrMethod = 'browser';
  browser.publicRouteChecks = ['desktop', 'mobile'].map((viewport) => {
    const desktop = viewport === 'desktop';
    return {
      routeRole: 'homepage',
      sourceUrl: `${sourceBaseUrl}/`,
      sourceFinalUrl: `${sourceBaseUrl}/`,
      targetUrl: `${targetBaseUrl}/`,
      targetFinalUrl: `${targetBaseUrl}/`,
      viewport: { name: viewport, width: desktop ? 1280 : 390, height: desktop ? 800 : 844 },
      sourceScreenshot: `evidence/blind-adversarial-review/source-${viewport}.png`,
      targetScreenshot: `evidence/blind-adversarial-review/target-${viewport}.png`,
      visualComparison: { method: 'human_review', diffImage: '', diffScore: null, status: 'pass', acceptedExceptions: [] },
      renderedSignals: {
        sourceTitle: 'Source home',
        targetTitle: 'Target site',
        sourceH1: 'Source home',
        targetH1: 'Target home',
        sourceKeyVisibleBodyIntent: 'Source homepage intent',
        targetKeyVisibleBodyIntent: 'Rebuilt homepage intent',
        sectionOrderMatches: true,
        headerFooterTreatmentMatches: true,
        typographySpacingMatches: true,
        mediaPlacementMatches: true,
        sourceLikeBehaviorMatches: true
      },
      firstFoldBrandAssetSignals: {
        sourceHeroArtwork: 'No hero artwork in fixture.',
        targetHeroArtwork: 'No hero artwork in fixture.',
        sourceLogoOrLockup: 'Text lockup',
        targetLogoOrLockup: 'Text lockup',
        sourceSignatureGraphics: [],
        targetSignatureGraphics: [],
        primaryCtaTreatmentMatches: true,
        brandDefiningAssetsMissingOrApproximated: []
      },
      renderedSeoSignals: {
        targetCanonicalUrl: `${targetBaseUrl}/`,
        targetMetaDescription: 'Fixture homepage description.',
        targetOpenGraphImage: '',
        metaDescriptionStatus: 'present',
        openGraphImageStatus: 'not_applicable',
        metaDescriptionApplicabilityReviewed: true,
        metaDescriptionNotApplicableRationale: '',
        openGraphImageApplicabilityReviewed: true,
        openGraphImageNotApplicableRationale: 'The source fixture has no social image.',
        accepted: true,
        evidence: 'browser route capture'
      },
      renderedItemCounts: [],
      notes: `Homepage checked at ${viewport}.`,
      accepted: true,
      blockers: []
    };
  });
  browser.editorWorkflowChecks = [
    {
      workflow: 'create',
      entityType: 'node',
      bundle: 'page',
      editorUser: 'editor',
      editorRole: 'content editor',
      drupalRoute: '/admin/content',
      taskPerformed: 'Created representative content.',
      formScreenshot: 'evidence/blind-adversarial-review/target-desktop.png',
      resultScreenshot: 'evidence/blind-adversarial-review/target-mobile.png',
      fieldsAndWidgetsVerified: ['title', 'body'],
      publicOutputAffected: '/',
      visualOrBehaviorResult: 'Public output changed.',
      status: 'pass',
      acceptedExceptions: [],
      accepted: true,
      blockers: []
    }
  ];
  browser.canvasAuthoringChecks = [];
  browser.missingBrowserEvidence = [];
  browser.browserEvidenceComplete = true;
  writeJson(browserPath, browser);

  const readbackPath = join(packetDir, 'drupal-readback.json');
  const readback = JSON.parse(readFileSync(readbackPath, 'utf8'));
  readback.site = targetBaseUrl;
  readback.checkedAt = testCheckedAt;
  readback.commands = [
    'drush status',
    'drush config:get system.site --field=uuid',
    'drush config:get system.site --field=page.front',
    'drush php:eval config sync directory',
    'drush config:status',
    'git ls-files config/sync/*.yml'
  ];
  readback.drupal.status = { bootstrap: 'Successful', uri: targetBaseUrl };
  readback.drupal.siteUuid = testSiteUuid;
  readback.drupal.enabledModules = ['node', 'media', 'views'];
  readback.drupal.defaultTheme = 'fixture_theme';
  readback.drupal.adminTheme = 'claro';
  readback.drupal.frontPage = '/';
  readback.drupal.configSyncDirectory = '../config/sync';
  readback.drupal.trackedConfigDirectory = 'config/sync';
  readback.drupal.trackedConfigYamlFiles = ['config/sync/system.site.yml', 'config/sync/system.theme.yml'];
  readback.drupal.configSyncDirectoryMatchesTrackedDirectory = true;
  readback.drupal.configStatus = 'No differences';
  readback.drupal.configStatusClean = true;
  readback.content.nodes = [{ id: 1, type: 'page', title: 'Target home', published: true }];
  readback.content.contentTypes = [{ machineName: 'page', label: 'Page' }];
  readback.content.fieldStorage = [{ field: 'body', type: 'text_long' }];
  readback.content.formDisplays = [{ bundle: 'page', mode: 'default' }];
  readback.content.viewDisplays = [{ bundle: 'page', mode: 'full' }];
  readback.routing.menus = [{ id: 'main', label: 'Main navigation' }];
  readback.routing.menuLinks = [{ menu: 'main', title: 'Home', url: '/' }];
  readback.routing.publicBundleAliasPolicies = [];
  readback.rolesAndPermissionsNotes = ['Content editor can create and edit Page content.'];
  readback.implementationQuality = {
    canvasTemplateAudit: {
      trackedConfigFileCount: 2,
      matchingConfigCount: 0,
      templates: [],
      errors: [],
      conflicts: [],
      completed: true
    },
    displayPluginAudit: {
      formComponentCount: 1,
      formComponents: [{
        displayConfig: 'core.entity_form_display.node.page.default',
        fieldName: 'body',
        fieldDefinitionPresent: true,
        fieldType: 'text_with_summary',
        configuredPlugin: 'text_textarea_with_summary',
        resolvedPlugin: 'text_textarea_with_summary',
        supportsFieldType: true,
        classApplicable: true,
        applicable: true,
        accepted: true
      }],
      viewComponents: [{
        displayConfig: 'core.entity_view_display.node.page.default',
        fieldName: 'body',
        fieldDefinitionPresent: true,
        fieldType: 'text_with_summary',
        configuredPlugin: 'text_default',
        resolvedPlugin: 'text_default',
        supportsFieldType: true,
        classApplicable: true,
        applicable: true,
        accepted: true
      }],
      viewComponentCount: 1,
      violations: [],
      completed: true
    },
    customCodeInventory: {
      applies: false,
      reason: 'The fixture project has no custom modules or themes.',
      extensions: [],
      sourceFiles: [],
      routes: [],
      controllers: [],
      tests: [],
      completed: true
    },
    blockers: []
  };
  readback.readbackComplete = true;
  readback.blockers = [];
  writeJson(readbackPath, readback);

  addQualifyingMarkdownEvidence(packetDir, sourceBaseUrl, targetBaseUrl);

  const gates = JSON.parse(readFileSync(join(repoRoot, 'gates.json'), 'utf8'));
  for (const packetFile of gates.reviewPacketFiles) {
    const path = join(packetDir, packetFile);
    if (packetFile.endsWith('.json')) {
      const record = resolveEnumSentinels(JSON.parse(readFileSync(path, 'utf8')));
      record.runSpecificEvidenceRecorded = true;
      writeJson(path, record);
    }
  }
}

test('default verifier fetches the declared real target and binds primary-route evidence', async () => {
  let requestCount = 0;
  await withHttpServer(
    (_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><head><title>Target site</title></head><body><h1>Target home</h1></body></html>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-target-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        cwd: repoRoot,
        environment: { DDEV_PRIMARY_URL: baseUrl }
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.liveTargetValid, true);
      assert.equal(report.routeChecks.length, 1);
      assert.equal(report.routeChecks[0].passed, true, report.routeChecks[0].errors.join('\n'));
      assert.match(report.routeChecks[0].bodySha256, /^sha256:[a-f0-9]{64}$/);
      assert.match(report.target.targetFingerprint, /^sha256:[a-f0-9]{64}$/);
      assert.equal(report.target.resolutionSource, 'ddev-environment');
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.packetVerification.completionEvidence.packetCompletionReady, false);
      assert.match(
        report.packetVerification.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /unchanged from the shipped template/
      );
      assert.match(report.completionBlockedReasons.join(' '), /Independent verification/);
    }
  );
  assert.equal(requestCount, 2, 'primary and target-required route checks should both fetch the declared target');
});

test('live verifier rejects Drupal display fallback even when packet evidence claims the configured plugin', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-display-plugin-fallback-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const runtime = injectedDrupalRuntime(baseUrl);
      runtime.displayPluginAudit.formComponents[0].resolvedPlugin = 'entity_reference_autocomplete';
      runtime.displayPluginAudit.formComponents[0].applicable = false;
      runtime.displayPluginAudit.violations = [runtime.displayPluginAudit.formComponents[0]];

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });

      assert.equal(report.liveTargetValid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /configured text_textarea_with_summary but resolved entity_reference_autocomplete/);
    }
  );
});

test('live display audit rejects unsupported field types and typed components without field definitions', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const cases = [
        {
          name: 'unsupported-field-type',
          mutate: (component) => {
            component.supportsFieldType = false;
            component.applicable = false;
            component.reason = 'plugin_field_type_not_supported';
          },
          expected: /does not declare support for field type text_with_summary/
        },
        {
          name: 'missing-field-definition',
          mutate: (component) => {
            component.fieldDefinitionPresent = false;
            component.fieldType = '';
            component.supportsFieldType = false;
            component.classApplicable = false;
            component.applicable = false;
            component.resolvedPlugin = '';
            component.reason = 'missing_field_definition';
          },
          expected: /typed component body has no Drupal field definition/
        }
      ];
      for (const auditCase of cases) {
        const temp = mkdtempSync(join(tmpdir(), `live-display-${auditCase.name}-`));
        const packetDir = join(temp, 'review-packet');
        copyTemplatePacket(packetDir);
        writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
        addQualifyingReviewEvidence(packetDir, baseUrl);
        const runtime = injectedDrupalRuntime(baseUrl);
        const component = runtime.displayPluginAudit.formComponents[0];
        auditCase.mutate(component);
        runtime.displayPluginAudit.violations = [component];

        const report = await verifyLive({
          packetDir,
          targetUrl: baseUrl,
          cwd: repoRoot,
          environment: {},
          drupalRuntime: runtime
        });

        assert.equal(report.liveTargetValid, false, auditCase.name);
        assert.match(report.errors.join('\n'), auditCase.expected, auditCase.name);
      }
    }
  );
});

test('completion requires valid display-plugin readback and future alias policy for public collections', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'drupal-maintainer-quality-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.displayPluginAudit.formComponents[0].resolvedPlugin = 'entity_reference_autocomplete';
    readback.implementationQuality.displayPluginAudit.formComponents[0].applicable = false;
  });
  mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
    patternMap.structuredContentModel.collectionOwnershipLedger = [{
      sourceRoute: '/articles',
      collectionPattern: 'archive',
      sourceObject: 'article',
      sourceItemCount: 3,
      drupalEntityType: 'node',
      contentTypeOrBundle: 'article',
      requiredFields: ['title'],
      collectionOwner: 'view',
      viewDisplayOrConfig: 'articles.page_1',
      detailRouteOwner: 'entity_view_display',
      editorAddRowEvidence: 'browser-evidence.json',
      exceptionRationale: '',
      accepted: true,
      notes: ''
    }];
  });

  const report = await validatePacket({ packetDir });
  const reasons = report.completionEvidence.packetCompletionBlockedReasons.join('\n');

  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(reasons, /configured field widget and formatter/);
  assert.match(reasons, /working future-content alias policy.*article/);
});

test('Canvas-unused claims fail when tracked config enables a public Canvas content template', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'canvas-unused-config-conflict-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  for (const testCase of [
    { name: 'enabled-public-template', enabled: true, expectsConflict: true },
    { name: 'disabled-public-template', enabled: false, expectsConflict: false }
  ]) {
    const packetDir = join(temp, testCase.name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
      const path = 'config/sync/canvas.content_template.node.page.full.yml';
      readback.drupal.trackedConfigYamlFiles.push(path);
      readback.implementationQuality.canvasTemplateAudit = {
        trackedConfigFileCount: 3,
        matchingConfigCount: 1,
        templates: [{
          configName: 'canvas.content_template.node.page.full',
          path,
          enabled: testCase.enabled,
          id: 'node.page.full',
          entityType: 'node',
          bundle: 'page',
          viewMode: 'full',
          publicTarget: true,
          accepted: true
        }],
        errors: [],
        conflicts: [],
        completed: true
      };
    });

    const report = await validatePacket({ packetDir });
    const reasons = report.completionEvidence.packetCompletionBlockedReasons.join('\n');
    assert.equal(
      /declares Canvas intentionally unused while tracked config enables/.test(reasons),
      testCase.expectsConflict,
      `${testCase.name}: ${reasons}`
    );
  }
});

test('live Canvas audit rejects readback that hides an enabled public content template', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-canvas-template-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const path = 'config/sync/canvas.content_template.node.page.full.yml';
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.drupal.trackedConfigYamlFiles.push(path);
        readback.implementationQuality.canvasTemplateAudit = {
          trackedConfigFileCount: 3,
          matchingConfigCount: 1,
          templates: [{
            configName: 'canvas.content_template.node.page.full',
            path,
            enabled: false,
            id: 'node.page.full',
            entityType: 'node',
            bundle: 'page',
            viewMode: 'full',
            publicTarget: true,
            accepted: true
          }],
          errors: [],
          conflicts: [],
          completed: true
        };
      });
      const runtime = injectedDrupalRuntime(baseUrl, {
        trackedConfigYamlFiles: [
          'config/sync/system.site.yml',
          'config/sync/system.theme.yml',
          path
        ],
        canvasTemplateAudit: {
          completed: true,
          trackedConfigFileCount: 3,
          matchingConfigCount: 1,
          templates: [{
            configName: 'canvas.content_template.node.page.full',
            path,
            enabled: true,
            id: 'node.page.full',
            entityType: 'node',
            bundle: 'page',
            viewMode: 'full'
          }],
          errors: []
        }
      });

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });

      assert.equal(report.liveTargetValid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /Canvas content template.*missing or inaccurate/);
    }
  );
});

test('future alias policy covers non-node detail owners but not row-only collections', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'alias-policy-entity-types-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'taxonomy-detail',
      entityType: 'taxonomy_term',
      detailRouteOwner: 'entity_view_display',
      expectsAliasFailure: true
    },
    {
      name: 'view-row-only',
      entityType: 'node',
      detailRouteOwner: 'view_row',
      expectsAliasFailure: false
    }
  ];
  for (const aliasCase of cases) {
    const packetDir = join(temp, aliasCase.name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, 'pattern-map.json'), (patternMap) => {
      patternMap.structuredContentModel.collectionOwnershipLedger = [{
        sourceRoute: '/topics',
        collectionPattern: 'directory',
        sourceObject: 'topic',
        sourceItemCount: 3,
        drupalEntityType: aliasCase.entityType,
        contentTypeOrBundle: 'topic',
        requiredFields: ['name'],
        collectionOwner: 'taxonomy_view',
        viewDisplayOrConfig: 'topics.page_1',
        detailRouteOwner: aliasCase.detailRouteOwner,
        editorAddRowEvidence: 'browser-evidence.json',
        exceptionRationale: '',
        accepted: true,
        notes: ''
      }];
    });

    const report = await validatePacket({ packetDir });
    const reasons = report.completionEvidence.packetCompletionBlockedReasons.join('\n');
    assert.equal(
      /future-content alias policy/.test(reasons),
      aliasCase.expectsAliasFailure,
      `${aliasCase.name}: ${reasons}`
    );
    if (aliasCase.expectsAliasFailure) {
      assert.match(reasons, /taxonomy_term\.topic/);
    }
  }
});

test('live alias policy binds a non-node probe entity and alias-manager result', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-alias-policy-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const policy = {
        entityType: 'taxonomy_term',
        bundle: 'topic',
        strategy: 'editor_supplied_alias',
        patternId: '',
        probeEntityId: '17',
        probeLanguage: 'en',
        existingAliasExample: '/topics/existing',
        probeAlias: '/topics/probe',
        structureMatchesExistingContent: true,
        editorCanCreateExpectedAlias: true,
        evidence: 'evidence/independent-verification/claim-evidence.json',
        accepted: true,
        notes: ''
      };
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.routing.publicBundleAliasPolicies = [policy];
      });
      const runtime = injectedDrupalRuntime(baseUrl, {
        aliasPolicyAudit: {
          completed: true,
          records: [{ ...policy, entityLoaded: true, bundleMatches: true, passed: true }],
          violations: []
        }
      });

      const passing = await verifyLive({
        packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {}, drupalRuntime: runtime
      });
      assert.equal(passing.drupalRuntime.implementationQualityValid, true, passing.errors.join('\n'));

      runtime.aliasPolicyAudit.records[0].passed = false;
      runtime.aliasPolicyAudit.records[0].violations = ['probe_alias_resolution_mismatch'];
      const failing = await verifyLive({
        packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {}, drupalRuntime: runtime
      });
      assert.equal(failing.drupalRuntime.implementationQualityValid, false);
      assert.match(failing.errors.join('\n'), /did not live-load its probe entity, applicable pattern, and alias resolution/);
    }
  );
});

test('custom PHP extensions require coding-standards and static-analysis dispositions', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'custom-code-quality-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory = {
      applies: true,
      reason: 'A custom capability module is present.',
      extensions: [{
        machineName: 'calendar_feed',
        type: 'module',
        path: 'web/modules/custom/calendar_feed',
        purpose: 'Expose a public calendar feed.',
        solutionLadders: [acceptedSolutionLadder()],
        phpFileCount: 1,
        qualityChecks: [{
          kind: 'coding_standards',
          status: 'verify',
          exception: { reason: '', acceptedBy: '', evidence: '' }
        }],
        accepted: true
      }],
      sourceFiles: [acceptedSourceFile({
        extension: 'calendar_feed',
        path: 'web/modules/custom/calendar_feed/calendar_feed.module'
      })],
      routes: [],
      controllers: [],
      tests: [],
      completed: true
    };
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /custom modules, themes, live source files\/surfaces, routes, controllers, tests/
  );
});

test('custom extensions require the complete structured solution ladder', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'custom-solution-ladder-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    const controllerSource = acceptedSourceFile({
      extension: 'calendar_adapter',
      path: 'web/modules/custom/calendar_adapter/src/Controller/AdapterController.php',
      surfaceName: 'AdapterController'
    });
    controllerSource.surfaces.push({
      id: 'SURFACE-2222222222222222',
      kind: 'function',
      name: 'calendar_adapter_secondary_behavior',
      line: 20
    });
    controllerSource.capabilityBindings[0].surfaceIds.push('SURFACE-2222222222222222');
    readback.implementationQuality.customCodeInventory = {
      applies: true,
      reason: 'A narrow custom capability module is present.',
      extensions: [{
        machineName: 'calendar_adapter',
        type: 'module',
        path: 'web/modules/custom/calendar_adapter',
        purpose: 'Adapt an existing Drupal collection to an external contract.',
        solutionLadders: [acceptedSolutionLadder()],
        phpFileCount: 0,
        qualityChecks: [],
        accepted: true
      }],
      sourceFiles: [controllerSource],
      routes: [],
      controllers: [{
        path: 'web/modules/custom/calendar_adapter/src/Controller/AdapterController.php',
        extension: 'calendar_adapter',
        capabilityId: 'calendar_feed.export',
        sourceSurfaceIds: [controllerSource.surfaces[0].id]
      }],
      tests: [],
      completed: true
    };
  });

  const passing = await validatePacket({ packetDir });
  assert.doesNotMatch(
    passing.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder/
  );
  assert.doesNotMatch(
    passing.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /custom modules, themes, live source files\/surfaces, routes, controllers, tests/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory.sourceFiles[0].capabilityBindings[0].surfaceIds.pop();
  });
  const uncoveredSourceSurface = await validatePacket({ packetDir });
  assert.match(
    uncoveredSourceSurface.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /bind every live custom source file and discovered surface/
  );
  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory.sourceFiles[0].capabilityBindings[0].surfaceIds.push('SURFACE-2222222222222222');
  });

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory.controllers[0].capabilityId = 'calendar_adapter.unknown';
  });
  const wrongControllerCapability = await validatePacket({ packetDir });
  assert.match(
    wrongControllerCapability.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /custom modules, themes, live source files\/surfaces, routes, controllers, tests/
  );
  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory.controllers[0].capabilityId = 'calendar_feed.export';
  });

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory.extensions[0].solutionLadders[0].core = {
      reviewed: true,
      noCandidateFound: true,
      candidates: [],
      conclusion: 'Core discovery found no candidate for the exact output contract.',
      evidence: 'evidence/independent-verification/claim-evidence.json'
    };
  });
  const explicitNoCandidate = await validatePacket({ packetDir });
  assert.doesNotMatch(
    explicitNoCandidate.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    readback.implementationQuality.customCodeInventory.extensions[0].solutionLadders = [
      acceptedSolutionLadder('First capability.', 'calendar_adapter.shared'),
      acceptedSolutionLadder('Second capability.', 'calendar_adapter.shared')
    ];
  });
  const duplicateCapabilityIds = await validatePacket({ packetDir });
  assert.match(
    duplicateCapabilityIds.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /per stable capabilityId.*calendar_adapter/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    const extension = readback.implementationQuality.customCodeInventory.extensions[0];
    delete extension.solutionLadders;
    extension.drupalNativeAlternativesReviewed = 'Core and contrib were reviewed.';
  });
  const freeTextOnly = await validatePacket({ packetDir });
  assert.match(
    freeTextOnly.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder.*calendar_adapter/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    const extension = readback.implementationQuality.customCodeInventory.extensions[0];
    extension.solutionLadders = [acceptedSolutionLadder()];
    extension.solutionLadders[0].installedDrupalCms.disabledCapabilitiesChecked = false;
  });
  const skippedDisabledCapabilities = await validatePacket({ packetDir });
  assert.match(
    skippedDisabledCapabilities.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder.*calendar_adapter/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    const extension = readback.implementationQuality.customCodeInventory.extensions[0];
    extension.solutionLadders = [acceptedSolutionLadder()];
    delete extension.solutionLadders[0].maintainedContrib.candidates[0].drupalCompatibility;
  });
  const missingDrupalCompatibility = await validatePacket({ packetDir });
  assert.match(
    missingDrupalCompatibility.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder.*calendar_adapter/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    const ladder = acceptedSolutionLadder();
    ladder.maintainedContrib.candidates[0].unmetCriteria = [];
    readback.implementationQuality.customCodeInventory.extensions[0].solutionLadders = [ladder];
  });
  const partialWithoutCriterion = await validatePacket({ packetDir });
  assert.match(
    partialWithoutCriterion.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder.*calendar_adapter/
  );

  mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
    const ladder = acceptedSolutionLadder();
    ladder.installedDrupalCms.capabilities[0].unmetCriteria = ['unknown_criterion'];
    readback.implementationQuality.customCodeInventory.extensions[0].solutionLadders = [ladder];
  });
  const unknownCriterionReference = await validatePacket({ packetDir });
  assert.match(
    unknownCriterionReference.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /complete accepted solution ladder.*calendar_adapter/
  );
});

test('live theme ownership findings require explicit review dispositions', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const projectRoot = mkdtempSync(join(tmpdir(), 'theme-ownership-live-'));
      const themeRoot = join(projectRoot, 'web', 'themes', 'custom', 'public_theme');
      mkdirSync(join(themeRoot, 'templates'), { recursive: true });
      writeFileSync(join(themeRoot, 'public_theme.info.yml'), 'name: Public theme\ntype: theme\n');
      writeFileSync(
        join(themeRoot, 'templates', 'page.html.twig'),
        '<form action="/search" role="search"><input name="keywords" type="search"><button>Search</button></form>\n'
      );
      const scanned = inspectCustomCode(projectRoot);
      assert.ok(scanned.themeOwnershipFindings.length > 0);

      const temp = mkdtempSync(join(tmpdir(), 'theme-ownership-packet-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const dispositions = scanned.themeOwnershipFindings.map((finding) => ({
        ...finding,
        capabilityId: 'public_theme.presentation',
        sourceSurfaceIds: owningSurfaceIds(scanned.sourceFiles, finding.file, finding.line),
        disposition: 'replace_with_drupal_owner',
        drupalOwner: finding.kind === 'handwritten_search_form' ? 'views_exposed_form' : 'config',
        reason: 'The public behavior should be owned by configured Drupal UI.',
        offRoadDisposition: 'OR-013 reviewed for replacement.',
        acceptedBy: 'Fixture Maintainer',
        evidence: 'evidence/independent-verification/claim-evidence.json',
        reviewed: true
      }));
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory = {
          applies: true,
          reason: 'A custom presentation theme is present.',
          extensions: [{
            machineName: 'public_theme',
            type: 'theme',
            path: 'web/themes/custom/public_theme',
            purpose: 'Provide source-like visual presentation.',
            solutionLadders: [acceptedSolutionLadder(
              'Provide source-like branded presentation.',
              'public_theme.presentation'
            )],
            phpFileCount: 0,
            qualityChecks: [],
            accepted: true
          }],
          sourceFiles: acceptedScannedSourceFiles(scanned.sourceFiles, 'public_theme.presentation'),
          themeOwnershipReviewCompleted: true,
          themeOwnershipFindings: dispositions,
          routes: [],
          controllers: [],
          tests: [],
          completed: true
        };
      });
      const runtime = injectedDrupalRuntime(baseUrl, {
        customCodeInventory: {
          completed: true,
          controllers: [],
          errors: [],
          extensions: scanned.extensions,
          routeAuditCompleted: true,
          routeAuditViolations: [],
          routes: [],
          sourceFiles: scanned.sourceFiles,
          tests: [],
          themeOwnershipFindings: scanned.themeOwnershipFindings
        }
      });

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.themeOwnershipFindings[0].capabilityId = 'other_theme.capability';
      });
      const wrongCapability = await validatePacket({ packetDir });
      assert.match(
        wrongCapability.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /custom theme ownership findings must be completely inventoried/
      );
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.themeOwnershipFindings[0].capabilityId = 'public_theme.presentation';
      });

      const pendingRemediation = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(pendingRemediation.drupalRuntime.implementationQualityValid, true, pendingRemediation.errors.join('\n'));
      assert.equal(pendingRemediation.packetVerification.completionEvidence.packetSupportsCompletion, false);
      assert.match(
        pendingRemediation.packetVerification.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /replace_with_drupal_owner.*pending remediation/
      );

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        for (const finding of readback.implementationQuality.customCodeInventory.themeOwnershipFindings) {
          finding.disposition = 'accepted_theme_exception';
          finding.drupalOwner = 'theme_exception';
          finding.reason = 'The maintainer accepted this narrow presentation-only theme ownership.';
        }
      });
      const acceptedExceptions = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(acceptedExceptions.drupalRuntime.implementationQualityValid, true, acceptedExceptions.errors.join('\n'));
      assert.doesNotMatch(
        acceptedExceptions.packetVerification.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /replace_with_drupal_owner.*pending remediation/
      );

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.sourceFiles[0].sha256 = `sha256:${'0'.repeat(64)}`;
      });
      const staleSourceHash = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(staleSourceHash.drupalRuntime.implementationQualityValid, false);
      assert.match(staleSourceHash.errors.join('\n'), /stale kind, hash, or discovered-surface evidence/);
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.sourceFiles = acceptedScannedSourceFiles(
          scanned.sourceFiles,
          'public_theme.presentation'
        );
      });

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.themeOwnershipFindings.pop();
      });
      const missingFinding = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(missingFinding.drupalRuntime.implementationQualityValid, false);
      assert.match(missingFinding.errors.join('\n'), /Theme ownership finding THEME-.*missing or stale/);

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.themeOwnershipFindings = [];
      });
      runtime.customCodeInventory.themeOwnershipFindings = [];
      const remediated = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(remediated.drupalRuntime.implementationQualityValid, true, remediated.errors.join('\n'));
      assert.doesNotMatch(
        remediated.packetVerification.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /theme ownership|replace_with_drupal_owner/i
      );
    }
  );
});

test('live custom-route review handles custom access, anonymous roles, and parameterized paths', async () => {
  await withHttpServer(
    (request, response) => {
      const denied = request.url === '/calendar/manage';
      response.writeHead(denied ? 403 : 200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'custom-route-live-access-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const routeDefinitions = [
        {
          name: 'calendar_feed.custom_access',
          path: '/calendar/{calendar}',
          requirements: { _custom_access: '\\Drupal\\calendar_feed\\Access\\CalendarAccess::access' },
          routeParameters: { calendar: '42' },
          requestMethod: 'GET',
          representativePath: '/calendar/42',
          anonymousAccessDisposition: 'allowed',
          bindingKind: 'route_name'
        },
        {
          name: 'calendar_feed.anonymous_role',
          path: '/calendar/public',
          requirements: { _role: 'anonymous' },
          routeParameters: {},
          requestMethod: 'GET',
          representativePath: '/calendar/public',
          anonymousAccessDisposition: 'allowed',
          bindingKind: 'concrete_path'
        },
        {
          name: 'calendar_feed.permission',
          path: '/calendar/manage',
          requirements: { _permission: 'administer calendar feed' },
          routeParameters: {},
          requestMethod: 'GET',
          representativePath: '/calendar/manage',
          anonymousAccessDisposition: 'denied',
          bindingKind: 'concrete_path'
        }
      ];
      const controller = '\\Drupal\\calendar_feed\\Controller\\CalendarController::feed';
      const routingSourceFile = acceptedSourceFile({
        capabilityId: 'calendar_feed.routes',
        extension: 'calendar_feed',
        hex: '2',
        kind: 'drupal_registration',
        path: 'web/modules/custom/calendar_feed/calendar_feed.routing.yml',
        surfaceKind: 'registration',
        surfaceName: routeDefinitions[0].name
      });
      routingSourceFile.surfaces = routeDefinitions.map((route, index) => ({
        id: `SURFACE-${String(index + 4).repeat(16)}`,
        kind: 'registration',
        name: route.name,
        line: index + 1
      }));
      routingSourceFile.capabilityBindings[0].surfaceIds = routingSourceFile.surfaces.map((surface) => surface.id);
      const routeSourceFiles = [
        acceptedSourceFile({
          capabilityId: 'calendar_feed.routes',
          extension: 'calendar_feed',
          hex: '1',
          kind: 'extension_metadata',
          path: 'web/modules/custom/calendar_feed/calendar_feed.info.yml',
          surfaceKind: 'whole_file',
          surfaceName: 'calendar_feed.info.yml'
        }),
        routingSourceFile,
        acceptedSourceFile({
          capabilityId: 'calendar_feed.routes',
          extension: 'calendar_feed',
          hex: '3',
          path: 'web/modules/custom/calendar_feed/src/Controller/CalendarController.php',
          surfaceName: 'CalendarController'
        })
      ];
      mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
        for (const route of routeDefinitions) {
          routeMatrix.targetRequiredRoutes.push({
            routeName: route.name,
            targetPath: route.representativePath,
            reasonRequired: 'other',
            targetStatus: route.anonymousAccessDisposition === 'denied' ? 403 : 200,
            targetFinalPath: route.representativePath,
            expectedPublicBehavior: route.anonymousAccessDisposition === 'denied' ? 'private_403' : 'public_200',
            drupalOwner: 'custom_route',
            shouldBePublic: route.anonymousAccessDisposition !== 'denied',
            accepted: true,
            notes: 'Custom route bound by live route name and representative path.'
          });
        }
      });
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory = {
          applies: true,
          reason: 'A custom calendar capability owns three reviewed routes.',
          extensions: [{
            machineName: 'calendar_feed',
            type: 'module',
            path: 'web/modules/custom/calendar_feed',
            purpose: 'Expose calendar capability routes.',
            solutionLadders: [acceptedSolutionLadder(
              'Expose access-controlled calendar capability routes.',
              'calendar_feed.routes'
            )],
            phpFileCount: 1,
            qualityChecks: [
              {
                kind: 'coding_standards', status: 'verify',
                exception: { reason: '', acceptedBy: '', evidence: '' }
              },
              {
                kind: 'static_analysis', status: 'verify',
                exception: { reason: '', acceptedBy: '', evidence: '' }
              }
            ],
            accepted: true
          }],
          sourceFiles: routeSourceFiles,
          routes: routeDefinitions.map((route) => ({
            name: route.name,
            path: route.path,
            extension: 'calendar_feed',
            capabilityId: 'calendar_feed.routes',
            sourceFile: 'web/modules/custom/calendar_feed/calendar_feed.routing.yml',
            sourceSurfaceIds: [routingSourceFile.surfaces.find((surface) => surface.name === route.name).id],
            controller,
            requirements: route.requirements,
            routeParameters: route.routeParameters,
            requestMethod: route.requestMethod,
            representativePath: route.representativePath,
            anonymousAccessDisposition: route.anonymousAccessDisposition,
            anonymousAccessEvidence: 'Live anonymous account access-manager result.',
            routeMatrixBinding: {
              kind: route.bindingKind,
              value: route.bindingKind === 'route_name' ? route.name : route.representativePath
            },
            accessReviewed: true,
            cacheabilityReviewed: true,
            sanitizationReviewed: true,
            dependencyInjectionReviewed: true,
            testEvidence: 'evidence/independent-verification/claim-evidence.json',
            testException: { reason: '', acceptedBy: '', evidence: '' },
            offRoadDisposition: 'OR-001 accepted capability route.',
            accepted: true
          })),
          controllers: [{
            path: 'web/modules/custom/calendar_feed/src/Controller/CalendarController.php',
            extension: 'calendar_feed',
            capabilityId: 'calendar_feed.routes',
            sourceSurfaceIds: [routeSourceFiles[2].surfaces[0].id]
          }],
          tests: ['web/modules/custom/calendar_feed/tests/src/Functional/CalendarFeedTest.php'],
          completed: true
        };
      });
      mutateJson(join(packetDir, 'independent-verification.json'), (independent) => {
        for (const route of routeDefinitions) {
          independent.drupalImplementationChecks.push({
            kind: 'custom_route',
            identity: route.name,
            liveReadback: `drupal-readback.json ${route.name}`,
            falsificationAttempt: 'Compared live router definition and anonymous access against the packet binding.',
            status: 'pass',
            evidence: 'claim-evidence.json'
          });
          independent.targetRequiredRouteChecks.push({
            targetPath: route.representativePath,
            reasonRequired: 'other',
            targetStatus: route.anonymousAccessDisposition === 'denied' ? 403 : 200,
            targetFinalUrl: `${baseUrl}${route.representativePath}`,
            expectedPublicBehavior: route.anonymousAccessDisposition === 'denied' ? 'private_403' : 'public_200',
            status: 'pass',
            evidence: 'claim-evidence.json'
          });
        }
      });

      const runtime = injectedDrupalRuntime(baseUrl, {
        customCodeInventory: {
          completed: true,
          controllers: [{
            path: 'web/modules/custom/calendar_feed/src/Controller/CalendarController.php',
            extension: 'calendar_feed'
          }],
          errors: [],
          extensions: [{
            machineName: 'calendar_feed',
            type: 'module',
            path: 'web/modules/custom/calendar_feed',
            phpFileCount: 1,
            qualityChecks: [
              { kind: 'coding_standards', supported: true, status: 'pass' },
              { kind: 'static_analysis', supported: true, status: 'pass' }
            ]
          }],
          routeAuditCompleted: true,
          routeAuditViolations: [],
          routes: routeDefinitions.map((route) => ({
            name: route.name,
            extension: 'calendar_feed',
            file: 'web/modules/custom/calendar_feed/calendar_feed.routing.yml',
            filesystemPath: route.path,
            filesystemController: controller,
            path: route.path,
            controller,
            requirements: route.requirements,
            routeParameters: route.routeParameters,
            requestMethod: route.requestMethod,
            parameterNames: [...route.path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]),
            accessCheckCompleted: true,
            parameterConversionCompleted: true,
            requestMatched: true,
            anonymousAccess: route.anonymousAccessDisposition,
            representativePath: route.representativePath
          })),
          sourceFiles: routeSourceFiles.map(({ capabilityBindings, reviewed, ...sourceFile }) => sourceFile),
          tests: ['web/modules/custom/calendar_feed/tests/src/Functional/CalendarFeedTest.php']
        }
      });

      const passingReport = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(passingReport.liveTargetValid, true, passingReport.errors.join('\n'));
      assert.equal(passingReport.drupalRuntime.implementationQualityValid, true);

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.routes[0].sourceSurfaceIds = [
          routingSourceFile.surfaces[1].id
        ];
      });
      const wrongRouteSurface = await validatePacket({ packetDir });
      assert.match(
        wrongRouteSurface.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /custom modules, themes, live source files\/surfaces, routes, controllers, tests/
      );
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.routes[0].sourceSurfaceIds = [
          routingSourceFile.surfaces[0].id
        ];
      });

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.routes[0].capabilityId = 'calendar_feed.unknown';
      });
      const wrongRouteCapability = await validatePacket({ packetDir });
      assert.match(
        wrongRouteCapability.completionEvidence.packetCompletionBlockedReasons.join('\n'),
        /custom modules, themes, live source files\/surfaces, routes, controllers, tests/
      );
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.routes[0].capabilityId = 'calendar_feed.routes';
      });

      runtime.customCodeInventory.extensions[0].qualityChecks[1] = {
        kind: 'static_analysis',
        supported: false,
        status: 'unsupported',
        reason: 'No project PHPStan configuration was found.'
      };
      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.extensions[0].qualityChecks[1] = {
          kind: 'static_analysis',
          status: 'exception',
          exception: {
            reason: 'The project has no PHPStan configuration.',
            acceptedBy: 'Fixture Maintainer',
            evidence: 'evidence/independent-verification/claim-evidence.json'
          }
        };
      });
      const exceptionReport = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(exceptionReport.drupalRuntime.implementationQualityValid, true, exceptionReport.errors.join('\n'));

      mutateJson(join(packetDir, 'drupal-readback.json'), (readback) => {
        readback.implementationQuality.customCodeInventory.routes[0].anonymousAccessDisposition = 'denied';
      });
      const mismatchReport = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: runtime
      });
      assert.equal(mismatchReport.liveTargetValid, false);
      assert.match(mismatchReport.errors.join('\n'), /anonymous-access disposition denied does not match live Drupal access allowed/);
    }
  );
});

test('live route verification rejects identity mismatches and accepts a declared same-origin redirect', async () => {
  let scenario = { status: 200, h1: 'Target home', title: 'Target site' };
  await withHttpServer(
    (request, response) => {
      if (scenario.redirect && request.url === '/') {
        response.writeHead(302, { location: '/home' });
        response.end();
        return;
      }
      response.writeHead(scenario.status, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>${scenario.title}</title></head><body><h1>${scenario.h1}</h1></body></html>`);
    },
    async (baseUrl) => {
      const mismatchCases = [
        {
          name: 'status',
          response: { status: 500, h1: 'Target home', title: 'Target site' },
          expected: /returned status 500; expected 200/
        },
        {
          name: 'final-path',
          response: { status: 200, h1: 'Target home', title: 'Target site' },
          mutate: (routeMatrix) => {
            routeMatrix.homepageParity.targetFinalPath = '/expected';
            routeMatrix.routes[0].targetFinalPath = '/expected';
          },
          expected: /resolved to \/; expected \/expected/
        },
        {
          name: 'h1',
          response: { status: 200, h1: 'Wrong home', title: 'Target site' },
          expected: /H1 was "Wrong home"; expected "Target home"/
        },
        {
          name: 'title',
          response: { status: 200, h1: 'Target home', title: 'Wrong site' },
          expected: /title was "Wrong site"; expected "Target site"/
        }
      ];

      for (const mismatch of mismatchCases) {
        scenario = mismatch.response;
        const temp = mkdtempSync(join(tmpdir(), `live-route-${mismatch.name}-`));
        const packetDir = join(temp, 'review-packet');
        copyTemplatePacket(packetDir);
        const routeMatrix = liveRouteMatrix(baseUrl);
        mismatch.mutate?.(routeMatrix);
        writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

        const report = await verifyLive({
          packetDir,
          targetUrl: baseUrl,
          cwd: repoRoot,
          environment: {},
          drupalRuntime: injectedDrupalRuntime(baseUrl)
        });

        assert.equal(report.valid, false, mismatch.name);
        assert.equal(report.routeChecks[0].passed, false, mismatch.name);
        assert.match(report.errors.join('\n'), mismatch.expected, mismatch.name);
      }

      scenario = { status: 500, h1: 'Target home', title: 'Target site' };
      const serverErrorTemp = mkdtempSync(join(tmpdir(), 'live-route-declared-500-'));
      const serverErrorPacket = join(serverErrorTemp, 'review-packet');
      copyTemplatePacket(serverErrorPacket);
      const serverErrorMatrix = liveRouteMatrix(baseUrl);
      serverErrorMatrix.homepageParity.targetStatus = 500;
      serverErrorMatrix.routes[0].targetStatus = 500;
      writeJson(join(serverErrorPacket, 'route-matrix.json'), serverErrorMatrix);

      const serverErrorReport = await verifyLive({
        packetDir: serverErrorPacket,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(serverErrorReport.valid, false);
      assert.equal(serverErrorReport.liveTargetValid, false);
      assert.equal(serverErrorReport.routeChecks[0].passed, false);
      assert.match(
        serverErrorReport.errors.join('\n'),
        /primary target route.*(?:cannot accept|must not accept).*500|HTTP 500.*cannot support/i
      );

      scenario = { redirect: true, status: 200, h1: 'Target home', title: 'Target site' };
      const temp = mkdtempSync(join(tmpdir(), 'live-route-redirect-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.homepageParity.targetFinalPath = '/home';
      routeMatrix.homepageParity.targetStatus = 302;
      routeMatrix.routes[0].targetFinalPath = '/home';
      routeMatrix.routes[0].targetStatus = 302;
      routeMatrix.routes[0].expectedRedirect = true;
      routeMatrix.targetRequiredRoutes[0].targetFinalPath = '/home';
      routeMatrix.targetRequiredRoutes[0].targetStatus = 302;
      routeMatrix.targetRequiredRoutes[0].expectedPublicBehavior = 'redirect';
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.routeChecks[0].passed, true, report.routeChecks[0].errors.join('\n'));
      assert.equal(report.routeChecks[0].initialStatus, 302);
      assert.equal(new URL(report.routeChecks[0].finalUrl).pathname, '/home');
      assert.equal(report.routeChecks[0].redirects.length, 1);
    }
  );
});

test('packet evidence can qualify but an injected Drupal runtime cannot authorize completion', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-complete-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const packetOnlyReport = await validatePacket({ packetDir });
      assert.equal(packetOnlyReport.valid, true, packetOnlyReport.errors.join('\n'));
      assert.equal(
        packetOnlyReport.completionEvidence.packetSupportsCompletion,
        true,
        JSON.stringify(packetOnlyReport.completionEvidence, null, 2)
      );
      assert.equal(packetOnlyReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(packetOnlyReport.claimScope, 'complete-local-rebuild');
      assert.equal(packetOnlyReport.productionReadinessEvaluated, false);
      assert.equal(packetOnlyReport.launchReady, false);

      const liveReport = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl, { mode: 'test' })
      });
      assert.equal(liveReport.valid, true, liveReport.errors.join('\n'));
      assert.equal(liveReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(liveReport.claimScope, 'complete-local-rebuild');
      assert.equal(liveReport.productionReadinessEvaluated, false);
      assert.equal(liveReport.launchReady, false);
      assert.equal(liveReport.drupalRuntime.authoritativeForCompletion, false);
      assert.match(
        liveReport.completionBlockedReasons.join('\n'),
        /injected.*non-authoritative|non-authoritative.*injected/i
      );
    }
  );
});

test('live verifier rejects fetched SEO metadata that is missing or differs from packet claims', async () => {
  let scenario = {};
  await withHttpServer(
    (_request, response) => {
      const canonical = scenario.canonical === null
        ? ''
        : `<link rel="canonical" href="${scenario.canonical}">`;
      const description = scenario.description === null
        ? ''
        : `<meta name="description" content="${scenario.description}">`;
      const socialImage = scenario.socialImage === null
        ? ''
        : `<meta property="og:image" content="${scenario.socialImage}">`;
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head><title>Target site</title>${canonical}${description}${socialImage}</head><body><h1>Target home</h1></body></html>`);
    },
    async (baseUrl) => {
      const expectedSeo = {
        canonical: `${baseUrl}/`,
        description: 'Fixture homepage description.',
        socialImage: `${baseUrl}/social.jpg`
      };
      const cases = [
        {
          name: 'missing-canonical',
          values: { ...expectedSeo, canonical: null },
          expected: /canonical.*missing|missing.*canonical/i
        },
        {
          name: 'mismatched-canonical',
          values: { ...expectedSeo, canonical: `${baseUrl}/wrong` },
          expected: /canonical.*(?:does not match|mismatch)|(?:does not match|mismatch).*canonical/i
        },
        {
          name: 'credential-bearing-canonical',
          values: { ...expectedSeo, canonical: baseUrl.replace('http://', 'http://user:secret@') },
          expected: /canonical.*missing|missing.*canonical/i
        },
        {
          name: 'missing-description',
          values: { ...expectedSeo, description: null },
          expected: /description.*missing|missing.*description/i
        },
        {
          name: 'mismatched-description',
          values: { ...expectedSeo, description: 'Wrong description.' },
          expected: /description.*(?:does not match|mismatch)|(?:does not match|mismatch).*description/i
        },
        {
          name: 'missing-social-image',
          values: { ...expectedSeo, socialImage: null },
          expected: /(?:og:image|social.image).*missing|missing.*(?:og:image|social.image)/i
        },
        {
          name: 'mismatched-social-image',
          values: { ...expectedSeo, socialImage: `${baseUrl}/wrong.jpg` },
          expected: /(?:og:image|social.image).*(?:does not match|mismatch)|(?:does not match|mismatch).*(?:og:image|social.image)/i
        }
      ];

      const temp = mkdtempSync(join(tmpdir(), 'live-seo-regressions-'));
      const canonicalPacket = join(temp, 'canonical');
      copyTemplatePacket(canonicalPacket);
      writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(canonicalPacket, baseUrl);
      mutateJson(join(canonicalPacket, 'browser-evidence.json'), (browser) => {
        for (const check of browser.publicRouteChecks) {
          check.renderedSeoSignals.targetCanonicalUrl = expectedSeo.canonical;
          check.renderedSeoSignals.targetMetaDescription = expectedSeo.description;
          check.renderedSeoSignals.metaDescriptionStatus = 'present';
          check.renderedSeoSignals.metaDescriptionApplicabilityReviewed = true;
          check.renderedSeoSignals.metaDescriptionNotApplicableRationale = '';
          check.renderedSeoSignals.targetOpenGraphImage = expectedSeo.socialImage;
          check.renderedSeoSignals.openGraphImageStatus = 'present';
          check.renderedSeoSignals.openGraphImageApplicabilityReviewed = true;
          check.renderedSeoSignals.openGraphImageNotApplicableRationale = '';
          check.renderedSeoSignals.accepted = true;
        }
      });

      for (const seoCase of cases) {
        scenario = seoCase.values;
        const packetDir = join(temp, seoCase.name);
        cpSync(canonicalPacket, packetDir, { recursive: true });

        const report = await verifyLive({
          packetDir,
          targetUrl: baseUrl,
          cwd: repoRoot,
          environment: {},
          drupalRuntime: {
            baseUrl,
            confirmed: true,
            configStatusClean: true,
            configSyncDirectory: '../config/sync',
            frontPage: '/',
            mode: 'test-injected',
            project: 'fixture',
            reason: '',
            siteUuid: testSiteUuid
          }
        });

        assert.equal(report.valid, false, seoCase.name);
        assert.equal(report.liveTargetValid, false, seoCase.name);
        assert.equal(report.completeLocalRebuildClaimAllowed, false, seoCase.name);
        assert.match(report.errors.join('\n'), seoCase.expected, seoCase.name);
      }
    }
  );
});

test('CLI discovers the DDEV Drupal runtime and requires clean status plus real Git-tracked config YAML', async () => {
  let liveBaseUrl = '';
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(`<!doctype html><html><head>
        <title>Target site</title>
        <link rel="canonical" href="${liveBaseUrl}/">
        <meta name="description" content="Fixture homepage description.">
      </head><body><h1>Target home</h1></body></html>`);
    },
    async (baseUrl) => {
      liveBaseUrl = baseUrl;
      const targetRoot = mkdtempSync(join(tmpdir(), 'live-fake-ddev-'));
      mkdirSync(join(targetRoot, '.ddev'), { recursive: true });
      mkdirSync(join(targetRoot, 'web'), { recursive: true });
      mkdirSync(join(targetRoot, 'config', 'sync'), { recursive: true });
      writeFileSync(join(targetRoot, '.ddev', 'config.yaml'), 'name: fake-runtime\ntype: drupal11\ndocroot: web\n');
      writeFileSync(join(targetRoot, 'config', 'sync', 'system.site.yml'), `uuid: ${testSiteUuid}\n`);
      writeFileSync(join(targetRoot, 'config', 'sync', 'system.theme.yml'), 'default: fixture_theme\nadmin: claro\n');

      const fakeBin = join(targetRoot, 'fake-bin');
      mkdirSync(fakeBin);
      const fakeDdev = join(fakeBin, 'ddev');
      writeFileSync(fakeDdev, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'describe' && args[1] === '-j') {
  process.stdout.write(JSON.stringify({ raw: { primary_url: process.env.FAKE_DDEV_URL } }) + '\\n');
  process.exit(0);
}
if (args[0] !== 'drush') {
  process.stderr.write('Unexpected fake DDEV command: ' + args.join(' ') + '\\n');
  process.exit(1);
}
const command = args.slice(1).join(' ');
if (args[1] === 'php:eval') {
  process.stdout.write(JSON.stringify({
    completed: true,
    formComponents: [{ displayConfig: 'core.entity_form_display.node.page.default', fieldName: 'body', fieldDefinitionPresent: true, fieldType: 'text_with_summary', configuredPlugin: 'text_textarea_with_summary', resolvedPlugin: 'text_textarea_with_summary', supportsFieldType: true, classApplicable: true, applicable: true }],
    formComponentCount: 1,
    viewComponents: [{ displayConfig: 'core.entity_view_display.node.page.default', fieldName: 'body', fieldDefinitionPresent: true, fieldType: 'text_with_summary', configuredPlugin: 'text_default', resolvedPlugin: 'text_default', supportsFieldType: true, classApplicable: true, applicable: true }],
    viewComponentCount: 1,
    violations: []
  }) + '\\n');
  process.exit(0);
}
const outputs = new Map([
  ['status --field=bootstrap', 'Successful'],
  ['status --field=root', 'web'],
  ['config:get system.site --field=uuid', '${testSiteUuid}'],
  ['config:get system.site page.front --format=string', '/'],
  ['config:get system.theme default --format=string', 'fixture_theme'],
  ['status --field=config-sync', '../config/sync'],
  ['config:status --format=json', process.env.FAKE_DDEV_CONFIG_DIRTY === '1' ? '{"changed":true}' : '[]']
]);
if (!outputs.has(command)) {
  process.stderr.write('Unexpected fake Drush command: ' + command + '\\n');
  process.exit(1);
}
process.stdout.write(outputs.get(command) + '\\n');
`);
      chmodSync(fakeDdev, 0o755);

      const packetDir = join(targetRoot, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const verifierArgs = [join(repoRoot, 'bin', 'verify.mjs'), '--packet', 'review-packet'];
      const cleanEnvironment = {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH}`,
        FAKE_DDEV_URL: baseUrl
      };

      const untrackedResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(untrackedResult.status, 2, untrackedResult.stderr);
      const untrackedReport = JSON.parse(
        readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8')
      );
      assert.equal(untrackedReport.completeLocalRebuildClaimAllowed, false);
      assert.equal(untrackedReport.drupalRuntime.configSyncTracked, false);
      assert.equal(untrackedReport.drupalRuntime.trackedConfigYamlPresent, false);
      assert.match(untrackedReport.completionBlockedReasons.join('\n'), /Git-tracked.*YAML/i);

      execFileSync('git', ['init', '-q'], { cwd: targetRoot });
      execFileSync('git', ['add', 'config/sync/system.site.yml', 'config/sync/system.theme.yml'], { cwd: targetRoot });

      const cleanResult = await runProcess(process.execPath, verifierArgs, targetRoot, { env: cleanEnvironment });
      assert.equal(cleanResult.status, 0, cleanResult.stderr);
      assert.match(cleanResult.stdout, /complete local rebuild claim authorized/);
      const cleanReport = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(cleanReport.target.resolutionSource, 'ddev-describe');
      assert.equal(cleanReport.drupalRuntime.mode, 'ddev-host');
      assert.equal(cleanReport.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(cleanReport.drupalRuntime.configStatusClean, true);
      assert.equal(cleanReport.drupalRuntime.configSyncTracked, true);
      assert.equal(cleanReport.drupalRuntime.trackedConfigYamlPresent, true);
      assert.equal(cleanReport.completeLocalRebuildClaimAllowed, true);

      const dirtyResult = await runProcess(process.execPath, verifierArgs, targetRoot, {
        env: { ...cleanEnvironment, FAKE_DDEV_CONFIG_DIRTY: '1' }
      });
      assert.equal(dirtyResult.status, 2, dirtyResult.stderr);
      const dirtyReport = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(dirtyReport.valid, true, dirtyReport.errors.join('\n'));
      assert.equal(dirtyReport.drupalRuntime.configStatusClean, false);
      assert.equal(dirtyReport.completeLocalRebuildClaimAllowed, false);
      assert.match(dirtyReport.completionBlockedReasons.join('\n'), /config status is not clean/i);
    }
  );
});

test('completion fails closed when structured gate evidence or applicability dispositions are missing', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'structured-gate-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'collection-scope',
      file: 'pattern-map.json',
      expected: /explicitly review collection applicability/i,
      mutate: (value) => { value.structuredContentModel.collectionScope.reviewed = false; }
    },
    {
      name: 'functional-scope',
      file: 'parity-report.json',
      expected: /parity-report\.json/i,
      mutate: (value) => { value.functionalScope.reviewed = false; }
    },
    {
      name: 'route-drift',
      file: 'route-matrix.json',
      expected: /classify and accept every discovered source route/i,
      mutate: (value) => { value.browserFirstRouteExpansion.candidateRoutesFromRenderedLinks = ['/legacy']; }
    },
    {
      name: 'target-required-route',
      file: 'route-matrix.json',
      expected: /accepted target-required route records/i,
      mutate: (value) => { value.targetRequiredRoutes[0].accepted = false; }
    },
    {
      name: 'item-reconciliation',
      file: 'route-matrix.json',
      expected: /reconcile every in-scope repeated-item count/i,
      mutate: (value) => {
        value.perRouteItemReconciliation = [{
          sourcePath: '/',
          targetPath: '/',
          itemType: 'card',
          sourceCount: 2,
          targetRenderedCount: 1,
          targetDrupalEntityCount: 1,
          mismatchDisposition: 'implementation_gap',
          accepted: false,
          notes: 'One card is missing.'
        }];
      }
    },
    {
      name: 'first-fold',
      file: 'route-matrix.json',
      expected: /first-fold brand parity.*mobile/i,
      mutate: (value) => { value.firstFoldBrandAssetParity = value.firstFoldBrandAssetParity.filter((entry) => entry.viewport !== 'mobile'); }
    },
    {
      name: 'rendered-seo',
      file: 'browser-evidence.json',
      expected: /rendered canonical, description, and social-image dispositions/i,
      mutate: (value) => {
        for (const check of value.publicRouteChecks) {
          check.renderedSeoSignals.accepted = false;
        }
      }
    },
    {
      name: 'off-road-scan',
      file: 'independent-verification.json',
      expected: /raw embed and markup scan must pass/i,
      mutate: (value) => { value.rawEmbedAndMarkupScan.status = 'blocked'; }
    },
    {
      name: 'tracked-config-yaml',
      file: 'drupal-readback.json',
      expected: /drupal-readback\.json must substantively identify/i,
      mutate: (value) => { value.drupal.trackedConfigYamlFiles = []; }
    },
    {
      name: 'content-parity',
      file: 'parity-report.json',
      expected: /parity-report\.json must pass/i,
      mutate: (value) => { value.contentChecks = []; }
    },
    {
      name: 'packet-freshness',
      file: 'independent-verification.json',
      expected: /packet freshness checks must pass pattern-map\.json/i,
      mutate: (value) => {
        value.packetFreshnessChecks = value.packetFreshnessChecks.filter((check) => check.artifact !== 'pattern-map.json');
      }
    }
  ];

  for (const { name, file, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutateJson(join(packetDir, file), mutate);
    const report = await validatePacket({ packetDir });
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('conditionally applicable hard gates fail closed when their verifier evidence is missing or blocked', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'conditional-gate-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'collections',
      expected: [
        /passing, evidence-backed per-route item counts/i,
        /passing collection ownership and editor-add-row checks/i,
        /passing editor-add-row checks/i
      ],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.structuredContentModel.collectionScope = {
            reviewed: true,
            applies: true,
            reason: 'The source homepage contains a repeatable card collection.'
          };
          value.structuredContentModel.collectionOwnershipLedger = [{
            sourceRoute: '/',
            collectionPattern: 'grid',
            sourceObject: 'card',
            sourceItemCount: 2,
            drupalEntityType: 'node',
            contentTypeOrBundle: 'card',
            requiredFields: ['title'],
            collectionOwner: 'view',
            viewDisplayOrConfig: 'views.view.cards',
            detailRouteOwner: 'entity_view_display',
            editorAddRowEvidence: 'editor-task.json',
            exceptionRationale: '',
            accepted: true,
            notes: 'Cards are Drupal-owned.'
          }];
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.perRouteItemCounts = [{
            sourceRoute: '/',
            targetRoute: '/',
            expectedSourceItemCount: 2,
            targetRenderedItemCount: 1,
            targetDrupalEntityCount: 1,
            missingItems: ['Second card'],
            extraItems: [],
            status: 'blocked',
            evidence: ''
          }];
          value.collectionOwnershipChecks = [{
            sourceRoute: '/',
            drupalOwner: 'body_markup_or_blob',
            viewOrCollectionConfig: '',
            editorAddRowEvidence: '',
            status: 'blocked',
            evidence: ''
          }];
          value.editorAddRowChecks = [{
            editorUser: '',
            publicOutputChanged: false,
            listingOrDetailUpdatedWithoutCode: false,
            status: 'blocked',
            evidence: ''
          }];
        });
      }
    },
    {
      name: 'embeds',
      expected: [/passing rendered embed\/media checks/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'source-audit.json'), (value) => {
          value.mediaSignals = [{ route: '/', type: 'video', evidence: 'Source video observed.' }];
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.renderedEmbedChecks = [{ route: '', status: 'blocked', evidence: '' }];
        });
      }
    },
    {
      name: 'canvas',
      expected: [/Canvas component-model checks must pass/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.buildTypeDeclaration.type = 'structured_drupal_native_canvas';
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.canvasComponentModelChecks = [];
        });
      }
    },
    {
      name: 'functional-parity',
      expected: [/parity-report\.json must pass with populated route checks/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'source-audit.json'), (value) => {
          value.functionalSignals = [{ route: '/', behavior: 'interactive search', evidence: 'Source behavior observed.' }];
        });
        mutateJson(join(packetDir, 'parity-report.json'), (value) => {
          value.functionalScope = {
            reviewed: true,
            applies: true,
            reason: 'The source has interactive behavior.'
          };
          value.functionalChecks = [];
        });
      }
    },
    {
      name: 'accepted-route-drift',
      expected: [/pass every source-route drift disposition check with evidence/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
          value.browserFirstRouteExpansion.candidateRoutesFromRenderedLinks = ['/legacy'];
          value.sourceRouteDriftClassification = [{
            sourcePath: '/legacy',
            sourceStatus: 200,
            classification: 'legacy',
            targetDisposition: 'intentionally_drop',
            targetPath: '',
            ownerDecisionEvidence: 'The source route is obsolete.',
            accepted: true,
            notes: 'Accepted legacy-route disposition.'
          }];
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.routeDriftDispositionChecks = [];
        });
      }
    },
    {
      name: 'direct-database-cleanup',
      expected: [/direct-database cleanup checks must be local-only, recorded, passing/i],
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.directDatabaseCleanupChecks = [{
            operation: 'direct_sql',
            localCleanRebuildOnly: false,
            recordedInOffRoadInventory: false,
            productionSafeAlternative: '',
            status: 'blocked',
            evidence: ''
          }];
        });
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    const blockedReasons = report.completionEvidence.packetCompletionBlockedReasons.join('\n');
    for (const expectedReason of expected) {
      assert.match(blockedReasons, expectedReason, name);
    }
  }
});

test('self-authored count and exclusion dispositions cannot hide collection shortfalls', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'collection-count-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'independent-pass-with-count-shortfall',
      expected: /per-route item counts.*(?:match|reconcile)|count shortfall/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.structuredContentModel.collectionScope = {
            reviewed: true,
            applies: true,
            reason: 'The source has a ten-item collection.'
          };
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.perRouteItemCounts = [{
            sourceRoute: '/',
            targetRoute: '/',
            expectedSourceItemCount: 10,
            targetRenderedItemCount: 5,
            targetDrupalEntityCount: 5,
            missingItems: [],
            extraItems: [],
            status: 'pass',
            evidence: 'count-evidence.json'
          }];
        });
      }
    },
    {
      name: 'none-disposition-with-count-shortfall',
      expected: /mismatchDisposition.*none.*(?:equal|matching)|count mismatch.*disposition/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
          value.perRouteItemReconciliation = [{
            sourcePath: '/',
            targetPath: '/',
            itemType: 'card',
            sourceCount: 10,
            targetRenderedCount: 5,
            targetDrupalEntityCount: 5,
            mismatchDisposition: 'none',
            accepted: true,
            notes: 'Incorrectly marked reconciled.'
          }];
        });
      }
    },
    {
      name: 'owner-exclusion-without-acceptance-evidence',
      expected: /owner_approved_exclusion.*(?:acceptedBy|dispositionEvidence)|(?:acceptedBy|dispositionEvidence).*owner_approved_exclusion/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (value) => {
          value.perRouteItemReconciliation = [{
            sourcePath: '/',
            targetPath: '/',
            itemType: 'card',
            sourceCount: 10,
            targetRenderedCount: 5,
            targetDrupalEntityCount: 5,
            mismatchDisposition: 'owner_approved_exclusion',
            acceptedBy: '',
            dispositionEvidence: '',
            accepted: true,
            notes: 'Five items were excluded without recorded approval.'
          }];
        });
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('completion evidence uses exact Drupal identities and explicit SEO applicability', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'exact-identity-regressions-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const cases = [
    {
      name: 'used-node-bundle-cannot-be-omitted-from-editor-evidence',
      expected: /field-output-matrix\.json must include the used node bundle node\.article/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.contentTypes.push({ machineName: 'article', label: 'Article', sourceObjects: ['news article'] });
        });
        mutateJson(join(packetDir, 'drupal-readback.json'), (value) => {
          value.content.nodes.push({ id: 2, type: 'article', title: 'News', published: true });
          value.content.contentTypes.push({ machineName: 'article', label: 'Article' });
        });
      }
    },
    {
      name: 'one-editor-workflow-cannot-cover-two-bundles',
      expected: /editor workflow mapped to node\.article/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'field-output-matrix.json'), (value) => {
        value.bundles.push({
          entityType: 'node',
          bundle: 'article',
          fields: [{
            ...value.bundles[0].fields[0],
            editorLabel: 'Article body'
          }]
        });
      })
    },
    {
      name: 'field-check-wrong-bundle',
      expected: /field-output falsification check for node\.page\.body/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
        value.fieldOutputFalsification[0].bundle = 'article';
      })
    },
    {
      name: 'composition-owner-mismatch',
      expected: /passing composition-fidelity check for \//i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
        value.compositionModelFidelityChecks[0].actualCompositionOwner = 'canvas_page';
        value.compositionModelFidelityChecks[0].deviationRecordRequired = true;
        value.compositionModelFidelityChecks[0].deviationRecordPresent = true;
        value.compositionModelFidelityChecks[0].deviationRationale = '';
        value.compositionModelFidelityChecks[0].deviationTargetUrl = '';
        value.compositionModelFidelityChecks[0].deviationEvidence = '';
      })
    },
    {
      name: 'admin-add-row',
      expected: /passing editor-add-row checks for in-scope collections/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'pattern-map.json'), (value) => {
          value.structuredContentModel.collectionScope = {
            reviewed: true,
            applies: true,
            reason: 'The source contains a repeatable collection.'
          };
        });
        mutateJson(join(packetDir, 'independent-verification.json'), (value) => {
          value.editorAddRowChecks = [{
            editorUser: 'admin',
            editorRole: 'administrator',
            publicOutputChanged: true,
            listingOrDetailUpdatedWithoutCode: true,
            status: 'pass',
            evidence: 'claim-evidence.json'
          }];
        });
      }
    },
    {
      name: 'seo-not-applicable-without-rationale',
      expected: /rendered canonical, description, and social-image dispositions/i,
      mutate: (packetDir) => mutateJson(join(packetDir, 'browser-evidence.json'), (value) => {
        for (const check of value.publicRouteChecks) {
          check.renderedSeoSignals.openGraphImageStatus = 'not_applicable';
          check.renderedSeoSignals.openGraphImageApplicabilityReviewed = true;
          check.renderedSeoSignals.openGraphImageNotApplicableRationale = '';
        }
      })
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), expected, name);
  }
});

test('a coherent but stale packet cannot authorize current local completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'stale-completion-packet-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  const staleCheckedAt = '2020-01-01T00:00:00Z';
  for (const file of [
    'source-audit.json',
    'pattern-map.json',
    'route-matrix.json',
    'parity-report.json',
    'browser-evidence.json',
    'independent-verification.json',
    'blind-adversarial-review.json',
    'drupal-readback.json',
    'field-output-matrix.json'
  ]) {
    mutateJson(join(packetDir, file), (value) => { value.checkedAt = staleCheckedAt; });
  }

  const report = await validatePacket({ packetDir });
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.completionEvidence.packetCompletionBlockedReasons.join('\n'),
    /newest completion evidence is older than seven days/i
  );
});

test('blanket-filled packet templates remain valid lint but cannot support completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blanket-filled-packet-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  for (const file of [
    'source-audit.json',
    'pattern-map.json',
    'field-output-matrix.json',
    'parity-report.json',
    'browser-evidence.json',
    'drupal-readback.json'
  ]) {
    const record = resolveEnumSentinels(JSON.parse(readFileSync(join(templatesDir, templateName(file)), 'utf8')));
    record.runSpecificEvidenceRecorded = true;
    writeJson(join(packetDir, file), record);
  }
  for (const file of [
    'operator-run.md',
    'maintainer-review.md',
    'recipe-start-point.md',
    'scoped-gap-list.md',
    'open-decisions.md',
    'off-road-inventory.md',
    'durable-intent.yml'
  ]) {
    writeFileSync(
      join(packetDir, file),
      `${readFileSync(join(templatesDir, templateName(file)), 'utf8')}\nRun-specific completion evidence recorded.\n`
    );
  }

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, true);
  assert.equal(report.completionEvidence.packetCompletionReady, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /source-audit\.json/);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /maintainer-review\.md/);
});

test('completed Markdown can retain instructional references to UNKNOWN without being treated as unresolved', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'completed-recipe-instructions-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');

  let recipe = readFileSync(join(templatesDir, 'recipe-start-point.template.md'), 'utf8');
  recipe = recipe
    .replace('- Source URL:', '- Source URL: https://source.example/')
    .replace('- Target site name:', '- Target site name: Fixture rebuild')
    .replace('- Target workspace:', '- Target workspace: DDEV fixture')
    .replace('- Source-use boundary:', '- Source-use boundary: Authorized public rebuild')
    .replace('- Decision date:', '- Decision date: 2026-07-09')
    .replace('- Decision owner:', '- Decision owner: Fixture Maintainer')
    .replace(
      '- [ ] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.',
      '- [x] Retain the installed Drupal CMS Starter plus bounded source-fit Recipes and overlays.'
    )
    .replace(/^Decision:\s*$/m, 'Decision: Retain the installed Drupal CMS Starter.')
    .replace(/^Rationale:\s*$/m, 'Rationale: The one-route source needs only bounded structured overlays.')
    .replace(/\|\s*UNKNOWN\s*\|/g, '| not_applicable |')
    .replace(/```text\s*UNKNOWN\s*```/m, '```text\nNo recipe was applied; discovery output reviewed.\n```');
  assert.match(recipe, /Decision values:.*UNKNOWN/);
  writeFileSync(join(packetDir, 'recipe-start-point.md'), recipe);

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.packetSupportsCompletion, true, JSON.stringify(report.completionEvidence, null, 2));
});

test('every nonempty durable intent record must be current before completion', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'durable-intent-current-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  const validRecord = `schema_version: public-kit.1
site: "https://target.example"
intent_records:
  - id: "homepage-owner"
    target_config: "system.site"
    purpose: "Keep the verified homepage owner explicit."
    source_evidence:
      - "route-matrix.json"
    rationale: "The route identity is load-bearing."
    asserted_by: "Fixture Maintainer"
    last_reviewed: "2026-07-09"
    config_hash: "sha256:${'a'.repeat(64)}"
    status: "hash-valid"
    stale_behavior: "treat_as_no_intent"
`;
  writeFileSync(join(packetDir, 'durable-intent.yml'), validRecord);
  const currentReport = await validatePacket({ packetDir });
  assert.equal(currentReport.completionEvidence.packetSupportsCompletion, true, JSON.stringify(currentReport, null, 2));

  writeFileSync(join(packetDir, 'durable-intent.yml'), `${validRecord}  - id: "stale-field"
    target_config: "field.storage.node.body"
    purpose: "Placeholder"
    source_evidence: []
    rationale: "Not reviewed"
    asserted_by: "Fixture"
    last_reviewed: "2026-07-09"
    config_hash: "not-applicable"
    status: "draft"
    stale_behavior: "treat_as_no_intent"
`);
  const staleReport = await validatePacket({ packetDir });
  assert.equal(staleReport.valid, true, staleReport.errors.join('\n'));
  assert.equal(staleReport.completionEvidence.packetSupportsCompletion, false);
  assert.match(staleReport.completionEvidence.packetCompletionBlockedReasons.join('\n'), /durable-intent\.yml/);
});

test('independent completion claims require target-bound concrete check evidence', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'generic-claim-evidence-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  writeJson(join(packetDir, 'evidence', 'independent-verification', 'claim-evidence.json'), {
    targetBaseUrl: 'https://target.example',
    status: 200
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.independentVerificationSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /bound to its claimId, gate, target, checkedAt time, and concrete passing checks/);
});

test('blind completion evidence fails closed on missing declarations, all-N/A checks, and copied captures', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-fail-closed-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    delete blind.reviewer.runtimeOrTool;
    for (const review of blind.routeViewportReviews) {
      for (const check of Object.keys(review.checks)) {
        review.checks[check] = 'not_applicable';
      }
    }
  });
  const evidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  for (const name of ['target-desktop.png', 'source-mobile.png', 'target-mobile.png']) {
    cpSync(join(evidenceDir, 'source-desktop.png'), join(evidenceDir, name));
  }

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /named fresh verifier|reviewer is fresh/);
  assert.match(report.errors.join('\n'), /actualRequestedOutcome must be pass/);
  assert.match(report.errors.join('\n'), /duplicates the bytes/);
  assert.match(report.errors.join('\n'), /dimensions do not match its mobile viewport/);
});

test('blind route comparisons cannot use the target as source truth', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-source-as-target-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    for (const review of blind.routeViewportReviews) {
      review.sourceTruthReference = 'https://target.example/';
    }
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /sourceTruthReference must use the declared source origin/);
});

test('blind review cannot treat an external blocker as an accepted primary-route omission', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-external-blocker-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const routeMatrix = liveRouteMatrix('https://target.example');
  routeMatrix.primaryRoutes.push({
    sourcePath: '/about',
    targetPath: '/about',
    sourceIntent: 'Source about page',
    targetIntent: 'Target about page',
    matchesBrowserRenderedSource: true,
    accepted: true,
    notes: ''
  });
  writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
    blind.routeCoverage = {
      strategy: 'representative_sample_with_rationale',
      primaryRoutesReviewed: ['/'],
      omittedPrimaryRoutes: [{
        route: '/about',
        disposition: 'external_blocker',
        rationale: 'The route could not be inspected.',
        acceptedBy: ''
      }],
      notes: ''
    };
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(
    report.errors.join('\n'),
    /external.blocker.*(?:cannot support|blocks).*completion|completion.*blocked.*external/i
  );
});

test('blind accepted-out-of-scope dispositions require an owner and reconciled summary counts', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-accepted-scope-'));
  const canonicalPacket = join(temp, 'canonical');
  copyTemplatePacket(canonicalPacket);
  writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(canonicalPacket, 'https://target.example');

  const acceptedDefect = {
    id: 'DEF-OUT-1',
    severity: 'medium',
    title: 'Known source-only behavior',
    briefExpectation: 'The behavior would normally be rebuilt.',
    sourceTruthEvidence: 'source-desktop.png',
    targetFinding: 'The target intentionally omits it.',
    evidence: ['target-desktop.png'],
    recommendedFix: 'Rebuild it if scope changes.',
    status: 'accepted_out_of_scope',
    resolvedByReviewPassId: '',
    acceptedBy: 'Fixture Owner',
    acceptedReason: 'Explicitly excluded from this rebuild.'
  };
  const cases = [
    {
      name: 'omission-missing-owner',
      expected: /accepted_out_of_scope.*acceptedBy|acceptedBy.*accepted_out_of_scope/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'route-matrix.json'), (routeMatrix) => {
          routeMatrix.primaryRoutes.push({
            sourcePath: '/about',
            targetPath: '/about',
            sourceIntent: 'Source about page',
            targetIntent: 'Target about page',
            matchesBrowserRenderedSource: true,
            accepted: true,
            notes: ''
          });
        });
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.routeCoverage = {
            strategy: 'representative_sample_with_rationale',
            primaryRoutesReviewed: ['/'],
            omittedPrimaryRoutes: [{
              route: '/about',
              disposition: 'accepted_out_of_scope',
              rationale: 'The owner allegedly excluded this route.',
              acceptedBy: ''
            }],
            notes: ''
          };
        });
      }
    },
    {
      name: 'defect-missing-owner',
      expected: /accepted_out_of_scope.*(?:acceptedBy|acceptedReason)|(?:acceptedBy|acceptedReason).*accepted_out_of_scope/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.productDefects = [{ ...acceptedDefect, acceptedBy: '', acceptedReason: '' }];
          blind.summary.acceptedOutOfScopeIssueCount = 1;
        });
      }
    },
    {
      name: 'summary-count-mismatch',
      expected: /summary\.acceptedOutOfScopeIssueCount must match/i,
      mutate: (packetDir) => {
        mutateJson(join(packetDir, 'blind-adversarial-review.json'), (blind) => {
          blind.productDefects = [acceptedDefect];
          blind.summary.acceptedOutOfScopeIssueCount = 0;
        });
      }
    }
  ];

  for (const { name, expected, mutate } of cases) {
    const packetDir = join(temp, name);
    cpSync(canonicalPacket, packetDir, { recursive: true });
    mutate(packetDir);

    const report = await validatePacket({ packetDir });

    assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false, name);
    assert.equal(report.completionEvidence.packetSupportsCompletion, false, name);
    assert.match(report.errors.join('\n'), expected, name);
  }
});

test('browser completion evidence requires real public and editor screenshots', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'browser-missing-screenshots-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  mutateJson(join(packetDir, 'browser-evidence.json'), (browser) => {
    browser.publicRouteChecks[0].sourceScreenshot = 'evidence/browser/missing-source.png';
    browser.editorWorkflowChecks[0].formScreenshot = 'evidence/browser/missing-editor.png';
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, true, report.errors.join('\n'));
  assert.equal(report.completionEvidence.packetCompletionReady, false);
  assert.equal(report.completionEvidence.packetSupportsCompletion, false);
  assert.match(report.completionEvidence.packetCompletionBlockedReasons.join('\n'), /browser-evidence\.json/);
});

test('blind editor evidence requires captures or a target-bound action record', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'blind-weak-editor-evidence-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix('https://target.example'));
  addQualifyingReviewEvidence(packetDir, 'https://target.example');
  writeJson(join(packetDir, 'evidence', 'blind-adversarial-review', 'editor-task.json'), {
    publicOutputChanged: true,
    role: 'content editor'
  });

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /credible before\/after captures or structured target-bound editor action evidence/);
});

test('qualifying review evidence is bound to the same target the live verifier checks', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-stale-review-target-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);
      const independentPath = join(packetDir, 'independent-verification.json');
      const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
      independent.target.baseUrl = 'https://stale-target.example/';
      writeJson(independentPath, independent);
      const claimEvidencePath = join(packetDir, 'evidence', 'independent-verification', 'claim-evidence.json');
      const claimEvidence = JSON.parse(readFileSync(claimEvidencePath, 'utf8'));
      claimEvidence.targetBaseUrl = 'https://stale-target.example/';
      writeJson(claimEvidencePath, claimEvidence);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /target\.baseUrl origin/);
    }
  );
});

test('every completion-bearing packet artifact is bound to the inspected source or target origin', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-artifact-origin-bindings-'));
      const canonicalPacket = join(temp, 'canonical-packet');
      copyTemplatePacket(canonicalPacket);
      writeJson(join(canonicalPacket, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(canonicalPacket, baseUrl);

      const cases = [
        ['parity-report.json', /parity-report\.json targetUrl origin/, (value) => { value.targetUrl = 'https://stale-target.example/'; }],
        ['browser-evidence.json', /browser-evidence\.json site origin/, (value) => { value.site = 'https://stale-target.example/'; }],
        ['browser-route-target.json', /publicRouteChecks\[0\]\.targetUrl origin/, (value) => {
          value.publicRouteChecks[0].targetUrl = 'https://stale-target.example/';
        }, 'browser-evidence.json'],
        ['browser-route-source.json', /publicRouteChecks\[0\]\.sourceUrl origin/, (value) => {
          value.publicRouteChecks[0].sourceUrl = 'https://wrong-source.example/';
        }, 'browser-evidence.json'],
        ['drupal-readback.json', /drupal-readback\.json site origin/, (value) => { value.site = 'https://stale-target.example/'; }],
        ['field-output-matrix.json', /field-output-matrix\.json site origin/, (value) => { value.site = 'https://stale-target.example/'; }],
        ['pattern-map.json', /pattern-map\.json sourceSite origin/, (value) => { value.sourceSite = 'https://wrong-source.example/'; }],
        ['source-audit.json', /source-audit\.json site\.baseUrl origin/, (value) => {
          value.site.baseUrl = 'https://wrong-source.example/';
        }],
        ['independent-admin.json', /target\.adminUrl origin/, (value) => {
          value.target.adminUrl = 'https://stale-target.example/admin';
        }, 'independent-verification.json'],
        ['blind-editor.json', /editorExperienceReviews\[0\]\.targetAdminUrl origin/, (value) => {
          value.editorExperienceReviews[0].targetAdminUrl = 'https://stale-target.example/admin';
        }, 'blind-adversarial-review.json']
      ];

      for (const [name, expectedError, mutate, sourceFile = name] of cases) {
        const packetDir = join(temp, name.replace(/\.json$/, ''));
        cpSync(canonicalPacket, packetDir, { recursive: true });
        mutateJson(join(packetDir, sourceFile), mutate);
        const report = await verifyLive({ packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {} });
        assert.equal(report.valid, false, `${name} should invalidate live evidence`);
        assert.equal(report.completeLocalRebuildClaimAllowed, false, name);
        assert.match(report.errors.join('\n'), expectedError, name);
      }
    }
  );
});

test('completion is blocked when live Drupal site UUID differs from packet readback', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-site-uuid-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl, {
          mode: 'test',
          siteUuid: '22222222-2222-4222-8222-222222222222'
        })
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.completionBlockedReasons.join('\n'), /siteUuid/);
    }
  );
});

test('completion is blocked when live front-page or config state differs from packet readback', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-drupal-state-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl, {
          configStatusClean: false,
          configSyncDirectory: '../different-config/sync',
          frontPage: '/different-home',
          mode: 'test'
        })
      });

      assert.equal(report.valid, true, report.errors.join('\n'));
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(report.drupalRuntime.frontPageMatchesPacket, false);
      assert.equal(report.drupalRuntime.configSyncDirectoryMatchesPacket, false);
      assert.equal(report.drupalRuntime.configStatusClean, false);
      assert.match(report.completionBlockedReasons.join('\n'), /front-page setting/);
      assert.match(report.completionBlockedReasons.join('\n'), /config-sync directory/);
      assert.match(report.completionBlockedReasons.join('\n'), /config status is not clean/);
    }
  );
});

test('completion is blocked when HTTP evidence and Drupal identity come from different targets', async () => {
  await withHttpServer(
    (request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixtureTargetHtml(request));
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-runtime-target-mismatch-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));
      addQualifyingReviewEvidence(packetDir, baseUrl);

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: {
          baseUrl: 'https://different-project.ddev.site/',
          confirmed: true,
          configStatusClean: true,
          configSyncDirectory: '../config/sync',
          frontPage: '/',
          mode: 'test',
          project: 'different-project',
          reason: '',
          siteUuid: testSiteUuid
        }
      });

      assert.equal(report.valid, false);
      assert.equal(report.routeChecks.length, 0);
      assert.equal(report.drupalRuntime.siteUuidMatchesPacket, true);
      assert.equal(report.drupalRuntime.targetOriginMatches, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /Explicit target HTTP checks are disabled/);
      assert.match(report.completionBlockedReasons.join('\n'), /runtime base URL/);
    }
  );
});

test('live verifier refuses to certify the original source origin as the target', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-source-equals-target-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      const routeMatrix = liveRouteMatrix(baseUrl);
      routeMatrix.sourceBaseUrl = baseUrl;
      writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

      const report = await verifyLive({ packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {} });

      assert.equal(report.valid, false);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.match(report.errors.join('\n'), /same origin as sourceBaseUrl/);
    }
  );
});

test('live verifier rejects a target route that redirects back to the source origin', async () => {
  let sourceRequestCount = 0;
  await withHttpServer(
    (_request, response) => {
      sourceRequestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (sourceBaseUrl) => {
      await withHttpServer(
        (_request, response) => {
          response.writeHead(302, { location: `${sourceBaseUrl}/` });
          response.end();
        },
        async (targetBaseUrl) => {
          const temp = mkdtempSync(join(tmpdir(), 'live-target-redirects-source-'));
          const packetDir = join(temp, 'review-packet');
          copyTemplatePacket(packetDir);
          const routeMatrix = liveRouteMatrix(targetBaseUrl);
          routeMatrix.sourceBaseUrl = sourceBaseUrl;
          writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);

          const report = await verifyLive({
            packetDir,
            targetUrl: targetBaseUrl,
            cwd: repoRoot,
            environment: {},
            drupalRuntime: injectedDrupalRuntime(targetBaseUrl)
          });

          assert.equal(report.valid, false);
          assert.match(report.errors.join('\n'), /Refusing cross-origin redirect/);
        }
      );
    }
  );
  assert.equal(sourceRequestCount, 0, 'the verifier must reject a cross-origin Location before requesting it');
});

test('an explicit target not bound to DDEV is not fetched and has no remote opt-in escape', async () => {
  let requestCount = 0;
  await withHttpServer(
    (_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-explicit-target-opt-in-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({ packetDir, targetUrl: baseUrl, cwd: repoRoot, environment: {} });

      assert.equal(report.valid, false);
      assert.equal(report.routeChecks.length, 0);
      assert.match(report.errors.join('\n'), /Explicit target HTTP checks are disabled/);
      assert.doesNotMatch(report.errors.join('\n'), /allow-remote-target/);
    }
  );
  assert.equal(requestCount, 0);
});

test('live verifier fails closed when the declared target cannot be reached', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'live-unavailable-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const unavailableUrl = 'http://127.0.0.1:1';
  writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(unavailableUrl));

  const report = await verifyLive({
    packetDir,
    targetUrl: unavailableUrl,
    cwd: repoRoot,
    environment: {},
    drupalRuntime: injectedDrupalRuntime(unavailableUrl)
  });

  assert.equal(report.valid, false);
  assert.equal(report.completeLocalRebuildClaimAllowed, false);
  assert.match(report.errors.join('\n'), /could not be fetched/);
});

test('live verifier rejects an HTTP response larger than the five MiB evidence limit', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, {
        'content-length': String(5 * 1024 * 1024 + 1),
        'content-type': 'text/html; charset=utf-8'
      });
      response.end('oversized');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-oversized-response-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({
        packetDir,
        targetUrl: baseUrl,
        cwd: repoRoot,
        environment: {},
        drupalRuntime: injectedDrupalRuntime(baseUrl)
      });

      assert.equal(report.valid, false);
      assert.equal(report.liveTargetValid, false);
      assert.match(report.errors.join('\n'), /Response body exceeds the 5242880 byte limit/);
    }
  );
});

test('default mode does not trust the packet target URL as runtime discovery', async () => {
  let requestCount = 0;
  await withHttpServer(
    (_request, response) => {
      requestCount += 1;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-no-packet-fallback-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const report = await verifyLive({ packetDir, cwd: temp, environment: {} });

      assert.equal(report.valid, false);
      assert.match(report.errors.join('\n'), /No live target URL found/);
    }
  );
  assert.equal(requestCount, 0);
});

test('default CLI exits 2 when live checks pass but completion evidence is incomplete', async () => {
  await withHttpServer(
    (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<title>Target site</title><h1>Target home</h1>');
    },
    async (baseUrl) => {
      const temp = mkdtempSync(join(tmpdir(), 'live-cli-incomplete-'));
      const packetDir = join(temp, 'review-packet');
      copyTemplatePacket(packetDir);
      writeJson(join(packetDir, 'route-matrix.json'), liveRouteMatrix(baseUrl));

      const result = await runProcess(process.execPath, [
        join(repoRoot, 'bin', 'verify.mjs'),
        '--packet',
        packetDir
      ], repoRoot, { env: { ...process.env, DDEV_PRIMARY_URL: baseUrl } });

      assert.equal(result.status, 2, result.stderr);
      assert.match(result.stderr, /completion remains blocked/);
      const report = JSON.parse(readFileSync(join(packetDir, 'evidence', 'live-verification.json'), 'utf8'));
      assert.equal(report.valid, true);
      assert.equal(report.completeLocalRebuildClaimAllowed, false);
      assert.equal(report.packetDir, 'review-packet');
      assert.doesNotMatch(JSON.stringify(report), new RegExp(temp.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    }
  );
});

test('packet-only verification rejects authored completion authority', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'authored-completion-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const independentPath = join(packetDir, 'independent-verification.json');
  const independent = JSON.parse(readFileSync(independentPath, 'utf8'));
  independent.summary.completeLocalRebuildClaimAllowed = true;
  writeJson(independentPath, independent);

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completeLocalRebuildClaimAllowed, false);
  assert.match(report.errors.join('\n'), /completion authority belongs only to the live verifier/);
});

test('blind completion evidence rejects a text file named like a screenshot', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'fake-screenshot-'));
  const packetDir = join(temp, 'review-packet');
  copyTemplatePacket(packetDir);
  const evidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');
  mkdirSync(evidenceDir, { recursive: true });
  writeFileSync(join(evidenceDir, 'fake.png'), 'not an image\n');

  const routeMatrix = liveRouteMatrix('https://target.example');
  writeJson(join(packetDir, 'route-matrix.json'), routeMatrix);
  const blindPath = join(packetDir, 'blind-adversarial-review.json');
  const blind = JSON.parse(readFileSync(blindPath, 'utf8'));
  blind.reviewer = {
    nameOrRole: 'fresh blind reviewer',
    runtimeOrTool: 'browser',
    freshContextUsed: true,
    sameContextAsBuilder: false,
    didNotBuildTarget: true,
    inputsRestrictedToBriefTargetAndSourceTruth: true,
    implementationFilesReadBeforePublicReview: false,
    reviewPacketReadBeforePublicReview: false,
    priorBuildConversationRead: false,
    builderSummaryExcluded: true,
    notes: ''
  };
  blind.reviewInputs = {
    originalBrief: 'Rebuild the source site.',
    acceptanceCriteria: [],
    targetUrlsOrArtifacts: ['https://target.example/'],
    sourceOfTruthMaterials: [{ type: 'source_site', reference: 'https://source.example/', notes: '' }],
    credentialsUsed: [],
    excludedInputs: []
  };
  blind.routeViewportReviews = ['desktop', 'mobile'].map((viewport) => ({
    route: '/',
    sourceTruthReference: 'https://source.example/',
    targetUrlOrArtifact: 'https://target.example/',
    viewport,
    sourceScreenshot: 'fake.png',
    targetScreenshot: 'fake.png',
    routeNotes: `${viewport} checked`,
    checks: {},
    verdict: 'good',
    evidence: []
  }));
  blind.productDefects = [];
  blind.reviewPasses = [
    { id: 'pass-1', checkedAt: '2026-07-09T00:00:00Z', reviewer: 'fresh reviewer', verdict: 'good', notes: '' }
  ];
  blind.summary = {
    verdict: 'good',
    completionState: 'parity_reviewed',
    desktopMobileReviewed: true,
    routeNotesPresent: true,
    rawEvidencePresent: true,
    openBlockerIssueCount: 0,
    openCriticalIssueCount: 0,
    openHighIssueCount: 0,
    acceptedOutOfScopeIssueCount: 0,
    externalBlockerIssueCount: 0,
    notes: ''
  };
  writeJson(blindPath, blind);

  const report = await validatePacket({ packetDir });

  assert.equal(report.valid, false);
  assert.equal(report.completionEvidence.blindAdversarialReviewSupportsCompletion, false);
  assert.match(report.errors.join('\n'), /checks\.actualRequestedOutcome must be pass/);
  assert.match(report.errors.join('\n'), /must be a credible packet-local PNG, JPEG, WebP, or GIF capture/);
});
