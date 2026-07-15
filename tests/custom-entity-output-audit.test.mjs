import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS,
  CUSTOM_ENTITY_OUTPUT_AUDIT_PHP,
  CUSTOM_ENTITY_OUTPUT_AUDIT_SCHEMA,
  buildCustomEntityOutputAuditPhp,
  deriveCustomEntityOutputAuditInput,
  inspectCustomEntityOutputAudit as inspectCustomEntityOutputAuditRuntime,
  parseCustomEntityOutputAudit
} from '../bin/custom-entity-output-audit.mjs';
import { sha256 } from '../bin/state-fingerprint.mjs';

const H = (character) => `sha256:${character.repeat(64)}`;
const FIXTURE_ORIGIN = 'https://fixture.ddev.site';
const DEFAULT_DECLARATION_ID = `DECLARATION-${sha256('node\u0000landing_page\u0000field_hero_media\u0000media').slice(7, 23)}`;
const DEFAULT_CONTROLLER_BINDING = Object.freeze({
  routeName: 'output_probe.entity_output',
  extensionId: 'EXTENSION-0123456789abcdef',
  routeSourceFileId: 'SOURCE-routing123456',
  routeSurfaceId: 'SURFACE-routing123456',
  controllerSourceFileId: 'SOURCE-controller123456',
  controllerSurfaceId: 'SURFACE-controller123456'
});

function inspectCustomEntityOutputAudit(options) {
  return inspectCustomEntityOutputAuditRuntime({ targetOrigin: FIXTURE_ORIGIN, ...options });
}

function inventory() {
  return {
    schemaVersion: 'public-kit.custom-code-inventory.2',
    bounded: true,
    completed: true,
    applies: true,
    errors: [],
    extensions: [{
      id: 'EXTENSION-0123456789abcdef',
      machineName: 'output_probe',
      type: 'module',
      path: 'web/modules/custom/output_probe',
      drupalPath: 'modules/custom/output_probe',
      sourceFileIds: [
        'SOURCE-0123456789abcdef',
        'SOURCE-fedcba9876543210',
        'SOURCE-controller123456',
        'SOURCE-routing123456'
      ],
      routeNames: ['output_probe.entity_output']
    }],
    sourceFiles: [
      {
        id: 'SOURCE-0123456789abcdef',
        extension: 'output_probe',
        path: 'web/modules/custom/output_probe/output_probe.module',
        kind: 'procedural_php',
        surfaces: [{
          id: 'SURFACE-0123456789abcdef',
          kind: 'hook_or_callback',
          name: 'output_probe_helper_callback',
          line: 7
        }]
      },
      {
        id: 'SOURCE-fedcba9876543210',
        extension: 'output_probe',
        path: 'web/modules/custom/output_probe/src/Helper.php',
        kind: 'php_class',
        surfaces: [{
          id: 'SURFACE-fedcba9876543210',
          kind: 'class',
          name: 'Helper',
          line: 5
        }]
      },
      {
        id: 'SOURCE-controller123456',
        extension: 'output_probe',
        path: 'web/modules/custom/output_probe/src/Controller/OutputProbeController.php',
        kind: 'php_class',
        surfaces: [{
          id: 'SURFACE-controller123456',
          kind: 'controller_class',
          name: 'OutputProbeController',
          line: 5
        }]
      },
      {
        id: 'SOURCE-routing123456',
        extension: 'output_probe',
        path: 'web/modules/custom/output_probe/output_probe.routing.yml',
        kind: 'drupal_registration',
        surfaces: [{
          id: 'SURFACE-routing123456',
          kind: 'route',
          name: 'output_probe.entity_output',
          line: 1
        }]
      }
    ],
    tests: [],
    controllers: [{
      extension: 'output_probe',
      path: 'web/modules/custom/output_probe/src/Controller/OutputProbeController.php',
      sourceFileId: 'SOURCE-controller123456',
      surfaceIds: ['SURFACE-controller123456']
    }],
    routes: [{
      controller: '\\Drupal\\output_probe\\Controller\\OutputProbeController::view',
      extension: 'output_probe',
      file: 'web/modules/custom/output_probe/output_probe.routing.yml',
      name: 'output_probe.entity_output',
      path: '/{node}',
      discovery: 'routing_yaml'
    }],
    fingerprint: H('a'),
    // This authored review hint must never control runtime applicability.
    loadBearing: false
  };
}

function inventoryWithEntityViewRoute(routeName = 'output_probe.entity_view') {
  const value = inventory();
  value.sourceFiles = value.sourceFiles.filter(({ id }) => id !== 'SOURCE-controller123456');
  value.extensions[0].sourceFileIds = value.extensions[0].sourceFileIds.filter((id) => id !== 'SOURCE-controller123456');
  value.controllers = [];
  const source = value.sourceFiles.find(({ id }) => id === 'SOURCE-routing123456');
  source.surfaces = [{
    id: 'SURFACE-entityview123456',
    kind: 'route',
    name: routeName,
    line: 1
  }];
  value.extensions[0].routeNames = [routeName];
  value.routes = [{
    controller: '',
    extension: 'output_probe',
    file: source.path,
    name: routeName,
    path: '/{node}',
    discovery: 'routing_yaml'
  }];
  return value;
}

function inventoryWithCoreRenderHook({ unrelatedCandidate = false } = {}) {
  const value = inventory();
  value.sourceFiles = value.sourceFiles.filter(({ id }) => !['SOURCE-controller123456', 'SOURCE-routing123456'].includes(id));
  value.extensions[0].sourceFileIds = value.extensions[0].sourceFileIds.filter((id) => !['SOURCE-controller123456', 'SOURCE-routing123456'].includes(id));
  value.extensions[0].routeNames = [];
  value.controllers = [];
  value.routes = [];
  value.sourceFiles[0].surfaces[0].name = 'output_probe_preprocess_node';
  if (unrelatedCandidate) {
    value.sourceFiles.push({
      id: 'SOURCE-unrelated123456',
      extension: 'output_probe',
      path: 'web/modules/custom/output_probe/src/Unrelated.php',
      kind: 'php_class',
      surfaces: [{
        id: 'SURFACE-unrelated123456',
        kind: 'hook_or_callback',
        name: 'output_probe_page_attachments',
        line: 3
      }]
    });
    value.extensions[0].sourceFileIds.push('SOURCE-unrelated123456');
  }
  return value;
}

function inventoryWithUnrelatedOutputCandidate() {
  const value = inventoryWithCoreRenderHook({ unrelatedCandidate: true });
  value.sourceFiles[0].surfaces[0].name = 'output_probe_helper_callback';
  return value;
}

function inventoryWithDefaultThemeTemplate({ includeBase = false, includeComposite = false } = {}) {
  const value = {
    ...inventory(),
    extensions: [{
      id: 'EXTENSION-theme1234567890',
      machineName: 'output_theme',
      type: 'theme',
      path: 'web/themes/custom/output_theme',
      drupalPath: 'themes/custom/output_theme',
      sourceFileIds: ['SOURCE-theme1234567890'],
      routeNames: []
    }],
    sourceFiles: [{
      id: 'SOURCE-theme1234567890',
      extension: 'output_theme',
      path: 'web/themes/custom/output_theme/templates/content/node--landing-page.html.twig',
      kind: 'twig_template',
      surfaces: [{
        id: 'SURFACE-theme1234567890',
        kind: 'twig_template',
        name: 'node--landing-page.html.twig',
        line: 1
      }]
    }],
    controllers: [],
    routes: []
  };
  if (includeBase) {
    value.extensions[0].sourceFileIds.push('SOURCE-themebase123456');
    value.sourceFiles.push({
      id: 'SOURCE-themebase123456',
      extension: 'output_theme',
      path: 'web/themes/custom/output_theme/templates/content/node.html.twig',
      kind: 'twig_template',
      surfaces: [{
        id: 'SURFACE-themebase123456',
        kind: 'twig_template',
        name: 'node.html.twig',
        line: 1
      }]
    });
  }
  if (includeComposite) {
    value.extensions[0].sourceFileIds.push('SOURCE-themecomposite12');
    value.sourceFiles.push({
      id: 'SOURCE-themecomposite12',
      extension: 'output_theme',
      path: 'web/themes/custom/output_theme/templates/content/node--landing-page--full.html.twig',
      kind: 'twig_template',
      surfaces: [{
        id: 'SURFACE-themecomposite12',
        kind: 'twig_template',
        name: 'node--landing-page--full.html.twig',
        line: 1
      }]
    });
  }
  return value;
}

function inventoryWithDefaultThemePreprocess() {
  const value = inventoryWithDefaultThemeTemplate();
  value.sourceFiles = [{
    id: 'SOURCE-theme1234567890',
    extension: 'output_theme',
    path: 'web/themes/custom/output_theme/output_theme.theme',
    kind: 'procedural_php',
    surfaces: [{
      id: 'SURFACE-theme1234567890',
      kind: 'hook_or_callback',
      name: 'output_theme_preprocess_node',
      line: 3
    }]
  }];
  return value;
}

function inventoryWithMultipleRenderLayers() {
  const moduleInventory = inventoryWithCoreRenderHook();
  const themeInventory = inventoryWithDefaultThemeTemplate({ includeBase: true });
  const themeExtension = themeInventory.extensions[0];
  themeExtension.sourceFileIds.push('SOURCE-themepreprocess');
  themeInventory.sourceFiles.push({
    id: 'SOURCE-themepreprocess',
    extension: 'output_theme',
    path: 'web/themes/custom/output_theme/output_theme.theme',
    kind: 'procedural_php',
    surfaces: [{
      id: 'SURFACE-themepreprocess',
      kind: 'hook_or_callback',
      name: 'output_theme_preprocess_node',
      line: 3
    }]
  });
  return {
    ...moduleInventory,
    extensions: [...moduleInventory.extensions, themeExtension],
    sourceFiles: [...moduleInventory.sourceFiles, ...themeInventory.sourceFiles],
    controllers: [],
    routes: []
  };
}

function fieldOutputMatrix() {
  return {
    bundles: [{
      entityType: 'node',
      bundle: 'landing_page',
      fields: [{
        machineName: 'field_hero_media',
        fieldType: 'entity_reference:media',
        targetEntityType: 'media',
        publicRenderLocations: ['/'],
        affectsAnonymousOutput: true,
        accepted: true,
        loadBearing: false
      }]
    }]
  };
}

function routeMatrix() {
  return {
    primaryRoutes: [{ targetPath: '/', accepted: true }],
    routes: [{ targetPath: '/', accepted: true }],
    targetRequiredRoutes: [{ targetPath: '/', shouldBePublic: true, accepted: true }]
  };
}

function derived(overrides = {}) {
  return deriveCustomEntityOutputAuditInput({
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    targetOrigin: FIXTURE_ORIGIN,
    ...overrides
  });
}

function dependency(entityType, character) {
  return {
    entityType,
    entitySha256: H(character),
    fieldPathSha256: H(character),
    access: 'allowed',
    accessMetadataSha256: H(character),
    cacheTagCount: 2,
    invalidationTagCount: 2,
    renderedTagIntersectionCount: 2
  };
}

function coverageKey(row) {
  return `${row.role}\u0000${row.extensionSha256}\u0000${row.sourceFileSha256}\u0000${row.surfaceSha256}`;
}

function sortedCoverage(rows) {
  return [...new Map(rows.map((row) => [coverageKey(row), row])).values()]
    .sort((left, right) => coverageKey(left) < coverageKey(right) ? -1 : coverageKey(left) > coverageKey(right) ? 1 : 0);
}

function routeCandidateCoverage(input, {
  handlerKind,
  runtimeRouteName,
  activeCandidateExtensionSha256,
  defaultThemeExtensionSha256,
  nodeBundle = 'landing_page',
  entityViewMode = 'full'
}) {
  if (!input) {
    return handlerKind === 'candidate_controller'
      ? sortedCoverage([
          {
            role: 'custom_route',
            extensionSha256: sha256(DEFAULT_CONTROLLER_BINDING.extensionId),
            sourceFileSha256: sha256(DEFAULT_CONTROLLER_BINDING.routeSourceFileId),
            surfaceSha256: sha256(DEFAULT_CONTROLLER_BINDING.routeSurfaceId)
          },
          {
            role: 'custom_controller',
            extensionSha256: sha256(DEFAULT_CONTROLLER_BINDING.extensionId),
            sourceFileSha256: sha256(DEFAULT_CONTROLLER_BINDING.controllerSourceFileId),
            surfaceSha256: sha256(DEFAULT_CONTROLLER_BINDING.controllerSurfaceId)
          }
        ])
      : [];
  }
  const coverage = [];
  const active = new Set(activeCandidateExtensionSha256);
  const candidateRouteBinding = input.candidateRouteBindings.find(({ routeName }) => routeName === runtimeRouteName);
  const routeBinding = candidateRouteBinding && active.has(sha256(candidateRouteBinding.extensionId))
    ? candidateRouteBinding
    : null;
  if (routeBinding) {
    coverage.push({
      role: 'custom_route',
      extensionSha256: sha256(routeBinding.extensionId),
      sourceFileSha256: sha256(routeBinding.routeSourceFileId),
      surfaceSha256: sha256(routeBinding.routeSurfaceId)
    });
  }
  if (handlerKind === 'candidate_controller') {
    if (routeBinding) {
      coverage.push({
        role: 'custom_controller',
        extensionSha256: sha256(routeBinding.extensionId),
        sourceFileSha256: sha256(routeBinding.controllerSourceFileId),
        surfaceSha256: sha256(routeBinding.controllerSurfaceId)
      });
    }
    return sortedCoverage(coverage);
  }
  if (handlerKind !== 'entity_view') return sortedCoverage(coverage);
  let selectedTemplate = null;
  let selectedPriority = -1;
  for (const binding of input.candidateRenderBindings) {
    const extensionSha256 = sha256(binding.extensionId);
    const bindingActive = binding.extensionType === 'module'
      ? active.has(extensionSha256)
      : binding.extensionType === 'theme' && extensionSha256 === defaultThemeExtensionSha256;
    if (!bindingActive) continue;
    if (['preprocess_node', 'node_render_hook'].includes(binding.selectorKind)) {
      coverage.push({
        role: 'render_hook',
        extensionSha256,
        sourceFileSha256: sha256(binding.sourceFileId),
        surfaceSha256: sha256(binding.surfaceId)
      });
      continue;
    }
    const [selectorBundle, selectorViewMode] = binding.selectorKind === 'node_bundle_view_mode_template'
      ? String(binding.selectorValue).split('\u0000')
      : ['', ''];
    const priority = binding.selectorKind === 'node_bundle_view_mode_template'
      ? (selectorBundle === nodeBundle && selectorViewMode === entityViewMode ? 4 : -1)
      : binding.selectorKind === 'node_bundle_template'
      ? (binding.selectorValue === nodeBundle ? 3 : -1)
      : binding.selectorKind === 'node_view_mode_template'
        ? (binding.selectorValue === entityViewMode ? 2 : -1)
        : binding.selectorKind === 'node_template'
          ? 1
          : -1;
    if (priority > selectedPriority) {
      selectedTemplate = binding;
      selectedPriority = priority;
    }
  }
  if (selectedTemplate && selectedPriority >= 0) {
    coverage.push({
      role: 'render_template',
      extensionSha256: sha256(selectedTemplate.extensionId),
      sourceFileSha256: sha256(selectedTemplate.sourceFileId),
      surfaceSha256: sha256(selectedTemplate.surfaceId)
    });
  }
  return sortedCoverage(coverage);
}

function validRuntime(inputOrFingerprint, options = {}) {
  const input = typeof inputOrFingerprint === 'string' ? null : inputOrFingerprint;
  const inputFingerprint = typeof inputOrFingerprint === 'string'
    ? inputOrFingerprint
    : inputOrFingerprint.inputFingerprint;
  const allow = options.allow ?? false;
  const routeHashes = options.routeHashes ?? input?.routes.map(({ path }) => sha256(path)) ?? [sha256('/')];
  const routeDeclarationIds = options.routeDeclarationIds ?? routeHashes.map((_, index) =>
    input?.routes[index]?.declarationIds ?? input?.routes[0]?.declarationIds ?? [DEFAULT_DECLARATION_ID]
  );
  const targetOrigin = options.targetOrigin ?? input?.targetOrigin ?? FIXTURE_ORIGIN;
  const activeCandidateExtensionSha256 = [...(options.activeCandidateExtensionSha256 ?? input?.extensions.map(({ id }) => sha256(id)) ?? [
    sha256(DEFAULT_CONTROLLER_BINDING.extensionId)
  ])].sort();
  const defaultThemeExtensionSha256 = options.defaultThemeExtensionSha256 ?? (
    input?.extensions.find(({ type }) => type === 'theme')?.id
      ? sha256(input.extensions.find(({ type }) => type === 'theme').id)
      : ''
  );
  const optionAt = (plural, singular, index, fallback) => Array.isArray(options[plural])
    ? options[plural][index] ?? fallback
    : Object.hasOwn(options, singular)
      ? options[singular]
      : fallback;
  const defaultCandidateRouteBinding = Object.hasOwn(options, 'candidateRouteBinding')
    ? options.candidateRouteBinding
    : input?.candidateRouteBindings[0] ?? DEFAULT_CONTROLLER_BINDING;
  const defaultRuntimeRouteName = options.runtimeRouteName ?? defaultCandidateRouteBinding?.routeName ?? 'entity.node.canonical';
  const routeApplies = routeHashes.map((_, index) => Boolean(optionAt('routeApplies', 'applies', index, true)));
  const routeRecords = routeHashes.map((routeSha256, index) => {
    const applies = routeApplies[index];
    const handlerKind = optionAt('handlerKinds', 'handlerKind', index, applies ? 'candidate_controller' : 'entity_view');
    const runtimeRouteName = optionAt('runtimeRouteNames', 'runtimeRouteName', index, defaultRuntimeRouteName);
    const entityViewMode = optionAt('entityViewModes', 'entityViewMode', index, 'full');
    const nodeBundle = optionAt('nodeBundles', 'nodeBundle', index, 'landing_page');
    const matched = applies && Boolean(optionAt('routeMatched', 'matched', index, true));
    const rendered = matched && Boolean(optionAt('routeRendered', 'rendered', index, true));
    const candidateRouteBinding = Object.hasOwn(options, 'candidateRouteBinding')
      ? options.candidateRouteBinding
      : input?.candidateRouteBindings.find(({ routeName }) => routeName === runtimeRouteName) ??
        (!input ? DEFAULT_CONTROLLER_BINDING : null);
    const activeRouteBinding = candidateRouteBinding && activeCandidateExtensionSha256.includes(sha256(candidateRouteBinding.extensionId))
      ? candidateRouteBinding
      : null;
    const expectedCoverage = routeCandidateCoverage(input, {
      handlerKind,
      runtimeRouteName,
      activeCandidateExtensionSha256,
      defaultThemeExtensionSha256,
      nodeBundle,
      entityViewMode
    });
    const suppliedCoverage = Array.isArray(options.candidateCoverages)
      ? options.candidateCoverages[index] ?? expectedCoverage
      : Object.hasOwn(options, 'candidateCoverage')
        ? options.candidateCoverage
        : expectedCoverage;
    const candidateCoverage = rendered ? suppliedCoverage : [];
    const primaryRenderCoverage = candidateCoverage.find(({ role }) => role === 'render_hook') ??
      candidateCoverage.find(({ role }) => role === 'render_template') ?? null;
    const candidateProvenanceKind = !applies
      ? ''
      : optionAt('candidateProvenanceKinds', 'candidateProvenanceKind', index,
          handlerKind === 'candidate_controller'
            ? 'custom_controller'
            : activeRouteBinding
              ? 'custom_route'
              : primaryRenderCoverage?.role === 'render_hook'
                ? 'render_hook'
                : 'default_theme_template');
    const candidateExtensionSha256 = !applies
      ? ''
      : activeRouteBinding
        ? sha256(activeRouteBinding.extensionId)
        : primaryRenderCoverage?.extensionSha256 ?? '';
    const coveredDeclarationIds = matched ? routeDeclarationIds[index] : [];
    const dependencies = rendered
      ? [dependency('node', '2'), dependency('media', '3'), dependency('file', '4')]
      : [];
    return {
      routeSha256,
      routeNameSha256: sha256(runtimeRouteName),
      declarationBindingSha256: sha256(routeDeclarationIds[index]),
      candidateExtensionSetSha256: activeCandidateExtensionSha256.length > 0 ? sha256(activeCandidateExtensionSha256) : '',
      applies,
      matched,
      nodeBundleSha256: sha256(nodeBundle),
      entityViewModeSha256: handlerKind === 'entity_view' ? sha256(entityViewMode) : '',
      outputHandlerKind: handlerKind,
      outputHandlerSha256: H('8'),
      controllerExtensionSha256: applies && handlerKind === 'candidate_controller' ? H('a') : '',
      candidateProvenanceKind,
      candidateExtensionSha256,
      candidateRouteSourceFileSha256: applies && activeRouteBinding ? sha256(activeRouteBinding.routeSourceFileId) : '',
      candidateRouteSurfaceSha256: applies && activeRouteBinding ? sha256(activeRouteBinding.routeSurfaceId) : '',
      candidateOutputSourceFileSha256: !applies
        ? ''
        : candidateProvenanceKind === 'custom_controller'
          ? sha256(activeRouteBinding?.controllerSourceFileId ?? '')
          : candidateProvenanceKind === 'custom_route'
            ? sha256(activeRouteBinding?.routeSourceFileId ?? '')
            : primaryRenderCoverage?.sourceFileSha256 ?? '',
      candidateOutputSurfaceSha256: !applies
        ? ''
        : candidateProvenanceKind === 'custom_controller'
          ? sha256(activeRouteBinding?.controllerSurfaceId ?? '')
          : candidateProvenanceKind === 'custom_route'
            ? sha256(activeRouteBinding?.routeSurfaceId ?? '')
            : primaryRenderCoverage?.surfaceSha256 ?? '',
      candidateCoverage,
      routeAccess: applies ? 'allowed' : '',
      routeAccessMetadataSha256: applies ? H('b') : '',
      nodeSha256: H('2'),
      rendered,
      renderedMetadataSha256: rendered ? H('9') : '',
      renderedTagCount: rendered ? 9 : 0,
      renderedContextCount: rendered ? 3 : 0,
      renderedMaxAge: rendered ? -1 : 0,
      coveredDeclarationCount: coveredDeclarationIds.length,
      coveredDeclarationSetSha256: coveredDeclarationIds.length > 0 ? sha256(coveredDeclarationIds) : '',
      dependencyCount: dependencies.length,
      dependencies
    };
  });
  const coveredDeclarationIds = [...new Set(routeRecords.flatMap((route, index) => route.matched ? routeDeclarationIds[index] : []))].sort();
  const allCandidateCoverage = routeRecords.flatMap(({ candidateCoverage }) => candidateCoverage);
  const coveredCandidateSourceFileSha256 = [...new Set(allCandidateCoverage.map(({ sourceFileSha256 }) => sourceFileSha256))].sort();
  const coveredCandidateSurfaceSha256 = [...new Set(allCandidateCoverage.map(({ surfaceSha256 }) => surfaceSha256))].sort();
  const dependencyCount = routeRecords.reduce((total, route) => total + route.dependencyCount, 0);
  const status = options.status ?? (routeApplies.some(Boolean) ? 'pass' : 'not_applicable');
  const invalidationProofCount = Math.min(3, dependencyCount);
  return {
    schemaVersion: CUSTOM_ENTITY_OUTPUT_AUDIT_SCHEMA,
    bounded: true,
    completed: true,
    status,
    noExplicitVerifierMutation: !allow,
    allowOwnedCacheInvalidation: allow,
    inputFingerprint,
    targetOriginSha256: sha256(targetOrigin),
    activeCandidateExtensionCount: activeCandidateExtensionSha256.length,
    activeCandidateExtensionSha256,
    defaultThemeExtensionSha256,
    routeCount: routeHashes.length,
    applicableRouteCount: routeApplies.filter(Boolean).length,
    matchedNodeRouteCount: routeRecords.filter(({ matched }) => matched).length,
    renderedRouteCount: routeRecords.filter(({ rendered }) => rendered).length,
    dependencyCount,
    coveredDeclarationCount: coveredDeclarationIds.length,
    coveredDeclarationSetSha256: coveredDeclarationIds.length > 0 ? sha256(coveredDeclarationIds) : '',
    coveredCandidateSourceFileCount: coveredCandidateSourceFileSha256.length,
    coveredCandidateSourceFileSetSha256: coveredCandidateSourceFileSha256.length > 0 ? sha256(coveredCandidateSourceFileSha256) : '',
    coveredCandidateSurfaceCount: coveredCandidateSurfaceSha256.length,
    coveredCandidateSurfaceSetSha256: coveredCandidateSurfaceSha256.length > 0 ? sha256(coveredCandidateSurfaceSha256) : '',
    routes: routeRecords,
    invalidation: allow
      ? status === 'not_applicable'
        ? {
            status: 'not_run_due_to_not_applicable', attempted: false, seededCount: 0, invalidatedCount: 0,
            cleanupRequired: false, cleanupCompleted: true, evidenceSha256: ''
          }
        : status === 'pass'
        ? {
          status: 'pass', attempted: true, seededCount: invalidationProofCount, invalidatedCount: invalidationProofCount,
          cleanupRequired: true, cleanupCompleted: true, evidenceSha256: H('b')
        }
        : {
            status: 'not_run_due_to_violations', attempted: false, seededCount: 0, invalidatedCount: 0,
            cleanupRequired: false, cleanupCompleted: true, evidenceSha256: ''
          }
      : {
          status: 'not_run', attempted: false, seededCount: 0, invalidatedCount: 0,
          cleanupRequired: false, cleanupCompleted: true, evidenceSha256: ''
        },
    violations: options.violations ?? []
  };
}

function clone(value) {
  return structuredClone(value);
}

function parserOptions(input, overrides = {}) {
  return {
    expectedInputFingerprint: input.inputFingerprint,
    expectedTargetOrigin: input.targetOrigin,
    expectedRouteCount: input.routes.length,
    expectedRouteSha256: input.routes.map(({ path }) => sha256(path)),
    expectedRouteBindings: input.routes,
    expectedCandidateRouteBindings: input.candidateRouteBindings,
    expectedCandidateRenderBindings: input.candidateRenderBindings,
    expectedCandidateSourceFileIds: input.candidateSourceFileIds,
    expectedCandidateSurfaceIds: input.candidateSurfaceIds,
    expectedExtensions: input.extensions,
    expectedDeclarationIds: input.declarations.map(({ id }) => id),
    maximumActiveCandidateExtensionCount: input.extensions.length,
    ...overrides
  };
}

test('derives output candidates without authored load-bearing identity and unions explicit static candidates', () => {
  const input = derived({
    staticAudit: {
      candidateSourceFileIds: ['SOURCE-fedcba9876543210'],
      candidateSurfaceIds: ['SURFACE-fedcba9876543210'],
      loadBearing: false
    }
  });
  assert.deepEqual(input.errors, []);
  assert.deepEqual(input.candidateSourceFileIds, [
    'SOURCE-controller123456',
    'SOURCE-fedcba9876543210',
    'SOURCE-routing123456'
  ]);
  assert.deepEqual(input.candidateSurfaceIds, [
    'SURFACE-controller123456',
    'SURFACE-fedcba9876543210',
    'SURFACE-routing123456'
  ]);
  assert.equal(input.declarations.length, 1);
  assert.equal(input.declarations[0].targetEntityType, 'media');
  assert.deepEqual(input.declarations[0].publicRoutePaths, ['/']);
  assert.deepEqual(input.routes, [{
    path: '/',
    declarationIds: [input.declarations[0].id],
    bundles: ['landing_page']
  }]);
});

test('probes only explicit public render locations and binds each route to its declarations', () => {
  const input = derived({
    routeMatrix: {
      routes: [
        { targetPath: '/', accepted: true },
        { targetPath: '/unrelated-listing', accepted: true }
      ]
    }
  });
  assert.deepEqual(input.routes.map(({ path }) => path), ['/']);
  assert.deepEqual(input.routes[0].declarationIds, [input.declarations[0].id]);
  assert.deepEqual(input.routes[0].bundles, ['landing_page']);
});

test('rejects one concrete public route bound to multiple node bundles before execution', () => {
  const matrix = fieldOutputMatrix();
  matrix.bundles.push({
    entityType: 'node',
    bundle: 'article',
    fields: [{
      machineName: 'field_article_media',
      fieldType: 'entity_reference:media',
      targetEntityType: 'media',
      publicRenderLocations: ['/'],
      affectsAnonymousOutput: true
    }]
  });
  const input = derived({ fieldOutputMatrix: matrix });
  assert.match(input.errors.join('\n'), /cannot bind declarations from multiple node bundles/i);
  let calls = 0;
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routeMatrix(),
    runner: () => { calls += 1; }
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.failures[0].code, 'invalid_verifier_inputs');
  assert.equal(calls, 0);
});

test('fails closed when a public field lacks an executable accepted route binding', async () => {
  for (const publicRenderLocations of [[], ['canonical_detail'], ['/missing']]) {
    const matrix = fieldOutputMatrix();
    matrix.bundles[0].fields[0].publicRenderLocations = publicRenderLocations;
    let calls = 0;
    const result = inspectCustomEntityOutputAudit({
      projectRoot: '/fixture',
      sourceInventory: inventory(),
      fieldOutputMatrix: matrix,
      routeMatrix: routeMatrix(),
      runner: () => { calls += 1; }
    });
    assert.equal(result.status, 'fail');
    assert.equal(result.failures[0].code, 'missing_public_route_targets');
    assert.equal(calls, 0);
  }
});

test('unions parser entity-output candidate bindings by file and surface inventory IDs', () => {
  const input = derived({
    staticAudit: {
      schemaVersion: 'public-kit.mutable-identity-drupal-ast.1',
      completed: true,
      entityOutputCandidates: [{
        id: 'ENTITYOUT-0123456789abcdef',
        fileId: 'SOURCE-fedcba9876543210',
        sourceSurfaceIds: ['SURFACE-fedcba9876543210'],
        entityKinds: ['media'],
        sinkKind: 'render_array'
      }]
    }
  });
  assert.deepEqual(input.errors, []);
  assert.deepEqual(input.candidateSourceFileIds, [
    'SOURCE-controller123456',
    'SOURCE-fedcba9876543210',
    'SOURCE-routing123456'
  ]);
  assert.deepEqual(input.candidateSurfaceIds, [
    'SURFACE-controller123456',
    'SURFACE-fedcba9876543210',
    'SURFACE-routing123456'
  ]);
});

test('rejects static candidate IDs that are not bound to the verifier source inventory', () => {
  const input = derived({ staticAudit: { candidateSourceFileIds: ['SOURCE-not-in-inventory'] } });
  assert.match(input.errors.join('\n'), /absent from the source inventory/i);
});

test('returns N/A without executing Drupal when candidates or typed declarations are absent', async () => {
  for (const options of [
    { sourceInventory: { ...inventory(), sourceFiles: [] } },
    { fieldOutputMatrix: { bundles: [] } }
  ]) {
    let calls = 0;
    const result = await inspectCustomEntityOutputAudit({
      projectRoot: '/fixture',
      sourceInventory: inventory(),
      fieldOutputMatrix: fieldOutputMatrix(),
      routeMatrix: routeMatrix(),
      ...options,
      runner: () => { calls += 1; throw new Error('must not execute'); }
    });
    assert.equal(result.status, 'not_applicable');
    assert.equal(result.completed, true);
    assert.equal(calls, 0);
  }
});

test('fails closed without executing Drupal when candidates lack a public route target', async () => {
  let calls = 0;
  const result = await inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: {},
    runner: () => { calls += 1; }
  });
  assert.equal(result.status, 'fail');
  assert.equal(result.applies, true);
  assert.equal(result.failures[0].code, 'missing_public_route_targets');
  assert.equal(calls, 0);
});

test('isolated invalidation requires exact disposable-boundary evidence before execution', async () => {
  for (const isolation of [
    null,
    { executionBoundary: 'working-target', workspaceId: 'DISPOSABLE-test', exactHead: true, freshDatabase: true },
    { executionBoundary: 'verifier-owned-disposable-ddev', workspaceId: 'working', exactHead: true, freshDatabase: true },
    { executionBoundary: 'verifier-owned-disposable-ddev', workspaceId: 'DISPOSABLE-test', exactHead: false, freshDatabase: true }
  ]) {
    let calls = 0;
    const result = await inspectCustomEntityOutputAudit({
      projectRoot: '/fixture',
      sourceInventory: inventory(),
      fieldOutputMatrix: fieldOutputMatrix(),
      routeMatrix: routeMatrix(),
      allowOwnedCacheInvalidation: true,
      isolation,
      runner: () => { calls += 1; }
    });
    assert.equal(result.status, 'blocked');
    assert.equal(result.failures[0].code, 'disposable_boundary_not_proven');
    assert.equal(calls, 0);
  }
});

test('isolated invalidation accepts the verifier canonical exact-head disposable boundary', async () => {
  const expected = derived();
  let calls = 0;
  const result = await inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    allowOwnedCacheInvalidation: true,
    isolation: {
      executionBoundary: 'exact-head-disposable-ddev',
      workspaceId: 'DISPOSABLE-fixture',
      exactHead: true,
      freshDatabase: true
    },
    runner: () => {
      calls += 1;
      return { ok: true, output: JSON.stringify(validRuntime(expected.inputFingerprint, { allow: true })) };
    }
  });
  assert.equal(result.status, 'pass');
  assert.equal(calls, 1);
});

test('accepts a strictly bound default fake-runner result without explicit verifier mutation', async () => {
  const expected = derived();
  let invocation;
  const result = await inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: (value) => {
      invocation = value;
      return { ok: true, output: JSON.stringify(validRuntime(expected.inputFingerprint)) };
    }
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.noExplicitVerifierMutation, true);
  assert.equal(result.runtime.invalidation.status, 'not_run');
  assert.deepEqual(result.candidateSourceFileIds, expected.candidateSourceFileIds);
  assert.equal(invocation.timeoutMs, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.timeoutMs);
  assert.equal(invocation.outputLimitBytes, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.outputBytes);
  assert.match(invocation.php, /allowOwnedCacheInvalidation/);
});

test('binds requests and evidence to the exact authoritative target origin', () => {
  const expected = derived();
  let payload;
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: ({ php }) => {
      const encoded = php.match(/base64_decode\('([^']+)'/)?.[1] ?? '';
      payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
      return { ok: true, output: JSON.stringify(validRuntime(expected)) };
    }
  });
  assert.equal(result.status, 'pass');
  assert.equal(payload.targetOrigin, FIXTURE_ORIGIN);
  assert.equal(result.runtime.targetOriginSha256, sha256(FIXTURE_ORIGIN));
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /Request::create\(\$target_origin \. \(string\) \$path, 'GET'\)/);
  assert.doesNotMatch(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /verifier\.invalid/);

  let calls = 0;
  const invalid = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    targetOrigin: `${FIXTURE_ORIGIN}/unexpected-path`,
    environment: { DDEV_PRIMARY_URL: FIXTURE_ORIGIN },
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => { calls += 1; }
  });
  assert.equal(invalid.status, 'blocked');
  assert.equal(invalid.failures[0].code, 'invalid_verifier_inputs');
  assert.equal(calls, 0);

  assert.throws(
    () => parseCustomEntityOutputAudit(validRuntime(expected), parserOptions(expected, {
      expectedTargetOrigin: 'https://other.ddev.site'
    })),
    /exact target origin/i
  );
});

test('accepts DDEV_PRIMARY_URL only as the environment origin fallback', () => {
  const expected = derived();
  const result = inspectCustomEntityOutputAuditRuntime({
    projectRoot: '/fixture',
    environment: { DDEV_PRIMARY_URL: FIXTURE_ORIGIN },
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({ ok: true, output: JSON.stringify(validRuntime(expected)) })
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.targetOriginSha256, sha256(FIXTURE_ORIGIN));
});

test('accepts an exact custom entity-view route without misattributing a core controller', () => {
  const sourceInventory = inventoryWithEntityViewRoute();
  const expected = derived({ sourceInventory });
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.routes[0].outputHandlerKind, 'entity_view');
  assert.equal(result.runtime.routes[0].controllerExtensionSha256, '');
});

test('rejects a core entity-view route laundered through an unrelated custom route candidate', () => {
  const expected = derived();
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, {
        handlerKind: 'entity_view',
        runtimeRouteName: 'entity.node.canonical'
      }))
    })
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.failures[0].code, 'runtime_schema_invalid');
});

test('accepts exact active render-hook provenance on a core entity-view route', () => {
  const sourceInventory = inventoryWithCoreRenderHook();
  const expected = derived({ sourceInventory });
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.routes[0].candidateProvenanceKind, 'render_hook');
});

test('accepts exact active default custom-theme Twig provenance on a core entity-view route', () => {
  const sourceInventory = inventoryWithDefaultThemeTemplate();
  const expected = derived({ sourceInventory });
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.routes[0].candidateProvenanceKind, 'default_theme_template');
});

test('covers only the selected bundle Twig layer when a default-theme base fallback also exists', () => {
  const sourceInventory = inventoryWithDefaultThemeTemplate({ includeBase: true });
  const expected = derived({ sourceInventory });
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(expected.candidateRenderBindings.length, 2);
  assert.equal(result.status, 'pass');
  assert.deepEqual(result.runtime.routes[0].candidateCoverage, [{
    role: 'render_template',
    extensionSha256: sha256('EXTENSION-theme1234567890'),
    sourceFileSha256: sha256('SOURCE-theme1234567890'),
    surfaceSha256: sha256('SURFACE-theme1234567890')
  }]);
});

test('accepts exact active default custom-theme preprocess provenance on a core entity-view route', () => {
  const sourceInventory = inventoryWithDefaultThemePreprocess();
  const expected = derived({ sourceInventory });
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.routes[0].candidateProvenanceKind, 'render_hook');
});

test('requires the exact union of active module hook, theme preprocess, and selected Twig layers', () => {
  const sourceInventory = inventoryWithMultipleRenderLayers();
  const expected = derived({ sourceInventory });
  const passingRuntime = validRuntime(expected, { handlerKind: 'entity_view' });
  const passing = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({ ok: true, output: JSON.stringify(passingRuntime) })
  });
  assert.equal(passing.status, 'pass');
  assert.deepEqual(
    passing.runtime.routes[0].candidateCoverage.map(({ role }) => role),
    ['render_hook', 'render_hook', 'render_template']
  );

  const omittedRuntime = validRuntime(expected, { handlerKind: 'entity_view' });
  omittedRuntime.routes[0].candidateCoverage = omittedRuntime.routes[0].candidateCoverage.slice(1);
  const sourceHashes = [...new Set(omittedRuntime.routes[0].candidateCoverage.map(({ sourceFileSha256 }) => sourceFileSha256))].sort();
  const surfaceHashes = [...new Set(omittedRuntime.routes[0].candidateCoverage.map(({ surfaceSha256 }) => surfaceSha256))].sort();
  omittedRuntime.coveredCandidateSourceFileCount = sourceHashes.length;
  omittedRuntime.coveredCandidateSourceFileSetSha256 = sourceHashes.length > 0 ? sha256(sourceHashes) : '';
  omittedRuntime.coveredCandidateSurfaceCount = surfaceHashes.length;
  omittedRuntime.coveredCandidateSurfaceSetSha256 = surfaceHashes.length > 0 ? sha256(surfaceHashes) : '';
  const omitted = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({ ok: true, output: JSON.stringify(omittedRuntime) })
  });
  assert.equal(omitted.status, 'blocked');
  assert.equal(omitted.failures[0].code, 'runtime_schema_invalid');
});

test('does not require unrelated output candidates to execute on a valid declared entity route', () => {
  const sourceInventory = inventoryWithCoreRenderHook({ unrelatedCandidate: true });
  const expected = derived({ sourceInventory });
  assert.ok(expected.candidateSourceFileIds.includes('SOURCE-unrelated123456'));
  assert.ok(expected.candidateSurfaceIds.includes('SURFACE-unrelated123456'));
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.coveredCandidateSourceFileCount, 1);
  assert.equal(result.runtime.coveredCandidateSurfaceCount, 1);
});

test('completes N/A with exact core-only route records when active candidates are unrelated', () => {
  const sourceInventory = inventoryWithUnrelatedOutputCandidate();
  const expected = derived({ sourceInventory });
  assert.ok(expected.candidateSourceFileIds.includes('SOURCE-unrelated123456'));
  assert.equal(expected.candidateRouteBindings.length, 0);
  assert.equal(expected.candidateRenderBindings.length, 0);
  for (const allowOwnedCacheInvalidation of [false, true]) {
    const result = inspectCustomEntityOutputAudit({
      projectRoot: '/fixture',
      sourceInventory,
      fieldOutputMatrix: fieldOutputMatrix(),
      routeMatrix: routeMatrix(),
      allowOwnedCacheInvalidation,
      isolation: allowOwnedCacheInvalidation
        ? {
            executionBoundary: 'verifier-owned-disposable-ddev',
            workspaceId: 'DISPOSABLE-core-only',
            exactHead: true,
            freshDatabase: true
          }
        : null,
      runner: () => ({
        ok: true,
        output: JSON.stringify(validRuntime(expected, {
          allow: allowOwnedCacheInvalidation,
          handlerKind: 'entity_view',
          runtimeRouteName: 'entity.node.canonical',
          routeApplies: [false]
        }))
      })
    });
    assert.equal(result.completed, true);
    assert.equal(result.status, 'not_applicable');
    assert.equal(result.applies, false);
    assert.equal(result.runtime.activeCandidateExtensionCount, 1);
    assert.equal(result.runtime.routeCount, 1);
    assert.equal(result.runtime.applicableRouteCount, 0);
    assert.equal(result.runtime.routes[0].applies, false);
    assert.equal(
      result.runtime.invalidation.status,
      allowOwnedCacheInvalidation ? 'not_run_due_to_not_applicable' : 'not_run'
    );
  }

  const ambiguous = validRuntime(expected, {
    handlerKind: 'entity_view',
    runtimeRouteName: 'entity.node.canonical',
    routeApplies: [false]
  });
  ambiguous.routes[0].outputHandlerKind = '';
  ambiguous.routes[0].outputHandlerSha256 = '';
  ambiguous.routes[0].entityViewModeSha256 = '';
  assert.throws(
    () => parseCustomEntityOutputAudit(ambiguous, parserOptions(expected)),
    /host-reconstructable core-only output evidence/i
  );
});

test('ignores candidate route bindings whose inventoried extension is not active', () => {
  const expected = derived();
  const runtime = validRuntime(expected, {
    activeCandidateExtensionSha256: [],
    handlerKind: 'core_controller',
    runtimeRouteName: 'output_probe.entity_output',
    routeApplies: [false]
  });
  const parsed = parseCustomEntityOutputAudit(runtime, parserOptions(expected));
  assert.equal(parsed.status, 'not_applicable');
  assert.equal(parsed.applicableRouteCount, 0);
  assert.equal(parsed.routes[0].applies, false);

  const forged = validRuntime(expected, {
    activeCandidateExtensionSha256: [],
    runtimeRouteName: 'output_probe.entity_output',
    routeApplies: [true]
  });
  assert.throws(
    () => parseCustomEntityOutputAudit(forged, parserOptions(expected)),
    /applicability is not bound to active exact candidate provenance/i
  );

  const launderedActiveRoute = validRuntime(expected, {
    handlerKind: 'core_controller',
    runtimeRouteName: 'output_probe.entity_output',
    routeApplies: [false]
  });
  assert.throws(
    () => parseCustomEntityOutputAudit(launderedActiveRoute, parserOptions(expected)),
    /applicability is not bound to active exact candidate provenance/i
  );
});

test('audits only exact custom-provenance routes in mixed custom and core route sets', () => {
  const matrix = fieldOutputMatrix();
  matrix.bundles[0].fields[0].publicRenderLocations = ['/', '/core'];
  const routes = {
    routes: [
      { targetPath: '/', accepted: true },
      { targetPath: '/core', accepted: true }
    ]
  };
  const expected = derived({ fieldOutputMatrix: matrix, routeMatrix: routes });
  const runtimeOptions = {
    runtimeRouteNames: ['output_probe.entity_output', 'entity.node.canonical'],
    handlerKinds: ['candidate_controller', 'entity_view'],
    routeApplies: [true, false]
  };
  const passing = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routes,
    runner: () => ({ ok: true, output: JSON.stringify(validRuntime(expected, runtimeOptions)) })
  });
  assert.equal(passing.status, 'pass');
  assert.equal(passing.runtime.routeCount, 2);
  assert.equal(passing.runtime.applicableRouteCount, 1);
  assert.equal(passing.runtime.matchedNodeRouteCount, 1);
  assert.equal(passing.runtime.renderedRouteCount, 1);
  assert.deepEqual(passing.runtime.routes.map(({ applies }) => applies), [true, false]);
  assert.equal(passing.runtime.coveredDeclarationCount, 1);

  const violation = {
    code: 'route_output_not_render_array',
    routeSha256: sha256('/'),
    subjectSha256: H('4')
  };
  const failing = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routes,
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, {
        ...runtimeOptions,
        routeRendered: [false, false],
        status: 'fail',
        violations: [violation]
      }))
    })
  });
  assert.equal(failing.completed, true);
  assert.equal(failing.status, 'fail');
  assert.equal(failing.runtime.matchedNodeRouteCount, 1);
  assert.equal(failing.runtime.renderedRouteCount, 0);
  assert.deepEqual(failing.runtime.routes.map(({ applies }) => applies), [true, false]);
  assert.deepEqual(failing.runtime.violations, [violation]);
});

test('selects composite bundle-view-mode Twig before bundle and base fallbacks', () => {
  const sourceInventory = inventoryWithDefaultThemeTemplate({ includeBase: true, includeComposite: true });
  const expected = derived({ sourceInventory });
  assert.ok(expected.candidateRenderBindings.some(({ selectorKind, selectorValue }) =>
    selectorKind === 'node_bundle_view_mode_template' && selectorValue === 'landing_page\u0000full'
  ));
  const composite = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view' }))
    })
  });
  assert.equal(composite.status, 'pass');
  assert.deepEqual(composite.runtime.routes[0].candidateCoverage, [{
    role: 'render_template',
    extensionSha256: sha256('EXTENSION-theme1234567890'),
    sourceFileSha256: sha256('SOURCE-themecomposite12'),
    surfaceSha256: sha256('SURFACE-themecomposite12')
  }]);

  const fallback = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory,
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected, { handlerKind: 'entity_view', entityViewMode: 'teaser' }))
    })
  });
  assert.equal(fallback.status, 'pass');
  assert.deepEqual(fallback.runtime.routes[0].candidateCoverage, [{
    role: 'render_template',
    extensionSha256: sha256('EXTENSION-theme1234567890'),
    sourceFileSha256: sha256('SOURCE-theme1234567890'),
    surfaceSha256: sha256('SURFACE-theme1234567890')
  }]);
});

test('rejects passing evidence that omits one declaration-specific Node-Media-File chain', () => {
  const matrix = fieldOutputMatrix();
  matrix.bundles[0].fields.push({
    machineName: 'field_secondary_media',
    fieldType: 'entity_reference:media',
    targetEntityType: 'media',
    publicRenderLocations: ['/'],
    affectsAnonymousOutput: true
  });
  const expected = derived({ fieldOutputMatrix: matrix });
  assert.equal(expected.declarations.length, 2);
  const runtime = validRuntime(expected);
  const covered = [expected.routes[0].declarationIds[0]];
  runtime.routes[0].coveredDeclarationCount = covered.length;
  runtime.routes[0].coveredDeclarationSetSha256 = sha256(covered);
  runtime.coveredDeclarationCount = covered.length;
  runtime.coveredDeclarationSetSha256 = sha256(covered);
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routeMatrix(),
    runner: () => ({ ok: true, output: JSON.stringify(runtime) })
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.failures[0].code, 'runtime_schema_invalid');
});

test('rejects controller evidence that is not bound to the exact inventoried class source and surface', () => {
  const expected = derived();
  const runtime = validRuntime(expected);
  runtime.routes[0].candidateOutputSourceFileSha256 = sha256('SOURCE-0123456789abcdef');
  runtime.routes[0].candidateOutputSurfaceSha256 = sha256('SURFACE-0123456789abcdef');
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({ ok: true, output: JSON.stringify(runtime) })
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.failures[0].code, 'runtime_schema_invalid');
});

test('binds exact unique route hashes and rejects replayed passing route evidence', () => {
  const matrix = fieldOutputMatrix();
  matrix.bundles[0].fields[0].publicRenderLocations = ['/', '/detail'];
  const routes = { routes: [
    { targetPath: '/', accepted: true },
    { targetPath: '/detail', accepted: true }
  ] };
  const expected = deriveCustomEntityOutputAuditInput({
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routes,
    targetOrigin: FIXTURE_ORIGIN
  });
  const expectedHashes = expected.routes.map(({ path }) => sha256(path));
  const passing = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routes,
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected.inputFingerprint, { routeHashes: expectedHashes }))
    })
  });
  assert.equal(passing.status, 'pass');

  const replayed = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: routes,
    runner: () => ({
      ok: true,
      output: JSON.stringify(validRuntime(expected.inputFingerprint, {
        routeHashes: [expectedHashes[0], expectedHashes[0]]
      }))
    })
  });
  assert.equal(replayed.status, 'blocked');
  assert.equal(replayed.failures[0].code, 'runtime_schema_invalid');
});

test('strict parser rejects invalid JSON, schema drift, count drift, raw fields, and mode drift', () => {
  const input = derived();
  const fingerprint = input.inputFingerprint;
  assert.throws(() => parseCustomEntityOutputAudit('{'), /invalid JSON/i);

  const cases = [
    [value => { value.schemaVersion = 'unknown'; }, /completed bounded schema/i],
    [value => { value.rawEntityId = 42; }, /unexpected schema/i],
    [value => { value.readOnly = true; }, /unexpected schema/i],
    [value => { value.routeCount = 2; }, /route count is inconsistent/i],
    [value => { value.dependencyCount = 4; }, /aggregate dependency count/i],
    [value => { value.routes[0].dependencies[0].entityId = 42; }, /unexpected schema/i],
    [value => { value.invalidation.attempted = true; }, /reported explicit verifier mutation/i],
    [value => { value.inputFingerprint = H('f'); }, /not bound to the requested input/i]
  ];
  for (const [mutate, expected] of cases) {
    const value = validRuntime(fingerprint);
    mutate(value);
    assert.throws(
      () => parseCustomEntityOutputAudit(value, parserOptions(input)),
      expected
    );
  }
});

test('strict parser enforces array, metadata, and byte budgets', () => {
  const fingerprint = derived().inputFingerprint;
  const tooMany = validRuntime(fingerprint);
  tooMany.routes[0].dependencies = Array.from(
    { length: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesPerRoute + 1 },
    (_, index) => dependency('file', String(index % 10))
  );
  tooMany.routes[0].dependencyCount = tooMany.routes[0].dependencies.length;
  tooMany.dependencyCount = tooMany.routes[0].dependencies.length;
  assert.throws(() => parseCustomEntityOutputAudit(tooMany), /outside its bounded range/i);

  const tooManyRenderedTags = validRuntime(fingerprint);
  tooManyRenderedTags.routes[0].renderedTagCount = CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsPerSet + 1;
  assert.throws(() => parseCustomEntityOutputAudit(tooManyRenderedTags), /outside its bounded range/i);

  const tooManyDependencyTags = validRuntime(fingerprint);
  tooManyDependencyTags.routes[0].dependencies[0].cacheTagCount = CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsPerSet + 1;
  assert.throws(() => parseCustomEntityOutputAudit(tooManyDependencyTags), /outside its bounded range/i);
  assert.throws(
    () => parseCustomEntityOutputAudit(' '.repeat(CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.outputBytes + 1)),
    /byte limit/i
  );
});

test('runtime failures, timeouts, and excessive output remain redacted and fail closed', async () => {
  const runners = [
    [{ ok: false, exitStatus: 7, failureSha256: H('c') }, 'runtime_execution_failed'],
    [{ ok: false, timedOut: true, failureSha256: H('d') }, 'runtime_timeout'],
    [{ ok: true, output: 'x'.repeat(CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.outputBytes + 1) }, 'runtime_output_budget_exceeded']
  ];
  for (const [execution, code] of runners) {
    const result = await inspectCustomEntityOutputAudit({
      projectRoot: '/fixture',
      sourceInventory: inventory(),
      fieldOutputMatrix: fieldOutputMatrix(),
      routeMatrix: routeMatrix(),
      runner: () => execution
    });
    assert.equal(result.status, 'blocked');
    assert.equal(result.completed, false);
    assert.equal(result.failures[0].code, code);
    assert.match(result.failures[0].detailSha256, /^sha256:/);
    assert.doesNotMatch(JSON.stringify(result), /stderr|entityId|field_hero_media/);
  }
});

test('preserves typed cache and access violations as completed failing runtime evidence', () => {
  const expected = derived();
  const violation = {
    code: 'render_missing_access_cache_metadata',
    routeSha256: sha256('/'),
    subjectSha256: H('4')
  };
  const runtime = validRuntime(expected, { status: 'fail', violations: [violation] });
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    runner: () => ({ ok: true, output: JSON.stringify(runtime) })
  });
  assert.equal(result.completed, true);
  assert.equal(result.status, 'fail');
  assert.deepEqual(result.runtime.violations, [violation]);
  assert.deepEqual(result.failures, []);
});

test('metadata budget violations fail closed without owned-cache invalidation', () => {
  const expected = derived();
  const violation = {
    code: 'cache_metadata_byte_limit_exceeded',
    routeSha256: sha256('/'),
    subjectSha256: H('4')
  };
  const runtime = validRuntime(expected, { allow: true, status: 'fail', violations: [violation] });
  runtime.invalidation = {
    status: 'not_run_due_to_violations', attempted: false, seededCount: 0, invalidatedCount: 0,
    cleanupRequired: false, cleanupCompleted: true, evidenceSha256: ''
  };
  const result = inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    allowOwnedCacheInvalidation: true,
    isolation: {
      executionBoundary: 'verifier-owned-disposable-ddev',
      workspaceId: 'DISPOSABLE-metadata-budget',
      exactHead: true,
      freshDatabase: true
    },
    runner: () => ({ ok: true, output: JSON.stringify(runtime) })
  });
  assert.equal(result.completed, true);
  assert.equal(result.status, 'fail');
  assert.deepEqual(result.runtime.violations, [violation]);
  assert.deepEqual(result.runtime.invalidation, runtime.invalidation);
});

test('aggregate PHP input budget blocks before the fake runner executes', async () => {
  let calls = 0;
  const routes = Array.from({ length: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes }, (_, index) => ({
    targetPath: `/${String(index).padStart(2, '0')}-${'x'.repeat(1_000)}`,
    accepted: true
  }));
  const matrix = fieldOutputMatrix();
  matrix.bundles[0].fields[0].publicRenderLocations = routes.map(({ targetPath }) => targetPath);
  const result = await inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: matrix,
    routeMatrix: { routes },
    runner: () => { calls += 1; }
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.failures[0].code, 'runtime_input_budget_exceeded');
  assert.equal(calls, 0);
});

test('PHP program performs anonymous route-bound render and exact Node-Media-File cache checks', () => {
  const source = CUSTOM_ENTITY_OUTPUT_AUDIT_PHP;
  for (const pattern of [
    /AnonymousUserSession/,
    /account_switcher/,
    /request_stack/,
    /access_manager/,
    /checkRequest\(\$request, \$anonymous, TRUE\)/,
    /router\.no_access_checks/,
    /matchRequest\(\$request\)/,
    /controller_resolver/,
    /http_kernel\.controller\.argument_resolver/,
    /route_controller_not_owned_by_candidate_extension/,
    /controllerSourceFileId/,
    /controllerSurfaceId/,
    /\$normalized_class === \$expected_class && \$method === \$expected_method && \$normalized_file === \$expected_file/,
    /getDefault\('_entity_view'\)/,
    /system\.theme/,
    /\$extension_machine === \$default_theme_machine/,
    /\$record\['applies'\] = TRUE/,
    /applicable_route_runtime_incomplete/,
    /node_bundle_view_mode_template/,
    /not_run_due_to_not_applicable/,
    /\$record\['outputHandlerKind'\] = 'entity_view'/,
    /getViewBuilder\('node'\)->view\(\$node, \$entity_view_mode\)/,
    /ReflectionMethod/,
    /call_user_func_array\(\$controller, \$arguments\)/,
    /route_output_not_render_array/,
    /NodeInterface/,
    /target_type.*media/s,
    /MediaInterface/,
    /getSource\(\)->getConfiguration\(\)/,
    /source_field/,
    /FileInterface/,
    /\$declaration_chain_counts/,
    /declared_node_media_field_has_no_complete_file_chain/,
    /route_did_not_cover_every_bound_declaration/,
    /ambiguous_declaration_dependency_provenance/,
    /candidate_route_coverage_limit_exceeded/,
    /candidate_coverage_total_limit_exceeded/,
    /candidateCoverage/,
    /RenderContext/,
    /executeInRenderContext/,
    /getCacheTagsToInvalidate/,
    /\$bounded_metadata/,
    /cache_metadata_item_limit_exceeded/,
    /cache_metadata_byte_limit_exceeded/,
    /cache_metadata_total_item_limit_exceeded/,
    /cache_metadata_total_byte_limit_exceeded/,
    /render_missing_entity_cache_tags/,
    /render_missing_invalidation_cache_tags/,
    /render_missing_access_cache_metadata/,
    /\$rendered_max_age === \\Drupal\\Core\\Cache\\Cache::PERMANENT/
  ]) assert.match(source, pattern);
  assert.ok(
    source.indexOf('$access_manager->checkRequest($request, $anonymous, TRUE)') < source.indexOf('call_user_func_array($controller, $arguments)'),
    'anonymous route access must be allowed before the controller is invoked'
  );
  assert.ok(
    source.indexOf('count($media_items)') < source.indexOf('$media = $media_item->entity'),
    'raw media reference counts must be bounded before referenced entities load'
  );
  assert.ok(
    source.indexOf('count($file_items)') < source.indexOf('$file = $file_item->entity'),
    'raw file reference counts must be bounded before referenced entities load'
  );
  assert.ok(
    source.indexOf('$item_count = count($values)') < source.indexOf('$normalized = array_values(array_unique($values, SORT_STRING))'),
    'raw metadata item counts must be bounded before deduplication'
  );
  assert.ok(
    source.indexOf('$byte_count += strlen($value)') < source.indexOf('$normalized = array_values(array_unique($values, SORT_STRING))'),
    'raw metadata bytes must be bounded before deduplication'
  );
  assert.ok(
    source.indexOf("$rendered_tags = $bounded_metadata($bubble->getCacheTags()") < source.indexOf('array_intersect($invalidation_tags, $rendered_tags)'),
    'rendered metadata must be bounded before set intersections'
  );
  assert.doesNotMatch(source, /referencedEntities\s*\(/);
  assert.doesNotMatch(source, /\$namespace_owned/);
  assert.doesNotMatch(source, /->save\s*\(/);
  assert.doesNotMatch(source, /entityTypeManager\(\)->getStorage\([^)]*\)->delete/);
});

test('default PHP path performs no explicit verifier mutation and isolated path only mutates verifier-owned cache CIDs', () => {
  const input = derived();
  const defaultProbe = buildCustomEntityOutputAuditPhp(input);
  const isolated = buildCustomEntityOutputAuditPhp(input, { allowOwnedCacheInvalidation: true, ownedCacheToken: 'owned-token' });
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /if \(\$allow_invalidation\)/);
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /custom-entity-output-audit:/);
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /\$cache->set\(/);
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /cache_tags\.invalidator/);
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /invalidateTags\(\$tags\)/);
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /finally/);
  assert.match(CUSTOM_ENTITY_OUTPUT_AUDIT_PHP, /\$cache->delete\(\$cid\)/);
  assert.doesNotMatch(defaultProbe, /owned-token/);
  assert.doesNotMatch(isolated, /owned-token/);
});

test('isolated fake-runner proof passes without emitting the random owner token', async () => {
  const expected = derived();
  let ownerToken = '';
  const result = await inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    allowOwnedCacheInvalidation: true,
    isolation: {
      executionBoundary: 'verifier-owned-disposable-ddev',
      workspaceId: 'DISPOSABLE-test',
      exactHead: true,
      freshDatabase: true
    },
    runner: ({ php }) => {
      const encoded = php.match(/base64_decode\('([^']+)'/)?.[1] ?? '';
      const payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
      ownerToken = payload.ownedCacheToken;
      assert.equal(payload.allowOwnedCacheInvalidation, true);
      return { ok: true, output: JSON.stringify(validRuntime(expected.inputFingerprint, { allow: true })) };
    }
  });
  assert.match(ownerToken, /^[a-f0-9]{64}$/);
  assert.equal(result.status, 'pass');
  assert.equal(result.runtime.invalidation.cleanupCompleted, true);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(ownerToken));
});

test('isolated cleanup gaps are accepted as fail evidence, never as a passing proof', async () => {
  const expected = derived();
  const runtime = validRuntime(expected.inputFingerprint, { allow: true });
  runtime.status = 'fail';
  runtime.invalidation.status = 'fail';
  runtime.invalidation.cleanupCompleted = false;
  runtime.violations = [{ code: 'owned_cache_cleanup_incomplete', routeSha256: '', subjectSha256: '' }];
  const result = await inspectCustomEntityOutputAudit({
    projectRoot: '/fixture',
    sourceInventory: inventory(),
    fieldOutputMatrix: fieldOutputMatrix(),
    routeMatrix: routeMatrix(),
    allowOwnedCacheInvalidation: true,
    isolation: {
      executionBoundary: 'verifier-owned-disposable-ddev',
      workspaceId: 'DISPOSABLE-test',
      exactHead: true,
      freshDatabase: true
    },
    runner: () => ({ ok: true, output: JSON.stringify(runtime) })
  });
  assert.equal(result.completed, true);
  assert.equal(result.status, 'fail');
  assert.equal(result.runtime.invalidation.cleanupCompleted, false);
});

test('input PHP and output evidence are deterministically bound without raw route or field data', () => {
  const input = derived();
  const php = buildCustomEntityOutputAuditPhp(input);
  const encoded = php.match(/base64_decode\('([^']+)'/)?.[1] ?? '';
  const payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  assert.equal(payload.inputFingerprint, input.inputFingerprint);
  assert.deepEqual(payload.limits, {
    routes: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes,
    candidateCoveragePerRoute: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces,
    candidateCoverageTotal: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateCoverageTotal,
    dependenciesPerRoute: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesPerRoute,
    dependenciesTotal: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesTotal,
    metadataItemsPerSet: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsPerSet,
    metadataBytesPerSet: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataBytesPerSet,
    metadataItemsTotal: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsTotal,
    metadataBytesTotal: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataBytesTotal,
    violations: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.violations
  });
  const runtime = parseCustomEntityOutputAudit(validRuntime(input), parserOptions(input));
  assert.equal(runtime.resultFingerprint, sha256({ ...runtime, resultFingerprint: undefined }));
  assert.doesNotMatch(JSON.stringify(runtime), /field_hero_media|landing_page|"routeName"|"entityId"|"uuid"/);
});
