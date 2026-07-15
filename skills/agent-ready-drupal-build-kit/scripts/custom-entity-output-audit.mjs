import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { sha256 } from './state-fingerprint.mjs';

export const CUSTOM_ENTITY_OUTPUT_AUDIT_SCHEMA = 'public-kit.custom-entity-output-audit.1';
export const CUSTOM_ENTITY_OUTPUT_INPUT_SCHEMA = 'public-kit.custom-entity-output-input.1';

export const CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS = Object.freeze({
  routes: 64,
  declarations: 512,
  candidateSourceFiles: 512,
  candidateSurfaces: 2_048,
  candidateCoverageTotal: 4_096,
  extensions: 256,
  dependenciesPerRoute: 64,
  dependenciesTotal: 512,
  metadataItemsPerSet: 4_096,
  metadataBytesPerSet: 256 * 1024,
  metadataItemsTotal: 16_384,
  metadataBytesTotal: 1024 * 1024,
  violations: 200,
  phpInputBytes: 48 * 1024,
  outputBytes: 1024 * 1024,
  timeoutMs: 60_000
});

const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const ID_RE = /^(?:SOURCE|SURFACE|EXTENSION)-[A-Za-z0-9_-]{4,128}$/;
const MACHINE_RE = /^[a-z][a-z0-9_]{0,127}$/;
const FIELD_RE = /^[a-z][a-z0-9_]{0,127}$/;
const ROUTE_NAME_RE = /^[A-Za-z0-9_.-]{1,255}$/;
const OUTPUT_FILE_KINDS = new Set(['twig_template', 'sdc_component']);
const OUTPUT_SURFACE_KINDS = new Set([
  'controller_class',
  'plugin_class',
  'route',
  'twig_template',
  'sdc_component'
]);
const OUTPUT_HOOK_RE = /(?:^|_)(?:entity_view|node_view|media_view|file_view|view_mode|view_display|prepare_view|display_build|build_defaults|preprocess|process|theme_suggestions|views_pre_render|views_post_render|page_attachments|block_view|field_formatter|template_preprocess)(?:_|$)/i;
const NODE_RENDER_HOOK_NAMES = new Set([
  'node_view_mode_alter',
  'entity_view_mode_alter',
  'node_build_defaults_alter',
  'entity_build_defaults_alter',
  'entity_view_display_alter',
  'entity_prepare_view',
  'entity_display_build_alter',
  'node_view',
  'entity_view',
  'node_view_alter',
  'entity_view_alter'
]);

function comparePortable(left, right) {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(comparePortable);
}

const CANDIDATE_COVERAGE_ROLES = new Set([
  'custom_route',
  'custom_controller',
  'field_formatter',
  'render_hook',
  'render_template'
]);

const RENDER_HOOK_SELECTOR_KINDS = new Set([
  'preprocess_node',
  'template_preprocess_hook',
  'node_render_hook',
  'theme_suggestion_hook'
]);

function candidateCoverageKey(row) {
  return `${String(row?.role ?? '')}\u0000${String(row?.extensionSha256 ?? '')}\u0000${String(row?.sourceFileSha256 ?? '')}\u0000${String(row?.surfaceSha256 ?? '')}`;
}

function uniqueSortedCandidateCoverage(rows) {
  return [...new Map(rows.map((row) => [candidateCoverageKey(row), row])).values()]
    .sort((left, right) => comparePortable(candidateCoverageKey(left), candidateCoverageKey(right)));
}

function expectedRouteCandidateCoverage({
  route,
  candidateRouteByNameSha256,
  candidateRenderBindings,
  activeExtensionSha256
}) {
  const activeExtensions = new Set(activeExtensionSha256);
  const activeThemeExtensions = new Set(route.activeThemeExtensionSha256);
  const selectedThemeTemplates = new Set(route.selectedThemeTemplateSha256);
  const selectedRenderHooks = new Set(route.selectedRenderHookSha256);
  const coverage = [];
  const candidateRouteBinding = candidateRouteByNameSha256.get(String(route?.routeNameSha256 ?? ''));
  const routeBinding = candidateRouteBinding && activeExtensions.has(candidateRouteBinding.extensionSha256)
    ? candidateRouteBinding
    : null;
  if (routeBinding) {
    coverage.push({
      role: 'custom_route',
      extensionSha256: routeBinding.extensionSha256,
      sourceFileSha256: routeBinding.routeSourceFileSha256,
      surfaceSha256: routeBinding.routeSurfaceSha256
    });
  }
  if (route.outputHandlerKind === 'candidate_controller') {
    if (routeBinding) {
      if (routeBinding.controllerSourceFileSha256 && routeBinding.controllerSurfaceSha256) {
        coverage.push({
          role: 'custom_controller',
          extensionSha256: routeBinding.extensionSha256,
          sourceFileSha256: routeBinding.controllerSourceFileSha256,
          surfaceSha256: routeBinding.controllerSurfaceSha256
        });
      }
    }
  }
  if (!['candidate_controller', 'entity_view'].includes(route.outputHandlerKind)) {
    return uniqueSortedCandidateCoverage(coverage);
  }
  for (const binding of candidateRenderBindings) {
    const hookActive = binding.extensionType === 'module'
      ? activeExtensions.has(binding.extensionSha256)
      : binding.extensionType === 'theme' && activeThemeExtensions.has(binding.extensionSha256);
    if (RENDER_HOOK_SELECTOR_KINDS.has(binding.selectorKind)) {
      if (!hookActive || !selectedRenderHooks.has(binding.runtimeIdentitySha256)) continue;
      coverage.push({
        role: 'render_hook',
        extensionSha256: binding.extensionSha256,
        sourceFileSha256: binding.outputSourceFileSha256,
        surfaceSha256: binding.outputSurfaceSha256
      });
      continue;
    }
    if (binding.selectorKind === 'field_formatter_plugin' &&
      activeExtensions.has(binding.extensionSha256) &&
      route.selectedFieldFormatterSha256.includes(binding.runtimeIdentitySha256)) {
      coverage.push({
        role: 'field_formatter',
        extensionSha256: binding.extensionSha256,
        sourceFileSha256: binding.outputSourceFileSha256,
        surfaceSha256: binding.outputSurfaceSha256
      });
      continue;
    }
    if (binding.selectorKind === 'theme_template' &&
      (binding.extensionType === 'module'
        ? activeExtensions.has(binding.extensionSha256)
        : activeThemeExtensions.has(binding.extensionSha256)) &&
      selectedThemeTemplates.has(binding.sourceDrupalPathSha256)) {
      coverage.push({
        role: 'render_template',
        extensionSha256: binding.extensionSha256,
        sourceFileSha256: binding.outputSourceFileSha256,
        surfaceSha256: binding.outputSurfaceSha256
      });
    }
  }
  return uniqueSortedCandidateCoverage(coverage);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const expected = [...keys].sort(comparePortable);
  const actual = Object.keys(value).sort(comparePortable);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has an unexpected schema.`);
  }
}

function assertBoolean(value, label) {
  if (typeof value !== 'boolean') throw new Error(`${label} must be boolean.`);
}

function assertCount(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} is outside its bounded range.`);
  }
}

function assertHash(value, label, allowEmpty = false) {
  if (allowEmpty && value === '') return;
  if (!HASH_RE.test(String(value ?? ''))) throw new Error(`${label} must be a SHA-256 fingerprint.`);
}

function safeRoutePath(value) {
  const text = String(value ?? '').trim();
  if (
    !text.startsWith('/') ||
    text.startsWith('//') ||
    text.includes('#') ||
    /[\u0000-\u001f\u007f]/.test(text) ||
    /(?:^|\/)\.\.(?:\/|$)/.test(text) ||
    text.length > 2_048
  ) {
    return '';
  }
  try {
    const parsed = new URL(text, 'http://verifier.invalid');
    if (parsed.origin !== 'http://verifier.invalid') return '';
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return '';
  }
}

function safeTargetOrigin(value) {
  try {
    const parsed = new URL(String(value ?? '').trim());
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
    return parsed.origin;
  } catch {
    return '';
  }
}

function targetOrigin(projectRoot, environment) {
  const environmentOrigin = safeTargetOrigin(environment?.DDEV_PRIMARY_URL);
  if (environmentOrigin) return environmentOrigin;
  const result = spawnSync('ddev', ['describe', '-j'], {
    cwd: projectRoot,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    shell: false,
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 15_000
  });
  if (result.error || result.status !== 0) return '';
  try {
    const description = JSON.parse(String(result.stdout ?? ''));
    return safeTargetOrigin(description?.raw?.primary_url);
  } catch {
    return '';
  }
}

function outputCapableSurface(surface) {
  if (!surface || typeof surface !== 'object') return false;
  if (OUTPUT_SURFACE_KINDS.has(String(surface.kind ?? ''))) return true;
  return surface.kind === 'hook_or_callback' && (
    OUTPUT_HOOK_RE.test(String(surface.name ?? '')) || OUTPUT_HOOK_RE.test(String(surface.hookName ?? ''))
  );
}

function collectExplicitStaticCandidates(value, sourceFileIds, surfaceIds, candidateContext = false, depth = 0) {
  if (!value || depth > 12) return;
  if (typeof value === 'string') {
    if (candidateContext && value.startsWith('SOURCE-')) sourceFileIds.add(value);
    if (candidateContext && value.startsWith('SURFACE-')) surfaceIds.add(value);
    return;
  }
  if (Array.isArray(value)) {
    if (candidateContext) {
      for (const item of value) {
        if (typeof item === 'string') {
          if (item.startsWith('SOURCE-')) sourceFileIds.add(item);
          if (item.startsWith('SURFACE-')) surfaceIds.add(item);
        }
      }
    }
    for (const item of value) collectExplicitStaticCandidates(item, sourceFileIds, surfaceIds, candidateContext, depth + 1);
    return;
  }
  if (typeof value !== 'object') return;
  const explicitlyCandidate = value.outputCandidate === true || value.outputCapable === true || value.entityOutputCandidate === true;
  if (explicitlyCandidate) {
    for (const key of ['id', 'sourceFileId', 'fileId']) {
      if (typeof value[key] === 'string' && value[key].startsWith('SOURCE-')) sourceFileIds.add(value[key]);
    }
    for (const key of ['id', 'surfaceId']) {
      if (typeof value[key] === 'string' && value[key].startsWith('SURFACE-')) surfaceIds.add(value[key]);
    }
  }
  for (const [key, child] of Object.entries(value)) {
    const childCandidateContext = candidateContext || /candidate/i.test(key);
    collectExplicitStaticCandidates(child, sourceFileIds, surfaceIds, childCandidateContext, depth + 1);
  }
}

function declaredReferenceTarget(field) {
  const type = String(field?.fieldType ?? '').toLowerCase();
  const target = String(
    field?.targetEntityType ??
    field?.referenceTargetEntityType ??
    field?.targetType ??
    field?.settings?.target_type ??
    ''
  ).toLowerCase();
  if (target === 'media' || /(?:^|:)media$/.test(type)) return 'media';
  return '';
}

function publicFieldDeclaration(field) {
  return field?.affectsAnonymousOutput === true || (
    Array.isArray(field?.publicRenderLocations) && field.publicRenderLocations.length > 0
  );
}

function acceptedRoutePaths(routeMatrix) {
  const routes = [];
  for (const collection of ['primaryRoutes', 'routes', 'targetRequiredRoutes']) {
    for (const row of Array.isArray(routeMatrix?.[collection]) ? routeMatrix[collection] : []) {
      if (row?.accepted === false || row?.shouldBePublic === false) continue;
      const path = safeRoutePath(row?.targetPath || row?.targetFinalPath || row?.path);
      if (path) routes.push(path);
    }
  }
  return uniqueSorted(routes);
}

function routeInputs(routeMatrix, declarations) {
  const accepted = new Set(acceptedRoutePaths(routeMatrix));
  const bindings = new Map();
  for (const declaration of declarations) {
    if (!Array.isArray(declaration.publicRoutePaths) || declaration.publicRoutePaths.length === 0) return [];
    for (const path of declaration.publicRoutePaths) {
      if (!accepted.has(path)) return [];
      if (!bindings.has(path)) bindings.set(path, { path, declarationIds: [], bundles: [] });
      bindings.get(path).declarationIds.push(declaration.id);
      bindings.get(path).bundles.push(declaration.bundle);
    }
  }
  return [...bindings.values()]
    .map((route) => ({
      path: route.path,
      declarationIds: uniqueSorted(route.declarationIds),
      bundles: uniqueSorted(route.bundles)
    }))
    .sort((left, right) => comparePortable(left.path, right.path));
}

/**
 * Derive bounded runtime inputs from verifier-owned inventory and typed public
 * output declarations. Authored capability/load-bearing flags are intentionally
 * not read here.
 */
export function deriveCustomEntityOutputAuditInput({
  sourceInventory,
  staticAudit = null,
  fieldOutputMatrix,
  routeMatrix,
  targetOrigin: requestedTargetOrigin = ''
} = {}) {
  const errors = [];
  const normalizedTargetOrigin = safeTargetOrigin(requestedTargetOrigin);
  if (requestedTargetOrigin && !normalizedTargetOrigin) errors.push('Custom entity-output audit requires an exact HTTP(S) target origin.');
  if (!sourceInventory || !['public-kit.custom-code-inventory.2', 'public-kit.custom-code-inventory.3'].includes(sourceInventory.schemaVersion)) {
    errors.push('Custom entity-output audit requires a supported custom-code inventory schema.');
  }
  if (sourceInventory?.completed !== true || !Array.isArray(sourceInventory?.extensions) || !Array.isArray(sourceInventory?.sourceFiles)) {
    errors.push('Custom entity-output audit requires a completed bounded custom-code inventory.');
  }

  const inventoryFiles = new Map();
  const inventorySurfaces = new Map();
  for (const file of Array.isArray(sourceInventory?.sourceFiles) ? sourceInventory.sourceFiles : []) {
    if (typeof file?.id === 'string') inventoryFiles.set(file.id, file);
    for (const surface of Array.isArray(file?.surfaces) ? file.surfaces : []) {
      if (typeof surface?.id === 'string') inventorySurfaces.set(surface.id, { ...surface, sourceFileId: file.id });
    }
  }

  const sourceFileIds = new Set();
  const surfaceIds = new Set();
  for (const file of inventoryFiles.values()) {
    const capableSurfaces = (Array.isArray(file.surfaces) ? file.surfaces : []).filter(outputCapableSurface);
    if (OUTPUT_FILE_KINDS.has(String(file.kind ?? '')) || capableSurfaces.length > 0) {
      sourceFileIds.add(file.id);
      for (const surface of capableSurfaces) surfaceIds.add(surface.id);
    }
  }
  collectExplicitStaticCandidates(staticAudit, sourceFileIds, surfaceIds, Array.isArray(staticAudit));

  for (const id of [...sourceFileIds]) {
    if (!inventoryFiles.has(id)) {
      errors.push(`Static entity-output candidate ${id} is absent from the source inventory.`);
      sourceFileIds.delete(id);
    }
  }
  for (const id of [...surfaceIds]) {
    const surface = inventorySurfaces.get(id);
    if (!surface) {
      errors.push(`Static entity-output surface ${id} is absent from the source inventory.`);
      surfaceIds.delete(id);
      continue;
    }
    sourceFileIds.add(surface.sourceFileId);
  }

  const candidateExtensions = new Set([...sourceFileIds].map((id) => inventoryFiles.get(id)?.extension).filter(Boolean));
  const extensions = (Array.isArray(sourceInventory?.extensions) ? sourceInventory.extensions : [])
    .filter((extension) => candidateExtensions.has(extension?.machineName))
    .map((extension) => ({
      id: String(extension.id ?? ''),
      machineName: String(extension.machineName ?? ''),
      type: String(extension.type ?? ''),
      drupalPath: String(extension.drupalPath ?? '')
    }))
    .sort((left, right) => comparePortable(left.id, right.id));

  for (const extension of extensions) {
    const expectedDrupalPath = `${extension.type}s/custom/${extension.machineName}`;
    if (
      !ID_RE.test(extension.id) ||
      !MACHINE_RE.test(extension.machineName) ||
      !['module', 'theme'].includes(extension.type) ||
      extension.drupalPath !== expectedDrupalPath
    ) {
      errors.push('A candidate custom extension has an invalid verifier-owned identity.');
    }
  }
  if ([...sourceFileIds].some((id) => !ID_RE.test(id)) || [...surfaceIds].some((id) => !ID_RE.test(id))) {
    errors.push('An entity-output candidate has an invalid verifier-owned source identity.');
  }
  if (extensions.length !== candidateExtensions.size) {
    errors.push('At least one entity-output candidate is not owned by an inventoried custom extension.');
  }

  const extensionByMachineName = new Map(extensions.map((extension) => [extension.machineName, extension]));
  const sourceByExtensionAndPath = new Map([...inventoryFiles.values()].map((file) => [
    `${String(file?.extension ?? '')}\u0000${String(file?.path ?? '')}`,
    file
  ]));
  const candidateRouteBindings = [];
  const candidateRouteNames = new Set();
  for (const route of Array.isArray(sourceInventory?.routes) ? sourceInventory.routes : []) {
    const routeName = String(route?.name ?? '');
    const extensionMachineName = String(route?.extension ?? '');
    const source = sourceByExtensionAndPath.get(`${extensionMachineName}\u0000${String(route?.file ?? '')}`);
    const surface = (Array.isArray(source?.surfaces) ? source.surfaces : []).find((candidate) =>
      candidate?.kind === 'route' && String(candidate?.name ?? '') === routeName
    );
    const extension = extensionByMachineName.get(extensionMachineName);
    if (!source || !surface || !extension || !sourceFileIds.has(source.id) || !surfaceIds.has(surface.id)) continue;
    if (!ROUTE_NAME_RE.test(routeName) || !ID_RE.test(String(source.id ?? '')) || !ID_RE.test(String(surface.id ?? ''))) {
      errors.push('A candidate entity-output route has an invalid verifier-owned identity.');
      continue;
    }
    if (candidateRouteNames.has(routeName)) {
      errors.push('A candidate entity-output route name is not uniquely owned.');
      continue;
    }
    candidateRouteNames.add(routeName);
    const controllerDefinition = String(route?.controller ?? '');
    let controllerClass = '';
    let controllerMethod = '';
    let controllerDrupalPath = '';
    let controllerSourceFileId = '';
    let controllerSurfaceId = '';
    const controllerMatch = controllerDefinition.match(/^\\?(Drupal\\([a-z][a-z0-9_]*)\\([A-Za-z_][A-Za-z0-9_\\]*))::([A-Za-z_][A-Za-z0-9_]*)$/);
    if (controllerMatch && controllerMatch[2] === extensionMachineName) {
      controllerClass = controllerMatch[1];
      controllerMethod = controllerMatch[4];
      controllerDrupalPath = `${extension.drupalPath}/src/${controllerMatch[3].replaceAll('\\', '/')}.php`;
      const controllerSources = [...inventoryFiles.values()].filter((candidate) =>
        candidate?.extension === extensionMachineName &&
        (String(candidate?.path ?? '') === controllerDrupalPath || String(candidate?.path ?? '').endsWith(`/${controllerDrupalPath}`)) &&
        sourceFileIds.has(candidate.id)
      );
      if (controllerSources.length === 1) {
        const controllerSurfaces = (Array.isArray(controllerSources[0].surfaces) ? controllerSources[0].surfaces : []).filter((candidate) =>
          candidate?.kind === 'controller_class' && candidate?.name === controllerMatch[3].split('\\').at(-1) && surfaceIds.has(candidate.id)
        );
        if (controllerSurfaces.length === 1) {
          controllerSourceFileId = controllerSources[0].id;
          controllerSurfaceId = controllerSurfaces[0].id;
        }
      }
    }
    candidateRouteBindings.push({
      routeName,
      extensionId: extension.id,
      extensionMachineName,
      routeSourceFileId: source.id,
      routeSurfaceId: surface.id,
      controllerDefinition,
      controllerClass,
      controllerMethod,
      controllerDrupalPath,
      controllerSourceFileId,
      controllerSurfaceId
    });
  }
  candidateRouteBindings.sort((left, right) => comparePortable(left.routeName, right.routeName));

  const declarations = [];
  for (const bundle of Array.isArray(fieldOutputMatrix?.bundles) ? fieldOutputMatrix.bundles : []) {
    if (String(bundle?.entityType ?? '') !== 'node' || !MACHINE_RE.test(String(bundle?.bundle ?? ''))) continue;
    for (const field of Array.isArray(bundle?.fields) ? bundle.fields : []) {
      const fieldName = String(field?.machineName ?? '');
      if (!FIELD_RE.test(fieldName) || !publicFieldDeclaration(field) || declaredReferenceTarget(field) !== 'media') continue;
      const identity = `node\u0000${bundle.bundle}\u0000${fieldName}\u0000media`;
      declarations.push({
        id: `DECLARATION-${sha256(identity).slice(7, 23)}`,
        entityType: 'node',
        bundle: bundle.bundle,
        fieldName,
        targetEntityType: 'media',
        publicRoutePaths: uniqueSorted((Array.isArray(field.publicRenderLocations)
          ? field.publicRenderLocations
          : []).map(safeRoutePath).filter(Boolean))
      });
    }
  }

  const normalizedDeclarations = [...new Map(declarations.map((row) => [row.id, row])).values()]
    .sort((left, right) => comparePortable(left.id, right.id));

  const candidateRenderBindings = [];
  for (const extension of extensions) {
    for (const source of inventoryFiles.values()) {
      if (source?.extension !== extension.machineName || !sourceFileIds.has(source.id)) continue;
      for (const surface of Array.isArray(source.surfaces) ? source.surfaces : []) {
        if (!surfaceIds.has(surface.id)) continue;
        const name = String(surface?.name ?? '');
        const normalizedSourcePath = String(source?.path ?? '').replaceAll('\\', '/').replace(/^\.\//, '');
        const extensionPathOffset = normalizedSourcePath.indexOf(`${extension.drupalPath}/`);
        const sourceDrupalPath = extensionPathOffset >= 0 ? normalizedSourcePath.slice(extensionPathOffset) : '';
        let selectorKind = '';
        let selectorValue = '';
        let runtimeClass = '';
        let runtimeMethod = '';
        let runtimeFunction = '';
        let hookName = String(surface?.hookName ?? '');
        let hookProviderMachineName = '';
        if (extension.type === 'module' && surface?.kind === 'plugin_class') {
          const sourceClassMatch = sourceDrupalPath.match(/\/src\/(.+)\.php$/);
          if (sourceClassMatch && sourceClassMatch[1].split('/').at(-1) === name) {
            selectorKind = 'field_formatter_plugin';
            selectorValue = name;
            runtimeClass = `Drupal\\${extension.machineName}\\${sourceClassMatch[1].replaceAll('/', '\\')}`;
          }
        } else if (surface?.kind === 'hook_or_callback') {
          if (!hookName && name.startsWith(`${extension.machineName}_`)) {
            hookName = name.slice(extension.machineName.length + 1);
          }
          hookProviderMachineName = String(surface?.moduleName ?? '') || extension.machineName;
          if (!hookName && !surface?.className) {
            const proceduralOverride = name.match(/^([a-z][a-z0-9_]*)_((?:preprocess|theme_suggestions)_.+)$/) ??
              [...NODE_RENDER_HOOK_NAMES]
                .sort((left, right) => right.length - left.length)
                .map((candidateHook) => {
                  const suffix = `_${candidateHook}`;
                  return name.endsWith(suffix)
                    ? [name, name.slice(0, -suffix.length), candidateHook]
                    : null;
                })
                .find(Boolean);
            if (proceduralOverride && MACHINE_RE.test(proceduralOverride[1])) {
              hookProviderMachineName = proceduralOverride[1];
              hookName = proceduralOverride[2];
            }
          }
          if (surface?.className && surface?.methodName) {
            runtimeClass = String(surface.className);
            runtimeMethod = String(surface.methodName);
          } else {
            runtimeFunction = name;
          }
          if (['theme_suggestions_node', 'theme_suggestions_node_alter', 'theme_suggestions_alter'].includes(hookName)) {
            // Themes only participate in alter hooks; module suggestion
            // providers and both module/theme alters participate in the chain.
            if (extension.type === 'module' || hookName.endsWith('_alter')) {
              selectorKind = 'theme_suggestion_hook';
              selectorValue = hookName;
            }
          } else if (hookName.startsWith('preprocess_')) {
            selectorKind = hookName === 'preprocess_node' || hookName.startsWith('preprocess_node__')
              ? 'preprocess_node'
              : 'template_preprocess_hook';
            selectorValue = hookName;
          } else if (extension.type === 'module' && NODE_RENDER_HOOK_NAMES.has(hookName)) {
            selectorKind = 'node_render_hook';
            selectorValue = hookName;
          }
        } else if (surface?.kind === 'twig_template') {
          // Broadly inventory module- and theme-owned templates here. Drupal's runtime theme
          // registry and suggestion APIs determine the exact selected file for
          // each route; filename heuristics cannot cover entity IDs or alters.
          selectorKind = 'theme_template';
          selectorValue = '*';
        }
        if (!selectorKind) continue;
        if (!sourceDrupalPath) {
          errors.push('A candidate render binding is not owned by its exact custom extension path.');
          continue;
        }
        candidateRenderBindings.push({
          extensionId: extension.id,
          extensionMachineName: extension.machineName,
          extensionType: extension.type,
          sourceDrupalPath,
          sourceFileId: source.id,
          surfaceId: surface.id,
          surfaceName: name,
          hookName,
          hookProviderMachineName,
          runtimeClass,
          runtimeMethod,
          runtimeFunction,
          runtimeIdentity: selectorKind === 'field_formatter_plugin'
            ? `${runtimeClass}\u0000${sourceDrupalPath}`
            : runtimeClass && runtimeMethod
              ? `${runtimeClass}::${runtimeMethod}\u0000${hookName}\u0000${hookProviderMachineName}\u0000${sourceDrupalPath}`
              : runtimeFunction
                ? `${runtimeFunction}\u0000${hookName}\u0000${hookProviderMachineName}\u0000${sourceDrupalPath}`
                : '',
          selectorKind,
          selectorValue
        });
      }
    }
  }
  candidateRenderBindings.sort((left, right) => comparePortable(
    `${left.extensionMachineName}\u0000${left.selectorKind}\u0000${left.selectorValue}\u0000${left.sourceFileId}\u0000${left.surfaceId}`,
    `${right.extensionMachineName}\u0000${right.selectorKind}\u0000${right.selectorValue}\u0000${right.sourceFileId}\u0000${right.surfaceId}`
  ));

  const normalizedRoutes = routeInputs(routeMatrix, normalizedDeclarations);
  if (normalizedRoutes.some((route) => route.bundles.length > 1)) {
    errors.push('A concrete entity-output route cannot bind declarations from multiple node bundles.');
  }

  const normalized = {
    schemaVersion: CUSTOM_ENTITY_OUTPUT_INPUT_SCHEMA,
    targetOrigin: normalizedTargetOrigin,
    candidateSourceFileIds: uniqueSorted([...sourceFileIds]),
    candidateSurfaceIds: uniqueSorted([...surfaceIds]),
    extensions,
    candidateRouteBindings,
    candidateRenderBindings,
    declarations: normalizedDeclarations,
    routes: normalizedRoutes,
    errors: uniqueSorted(errors)
  };
  for (const [values, maximum, label] of [
    [normalized.candidateSourceFileIds, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSourceFiles, 'candidate source files'],
    [normalized.candidateSurfaceIds, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces, 'candidate surfaces'],
    [normalized.extensions, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.extensions, 'candidate extensions'],
    [normalized.candidateRouteBindings, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces, 'candidate route bindings'],
    [normalized.candidateRenderBindings, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces, 'candidate render bindings'],
    [normalized.declarations, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.declarations, 'typed declarations'],
    [normalized.routes, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes, 'public routes']
  ]) {
    if (values.length > maximum) normalized.errors.push(`Custom entity-output audit exceeded ${maximum} ${label}.`);
  }
  normalized.errors = uniqueSorted(normalized.errors);
  normalized.inputFingerprint = sha256({
    schemaVersion: normalized.schemaVersion,
    targetOrigin: normalized.targetOrigin,
    candidateSourceFileIds: normalized.candidateSourceFileIds,
    candidateSurfaceIds: normalized.candidateSurfaceIds,
    extensions: normalized.extensions,
    candidateRouteBindings: normalized.candidateRouteBindings,
    candidateRenderBindings: normalized.candidateRenderBindings,
    declarations: normalized.declarations,
    routes: normalized.routes
  });
  return normalized;
}

function isolatedBoundaryAccepted(isolation) {
  return ['exact-head-disposable-ddev', 'verifier-owned-disposable-ddev'].includes(isolation?.executionBoundary) &&
    /^DISPOSABLE-[A-Za-z0-9_-]{1,128}$/.test(String(isolation?.workspaceId ?? '')) &&
    isolation?.exactHead === true &&
    isolation?.freshDatabase === true;
}

function currentDdevTargetBoundaryAccepted(projectRoot, environment, expectedOrigin) {
  const normalizedExpectedOrigin = safeTargetOrigin(expectedOrigin);
  if (!normalizedExpectedOrigin) return false;
  const inContainer = /^(?:1|true|yes)$/i.test(String(environment?.IS_DDEV_PROJECT ?? '')) &&
    String(environment?.DDEV_APPROOT ?? '') === String(projectRoot);
  if (inContainer) {
    return safeTargetOrigin(environment?.DDEV_PRIMARY_URL) === normalizedExpectedOrigin;
  }
  const result = spawnSync('ddev', ['describe', '-j'], {
    cwd: projectRoot,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    shell: false,
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 15_000
  });
  if (result.error || result.status !== 0) return false;
  try {
    return safeTargetOrigin(JSON.parse(String(result.stdout ?? ''))?.raw?.primary_url) === normalizedExpectedOrigin;
  } catch {
    return false;
  }
}

function evidenceBase(derived, allowOwnedCacheInvalidation) {
  return {
    schemaVersion: CUSTOM_ENTITY_OUTPUT_AUDIT_SCHEMA,
    candidateSourceFileIds: derived.candidateSourceFileIds,
    candidateSurfaceIds: derived.candidateSurfaceIds,
    typedDeclarationIds: derived.declarations.map((row) => row.id),
    publicRouteCount: derived.routes.length,
    inputFingerprint: derived.inputFingerprint,
    // This describes verifier-owned mutation only. Drupal rendering can warm
    // caches or invoke application-defined side effects.
    noExplicitVerifierMutation: !allowOwnedCacheInvalidation,
    allowOwnedCacheInvalidation
  };
}

export function customEntityOutputAuditResultFingerprint(record) {
  const unsigned = { ...record };
  delete unsigned.resultFingerprint;
  return sha256(unsigned);
}

function localResult(derived, allowOwnedCacheInvalidation, status, completed, code) {
  const result = {
    ...evidenceBase(derived, allowOwnedCacheInvalidation),
    applies: derived.candidateSourceFileIds.length > 0 && derived.declarations.length > 0,
    completed,
    status,
    runtime: null,
    failures: code ? [{ code, detailSha256: sha256(code) }] : []
  };
  result.resultFingerprint = customEntityOutputAuditResultFingerprint(result);
  return result;
}

function defaultRunner({ projectRoot, environment, php, timeoutMs, outputLimitBytes }) {
  const inContainer = Boolean(
    /^(?:1|true|yes)$/i.test(String(environment?.IS_DDEV_PROJECT ?? '')) &&
    environment?.DDEV_APPROOT &&
    String(environment.DDEV_APPROOT) === String(projectRoot)
  );
  const command = inContainer ? 'drush' : 'ddev';
  const args = inContainer ? ['php:eval', php] : ['drush', 'php:eval', php];
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    encoding: 'utf8',
    input: '',
    maxBuffer: outputLimitBytes,
    timeout: timeoutMs,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  return {
    ok: !result.error && result.status === 0 && Buffer.byteLength(stdout, 'utf8') <= outputLimitBytes,
    output: stdout,
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    timedOut: result.error?.code === 'ETIMEDOUT',
    outputExceeded: result.error?.code === 'ENOBUFS' || Buffer.byteLength(stdout, 'utf8') > outputLimitBytes,
    failureSha256: sha256(`${result.error?.code ?? ''}\u0000${result.status ?? ''}\u0000${stderr}`)
  };
}

export const CUSTOM_ENTITY_OUTPUT_AUDIT_PHP = String.raw`
$audit_schema = 'public-kit.custom-entity-output-audit.1';
$hash_value = static fn (string $value): string => 'sha256:' . hash('sha256', $value);
$canonicalize = NULL;
$canonicalize = static function (mixed $value) use (&$canonicalize): mixed {
  if (is_array($value)) {
    $is_list = array_is_list($value);
    if (!$is_list) ksort($value);
    foreach ($value as $key => $child) {
      $value[$key] = $canonicalize($child);
    }
  }
  return $value;
};
$hash_json = static function (mixed $value) use ($canonicalize): string {
  return 'sha256:' . hash('sha256', json_encode($canonicalize($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
};
$input = is_array($audit_input ?? NULL) ? $audit_input : [];
$allow_invalidation = ($input['allowOwnedCacheInvalidation'] ?? FALSE) === TRUE;
$limits = is_array($input['limits'] ?? NULL) ? $input['limits'] : [];
$target_origin = rtrim((string) ($input['targetOrigin'] ?? ''), '/');
$result = [
  'schemaVersion' => $audit_schema,
  'bounded' => TRUE,
  'completed' => FALSE,
  'status' => 'fail',
  'noExplicitVerifierMutation' => !$allow_invalidation,
  'allowOwnedCacheInvalidation' => $allow_invalidation,
  'inputFingerprint' => (string) ($input['inputFingerprint'] ?? ''),
  'targetOriginSha256' => $target_origin !== '' ? $hash_value($target_origin) : '',
  'activeCandidateExtensionCount' => 0,
  'activeCandidateExtensionSha256' => [],
  'defaultThemeExtensionSha256' => '',
  'routeCount' => 0,
  'applicableRouteCount' => 0,
  'matchedNodeRouteCount' => 0,
  'renderedRouteCount' => 0,
  'dependencyCount' => 0,
  'coveredDeclarationCount' => 0,
  'coveredDeclarationSetSha256' => '',
  'coveredCandidateSourceFileCount' => 0,
  'coveredCandidateSourceFileSetSha256' => '',
  'coveredCandidateSurfaceCount' => 0,
  'coveredCandidateSurfaceSetSha256' => '',
  'routes' => [],
  'invalidation' => [
    'status' => $allow_invalidation ? 'pending' : 'not_run',
    'preCaptureAttempted' => FALSE,
    'preCaptureTagCount' => 0,
    'preCaptureEvidenceSha256' => '',
    'attempted' => FALSE,
    'seededCount' => 0,
    'invalidatedCount' => 0,
    'cleanupRequired' => FALSE,
    'cleanupCompleted' => TRUE,
    'evidenceSha256' => '',
  ],
  'violations' => [],
];
$violate = static function (string $code, string $route_hash = '', string $subject_hash = '') use (&$result, $limits): void {
  if (count($result['violations']) < (int) ($limits['violations'] ?? 0)) {
    $result['violations'][] = ['code' => $code, 'routeSha256' => $route_hash, 'subjectSha256' => $subject_hash];
  }
};
$metadata_budget = ['items' => 0, 'bytes' => 0];
$bounded_metadata = static function (
  array $values,
  string $kind,
  string $route_hash = '',
  string $subject_hash = '',
) use (&$metadata_budget, $hash_value, $limits, $violate): ?array {
  $item_count = count($values);
  $failure_subject = $subject_hash !== '' ? $subject_hash : $hash_value($kind);
  if ($item_count > (int) ($limits['metadataItemsPerSet'] ?? 0)) {
    $violate('cache_metadata_item_limit_exceeded', $route_hash, $failure_subject);
    return NULL;
  }
  $byte_count = 0;
  foreach ($values as $value) {
    if (!is_string($value)) {
      $violate('cache_metadata_value_invalid', $route_hash, $failure_subject);
      return NULL;
    }
    $byte_count += strlen($value);
    if ($byte_count > (int) ($limits['metadataBytesPerSet'] ?? 0)) {
      $violate('cache_metadata_byte_limit_exceeded', $route_hash, $failure_subject);
      return NULL;
    }
  }
  if ($metadata_budget['items'] + $item_count > (int) ($limits['metadataItemsTotal'] ?? 0)) {
    $violate('cache_metadata_total_item_limit_exceeded', $route_hash, $failure_subject);
    return NULL;
  }
  if ($metadata_budget['bytes'] + $byte_count > (int) ($limits['metadataBytesTotal'] ?? 0)) {
    $violate('cache_metadata_total_byte_limit_exceeded', $route_hash, $failure_subject);
    return NULL;
  }
  $metadata_budget['items'] += $item_count;
  $metadata_budget['bytes'] += $byte_count;
  $normalized = array_values(array_unique($values, SORT_STRING));
  sort($normalized, SORT_STRING);
  return $normalized;
};
$target_parts = parse_url($target_origin);
if (!is_array($target_parts) || !in_array((string) ($target_parts['scheme'] ?? ''), ['http', 'https'], TRUE) ||
  empty($target_parts['host']) || isset($target_parts['user']) || isset($target_parts['pass']) ||
  !in_array((string) ($target_parts['path'] ?? ''), ['', '/'], TRUE) || isset($target_parts['query']) || isset($target_parts['fragment'])) {
  $violate('target_origin_invalid');
}
$set_subset = static function (array $required, array $actual): bool {
  $actual_set = array_fill_keys($actual, TRUE);
  foreach ($required as $item) {
    if (!isset($actual_set[$item])) return FALSE;
  }
  return TRUE;
};
$metadata_hash = static function (array $tags, array $contexts, int $max_age) use ($hash_json): string {
  return $hash_json(['tags' => $tags, 'contexts' => $contexts, 'maxAge' => $max_age]);
};

$declarations_by_bundle = [];
foreach (is_array($input['declarations'] ?? NULL) ? $input['declarations'] : [] as $declaration) {
  $bundle = (string) ($declaration['bundle'] ?? '');
  if ($bundle !== '') $declarations_by_bundle[$bundle][] = $declaration;
}

$active_storage = \Drupal::service('config.storage');
$core_extensions = $active_storage->read('core.extension') ?: [];
$active_extensions = [];
$active_extensions_by_machine = [];
foreach (is_array($input['extensions'] ?? NULL) ? $input['extensions'] : [] as $extension) {
  $machine = (string) ($extension['machineName'] ?? '');
  $type = (string) ($extension['type'] ?? '');
  $expected_path = trim(str_replace('\\', '/', (string) ($extension['drupalPath'] ?? '')), '/');
  $subject_hash = $hash_value($type . "\0" . $machine);
  try {
    $is_active = $type === 'module'
      ? array_key_exists($machine, is_array($core_extensions['module'] ?? NULL) ? $core_extensions['module'] : [])
      : $type === 'theme' && array_key_exists($machine, is_array($core_extensions['theme'] ?? NULL) ? $core_extensions['theme'] : []);
    if (!$is_active) continue;
    $list = \Drupal::service($type === 'module' ? 'extension.list.module' : 'extension.list.theme');
    $runtime_path = trim(str_replace('\\', '/', (string) $list->getPath($machine)), '/');
    if ($runtime_path !== $expected_path) {
      $violate('candidate_extension_path_mismatch', '', $subject_hash);
      continue;
    }
    $active_extensions[$subject_hash] = [
      'subjectSha256' => $subject_hash,
      'id' => (string) ($extension['id'] ?? ''),
      'machineName' => $machine,
      'type' => $type,
      'drupalPath' => $runtime_path,
    ];
    $active_extensions_by_machine[$machine] = $active_extensions[$subject_hash];
  }
  catch (\Throwable $error) {
    $violate('candidate_extension_resolution_failed', '', $hash_value($subject_hash . "\0" . get_class($error) . "\0" . $error->getMessage()));
  }
}
$result['activeCandidateExtensionCount'] = count($active_extensions);
$active_candidate_extension_hashes = array_values(array_map(
  static fn (array $extension): string => $hash_value((string) ($extension['id'] ?? '')),
  $active_extensions,
));
sort($active_candidate_extension_hashes, SORT_STRING);
$result['activeCandidateExtensionSha256'] = $active_candidate_extension_hashes;
$active_candidate_set_hash = $active_candidate_extension_hashes ? $hash_json($active_candidate_extension_hashes) : '';
$candidate_routes_by_name = [];
foreach (is_array($input['candidateRouteBindings'] ?? NULL) ? $input['candidateRouteBindings'] : [] as $binding) {
  $route_name = (string) ($binding['routeName'] ?? '');
  $extension_machine = (string) ($binding['extensionMachineName'] ?? '');
  $extension = $active_extensions_by_machine[$extension_machine] ?? NULL;
  if (!is_array($extension) || (string) ($extension['id'] ?? '') !== (string) ($binding['extensionId'] ?? '')) continue;
  if ($route_name === '' || isset($candidate_routes_by_name[$route_name])) {
    $violate('candidate_route_binding_not_unique', '', $hash_value($route_name));
    continue;
  }
  $candidate_routes_by_name[$route_name] = $binding + [
    'extensionSubjectSha256' => (string) ($extension['subjectSha256'] ?? ''),
  ];
}
$default_theme_machine = (string) \Drupal::config('system.theme')->get('default');
$default_theme_extension = $active_extensions_by_machine[$default_theme_machine] ?? NULL;
if (is_array($default_theme_extension) && (string) ($default_theme_extension['type'] ?? '') === 'theme') {
  $result['defaultThemeExtensionSha256'] = $hash_value((string) ($default_theme_extension['id'] ?? ''));
}
$candidate_active_render_bindings = [];
foreach (is_array($input['candidateRenderBindings'] ?? NULL) ? $input['candidateRenderBindings'] : [] as $binding) {
  $extension_machine = (string) ($binding['extensionMachineName'] ?? '');
  $extension_type = (string) ($binding['extensionType'] ?? '');
  $extension = $active_extensions_by_machine[$extension_machine] ?? NULL;
  $selector_kind = (string) ($binding['selectorKind'] ?? '');
  $render_extension_active = in_array($extension_type, ['module', 'theme'], TRUE);
  if (!$render_extension_active || !is_array($extension) ||
    (string) ($extension['id'] ?? '') !== (string) ($binding['extensionId'] ?? '')) continue;
  $source_drupal_path = trim(str_replace('\\', '/', (string) ($binding['sourceDrupalPath'] ?? '')), '/');
  $source_realpath = $source_drupal_path !== ''
    ? str_replace('\\', '/', (string) (realpath(DRUPAL_ROOT . '/' . $source_drupal_path) ?: ''))
    : '';
  $extension_realpath = str_replace('\\', '/', (string) (realpath(DRUPAL_ROOT . '/' . ($extension['drupalPath'] ?? '')) ?: ''));
  $source_subject_hash = $hash_value((string) ($binding['sourceFileId'] ?? ''));
  if ($source_realpath === '' || $extension_realpath === '' || !str_starts_with($source_realpath, $extension_realpath . '/')) {
    $violate('candidate_render_source_path_mismatch', '', $source_subject_hash);
    continue;
  }
  $candidate_active_render_bindings[] = $binding + [
    'extensionSubjectSha256' => (string) ($extension['subjectSha256'] ?? ''),
    'sourceRealpath' => $source_realpath,
  ];
}
$callable_details = static function (callable $callable): array {
  $class = '';
  $method = '';
  $function = '';
  if (is_array($callable) && count($callable) === 2) {
    $class = is_object($callable[0]) ? get_class($callable[0]) : ltrim((string) $callable[0], '\\');
    $method = (string) $callable[1];
    $reflection = new \ReflectionMethod($class, $method);
  }
  else {
    $reflection = new \ReflectionFunction($callable);
    $scope = $reflection->getClosureScopeClass();
    if ($scope instanceof \ReflectionClass && $reflection->getName() !== '{closure}') {
      $class = $scope->getName();
      $method = $reflection->getName();
    }
    else {
      $function = $reflection->getName();
    }
  }
  $file = str_replace('\\', '/', (string) (realpath((string) ($reflection->getFileName() ?: '')) ?: ''));
  return [ltrim($class, '\\'), $method, $function, $file];
};
$active_module_render_bindings = [];
$module_handler = \Drupal::moduleHandler();
foreach ([
  'node_view_mode_alter', 'entity_view_mode_alter',
  'node_build_defaults_alter', 'entity_build_defaults_alter',
  'entity_view_display_alter', 'entity_prepare_view', 'entity_display_build_alter',
  'entity_view', 'entity_view_alter', 'node_view', 'node_view_alter',
  'theme_suggestions_node', 'theme_suggestions_node_alter', 'theme_suggestions_alter',
] as $hook_name) {
  try {
    $module_handler->invokeAllWith($hook_name, static function (callable $listener, string $module) use (
      &$active_module_render_bindings,
      $callable_details,
      $candidate_active_render_bindings,
      $hash_value,
      $violate,
      $hook_name,
    ): void {
      try {
        [$class, $method, $function, $file] = $callable_details($listener);
      }
      catch (\Throwable $error) {
        $violate('candidate_render_hook_resolution_failed', '', $hash_value(get_class($error) . "\0" . $error->getMessage()));
        return;
      }
      $matches = [];
      foreach ($candidate_active_render_bindings as $binding) {
        if ((string) ($binding['extensionType'] ?? '') !== 'module' ||
          (string) ($binding['hookProviderMachineName'] ?? '') !== $module ||
          (string) ($binding['hookName'] ?? '') !== $hook_name ||
          (string) ($binding['sourceRealpath'] ?? '') !== $file) continue;
        $binding_class = ltrim((string) ($binding['runtimeClass'] ?? ''), '\\');
        $binding_method = (string) ($binding['runtimeMethod'] ?? '');
        $binding_function = (string) ($binding['runtimeFunction'] ?? '');
        if (($class !== '' && $binding_class === $class && $binding_method === $method) ||
          ($function !== '' && $binding_function === $function)) {
          $matches[] = $binding;
        }
      }
      if (count($matches) === 0) return;
      if (count($matches) !== 1) {
        $violate('active_render_hook_not_uniquely_inventoried', '', $hash_value($module . "\0" . $hook_name . "\0" . $class . "\0" . $method . "\0" . $function . "\0" . $file));
        return;
      }
      $binding = reset($matches);
      $key = implode("\0", [(string) ($binding['extensionId'] ?? ''), (string) ($binding['sourceFileId'] ?? ''), (string) ($binding['surfaceId'] ?? '')]);
      $active_module_render_bindings[$key] = $binding;
    });
  }
  catch (\Throwable $error) {
    $violate('candidate_render_hook_enumeration_failed', '', $hash_value($hook_name . "\0" . get_class($error) . "\0" . $error->getMessage()));
  }
}
ksort($active_module_render_bindings, SORT_STRING);
$active_module_render_bindings = array_values($active_module_render_bindings);
$match_candidate_callable = static function (
  callable $listener,
  string $extension_type,
  string $extension_machine,
  string $hook_name,
  array $selector_kinds,
) use ($callable_details, $candidate_active_render_bindings): array {
  [$class, $method, $function, $file] = $callable_details($listener);
  $matches = [];
  foreach ($candidate_active_render_bindings as $binding) {
    $binding_provider = $extension_type === 'module'
      ? (string) ($binding['hookProviderMachineName'] ?? '')
      : (string) ($binding['extensionMachineName'] ?? '');
    if ((string) ($binding['extensionType'] ?? '') !== $extension_type ||
      $binding_provider !== $extension_machine ||
      (string) ($binding['hookName'] ?? '') !== $hook_name ||
      !in_array((string) ($binding['selectorKind'] ?? ''), $selector_kinds, TRUE) ||
      (string) ($binding['sourceRealpath'] ?? '') !== $file) continue;
    $binding_class = ltrim((string) ($binding['runtimeClass'] ?? ''), '\\');
    $binding_method = (string) ($binding['runtimeMethod'] ?? '');
    $binding_function = (string) ($binding['runtimeFunction'] ?? '');
    if (($class !== '' && $binding_class === $class && $binding_method === $method) ||
      ($function !== '' && $binding_function === $function)) {
      $matches[] = $binding;
    }
  }
  return $matches;
};
$router = \Drupal::service('router.no_access_checks');
$request_stack = \Drupal::service('request_stack');
$account_switcher = \Drupal::service('account_switcher');
$access_manager = \Drupal::service('access_manager');
$controller_resolver = \Drupal::service('controller_resolver');
$argument_resolver = \Drupal::service('http_kernel.controller.argument_resolver');
$renderer = \Drupal::service('renderer');
$anonymous = new \Drupal\Core\Session\AnonymousUserSession();
$invalidation_tag_sets = [];
$pre_capture_invalidation_tag_sets = [];
$total_dependencies = 0;
$candidate_coverage_total = 0;
$covered_declaration_set = [];
$covered_candidate_source_file_set = [];
$covered_candidate_surface_set = [];
$invalidate_route_render_cache = static function (
  \Drupal\node\NodeInterface $node,
  array $declarations,
  string $route_hash,
) use (&$pre_capture_invalidation_tag_sets, &$result, $allow_invalidation, $anonymous, $bounded_metadata, $hash_json, $limits): void {
  if (!$allow_invalidation) return;
  $entities = [
    'node:' . (string) $node->id() => $node,
  ];
  foreach ($declarations as $declaration) {
    $field_name = (string) ($declaration['fieldName'] ?? '');
    if ($field_name === '' || !$node->hasField($field_name)) continue;
    $field_dependency_count = 0;
    foreach ($node->get($field_name) as $item) {
      $media = $item->entity;
      if (!$media instanceof \Drupal\media\MediaInterface) continue;
      $field_dependency_count++;
      if ($field_dependency_count > (int) ($limits['dependenciesPerRoute'] ?? 0) ||
        count($entities) + 1 > (int) ($limits['dependenciesTotal'] ?? 0)) {
        throw new \RuntimeException('pre_capture_invalidation_entity_limit_exceeded');
      }
      $pre_capture_media_access = $media->access('view', $anonymous, TRUE);
      if (!$pre_capture_media_access->isAllowed()) {
        throw new \RuntimeException('pre_capture_dependency_access_not_allowed');
      }
      $entities['media:' . (string) $media->id()] = $media;
      $source_field = (string) ($media->getSource()->getConfiguration()['source_field'] ?? '');
      if ($source_field === '' || !$media->hasField($source_field)) continue;
      foreach ($media->get($source_field) as $source_item) {
        $file = $source_item->entity;
        if (!$file instanceof \Drupal\file\FileInterface) continue;
        $field_dependency_count++;
        if ($field_dependency_count > (int) ($limits['dependenciesPerRoute'] ?? 0) ||
          count($entities) + 1 > (int) ($limits['dependenciesTotal'] ?? 0)) {
          throw new \RuntimeException('pre_capture_invalidation_entity_limit_exceeded');
        }
        $pre_capture_file_access = $file->access('view', $anonymous, TRUE);
        if (!$pre_capture_file_access->isAllowed()) {
          throw new \RuntimeException('pre_capture_dependency_access_not_allowed');
        }
        $entities['file:' . (string) $file->id()] = $file;
      }
    }
  }
  $tags = [];
  foreach ($entities as $entity) {
    if (!method_exists($entity, 'getCacheTagsToInvalidate')) continue;
    foreach ($entity->getCacheTagsToInvalidate() as $tag) {
      $tags[] = $tag;
    }
  }
  $tags = $bounded_metadata($tags, 'pre_capture_invalidation_tags', $route_hash);
  if ($tags === NULL) throw new \RuntimeException('pre_capture_invalidation_tags_outside_budget');
  if (!$tags) throw new \RuntimeException('pre_capture_invalidation_tags_unavailable');
  \Drupal::service('cache_tags.invalidator')->invalidateTags($tags);
  $evidence = $hash_json($tags);
  $pre_capture_invalidation_tag_sets[$evidence] = $tags;
  $result['invalidation']['preCaptureAttempted'] = TRUE;
  $result['invalidation']['preCaptureTagCount'] += count($tags);
  $evidence_set = array_keys($pre_capture_invalidation_tag_sets);
  sort($evidence_set, SORT_STRING);
  $result['invalidation']['preCaptureEvidenceSha256'] = $hash_json($evidence_set);
};
$capture_render = static function (callable $build_factory) use ($renderer): array {
  /** @var \Twig\Environment $twig */
  $twig = \Drupal::service('twig');
  $original_loader = $twig->getLoader();
  $recording_loader = new class($original_loader) implements \Twig\Loader\LoaderInterface {
    private array $realpaths = [];

    public function __construct(private \Twig\Loader\LoaderInterface $inner) {}

    private function record(string $value): void {
      if ($value === '') return;
      $candidates = [$value];
      if (!str_starts_with($value, '/')) $candidates[] = DRUPAL_ROOT . '/' . ltrim($value, '/\\');
      foreach ($candidates as $candidate) {
        $realpath = realpath($candidate);
        if ($realpath === FALSE || !is_file($realpath)) continue;
        $normalized = str_replace('\\', '/', $realpath);
        $this->realpaths[$normalized] = TRUE;
      }
    }

    public function getSourceContext(string $name): \Twig\Source {
      $this->record($name);
      $source = $this->inner->getSourceContext($name);
      $this->record($source->getPath());
      return $source;
    }

    public function getCacheKey(string $name): string {
      $this->record($name);
      $key = $this->inner->getCacheKey($name);
      $this->record($key);
      return $key;
    }

    public function isFresh(string $name, int $time): bool {
      $this->record($name);
      return $this->inner->isFresh($name, $time);
    }

    public function exists(string $name) {
      $this->record($name);
      return $this->inner->exists($name);
    }

    public function recordedRealpaths(): array {
      $realpaths = array_keys($this->realpaths);
      sort($realpaths, SORT_STRING);
      return $realpaths;
    }
  };
  $render_context = new \Drupal\Core\Render\RenderContext();
  $build = NULL;
  $twig->setLoader($recording_loader);
  try {
    $renderer->executeInRenderContext($render_context, static function () use ($build_factory, $renderer, &$build): void {
      $build = $build_factory();
      if (is_array($build)) {
        $build['#cache']['max-age'] = 0;
        $renderer->render($build);
      }
    });
  }
  finally {
    $twig->setLoader($original_loader);
  }
  return [$build, $render_context, $recording_loader->recordedRealpaths()];
};
$resolve_recorded_render = static function (array $recorded_realpaths, bool $entity_view_handler) use (
  $active_extensions_by_machine,
  $active_module_render_bindings,
  $candidate_active_render_bindings,
  $callable_details,
  $match_candidate_callable,
): array {
  $theme_manager = \Drupal::service('theme.manager');
  $active_theme = $theme_manager->getActiveTheme();
  $active_theme_machines = array_values(array_unique(array_merge(
    array_keys($active_theme->getBaseThemeExtensions()),
    [(string) $active_theme->getName()],
  )));
  sort($active_theme_machines, SORT_STRING);
  $active_theme_machine_set = array_fill_keys($active_theme_machines, TRUE);
  $theme_registry = \Drupal::service('theme.registry')->getRuntime();
  $complete_theme_registry = \Drupal::service('theme.registry')->get();
  $module_handler = \Drupal::moduleHandler();
  $recorded_realpath_set = array_fill_keys(array_map(
    static fn (string $path): string => str_replace('\\', '/', $path),
    $recorded_realpaths,
  ), TRUE);
  $drupal_root_realpath = str_replace('\\', '/', (string) (realpath(DRUPAL_ROOT) ?: DRUPAL_ROOT));
  $selected_template_paths = [];
  foreach (array_keys($recorded_realpath_set) as $recorded_realpath) {
    if (!str_ends_with($recorded_realpath, '.twig') || !str_starts_with($recorded_realpath, $drupal_root_realpath . '/')) continue;
    $selected_template_paths[substr($recorded_realpath, strlen($drupal_root_realpath) + 1)] = TRUE;
  }
  $selected_template_bindings = [];
  foreach ($candidate_active_render_bindings as $binding) {
    if ((string) ($binding['selectorKind'] ?? '') !== 'theme_template') continue;
    if ((string) ($binding['extensionType'] ?? '') === 'theme' &&
      !isset($active_theme_machine_set[(string) ($binding['extensionMachineName'] ?? '')])) continue;
    if (!isset($recorded_realpath_set[(string) ($binding['sourceRealpath'] ?? '')])) continue;
    $key = implode("\0", [(string) ($binding['extensionId'] ?? ''), (string) ($binding['sourceFileId'] ?? ''), (string) ($binding['surfaceId'] ?? '')]);
    $selected_template_bindings[$key] = $binding;
  }
  ksort($selected_template_bindings, SORT_STRING);
  $selected_template_paths = array_values(array_filter(array_keys($selected_template_paths), 'strlen'));
  sort($selected_template_paths, SORT_STRING);

  $selected_registry_entries = [];
  foreach ($complete_theme_registry as $hook => $info) {
    if (!is_array($info)) continue;
    $template_candidates = [];
    if (isset($info['template_file']) && is_string($info['template_file'])) $template_candidates[] = $info['template_file'];
    if (isset($info['template']) && is_string($info['template'])) {
      $path = isset($info['path']) && is_string($info['path']) ? rtrim($info['path'], '/\\') . '/' : '';
      $template_candidates[] = $path . $info['template'];
      $template_candidates[] = $path . $info['template'] . '.html.twig';
    }
    foreach ($template_candidates as $template_candidate) {
      $absolute_candidate = str_starts_with($template_candidate, '/')
        ? $template_candidate
        : DRUPAL_ROOT . '/' . ltrim($template_candidate, '/\\');
      $resolved_candidate = realpath($absolute_candidate);
      if ($resolved_candidate === FALSE || !isset($recorded_realpath_set[str_replace('\\', '/', $resolved_candidate)])) continue;
      $selected_registry_entries[(string) $hook] = $info;
      break;
    }
  }

  $selected_preprocess_bindings = [];
  $preprocess_invoke_map = $theme_registry->getPreprocessInvokes();
  $preprocess_callbacks = $theme_registry->getGlobalPreprocess();
  foreach ($selected_registry_entries as $info) {
    if (is_array($info['preprocess functions'] ?? NULL)) {
      $preprocess_callbacks = array_merge($preprocess_callbacks, $info['preprocess functions']);
    }
  }
  foreach ($preprocess_callbacks as $preprocess_callback) {
    if (is_string($preprocess_callback) && isset($preprocess_invoke_map[$preprocess_callback])) {
      $invoke = $preprocess_invoke_map[$preprocess_callback];
      $extension_type = isset($invoke['module']) ? 'module' : 'theme';
      $extension_machine = (string) ($invoke[$extension_type] ?? '');
      $hook_name = (string) ($invoke['hook'] ?? '');
      $handler = $extension_type === 'module' ? $module_handler : $theme_manager;
      $handler->invokeAllWith($hook_name, static function (callable $listener, string $provider) use (
        &$selected_preprocess_bindings,
        $extension_machine,
        $extension_type,
        $hook_name,
        $match_candidate_callable,
      ): void {
        if ($provider !== $extension_machine) return;
        $matches = $match_candidate_callable($listener, $extension_type, $provider, $hook_name, ['preprocess_node', 'template_preprocess_hook']);
        if (count($matches) === 0) return;
        if (count($matches) !== 1) throw new \RuntimeException('selected_preprocess_hook_not_uniquely_inventoried');
        $binding = reset($matches);
        $key = implode("\0", [(string) ($binding['extensionId'] ?? ''), (string) ($binding['sourceFileId'] ?? ''), (string) ($binding['surfaceId'] ?? '')]);
        $selected_preprocess_bindings[$key] = $binding;
      });
      continue;
    }
    if (!is_callable($preprocess_callback)) continue;
    [$class, $method, $function, $file] = $callable_details($preprocess_callback);
    foreach ($candidate_active_render_bindings as $binding) {
      if (!in_array((string) ($binding['selectorKind'] ?? ''), ['preprocess_node', 'template_preprocess_hook'], TRUE) ||
        (string) ($binding['sourceRealpath'] ?? '') !== $file) continue;
      $binding_class = ltrim((string) ($binding['runtimeClass'] ?? ''), '\\');
      $binding_method = (string) ($binding['runtimeMethod'] ?? '');
      $binding_function = (string) ($binding['runtimeFunction'] ?? '');
      if (!(($class !== '' && $binding_class === $class && $binding_method === $method) ||
        ($function !== '' && $binding_function === $function))) continue;
      $key = implode("\0", [(string) ($binding['extensionId'] ?? ''), (string) ($binding['sourceFileId'] ?? ''), (string) ($binding['surfaceId'] ?? '')]);
      $selected_preprocess_bindings[$key] = $binding;
    }
  }
  ksort($selected_preprocess_bindings, SORT_STRING);

  $base_hooks = [];
  foreach ($selected_registry_entries as $hook => $info) {
    $base_hook = (string) ($info['base hook'] ?? $hook);
    if ($base_hook !== '') $base_hooks[$base_hook] = TRUE;
  }
  $active_theme_suggestion_bindings = [];
  $theme_suggestion_alter_hooks = ['theme_suggestions_alter' => TRUE];
  foreach (array_keys($base_hooks) as $base_hook) {
    $theme_suggestion_alter_hooks['theme_suggestions_' . $base_hook . '_alter'] = TRUE;
  }
  foreach (array_keys($theme_suggestion_alter_hooks) as $suggestion_alter_hook) {
    $theme_manager->invokeAllWith($suggestion_alter_hook, static function (callable $listener, string $theme) use (
      &$active_theme_suggestion_bindings,
      $active_extensions_by_machine,
      $match_candidate_callable,
      $suggestion_alter_hook,
    ): void {
      if (!isset($active_extensions_by_machine[$theme])) return;
      $matches = $match_candidate_callable($listener, 'theme', $theme, $suggestion_alter_hook, ['theme_suggestion_hook']);
      if (count($matches) !== 1) throw new \RuntimeException('active_theme_suggestion_hook_not_uniquely_inventoried');
      $binding = reset($matches);
      $key = implode("\0", [(string) ($binding['extensionId'] ?? ''), (string) ($binding['sourceFileId'] ?? ''), (string) ($binding['surfaceId'] ?? '')]);
      $active_theme_suggestion_bindings[$key] = $binding;
    });
  }
  ksort($active_theme_suggestion_bindings, SORT_STRING);

  $active_module_selected_bindings = [];
  $module_suggestion_hooks = ['theme_suggestions_alter' => TRUE];
  foreach (array_keys($base_hooks) as $base_hook) {
    $module_suggestion_hooks['theme_suggestions_' . $base_hook] = TRUE;
    $module_suggestion_hooks['theme_suggestions_' . $base_hook . '_alter'] = TRUE;
  }
  foreach ($active_module_render_bindings as $binding) {
    $selector_kind = (string) ($binding['selectorKind'] ?? '');
    $hook_name = (string) ($binding['hookName'] ?? '');
    if (!(($entity_view_handler && $selector_kind === 'node_render_hook') ||
      ($selector_kind === 'theme_suggestion_hook' && isset($module_suggestion_hooks[$hook_name])))) continue;
    $key = implode("\0", [(string) ($binding['extensionId'] ?? ''), (string) ($binding['sourceFileId'] ?? ''), (string) ($binding['surfaceId'] ?? '')]);
    $active_module_selected_bindings[$key] = $binding;
  }
  ksort($active_module_selected_bindings, SORT_STRING);

  $active_theme_extension_ids = [];
  foreach ($active_theme_machines as $machine) {
    $extension = $active_extensions_by_machine[$machine] ?? NULL;
    if (is_array($extension) && (string) ($extension['type'] ?? '') === 'theme') {
      $active_theme_extension_ids[] = (string) ($extension['id'] ?? '');
    }
  }
  sort($active_theme_extension_ids, SORT_STRING);
  $render_hook_bindings = array_merge(
    array_values($active_module_selected_bindings),
    array_values($selected_preprocess_bindings),
    array_values($active_theme_suggestion_bindings),
  );
  return [$selected_template_paths, array_values($selected_template_bindings), $render_hook_bindings, $active_theme_extension_ids];
};
$resolve_field_formatters = static function (array $rendered_build) use ($candidate_active_render_bindings, $limits): array {
  $plugin_manager = \Drupal::service('plugin.manager.field.formatter');
  $plugin_ids = [];
  $visited = 0;
  $collect_plugin_ids = static function (array $element, int $depth = 0) use (&$collect_plugin_ids, &$plugin_ids, &$visited, $limits): void {
    $visited++;
    if ($depth > 64 || $visited > (int) ($limits['metadataItemsTotal'] ?? 0)) {
      throw new \RuntimeException('rendered_formatter_scan_limit_exceeded');
    }
    if (isset($element['#formatter']) && is_string($element['#formatter']) && $element['#formatter'] !== '') {
      $plugin_ids[$element['#formatter']] = TRUE;
    }
    foreach ($element as $key => $value) {
      // Render-array children cannot use property keys beginning with '#'.
      // Skipping property payloads avoids walking arbitrary cache/attribute data.
      if (is_array($value) && !(is_string($key) && str_starts_with($key, '#'))) {
        $collect_plugin_ids($value, $depth + 1);
      }
    }
  };
  $collect_plugin_ids($rendered_build);
  ksort($plugin_ids, SORT_STRING);
  $runtime_identities = [];
  $selected_bindings = [];
  foreach (array_keys($plugin_ids) as $plugin_id) {
    $definition = $plugin_manager->getDefinition($plugin_id, FALSE);
    $class = is_array($definition)
      ? (string) ($definition['class'] ?? '')
      : (is_object($definition) && method_exists($definition, 'getClass') ? (string) $definition->getClass() : '');
    if ($class === '' || !class_exists($class)) continue;
    $reflection = new \ReflectionClass($class);
    $formatter_realpath = str_replace('\\', '/', (string) (realpath((string) ($reflection->getFileName() ?: '')) ?: ''));
    if ($formatter_realpath === '') continue;
    foreach ($candidate_active_render_bindings as $binding) {
      if ((string) ($binding['selectorKind'] ?? '') !== 'field_formatter_plugin' ||
        (string) ($binding['runtimeClass'] ?? '') !== $class ||
        (string) ($binding['sourceRealpath'] ?? '') !== $formatter_realpath) continue;
      $binding_key = implode("\0", [
        (string) ($binding['extensionId'] ?? ''),
        (string) ($binding['sourceFileId'] ?? ''),
        (string) ($binding['surfaceId'] ?? ''),
      ]);
      $selected_bindings[$binding_key] = $binding;
      $binding_identity = (string) ($binding['runtimeIdentity'] ?? '');
      if ($binding_identity !== '') $runtime_identities[$binding_identity] = TRUE;
    }
  }
  ksort($runtime_identities, SORT_STRING);
  ksort($selected_bindings, SORT_STRING);
  return [array_keys($runtime_identities), array_values($selected_bindings)];
};
$controller_owner = static function (callable $controller, array $candidate_route) use ($hash_value): array {
  $class = '';
  $method = '';
  $file = '';
  try {
    if (is_array($controller) && count($controller) === 2) {
      $class = is_object($controller[0]) ? get_class($controller[0]) : ltrim((string) $controller[0], '\\');
      $method = (string) $controller[1];
      $reflection = new \ReflectionMethod($class, $method);
      $file = (string) ($reflection->getFileName() ?: '');
    }
    elseif ($controller instanceof \Closure || is_string($controller)) {
      $reflection = new \ReflectionFunction($controller);
      $file = (string) ($reflection->getFileName() ?: '');
      $method = $reflection->getName();
    }
    elseif (is_object($controller) && is_callable($controller)) {
      $class = get_class($controller);
      $method = '__invoke';
      $reflection = new \ReflectionMethod($class, $method);
      $file = (string) ($reflection->getFileName() ?: '');
    }
  }
  catch (\Throwable) {
    return ['', ''];
  }
  $normalized_class = ltrim($class, '\\');
  $normalized_file = $file !== '' ? str_replace('\\', '/', (string) (realpath($file) ?: $file)) : '';
  $expected_class = ltrim((string) ($candidate_route['controllerClass'] ?? ''), '\\');
  $expected_method = (string) ($candidate_route['controllerMethod'] ?? '');
  $expected_file = str_replace('\\', '/', (string) (realpath(DRUPAL_ROOT . '/' . ($candidate_route['controllerDrupalPath'] ?? '')) ?: ''));
  if (
    $expected_class !== '' && $expected_method !== '' && $expected_file !== '' &&
    (string) ($candidate_route['controllerSourceFileId'] ?? '') !== '' &&
    (string) ($candidate_route['controllerSurfaceId'] ?? '') !== '' &&
    $normalized_class === $expected_class && $method === $expected_method && $normalized_file === $expected_file
  ) {
    return [
      (string) ($candidate_route['extensionSubjectSha256'] ?? ''),
      $hash_value($normalized_class . "\0" . $method . "\0" . $normalized_file),
    ];
  }
  return ['', $hash_value($normalized_class . "\0" . $method . "\0" . $normalized_file)];
};
$custom_controller_owner = static function (callable $controller) use ($active_extensions_by_machine, $hash_value): array {
  $class = '';
  $method = '';
  $file = '';
  try {
    if (is_array($controller) && count($controller) === 2) {
      $class = is_object($controller[0]) ? get_class($controller[0]) : ltrim((string) $controller[0], '\\');
      $method = (string) $controller[1];
      $reflection = new \ReflectionMethod($class, $method);
      $file = (string) ($reflection->getFileName() ?: '');
    }
    elseif ($controller instanceof \Closure || is_string($controller)) {
      $reflection = new \ReflectionFunction($controller);
      $method = $reflection->getName();
      $file = (string) ($reflection->getFileName() ?: '');
    }
    elseif (is_object($controller) && is_callable($controller)) {
      $class = get_class($controller);
      $method = '__invoke';
      $reflection = new \ReflectionMethod($class, $method);
      $file = (string) ($reflection->getFileName() ?: '');
    }
  }
  catch (\Throwable) {
    return ['', ''];
  }
  $normalized_file = $file !== '' ? str_replace('\\', '/', (string) (realpath($file) ?: '')) : '';
  $identity_hash = $hash_value(ltrim($class, '\\') . "\0" . $method . "\0" . $normalized_file);
  if ($normalized_file === '') return ['', $identity_hash];
  foreach ($active_extensions_by_machine as $extension) {
    if ((string) ($extension['type'] ?? '') !== 'module') continue;
    $extension_root = str_replace('\\', '/', (string) (realpath(DRUPAL_ROOT . '/' . ($extension['drupalPath'] ?? '')) ?: ''));
    if ($extension_root !== '' && str_starts_with($normalized_file, $extension_root . '/')) {
      return [(string) ($extension['id'] ?? ''), $identity_hash];
    }
  }
  return ['', $identity_hash];
};

foreach (is_array($input['routes'] ?? NULL) ? $input['routes'] : [] as $route_input) {
  if (count($result['routes']) >= (int) ($limits['routes'] ?? 0)) {
    $violate('route_limit_exceeded');
    break;
  }
  $path = is_array($route_input) ? (string) ($route_input['path'] ?? '') : '';
  $route_declaration_ids = array_values(array_unique(array_map('strval', is_array($route_input['declarationIds'] ?? NULL) ? $route_input['declarationIds'] : [])));
  sort($route_declaration_ids);
  $route_declaration_set = array_fill_keys($route_declaration_ids, TRUE);
  $route_hash = $hash_value($path);
  $record = [
    'routeSha256' => $route_hash,
    'routeNameSha256' => '',
    'declarationBindingSha256' => $route_declaration_ids ? $hash_json($route_declaration_ids) : '',
    'candidateExtensionSetSha256' => $active_candidate_set_hash,
    'applies' => FALSE,
    'matched' => FALSE,
    'nodeBundleSha256' => '',
    'requestedEntityViewModeSha256' => '',
    'entityViewModeSha256' => '',
    'activeThemeExtensionSha256' => [],
    'selectedThemeTemplateSha256' => [],
    'selectedRenderHookSha256' => [],
    'selectedFieldFormatterSha256' => [],
    'outputHandlerKind' => '',
    'outputHandlerSha256' => '',
    'controllerExtensionSha256' => '',
    'candidateProvenanceKind' => '',
    'candidateExtensionSha256' => '',
    'candidateRouteSourceFileSha256' => '',
    'candidateRouteSurfaceSha256' => '',
    'candidateOutputSourceFileSha256' => '',
    'candidateOutputSurfaceSha256' => '',
    'candidateCoverage' => [],
    'routeAccess' => '',
    'routeAccessMetadataSha256' => '',
    'nodeSha256' => '',
    'rendered' => FALSE,
    'renderedMetadataSha256' => '',
    'renderedTagCount' => 0,
    'renderedContextCount' => 0,
    'renderedMaxAge' => 0,
    'coveredDeclarationCount' => 0,
    'coveredDeclarationSetSha256' => '',
    'dependencyCount' => 0,
    'dependencies' => [],
  ];
  $request = \Symfony\Component\HttpFoundation\Request::create($target_origin . (string) $path, 'GET');
  $request_stack->push($request);
  $account_switched = FALSE;
  try {
    $account_switcher->switchTo($anonymous);
    $account_switched = TRUE;
    $matched = $router->matchRequest($request);
    $request->attributes->add($matched);
    $route_name = (string) ($matched[\Drupal\Core\Routing\RouteObjectInterface::ROUTE_NAME] ?? '');
    $record['routeNameSha256'] = $hash_value($route_name);
    $candidate_route = $candidate_routes_by_name[$route_name] ?? NULL;
    if (is_array($candidate_route)) $record['applies'] = TRUE;
    $nodes = [];
    foreach ($request->attributes->all() as $parameter) {
      if ($parameter instanceof \Drupal\node\NodeInterface) $nodes[spl_object_id($parameter)] = $parameter;
    }
    if (count($nodes) !== 1) {
      $violate('route_did_not_resolve_exactly_one_node', $route_hash);
      $result['routes'][] = $record;
      continue;
    }
    /** @var \Drupal\node\NodeInterface $node */
    $node = reset($nodes);
    $bundle = (string) $node->bundle();
    $record['nodeBundleSha256'] = $hash_value($bundle);
    $record['nodeSha256'] = $hash_value('node' . "\0" . ($node->uuid() ?: (string) $node->id()));
    $selection_declarations = array_values(array_filter(
      $declarations_by_bundle[$bundle] ?? [],
      static fn (array $declaration): bool => isset($route_declaration_set[(string) ($declaration['id'] ?? '')]),
    ));
    $route_cache_invalidated = FALSE;
    $controller = NULL;
    $arguments = [];
    $entity_view_mode = '';
    $entity_view_build = NULL;
    $build = NULL;
    $render_context = NULL;
    $recorded_twig_realpaths = [];
    $route_candidate_coverage = [];
    $route_render_bindings = [];
    $route_object = $matched[\Drupal\Core\Routing\RouteObjectInterface::ROUTE_OBJECT] ?? NULL;
    $entity_view_default = $route_object instanceof \Symfony\Component\Routing\Route
      ? (string) ($route_object->getDefault('_entity_view') ?? '')
      : (string) ($matched['_entity_view'] ?? '');
    if ($entity_view_default !== '') {
      if (!preg_match('/^node\.([a-z][a-z0-9_]*)$/', $entity_view_default, $entity_view_match)) {
        $violate('route_entity_view_not_supported', $route_hash, $hash_value($entity_view_default));
        $result['routes'][] = $record;
        continue;
      }
      $requested_entity_view_mode = (string) $entity_view_match[1];
      $entity_view_mode = $requested_entity_view_mode;
      $record['requestedEntityViewModeSha256'] = $hash_value($requested_entity_view_mode);
      $record['outputHandlerKind'] = 'entity_view';
      // Do not instantiate view builders, formatters, or suggestion callbacks
      // until both the route and resolved Node are viewable anonymously.
      $preflight_route_access = $access_manager->checkRequest($request, $anonymous, TRUE);
      if (!$preflight_route_access->isAllowed()) {
        $record['routeAccess'] = $preflight_route_access->isForbidden() ? 'denied' : 'neutral';
        $preflight_tags = $bounded_metadata($preflight_route_access->getCacheTags(), 'route_access_tags', $route_hash);
        $preflight_contexts = $bounded_metadata($preflight_route_access->getCacheContexts(), 'route_access_contexts', $route_hash);
        if (is_array($preflight_tags) && is_array($preflight_contexts)) {
          $record['routeAccessMetadataSha256'] = $metadata_hash($preflight_tags, $preflight_contexts, (int) $preflight_route_access->getCacheMaxAge());
        }
        $violate('anonymous_route_access_not_allowed', $route_hash, $record['routeAccessMetadataSha256']);
        $result['routes'][] = $record;
        continue;
      }
      $preflight_node_access = $node->access('view', $anonymous, TRUE);
      if (!$preflight_node_access->isAllowed()) {
        $violate('anonymous_node_access_not_allowed', $route_hash, $record['nodeSha256']);
        $result['routes'][] = $record;
        continue;
      }
      $invalidate_route_render_cache($node, $selection_declarations, $route_hash);
      $route_cache_invalidated = $allow_invalidation;
      $entity_view_build = \Drupal::entityTypeManager()->getViewBuilder('node')->view($node, $entity_view_mode);
      if (!is_array($entity_view_build)) {
        $violate('entity_view_build_unavailable', $route_hash, $record['nodeSha256']);
        $result['routes'][] = $record;
        continue;
      }
      $effective_entity_view_mode = (string) ($entity_view_build['#view_mode'] ?? '');
      if (!preg_match('/^[a-z][a-z0-9_]*$/', $effective_entity_view_mode)) {
        $violate('effective_entity_view_mode_invalid', $route_hash, $hash_value($effective_entity_view_mode));
        $result['routes'][] = $record;
        continue;
      }
      $entity_view_mode = $effective_entity_view_mode;
      $record['entityViewModeSha256'] = $hash_value($effective_entity_view_mode);
      $record['outputHandlerSha256'] = $hash_value('entity_view' . "\0" . 'node' . "\0" . $requested_entity_view_mode . "\0" . $effective_entity_view_mode . "\0" . $route_name);

      // Force this local audit build through the actual pre-render, formatter,
      // suggestion, preprocess, and Twig pipeline even when render cache is
      // warm. This does not alter the entity or stored display configuration.
      $entity_view_build['#cache']['max-age'] = 0;
      [$build, $render_context, $recorded_twig_realpaths] = $capture_render(
        static fn (): array => $entity_view_build,
      );
      if (!is_array($build)) {
        $violate('route_output_not_render_array', $route_hash, $hash_value(get_debug_type($build)));
        $result['routes'][] = $record;
        continue;
      }
      [$selected_theme_paths, $selected_template_bindings, $active_render_hook_bindings, $active_theme_extension_ids] = $resolve_recorded_render($recorded_twig_realpaths, TRUE);
      $record['selectedThemeTemplateSha256'] = array_values(array_map($hash_value, $selected_theme_paths));
      sort($record['selectedThemeTemplateSha256'], SORT_STRING);
      $record['activeThemeExtensionSha256'] = array_values(array_map($hash_value, $active_theme_extension_ids));
      sort($record['activeThemeExtensionSha256'], SORT_STRING);
      $selected_render_hook_identities = array_values(array_unique(array_filter(array_map(
        static fn (array $binding): string => (string) ($binding['runtimeIdentity'] ?? ''),
        $active_render_hook_bindings,
      ))));
      sort($selected_render_hook_identities, SORT_STRING);
      $record['selectedRenderHookSha256'] = array_values(array_map($hash_value, $selected_render_hook_identities));
      sort($record['selectedRenderHookSha256'], SORT_STRING);
      [$field_formatter_identities, $field_formatter_bindings] = $resolve_field_formatters($build);
      $record['selectedFieldFormatterSha256'] = array_values(array_map($hash_value, $field_formatter_identities));
      sort($record['selectedFieldFormatterSha256'], SORT_STRING);
      $primary_render_binding = NULL;
      $primary_render_priority = -1;
      foreach (array_merge($active_render_hook_bindings, $field_formatter_bindings) as $binding) {
        $selector_kind = (string) ($binding['selectorKind'] ?? '');
        $route_render_bindings[] = $binding;
        $priority = match ($selector_kind) {
          'node_render_hook' => 6,
          'preprocess_node', 'template_preprocess_hook' => 5,
          'theme_suggestion_hook' => 4,
          'field_formatter_plugin' => 3,
          default => -1,
        };
        if ($priority > $primary_render_priority) {
          $primary_render_binding = $binding;
          $primary_render_priority = $priority;
        }
      }
      foreach ($selected_template_bindings as $selected_template_binding) {
        $route_render_bindings[] = $selected_template_binding;
        if (2 > $primary_render_priority) {
          $primary_render_binding = $selected_template_binding;
          $primary_render_priority = 2;
        }
      }
      if (is_array($candidate_route)) {
        $record['applies'] = TRUE;
        $record['candidateProvenanceKind'] = 'custom_route';
        $record['candidateExtensionSha256'] = $hash_value((string) ($candidate_route['extensionId'] ?? ''));
        $record['candidateRouteSourceFileSha256'] = $hash_value((string) ($candidate_route['routeSourceFileId'] ?? ''));
        $record['candidateRouteSurfaceSha256'] = $hash_value((string) ($candidate_route['routeSurfaceId'] ?? ''));
        $record['candidateOutputSourceFileSha256'] = $record['candidateRouteSourceFileSha256'];
        $record['candidateOutputSurfaceSha256'] = $record['candidateRouteSurfaceSha256'];
        $route_candidate_coverage[] = [
          'role' => 'custom_route',
          'extensionId' => (string) ($candidate_route['extensionId'] ?? ''),
          'sourceFileId' => (string) ($candidate_route['routeSourceFileId'] ?? ''),
          'surfaceId' => (string) ($candidate_route['routeSurfaceId'] ?? ''),
        ];
      }
      else {
        if (!is_array($primary_render_binding) || $primary_render_priority < 0) {
          $result['routes'][] = $record;
          continue;
        }
        $record['applies'] = TRUE;
        $primary_selector_kind = (string) ($primary_render_binding['selectorKind'] ?? '');
        $record['candidateProvenanceKind'] = in_array($primary_selector_kind, ['preprocess_node', 'template_preprocess_hook', 'node_render_hook', 'theme_suggestion_hook'], TRUE)
          ? 'render_hook'
          : ($primary_selector_kind === 'field_formatter_plugin' ? 'field_formatter' : 'default_theme_template');
        $record['candidateExtensionSha256'] = $hash_value((string) ($primary_render_binding['extensionId'] ?? ''));
        $record['candidateOutputSourceFileSha256'] = $hash_value((string) ($primary_render_binding['sourceFileId'] ?? ''));
        $record['candidateOutputSurfaceSha256'] = $hash_value((string) ($primary_render_binding['surfaceId'] ?? ''));
      }
    }
    else {
      $controller_definition = $route_object instanceof \Symfony\Component\Routing\Route
        ? (string) ($route_object->getDefault('_controller') ?? '')
        : (string) ($matched['_controller'] ?? '');
      if (!is_array($candidate_route)) {
        $preflight_route_access = $access_manager->checkRequest($request, $anonymous, TRUE);
        if (!$preflight_route_access->isAllowed()) {
          $record['routeAccess'] = $preflight_route_access->isForbidden() ? 'denied' : 'neutral';
          $violate('anonymous_route_access_not_allowed', $route_hash);
          $result['routes'][] = $record;
          continue;
        }
        $preflight_node_access = $node->access('view', $anonymous, TRUE);
        if (!$preflight_node_access->isAllowed()) {
          $violate('anonymous_node_access_not_allowed', $route_hash, $record['nodeSha256']);
          $result['routes'][] = $record;
          continue;
        }
        $resolved_controller = $controller_resolver->getController($request);
        if (!is_callable($resolved_controller)) {
          $violate('route_controller_not_resolvable', $route_hash, $hash_value($controller_definition));
          $result['routes'][] = $record;
          continue;
        }
        [$custom_controller_extension_id, $resolved_controller_hash] = $custom_controller_owner($resolved_controller);
        $record['outputHandlerKind'] = 'core_controller';
        $record['outputHandlerSha256'] = $resolved_controller_hash;
        if ($custom_controller_extension_id !== '') {
          $violate('route_altered_custom_controller_lacks_candidate_route_provenance', $route_hash, $hash_value($custom_controller_extension_id));
        }
        $result['routes'][] = $record;
        continue;
      }
      $record['applies'] = TRUE;
      $record['outputHandlerKind'] = 'candidate_controller';
      if ($controller_definition === '' || $controller_definition !== (string) ($candidate_route['controllerDefinition'] ?? '')) {
        $record['outputHandlerSha256'] = $hash_value('candidate_controller' . "\0" . $route_name . "\0" . $controller_definition);
        $violate('route_controller_lacks_exact_candidate_route_provenance', $route_hash, $record['routeNameSha256']);
        $result['routes'][] = $record;
        continue;
      }
      // Resolve neither the custom controller nor its arguments until the
      // anonymous route and resolved Node have passed their access preflight.
      $preflight_route_access = $access_manager->checkRequest($request, $anonymous, TRUE);
      if (!$preflight_route_access->isAllowed()) {
        $record['routeAccess'] = $preflight_route_access->isForbidden() ? 'denied' : 'neutral';
        $preflight_tags = $bounded_metadata($preflight_route_access->getCacheTags(), 'route_access_tags', $route_hash);
        $preflight_contexts = $bounded_metadata($preflight_route_access->getCacheContexts(), 'route_access_contexts', $route_hash);
        if (is_array($preflight_tags) && is_array($preflight_contexts)) {
          $record['routeAccessMetadataSha256'] = $metadata_hash($preflight_tags, $preflight_contexts, (int) $preflight_route_access->getCacheMaxAge());
        }
        $violate('anonymous_route_access_not_allowed', $route_hash, $record['routeAccessMetadataSha256']);
        $result['routes'][] = $record;
        continue;
      }
      $preflight_node_access = $node->access('view', $anonymous, TRUE);
      if (!$preflight_node_access->isAllowed()) {
        $violate('anonymous_node_access_not_allowed', $route_hash, $record['nodeSha256']);
        $result['routes'][] = $record;
        continue;
      }
      $invalidate_route_render_cache($node, $selection_declarations, $route_hash);
      $route_cache_invalidated = $allow_invalidation;
      $controller = $controller_resolver->getController($request);
      if (!is_callable($controller)) {
        $violate('route_controller_not_resolvable', $route_hash, $record['nodeSha256']);
        $result['routes'][] = $record;
        continue;
      }
      [$controller_extension_hash, $controller_hash] = $controller_owner($controller, $candidate_route);
      $record['outputHandlerSha256'] = $controller_hash;
      $record['controllerExtensionSha256'] = $controller_extension_hash;
      if ($controller_extension_hash === '') {
        $violate('route_controller_not_owned_by_candidate_extension', $route_hash, $controller_hash);
        $result['routes'][] = $record;
        continue;
      }
      $record['candidateProvenanceKind'] = 'custom_controller';
      $record['candidateExtensionSha256'] = $hash_value((string) ($candidate_route['extensionId'] ?? ''));
      $record['candidateRouteSourceFileSha256'] = $hash_value((string) ($candidate_route['routeSourceFileId'] ?? ''));
      $record['candidateRouteSurfaceSha256'] = $hash_value((string) ($candidate_route['routeSurfaceId'] ?? ''));
      $record['candidateOutputSourceFileSha256'] = $hash_value((string) ($candidate_route['controllerSourceFileId'] ?? ''));
      $record['candidateOutputSurfaceSha256'] = $hash_value((string) ($candidate_route['controllerSurfaceId'] ?? ''));
      $route_candidate_coverage[] = [
        'role' => 'custom_route',
        'extensionId' => (string) ($candidate_route['extensionId'] ?? ''),
        'sourceFileId' => (string) ($candidate_route['routeSourceFileId'] ?? ''),
        'surfaceId' => (string) ($candidate_route['routeSurfaceId'] ?? ''),
      ];
      $route_candidate_coverage[] = [
        'role' => 'custom_controller',
        'extensionId' => (string) ($candidate_route['extensionId'] ?? ''),
        'sourceFileId' => (string) ($candidate_route['controllerSourceFileId'] ?? ''),
        'surfaceId' => (string) ($candidate_route['controllerSurfaceId'] ?? ''),
      ];
      $arguments = $argument_resolver->getArguments($request, $controller);
    }
    $route_access = $access_manager->checkRequest($request, $anonymous, TRUE);
    $record['routeAccess'] = $route_access->isAllowed() ? 'allowed' : ($route_access->isForbidden() ? 'denied' : 'neutral');
    $route_access_tags = $bounded_metadata($route_access->getCacheTags(), 'route_access_tags', $route_hash);
    if ($route_access_tags === NULL) {
      $result['routes'][] = $record;
      continue;
    }
    $route_access_contexts = $bounded_metadata($route_access->getCacheContexts(), 'route_access_contexts', $route_hash);
    if ($route_access_contexts === NULL) {
      $result['routes'][] = $record;
      continue;
    }
    $route_access_max_age = (int) $route_access->getCacheMaxAge();
    $record['routeAccessMetadataSha256'] = $metadata_hash($route_access_tags, $route_access_contexts, $route_access_max_age);
    if (!$route_access->isAllowed()) {
      $violate('anonymous_route_access_not_allowed', $route_hash, $record['routeAccessMetadataSha256']);
      $result['routes'][] = $record;
      continue;
    }
    $declarations = array_values(array_filter(
      $declarations_by_bundle[$bundle] ?? [],
      static fn (array $declaration): bool => isset($route_declaration_set[(string) ($declaration['id'] ?? '')]),
    ));
    $resolved_declaration_ids = array_values(array_unique(array_map(
      static fn (array $declaration): string => (string) ($declaration['id'] ?? ''),
      $declarations,
    )));
    sort($resolved_declaration_ids);
    if (!$declarations || $resolved_declaration_ids !== $route_declaration_ids) {
      $violate('route_node_bundle_has_no_bound_media_output', $route_hash, $record['nodeBundleSha256']);
      $result['routes'][] = $record;
      continue;
    }
    $node_access = $node->access('view', $anonymous, TRUE);
    if (!$node_access->isAllowed()) {
      $violate('anonymous_node_access_not_allowed', $route_hash, $record['nodeSha256']);
      $result['routes'][] = $record;
      continue;
    }

    $entities = [['entity' => $node, 'type' => 'node', 'fieldPath' => 'node-root', 'access' => $node_access]];
    $chain_count = 0;
    $declaration_chain_counts = array_fill_keys($resolved_declaration_ids, 0);
    $declaration_dependency_owners = [];
    foreach ($declarations as $declaration) {
      $declaration_id = (string) ($declaration['id'] ?? '');
      $field_name = (string) ($declaration['fieldName'] ?? '');
      $field_path_hash = $hash_value('node' . "\0" . $bundle . "\0" . $field_name);
      if (!$node->hasField($field_name)) {
        $violate('declared_node_media_field_missing', $route_hash, $field_path_hash);
        continue;
      }
      $definition = $node->getFieldDefinition($field_name);
      $settings = $definition->getSettings();
      if ($definition->getType() !== 'entity_reference' || (string) ($settings['target_type'] ?? '') !== 'media') {
        $violate('declared_node_media_field_type_mismatch', $route_hash, $field_path_hash);
        continue;
      }
      $media_items = $node->get($field_name);
      $remaining_route_dependencies = max(0, (int) ($limits['dependenciesPerRoute'] ?? 0) - count($entities));
      $remaining_total_dependencies = max(0, (int) ($limits['dependenciesTotal'] ?? 0) - $total_dependencies - count($entities));
      if (count($media_items) > min($remaining_route_dependencies, $remaining_total_dependencies)) {
        $violate('dependency_reference_item_limit_exceeded', $route_hash, $field_path_hash);
        continue;
      }
      foreach ($media_items as $media_item) {
        if (count($entities) >= (int) ($limits['dependenciesPerRoute'] ?? 0) ||
          $total_dependencies + count($entities) >= (int) ($limits['dependenciesTotal'] ?? 0)) {
          $violate('dependency_entity_load_limit_exceeded', $route_hash, $field_path_hash);
          break 2;
        }
        $media = $media_item->entity;
        if (!$media instanceof \Drupal\media\MediaInterface) {
          $violate('declared_node_reference_is_not_media', $route_hash, $field_path_hash);
          continue;
        }
        $media_access = $media->access('view', $anonymous, TRUE);
        $media_hash = $hash_value('media' . "\0" . ($media->uuid() ?: (string) $media->id()));
        if (!$media_access->isAllowed()) {
          $violate('anonymous_dependency_access_not_allowed', $route_hash, $media_hash);
          continue;
        }
        if (isset($declaration_dependency_owners[$media_hash])) {
          if ($declaration_dependency_owners[$media_hash] !== $declaration_id) {
            $violate('ambiguous_declaration_dependency_provenance', $route_hash, $media_hash);
          }
          continue;
        }
        $declaration_dependency_owners[$media_hash] = $declaration_id;
        $entities[] = ['entity' => $media, 'type' => 'media', 'fieldPath' => $field_name, 'access' => $media_access];
        $configuration = $media->getSource()->getConfiguration();
        $source_field = (string) ($configuration['source_field'] ?? '');
        if ($source_field === '' || !$media->hasField($source_field)) {
          $violate('media_source_field_unavailable', $route_hash, $media_hash);
          continue;
        }
        $source_definition = $media->getFieldDefinition($source_field);
        $source_settings = $source_definition->getSettings();
        if (!in_array($source_definition->getType(), ['image', 'file', 'entity_reference'], TRUE) || (string) ($source_settings['target_type'] ?? 'file') !== 'file') {
          $violate('media_source_field_is_not_file_reference', $route_hash, $media_hash);
          continue;
        }
        $file_items = $media->get($source_field);
        if (count($file_items) === 0) {
          $violate('media_source_has_no_file', $route_hash, $media_hash);
          continue;
        }
        $remaining_route_dependencies = max(0, (int) ($limits['dependenciesPerRoute'] ?? 0) - count($entities));
        $remaining_total_dependencies = max(0, (int) ($limits['dependenciesTotal'] ?? 0) - $total_dependencies - count($entities));
        if (count($file_items) > min($remaining_route_dependencies, $remaining_total_dependencies)) {
          $violate('dependency_reference_item_limit_exceeded', $route_hash, $media_hash);
          continue;
        }
        foreach ($file_items as $file_item) {
          if (count($entities) >= (int) ($limits['dependenciesPerRoute'] ?? 0) ||
            $total_dependencies + count($entities) >= (int) ($limits['dependenciesTotal'] ?? 0)) {
            $violate('dependency_entity_load_limit_exceeded', $route_hash, $media_hash);
            break 3;
          }
          $file = $file_item->entity;
          if (!$file instanceof \Drupal\file\FileInterface) {
            $violate('media_source_reference_is_not_file', $route_hash, $media_hash);
            continue;
          }
          $file_access = $file->access('view', $anonymous, TRUE);
          $file_hash = $hash_value('file' . "\0" . ($file->uuid() ?: (string) $file->id()));
          if (!$file_access->isAllowed()) {
            $violate('anonymous_dependency_access_not_allowed', $route_hash, $file_hash);
            continue;
          }
          if (isset($declaration_dependency_owners[$file_hash])) {
            if ($declaration_dependency_owners[$file_hash] !== $declaration_id) {
              $violate('ambiguous_declaration_dependency_provenance', $route_hash, $file_hash);
            }
            continue;
          }
          $declaration_dependency_owners[$file_hash] = $declaration_id;
          $entities[] = [
            'entity' => $file,
            'type' => 'file',
            'fieldPath' => $field_name . "\0" . $source_field,
            'access' => $file_access,
          ];
          $chain_count++;
          $declaration_chain_counts[$declaration_id]++;
        }
      }
    }
    $covered_route_declaration_ids = [];
    foreach ($declaration_chain_counts as $declaration_id => $declaration_chain_count) {
      if ($declaration_chain_count > 0) {
        $covered_route_declaration_ids[] = (string) $declaration_id;
        $covered_declaration_set[(string) $declaration_id] = TRUE;
      }
      else {
        $violate('declared_node_media_field_has_no_complete_file_chain', $route_hash, $hash_value((string) $declaration_id));
      }
    }
    sort($covered_route_declaration_ids);
    $record['coveredDeclarationCount'] = count($covered_route_declaration_ids);
    $record['coveredDeclarationSetSha256'] = $covered_route_declaration_ids ? $hash_json($covered_route_declaration_ids) : '';
    if ($chain_count === 0) {
      $violate('route_has_no_node_media_file_chain', $route_hash, $record['nodeSha256']);
      $result['routes'][] = $record;
      continue;
    }
    if ($covered_route_declaration_ids !== $route_declaration_ids) {
      $violate('route_did_not_cover_every_bound_declaration', $route_hash, $record['coveredDeclarationSetSha256']);
      $result['routes'][] = $record;
      continue;
    }
    $record['matched'] = TRUE;

    if (!$render_context instanceof \Drupal\Core\Render\RenderContext) {
      [$build, $render_context, $recorded_twig_realpaths] = $capture_render(
        static fn () => call_user_func_array($controller, $arguments),
      );
      if (is_array($build)) {
        [$selected_theme_paths, $selected_template_bindings, $active_render_hook_bindings, $active_theme_extension_ids] = $resolve_recorded_render($recorded_twig_realpaths, FALSE);
        $record['selectedThemeTemplateSha256'] = array_values(array_map($hash_value, $selected_theme_paths));
        sort($record['selectedThemeTemplateSha256'], SORT_STRING);
        $record['activeThemeExtensionSha256'] = array_values(array_map($hash_value, $active_theme_extension_ids));
        sort($record['activeThemeExtensionSha256'], SORT_STRING);
        $selected_render_hook_identities = array_values(array_unique(array_filter(array_map(
          static fn (array $binding): string => (string) ($binding['runtimeIdentity'] ?? ''),
          $active_render_hook_bindings,
        ))));
        sort($selected_render_hook_identities, SORT_STRING);
        $record['selectedRenderHookSha256'] = array_values(array_map($hash_value, $selected_render_hook_identities));
        sort($record['selectedRenderHookSha256'], SORT_STRING);
        [$field_formatter_identities, $field_formatter_bindings] = $resolve_field_formatters($build);
        $record['selectedFieldFormatterSha256'] = array_values(array_map($hash_value, $field_formatter_identities));
        sort($record['selectedFieldFormatterSha256'], SORT_STRING);
        $route_render_bindings = array_merge(
          $route_render_bindings,
          $active_render_hook_bindings,
          $field_formatter_bindings,
          $selected_template_bindings,
        );
      }
    }
    if (!is_array($build)) {
      $unsupported_hash = is_object($build) ? $hash_value(get_class($build)) : $hash_value(get_debug_type($build));
      $violate('route_output_not_render_array', $route_hash, $unsupported_hash);
      $result['routes'][] = $record;
      continue;
    }
    $bubble = $render_context->isEmpty() ? new \Drupal\Core\Render\BubbleableMetadata() : $render_context->pop();
    $rendered_tags = $bounded_metadata($bubble->getCacheTags(), 'rendered_cache_tags', $route_hash);
    if ($rendered_tags === NULL) {
      $result['routes'][] = $record;
      continue;
    }
    $rendered_contexts = $bounded_metadata($bubble->getCacheContexts(), 'rendered_cache_contexts', $route_hash);
    if ($rendered_contexts === NULL) {
      $result['routes'][] = $record;
      continue;
    }
    $rendered_max_age = (int) $bubble->getCacheMaxAge();
    $record['rendered'] = TRUE;
    $record['renderedTagCount'] = count($rendered_tags);
    $record['renderedContextCount'] = count($rendered_contexts);
    $record['renderedMaxAge'] = $rendered_max_age;
    $record['renderedMetadataSha256'] = $metadata_hash($rendered_tags, $rendered_contexts, $rendered_max_age);
    $route_coverage_by_key = [];
    foreach (array_merge($route_candidate_coverage, $route_render_bindings) as $coverage) {
      $selector_kind = (string) ($coverage['selectorKind'] ?? '');
      $role = (string) ($coverage['role'] ?? '');
      if ($role === '') {
        $role = in_array($selector_kind, ['preprocess_node', 'template_preprocess_hook', 'node_render_hook', 'theme_suggestion_hook'], TRUE)
          ? 'render_hook'
          : ($selector_kind === 'field_formatter_plugin' ? 'field_formatter' : 'render_template');
      }
      $extension_id = (string) ($coverage['extensionId'] ?? '');
      $source_file_id = (string) ($coverage['sourceFileId'] ?? '');
      $surface_id = (string) ($coverage['surfaceId'] ?? '');
      if ($extension_id === '' || $source_file_id === '' || $surface_id === '') {
        $violate('candidate_route_coverage_identity_missing', $route_hash);
        continue;
      }
      $row = [
        'role' => $role,
        'extensionSha256' => $hash_value($extension_id),
        'sourceFileSha256' => $hash_value($source_file_id),
        'surfaceSha256' => $hash_value($surface_id),
      ];
      $key = implode("\0", array_values($row));
      $route_coverage_by_key[$key] = $row;
      $covered_candidate_source_file_set[$source_file_id] = TRUE;
      $covered_candidate_surface_set[$surface_id] = TRUE;
    }
    ksort($route_coverage_by_key, SORT_STRING);
    if (count($route_coverage_by_key) > (int) ($limits['candidateCoveragePerRoute'] ?? 0)) {
      $violate('candidate_route_coverage_limit_exceeded', $route_hash);
    }
    elseif ($candidate_coverage_total + count($route_coverage_by_key) > (int) ($limits['candidateCoverageTotal'] ?? 0)) {
      $violate('candidate_coverage_total_limit_exceeded', $route_hash);
    }
    else {
      $candidate_coverage_total += count($route_coverage_by_key);
      $record['candidateCoverage'] = array_values($route_coverage_by_key);
    }

    $seen_entities = [];
    foreach ($entities as $dependency) {
      $entity = $dependency['entity'];
      $entity_type = (string) $dependency['type'];
      $entity_hash = $hash_value($entity_type . "\0" . ($entity->uuid() ?: (string) $entity->id()));
      if (isset($seen_entities[$entity_hash])) continue;
      $seen_entities[$entity_hash] = TRUE;
      $total_dependencies++;
      if ($total_dependencies > (int) ($limits['dependenciesTotal'] ?? 0)) {
        $violate('dependency_total_limit_exceeded', $route_hash);
        break;
      }
      $access = $dependency['access'];
      $entity_tags = $bounded_metadata($entity->getCacheTags(), 'entity_cache_tags', $route_hash, $entity_hash);
      if ($entity_tags === NULL) break;
      $invalidation_tags = method_exists($entity, 'getCacheTagsToInvalidate')
        ? $bounded_metadata($entity->getCacheTagsToInvalidate(), 'entity_invalidation_tags', $route_hash, $entity_hash)
        : [];
      if ($invalidation_tags === NULL) break;
      $access_tags = $bounded_metadata($access->getCacheTags(), 'entity_access_tags', $route_hash, $entity_hash);
      if ($access_tags === NULL) break;
      $access_contexts = $bounded_metadata($access->getCacheContexts(), 'entity_access_contexts', $route_hash, $entity_hash);
      if ($access_contexts === NULL) break;
      $access_max_age = (int) $access->getCacheMaxAge();
      if (!$access->isAllowed()) $violate('anonymous_dependency_access_not_allowed', $route_hash, $entity_hash);
      if (!$set_subset($entity_tags, $rendered_tags)) $violate('render_missing_entity_cache_tags', $route_hash, $entity_hash);
      if (!$set_subset($invalidation_tags, $rendered_tags)) $violate('render_missing_invalidation_cache_tags', $route_hash, $entity_hash);
      if (!$set_subset($access_tags, $rendered_tags) || !$set_subset($access_contexts, $rendered_contexts)) {
        $violate('render_missing_access_cache_metadata', $route_hash, $entity_hash);
      }
      if ($access_max_age !== \Drupal\Core\Cache\Cache::PERMANENT && (
        $rendered_max_age === \Drupal\Core\Cache\Cache::PERMANENT ||
        $rendered_max_age > $access_max_age
      )) {
        $violate('render_access_max_age_is_too_permissive', $route_hash, $entity_hash);
      }
      $intersection = count(array_intersect($invalidation_tags, $rendered_tags));
      $record['dependencies'][] = [
        'entityType' => $entity_type,
        'entitySha256' => $entity_hash,
        'fieldPathSha256' => $hash_value((string) $dependency['fieldPath']),
        'access' => $access->isAllowed() ? 'allowed' : ($access->isForbidden() ? 'denied' : 'neutral'),
        'accessMetadataSha256' => $metadata_hash($access_tags, $access_contexts, $access_max_age),
        'cacheTagCount' => count($entity_tags),
        'invalidationTagCount' => count($invalidation_tags),
        'renderedTagIntersectionCount' => $intersection,
      ];
      if ($invalidation_tags) {
        $invalidation_tag_sets[$hash_json($invalidation_tags)] = $invalidation_tags;
      }
    }
    $record['dependencyCount'] = count($record['dependencies']);
  }
  catch (\Throwable $error) {
    $violate('route_entity_output_audit_failed', $route_hash, $hash_value(get_class($error) . "\0" . $error->getMessage()));
  }
  finally {
    if ($account_switched) $account_switcher->switchBack();
    $request_stack->pop();
  }
  $result['routes'][] = $record;
}
$result['routeCount'] = count($result['routes']);
$result['applicableRouteCount'] = count(array_filter($result['routes'], static fn (array $route): bool => ($route['applies'] ?? FALSE) === TRUE));
$result['matchedNodeRouteCount'] = count(array_filter($result['routes'], static fn (array $route): bool => ($route['matched'] ?? FALSE) === TRUE));
$result['renderedRouteCount'] = count(array_filter($result['routes'], static fn (array $route): bool => ($route['rendered'] ?? FALSE) === TRUE));
$result['dependencyCount'] = array_sum(array_map(static fn (array $route): int => count($route['dependencies'] ?? []), $result['routes']));
$covered_declaration_ids = array_keys($covered_declaration_set);
sort($covered_declaration_ids);
$result['coveredDeclarationCount'] = count($covered_declaration_ids);
$result['coveredDeclarationSetSha256'] = $covered_declaration_ids ? $hash_json($covered_declaration_ids) : '';
$covered_candidate_source_file_ids = array_keys($covered_candidate_source_file_set);
sort($covered_candidate_source_file_ids);
$covered_candidate_source_file_hashes = array_map($hash_value, $covered_candidate_source_file_ids);
sort($covered_candidate_source_file_hashes, SORT_STRING);
$result['coveredCandidateSourceFileCount'] = count($covered_candidate_source_file_ids);
$result['coveredCandidateSourceFileSetSha256'] = $covered_candidate_source_file_hashes ? $hash_json($covered_candidate_source_file_hashes) : '';
$covered_candidate_surface_ids = array_keys($covered_candidate_surface_set);
sort($covered_candidate_surface_ids);
$covered_candidate_surface_hashes = array_map($hash_value, $covered_candidate_surface_ids);
sort($covered_candidate_surface_hashes, SORT_STRING);
$result['coveredCandidateSurfaceCount'] = count($covered_candidate_surface_ids);
$result['coveredCandidateSurfaceSetSha256'] = $covered_candidate_surface_hashes ? $hash_json($covered_candidate_surface_hashes) : '';
foreach ($result['routes'] as $route) {
  if (($route['applies'] ?? FALSE) === TRUE && (($route['matched'] ?? FALSE) !== TRUE || ($route['rendered'] ?? FALSE) !== TRUE)) {
    $violate('applicable_route_runtime_incomplete', (string) ($route['routeSha256'] ?? ''));
  }
}

if ($allow_invalidation) {
  if ($result['applicableRouteCount'] === 0) {
    $result['invalidation']['status'] = $result['invalidation']['preCaptureAttempted']
      ? 'pre_capture_performed_not_applicable'
      : 'not_run_due_to_not_applicable';
  }
  else {
    if (!$result['violations'] && !$invalidation_tag_sets) {
      $violate('no_entity_invalidation_tag_sets');
    }
    if ($result['violations']) {
      $result['invalidation']['status'] = $result['invalidation']['preCaptureAttempted']
        ? 'pre_capture_performed_proof_not_run_due_to_violations'
        : 'not_run_due_to_violations';
    }
    else {
    $result['invalidation']['status'] = 'running';
    $result['invalidation']['attempted'] = TRUE;
    $result['invalidation']['cleanupRequired'] = TRUE;
    $owner = (string) ($input['ownedCacheToken'] ?? '');
    $cache = \Drupal::cache('data');
    $invalidator = \Drupal::service('cache_tags.invalidator');
    $seeded_cids = [];
    $invalidation_evidence = [];
    try {
      foreach (array_values($invalidation_tag_sets) as $index => $tags) {
        $cid = 'custom-entity-output-audit:' . hash('sha256', $owner . "\0" . (string) $index);
        if ($cache->get($cid, TRUE) !== FALSE) throw new \RuntimeException('owned_cache_cid_preexisted');
        $cache->set($cid, ['ownerSha256' => $hash_value($owner)], \Drupal\Core\Cache\Cache::PERMANENT, $tags);
        $seeded_cids[$cid] = TRUE;
        $result['invalidation']['seededCount']++;
        $seed = $cache->get($cid, TRUE);
        if ($seed === FALSE || ($seed->data['ownerSha256'] ?? '') !== $hash_value($owner)) throw new \RuntimeException('owned_cache_seed_unreadable');
        $invalidator->invalidateTags($tags);
        if ($cache->get($cid) !== FALSE) throw new \RuntimeException('owned_cache_seed_not_invalidated');
        $result['invalidation']['invalidatedCount']++;
        $invalidation_evidence[] = $hash_json($tags);
      }
      $result['invalidation']['status'] = 'pass';
    }
    catch (\Throwable $error) {
      $result['invalidation']['status'] = 'fail';
      $violate('owned_cache_invalidation_proof_failed', '', $hash_value(get_class($error) . "\0" . $error->getMessage()));
    }
    finally {
      foreach (array_keys($seeded_cids) as $cid) {
        try {
          $cache->delete($cid);
          if ($cache->get($cid, TRUE) !== FALSE) $result['invalidation']['cleanupCompleted'] = FALSE;
        }
        catch (\Throwable) {
          $result['invalidation']['cleanupCompleted'] = FALSE;
        }
      }
      if (!$result['invalidation']['cleanupCompleted']) {
        $result['invalidation']['status'] = 'fail';
        $violate('owned_cache_cleanup_incomplete');
      }
    }
    sort($invalidation_evidence);
    $result['invalidation']['evidenceSha256'] = $hash_json($invalidation_evidence);
    }
  }
}

usort($result['routes'], static fn (array $left, array $right): int => strcmp($left['routeSha256'], $right['routeSha256']));
usort($result['violations'], static fn (array $left, array $right): int => strcmp(json_encode($left), json_encode($right)));
$result['completed'] = TRUE;
$result['status'] = $result['violations'] ? 'fail' : ($result['applicableRouteCount'] > 0 ? 'pass' : 'not_applicable');
print json_encode($result, JSON_UNESCAPED_SLASHES);
`;

export function buildCustomEntityOutputAuditPhp(derived, {
  allowOwnedCacheInvalidation = false,
  ownedCacheToken = ''
} = {}) {
  const auditInput = {
    schemaVersion: CUSTOM_ENTITY_OUTPUT_INPUT_SCHEMA,
    inputFingerprint: derived.inputFingerprint,
    targetOrigin: derived.targetOrigin,
    extensions: derived.extensions,
    candidateRouteBindings: derived.candidateRouteBindings,
    candidateRenderBindings: derived.candidateRenderBindings,
    candidateSourceFileIds: derived.candidateSourceFileIds,
    candidateSurfaceIds: derived.candidateSurfaceIds,
    declarations: derived.declarations.map(({ id, entityType, bundle, fieldName, targetEntityType }) => ({ id, entityType, bundle, fieldName, targetEntityType })),
    routes: derived.routes,
    allowOwnedCacheInvalidation,
    ownedCacheToken: allowOwnedCacheInvalidation ? ownedCacheToken : '',
    limits: {
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
    }
  };
  const serialized = JSON.stringify(auditInput);
  if (Buffer.byteLength(serialized, 'utf8') > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.phpInputBytes) {
    throw new Error(`Custom entity-output audit input exceeded ${CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.phpInputBytes} bytes.`);
  }
  const encoded = Buffer.from(serialized, 'utf8').toString('base64');
  return `$audit_input = json_decode(base64_decode('${encoded}', TRUE), TRUE, 512, JSON_THROW_ON_ERROR);\n${CUSTOM_ENTITY_OUTPUT_AUDIT_PHP}`;
}

export function parseCustomEntityOutputAudit(value, {
  expectedInputFingerprint,
  expectedTargetOrigin = '',
  expectedRouteCount,
  expectedRouteSha256 = [],
  expectedRouteBindings = [],
  expectedCandidateRouteBindings = [],
  expectedCandidateRenderBindings = [],
  expectedCandidateSourceFileIds = [],
  expectedCandidateSurfaceIds = [],
  expectedExtensions = [],
  expectedDeclarationIds = [],
  maximumActiveCandidateExtensionCount,
  allowOwnedCacheInvalidation = false
} = {}) {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  if (Buffer.byteLength(serialized, 'utf8') > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.outputBytes) {
    throw new Error('Custom entity-output audit output exceeded its byte limit.');
  }
  let audit;
  try {
    audit = typeof value === 'string' ? JSON.parse(value) : value;
  } catch {
    throw new Error('Custom entity-output audit returned invalid JSON.');
  }
  const expectedRouteBySha256 = new Map(expectedRouteBindings.map((route) => [sha256(route.path), route]));
  const expectedCandidateRouteByNameSha256 = new Map(expectedCandidateRouteBindings.map((binding) => [
    sha256(binding.routeName),
    {
      extensionSha256: sha256(binding.extensionId),
      routeSourceFileSha256: sha256(binding.routeSourceFileId),
      routeSurfaceSha256: sha256(binding.routeSurfaceId),
      controllerSourceFileSha256: binding.controllerSourceFileId ? sha256(binding.controllerSourceFileId) : '',
      controllerSurfaceSha256: binding.controllerSurfaceId ? sha256(binding.controllerSurfaceId) : ''
    }
  ]));
  const expectedCandidateRenderProvenance = expectedCandidateRenderBindings.map((binding) => ({
    provenanceKind: RENDER_HOOK_SELECTOR_KINDS.has(binding.selectorKind)
      ? 'render_hook'
      : binding.selectorKind === 'field_formatter_plugin'
        ? 'field_formatter'
      : 'default_theme_template',
    extensionSha256: sha256(binding.extensionId),
    extensionType: String(binding.extensionType ?? ''),
    outputSourceFileSha256: sha256(binding.sourceFileId),
    outputSurfaceSha256: sha256(binding.surfaceId),
    sourceDrupalPathSha256: sha256(binding.sourceDrupalPath),
    runtimeIdentitySha256: binding.runtimeIdentity
      ? sha256(binding.runtimeIdentity)
      : '',
    selectorKind: String(binding.selectorKind ?? ''),
    selectorValue: String(binding.selectorValue ?? '')
  }));
  const expectedRenderHookIdentitySha256 = new Set(expectedCandidateRenderProvenance
    .filter(({ selectorKind }) => RENDER_HOOK_SELECTOR_KINDS.has(selectorKind))
    .map(({ runtimeIdentitySha256 }) => runtimeIdentitySha256));
  const expectedFieldFormatterIdentitySha256 = new Set(expectedCandidateRenderProvenance
    .filter(({ selectorKind }) => selectorKind === 'field_formatter_plugin')
    .map(({ runtimeIdentitySha256 }) => runtimeIdentitySha256));
  const normalizedExpectedDeclarationIds = uniqueSorted(expectedDeclarationIds);
  const normalizedExpectedCandidateSourceFileIds = uniqueSorted(expectedCandidateSourceFileIds);
  const normalizedExpectedCandidateSurfaceIds = uniqueSorted(expectedCandidateSurfaceIds);
  const expectedCandidateSourceFileSha256 = new Set(normalizedExpectedCandidateSourceFileIds.map((id) => sha256(id)));
  const expectedCandidateSurfaceSha256 = new Set(normalizedExpectedCandidateSurfaceIds.map((id) => sha256(id)));
  const expectedExtensionBySha256 = new Map(expectedExtensions.map((extension) => [
    sha256(extension.id),
    { type: String(extension.type ?? ''), machineName: String(extension.machineName ?? '') }
  ]));
  const validateExpectedApplicability = expectedRouteBindings.length > 0 && (
    expectedCandidateRouteBindings.length > 0 || expectedCandidateRenderBindings.length > 0 ||
    expectedCandidateSourceFileIds.length > 0 || expectedCandidateSurfaceIds.length > 0 || expectedExtensions.length > 0
  );
  exactKeys(audit, [
    'schemaVersion', 'bounded', 'completed', 'status', 'noExplicitVerifierMutation', 'allowOwnedCacheInvalidation',
    'inputFingerprint', 'targetOriginSha256', 'activeCandidateExtensionCount', 'activeCandidateExtensionSha256',
    'defaultThemeExtensionSha256', 'routeCount', 'applicableRouteCount', 'matchedNodeRouteCount',
    'renderedRouteCount', 'dependencyCount', 'coveredDeclarationCount', 'coveredDeclarationSetSha256',
    'coveredCandidateSourceFileCount', 'coveredCandidateSourceFileSetSha256',
    'coveredCandidateSurfaceCount', 'coveredCandidateSurfaceSetSha256',
    'routes', 'invalidation', 'violations'
  ], 'Custom entity-output audit');
  if (audit.schemaVersion !== CUSTOM_ENTITY_OUTPUT_AUDIT_SCHEMA || audit.bounded !== true || audit.completed !== true) {
    throw new Error('Custom entity-output audit did not return a completed bounded schema.');
  }
  if (!['pass', 'fail', 'not_applicable'].includes(audit.status)) throw new Error('Custom entity-output audit has an invalid status.');
  assertBoolean(audit.noExplicitVerifierMutation, 'Custom entity-output audit noExplicitVerifierMutation');
  assertBoolean(audit.allowOwnedCacheInvalidation, 'Custom entity-output audit allowOwnedCacheInvalidation');
  if (audit.allowOwnedCacheInvalidation !== allowOwnedCacheInvalidation || audit.noExplicitVerifierMutation === allowOwnedCacheInvalidation) {
    throw new Error('Custom entity-output audit mutation mode does not match the caller.');
  }
  assertHash(audit.inputFingerprint, 'Custom entity-output audit input fingerprint');
  if (expectedInputFingerprint && audit.inputFingerprint !== expectedInputFingerprint) {
    throw new Error('Custom entity-output audit is not bound to the requested input.');
  }
  assertHash(audit.targetOriginSha256, 'Custom entity-output audit target origin');
  if (expectedTargetOrigin && audit.targetOriginSha256 !== sha256(expectedTargetOrigin)) {
    throw new Error('Custom entity-output audit is not bound to the exact target origin.');
  }
  for (const [key, maximum] of [
    ['activeCandidateExtensionCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.extensions],
    ['routeCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes],
    ['applicableRouteCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes],
    ['matchedNodeRouteCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes],
    ['renderedRouteCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.routes],
    ['dependencyCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesTotal],
    ['coveredDeclarationCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.declarations],
    ['coveredCandidateSourceFileCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSourceFiles],
    ['coveredCandidateSurfaceCount', CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces]
  ]) assertCount(audit[key], maximum, `Custom entity-output audit ${key}`);
  if (!Array.isArray(audit.activeCandidateExtensionSha256) ||
    audit.activeCandidateExtensionSha256.length !== audit.activeCandidateExtensionCount ||
    audit.activeCandidateExtensionSha256.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.extensions ||
    JSON.stringify(audit.activeCandidateExtensionSha256) !== JSON.stringify(uniqueSorted(audit.activeCandidateExtensionSha256))) {
    throw new Error('Custom entity-output audit active candidate extension set is inconsistent.');
  }
  for (const hash of audit.activeCandidateExtensionSha256) {
    assertHash(hash, 'Custom entity-output audit active candidate extension');
    if (expectedExtensionBySha256.size > 0 && !expectedExtensionBySha256.has(hash)) {
      throw new Error('Custom entity-output audit reported an uninventoried active extension.');
    }
  }
  assertHash(audit.defaultThemeExtensionSha256, 'Custom entity-output audit default theme extension', true);
  if (audit.defaultThemeExtensionSha256 && (
    !audit.activeCandidateExtensionSha256.includes(audit.defaultThemeExtensionSha256) ||
    (expectedExtensionBySha256.size > 0 && expectedExtensionBySha256.get(audit.defaultThemeExtensionSha256)?.type !== 'theme')
  )) {
    throw new Error('Custom entity-output audit default theme is not an active inventoried candidate theme.');
  }
  assertHash(audit.coveredDeclarationSetSha256, 'Custom entity-output audit covered declaration set', true);
  if ((audit.coveredDeclarationCount === 0) !== (audit.coveredDeclarationSetSha256 === '')) {
    throw new Error('Custom entity-output audit covered declaration aggregate is inconsistent.');
  }
  for (const [countKey, hashKey, label] of [
    ['coveredCandidateSourceFileCount', 'coveredCandidateSourceFileSetSha256', 'candidate source file'],
    ['coveredCandidateSurfaceCount', 'coveredCandidateSurfaceSetSha256', 'candidate surface']
  ]) {
    assertHash(audit[hashKey], `Custom entity-output audit covered ${label} set`, true);
    if ((audit[countKey] === 0) !== (audit[hashKey] === '')) {
      throw new Error(`Custom entity-output audit covered ${label} aggregate is inconsistent.`);
    }
  }
  if (!Array.isArray(audit.routes) || audit.routes.length !== audit.routeCount) throw new Error('Custom entity-output audit route count is inconsistent.');
  if (Number.isSafeInteger(expectedRouteCount) && audit.routeCount !== expectedRouteCount) {
    throw new Error('Custom entity-output audit did not cover every requested public route.');
  }
  if (Number.isSafeInteger(maximumActiveCandidateExtensionCount) && audit.activeCandidateExtensionCount > maximumActiveCandidateExtensionCount) {
    throw new Error('Custom entity-output audit reported an uninventoried active extension.');
  }
  const actualRouteSha256 = audit.routes.map((route) => String(route?.routeSha256 ?? '')).sort(comparePortable);
  const requestedRouteSha256 = uniqueSorted(expectedRouteSha256);
  if (new Set(actualRouteSha256).size !== actualRouteSha256.length ||
    (requestedRouteSha256.length > 0 &&
      JSON.stringify(actualRouteSha256) !== JSON.stringify(requestedRouteSha256))) {
    throw new Error('Custom entity-output audit did not bind the exact unique requested route set.');
  }
  if (!Array.isArray(audit.violations) || audit.violations.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.violations) {
    throw new Error('Custom entity-output audit violations are outside their bound.');
  }
  let dependencyCount = 0;
  let applicableRouteCount = 0;
  let matchedRouteCount = 0;
  let renderedRouteCount = 0;
  let candidateCoverageTotal = 0;
  const coveredCandidateSourceFileSha256 = new Set();
  const coveredCandidateSurfaceSha256 = new Set();
  const expectedApplicableDeclarationIds = new Set();
  const activeCandidateExtensionSetSha256 = audit.activeCandidateExtensionSha256.length > 0
    ? sha256(audit.activeCandidateExtensionSha256)
    : '';
  for (const [index, route] of audit.routes.entries()) {
    exactKeys(route, [
      'routeSha256', 'routeNameSha256', 'declarationBindingSha256', 'candidateExtensionSetSha256',
      'applies', 'matched', 'nodeBundleSha256', 'requestedEntityViewModeSha256', 'entityViewModeSha256',
      'activeThemeExtensionSha256', 'selectedThemeTemplateSha256', 'selectedRenderHookSha256',
      'selectedFieldFormatterSha256',
      'outputHandlerKind', 'outputHandlerSha256',
      'controllerExtensionSha256', 'candidateProvenanceKind', 'candidateExtensionSha256',
      'candidateRouteSourceFileSha256', 'candidateRouteSurfaceSha256',
      'candidateOutputSourceFileSha256', 'candidateOutputSurfaceSha256', 'candidateCoverage',
      'routeAccess', 'routeAccessMetadataSha256', 'nodeSha256',
      'rendered', 'renderedMetadataSha256', 'renderedTagCount',
      'renderedContextCount', 'renderedMaxAge', 'coveredDeclarationCount',
      'coveredDeclarationSetSha256', 'dependencyCount', 'dependencies'
    ], `Custom entity-output audit route ${index}`);
    for (const key of ['routeSha256']) assertHash(route[key], `Custom entity-output audit route ${index} ${key}`);
    for (const key of [
      'routeNameSha256', 'declarationBindingSha256', 'candidateExtensionSetSha256', 'nodeBundleSha256',
      'requestedEntityViewModeSha256', 'entityViewModeSha256',
      'outputHandlerSha256', 'controllerExtensionSha256', 'candidateExtensionSha256',
      'candidateRouteSourceFileSha256', 'candidateRouteSurfaceSha256',
      'candidateOutputSourceFileSha256', 'candidateOutputSurfaceSha256',
      'coveredDeclarationSetSha256',
      'routeAccessMetadataSha256', 'nodeSha256', 'renderedMetadataSha256'
    ]) {
      assertHash(route[key], `Custom entity-output audit route ${index} ${key}`, true);
    }
    if (!['', 'candidate_controller', 'entity_view', 'core_controller'].includes(route.outputHandlerKind)) {
      throw new Error('Custom entity-output audit emitted an invalid output handler kind.');
    }
    if (!Array.isArray(route.selectedThemeTemplateSha256) ||
      route.selectedThemeTemplateSha256.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces ||
      JSON.stringify(route.selectedThemeTemplateSha256) !== JSON.stringify(uniqueSorted(route.selectedThemeTemplateSha256))) {
      throw new Error('Custom entity-output audit selected theme-template set is inconsistent.');
    }
    for (const hash of route.selectedThemeTemplateSha256) {
      assertHash(hash, `Custom entity-output audit route ${index} selected theme template`);
    }
    if (!Array.isArray(route.activeThemeExtensionSha256) ||
      route.activeThemeExtensionSha256.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.extensions ||
      JSON.stringify(route.activeThemeExtensionSha256) !== JSON.stringify(uniqueSorted(route.activeThemeExtensionSha256))) {
      throw new Error('Custom entity-output audit active route theme set is inconsistent.');
    }
    for (const hash of route.activeThemeExtensionSha256) {
      assertHash(hash, `Custom entity-output audit route ${index} active theme extension`);
      if (!audit.activeCandidateExtensionSha256.includes(hash) || expectedExtensionBySha256.get(hash)?.type !== 'theme') {
        throw new Error('Custom entity-output audit route names an inactive or uninventoried custom theme.');
      }
    }
    if (!Array.isArray(route.selectedRenderHookSha256) ||
      route.selectedRenderHookSha256.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces ||
      JSON.stringify(route.selectedRenderHookSha256) !== JSON.stringify(uniqueSorted(route.selectedRenderHookSha256))) {
      throw new Error('Custom entity-output audit selected render-hook set is inconsistent.');
    }
    for (const hash of route.selectedRenderHookSha256) {
      assertHash(hash, `Custom entity-output audit route ${index} selected render hook`);
      if (!expectedRenderHookIdentitySha256.has(hash)) {
        throw new Error('Custom entity-output audit selected render hook is not exactly inventoried.');
      }
    }
    if (!Array.isArray(route.selectedFieldFormatterSha256) ||
      route.selectedFieldFormatterSha256.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces ||
      JSON.stringify(route.selectedFieldFormatterSha256) !== JSON.stringify(uniqueSorted(route.selectedFieldFormatterSha256))) {
      throw new Error('Custom entity-output audit selected field-formatter set is inconsistent.');
    }
    for (const hash of route.selectedFieldFormatterSha256) {
      assertHash(hash, `Custom entity-output audit route ${index} selected field formatter`);
      if (!expectedFieldFormatterIdentitySha256.has(hash)) {
        throw new Error('Custom entity-output audit selected field formatter is not exactly inventoried.');
      }
    }
    if (route.candidateExtensionSetSha256 !== activeCandidateExtensionSetSha256) {
      throw new Error('Custom entity-output audit route is not bound to the exact active candidate extension set.');
    }
    if (!['', 'custom_route', 'custom_controller', 'field_formatter', 'render_hook', 'default_theme_template'].includes(route.candidateProvenanceKind)) {
      throw new Error('Custom entity-output audit emitted an invalid candidate provenance kind.');
    }
    if (!['', 'allowed', 'denied', 'neutral'].includes(route.routeAccess)) throw new Error('Custom entity-output audit emitted an invalid route access result.');
    assertBoolean(route.applies, `Custom entity-output audit route ${index} applies`);
    assertBoolean(route.matched, `Custom entity-output audit route ${index} matched`);
    assertBoolean(route.rendered, `Custom entity-output audit route ${index} rendered`);
    if (route.matched) matchedRouteCount += 1;
    if (route.rendered) renderedRouteCount += 1;
    if (route.rendered && !route.matched) throw new Error('Custom entity-output audit rendered an unmatched route.');
    if ((route.outputHandlerKind === 'entity_view') !==
      (route.requestedEntityViewModeSha256 !== '' && route.entityViewModeSha256 !== '')) {
      throw new Error('Custom entity-output audit entity-view mode evidence is inconsistent.');
    }
    if (!['entity_view', 'candidate_controller'].includes(route.outputHandlerKind) && (
      route.activeThemeExtensionSha256.length !== 0 || route.selectedThemeTemplateSha256.length !== 0 ||
      route.selectedRenderHookSha256.length !== 0 || route.selectedFieldFormatterSha256.length !== 0
    )) {
      throw new Error('Custom entity-output audit non-entity handler contains theme or formatter selection evidence.');
    }
    if (audit.status !== 'fail' && route.outputHandlerKind === 'entity_view' &&
      route.applies && route.selectedThemeTemplateSha256.length === 0) {
      throw new Error('Custom entity-output audit applicable entity-view route lacks exact selected template evidence.');
    }
    const expectedRoute = expectedRouteBySha256.get(route.routeSha256);
    const expectedRouteDeclarationIds = uniqueSorted(expectedRoute?.declarationIds ?? []);
    const expectedRouteBundles = uniqueSorted(expectedRoute?.bundles ?? []);
    if (expectedRoute && route.declarationBindingSha256 !== sha256(expectedRouteDeclarationIds)) {
      throw new Error('Custom entity-output audit route declaration binding is not exact.');
    }
    if (expectedRouteBundles.length === 1 && route.outputHandlerKind !== '' &&
      route.nodeBundleSha256 !== sha256(expectedRouteBundles[0])) {
      throw new Error('Custom entity-output audit route node bundle is not bound to the requested declaration route.');
    }
    const expectedRouteCoverage = expectedRouteCandidateCoverage({
      route,
      candidateRouteByNameSha256: expectedCandidateRouteByNameSha256,
      candidateRenderBindings: expectedCandidateRenderProvenance,
      activeExtensionSha256: audit.activeCandidateExtensionSha256
    });
    const expectedApplies = expectedRouteCoverage.length > 0;
    if (validateExpectedApplicability && audit.status !== 'fail' && route.applies !== expectedApplies) {
      throw new Error('Custom entity-output audit route applicability is not bound to active exact candidate provenance.');
    }
    if (route.applies) {
      applicableRouteCount += 1;
      for (const declarationId of expectedRouteDeclarationIds) expectedApplicableDeclarationIds.add(declarationId);
    }
    if ((route.matched || route.rendered) && !route.applies) {
      throw new Error('Custom entity-output audit completed runtime proof for a non-applicable route.');
    }
    if (!Array.isArray(route.candidateCoverage) || route.candidateCoverage.length > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateSurfaces) {
      throw new Error('Custom entity-output audit route candidate coverage is outside its bounded range.');
    }
    candidateCoverageTotal += route.candidateCoverage.length;
    if (candidateCoverageTotal > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.candidateCoverageTotal) {
      throw new Error('Custom entity-output audit candidate coverage exceeded its total bound.');
    }
    const normalizedRouteCandidateCoverage = [];
    for (const [coverageIndex, coverage] of route.candidateCoverage.entries()) {
      exactKeys(coverage, ['role', 'extensionSha256', 'sourceFileSha256', 'surfaceSha256'], `Custom entity-output candidate coverage ${index}.${coverageIndex}`);
      if (!CANDIDATE_COVERAGE_ROLES.has(coverage.role)) throw new Error('Custom entity-output audit emitted an invalid candidate coverage role.');
      for (const key of ['extensionSha256', 'sourceFileSha256', 'surfaceSha256']) {
        assertHash(coverage[key], `Custom entity-output candidate coverage ${index}.${coverageIndex} ${key}`);
      }
      if (!audit.activeCandidateExtensionSha256.includes(coverage.extensionSha256)) {
        throw new Error('Custom entity-output audit candidate coverage names an inactive extension.');
      }
      if (expectedCandidateSourceFileSha256.size > 0 && !expectedCandidateSourceFileSha256.has(coverage.sourceFileSha256)) {
        throw new Error('Custom entity-output audit candidate coverage names an uninventoried source file.');
      }
      if (expectedCandidateSurfaceSha256.size > 0 && !expectedCandidateSurfaceSha256.has(coverage.surfaceSha256)) {
        throw new Error('Custom entity-output audit candidate coverage names an uninventoried surface.');
      }
      normalizedRouteCandidateCoverage.push(coverage);
      coveredCandidateSourceFileSha256.add(coverage.sourceFileSha256);
      coveredCandidateSurfaceSha256.add(coverage.surfaceSha256);
    }
    if (JSON.stringify(normalizedRouteCandidateCoverage) !== JSON.stringify(uniqueSortedCandidateCoverage(normalizedRouteCandidateCoverage))) {
      throw new Error('Custom entity-output audit route candidate coverage is not exact, unique, and sorted.');
    }
    if (validateExpectedApplicability && route.rendered &&
      JSON.stringify(normalizedRouteCandidateCoverage) !== JSON.stringify(expectedRouteCoverage)) {
      throw new Error('Custom entity-output audit route did not cover the exact applicable candidate provenance set.');
    }
    if (!route.rendered && normalizedRouteCandidateCoverage.length > 0) {
      throw new Error('Custom entity-output audit reported candidate coverage before rendering completed.');
    }
    assertCount(route.renderedTagCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsPerSet, `Custom entity-output audit route ${index} renderedTagCount`);
    assertCount(route.renderedContextCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsPerSet, `Custom entity-output audit route ${index} renderedContextCount`);
    if (!Number.isSafeInteger(route.renderedMaxAge) || route.renderedMaxAge < -1) throw new Error('Custom entity-output audit has an invalid rendered max age.');
    assertCount(route.coveredDeclarationCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.declarations, `Custom entity-output audit route ${index} coveredDeclarationCount`);
    if ((route.coveredDeclarationCount === 0) !== (route.coveredDeclarationSetSha256 === '')) {
      throw new Error('Custom entity-output audit route covered declaration evidence is inconsistent.');
    }
    if (expectedRoute && route.coveredDeclarationCount > expectedRouteDeclarationIds.length) {
      throw new Error('Custom entity-output audit route over-reported covered declarations.');
    }
    assertCount(route.dependencyCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesPerRoute, `Custom entity-output audit route ${index} dependencyCount`);
    if (!Array.isArray(route.dependencies) || route.dependencies.length !== route.dependencyCount) throw new Error('Custom entity-output audit route dependency count is inconsistent.');
    dependencyCount += route.dependencyCount;
    for (const [dependencyIndex, dependency] of route.dependencies.entries()) {
      exactKeys(dependency, [
        'entityType', 'entitySha256', 'fieldPathSha256', 'access', 'accessMetadataSha256',
        'cacheTagCount', 'invalidationTagCount', 'renderedTagIntersectionCount'
      ], `Custom entity-output dependency ${index}.${dependencyIndex}`);
      if (!['node', 'media', 'file'].includes(dependency.entityType)) throw new Error('Custom entity-output audit emitted an unexpected entity type.');
      if (!['allowed', 'denied', 'neutral'].includes(dependency.access)) throw new Error('Custom entity-output audit emitted an invalid access result.');
      for (const key of ['entitySha256', 'fieldPathSha256', 'accessMetadataSha256']) assertHash(dependency[key], `Custom entity-output dependency ${key}`);
      for (const key of ['cacheTagCount', 'invalidationTagCount', 'renderedTagIntersectionCount']) {
        assertCount(dependency[key], CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsPerSet, `Custom entity-output dependency ${key}`);
      }
      if (dependency.renderedTagIntersectionCount > dependency.invalidationTagCount) throw new Error('Custom entity-output audit emitted an impossible cache-tag intersection.');
    }
    if (!route.applies && (
      route.candidateCoverage.length !== 0 || route.dependencyCount !== 0 || route.coveredDeclarationCount !== 0 ||
      route.coveredDeclarationSetSha256 !== '' || route.candidateProvenanceKind !== '' || route.candidateExtensionSha256 !== '' ||
      route.candidateRouteSourceFileSha256 !== '' || route.candidateRouteSurfaceSha256 !== '' ||
      route.candidateOutputSourceFileSha256 !== '' || route.candidateOutputSurfaceSha256 !== '' ||
      route.controllerExtensionSha256 !== '' || route.routeAccess !== '' || route.routeAccessMetadataSha256 !== '' ||
      route.renderedMetadataSha256 !== '' || route.renderedTagCount !== 0 || route.renderedContextCount !== 0 || route.renderedMaxAge !== 0
    )) {
      throw new Error('Custom entity-output audit non-applicable route contains runtime proof or candidate provenance.');
    }
    if (!route.applies && audit.status !== 'fail' && (
      !['entity_view', 'core_controller'].includes(route.outputHandlerKind) ||
      route.routeNameSha256 === '' || route.nodeBundleSha256 === '' || route.nodeSha256 === '' || route.outputHandlerSha256 === ''
    )) {
      throw new Error('Custom entity-output audit ignored a route without host-reconstructable core-only output evidence.');
    }
    if (route.matched) {
      if (route.rendered) {
        const entityTypes = new Set(route.dependencies.map((dependency) => dependency.entityType));
        if (!['node', 'media', 'file'].every((entityType) => entityTypes.has(entityType))) {
          throw new Error('Rendered custom entity-output route lacks a complete Node-Media-File dependency chain.');
        }
      }
      if (!expectedRoute || route.coveredDeclarationCount !== expectedRouteDeclarationIds.length ||
        route.coveredDeclarationSetSha256 !== sha256(expectedRouteDeclarationIds)) {
        throw new Error('Matched custom entity-output route did not cover every exact bound declaration.');
      }
      const expectedCandidateRoute = expectedCandidateRouteByNameSha256.get(route.routeNameSha256);
      const exactCustomRouteProvenance = route.outputHandlerKind === 'entity_view' &&
        route.candidateProvenanceKind === 'custom_route' && expectedCandidateRoute &&
        route.candidateExtensionSha256 === expectedCandidateRoute.extensionSha256 &&
        route.candidateRouteSourceFileSha256 === expectedCandidateRoute.routeSourceFileSha256 &&
        route.candidateRouteSurfaceSha256 === expectedCandidateRoute.routeSurfaceSha256 &&
        route.candidateOutputSourceFileSha256 === expectedCandidateRoute.routeSourceFileSha256 &&
        route.candidateOutputSurfaceSha256 === expectedCandidateRoute.routeSurfaceSha256;
      const exactControllerProvenance = route.outputHandlerKind === 'candidate_controller' &&
        route.candidateProvenanceKind === 'custom_controller' && expectedCandidateRoute &&
        expectedCandidateRoute.controllerSourceFileSha256 !== '' && expectedCandidateRoute.controllerSurfaceSha256 !== '' &&
        route.candidateExtensionSha256 === expectedCandidateRoute.extensionSha256 &&
        route.candidateRouteSourceFileSha256 === expectedCandidateRoute.routeSourceFileSha256 &&
        route.candidateRouteSurfaceSha256 === expectedCandidateRoute.routeSurfaceSha256 &&
        route.candidateOutputSourceFileSha256 === expectedCandidateRoute.controllerSourceFileSha256 &&
        route.candidateOutputSurfaceSha256 === expectedCandidateRoute.controllerSurfaceSha256;
      const exactRenderProvenance = route.outputHandlerKind === 'entity_view' &&
        ['field_formatter', 'render_hook', 'default_theme_template'].includes(route.candidateProvenanceKind) &&
        route.candidateRouteSourceFileSha256 === '' && route.candidateRouteSurfaceSha256 === '' &&
        expectedRouteCoverage.some((coverage) =>
          (route.candidateProvenanceKind === 'render_hook'
            ? coverage.role === 'render_hook'
            : route.candidateProvenanceKind === 'field_formatter'
              ? coverage.role === 'field_formatter'
              : coverage.role === 'render_template') &&
          route.candidateExtensionSha256 === coverage.extensionSha256 &&
          route.candidateOutputSourceFileSha256 === coverage.sourceFileSha256 &&
          route.candidateOutputSurfaceSha256 === coverage.surfaceSha256
        );
      if (route.routeAccess !== 'allowed' || !route.routeAccessMetadataSha256 || !route.declarationBindingSha256 ||
        !route.candidateExtensionSetSha256 || !route.outputHandlerSha256 ||
        !['candidate_controller', 'entity_view'].includes(route.outputHandlerKind) ||
        (route.outputHandlerKind === 'candidate_controller' && !route.controllerExtensionSha256) ||
        (route.outputHandlerKind === 'entity_view' && route.controllerExtensionSha256 !== '') ||
        (!exactCustomRouteProvenance && !exactControllerProvenance && !exactRenderProvenance)) {
        throw new Error('Matched custom entity-output route lacks anonymous access, declaration, candidate, and output-handler binding evidence.');
      }
    }
  }
  if (dependencyCount !== audit.dependencyCount) throw new Error('Custom entity-output audit aggregate dependency count is inconsistent.');
  if (applicableRouteCount !== audit.applicableRouteCount) {
    throw new Error('Custom entity-output audit applicable route count is inconsistent.');
  }
  if (matchedRouteCount !== audit.matchedNodeRouteCount || renderedRouteCount !== audit.renderedRouteCount) {
    throw new Error('Custom entity-output audit route state counts are inconsistent.');
  }
  const aggregateCandidateSourceFileSha256 = uniqueSorted([...coveredCandidateSourceFileSha256]);
  const aggregateCandidateSurfaceSha256 = uniqueSorted([...coveredCandidateSurfaceSha256]);
  if (audit.coveredCandidateSourceFileCount !== aggregateCandidateSourceFileSha256.length ||
    audit.coveredCandidateSourceFileSetSha256 !== (aggregateCandidateSourceFileSha256.length > 0 ? sha256(aggregateCandidateSourceFileSha256) : '')) {
    throw new Error('Custom entity-output audit candidate source-file aggregate does not match exact route provenance.');
  }
  if (audit.coveredCandidateSurfaceCount !== aggregateCandidateSurfaceSha256.length ||
    audit.coveredCandidateSurfaceSetSha256 !== (aggregateCandidateSurfaceSha256.length > 0 ? sha256(aggregateCandidateSurfaceSha256) : '')) {
    throw new Error('Custom entity-output audit candidate surface aggregate does not match exact route provenance.');
  }
  for (const [index, violation] of audit.violations.entries()) {
    exactKeys(violation, ['code', 'routeSha256', 'subjectSha256'], `Custom entity-output violation ${index}`);
    if (!/^[a-z][a-z0-9_]{2,127}$/.test(violation.code)) throw new Error('Custom entity-output audit emitted an invalid violation code.');
    assertHash(violation.routeSha256, 'Custom entity-output violation route hash', true);
    assertHash(violation.subjectSha256, 'Custom entity-output violation subject hash', true);
  }
  exactKeys(audit.invalidation, [
    'status', 'preCaptureAttempted', 'preCaptureTagCount', 'preCaptureEvidenceSha256',
    'attempted', 'seededCount', 'invalidatedCount', 'cleanupRequired', 'cleanupCompleted', 'evidenceSha256'
  ], 'Custom entity-output invalidation audit');
  assertBoolean(audit.invalidation.preCaptureAttempted, 'Custom entity-output pre-capture invalidation attempted');
  assertBoolean(audit.invalidation.attempted, 'Custom entity-output invalidation attempted');
  assertBoolean(audit.invalidation.cleanupRequired, 'Custom entity-output invalidation cleanupRequired');
  assertBoolean(audit.invalidation.cleanupCompleted, 'Custom entity-output invalidation cleanupCompleted');
  assertCount(audit.invalidation.seededCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesTotal, 'Custom entity-output invalidation seededCount');
  assertCount(audit.invalidation.invalidatedCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.dependenciesTotal, 'Custom entity-output invalidation invalidatedCount');
  assertCount(audit.invalidation.preCaptureTagCount, CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.metadataItemsTotal, 'Custom entity-output pre-capture invalidation tag count');
  assertHash(audit.invalidation.preCaptureEvidenceSha256, 'Custom entity-output pre-capture invalidation evidence', true);
  assertHash(audit.invalidation.evidenceSha256, 'Custom entity-output invalidation evidence', true);
  if (!allowOwnedCacheInvalidation) {
    if (audit.invalidation.status !== 'not_run' || audit.invalidation.preCaptureAttempted || audit.invalidation.preCaptureTagCount !== 0 || audit.invalidation.preCaptureEvidenceSha256 !== '' || audit.invalidation.attempted || audit.invalidation.seededCount !== 0 || audit.invalidation.invalidatedCount !== 0 || audit.invalidation.cleanupRequired || !audit.invalidation.cleanupCompleted || audit.invalidation.evidenceSha256 !== '') {
      throw new Error('Default custom entity-output audit reported explicit verifier mutation.');
    }
  } else if (![
    'pass', 'fail', 'not_run_due_to_violations', 'not_run_due_to_not_applicable',
    'pre_capture_performed_proof_not_run_due_to_violations', 'pre_capture_performed_not_applicable'
  ].includes(audit.invalidation.status)) {
    throw new Error('Isolated custom entity-output audit has an invalid invalidation status.');
  } else if (audit.invalidation.status === 'pass' && (!audit.invalidation.preCaptureAttempted || audit.invalidation.preCaptureTagCount === 0 || !audit.invalidation.preCaptureEvidenceSha256 || !audit.invalidation.attempted || !audit.invalidation.cleanupRequired || !audit.invalidation.cleanupCompleted || audit.invalidation.seededCount === 0 || audit.invalidation.seededCount !== audit.invalidation.invalidatedCount || !audit.invalidation.evidenceSha256)) {
    throw new Error('Isolated custom entity-output audit lacks a complete owned-cache proof.');
  } else if (audit.invalidation.status.startsWith('not_run_') && (audit.invalidation.attempted || audit.invalidation.seededCount !== 0 || audit.invalidation.invalidatedCount !== 0 || audit.invalidation.cleanupRequired || !audit.invalidation.cleanupCompleted || audit.invalidation.evidenceSha256 !== '')) {
    throw new Error('Unattempted isolated custom entity-output audit reported cache mutation.');
  } else if (audit.invalidation.status.startsWith('pre_capture_performed_') &&
    (!audit.invalidation.preCaptureAttempted || audit.invalidation.preCaptureTagCount === 0 ||
      !audit.invalidation.preCaptureEvidenceSha256 || audit.invalidation.attempted ||
      audit.invalidation.seededCount !== 0 || audit.invalidation.invalidatedCount !== 0 ||
      audit.invalidation.cleanupRequired || !audit.invalidation.cleanupCompleted || audit.invalidation.evidenceSha256 !== '')) {
    throw new Error('Pre-capture-only custom entity-output invalidation evidence is inconsistent.');
  }
  if (audit.status === 'pass' && audit.violations.length > 0) throw new Error('Passing custom entity-output audit contains violations.');
  if (audit.status === 'fail' && audit.violations.length === 0) throw new Error('Failing custom entity-output audit lacks violations.');
  if (audit.status === 'not_applicable' && (audit.applicableRouteCount !== 0 || audit.violations.length > 0 ||
    audit.matchedNodeRouteCount !== 0 || audit.renderedRouteCount !== 0 || audit.dependencyCount !== 0 ||
    audit.coveredDeclarationCount !== 0 || audit.coveredDeclarationSetSha256 !== '' ||
    audit.coveredCandidateSourceFileCount !== 0 || audit.coveredCandidateSourceFileSetSha256 !== '' ||
    audit.coveredCandidateSurfaceCount !== 0 || audit.coveredCandidateSurfaceSetSha256 !== '')) {
    throw new Error('Custom entity-output N/A result is inconsistent with runtime applicability.');
  }
  if (audit.status === 'pass') {
    if (audit.activeCandidateExtensionCount === 0 || audit.applicableRouteCount === 0 ||
      audit.matchedNodeRouteCount !== audit.applicableRouteCount || audit.renderedRouteCount !== audit.applicableRouteCount || audit.dependencyCount === 0 ||
      audit.coveredCandidateSourceFileCount === 0 || audit.coveredCandidateSurfaceCount === 0) {
      throw new Error('Passing custom entity-output audit lacks complete runtime coverage.');
    }
    const normalizedExpectedApplicableDeclarationIds = uniqueSorted([...expectedApplicableDeclarationIds]);
    if (normalizedExpectedDeclarationIds.length > 0 && (
      audit.coveredDeclarationCount !== normalizedExpectedApplicableDeclarationIds.length ||
      audit.coveredDeclarationSetSha256 !== sha256(normalizedExpectedApplicableDeclarationIds)
    )) {
      throw new Error('Passing custom entity-output audit did not cover the exact applicable typed declaration set.');
    }
    for (const route of audit.routes.filter((row) => row.matched)) {
      for (const dependency of route.dependencies) {
        if (dependency.access !== 'allowed' || dependency.cacheTagCount === 0 || dependency.invalidationTagCount === 0 || dependency.renderedTagIntersectionCount !== dependency.invalidationTagCount) {
          throw new Error('Passing custom entity-output audit lacks exact dependency and access cache evidence.');
        }
      }
    }
    if (allowOwnedCacheInvalidation && audit.invalidation.status !== 'pass') {
      throw new Error('Passing isolated custom entity-output audit lacks a passing invalidation proof.');
    }
  }
  const parsed = structuredClone(audit);
  parsed.resultFingerprint = customEntityOutputAuditResultFingerprint(parsed);
  return parsed;
}

export function inspectCustomEntityOutputAudit({
  projectRoot,
  environment = process.env,
  sourceInventory,
  staticAudit = null,
  fieldOutputMatrix,
  routeMatrix,
  allowOwnedCacheInvalidation = false,
  isolation = null,
  targetOrigin: requestedTargetOrigin = '',
  runner = defaultRunner
} = {}) {
  const hasRequestedTargetOrigin = String(requestedTargetOrigin ?? '').trim() !== '';
  const resolvedTargetOrigin = hasRequestedTargetOrigin
    ? safeTargetOrigin(requestedTargetOrigin)
    : targetOrigin(projectRoot, environment);
  const derived = deriveCustomEntityOutputAuditInput({
    sourceInventory,
    staticAudit,
    fieldOutputMatrix,
    routeMatrix,
    targetOrigin: hasRequestedTargetOrigin ? requestedTargetOrigin : resolvedTargetOrigin
  });
  if (derived.errors.length > 0) return localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, 'invalid_verifier_inputs');
  if (!resolvedTargetOrigin) return localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, 'target_origin_unavailable');
  if (derived.candidateSourceFileIds.length === 0 || derived.declarations.length === 0) {
    return localResult(derived, allowOwnedCacheInvalidation, 'not_applicable', true, '');
  }
  if (derived.routes.length === 0) return localResult(derived, allowOwnedCacheInvalidation, 'fail', true, 'missing_public_route_targets');
  if (allowOwnedCacheInvalidation && !isolatedBoundaryAccepted(isolation) &&
    !currentDdevTargetBoundaryAccepted(projectRoot, environment, derived.targetOrigin)) {
    return localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, 'disposable_boundary_not_proven');
  }

  const ownedCacheToken = allowOwnedCacheInvalidation ? randomBytes(32).toString('hex') : '';
  let php;
  try {
    php = buildCustomEntityOutputAuditPhp(derived, { allowOwnedCacheInvalidation, ownedCacheToken });
  } catch (error) {
    return localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, 'runtime_input_budget_exceeded');
  }
  let execution;
  try {
    execution = runner({
      projectRoot,
      environment,
      php,
      timeoutMs: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.timeoutMs,
      outputLimitBytes: CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.outputBytes
    });
  } catch (error) {
    execution = { ok: false, failureSha256: sha256(`${error?.name ?? ''}\u0000${error?.message ?? ''}`) };
  }
  if (execution && typeof execution.then === 'function') {
    execution = { ok: false, failureSha256: sha256('unsupported_async_runner') };
  }
  const output = String(execution?.output ?? execution?.stdout ?? '');
  if (Buffer.byteLength(output, 'utf8') > CUSTOM_ENTITY_OUTPUT_AUDIT_LIMITS.outputBytes) {
    return localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, 'runtime_output_budget_exceeded');
  }
  if (execution?.ok !== true) {
    const code = execution?.timedOut
      ? 'runtime_timeout'
      : execution?.outputExceeded
        ? 'runtime_output_budget_exceeded'
        : 'runtime_execution_failed';
    const result = localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, code);
    result.failures[0].detailSha256 = HASH_RE.test(String(execution?.failureSha256 ?? ''))
      ? execution.failureSha256
      : sha256(`${code}\u0000${execution?.exitStatus ?? ''}`);
    result.resultFingerprint = customEntityOutputAuditResultFingerprint(result);
    return result;
  }
  let runtime;
  try {
    runtime = parseCustomEntityOutputAudit(output, {
      expectedInputFingerprint: derived.inputFingerprint,
      expectedTargetOrigin: derived.targetOrigin,
      expectedRouteCount: derived.routes.length,
      expectedRouteSha256: derived.routes.map(({ path }) => sha256(path)),
      expectedRouteBindings: derived.routes,
      expectedCandidateRouteBindings: derived.candidateRouteBindings,
      expectedCandidateRenderBindings: derived.candidateRenderBindings,
      expectedCandidateSourceFileIds: derived.candidateSourceFileIds,
      expectedCandidateSurfaceIds: derived.candidateSurfaceIds,
      expectedExtensions: derived.extensions,
      expectedDeclarationIds: derived.declarations.map(({ id }) => id),
      maximumActiveCandidateExtensionCount: derived.extensions.length,
      allowOwnedCacheInvalidation
    });
  } catch (error) {
    const result = localResult(derived, allowOwnedCacheInvalidation, 'blocked', false, 'runtime_schema_invalid');
    result.failures[0].detailSha256 = sha256(error?.message ?? 'runtime_schema_invalid');
    result.resultFingerprint = customEntityOutputAuditResultFingerprint(result);
    return result;
  }
  const result = {
    ...evidenceBase(derived, allowOwnedCacheInvalidation),
    applies: runtime.status !== 'not_applicable',
    completed: runtime.completed,
    status: runtime.status,
    runtime,
    failures: []
  };
  result.resultFingerprint = customEntityOutputAuditResultFingerprint(result);
  return result;
}
