import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import { assemblyTargetKey } from './assembly-contract.mjs';
import { collectFileManifest, collectRuntimeCodeManifest, sha256 } from './state-fingerprint.mjs';

export const ASSEMBLY_PERSISTENCE_SCHEMA = 'public-kit.assembly-persistence.1';
export const ASSEMBLY_FILE_SURFACES_SCHEMA = 'public-kit.assembly-file-surfaces.1';
export const ASSEMBLY_ENTITY_IDENTITY_SCHEMA = 'public-kit.assembly-entity-identity.1';
export const ASSEMBLY_STORAGE_RESIDUAL_SCHEMA = 'public-kit.assembly-storage-residual.1';
export const ASSEMBLY_SOURCE_BYTES_SCHEMA = 'public-kit.assembly-source-bytes.1';
export const ASSEMBLY_FILE_BACKUP_SCHEMA = 'public-kit.assembly-file-backup.1';
export const ASSEMBLY_DATABASE_SOURCE_EXCLUSION_SCHEMA = 'public-kit.assembly-database-source-exclusion.1';

export const DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS = Object.freeze({
  maxTables: 1_024,
  maxRowsPerTable: 250_000,
  maxAggregateRows: 1_000_000,
  maxEntriesPerFileSurface: 100_000,
  maxBytesPerFile: 256 * 1024 * 1024,
  maxBytesPerFileSurface: 2 * 1024 * 1024 * 1024,
  maxAggregateFileBytes: 4 * 1024 * 1024 * 1024,
  maxElapsedMs: 240_000
});

const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const TABLE_ID_RE = /^table:[A-Za-z0-9_.-]{1,255}$/;
const FILE_SURFACE_ID_RE = /^file:(?:public|private)$/;
const SOURCE_MAX_UNTRACKED_FILES = 20_000;
const SOURCE_MAX_UNTRACKED_BYTES = 512 * 1024 * 1024;
const SOURCE_MAX_DIFF_BYTES = 64 * 1024 * 1024;
const FILE_BACKUP_TOKENS = new WeakMap();
const DATABASE_SOURCE_EXCLUSIONS = new WeakMap();
const FILE_BACKUP_OWNER = '.agent-ready-assembly-file-backup.json';

function comparePortable(left, right) {
  return String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0;
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
}

function assertExactKeys(value, allowed, label) {
  assertObject(value, label);
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort(comparePortable);
  if (unknown.length > 0) throw new Error(`${label} contains unsupported field(s): ${unknown.join(', ')}.`);
}

function normalizedHash(value, label) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!HASH_RE.test(text)) throw new Error(`${label} must be a SHA-256 digest.`);
  return text;
}

function boundedInteger(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} must be an integer between 0 and ${maximum}.`);
  }
  return value;
}

function normalizeLimits(value = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS) {
  assertExactKeys(value, Object.keys(DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS), 'Assembly persistence limits');
  const limits = {};
  for (const [key, fallback] of Object.entries(DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS)) {
    const number = Number(value[key]);
    if (!Number.isSafeInteger(number) || number <= 0 || number > Number.MAX_SAFE_INTEGER) {
      throw new Error(`Assembly persistence limit ${key} must be a positive safe integer.`);
    }
    limits[key] = number || fallback;
  }
  return limits;
}

function normalizeFileSurfaces(value = ['public', 'private']) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 2) {
    throw new Error('Assembly file surfaces must be a non-empty bounded array.');
  }
  const surfaces = value.map((surface) => String(surface ?? '').trim());
  if (surfaces.some((surface) => !['public', 'private'].includes(surface))) {
    throw new Error('Assembly file surfaces may contain only public and private.');
  }
  if (new Set(surfaces).size !== surfaces.length) throw new Error('Assembly file surfaces contain duplicates.');
  return surfaces.sort(comparePortable);
}

function parseTableRows(value, limits) {
  if (!Array.isArray(value) || value.length > limits.maxTables) {
    throw new Error(`Assembly persistence tables exceed the cap of ${limits.maxTables}.`);
  }
  const ids = new Set();
  let aggregateRows = 0;
  const rows = value.map((row, index) => {
    assertExactKeys(
      row,
      ['id', 'policy', 'rowCount', 'sha256', 'definitionSha256', 'sequenceSha256'],
      `Assembly persistence tables[${index}]`
    );
    const id = String(row.id ?? '').trim();
    if (!TABLE_ID_RE.test(id)) throw new Error(`Assembly persistence tables[${index}].id is invalid.`);
    if (ids.has(id)) throw new Error(`Assembly persistence contains duplicate table ${id}.`);
    ids.add(id);
    const rowCount = boundedInteger(row.rowCount, limits.maxRowsPerTable, `Assembly persistence ${id} rowCount`);
    aggregateRows += rowCount;
    if (aggregateRows > limits.maxAggregateRows) {
      throw new Error(`Assembly persistence aggregate rows exceed the cap of ${limits.maxAggregateRows}.`);
    }
    const policy = String(row.policy ?? '').trim();
    if (!['durable', 'ephemeral'].includes(policy)) {
      throw new Error(`Assembly persistence ${id} policy must be durable or ephemeral.`);
    }
    return {
      id,
      policy,
      rowCount,
      sha256: normalizedHash(row.sha256, `Assembly persistence ${id} sha256`),
      definitionSha256: normalizedHash(
        row.definitionSha256,
        `Assembly persistence ${id} definitionSha256`
      ),
      sequenceSha256: normalizedHash(row.sequenceSha256, `Assembly persistence ${id} sequenceSha256`)
    };
  }).sort((left, right) => comparePortable(left.id, right.id));
  return { rows, aggregateRows };
}

function parseFileRows(value, limits, expectedSurfaces) {
  if (!Array.isArray(value) || value.length !== expectedSurfaces.length) {
    throw new Error('Assembly persistence file surfaces do not cover the exact declared surface set.');
  }
  const ids = new Set();
  let aggregateBytes = 0;
  const rows = value.map((row, index) => {
    assertExactKeys(
      row,
      ['id', 'available', 'fileCount', 'directoryCount', 'byteCount', 'ephemeralPrefixes', 'sha256', 'physicalSha256'],
      `Assembly persistence files[${index}]`
    );
    const id = String(row.id ?? '').trim();
    if (!FILE_SURFACE_ID_RE.test(id)) throw new Error(`Assembly persistence files[${index}].id is invalid.`);
    if (ids.has(id)) throw new Error(`Assembly persistence contains duplicate file surface ${id}.`);
    ids.add(id);
    if (typeof row.available !== 'boolean') throw new Error(`Assembly persistence ${id}.available must be boolean.`);
    const fileCount = boundedInteger(
      row.fileCount,
      limits.maxEntriesPerFileSurface,
      `Assembly persistence ${id} fileCount`
    );
    const directoryCount = boundedInteger(
      row.directoryCount,
      limits.maxEntriesPerFileSurface,
      `Assembly persistence ${id} directoryCount`
    );
    if (fileCount + directoryCount > limits.maxEntriesPerFileSurface) {
      throw new Error(`Assembly persistence ${id} entries exceed the cap of ${limits.maxEntriesPerFileSurface}.`);
    }
    const byteCount = boundedInteger(
      row.byteCount,
      limits.maxBytesPerFileSurface,
      `Assembly persistence ${id} byteCount`
    );
    aggregateBytes += byteCount;
    if (aggregateBytes > limits.maxAggregateFileBytes) {
      throw new Error(`Assembly persistence aggregate file bytes exceed the cap of ${limits.maxAggregateFileBytes}.`);
    }
    if (!row.available && (fileCount !== 0 || directoryCount !== 0 || byteCount !== 0)) {
      throw new Error(`Unavailable assembly persistence surface ${id} must have zero counts.`);
    }
    if (!Array.isArray(row.ephemeralPrefixes)) throw new Error(`Assembly persistence ${id}.ephemeralPrefixes must be an array.`);
    const ephemeralPrefixes = row.ephemeralPrefixes.map((prefix) => String(prefix ?? '')).sort(comparePortable);
    const expectedPrefixes = id === 'file:public' ? ['css/', 'js/', 'php/', 'styles/'] : [];
    if (new Set(ephemeralPrefixes).size !== ephemeralPrefixes.length || JSON.stringify(ephemeralPrefixes) !== JSON.stringify(expectedPrefixes)) {
      throw new Error(`Assembly persistence ${id}.ephemeralPrefixes does not match the fixed verifier policy.`);
    }
    return {
      id,
      available: row.available,
      fileCount,
      directoryCount,
      byteCount,
      ephemeralPrefixes,
      sha256: normalizedHash(row.sha256, `Assembly persistence ${id} durable sha256`),
      physicalSha256: normalizedHash(row.physicalSha256, `Assembly persistence ${id} physical sha256`)
    };
  }).sort((left, right) => comparePortable(left.id, right.id));
  const expectedIds = expectedSurfaces.map((surface) => `file:${surface}`).sort(comparePortable);
  if (JSON.stringify(rows.map(({ id }) => id)) !== JSON.stringify(expectedIds)) {
    throw new Error('Assembly persistence file surfaces do not match the declared public/private set.');
  }
  return { rows, aggregateBytes };
}

export function parseAssemblyPersistenceSnapshot(
  value,
  { limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS, surfaces: rawSurfaces = ['public', 'private'] } = {}
) {
  assertObject(value, 'Assembly persistence readback');
  if (value.complete !== true) throw new Error('Assembly persistence readback was truncated or incomplete.');
  assertExactKeys(value, [
    'schemaVersion', 'complete', 'tableCount', 'aggregateRowCount', 'ephemeralTableIds', 'tables', 'files', 'aggregateSha256'
  ], 'Assembly persistence readback');
  if (value.schemaVersion !== ASSEMBLY_PERSISTENCE_SCHEMA) {
    throw new Error(`Assembly persistence schemaVersion must be ${ASSEMBLY_PERSISTENCE_SCHEMA}.`);
  }
  const limits = normalizeLimits(rawLimits);
  const surfaces = normalizeFileSurfaces(rawSurfaces);
  const tables = parseTableRows(value.tables, limits);
  const files = parseFileRows(value.files, limits, surfaces);
  if (value.tableCount !== tables.rows.length) throw new Error('Assembly persistence tableCount is inconsistent.');
  if (value.aggregateRowCount !== tables.aggregateRows) {
    throw new Error('Assembly persistence aggregateRowCount is inconsistent.');
  }
  if (!Array.isArray(value.ephemeralTableIds)) throw new Error('Assembly persistence ephemeralTableIds must be an array.');
  const ephemeralTableIds = value.ephemeralTableIds.map((id) => String(id ?? '').trim()).sort(comparePortable);
  const expectedEphemeral = tables.rows.filter(({ policy }) => policy === 'ephemeral').map(({ id }) => id);
  if (
    ephemeralTableIds.some((id) => !TABLE_ID_RE.test(id)) ||
    new Set(ephemeralTableIds).size !== ephemeralTableIds.length ||
    JSON.stringify(ephemeralTableIds) !== JSON.stringify(expectedEphemeral)
  ) {
    throw new Error('Assembly persistence ephemeralTableIds do not match the explicit table policies.');
  }
  const aggregateSha256 = normalizedHash(value.aggregateSha256, 'Assembly persistence aggregateSha256');
  const expectedHash = sha256({ files: files.rows, tables: tables.rows });
  if (aggregateSha256 !== expectedHash) throw new Error('Assembly persistence aggregate fingerprint is inconsistent.');
  return {
    schemaVersion: ASSEMBLY_PERSISTENCE_SCHEMA,
    complete: true,
    tableCount: tables.rows.length,
    aggregateRowCount: tables.aggregateRows,
    ephemeralTableIds,
    tables: tables.rows,
    files: files.rows,
    aggregateSha256
  };
}

export function parseAssemblyFileSurfaceSnapshot(
  value,
  { limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS, surfaces: rawSurfaces = ['public', 'private'] } = {}
) {
  assertObject(value, 'Assembly file-surface readback');
  if (value.complete !== true) throw new Error('Assembly file-surface readback was truncated or incomplete.');
  assertExactKeys(value, ['schemaVersion', 'complete', 'files', 'aggregateSha256'], 'Assembly file-surface readback');
  if (value.schemaVersion !== ASSEMBLY_FILE_SURFACES_SCHEMA) {
    throw new Error(`Assembly file-surface schemaVersion must be ${ASSEMBLY_FILE_SURFACES_SCHEMA}.`);
  }
  const limits = normalizeLimits(rawLimits);
  const surfaces = normalizeFileSurfaces(rawSurfaces);
  const files = parseFileRows(value.files, limits, surfaces).rows;
  const aggregateSha256 = normalizedHash(value.aggregateSha256, 'Assembly file-surface aggregateSha256');
  if (aggregateSha256 !== sha256(files)) throw new Error('Assembly file-surface aggregate fingerprint is inconsistent.');
  return { schemaVersion: ASSEMBLY_FILE_SURFACES_SCHEMA, complete: true, files, aggregateSha256 };
}

function keyed(rows) {
  return new Map(rows.map((row) => [row.id, row]));
}

function changedIds(beforeRows, afterRows) {
  const before = keyed(beforeRows);
  const after = keyed(afterRows);
  return [...new Set([...before.keys(), ...after.keys()])].sort(comparePortable).filter((id) => {
    const left = before.get(id);
    const right = after.get(id);
    return !left || !right || sha256(left) !== sha256(right);
  });
}

/** Compare only bounded digests and counts; raw database rows and file paths never enter evidence. */
export function compareAssemblyPersistenceSnapshots(before, after) {
  const beforeTables = keyed(before.tables);
  const afterTables = keyed(after.tables);
  const allTableIds = [...new Set([...beforeTables.keys(), ...afterTables.keys()])].sort(comparePortable);
  const changedTableComponentIds = (field) => allTableIds.filter((id) => (
    !beforeTables.has(id) || !afterTables.has(id) || beforeTables.get(id)[field] !== afterTables.get(id)[field]
  ));
  const changedRowTableIds = changedTableComponentIds('sha256');
  const changedDefinitionTableIds = changedTableComponentIds('definitionSha256');
  const changedSequenceTableIds = changedTableComponentIds('sequenceSha256');
  const changedAllTableIds = [...new Set([
    ...changedRowTableIds,
    ...changedDefinitionTableIds,
    ...changedSequenceTableIds
  ])].sort(comparePortable);
  const policies = new Map([...before.tables, ...after.tables].map((row) => [row.id, row.policy]));
  const changedEphemeralTableIds = changedAllTableIds.filter((id) => policies.get(id) === 'ephemeral');
  const changedTableIds = changedAllTableIds.filter((id) => policies.get(id) !== 'ephemeral');
  const beforeFiles = new Map(before.files.map((row) => [row.id, row]));
  const afterFiles = new Map(after.files.map((row) => [row.id, row]));
  const allFileIds = [...new Set([...beforeFiles.keys(), ...afterFiles.keys()])].sort(comparePortable);
  const changedFileSurfaceIds = allFileIds.filter((id) => {
    const left = beforeFiles.get(id);
    const right = afterFiles.get(id);
    return !left || !right || left.available !== right.available || left.sha256 !== right.sha256;
  });
  const changedAllFileSurfaceIds = changedIds(before.files, after.files);
  const changedEphemeralFileSurfaceIds = changedAllFileSurfaceIds.filter((id) => !changedFileSurfaceIds.includes(id));
  return {
    exact: changedDefinitionTableIds.length === 0 && changedTableIds.length === 0 && changedFileSurfaceIds.length === 0,
    physicalExact: changedAllTableIds.length === 0 && changedAllFileSurfaceIds.length === 0 &&
      before.aggregateSha256 === after.aggregateSha256,
    changedTableIds,
    changedEphemeralTableIds,
    changedRowTableIds,
    changedDefinitionTableIds,
    changedSequenceTableIds,
    changedFileSurfaceIds,
    changedEphemeralFileSurfaceIds
  };
}

function normalizedAllowedIds(value, pattern, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  const rows = value.map((id) => String(id ?? '').trim());
  if (rows.some((id) => !pattern.test(id))) throw new Error(`${label} contains an invalid surface ID.`);
  if (new Set(rows).size !== rows.length) throw new Error(`${label} contains duplicates.`);
  return new Set(rows);
}

export function assertFirstRunPersistenceChanges({
  before,
  after,
  allowedTableIds,
  allowedSequenceTableIds = [],
  allowedFileSurfaceIds = [],
  label = 'First assembly run'
}) {
  const comparison = compareAssemblyPersistenceSnapshots(before, after);
  const allowedTables = normalizedAllowedIds(allowedTableIds, TABLE_ID_RE, 'Allowed table IDs');
  const allowedSequences = normalizedAllowedIds(
    allowedSequenceTableIds,
    TABLE_ID_RE,
    'Allowed sequence table IDs'
  );
  const allowedFiles = normalizedAllowedIds(allowedFileSurfaceIds, FILE_SURFACE_ID_RE, 'Allowed file-surface IDs');
  if (comparison.changedDefinitionTableIds.length > 0) {
    throw new Error(`${label} changed database definition surface ${comparison.changedDefinitionTableIds[0]}; assembly operations never authorize DDL.`);
  }
  const changedDurableRows = comparison.changedRowTableIds.filter((id) => !comparison.changedEphemeralTableIds.includes(id));
  const changedDurableSequences = comparison.changedSequenceTableIds.filter((id) => !comparison.changedEphemeralTableIds.includes(id));
  const outsideTables = changedDurableRows.filter((id) => !allowedTables.has(id));
  const outsideSequences = changedDurableSequences.filter((id) => !allowedSequences.has(id));
  const outsideFiles = comparison.changedFileSurfaceIds.filter((id) => !allowedFiles.has(id));
  if (outsideTables.length > 0 || outsideSequences.length > 0 || outsideFiles.length > 0) {
    const first = outsideTables[0] ?? outsideSequences[0] ?? outsideFiles[0];
    throw new Error(`${label} changed persistence surface ${first} outside the exact provenance storage allowlist.`);
  }
  return comparison;
}

export function assertExactPersistenceEquality(expected, actual, label = 'Assembly persistence') {
  const comparison = compareAssemblyPersistenceSnapshots(expected, actual);
  if (!comparison.exact) {
    const first = comparison.changedTableIds[0] ?? comparison.changedFileSurfaceIds[0] ?? 'aggregate';
    throw new Error(`${label} is not durably persistence-equivalent; changed surface ${first}.`);
  }
  return comparison;
}

export function assertNoOpPersistence(first, second) {
  return assertExactPersistenceEquality(first, second, 'Second assembly run');
}

export function assertRestoredPersistence(baseline, restored) {
  return assertExactPersistenceEquality(baseline, restored, 'Verifier-owned restoration');
}

function fixedEval(execute, projectRoot, target, phase, source, timeout) {
  const result = execute('ddev', ['drush', 'php:eval', source], {
    cwd: projectRoot,
    phase,
    target,
    timeout,
    maxBuffer: 64 * 1024 * 1024,
    recordedArgs: ['drush', 'php:eval', `<verifier-owned:${sha256(source)}>`]
  });
  if (!result || result.status !== 0) throw new Error(`${phase} failed.`);
  return String(result.stdout ?? '');
}

function parseJsonOutput(output, label) {
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${label} returned invalid JSON.`);
  }
}

const PHP_CANONICAL_AND_FILE_HELPERS = String.raw`
$normalize = function ($value) use (&$normalize) {
  if (!is_array($value)) return $value;
  if (!array_is_list($value)) ksort($value, SORT_STRING);
  foreach ($value as $key => $child) $value[$key] = $normalize($child);
  return $value;
};
$encode = static function ($value) use ($normalize): string {
  $encoded = json_encode($normalize($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
  return $encoded;
};
$hash_value = static fn ($value): string => 'sha256:' . hash('sha256', $encode($value));
$started = microtime(TRUE);
$check_deadline = static function () use ($spec, $started): void {
  if (((microtime(TRUE) - $started) * 1000) > $spec['limits']['maxElapsedMs']) throw new \OverflowException('elapsed_time_cap');
};
$resolve_surface = static function (string $scheme, bool $required): ?string {
  $manager = \Drupal::service('stream_wrapper_manager');
  $wrapper = $manager->getViaScheme($scheme);
  if ($wrapper === FALSE || $wrapper === NULL) {
    if ($required) throw new \RuntimeException('declared_file_surface_unavailable');
    return NULL;
  }
  $root = \Drupal::service('file_system')->realpath($scheme . '://');
  if ($root === FALSE || !is_dir($root)) {
    if ($required) throw new \RuntimeException('declared_file_surface_unresolved');
    return NULL;
  }
  if (is_link($root)) throw new \RuntimeException('file_surface_symlink');
  return $root;
};
$scan_tree = function (string $root, string $id) use ($spec, $hash_value, $check_deadline): array {
  $entries = [];
  $file_count = 0;
  $directory_count = 0;
  $byte_count = 0;
  $visit = function (string $absolute, string $relative) use (&$visit, &$entries, &$file_count, &$directory_count, &$byte_count, $spec, $check_deadline, $id): void {
    $check_deadline();
    $metadata = @lstat($absolute);
    if ($metadata === FALSE) throw new \RuntimeException('file_surface_entry_disappeared');
    if (is_link($absolute)) throw new \RuntimeException('file_surface_symlink');
    if (is_dir($absolute)) {
      if ($relative !== '') {
        $directory_count++;
        if (($file_count + $directory_count) > $spec['limits']['maxEntriesPerFileSurface']) throw new \OverflowException('file_entry_cap');
        $ephemeral = $id === 'file:public' && preg_match('#^(?:css|js|php|styles)(?:/|$)#D', $relative) === 1;
        $entries[] = ['kind' => 'directory', 'ephemeral' => $ephemeral, 'pathSha256' => 'sha256:' . hash('sha256', $relative)];
      }
      $children = scandir($absolute);
      if ($children === FALSE) throw new \RuntimeException('file_surface_directory_unreadable');
      $children = array_values(array_diff($children, ['.', '..']));
      sort($children, SORT_STRING);
      foreach ($children as $child) {
        $child_relative = $relative === '' ? $child : $relative . '/' . $child;
        if (strlen($child_relative) > 2048) throw new \OverflowException('file_path_cap');
        $visit($absolute . DIRECTORY_SEPARATOR . $child, $child_relative);
      }
      return;
    }
    if (!is_file($absolute)) throw new \RuntimeException('file_surface_unsupported_entry');
    $size = filesize($absolute);
    if ($size === FALSE || $size > $spec['limits']['maxBytesPerFile']) throw new \OverflowException('file_size_cap');
    $file_count++;
    $byte_count += $size;
    if (($file_count + $directory_count) > $spec['limits']['maxEntriesPerFileSurface']) throw new \OverflowException('file_entry_cap');
    if ($byte_count > $spec['limits']['maxBytesPerFileSurface']) throw new \OverflowException('file_surface_byte_cap');
    $content_hash = hash_file('sha256', $absolute);
    if ($content_hash === FALSE || filesize($absolute) !== $size || is_link($absolute)) throw new \RuntimeException('file_surface_entry_changed_during_readback');
    $entries[] = [
      'kind' => 'file',
      'ephemeral' => $id === 'file:public' && preg_match('#^(?:css|js|php|styles)(?:/|$)#D', $relative) === 1,
      'pathSha256' => 'sha256:' . hash('sha256', $relative),
      'byteCount' => $size,
      'contentSha256' => 'sha256:' . $content_hash,
    ];
  };
  $visit($root, '');
  usort($entries, static fn ($left, $right): int => strcmp($left['kind'] . '|' . $left['pathSha256'], $right['kind'] . '|' . $right['pathSha256']));
  $ephemeral_prefixes = $id === 'file:public' ? ['css/', 'js/', 'php/', 'styles/'] : [];
  $durable_entries = array_values(array_filter($entries, static fn ($entry): bool => !$entry['ephemeral']));
  $physical_payload = [
    'id' => $id,
    'available' => TRUE,
    'fileCount' => $file_count,
    'directoryCount' => $directory_count,
    'byteCount' => $byte_count,
    'entries' => $entries,
  ];
  $durable_payload = ['id' => $id, 'available' => TRUE, 'entries' => $durable_entries, 'ephemeralPrefixes' => $ephemeral_prefixes];
  return [
    'id' => $id,
    'available' => TRUE,
    'fileCount' => $file_count,
    'directoryCount' => $directory_count,
    'byteCount' => $byte_count,
    'ephemeralPrefixes' => $ephemeral_prefixes,
    'sha256' => $hash_value($durable_payload),
    'physicalSha256' => $hash_value($physical_payload),
  ];
};
$empty_surface = static function (string $id) use ($hash_value): array {
  $ephemeral_prefixes = $id === 'file:public' ? ['css/', 'js/', 'php/', 'styles/'] : [];
  $physical = ['id' => $id, 'available' => FALSE, 'fileCount' => 0, 'directoryCount' => 0, 'byteCount' => 0, 'entries' => []];
  $durable = ['id' => $id, 'available' => FALSE, 'entries' => [], 'ephemeralPrefixes' => $ephemeral_prefixes];
  return [
    'id' => $id,
    'available' => FALSE,
    'fileCount' => 0,
    'directoryCount' => 0,
    'byteCount' => 0,
    'ephemeralPrefixes' => $ephemeral_prefixes,
    'sha256' => $hash_value($durable),
    'physicalSha256' => $hash_value($physical),
  ];
};
$copy_tree = function (string $source, string $destination) use (&$copy_tree, $check_deadline): void {
  $check_deadline();
  if (is_link($source)) throw new \RuntimeException('file_backup_symlink');
  if (is_dir($source)) {
    if (!is_dir($destination) && !mkdir($destination, 0700, TRUE)) throw new \RuntimeException('file_backup_directory_create_failed');
    $children = scandir($source);
    if ($children === FALSE) throw new \RuntimeException('file_backup_directory_unreadable');
    $children = array_values(array_diff($children, ['.', '..']));
    sort($children, SORT_STRING);
    foreach ($children as $child) $copy_tree($source . DIRECTORY_SEPARATOR . $child, $destination . DIRECTORY_SEPARATOR . $child);
    return;
  }
  if (!is_file($source) || !copy($source, $destination)) throw new \RuntimeException('file_backup_copy_failed');
};
$remove_children = function (string $root) use (&$remove_children, $check_deadline): void {
  $check_deadline();
  if (is_link($root) || !is_dir($root)) throw new \RuntimeException('file_restore_root_unsafe');
  $children = scandir($root);
  if ($children === FALSE) throw new \RuntimeException('file_restore_root_unreadable');
  foreach (array_values(array_diff($children, ['.', '..'])) as $child) {
    $path = $root . DIRECTORY_SEPARATOR . $child;
    if (is_link($path)) throw new \RuntimeException('file_restore_symlink');
    if (is_dir($path)) {
      $remove_children($path);
      if (!rmdir($path)) throw new \RuntimeException('file_restore_directory_remove_failed');
    }
    elseif (!is_file($path) || !unlink($path)) throw new \RuntimeException('file_restore_file_remove_failed');
  }
};
`;

function encodedSpec(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

function persistenceEvalSource(surfaces, limits) {
  const specification = encodedSpec({ surfaces, limits });
  return String.raw`
$spec = json_decode(base64_decode('${specification}', TRUE), TRUE, 32, JSON_THROW_ON_ERROR);
${PHP_CANONICAL_AND_FILE_HELPERS}
try {
  $connection = \Drupal::database();
  $connection_options = $connection->getConnectionOptions();
  if (($connection_options['driver'] ?? '') !== 'mysql' || !is_string($connection_options['database'] ?? NULL)) {
    throw new \RuntimeException('assembly_persistence_requires_mysql_metadata');
  }
  $database_name = $connection_options['database'];
  $table_prefix = $connection->getPrefix();
  $capture_table_metadata = static function (string $table_name) use ($connection, $database_name, $hash_value, $table_prefix): array {
    $create_row = $connection->query('SHOW CREATE TABLE {' . $table_name . '}')->fetchAssoc();
    if (!is_array($create_row) || count($create_row) < 2) throw new \RuntimeException('table_definition_unavailable');
    $create_sql = (string) array_values($create_row)[1];
    $sequence_value = '';
    if (preg_match('/\\sAUTO_INCREMENT=(\\d+)\\b/i', $create_sql, $matches) === 1) $sequence_value = $matches[1];
    $definition_sql = preg_replace('/\\sAUTO_INCREMENT=\\d+\\b/i', '', $create_sql);
    if (!is_string($definition_sql)) throw new \RuntimeException('table_definition_normalization_failed');
    $actual_table_name = $table_prefix . $table_name;
    $trigger_hashes = [];
    $triggers = $connection->query(
      'SELECT * FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = :schema AND EVENT_OBJECT_TABLE = :table ORDER BY TRIGGER_NAME',
      [':schema' => $database_name, ':table' => $actual_table_name]
    );
    while ($trigger = $triggers->fetchAssoc()) {
      $opaque_trigger = [];
      foreach ($trigger as $column => $cell) {
        if ($cell === NULL) $opaque_trigger[$column] = ['type' => 'null'];
        else {
          $bytes = (string) $cell;
          $opaque_trigger[$column] = [
            'type' => gettype($cell),
            'byteCount' => strlen($bytes),
            'sha256' => 'sha256:' . hash('sha256', $bytes),
          ];
        }
      }
      $trigger_hashes[] = $hash_value($opaque_trigger);
    }
    sort($trigger_hashes, SORT_STRING);
    return [
      'definitionSha256' => $hash_value([
        'createTableSha256' => 'sha256:' . hash('sha256', $definition_sql),
        'triggerSha256' => $trigger_hashes,
      ]),
      'sequenceSha256' => $hash_value(['autoIncrement' => $sequence_value]),
    ];
  };
  $table_names = array_values($connection->schema()->findTables('%'));
  sort($table_names, SORT_STRING);
  if (count($table_names) > $spec['limits']['maxTables']) throw new \OverflowException('table_cap');
  $tables = [];
  $aggregate_rows = 0;
  foreach ($table_names as $table_name) {
    $check_deadline();
    if (!is_string($table_name) || !preg_match('/^[A-Za-z0-9_.-]{1,255}$/D', $table_name)) throw new \RuntimeException('unsupported_table_identifier');
    $metadata_before = $capture_table_metadata($table_name);
    $count = (int) $connection->select($table_name, 't')->countQuery()->execute()->fetchField();
    if ($count > $spec['limits']['maxRowsPerTable']) throw new \OverflowException('table_row_cap');
    $aggregate_rows += $count;
    if ($aggregate_rows > $spec['limits']['maxAggregateRows']) throw new \OverflowException('aggregate_row_cap');
    $row_hashes = [];
    $result = $connection->select($table_name, 't')->fields('t')->execute();
    while ($row = $result->fetchAssoc()) {
      $check_deadline();
      $opaque_row = [];
      foreach ($row as $column => $cell) {
        if ($cell === NULL) $opaque_row[$column] = ['type' => 'null'];
        else {
          $bytes = (string) $cell;
          $opaque_row[$column] = [
            'type' => gettype($cell),
            'byteCount' => strlen($bytes),
            'sha256' => 'sha256:' . hash('sha256', $bytes),
          ];
        }
      }
      $row_hashes[] = $hash_value($opaque_row);
      if (count($row_hashes) > $count) throw new \RuntimeException('table_changed_during_readback');
    }
    if (count($row_hashes) !== $count) throw new \RuntimeException('table_changed_during_readback');
    sort($row_hashes, SORT_STRING);
    $metadata_after = $capture_table_metadata($table_name);
    if ($metadata_before !== $metadata_after) throw new \RuntimeException('table_metadata_changed_during_readback');
    $tables[] = [
      'id' => 'table:' . $table_name,
      'policy' => ($table_name === 'cache' || $table_name === 'cachetags' || $table_name === 'semaphore' || str_starts_with($table_name, 'cache_')) ? 'ephemeral' : 'durable',
      'rowCount' => $count,
      'sha256' => $hash_value(['id' => 'table:' . $table_name, 'rowCount' => $count, 'rowSha256' => $row_hashes]),
      'definitionSha256' => $metadata_before['definitionSha256'],
      'sequenceSha256' => $metadata_before['sequenceSha256'],
    ];
  }
  usort($tables, static fn ($left, $right): int => strcmp($left['id'], $right['id']));
  $ephemeral_table_ids = array_values(array_map(
    static fn ($row): string => $row['id'],
    array_filter($tables, static fn ($row): bool => $row['policy'] === 'ephemeral')
  ));
  $files = [];
  $aggregate_file_bytes = 0;
  foreach ($spec['surfaces'] as $scheme) {
    $id = 'file:' . $scheme;
    $root = $resolve_surface($scheme, FALSE);
    $row = $root === NULL ? $empty_surface($id) : $scan_tree($root, $id);
    $aggregate_file_bytes += $row['byteCount'];
    if ($aggregate_file_bytes > $spec['limits']['maxAggregateFileBytes']) throw new \OverflowException('aggregate_file_byte_cap');
    $files[] = $row;
  }
  usort($files, static fn ($left, $right): int => strcmp($left['id'], $right['id']));
  print json_encode([
    'schemaVersion' => 'public-kit.assembly-persistence.1',
    'complete' => TRUE,
    'tableCount' => count($tables),
    'aggregateRowCount' => $aggregate_rows,
    'ephemeralTableIds' => $ephemeral_table_ids,
    'tables' => $tables,
    'files' => $files,
    'aggregateSha256' => $hash_value(['files' => $files, 'tables' => $tables]),
  ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
catch (\OverflowException $exception) {
  print json_encode(['schemaVersion' => 'public-kit.assembly-persistence.1', 'complete' => FALSE, 'reason' => $exception->getMessage()], JSON_THROW_ON_ERROR);
}
`;
}

export function captureAssemblyPersistenceSnapshot({
  execute,
  projectRoot,
  target = 'disposable',
  limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS,
  surfaces: rawSurfaces = ['public', 'private']
}) {
  const limits = normalizeLimits(rawLimits);
  const surfaces = normalizeFileSurfaces(rawSurfaces);
  const source = persistenceEvalSource(surfaces, limits);
  const output = fixedEval(
    execute,
    projectRoot,
    target,
    'assembly-persistence-readback',
    source,
    Math.min(limits.maxElapsedMs + 30_000, 600_000)
  );
  return parseAssemblyPersistenceSnapshot(parseJsonOutput(output, 'Assembly persistence readback'), { limits, surfaces });
}

function storageResidualOwnerKeys(provenance) {
  if (!provenance || !Array.isArray(provenance.resources) || provenance.resources.length > 5_000) {
    throw new Error('Assembly storage residual provenance must contain a bounded resource array.');
  }
  const keys = provenance.resources.map(({ target }) => assemblyTargetKey(target)).sort(comparePortable);
  if (new Set(keys).size !== keys.length) throw new Error('Assembly storage residual provenance contains duplicate targets.');
  return keys;
}

export function parseProvenanceStorageResidual(
  value,
  provenance,
  { limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS } = {}
) {
  assertExactKeys(
    value,
    ['schemaVersion', 'complete', 'ownerKeys', 'owners', 'tables', 'aggregateSha256'],
    'Assembly storage residual'
  );
  if (value.schemaVersion !== ASSEMBLY_STORAGE_RESIDUAL_SCHEMA) {
    throw new Error(`Assembly storage residual schemaVersion must be ${ASSEMBLY_STORAGE_RESIDUAL_SCHEMA}.`);
  }
  if (value.complete !== true) throw new Error('Assembly storage residual was truncated or incomplete.');
  const limits = normalizeLimits(rawLimits);
  const expectedOwnerKeys = storageResidualOwnerKeys(provenance);
  if (!Array.isArray(value.ownerKeys)) throw new Error('Assembly storage residual ownerKeys must be an array.');
  const ownerKeys = value.ownerKeys.map((key) => String(key ?? '').trim()).sort(comparePortable);
  if (JSON.stringify(ownerKeys) !== JSON.stringify(expectedOwnerKeys)) {
    throw new Error('Assembly storage residual ownerKeys do not match the exact mutating provenance prefix.');
  }
  if (!Array.isArray(value.owners) || value.owners.length !== ownerKeys.length) {
    throw new Error('Assembly storage residual owners must cover every exact prefix owner.');
  }
  const owners = value.owners.map((owner, index) => {
    assertExactKeys(owner, ['key', 'tableIds'], `Assembly storage residual owners[${index}]`);
    const key = String(owner.key ?? '').trim();
    if (!Array.isArray(owner.tableIds) || owner.tableIds.length === 0 || owner.tableIds.length > limits.maxTables) {
      throw new Error(`Assembly storage residual owner ${key} tableIds must be a non-empty bounded array.`);
    }
    const tableIds = owner.tableIds.map((id) => String(id ?? '').trim()).sort(comparePortable);
    if (tableIds.some((id) => !TABLE_ID_RE.test(id)) || new Set(tableIds).size !== tableIds.length) {
      throw new Error(`Assembly storage residual owner ${key} tableIds are invalid.`);
    }
    return { key, tableIds };
  }).sort((left, right) => comparePortable(left.key, right.key));
  if (JSON.stringify(owners.map(({ key }) => key)) !== JSON.stringify(ownerKeys)) {
    throw new Error('Assembly storage residual owner rows do not match ownerKeys.');
  }
  if (!Array.isArray(value.tables) || value.tables.length === 0 || value.tables.length > limits.maxTables) {
    throw new Error('Assembly storage residual tables must be a non-empty bounded array.');
  }
  let aggregateRows = 0;
  const tables = value.tables.map((table, index) => {
    assertExactKeys(
      table,
      ['id', 'residualRowCount', 'residualSha256'],
      `Assembly storage residual tables[${index}]`
    );
    const id = String(table.id ?? '').trim();
    if (!TABLE_ID_RE.test(id)) throw new Error(`Assembly storage residual tables[${index}].id is invalid.`);
    const residualRowCount = boundedInteger(
      table.residualRowCount,
      limits.maxRowsPerTable,
      `Assembly storage residual ${id} residualRowCount`
    );
    aggregateRows += residualRowCount;
    if (aggregateRows > limits.maxAggregateRows) {
      throw new Error('Assembly storage residual aggregate rows exceed the verifier cap.');
    }
    return {
      id,
      residualRowCount,
      residualSha256: normalizedHash(
        table.residualSha256,
        `Assembly storage residual ${id} residualSha256`
      )
    };
  }).sort((left, right) => comparePortable(left.id, right.id));
  if (new Set(tables.map(({ id }) => id)).size !== tables.length) {
    throw new Error('Assembly storage residual contains duplicate tables.');
  }
  const ownerTableIds = [...new Set(owners.flatMap(({ tableIds }) => tableIds))].sort(comparePortable);
  if (JSON.stringify(ownerTableIds) !== JSON.stringify(tables.map(({ id }) => id))) {
    throw new Error('Assembly storage residual table coverage does not equal the exact owner table union.');
  }
  const aggregateSha256 = normalizedHash(value.aggregateSha256, 'Assembly storage residual aggregateSha256');
  if (aggregateSha256 !== sha256({ ownerKeys, owners, tables })) {
    throw new Error('Assembly storage residual aggregate fingerprint is inconsistent.');
  }
  return { schemaVersion: ASSEMBLY_STORAGE_RESIDUAL_SCHEMA, complete: true, ownerKeys, owners, tables, aggregateSha256 };
}

function storageResidualEvalSource(resources, limits) {
  const specification = encodedSpec({ resources, limits });
  return String.raw`
$spec = json_decode(base64_decode('${specification}', TRUE), TRUE, 64, JSON_THROW_ON_ERROR);
$normalize = function ($value) use (&$normalize) {
  if (!is_array($value)) return $value;
  if (!array_is_list($value)) ksort($value, SORT_STRING);
  foreach ($value as $key => $child) $value[$key] = $normalize($child);
  return $value;
};
$hash_value = static function ($value) use ($normalize): string {
  return 'sha256:' . hash('sha256', json_encode($normalize($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
};
$started = microtime(TRUE);
$check_deadline = static function () use ($spec, $started): void {
  if (((microtime(TRUE) - $started) * 1000) > $spec['limits']['maxElapsedMs']) throw new \OverflowException('elapsed_time_cap');
};
try {
  $connection = \Drupal::database();
  $schema = $connection->schema();
  $manager = \Drupal::entityTypeManager();
  $owner_tables = [];
  $selectors = [];
  $covered_tables = [];
  $add_table = static function (string $owner_key, string $table_name, ?array $conditions = NULL) use (&$owner_tables, &$selectors, &$covered_tables, $schema): void {
    if (!preg_match('/^[A-Za-z0-9_.-]{1,255}$/D', $table_name) || !$schema->tableExists($table_name)) {
      throw new \RuntimeException('storage_residual_table_unverifiable');
    }
    $owner_tables[$owner_key][$table_name] = TRUE;
    $covered_tables[$table_name] = TRUE;
    if ($conditions === NULL) return;
    if ($conditions === []) throw new \RuntimeException('storage_residual_selector_empty');
    foreach ($conditions as $column => $_value) {
      if (!is_string($column) || !$schema->fieldExists($table_name, $column)) {
        throw new \RuntimeException('storage_residual_selector_column_unverifiable');
      }
    }
    $selectors[$table_name][] = ['ownerKey' => $owner_key, 'conditions' => $conditions];
  };
  foreach ($spec['resources'] as $resource) {
    $target = $resource['target'];
    if ($target['kind'] === 'config') {
      $owner_key = 'config:' . $target['name'];
      $add_table($owner_key, 'config', ['collection' => '', 'name' => $target['name']]);
      if (($resource['surface'] ?? '') === 'view') {
        if (!str_starts_with($target['name'], 'views.view.')) throw new \RuntimeException('storage_residual_view_target_invalid');
        if ($schema->tableExists('router')) {
          $view_id = substr($target['name'], strlen('views.view.'));
          $view_data = \Drupal::config($target['name'])->getRawData();
          $displays = is_array($view_data['display'] ?? NULL) ? $view_data['display'] : [];
          $route_names = [];
          foreach ($displays as $display_id => $display) {
            if (($display['display_plugin'] ?? '') === 'page') $route_names[] = 'view.' . $view_id . '.' . $display_id;
          }
          sort($route_names, SORT_STRING);
          if ($route_names === []) $add_table($owner_key, 'router');
          else foreach ($route_names as $route_name) $add_table($owner_key, 'router', ['name' => $route_name]);
        }
      }
      continue;
    }
    if ($target['kind'] !== 'entity') throw new \RuntimeException('storage_residual_target_unsupported');
    $owner_key = 'entity:' . $target['entityType'] . ':' . $target['stableId'];
    if (!preg_match('/^uuid:([a-f0-9-]{36})$/D', $target['stableId'], $uuid_match)) {
      throw new \RuntimeException('storage_residual_uuid_required');
    }
    $definition = $manager->getDefinition($target['entityType'], FALSE);
    if (!$definition instanceof \Drupal\Core\Entity\ContentEntityTypeInterface) throw new \RuntimeException('storage_residual_entity_definition_unsupported');
    $storage = $manager->getStorage($target['entityType']);
    if (!$storage instanceof \Drupal\Core\Entity\Sql\SqlContentEntityStorage) throw new \RuntimeException('storage_residual_entity_storage_unsupported');
    $mapping = $storage->getTableMapping();
    if (!$mapping instanceof \Drupal\Core\Entity\Sql\DefaultTableMapping || !method_exists($mapping, 'getTableNames')) {
      throw new \RuntimeException('storage_residual_table_mapping_unsupported');
    }
    $id_key = (string) ($definition->getKey('id') ?? '');
    $uuid_key = (string) ($definition->getKey('uuid') ?? '');
    if ($id_key === '' || $uuid_key === '') throw new \RuntimeException('storage_residual_entity_keys_missing');
    $entities = $storage->loadByProperties([$uuid_key => $uuid_match[1]]);
    if (count($entities) > 1) throw new \RuntimeException('storage_residual_uuid_ambiguous');
    $entity_id = count($entities) === 1 ? (string) reset($entities)->id() : NULL;
    $table_names = array_values(array_unique(array_filter($mapping->getTableNames(), 'is_string')));
    sort($table_names, SORT_STRING);
    if ($table_names === []) throw new \RuntimeException('storage_residual_table_mapping_empty');
    foreach ($table_names as $table_name) {
      $owner_column = $schema->fieldExists($table_name, 'entity_id') ? 'entity_id' : ($schema->fieldExists($table_name, $id_key) ? $id_key : '');
      if ($owner_column === '') throw new \RuntimeException('storage_residual_owner_column_unverifiable');
      $add_table($owner_key, $table_name, $entity_id === NULL ? NULL : [$owner_column => $entity_id]);
    }
    if (($resource['surface'] ?? '') === 'node' && $schema->tableExists('node_access')) {
      $add_table($owner_key, 'node_access', $entity_id === NULL ? NULL : ['nid' => $entity_id]);
    }
    if (($resource['surface'] ?? '') === 'menu' && $schema->tableExists('menu_tree')) {
      if ($target['entityType'] !== 'menu_link_content') throw new \RuntimeException('storage_residual_menu_target_unsupported');
      $add_table($owner_key, 'menu_tree', ['id' => 'menu_link_content:' . $uuid_match[1]]);
    }
  }
  ksort($covered_tables, SORT_STRING);
  if (count($covered_tables) > $spec['limits']['maxTables']) throw new \OverflowException('table_cap');
  $aggregate_rows = 0;
  $tables = [];
  foreach (array_keys($covered_tables) as $table_name) {
    $check_deadline();
    $residual_hashes = [];
    $result = $connection->select($table_name, 't')->fields('t')->execute();
    while ($row = $result->fetchAssoc()) {
      $check_deadline();
      $matching_owners = [];
      foreach (($selectors[$table_name] ?? []) as $selector) {
        $matches = TRUE;
        foreach ($selector['conditions'] as $column => $expected) {
          if (!array_key_exists($column, $row) || (string) $row[$column] !== (string) $expected) {
            $matches = FALSE;
            break;
          }
        }
        if ($matches) $matching_owners[$selector['ownerKey']] = TRUE;
      }
      if (count($matching_owners) > 1) throw new \RuntimeException('storage_residual_selector_overlap');
      if ($matching_owners !== []) continue;
      $opaque_row = [];
      foreach ($row as $column => $cell) {
        if ($cell === NULL) $opaque_row[$column] = ['type' => 'null'];
        else {
          $bytes = (string) $cell;
          $opaque_row[$column] = [
            'type' => gettype($cell),
            'byteCount' => strlen($bytes),
            'sha256' => 'sha256:' . hash('sha256', $bytes),
          ];
        }
      }
      $residual_hashes[] = $hash_value($opaque_row);
      if (count($residual_hashes) > $spec['limits']['maxRowsPerTable']) throw new \OverflowException('table_row_cap');
      $aggregate_rows++;
      if ($aggregate_rows > $spec['limits']['maxAggregateRows']) throw new \OverflowException('aggregate_row_cap');
    }
    sort($residual_hashes, SORT_STRING);
    $tables[] = [
      'id' => 'table:' . $table_name,
      'residualRowCount' => count($residual_hashes),
      'residualSha256' => $hash_value(['id' => 'table:' . $table_name, 'rowSha256' => $residual_hashes]),
    ];
  }
  $owners = [];
  ksort($owner_tables, SORT_STRING);
  foreach ($owner_tables as $key => $table_names) {
    $ids = array_map(static fn ($table_name): string => 'table:' . $table_name, array_keys($table_names));
    sort($ids, SORT_STRING);
    $owners[] = ['key' => $key, 'tableIds' => $ids];
  }
  $owner_keys = array_map(static fn ($owner): string => $owner['key'], $owners);
  print json_encode([
    'schemaVersion' => 'public-kit.assembly-storage-residual.1',
    'complete' => TRUE,
    'ownerKeys' => $owner_keys,
    'owners' => $owners,
    'tables' => $tables,
    'aggregateSha256' => $hash_value(['ownerKeys' => $owner_keys, 'owners' => $owners, 'tables' => $tables]),
  ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
catch (\OverflowException $exception) {
  print json_encode(['schemaVersion' => 'public-kit.assembly-storage-residual.1', 'complete' => FALSE, 'reason' => $exception->getMessage()], JSON_THROW_ON_ERROR);
}
`;
}

/** Hash only rows outside exact prefix ownership in every prefix-covered table. */
export function captureProvenanceStorageResidual({
  execute,
  projectRoot,
  provenance,
  target = 'disposable',
  limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS
}) {
  const limits = normalizeLimits(rawLimits);
  storageResidualOwnerKeys(provenance);
  const resources = provenance.resources.map(({ surface, target: resourceTarget }) => ({
    surface,
    target: resourceTarget
  }));
  const source = storageResidualEvalSource(resources, limits);
  const output = fixedEval(
    execute,
    projectRoot,
    target,
    'assembly-storage-residual-readback',
    source,
    Math.min(limits.maxElapsedMs + 30_000, 600_000)
  );
  return parseProvenanceStorageResidual(
    parseJsonOutput(output, 'Assembly storage residual readback'),
    provenance,
    { limits }
  );
}

export function compareProvenanceStorageResidual(before, after) {
  const beforeTables = new Map(before.tables.map((row) => [row.id, row]));
  const afterTables = new Map(after.tables.map((row) => [row.id, row]));
  const changedTableIds = [...new Set([...beforeTables.keys(), ...afterTables.keys()])]
    .sort(comparePortable)
    .filter((id) => sha256(beforeTables.get(id)) !== sha256(afterTables.get(id)));
  return {
    exact: changedTableIds.length === 0 && before.aggregateSha256 === after.aggregateSha256,
    changedTableIds
  };
}

export function assertExactProvenanceStorageResidual(before, after, label = 'Assembly storage residual') {
  const comparison = compareProvenanceStorageResidual(before, after);
  if (!comparison.exact) {
    throw new Error(`${label} changed rows outside exact prefix ownership in ${comparison.changedTableIds[0] ?? 'coverage'}.`);
  }
  return comparison;
}

function provenanceEntityTargets(provenance) {
  if (!provenance || !Array.isArray(provenance.resources)) {
    throw new Error('Assembly provenance must contain a bounded resource array.');
  }
  const targets = provenance.resources.filter(({ target }) => target?.kind === 'entity').map(({ target }) => {
    const key = assemblyTargetKey(target);
    const entityType = String(target.entityType ?? '').trim();
    const stableId = String(target.stableId ?? '').trim().toLowerCase();
    if (!/^[a-z][a-z0-9_]{0,127}$/.test(entityType)) {
      throw new Error(`Provenance entity target ${key} has an unsupported entity type.`);
    }
    if (!/^uuid:[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(stableId)) {
      throw new Error(`Provenance entity target ${key} must use UUID identity for safe storage attribution.`);
    }
    return { key, entityType, stableId };
  }).sort((left, right) => comparePortable(left.key, right.key));
  if (targets.length > 5_000) throw new Error('Assembly provenance contains too many entity identity targets.');
  if (new Set(targets.map(({ key }) => key)).size !== targets.length) {
    throw new Error('Assembly provenance contains duplicate entity identity targets.');
  }
  return targets;
}

function identityEvalSource(targets) {
  const specification = encodedSpec({ targets });
  return String.raw`
$spec = json_decode(base64_decode('${specification}', TRUE), TRUE, 32, JSON_THROW_ON_ERROR);
$normalize = function ($value) use (&$normalize) {
  if (!is_array($value)) return $value;
  if (!array_is_list($value)) ksort($value, SORT_STRING);
  foreach ($value as $key => $child) $value[$key] = $normalize($child);
  return $value;
};
$hash_value = static function ($value) use ($normalize): string {
  return 'sha256:' . hash('sha256', json_encode($normalize($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
};
$manager = \Drupal::entityTypeManager();
$schema = \Drupal::database()->schema();
$rows = [];
foreach ($spec['targets'] as $target) {
  $definition = $manager->getDefinition($target['entityType'], FALSE);
  if (!$definition instanceof \Drupal\Core\Entity\ContentEntityTypeInterface) throw new \RuntimeException('unsupported_entity_definition');
  $storage = $manager->getStorage($target['entityType']);
  if (!$storage instanceof \Drupal\Core\Entity\Sql\SqlContentEntityStorage) throw new \RuntimeException('unsupported_entity_storage');
  $mapping = $storage->getTableMapping();
  if (!$mapping instanceof \Drupal\Core\Entity\Sql\DefaultTableMapping || !method_exists($mapping, 'getTableNames')) {
    throw new \RuntimeException('unsupported_entity_table_mapping');
  }
  $uuid_key = (string) ($definition->getKey('uuid') ?? '');
  if ($uuid_key === '') throw new \RuntimeException('entity_uuid_key_missing');
  $table_names = array_values(array_unique(array_filter($mapping->getTableNames(), 'is_string')));
  sort($table_names, SORT_STRING);
  if ($table_names === []) throw new \RuntimeException('entity_table_mapping_empty');
  $table_ids = [];
  foreach ($table_names as $table_name) {
    if (!preg_match('/^[A-Za-z0-9_.-]{1,255}$/D', $table_name) || !$schema->tableExists($table_name)) {
      throw new \RuntimeException('entity_table_mapping_unverifiable');
    }
    $table_ids[] = 'table:' . $table_name;
  }
  $sequence_table_ids = static function (array $table_names) use ($schema, $table_ids): array {
    $ids = [];
    foreach (array_values(array_unique(array_filter($table_names, 'is_string'))) as $table_name) {
      $id = 'table:' . $table_name;
      if (!$schema->tableExists($table_name) || !in_array($id, $table_ids, TRUE)) {
        throw new \RuntimeException('entity_sequence_table_mapping_unverifiable');
      }
      $ids[] = $id;
    }
    sort($ids, SORT_STRING);
    return $ids;
  };
  $revision_table = $definition->isRevisionable() ? (string) ($mapping->getRevisionTable() ?? '') : '';
  $base_table = (string) ($mapping->getBaseTable() ?? '');
  $create_sequence_table_ids = $sequence_table_ids(array_filter([$base_table, $revision_table]));
  $update_sequence_table_ids = $sequence_table_ids(array_filter([$revision_table]));
  $uuid = substr($target['stableId'], strlen('uuid:'));
  $entities = $storage->loadByProperties([$uuid_key => $uuid]);
  if (count($entities) > 1) throw new \RuntimeException('entity_uuid_ambiguous');
  $present = count($entities) === 1;
  $storage_opaque = ['key' => $target['key'], 'present' => $present];
  $revision_opaque = ['key' => $target['key'], 'present' => $present];
  if ($present) {
    $entity = reset($entities);
    $storage_opaque['storageId'] = (string) $entity->id();
    $revision_opaque['revisionId'] = method_exists($entity, 'getRevisionId') ? (string) ($entity->getRevisionId() ?? '') : '';
  }
  $storage_identity = $hash_value($storage_opaque);
  $revision_identity = $hash_value($revision_opaque);
  $rows[] = [
    'key' => $target['key'],
    'present' => $present,
    'identitySha256' => $hash_value([
      'storageIdentitySha256' => $storage_identity,
      'revisionIdentitySha256' => $revision_identity,
    ]),
    'storageIdentitySha256' => $storage_identity,
    'revisionIdentitySha256' => $revision_identity,
    'tableIds' => $table_ids,
    'createSequenceTableIds' => $create_sequence_table_ids,
    'updateSequenceTableIds' => $update_sequence_table_ids,
  ];
}
usort($rows, static fn ($left, $right): int => strcmp($left['key'], $right['key']));
print json_encode([
  'schemaVersion' => 'public-kit.assembly-entity-identity.1',
  'rows' => $rows,
  'aggregateSha256' => $hash_value($rows),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
`;
}

export function parseProvenanceEntityIdentity(value, targets) {
  assertExactKeys(value, ['schemaVersion', 'rows', 'aggregateSha256'], 'Assembly entity identity');
  if (value.schemaVersion !== ASSEMBLY_ENTITY_IDENTITY_SCHEMA) {
    throw new Error(`Assembly entity identity schemaVersion must be ${ASSEMBLY_ENTITY_IDENTITY_SCHEMA}.`);
  }
  if (!Array.isArray(targets) || !Array.isArray(value.rows) || value.rows.length !== targets.length) {
    throw new Error('Assembly entity identity must cover every provenance entity target exactly once.');
  }
  const rows = value.rows.map((row, index) => {
    assertExactKeys(
      row,
      [
        'key',
        'present',
        'identitySha256',
        'storageIdentitySha256',
        'revisionIdentitySha256',
        'tableIds',
        'createSequenceTableIds',
        'updateSequenceTableIds'
      ],
      `Assembly entity identity rows[${index}]`
    );
    const key = String(row.key ?? '').trim();
    if (typeof row.present !== 'boolean') throw new Error(`Assembly entity identity rows[${index}].present must be boolean.`);
    if (!Array.isArray(row.tableIds) || row.tableIds.length === 0 || row.tableIds.length > 1_024) {
      throw new Error(`Assembly entity identity rows[${index}].tableIds must be a non-empty bounded array.`);
    }
    const tableIds = row.tableIds.map((id) => String(id ?? '').trim()).sort(comparePortable);
    if (tableIds.some((id) => !TABLE_ID_RE.test(id)) || new Set(tableIds).size !== tableIds.length) {
      throw new Error(`Assembly entity identity rows[${index}].tableIds are invalid.`);
    }
    const sequenceTableIds = (value, field) => {
      if (!Array.isArray(value) || value.length > tableIds.length) {
        throw new Error(`Assembly entity identity rows[${index}].${field} must be a bounded array.`);
      }
      const ids = value.map((id) => String(id ?? '').trim()).sort(comparePortable);
      if (
        ids.some((id) => !TABLE_ID_RE.test(id) || !tableIds.includes(id)) ||
        new Set(ids).size !== ids.length
      ) {
        throw new Error(`Assembly entity identity rows[${index}].${field} is invalid.`);
      }
      return ids;
    };
    const createSequenceTableIds = sequenceTableIds(row.createSequenceTableIds, 'createSequenceTableIds');
    const updateSequenceTableIds = sequenceTableIds(row.updateSequenceTableIds, 'updateSequenceTableIds');
    if (updateSequenceTableIds.some((id) => !createSequenceTableIds.includes(id))) {
      throw new Error(`Assembly entity identity rows[${index}] update sequence tables must be create sequence tables.`);
    }
    const storageIdentitySha256 = normalizedHash(
      row.storageIdentitySha256,
      `Assembly entity identity ${key} storage digest`
    );
    const revisionIdentitySha256 = normalizedHash(
      row.revisionIdentitySha256,
      `Assembly entity identity ${key} revision digest`
    );
    const identitySha256 = normalizedHash(row.identitySha256, `Assembly entity identity ${key} digest`);
    if (identitySha256 !== sha256({ storageIdentitySha256, revisionIdentitySha256 })) {
      throw new Error(`Assembly entity identity ${key} aggregate identity digest is inconsistent.`);
    }
    return {
      key,
      present: row.present,
      identitySha256,
      storageIdentitySha256,
      revisionIdentitySha256,
      tableIds,
      createSequenceTableIds,
      updateSequenceTableIds
    };
  }).sort((left, right) => comparePortable(left.key, right.key));
  const expected = targets.map(({ key }) => key).sort(comparePortable);
  if (JSON.stringify(rows.map(({ key }) => key)) !== JSON.stringify(expected)) {
    throw new Error('Assembly entity identity keys do not match the exact provenance entity target set.');
  }
  const aggregateSha256 = normalizedHash(value.aggregateSha256, 'Assembly entity identity aggregateSha256');
  if (aggregateSha256 !== sha256(rows)) throw new Error('Assembly entity identity aggregate fingerprint is inconsistent.');
  return { schemaVersion: ASSEMBLY_ENTITY_IDENTITY_SCHEMA, rows, aggregateSha256 };
}

/** Hash storage/revision IDs inside Drupal and return only opaque identity digests. */
export function captureProvenanceEntityIdentity({ execute, projectRoot, provenance, target = 'disposable' }) {
  const targets = provenanceEntityTargets(provenance);
  if (targets.length === 0) {
    const rows = [];
    return { schemaVersion: ASSEMBLY_ENTITY_IDENTITY_SCHEMA, rows, aggregateSha256: sha256(rows) };
  }
  const source = identityEvalSource(targets);
  const output = fixedEval(execute, projectRoot, target, 'assembly-entity-identity-readback', source, 120_000);
  return parseProvenanceEntityIdentity(
    parseJsonOutput(output, 'Assembly entity identity readback'),
    targets
  );
}

export function compareProvenanceEntityIdentity(before, after) {
  const beforeRows = new Map(before.rows.map((row) => [row.key, row]));
  const afterRows = new Map(after.rows.map((row) => [row.key, row]));
  const keys = [...new Set([...beforeRows.keys(), ...afterRows.keys()])].sort(comparePortable);
  const changedTargetKeys = keys.filter((key) => sha256(beforeRows.get(key)) !== sha256(afterRows.get(key)));
  const changedStorageTargetKeys = keys.filter((key) => (
    beforeRows.get(key)?.storageIdentitySha256 !== afterRows.get(key)?.storageIdentitySha256
  ));
  const changedRevisionTargetKeys = keys.filter((key) => (
    beforeRows.get(key)?.revisionIdentitySha256 !== afterRows.get(key)?.revisionIdentitySha256
  ));
  return {
    exact: changedTargetKeys.length === 0 && before.aggregateSha256 === after.aggregateSha256,
    changedTargetKeys,
    changedStorageTargetKeys,
    changedRevisionTargetKeys
  };
}

export function assertExactEntityIdentityEquality(expected, actual, label = 'Assembly entity identity') {
  const comparison = compareProvenanceEntityIdentity(expected, actual);
  if (!comparison.exact) {
    throw new Error(`${label} changed opaque storage/revision identity for ${comparison.changedTargetKeys[0] ?? 'aggregate'}.`);
  }
  return comparison;
}

function fileSurfaceEvalSource(mode, surfaces, limits, backup = null) {
  const specification = encodedSpec({ mode, surfaces, limits, backup });
  return String.raw`
$spec = json_decode(base64_decode('${specification}', TRUE), TRUE, 64, JSON_THROW_ON_ERROR);
${PHP_CANONICAL_AND_FILE_HELPERS}
try {
  $files = [];
  if ($spec['mode'] === 'scan') {
    foreach ($spec['surfaces'] as $scheme) {
      $id = 'file:' . $scheme;
      $root = $resolve_surface($scheme, FALSE);
      $files[] = $root === NULL ? $empty_surface($id) : $scan_tree($root, $id);
    }
  }
  else {
    $project_root = realpath('/var/www/html');
    if ($project_root === FALSE) throw new \RuntimeException('ddev_project_root_unavailable');
    $backup_root = realpath($project_root . DIRECTORY_SEPARATOR . $spec['backup']['relativePath']);
    if ($backup_root === FALSE || !is_dir($backup_root) || is_link($backup_root) || !str_starts_with($backup_root . DIRECTORY_SEPARATOR, $project_root . DIRECTORY_SEPARATOR . '.ddev' . DIRECTORY_SEPARATOR)) {
      throw new \RuntimeException('file_backup_root_unsafe');
    }
    $owner_path = $backup_root . DIRECTORY_SEPARATOR . '.agent-ready-assembly-file-backup.json';
    $owner = json_decode((string) file_get_contents($owner_path), TRUE, 16, JSON_THROW_ON_ERROR);
    if (!is_array($owner) || !hash_equals($spec['backup']['token'], (string) ($owner['token'] ?? ''))) throw new \RuntimeException('file_backup_owner_mismatch');
    $paths_overlap = static function (string $left, string $right): bool {
      $left = rtrim($left, DIRECTORY_SEPARATOR);
      $right = rtrim($right, DIRECTORY_SEPARATOR);
      return $left === $right ||
        str_starts_with($left . DIRECTORY_SEPARATOR, $right . DIRECTORY_SEPARATOR) ||
        str_starts_with($right . DIRECTORY_SEPARATOR, $left . DIRECTORY_SEPARATOR);
    };
    $live_roots = [];
    foreach ($spec['surfaces'] as $scheme) {
      $live_root = $resolve_surface($scheme, TRUE);
      if ($paths_overlap($live_root, $backup_root)) throw new \RuntimeException('file_surface_overlaps_backup');
      foreach ($live_roots as $other_root) {
        if ($paths_overlap($live_root, $other_root)) throw new \RuntimeException('file_surfaces_overlap');
      }
      $live_roots[$scheme] = $live_root;
    }
    foreach ($spec['surfaces'] as $scheme) {
      $id = 'file:' . $scheme;
      $live_root = $live_roots[$scheme];
      $copy_root = $backup_root . DIRECTORY_SEPARATOR . $scheme;
      if ($spec['mode'] === 'backup') {
        if (file_exists($copy_root)) throw new \RuntimeException('file_backup_destination_exists');
        $before = $scan_tree($live_root, $id);
        $copy_tree($live_root, $copy_root);
        $after_source = $scan_tree($live_root, $id);
        $copied = $scan_tree($copy_root, $id);
        if ($before['physicalSha256'] !== $after_source['physicalSha256'] || $after_source['physicalSha256'] !== $copied['physicalSha256']) {
          throw new \RuntimeException('file_surface_changed_during_backup');
        }
        $files[] = $copied;
      }
      elseif ($spec['mode'] === 'restore') {
        if (!is_dir($copy_root) || is_link($copy_root)) throw new \RuntimeException('file_backup_surface_missing');
        $copied = $scan_tree($copy_root, $id);
        $expected = NULL;
        foreach ($spec['backup']['files'] as $row) if ($row['id'] === $id) $expected = $row;
        if ($expected === NULL || $hash_value($copied) !== $hash_value($expected)) throw new \RuntimeException('file_backup_fingerprint_mismatch');
        $scan_tree($live_root, $id);
        $remove_children($live_root);
        $children = scandir($copy_root);
        if ($children === FALSE) throw new \RuntimeException('file_backup_directory_unreadable');
        $children = array_values(array_diff($children, ['.', '..']));
        sort($children, SORT_STRING);
        foreach ($children as $child) $copy_tree($copy_root . DIRECTORY_SEPARATOR . $child, $live_root . DIRECTORY_SEPARATOR . $child);
        $restored = $scan_tree($live_root, $id);
        if ($hash_value($restored) !== $hash_value($expected)) throw new \RuntimeException('file_restore_fingerprint_mismatch');
        $files[] = $restored;
      }
      else throw new \RuntimeException('unsupported_file_backup_mode');
    }
  }
  usort($files, static fn ($left, $right): int => strcmp($left['id'], $right['id']));
  print json_encode([
    'schemaVersion' => 'public-kit.assembly-file-surfaces.1',
    'complete' => TRUE,
    'files' => $files,
    'aggregateSha256' => $hash_value($files),
  ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
catch (\OverflowException $exception) {
  print json_encode(['schemaVersion' => 'public-kit.assembly-file-surfaces.1', 'complete' => FALSE, 'reason' => $exception->getMessage()], JSON_THROW_ON_ERROR);
}
`;
}

export function captureAssemblyFileSurfaces({
  execute,
  projectRoot,
  target = 'disposable',
  limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS,
  surfaces: rawSurfaces = ['public', 'private']
}) {
  const limits = normalizeLimits(rawLimits);
  const surfaces = normalizeFileSurfaces(rawSurfaces);
  const output = fixedEval(
    execute,
    projectRoot,
    target,
    'assembly-file-surface-readback',
    fileSurfaceEvalSource('scan', surfaces, limits),
    Math.min(limits.maxElapsedMs + 30_000, 600_000)
  );
  return parseAssemblyFileSurfaceSnapshot(parseJsonOutput(output, 'Assembly file-surface readback'), { limits, surfaces });
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function regularRealRoot(projectRoot) {
  const root = resolve(projectRoot);
  if (!existsSync(root) || !lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) {
    throw new Error('Assembly project root must be a regular directory.');
  }
  return realpathSync(root);
}

function safeBackupRoot(projectRoot, relativePath) {
  const root = regularRealRoot(projectRoot);
  const path = resolve(root, String(relativePath ?? ''));
  const ddevRoot = resolve(root, '.ddev');
  if (!isInside(ddevRoot, path) || path === ddevRoot) throw new Error('Assembly file backup escaped the verifier-owned DDEV temp area.');
  let cursor = path;
  while (cursor !== root) {
    if (!existsSync(cursor) || lstatSync(cursor).isSymbolicLink()) {
      throw new Error('Assembly file backup path is missing or traverses a symbolic link.');
    }
    cursor = resolve(cursor, '..');
  }
  if (!lstatSync(path).isDirectory()) throw new Error('Assembly file backup root must be a regular directory.');
  return { root, path };
}

function requireBackupHandle(projectRoot, handle) {
  if (!handle || handle.schemaVersion !== ASSEMBLY_FILE_BACKUP_SCHEMA) {
    throw new Error('Assembly file backup handle is invalid.');
  }
  const record = FILE_BACKUP_TOKENS.get(handle);
  if (!record) throw new Error('Assembly file backup is not owned by this verifier process.');
  const { token } = record;
  const { path } = safeBackupRoot(projectRoot, handle.relativePath);
  const ownerPath = join(path, FILE_BACKUP_OWNER);
  if (!existsSync(ownerPath) || lstatSync(ownerPath).isSymbolicLink() || !lstatSync(ownerPath).isFile()) {
    throw new Error('Assembly file backup owner marker is missing or unsafe.');
  }
  let owner;
  try {
    owner = JSON.parse(readFileSync(ownerPath, 'utf8'));
  } catch {
    throw new Error('Assembly file backup owner marker is invalid.');
  }
  if (
    owner?.schemaVersion !== ASSEMBLY_FILE_BACKUP_SCHEMA ||
    owner?.token !== token ||
    sha256(token) !== handle.tokenSha256
  ) {
    throw new Error('Assembly file backup owner identity changed.');
  }
  return { path, token, manifestFingerprint: record.manifestFingerprint };
}

/**
 * Copy every declared live stream-wrapper root into a verifier-owned temp tree.
 * The handle exposes no backup token or source path and is process-local.
 */
export function createAssemblyFileBackup({
  execute,
  projectRoot,
  target = 'disposable',
  limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS,
  surfaces: rawSurfaces,
  baseline = null
}) {
  const root = regularRealRoot(projectRoot);
  const limits = normalizeLimits(rawLimits);
  const baselineSurfaces = baseline?.files?.filter(({ available }) => available).map(({ id }) => String(id).replace(/^file:/, ''));
  const surfaces = normalizeFileSurfaces(rawSurfaces ?? baselineSurfaces ?? ['public', 'private']);
  const ddevRoot = resolve(root, '.ddev');
  if (!existsSync(ddevRoot) || lstatSync(ddevRoot).isSymbolicLink() || !lstatSync(ddevRoot).isDirectory()) {
    throw new Error('Assembly file backup requires a regular disposable .ddev directory.');
  }
  const backupRoot = mkdtempSync(join(ddevRoot, '.agent-ready-assembly-files-'));
  const relativePath = relative(root, backupRoot).split(sep).join('/');
  const token = randomUUID();
  writeFileSync(join(backupRoot, FILE_BACKUP_OWNER), `${JSON.stringify({
    schemaVersion: ASSEMBLY_FILE_BACKUP_SCHEMA,
    token
  })}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  const source = fileSurfaceEvalSource('backup', surfaces, limits, { relativePath, token, files: [] });
  let snapshot;
  try {
    snapshot = parseAssemblyFileSurfaceSnapshot(parseJsonOutput(
      fixedEval(
        execute,
        root,
        target,
        'assembly-file-surface-backup',
        source,
        Math.min(limits.maxElapsedMs + 30_000, 600_000)
      ),
      'Assembly file-surface backup'
    ), { limits, surfaces });
    if (snapshot.files.some(({ available }) => !available)) {
      throw new Error('Assembly file backup did not cover every declared live file surface.');
    }
  } catch (error) {
    const metadata = lstatSync(backupRoot);
    if (!metadata.isSymbolicLink() && metadata.isDirectory()) rmSync(backupRoot, { recursive: true, force: false });
    throw error;
  }
  const handle = {
    schemaVersion: ASSEMBLY_FILE_BACKUP_SCHEMA,
    relativePath,
    tokenSha256: sha256(token),
    surfaces,
    files: snapshot.files,
    aggregateSha256: snapshot.aggregateSha256
  };
  const backupManifest = collectFileManifest(root, [relativePath]);
  FILE_BACKUP_TOKENS.set(handle, { token, manifestFingerprint: backupManifest.fingerprint });
  return handle;
}

/** Restore declared roots and require the fixed readback to equal the backup fingerprint exactly. */
export function restoreAssemblyFileBackup({
  execute,
  projectRoot,
  backup,
  target = 'disposable',
  limits: rawLimits = DEFAULT_ASSEMBLY_PERSISTENCE_LIMITS
}) {
  const limits = normalizeLimits(rawLimits);
  const surfaces = normalizeFileSurfaces(backup?.surfaces);
  const { token } = requireBackupHandle(projectRoot, backup);
  const source = fileSurfaceEvalSource('restore', surfaces, limits, {
    relativePath: backup.relativePath,
    token,
    files: backup.files
  });
  const restored = parseAssemblyFileSurfaceSnapshot(parseJsonOutput(
    fixedEval(
      execute,
      projectRoot,
      target,
      'assembly-file-surface-restore',
      source,
      Math.min(limits.maxElapsedMs + 30_000, 600_000)
    ),
    'Assembly file-surface restore'
  ), { limits, surfaces });
  if (restored.aggregateSha256 !== backup.aggregateSha256) {
    throw new Error('Verifier-owned file restoration did not reproduce the exact backup fingerprint.');
  }
  return restored;
}

/** Remove only a still-owned, symlink-free verifier temp backup. */
export function disposeAssemblyFileBackup({ projectRoot, backup }) {
  const { path } = requireBackupHandle(projectRoot, backup);
  rmSync(path, { recursive: true, force: false });
  FILE_BACKUP_TOKENS.delete(backup);
  return true;
}

/** Register only the verifier's fixed random-name database dump as a process-owned source exclusion. */
export function registerVerifierDatabaseSourceExclusion({ projectRoot, relativePath, expectedFingerprint = '' }) {
  const root = regularRealRoot(projectRoot);
  const portable = String(relativePath ?? '').replaceAll('\\', '/');
  if (!/^\.ddev\/agent-ready-assembly-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.sql\.gz$/i.test(portable)) {
    throw new Error('Verifier database source exclusion path is not the fixed random backup form.');
  }
  const path = resolve(root, portable);
  if (!isInside(root, path) || !existsSync(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) {
    throw new Error('Verifier database source exclusion must be an owned regular file inside the disposable clone.');
  }
  const manifest = collectFileManifest(root, [portable]);
  if (expectedFingerprint && manifest.fingerprint !== expectedFingerprint) {
    throw new Error('Verifier database source exclusion bytes do not match the created backup.');
  }
  const handle = {
    schemaVersion: ASSEMBLY_DATABASE_SOURCE_EXCLUSION_SCHEMA,
    relativePath: portable,
    entryCount: manifest.entryCount,
    byteCount: manifest.entries.reduce((sum, row) => sum + row.size, 0),
    fingerprint: manifest.fingerprint
  };
  DATABASE_SOURCE_EXCLUSIONS.set(handle, { root });
  return handle;
}

function requireDatabaseSourceExclusion(projectRoot, handle) {
  const root = regularRealRoot(projectRoot);
  const record = DATABASE_SOURCE_EXCLUSIONS.get(handle);
  if (!record || record.root !== root || handle?.schemaVersion !== ASSEMBLY_DATABASE_SOURCE_EXCLUSION_SCHEMA) {
    throw new Error('Verifier database source exclusion is not owned by this verifier process.');
  }
  const manifest = collectFileManifest(root, [handle.relativePath]);
  if (manifest.fingerprint !== handle.fingerprint) {
    throw new Error('Verifier database source exclusion bytes changed after backup creation.');
  }
  return manifest;
}

function checkedGitOutput(execute, args, projectRoot, phase, { binary = false } = {}) {
  const result = execute('git', args, {
    cwd: projectRoot,
    phase,
    target: 'disposable',
    timeout: 60_000,
    maxBuffer: SOURCE_MAX_DIFF_BYTES + 1
  });
  if (!result || result.status !== 0) throw new Error(`${phase} failed.`);
  const output = binary && Buffer.isBuffer(result.stdout) ? result.stdout : String(result.stdout ?? '');
  if (Buffer.byteLength(output) > SOURCE_MAX_DIFF_BYTES) throw new Error(`${phase} exceeded its byte cap.`);
  return output;
}

/**
 * Fingerprint exact HEAD plus tracked worktree diff bytes and every nonignored
 * untracked file byte. Paths and bytes are reduced to counts/digests.
 */
export function captureDisposableSourceBytes({
  execute,
  projectRoot,
  excludedFileBackups = [],
  excludedSourceArtifacts = []
}) {
  const root = regularRealRoot(projectRoot);
  if (!Array.isArray(excludedFileBackups)) throw new Error('Excluded file backups must be an array.');
  if (!Array.isArray(excludedSourceArtifacts)) throw new Error('Excluded source artifacts must be an array.');
  const exclusionRows = [];
  const excludedPrefixes = excludedFileBackups.map((backup) => {
    const { manifestFingerprint } = requireBackupHandle(root, backup);
    const manifest = collectFileManifest(root, [backup.relativePath]);
    if (manifest.fingerprint !== manifestFingerprint) {
      throw new Error('Verifier-owned file backup bytes changed after backup creation.');
    }
    exclusionRows.push({
      pathSha256: sha256(backup.relativePath),
      entryCount: manifest.entryCount,
      byteCount: manifest.entries.reduce((sum, row) => sum + row.size, 0),
      fingerprint: manifest.fingerprint
    });
    return `${String(backup.relativePath).replaceAll('\\', '/').replace(/\/$/, '')}/`;
  });
  for (const artifact of excludedSourceArtifacts) {
    const manifest = requireDatabaseSourceExclusion(root, artifact);
    exclusionRows.push({
      pathSha256: sha256(artifact.relativePath),
      entryCount: manifest.entryCount,
      byteCount: manifest.entries.reduce((sum, row) => sum + row.size, 0),
      fingerprint: manifest.fingerprint
    });
    excludedPrefixes.push(`${String(artifact.relativePath).replaceAll('\\', '/')}/`);
  }
  exclusionRows.sort((left, right) => comparePortable(left.pathSha256, right.pathSha256));
  const head = String(checkedGitOutput(execute, ['rev-parse', 'HEAD'], root, 'assembly-source-bytes:head')).trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(head)) throw new Error('Disposable source HEAD is not a full Git object ID.');
  const trackedDiff = checkedGitOutput(
    execute,
    ['diff', '--binary', '--no-ext-diff', 'HEAD', '--'],
    root,
    'assembly-source-bytes:tracked-diff',
    { binary: true }
  );
  const untrackedOutput = checkedGitOutput(
    execute,
    ['ls-files', '--others', '--exclude-standard', '-z'],
    root,
    'assembly-source-bytes:untracked'
  );
  const untracked = String(untrackedOutput).split('\0').filter(Boolean).filter((path) => {
    const portable = String(path).replaceAll('\\', '/');
    return !excludedPrefixes.some((prefix) => portable === prefix.slice(0, -1) || portable.startsWith(prefix));
  });
  if (untracked.length > SOURCE_MAX_UNTRACKED_FILES) {
    throw new Error(`Disposable source contains more than ${SOURCE_MAX_UNTRACKED_FILES} nonignored untracked files.`);
  }
  const manifest = collectFileManifest(root, untracked);
  const untrackedBytes = manifest.entries.reduce((sum, row) => sum + row.size, 0);
  if (untrackedBytes > SOURCE_MAX_UNTRACKED_BYTES) {
    throw new Error(`Disposable nonignored untracked bytes exceed ${SOURCE_MAX_UNTRACKED_BYTES}.`);
  }
  const runtimeBindingSha256 = sha256(collectRuntimeCodeManifest(root));
  const snapshot = {
    schemaVersion: ASSEMBLY_SOURCE_BYTES_SCHEMA,
    head,
    trackedDiffSha256: sha256(trackedDiff),
    untrackedFileCount: manifest.entryCount,
    untrackedByteCount: untrackedBytes,
    untrackedSha256: manifest.fingerprint,
    runtimeBindingSha256,
    excludedArtifactCount: exclusionRows.length,
    excludedArtifactSha256: sha256(exclusionRows)
  };
  return { ...snapshot, aggregateSha256: sha256(snapshot) };
}

export function assertDisposableSourceBytesEqual(expected, actual, label = 'Disposable source bytes') {
  assertExactKeys(expected, [
    'schemaVersion', 'head', 'trackedDiffSha256', 'untrackedFileCount', 'untrackedByteCount', 'untrackedSha256',
    'runtimeBindingSha256', 'excludedArtifactCount', 'excludedArtifactSha256', 'aggregateSha256'
  ], `${label} expected snapshot`);
  assertExactKeys(actual, [
    'schemaVersion', 'head', 'trackedDiffSha256', 'untrackedFileCount', 'untrackedByteCount', 'untrackedSha256',
    'runtimeBindingSha256', 'excludedArtifactCount', 'excludedArtifactSha256', 'aggregateSha256'
  ], `${label} actual snapshot`);
  if (expected.schemaVersion !== ASSEMBLY_SOURCE_BYTES_SCHEMA || actual.schemaVersion !== ASSEMBLY_SOURCE_BYTES_SCHEMA) {
    throw new Error(`${label} schemaVersion is invalid.`);
  }
  const withoutAggregate = (snapshot) => ({
    schemaVersion: snapshot.schemaVersion,
    head: snapshot.head,
    trackedDiffSha256: snapshot.trackedDiffSha256,
    untrackedFileCount: snapshot.untrackedFileCount,
    untrackedByteCount: snapshot.untrackedByteCount,
    untrackedSha256: snapshot.untrackedSha256,
    runtimeBindingSha256: snapshot.runtimeBindingSha256,
    excludedArtifactCount: snapshot.excludedArtifactCount,
    excludedArtifactSha256: snapshot.excludedArtifactSha256
  });
  if (
    sha256(withoutAggregate(expected)) !== expected.aggregateSha256 ||
    sha256(withoutAggregate(actual)) !== actual.aggregateSha256 ||
    expected.aggregateSha256 !== actual.aggregateSha256
  ) {
    throw new Error(`${label} changed across the assembly operation.`);
  }
  return true;
}
