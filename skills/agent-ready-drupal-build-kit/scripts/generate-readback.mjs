#!/usr/bin/env node

import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DRUSH_SITE_UUID_ARGS,
  READBACK_COUNT_QUERIES,
  UUID_RE,
  cleanScalar,
  configStatusIsClean,
  ddevTargetUrl,
  environmentTargetUrl,
  findDrupalDdevRoot,
  parseCountRows,
  runDrushResult,
  sharedConfigSyncDirectory,
  trackedConfigEvidence
} from './verify.mjs';

const KIT_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const USAGE = `Usage: node <path-to-skill>/scripts/generate-readback.mjs [options]

Generate review-packet/drupal-readback.json from the current DDEV Drupal runtime.
This kit-owned script executes the declared readback commands and embeds
per-measurement timestamps and raw output excerpts; builders must not author
or hand-edit drupal-readback.json.

Options:
  --packet <path>   Review packet directory (default: review-packet)
  --help            Show this help`;
const MAX_OUTPUT_EXCERPT_CHARS = 4000;
const NODE_LIST_QUERY = 'SELECT nid, type, title, status FROM node_field_data ORDER BY nid';
const MEDIA_LIST_QUERY = 'SELECT mid, bundle, name, status FROM media_field_data ORDER BY mid';

class UsageError extends Error {}

function parseArgs(argv) {
  const args = { packet: 'review-packet' };
  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      args.help = true;
      continue;
    }
    const equalsIndex = argument.indexOf('=');
    const option = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    if (option !== '--packet') {
      throw new UsageError(
        argument.startsWith('-') ? `Unknown option: ${argument}.` : `Unexpected positional argument: ${argument}.`
      );
    }
    const value = equalsIndex === -1 ? argv[index + 1] : argument.slice(equalsIndex + 1);
    if (!value || (equalsIndex === -1 && value.startsWith('--'))) {
      throw new UsageError(`${option} requires a value.`);
    }
    if (equalsIndex === -1) {
      index += 1;
    }
    args.packet = value;
  }
  return args;
}

function isDirectRun() {
  if (!process.argv[1]) {
    return false;
  }
  try {
    return realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);
  } catch {
    return false;
  }
}

function outputExcerpt(output) {
  const text = String(output ?? '');
  return text.length > MAX_OUTPUT_EXCERPT_CHARS ? `${text.slice(0, MAX_OUTPUT_EXCERPT_CHARS)}\n[truncated]` : text;
}

function parseJsonObject(text) {
  try {
    const parsed = JSON.parse(text);
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function readbackSkeleton(packetPath) {
  if (existsSync(packetPath)) {
    const existing = parseJsonObject(readFileSync(packetPath, 'utf8'));
    if (existing) {
      return existing;
    }
  }
  for (const templatePath of [
    join(KIT_ROOT, 'templates', 'drupal-readback.template.json'),
    join(KIT_ROOT, 'assets', 'templates', 'drupal-readback.template.json')
  ]) {
    if (existsSync(templatePath)) {
      const template = parseJsonObject(readFileSync(templatePath, 'utf8'));
      if (template) {
        return template;
      }
    }
  }
  return {};
}

function parseEntityRows(output, idField, bundleField) {
  const rows = [];
  for (const line of String(output ?? '').split(/\r?\n/)) {
    const match = line.match(/^(\d+)\t([^\t]+)\t(.*)\t([01])$/);
    if (match) {
      rows.push({
        [idField]: Number(match[1]),
        [bundleField]: match[2].trim(),
        title: match[3].trim(),
        published: match[4] === '1'
      });
    }
  }
  return rows;
}

function mergedBundleCounts(publishedCounts, rawCounts) {
  const counts = {};
  for (const bundle of new Set([...Object.keys(publishedCounts), ...Object.keys(rawCounts)])) {
    counts[bundle] = {
      published: publishedCounts[bundle] ?? 0,
      raw: rawCounts[bundle] ?? 0
    };
  }
  return counts;
}

function countDeltaRecords(entityType, countsByBundle, existingRecords) {
  const records = [];
  for (const [bundle, counts] of Object.entries(countsByBundle)) {
    if (counts.raw <= counts.published) {
      continue;
    }
    const existing = existingRecords.find((record) =>
      String(record?.entityType ?? '').trim() === entityType &&
      String(record?.bundle ?? '').trim() === bundle &&
      Number(record?.publishedCount) === counts.published &&
      Number(record?.rawCount) === counts.raw
    );
    records.push(existing ?? {
      entityType,
      bundle,
      publishedCount: counts.published,
      rawCount: counts.raw,
      reason: '',
      explanation: '',
      owner: ''
    });
  }
  return records;
}

export function generateReadback({
  packetDir = 'review-packet',
  cwd = process.cwd(),
  environment = process.env
} = {}) {
  const projectRoot = findDrupalDdevRoot(cwd);
  if (!projectRoot) {
    throw new Error('No DDEV Drupal project found. Run the readback generator from inside the target project.');
  }

  const measurements = [];
  const measure = (name, args, { required = true } = {}) => {
    const result = runDrushResult(projectRoot, environment, args);
    measurements.push({
      name,
      command: `drush ${args.join(' ')}`,
      checkedAt: new Date().toISOString(),
      ok: result.ok,
      required,
      outputExcerpt: outputExcerpt(result.output)
    });
    return result;
  };

  const status = measure('status', ['status', '--format=json']);
  const uuid = measure('site-uuid', [...DRUSH_SITE_UUID_ARGS]);
  const frontPage = measure('front-page', ['config:get', 'system.site', 'page.front', '--format=string']);
  const configStatus = measure('config-status', ['config:status', '--format=json']);
  const enabledModules = measure('enabled-modules', ['pm:list', '--status=enabled', '--type=module', '--format=json']);
  const nodePublished = measure('node-counts-published', ['sql:query', READBACK_COUNT_QUERIES.nodePublished]);
  const nodeRaw = measure('node-counts-raw', ['sql:query', READBACK_COUNT_QUERIES.nodeRaw]);
  const nodeList = measure('node-list', ['sql:query', NODE_LIST_QUERY]);
  // Media tables are absent when the media module is not installed; the
  // verifier cross-checks that an absent table matches empty packet counts.
  const mediaPublished = measure('media-counts-published', ['sql:query', READBACK_COUNT_QUERIES.mediaPublished], { required: false });
  const mediaRaw = measure('media-counts-raw', ['sql:query', READBACK_COUNT_QUERIES.mediaRaw], { required: false });
  const mediaList = measure('media-list', ['sql:query', MEDIA_LIST_QUERY], { required: false });

  const statusRecord = parseJsonObject(status.output) ?? {};
  const configSyncDirectory = cleanScalar(statusRecord['config-sync']);
  const drupalRoot = cleanScalar(statusRecord.root);
  const trackedConfig = trackedConfigEvidence(projectRoot, configSyncDirectory, drupalRoot);
  measurements.push({
    name: 'git-tracked-config-yaml',
    command: `git ls-files -- ${trackedConfig.directory || sharedConfigSyncDirectory(configSyncDirectory) || '(unresolved config sync directory)'}`,
    checkedAt: new Date().toISOString(),
    ok: trackedConfig.yamlFiles.length > 0,
    required: true,
    outputExcerpt: outputExcerpt(trackedConfig.yamlFiles.join('\n'))
  });

  const enabledModuleRecord = parseJsonObject(enabledModules.output) ?? {};
  const nodeCountsByBundle = mergedBundleCounts(parseCountRows(nodePublished.output), parseCountRows(nodeRaw.output));
  const mediaCountsAvailable = mediaPublished.ok && mediaRaw.ok;
  const mediaPublishedRows = mediaCountsAvailable ? parseCountRows(mediaPublished.output) : {};
  const mediaRawRows = mediaCountsAvailable ? parseCountRows(mediaRaw.output) : {};
  // Emit an explicit count for every bundle seen by either query so a bundle
  // with zero published rows (unpublished or trashed media) still appears as
  // an explicit zero claim instead of a missing key the verifier cannot match.
  const mediaCountsByType = {};
  const mediaRawCountsByType = {};
  for (const bundle of new Set([...Object.keys(mediaPublishedRows), ...Object.keys(mediaRawRows)])) {
    mediaCountsByType[bundle] = mediaPublishedRows[bundle] ?? 0;
    mediaRawCountsByType[bundle] = mediaRawRows[bundle] ?? 0;
  }
  const nodes = parseEntityRows(nodeList.output, 'id', 'type');
  const mediaItems = mediaList.ok ? parseEntityRows(mediaList.output, 'id', 'bundle') : [];

  const packetPath = join(resolve(cwd, packetDir), 'drupal-readback.json');
  const readback = readbackSkeleton(packetPath);
  const existingDeltaRecords = Array.isArray(readback?.content?.publishedVersusRawDeltas)
    ? readback.content.publishedVersusRawDeltas
    : [];
  const publishedVersusRawDeltas = [
    ...countDeltaRecords('node', nodeCountsByBundle, existingDeltaRecords),
    ...countDeltaRecords(
      'media',
      mergedBundleCounts(mediaCountsByType, mediaRawCountsByType),
      existingDeltaRecords
    )
  ];
  const blockers = measurements
    .filter((measurement) => measurement.required && !measurement.ok)
    .map((measurement) => `Readback measurement failed: ${measurement.command}`);

  readback.schemaVersion = 'public-kit.drupal-readback.1';
  readback.site = environmentTargetUrl(environment) || ddevTargetUrl(projectRoot) || String(readback.site ?? '');
  readback.checkedAt = new Date().toISOString();
  readback.generator = { script: 'generate-readback.mjs', kitOwned: true };
  readback.commands = measurements.map((measurement) => measurement.command);
  readback.measurements = measurements;
  readback.drupal = {
    ...(readback.drupal ?? {}),
    status: statusRecord,
    siteUuid: uuid.output.match(UUID_RE)?.[0]?.toLowerCase() ?? '',
    coreVersion: cleanScalar(statusRecord['drupal-version']),
    enabledModules: Object.keys(enabledModuleRecord),
    defaultTheme: cleanScalar(statusRecord.theme),
    adminTheme: cleanScalar(statusRecord['admin-theme']),
    frontPage: cleanScalar(frontPage.output),
    configSyncDirectory,
    trackedConfigDirectory: trackedConfig.directory,
    trackedConfigYamlFiles: trackedConfig.yamlFiles,
    configSyncDirectoryMatchesTrackedDirectory:
      Boolean(trackedConfig.directory) &&
      sharedConfigSyncDirectory(configSyncDirectory) === sharedConfigSyncDirectory(trackedConfig.directory),
    configStatus: configStatus.output || (configStatus.ok ? 'No differences' : ''),
    configStatusClean: configStatusIsClean(configStatus)
  };
  readback.content = {
    ...(readback.content ?? {}),
    nodes,
    unpublishedNodes: nodes.filter((node) => !node.published),
    nodeCountsByBundle,
    publishedVersusRawDeltas
  };
  readback.media = {
    ...(readback.media ?? {}),
    countsByType: mediaCountsByType,
    rawCountsByType: mediaRawCountsByType,
    items: mediaItems
  };
  readback.readbackComplete = blockers.length === 0 && Boolean(readback.drupal.siteUuid);
  readback.blockers = readback.readbackComplete
    ? []
    : [...blockers, ...(readback.drupal.siteUuid ? [] : ['Drupal did not expose a valid system.site UUID through Drush.'])];

  return { outPath: packetPath, readback };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  if (!existsSync(args.packet)) {
    throw new UsageError(`Packet directory does not exist: ${args.packet}.`);
  }

  const { outPath, readback } = generateReadback({ packetDir: args.packet });
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${JSON.stringify(readback, null, 2)}\n`);

  if (!readback.readbackComplete) {
    process.stderr.write(`Drupal readback incomplete. Readback: ${outPath}\n`);
    for (const blocker of readback.blockers) {
      process.stderr.write(`- ${blocker}\n`);
    }
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`Drupal readback generated from the live runtime. Readback: ${outPath}\n`);
}

if (isDirectRun()) {
  main().catch((error) => {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n${USAGE}\n`);
    } else {
      process.stderr.write(`${error.stack || error.message}\n`);
    }
    process.exitCode = 1;
  });
}
