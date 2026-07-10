#!/usr/bin/env node

import { constants } from 'node:fs';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const START_MARKER = '<!-- agent-ready-drupal-build-kit:start -->';
const END_MARKER = '<!-- agent-ready-drupal-build-kit:end -->';
const scriptDir = dirname(fileURLToPath(import.meta.url));
const skillRoot = resolve(scriptDir, '..');

function usage() {
  return `Usage: node scripts/init-kit.mjs --source-url <url> [options]

Initialize the Agent-Ready Drupal Build Kit inside an existing Drupal/DDEV target.

Options:
  --source-url <url>  Required public source site URL (http or https)
  --project <path>    Target project root (default: nearest target at or above cwd)
  --packet <path>     Packet directory inside the target (default: review-packet)
  --dry-run           Validate and report without writing files
  --help              Show this help
`;
}

function parseArgs(argv) {
  const result = {
    dryRun: false,
    packet: 'review-packet',
    project: null,
    sourceUrl: null
  };

  const valueOptions = new Map([
    ['--source-url', 'sourceUrl'],
    ['--project', 'project'],
    ['--packet', 'packet']
  ]);

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help') {
      process.stdout.write(usage());
      process.exit(0);
    }
    if (argument === '--dry-run') {
      result.dryRun = true;
      continue;
    }

    const equalsIndex = argument.indexOf('=');
    const option = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    if (!valueOptions.has(option)) {
      throw new Error(`Unknown argument: ${argument}`);
    }

    const value = equalsIndex === -1 ? argv[index + 1] : argument.slice(equalsIndex + 1);
    if (!value || (equalsIndex === -1 && value.startsWith('--'))) {
      throw new Error(`${option} requires a value`);
    }
    if (equalsIndex === -1) {
      index += 1;
    }
    result[valueOptions.get(option)] = value;
  }

  if (!result.sourceUrl) {
    throw new Error('--source-url is required');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(result.sourceUrl);
  } catch {
    throw new Error('--source-url must be a valid http or https URL');
  }
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error('--source-url must be a valid http or https URL');
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error('--source-url must not contain embedded credentials');
  }
  result.sourceUrl = parsedUrl.href;

  return result;
}

function readComposer(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function targetMarkers(directory) {
  const markers = [];
  let hasProjectRootMarker = false;
  const ddevConfig = join(directory, '.ddev', 'config.yaml');
  if (existsSync(ddevConfig)) {
    const config = readFileSync(ddevConfig, 'utf8');
    if (/^\s*type:\s*["']?drupal(?:\d+)?["']?\s*(?:#.*)?$/mi.test(config)) {
      markers.push('.ddev/config.yaml declares a Drupal project');
      hasProjectRootMarker = true;
    }
  }

  const composerPath = join(directory, 'composer.json');
  if (existsSync(composerPath)) {
    const composer = readComposer(composerPath);
    const packages = composer?.require ?? {};
    const extensionTypes = new Set([
      'drupal-library',
      'drupal-module',
      'drupal-profile',
      'drupal-recipe',
      'drupal-theme'
    ]);
    const knownProjectPackage = ['drupal/cms', 'drupal/recommended-project'].includes(composer?.name);
    const hasProjectShape = composer?.type === 'project' || Boolean(composer?.extra?.['drupal-scaffold']);
    const requiresDrupalCore = ['drupal/core', 'drupal/core-recommended'].some((name) => name in packages);
    if (
      !extensionTypes.has(composer?.type) &&
      (knownProjectPackage || (hasProjectShape && requiresDrupalCore))
    ) {
      markers.push('composer.json declares a Drupal site project');
      hasProjectRootMarker = true;
    }
  }

  for (const candidate of [
    join('web', 'core', 'lib', 'Drupal.php'),
    join('docroot', 'core', 'lib', 'Drupal.php'),
    join('core', 'lib', 'Drupal.php')
  ]) {
    if (existsSync(join(directory, candidate))) {
      markers.push(candidate);
      break;
    }
  }

  return { hasProjectRootMarker, markers };
}

function findProjectRoot(startDirectory, explicit) {
  let candidate = resolve(startDirectory);
  if (explicit) {
    const evidence = targetMarkers(candidate);
    return evidence.hasProjectRootMarker ? { markers: evidence.markers, root: candidate } : null;
  }

  while (true) {
    const evidence = targetMarkers(candidate);
    if (evidence.hasProjectRootMarker) {
      return { markers: evidence.markers, root: candidate };
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      return null;
    }
    candidate = parent;
  }
}

function countOccurrences(content, needle) {
  let count = 0;
  let offset = 0;
  while ((offset = content.indexOf(needle, offset)) !== -1) {
    count += 1;
    offset += needle.length;
  }
  return count;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function renderManagedBlock({ packetPath, projectRoot, sourceUrl }) {
  const templatePath = join(skillRoot, 'assets', 'AGENTS.block.md');
  const template = readFileSync(templatePath, 'utf8').trim();
  const relativeSkillPath = relative(projectRoot, skillRoot).split(sep).join('/') || '.';
  const relativePacketPath = relative(projectRoot, packetPath).split(sep).join('/') || '.';
  const replacements = new Map([
    ['{{SOURCE_URL}}', sourceUrl],
    ['{{SKILL_PATH}}', relativeSkillPath],
    ['{{PACKET_PATH}}', relativePacketPath],
    ['{{SHELL_SKILL_PATH}}', shellQuote(relativeSkillPath)],
    ['{{SHELL_PACKET_PATH}}', shellQuote(relativePacketPath)]
  ]);

  let rendered = template;
  for (const [placeholder, value] of replacements) {
    rendered = rendered.replaceAll(placeholder, value);
  }
  if (/\{\{[A-Z_]+\}\}/.test(rendered)) {
    throw new Error(`Unresolved placeholder in ${templatePath}`);
  }

  return `${START_MARKER}\n${rendered}\n${END_MARKER}`;
}

function mergeManagedBlock(existing, managedBlock) {
  const startCount = countOccurrences(existing, START_MARKER);
  const endCount = countOccurrences(existing, END_MARKER);
  if (startCount !== endCount || startCount > 1) {
    throw new Error('AGENTS.md has malformed or duplicate Agent-Ready Drupal Build Kit markers; no files were changed');
  }

  if (startCount === 0) {
    if (!existing) {
      return `${managedBlock}\n`;
    }
    const separator = existing.endsWith('\n\n') ? '' : existing.endsWith('\n') ? '\n' : '\n\n';
    return `${existing}${separator}${managedBlock}\n`;
  }

  const start = existing.indexOf(START_MARKER);
  const end = existing.indexOf(END_MARKER, start + START_MARKER.length);
  if (end < start) {
    throw new Error('AGENTS.md has reversed Agent-Ready Drupal Build Kit markers; no files were changed');
  }
  return `${existing.slice(0, start)}${managedBlock}${existing.slice(end + END_MARKER.length)}`;
}

function templateName(packetFile) {
  const finalDot = packetFile.lastIndexOf('.');
  return finalDot === -1
    ? `${packetFile}.template`
    : `${packetFile.slice(0, finalDot)}.template${packetFile.slice(finalDot)}`;
}

function packetPlan(packetPath) {
  const gatesPath = join(skillRoot, 'gates.json');
  const gates = JSON.parse(readFileSync(gatesPath, 'utf8'));
  if (!Array.isArray(gates.reviewPacketFiles) || gates.reviewPacketFiles.length === 0) {
    throw new Error(`${gatesPath} does not declare reviewPacketFiles`);
  }

  const uniqueFiles = new Set(gates.reviewPacketFiles);
  if (uniqueFiles.size !== gates.reviewPacketFiles.length) {
    throw new Error(`${gatesPath} contains duplicate reviewPacketFiles`);
  }

  return gates.reviewPacketFiles.map((packetFile) => {
    if (typeof packetFile !== 'string' || packetFile !== basename(packetFile) || ['.', '..'].includes(packetFile)) {
      throw new Error(`Unsafe review packet filename in ${gatesPath}: ${String(packetFile)}`);
    }
    const source = join(skillRoot, 'assets', 'templates', templateName(packetFile));
    if (!existsSync(source)) {
      throw new Error(`Missing installed packet template: ${source}`);
    }
    return { destination: join(packetPath, packetFile), packetFile, source };
  });
}

function isInside(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (!pathFromParent.startsWith(`..${sep}`) && pathFromParent !== '..' && !isAbsolute(pathFromParent));
}

function pathEntryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

function nearestExistingAncestor(path) {
  let candidate = path;
  while (!pathEntryExists(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate) {
      return candidate;
    }
    candidate = parent;
  }
  return candidate;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const requestedProject = options.project ? resolve(options.project) : process.cwd();
  const target = findProjectRoot(requestedProject, Boolean(options.project));
  if (!target) {
    throw new Error('No existing Drupal/DDEV target found. Run this initializer from a Drupal project created by the One Line Installer, or pass --project <path>.');
  }

  const projectRoot = realpathSync(target.root);
  const packetPath = resolve(projectRoot, options.packet);
  if (!isInside(projectRoot, packetPath) || packetPath === projectRoot) {
    throw new Error('--packet must be a directory inside the Drupal target, not the target root');
  }
  const realTargetRoot = projectRoot;
  if (pathEntryExists(packetPath) && lstatSync(packetPath).isSymbolicLink()) {
    throw new Error('--packet must not be a symbolic link');
  }
  const realPacketAncestor = realpathSync(nearestExistingAncestor(packetPath));
  if (!isInside(realTargetRoot, realPacketAncestor)) {
    throw new Error('--packet must not escape the Drupal target through a symbolic link');
  }
  if (pathEntryExists(packetPath) && !statSync(packetPath).isDirectory()) {
    throw new Error('--packet must name a directory');
  }

  const agentsPath = join(projectRoot, 'AGENTS.md');
  if (pathEntryExists(agentsPath) && lstatSync(agentsPath).isSymbolicLink()) {
    throw new Error('AGENTS.md is a symbolic link; refusing to update a target outside this project');
  }
  const existingAgents = pathEntryExists(agentsPath) ? readFileSync(agentsPath, 'utf8') : '';
  const managedBlock = renderManagedBlock({
    packetPath,
    projectRoot,
    sourceUrl: options.sourceUrl
  });
  const nextAgents = mergeManagedBlock(existingAgents, managedBlock);
  const plannedTemplates = packetPlan(packetPath);
  const invalidExistingTemplates = plannedTemplates.filter(
    ({ destination }) => pathEntryExists(destination) && (
      lstatSync(destination).isSymbolicLink() || !statSync(destination).isFile()
    )
  );
  if (invalidExistingTemplates.length > 0) {
    throw new Error(`Review packet paths must be regular non-symlink files: ${invalidExistingTemplates.map(({ packetFile }) => packetFile).join(', ')}`);
  }
  const missingTemplates = plannedTemplates.filter(({ destination }) => !pathEntryExists(destination));

  if (!options.dryRun) {
    mkdirSync(packetPath, { recursive: true });
    for (const { destination, source } of missingTemplates) {
      copyFileSync(source, destination, constants.COPYFILE_EXCL);
    }
    // Keep the project contract unchanged unless the review packet is ready.
    // Packet creation can still fail after validation (for example, because
    // the destination is not writable), so AGENTS.md must be the last write.
    if (nextAgents !== existingAgents) {
      writeFileSync(agentsPath, nextAgents, 'utf8');
    }
  }

  const mode = options.dryRun ? 'Dry run valid' : 'Kit initialized';
  process.stdout.write(`${mode}: ${projectRoot}\n`);
  process.stdout.write(`Target evidence: ${target.markers.join('; ')}\n`);
  process.stdout.write(`AGENTS.md: ${nextAgents === existingAgents ? 'unchanged' : options.dryRun ? 'would update kit block' : 'kit block updated'}\n`);
  process.stdout.write(`Review packet: ${missingTemplates.length} ${options.dryRun ? 'missing' : 'created'}, ${plannedTemplates.length - missingTemplates.length} preserved\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`Initializer failed: ${error.message}\n`);
  process.exitCode = 1;
}
