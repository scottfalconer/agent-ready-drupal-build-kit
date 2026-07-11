#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canvasIntentionallyUnusedClaim,
  canvasTemplateTargetsPublicOutput,
  validatePacket
} from './verify-packet.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const USAGE = `Usage: node <path-to-skill>/scripts/verify.mjs [options]

Verify the packet against the real target by default.

Options:
  --packet <path>      Review packet directory (default: review-packet)
  --target-url <url>   Explicit target URL (otherwise detect current DDEV target)
  --out <path>         Report path (default: review-packet/evidence/live-verification.json)
  --packet-only        Run structural packet lint only; never authorizes completion
  --help               Show this help`;
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 15_000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;

class UsageError extends Error {}

function parseArgs(argv) {
  const args = { packet: 'review-packet', out: '', packetOnly: false, targetUrl: '' };
  const valueOptions = new Map([
    ['--packet', 'packet'],
    ['--out', 'out'],
    ['--target-url', 'targetUrl']
  ]);

  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      args.help = true;
      continue;
    }
    if (argument === '--packet-only') {
      args.packetOnly = true;
      continue;
    }
    const equalsIndex = argument.indexOf('=');
    const option = equalsIndex === -1 ? argument : argument.slice(0, equalsIndex);
    if (!valueOptions.has(option)) {
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
    args[valueOptions.get(option)] = value;
  }

  if (args.packetOnly && args.targetUrl) {
    throw new UsageError('--target-url cannot be combined with --packet-only.');
  }
  if (!args.out) {
    const filename = args.packetOnly ? 'packet-verification.json' : 'live-verification.json';
    args.out = join(args.packet, 'evidence', filename);
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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sharedMessage(value, absolutePacketDir) {
  return String(value).replaceAll(absolutePacketDir, basename(absolutePacketDir));
}

function normalizeText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim();
}

function decodeEntities(value) {
  const named = new Map([
    ['amp', '&'],
    ['apos', "'"],
    ['gt', '>'],
    ['lt', '<'],
    ['nbsp', ' '],
    ['quot', '"']
  ]);
  return value.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (match, entity) => {
    if (entity.startsWith('#')) {
      const radix = entity.startsWith('#x') ? 16 : 10;
      const digits = entity.slice(radix === 16 ? 2 : 1);
      const codePoint = Number.parseInt(digits, radix);
      return Number.isInteger(codePoint) && codePoint >= 0 && codePoint <= 0x10ffff
        ? String.fromCodePoint(codePoint)
        : match;
    }
    return named.get(entity.toLowerCase()) ?? match;
  });
}

function elementText(html, tag) {
  const match = html.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  if (!match) {
    return '';
  }
  return normalizeText(decodeEntities(match[1].replace(/<[^>]+>/g, ' ')));
}

function tagAttributes(tag) {
  const attributes = {};
  const matcher = /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const match of tag.matchAll(matcher)) {
    const name = match[1].toLowerCase();
    if (name.startsWith('<') || name === 'link' || name === 'meta') {
      continue;
    }
    attributes[name] = decodeEntities(match[2] ?? match[3] ?? match[4] ?? '');
  }
  return attributes;
}

function matchingTags(html, tagName, predicate) {
  const tags = html.match(new RegExp(`<${tagName}\\b[^>]*>`, 'gi')) ?? [];
  return tags.map(tagAttributes).filter(predicate);
}

function renderedMetadata(html, finalUrl) {
  const canonicals = matchingTags(html, 'link', (attributes) =>
    String(attributes.rel ?? '').toLowerCase().split(/\s+/).includes('canonical')
  );
  const descriptions = matchingTags(html, 'meta', (attributes) =>
    String(attributes.name ?? '').toLowerCase() === 'description'
  );
  const openGraphImages = matchingTags(html, 'meta', (attributes) =>
    String(attributes.property ?? '').toLowerCase() === 'og:image'
  );
  const robots = matchingTags(html, 'meta', (attributes) =>
    ['robots', 'googlebot'].includes(String(attributes.name ?? '').toLowerCase())
  );
  const absolute = (value) => {
    const text = String(value ?? '').trim();
    if (!text) {
      return '';
    }
    try {
      const url = new URL(text, finalUrl);
      if (url.username || url.password) {
        return '';
      }
      url.hash = '';
      return url.href;
    } catch {
      return '';
    }
  };
  return {
    canonicalCount: canonicals.length,
    canonicalUrl: absolute(canonicals[0]?.href),
    metaDescription: normalizeText(descriptions[0]?.content),
    metaDescriptionCount: descriptions.length,
    noindex: robots.some((attributes) => /(?:^|,)\s*noindex\b/i.test(String(attributes.content ?? ''))),
    openGraphImage: absolute(openGraphImages[0]?.content),
    openGraphImageCount: openGraphImages.length
  };
}

function renderedAssets(html, finalUrl) {
  const absolute = (value) => {
    try {
      const url = new URL(String(value ?? '').trim(), finalUrl);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
        return '';
      }
      url.hash = '';
      return url.href;
    } catch {
      return '';
    }
  };
  const stylesheets = matchingTags(html, 'link', (attributes) =>
    String(attributes.rel ?? '').toLowerCase().split(/\s+/).includes('stylesheet') && Boolean(attributes.href)
  ).map((attributes) => ({
    observedBy: 'link_stylesheet',
    type: 'css',
    url: absolute(attributes.href)
  }));
  const scripts = matchingTags(html, 'script', (attributes) => Boolean(attributes.src)).map((attributes) => ({
    observedBy: 'script_src',
    type: 'js',
    url: absolute(attributes.src)
  }));
  return [...stylesheets, ...scripts].filter((asset) => asset.url);
}

function normalizePath(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  let pathname;
  try {
    pathname = new URL(text).pathname;
  } catch {
    pathname = text.split(/[?#]/)[0] || '/';
  }
  if (!pathname.startsWith('/')) {
    pathname = `/${pathname}`;
  }
  return pathname !== '/' ? pathname.replace(/\/+$/, '') : '/';
}

function parseHttpUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid HTTP or HTTPS URL.`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`${label} must use HTTP or HTTPS.`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not contain credentials.`);
  }
  parsed.hash = '';
  return parsed;
}

function localTlsHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return (
    host === 'localhost' ||
    host === '::1' ||
    host === 'host.docker.internal' ||
    host.endsWith('.localhost') ||
    host.endsWith('.ddev.site') ||
    /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

function requestOnce(url) {
  return new Promise((resolveRequest, rejectRequest) => {
    const client = url.protocol === 'https:' ? https : http;
    const allowLocalCertificate = url.protocol === 'https:' && localTlsHost(url.hostname);
    let settled = false;
    let request;
    const finish = (callback, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(wallClockTimeout);
      callback(value);
    };
    const fail = (error) => {
      finish(rejectRequest, error);
      request?.destroy();
    };
    const wallClockTimeout = setTimeout(
      () => fail(new Error(`Request exceeded the ${REQUEST_TIMEOUT_MS} ms wall-clock limit.`)),
      REQUEST_TIMEOUT_MS
    );
    request = client.request(
      url,
      {
        headers: {
          accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
          'accept-encoding': 'identity',
          'user-agent': 'agent-ready-drupal-build-kit-live-verifier/1'
        },
        method: 'GET',
        rejectUnauthorized: !allowLocalCertificate,
        timeout: REQUEST_TIMEOUT_MS
      },
      (response) => {
        const chunks = [];
        let size = 0;
        const declaredLength = Number(response.headers['content-length']);
        if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
          fail(new Error(`Response body exceeds the ${MAX_BODY_BYTES} byte limit.`));
          response.destroy();
          return;
        }
        response.on('data', (chunk) => {
          if (settled) {
            return;
          }
          if (size + chunk.length > MAX_BODY_BYTES) {
            fail(new Error(`Response body exceeds the ${MAX_BODY_BYTES} byte limit.`));
            response.destroy();
            return;
          }
          chunks.push(chunk);
          size += chunk.length;
        });
        response.on('end', () => {
          finish(resolveRequest, {
            body: Buffer.concat(chunks).toString('utf8'),
            headers: response.headers,
            localTlsVerificationBypassed: allowLocalCertificate,
            status: response.statusCode ?? 0
          });
        });
        response.on('error', fail);
      }
    );
    request.on('timeout', () => fail(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS} ms.`)));
    request.on('error', fail);
    request.end();
  });
}

async function requestFollowingRedirects(startUrl) {
  let current = new URL(startUrl);
  const allowedOrigin = current.origin;
  const redirects = [];
  let localTlsVerificationBypassed = false;

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    const response = await requestOnce(current);
    localTlsVerificationBypassed ||= response.localTlsVerificationBypassed;
    const location = response.headers.location;
    if (REDIRECT_STATUSES.has(response.status) && location) {
      if (redirectCount === MAX_REDIRECTS) {
        throw new Error(`Too many redirects (more than ${MAX_REDIRECTS}).`);
      }
      const next = new URL(location, current);
      if (next.origin !== allowedOrigin) {
        throw new Error(`Refusing cross-origin redirect from ${current.origin} to ${next.origin}.`);
      }
      redirects.push({ from: current.href, status: response.status, to: next.href });
      current = next;
      continue;
    }
    return {
      ...response,
      finalUrl: current.href,
      initialStatus: redirects[0]?.status ?? response.status,
      localTlsVerificationBypassed,
      redirects
    };
  }
  throw new Error('Redirect resolution failed.');
}

function recursiveStringForKey(value, keys) {
  if (!value || typeof value !== 'object') {
    return '';
  }
  for (const [key, child] of Object.entries(value)) {
    if (keys.has(key) && typeof child === 'string' && child.trim()) {
      return child.trim().split(',')[0];
    }
  }
  for (const child of Object.values(value)) {
    const found = recursiveStringForKey(child, keys);
    if (found) {
      return found;
    }
  }
  return '';
}

function ddevTargetUrl(cwd) {
  try {
    const output = execFileSync('ddev', ['describe', '-j'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000
    });
    const description = JSON.parse(output);
    return recursiveStringForKey(description, new Set(['primary_url', 'primaryUrl']));
  } catch {
    return '';
  }
}

function findDrupalDdevRoot(cwd) {
  let candidate = resolve(cwd);
  while (true) {
    const configPath = join(candidate, '.ddev', 'config.yaml');
    if (existsSync(configPath)) {
      try {
        const config = readFileSync(configPath, 'utf8');
        if (/^\s*type:\s*["']?drupal(?:\d+)?["']?\s*(?:#.*)?$/mi.test(config)) {
          return realpathSync(candidate);
        }
      } catch {
        return '';
      }
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      return '';
    }
    candidate = parent;
  }
}

function runDrushResult(projectRoot, environment, args) {
  const inContainer = Boolean(environment.DDEV_PRIMARY_URL || environment.DDEV_PROJECT || environment.DDEV_SITENAME);
  const commands = inContainer
    ? [
        ['drush', args],
        [join(projectRoot, 'vendor', 'bin', 'drush'), args]
      ]
    : [['ddev', ['drush', ...args]]];
  for (const [command, commandArgs] of commands) {
    try {
      return {
        ok: true,
        output: execFileSync(command, commandArgs, {
          cwd: projectRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 15_000
        }).trim()
      };
    } catch {
      // Try the next supported host/container form.
    }
  }
  return { ok: false, output: '' };
}

function runDrush(projectRoot, environment, args) {
  return runDrushResult(projectRoot, environment, args).output;
}

function cleanScalar(value) {
  return String(value ?? '').trim().replace(/^(?:['"])(.*)(?:['"])$/s, '$1').trim();
}

function sharedConfigSyncDirectory(value) {
  const path = cleanScalar(value);
  if (!path || !/^[/\\]|^[a-z]:[/\\]/i.test(path)) {
    return path.replace(/^\.\.[/\\]/, '').replaceAll('\\', '/');
  }
  return path.split(/[/\\]+/).filter(Boolean).slice(-2).join('/');
}

function pathIsInside(parent, child) {
  const pathFromParent = relative(parent, child);
  return pathFromParent === '' || (
    pathFromParent !== '..' &&
    !pathFromParent.startsWith(`..${sep}`) &&
    !isAbsolute(pathFromParent)
  );
}

function ddevDocroot(projectRoot) {
  try {
    const config = readFileSync(join(projectRoot, '.ddev', 'config.yaml'), 'utf8');
    const match = config.match(/^\s*docroot:\s*["']?([^\s#"']+)["']?\s*(?:#.*)?$/mi);
    return match?.[1]?.trim() || 'web';
  } catch {
    return 'web';
  }
}

function filesBelow(root, limit = 10_000) {
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    return [];
  }
  const files = [];
  const pending = [root];
  while (pending.length > 0 && files.length < limit) {
    const directory = pending.pop();
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!['.git', 'node_modules', 'vendor'].includes(entry.name)) {
          pending.push(path);
        }
      } else if (entry.isFile()) {
        files.push(path);
        if (files.length >= limit) {
          throw new Error(`Custom extension file inventory exceeded ${limit} files under ${root}.`);
        }
      }
    }
  }
  return files;
}

function routingRecords(text, file, extension) {
  return text
    .split(/\n(?=[A-Za-z0-9_.-]+:\s*(?:#.*)?\n)/)
    .map((block) => {
      const name = block.match(/^([A-Za-z0-9_.-]+):\s*(?:#.*)?$/m)?.[1] ?? '';
      const path = block.match(/^\s+path:\s*['"]?([^'"\n#]+)['"]?\s*(?:#.*)?$/m)?.[1]?.trim() ?? '';
      const controller = block.match(/^\s+_controller:\s*['"]?([^'"\n#]+)['"]?\s*(?:#.*)?$/m)?.[1]?.trim() ?? '';
      return { controller, extension, file, name, path };
    })
    .filter((route) => route.name && route.path);
}

function sourceLocation(text, index) {
  const before = text.slice(0, Math.max(0, index));
  const lastNewline = before.lastIndexOf('\n');
  return {
    column: index - lastNewline,
    line: before.split('\n').length
  };
}

function themeOwnershipFinding(extension, kind, file, text, index, matchedText) {
  const location = sourceLocation(text, index);
  const matchHash = `sha256:${sha256(normalizeText(matchedText))}`;
  const identity = `${extension}\u0000${kind}\u0000${file}\u0000${location.line}\u0000${location.column}\u0000${matchHash}`;
  return {
    id: `THEME-${sha256(identity).slice(0, 16)}`,
    extension,
    kind,
    file,
    line: location.line,
    column: location.column,
    matchHash
  };
}

function formLooksLikeHandwrittenSearch(form) {
  const inputTags = form.match(/<input\b[^>]*>/gi) ?? [];
  const textInputs = inputTags.filter((tag) => {
    const type = tag.match(/\btype\s*=\s*['"]([^'"]+)['"]/i)?.[1]?.toLowerCase() ?? '';
    return !type || ['search', 'text'].includes(type);
  });
  if (textInputs.length === 0) {
    return false;
  }
  const commonSearchName = textInputs.some((tag) =>
    /\bname\s*=\s*['"](?:keys|keywords|query|q|search|search_api_fulltext)['"]/i.test(tag)
  );
  const formTag = form.match(/^<form\b[^>]*>/i)?.[0] ?? '';
  const searchAttribute = /\b(?:action|class|id|role)\s*=\s*(['"])[^'"]*search[^'"]*\1/i.test(formTag) ||
    /\baction\s*=\s*(['"])[\s\S]*?\bpath\s*\([^)]*search[^)]*\)[\s\S]*?\1/i.test(formTag);
  const searchLabelOrClass = /<label\b[^>]*>[\s\S]{0,500}?\bsearch\b/i.test(form) ||
    /\bclass\s*=\s*(['"])[^'"]*search[^'"]*\1/i.test(form);
  return textInputs.some((tag) => /\btype\s*=\s*['"]search['"]/i.test(tag)) ||
    /\brole\s*=\s*['"]search['"]/i.test(formTag) ||
    commonSearchName ||
    searchAttribute ||
    searchLabelOrClass;
}

function inspectThemeOwnership(extension, projectRoot, files) {
  const findings = [];
  const errors = [];
  for (const file of files) {
    const sharedPath = relative(projectRoot, file).split(sep).join('/');
    const filename = basename(file).toLowerCase();
    const pathSegments = sharedPath.toLowerCase().split('/');
    if (pathSegments.some((segment) =>
      ['test', 'tests', 'fixture', 'fixtures', 'test-data', 'test_data', 'testdata', 'tools', 'tooling'].includes(segment)
    )) {
      continue;
    }
    const globalViewsOverride = /^views-[a-z0-9_-]+\.html\.twig$/i.test(filename) && !filename.includes('--');
    const eligibleSource = /\.(?:twig|php|theme)$/i.test(file);
    if (!eligibleSource && !globalViewsOverride) {
      continue;
    }
    let text;
    try {
      text = readFileSync(file, 'utf8');
    } catch (error) {
      errors.push(`Theme ownership scan could not read ${sharedPath}: ${error.message}`);
      continue;
    }

    if (globalViewsOverride) {
      findings.push(themeOwnershipFinding(
        extension,
        'global_views_template_override',
        sharedPath,
        text,
        0,
        filename
      ));
    }

    for (const match of text.matchAll(/(['"])(\/(?!\/|#)[^'"\r\n]+)\1/g)) {
      const internalPath = match[2].trim();
      if (
        /[<{]/.test(internalPath) ||
        /^\/(?:core|modules|profiles|sites|themes)\//i.test(internalPath) ||
        /\.(?:avif|css|gif|ico|jpe?g|js|map|png|svg|ttf|webp|woff2?)(?:[?#].*)?$/i.test(internalPath)
      ) {
        continue;
      }
      const pathOffset = match[0].indexOf(match[2]);
      findings.push(themeOwnershipFinding(
        extension,
        'hardcoded_internal_path',
        sharedPath,
        text,
        match.index + Math.max(0, pathOffset),
        internalPath
      ));
    }

    const metaMatch = text.match(/['"]#tag['"]\s*=>\s*['"]meta['"]/i);
    if (metaMatch && /html_head|page_attachments|preprocess_html/i.test(text)) {
      findings.push(themeOwnershipFinding(
        extension,
        'theme_meta_injection',
        sharedPath,
        text,
        metaMatch.index,
        metaMatch[0]
      ));
    }

    for (const formMatch of text.matchAll(/<form\b[\s\S]{0,4000}?<\/form\s*>/gi)) {
      if (!formLooksLikeHandwrittenSearch(formMatch[0])) {
        continue;
      }
      findings.push(themeOwnershipFinding(
        extension,
        'handwritten_search_form',
        sharedPath,
        text,
        formMatch.index,
        formMatch[0]
      ));
    }
  }
  const uniqueFindings = [...new Map(findings.map((finding) => [finding.id, finding])).values()];
  return {
    errors,
    findings: uniqueFindings.sort((left, right) =>
      `${left.file}:${String(left.line).padStart(8, '0')}:${left.kind}`.localeCompare(
        `${right.file}:${String(right.line).padStart(8, '0')}:${right.kind}`
      )
    )
  };
}

const CUSTOM_SOURCE_EXCLUDED_SEGMENTS = new Set([
  '.cache', '.ddev', '.git', '.github', '.idea', '.vscode', 'bower_components', 'build', 'coverage', 'dist', 'docs', 'fixture', 'fixtures',
  'generated', 'node_modules', 'scripts', 'test', 'test-data', 'test_data', 'testdata', 'tests', 'tmp', 'tooling',
  'tools', 'translations', 'vendor'
]);

function customSourceKind(extensionRelativePath) {
  const normalized = extensionRelativePath.toLowerCase();
  const filename = basename(normalized);
  if (/\.info\.ya?ml$/.test(filename)) {
    return 'extension_metadata';
  }
  if (/(?:^|\/)config\/(?:install|optional)\//.test(normalized)) {
    return 'shipped_config';
  }
  if (/(?:^|\/)components?\/.*\.component\.ya?ml$/.test(normalized) || filename === 'component.yml') {
    return 'sdc_component';
  }
  if (/\.(?:module|theme|install|inc)$/.test(filename)) {
    return 'procedural_php';
  }
  if (/\.php$/.test(filename)) {
    return 'php_class';
  }
  if (/\.html\.twig$/.test(filename)) {
    return 'twig_template';
  }
  if (/\.(?:js|mjs|ts)$/.test(filename)) {
    return 'javascript';
  }
  if (/\.(?:css|less|sass|scss)$/.test(filename)) {
    return 'stylesheet';
  }
  if (/\.ya?ml$/.test(filename)) {
    return 'drupal_registration';
  }
  return '';
}

function customSourceFileEligible(extensionRelativePath) {
  const normalized = extensionRelativePath.split(sep).join('/');
  const segments = normalized.toLowerCase().split('/');
  const filename = basename(normalized).toLowerCase();
  if (segments.some((segment) => CUSTOM_SOURCE_EXCLUDED_SEGMENTS.has(segment))) {
    return false;
  }
  if (filename.startsWith('.')) {
    return false;
  }
  if (/\.(?:map|min\.css|min\.js)$/.test(filename) || /^(?:readme|changelog|license)(?:\.|$)/.test(filename)) {
    return false;
  }
  return Boolean(customSourceKind(normalized));
}

function customSourceSurface(extension, path, kind, name, text, index = 0) {
  const location = sourceLocation(text, index);
  const identity = `${extension}\u0000${path}\u0000${kind}\u0000${name}`;
  return {
    id: `SURFACE-${sha256(identity).slice(0, 16)}`,
    kind,
    name,
    line: location.line
  };
}

function yamlMappingChildren(text, rootKey) {
  const lines = text.split('\n');
  let offset = 0;
  let rootIndent = -1;
  let childIndent = -1;
  const children = [];
  for (const line of lines) {
    const mapping = line.match(/^(\s*)(['"]?)([A-Za-z0-9_.\\-]+)\2:\s*(?:#.*)?$/);
    const indent = line.match(/^\s*/)?.[0]?.length ?? 0;
    if (rootIndent < 0) {
      if (mapping?.[3] === rootKey) {
        rootIndent = mapping[1].length;
      }
      offset += line.length + 1;
      continue;
    }
    if (!line.trim() || line.trimStart().startsWith('#')) {
      offset += line.length + 1;
      continue;
    }
    if (indent <= rootIndent) {
      break;
    }
    if (mapping) {
      if (childIndent < 0) {
        childIndent = mapping[1].length;
      }
      if (mapping[1].length === childIndent && !mapping[3].startsWith('_')) {
        children.push({ index: offset + mapping[1].length, name: mapping[3] });
      }
    }
    offset += line.length + 1;
  }
  return children;
}

function customSourceSurfaces(extension, sharedPath, kind, text) {
  const surfaces = [];
  if (kind === 'procedural_php') {
    for (const match of text.matchAll(/\bfunction\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)) {
      surfaces.push(customSourceSurface(extension, sharedPath, 'function', match[1], text, match.index));
    }
  } else if (kind === 'php_class') {
    for (const match of text.matchAll(/\b(?:abstract\s+|final\s+)?(class|interface|trait|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
      surfaces.push(customSourceSurface(extension, sharedPath, match[1], match[2], text, match.index));
    }
  } else if (kind === 'javascript') {
    for (const match of text.matchAll(/\bDrupal\.behaviors\.([A-Za-z_][A-Za-z0-9_]*)\s*=/g)) {
      surfaces.push(customSourceSurface(extension, sharedPath, 'drupal_behavior', match[1], text, match.index));
    }
  } else if (kind === 'drupal_registration') {
    if (/\.services\.ya?ml$/i.test(sharedPath)) {
      for (const registration of yamlMappingChildren(text, 'services')) {
        surfaces.push(customSourceSurface(
          extension,
          sharedPath,
          'registration',
          registration.name,
          text,
          registration.index
        ));
      }
    } else {
      for (const match of text.matchAll(/^([A-Za-z0-9_.\\-]+):\s*(?:#.*)?$/gm)) {
        if (!match[1].startsWith('_')) {
          surfaces.push(customSourceSurface(extension, sharedPath, 'registration', match[1], text, match.index));
        }
      }
    }
  }
  if (surfaces.length === 0) {
    surfaces.push(customSourceSurface(extension, sharedPath, 'whole_file', basename(sharedPath), text));
  }
  return [...new Map(surfaces.map((surface) => [surface.id, surface])).values()];
}

function inspectCustomSourceFile(extension, extensionRoot, projectRoot, file) {
  const extensionRelativePath = relative(extensionRoot, file);
  if (!customSourceFileEligible(extensionRelativePath)) {
    return null;
  }
  const sharedPath = relative(projectRoot, file).split(sep).join('/');
  const kind = customSourceKind(extensionRelativePath);
  const text = readFileSync(file, 'utf8');
  const identity = `${extension}\u0000${sharedPath}`;
  return {
    id: `SOURCE-${sha256(identity).slice(0, 16)}`,
    extension,
    path: sharedPath,
    kind,
    sha256: `sha256:${sha256(text)}`,
    surfaces: customSourceSurfaces(extension, sharedPath, kind, text)
  };
}

export const CUSTOM_ROUTE_AUDIT_PHP = String.raw`
$output = ['routes' => [], 'violations' => [], 'completed' => FALSE];
$route_provider = \Drupal::service('router.route_provider');
$url_generator = \Drupal::service('url_generator');
$access_manager = \Drupal::service('access_manager');
$router = \Drupal::service('router.no_access_checks');
$param_converter = \Drupal::service('paramconverter_manager');
$container = \Drupal::getContainer();
$anonymous = new \Drupal\Core\Session\AnonymousUserSession();
$route_inputs = is_array($audit_input['routes'] ?? NULL) ? $audit_input['routes'] : [];
$route_bindings = is_array($audit_input['bindings'] ?? NULL) ? $audit_input['bindings'] : [];
$custom_extensions = is_array($audit_input['extensions'] ?? NULL) ? $audit_input['extensions'] : [];
$base_url = rtrim((string) ($audit_input['baseUrl'] ?? 'http://localhost'), '/');

$bindings_by_name = [];
foreach ($route_bindings as $binding) {
  if (is_array($binding) && !empty($binding['name'])) {
    $bindings_by_name[(string) $binding['name']] = $binding;
  }
}
$inputs_by_name = [];
foreach ($route_inputs as $input) {
  if (is_array($input) && !empty($input['name'])) {
    $inputs_by_name[(string) $input['name']] = $input;
  }
}

function custom_route_callback_class(string $definition, string $kind, $container): string {
  $definition = ltrim(trim($definition), '\\');
  if ($definition === '') {
    return '';
  }
  if (str_contains($definition, '::')) {
    return ltrim(explode('::', $definition, 2)[0], '\\');
  }
  if ($kind === '_form' && class_exists($definition)) {
    return $definition;
  }
  if (str_contains($definition, ':')) {
    [$service_id] = explode(':', $definition, 2);
    if ($container->has($service_id)) {
      return get_class($container->get($service_id));
    }
  }
  if ($container->has($definition)) {
    return get_class($container->get($definition));
  }
  return class_exists($definition) ? $definition : '';
}

function custom_route_extension_for_class(string $class, array $extensions): string {
  $normalized_class = ltrim($class, '\\');
  $class_file = '';
  try {
    $class_file = (new \ReflectionClass($normalized_class))->getFileName() ?: '';
    $class_file = $class_file ? str_replace('\\', '/', realpath($class_file) ?: $class_file) : '';
  }
  catch (\Throwable) {
    // Namespace ownership can still identify a class that cannot be reflected.
  }
  foreach ($extensions as $extension) {
    $machine_name = (string) ($extension['machineName'] ?? '');
    $type = (string) ($extension['type'] ?? '');
    if ($machine_name === '' || !in_array($type, ['module', 'theme'], TRUE)) {
      continue;
    }
    $namespace_prefix = 'Drupal\\' . $machine_name . '\\';
    if (str_starts_with($normalized_class, $namespace_prefix)) {
      return $machine_name;
    }
    try {
      $list = \Drupal::service($type === 'module' ? 'extension.list.module' : 'extension.list.theme');
      $extension_root = str_replace('\\', '/', realpath(DRUPAL_ROOT . '/' . $list->getPath($machine_name)) ?: '');
      if ($class_file && $extension_root && ($class_file === $extension_root || str_starts_with($class_file, $extension_root . '/'))) {
        return $machine_name;
      }
    }
    catch (\Throwable) {
      // Continue with the other known custom extensions.
    }
  }
  return '';
}

// Supplement YAML discovery with attribute/callback routes whose executable
// callbacks resolve to a custom extension namespace or filesystem path.
foreach ($route_provider->getAllRoutes() as $live_name => $live_route) {
  if (isset($inputs_by_name[$live_name])) {
    continue;
  }
  $definitions = [];
  foreach (['_controller', '_form', '_title_callback'] as $key) {
    $value = $live_route->getDefault($key);
    if (is_string($value) && $value !== '') {
      $definitions[$key] = $value;
    }
  }
  foreach ($live_route->getRequirements() as $key => $value) {
    if (is_string($value) && str_starts_with((string) $key, '_') && str_contains((string) $key, 'access')) {
      $definitions[(string) $key] = $value;
    }
  }
  foreach ($definitions as $kind => $definition) {
    $class = custom_route_callback_class($definition, $kind, $container);
    $extension = $class ? custom_route_extension_for_class($class, $custom_extensions) : '';
    if ($extension === '') {
      continue;
    }
    $binding = $bindings_by_name[(string) $live_name] ?? [];
    $inputs_by_name[(string) $live_name] = [
      'name' => (string) $live_name,
      'extension' => $extension,
      'file' => 'live-router:' . $extension,
      'path' => (string) $live_route->getPath(),
      'controller' => (string) $live_route->getDefault('_controller'),
      'routeParameters' => is_array($binding['routeParameters'] ?? NULL) ? $binding['routeParameters'] : [],
      'requestMethod' => (string) ($binding['requestMethod'] ?? ''),
      'discovery' => 'live_callback',
    ];
    break;
  }
}
$route_inputs = array_values($inputs_by_name);

foreach ($route_inputs as $input) {
  $record = [
    'name' => (string) ($input['name'] ?? ''),
    'extension' => (string) ($input['extension'] ?? ''),
    'file' => (string) ($input['file'] ?? ''),
    'filesystemPath' => (string) ($input['path'] ?? ''),
    'filesystemController' => (string) ($input['controller'] ?? ''),
    'routeParameters' => is_array($input['routeParameters'] ?? NULL) ? $input['routeParameters'] : [],
    'requestMethod' => strtoupper((string) ($input['requestMethod'] ?? '')),
    'discovery' => (string) ($input['discovery'] ?? 'routing_yaml'),
    'accessCheckCompleted' => FALSE,
    'parameterConversionCompleted' => FALSE,
    'requestMatched' => FALSE,
    'anonymousAccess' => '',
    'representativePath' => '',
  ];
  try {
    $route = $route_provider->getRouteByName($record['name']);
    $record['path'] = (string) $route->getPath();
    $record['controller'] = (string) $route->getDefault('_controller');
    $record['requirements'] = $route->getRequirements();
    $record['allowedMethods'] = array_values($route->getMethods());
    preg_match_all('/\{([^}]+)\}/', $record['path'], $matches);
    $record['parameterNames'] = array_values($matches[1] ?? []);
    $defaults = $route->getDefaults();
    $missing = array_values(array_filter($record['parameterNames'], static fn ($name) =>
      !array_key_exists($name, $record['routeParameters']) && !array_key_exists($name, $defaults)
    ));
    if ($missing) {
      $record['reason'] = 'missing_route_parameters';
      $record['missingParameters'] = $missing;
      $output['violations'][] = $record;
    }
    elseif ($record['requestMethod'] === '') {
      $record['reason'] = 'missing_request_method';
      $output['violations'][] = $record;
    }
    else {
      $record['representativePath'] = (string) $url_generator->generateFromRoute(
        $record['name'],
        $record['routeParameters'],
        ['absolute' => FALSE]
      );
      $request_uri = ($base_url ?: 'http://localhost') . $record['representativePath'];
      $request = \Symfony\Component\HttpFoundation\Request::create($request_uri, $record['requestMethod']);
      $matched = $router->matchRequest($request);
      $record['matchedRouteName'] = (string) ($matched[\Drupal\Core\Routing\RouteObjectInterface::ROUTE_NAME] ?? '');
      if ($record['matchedRouteName'] !== $record['name']) {
        $record['reason'] = 'representative_request_route_mismatch';
        $output['violations'][] = $record;
        $output['routes'][] = $record;
        continue;
      }
      $record['requestMatched'] = TRUE;
      $converted = $param_converter->convert($matched);
      $request->attributes->add($matched);
      $request->attributes->add($converted);
      $record['parameterConversionCompleted'] = TRUE;
      $access = $access_manager->checkRequest($request, $anonymous, TRUE);
      $record['anonymousAccess'] = $access->isAllowed()
        ? 'allowed'
        : ($access->isForbidden() ? 'denied' : 'neutral');
      $record['accessCheckCompleted'] = TRUE;
      if ($record['anonymousAccess'] === 'neutral') {
        $record['reason'] = 'neutral_access_result';
        $output['violations'][] = $record;
      }
    }
    if ($record['filesystemPath'] !== $record['path']) {
      $mismatch = $record;
      $mismatch['reason'] = 'route_path_mismatch';
      $output['violations'][] = $mismatch;
    }
    if ($record['filesystemController'] !== $record['controller']) {
      $mismatch = $record;
      $mismatch['reason'] = 'route_controller_mismatch';
      $output['violations'][] = $mismatch;
    }
  }
  catch (\Throwable $error) {
    $record['reason'] = 'live_route_audit_failed';
    $record['error'] = $error->getMessage();
    $output['violations'][] = $record;
  }
  $output['routes'][] = $record;
}
$output['completed'] = TRUE;
print json_encode($output, JSON_UNESCAPED_SLASHES);
`;

export function inspectCustomRouteRuntime(projectRoot, environment, routes, extensions = [], routeBindings = []) {
  if (routes.length === 0 && extensions.length === 0) {
    return { completed: true, routes: [], violations: [] };
  }
  const inputs = routes.map((route) => {
    const binding = routeBindings.find((candidate) => candidate?.name === route.name) ?? {};
    const parameters = binding.routeParameters;
    return {
      ...route,
      routeParameters: parameters && typeof parameters === 'object' && !Array.isArray(parameters)
        ? parameters
        : {},
      requestMethod: String(binding.requestMethod ?? '').trim().toUpperCase()
    };
  });
  const baseUrl = environmentTargetUrl(environment) || ddevTargetUrl(projectRoot) || 'http://localhost';
  const encodedInputs = Buffer.from(JSON.stringify({
    baseUrl,
    bindings: routeBindings,
    extensions,
    routes: inputs
  }), 'utf8').toString('base64');
  const php = `$audit_input = json_decode(base64_decode('${encodedInputs}'), TRUE);\n${CUSTOM_ROUTE_AUDIT_PHP}`;
  const result = runDrushResult(projectRoot, environment, ['php:eval', php]);
  if (!result.ok) {
    return { completed: false, error: 'Live Drupal custom-route audit could not run.', routes: [], violations: [] };
  }
  try {
    const audit = JSON.parse(result.output);
    return {
      completed: audit?.completed === true,
      routes: Array.isArray(audit?.routes) ? audit.routes : [],
      violations: Array.isArray(audit?.violations) ? audit.violations : []
    };
  } catch {
    return { completed: false, error: 'Live Drupal custom-route audit returned invalid JSON.', routes: [], violations: [] };
  }
}

export function inspectCustomCode(projectRoot) {
  const docroot = ddevDocroot(projectRoot);
  const extensions = [];
  const routes = [];
  const controllers = [];
  const sourceFiles = [];
  const tests = [];
  const themeOwnershipFindings = [];
  const errors = [];
  for (const [type, relativeRoot] of [
    ['module', join(docroot, 'modules', 'custom')],
    ['theme', join(docroot, 'themes', 'custom')]
  ]) {
    const root = join(projectRoot, relativeRoot);
    if (!existsSync(root) || !statSync(root).isDirectory()) {
      continue;
    }
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      const extensionRoot = join(root, entry.name);
      if (!existsSync(join(extensionRoot, `${entry.name}.info.yml`))) {
        continue;
      }
      const extensionPath = relative(projectRoot, extensionRoot).split(sep).join('/');
      let files = [];
      try {
        files = filesBelow(extensionRoot);
      } catch (error) {
        errors.push(error.message);
      }
      extensions.push({
        machineName: entry.name,
        path: extensionPath,
        phpFileCount: files.filter((file) => /\.(?:php|module|install|inc|theme)$/i.test(file)).length,
        type
      });
      if (type === 'theme') {
        const themeOwnership = inspectThemeOwnership(entry.name, projectRoot, files);
        errors.push(...themeOwnership.errors);
        themeOwnershipFindings.push(...themeOwnership.findings);
      }
      for (const file of files) {
        const sharedPath = relative(projectRoot, file).split(sep).join('/');
        try {
          const sourceFile = inspectCustomSourceFile(entry.name, extensionRoot, projectRoot, file);
          if (sourceFile) {
            sourceFiles.push(sourceFile);
          }
        } catch (error) {
          errors.push(`Custom source inventory could not read ${sharedPath}: ${error.message}`);
        }
        if (/\/src\/Controller\/.*\.php$/i.test(sharedPath)) {
          controllers.push({ extension: entry.name, path: sharedPath });
        }
        if (/\/tests\/.*\.(?:php|yml)$/i.test(sharedPath)) {
          tests.push(sharedPath);
        }
        if (/\.routing\.ya?ml$/i.test(sharedPath)) {
          try {
            routes.push(...routingRecords(readFileSync(file, 'utf8'), sharedPath, entry.name));
          } catch {
            routes.push({ controller: '', extension: entry.name, file: sharedPath, name: '', path: '', public: false });
          }
        }
      }
    }
  }
  return {
    completed: errors.length === 0,
    controllers: controllers.sort((left, right) => left.path.localeCompare(right.path)),
    errors,
    extensions: extensions.sort((left, right) => left.path.localeCompare(right.path)),
    routes: routes.sort((left, right) => `${left.file}:${left.name}`.localeCompare(`${right.file}:${right.name}`)),
    sourceFiles: sourceFiles.sort((left, right) => left.path.localeCompare(right.path)),
    tests: tests.sort(),
    themeOwnershipFindings: themeOwnershipFindings.sort((left, right) => left.id.localeCompare(right.id))
  };
}

function boundedToolResult(command, args, cwd, timeout = 60_000) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout
  });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim();
  return {
    command: [relative(cwd, command).split(sep).join('/') || command, ...args],
    exitCode: Number.isInteger(result.status) ? result.status : null,
    outputSha256: `sha256:${sha256(output)}`,
    outputSummary: output.replace(/\s+/g, ' ').slice(0, 500),
    passed: result.status === 0,
    spawnError: result.error?.message ?? ''
  };
}

function phpcsSummary(result) {
  try {
    const parsed = JSON.parse(String(result.stdout ?? ''));
    return {
      errors: Number(parsed?.totals?.errors ?? 0),
      files: Object.keys(parsed?.files ?? {}).length,
      warnings: Number(parsed?.totals?.warnings ?? 0)
    };
  } catch {
    return {};
  }
}

function phpstanSummary(result) {
  try {
    const parsed = JSON.parse(String(result.stdout ?? ''));
    return {
      errors: Number(parsed?.totals?.errors ?? 0),
      fileErrors: Number(parsed?.totals?.file_errors ?? 0)
    };
  } catch {
    return {};
  }
}

export function inspectCustomPhpQuality(projectRoot, extensions) {
  const phpExtensions = extensions.filter((extension) => extension.phpFileCount > 0);
  if (phpExtensions.length === 0) {
    return [];
  }

  const phpcs = join(projectRoot, 'vendor', 'bin', 'phpcs');
  const phpstan = join(projectRoot, 'vendor', 'bin', 'phpstan');
  let phpcsSupported = existsSync(phpcs);
  let phpcsUnsupportedReason = phpcsSupported ? '' : 'vendor/bin/phpcs is unavailable.';
  if (phpcsSupported) {
    const standards = boundedToolResult(phpcs, ['-i'], projectRoot, 15_000);
    phpcsSupported = standards.passed && /\bDrupal\b/.test(standards.outputSummary) && /\bDrupalPractice\b/.test(standards.outputSummary);
    if (!phpcsSupported) {
      phpcsUnsupportedReason = 'PHPCS is unavailable or the Drupal and DrupalPractice standards are not installed.';
    }
  }

  const phpstanConfig = [
    'phpstan.neon',
    'phpstan.neon.dist',
    'phpstan.dist.neon'
  ].find((path) => existsSync(join(projectRoot, path))) ?? '';
  const phpstanSupported = existsSync(phpstan) && Boolean(phpstanConfig);
  const phpstanUnsupportedReason = existsSync(phpstan)
    ? 'No project PHPStan configuration was found.'
    : 'vendor/bin/phpstan is unavailable.';

  return phpExtensions.map((extension) => {
    const checks = [];
    if (phpcsSupported) {
      const args = [
        '--standard=Drupal,DrupalPractice',
        '--extensions=php,module,install,inc,theme',
        '--report=json',
        extension.path
      ];
      const raw = spawnSync(phpcs, args, {
        cwd: projectRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 60_000
      });
      const combined = `${raw.stdout ?? ''}\n${raw.stderr ?? ''}`.trim();
      checks.push({
        kind: 'coding_standards',
        supported: true,
        status: raw.status === 0 ? 'pass' : 'fail',
        command: [relative(projectRoot, phpcs).split(sep).join('/'), ...args],
        exitCode: Number.isInteger(raw.status) ? raw.status : null,
        outputSha256: `sha256:${sha256(combined)}`,
        summary: phpcsSummary(raw),
        error: raw.error?.message ?? ''
      });
    } else {
      checks.push({
        kind: 'coding_standards',
        supported: false,
        status: 'unsupported',
        reason: phpcsUnsupportedReason
      });
    }

    if (phpstanSupported) {
      const args = [
        'analyse',
        `--configuration=${phpstanConfig}`,
        '--error-format=json',
        '--no-progress',
        extension.path
      ];
      const raw = spawnSync(phpstan, args, {
        cwd: projectRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 120_000
      });
      const combined = `${raw.stdout ?? ''}\n${raw.stderr ?? ''}`.trim();
      checks.push({
        kind: 'static_analysis',
        supported: true,
        status: raw.status === 0 ? 'pass' : 'fail',
        command: [relative(projectRoot, phpstan).split(sep).join('/'), ...args],
        config: phpstanConfig,
        exitCode: Number.isInteger(raw.status) ? raw.status : null,
        outputSha256: `sha256:${sha256(combined)}`,
        summary: phpstanSummary(raw),
        error: raw.error?.message ?? ''
      });
    } else {
      checks.push({
        kind: 'static_analysis',
        supported: false,
        status: 'unsupported',
        reason: phpstanUnsupportedReason
      });
    }

    return {
      machineName: extension.machineName,
      path: extension.path,
      type: extension.type,
      checks
    };
  });
}

export const DISPLAY_PLUGIN_AUDIT_PHP = String.raw`
$output = ['formComponents' => [], 'viewComponents' => [], 'extraComponents' => [], 'viewDisplays' => [], 'violations' => [], 'completed' => FALSE];
$field_manager = \Drupal::service('entity_field.manager');
$display_repository = \Drupal::service('entity_display.repository');
$entity_type_manager = \Drupal::entityTypeManager();
foreach ([
  ['storage' => 'entity_form_display', 'manager' => 'plugin.manager.field.widget', 'key' => 'formComponents'],
  ['storage' => 'entity_view_display', 'manager' => 'plugin.manager.field.formatter', 'key' => 'viewComponents'],
] as $audit) {
  $plugin_manager = \Drupal::service($audit['manager']);
  foreach ($entity_type_manager->getStorage($audit['storage'])->loadMultiple() as $display) {
    $entity_type = $display->getTargetEntityTypeId();
    $bundle = $display->getTargetBundle();
    $definitions = $field_manager->getFieldDefinitions($entity_type, $bundle);
    $extra_context = $audit['storage'] === 'entity_form_display' ? 'form' : 'display';
    $extra_fields = $field_manager->getExtraFields($entity_type, $bundle)[$extra_context] ?? [];
    if ($audit['storage'] === 'entity_view_display') {
      $output['viewDisplays'][] = [
        'displayConfig' => $display->getConfigDependencyName(),
        'entityType' => $entity_type,
        'bundle' => $bundle,
        'viewMode' => $display->getMode(),
      ];
    }
    foreach ($display->getComponents() as $field_name => $component) {
      $field_definition = $definitions[$field_name] ?? NULL;
      if (!$field_definition && isset($extra_fields[$field_name])) {
        $output['extraComponents'][] = [
          'displayConfig' => $display->getConfigDependencyName(),
          'fieldName' => $field_name,
          'context' => $extra_context,
          'configuredType' => (string) ($component['type'] ?? ''),
          'registeredExtraField' => TRUE,
        ];
        continue;
      }
      if (empty($component['type'])) {
        continue;
      }
      $configured = (string) $component['type'];
      $resolved = '';
      $field_type = $field_definition ? (string) $field_definition->getType() : '';
      $field_type_supported = FALSE;
      $class_applicable = FALSE;
      $applicable = FALSE;
      if ($field_definition) {
        try {
        $definition = $plugin_manager->getDefinition($configured);
        $field_type_supported = in_array($field_type, $definition['field_types'] ?? [], TRUE);
        $class = $definition['class'] ?? '';
        $class_applicable = $class && $class::isApplicable($field_definition);
        $applicable = $field_type_supported && $class_applicable;
        $renderer = $display->getRenderer($field_name);
        $resolved = $renderer ? $renderer->getPluginId() : '';
        }
        catch (\Throwable $error) {
          $resolved = '';
        }
      }
      $record = [
        'displayConfig' => $display->getConfigDependencyName(),
        'fieldName' => $field_name,
        'fieldDefinitionPresent' => (bool) $field_definition,
        'fieldType' => $field_type,
        'configuredPlugin' => $configured,
        'resolvedPlugin' => $resolved,
        'supportsFieldType' => (bool) $field_type_supported,
        'classApplicable' => (bool) $class_applicable,
        'applicable' => (bool) $applicable,
      ];
      $output[$audit['key']][] = $record;
      if (!$field_definition) {
        $record['reason'] = 'missing_field_definition';
        $output['violations'][] = $record;
      }
      elseif (!$field_type_supported) {
        $record['reason'] = 'plugin_field_type_not_supported';
        $output['violations'][] = $record;
      }
      elseif (!$class_applicable) {
        $record['reason'] = 'plugin_class_not_applicable';
        $output['violations'][] = $record;
      }
      if ($field_definition && $audit['storage'] === 'entity_view_display') {
        $requested_view_mode = (string) ($component['settings']['view_mode'] ?? '');
        $target_type = (string) ($definitions[$field_name]->getSetting('target_type') ?? '');
        if ($requested_view_mode && $requested_view_mode !== 'default' && $target_type && !isset($display_repository->getViewModes($target_type)[$requested_view_mode])) {
          $record['reason'] = 'missing_target_view_mode';
          $record['targetEntityType'] = $target_type;
          $record['targetViewMode'] = $requested_view_mode;
          $output['violations'][] = $record;
        }
      }
    }
  }
}
$output['completed'] = TRUE;
print json_encode($output, JSON_UNESCAPED_SLASHES);
`;

function inspectDisplayPluginCompatibility(projectRoot, environment) {
  const result = runDrushResult(projectRoot, environment, ['php:eval', DISPLAY_PLUGIN_AUDIT_PHP]);
  if (!result.ok) {
    return { completed: false, error: 'Drupal display-plugin audit could not run.', formComponents: [], viewComponents: [], violations: [] };
  }
  try {
    const audit = JSON.parse(result.output);
    return {
      completed: audit?.completed === true,
      extraComponentCount: Array.isArray(audit?.extraComponents) ? audit.extraComponents.length : 0,
      extraComponents: Array.isArray(audit?.extraComponents) ? audit.extraComponents : [],
      formComponentCount: Array.isArray(audit?.formComponents) ? audit.formComponents.length : 0,
      formComponents: Array.isArray(audit?.formComponents) ? audit.formComponents : [],
      viewComponentCount: Array.isArray(audit?.viewComponents) ? audit.viewComponents.length : 0,
      viewComponents: Array.isArray(audit?.viewComponents) ? audit.viewComponents : [],
      viewDisplays: Array.isArray(audit?.viewDisplays) ? audit.viewDisplays : [],
      violations: Array.isArray(audit?.violations) ? audit.violations : []
    };
  } catch {
    return { completed: false, error: 'Drupal display-plugin audit returned invalid JSON.', formComponents: [], viewComponents: [], violations: [] };
  }
}

const ALIAS_POLICY_AUDIT_PHP = String.raw`
$output = ['records' => [], 'violations' => [], 'completed' => FALSE];
$entity_type_manager = \Drupal::entityTypeManager();
$alias_manager = \Drupal::service('path_alias.manager');
foreach ($alias_policies as $policy) {
  $record = [
    'entityType' => (string) ($policy['entityType'] ?? ''),
    'bundle' => (string) ($policy['bundle'] ?? ''),
    'strategy' => (string) ($policy['strategy'] ?? ''),
    'patternId' => (string) ($policy['patternId'] ?? ''),
    'probeEntityId' => (string) ($policy['probeEntityId'] ?? ''),
    'probeAlias' => (string) ($policy['probeAlias'] ?? ''),
    'probeLanguage' => (string) ($policy['probeLanguage'] ?? ''),
    'entityLoaded' => FALSE,
    'bundleMatches' => FALSE,
    'aliasResolvesToEntity' => FALSE,
    'entityResolvesToAlias' => FALSE,
    'patternLoaded' => FALSE,
    'patternEnabled' => FALSE,
    'patternApplies' => FALSE,
    'selectedPatternId' => '',
    'passed' => FALSE,
  ];
  $record_violations = [];
  try {
    if (!$entity_type_manager->hasDefinition($record['entityType'])) {
      throw new \RuntimeException('unknown_entity_type');
    }
    $entity = $entity_type_manager->getStorage($record['entityType'])->load($record['probeEntityId']);
    $record['entityLoaded'] = (bool) $entity;
    if (!$entity) {
      throw new \RuntimeException('probe_entity_not_found');
    }
    $record['bundleMatches'] = $entity->bundle() === $record['bundle'];
    if (!$record['bundleMatches']) {
      $record_violations[] = 'probe_entity_bundle_mismatch';
    }
    $record['probeLanguage'] = $record['probeLanguage'] ?: $entity->language()->getId();
    $internal_path = '/' . ltrim($entity->toUrl('canonical')->getInternalPath(), '/');
    $record['internalPath'] = $internal_path;
    $record['resolvedInternalPath'] = $alias_manager->getPathByAlias($record['probeAlias'], $record['probeLanguage']);
    $record['resolvedAlias'] = $alias_manager->getAliasByPath($internal_path, $record['probeLanguage']);
    $normalize = static fn (string $path): string => '/' . trim($path, '/');
    $record['aliasResolvesToEntity'] = $normalize($record['resolvedInternalPath']) === $normalize($internal_path);
    $record['entityResolvesToAlias'] = $normalize($record['resolvedAlias']) === $normalize($record['probeAlias']);
    if (!$record['aliasResolvesToEntity'] || !$record['entityResolvesToAlias']) {
      $record_violations[] = 'probe_alias_resolution_mismatch';
    }
    if ($record['strategy'] === 'pathauto_pattern') {
      if (!$entity_type_manager->hasDefinition('pathauto_pattern') || !\Drupal::hasService('pathauto.generator')) {
        $record_violations[] = 'pathauto_unavailable';
      }
      else {
        $pattern = $entity_type_manager->getStorage('pathauto_pattern')->load($record['patternId']);
        $record['patternLoaded'] = (bool) $pattern;
        if (!$pattern) {
          $record_violations[] = 'pathauto_pattern_not_found';
        }
        else {
          $record['patternEnabled'] = $pattern->status();
          $record['patternApplies'] = $pattern->applies($entity);
          $selected = \Drupal::service('pathauto.generator')->getPatternByEntity($entity);
          $record['selectedPatternId'] = $selected ? (string) $selected->id() : '';
          if (!$record['patternEnabled']) {
            $record_violations[] = 'pathauto_pattern_disabled';
          }
          if (!$record['patternApplies']) {
            $record_violations[] = 'pathauto_pattern_not_applicable';
          }
          if ($record['selectedPatternId'] !== $record['patternId']) {
            $record_violations[] = 'pathauto_pattern_not_selected';
          }
        }
      }
    }
  }
  catch (\Throwable $error) {
    $record_violations[] = $error->getMessage();
  }
  $record['violations'] = array_values(array_unique($record_violations));
  $record['passed'] = count($record['violations']) === 0;
  if (!$record['passed']) {
    $output['violations'][] = $record;
  }
  $output['records'][] = $record;
}
$output['completed'] = TRUE;
print json_encode($output, JSON_UNESCAPED_SLASHES);
`;

export function inspectAliasPolicies(projectRoot, environment, policies) {
  const auditablePolicies = Array.isArray(policies)
    ? policies.filter((policy) => ['pathauto_pattern', 'editor_supplied_alias'].includes(policy?.strategy))
    : [];
  if (auditablePolicies.length === 0) {
    return { completed: true, records: [], violations: [] };
  }
  const encodedPolicies = Buffer.from(JSON.stringify(auditablePolicies), 'utf8').toString('base64');
  const php = `$alias_policies = json_decode(base64_decode('${encodedPolicies}'), TRUE);\n${ALIAS_POLICY_AUDIT_PHP}`;
  const result = runDrushResult(projectRoot, environment, ['php:eval', php]);
  if (!result.ok) {
    return { completed: false, error: 'Live Drupal alias-policy audit could not run.', records: [], violations: [] };
  }
  try {
    const audit = JSON.parse(result.output);
    return {
      completed: audit?.completed === true,
      records: Array.isArray(audit?.records) ? audit.records : [],
      violations: Array.isArray(audit?.violations) ? audit.violations : []
    };
  } catch {
    return { completed: false, error: 'Live Drupal alias-policy audit returned invalid JSON.', records: [], violations: [] };
  }
}

function hostConfigSyncPath(projectRoot, configSyncDirectory, drupalRoot) {
  const configured = cleanScalar(configSyncDirectory);
  if (!configured) {
    return '';
  }
  const docroot = ddevDocroot(projectRoot);
  if (!isAbsolute(configured)) {
    const candidate = resolve(projectRoot, docroot, configured);
    return pathIsInside(projectRoot, candidate) ? candidate : '';
  }
  if (existsSync(configured) && pathIsInside(projectRoot, configured)) {
    return resolve(configured);
  }

  const normalizedDrupalRoot = cleanScalar(drupalRoot).replaceAll('\\', '/').replace(/\/+$/, '');
  const normalizedConfigured = configured.replaceAll('\\', '/');
  const docrootSuffix = `/${docroot.replace(/^\/+|\/+$/g, '')}`;
  const containerProjectRoot = normalizedDrupalRoot.endsWith(docrootSuffix)
    ? normalizedDrupalRoot.slice(0, -docrootSuffix.length)
    : '';
  if (containerProjectRoot && normalizedConfigured.startsWith(`${containerProjectRoot}/`)) {
    const candidate = resolve(projectRoot, normalizedConfigured.slice(containerProjectRoot.length + 1));
    return pathIsInside(projectRoot, candidate) ? candidate : '';
  }
  return '';
}

function trackedConfigEvidence(projectRoot, configSyncDirectory, drupalRoot) {
  const hostPath = hostConfigSyncPath(projectRoot, configSyncDirectory, drupalRoot);
  if (!hostPath || !existsSync(hostPath) || !statSync(hostPath).isDirectory()) {
    return { confirmed: false, directory: '', yamlFiles: [] };
  }
  const directory = relative(projectRoot, hostPath).split(sep).join('/');
  try {
    const output = execFileSync('git', ['ls-files', '--', directory], {
      cwd: projectRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000
    });
    const yamlFiles = output
      .split(/\r?\n/)
      .map((path) => path.trim())
      .filter((path) => /\.ya?ml$/i.test(path) && existsSync(join(projectRoot, path)));
    return { confirmed: yamlFiles.length > 0, directory, yamlFiles };
  } catch {
    return { confirmed: false, directory, yamlFiles: [] };
  }
}

function topLevelYamlScalars(source) {
  const values = new Map();
  for (const line of String(source).split(/\r?\n/)) {
    if (!line || /^\s|^#/.test(line)) {
      continue;
    }
    const match = line.match(/^([a-z0-9_]+):(?:\s*(.*))?$/i);
    if (!match) {
      continue;
    }
    let value = String(match[2] ?? '').trim();
    if (!/^['"]/.test(value)) {
      value = value.replace(/\s+#.*$/, '').trim();
    }
    values.set(match[1], cleanScalar(value));
  }
  return values;
}

function yamlBoolean(value) {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (['true', '1'].includes(normalized)) {
    return true;
  }
  if (['false', '0'].includes(normalized)) {
    return false;
  }
  return null;
}

export function inspectTrackedCanvasTemplates(projectRoot, trackedConfigYamlFiles, trackedConfigDirectory = '') {
  const normalizedConfigDirectory = String(trackedConfigDirectory ?? '').replaceAll('\\', '/').replace(/\/+$/, '');
  const trackedFiles = Array.isArray(trackedConfigYamlFiles)
    ? trackedConfigYamlFiles.map((path) => String(path).replaceAll('\\', '/')).filter(Boolean)
    : [];
  const templatePaths = trackedFiles.filter((path) => {
    if (normalizedConfigDirectory && dirname(path).replaceAll('\\', '/') !== normalizedConfigDirectory) {
      return false;
    }
    return /^canvas\.content_template\..+\.ya?ml$/i.test(basename(path));
  });
  const templates = [];
  const errors = [];

  for (const path of templatePaths) {
    const absolutePath = resolve(projectRoot, path);
    if (!pathIsInside(projectRoot, absolutePath) || !existsSync(absolutePath)) {
      errors.push(`${path}: tracked Canvas content-template config is missing or outside the Drupal project.`);
      continue;
    }
    try {
      const values = topLevelYamlScalars(readFileSync(absolutePath, 'utf8'));
      const status = yamlBoolean(values.get('status'));
      const record = {
        configName: basename(path).replace(/\.ya?ml$/i, ''),
        path,
        enabled: status === true,
        id: values.get('id') || '',
        entityType: values.get('content_entity_type_id') || '',
        bundle: values.get('content_entity_type_bundle') || '',
        viewMode: values.get('content_entity_type_view_mode') || ''
      };
      templates.push(record);
      if (status === null) {
        errors.push(`${path}: Canvas content-template config must declare a top-level boolean status.`);
      }
      for (const [field, label] of [
        ['id', 'id'],
        ['entityType', 'content_entity_type_id'],
        ['bundle', 'content_entity_type_bundle'],
        ['viewMode', 'content_entity_type_view_mode']
      ]) {
        if (!record[field]) {
          errors.push(`${path}: Canvas content-template config is missing top-level ${label}.`);
        }
      }
    } catch (error) {
      errors.push(`${path}: Canvas content-template config could not be read: ${error.message}`);
    }
  }

  return {
    completed: errors.length === 0,
    trackedConfigFileCount: trackedFiles.length,
    matchingConfigCount: templates.length,
    templates,
    errors
  };
}

function configStatusIsClean(result) {
  if (!result.ok) {
    return false;
  }
  const output = result.output.trim();
  if (!output || /no differences/i.test(output)) {
    return true;
  }
  try {
    const parsed = JSON.parse(output);
    return (Array.isArray(parsed) && parsed.length === 0) ||
      (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length === 0);
  } catch {
    return false;
  }
}

function inspectDrupalRuntime(cwd, environment, customRouteBindings = [], aliasPolicies = []) {
  const projectRoot = findDrupalDdevRoot(cwd);
  if (!projectRoot) {
    return {
      baseUrl: '',
      confirmed: false,
      configStatusClean: false,
      configSyncTracked: false,
      configSyncDirectory: '',
      canvasTemplateAudit: {
        completed: false,
        trackedConfigFileCount: 0,
        matchingConfigCount: 0,
        templates: [],
        errors: ['Tracked Drupal config was unavailable.']
      },
      aliasPolicyAudit: { completed: false, records: [], violations: [] },
      customCodeInventory: { completed: false, controllers: [], extensions: [], routes: [], sourceFiles: [], tests: [] },
      defaultTheme: '',
      displayPluginAudit: { completed: false, extraComponents: [], formComponents: [], viewComponents: [], viewDisplays: [], violations: [] },
      frontPage: '',
      mode: 'unavailable',
      reason: 'Current working directory is not inside a DDEV Drupal project.',
      siteUuid: '',
      trackedConfigDirectory: '',
      trackedConfigYamlFiles: []
    };
  }
  const inContainer = Boolean(environment.DDEV_PRIMARY_URL || environment.DDEV_PROJECT || environment.DDEV_SITENAME);
  const bootstrap = runDrush(projectRoot, environment, ['status', '--field=bootstrap']);
  const uuidOutput = runDrush(projectRoot, environment, ['config:get', 'system.site', '--field=uuid']);
  const frontPage = cleanScalar(
    runDrush(projectRoot, environment, ['config:get', 'system.site', 'page.front', '--format=string'])
  );
  const defaultTheme = cleanScalar(
    runDrush(projectRoot, environment, ['config:get', 'system.theme', 'default', '--format=string'])
  );
  const configSyncDirectory = cleanScalar(
    runDrush(projectRoot, environment, ['status', '--field=config-sync'])
  );
  const drupalRoot = cleanScalar(runDrush(projectRoot, environment, ['status', '--field=root']));
  const configStatus = runDrushResult(projectRoot, environment, ['config:status', '--format=json']);
  const trackedConfig = trackedConfigEvidence(projectRoot, configSyncDirectory, drupalRoot);
  const canvasTemplateAudit = trackedConfig.confirmed
    ? inspectTrackedCanvasTemplates(projectRoot, trackedConfig.yamlFiles, trackedConfig.directory)
    : {
        completed: false,
        trackedConfigFileCount: trackedConfig.yamlFiles.length,
        matchingConfigCount: 0,
        templates: [],
        errors: ['Tracked Drupal config was unavailable.']
      };
  const filesystemCustomCode = inspectCustomCode(projectRoot);
  const customQuality = inspectCustomPhpQuality(projectRoot, filesystemCustomCode.extensions);
  const customRouteAudit = inspectCustomRouteRuntime(
    projectRoot,
    environment,
    filesystemCustomCode.routes,
    filesystemCustomCode.extensions,
    customRouteBindings
  );
  const customCodeInventory = {
    ...filesystemCustomCode,
    completed:
      filesystemCustomCode.completed === true &&
      customRouteAudit.completed === true &&
      customRouteAudit.violations.length === 0,
    errors: [
      ...filesystemCustomCode.errors,
      ...customRouteAudit.violations.map((violation) =>
        `${violation.name || '(unknown route)'}: ${violation.reason || 'route audit violation'}`
      )
    ],
    extensions: filesystemCustomCode.extensions.map((extension) => ({
      ...extension,
      qualityChecks: customQuality.find((record) =>
        record.machineName === extension.machineName &&
        record.type === extension.type &&
        record.path === extension.path
      )?.checks ?? []
    })),
    routeAuditCompleted: customRouteAudit.completed === true,
    routeAuditViolations: customRouteAudit.violations,
    routes: customRouteAudit.routes
  };
  const displayPluginAudit = inspectDisplayPluginCompatibility(projectRoot, environment);
  const aliasPolicyAudit = inspectAliasPolicies(projectRoot, environment, aliasPolicies);
  const siteUuid = uuidOutput.match(UUID_RE)?.[0]?.toLowerCase() ?? '';
  const confirmed = /successful/i.test(bootstrap) && Boolean(siteUuid);
  const baseUrl = inContainer ? environmentTargetUrl(environment) : ddevTargetUrl(projectRoot);
  return {
    baseUrl,
    confirmed,
    aliasPolicyAudit,
    canvasTemplateAudit,
    configStatusClean: configStatusIsClean(configStatus),
    configSyncTracked: trackedConfig.confirmed,
    configSyncDirectory,
    customCodeInventory,
    displayPluginAudit,
    defaultTheme,
    drupalRoot,
    frontPage,
    mode: inContainer ? 'ddev-container' : 'ddev-host',
    project: basename(projectRoot),
    reason: confirmed ? '' : 'Drupal did not bootstrap or expose a valid system.site UUID through Drush.',
    siteUuid,
    trackedConfigDirectory: trackedConfig.directory,
    trackedConfigYamlFiles: trackedConfig.yamlFiles
  };
}

function environmentTargetUrl(environment) {
  for (const key of ['DDEV_PRIMARY_URL', 'DDEV_PRIMARY_URLS']) {
    const value = String(environment[key] ?? '').trim();
    if (value) {
      return value.split(',')[0].trim();
    }
  }
  return '';
}

function resolveTargetUrl({ explicitTargetUrl, cwd, environment }) {
  const choices = [
    ['explicit', explicitTargetUrl],
    ['ddev-environment', environmentTargetUrl(environment)],
    ['ddev-describe', ddevTargetUrl(cwd)]
  ];
  const [source, value] = choices.find(([, candidate]) => String(candidate ?? '').trim()) ?? [];
  if (!value) {
    throw new Error('No live target URL found. Pass --target-url or run from the intended DDEV project.');
  }
  return { source, url: parseHttpUrl(value, 'Live target URL') };
}

function matchingRouteRecord(routeMatrix, targetPath) {
  return (Array.isArray(routeMatrix.routes) ? routeMatrix.routes : []).find(
    (route) => normalizePath(route?.targetPath) === targetPath
  );
}

function comparableUrl(value, baseUrl = undefined) {
  try {
    const url = baseUrl ? new URL(value, baseUrl) : new URL(value);
    if (url.username || url.password) {
      return '';
    }
    url.hash = '';
    return url.href;
  } catch {
    return '';
  }
}

function expectedRenderedSeo(browserEvidence, targetPath) {
  const records = (Array.isArray(browserEvidence?.publicRouteChecks) ? browserEvidence.publicRouteChecks : [])
    .filter((check) => [check?.targetUrl, check?.targetFinalUrl].some((url) => normalizePath(url) === targetPath))
    .filter((check) => check?.accepted === true && check?.renderedSeoSignals?.accepted === true)
    .map((check) => check?.renderedSeoSignals ?? {});
  if (records.length === 0) {
    return null;
  }

  const fields = [
    'targetCanonicalUrl',
    'metaDescriptionStatus',
    'targetMetaDescription',
    'openGraphImageStatus',
    'targetOpenGraphImage'
  ];
  const errors = [];
  for (const field of fields) {
    const values = new Set(records.map((record) => normalizeText(record?.[field])));
    if (values.size > 1) {
      errors.push(`${targetPath} has inconsistent browser-evidence.json renderedSeoSignals.${field} values across viewports.`);
    }
  }
  const record = records[0];
  return {
    canonicalUrl: comparableUrl(record?.targetCanonicalUrl),
    errors,
    metaDescription: normalizeText(record?.targetMetaDescription),
    metaDescriptionStatus: record?.metaDescriptionStatus,
    openGraphImage: comparableUrl(record?.targetOpenGraphImage),
    openGraphImageStatus: record?.openGraphImageStatus
  };
}

function expectedRoute(routeMatrix, primaryRoute, browserEvidence) {
  const targetPath = normalizePath(primaryRoute?.targetPath || primaryRoute?.sourcePath);
  const record = matchingRouteRecord(routeMatrix, targetPath) ?? {};
  const homepage = targetPath === '/' ? routeMatrix.homepageParity ?? {} : {};
  const declaredStatus = record.targetStatus;
  const expectedStatus = declaredStatus !== null && declaredStatus !== '' && Number.isFinite(Number(declaredStatus))
    ? Number(declaredStatus)
    : 200;
  return {
    accepted: primaryRoute?.accepted === true,
    expectedBehavior: record.expectedRedirect === true ? 'redirect' : 'public_200',
    expectedFinalPath: normalizePath(record.targetFinalPath || homepage.targetFinalPath || targetPath),
    expectedH1: normalizeText(record.targetH1 || homepage.targetH1),
    expectedStatus,
    expectedTitle: normalizeText(record.targetTitle || homepage.targetTitle),
    identityRequired: true,
    matchesBrowserRenderedSource: primaryRoute?.matchesBrowserRenderedSource === true,
    renderedSeo: expectedRenderedSeo(browserEvidence, targetPath),
    routeKind: 'primary',
    statusUsesInitialResponse: record.expectedRedirect === true,
    targetPath
  };
}

function expectedTargetRequiredRoute(record) {
  const targetPath = normalizePath(record?.targetPath);
  return {
    accepted: record?.accepted === true,
    expectedBehavior: String(record?.expectedPublicBehavior ?? ''),
    expectedFinalPath: normalizePath(record?.targetFinalPath || targetPath),
    expectedH1: '',
    expectedStatus: Number(record?.targetStatus),
    expectedTitle: '',
    identityRequired: false,
    matchesBrowserRenderedSource: true,
    renderedSeo: null,
    routeKind: 'target-required',
    statusUsesInitialResponse: record?.expectedPublicBehavior === 'redirect',
    targetPath
  };
}

function requiredOriginMatch(errors, label, value, expectedOrigin) {
  const text = String(value ?? '').trim();
  if (!text) {
    errors.push(`${label} is required for qualifying completion evidence.`);
    return;
  }
  try {
    const foundOrigin = parseHttpUrl(text, label).origin;
    if (foundOrigin !== expectedOrigin) {
      errors.push(`${label} origin ${foundOrigin} does not match ${expectedOrigin}.`);
    }
  } catch (error) {
    errors.push(error.message);
  }
}

function absoluteUrlOriginMatch(errors, label, value, expectedOrigin) {
  const text = String(value ?? '').trim();
  if (!/^https?:\/\//i.test(text)) {
    return;
  }
  requiredOriginMatch(errors, label, text, expectedOrigin);
}

function completionEvidenceTargetErrors({
  blindReview,
  browserEvidence,
  drupalReadback,
  fieldOutputMatrix,
  independentVerification,
  parityReport,
  patternMap,
  sourceAudit,
  sourceUrl,
  targetUrl
}) {
  const errors = [];
  const targetOrigin = targetUrl.origin;
  const sourceOrigin = sourceUrl.origin;
  requiredOriginMatch(errors, 'source-audit.json site.baseUrl', sourceAudit?.site?.baseUrl, sourceOrigin);
  requiredOriginMatch(errors, 'pattern-map.json sourceSite', patternMap?.sourceSite, sourceOrigin);
  requiredOriginMatch(errors, 'field-output-matrix.json site', fieldOutputMatrix?.site, targetOrigin);
  requiredOriginMatch(errors, 'parity-report.json targetUrl', parityReport?.targetUrl, targetOrigin);
  requiredOriginMatch(errors, 'browser-evidence.json site', browserEvidence?.site, targetOrigin);
  requiredOriginMatch(errors, 'drupal-readback.json site', drupalReadback?.site, targetOrigin);
  requiredOriginMatch(
    errors,
    'independent-verification.json target.baseUrl',
    independentVerification?.target?.baseUrl,
    targetOrigin
  );
  requiredOriginMatch(
    errors,
    'independent-verification.json target.adminUrl',
    independentVerification?.target?.adminUrl,
    targetOrigin
  );

  for (const [index, check] of (Array.isArray(browserEvidence?.publicRouteChecks)
    ? browserEvidence.publicRouteChecks
    : []).entries()) {
    requiredOriginMatch(errors, `browser-evidence.json publicRouteChecks[${index}].sourceUrl`, check?.sourceUrl, sourceOrigin);
    requiredOriginMatch(
      errors,
      `browser-evidence.json publicRouteChecks[${index}].sourceFinalUrl`,
      check?.sourceFinalUrl,
      sourceOrigin
    );
    requiredOriginMatch(errors, `browser-evidence.json publicRouteChecks[${index}].targetUrl`, check?.targetUrl, targetOrigin);
    requiredOriginMatch(
      errors,
      `browser-evidence.json publicRouteChecks[${index}].targetFinalUrl`,
      check?.targetFinalUrl,
      targetOrigin
    );
  }
  for (const [index, check] of (Array.isArray(browserEvidence?.canvasAuthoringChecks)
    ? browserEvidence.canvasAuthoringChecks
    : []).entries()) {
    absoluteUrlOriginMatch(
      errors,
      `browser-evidence.json canvasAuthoringChecks[${index}].canvasEditorUrl`,
      check?.canvasEditorUrl,
      targetOrigin
    );
  }
  for (const [index, check] of (Array.isArray(browserEvidence?.editorWorkflowChecks)
    ? browserEvidence.editorWorkflowChecks
    : []).entries()) {
    absoluteUrlOriginMatch(
      errors,
      `browser-evidence.json editorWorkflowChecks[${index}].drupalRoute`,
      check?.drupalRoute,
      targetOrigin
    );
  }
  for (const [index, review] of (Array.isArray(blindReview?.editorExperienceReviews)
    ? blindReview.editorExperienceReviews
    : []).entries()) {
    requiredOriginMatch(
      errors,
      `blind-adversarial-review.json editorExperienceReviews[${index}].targetAdminUrl`,
      review?.targetAdminUrl,
      targetOrigin
    );
  }

  const targetReferences = [
    ...(Array.isArray(blindReview?.reviewInputs?.targetUrlsOrArtifacts)
      ? blindReview.reviewInputs.targetUrlsOrArtifacts
      : []),
    ...(Array.isArray(blindReview?.routeViewportReviews)
      ? blindReview.routeViewportReviews.map((review) => review?.targetUrlOrArtifact)
      : [])
  ];
  let matchingTargetUrlCount = 0;
  for (const reference of targetReferences) {
    const text = String(reference ?? '').trim();
    if (!/^https?:\/\//i.test(text)) {
      continue;
    }
    try {
      const referenceUrl = parseHttpUrl(text, 'blind-adversarial-review.json target URL');
      if (referenceUrl.origin === targetUrl.origin) {
        matchingTargetUrlCount += 1;
      } else {
        errors.push(`Blind review target URL ${referenceUrl.origin} does not match the resolved live target ${targetUrl.origin}.`);
      }
    } catch (error) {
      errors.push(error.message);
    }
  }
  if (matchingTargetUrlCount === 0) {
    errors.push('Qualifying blind review evidence must reference the resolved live target URL.');
  }
  return errors;
}

async function verifyRoute(baseUrl, expected) {
  const requestedUrl = new URL(expected.targetPath.replace(/^\//, ''), new URL('/', baseUrl));
  const errors = [];
  if (!expected.accepted) {
    errors.push(`${expected.targetPath} is not accepted in route-matrix.json.`);
  }
  if (!expected.matchesBrowserRenderedSource) {
    errors.push(`${expected.targetPath} is not bound to browser-rendered source truth.`);
  }
  if (expected.identityRequired && !expected.expectedH1 && !expected.expectedTitle) {
    errors.push(`${expected.targetPath} needs an expected target H1 or title for live identity checking.`);
  }
  if (!Number.isFinite(expected.expectedStatus)) {
    errors.push(`${expected.targetPath} needs a finite expected target status.`);
  } else if (expected.routeKind === 'primary') {
    if (expected.expectedBehavior === 'redirect') {
      if (!REDIRECT_STATUSES.has(expected.expectedStatus)) {
        errors.push(`${expected.targetPath} declares a redirect but expected status ${expected.expectedStatus} is not an HTTP redirect.`);
      }
    } else if (expected.expectedStatus < 200 || expected.expectedStatus >= 300) {
      errors.push(`${expected.targetPath} is a primary target route and cannot accept HTTP ${expected.expectedStatus}; expected a final 2xx response or an explicit redirect.`);
    }
  } else if (!['public_200', 'redirect', 'private_403', 'noindex'].includes(expected.expectedBehavior)) {
    errors.push(`${expected.targetPath} has unsupported target-required behavior ${JSON.stringify(expected.expectedBehavior)}.`);
  } else if (expected.expectedBehavior === 'redirect' && !REDIRECT_STATUSES.has(expected.expectedStatus)) {
    errors.push(`${expected.targetPath} target-required redirect must declare an HTTP redirect status.`);
  } else if (expected.expectedBehavior === 'private_403' && expected.expectedStatus !== 403) {
    errors.push(`${expected.targetPath} target-required private_403 behavior must declare status 403.`);
  } else if (
    ['public_200', 'noindex'].includes(expected.expectedBehavior) &&
    (expected.expectedStatus < 200 || expected.expectedStatus >= 300)
  ) {
    errors.push(`${expected.targetPath} target-required ${expected.expectedBehavior} behavior must declare a 2xx status.`);
  }
  if (expected.renderedSeo) {
    errors.push(...(expected.renderedSeo.errors ?? []));
  }

  try {
    const response = await requestFollowingRedirects(requestedUrl);
    const actualH1 = elementText(response.body, 'h1');
    const actualTitle = elementText(response.body, 'title');
    const actualMetadata = renderedMetadata(response.body, response.finalUrl);
    const actualAssets = renderedAssets(response.body, response.finalUrl);
    const actualStatus = expected.statusUsesInitialResponse ? response.initialStatus : response.status;
    if (actualStatus !== expected.expectedStatus) {
      errors.push(`${expected.targetPath} returned status ${actualStatus}; expected ${expected.expectedStatus}.`);
    }
    if (normalizePath(response.finalUrl) !== expected.expectedFinalPath) {
      errors.push(
        `${expected.targetPath} resolved to ${normalizePath(response.finalUrl)}; expected ${expected.expectedFinalPath}.`
      );
    }
    if (new URL(response.finalUrl).origin !== baseUrl.origin) {
      errors.push(
        `${expected.targetPath} left the target origin and resolved to ${new URL(response.finalUrl).origin}.`
      );
    }
    if (
      (expected.routeKind === 'primary' || ['public_200', 'redirect', 'noindex'].includes(expected.expectedBehavior)) &&
      (response.status < 200 || response.status >= 300)
    ) {
      errors.push(`${expected.targetPath} ended with HTTP ${response.status}; completion routes must end with a same-origin 2xx response.`);
    }
    if (expected.expectedBehavior === 'noindex' && !actualMetadata.noindex) {
      errors.push(`${expected.targetPath} declares noindex behavior but the fetched page has no rendered noindex directive.`);
    }
    if (expected.expectedH1 && normalizeText(actualH1) !== expected.expectedH1) {
      errors.push(`${expected.targetPath} H1 was ${JSON.stringify(actualH1)}; expected ${JSON.stringify(expected.expectedH1)}.`);
    }
    if (expected.expectedTitle && normalizeText(actualTitle) !== expected.expectedTitle) {
      errors.push(
        `${expected.targetPath} title was ${JSON.stringify(actualTitle)}; expected ${JSON.stringify(expected.expectedTitle)}.`
      );
    }
    if (expected.renderedSeo) {
      const seo = expected.renderedSeo;
      if (actualMetadata.canonicalCount !== 1 || !actualMetadata.canonicalUrl) {
        errors.push(`${expected.targetPath} rendered canonical is missing or duplicated; expected exactly one usable link and found ${actualMetadata.canonicalCount}.`);
      } else {
        const actualCanonical = new URL(actualMetadata.canonicalUrl);
        if (actualCanonical.origin !== baseUrl.origin) {
          errors.push(`${expected.targetPath} rendered canonical origin ${actualCanonical.origin} does not match ${baseUrl.origin}.`);
        }
        if (normalizePath(actualCanonical.href) !== normalizePath(response.finalUrl)) {
          errors.push(`${expected.targetPath} rendered canonical path ${normalizePath(actualCanonical.href)} does not match final path ${normalizePath(response.finalUrl)}.`);
        }
        if (!seo.canonicalUrl || actualMetadata.canonicalUrl !== seo.canonicalUrl) {
          errors.push(`${expected.targetPath} rendered canonical ${JSON.stringify(actualMetadata.canonicalUrl)} does not match browser evidence ${JSON.stringify(seo.canonicalUrl)}.`);
        }
      }
      if (seo.metaDescriptionStatus === 'present') {
        if (actualMetadata.metaDescriptionCount !== 1 || !actualMetadata.metaDescription) {
          errors.push(`${expected.targetPath} rendered meta description is missing or duplicated; the fetched page must contain exactly one non-empty description.`);
        } else if (actualMetadata.metaDescription !== seo.metaDescription) {
          errors.push(`${expected.targetPath} rendered meta description does not match browser evidence.`);
        }
      }
      if (seo.openGraphImageStatus === 'present') {
        if (actualMetadata.openGraphImageCount !== 1 || !actualMetadata.openGraphImage) {
          errors.push(`${expected.targetPath} rendered og:image is missing or duplicated; the fetched page must contain exactly one usable social image.`);
        } else if (actualMetadata.openGraphImage !== seo.openGraphImage) {
          errors.push(`${expected.targetPath} rendered og:image does not match browser evidence.`);
        }
      }
    }
    return {
      ...expected,
      actualH1,
      actualMetadata,
      actualTitle,
      bodySha256: `sha256:${sha256(response.body)}`,
      errors,
      finalStatus: response.status,
      finalUrl: response.finalUrl,
      initialStatus: response.initialStatus,
      localTlsVerificationBypassed: response.localTlsVerificationBypassed,
      loadedAssets: actualAssets,
      passed: errors.length === 0,
      redirects: response.redirects,
      requestedUrl: requestedUrl.href
    };
  } catch (error) {
    errors.push(`${expected.targetPath} could not be fetched: ${error.message}`);
    return { ...expected, errors, passed: false, requestedUrl: requestedUrl.href };
  }
}

function packetBrowserArtifactValid(packetDir, value, { allowedScreenshots, effectiveness, publicRoute }) {
  const text = String(value ?? '').trim();
  if (!text || isAbsolute(text) || /^https?:\/\//i.test(text)) {
    return false;
  }
  const evidenceRoot = resolve(packetDir, 'evidence', 'browser');
  const evidencePath = resolve(packetDir, text);
  try {
    if (!(pathIsInside(evidenceRoot, evidencePath) &&
      statSync(evidencePath).isFile() &&
      statSync(evidencePath).size > 0)) {
      return false;
    }
    if (/\.json$/i.test(evidencePath)) {
      const artifact = JSON.parse(readFileSync(evidencePath, 'utf8'));
      return normalizePath(artifact?.publicRoute) === publicRoute &&
        artifact?.method === effectiveness?.method &&
        String(artifact?.selector ?? '').trim() === String(effectiveness?.selector ?? '').trim() &&
        String(artifact?.observedResult ?? '').trim() === String(effectiveness?.observedResult ?? '').trim();
    }
    return effectiveness?.method === 'visual_review' && allowedScreenshots.has(text);
  } catch {
    return false;
  }
}

export function canvasAssetRuntimeErrors({ browserEvidence, packetDir, routeChecks, runtimeDefaultTheme }) {
  const errors = [];
  const checks = (Array.isArray(browserEvidence?.canvasAuthoringChecks)
    ? browserEvidence.canvasAuthoringChecks
    : []).filter((check) =>
    check?.accepted === true && check?.canvasOwnsPublicRoute === true
  );
  for (const check of checks) {
    const publicRoute = normalizePath(check?.publicRoute);
    const route = (Array.isArray(routeChecks) ? routeChecks : []).find((candidate) =>
      normalizePath(candidate?.finalUrl || candidate?.expectedFinalPath || candidate?.targetPath) === publicRoute
    );
    if (!publicRoute || !route) {
      errors.push(`Canvas/component asset evidence for ${publicRoute || '(unknown route)'} has no matching live-fetched route.`);
      continue;
    }
    if (!runtimeDefaultTheme || String(check?.activePublicTheme ?? '').trim() !== runtimeDefaultTheme) {
      errors.push(`Canvas/component asset evidence for ${publicRoute} does not match live system.theme:default ${runtimeDefaultTheme || '(missing)'}.`);
    }
    const liveAssets = Array.isArray(route.loadedAssets) ? route.loadedAssets : [];
    const allowedScreenshots = new Set([
      check?.editorScreenshot,
      check?.publicRouteBeforeEditScreenshot,
      check?.publicRouteAfterEditScreenshot,
      ...(Array.isArray(browserEvidence?.publicRouteChecks) ? browserEvidence.publicRouteChecks : [])
        .filter((routeCheck) =>
          normalizePath(routeCheck?.targetFinalUrl || routeCheck?.targetUrl) === publicRoute
        )
        .map((routeCheck) => routeCheck?.targetScreenshot)
    ].map((path) => String(path ?? '').trim()).filter(Boolean));
    for (const provider of Array.isArray(check?.providerAssetChecks) ? check.providerAssetChecks : []) {
      for (const asset of Array.isArray(provider?.loadedAssets) ? provider.loadedAssets : []) {
        let declaredUrl = '';
        try {
          declaredUrl = new URL(String(asset?.url ?? '')).href;
        } catch {
          // Packet validation reports malformed URLs separately.
        }
        if (!liveAssets.some((candidate) =>
          candidate?.url === declaredUrl &&
          candidate?.type === asset?.type &&
          candidate?.observedBy === asset?.observedBy
        )) {
          errors.push(`Canvas/component provider ${provider?.provider || '(unknown provider)'} asset ${declaredUrl || asset?.url || '(missing URL)'} was not present in the live HTML for ${publicRoute}.`);
        }
      }
      for (const effectiveness of Array.isArray(provider?.effectivenessChecks) ? provider.effectivenessChecks : []) {
        if (!packetBrowserArtifactValid(packetDir, effectiveness?.evidence, {
          allowedScreenshots,
          effectiveness,
          publicRoute
        })) {
          errors.push(`Canvas/component provider ${provider?.provider || '(unknown provider)'} effectiveness evidence for ${publicRoute} is not a non-empty packet-local browser artifact.`);
        }
      }
    }
  }
  return errors;
}

function implementationQualityErrors(runtime, readback, routeMatrix, patternMap, independentVerification) {
  const errors = [];
  const runtimeCanvas = runtime?.canvasTemplateAudit ?? {};
  const packetCanvas = readback?.implementationQuality?.canvasTemplateAudit ?? {};
  const runtimeCanvasTemplates = Array.isArray(runtimeCanvas.templates) ? runtimeCanvas.templates : [];
  const packetCanvasTemplates = Array.isArray(packetCanvas.templates) ? packetCanvas.templates : [];
  const canvasUnused = canvasIntentionallyUnusedClaim(patternMap, routeMatrix, independentVerification);
  if (runtime?.configSyncTracked === true) {
    if (runtimeCanvas.completed !== true) {
      errors.push('The tracked-config Canvas content-template audit did not complete.');
    }
    if (
      packetCanvas.completed !== true ||
      packetCanvas.trackedConfigFileCount !== runtimeCanvas.trackedConfigFileCount ||
      packetCanvas.matchingConfigCount !== runtimeCanvas.matchingConfigCount ||
      packetCanvasTemplates.length !== runtimeCanvasTemplates.length
    ) {
      errors.push('drupal-readback.json Canvas content-template counts do not match the tracked config audit.');
    }
    for (const template of runtimeCanvasTemplates) {
      const packetTemplate = packetCanvasTemplates.find((record) =>
        record?.configName === template.configName && record?.path === template.path
      );
      if (
        !packetTemplate ||
        packetTemplate.enabled !== template.enabled ||
        packetTemplate.id !== template.id ||
        packetTemplate.entityType !== template.entityType ||
        packetTemplate.bundle !== template.bundle ||
        packetTemplate.viewMode !== template.viewMode
      ) {
        errors.push(`Tracked Canvas content template ${template.configName || template.path} is missing or inaccurate in drupal-readback.json.`);
        continue;
      }
      const publicTarget = canvasTemplateTargetsPublicOutput(template, readback, patternMap);
      if (packetTemplate.publicTarget !== publicTarget) {
        errors.push(`Tracked Canvas content template ${template.configName} has an inaccurate public-target disposition in drupal-readback.json.`);
      }
      if (canvasUnused && template.enabled === true && publicTarget) {
        errors.push(
          `Tracked config enables Canvas content template ${template.configName} for public ${template.entityType}.${template.bundle}.${template.viewMode} while the packet declares Canvas intentionally unused; active Canvas content templates supersede theme entity templates for that target.`
        );
      }
    }
  }

  const runtimeDisplay = runtime?.displayPluginAudit ?? {};
  const packetDisplay = readback?.implementationQuality?.displayPluginAudit ?? {};
  if (runtimeDisplay.completed !== true) {
    errors.push('The live Drupal display-plugin audit did not complete.');
  }
  for (const violation of Array.isArray(runtimeDisplay.violations) ? runtimeDisplay.violations : []) {
    if (violation.reason === 'missing_target_view_mode') {
      errors.push(`${violation.displayConfig || 'Drupal display'} field ${violation.fieldName || '(unknown)'} references missing ${violation.targetEntityType || 'target'} view mode ${violation.targetViewMode || '(unknown)'}.`);
    } else if (violation.reason === 'missing_field_definition') {
      errors.push(`${violation.displayConfig || 'Drupal display'} typed component ${violation.fieldName || '(unknown)'} has no Drupal field definition.`);
    } else if (violation.reason === 'plugin_field_type_not_supported') {
      errors.push(`${violation.displayConfig || 'Drupal display'} field ${violation.fieldName || '(unknown)'} configures ${violation.configuredPlugin || '(missing)'}, which does not declare support for field type ${violation.fieldType || '(unknown)'}.`);
    } else {
      errors.push(
        `${violation.displayConfig || 'Drupal display'} field ${violation.fieldName || '(unknown)'} configured ${violation.configuredPlugin || '(missing)'} but resolved ${violation.resolvedPlugin || '(missing)'} or failed the plugin class applicability check.`
      );
    }
  }
  if (
    packetDisplay.formComponentCount !== runtimeDisplay.formComponentCount ||
    packetDisplay.viewComponentCount !== runtimeDisplay.viewComponentCount
  ) {
    errors.push('drupal-readback.json display-plugin component counts do not match the live Drupal audit.');
  }
  const runtimeViewDisplays = Array.isArray(runtimeDisplay.viewDisplays) ? runtimeDisplay.viewDisplays : [];
  for (const display of Array.isArray(readback?.content?.viewDisplays) ? readback.content.viewDisplays : []) {
    if (display?.publicOutput !== true && display?.usedOnPublicRoute !== true && display?.embeddedOnPublicOutput !== true) {
      continue;
    }
    if (!runtimeViewDisplays.some((record) =>
      record?.entityType === (display.entityType || display.targetEntityType) &&
      record?.bundle === (display.bundle || display.targetBundle) &&
      record?.viewMode === (display.viewMode || display.mode)
    )) {
      errors.push(`Public or embedded view display ${(display.entityType || display.targetEntityType || '(entity)')}.${display.bundle || display.targetBundle || '(bundle)'}.${display.viewMode || display.mode || '(mode)'} does not exist in the live Drupal display audit.`);
    }
  }

  const runtimeCustom = runtime?.customCodeInventory ?? {};
  const packetCustom = readback?.implementationQuality?.customCodeInventory ?? {};
  const runtimeExtensions = Array.isArray(runtimeCustom.extensions) ? runtimeCustom.extensions : [];
  const packetExtensions = Array.isArray(packetCustom.extensions) ? packetCustom.extensions : [];
  if (runtimeCustom.completed !== true) {
    errors.push('The live custom-code inventory did not complete.');
  }
  for (const violation of Array.isArray(runtimeCustom.routeAuditViolations) ? runtimeCustom.routeAuditViolations : []) {
    errors.push(`Custom route ${violation.name || violation.filesystemPath || '(unknown)'} failed live Drupal router audit: ${violation.reason || 'unknown violation'}.`);
  }
  if ((runtimeExtensions.length > 0) !== (packetCustom.applies === true)) {
    errors.push('drupal-readback.json custom-code applicability does not match the live custom module/theme inventory.');
  }
  for (const extension of runtimeExtensions) {
    const packetExtension = packetExtensions.find((record) =>
      record?.accepted === true &&
      record?.machineName === extension.machineName &&
      record?.type === extension.type &&
      record?.path === extension.path &&
      record?.phpFileCount === extension.phpFileCount
    );
    if (!packetExtension) {
      errors.push(`Custom ${extension.type} ${extension.machineName} is missing from the accepted Drupal readback inventory.`);
      continue;
    }
    if (extension.phpFileCount > 0) {
      for (const kind of ['coding_standards', 'static_analysis']) {
        const liveCheck = (Array.isArray(extension.qualityChecks) ? extension.qualityChecks : []).find(
          (check) => check?.kind === kind
        );
        const packetDisposition = (Array.isArray(packetExtension.qualityChecks) ? packetExtension.qualityChecks : []).find(
          (check) => check?.kind === kind
        );
        if (!liveCheck) {
          errors.push(`Custom ${extension.type} ${extension.machineName} has no verifier-produced ${kind} result.`);
        } else if (liveCheck.supported === true && liveCheck.status !== 'pass') {
          errors.push(`Custom ${extension.type} ${extension.machineName} failed verifier-produced ${kind}.`);
        } else if (liveCheck.supported !== true) {
          const exception = packetDisposition?.exception ?? {};
          if (
            packetDisposition?.status !== 'exception' ||
            !String(exception.reason ?? '').trim() ||
            !String(exception.acceptedBy ?? '').trim() ||
            !String(exception.evidence ?? '').trim()
          ) {
            errors.push(`Custom ${extension.type} ${extension.machineName} requires a named ${kind} exception because the canonical local check is unsupported.`);
          }
        }
      }
    }
  }
  const runtimeSourceFiles = Array.isArray(runtimeCustom.sourceFiles) ? runtimeCustom.sourceFiles : [];
  const packetSourceFiles = Array.isArray(packetCustom.sourceFiles) ? packetCustom.sourceFiles : [];
  const normalizedSourceSurfaces = (surfaces) => JSON.stringify(
    (Array.isArray(surfaces) ? surfaces : [])
      .map((surface) => ({
        id: surface?.id,
        kind: surface?.kind,
        line: surface?.line,
        name: surface?.name
      }))
      .sort((left, right) => String(left.id).localeCompare(String(right.id)))
  );
  if (runtimeExtensions.length > 0 && runtimeSourceFiles.length === 0) {
    errors.push('The live custom-code inventory found extensions but no eligible custom source files.');
  }
  for (const sourceFile of runtimeSourceFiles) {
    const packetSourceFile = packetSourceFiles.find((record) =>
      record?.id === sourceFile?.id &&
      record?.extension === sourceFile?.extension &&
      record?.path === sourceFile?.path
    );
    if (!packetSourceFile) {
      errors.push(`Custom source file ${sourceFile?.path || '(unknown source file)'} is missing from drupal-readback.json.`);
      continue;
    }
    if (
      packetSourceFile.kind !== sourceFile.kind ||
      packetSourceFile.sha256 !== sourceFile.sha256 ||
      normalizedSourceSurfaces(packetSourceFile.surfaces) !== normalizedSourceSurfaces(sourceFile.surfaces)
    ) {
      errors.push(`Custom source file ${sourceFile.path} has stale kind, hash, or discovered-surface evidence in drupal-readback.json.`);
    }
  }
  for (const sourceFile of packetSourceFiles) {
    if (!runtimeSourceFiles.some((record) =>
      record?.id === sourceFile?.id &&
      record?.extension === sourceFile?.extension &&
      record?.path === sourceFile?.path
    )) {
      errors.push(`Custom source file ${sourceFile?.path || '(unknown source file)'} is not present in the live custom-code scan.`);
    }
  }
  const runtimeThemeFindings = Array.isArray(runtimeCustom.themeOwnershipFindings)
    ? runtimeCustom.themeOwnershipFindings
    : [];
  const packetThemeFindings = Array.isArray(packetCustom.themeOwnershipFindings)
    ? packetCustom.themeOwnershipFindings
    : [];
  if (runtimeExtensions.some((extension) => extension?.type === 'theme') && packetCustom.themeOwnershipReviewCompleted !== true) {
    errors.push('drupal-readback.json did not complete the custom-theme ownership review.');
  }
  for (const finding of runtimeThemeFindings) {
    const packetFinding = packetThemeFindings.find((record) =>
      record?.reviewed === true &&
      record?.id === finding.id &&
      record?.extension === finding.extension &&
      record?.kind === finding.kind &&
      record?.file === finding.file &&
      record?.line === finding.line &&
      record?.column === finding.column &&
      record?.matchHash === finding.matchHash
    );
    if (!packetFinding) {
      errors.push(`Theme ownership finding ${finding.id || finding.file} is missing or stale in the accepted Drupal readback inventory.`);
    }
  }
  for (const finding of packetThemeFindings) {
    if (!runtimeThemeFindings.some((record) => record?.id === finding?.id)) {
      errors.push(`Theme ownership finding ${finding?.id || finding?.file || '(unknown)'} is not present in the live custom-theme scan.`);
    }
  }
  const packetRoutes = Array.isArray(packetCustom.routes) ? packetCustom.routes : [];
  const routeMatrixRecords = [
    ...(Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : []),
    ...(Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : []),
    ...(Array.isArray(routeMatrix?.targetRequiredRoutes) ? routeMatrix.targetRequiredRoutes : [])
  ];
  const normalizedObject = (value) => JSON.stringify(
    Object.entries(value && typeof value === 'object' && !Array.isArray(value) ? value : {})
      .sort(([left], [right]) => left.localeCompare(right))
  );
  for (const route of Array.isArray(runtimeCustom.routes) ? runtimeCustom.routes : []) {
    const packetRoute = packetRoutes.find((record) =>
      record?.name === route.name &&
      normalizePath(record?.path) === normalizePath(route.path) &&
      record?.extension === route.extension &&
      String(record?.controller ?? '') === String(route.controller ?? '')
    );
    if (!packetRoute?.accepted) {
      errors.push(`Custom route ${route.name || route.path} is missing from the accepted Drupal readback inventory.`);
      continue;
    }
    if (route.accessCheckCompleted !== true) {
      errors.push(`Custom route ${route.name} did not complete a live anonymous-access check.`);
    }
    if (route.requestMatched !== true || route.parameterConversionCompleted !== true) {
      errors.push(`Custom route ${route.name} did not match and convert its declared representative HTTP request.`);
    }
    if (route.anonymousAccess === 'neutral') {
      errors.push(`Custom route ${route.name} returned neutral anonymous access instead of an effective allowed or denied result.`);
    }
    if (packetRoute.requestMethod !== route.requestMethod) {
      errors.push(`Custom route ${route.name} request method ${packetRoute.requestMethod || '(missing)'} does not match the live request audit method ${route.requestMethod || '(missing)'}.`);
    }
    if (packetRoute.anonymousAccessDisposition !== route.anonymousAccess) {
      errors.push(`Custom route ${route.name} anonymous-access disposition ${packetRoute.anonymousAccessDisposition || '(missing)'} does not match live Drupal access ${route.anonymousAccess || '(unknown)'}.`);
    }
    if (normalizePath(packetRoute.representativePath) !== normalizePath(route.representativePath)) {
      errors.push(`Custom route ${route.name} representative path does not match the path generated by live Drupal routing.`);
    }
    if (normalizedObject(packetRoute.requirements) !== normalizedObject(route.requirements)) {
      errors.push(`Custom route ${route.name} requirements do not match the live Drupal route definition.`);
    }
    if (route.discovery !== 'live_callback' && packetRoute.sourceFile !== route.file) {
      errors.push(`Custom route ${route.name} source file does not match its live routing definition.`);
    }
    const binding = packetRoute.routeMatrixBinding ?? {};
    const matrixBindingPresent = routeMatrixRecords.some((record) =>
      (binding.kind === 'concrete_path' && normalizePath(record?.targetPath) === normalizePath(binding.value)) ||
      (binding.kind === 'route_name' && record?.routeName === binding.value)
    );
    if (!matrixBindingPresent) {
      errors.push(`Custom route ${route.name} has no matching concrete-path or route-name binding in route-matrix.json.`);
    }
  }
  for (const controller of Array.isArray(runtimeCustom.controllers) ? runtimeCustom.controllers : []) {
    const packetController = (Array.isArray(packetCustom.controllers) ? packetCustom.controllers : []).find((record) =>
      record?.path === controller?.path && record?.extension === controller?.extension
    );
    if (!packetController) {
      errors.push(`Custom controller ${controller?.path || '(unknown controller)'} is missing from drupal-readback.json.`);
    }
  }
  for (const controller of Array.isArray(packetCustom.controllers) ? packetCustom.controllers : []) {
    if (!(Array.isArray(runtimeCustom.controllers) ? runtimeCustom.controllers : []).some((record) =>
      record?.path === controller?.path && record?.extension === controller?.extension
    )) {
      errors.push(`Custom controller ${controller?.path || '(unknown controller)'} is not present in the live custom-code scan.`);
    }
  }
  for (const path of Array.isArray(runtimeCustom.tests) ? runtimeCustom.tests : []) {
    if (!Array.isArray(packetCustom.tests) || !packetCustom.tests.includes(path)) {
      errors.push(`Custom test ${path} is missing from drupal-readback.json.`);
    }
  }

  const packetAliasPolicies = Array.isArray(readback?.routing?.publicBundleAliasPolicies)
    ? readback.routing.publicBundleAliasPolicies.filter((policy) =>
        ['pathauto_pattern', 'editor_supplied_alias'].includes(policy?.strategy)
      )
    : [];
  const runtimeAliases = runtime?.aliasPolicyAudit ?? {};
  if (packetAliasPolicies.length > 0 && runtimeAliases.completed !== true) {
    errors.push('The live Drupal alias-policy audit did not complete.');
  }
  for (const policy of packetAliasPolicies) {
    const record = (Array.isArray(runtimeAliases.records) ? runtimeAliases.records : []).find((candidate) =>
      candidate?.entityType === policy?.entityType &&
      candidate?.bundle === policy?.bundle &&
      String(candidate?.probeEntityId ?? '') === String(policy?.probeEntityId ?? '') &&
      candidate?.probeAlias === policy?.probeAlias
    );
    if (!record?.passed) {
      errors.push(`Future alias policy ${policy?.entityType || '(entity)'}.${policy?.bundle || '(bundle)'} did not live-load its probe entity, applicable pattern, and alias resolution.`);
    }
  }
  return errors;
}

export async function verifyLive({
  packetDir = 'review-packet',
  targetUrl = '',
  cwd = process.cwd(),
  environment = process.env,
  drupalRuntime = null
} = {}) {
  const absolutePacketDir = resolve(cwd, packetDir);
  const routeMatrixPath = join(absolutePacketDir, 'route-matrix.json');
  const packetReport = await validatePacket({ packetDir: absolutePacketDir });
  let routeMatrixText = '';
  let routeMatrix = {};
  let routeMatrixError = '';
  try {
    routeMatrixText = await readFile(routeMatrixPath, 'utf8');
    routeMatrix = JSON.parse(routeMatrixText);
  } catch (error) {
    routeMatrixError = `route-matrix.json cannot be used for live verification: ${error.message}`;
  }
  let independentVerification = null;
  let blindReview = null;
  let drupalReadback = null;
  let browserEvidence = null;
  let fieldOutputMatrix = null;
  let parityReport = null;
  let patternMap = null;
  let sourceAudit = null;
  try {
    independentVerification = JSON.parse(
      await readFile(join(absolutePacketDir, 'independent-verification.json'), 'utf8')
    );
    blindReview = JSON.parse(
      await readFile(join(absolutePacketDir, 'blind-adversarial-review.json'), 'utf8')
    );
    drupalReadback = JSON.parse(
      await readFile(join(absolutePacketDir, 'drupal-readback.json'), 'utf8')
    );
    browserEvidence = JSON.parse(
      await readFile(join(absolutePacketDir, 'browser-evidence.json'), 'utf8')
    );
    fieldOutputMatrix = JSON.parse(
      await readFile(join(absolutePacketDir, 'field-output-matrix.json'), 'utf8')
    );
    parityReport = JSON.parse(
      await readFile(join(absolutePacketDir, 'parity-report.json'), 'utf8')
    );
    patternMap = JSON.parse(
      await readFile(join(absolutePacketDir, 'pattern-map.json'), 'utf8')
    );
    sourceAudit = JSON.parse(
      await readFile(join(absolutePacketDir, 'source-audit.json'), 'utf8')
    );
  } catch {
    // Packet validation already records malformed or missing required JSON.
  }
  const liveErrors = routeMatrixError ? [routeMatrixError] : [];
  const declaredSource = String(routeMatrix.sourceBaseUrl ?? '').trim();
  const declaredTarget = String(routeMatrix.targetBaseUrl ?? '').trim();
  if (!declaredSource) {
    liveErrors.push('route-matrix.json must declare sourceBaseUrl for target/source identity checking.');
  }
  if (!declaredTarget) {
    liveErrors.push('route-matrix.json must declare targetBaseUrl for target identity checking.');
  }

  let target;
  try {
    target = resolveTargetUrl({
      cwd,
      environment,
      explicitTargetUrl: targetUrl
    });
  } catch (error) {
    liveErrors.push(error.message);
  }

  const runtimeWasInjected = drupalRuntime !== null;
  const customRouteBindings = drupalReadback?.implementationQuality?.customCodeInventory?.routes;
  const aliasPolicies = drupalReadback?.routing?.publicBundleAliasPolicies;
  const inspectedDrupalRuntime = drupalRuntime ?? inspectDrupalRuntime(
    cwd,
    environment,
    Array.isArray(customRouteBindings) ? customRouteBindings : [],
    Array.isArray(aliasPolicies) ? aliasPolicies : []
  );
  const runtimeAuthoritativeForCompletion = !runtimeWasInjected;
  let runtimeTargetOriginMatches = false;
  if (target && inspectedDrupalRuntime.baseUrl) {
    try {
      const runtimeTarget = parseHttpUrl(inspectedDrupalRuntime.baseUrl, 'Current DDEV runtime base URL');
      runtimeTargetOriginMatches = runtimeTarget.origin === target.url.origin;
    } catch {
      // An invalid or unavailable DDEV URL cannot bind the inspected Drupal runtime to the HTTP target.
    }
  }
  const explicitTargetFetchAllowed =
    !target || target.source !== 'explicit' || runtimeTargetOriginMatches;
  if (!explicitTargetFetchAllowed) {
    liveErrors.push(
      'Explicit target HTTP checks are disabled unless the URL matches the current DDEV runtime.'
    );
  }

  if (target && declaredSource) {
    try {
      const sourceUrl = parseHttpUrl(declaredSource, 'route-matrix.json sourceBaseUrl');
      if (sourceUrl.origin === target.url.origin) {
        liveErrors.push('The resolved live target has the same origin as sourceBaseUrl; refusing to certify the source site as the rebuild.');
      }
    } catch (error) {
      liveErrors.push(error.message);
    }
  }
  if (target && declaredTarget) {
    try {
      const packetTarget = parseHttpUrl(declaredTarget, 'route-matrix.json targetBaseUrl');
      if (packetTarget.origin !== target.url.origin) {
        liveErrors.push(
          `The resolved live target origin ${target.url.origin} does not match route-matrix.json targetBaseUrl ${packetTarget.origin}.`
        );
      }
    } catch (error) {
      liveErrors.push(error.message);
    }
  }

  const primaryRoutes = Array.isArray(routeMatrix.primaryRoutes) ? routeMatrix.primaryRoutes : [];
  if (primaryRoutes.length === 0) {
    liveErrors.push('route-matrix.json must declare at least one primary route.');
  }
  const routeChecks = target && explicitTargetFetchAllowed
    ? await Promise.all(primaryRoutes.map((route) => verifyRoute(
        target.url,
        expectedRoute(routeMatrix, route, browserEvidence)
      )))
    : [];
  for (const route of routeChecks) {
    liveErrors.push(...route.errors);
  }
  const targetRequiredRoutes = Array.isArray(routeMatrix.targetRequiredRoutes)
    ? routeMatrix.targetRequiredRoutes
    : [];
  const targetRequiredRouteChecks = target && explicitTargetFetchAllowed
    ? await Promise.all(targetRequiredRoutes.map((route) => verifyRoute(target.url, expectedTargetRequiredRoute(route))))
    : [];
  for (const route of targetRequiredRouteChecks) {
    liveErrors.push(...route.errors);
  }
  const canvasRuntimeErrors = canvasAssetRuntimeErrors({
    browserEvidence,
    packetDir: absolutePacketDir,
    routeChecks: [...routeChecks, ...targetRequiredRouteChecks],
    runtimeDefaultTheme: inspectedDrupalRuntime.defaultTheme
  });
  liveErrors.push(...canvasRuntimeErrors);
  const drupalImplementationErrors = implementationQualityErrors(
    inspectedDrupalRuntime,
    drupalReadback,
    routeMatrix,
    patternMap,
    independentVerification
  );

  const packetSupportsCompletion = packetReport.completionEvidence?.packetSupportsCompletion === true;
  const packetClaimsQualifyingReview =
    independentVerification?.summary?.verdict === 'pass' ||
    ['good', 'good_enough'].includes(blindReview?.summary?.verdict);
  const implementationReviewRequired = packetSupportsCompletion || packetClaimsQualifyingReview;
  if (implementationReviewRequired) {
    liveErrors.push(...drupalImplementationErrors);
  }
  if (target && (packetSupportsCompletion || packetClaimsQualifyingReview) && declaredSource) {
    try {
      const sourceUrl = parseHttpUrl(declaredSource, 'route-matrix.json sourceBaseUrl');
      liveErrors.push(
        ...completionEvidenceTargetErrors({
          blindReview,
          browserEvidence,
          drupalReadback,
          fieldOutputMatrix,
          independentVerification,
          parityReport,
          patternMap,
          sourceAudit,
          sourceUrl,
          targetUrl: target.url
        })
      );
    } catch (error) {
      liveErrors.push(error.message);
    }
  }

  const liveTargetValid = Boolean(target) && liveErrors.length === 0;
  const packetSiteUuid = String(drupalReadback?.drupal?.siteUuid ?? '').trim().toLowerCase();
  const packetDefaultTheme = String(drupalReadback?.drupal?.defaultTheme ?? '').trim();
  const packetFrontPage = normalizePath(drupalReadback?.drupal?.frontPage);
  const runtimeFrontPage = normalizePath(inspectedDrupalRuntime.frontPage);
  const packetConfigSyncDirectory = sharedConfigSyncDirectory(drupalReadback?.drupal?.configSyncDirectory);
  const runtimeConfigSyncDirectory = sharedConfigSyncDirectory(inspectedDrupalRuntime.configSyncDirectory);
  const packetTrackedConfigDirectory = sharedConfigSyncDirectory(drupalReadback?.drupal?.trackedConfigDirectory);
  const runtimeTrackedConfigDirectory = sharedConfigSyncDirectory(inspectedDrupalRuntime.trackedConfigDirectory);
  const packetTrackedConfigYamlFiles = (Array.isArray(drupalReadback?.drupal?.trackedConfigYamlFiles)
    ? drupalReadback.drupal.trackedConfigYamlFiles
    : [])
    .map((path) => String(path).trim().replaceAll('\\', '/'))
    .filter(Boolean);
  const runtimeTrackedConfigYamlFiles = (Array.isArray(inspectedDrupalRuntime.trackedConfigYamlFiles)
    ? inspectedDrupalRuntime.trackedConfigYamlFiles
    : [])
    .map((path) => String(path).trim().replaceAll('\\', '/'))
    .filter(Boolean);
  const runtimeTrackedConfigSet = new Set(runtimeTrackedConfigYamlFiles);
  const drupalRuntimeTargetMatches = runtimeTargetOriginMatches;
  const drupalRuntimeSiteUuidMatches =
    Boolean(packetSiteUuid) &&
    packetSiteUuid === String(inspectedDrupalRuntime.siteUuid ?? '').trim().toLowerCase();
  const drupalRuntimeDefaultThemeMatches =
    Boolean(packetDefaultTheme) &&
    packetDefaultTheme === String(inspectedDrupalRuntime.defaultTheme ?? '').trim();
  const drupalRuntimeFrontPageMatches =
    Boolean(String(drupalReadback?.drupal?.frontPage ?? '').trim()) &&
    Boolean(String(inspectedDrupalRuntime.frontPage ?? '').trim()) &&
    packetFrontPage === runtimeFrontPage;
  const drupalRuntimeConfigSyncMatches =
    Boolean(packetConfigSyncDirectory) &&
    Boolean(runtimeConfigSyncDirectory) &&
    packetConfigSyncDirectory === runtimeConfigSyncDirectory;
  const drupalRuntimeConfigStatusClean = inspectedDrupalRuntime.configStatusClean === true;
  const drupalRuntimeConfigSyncTracked =
    inspectedDrupalRuntime.configSyncTracked === true &&
    runtimeTrackedConfigYamlFiles.length > 0;
  const drupalRuntimeTrackedConfigReadbackMatches =
    Boolean(packetTrackedConfigDirectory) &&
    packetTrackedConfigDirectory === runtimeTrackedConfigDirectory &&
    packetTrackedConfigYamlFiles.length > 0 &&
    packetTrackedConfigYamlFiles.every((path) => runtimeTrackedConfigSet.has(path));
  const drupalRuntimeImplementationQualityValid =
    !implementationReviewRequired || drupalImplementationErrors.length === 0;
  const drupalRuntimeSupportsCompletion =
    runtimeAuthoritativeForCompletion &&
    inspectedDrupalRuntime.confirmed === true &&
    drupalRuntimeTargetMatches &&
    drupalRuntimeSiteUuidMatches &&
    drupalRuntimeDefaultThemeMatches &&
    drupalRuntimeFrontPageMatches &&
    drupalRuntimeConfigSyncMatches &&
    drupalRuntimeConfigStatusClean &&
    drupalRuntimeConfigSyncTracked &&
    drupalRuntimeTrackedConfigReadbackMatches &&
    drupalRuntimeImplementationQualityValid;
  const completeLocalRebuildClaimAllowed =
    packetReport.valid &&
    liveTargetValid &&
    packetSupportsCompletion &&
    drupalRuntimeSupportsCompletion;
  const completionBlockedReasons = [];
  if (!packetReport.valid) {
    completionBlockedReasons.push('Packet validation failed.');
  }
  if (!liveTargetValid) {
    completionBlockedReasons.push('Live target identity or route verification failed.');
  }
  if (!packetReport.completionEvidence?.independentVerificationSupportsCompletion) {
    completionBlockedReasons.push('Independent verification evidence does not support completion.');
  }
  if (!packetReport.completionEvidence?.blindAdversarialReviewSupportsCompletion) {
    completionBlockedReasons.push('Blind adversarial review evidence does not support completion.');
  }
  if (!packetReport.completionEvidence?.packetCompletionReady) {
    completionBlockedReasons.push('Required packet evidence is still template-like, unresolved, or not accepted.');
  }
  if (inspectedDrupalRuntime.confirmed !== true || !drupalRuntimeSiteUuidMatches) {
    completionBlockedReasons.push('Current DDEV Drupal runtime identity does not match drupal-readback.json siteUuid.');
  }
  if (!drupalRuntimeDefaultThemeMatches) {
    completionBlockedReasons.push('Current DDEV system.theme:default does not match drupal-readback.json defaultTheme.');
  }
  if (!drupalRuntimeTargetMatches) {
    completionBlockedReasons.push('Current DDEV runtime base URL does not match the live target origin.');
  }
  if (!drupalRuntimeFrontPageMatches) {
    completionBlockedReasons.push('Current DDEV front-page setting does not match drupal-readback.json.');
  }
  if (!drupalRuntimeConfigSyncMatches) {
    completionBlockedReasons.push('Current DDEV config-sync directory does not match drupal-readback.json.');
  }
  if (!drupalRuntimeConfigStatusClean) {
    completionBlockedReasons.push('Current DDEV config status is not clean or could not be verified.');
  }
  if (!drupalRuntimeConfigSyncTracked) {
    completionBlockedReasons.push('Current DDEV config-sync directory does not contain real Git-tracked YAML files.');
  }
  if (!drupalRuntimeTrackedConfigReadbackMatches) {
    completionBlockedReasons.push('Current Git-tracked config evidence does not match drupal-readback.json.');
  }
  if (!drupalRuntimeImplementationQualityValid) {
    completionBlockedReasons.push('Current Drupal display plugins, alias policies, or custom runtime code do not match the accepted maintainer-quality readback.');
  }
  if (!runtimeAuthoritativeForCompletion) {
    completionBlockedReasons.push('Injected Drupal runtime evidence is non-authoritative and cannot authorize completion.');
  }

  const targetFingerprintInput = JSON.stringify({
    origin: target?.url.origin ?? '',
    routeChecks: [...routeChecks, ...targetRequiredRouteChecks].map((route) => ({
      bodySha256: route.bodySha256 ?? '',
      finalUrl: route.finalUrl ?? '',
      h1: route.actualH1 ?? '',
      path: route.targetPath,
      status: route.finalStatus ?? 0,
      title: route.actualTitle ?? ''
    }))
  });
  const sharedPacketReport = {
    ...packetReport,
    packetDir: basename(absolutePacketDir),
    errors: packetReport.errors.map((error) => sharedMessage(error, absolutePacketDir)),
    warnings: packetReport.warnings.map((warning) => sharedMessage(warning, absolutePacketDir))
  };

  return {
    schemaVersion: 'public-kit.live-verification.1',
    checkedAt: new Date().toISOString(),
    claimScope: 'complete-local-rebuild',
    productionReadinessEvaluated: false,
    launchReady: false,
    verificationMode: 'live-target-and-packet',
    packetDir: basename(absolutePacketDir),
    target: target
      ? {
          declaredSourceBaseUrl: declaredSource,
          declaredTargetBaseUrl: declaredTarget,
          resolvedBaseUrl: target.url.href,
          resolutionSource: target.source,
          targetFingerprint: `sha256:${sha256(targetFingerprintInput)}`
        }
      : null,
    evidenceBinding: {
      routeMatrixSha256: `sha256:${sha256(routeMatrixText)}`,
      targetFingerprintInputVersion: 1
    },
    routeChecks,
    targetRequiredRouteChecks,
    liveTargetValid,
    drupalRuntime: {
      ...inspectedDrupalRuntime,
      authoritativeForCompletion: runtimeAuthoritativeForCompletion,
      configStatusClean: drupalRuntimeConfigStatusClean,
      configSyncTracked: drupalRuntimeConfigSyncTracked,
      configSyncDirectory: sharedConfigSyncDirectory(inspectedDrupalRuntime.configSyncDirectory),
      configSyncDirectoryMatchesPacket: drupalRuntimeConfigSyncMatches,
      defaultThemeMatchesPacket: drupalRuntimeDefaultThemeMatches,
      frontPageMatchesPacket: drupalRuntimeFrontPageMatches,
      implementationQualityValid: drupalRuntimeImplementationQualityValid,
      siteUuidMatchesPacket: drupalRuntimeSiteUuidMatches,
      targetOriginMatches: drupalRuntimeTargetMatches,
      trackedConfigYamlPresent: drupalRuntimeConfigSyncTracked,
      trackedConfigDirectory: runtimeTrackedConfigDirectory,
      trackedConfigReadbackMatches: drupalRuntimeTrackedConfigReadbackMatches,
      trackedConfigYamlFiles: runtimeTrackedConfigYamlFiles
    },
    packetVerification: sharedPacketReport,
    completeLocalRebuildClaimAllowed,
    completionBlockedReasons,
    valid: packetReport.valid && liveTargetValid,
    errors: [...sharedPacketReport.errors, ...liveErrors.map((error) => sharedMessage(error, absolutePacketDir))],
    warnings: sharedPacketReport.warnings
  };
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

  const report = args.packetOnly
    ? await validatePacket({ packetDir: resolve(args.packet) })
    : await verifyLive({
        packetDir: args.packet,
        targetUrl: args.targetUrl
      });
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, `${JSON.stringify(report, null, 2)}\n`);

  if (!report.valid) {
    process.stderr.write(`${args.packetOnly ? 'Packet' : 'Live target'} verification failed. Report: ${args.out}\n`);
    for (const error of report.errors) {
      process.stderr.write(`- ${error}\n`);
    }
    process.exitCode = 1;
    return;
  }
  if (args.packetOnly) {
    process.stdout.write(`Packet structure valid; packet-only verification never authorizes completion. Report: ${args.out}\n`);
  } else if (report.completeLocalRebuildClaimAllowed) {
    process.stdout.write(`Live target and packet verification passed; complete local rebuild claim authorized. Report: ${args.out}\n`);
  } else {
    process.stderr.write(`Live target checks passed, but completion remains blocked by required review evidence. Report: ${args.out}\n`);
    process.exitCode = 2;
  }
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
