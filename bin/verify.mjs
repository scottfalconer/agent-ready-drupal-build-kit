#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validatePacket } from './verify-packet.mjs';
import { applyVerificationLifecycle, globalChromeCaptureContext } from './lifecycle.mjs';
import {
  captureBeforeConsentNetwork,
  captureGlobalChrome,
  captureSummary,
  finalizeBeforeConsentNetworkCapture,
  finalizeGlobalChromeCapture,
  validateBeforeConsentNetworkCapture
} from './global-chrome.mjs';
import {
  buildSiteState,
  collectFileManifest,
  collectRuntimeCodeManifest,
  sha256 as stateSha256
} from './state-fingerprint.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const KIT_ROOT = resolve(dirname(SCRIPT_PATH), '..');
const USAGE = `Usage: node <path-to-skill>/scripts/verify.mjs [options]

Verify the packet against the real target by default.

Options:
  --packet <path>      Review packet directory (default: review-packet)
  --target-url <url>   Explicit target URL (otherwise detect current DDEV target)
  --out <path>         Report path (default: review-packet/evidence/live-verification.json)
  --change <id>        Bind a passing full run to an evidence-recorded repair or extension
  --checkpoint <id>    Create a create-only checkpoint for the passing change
  --packet-only        Run structural packet lint only; never authorizes completion
  --help               Show this help`;
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 15_000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;

class UsageError extends Error {}

function parseArgs(argv) {
  const args = {
    changeId: '',
    checkpointId: '',
    packet: 'review-packet',
    out: '',
    packetOnly: false,
    targetUrl: ''
  };
  const valueOptions = new Map([
    ['--change', 'changeId'],
    ['--checkpoint', 'checkpointId'],
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
  if (args.packetOnly && (args.changeId || args.checkpointId)) {
    throw new UsageError('Lifecycle change/checkpoint options cannot be combined with --packet-only.');
  }
  if (args.checkpointId && !args.changeId) {
    throw new UsageError('--checkpoint requires --change <id>.');
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

function packetEvidenceManifest(packetDir, outPath = '') {
  const excluded = new Set([
    'evidence/live-verification.json',
    'evidence/packet-verification.json'
  ]);
  const absoluteOut = outPath ? resolve(outPath) : '';
  if (absoluteOut && pathIsInside(packetDir, absoluteOut)) {
    excluded.add(relative(packetDir, absoluteOut).split(sep).join('/'));
  }
  const files = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => comparePortable(left.name, right.name))) {
      const path = join(directory, entry.name);
      const packetPath = relative(packetDir, path).split(sep).join('/');
      const metadata = lstatSync(path);
      if (entry.isSymbolicLink() || metadata.isSymbolicLink()) {
        throw new Error(`Review packet evidence must not contain symbolic links: ${packetPath}`);
      }
      if (metadata.isDirectory()) {
        if (packetPath === 'evidence/lifecycle' || packetPath.startsWith('evidence/lifecycle/')) {
          continue;
        }
        visit(path);
      } else if (metadata.isFile()) {
        if (!excluded.has(packetPath)) {
          files.push(packetPath);
        }
      } else {
        throw new Error(`Review packet evidence must contain only regular files and directories: ${packetPath}`);
      }
    }
  };
  visit(packetDir);
  return collectFileManifest(packetDir, files);
}

function assertVerificationPacketInputs(packetDir) {
  if (!existsSync(packetDir)) {
    throw new Error(`Review packet directory does not exist: ${packetDir}`);
  }
  const packetMetadata = lstatSync(packetDir);
  if (packetMetadata.isSymbolicLink() || !packetMetadata.isDirectory()) {
    throw new Error('Review packet input must be a real directory, not a file or symbolic link.');
  }
  for (const entry of readdirSync(packetDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink() || lstatSync(join(packetDir, entry.name)).isSymbolicLink()) {
      throw new Error(`Review packet top-level input must not be a symbolic link: ${entry.name}`);
    }
  }
}

function verifierFingerprint() {
  const scriptDirectory = dirname(SCRIPT_PATH);
  const files = [
    SCRIPT_PATH,
    join(scriptDirectory, 'verify-packet.mjs'),
    join(scriptDirectory, 'state-fingerprint.mjs'),
    join(scriptDirectory, 'lifecycle.mjs'),
    join(KIT_ROOT, 'gates.json')
  ]
    .filter((path) => existsSync(path))
    .map((path) => relative(KIT_ROOT, path));
  return collectFileManifest(KIT_ROOT, files).fingerprint;
}

function sharedMessage(value, absolutePacketDir) {
  return String(value).replaceAll(absolutePacketDir, basename(absolutePacketDir));
}

function normalizeText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim();
}

function comparePortable(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
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

function intrinsicUrl(value, finalUrl, { asset = false } = {}) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  try {
    const base = new URL(finalUrl);
    const url = new URL(text, base);
    if (!['http:', 'https:'].includes(url.protocol)) {
      return `${url.protocol}${url.pathname || url.href.slice(url.protocol.length)}`;
    }
    const params = [...url.searchParams.entries()]
      .map(([key, parameterValue]) => {
        const drupalToken = /^(?:_?token|csrf(?:_token)?|form_build_id|form_token|nonce)$/i.test(key);
        const assetCacheBuster = asset && /^(?:_|cache|cb|v|ver|version)$/i.test(key);
        return [key, drupalToken ? '{drupal-token}' : assetCacheBuster ? '{asset-cache-buster}' : parameterValue];
      })
      .sort(([leftKey, leftValue], [rightKey, rightValue]) => (
        comparePortable(leftKey, rightKey) || comparePortable(leftValue, rightValue)
      ));
    const query = params.length
      ? `?${params.map(([key, parameterValue]) => `${encodeURIComponent(key)}=${encodeURIComponent(parameterValue)}`).join('&')}`
      : '';
    const fragment = url.hash;
    const scope = url.origin === base.origin ? 'local:' : `external:${url.protocol}//${url.host}`;
    return `${scope}${normalizePath(url.pathname)}${query}${fragment}`;
  } catch {
    return normalizeText(text);
  }
}

function intrinsicRouteSemantics(html, finalUrl) {
  const bodyMatch = String(html).match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
  const visibleSource = (bodyMatch?.[1] ?? String(html))
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|template|noscript|svg)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<input\b[^>]*>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');
  let visibleTextValue = decodeEntities(visibleSource);
  try {
    visibleTextValue = visibleTextValue.replaceAll(new URL(finalUrl).origin, '{target-origin}');
  } catch {
    // The route verifier already validates finalUrl. Keep text as-is if a
    // caller uses this helper with a malformed synthetic value.
  }
  const visibleText = normalizeText(visibleTextValue);
  const links = matchingTags(html, 'a', (attributes) => Boolean(attributes.href))
    .map((attributes) => intrinsicUrl(attributes.href, finalUrl));
  const media = [];
  for (const tagName of ['img', 'source', 'video', 'audio', 'iframe']) {
    for (const attributes of matchingTags(html, tagName, () => true)) {
      const asset = tagName !== 'iframe';
      for (const attribute of ['src', 'poster']) {
        if (attributes[attribute]) {
          media.push(`${tagName}:${attribute}:${intrinsicUrl(attributes[attribute], finalUrl, { asset })}`);
        }
      }
      if (attributes.srcset) {
        for (const candidate of attributes.srcset.split(',')) {
          const [url, descriptor = ''] = candidate.trim().split(/\s+/, 2);
          if (url) {
            media.push(`${tagName}:srcset:${intrinsicUrl(url, finalUrl, { asset })}:${descriptor}`);
          }
        }
      }
    }
  }
  const forms = matchingTags(html, 'form', () => true).map((attributes) => ({
    action: intrinsicUrl(attributes.action || finalUrl, finalUrl),
    method: String(attributes.method || 'get').toLowerCase()
  }));
  const controls = [];
  for (const tagName of ['input', 'select', 'textarea', 'button']) {
    for (const attributes of matchingTags(html, tagName, () => true)) {
      controls.push({
        tag: tagName,
        name: String(attributes.name ?? ''),
        type: String(attributes.type ?? '').toLowerCase()
      });
    }
  }
  const semantics = {
    visibleTextSha256: stateSha256(visibleText),
    visibleTextLength: visibleText.length,
    linkTargetsSha256: stateSha256(links),
    linkCount: links.length,
    mediaTargetsSha256: stateSha256(media),
    mediaCount: media.length,
    formShapeSha256: stateSha256({ forms, controls }),
    formCount: forms.length,
    formControlCount: controls.length
  };
  return {
    schemaVersion: 'public-kit.route-semantics.1',
    ...semantics,
    fingerprint: stateSha256({ schemaVersion: 'public-kit.route-semantics.1', ...semantics })
  };
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

function absoluteRenderedUrl(value, finalUrl) {
  const text = String(value ?? '').trim();
  if (!text || /^(?:data|javascript|mailto|tel):/i.test(text)) {
    return '';
  }
  try {
    const url = new URL(text, finalUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      return '';
    }
    url.hash = '';
    return url.href;
  } catch {
    return '';
  }
}

function renderedLegalLinks(html, finalUrl) {
  const final = new URL(finalUrl);
  const legalSignal = /(?:privacy|legal|terms|cookie|data[ -]?protection|do[ -]?not[ -]?sell|accessibility(?:[ -]?statement)?)/i;
  const links = [];
  for (const match of html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
    const attributes = tagAttributes(`<a ${match[1]}>`);
    const url = absoluteRenderedUrl(attributes.href, finalUrl);
    const text = normalizeText(decodeEntities(match[2].replace(/<[^>]+>/g, ' ')));
    const label = normalizeText(`${text} ${attributes['aria-label'] ?? ''} ${attributes.title ?? ''}`);
    if (!url || new URL(url).origin !== final.origin || !legalSignal.test(`${label} ${new URL(url).pathname}`)) {
      continue;
    }
    links.push({ sourceUrl: finalUrl, text: label, url });
  }
  return links;
}

function renderedResourceUrls(html, finalUrl) {
  const urls = new Set();
  const tags = [
    ['script', 'src'],
    ['iframe', 'src'],
    ['img', 'src'],
    ['source', 'src'],
    ['link', 'href']
  ];
  for (const [tag, attribute] of tags) {
    for (const attributes of matchingTags(html, tag, () => true)) {
      const url = absoluteRenderedUrl(attributes[attribute], finalUrl);
      if (url) {
        urls.add(url);
      }
    }
  }
  return [...urls].sort();
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

function normalizeRouteKey(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  try {
    const url = /^https?:\/\//i.test(text)
      ? new URL(text)
      : new URL(text, 'https://route-key.invalid/');
    return `${normalizePath(url.pathname)}${url.search}`;
  } catch {
    return normalizePath(text);
  }
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
  current.hash = '';
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
      next.hash = '';
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

function ddevTargetUrl(cwd, environment = process.env) {
  try {
    const output = execFileSync('ddev', ['describe', '-j'], {
      cwd,
      encoding: 'utf8',
      env: environment,
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

function ddevConfigValue(projectRoot, key) {
  try {
    const config = readFileSync(join(projectRoot, '.ddev', 'config.yaml'), 'utf8');
    const match = config.match(new RegExp(`^\\s*${key}:\\s*(?:["']([^"']*)["']|([^#\\r\\n]*?))\\s*(?:#.*)?$`, 'mi'));
    return String(match?.[1] ?? match?.[2] ?? '').trim();
  } catch {
    return '';
  }
}

function ddevContainerContext(projectRoot, environment) {
  if (!/^(?:1|true|yes)$/i.test(String(environment.IS_DDEV_PROJECT ?? '').trim())) {
    return false;
  }
  const appRoot = String(environment.DDEV_APPROOT ?? '').trim();
  if (!appRoot || !isAbsolute(appRoot) || !existsSync(appRoot)) {
    return false;
  }
  let realAppRoot;
  try {
    realAppRoot = realpathSync(appRoot);
  } catch {
    return false;
  }
  if (realAppRoot !== realpathSync(projectRoot)) {
    return false;
  }
  const configuredName = ddevConfigValue(projectRoot, 'name');
  const environmentName = String(environment.DDEV_PROJECT || environment.DDEV_SITENAME || '').trim();
  if (!configuredName || !environmentName || configuredName !== environmentName) {
    return false;
  }
  const configuredDocroot = ddevConfigValue(projectRoot, 'docroot').replace(/^\.\//, '').replace(/\/+$/, '');
  const environmentDocroot = String(environment.DDEV_DOCROOT ?? '').trim().replace(/^\.\//, '').replace(/\/+$/, '');
  return Boolean(configuredDocroot && environmentDocroot && configuredDocroot === environmentDocroot);
}

function runDrushResult(projectRoot, environment, args, timeout = 15_000) {
  const inContainer = ddevContainerContext(projectRoot, environment);
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
          timeout
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

const DRUPAL_ENTITY_INVENTORY_SCHEMA = 'public-kit.drupal-entity-inventory.4';
export const DRUPAL_ENTITY_INVENTORY_EVAL = String.raw`
$manager = \Drupal::entityTypeManager();
$definitions = $manager->getDefinitions();
$declared_editorial_roots = isset($declared_editorial_roots) && is_array($declared_editorial_roots)
  ? $declared_editorial_roots
  : [];
$declared_public_fields = isset($declared_public_fields) && is_array($declared_public_fields)
  ? $declared_public_fields
  : [];
$public_route_paths = isset($public_route_paths) && is_array($public_route_paths)
  ? $public_route_paths
  : [];
$normalize = function ($value) use (&$normalize) {
  if (!is_array($value)) {
    return $value;
  }
  if (!array_is_list($value)) {
    ksort($value, SORT_STRING);
  }
  foreach ($value as $key => $child) {
    $value[$key] = $normalize($child);
  }
  return $value;
};
$encode = static function ($value): string {
  $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
  return $encoded === false ? serialize($value) : $encoded;
};
foreach ($declared_editorial_roots as $entity_type_id => $bundles) {
  $bundles = array_values(array_unique(array_map('strval', is_array($bundles) ? $bundles : [])));
  sort($bundles, SORT_STRING);
  $declared_editorial_roots[(string) $entity_type_id] = $bundles;
}
ksort($declared_editorial_roots, SORT_STRING);
foreach ($declared_public_fields as $entity_type_id => $by_bundle) {
  if (!is_array($by_bundle)) {
    unset($declared_public_fields[$entity_type_id]);
    continue;
  }
  foreach ($by_bundle as $bundle => $field_names) {
    $field_names = array_values(array_unique(array_map('strval', is_array($field_names) ? $field_names : [])));
    sort($field_names, SORT_STRING);
    $declared_public_fields[(string) $entity_type_id][(string) $bundle] = $field_names;
  }
  ksort($declared_public_fields[(string) $entity_type_id], SORT_STRING);
}
ksort($declared_public_fields, SORT_STRING);
$public_route_paths = array_values(array_unique(array_filter(array_map('strval', $public_route_paths), static fn ($path): bool => str_starts_with($path, '/'))));
sort($public_route_paths, SORT_STRING);
$infrastructure_type_policy = [
  'menu_link_content' => 'public navigation infrastructure',
  'path_alias' => 'public routing infrastructure',
  'redirect' => 'public redirect infrastructure',
];
$excluded_type_policy = [
  'user' => 'excluded as a broad root; only transitively referenced users are admitted through a privacy-safe display-field projection',
  'file' => 'excluded as a broad root; only transitively referenced managed files are admitted and only public:// bytes are streamed',
  'media' => 'excluded as a broad root; only transitively referenced media are admitted',
  'crop' => 'excluded as a broad root; focal/crop state is admitted only for files already in the public closure',
  'webform_submission' => 'private form submissions',
  'contact_message' => 'private contact submissions',
  'easy_email' => 'private generated email messages',
  'oauth2_token' => 'volatile authentication token',
  'oauth2_refresh_token' => 'volatile authentication token',
  'oauth2_auth_code' => 'volatile authentication token',
  'simple_oauth_token' => 'volatile authentication token',
  'simple_oauth_refresh_token' => 'volatile authentication token',
  'simple_oauth_auth_code' => 'volatile authentication token',
  'search_api_task' => 'derived search indexing task',
  'content_moderation_state' => 'derived revision moderation state',
  'workspace' => 'private derived workspace state',
  'workspace_association' => 'derived workspace association',
  'commerce_order' => 'private customer transaction data',
  'commerce_order_item' => 'private customer transaction data',
  'commerce_payment' => 'private payment data',
  'commerce_payment_method' => 'private payment credentials and customer data',
  'commerce_log' => 'private transaction audit data',
  'consumer' => 'private API consumer credentials and identity data',
];
$queue = [];
$roles = [];
$processed = [];
$declared_root_keys = [];
$enqueue = function (string $entity_type_id, $entity_id, string $role) use (&$enqueue, &$queue, &$roles, $definitions): void {
  $entity_id = (string) $entity_id;
  if ($entity_id === '' || !isset($definitions[$entity_type_id]) || !($definitions[$entity_type_id] instanceof \Drupal\Core\Entity\ContentEntityTypeInterface)) {
    return;
  }
  $key = $entity_type_id . ':' . $entity_id;
  $roles[$key][$role] = TRUE;
  if (!isset($queue[$key])) {
    $queue[$key] = ['entityType' => $entity_type_id, 'id' => $entity_id];
  }
};
$missing_declared_roots = [];
$bundle_info = \Drupal::service('entity_type.bundle.info');
foreach ($declared_editorial_roots as $entity_type_id => $bundles) {
  if (!isset($definitions[$entity_type_id]) || !($definitions[$entity_type_id] instanceof \Drupal\Core\Entity\ContentEntityTypeInterface)) {
    foreach ($bundles as $bundle) {
      $missing_declared_roots[] = $entity_type_id . '.' . $bundle;
    }
    continue;
  }
  $definition = $definitions[$entity_type_id];
  $available_bundles = $bundle_info->getBundleInfo($entity_type_id);
  $bundle_key = $definition->getKey('bundle');
  foreach ($bundles as $bundle) {
    if (!isset($available_bundles[$bundle])) {
      $missing_declared_roots[] = $entity_type_id . '.' . $bundle;
      continue;
    }
    $query = $manager->getStorage($entity_type_id)->getQuery()->accessCheck(FALSE);
    if ($bundle_key) {
      $query->condition($bundle_key, $bundle);
    }
    $ids = array_map('strval', array_values($query->execute()));
    sort($ids, SORT_STRING);
    foreach ($ids as $id) {
      $key = $entity_type_id . ':' . $id;
      $declared_root_keys[$key] = TRUE;
      $enqueue($entity_type_id, $id, 'declared-output-root');
    }
  }
}
sort($missing_declared_roots, SORT_STRING);
$entity_backed_route_count = 0;
$infrastructure_route_count = 0;
foreach ($public_route_paths as $route_path) {
  $route_entities = [];
  try {
    $parameters = \Drupal::service('router.no_access_checks')->match($route_path);
    foreach ($parameters as $parameter) {
      if ($parameter instanceof \Drupal\Core\Entity\EntityInterface) {
        $route_entities[$parameter->getEntityTypeId() . ':' . $parameter->id()] = $parameter;
      }
    }
  }
  catch (\Throwable) {
    // A View or other non-entity route remains covered by HTTP semantics and
    // active configuration; it is counted as route infrastructure below.
  }
  if (count($route_entities) === 0 && isset($definitions['path_alias'])) {
    try {
      $internal_path = (string) \Drupal::service('path_alias.manager')->getPathByAlias($route_path);
      if (preg_match('#^/([a-z][a-z0-9_]*)/([^/]+)$#', $internal_path, $match) && isset($definitions[$match[1]])) {
        $entity = $manager->getStorage($match[1])->load($match[2]);
        if ($entity instanceof \Drupal\Core\Entity\EntityInterface) {
          $route_entities[$entity->getEntityTypeId() . ':' . $entity->id()] = $entity;
        }
      }
    }
    catch (\Throwable) {
      // Continue as a non-entity route.
    }
  }
  if (count($route_entities) > 0) {
    $entity_backed_route_count++;
    foreach ($route_entities as $entity) {
      $enqueue($entity->getEntityTypeId(), $entity->id(), 'route-composition-root');
    }
  }
  else {
    $infrastructure_route_count++;
  }
}
foreach ($infrastructure_type_policy as $entity_type_id => $description) {
  if (!isset($definitions[$entity_type_id]) || !($definitions[$entity_type_id] instanceof \Drupal\Core\Entity\ContentEntityTypeInterface)) {
    continue;
  }
  $definition = $definitions[$entity_type_id];
  $query = $manager->getStorage($entity_type_id)->getQuery()->accessCheck(FALSE);
  $status_key = $definition->getKey('status');
  if ($status_key) {
    $query->condition($status_key, TRUE);
  }
  $ids = array_map('strval', array_values($query->execute()));
  sort($ids, SORT_STRING);
  foreach ($ids as $id) {
    $enqueue($entity_type_id, $id, 'route-navigation-infrastructure');
  }
}
$privacy_safe_user_values = function ($translation) use ($normalize): array {
  $safe = [];
  $base_fields = ['name', 'status', 'user_picture', 'langcode'];
  foreach ($translation->toArray() as $field_name => $field_value) {
    $base_allowed = in_array($field_name, $base_fields, TRUE);
    $custom_allowed = str_starts_with($field_name, 'field_') &&
      !preg_match('/(?:pass|password|mail|email|phone|address|token|secret|auth|login|access|init|session|ip|key|hash|salt)/i', $field_name);
    if ($base_allowed || $custom_allowed) {
      $safe[$field_name] = $normalize($field_value);
    }
  }
  ksort($safe, SORT_STRING);
  return $safe;
};
$entity_record = function ($entity, string $entity_type_id, string $kind) use ($normalize, $encode, $privacy_safe_user_values): array {
  $languages = method_exists($entity, 'getTranslationLanguages')
    ? array_keys($entity->getTranslationLanguages(TRUE))
    : [(string) $entity->language()->getId()];
  sort($languages, SORT_STRING);
  $translations = [];
  foreach ($languages as $langcode) {
    $translation = method_exists($entity, 'hasTranslation') && $entity->hasTranslation($langcode)
      ? $entity->getTranslation($langcode)
      : $entity;
    $values = $entity_type_id === 'user'
      ? $privacy_safe_user_values($translation)
      : $normalize($translation->toArray());
    $translations[(string) $langcode] = 'sha256:' . hash('sha256', $encode($values));
  }
  ksort($translations, SORT_STRING);
  $record = [
    'kind' => $kind,
    'id' => (string) $entity->id(),
    'uuid' => method_exists($entity, 'uuid') ? (string) $entity->uuid() : '',
    'bundle' => method_exists($entity, 'bundle') ? (string) $entity->bundle() : '',
    'revisionId' => method_exists($entity, 'getRevisionId') ? (string) ($entity->getRevisionId() ?? '') : '',
    'translations' => $translations,
  ];
  $missing_managed_files = 0;
  if ($entity_type_id === 'file' && method_exists($entity, 'getFileUri')) {
    $uri = (string) $entity->getFileUri();
    $scheme = (string) (\Drupal\Core\StreamWrapper\StreamWrapperManager::getScheme($uri) ?? '');
    $metadata = [
      'scheme' => $scheme,
      'filename' => method_exists($entity, 'getFilename') ? (string) $entity->getFilename() : '',
      'mime' => method_exists($entity, 'getMimeType') ? (string) $entity->getMimeType() : '',
      'declaredSize' => method_exists($entity, 'getSize') ? (int) $entity->getSize() : 0,
      'status' => method_exists($entity, 'isPermanent') ? (bool) $entity->isPermanent() : NULL,
    ];
    $record['managed_file'] = [
      'scheme' => $scheme,
      'metadataSha256' => 'sha256:' . hash('sha256', $encode($normalize($metadata))),
      'publicBytesHashed' => FALSE,
    ];
    if ($scheme === 'public') {
      $handle = @fopen($uri, 'rb');
      if (is_resource($handle)) {
        $byte_context = hash_init('sha256');
        $bytes_read = hash_update_stream($byte_context, $handle);
        fclose($handle);
        $record['managed_file']['publicBytesHashed'] = TRUE;
        $record['managed_file']['streamedSize'] = $bytes_read;
        $record['managed_file']['sha256'] = 'sha256:' . hash_final($byte_context);
      }
      else {
        $record['managed_file']['sha256'] = '';
        $missing_managed_files = 1;
      }
    }
  }
  return [
    'encoded' => $encode($record),
    'translationCount' => count($translations),
    'missingManagedFileCount' => $missing_managed_files,
  ];
};
$variant_digests = [];
$type_metrics = [];
$missing_managed_file_count = 0;
while (count($queue) > 0) {
  ksort($queue, SORT_STRING);
  $first = reset($queue);
  $batch_type = $first['entityType'];
  $batch = [];
  foreach ($queue as $key => $queued) {
    if ($queued['entityType'] === $batch_type && count($batch) < 100) {
      $batch[$key] = $queued;
      unset($queue[$key]);
    }
  }
  $ids = array_values(array_map(static fn ($queued): string => $queued['id'], $batch));
  sort($ids, SORT_STRING);
  $definition = $definitions[$batch_type];
  $storage = $manager->getStorage($batch_type);
  $entities = $storage->loadMultiple($ids);
  $entities_by_id = [];
  foreach ($entities as $entity) {
    $entities_by_id[(string) $entity->id()] = $entity;
  }
  $latest_non_default_revisions = [];
  if ($definition->isRevisionable() && method_exists($storage, 'loadMultipleRevisions')) {
    $id_key = $definition->getKey('id');
    $revision_key = $definition->getKey('revision');
    $revision_table = $definition->getRevisionTable();
    $revision_default_key = $definition->getRevisionMetadataKey('revision_default');
    if ($id_key && $revision_key && $revision_table) {
      $query = \Drupal::database()->select($revision_table, 'revision');
      $query->fields('revision', [$id_key, $revision_key]);
      $query->condition($id_key, $ids, 'IN');
      if ($revision_default_key) {
        $query->condition($revision_default_key, 0);
      }
      $query->orderBy($revision_key, 'DESC');
      $revision_ids_by_entity = [];
      foreach ($query->execute() as $row) {
        $entity_id = (string) $row->{$id_key};
        $revision_id = (string) $row->{$revision_key};
        $current_revision_id = isset($entities_by_id[$entity_id]) && method_exists($entities_by_id[$entity_id], 'getRevisionId')
          ? (string) ($entities_by_id[$entity_id]->getRevisionId() ?? '')
          : '';
        if (!isset($revision_ids_by_entity[$entity_id]) && $revision_id !== $current_revision_id) {
          $revision_ids_by_entity[$entity_id] = $revision_id;
        }
      }
      if (count($revision_ids_by_entity) > 0) {
        $loaded_revisions = $storage->loadMultipleRevisions(array_values($revision_ids_by_entity));
        foreach ($loaded_revisions as $revision) {
          $latest_non_default_revisions[(string) $revision->id()] = $revision;
        }
      }
    }
  }
  foreach ($ids as $entity_id) {
    $key = $batch_type . ':' . $entity_id;
    if (isset($processed[$key])) {
      continue;
    }
    $processed[$key] = TRUE;
    if (!isset($entities_by_id[$entity_id])) {
      continue;
    }
    $entity = $entities_by_id[$entity_id];
    $variants = [['kind' => 'current-default', 'entity' => $entity]];
    if (isset($latest_non_default_revisions[$entity_id])) {
      $variants[] = ['kind' => 'latest-non-default', 'entity' => $latest_non_default_revisions[$entity_id]];
    }
    $variant_digests[$batch_type][$entity_id] = [];
    foreach ($variants as $variant) {
      $record = $entity_record($variant['entity'], $batch_type, $variant['kind']);
      $variant_digests[$batch_type][$entity_id][] = 'sha256:' . hash('sha256', $record['encoded']);
      $type_metrics[$batch_type]['translationCount'] = ($type_metrics[$batch_type]['translationCount'] ?? 0) + $record['translationCount'];
      if ($variant['kind'] === 'latest-non-default') {
        $type_metrics[$batch_type]['revisionCount'] = ($type_metrics[$batch_type]['revisionCount'] ?? 0) + 1;
        $type_metrics[$batch_type]['revisionTranslationCount'] = ($type_metrics[$batch_type]['revisionTranslationCount'] ?? 0) + $record['translationCount'];
      }
      $type_metrics[$batch_type]['missingManagedFileCount'] = ($type_metrics[$batch_type]['missingManagedFileCount'] ?? 0) + $record['missingManagedFileCount'];
      $missing_managed_file_count += $record['missingManagedFileCount'];
      $variant_entity = $variant['entity'];
      $languages = method_exists($variant_entity, 'getTranslationLanguages')
        ? array_keys($variant_entity->getTranslationLanguages(TRUE))
        : [(string) $variant_entity->language()->getId()];
      foreach ($languages as $langcode) {
        $translation = method_exists($variant_entity, 'hasTranslation') && $variant_entity->hasTranslation($langcode)
          ? $variant_entity->getTranslation($langcode)
          : $variant_entity;
        $bundle = method_exists($translation, 'bundle') ? (string) $translation->bundle() : '';
        $declared_fields = $declared_public_fields[$batch_type][$bundle] ?? [];
        foreach ($translation->getFieldDefinitions() as $field_name => $field_definition) {
          $field_type = (string) $field_definition->getType();
          if (!in_array($field_type, ['entity_reference', 'entity_reference_revisions', 'file', 'image'], TRUE) || !$translation->hasField($field_name)) {
            continue;
          }
          $is_declared_root = isset($declared_root_keys[$key]);
          $field_is_public = in_array($field_name, $declared_fields, TRUE);
          $transitive_field = str_starts_with($field_name, 'field_') || $field_name === 'user_picture';
          if (($is_declared_root && !$field_is_public) || (!$is_declared_root && !$transitive_field)) {
            continue;
          }
          $target_type = in_array($field_type, ['file', 'image'], TRUE)
            ? 'file'
            : (string) ($field_definition->getSetting('target_type') ?? '');
          if ($target_type === 'user' && !$field_is_public && $field_name !== 'user_picture') {
            continue;
          }
          try {
            foreach ($translation->get($field_name)->referencedEntities() as $referenced_entity) {
              if ($referenced_entity instanceof \Drupal\Core\Entity\ContentEntityInterface) {
                $enqueue($referenced_entity->getEntityTypeId(), $referenced_entity->id(), 'transitive-public-reference');
              }
            }
          }
          catch (\Throwable) {
            // A broken reference remains represented in the source field value
            // digest and does not broaden the closure speculatively.
          }
        }
      }
    }
    if ($batch_type === 'file' && isset($definitions['crop'])) {
      try {
        $crop_ids = $manager->getStorage('crop')->getQuery()
          ->accessCheck(FALSE)
          ->condition('entity_type', 'file')
          ->condition('entity_id', $entity_id)
          ->execute();
        foreach ($crop_ids as $crop_id) {
          $enqueue('crop', $crop_id, 'referenced-file-presentation-state');
        }
      }
      catch (\Throwable) {
        // Sites without compatible Crop storage simply have no crop closure.
      }
    }
  }
  unset($entities, $entities_by_id, $latest_non_default_revisions);
}
$types = [];
ksort($variant_digests, SORT_STRING);
foreach ($variant_digests as $entity_type_id => $by_entity) {
  ksort($by_entity, SORT_STRING);
  $context = hash_init('sha256');
  foreach ($by_entity as $entity_id => $digests) {
    $encoded = $encode(['id' => (string) $entity_id, 'variants' => $digests]);
    hash_update($context, pack('N', strlen($encoded)) . $encoded);
  }
  $metrics = $type_metrics[$entity_type_id] ?? [];
  $types[$entity_type_id] = [
    'count' => count($by_entity),
    'translationCount' => (int) ($metrics['translationCount'] ?? 0),
    'revisionCount' => (int) ($metrics['revisionCount'] ?? 0),
    'revisionTranslationCount' => (int) ($metrics['revisionTranslationCount'] ?? 0),
    'missingManagedFileCount' => (int) ($metrics['missingManagedFileCount'] ?? 0),
    'fingerprint' => 'sha256:' . hash_final($context),
  ];
}
ksort($types, SORT_STRING);
$role_counts = [
  'declaredOutputRootCount' => 0,
  'routeCompositionRootCount' => 0,
  'routeNavigationInfrastructureCount' => 0,
  'transitivePublicReferenceCount' => 0,
  'referencedFilePresentationStateCount' => 0,
];
foreach ($roles as $entity_roles) {
  foreach (array_keys($entity_roles) as $role) {
    $role_key = match ($role) {
      'declared-output-root' => 'declaredOutputRootCount',
      'route-composition-root' => 'routeCompositionRootCount',
      'route-navigation-infrastructure' => 'routeNavigationInfrastructureCount',
      'transitive-public-reference' => 'transitivePublicReferenceCount',
      'referenced-file-presentation-state' => 'referencedFilePresentationStateCount',
      default => '',
    };
    if ($role_key !== '') {
      $role_counts[$role_key]++;
    }
  }
}
$public_author_user_digest = [
  'count' => (int) ($types['user']['count'] ?? 0),
  'translationCount' => (int) ($types['user']['translationCount'] ?? 0),
  'fingerprint' => (string) ($types['user']['fingerprint'] ?? ('sha256:' . hash('sha256', ''))),
  'includedBaseFields' => ['name', 'status', 'user_picture', 'langcode'],
  'customFieldPolicy' => 'Referenced users only; field_* values are hashed unless the machine name signals authentication or private contact data.',
];
$policy = [
  'batchSize' => 100,
  'inclusion' => 'Public reference closure rooted in every entity from declared anonymous-output bundles (including unpublished/draft instances), entity-backed verified routes/compositions, and public route/navigation infrastructure.',
  'declaredEditorialRoots' => $declared_editorial_roots,
  'declaredPublicReferenceFields' => $declared_public_fields,
  'routePathCount' => count($public_route_paths),
  'entityBackedRouteCount' => $entity_backed_route_count,
  'infrastructureRouteCount' => $infrastructure_route_count,
  'infrastructureEntityTypes' => array_keys($infrastructure_type_policy),
  'references' => 'entity_reference, entity_reference_revisions, file, and image fields are followed transitively; broad media, file, user, taxonomy, paragraph, and reusable-content tables are never swept.',
  'revisions' => 'Current default plus only the latest non-default revision and every available translation are included for each entity in the closure.',
  'managedFiles' => 'Only referenced files count. public:// bytes are streamed into the digest; other schemes contribute privacy-safe metadata only and are never byte-read.',
  'cropAndFocalPresentation' => 'Crop entities are included only when they describe a referenced file, preserving focal/crop presentation state without sweeping unrelated crops.',
  'publicAuthorUsers' => 'Only explicitly referenced users count; raw user entities are projected to privacy-safe public display fields, and base owner/revision-user fields do not broaden the closure.',
  'rawPerItemRowsEmitted' => FALSE,
];
$closure_counts = ['entityCount' => count($processed), 'entityTypeCount' => count($types)] + $role_counts;
$fingerprint_input = [
  'closureCounts' => $closure_counts,
  'excludedEntityTypes' => $excluded_type_policy,
  'missingDeclaredRoots' => $missing_declared_roots,
  'policy' => $policy,
  'publicAuthorUserDigest' => $public_author_user_digest,
  'types' => $types,
];
print json_encode([
  'schemaVersion' => 'public-kit.drupal-entity-inventory.4',
  'fingerprint' => 'sha256:' . hash('sha256', $encode($fingerprint_input)),
  'entityTypeCount' => count($types),
  'closureCounts' => $closure_counts,
  'excludedEntityTypes' => $excluded_type_policy,
  'missingDeclaredRoots' => $missing_declared_roots,
  'missingManagedFileCount' => $missing_managed_file_count,
  'policy' => $policy,
  'publicAuthorUserDigest' => $public_author_user_digest,
  'types' => $types,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;
const DRUPAL_RUNTIME_FACTS_SCHEMA = 'public-kit.drupal-runtime-facts.2';
export const DRUPAL_RUNTIME_FACTS_EVAL = String.raw`
$normalize = function ($value) use (&$normalize) {
  if (is_array($value)) {
    if (!array_is_list($value)) {
      ksort($value, SORT_STRING);
    }
    foreach ($value as $key => $child) {
      $value[$key] = $normalize($child);
    }
    return $value;
  }
  if (is_object($value)) {
    return [
      '__class' => get_class($value),
      '__properties' => $normalize(get_object_vars($value)),
    ];
  }
  if (is_resource($value)) {
    return ['__resource' => get_resource_type($value)];
  }
  return $value;
};
$system_schema = \Drupal::keyValue('system.schema')->getAll();
ksort($system_schema, SORT_STRING);
$encoded_schema = json_encode($normalize($system_schema), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
$settings = $normalize(\Drupal\Core\Site\Settings::getAll());
$encoded_settings = json_encode($settings, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
$hash_salt = (string) \Drupal\Core\Site\Settings::getHashSalt();
$config_factory = \Drupal::configFactory();
$config_names = $config_factory->listAll();
sort($config_names, SORT_STRING);
$active_config_context = hash_init('sha256');
foreach ($config_names as $config_name) {
  $config = $config_factory->get($config_name);
  $record = [
    'name' => (string) $config_name,
    'raw' => $normalize($config->getRawData()),
    'effective' => $normalize($config->get()),
  ];
  $encoded_record = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
  $encoded_record = $encoded_record === false ? serialize($record) : $encoded_record;
  hash_update($active_config_context, pack('N', strlen($encoded_record)) . $encoded_record);
}
$pending_update_count = 0;
$database_update_status_confirmed = FALSE;
try {
  \Drupal::moduleHandler()->loadAllIncludes('install');
  $update_hook_registry = \Drupal::service('update.update_hook_registry');
  foreach (array_keys(\Drupal::moduleHandler()->getModuleList()) as $module_name) {
    $installed_version = $update_hook_registry->getInstalledVersion($module_name);
    foreach ($update_hook_registry->getAvailableUpdates($module_name) as $available_update) {
      if ($available_update > $installed_version) {
        $pending_update_count++;
      }
    }
  }
  $pending_update_count += count(\Drupal::service('update.post_update_registry')->getPendingUpdateFunctions());
  $database_update_status_confirmed = TRUE;
}
catch (\Throwable) {
  $database_update_status_confirmed = FALSE;
}
$config_split_directories = [];
foreach ($config_factory->listAll('config_split.config_split.') as $config_split_name) {
  $split = $config_factory->get($config_split_name)->getRawData();
  foreach (['folder', 'directory'] as $directory_key) {
    $directory = trim((string) ($split[$directory_key] ?? ''));
    if ($directory !== '') {
      $config_split_directories[] = $directory;
    }
  }
}
$config_split_directories = array_values(array_unique($config_split_directories));
sort($config_split_directories, SORT_STRING);
$facts = [
  'coreVersion' => \Drupal::VERSION,
  'phpVersion' => PHP_VERSION,
  'databaseDriver' => (string) \Drupal::database()->driver(),
  'activeConfigEntryCount' => count($config_names),
  'effectiveActiveConfigSha256' => 'sha256:' . hash_final($active_config_context),
  'systemSchemaEntryCount' => count($system_schema),
  'systemSchemaSha256' => 'sha256:' . hash('sha256', $encoded_schema === false ? serialize($system_schema) : $encoded_schema),
  'effectiveSettingsEntryCount' => count($settings),
  'effectiveSettingsHmacSha256' => 'sha256:' . hash_hmac('sha256', $encoded_settings === false ? serialize($settings) : $encoded_settings, $hash_salt),
  'databaseUpdateStatusConfirmed' => $database_update_status_confirmed,
  'pendingDatabaseUpdateCount' => $pending_update_count,
  'databaseUpdatesPending' => $pending_update_count > 0,
  'configSplitDirectories' => $config_split_directories,
];
ksort($facts, SORT_STRING);
$encoded_facts = json_encode($facts, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
print json_encode([
  'schemaVersion' => 'public-kit.drupal-runtime-facts.2',
  'fingerprint' => 'sha256:' . hash('sha256', $encoded_facts === false ? serialize($facts) : $encoded_facts),
] + $facts, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;

function inspectDrupalRuntimeFacts(projectRoot, environment) {
  const result = runDrushResult(
    projectRoot,
    environment,
    ['php:eval', DRUPAL_RUNTIME_FACTS_EVAL],
    30_000
  );
  if (!result.ok || !result.output) {
    return {
      confirmed: false,
      fingerprint: '',
      reason: 'Drupal runtime facts could not be read through Drush.',
      schemaVersion: DRUPAL_RUNTIME_FACTS_SCHEMA
    };
  }
  try {
    const facts = JSON.parse(result.output);
    const confirmed =
      facts?.schemaVersion === DRUPAL_RUNTIME_FACTS_SCHEMA &&
      /^sha256:[a-f0-9]{64}$/.test(String(facts?.fingerprint ?? '')) &&
      /^sha256:[a-f0-9]{64}$/.test(String(facts?.systemSchemaSha256 ?? '')) &&
      /^sha256:[a-f0-9]{64}$/.test(String(facts?.effectiveSettingsHmacSha256 ?? '')) &&
      /^sha256:[a-f0-9]{64}$/.test(String(facts?.effectiveActiveConfigSha256 ?? '')) &&
      facts?.databaseUpdateStatusConfirmed === true &&
      Number.isSafeInteger(Number(facts?.pendingDatabaseUpdateCount)) &&
      Number(facts.pendingDatabaseUpdateCount) >= 0 &&
      Boolean(String(facts?.coreVersion ?? '').trim()) &&
      Boolean(String(facts?.phpVersion ?? '').trim()) &&
      Boolean(String(facts?.databaseDriver ?? '').trim());
    return {
      ...facts,
      confirmed,
      reason: confirmed ? '' : 'Drupal runtime facts were incomplete or malformed.'
    };
  } catch {
    return {
      confirmed: false,
      fingerprint: '',
      reason: 'Drupal runtime facts returned malformed JSON.',
      schemaVersion: DRUPAL_RUNTIME_FACTS_SCHEMA
    };
  }
}

function declaredEditorialRoots(fieldOutputMatrix) {
  const roots = new Map();
  for (const row of Array.isArray(fieldOutputMatrix?.bundles) ? fieldOutputMatrix.bundles : []) {
    const entityType = String(row?.entityType ?? '').trim();
    const bundle = String(row?.bundle ?? '').trim();
    if (!/^[a-z][a-z0-9_]*$/.test(entityType) || !/^[a-z][a-z0-9_]*$/.test(bundle)) {
      continue;
    }
    if (!roots.has(entityType)) {
      roots.set(entityType, new Set());
    }
    roots.get(entityType).add(bundle);
  }
  return Object.fromEntries(
    [...roots.entries()]
      .sort(([left], [right]) => comparePortable(left, right))
      .map(([entityType, bundles]) => [entityType, [...bundles].sort(comparePortable)])
  );
}

function declaredPublicReferenceFields(fieldOutputMatrix) {
  const fields = new Map();
  for (const row of Array.isArray(fieldOutputMatrix?.bundles) ? fieldOutputMatrix.bundles : []) {
    const entityType = String(row?.entityType ?? '').trim();
    const bundle = String(row?.bundle ?? '').trim();
    if (!/^[a-z][a-z0-9_]*$/.test(entityType) || !/^[a-z][a-z0-9_]*$/.test(bundle)) {
      continue;
    }
    const key = `${entityType}:${bundle}`;
    if (!fields.has(key)) {
      fields.set(key, new Set());
    }
    for (const field of Array.isArray(row?.fields) ? row.fields : []) {
      const machineName = String(field?.machineName ?? '').trim();
      const fieldType = String(field?.fieldType ?? '').trim();
      if (
        /^[a-z][a-z0-9_]*$/.test(machineName) &&
        field?.affectsAnonymousOutput === true &&
        (fieldType.startsWith('entity_reference') || ['file', 'image'].includes(fieldType.split(':')[0]))
      ) {
        fields.get(key).add(machineName);
      }
    }
  }
  const result = {};
  for (const [key, names] of [...fields.entries()].sort(([left], [right]) => comparePortable(left, right))) {
    const [entityType, bundle] = key.split(':');
    result[entityType] ??= {};
    result[entityType][bundle] = [...names].sort(comparePortable);
  }
  return result;
}

function publicClosureRoutePaths(routeMatrix, patternMap) {
  const paths = new Set();
  const add = (value) => {
    const path = normalizePath(value);
    if (path.startsWith('/')) {
      paths.add(path);
    }
  };
  for (const route of Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : []) {
    add(route?.targetPath);
  }
  for (const route of Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : []) {
    add(route?.targetPath ?? route?.targetFinalPath);
  }
  for (const route of Array.isArray(routeMatrix?.targetRequiredRoutes) ? routeMatrix.targetRequiredRoutes : []) {
    add(route?.targetPath ?? route?.path);
  }
  for (const route of Array.isArray(patternMap?.compositionModel?.flexibleLandingRoutes)
    ? patternMap.compositionModel.flexibleLandingRoutes
    : []) {
    add(route?.targetRoute);
  }
  for (const route of Array.isArray(patternMap?.pageCompositionOwnership)
    ? patternMap.pageCompositionOwnership
    : []) {
    add(route?.targetRoute ?? route?.sourceRoute);
  }
  return [...paths].sort(comparePortable);
}

function inspectDrupalEntityInventory(projectRoot, environment, fieldOutputMatrix, routeMatrix, patternMap) {
  const roots = Buffer.from(JSON.stringify(declaredEditorialRoots(fieldOutputMatrix)), 'utf8').toString('base64');
  const fields = Buffer.from(JSON.stringify(declaredPublicReferenceFields(fieldOutputMatrix)), 'utf8').toString('base64');
  const routes = Buffer.from(JSON.stringify(publicClosureRoutePaths(routeMatrix, patternMap)), 'utf8').toString('base64');
  const evaluation = [
    `$declared_editorial_roots = json_decode(base64_decode('${roots}', TRUE), TRUE);`,
    `$declared_public_fields = json_decode(base64_decode('${fields}', TRUE), TRUE);`,
    `$public_route_paths = json_decode(base64_decode('${routes}', TRUE), TRUE);`,
    DRUPAL_ENTITY_INVENTORY_EVAL
  ].join('\n');
  const result = runDrushResult(
    projectRoot,
    environment,
    ['php:eval', evaluation],
    120_000
  );
  if (!result.ok || !result.output) {
    return {
      confirmed: false,
      fingerprint: '',
      reason: 'Drupal content-entity inventory could not be read through Drush.',
      schemaVersion: DRUPAL_ENTITY_INVENTORY_SCHEMA,
      types: {}
    };
  }
  try {
    const inventory = JSON.parse(result.output);
    const typeErrors = Object.entries(inventory?.types ?? {})
      .filter(([, value]) => value?.error)
      .map(([entityType]) => entityType);
    const authorDigestError = String(inventory?.publicAuthorUserDigest?.error ?? '');
    const confirmed =
      inventory?.schemaVersion === DRUPAL_ENTITY_INVENTORY_SCHEMA &&
      /^sha256:[a-f0-9]{64}$/.test(String(inventory?.fingerprint ?? '')) &&
      /^sha256:[a-f0-9]{64}$/.test(String(inventory?.publicAuthorUserDigest?.fingerprint ?? '')) &&
      Array.isArray(inventory?.missingDeclaredRoots) &&
      inventory.missingDeclaredRoots.length === 0 &&
      Number(inventory?.missingManagedFileCount ?? 0) === 0 &&
      !authorDigestError &&
      typeErrors.length === 0;
    return {
      ...inventory,
      confirmed,
      reason: confirmed
        ? ''
        : `Drupal entity inventory was incomplete${typeErrors.length ? ` for: ${typeErrors.join(', ')}` : ''}${authorDigestError ? '; public author digest failed' : ''}${Array.isArray(inventory?.missingDeclaredRoots) && inventory.missingDeclaredRoots.length ? `; declared roots were missing: ${inventory.missingDeclaredRoots.join(', ')}` : ''}${Number(inventory?.missingManagedFileCount ?? 0) > 0 ? `; ${inventory.missingManagedFileCount} managed files were unreadable` : ''}.`
    };
  } catch {
    return {
      confirmed: false,
      fingerprint: '',
      reason: 'Drupal content-entity inventory returned malformed JSON.',
      schemaVersion: DRUPAL_ENTITY_INVENTORY_SCHEMA,
      types: {}
    };
  }
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

function safeExistingProjectDirectory(projectRoot, candidate) {
  const root = resolve(projectRoot);
  const path = resolve(candidate);
  if (
    !pathIsInside(root, path) ||
    !existsSync(root) ||
    !existsSync(path) ||
    lstatSync(root).isSymbolicLink() ||
    !statSync(path).isDirectory()
  ) {
    return '';
  }
  let current = path;
  while (current !== root) {
    if (lstatSync(current).isSymbolicLink()) {
      return '';
    }
    const parent = dirname(current);
    if (!pathIsInside(root, parent)) {
      return '';
    }
    current = parent;
  }
  try {
    const realRoot = realpathSync(root);
    const realPath = realpathSync(path);
    return pathIsInside(realRoot, realPath) ? realPath : '';
  } catch {
    return '';
  }
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

function hostConfigSyncPath(projectRoot, configSyncDirectory, drupalRoot) {
  const configured = cleanScalar(configSyncDirectory);
  if (!configured) {
    return '';
  }
  const docroot = ddevDocroot(projectRoot);
  if (!isAbsolute(configured)) {
    const candidate = resolve(projectRoot, docroot, configured);
    return safeExistingProjectDirectory(projectRoot, candidate);
  }
  if (existsSync(configured) && pathIsInside(projectRoot, configured)) {
    return safeExistingProjectDirectory(projectRoot, configured);
  }

  const normalizedDrupalRoot = cleanScalar(drupalRoot).replaceAll('\\', '/').replace(/\/+$/, '');
  const normalizedConfigured = configured.replaceAll('\\', '/');
  const docrootSuffix = `/${docroot.replace(/^\/+|\/+$/g, '')}`;
  const containerProjectRoot = normalizedDrupalRoot.endsWith(docrootSuffix)
    ? normalizedDrupalRoot.slice(0, -docrootSuffix.length)
    : '';
  if (containerProjectRoot && normalizedConfigured.startsWith(`${containerProjectRoot}/`)) {
    const candidate = resolve(projectRoot, normalizedConfigured.slice(containerProjectRoot.length + 1));
    return safeExistingProjectDirectory(projectRoot, candidate);
  }
  return '';
}

function trackedConfigEvidence(projectRoot, configSyncDirectory, drupalRoot, configSplitDirectories = []) {
  const hostPath = hostConfigSyncPath(projectRoot, configSyncDirectory, drupalRoot);
  const splitPaths = [];
  const missingConfigSplitDirectories = [];
  for (const configured of Array.isArray(configSplitDirectories) ? configSplitDirectories : []) {
    const path = hostConfigSyncPath(projectRoot, configured, drupalRoot);
    if (path) {
      splitPaths.push(path);
    } else if (cleanScalar(configured)) {
      missingConfigSplitDirectories.push(cleanScalar(configured));
    }
  }
  if (!hostPath || !existsSync(hostPath) || !statSync(hostPath).isDirectory()) {
    return {
      allYamlFiles: [],
      confirmed: false,
      configManifest: collectFileManifest(projectRoot, []),
      configSplitDirectories: [],
      directory: '',
      missingConfigSplitDirectories,
      untrackedYamlFiles: [],
      yamlFiles: []
    };
  }
  const directory = relative(projectRoot, hostPath).split(sep).join('/');
  const directories = [...new Set([hostPath, ...splitPaths])];
  const relativeDirectories = directories.map((path) => relative(projectRoot, path).split(sep).join('/'));
  try {
    const output = execFileSync('git', ['ls-files', '--', ...relativeDirectories], {
      cwd: projectRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000
    });
    const yamlFiles = output
      .split(/\r?\n/)
      .map((path) => path.trim())
      .filter((path) => /\.ya?ml$/i.test(path) && existsSync(join(projectRoot, path)))
      .sort();
    const allYamlFiles = [];
    const visit = (directoryPath) => {
      for (const entry of readdirSync(directoryPath, { withFileTypes: true })) {
        const path = join(directoryPath, entry.name);
        if (entry.isSymbolicLink() || lstatSync(path).isSymbolicLink()) {
          throw new Error(`Config sync contains a symbolic link: ${relative(projectRoot, path)}.`);
        }
        if (entry.isDirectory()) {
          visit(path);
        } else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
          allYamlFiles.push(relative(projectRoot, path).split(sep).join('/'));
        }
      }
    };
    for (const path of directories) {
      visit(path);
    }
    allYamlFiles.sort(comparePortable);
    const trackedSet = new Set(yamlFiles);
    const untrackedYamlFiles = allYamlFiles.filter((path) => !trackedSet.has(path));
    const configManifest = collectFileManifest(projectRoot, allYamlFiles);
    return {
      allYamlFiles,
      confirmed: yamlFiles.length > 0 && untrackedYamlFiles.length === 0 && missingConfigSplitDirectories.length === 0,
      configManifest,
      configSplitDirectories: relativeDirectories.slice(1),
      directory,
      missingConfigSplitDirectories,
      untrackedYamlFiles,
      yamlFiles
    };
  } catch {
    return {
      allYamlFiles: [],
      confirmed: false,
      configManifest: collectFileManifest(projectRoot, []),
      configSplitDirectories: relativeDirectories.slice(1),
      directory,
      missingConfigSplitDirectories,
      untrackedYamlFiles: [],
      yamlFiles: []
    };
  }
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

function inspectConsentInventory(projectRoot, environment) {
  const php = String.raw`$storage = \Drupal::service('config.storage');
$extension = $storage->read('core.extension') ?: [];
$module_names = array_keys($extension['module'] ?? []);
$manager_modules = array_values(array_filter($module_names, static fn($name) => preg_match('/consent|cookie|privacy|klaro/i', $name)));
$config_names = array_values(array_filter($storage->listAll(), static fn($name) => preg_match('/consent|cookie|privacy|klaro/i', $name)));
$applications = [];
foreach ($config_names as $config_name) {
  $data = $storage->read($config_name) ?: [];
  $is_application = preg_match('/(?:^|\.)(?:application|app|service|integration)(?:\.|$)/i', $config_name) || array_intersect(['required', 'javascripts', 'wrapper_identifier', 'attachments'], array_keys($data));
  if (!$is_application) { continue; }
  $resources = [];
  $walk = function ($value, $key = '') use (&$walk, &$resources) {
    if (is_array($value)) { foreach ($value as $child_key => $child) { $walk($child, $key === '' ? (string) $child_key : $key . '.' . $child_key); } return; }
    if (!is_string($value) || trim($value) === '' || preg_match('/secret|password|token|api[_-]?key/i', $key)) { return; }
    $kinds = ['javascripts' => 'script', 'javascript' => 'script', 'scripts' => 'script', 'wrapper_identifier' => 'selector', 'attachments' => 'attachment', 'iframe' => 'iframe', 'images' => 'image', 'styles' => 'style', 'resources' => 'resource', 'urls' => 'resource', 'domains' => 'resource'];
    $normalized = strtolower(str_replace('-', '_', $key));
    foreach ($kinds as $needle => $kind) { if (str_contains($normalized, $needle)) { $pattern = trim($value); if (preg_match('/^https?:\/\//i', $pattern)) { $pattern = preg_replace('/[?#].*$/', '', $pattern); } $resources[] = ['kind' => $kind, 'pattern' => $pattern]; break; } }
  };
  $walk($data);
  $id = (string) ($data['id'] ?? preg_replace('/^.*\./', '', $config_name));
  $applications[] = ['configName' => $config_name, 'id' => $id, 'enabled' => (bool) ($data['status'] ?? $data['enabled'] ?? TRUE), 'required' => (bool) ($data['required'] ?? FALSE), 'resources' => array_values(array_unique($resources, SORT_REGULAR))];
}
print json_encode(['schemaVersion' => 'public-kit.consent-runtime.1', 'confirmed' => TRUE, 'detected' => (bool) ($manager_modules || $config_names), 'managerModules' => $manager_modules, 'configNames' => $config_names, 'applications' => $applications], JSON_UNESCAPED_SLASHES);`;
  const result = runDrushResult(projectRoot, environment, ['php:eval', php]);
  if (!result.ok) {
    return {
      applications: [],
      configNames: [],
      confirmed: false,
      detected: false,
      managerModules: [],
      reason: 'Drupal consent configuration could not be inspected through Drush.'
    };
  }
  try {
    const parsed = JSON.parse(result.output);
    return {
      applications: Array.isArray(parsed.applications) ? parsed.applications : [],
      configNames: Array.isArray(parsed.configNames) ? parsed.configNames : [],
      confirmed: parsed.confirmed === true,
      detected: parsed.detected === true,
      managerModules: Array.isArray(parsed.managerModules) ? parsed.managerModules : [],
      reason: ''
    };
  } catch {
    return {
      applications: [],
      configNames: [],
      confirmed: false,
      detected: false,
      managerModules: [],
      reason: 'Drupal consent configuration inspection returned invalid JSON.'
    };
  }
}

function inspectDrupalRuntime(cwd, environment, fieldOutputMatrix, routeMatrix, patternMap) {
  const projectRoot = findDrupalDdevRoot(cwd);
  if (!projectRoot) {
    return {
      baseUrl: '',
      confirmed: false,
      configStatusClean: false,
      consentInventory: {
        applications: [], configNames: [], confirmed: false, detected: false, managerModules: [],
        reason: 'Current working directory is not inside a DDEV Drupal project.'
      },
      configSyncTracked: false,
      configSyncDirectory: '',
      configManifest: null,
      configSplitDirectories: [],
      entityInventory: {
        confirmed: false,
        fingerprint: '',
        reason: 'Drupal runtime is unavailable.',
        schemaVersion: DRUPAL_ENTITY_INVENTORY_SCHEMA,
        types: {}
      },
      runtimeFacts: {
        confirmed: false,
        fingerprint: '',
        reason: 'Drupal runtime is unavailable.',
        schemaVersion: DRUPAL_RUNTIME_FACTS_SCHEMA
      },
      frontPage: '',
      mode: 'unavailable',
      reason: 'Current working directory is not inside a DDEV Drupal project.',
      siteUuid: '',
      trackedConfigDirectory: '',
      missingConfigSplitDirectories: [],
      trackedConfigYamlFiles: [],
      untrackedConfigYamlFiles: []
    };
  }
  const inContainer = ddevContainerContext(projectRoot, environment);
  const bootstrap = runDrush(projectRoot, environment, ['status', '--field=bootstrap']);
  const uuidOutput = runDrush(
    projectRoot,
    environment,
    ['config:get', 'system.site', 'uuid', '--format=string']
  );
  const frontPage = cleanScalar(
    runDrush(projectRoot, environment, ['config:get', 'system.site', 'page.front', '--format=string'])
  );
  const configSyncDirectory = cleanScalar(
    runDrush(projectRoot, environment, ['status', '--field=config-sync'])
  );
  const drupalRoot = cleanScalar(runDrush(projectRoot, environment, ['status', '--field=root']));
  const configStatus = runDrushResult(projectRoot, environment, ['config:status', '--format=json']);
  const runtimeFacts = inspectDrupalRuntimeFacts(projectRoot, environment);
  const trackedConfig = trackedConfigEvidence(
    projectRoot,
    configSyncDirectory,
    drupalRoot,
    runtimeFacts?.configSplitDirectories
  );
  const entityInventory = inspectDrupalEntityInventory(
    projectRoot,
    environment,
    fieldOutputMatrix,
    routeMatrix,
    patternMap
  );
  const consentInventory = inspectConsentInventory(projectRoot, environment);
  const siteUuid = uuidOutput.match(UUID_RE)?.[0]?.toLowerCase() ?? '';
  const confirmed = /successful/i.test(bootstrap) && Boolean(siteUuid);
  const baseUrl = inContainer ? environmentTargetUrl(environment) : ddevTargetUrl(projectRoot, environment);
  return {
    baseUrl,
    confirmed,
    configStatusClean: configStatusIsClean(configStatus),
    consentInventory,
    configSyncTracked: trackedConfig.confirmed,
    configSyncDirectory,
    configManifest: trackedConfig.configManifest,
    configSplitDirectories: trackedConfig.configSplitDirectories,
    drupalRoot,
    entityInventory,
    runtimeFacts,
    frontPage,
    mode: inContainer ? 'ddev-container' : 'ddev-host',
    project: basename(projectRoot),
    reason: confirmed ? '' : 'Drupal did not bootstrap or expose a valid system.site UUID through Drush.',
    siteUuid,
    trackedConfigDirectory: trackedConfig.directory,
    missingConfigSplitDirectories: trackedConfig.missingConfigSplitDirectories,
    trackedConfigYamlFiles: trackedConfig.yamlFiles,
    untrackedConfigYamlFiles: trackedConfig.untrackedYamlFiles
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
  const projectRoot = findDrupalDdevRoot(cwd);
  const inContainer = Boolean(projectRoot && ddevContainerContext(projectRoot, environment));
  const choices = [
    ['explicit', explicitTargetUrl],
    ['ddev-environment', inContainer ? environmentTargetUrl(environment) : ''],
    ['ddev-describe', inContainer ? '' : ddevTargetUrl(projectRoot || cwd, environment)]
  ];
  const [source, value] = choices.find(([, candidate]) => String(candidate ?? '').trim()) ?? [];
  if (!value) {
    throw new Error('No live target URL found. Pass --target-url or run from the intended DDEV project.');
  }
  return { source, url: parseHttpUrl(value, 'Live target URL') };
}

function matchingRouteRecord(routeMatrix, targetPath) {
  return (Array.isArray(routeMatrix.routes) ? routeMatrix.routes : []).find(
    (route) => normalizeRouteKey(route?.targetPath) === targetPath
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
    .filter((check) => [check?.targetUrl, check?.targetFinalUrl].some((url) => normalizeRouteKey(url) === targetPath))
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
  const targetPath = normalizeRouteKey(primaryRoute?.targetPath || primaryRoute?.sourcePath);
  const record = matchingRouteRecord(routeMatrix, targetPath) ?? {};
  const homepage = targetPath === '/' ? routeMatrix.homepageParity ?? {} : {};
  const declaredStatus = record.targetStatus;
  const expectedStatus = declaredStatus !== null && declaredStatus !== '' && Number.isFinite(Number(declaredStatus))
    ? Number(declaredStatus)
    : 200;
  return {
    accepted: primaryRoute?.accepted === true,
    expectedBehavior: record.expectedRedirect === true ? 'redirect' : 'public_200',
    expectedFinalPath: normalizeRouteKey(record.targetFinalPath || homepage.targetFinalPath || targetPath),
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
  const targetPath = normalizeRouteKey(record?.targetPath);
  return {
    accepted: record?.accepted === true,
    expectedBehavior: String(record?.expectedPublicBehavior ?? ''),
    expectedFinalPath: normalizeRouteKey(record?.targetFinalPath || targetPath),
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
  negativeRouteConsent,
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
  requiredOriginMatch(errors, 'negative-route-consent.json site', negativeRouteConsent?.site, targetOrigin);
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
  const requestedUrl = new URL(expected.targetPath, new URL('/', baseUrl));
  requestedUrl.hash = '';
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
    const intrinsicSemantics = intrinsicRouteSemantics(response.body, response.finalUrl);
    const actualStatus = expected.statusUsesInitialResponse ? response.initialStatus : response.status;
    if (actualStatus !== expected.expectedStatus) {
      errors.push(`${expected.targetPath} returned status ${actualStatus}; expected ${expected.expectedStatus}.`);
    }
    if (normalizeRouteKey(response.finalUrl) !== expected.expectedFinalPath) {
      errors.push(
        `${expected.targetPath} resolved to ${normalizeRouteKey(response.finalUrl)}; expected ${expected.expectedFinalPath}.`
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
      intrinsicSemantics,
      errors,
      finalStatus: response.status,
      finalUrl: response.finalUrl,
      initialStatus: response.initialStatus,
      localTlsVerificationBypassed: response.localTlsVerificationBypassed,
      passed: errors.length === 0,
      redirects: response.redirects,
      renderedLegalLinks: renderedLegalLinks(response.body, response.finalUrl),
      renderedResourceUrls: renderedResourceUrls(response.body, response.finalUrl),
      requestedUrl: requestedUrl.href
    };
  } catch (error) {
    errors.push(`${expected.targetPath} could not be fetched: ${error.message}`);
    return { ...expected, errors, passed: false, requestedUrl: requestedUrl.href };
  }
}

async function verifyGeneratedMissingRoute(baseUrl, policy) {
  const path = `/.well-known/agent-ready-missing-${randomBytes(16).toString('hex')}`;
  const requestedUrl = new URL(path, baseUrl);
  const errors = [];
  try {
    const response = await requestOnce(requestedUrl);
    const metadata = renderedMetadata(response.body, requestedUrl.href);
    const title = elementText(response.body, 'title');
    const h1 = elementText(response.body, 'h1');
    if (response.status !== 404) {
      errors.push(`${path} returned HTTP ${response.status}; a generated missing route must return exactly 404 without redirecting.`);
    }
    if (!title || !h1) {
      errors.push(`${path} must render a non-empty title and H1 on the 404 response.`);
    }
    if (metadata.canonicalCount > 1) {
      errors.push(`${path} rendered multiple canonicals; a missing route canonical must be absent or self-referential.`);
    } else if (metadata.canonicalCount === 1 && metadata.canonicalUrl !== requestedUrl.href) {
      errors.push(`${path} rendered canonical ${JSON.stringify(metadata.canonicalUrl)} instead of itself.`);
    }
    if (policy?.noindexPolicy === 'required' && !metadata.noindex) {
      errors.push(`${path} did not render the required noindex directive.`);
    }
    return {
      actualH1: h1,
      actualMetadata: metadata,
      actualTitle: title,
      bodySha256: `sha256:${sha256(response.body)}`,
      errors,
      passed: errors.length === 0,
      path,
      requestedUrl: requestedUrl.href,
      status: response.status
    };
  } catch (error) {
    errors.push(`${path} could not be fetched: ${error.message}`);
    return { errors, passed: false, path, requestedUrl: requestedUrl.href };
  }
}

async function verifyAccessWallRoute(baseUrl, declaration) {
  const path = normalizePath(declaration?.path);
  const requestedUrl = new URL(path.replace(/^\//, ''), new URL('/', baseUrl));
  const errors = [];
  try {
    if (declaration?.expectedBehavior === 'external_auth') {
      const response = await requestOnce(requestedUrl);
      const location = response.headers.location;
      const destination = location ? new URL(location, requestedUrl) : null;
      const expectedOrigin = parseHttpUrl(
        declaration?.externalAuthDisposition?.expectedOrigin,
        `${path} external authentication origin`
      ).origin;
      if (!REDIRECT_STATUSES.has(response.status) || destination?.origin !== expectedOrigin) {
        errors.push(`${path} did not redirect to the declared external authentication origin ${expectedOrigin}.`);
      }
      const metadata = renderedMetadata(response.body, requestedUrl.href);
      if (metadata.canonicalCount > 1 || (metadata.canonicalCount === 1 && metadata.canonicalUrl !== requestedUrl.href)) {
        errors.push(`${path} rendered an unrelated public canonical on its access-wall response.`);
      }
      return {
        actualMetadata: metadata,
        errors,
        finalUrl: destination?.href ?? requestedUrl.href,
        passed: errors.length === 0,
        path,
        requestedUrl: requestedUrl.href,
        status: response.status
      };
    }
    const response = await requestFollowingRedirects(requestedUrl);
    const metadata = renderedMetadata(response.body, response.finalUrl);
    const expectedBehavior = declaration?.expectedBehavior;
    if (normalizePath(response.finalUrl) !== path) {
      errors.push(`${path} resolved to unrelated access-wall path ${normalizePath(response.finalUrl)}.`);
    }
    if (expectedBehavior === 'available' && (response.status < 200 || response.status >= 300)) {
      errors.push(`${path} should be available but ended with HTTP ${response.status}.`);
    } else if (expectedBehavior === 'denied' && ![401, 403].includes(response.status)) {
      errors.push(`${path} should deny anonymous access with 401 or 403 but ended with HTTP ${response.status}.`);
    } else if (expectedBehavior === 'disabled' && ![404, 410].includes(response.status)) {
      errors.push(`${path} should be disabled with 404 or 410 but ended with HTTP ${response.status}.`);
    }
    if (metadata.canonicalCount > 1) {
      errors.push(`${path} rendered multiple public canonicals.`);
    } else if (metadata.canonicalCount === 1) {
      const canonical = new URL(metadata.canonicalUrl);
      const final = new URL(response.finalUrl);
      if (canonical.origin !== baseUrl.origin || normalizePath(canonical.href) !== normalizePath(final.href)) {
        errors.push(`${path} rendered unrelated canonical ${metadata.canonicalUrl} on its access-wall response.`);
      }
    }
    return {
      actualMetadata: metadata,
      errors,
      finalUrl: response.finalUrl,
      passed: errors.length === 0,
      path,
      requestedUrl: requestedUrl.href,
      status: response.status
    };
  } catch (error) {
    errors.push(`${path || '(missing access-wall route)'} could not be verified: ${error.message}`);
    return { errors, passed: false, path, requestedUrl: requestedUrl.href };
  }
}

async function verifyRenderedLegalLinks(baseUrl, routeChecks, declaration) {
  const rendered = [...routeChecks.flatMap((route) => route.renderedLegalLinks ?? [])];
  const activeRequirements = (Array.isArray(declaration?.requirements) ? declaration.requirements : [])
    .filter((requirement) => requirement?.status === 'active')
    .map((requirement) => ({ sourceUrl: 'negative-route-consent.json', text: '', url: new URL(normalizePath(requirement.path).replace(/^\//, ''), new URL('/', baseUrl)).href }));
  const candidates = [...rendered, ...activeRequirements];
  const unique = [...new Map(candidates.map((link) => [link.url, link])).values()];
  return Promise.all(unique.map(async (link) => {
    const errors = [];
    try {
      const response = await requestFollowingRedirects(new URL(link.url));
      if (new URL(response.finalUrl).origin !== baseUrl.origin || response.status < 200 || response.status >= 300) {
        errors.push(`Rendered or active legal/privacy link ${link.url} ended at ${response.finalUrl} with HTTP ${response.status}; it cannot be treated as not applicable.`);
      }
      return { ...link, errors, finalUrl: response.finalUrl, passed: errors.length === 0, status: response.status };
    } catch (error) {
      errors.push(`Rendered or active legal/privacy link ${link.url} could not be fetched: ${error.message}`);
      return { ...link, errors, passed: false };
    }
  }));
}

function controlledResourceMatches(resource, url) {
  if (['selector', 'attachment'].includes(resource?.kind)) {
    return false;
  }
  const pattern = String(resource?.pattern ?? '').trim();
  if (!pattern) {
    return false;
  }
  if (pattern.startsWith('regex:')) {
    try {
      return new RegExp(pattern.slice('regex:'.length), 'i').test(url);
    } catch {
      return false;
    }
  }
  const normalizedPattern = pattern.replaceAll('*', '').toLowerCase();
  return Boolean(normalizedPattern) && url.toLowerCase().includes(normalizedPattern);
}

function sameStringSet(left, right) {
  const a = [...new Set(left.map((value) => String(value ?? '').trim()).filter(Boolean))].sort();
  const b = [...new Set(right.map((value) => String(value ?? '').trim()).filter(Boolean))].sort();
  return JSON.stringify(a) === JSON.stringify(b);
}

export function consentNetworkCaptureRequired(declaration) {
  if (declaration?.discoveryStatus !== 'installed') return false;
  return (Array.isArray(declaration?.applications) ? declaration.applications : []).some((application) =>
    (application?.enabled !== true || application?.required !== true) &&
    (Array.isArray(application?.controlledResources) ? application.controlledResources : []).some((resource) =>
      !['selector', 'attachment'].includes(resource?.kind) && String(resource?.pattern ?? '').trim()
    )
  );
}

export function verifyConsentReconciliation(
  declaration,
  runtime,
  routeChecks,
  beforeConsentCapture = null,
  { targetOrigin = '', primaryRoutes = [], stateFingerprint = '' } = {}
) {
  const errors = [];
  const discoveryStatus = declaration?.discoveryStatus;
  const runtimeInventory = runtime ?? {
    applications: [], configNames: [], confirmed: false, detected: false, managerModules: []
  };
  if (['installed', 'not_installed'].includes(discoveryStatus) && runtimeInventory.confirmed !== true) {
    errors.push('Active Drupal consent configuration could not be independently inspected.');
  }
  if (runtimeInventory.detected === true && discoveryStatus !== 'installed') {
    errors.push('Drupal consent configuration is active but negative-route-consent.json says it is not installed.');
  }
  if (runtimeInventory.detected !== true && discoveryStatus === 'installed') {
    errors.push('negative-route-consent.json declares installed consent, but active Drupal configuration contains no consent manager.');
  }
  const managers = Array.isArray(declaration?.managers) ? declaration.managers : [];
  const applications = Array.isArray(declaration?.applications) ? declaration.applications : [];
  if (discoveryStatus === 'installed' && runtimeInventory.detected === true) {
    if (!sameStringSet(managers.map((manager) => manager.module), runtimeInventory.managerModules ?? [])) {
      errors.push('Declared consent manager modules do not exactly reconcile with enabled Drupal consent modules.');
    }
    const declaredConfigNames = managers.flatMap((manager) => Array.isArray(manager.configNames) ? manager.configNames : []);
    if (!sameStringSet(declaredConfigNames, runtimeInventory.configNames ?? [])) {
      errors.push('Declared consent config names do not exactly reconcile with active Drupal consent config.');
    }
    for (const runtimeApplication of runtimeInventory.applications ?? []) {
      const declared = applications.find((application) =>
        application.configName === runtimeApplication.configName || application.id === runtimeApplication.id
      );
      if (!declared) {
        errors.push(`Active consent application ${runtimeApplication.configName || runtimeApplication.id} is not declared.`);
        continue;
      }
      if (declared.enabled !== runtimeApplication.enabled || declared.required !== runtimeApplication.required) {
        errors.push(`Consent application ${declared.id} enabled/required state contradicts active Drupal config.`);
      }
      for (const resource of runtimeApplication.resources ?? []) {
        if (!(declared.controlledResources ?? []).some((candidate) =>
          candidate.kind === resource.kind && candidate.pattern === resource.pattern
        )) {
          errors.push(`Consent application ${declared.id} omits active controlled resource ${resource.kind}:${resource.pattern}.`);
        }
      }
    }
    for (const declared of applications) {
      if (!(runtimeInventory.applications ?? []).some((application) =>
        application.configName === declared.configName || application.id === declared.id
      )) {
        errors.push(`Declared consent application ${declared.id} does not exist in active Drupal config.`);
      }
    }
  }

  const serverRenderedUrls = routeChecks.flatMap((route) => route.renderedResourceUrls ?? []);
  const beforeChecks = Array.isArray(declaration?.beforeConsentChecks) ? declaration.beforeConsentChecks : [];
  const authoredBrowserObservedUrls = beforeChecks.flatMap((check) =>
    Array.isArray(check.observedResourceUrls) ? check.observedResourceUrls : []
  );
  // Packet browser transcripts remain diagnostic authored evidence. Only this
  // run's verifier-owned CDP capture may supply browser-observed URLs.
  const networkRequired = consentNetworkCaptureRequired(declaration);
  let authoritativeBeforeConsentCapture = false;
  let browserObservedRequests = [];
  if (networkRequired) {
    try {
      const capture = validateBeforeConsentNetworkCapture(beforeConsentCapture, {
        stateFingerprint,
        targetOrigin,
        primaryRoutes
      });
      authoritativeBeforeConsentCapture = true;
      browserObservedRequests = capture.routes.flatMap((route) =>
        route.requests.map((request) => ({ ...request, route: route.path }))
      );
    } catch (error) {
      errors.push(`G-PRIVACY-01 requires verifier-owned fresh browser/network capture for optional or disabled controlled resources: ${error.message}`);
    }
  }
  const browserObservedUrls = [...new Set(browserObservedRequests.map((request) => request.url))];
  const observedUrls = [...new Set([...serverRenderedUrls, ...browserObservedUrls])];
  for (const application of discoveryStatus === 'installed'
    ? applications.filter((candidate) => String(candidate?.id ?? '').trim())
    : []) {
    const violating = observedUrls.filter((url) =>
      (application.controlledResources ?? []).some((resource) => controlledResourceMatches(resource, url))
    );
    if (violating.length > 0 && (application.enabled !== true || application.required !== true)) {
      const state = application.enabled === true ? 'before consent' : 'while its consent application is disabled';
      errors.push(`Controlled resource for ${application.id} loaded ${state}: ${violating[0]}.`);
    }
  }
  return {
    authoredBrowserObservedUrls,
    authoritativeBeforeConsentCapture,
    beforeConsentCaptureFingerprint: authoritativeBeforeConsentCapture ? beforeConsentCapture.captureFingerprint : '',
    browserObservedRequests,
    browserObservedUrls,
    errors,
    passed: errors.length === 0,
    runtimeInventory,
    serverRenderedUrls
  };
}

export async function verifyLive({
  packetDir = 'review-packet',
  targetUrl = '',
  outPath = '',
  cwd = process.cwd(),
  environment = process.env,
  drupalRuntime = null
} = {}) {
  const absolutePacketDir = resolve(cwd, packetDir);
  assertVerificationPacketInputs(absolutePacketDir);
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
  let negativeRouteConsent = null;
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
    negativeRouteConsent = JSON.parse(
      await readFile(join(absolutePacketDir, 'negative-route-consent.json'), 'utf8')
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
  const inspectedDrupalRuntime = drupalRuntime ?? inspectDrupalRuntime(
    cwd,
    environment,
    fieldOutputMatrix,
    routeMatrix,
    patternMap
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
  let chromeContext = { lifecyclePresent: false, latestVerifiedAnchor: null, contract: null };
  try {
    chromeContext = globalChromeCaptureContext({ packetDir: absolutePacketDir });
  } catch (error) {
    liveErrors.push(`Global chrome lifecycle context could not be read: ${error.message}`);
  }
  const rawGlobalChromeCapture = chromeContext.lifecyclePresent && target && explicitTargetFetchAllowed && runtimeAuthoritativeForCompletion
    ? await captureGlobalChrome({
        baseUrl: target.url,
        primaryRoutes,
        contract: chromeContext.contract ?? browserEvidence?.globalChromeRegression ?? {},
        environment
      })
    : {
        schemaVersion: 'public-kit.global-chrome-capture.1',
        checkedAt: new Date().toISOString(),
        status: 'unavailable',
        authoritative: false,
        captureMode: 'verifier-owned-browser',
        targetOrigin: target?.url?.origin ?? '',
        contract: chromeContext.contract ?? browserEvidence?.globalChromeRegression ?? {},
        browser: { executable: '', product: '' },
        routes: [],
        errors: [chromeContext.lifecyclePresent
          ? 'Verifier-owned browser capture is disabled for an injected or unavailable runtime.'
          : 'No lifecycle baseline exists yet; the next live verifier run will establish the global chrome anchor.']
      };
  const negativeRouteCheck = target && explicitTargetFetchAllowed
    ? await verifyGeneratedMissingRoute(target.url, negativeRouteConsent?.missingRoute)
    : null;
  if (negativeRouteCheck) {
    liveErrors.push(...negativeRouteCheck.errors);
  }
  const accessWallChecks = target && explicitTargetFetchAllowed
    ? await Promise.all((Array.isArray(negativeRouteConsent?.accessWallRoutes)
      ? negativeRouteConsent.accessWallRoutes
      : []).map((route) => verifyAccessWallRoute(target.url, route)))
    : [];
  for (const check of accessWallChecks) {
    liveErrors.push(...check.errors);
  }
  const legalPrivacyLinkChecks = target && explicitTargetFetchAllowed
    ? await verifyRenderedLegalLinks(
        target.url,
        [...routeChecks, ...targetRequiredRouteChecks],
        negativeRouteConsent?.legalPrivacyScope
      )
    : [];
  for (const check of legalPrivacyLinkChecks) {
    liveErrors.push(...check.errors);
  }
  const consentInventory = inspectedDrupalRuntime.consentInventory ?? {
    applications: [],
    configNames: [],
    confirmed: runtimeWasInjected,
    detected: false,
    managerModules: [],
    reason: runtimeWasInjected ? '' : 'Consent inventory is unavailable.'
  };
  const consentNetworkApplicable = consentNetworkCaptureRequired(negativeRouteConsent?.consent);
  const rawBeforeConsentNetworkCapture = consentNetworkApplicable && target && explicitTargetFetchAllowed && runtimeAuthoritativeForCompletion
    ? await captureBeforeConsentNetwork({
        baseUrl: target.url,
        primaryRoutes,
        environment
      })
    : {
        schemaVersion: 'public-kit.before-consent-network-capture.1',
        checkedAt: new Date().toISOString(),
        status: consentNetworkApplicable ? 'unavailable' : 'not_applicable',
        authoritative: false,
        captureMode: 'verifier-owned-cdp-network',
        targetOrigin: target?.url?.origin ?? '',
        browser: { executable: '', product: '' },
        primaryRoutes: primaryRoutes.map((route) => String(route?.targetPath ?? route)),
        routes: [],
        errors: consentNetworkApplicable
          ? ['Verifier-owned before-consent capture is disabled for an injected or unavailable Drupal runtime.']
          : []
      };

  const packetSupportsCompletion = packetReport.completionEvidence?.packetSupportsCompletion === true;
  const packetClaimsQualifyingReview =
    independentVerification?.summary?.verdict === 'pass' ||
    ['good', 'good_enough'].includes(blindReview?.summary?.verdict);
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
          negativeRouteConsent,
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

  const packetSiteUuid = String(drupalReadback?.drupal?.siteUuid ?? '').trim().toLowerCase();
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
    packetTrackedConfigYamlFiles.length === runtimeTrackedConfigYamlFiles.length &&
    new Set(packetTrackedConfigYamlFiles).size === packetTrackedConfigYamlFiles.length &&
    packetTrackedConfigYamlFiles.every((path) => runtimeTrackedConfigSet.has(path));
  const routeEvidenceManifest = [...routeChecks, ...targetRequiredRouteChecks]
    .map((route) => ({
      bodySha256: route.bodySha256 ?? '',
      finalUrl: route.finalUrl ?? '',
      h1: route.actualH1 ?? '',
      path: route.targetPath,
      routeKind: route.routeKind ?? '',
      status: route.finalStatus ?? 0,
      title: route.actualTitle ?? ''
    }))
    .sort((left, right) => comparePortable(`${left.path}\0${left.routeKind}`, `${right.path}\0${right.routeKind}`));
  const routeStateManifest = [...routeChecks, ...targetRequiredRouteChecks]
    .map((route) => ({
      canonicalPath: normalizeRouteKey(route.actualMetadata?.canonicalUrl),
      finalPath: normalizeRouteKey(route.finalUrl),
      h1: route.actualH1 ?? '',
      initialStatus: route.initialStatus ?? 0,
      intrinsicSemanticsSha256: route.intrinsicSemantics?.fingerprint ?? '',
      metaDescriptionSha256: stateSha256(route.actualMetadata?.metaDescription ?? ''),
      noindex: route.actualMetadata?.noindex === true,
      openGraphImagePath: normalizePath(route.actualMetadata?.openGraphImage),
      path: normalizeRouteKey(route.targetPath),
      routeKind: route.routeKind ?? '',
      status: route.finalStatus ?? 0,
      title: route.actualTitle ?? ''
    }))
    .sort((left, right) => comparePortable(`${left.path}\0${left.routeKind}`, `${right.path}\0${right.routeKind}`));
  const stateBlockers = [];
  const runtimeProjectRoot = findDrupalDdevRoot(cwd);
  if (!runtimeProjectRoot) {
    stateBlockers.push('Current Drupal project root could not be resolved for state fingerprinting.');
  }
  if (!target) {
    stateBlockers.push('Current live target could not be resolved for state fingerprinting.');
  }
  if (!inspectedDrupalRuntime.configManifest?.entryCount) {
    stateBlockers.push('Current tracked configuration tree is unavailable for state fingerprinting.');
  }
  if (inspectedDrupalRuntime.entityInventory?.confirmed !== true) {
    stateBlockers.push(inspectedDrupalRuntime.entityInventory?.reason || 'Drupal entity inventory is unavailable.');
  }
  if (inspectedDrupalRuntime.runtimeFacts?.confirmed !== true) {
    stateBlockers.push(inspectedDrupalRuntime.runtimeFacts?.reason || 'Drupal runtime facts are unavailable.');
  }
  if (inspectedDrupalRuntime.runtimeFacts?.databaseUpdatesPending === true) {
    stateBlockers.push(
      `Drupal reports ${Number(inspectedDrupalRuntime.runtimeFacts.pendingDatabaseUpdateCount ?? 0)} pending database update(s).`
    );
  }
  let buildState = null;
  try {
    const codeManifest = runtimeProjectRoot
      ? collectRuntimeCodeManifest(runtimeProjectRoot)
      : collectFileManifest(cwd, []);
    const entityInventory = {
      schemaVersion: inspectedDrupalRuntime.entityInventory?.schemaVersion ?? '',
      fingerprint: inspectedDrupalRuntime.entityInventory?.fingerprint ?? '',
      entityTypeCount: inspectedDrupalRuntime.entityInventory?.entityTypeCount ?? 0,
      closureCounts: inspectedDrupalRuntime.entityInventory?.closureCounts ?? {},
      excludedEntityTypes: inspectedDrupalRuntime.entityInventory?.excludedEntityTypes ?? {},
      missingDeclaredRoots: inspectedDrupalRuntime.entityInventory?.missingDeclaredRoots ?? [],
      missingManagedFileCount: inspectedDrupalRuntime.entityInventory?.missingManagedFileCount ?? 0,
      policy: inspectedDrupalRuntime.entityInventory?.policy ?? {},
      publicAuthorUserDigest: inspectedDrupalRuntime.entityInventory?.publicAuthorUserDigest ?? {},
      types: Object.fromEntries(
        Object.entries(inspectedDrupalRuntime.entityInventory?.types ?? {}).map(([entityType, value]) => [
          entityType,
          {
            count: value?.count ?? 0,
            translationCount: value?.translationCount ?? 0,
            revisionCount: value?.revisionCount ?? 0,
            revisionTranslationCount: value?.revisionTranslationCount ?? 0,
            missingManagedFileCount: value?.missingManagedFileCount ?? 0,
            fingerprint: value?.fingerprint ?? '',
            error: value?.error ?? ''
          }
        ])
      )
    };
    const runtimeFacts = {
      schemaVersion: inspectedDrupalRuntime.runtimeFacts?.schemaVersion ?? '',
      fingerprint: inspectedDrupalRuntime.runtimeFacts?.fingerprint ?? '',
      coreVersion: inspectedDrupalRuntime.runtimeFacts?.coreVersion ?? '',
      phpVersion: inspectedDrupalRuntime.runtimeFacts?.phpVersion ?? '',
      databaseDriver: inspectedDrupalRuntime.runtimeFacts?.databaseDriver ?? '',
      activeConfigEntryCount: inspectedDrupalRuntime.runtimeFacts?.activeConfigEntryCount ?? 0,
      effectiveActiveConfigSha256: inspectedDrupalRuntime.runtimeFacts?.effectiveActiveConfigSha256 ?? '',
      systemSchemaEntryCount: inspectedDrupalRuntime.runtimeFacts?.systemSchemaEntryCount ?? 0,
      systemSchemaSha256: inspectedDrupalRuntime.runtimeFacts?.systemSchemaSha256 ?? '',
      effectiveSettingsEntryCount: inspectedDrupalRuntime.runtimeFacts?.effectiveSettingsEntryCount ?? 0,
      effectiveSettingsHmacSha256: inspectedDrupalRuntime.runtimeFacts?.effectiveSettingsHmacSha256 ?? '',
      databaseUpdateStatusConfirmed: inspectedDrupalRuntime.runtimeFacts?.databaseUpdateStatusConfirmed === true,
      pendingDatabaseUpdateCount: inspectedDrupalRuntime.runtimeFacts?.pendingDatabaseUpdateCount ?? 0,
      databaseUpdatesPending: inspectedDrupalRuntime.runtimeFacts?.databaseUpdatesPending === true,
      configSplitDirectories: Array.isArray(inspectedDrupalRuntime.runtimeFacts?.configSplitDirectories)
        ? [...inspectedDrupalRuntime.runtimeFacts.configSplitDirectories].sort(comparePortable)
        : []
    };
    const packetEvidence = packetEvidenceManifest(
      absolutePacketDir,
      outPath || join(absolutePacketDir, 'evidence', 'live-verification.json')
    );
    buildState = buildSiteState({
      targetIdentity: {
        configSyncDirectory: runtimeConfigSyncDirectory,
        frontPage: runtimeFrontPage,
        siteUuid: String(inspectedDrupalRuntime.siteUuid ?? '').trim().toLowerCase()
      },
      configManifest: inspectedDrupalRuntime.configManifest ?? collectFileManifest(cwd, []),
      codeManifest,
      entityInventory,
      routeManifest: routeStateManifest,
      runtimeFacts,
      packetFingerprint: packetEvidence.fingerprint,
      packetEvidenceManifest: packetEvidence,
      verifierFingerprint: verifierFingerprint()
    });
  } catch (error) {
    stateBlockers.push(`Build-state fingerprint failed: ${error.message}`);
  }
  const buildStateReady = Boolean(buildState) && stateBlockers.length === 0;
  if (buildState) {
    buildState.complete = buildStateReady;
    buildState.blockers = stateBlockers;
  }
  let globalChromeCapture = null;
  if (buildStateReady) {
    try {
      globalChromeCapture = finalizeGlobalChromeCapture({
        capture: rawGlobalChromeCapture,
        packetDir: absolutePacketDir,
        stateFingerprint: buildState.fingerprint
      });
    } catch (error) {
      globalChromeCapture = {
        schemaVersion: 'public-kit.global-chrome-capture.1',
        checkedAt: rawGlobalChromeCapture.checkedAt,
        status: 'blocked',
        authoritative: false,
        captureMode: 'verifier-owned-browser',
        targetOrigin: target?.url?.origin ?? '',
        resultStateFingerprint: buildState.fingerprint,
        contract: rawGlobalChromeCapture.contract,
        browser: rawGlobalChromeCapture.browser,
        routes: [],
        errors: [`Global chrome capture finalization failed: ${error.message}`]
      };
    }
  }
  let beforeConsentNetworkCapture = rawBeforeConsentNetworkCapture;
  if (consentNetworkApplicable && buildStateReady) {
    try {
      beforeConsentNetworkCapture = finalizeBeforeConsentNetworkCapture({
        capture: rawBeforeConsentNetworkCapture,
        stateFingerprint: buildState.fingerprint,
        targetOrigin: target?.url?.origin ?? ''
      });
    } catch (error) {
      beforeConsentNetworkCapture = {
        schemaVersion: 'public-kit.before-consent-network-capture.1',
        checkedAt: rawBeforeConsentNetworkCapture.checkedAt,
        status: 'blocked',
        authoritative: false,
        captureMode: 'verifier-owned-cdp-network',
        targetOrigin: target?.url?.origin ?? '',
        resultStateFingerprint: buildState.fingerprint,
        browser: rawBeforeConsentNetworkCapture.browser,
        primaryRoutes: rawBeforeConsentNetworkCapture.primaryRoutes ?? [],
        routes: [],
        errors: [`Before-consent capture finalization failed: ${error.message}`]
      };
    }
  }
  const consentReconciliation = verifyConsentReconciliation(
    negativeRouteConsent?.consent,
    consentInventory,
    [...routeChecks, ...targetRequiredRouteChecks],
    beforeConsentNetworkCapture,
    {
      targetOrigin: target?.url?.origin ?? '',
      primaryRoutes,
      stateFingerprint: buildStateReady ? buildState.fingerprint : ''
    }
  );
  liveErrors.push(...consentReconciliation.errors);
  const liveTargetValid = Boolean(target) && liveErrors.length === 0;
  const drupalRuntimeSupportsCompletion =
    runtimeAuthoritativeForCompletion &&
    inspectedDrupalRuntime.confirmed === true &&
    drupalRuntimeTargetMatches &&
    drupalRuntimeSiteUuidMatches &&
    drupalRuntimeFrontPageMatches &&
    drupalRuntimeConfigSyncMatches &&
    drupalRuntimeConfigStatusClean &&
    drupalRuntimeConfigSyncTracked &&
    drupalRuntimeTrackedConfigReadbackMatches &&
    buildStateReady;
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
    completionBlockedReasons.push('Current DDEV config-sync and configured Config Split directories do not contain complete Git-tracked YAML evidence.');
  }
  if (!drupalRuntimeTrackedConfigReadbackMatches) {
    completionBlockedReasons.push('Current Git-tracked config evidence does not match drupal-readback.json.');
  }
  if (!buildStateReady) {
    completionBlockedReasons.push(...stateBlockers);
  }
  if (!runtimeAuthoritativeForCompletion) {
    completionBlockedReasons.push('Injected Drupal runtime evidence is non-authoritative and cannot authorize completion.');
  }

  const targetFingerprintInput = JSON.stringify({
    origin: target?.url.origin ?? '',
    routeChecks: routeEvidenceManifest,
    globalChromeCaptureFingerprint: globalChromeCapture?.captureFingerprint ?? '',
    beforeConsentNetworkCaptureFingerprint: beforeConsentNetworkCapture?.captureFingerprint ?? '',
    negativeRouteCheck: negativeRouteCheck
      ? { bodySha256: negativeRouteCheck.bodySha256 ?? '', path: negativeRouteCheck.path, status: negativeRouteCheck.status ?? 0 }
      : null,
    accessWallChecks: accessWallChecks.map((check) => ({ finalUrl: check.finalUrl ?? '', path: check.path, status: check.status ?? 0 })),
    legalPrivacyLinkChecks: legalPrivacyLinkChecks.map((check) => ({ finalUrl: check.finalUrl ?? '', status: check.status ?? 0, url: check.url })),
    consentRuntime: consentInventory
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
      packetEvidenceSha256: buildState?.evidenceBindings?.packetFingerprint ?? '',
      targetFingerprintInputVersion: 3
    },
    routeChecks,
    targetRequiredRouteChecks,
    globalChromeCapture,
    globalChromeCaptureSummary: captureSummary(globalChromeCapture),
    beforeConsentNetworkCapture,
    negativeRouteCheck,
    accessWallChecks,
    legalPrivacyLinkChecks,
    consentReconciliation,
    liveTargetValid,
    buildState,
    drupalRuntime: {
      ...inspectedDrupalRuntime,
      authoritativeForCompletion: runtimeAuthoritativeForCompletion,
      configStatusClean: drupalRuntimeConfigStatusClean,
      configSyncTracked: drupalRuntimeConfigSyncTracked,
      configSyncDirectory: sharedConfigSyncDirectory(inspectedDrupalRuntime.configSyncDirectory),
      configSyncDirectoryMatchesPacket: drupalRuntimeConfigSyncMatches,
      frontPageMatchesPacket: drupalRuntimeFrontPageMatches,
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
        targetUrl: args.targetUrl,
        outPath: args.out
      });
  if (!args.packetOnly) {
    const operationCanRun = !args.changeId || report.completeLocalRebuildClaimAllowed === true;
    const lifecycle = applyVerificationLifecycle({
      packetDir: args.packet,
      report,
      checkpointId: operationCanRun ? args.checkpointId : '',
      changeId: operationCanRun ? args.changeId : ''
    });
    report.lifecycle = {
      ...lifecycle,
      requestedOperation: args.changeId
        ? {
            changeId: args.changeId,
            checkpointId: args.checkpointId,
            status: operationCanRun ? 'completed' : 'blocked',
            blockedReasons: operationCanRun ? [] : report.completionBlockedReasons
          }
        : null
    };
    report.currentSiteClaimAllowed =
      report.completeLocalRebuildClaimAllowed === true &&
      report.lifecycle.currentStateVerified === true;
    report.currentStateBlockedReasons = report.lifecycle.currentStateVerified
      ? []
      : report.lifecycle.relation === 'changed-since-latest-anchor' &&
          report.lifecycle.currentStateClassification?.kind === 'unclassified'
        ? ['Current state differs from the latest lifecycle anchor and has no classified repair or extension; revert it or begin with explicit --adopt-current classification.']
        : ['Current derived state is not yet verified against its lifecycle baseline or checkpoint.'];
  }
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
  } else if (report.completeLocalRebuildClaimAllowed && report.currentSiteClaimAllowed) {
    const lifecycleNote = report.lifecycle?.requestedOperation?.checkpointId
      ? ` Checkpoint ${report.lifecycle.requestedOperation.checkpointId} recorded.`
      : report.lifecycle?.initialBaseline?.status === 'passed'
        ? ' The create-once, integrity-checked initial baseline remains recorded.'
        : '';
    process.stdout.write(`Live target and packet verification passed; complete local rebuild claim authorized.${lifecycleNote} Report: ${args.out}\n`);
  } else {
    const baselineNote = report.lifecycle?.initialBaseline?.status === 'passed'
      ? ' The create-once, integrity-checked initial baseline remains passed; the current derived state is not yet verified.'
      : '';
    const reason = report.completeLocalRebuildClaimAllowed && !report.currentSiteClaimAllowed
      ? 'Full rebuild checks passed, but the changed current state is not classified and lifecycle-verified.'
      : 'Live target checks passed, but completion remains blocked by required review evidence.';
    process.stderr.write(`${reason}${baselineNote} Report: ${args.out}\n`);
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
