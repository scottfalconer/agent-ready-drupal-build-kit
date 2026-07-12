#!/usr/bin/env node

import { createHash } from 'node:crypto';
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
  captureGlobalChrome,
  captureSummary,
  finalizeGlobalChromeCapture
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
const MAX_LIVE_ROUTE_CHECKS = 1_000;
const MAX_LIVE_ROUTE_CONCURRENCY = 12;
const MAX_LIVE_HTTP_REQUESTS = 2_000;
const MAX_LIVE_HTTP_TASKS = 20_000;
const LIVE_ROUTE_DEADLINE_MS = 90_000;
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

function redactedUrl(value, baseUrl = undefined) {
  try {
    const url = baseUrl ? new URL(value, baseUrl) : new URL(value);
    url.username = '';
    url.password = '';
    url.hash = '';
    if (url.search) {
      url.search = `?query-sha256=${sha256(url.search)}`;
    }
    return url.href;
  } catch {
    return '[invalid-url]';
  }
}

function redactedPath(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    return `${url.pathname}${url.search ? `?query-sha256=${sha256(url.search)}` : ''}`;
  } catch {
    return '[invalid-path]';
  }
}

function redactQueryValuesInMessage(value) {
  return String(value).replace(
    /((?:https?:\/\/[^\s"'<>?]+|\/[^\s"'<>?]*))\?([^\s"'<>]+)/g,
    (_match, prefix, rawQueryWithPunctuation) => {
      const [, rawQuery, punctuation = ''] = rawQueryWithPunctuation.match(/^(.*?)([),.;:]*)$/) ?? [];
      return rawQuery
        ? `${prefix}?query-sha256=${sha256(`?${rawQuery}`)}${punctuation}`
        : _match;
    }
  );
}

function sharedPacketDirName(absolutePacketDir) {
  const name = basename(absolutePacketDir);
  const queryIndex = name.indexOf('?');
  return queryIndex === -1
    ? name
    : `${name.slice(0, queryIndex)}?query-sha256=${sha256(name.slice(queryIndex))}`;
}

function sharedMessage(value, absolutePacketDir) {
  const rawName = basename(absolutePacketDir);
  const sharedName = sharedPacketDirName(absolutePacketDir);
  return redactQueryValuesInMessage(
    String(value)
      .replaceAll(absolutePacketDir, sharedName)
      .replaceAll(rawName, sharedName)
  );
}

function sharedValue(value, absolutePacketDir) {
  if (typeof value === 'string') {
    return sharedMessage(value, absolutePacketDir);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sharedValue(entry, absolutePacketDir));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, sharedValue(entry, absolutePacketDir)])
    );
  }
  return value;
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

function serverResponseLinks(html, documentUrl, targetOrigin, sourceOrigin) {
  const errors = [];
  const renderedHtml = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '');
  let resolutionBase = documentUrl;
  const baseHref = matchingTags(renderedHtml, 'base', (attributes) => Object.hasOwn(attributes, 'href'))[0]?.href;
  if (baseHref !== undefined) {
    try {
      resolutionBase = new URL(baseHref, documentUrl).href;
    } catch {
      errors.push(`${redactedUrl(documentUrl)} renders an invalid <base href> value with sha256:${sha256(baseHref)}.`);
    }
  }

  const internalLinks = [];
  const sourceOriginLinks = [];
  for (const attributes of [
    ...matchingTags(renderedHtml, 'a', (candidate) => Object.hasOwn(candidate, 'href')),
    ...matchingTags(renderedHtml, 'area', (candidate) => Object.hasOwn(candidate, 'href'))
  ]) {
    const href = String(attributes.href ?? '').trim();
    if (href.startsWith('#')) {
      continue;
    }
    let url;
    try {
      url = new URL(href, resolutionBase);
    } catch {
      errors.push(`${redactedUrl(documentUrl)} renders an invalid link target with sha256:${sha256(href)}.`);
      continue;
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
      continue;
    }
    if ((url.origin === targetOrigin || url.origin === sourceOrigin) && (url.username || url.password)) {
      errors.push(`${redactedUrl(documentUrl)} renders a credential-bearing public link with sha256:${sha256(href)}.`);
      continue;
    }
    url.hash = '';
    if (url.origin === targetOrigin) {
      internalLinks.push({ href, url: url.href });
    } else if (url.origin === sourceOrigin) {
      sourceOriginLinks.push({ href, url: url.href });
    }
  }
  return { errors, internalLinks, sourceOriginLinks };
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

function requestPathAndSearch(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  try {
    const url = new URL(text, 'https://route-key.invalid/');
    return `${normalizePath(url.pathname)}${url.search}`;
  } catch {
    return '';
  }
}

function normalizeRouteKey(value) {
  return requestPathAndSearch(value) || normalizePath(value);
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

export function isLocalEnvironmentHost(hostname) {
  const host = String(hostname ?? '').toLowerCase().replace(/^\[|\]$/g, '');
  return (
    host === 'localhost' ||
    host === '::1' ||
    host === '0.0.0.0' ||
    host === 'host.docker.internal' ||
    host.endsWith('.localhost') ||
    host.endsWith('.ddev.site') ||
    host.endsWith('.test') ||
    /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

function requestOnce(
  url,
  { allowRuntimeBoundLocalCertificate = false, captureBody = 'always', deadlineAt = 0 } = {}
) {
  return new Promise((resolveRequest, rejectRequest) => {
    const remainingDeadlineMs = deadlineAt > 0 ? deadlineAt - Date.now() : REQUEST_TIMEOUT_MS;
    if (remainingDeadlineMs <= 0) {
      rejectRequest(new Error('Live route verification exceeded its total wall-clock deadline.'));
      return;
    }
    const timeoutMs = Math.max(1, Math.min(REQUEST_TIMEOUT_MS, remainingDeadlineMs));
    const client = url.protocol === 'https:' ? https : http;
    const allowLocalCertificate = url.protocol === 'https:' && (
      isLocalEnvironmentHost(url.hostname) || allowRuntimeBoundLocalCertificate
    );
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
      () => fail(new Error(
        deadlineAt > 0 && Date.now() >= deadlineAt
          ? 'Live route verification exceeded its total wall-clock deadline.'
          : `Request exceeded the ${REQUEST_TIMEOUT_MS} ms wall-clock limit.`
      )),
      timeoutMs
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
        timeout: timeoutMs
      },
      (response) => {
        const contentType = String(response.headers['content-type'] ?? '').toLowerCase();
        const shouldCaptureBody = captureBody === 'always' || (
          captureBody === 'html' &&
          (!contentType || /(?:text\/html|application\/xhtml\+xml)/.test(contentType))
        );
        if (!shouldCaptureBody) {
          finish(resolveRequest, {
            body: '',
            headers: response.headers,
            localTlsVerificationBypassed: allowLocalCertificate,
            status: response.statusCode ?? 0
          });
          response.destroy();
          return;
        }
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
    request.on('timeout', () => fail(new Error(
      deadlineAt > 0 && Date.now() >= deadlineAt
        ? 'Live route verification exceeded its total wall-clock deadline.'
        : `Request timed out after ${timeoutMs} ms.`
    )));
    request.on('error', fail);
    request.end();
  });
}

export function createLiveHttpContext({
  allowRuntimeBoundLocalCertificate = false,
  attempted = true,
  concurrency = MAX_LIVE_ROUTE_CONCURRENCY,
  deadlineMs = LIVE_ROUTE_DEADLINE_MS,
  maxRequests = MAX_LIVE_HTTP_REQUESTS,
  maxTasks = MAX_LIVE_HTTP_TASKS
} = {}) {
  const startedAt = Date.now();
  const errors = [];
  const errorSet = new Set();
  const limits = { concurrency, deadlineMs, maxRequests, maxTasks };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      const message = `Live HTTP verification ${name} must be a positive safe integer.`;
      errors.push(message);
      errorSet.add(message);
    }
  }
  const limitsValid = errors.length === 0;
  const deadlineAt = limitsValid ? startedAt + deadlineMs : startedAt;
  const waiters = [];
  const tasksByKind = {};
  let activeRequests = 0;
  let completedTaskCount = 0;
  let deadlineExceeded = false;
  let peakConcurrency = 0;
  let requestCapExhausted = false;
  let requestCount = 0;
  let taskCapExhausted = false;
  let taskCount = 0;
  let taskRejectedCount = 0;

  const recordError = (message) => {
    if (!errorSet.has(message)) {
      errorSet.add(message);
      errors.push(message);
    }
    return new Error(message);
  };
  const deadlineError = () => {
    deadlineExceeded = true;
    return recordError('Live route verification exceeded its total wall-clock deadline.');
  };
  const ensureUsable = () => {
    if (!limitsValid) {
      throw new Error(errors[0]);
    }
    if (Date.now() >= deadlineAt) {
      throw deadlineError();
    }
  };
  const dispatch = () => {
    while (activeRequests < concurrency && waiters.length > 0) {
      const waiter = waiters.shift();
      if (waiter.cancelled) {
        continue;
      }
      if (Date.now() >= deadlineAt) {
        waiter.cancelled = true;
        clearTimeout(waiter.timer);
        waiter.reject(deadlineError());
        continue;
      }
      clearTimeout(waiter.timer);
      activeRequests += 1;
      peakConcurrency = Math.max(peakConcurrency, activeRequests);
      waiter.resolve();
    }
  };
  const acquire = () => {
    ensureUsable();
    if (activeRequests < concurrency) {
      activeRequests += 1;
      peakConcurrency = Math.max(peakConcurrency, activeRequests);
      return Promise.resolve();
    }
    return new Promise((resolveAcquire, rejectAcquire) => {
      const remainingMs = Math.max(1, deadlineAt - Date.now());
      const waiter = {
        cancelled: false,
        reject: rejectAcquire,
        resolve: resolveAcquire,
        timer: null
      };
      waiter.timer = setTimeout(() => {
        if (waiter.cancelled) {
          return;
        }
        waiter.cancelled = true;
        rejectAcquire(deadlineError());
      }, remainingMs);
      waiters.push(waiter);
    });
  };
  const release = () => {
    activeRequests = Math.max(0, activeRequests - 1);
    dispatch();
  };

  return {
    allowRuntimeBoundLocalCertificate,
    deadlineAt,
    errors,
    async request(url, { captureBody = 'always' } = {}) {
      ensureUsable();
      if (requestCount >= maxRequests) {
        requestCapExhausted = true;
        throw recordError(`Live route verification exhausted its ${maxRequests} HTTP request budget.`);
      }
      requestCount += 1;
      await acquire();
      try {
        ensureUsable();
        return await requestOnce(url, {
          allowRuntimeBoundLocalCertificate,
          captureBody,
          deadlineAt
        });
      } catch (error) {
        if (/total wall-clock deadline/i.test(String(error?.message ?? error))) {
          throw deadlineError();
        }
        throw error;
      } finally {
        release();
      }
    },
    async runTask(kind, task) {
      ensureUsable();
      if (taskCapExhausted || taskCount >= maxTasks) {
        taskCapExhausted = true;
        taskRejectedCount += 1;
        throw recordError(`Live route verification exhausted its ${maxTasks} task budget.`);
      }
      const taskKind = String(kind || 'unspecified');
      taskCount += 1;
      tasksByKind[taskKind] = (tasksByKind[taskKind] ?? 0) + 1;
      try {
        return await task();
      } finally {
        completedTaskCount += 1;
      }
    },
    async runTasks(kind, values, mapper) {
      const items = [...values];
      ensureUsable();
      if (taskCapExhausted || taskCount + items.length > maxTasks) {
        taskCapExhausted = true;
        taskRejectedCount += items.length;
        throw recordError(
          `Live route verification exhausted its ${maxTasks} task budget; ${items.length} ${String(kind || 'unspecified')} tasks could not be scheduled.`
        );
      }
      const outcomes = await Promise.allSettled(items.map((value, index) => this.runTask(
        kind,
        () => mapper(value, index)
      )));
      const rejected = outcomes.find((outcome) => outcome.status === 'rejected');
      if (rejected) {
        throw rejected.reason;
      }
      return outcomes.map((outcome) => outcome.value);
    },
    metrics() {
      return {
        attempted,
        deadlineAt: new Date(deadlineAt).toISOString(),
        deadlineExceeded,
        deadlineMs,
        elapsedMs: Date.now() - startedAt,
        maxConcurrency: concurrency,
        maxRequests,
        maxTasks,
        peakConcurrency,
        requestCapExhausted,
        requestCount,
        taskCapExhausted,
        taskCount,
        taskRejectedCount,
        completedTaskCount,
        tasksByKind: { ...tasksByKind }
      };
    }
  };
}

async function requestFollowingRedirects(
  startUrl,
  { captureBody = 'always', liveHttpContext, stopAtExternalRedirect = false } = {}
) {
  if (!liveHttpContext) {
    throw new Error('A verifier-wide live HTTP context is required.');
  }
  let current = new URL(startUrl);
  current.hash = '';
  if (current.username || current.password) {
    throw new Error(`Refusing credential-bearing request URL ${redactedUrl(current)}.`);
  }
  const allowedOrigin = current.origin;
  const redirects = [];
  let localTlsVerificationBypassed = false;

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    const response = await liveHttpContext.request(current, { captureBody });
    localTlsVerificationBypassed ||= response.localTlsVerificationBypassed;
    const location = response.headers.location;
    if (REDIRECT_STATUSES.has(response.status) && location) {
      if (redirectCount === MAX_REDIRECTS) {
        throw new Error(`Too many redirects (more than ${MAX_REDIRECTS}).`);
      }
      const next = new URL(location, current);
      next.hash = '';
      if (next.username || next.password) {
        throw new Error(`Refusing credential-bearing redirect from ${redactedUrl(current)} to ${redactedUrl(next)}.`);
      }
      if (next.origin !== allowedOrigin) {
        if (stopAtExternalRedirect) {
          redirects.push({ from: current.href, status: response.status, to: next.href });
          return {
            ...response,
            externalRedirect: true,
            finalUrl: next.href,
            initialStatus: redirects[0]?.status ?? response.status,
            localTlsVerificationBypassed,
            redirects
          };
        }
        throw new Error(`Refusing cross-origin redirect from ${redactedUrl(current)} to ${redactedUrl(next)}.`);
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
      externalRedirect: false,
      redirects
    };
  }
  throw new Error('Redirect resolution failed.');
}

async function inspectServerRenderedResponseSurface(baseUrl, routeMatrix, liveHttpContext) {
  let sourceOrigin = '';
  try {
    sourceOrigin = parseHttpUrl(routeMatrix?.sourceBaseUrl, 'route-matrix.json sourceBaseUrl').origin;
  } catch {
    // Packet and live identity validation report the malformed source URL separately.
  }
  const declaredSameOriginRequests = new Set();
  const declarePath = (value) => {
    const request = requestPathAndSearch(value);
    if (request) {
      declaredSameOriginRequests.add(request);
    }
  };
  const routeSeeds = new Map();
  const seedErrors = [];
  const addSeed = (path, reason, contract = null) => {
    const text = String(path ?? '').trim();
    if (!text) {
      return;
    }
    let url;
    try {
      url = new URL(text.replace(/^\//, ''), new URL('/', baseUrl));
    } catch {
      seedErrors.push(`Accepted public route value with sha256:${sha256(text)} is not a usable URL path.`);
      return;
    }
    if (url.origin !== baseUrl.origin) {
      seedErrors.push(`Accepted public route ${redactedUrl(url)} does not stay on target origin ${baseUrl.origin}.`);
      return;
    }
    url.hash = '';
    const existing = routeSeeds.get(url.href) ?? { contracts: [], reasons: new Set(), url };
    if (contract) {
      existing.contracts.push(contract);
    }
    existing.reasons.add(reason);
    routeSeeds.set(url.href, existing);
  };
  for (const route of Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : []) {
    if (route?.accepted === true) {
      declarePath(route.targetPath);
      declarePath(route.targetFinalPath);
      addSeed(route.targetPath, 'accepted-route', {
        expectedFinalRequest: requestPathAndSearch(route.targetFinalPath || route.targetPath),
        expectedRedirect: route.expectedRedirect === true,
        expectedStatus: Number(route.targetStatus),
        kind: 'accepted route'
      });
    }
  }
  for (const route of Array.isArray(routeMatrix?.targetRequiredRoutes) ? routeMatrix.targetRequiredRoutes : []) {
    if (route?.accepted === true) {
      declarePath(route.targetPath);
      declarePath(route.targetFinalPath);
    }
    if (
      route?.accepted === true &&
      ['public_200', 'redirect', 'noindex'].includes(String(route?.expectedPublicBehavior ?? ''))
    ) {
      addSeed(route.targetPath, 'target-required-route', {
        expectedFinalRequest: requestPathAndSearch(route.targetFinalPath || route.targetPath),
        expectedRedirect: route.expectedPublicBehavior === 'redirect',
        expectedStatus: Number(route.targetStatus),
        kind: 'target-required route'
      });
    }
  }

  const routeChecks = await liveHttpContext.runTasks(
    'accepted-route-seed',
    [...routeSeeds.values()],
    async (seed) => {
      const errors = [];
      try {
        const response = await requestFollowingRedirects(seed.url, {
          captureBody: 'html',
          liveHttpContext
        });
        if (response.status < 200 || response.status >= 300) {
          errors.push(`${redactedPath(seed.url.href, baseUrl)} ended with HTTP ${response.status}; accepted public routes must end with a 2xx response.`);
        }
        if (new URL(response.finalUrl).origin !== baseUrl.origin) {
          errors.push(`${redactedPath(seed.url.href, baseUrl)} left the target origin and resolved to ${new URL(response.finalUrl).origin}.`);
        }
        for (const contract of seed.contracts) {
          const routeLabel = `${contract.kind} ${redactedPath(seed.url.href, baseUrl)}`;
          const actualStatus = contract.expectedRedirect ? response.initialStatus : response.status;
          if (!Number.isFinite(contract.expectedStatus) || actualStatus !== contract.expectedStatus) {
            errors.push(`${routeLabel} returned status ${actualStatus}; expected ${contract.expectedStatus}.`);
          }
          if (contract.expectedRedirect && response.redirects.length === 0) {
            errors.push(`${routeLabel} declares a redirect but the live response did not follow a redirect.`);
          }
          if (!contract.expectedRedirect && response.redirects.length > 0) {
            errors.push(`${routeLabel} declares a direct response but the live response redirected.`);
          }
          const actualFinalRequest = requestPathAndSearch(response.finalUrl);
          if (actualFinalRequest !== contract.expectedFinalRequest) {
            errors.push(
              `${routeLabel} resolved to ${redactedPath(response.finalUrl, baseUrl)}; expected ${redactedPath(contract.expectedFinalRequest, baseUrl)}.`
            );
          }
        }
        const contentType = String(response.headers['content-type'] ?? '').toLowerCase();
        const isHtml = /(?:text\/html|application\/xhtml\+xml)/.test(contentType) ||
          (!contentType && /<(?:!doctype\s+html|html)\b/i.test(response.body));
        const extracted = isHtml
          ? serverResponseLinks(response.body, response.finalUrl, baseUrl.origin, sourceOrigin)
          : { errors: [], internalLinks: [], sourceOriginLinks: [] };
        errors.push(...extracted.errors);
        return {
          bodySha256: `sha256:${sha256(response.body)}`,
          errors,
          finalStatus: response.status,
          finalUrl: response.finalUrl,
          initialStatus: response.initialStatus,
          internalLinks: extracted.internalLinks,
          isHtml,
          passed: errors.length === 0,
          reasons: [...seed.reasons],
          requestedUrl: seed.url.href,
          sourceOriginLinks: extracted.sourceOriginLinks
        };
      } catch (error) {
        errors.push(`${redactedPath(seed.url.href, baseUrl)} could not be fetched for server-response link inspection: ${error.message}`);
        return {
          errors,
          internalLinks: [],
          isHtml: false,
          passed: false,
          reasons: [...seed.reasons],
          requestedUrl: seed.url.href,
          sourceOriginLinks: []
        };
      }
    }
  );

  const internalTargets = new Map();
  for (const route of routeChecks) {
    for (const link of route.internalLinks) {
      const target = internalTargets.get(link.url) ?? { hrefs: new Set(), referrers: new Set(), url: link.url };
      target.hrefs.add(link.href);
      target.referrers.add(route.finalUrl || route.requestedUrl);
      internalTargets.set(link.url, target);
    }
  }

  const acceptedSameOriginExceptions = new Map();
  for (const exception of Array.isArray(routeMatrix?.sameOriginLinkExceptions)
    ? routeMatrix.sameOriginLinkExceptions
    : []) {
    if (exception?.accepted !== true) {
      continue;
    }
    try {
      const referrer = new URL(String(exception.referrer ?? ''), new URL('/', baseUrl));
      const target = new URL(String(exception.target ?? ''), new URL('/', baseUrl));
      referrer.hash = '';
      target.hash = '';
      if (referrer.origin !== baseUrl.origin || target.origin !== baseUrl.origin) {
        continue;
      }
      acceptedSameOriginExceptions.set(`${referrer.href}\n${target.href}`, exception);
    } catch {
      // Packet completion validation reports malformed exceptions separately.
    }
  }

  const expectedExternalRedirects = new Map();
  for (const expectation of Array.isArray(routeMatrix?.expectedExternalLinkRedirects)
    ? routeMatrix.expectedExternalLinkRedirects
    : []) {
    if (expectation?.accepted !== true) {
      continue;
    }
    try {
      const referrer = new URL(String(expectation.referrer ?? ''), new URL('/', baseUrl));
      const start = new URL(String(expectation.start ?? ''), new URL('/', baseUrl));
      const final = new URL(String(expectation.final ?? ''));
      referrer.hash = '';
      start.hash = '';
      final.hash = '';
      if (
        referrer.origin !== baseUrl.origin ||
        start.origin !== baseUrl.origin ||
        final.origin === baseUrl.origin ||
        !['exact_url', 'origin'].includes(expectation.finalMatch)
      ) {
        continue;
      }
      const key = `${referrer.href}\n${start.href}`;
      const records = expectedExternalRedirects.get(key) ?? [];
      records.push({ expectation, final });
      expectedExternalRedirects.set(key, records);
    } catch {
      // Packet completion validation reports malformed expectations separately.
    }
  }

  const acceptedSourceExceptions = new Map();
  for (const exception of Array.isArray(routeMatrix?.sourceOriginLinkExceptions)
    ? routeMatrix.sourceOriginLinkExceptions
    : []) {
    if (exception?.accepted !== true) {
      continue;
    }
    try {
      const referrer = new URL(String(exception.referrer ?? ''), new URL('/', baseUrl));
      const target = new URL(String(exception.target ?? ''));
      referrer.hash = '';
      target.hash = '';
      if (referrer.origin !== baseUrl.origin || target.origin !== sourceOrigin) {
        continue;
      }
      acceptedSourceExceptions.set(`${referrer.href}\n${target.href}`, exception);
    } catch {
      // Packet completion validation reports malformed exceptions separately.
    }
  }
  const sourceOriginPairs = new Map();
  for (const route of routeChecks) {
    const referrer = route.finalUrl || route.requestedUrl;
    for (const link of route.sourceOriginLinks) {
      const pairKey = `${referrer}\n${link.url}`;
      const pair = sourceOriginPairs.get(pairKey) ?? {
        hrefs: new Set(),
        referrer,
        target: link.url
      };
      pair.hrefs.add(link.href);
      sourceOriginPairs.set(pairKey, pair);
    }
  }
  const sourceOriginLinkChecks = await liveHttpContext.runTasks(
    'source-origin-link',
    [...sourceOriginPairs.entries()],
    async ([pairKey, pair]) => {
      const exception = acceptedSourceExceptions.get(pairKey);
      const passed = Boolean(exception);
      const checkErrors = passed
        ? []
        : [`Server-rendered response link ${redactedUrl(pair.target)} from ${redactedUrl(pair.referrer)} points back to source origin ${sourceOrigin} without an accepted per-link exception.`];
      return {
        acceptedException: exception
          ? {
                accepter: exception.accepter,
                evidence: exception.evidence,
                rationaleSha256: `sha256:${sha256(String(exception.rationale ?? ''))}`
            }
          : null,
        errors: checkErrors,
        hrefCount: pair.hrefs.size,
        hrefSha256: [...pair.hrefs].slice(0, 10).map((href) => `sha256:${sha256(href)}`),
        passed,
        referrer: pair.referrer,
        target: pair.target
      };
    }
  );

  const errors = [
    ...seedErrors,
    ...routeChecks.flatMap((check) => check.errors),
    ...sourceOriginLinkChecks.flatMap((check) => check.errors)
  ];
  const linkChecks = await liveHttpContext.runTasks(
    'server-rendered-link',
    [...internalTargets.values()],
    async (target) => {
        const targetErrors = [];
        const hrefs = [...target.hrefs];
        const referrers = [...target.referrers];
        try {
          const response = await requestFollowingRedirects(new URL(target.url), {
            captureBody: 'never',
            liveHttpContext,
            stopAtExternalRedirect: true
          });
          const finalUrl = new URL(response.finalUrl);
          finalUrl.hash = '';
          const startPathDeclared = declaredSameOriginRequests.has(requestPathAndSearch(target.url));
          const finalPathDeclared = finalUrl.origin === baseUrl.origin &&
            declaredSameOriginRequests.has(requestPathAndSearch(finalUrl.href));
          const acceptedDispositions = [];
          if (response.externalRedirect) {
            for (const referrer of referrers) {
              const candidates = expectedExternalRedirects.get(`${referrer}\n${target.url}`) ?? [];
              const match = candidates.find(({ expectation, final }) =>
                expectation.finalMatch === 'origin'
                  ? finalUrl.origin === final.origin
                  : finalUrl.href === final.href
              );
              if (!match) {
                targetErrors.push(
                  `Server-rendered same-origin link ${redactedUrl(target.url)} from ${redactedUrl(referrer)} redirects externally to ${redactedUrl(finalUrl)} without an exact accepted expectation.`
                );
              } else {
                acceptedDispositions.push({
                  accepter: match.expectation.accepter,
                  disposition: 'expected_external_redirect',
                  evidence: match.expectation.evidence,
                  finalMatch: match.expectation.finalMatch,
                  rationaleSha256: `sha256:${sha256(String(match.expectation.rationale ?? ''))}`,
                  referrer: redactedUrl(referrer)
                });
              }
            }
          } else {
            if (response.status < 200 || response.status >= 300) {
              targetErrors.push(`Server-rendered same-origin link ${redactedUrl(target.url)} ended with HTTP ${response.status}.`);
            }
            if (finalUrl.origin !== baseUrl.origin) {
              targetErrors.push(`Server-rendered same-origin link ${redactedUrl(target.url)} left the target origin.`);
            }
            for (const referrer of referrers) {
              const exception = acceptedSameOriginExceptions.get(`${referrer}\n${target.url}`);
              if ((!startPathDeclared || !finalPathDeclared) && !exception) {
                targetErrors.push(
                  `Server-rendered same-origin link target ${redactedUrl(target.url)} from ${redactedUrl(referrer)} is not represented by an accepted routes or targetRequiredRoutes entry and has no exact accepted disposition.`
                );
              } else if (exception) {
                acceptedDispositions.push({
                  accepter: exception.accepter,
                  disposition: exception.disposition,
                  evidence: exception.evidence,
                  rationaleSha256: `sha256:${sha256(String(exception.rationale ?? ''))}`,
                  referrer: redactedUrl(referrer)
                });
              }
            }
          }
          return {
            acceptedDispositions,
            errors: targetErrors,
            externalRedirect: response.externalRedirect,
            finalStatus: response.status,
            finalUrl: redactedUrl(response.finalUrl),
            hrefCount: hrefs.length,
            hrefSha256: hrefs.slice(0, 10).map((href) => `sha256:${sha256(href)}`),
            initialStatus: response.initialStatus,
            passed: targetErrors.length === 0,
            referrerCount: referrers.length,
            referrers: referrers.slice(0, 25).map((referrer) => redactedUrl(referrer)),
            redirects: response.redirects.map((redirect) => ({
              from: redactedUrl(redirect.from),
              status: redirect.status,
              to: redactedUrl(redirect.to)
            })),
            requestedUrl: redactedUrl(target.url)
          };
        } catch (error) {
          targetErrors.push(`Server-rendered same-origin link ${redactedUrl(target.url)} could not be fetched: ${error.message}`);
          return {
            errors: targetErrors,
            hrefCount: hrefs.length,
            hrefSha256: hrefs.slice(0, 10).map((href) => `sha256:${sha256(href)}`),
            passed: false,
            referrerCount: referrers.length,
            referrers: referrers.slice(0, 25).map((referrer) => redactedUrl(referrer)),
            requestedUrl: redactedUrl(target.url)
          };
        }
    }
  );
  errors.push(...linkChecks.flatMap((check) => check.errors));

  return {
    errors,
    htmlRouteCount: routeChecks.filter((check) => check.isHtml).length,
    linkChecks,
    passed: errors.length === 0,
    routeChecks: routeChecks.map(({
      internalLinks: _internalLinks,
      sourceOriginLinks: _sourceOriginLinks,
      ...check
    }) => ({
      ...check,
      finalUrl: check.finalUrl ? redactedUrl(check.finalUrl) : '',
      requestedUrl: redactedUrl(check.requestedUrl)
    })),
    seedRouteCount: routeSeeds.size,
    sourceOriginLinkChecks: sourceOriginLinkChecks.map((check) => ({
      ...check,
      referrer: redactedUrl(check.referrer),
      target: redactedUrl(check.target)
    })),
    sourceOriginLinkCount: sourceOriginLinkChecks.length,
    uniqueInternalLinkCount: internalTargets.size
  };
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

function stringValues(value) {
  if (typeof value === 'string') {
    return value.split(',').map((item) => item.trim()).filter(Boolean);
  }
  return Array.isArray(value) ? value.flatMap(stringValues) : [];
}

export function ddevProjectWebUrls(description) {
  const urls = new Set();
  const visit = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return;
    }
    const primaryValues = [value.primary_url, value.primaryUrl].flatMap(stringValues);
    const projectWebRecord = primaryValues.length > 0 && (
      Object.hasOwn(value, 'httpurl') ||
      Object.hasOwn(value, 'httpsurl') ||
      Object.hasOwn(value, 'httpUrl') ||
      Object.hasOwn(value, 'httpsUrl') ||
      Object.hasOwn(value, 'httpURLs') ||
      Object.hasOwn(value, 'httpsURLs') ||
      Object.hasOwn(value, 'docroot') ||
      Object.hasOwn(value, 'project_tld') ||
      Object.hasOwn(value, 'additional_fqdns')
    );
    if (projectWebRecord) {
      for (const candidate of [
        ...primaryValues,
        ...stringValues(value.urls),
        ...stringValues(value.httpurl),
        ...stringValues(value.httpsurl),
        ...stringValues(value.httpUrl),
        ...stringValues(value.httpsUrl),
        ...stringValues(value.httpURLs),
        ...stringValues(value.httpsURLs)
      ]) {
        try {
          urls.add(parseHttpUrl(candidate, 'DDEV project web URL').origin);
        } catch {
          // Ignore malformed describe fields; runtime identity will fail separately if primary is unusable.
        }
      }
    }
    for (const child of Object.values(value)) {
      visit(child);
    }
  };
  visit(description);
  return [...urls];
}

function ddevTargetDescription(cwd, environment = process.env) {
  try {
    const output = execFileSync('ddev', ['describe', '-j'], {
      cwd,
      encoding: 'utf8',
      env: environment,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000
    });
    const description = JSON.parse(output);
    return {
      primaryUrl: recursiveStringForKey(description, new Set(['primary_url', 'primaryUrl'])),
      webOrigins: ddevProjectWebUrls(description)
    };
  } catch {
    return { primaryUrl: '', webOrigins: [] };
  }
}

function ddevTargetUrl(cwd, environment = process.env) {
  return ddevTargetDescription(cwd, environment).primaryUrl;
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

function firstNonEmptyLine(value) {
  return String(value ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean) ?? '';
}

function runDrushResult(projectRoot, environment, args, timeout = 15_000) {
  const inContainer = ddevContainerContext(projectRoot, environment);
  const commands = inContainer
    ? [
        ['drush', args],
        [join(projectRoot, 'vendor', 'bin', 'drush'), args]
      ]
    : [['ddev', ['drush', ...args]]];
  let failure = null;
  for (const [command, commandArgs] of commands) {
    try {
      return {
        ok: true,
        output: execFileSync(command, commandArgs, {
          cwd: projectRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout
        }).trim()
      };
    } catch (error) {
      // Try the next supported host/container form, keeping the most informative failure.
      const candidate = {
        argv: ['drush', ...args],
        exitStatus: Number.isInteger(error?.status) ? error.status : null,
        stderr: firstNonEmptyLine(error?.stderr) || firstNonEmptyLine(error?.message)
      };
      if (!failure || (candidate.stderr && !failure.stderr)) {
        failure = candidate;
      }
    }
  }
  return { ok: false, output: '', failure };
}

function describeDrushFailure(failure) {
  const exitStatus = failure?.exitStatus === null || failure?.exitStatus === undefined
    ? 'unavailable'
    : failure.exitStatus;
  const stderr = failure?.stderr ? `: ${failure.stderr}` : '';
  return `\`${(failure?.argv ?? []).join(' ')}\` failed (exit ${exitStatus})${stderr}`;
}

function runDrush(projectRoot, environment, args) {
  return runDrushResult(projectRoot, environment, args).output;
}

const DRUPAL_LIVE_SURFACE_SCHEMA = 'public-kit.drupal-live-surface.1';
const DRUPAL_LIVE_SURFACE_LIMIT = 5000;
export const DRUPAL_LIVE_SURFACE_EVAL = String.raw`
$manager = \Drupal::entityTypeManager();
$definitions = $manager->getDefinitions();
$bundle_info = \Drupal::service('entity_type.bundle.info');
$config_factory = \Drupal::configFactory();
$surface_limit = ${DRUPAL_LIVE_SURFACE_LIMIT};
$items = [];
$errors = [];
$truncated = FALSE;
$public_editorial_roots = [];
$excluded_entity_types = [
  'user' => 'broad user rows are never swept',
  'webform_submission' => 'private form submissions',
  'contact_message' => 'private contact submissions',
  'easy_email' => 'private generated email messages',
  'oauth2_token' => 'authentication credentials',
  'oauth2_refresh_token' => 'authentication credentials',
  'oauth2_auth_code' => 'authentication credentials',
  'simple_oauth_token' => 'authentication credentials',
  'simple_oauth_refresh_token' => 'authentication credentials',
  'simple_oauth_auth_code' => 'authentication credentials',
  'commerce_order' => 'private customer transactions',
  'commerce_order_item' => 'private customer transactions',
  'commerce_payment' => 'private payment data',
  'commerce_payment_method' => 'private payment credentials',
  'commerce_log' => 'private transaction audit data',
  'consumer' => 'private API consumer credentials',
  'search_api_task' => 'derived indexing tasks',
  'content_moderation_state' => 'derived moderation state',
  'workspace' => 'private derived workspace state',
  'workspace_association' => 'derived workspace association',
];
$normalize_path = static function ($value): string {
  $path = trim((string) $value);
  if ($path === '') {
    return '';
  }
  return '/' . ltrim($path, '/');
};
$safe_public_uri = static function ($value): string {
  $uri = trim((string) $value);
  if ($uri === '') {
    return '';
  }
  $parts = parse_url($uri);
  if (is_array($parts) && isset($parts['scheme'], $parts['host'])) {
    $port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
    return (string) $parts['scheme'] . '://' . (string) $parts['host'] . $port . (string) ($parts['path'] ?? '/');
  }
  return preg_split('/[?#]/', $uri, 2)[0] ?? '';
};
$add_surface = function (string $kind, string $identity, array $metadata = []) use (&$items, &$truncated, $surface_limit): void {
  $identity = trim($identity);
  if ($kind === '' || $identity === '') {
    return;
  }
  $key = $kind . ':' . $identity;
  if (isset($items[$key])) {
    return;
  }
  if (count($items) >= $surface_limit) {
    $truncated = TRUE;
    return;
  }
  ksort($metadata, SORT_STRING);
  $items[$key] = ['key' => $key, 'kind' => $kind] + $metadata;
};
$bounded_ids = function ($query, string $context) use (&$truncated, &$errors, $surface_limit): array {
  try {
    $ids = array_values($query->range(0, $surface_limit + 1)->execute());
    if (count($ids) > $surface_limit) {
      $truncated = TRUE;
      $ids = array_slice($ids, 0, $surface_limit);
    }
    return $ids;
  }
  catch (\Throwable) {
    $errors[] = $context . ' inventory query failed.';
    return [];
  }
};

// Bundle definitions come from Drupal before packet claims. Only aggregate
// publication counts and stable machine identifiers are emitted.
$public_root_allowlist = ['block_content', 'canvas_page', 'media', 'node', 'taxonomy_term'];
ksort($definitions, SORT_STRING);
foreach ($definitions as $entity_type_id => $definition) {
  if (!($definition instanceof \Drupal\Core\Entity\ContentEntityTypeInterface) || isset($excluded_entity_types[$entity_type_id])) {
    continue;
  }
  $bundle_key = (string) ($definition->getKey('bundle') ?? '');
  if ($bundle_key === '') {
    continue;
  }
  $bundles = $bundle_info->getBundleInfo($entity_type_id);
  ksort($bundles, SORT_STRING);
  $has_canonical_route = (string) ($definition->getLinkTemplate('canonical') ?? '') !== '';
  $status_key = (string) ($definition->getKey('status') ?? '');
  $is_public_root_type = in_array($entity_type_id, $public_root_allowlist, TRUE) || ($has_canonical_route && $status_key !== '');
  foreach (array_keys($bundles) as $bundle) {
    $published_count = 0;
    if ($is_public_root_type) {
      try {
        $query = $manager->getStorage($entity_type_id)->getQuery()->accessCheck(FALSE)->condition($bundle_key, $bundle);
        if ($status_key !== '') {
          $query->condition($status_key, TRUE);
        }
        $published_count = (int) $query->count()->execute();
      }
      catch (\Throwable) {
        $errors[] = 'Bundle publication count failed for ' . $entity_type_id . '.' . $bundle . '.';
      }
      $public_editorial_roots[$entity_type_id][] = (string) $bundle;
    }
    $add_surface('bundle', $entity_type_id . ':' . $bundle, [
      'bundle' => (string) $bundle,
      'entityType' => (string) $entity_type_id,
      'publicEditorialRoot' => $is_public_root_type,
      'publicSurface' => $is_public_root_type,
      'publishedCount' => $published_count,
    ]);
  }
}
foreach ($public_editorial_roots as $entity_type_id => $bundles) {
  $bundles = array_values(array_unique(array_map('strval', $bundles)));
  sort($bundles, SORT_STRING);
  $public_editorial_roots[$entity_type_id] = $bundles;
}
ksort($public_editorial_roots, SORT_STRING);

// Active View definitions and every enabled non-default display are surface
// metadata. Anonymous permissions plus active block/Canvas registration decide
// whether a display is public; non-public records still require owned exclusion.
$anonymous_permissions = $config_factory->get('user.role.anonymous')->get('permissions') ?? [];
$anonymous_permissions = array_values(array_map('strval', is_array($anonymous_permissions) ? $anonymous_permissions : []));
$public_view_blocks = [];
$public_menus = ['footer' => TRUE, 'main' => TRUE];
foreach ($config_factory->listAll('block.block.') as $block_config_name) {
  $block = $config_factory->get($block_config_name)->getRawData();
  if (($block['status'] ?? FALSE) !== TRUE) {
    continue;
  }
  $plugin = (string) ($block['plugin'] ?? '');
  if (str_starts_with($plugin, 'views_block:')) {
    $public_view_blocks[substr($plugin, strlen('views_block:'))] = TRUE;
  }
  if (str_starts_with($plugin, 'system_menu_block:')) {
    $public_menus[substr($plugin, strlen('system_menu_block:'))] = TRUE;
  }
}
foreach ($config_factory->listAll('canvas.component.block.views_block.') as $component_config_name) {
  $public_view_blocks[substr($component_config_name, strlen('canvas.component.block.views_block.'))] = TRUE;
}
foreach ($config_factory->listAll('views.view.') as $config_name) {
  $view = $config_factory->get($config_name)->getRawData();
  if (($view['status'] ?? TRUE) !== TRUE) {
    continue;
  }
  $view_id = (string) ($view['id'] ?? substr($config_name, strlen('views.view.')));
  $displays = is_array($view['display'] ?? NULL) ? $view['display'] : [];
  ksort($displays, SORT_STRING);
  $default_options = is_array($displays['default']['display_options'] ?? NULL) ? $displays['default']['display_options'] : [];
  $view_is_public = FALSE;
  foreach ($displays as $display_id => $display) {
    if ($display_id === 'default' || !is_array($display) || ($display['enabled'] ?? TRUE) === FALSE) {
      continue;
    }
    $options = is_array($display['display_options'] ?? NULL) ? $display['display_options'] : [];
    $path = $normalize_path($options['path'] ?? '');
    $access = is_array($options['access'] ?? NULL)
      ? $options['access']
      : (is_array($default_options['access'] ?? NULL) ? $default_options['access'] : []);
    $access_type = (string) ($access['type'] ?? 'none');
    $access_options = is_array($access['options'] ?? NULL) ? $access['options'] : [];
    $access_roles = is_array($access_options['role'] ?? NULL) ? $access_options['role'] : [];
    $anonymous_access = $access_type === 'none' ||
      ($access_type === 'perm' && in_array((string) ($access_options['perm'] ?? ''), $anonymous_permissions, TRUE)) ||
      ($access_type === 'role' && in_array('anonymous', array_map('strval', array_merge(array_keys($access_roles), array_values($access_roles))), TRUE));
    $display_plugin = (string) ($display['display_plugin'] ?? '');
    $registered_block = isset($public_view_blocks[$view_id . '-' . $display_id]);
    $public_surface = $anonymous_access && ($path !== '' || ($display_plugin === 'block' && $registered_block));
    $view_is_public = $view_is_public || $public_surface;
    $add_surface('view_display', $view_id . ':' . $display_id, [
      'anonymousAccessConfigured' => $anonymous_access,
      'displayId' => (string) $display_id,
      'displayPlugin' => $display_plugin,
      'path' => $path,
      'publicSurface' => $public_surface,
      'routeName' => $path !== '' ? 'view.' . $view_id . '.' . $display_id : '',
      'viewId' => $view_id,
    ]);
  }
  $add_surface('view', $view_id, [
    'configName' => (string) $config_name,
    'publicSurface' => $view_is_public,
  ]);
}

// Published routing/navigation infrastructure is public metadata. No labels,
// titles, descriptions, or row payloads are returned.
if (isset($definitions['path_alias'])) {
  $definition = $definitions['path_alias'];
  $query = $manager->getStorage('path_alias')->getQuery()->accessCheck(FALSE);
  if ($status_key = $definition->getKey('status')) {
    $query->condition($status_key, TRUE);
  }
  foreach ($manager->getStorage('path_alias')->loadMultiple($bounded_ids($query, 'Published alias')) as $alias) {
    $internal = $normalize_path($alias->get('path')->value ?? '');
    $public = $normalize_path($alias->get('alias')->value ?? '');
    $langcode = (string) ($alias->language()->getId() ?? 'und');
    $add_surface('alias', $langcode . ':' . $public . ':' . $internal, [
      'alias' => $public,
      'internalPath' => $internal,
      'langcode' => $langcode,
    ]);
  }
}
if (isset($definitions['menu_link_content'])) {
  $definition = $definitions['menu_link_content'];
  $query = $manager->getStorage('menu_link_content')->getQuery()->accessCheck(FALSE);
  if ($status_key = $definition->getKey('status')) {
    $query->condition($status_key, TRUE);
  }
  $menu_links = $manager->getStorage('menu_link_content')->loadMultiple($bounded_ids($query, 'Enabled menu link'));
  foreach ($menu_links as $link) {
    $menu_name = (string) ($link->get('menu_name')->value ?? '');
    if ($menu_name !== '') {
      $public_menus[$menu_name] = TRUE;
    }
  }
  foreach ($menu_links as $link) {
    $uuid = method_exists($link, 'uuid') ? (string) $link->uuid() : (string) $link->id();
    $uri = $safe_public_uri($link->get('link')->uri ?? '');
    $menu_name = (string) ($link->get('menu_name')->value ?? '');
    $add_surface('menu_link', $uuid, [
      'menu' => $menu_name,
      'publicSurface' => isset($public_menus[$menu_name]),
      'uri' => $uri,
    ]);
  }
}
foreach ($config_factory->listAll('system.menu.') as $config_name) {
  $menu_id = substr($config_name, strlen('system.menu.'));
  $add_surface('menu', $menu_id, [
    'configName' => (string) $config_name,
    'publicSurface' => isset($public_menus[$menu_id]),
  ]);
}
if (isset($definitions['redirect'])) {
  $definition = $definitions['redirect'];
  $query = $manager->getStorage('redirect')->getQuery()->accessCheck(FALSE);
  if ($status_key = $definition->getKey('status')) {
    $query->condition($status_key, TRUE);
  }
  foreach ($manager->getStorage('redirect')->loadMultiple($bounded_ids($query, 'Enabled redirect')) as $redirect) {
    $uuid = method_exists($redirect, 'uuid') ? (string) $redirect->uuid() : (string) $redirect->id();
    $source = method_exists($redirect, 'getSourceUrl') ? $safe_public_uri($redirect->getSourceUrl()) : $normalize_path($redirect->get('redirect_source')->path ?? '');
    $target = method_exists($redirect, 'getRedirectUrl') ? $safe_public_uri($redirect->getRedirectUrl()->toString()) : $safe_public_uri($redirect->get('redirect_redirect')->uri ?? '');
    $add_surface('redirect', $uuid, ['source' => $source, 'target' => $target]);
  }
}

// Canvas config entities and published Canvas pages are enumerated by stable
// config names/UUIDs. Component settings and page content are not emitted.
foreach ($config_factory->listAll() as $config_name) {
  if (preg_match('/^(?:canvas|experience_builder)\\.component\\./', $config_name)) {
    $add_surface('canvas_component', $config_name, ['configName' => (string) $config_name]);
  }
  elseif (preg_match('/^(?:canvas|experience_builder)\\.(?:content_template|page_template|page_region)\\./', $config_name)) {
    $config = $config_factory->get($config_name)->getRawData();
    $add_surface('canvas_template', $config_name, [
      'bundle' => (string) ($config['content_entity_type_bundle'] ?? ''),
      'configName' => (string) $config_name,
      'entityType' => (string) ($config['content_entity_type_id'] ?? ''),
      'viewMode' => (string) ($config['content_entity_type_view_mode'] ?? ''),
    ]);
  }
  elseif (preg_match('/^(?:simple_sitemap\\.(?:sitemap|type)\\.|xmlsitemap\\.)/', $config_name)) {
    $add_surface('sitemap', $config_name, ['configName' => (string) $config_name]);
  }
}
if (isset($definitions['canvas_page']) && $definitions['canvas_page'] instanceof \Drupal\Core\Entity\ContentEntityTypeInterface) {
  $definition = $definitions['canvas_page'];
  $query = $manager->getStorage('canvas_page')->getQuery()->accessCheck(FALSE);
  if ($status_key = $definition->getKey('status')) {
    $query->condition($status_key, TRUE);
  }
  foreach ($manager->getStorage('canvas_page')->loadMultiple($bounded_ids($query, 'Published Canvas page')) as $page) {
    $uuid = method_exists($page, 'uuid') ? (string) $page->uuid() : (string) $page->id();
    $path = '';
    try {
      $path = $page->toUrl('canonical')->toString();
    }
    catch (\Throwable) {
      // A missing canonical link remains visible as a page with an empty path.
    }
    $add_surface('canvas_page', $uuid, ['path' => $normalize_path($path)]);
  }
}

// Active custom extensions come from Drupal's installed extension lists.
$custom_extensions = [];
foreach (\Drupal::moduleHandler()->getModuleList() as $machine_name => $extension) {
  $path = str_replace('\\\\', '/', (string) $extension->getPath());
  if (preg_match('#(?:^|/)modules/custom(?:/|$)#', $path)) {
    $custom_extensions[(string) $machine_name] = 'module';
    $add_surface('custom_extension', 'module:' . $machine_name, [
      'machineName' => (string) $machine_name,
      'path' => $path,
      'type' => 'module',
    ]);
  }
}
$installed_themes = $config_factory->get('core.extension')->get('theme') ?? [];
foreach (array_keys(is_array($installed_themes) ? $installed_themes : []) as $machine_name) {
  try {
    $path = str_replace('\\\\', '/', (string) \Drupal::service('extension.list.theme')->getPath($machine_name));
    if (preg_match('#(?:^|/)themes/custom(?:/|$)#', $path)) {
      $custom_extensions[(string) $machine_name] = 'theme';
      $add_surface('custom_extension', 'theme:' . $machine_name, [
        'machineName' => (string) $machine_name,
        'path' => $path,
        'type' => 'theme',
      ]);
    }
  }
  catch (\Throwable) {
    $errors[] = 'Installed custom theme path lookup failed for ' . $machine_name . '.';
  }
}

// The live router is authoritative for sitemap and custom routes. Route paths,
// methods, and owner names are metadata; callbacks and request data are omitted.
try {
  foreach (\Drupal::service('router.route_provider')->getAllRoutes() as $route_name => $route) {
    $route_path = (string) $route->getPath();
    if (preg_match('/sitemap/i', (string) $route_name) || preg_match('#(?:^|/)sitemap(?:[^/]*)?(?:\\.xml)?(?:/|$)#i', $route_path)) {
      $add_surface('sitemap_route', (string) $route_name, [
        'methods' => array_values($route->getMethods()),
        'path' => $route_path,
        'routeName' => (string) $route_name,
      ]);
    }
    $owner = '';
    foreach (['_controller', '_form', '_title_callback'] as $default_key) {
      $definition = (string) ($route->getDefault($default_key) ?? '');
      if (preg_match('/^\\\\?Drupal\\\\([a-z0-9_]+)\\\\/i', $definition, $match) && isset($custom_extensions[$match[1]])) {
        $owner = (string) $match[1];
        break;
      }
    }
    if ($owner === '') {
      foreach ($custom_extensions as $machine_name => $type) {
        if ($type === 'module' && ((string) $route_name === $machine_name || str_starts_with((string) $route_name, $machine_name . '.'))) {
          $owner = (string) $machine_name;
          break;
        }
      }
    }
    if ($owner !== '') {
      $add_surface('custom_route', $owner . ':' . $route_name, [
        'extension' => $owner,
        'methods' => array_values($route->getMethods()),
        'path' => $route_path,
        'routeName' => (string) $route_name,
      ]);
    }
  }
}
catch (\Throwable) {
  $errors[] = 'Live router surface inventory failed.';
}

ksort($items, SORT_STRING);
sort($errors, SORT_STRING);
$counts_by_kind = [];
foreach ($items as $item) {
  $counts_by_kind[$item['kind']] = ($counts_by_kind[$item['kind']] ?? 0) + 1;
}
ksort($counts_by_kind, SORT_STRING);
$fingerprint_input = [
  'items' => array_values($items),
  'publicEditorialRoots' => $public_editorial_roots,
  'countsByKind' => $counts_by_kind,
  'excludedEntityTypes' => $excluded_entity_types,
];
$encoded = json_encode($fingerprint_input, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
print json_encode([
  'schemaVersion' => 'public-kit.drupal-live-surface.1',
  'fingerprint' => 'sha256:' . hash('sha256', $encoded === FALSE ? serialize($fingerprint_input) : $encoded),
  'confirmed' => !$truncated && count($errors) === 0,
  'bounded' => TRUE,
  'limit' => $surface_limit,
  'truncated' => $truncated,
  'itemCount' => count($items),
  'countsByKind' => $counts_by_kind,
  'items' => array_values($items),
  'publicEditorialRoots' => $public_editorial_roots,
  'excludedEntityTypes' => $excluded_entity_types,
  'errors' => $errors,
  'policy' => [
    'metadataOnly' => TRUE,
    'rawContentRowsEmitted' => FALSE,
    'privateEntityRowsQueried' => FALSE,
    'source' => 'active Drupal configuration, published public infrastructure, installed custom extensions, and the live router; clean tracked config is verified separately',
  ],
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
`;

const DRUPAL_ENTITY_INVENTORY_SCHEMA = 'public-kit.drupal-entity-inventory.5';
export const DRUPAL_ENTITY_INVENTORY_EVAL = String.raw`
$manager = \Drupal::entityTypeManager();
$definitions = $manager->getDefinitions();
$live_editorial_roots = isset($live_editorial_roots) && is_array($live_editorial_roots)
  ? $live_editorial_roots
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
foreach ($live_editorial_roots as $entity_type_id => $bundles) {
  $bundles = array_values(array_unique(array_map('strval', is_array($bundles) ? $bundles : [])));
  sort($bundles, SORT_STRING);
  $live_editorial_roots[(string) $entity_type_id] = $bundles;
}
ksort($live_editorial_roots, SORT_STRING);
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
$live_root_keys = [];
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
$missing_live_roots = [];
$bundle_info = \Drupal::service('entity_type.bundle.info');
foreach ($live_editorial_roots as $entity_type_id => $bundles) {
  if (!isset($definitions[$entity_type_id]) || !($definitions[$entity_type_id] instanceof \Drupal\Core\Entity\ContentEntityTypeInterface)) {
    foreach ($bundles as $bundle) {
      $missing_live_roots[] = $entity_type_id . '.' . $bundle;
    }
    continue;
  }
  $definition = $definitions[$entity_type_id];
  $available_bundles = $bundle_info->getBundleInfo($entity_type_id);
  $bundle_key = $definition->getKey('bundle');
  foreach ($bundles as $bundle) {
    if (!isset($available_bundles[$bundle])) {
      $missing_live_roots[] = $entity_type_id . '.' . $bundle;
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
      $live_root_keys[$key] = TRUE;
      $enqueue($entity_type_id, $id, 'live-output-root');
    }
  }
}
sort($missing_live_roots, SORT_STRING);
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
          $is_live_root = isset($live_root_keys[$key]);
          $field_is_public = in_array($field_name, $declared_fields, TRUE);
          $transitive_field = str_starts_with($field_name, 'field_') || $field_name === 'user_picture';
          if (($is_live_root && !$field_is_public) || (!$is_live_root && !$transitive_field)) {
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
  'liveOutputRootCount' => 0,
  'routeCompositionRootCount' => 0,
  'routeNavigationInfrastructureCount' => 0,
  'transitivePublicReferenceCount' => 0,
  'referencedFilePresentationStateCount' => 0,
];
foreach ($roles as $entity_roles) {
  foreach (array_keys($entity_roles) as $role) {
    $role_key = match ($role) {
      'live-output-root' => 'liveOutputRootCount',
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
  'inclusion' => 'Public reference closure rooted in every entity, including drafts and unpublished revisions, from live-derived public editorial bundles, plus entity-backed verified routes/compositions and public route/navigation infrastructure.',
  'liveEditorialRoots' => $live_editorial_roots,
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
  'missingLiveRoots' => $missing_live_roots,
  'policy' => $policy,
  'publicAuthorUserDigest' => $public_author_user_digest,
  'types' => $types,
];
print json_encode([
  'schemaVersion' => 'public-kit.drupal-entity-inventory.5',
  'fingerprint' => 'sha256:' . hash('sha256', $encode($fingerprint_input)),
  'entityTypeCount' => count($types),
  'closureCounts' => $closure_counts,
  'excludedEntityTypes' => $excluded_type_policy,
  'missingLiveRoots' => $missing_live_roots,
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

export function stateBoundRuntimeFacts(facts = {}) {
  const intrinsic = {
    schemaVersion: 'public-kit.drupal-intrinsic-runtime-facts.1',
    coreVersion: facts?.coreVersion ?? '',
    activeConfigEntryCount: facts?.activeConfigEntryCount ?? 0,
    effectiveActiveConfigSha256: facts?.effectiveActiveConfigSha256 ?? '',
    systemSchemaEntryCount: facts?.systemSchemaEntryCount ?? 0,
    systemSchemaSha256: facts?.systemSchemaSha256 ?? '',
    databaseUpdateStatusConfirmed: facts?.databaseUpdateStatusConfirmed === true,
    pendingDatabaseUpdateCount: facts?.pendingDatabaseUpdateCount ?? 0,
    databaseUpdatesPending: facts?.databaseUpdatesPending === true
  };
  const environment = {
    schemaVersion: 'public-kit.drupal-runtime-environment.1',
    phpVersion: facts?.phpVersion ?? '',
    databaseDriver: facts?.databaseDriver ?? '',
    effectiveSettingsEntryCount: facts?.effectiveSettingsEntryCount ?? 0,
    effectiveSettingsHmacSha256: facts?.effectiveSettingsHmacSha256 ?? '',
    configSplitDirectories: Array.isArray(facts?.configSplitDirectories)
      ? [...facts.configSplitDirectories].sort(comparePortable)
      : []
  };
  return {
    intrinsic,
    environmentBinding: {
      schemaVersion: 'public-kit.runtime-environment-binding.1',
      entryCount: Object.keys(environment).length - 1,
      fingerprint: stateSha256(environment)
    }
  };
}

function inspectDrupalLiveSurface(projectRoot, environment) {
  const result = runDrushResult(
    projectRoot,
    environment,
    ['php:eval', DRUPAL_LIVE_SURFACE_EVAL],
    120_000
  );
  if (!result.ok || !result.output) {
    return {
      bounded: true,
      confirmed: false,
      countsByKind: {},
      errors: [],
      fingerprint: '',
      itemCount: 0,
      items: [],
      limit: DRUPAL_LIVE_SURFACE_LIMIT,
      publicEditorialRoots: {},
      reason: 'Drupal live public-surface inventory could not be read through Drush.',
      schemaVersion: DRUPAL_LIVE_SURFACE_SCHEMA,
      truncated: false
    };
  }
  try {
    const inventory = JSON.parse(result.output);
    const items = Array.isArray(inventory?.items) ? inventory.items : [];
    const keys = items.map((item) => String(item?.key ?? ''));
    const structurallyValid =
      inventory?.schemaVersion === DRUPAL_LIVE_SURFACE_SCHEMA &&
      inventory?.bounded === true &&
      inventory?.truncated === false &&
      Number(inventory?.limit) === DRUPAL_LIVE_SURFACE_LIMIT &&
      Number(inventory?.itemCount) === items.length &&
      items.length <= DRUPAL_LIVE_SURFACE_LIMIT &&
      new Set(keys).size === keys.length &&
      items.every((item) =>
        /^[a-z][a-z0-9_]*:.+/.test(String(item?.key ?? '')) &&
        /^[a-z][a-z0-9_]*$/.test(String(item?.kind ?? '')) &&
        String(item.key).startsWith(`${item.kind}:`)
      ) &&
      inventory?.publicEditorialRoots &&
      typeof inventory.publicEditorialRoots === 'object' &&
      !Array.isArray(inventory.publicEditorialRoots) &&
      /^sha256:[a-f0-9]{64}$/.test(String(inventory?.fingerprint ?? ''));
    const confirmed = inventory?.confirmed === true && structurallyValid;
    return {
      ...inventory,
      confirmed,
      reason: confirmed
        ? ''
        : inventory?.truncated === true
          ? `Drupal live public-surface inventory exceeded its ${DRUPAL_LIVE_SURFACE_LIMIT}-item bound.`
          : `Drupal live public-surface inventory was incomplete${Array.isArray(inventory?.errors) && inventory.errors.length ? `: ${inventory.errors.join(' ')}` : '.'}`
    };
  } catch {
    return {
      bounded: true,
      confirmed: false,
      countsByKind: {},
      errors: [],
      fingerprint: '',
      itemCount: 0,
      items: [],
      limit: DRUPAL_LIVE_SURFACE_LIMIT,
      publicEditorialRoots: {},
      reason: 'Drupal live public-surface inventory returned malformed JSON.',
      schemaVersion: DRUPAL_LIVE_SURFACE_SCHEMA,
      truncated: false
    };
  }
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

function inspectDrupalEntityInventory(projectRoot, environment, liveSurfaceInventory, fieldOutputMatrix, routeMatrix, patternMap) {
  const roots = Buffer.from(JSON.stringify(liveSurfaceInventory?.publicEditorialRoots ?? {}), 'utf8').toString('base64');
  const fields = Buffer.from(JSON.stringify(declaredPublicReferenceFields(fieldOutputMatrix)), 'utf8').toString('base64');
  const routes = Buffer.from(JSON.stringify(publicClosureRoutePaths(routeMatrix, patternMap)), 'utf8').toString('base64');
  const evaluation = [
    `$live_editorial_roots = json_decode(base64_decode('${roots}', TRUE), TRUE);`,
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
      Array.isArray(inventory?.missingLiveRoots) &&
      inventory.missingLiveRoots.length === 0 &&
      Number(inventory?.missingManagedFileCount ?? 0) === 0 &&
      !authorDigestError &&
      typeErrors.length === 0;
    return {
      ...inventory,
      confirmed,
      reason: confirmed
        ? ''
        : `Drupal entity inventory was incomplete${typeErrors.length ? ` for: ${typeErrors.join(', ')}` : ''}${authorDigestError ? '; public author digest failed' : ''}${Array.isArray(inventory?.missingLiveRoots) && inventory.missingLiveRoots.length ? `; live-derived roots were missing: ${inventory.missingLiveRoots.join(', ')}` : ''}${Number(inventory?.missingManagedFileCount ?? 0) > 0 ? `; ${inventory.missingManagedFileCount} managed files were unreadable` : ''}.`
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

function nonEmptyPacketFile(packetDir, reference, { requireFragment = false, evidenceOnly = false } = {}) {
  const text = String(reference ?? '').trim();
  const hashIndex = text.indexOf('#');
  const relativePath = (hashIndex === -1 ? text : text.slice(0, hashIndex)).replaceAll('\\', '/');
  const fragment = hashIndex === -1 ? '' : text.slice(hashIndex + 1).trim();
  if (
    !relativePath ||
    isAbsolute(relativePath) ||
    relativePath.split('/').includes('..') ||
    (requireFragment && !fragment) ||
    (requireFragment && relativePath === 'drupal-readback.json' && fragment.startsWith('liveSurfaceReconciliation')) ||
    (evidenceOnly && !relativePath.startsWith('evidence/'))
  ) {
    return false;
  }
  const packetRoot = resolve(packetDir);
  const candidate = resolve(packetRoot, relativePath);
  if (!pathIsInside(packetRoot, candidate) || !existsSync(candidate)) {
    return false;
  }
  try {
    const realPacketRoot = realpathSync(packetRoot);
    const realCandidate = realpathSync(candidate);
    return pathIsInside(realPacketRoot, realCandidate) && statSync(realCandidate).isFile() && statSync(realCandidate).size > 0;
  } catch {
    return false;
  }
}

export function liveSurfaceReconciliationErrors(liveInventory, reconciliation, packetDir) {
  const errors = [];
  const push = (message) => {
    if (errors.length < 200) {
      errors.push(message);
    } else if (errors.length === 200) {
      errors.push('Live public-surface reconciliation produced more than 200 errors; remaining errors were bounded.');
    }
  };
  if (liveInventory?.confirmed !== true) {
    push(liveInventory?.reason || 'The live-derived Drupal public-surface inventory did not complete.');
    return errors;
  }
  if (!reconciliation || typeof reconciliation !== 'object' || Array.isArray(reconciliation)) {
    push('drupal-readback.json liveSurfaceReconciliation must be an object.');
    return errors;
  }
  if (reconciliation.schemaVersion !== 'public-kit.live-surface-reconciliation.1') {
    push('drupal-readback.json liveSurfaceReconciliation must use schemaVersion public-kit.live-surface-reconciliation.1.');
  }
  if (reconciliation.reconciliationComplete !== true || (Array.isArray(reconciliation.blockers) && reconciliation.blockers.length > 0)) {
    push('drupal-readback.json liveSurfaceReconciliation must be complete with no blockers.');
  }
  if (String(reconciliation.inventoryFingerprint ?? '') !== String(liveInventory.fingerprint ?? '')) {
    push('drupal-readback.json liveSurfaceReconciliation inventoryFingerprint does not match the current live-derived Drupal surface.');
  }
  const expectedCounts = liveInventory?.countsByKind && typeof liveInventory.countsByKind === 'object'
    ? liveInventory.countsByKind
    : {};
  const recordedCounts = reconciliation?.countsByKind && typeof reconciliation.countsByKind === 'object'
    ? reconciliation.countsByKind
    : {};
  const normalizedCounts = (counts) => Object.fromEntries(
    Object.entries(counts)
      .map(([kind, count]) => [String(kind), Number(count)])
      .sort(([left], [right]) => comparePortable(left, right))
  );
  if (JSON.stringify(normalizedCounts(recordedCounts)) !== JSON.stringify(normalizedCounts(expectedCounts))) {
    push('drupal-readback.json liveSurfaceReconciliation countsByKind does not exactly match the live-derived Drupal surface.');
  }

  const declarations = Array.isArray(reconciliation.declarations) ? reconciliation.declarations : [];
  const exclusions = Array.isArray(reconciliation.exclusions) ? reconciliation.exclusions : [];
  const liveItems = Array.isArray(liveInventory.items) ? liveInventory.items : [];
  const liveByKey = new Map(liveItems.map((item) => [String(item?.key ?? ''), item]));
  const declaredByKey = new Map();
  const excludedByKey = new Map();
  for (const [index, declaration] of declarations.entries()) {
    const key = String(declaration?.key ?? '').trim();
    if (!key || declaredByKey.has(key)) {
      push(`drupal-readback.json liveSurfaceReconciliation declarations[${index}] has a missing or duplicate key.`);
      continue;
    }
    declaredByKey.set(key, declaration);
    const references = Array.isArray(declaration?.packetReferences) ? declaration.packetReferences : [];
    if (
      references.length === 0 ||
      references.some((reference) => !nonEmptyPacketFile(packetDir, reference, { requireFragment: true }))
    ) {
      push(`Declared live surface ${key} must reference a non-empty packet artifact and a specific section using file#fragment.`);
    }
  }
  for (const [index, exclusion] of exclusions.entries()) {
    const key = String(exclusion?.key ?? '').trim();
    if (!key || excludedByKey.has(key)) {
      push(`drupal-readback.json liveSurfaceReconciliation exclusions[${index}] has a missing or duplicate key.`);
      continue;
    }
    excludedByKey.set(key, exclusion);
    const evidence = Array.isArray(exclusion?.evidence) ? exclusion.evidence : [];
    if (
      !String(exclusion?.owner ?? '').trim() ||
      !String(exclusion?.rationale ?? '').trim() ||
      evidence.length === 0 ||
      evidence.some((reference) => !nonEmptyPacketFile(packetDir, reference, { evidenceOnly: true }))
    ) {
      push(`Excluded live surface ${key} requires a named owner, rationale, and non-empty packet-local evidence under evidence/.`);
    }
  }

  for (const [key, item] of liveByKey) {
    const declaration = declaredByKey.get(key);
    const exclusion = excludedByKey.get(key);
    if (!declaration && !exclusion) {
      push(`Live-only ${item?.kind || 'surface'} ${key} is omitted from drupal-readback.json liveSurfaceReconciliation.`);
      continue;
    }
    if (declaration && exclusion) {
      push(`Live surface ${key} is both declared and excluded; it must have exactly one disposition.`);
      continue;
    }
    if (declaration && (item?.publicSurface === false || item?.publicEditorialRoot === false)) {
      push(`Live surface ${key} is classified non-public and therefore requires an owned evidence-backed exclusion, not a declaration.`);
    }
    const disposition = declaration ?? exclusion;
    if (String(disposition?.kind ?? '') !== String(item?.kind ?? '')) {
      push(`Live surface ${key} has kind ${item?.kind || '(missing)'} but the packet records ${disposition?.kind || '(missing)'}.`);
    }
  }
  for (const [key] of [...declaredByKey, ...excludedByKey]) {
    if (!liveByKey.has(key)) {
      push(`Packet-only live surface ${key} is not present in the current Drupal census.`);
    }
  }
  return errors;
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

function yamlFilesOnDisk(projectRoot, roots) {
  const pending = Array.isArray(roots) ? [...roots] : [roots];
  const files = new Set();
  let entriesChecked = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      entriesChecked += 1;
      if (entriesChecked > 20_000) {
        throw new Error('Config sync exceeds the 20,000-entry verification limit.');
      }
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`Config sync contains a symbolic link: ${relative(projectRoot, path)}`);
      }
      if (entry.isDirectory()) {
        pending.push(path);
      } else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
        files.add(relative(projectRoot, path).split(sep).join('/'));
      }
    }
  }
  return [...files].sort(comparePortable);
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
      matchesHead: false,
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
      .sort(comparePortable);
    const allYamlFiles = yamlFilesOnDisk(projectRoot, directories);
    const trackedSet = new Set(yamlFiles);
    const untrackedYamlFiles = allYamlFiles.filter((path) => !trackedSet.has(path));
    const configManifest = collectFileManifest(projectRoot, allYamlFiles);
    let matchesHead = false;
    if (yamlFiles.length > 0) {
      try {
        const headOutput = execFileSync('git', ['ls-tree', '-r', '--name-only', 'HEAD', '--', ...relativeDirectories], {
          cwd: projectRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 10_000
        });
        const headYamlFiles = headOutput
          .split(/\r?\n/)
          .map((path) => path.trim())
          .filter((path) => /\.ya?ml$/i.test(path))
          .sort(comparePortable);
        const status = execFileSync(
          'git',
          ['status', '--porcelain=v1', '--untracked-files=all', '--', ...relativeDirectories],
          {
            cwd: projectRoot,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 10_000
          }
        );
        matchesHead =
          status.length === 0 &&
          allYamlFiles.length === headYamlFiles.length &&
          allYamlFiles.every((path, index) => path === headYamlFiles[index]);
      } catch {
        matchesHead = false;
      }
    }
    return {
      allYamlFiles,
      confirmed: yamlFiles.length > 0 && missingConfigSplitDirectories.length === 0,
      configManifest,
      configSplitDirectories: relativeDirectories.slice(1),
      directory,
      matchesHead,
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
      matchesHead: false,
      missingConfigSplitDirectories,
      untrackedYamlFiles: [],
      yamlFiles: []
    };
  }
}

function stripYamlComment(line) {
  let singleQuoted = false;
  let doubleQuoted = false;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (doubleQuoted && escaped) {
      escaped = false;
      continue;
    }
    if (doubleQuoted && character === '\\') {
      escaped = true;
      continue;
    }
    if (!doubleQuoted && character === "'") {
      if (singleQuoted && line[index + 1] === "'") {
        index += 1;
        continue;
      }
      singleQuoted = !singleQuoted;
      continue;
    }
    if (!singleQuoted && character === '"') {
      doubleQuoted = !doubleQuoted;
      continue;
    }
    if (!singleQuoted && !doubleQuoted && character === '#' && (index === 0 || /\s/.test(line[index - 1]))) {
      return line.slice(0, index);
    }
  }
  return line;
}

function yamlMappingColon(value) {
  let singleQuoted = false;
  let doubleQuoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (doubleQuoted && escaped) {
      escaped = false;
      continue;
    }
    if (doubleQuoted && character === '\\') {
      escaped = true;
      continue;
    }
    if (!doubleQuoted && character === "'") {
      if (singleQuoted && value[index + 1] === "'") {
        index += 1;
        continue;
      }
      singleQuoted = !singleQuoted;
      continue;
    }
    if (!singleQuoted && character === '"') {
      doubleQuoted = !doubleQuoted;
      continue;
    }
    if (
      !singleQuoted &&
      !doubleQuoted &&
      character === ':' &&
      (index === value.length - 1 || /\s/.test(value[index + 1]))
    ) {
      return index;
    }
  }
  return -1;
}

function yamlScalarValues(content) {
  const values = [];
  let blockScalar = null;
  let currentKey = '';
  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    const indentation = rawLine.match(/^\s*/)?.[0].length ?? 0;
    if (blockScalar) {
      if (!rawLine.trim() || indentation > blockScalar.indentation) {
        if (rawLine.trim()) {
          values.push({ key: blockScalar.key, line: index + 1, value: rawLine.trim() });
        }
        continue;
      }
      blockScalar = null;
    }

    const uncommented = stripYamlComment(rawLine);
    const trimmed = uncommented.trim();
    if (!trimmed || trimmed.startsWith('---') || trimmed.startsWith('...')) {
      continue;
    }
    const sequenceValue = trimmed.startsWith('- ') ? trimmed.slice(2).trim() : trimmed;
    const colon = yamlMappingColon(sequenceValue);
    if (colon === -1) {
      if (trimmed.startsWith('- ') && sequenceValue) {
        values.push({ key: currentKey, line: index + 1, value: sequenceValue });
      }
      continue;
    }
    const key = sequenceValue.slice(0, colon).trim().replace(/^['"]|['"]$/g, '');
    const scalar = sequenceValue.slice(colon + 1).trim();
    currentKey = key || currentKey;
    if (/^[>|][+-]?\d*$/.test(scalar)) {
      blockScalar = { indentation, key: currentKey };
    } else if (scalar) {
      values.push({ key: currentKey, line: index + 1, value: scalar });
    }
  }
  return values;
}

export function exportedSeoUrlPortabilityFindings(
  projectRoot,
  trackedYamlFiles,
  targetBaseUrl = '',
  targetOriginIsAuthoritativeRuntime = false,
  authoritativeRuntimeOrigins = []
) {
  const targetOrigins = new Set((Array.isArray(authoritativeRuntimeOrigins) ? authoritativeRuntimeOrigins : [])
    .map((origin) => String(origin).trim()).filter(Boolean));
  try {
    if (targetBaseUrl) {
      targetOrigins.add(new URL(targetBaseUrl).origin);
    }
  } catch {
    // Existing target validation reports malformed URLs separately.
  }
  const findings = [];
  for (const file of trackedYamlFiles) {
    const name = basename(file);
    if (!/^metatag\.metatag_defaults\..+\.ya?ml$/i.test(name) && !/^schema_metatag\..+\.ya?ml$/i.test(name)) {
      continue;
    }
    let content = '';
    try {
      content = readFileSync(join(projectRoot, file), 'utf8');
    } catch {
      continue;
    }
    for (const scalar of yamlScalarValues(content)) {
      for (const match of scalar.value.matchAll(/https?:\/\/[^\s'"<>]+/gi)) {
        try {
          const url = new URL(match[0].replace(/[\])},.;]+$/, ''));
          if (
            isLocalEnvironmentHost(url.hostname) ||
            (targetOriginIsAuthoritativeRuntime && targetOrigins.has(url.origin))
          ) {
            findings.push({
              file,
              host: url.host,
              key: scalar.key,
              line: scalar.line
            });
          }
        } catch {
          // Rendered metadata validation handles malformed public URLs.
        }
      }
    }
  }
  return findings;
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

function inspectDrupalRuntime(cwd, environment, fieldOutputMatrix, routeMatrix, patternMap) {
  const projectRoot = findDrupalDdevRoot(cwd);
  if (!projectRoot) {
    return {
      baseUrl: '',
      confirmed: false,
      configStatusClean: false,
      configSyncMatchesHead: false,
      configSyncTracked: false,
      configSyncDirectory: '',
      configManifest: null,
      configSplitDirectories: [],
      liveSurfaceInventory: {
        bounded: true,
        confirmed: false,
        countsByKind: {},
        errors: [],
        fingerprint: '',
        itemCount: 0,
        items: [],
        limit: DRUPAL_LIVE_SURFACE_LIMIT,
        publicEditorialRoots: {},
        reason: 'Drupal runtime is unavailable.',
        schemaVersion: DRUPAL_LIVE_SURFACE_SCHEMA,
        truncated: false
      },
      drushCommandFailures: [],
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
      identityReadbackFailed: false,
      mode: 'unavailable',
      reason: 'Current working directory is not inside a DDEV Drupal project.',
      siteUuid: '',
      trackedConfigDirectory: '',
      missingConfigSplitDirectories: [],
      trackedConfigYamlFiles: [],
      untrackedConfigYamlFiles: [],
      exportedSeoUrlPortabilityFindings: [],
      webOrigins: []
    };
  }
  const inContainer = ddevContainerContext(projectRoot, environment);
  const drushCommandFailures = [];
  const readDrush = (args) => {
    const result = runDrushResult(projectRoot, environment, args);
    if (!result.ok) {
      drushCommandFailures.push(describeDrushFailure(result.failure ?? { argv: ['drush', ...args] }));
    }
    return result;
  };
  const bootstrapResult = readDrush(['status', '--field=bootstrap']);
  // Drush 13 removed `config:get --field`; the key-argument form works on Drush 12 and 13.
  const uuidResult = readDrush(['config:get', 'system.site', 'uuid', '--format=string']);
  const frontPage = cleanScalar(
    readDrush(['config:get', 'system.site', 'page.front', '--format=string']).output
  );
  const configSyncDirectory = cleanScalar(readDrush(['status', '--field=config-sync']).output);
  const drupalRoot = cleanScalar(readDrush(['status', '--field=root']).output);
  const configStatus = readDrush(['config:status', '--format=json']);
  const runtimeFacts = inspectDrupalRuntimeFacts(projectRoot, environment);
  const trackedConfig = trackedConfigEvidence(
    projectRoot,
    configSyncDirectory,
    drupalRoot,
    runtimeFacts?.configSplitDirectories
  );
  const liveSurfaceInventory = inspectDrupalLiveSurface(projectRoot, environment);
  const entityInventory = inspectDrupalEntityInventory(
    projectRoot,
    environment,
    liveSurfaceInventory,
    fieldOutputMatrix,
    routeMatrix,
    patternMap
  );
  const siteUuid = uuidResult.output.match(UUID_RE)?.[0]?.toLowerCase() ?? '';
  const confirmed = /successful/i.test(bootstrapResult.output) && Boolean(siteUuid);
  const identityReadbackFailed = !bootstrapResult.ok || !uuidResult.ok;
  const describedTarget = inContainer
    ? { primaryUrl: environmentTargetUrl(environment), webOrigins: environmentWebOrigins(environment) }
    : ddevTargetDescription(projectRoot, environment);
  const baseUrl = describedTarget.primaryUrl;
  const webOrigins = new Set(describedTarget.webOrigins);
  try {
    if (baseUrl) {
      webOrigins.add(parseHttpUrl(baseUrl, 'Current DDEV runtime base URL').origin);
    }
  } catch {
    // Runtime identity validation reports an unusable primary URL separately.
  }
  const seoUrlFindings = exportedSeoUrlPortabilityFindings(
    projectRoot,
    trackedConfig.yamlFiles,
    baseUrl,
    true,
    [...webOrigins]
  );
  return {
    baseUrl,
    confirmed,
    configStatusClean: configStatusIsClean(configStatus),
    configSyncMatchesHead: trackedConfig.matchesHead,
    configSyncTracked: trackedConfig.confirmed,
    configSyncDirectory,
    configManifest: trackedConfig.configManifest,
    configSplitDirectories: trackedConfig.configSplitDirectories,
    drupalRoot,
    entityInventory,
    liveSurfaceInventory,
    runtimeFacts,
    drushCommandFailures,
    frontPage,
    identityReadbackFailed,
    mode: inContainer ? 'ddev-container' : 'ddev-host',
    project: basename(projectRoot),
    reason: confirmed
      ? ''
      : drushCommandFailures.length > 0
        ? `Drush runtime inspection command failed: ${drushCommandFailures[0]}`
        : 'Drupal did not bootstrap or expose a valid system.site UUID through Drush.',
    siteUuid,
    trackedConfigDirectory: trackedConfig.directory,
    missingConfigSplitDirectories: trackedConfig.missingConfigSplitDirectories,
    trackedConfigYamlFiles: trackedConfig.yamlFiles,
    untrackedConfigYamlFiles: trackedConfig.untrackedYamlFiles,
    exportedSeoUrlPortabilityFindings: seoUrlFindings,
    webOrigins: [...webOrigins]
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

function environmentWebOrigins(environment) {
  const origins = new Set();
  for (const key of ['DDEV_PRIMARY_URL', 'DDEV_PRIMARY_URLS']) {
    for (const candidate of stringValues(environment[key])) {
      try {
        origins.add(parseHttpUrl(candidate, key).origin);
      } catch {
        // Invalid environment URLs cannot become authoritative origins.
      }
    }
  }
  return [...origins];
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

function matchingRouteRecord(routeMatrix, targetPath, exactRequest = '') {
  return (Array.isArray(routeMatrix.routes) ? routeMatrix.routes : []).find(
    (route) => exactRequest
      ? requestPathAndSearch(route?.targetPath) === exactRequest
      : normalizePath(route?.targetPath) === targetPath
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

function expectedRenderedSeo(browserEvidence, targetPath, requestTarget = '') {
  const requestKey = requestPathAndSearch(requestTarget);
  const records = (Array.isArray(browserEvidence?.publicRouteChecks) ? browserEvidence.publicRouteChecks : [])
    .filter((check) => [check?.targetUrl, check?.targetFinalUrl].some((url) =>
      requestKey ? requestPathAndSearch(url) === requestKey : normalizePath(url) === targetPath
    ))
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
  const requestTarget = requestPathAndSearch(primaryRoute?.targetPath || primaryRoute?.sourcePath);
  const targetPath = normalizePath(requestTarget);
  const record = matchingRouteRecord(routeMatrix, targetPath, requestTarget) ?? {};
  const homepage = targetPath === '/' ? routeMatrix.homepageParity ?? {} : {};
  const declaredStatus = record.targetStatus;
  const expectedStatus = declaredStatus !== null && declaredStatus !== '' && Number.isFinite(Number(declaredStatus))
    ? Number(declaredStatus)
    : 200;
  return {
    accepted: primaryRoute?.accepted === true,
    expectedBehavior: record.expectedRedirect === true ? 'redirect' : 'public_200',
    expectedFinalPath: normalizePath(record.targetFinalPath || homepage.targetFinalPath || targetPath),
    expectedFinalRequest: requestPathAndSearch(record.targetFinalPath || homepage.targetFinalPath || requestTarget),
    expectedH1: normalizeText(record.targetH1 || homepage.targetH1),
    expectedStatus,
    expectedTitle: normalizeText(record.targetTitle || homepage.targetTitle),
    identityRequired: true,
    matchesBrowserRenderedSource: primaryRoute?.matchesBrowserRenderedSource === true,
    renderedSeo: expectedRenderedSeo(browserEvidence, targetPath, requestTarget),
    requestTarget,
    routeKind: 'primary',
    statusUsesInitialResponse: record.expectedRedirect === true,
    targetPath
  };
}

function expectedBrowserRepresentativeRoute(routeMatrix, check, browserEvidence) {
  const requestTarget = requestPathAndSearch(check?.targetUrl || check?.targetFinalUrl);
  const expectedFinalRequest = requestPathAndSearch(check?.targetFinalUrl || check?.targetUrl);
  const targetPath = normalizePath(requestTarget);
  const record = matchingRouteRecord(routeMatrix, targetPath) ?? {};
  const declaredStatus = record.targetStatus;
  const expectedStatus = declaredStatus !== null && declaredStatus !== '' && Number.isFinite(Number(declaredStatus))
    ? Number(declaredStatus)
    : 200;
  return {
    accepted: check?.accepted === true && Boolean(record.targetPath),
    expectedBehavior: record.expectedRedirect === true ? 'redirect' : 'public_200',
    expectedFinalPath: normalizePath(record.targetFinalPath || targetPath),
    expectedFinalRequest,
    expectedH1: normalizeText(record.targetH1 || check?.renderedSignals?.targetH1),
    expectedStatus,
    expectedTitle: normalizeText(record.targetTitle || check?.renderedSignals?.targetTitle),
    identityRequired: true,
    matchesBrowserRenderedSource: true,
    renderedSeo: expectedRenderedSeo(browserEvidence, targetPath, requestTarget),
    requestTarget,
    routeKind: 'browser-representative',
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

function packetLocalEvidencePresent(packetDir, value) {
  const evidence = String(value ?? '').trim();
  if (!evidence || isAbsolute(evidence)) {
    return false;
  }
  try {
    const packetRoot = realpathSync(packetDir);
    for (const candidate of [resolve(packetRoot, 'evidence', evidence), resolve(packetRoot, evidence)]) {
      try {
        const evidencePath = realpathSync(candidate);
        const evidenceStat = statSync(evidencePath);
        if (pathIsInside(packetRoot, evidencePath) && evidenceStat.isFile() && evidenceStat.size > 0) {
          return true;
        }
      } catch {
        // Try the other packet-local evidence convention.
      }
    }
    return false;
  } catch {
    return false;
  }
}

function normalizedNoRedirectDisposition(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }
  return {
    accepted: value.accepted === true,
    acceptedBy: String(value.acceptedBy ?? '').trim(),
    evidence: String(value.evidence ?? '').trim(),
    rationale: String(value.rationale ?? '').trim()
  };
}

function redirectMaterializationExpectations(routeMatrix, packetDir, baseUrl) {
  const conflicts = [];
  const expectations = new Map();
  const addExpectation = ({ declaredIn, noRedirectDisposition, sourceRequest, expectedFinalRequest }) => {
    const contract = {
      expectedFinalRequest,
      noRedirectDisposition: normalizedNoRedirectDisposition(noRedirectDisposition)
    };
    const signature = JSON.stringify(contract);
    const existing = expectations.get(sourceRequest);
    if (existing) {
      existing.declaredIn.add(declaredIn);
      if (existing.signature !== signature) {
        conflicts.push(
          `Duplicate redirect mapping contracts for ${redactedPath(sourceRequest, baseUrl)} do not fully agree; reconcile target path+query and noRedirectDisposition across ${[...existing.declaredIn].sort().join(', ')}.`
        );
      }
      return;
    }
    expectations.set(sourceRequest, {
      ...contract,
      declaredIn: new Set([declaredIn]),
      signature,
      sourceRequest
    });
  };

  for (const row of Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : []) {
    const sourceRequest = requestPathAndSearch(row?.sourcePath);
    const targetRequest = requestPathAndSearch(row?.targetPath);
    const expectedFinalRequest = requestPathAndSearch(row?.targetFinalPath || row?.targetPath);
    if (!sourceRequest || !targetRequest || !expectedFinalRequest || sourceRequest === targetRequest) {
      continue;
    }
    addExpectation({
      declaredIn: 'routes',
      expectedFinalRequest,
      noRedirectDisposition: row?.noRedirectDisposition,
      sourceRequest
    });
  }
  for (const record of Array.isArray(routeMatrix?.sourceRouteDriftClassification)
    ? routeMatrix.sourceRouteDriftClassification
    : []) {
    const sourceRequest = requestPathAndSearch(record?.sourcePath);
    const targetRequest = requestPathAndSearch(record?.targetPath);
    if (
      record?.targetDisposition !== 'redirect' ||
      !sourceRequest ||
      !targetRequest ||
      sourceRequest === targetRequest
    ) {
      continue;
    }
    addExpectation({
      declaredIn: 'sourceRouteDriftClassification',
      expectedFinalRequest: targetRequest,
      noRedirectDisposition: record?.noRedirectDisposition,
      sourceRequest
    });
  }

  return {
    conflicts,
    expectations: [...expectations.values()].map((expectation) => {
      const disposition = expectation.noRedirectDisposition;
      const dispositionAccepted = Boolean(
        disposition?.accepted === true &&
        disposition.acceptedBy &&
        disposition.rationale &&
        packetLocalEvidencePresent(packetDir, disposition.evidence)
      );
      return {
        declaredIn: [...expectation.declaredIn].sort(),
        expectedFinalRequest: expectation.expectedFinalRequest,
        noRedirectDisposition: dispositionAccepted ? disposition : null,
        sourceRequest: expectation.sourceRequest
      };
    })
  };
}

async function verifyRedirectMaterialization(baseUrl, expectation, liveHttpContext) {
  const sourceLabel = redactedPath(expectation.sourceRequest, baseUrl);
  const finalLabel = redactedPath(expectation.expectedFinalRequest, baseUrl);
  const shared = {
    declaredIn: expectation.declaredIn,
    expectedFinalPath: finalLabel,
    sourcePath: sourceLabel
  };
  if (expectation.noRedirectDisposition) {
    return {
      ...shared,
      checked: false,
      errors: [],
      noRedirectDisposition: {
        accepted: true,
        acceptedBy: expectation.noRedirectDisposition.acceptedBy,
        evidence: expectation.noRedirectDisposition.evidence,
        rationaleSha256: `sha256:${sha256(expectation.noRedirectDisposition.rationale)}`
      },
      passed: true
    };
  }
  const errors = [];
  try {
    const response = await requestFollowingRedirects(
      new URL(expectation.sourceRequest.replace(/^\//, ''), new URL('/', baseUrl)),
      { liveHttpContext }
    );
    if (![301, 308].includes(response.initialStatus)) {
      errors.push(
        `${sourceLabel} is mapped to ${finalLabel} in ${expectation.declaredIn.join(', ')} but returned initial status ${response.initialStatus}; materialize a permanent HTTP 301 or 308 redirect or record a fully accepted, evidenced noRedirectDisposition.`
      );
    }
    const finalUrl = new URL(response.finalUrl);
    if (finalUrl.origin !== baseUrl.origin) {
      errors.push(`${sourceLabel} left the target origin instead of resolving to ${finalLabel}.`);
    }
    if (requestPathAndSearch(finalUrl) !== expectation.expectedFinalRequest) {
      errors.push(
        `${sourceLabel} resolved to ${redactedPath(finalUrl, baseUrl)}; the declared mapping expects exact path+query ${finalLabel}.`
      );
    }
    return {
      ...shared,
      checked: true,
      errors,
      finalPath: redactedPath(finalUrl, baseUrl),
      initialStatus: response.initialStatus,
      passed: errors.length === 0,
      redirects: response.redirects.map((redirect) => ({
        from: redactedUrl(redirect.from),
        status: redirect.status,
        to: redactedUrl(redirect.to)
      }))
    };
  } catch (error) {
    errors.push(`${sourceLabel} is mapped to ${finalLabel} but could not be verified on the target: ${error.message}`);
    return { ...shared, checked: true, errors, passed: false };
  }
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

export function localOnlyFormExceptionsBoundToRuntime(browserEvidence, targetUrl, runtimeOrigins) {
  const checks = (Array.isArray(browserEvidence?.anonymousFormChecks)
    ? browserEvidence.anonymousFormChecks
    : []).filter((check) => check?.abuseProtection?.mode === 'local_only_exception');
  if (checks.length === 0) {
    return true;
  }
  try {
    const target = parseHttpUrl(String(targetUrl), 'Live target URL');
    const origins = new Set((Array.isArray(runtimeOrigins) ? runtimeOrigins : [runtimeOrigins])
      .map((value) => parseHttpUrl(String(value), 'Current DDEV runtime web URL').origin));
    return origins.has(target.origin) && checks.every((check) =>
      origins.has(parseHttpUrl(String(check?.targetUrl), 'Local-only form target URL').origin)
    );
  } catch {
    return false;
  }
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
  for (const [index, check] of (Array.isArray(browserEvidence?.anonymousFormChecks)
    ? browserEvidence.anonymousFormChecks
    : []).entries()) {
    requiredOriginMatch(
      errors,
      `browser-evidence.json anonymousFormChecks[${index}].targetUrl`,
      check?.targetUrl,
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

async function verifyRoute(baseUrl, expected, liveHttpContext) {
  const requestTarget = expected.requestTarget || expected.targetPath;
  const requestedUrl = new URL(requestTarget.replace(/^\//, ''), new URL('/', baseUrl));
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
    const response = await requestFollowingRedirects(requestedUrl, { liveHttpContext });
    const actualH1 = elementText(response.body, 'h1');
    const actualTitle = elementText(response.body, 'title');
    const actualMetadata = renderedMetadata(response.body, response.finalUrl);
    const intrinsicSemantics = intrinsicRouteSemantics(response.body, response.finalUrl);
    const actualStatus = expected.statusUsesInitialResponse ? response.initialStatus : response.status;
    if (actualStatus !== expected.expectedStatus) {
      errors.push(`${expected.targetPath} returned status ${actualStatus}; expected ${expected.expectedStatus}.`);
    }
    if (normalizePath(response.finalUrl) !== expected.expectedFinalPath) {
      errors.push(
        `${expected.targetPath} resolved to ${normalizePath(response.finalUrl)}; expected ${expected.expectedFinalPath}.`
      );
    }
    if (
      expected.expectedFinalRequest &&
      requestPathAndSearch(response.finalUrl) !== expected.expectedFinalRequest
    ) {
      const stateKind = expected.routeKind === 'primary' ? 'primary' : 'representative';
      errors.push(
        `${expected.targetPath} resolved to ${redactedPath(response.finalUrl, baseUrl)}; expected exact ${stateKind} state ${redactedPath(expected.expectedFinalRequest, baseUrl)}.`
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
          errors.push(`${expected.targetPath} rendered canonical ${redactedUrl(actualMetadata.canonicalUrl)} does not match browser evidence ${redactedUrl(seo.canonicalUrl)}.`);
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
      expectedFinalRequest: expected.expectedFinalRequest
        ? redactedPath(expected.expectedFinalRequest, baseUrl)
        : undefined,
      requestTarget: expected.requestTarget ? redactedPath(expected.requestTarget, baseUrl) : undefined,
      actualH1,
      actualMetadata: {
        ...actualMetadata,
        canonicalUrl: actualMetadata.canonicalUrl ? redactedUrl(actualMetadata.canonicalUrl) : '',
        openGraphImage: actualMetadata.openGraphImage ? redactedUrl(actualMetadata.openGraphImage) : ''
      },
      actualTitle,
      bodySha256: `sha256:${sha256(response.body)}`,
      intrinsicSemantics,
      errors,
      finalStatus: response.status,
      finalUrl: redactedUrl(response.finalUrl),
      initialStatus: response.initialStatus,
      localTlsVerificationBypassed: response.localTlsVerificationBypassed,
      passed: errors.length === 0,
      redirects: response.redirects.map((redirect) => ({
        from: redactedUrl(redirect.from),
        status: redirect.status,
        to: redactedUrl(redirect.to)
      })),
      renderedSeo: expected.renderedSeo
        ? {
            ...expected.renderedSeo,
            canonicalUrl: expected.renderedSeo.canonicalUrl
              ? redactedUrl(expected.renderedSeo.canonicalUrl)
              : '',
            openGraphImage: expected.renderedSeo.openGraphImage
              ? redactedUrl(expected.renderedSeo.openGraphImage)
              : ''
          }
        : null,
      requestedUrl: redactedUrl(requestedUrl)
    };
  } catch (error) {
    errors.push(`${expected.targetPath} could not be fetched: ${error.message}`);
    return {
      ...expected,
      expectedFinalRequest: expected.expectedFinalRequest
        ? redactedPath(expected.expectedFinalRequest, baseUrl)
        : undefined,
      requestTarget: expected.requestTarget ? redactedPath(expected.requestTarget, baseUrl) : undefined,
      errors,
      passed: false,
      renderedSeo: expected.renderedSeo
        ? {
            ...expected.renderedSeo,
            canonicalUrl: expected.renderedSeo.canonicalUrl
              ? redactedUrl(expected.renderedSeo.canonicalUrl)
              : '',
            openGraphImage: expected.renderedSeo.openGraphImage
              ? redactedUrl(expected.renderedSeo.openGraphImage)
              : ''
          }
        : null,
      requestedUrl: redactedUrl(requestedUrl)
    };
  }
}

export async function scheduleLiveRouteChecks({
  baseUrl,
  tasks = [],
  allowRuntimeBoundLocalCertificate = false,
  maxRoutes = MAX_LIVE_ROUTE_CHECKS,
  concurrency = MAX_LIVE_ROUTE_CONCURRENCY,
  deadlineMs = LIVE_ROUTE_DEADLINE_MS,
  maxRequests = MAX_LIVE_HTTP_REQUESTS,
  liveHttpContext = null
} = {}) {
  const routeTasks = Array.isArray(tasks) ? tasks : [];
  const errors = [];
  const numericLimits = { concurrency, deadlineMs, maxRequests, maxRoutes };
  for (const [name, value] of Object.entries(numericLimits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      errors.push(`Live route verification ${name} must be a positive safe integer.`);
    }
  }
  if (errors.length > 0) {
    return {
      checks: [],
      errors,
      budget: {
        attempted: false,
        deadlineMs,
        maxConcurrency: concurrency,
        maxRequests,
        maxRoutes,
        requestCount: 0,
        routeCount: routeTasks.length
      }
    };
  }
  if (routeTasks.length > maxRoutes) {
    return {
      checks: [],
      errors: [
        `Live route verification requires ${routeTasks.length} checks, exceeding the ${maxRoutes} route limit; no routes were fetched.`
      ],
      budget: {
        attempted: false,
        deadlineMs,
        maxConcurrency: concurrency,
        maxRequests,
        maxRoutes,
        requestCount: 0,
        routeCount: routeTasks.length
      }
    };
  }

  const context = liveHttpContext ?? createLiveHttpContext({
    allowRuntimeBoundLocalCertificate,
    concurrency,
    deadlineMs,
    maxRequests,
    maxTasks: maxRoutes
  });
  const checks = await Promise.all(routeTasks.map(async (task) => {
    const kind = task.bucket === 'primary'
      ? 'primary-route'
      : task.bucket === 'target-required'
        ? 'target-required-route'
        : 'browser-representative-route';
    try {
      return {
        bucket: task.bucket,
        check: await context.runTask(kind, () => verifyRoute(baseUrl, task.expected, context))
      };
    } catch (error) {
      return {
        bucket: task.bucket,
        check: {
          ...task.expected,
          expectedFinalRequest: task.expected?.expectedFinalRequest
            ? redactedPath(task.expected.expectedFinalRequest, baseUrl)
            : undefined,
          errors: [`${task.expected?.targetPath || 'Live route'} could not be scheduled: ${error.message}`],
          passed: false,
          renderedSeo: task.expected?.renderedSeo
            ? {
                ...task.expected.renderedSeo,
                canonicalUrl: task.expected.renderedSeo.canonicalUrl
                  ? redactedUrl(task.expected.renderedSeo.canonicalUrl)
                  : '',
                openGraphImage: task.expected.renderedSeo.openGraphImage
                  ? redactedUrl(task.expected.renderedSeo.openGraphImage)
                  : ''
              }
            : null,
          requestTarget: task.expected?.requestTarget
            ? redactedPath(task.expected.requestTarget, baseUrl)
            : undefined
        }
      };
    }
  }));
  const metrics = context.metrics();
  errors.push(...context.errors);
  return {
    checks,
    errors,
    budget: {
      ...metrics,
      maxRoutes,
      routeCount: routeTasks.length
    }
  };
}

export async function verifyLive({
  packetDir = 'review-packet',
  targetUrl = '',
  outPath = '',
  cwd = process.cwd(),
  environment = process.env,
  drupalRuntime = null,
  liveHttpLimits = {}
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
  const inspectedDrupalRuntime = drupalRuntime ?? inspectDrupalRuntime(
    cwd,
    environment,
    fieldOutputMatrix,
    routeMatrix,
    patternMap
  );
  const runtimeAuthoritativeForCompletion = !runtimeWasInjected;
  const runtimeWebOrigins = new Set(Array.isArray(inspectedDrupalRuntime.webOrigins)
    ? inspectedDrupalRuntime.webOrigins
    : []);
  if (inspectedDrupalRuntime.baseUrl) {
    try {
      const runtimeTarget = parseHttpUrl(inspectedDrupalRuntime.baseUrl, 'Current DDEV runtime base URL');
      runtimeWebOrigins.add(runtimeTarget.origin);
    } catch {
      // An invalid or unavailable DDEV URL cannot bind the inspected Drupal runtime.
    }
  }
  const runtimeTargetOriginMatches = Boolean(target && runtimeWebOrigins.has(target.url.origin));
  const explicitTargetFetchAllowed =
    !target || target.source !== 'explicit' || runtimeTargetOriginMatches;
  if (!explicitTargetFetchAllowed) {
    liveErrors.push(
      'Explicit target HTTP checks are disabled unless the URL matches the current DDEV runtime.'
    );
  }
  const hasLocalOnlyFormException = (Array.isArray(browserEvidence?.anonymousFormChecks)
    ? browserEvidence.anonymousFormChecks
    : []).some((check) => check?.abuseProtection?.mode === 'local_only_exception');
  const localOnlyFormExceptionRuntimeBound = Boolean(
    target &&
    runtimeAuthoritativeForCompletion &&
    localOnlyFormExceptionsBoundToRuntime(browserEvidence, target.url.href, [...runtimeWebOrigins])
  );
  if (hasLocalOnlyFormException && !localOnlyFormExceptionRuntimeBound) {
    liveErrors.push(
      'A local_only_exception form disposition is valid only when its exact target origin is bound to the current authoritative DDEV runtime.'
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
  const targetRequiredRoutes = Array.isArray(routeMatrix.targetRequiredRoutes)
    ? routeMatrix.targetRequiredRoutes
    : [];
  const primaryRoutePaths = new Set(primaryRoutes.map((route) => requestPathAndSearch(route?.targetPath)).filter(Boolean));
  const representativeChecksByPath = new Map();
  for (const check of (Array.isArray(browserEvidence?.publicRouteChecks) ? browserEvidence.publicRouteChecks : [])) {
    const path = requestPathAndSearch(check?.targetUrl || check?.targetFinalUrl);
    if (path && !primaryRoutePaths.has(path) && !representativeChecksByPath.has(path)) {
      representativeChecksByPath.set(path, check);
    }
  }
  const liveRouteTasks = [
    ...primaryRoutes.map((route) => ({
      bucket: 'primary',
      expected: expectedRoute(routeMatrix, route, browserEvidence)
    })),
    ...targetRequiredRoutes.map((route) => ({
      bucket: 'target-required',
      expected: expectedTargetRequiredRoute(route)
    })),
    ...[...representativeChecksByPath.values()].map((check) => ({
      bucket: 'browser-representative',
      expected: expectedBrowserRepresentativeRoute(routeMatrix, check, browserEvidence)
    }))
  ];
  const fetchChecksEnabled = Boolean(target && explicitTargetFetchAllowed);
  const liveHttpContext = createLiveHttpContext({
    allowRuntimeBoundLocalCertificate: runtimeAuthoritativeForCompletion && runtimeTargetOriginMatches,
    attempted: fetchChecksEnabled,
    concurrency: liveHttpLimits.concurrency ?? MAX_LIVE_ROUTE_CONCURRENCY,
    deadlineMs: liveHttpLimits.deadlineMs ?? LIVE_ROUTE_DEADLINE_MS,
    maxRequests: liveHttpLimits.maxRequests ?? MAX_LIVE_HTTP_REQUESTS,
    maxTasks: liveHttpLimits.maxTasks ?? MAX_LIVE_HTTP_TASKS
  });
  const liveRouteSchedule = fetchChecksEnabled
    ? await scheduleLiveRouteChecks({
        allowRuntimeBoundLocalCertificate: runtimeAuthoritativeForCompletion && runtimeTargetOriginMatches,
        baseUrl: target.url,
        liveHttpContext,
        tasks: liveRouteTasks
      })
    : {
        checks: [],
        errors: [],
        budget: {
          attempted: false,
          deadlineMs: LIVE_ROUTE_DEADLINE_MS,
          maxConcurrency: MAX_LIVE_ROUTE_CONCURRENCY,
          maxRequests: MAX_LIVE_HTTP_REQUESTS,
          maxRoutes: MAX_LIVE_ROUTE_CHECKS,
          requestCount: 0,
          routeCount: liveRouteTasks.length
        }
      };
  liveErrors.push(...liveRouteSchedule.errors);
  const checksForBucket = (bucket) => liveRouteSchedule.checks
    .filter((entry) => entry.bucket === bucket)
    .map((entry) => entry.check);
  const routeChecks = checksForBucket('primary');
  const targetRequiredRouteChecks = checksForBucket('target-required');
  const browserRepresentativeRouteChecks = checksForBucket('browser-representative');
  for (const route of [...routeChecks, ...targetRequiredRouteChecks, ...browserRepresentativeRouteChecks]) {
    liveErrors.push(...route.errors);
  }
  const emptyServerRenderedResponseSurface = () => ({
    errors: [],
    htmlRouteCount: 0,
    linkChecks: [],
    passed: false,
    routeChecks: [],
    seedRouteCount: 0,
    sourceOriginLinkChecks: [],
    sourceOriginLinkCount: 0,
    uniqueInternalLinkCount: 0
  });
  let serverRenderedResponseSurface = emptyServerRenderedResponseSurface();
  if (fetchChecksEnabled) {
    try {
      serverRenderedResponseSurface = await inspectServerRenderedResponseSurface(
        target.url,
        routeMatrix,
        liveHttpContext
      );
    } catch (error) {
      serverRenderedResponseSurface.errors.push(
        `Server-rendered response surface verification could not complete: ${error.message}`
      );
    }
  }
  liveErrors.push(...serverRenderedResponseSurface.errors);

  const redirectMaterialization = target
    ? redirectMaterializationExpectations(routeMatrix, absolutePacketDir, target.url)
    : { conflicts: [], expectations: [] };
  liveErrors.push(...redirectMaterialization.conflicts);
  let redirectMaterializationChecks = [];
  if (fetchChecksEnabled) {
    try {
      redirectMaterializationChecks = await liveHttpContext.runTasks(
        'redirect-materialization',
        redirectMaterialization.expectations,
        (expectation) => verifyRedirectMaterialization(target.url, expectation, liveHttpContext)
      );
    } catch (error) {
      liveErrors.push(`Redirect materialization verification could not complete: ${error.message}`);
    }
  }
  liveErrors.push(...redirectMaterializationChecks.flatMap((check) => check.errors));
  for (const error of liveHttpContext.errors) {
    if (!liveErrors.includes(error)) {
      liveErrors.push(error);
    }
  }
  const liveHttpBudget = liveHttpContext.metrics();

  let chromeContext = { lifecyclePresent: false, latestVerifiedAnchor: null, contract: null };
  try {
    chromeContext = globalChromeCaptureContext({ packetDir: absolutePacketDir });
  } catch (error) {
    liveErrors.push(`Global chrome lifecycle context could not be read: ${error.message}`);
  }
  const rawGlobalChromeCapture = chromeContext.lifecyclePresent && fetchChecksEnabled && runtimeAuthoritativeForCompletion
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
        primaryRoutes: [],
        routes: [],
        budget: null,
        errors: [chromeContext.lifecyclePresent
          ? 'Verifier-owned browser capture is disabled for an injected or unavailable runtime.'
          : 'No lifecycle baseline exists yet; the next live verifier run will establish the global chrome anchor.']
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

  const surfaceReconciliationErrors = !runtimeWasInjected || Object.hasOwn(inspectedDrupalRuntime, 'liveSurfaceInventory')
    ? liveSurfaceReconciliationErrors(
      inspectedDrupalRuntime.liveSurfaceInventory,
      drupalReadback?.liveSurfaceReconciliation,
      absolutePacketDir
    )
    : [];
  liveErrors.push(...surfaceReconciliationErrors);

  const liveTargetValid = Boolean(target) && liveErrors.length === 0;
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
  const drupalRuntimeConfigSyncMatchesHead = inspectedDrupalRuntime.configSyncMatchesHead === true;
  const drupalRuntimeTrackedConfigReadbackMatches =
    Boolean(packetTrackedConfigDirectory) &&
    packetTrackedConfigDirectory === runtimeTrackedConfigDirectory &&
    packetTrackedConfigYamlFiles.length > 0 &&
    packetTrackedConfigYamlFiles.length === runtimeTrackedConfigYamlFiles.length &&
    new Set(packetTrackedConfigYamlFiles).size === packetTrackedConfigYamlFiles.length &&
    packetTrackedConfigYamlFiles.every((path) => runtimeTrackedConfigSet.has(path));
  const runtimeSeoUrlPortabilityFindings = Array.isArray(inspectedDrupalRuntime.exportedSeoUrlPortabilityFindings)
    ? inspectedDrupalRuntime.exportedSeoUrlPortabilityFindings
    : [];
  const drupalRuntimeSeoUrlsPortable = runtimeSeoUrlPortabilityFindings.length === 0;
  const routeEvidenceManifest = [...routeChecks, ...targetRequiredRouteChecks, ...browserRepresentativeRouteChecks]
    .map((route) => ({
      bodySha256: route.bodySha256 ?? '',
      finalUrl: route.finalUrl ?? '',
      h1: route.actualH1 ?? '',
      path: route.targetPath,
      requestTarget: route.requestTarget ?? '',
      routeKind: route.routeKind ?? '',
      status: route.finalStatus ?? 0,
      title: route.actualTitle ?? ''
    }))
    .sort((left, right) => comparePortable(
      `${left.path}\0${left.requestTarget}\0${left.routeKind}`,
      `${right.path}\0${right.requestTarget}\0${right.routeKind}`
    ));
  const routeStateManifest = [...routeChecks, ...targetRequiredRouteChecks, ...browserRepresentativeRouteChecks]
    .map((route) => ({
      canonicalPath: normalizeRouteKey(route.actualMetadata?.canonicalUrl),
      finalPath: normalizeRouteKey(route.finalUrl),
      h1: route.actualH1 ?? '',
      initialStatus: route.initialStatus ?? 0,
      intrinsicSemanticsSha256: route.intrinsicSemantics?.fingerprint ?? '',
      metaDescriptionSha256: stateSha256(route.actualMetadata?.metaDescription ?? ''),
      noindex: route.actualMetadata?.noindex === true,
      openGraphImagePath: normalizePath(route.actualMetadata?.openGraphImage),
      path: normalizeRouteKey(route.requestTarget || route.targetPath),
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
  if (inspectedDrupalRuntime.liveSurfaceInventory?.confirmed !== true) {
    stateBlockers.push(inspectedDrupalRuntime.liveSurfaceInventory?.reason || 'Drupal live public-surface inventory is unavailable.');
  }
  if (surfaceReconciliationErrors.length > 0) {
    stateBlockers.push('The current live-derived Drupal public surface is not exactly reconciled to packet declarations or owned exclusions.');
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
      liveSurfaceCountsByKind: inspectedDrupalRuntime.liveSurfaceInventory?.countsByKind ?? {},
      liveSurfaceFingerprint: inspectedDrupalRuntime.liveSurfaceInventory?.fingerprint ?? '',
      missingLiveRoots: inspectedDrupalRuntime.entityInventory?.missingLiveRoots ?? [],
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
    // Only Drupal-owned facts participate in the intrinsic site fingerprint.
    // PHP/database choices and the digest of effective settings remain
    // machine-local evidence beside that fingerprint.
    const {
      intrinsic: runtimeFacts,
      environmentBinding: runtimeEnvironmentBinding
    } = stateBoundRuntimeFacts(inspectedDrupalRuntime.runtimeFacts);
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
      runtimeEnvironmentBinding,
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
        primaryRoutes: rawGlobalChromeCapture.primaryRoutes ?? [],
        routes: [],
        budget: rawGlobalChromeCapture.budget ?? null,
        errors: [`Global chrome capture finalization failed: ${error.message}`]
      };
    }
  }
  const drupalRuntimeSupportsCompletion =
    runtimeAuthoritativeForCompletion &&
    inspectedDrupalRuntime.confirmed === true &&
    drupalRuntimeTargetMatches &&
    drupalRuntimeSiteUuidMatches &&
    drupalRuntimeFrontPageMatches &&
    drupalRuntimeConfigSyncMatches &&
    drupalRuntimeConfigStatusClean &&
    drupalRuntimeConfigSyncTracked &&
    drupalRuntimeConfigSyncMatchesHead &&
    drupalRuntimeTrackedConfigReadbackMatches &&
    drupalRuntimeSeoUrlsPortable &&
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
    completionBlockedReasons.push('Required machine-checkable packet evidence is still template-like, unresolved, or incomplete.');
  }
  const runtimeDrushCommandFailures = Array.isArray(inspectedDrupalRuntime.drushCommandFailures)
    ? inspectedDrupalRuntime.drushCommandFailures.filter(Boolean)
    : [];
  for (const failure of runtimeDrushCommandFailures) {
    completionBlockedReasons.push(`Drush runtime inspection command failed: ${failure}`);
  }
  if (inspectedDrupalRuntime.confirmed !== true || !drupalRuntimeSiteUuidMatches) {
    // A failed identity readback command must never be reported as an identity mismatch.
    if (inspectedDrupalRuntime.identityReadbackFailed !== true) {
      completionBlockedReasons.push('Current DDEV Drupal runtime identity does not match drupal-readback.json siteUuid.');
    }
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
  if (!drupalRuntimeConfigSyncMatchesHead) {
    completionBlockedReasons.push(
      'Current DDEV config-sync YAML does not match HEAD; commit or remove staged, modified, deleted, untracked, or ignored sync YAML before completion.'
    );
  }
  if (!drupalRuntimeTrackedConfigReadbackMatches) {
    completionBlockedReasons.push('Current Git-tracked config evidence does not match drupal-readback.json.');
  }
  if (!buildStateReady) {
    completionBlockedReasons.push(...stateBlockers);
  }
  if (!drupalRuntimeSeoUrlsPortable) {
    completionBlockedReasons.push('Exported SEO configuration contains literal local-environment URLs; use request-aware Drupal tokens or managed media tokens.');
  }
  if (!runtimeAuthoritativeForCompletion) {
    completionBlockedReasons.push('Injected Drupal runtime evidence is non-authoritative and cannot authorize completion.');
  }

  const targetFingerprintInput = JSON.stringify({
    origin: target?.url.origin ?? '',
    globalChromeCaptureFingerprint: globalChromeCapture?.captureFingerprint ?? '',
    redirectMaterializationChecks: redirectMaterializationChecks.map((check) => ({
      finalPath: check.finalPath ?? '',
      initialStatus: check.initialStatus ?? 0,
      passed: check.passed,
      sourcePath: check.sourcePath
    })),
    serverRenderedResponseSurface: {
      linkChecks: serverRenderedResponseSurface.linkChecks.map((check) => ({
        finalStatus: check.finalStatus ?? 0,
        finalUrl: check.finalUrl ?? '',
        passed: check.passed,
        requestedUrl: check.requestedUrl
      })),
      routeChecks: serverRenderedResponseSurface.routeChecks.map((check) => ({
        bodySha256: check.bodySha256 ?? '',
        finalStatus: check.finalStatus ?? 0,
        finalUrl: check.finalUrl ?? '',
        passed: check.passed,
        requestedUrl: check.requestedUrl
      })),
      sourceOriginLinkChecks: serverRenderedResponseSurface.sourceOriginLinkChecks.map((check) => ({
        passed: check.passed,
        referrer: check.referrer,
        target: check.target
      }))
    },
    routeChecks: routeEvidenceManifest
  });
  const sharedPacketReport = {
    ...sharedValue(packetReport, absolutePacketDir),
    packetDir: sharedPacketDirName(absolutePacketDir)
  };

  return {
    schemaVersion: 'public-kit.live-verification.1',
    checkedAt: new Date().toISOString(),
    claimScope: 'complete-local-rebuild',
    productionReadinessEvaluated: false,
    launchReady: false,
    verificationMode: 'live-target-and-packet',
    packetDir: sharedPacketDirName(absolutePacketDir),
    target: target
      ? {
          declaredSourceBaseUrl: declaredSource ? redactedUrl(declaredSource) : '',
          declaredTargetBaseUrl: declaredTarget ? redactedUrl(declaredTarget) : '',
          resolvedBaseUrl: redactedUrl(target.url),
          resolutionSource: target.source,
          targetFingerprint: `sha256:${sha256(targetFingerprintInput)}`
        }
      : null,
    evidenceBinding: {
      routeMatrixSha256: `sha256:${sha256(routeMatrixText)}`,
      packetEvidenceSha256: buildState?.evidenceBindings?.packetFingerprint ?? '',
      targetFingerprintInputVersion: 4
    },
    routeChecks,
    targetRequiredRouteChecks,
    globalChromeCapture,
    globalChromeCaptureSummary: captureSummary(globalChromeCapture),
    browserRepresentativeRouteChecks,
    serverRenderedResponseSurface,
    redirectMappingConflicts: redirectMaterialization.conflicts,
    redirectMaterializationChecks,
    liveHttpBudget,
    liveRouteBudget: liveRouteSchedule.budget,
    liveTargetValid,
    buildState,
    drupalRuntime: {
      ...inspectedDrupalRuntime,
      authoritativeForCompletion: runtimeAuthoritativeForCompletion,
      baseUrl: inspectedDrupalRuntime.baseUrl ? redactedUrl(inspectedDrupalRuntime.baseUrl) : '',
      configStatusClean: drupalRuntimeConfigStatusClean,
      configSyncMatchesHead: drupalRuntimeConfigSyncMatchesHead,
      configSyncTracked: drupalRuntimeConfigSyncTracked,
      configSyncDirectory: sharedConfigSyncDirectory(inspectedDrupalRuntime.configSyncDirectory),
      configSyncDirectoryMatchesPacket: drupalRuntimeConfigSyncMatches,
      drushCommandFailures: runtimeDrushCommandFailures,
      identityReadbackFailed: inspectedDrupalRuntime.identityReadbackFailed === true,
      frontPage: inspectedDrupalRuntime.frontPage
        ? redactedPath(inspectedDrupalRuntime.frontPage, target?.url ?? 'http://invalid.local/')
        : '',
      frontPageMatchesPacket: drupalRuntimeFrontPageMatches,
      siteUuidMatchesPacket: drupalRuntimeSiteUuidMatches,
      seoUrlsPortable: drupalRuntimeSeoUrlsPortable,
      targetOriginMatches: drupalRuntimeTargetMatches,
      trackedConfigYamlPresent: drupalRuntimeConfigSyncTracked,
      trackedConfigDirectory: runtimeTrackedConfigDirectory,
      trackedConfigReadbackMatches: drupalRuntimeTrackedConfigReadbackMatches,
      trackedConfigYamlFiles: runtimeTrackedConfigYamlFiles
    },
    packetVerification: sharedPacketReport,
    recordedHumanGateStatus: sharedPacketReport.recordedHumanGateStatus,
    completeLocalRebuildClaimAllowed,
    verdict: completeLocalRebuildClaimAllowed
      ? 'complete-local-rebuild'
      : packetReport.valid && liveTargetValid
        ? 'machine-incomplete'
        : 'blocked',
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
    const independence = report.packetVerification?.completionEvidence?.independence ?? {};
    const independenceSummary = [
      ...new Set([independence.independentVerification, independence.blindAdversarialReview].filter(Boolean))
    ].join(', ') || 'not-declared';
    const recordedHumanStatus = report.recordedHumanGateStatus?.localRebuildStatus ?? 'pending';
    const lifecycleNote = report.lifecycle?.requestedOperation?.checkpointId
      ? ` Checkpoint ${report.lifecycle.requestedOperation.checkpointId} recorded.`
      : report.lifecycle?.initialBaseline?.status === 'passed'
        ? ' The create-once, integrity-checked initial baseline remains recorded.'
        : '';
    process.stdout.write(`Live target and packet verification passed; complete local rebuild machine claim authorized for the lifecycle-verified current state (independence evidence: ${independenceSummary}; recorded local-rebuild operator/maintainer status: ${recordedHumanStatus}, self-attested record only).${lifecycleNote} Report: ${args.out}\n`);
  } else {
    const baselineNote = report.lifecycle?.initialBaseline?.status === 'passed'
      ? ' The create-once, integrity-checked initial baseline remains passed; the current derived state is not yet verified.'
      : '';
    const reason = report.completeLocalRebuildClaimAllowed && !report.currentSiteClaimAllowed
      ? 'Full rebuild checks passed, but the changed current state is not classified and lifecycle-verified.'
      : 'Live target checks passed, but complete local rebuild machine authorization remains blocked by required machine evidence.';
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
