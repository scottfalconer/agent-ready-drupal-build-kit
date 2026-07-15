#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseBoundedJsonText,
  perGateResults,
  readBoundedJsonFile,
  validatePacket
} from './verify-packet.mjs';
import { reviewHandoffStateErrors } from './review-handoff.mjs';
import { applyVerificationLifecycle, globalChromeCaptureContext } from './lifecycle.mjs';
import {
  captureBeforeConsentNetwork,
  captureGlobalChrome,
  captureSummary,
  finalizeBeforeConsentNetworkCapture,
  finalizeGlobalChromeCapture,
  validateBeforeConsentNetworkCapture,
  verifierAxeCompletionErrors
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
const MAX_CRITICAL_ASSET_BYTES = 20 * 1024 * 1024;
const MAX_CRITICAL_ASSET_REQUESTS = 160;
const MAX_CRITICAL_ASSET_TOTAL_BYTES = 100 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_LIVE_ROUTE_CHECKS = 1_000;
const MAX_LIVE_ROUTE_CONCURRENCY = 12;
const MAX_LIVE_HTTP_REQUESTS = 2_000;
const MAX_LIVE_HTTP_TASKS = 20_000;
const LIVE_ROUTE_DEADLINE_MS = 90_000;
export const SOURCE_SURFACE_LIMITS = Object.freeze({
  concurrency: 8,
  deadlineMs: 90_000,
  maxBodyBytes: 2 * 1024 * 1024,
  maxRequests: 768,
  maxRoutes: 512,
  maxSitemapLocs: 5_000,
  maxSitemaps: 24,
  maxTasks: 1_024
});
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;

class UsageError extends Error {}

function boundedReportMessages(initial = [], limit = 500) {
  const values = [];
  Object.defineProperty(values, 'push', {
    value(...messages) {
      for (const message of messages) {
        if (values.length < limit - 1) {
          Array.prototype.push.call(values, String(message ?? '').replace(/\s+/g, ' ').trim().slice(0, 1_000));
        } else if (values.length === limit - 1) {
          Array.prototype.push.call(values, `Live verification reached its ${limit}-message reporting cap; remaining messages were bounded.`);
        }
      }
      return values.length;
    }
  });
  values.push(...initial);
  return values;
}

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
    'evidence/packet-verification.json',
    'evidence/review-handoff.json',
    'evidence/review-handoff-independent.json',
    'evidence/review-handoff-blind.json'
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

export function verifierFingerprint({ kitRoot = KIT_ROOT, scriptPath = SCRIPT_PATH } = {}) {
  const scriptDirectory = dirname(scriptPath);
  const files = [
    scriptPath,
    join(scriptDirectory, 'verify-packet.mjs'),
    join(scriptDirectory, 'review-handoff.mjs'),
    join(scriptDirectory, 'state-fingerprint.mjs'),
    join(scriptDirectory, 'lifecycle.mjs'),
    join(scriptDirectory, 'global-chrome.mjs'),
    join(kitRoot, 'gates.json'),
    join(kitRoot, 'assets', 'vendor', 'axe-core', '4.10.3', 'axe.min.js'),
    join(kitRoot, 'vendor', 'ws', '8.21.0', 'INTEGRITY.json'),
    join(kitRoot, 'vendor', 'ws', '8.21.0', 'ws.mjs')
  ]
    .filter((path) => existsSync(path))
    .map((path) => relative(kitRoot, path));
  return collectFileManifest(kitRoot, files).fingerprint;
}

const REDACTED_QUERY_TOKEN_RE = /^\?\u0000agent-ready-query-sha256:([a-f0-9]{64})\u0000$/;
const REDACTED_QUERY_TOKEN_GLOBAL_RE = /\?\u0000agent-ready-query-sha256:([a-f0-9]{64})\u0000/g;

function redactedQuery(value) {
  const query = String(value ?? '');
  if (!query) return '';
  const normalized = query.startsWith('?') ? query : `?${query}`;
  return REDACTED_QUERY_TOKEN_RE.test(normalized)
    ? normalized
    : `?\u0000agent-ready-query-sha256:${sha256(normalized)}\u0000`;
}

function publicRedactedValue(value) {
  if (typeof value === 'string') {
    return value.replace(REDACTED_QUERY_TOKEN_GLOBAL_RE, '?query-sha256=$1');
  }
  if (Array.isArray(value)) {
    return value.map(publicRedactedValue);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, publicRedactedValue(entry)])
    );
  }
  return value;
}

function redactedUrl(value, baseUrl = undefined) {
  try {
    const url = baseUrl ? new URL(value, baseUrl) : new URL(value);
    url.username = '';
    url.password = '';
    url.hash = '';
    const search = redactedQuery(url.search);
    url.search = '';
    return `${url.href}${search}`;
  } catch {
    return '[invalid-url]';
  }
}

function redactedPath(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    return `${url.pathname}${redactedQuery(url.search)}`;
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
        ? `${prefix}${redactedQuery(rawQuery)}${punctuation}`
        : _match;
    }
  );
}

function sharedPacketDirName(absolutePacketDir) {
  const name = basename(absolutePacketDir);
  const queryIndex = name.indexOf('?');
  return queryIndex === -1
    ? name
    : `${name.slice(0, queryIndex)}${redactedQuery(name.slice(queryIndex))}`;
}

function sharedMessage(value, absolutePacketDir, { redactQueries = true } = {}) {
  const rawName = basename(absolutePacketDir);
  const sharedName = sharedPacketDirName(absolutePacketDir);
  const shared = String(value)
    .replaceAll(absolutePacketDir, sharedName)
    .replaceAll(rawName, sharedName);
  return redactQueries ? redactQueryValuesInMessage(shared) : shared;
}

function sharedValue(value, absolutePacketDir, options = {}) {
  if (typeof value === 'string') {
    return sharedMessage(value, absolutePacketDir, options);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sharedValue(entry, absolutePacketDir, options));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, sharedValue(entry, absolutePacketDir, options)])
    );
  }
  return value;
}

function globalChromeCaptureWithoutArtifacts(capture, {
  error = '',
  resultStateFingerprint = '',
  status = ''
} = {}) {
  const errors = [
    ...(Array.isArray(capture?.errors) ? capture.errors : []),
    error
  ].filter(Boolean);
  return {
    schemaVersion: capture?.schemaVersion ?? 'public-kit.global-chrome-capture.1',
    checkedAt: capture?.checkedAt ?? new Date().toISOString(),
    status: status || capture?.status || 'unavailable',
    authoritative: false,
    captureMode: capture?.captureMode ?? 'verifier-owned-browser',
    targetOrigin: capture?.targetOrigin ?? '',
    ...(resultStateFingerprint ? { resultStateFingerprint } : {}),
    contract: capture?.contract ?? {},
    browser: capture?.browser ?? { executable: '', product: '' },
    runtime: capture?.runtime ?? {
      backend: 'unavailable',
      executionBoundary: 'unavailable',
      service: '',
      addOnRelease: '',
      image: '',
      executable: '',
      product: '',
      protocolVersion: '',
      ready: false
    },
    primaryRoutes: capture?.primaryRoutes ?? [],
    routes: [],
    budget: capture?.budget ?? null,
    warnings: capture?.warnings ?? [],
    errors
  };
}

export function browserRuntimePreflightUnavailable(capture, { attempted = false } = {}) {
  if (!attempted) return false;
  if (capture?.status === 'unavailable') return true;
  return capture?.budget?.attempted === true && capture?.runtime?.ready !== true;
}

function sharedRouteCheck(route, absolutePacketDir) {
  return {
    ...route,
    renderedLegalLinks: sharedValue(route?.renderedLegalLinks ?? [], absolutePacketDir),
    renderedResourceUrls: sharedValue(route?.renderedResourceUrls ?? [], absolutePacketDir)
  };
}

export function sharedBeforeConsentNetworkCapture(capture, absolutePacketDir) {
  const shared = publicRedactedValue(sharedValue(capture, absolutePacketDir));
  if (!capture?.captureFingerprint) {
    return shared;
  }
  validateBeforeConsentNetworkCapture(capture, {
    stateFingerprint: capture.resultStateFingerprint,
    targetOrigin: capture.targetOrigin,
    primaryRoutes: capture.primaryRoutes
  });
  const fingerprintInput = { ...shared };
  delete fingerprintInput.captureFingerprint;
  return { ...shared, captureFingerprint: stateSha256(fingerprintInput) };
}

export function sharedGlobalChromeCapture(capture, absolutePacketDir) {
  const privacyBound = capture?.queryPrivacy?.schemaVersion === 'public-kit.query-privacy.1' &&
    capture?.queryPrivacy?.method === 'sha256' &&
    capture?.queryPrivacy?.authoritative === true;
  const shared = publicRedactedValue(sharedValue(capture, absolutePacketDir, {
    redactQueries: !privacyBound
  }));
  if (!capture?.captureFingerprint) {
    return shared;
  }
  const fingerprintInput = { ...shared };
  delete fingerprintInput.captureFingerprint;
  return { ...shared, captureFingerprint: stateSha256(fingerprintInput) };
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
  {
    allowRuntimeBoundLocalCertificate = false,
    captureBody = 'always',
    deadlineAt = 0,
    maxBodyBytes = MAX_BODY_BYTES
  } = {}
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
            bodyBytes: Buffer.alloc(0),
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
        if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
          fail(new Error(`Response body exceeds the ${maxBodyBytes} byte limit.`));
          response.destroy();
          return;
        }
        response.on('data', (chunk) => {
          if (settled) {
            return;
          }
          if (size + chunk.length > maxBodyBytes) {
            fail(new Error(`Response body exceeds the ${maxBodyBytes} byte limit.`));
            response.destroy();
            return;
          }
          chunks.push(chunk);
          size += chunk.length;
        });
        response.on('end', () => {
          const bodyBytes = Buffer.concat(chunks);
          finish(resolveRequest, {
            body: bodyBytes.toString('utf8'),
            bodyBytes,
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
    async request(url, { captureBody = 'always', maxBodyBytes = MAX_BODY_BYTES } = {}) {
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
          deadlineAt,
          maxBodyBytes
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
  {
    captureBody = 'always',
    liveHttpContext,
    maxBodyBytes = MAX_BODY_BYTES,
    stopAtExternalRedirect = false
  } = {}
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
    const response = await liveHttpContext.request(current, { captureBody, maxBodyBytes });
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

const SOURCE_NON_DOCUMENT_EXTENSION_RE = /\.(?:avif|bmp|css|csv|docx?|eot|gif|gz|ico|jpe?g|js|json|m4a|m4v|mov|mp3|mp4|ogg|ogv|otf|pdf|png|pptx?|rar|rss|svg|tar|tiff?|ttf|txt|wav|webm|webp|woff2?|xlsx?|xml|zip)$/i;

function sourceDocumentPath(value, sourceBaseUrl) {
  try {
    const url = new URL(String(value ?? ''), sourceBaseUrl);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.origin !== sourceBaseUrl.origin ||
      url.username ||
      url.password
    ) {
      return '';
    }
    const path = normalizePath(url.pathname);
    return SOURCE_NON_DOCUMENT_EXTENSION_RE.test(path) ? '' : path;
  } catch {
    return '';
  }
}

function sourceRenderedRouteLinks(html, finalUrl, sourceOrigin) {
  const extracted = serverResponseLinks(html, finalUrl, sourceOrigin, '');
  return {
    paths: [...new Set(extracted.internalLinks
      .map((link) => sourceDocumentPath(link.url, new URL('/', sourceOrigin)))
      .filter(Boolean))].sort(comparePortable),
    warnings: extracted.errors
  };
}

function sourceRobotsSitemapUrls(body, sourceBaseUrl) {
  const urls = [];
  for (const match of String(body).matchAll(/^\s*sitemap\s*:\s*(\S+)\s*$/gim)) {
    try {
      const url = new URL(decodeEntities(match[1]), sourceBaseUrl);
      url.hash = '';
      if (['http:', 'https:'].includes(url.protocol) && url.origin === sourceBaseUrl.origin && !url.username && !url.password) {
        urls.push(url.href);
      }
    } catch {
      // Malformed source directives are recorded as source warnings by omission.
    }
  }
  return [...new Set(urls)].sort(comparePortable);
}

function sourceSitemapLocUrls(body, sourceBaseUrl) {
  const urls = [];
  for (const match of String(body).matchAll(/<loc\b[^>]*>([\s\S]*?)<\/loc>/gi)) {
    const text = normalizeText(decodeEntities(match[1].replace(/<[^>]+>/g, ' ')));
    try {
      const url = new URL(text, sourceBaseUrl);
      url.hash = '';
      if (['http:', 'https:'].includes(url.protocol) && url.origin === sourceBaseUrl.origin && !url.username && !url.password) {
        urls.push(url.href);
      }
    } catch {
      // The bounded census ignores malformed or cross-origin sitemap entries.
    }
  }
  return [...new Set(urls)].sort(comparePortable);
}

function sourceBoundaryKind(status) {
  if ([401, 403].includes(status)) return 'private';
  if ([404, 410].includes(status)) return 'unreachable';
  return '';
}

function sourceBoundaryDisposition(routeMatrix, independentVerification, path, status) {
  const boundaryKind = sourceBoundaryKind(status);
  if (!boundaryKind) return null;
  const record = (Array.isArray(routeMatrix?.sourceRouteDriftClassification)
    ? routeMatrix.sourceRouteDriftClassification
    : []).find((candidate) => normalizePath(candidate?.sourcePath) === path);
  const check = (Array.isArray(independentVerification?.routeDriftDispositionChecks)
    ? independentVerification.routeDriftDispositionChecks
    : []).find((candidate) => normalizePath(candidate?.sourcePath) === path);
  const allowedClassifications = boundaryKind === 'private'
    ? new Set(['private_boundary'])
    : new Set(['legacy', 'private_boundary', 'test_staging']);
  const allowedDispositions = new Set(['intentionally_drop', 'unpublished_import']);
  const recordEvidence = String(
    record?.ownerDecisionEvidence || record?.noRedirectDisposition?.evidence || ''
  ).trim();
  const checkMatches = Boolean(
    check &&
    check.status === 'pass' &&
    String(check.dispositionEvidence ?? '').trim() &&
    (!String(check.classification ?? '').trim() || check.classification === record?.classification) &&
    (!String(check.targetDisposition ?? '').trim() || check.targetDisposition === record?.targetDisposition)
  );
  const valid = Boolean(
    record?.accepted === true &&
    allowedClassifications.has(record.classification) &&
    allowedDispositions.has(record.targetDisposition) &&
    String(record.notes ?? '').trim() &&
    recordEvidence &&
    checkMatches &&
    (!Number.isFinite(Number(record.sourceStatus)) || Number(record.sourceStatus) === status)
  );
  return valid
    ? {
        classification: record.classification,
        evidenceSha256: `sha256:${sha256(`${recordEvidence}\n${check.dispositionEvidence}`)}`,
        targetDisposition: record.targetDisposition
      }
    : null;
}

function sourceSurfaceNotRun(reason, { status = 'not_run', authoritative = false } = {}) {
  return {
    schemaVersion: 'public-kit.source-surface-census.1',
    checkedAt: new Date().toISOString(),
    status,
    authoritative,
    sourceOrigin: '',
    routes: [],
    sitemaps: [],
    robots: null,
    discoveredPublicPaths: [],
    errors: [],
    warnings: [reason],
    budget: {
      attempted: false,
      maxRoutes: SOURCE_SURFACE_LIMITS.maxRoutes,
      maxSitemapLocs: SOURCE_SURFACE_LIMITS.maxSitemapLocs,
      maxSitemaps: SOURCE_SURFACE_LIMITS.maxSitemaps
    },
    fingerprint: ''
  };
}

export async function inspectSourceSurface({
  independentVerification = {},
  limits = {},
  liveHttpContext = null,
  routeMatrix = {}
} = {}) {
  const checkedAt = new Date().toISOString();
  const effectiveLimits = { ...SOURCE_SURFACE_LIMITS, ...limits };
  const positiveLimitNames = [
    'concurrency', 'deadlineMs', 'maxBodyBytes', 'maxRequests', 'maxRoutes',
    'maxSitemapLocs', 'maxSitemaps', 'maxTasks'
  ];
  const invalidLimit = positiveLimitNames.find((name) =>
    !Number.isSafeInteger(effectiveLimits[name]) || effectiveLimits[name] <= 0
  );
  if (invalidLimit) {
    return {
      ...sourceSurfaceNotRun(`Source surface ${invalidLimit} must be a positive safe integer.`),
      checkedAt,
      status: 'blocked',
      errors: [`Source surface ${invalidLimit} must be a positive safe integer.`],
      warnings: []
    };
  }

  let sourceBaseUrl;
  try {
    sourceBaseUrl = parseHttpUrl(routeMatrix?.sourceBaseUrl, 'route-matrix.json sourceBaseUrl');
    sourceBaseUrl.pathname = '/';
    sourceBaseUrl.search = '';
  } catch (error) {
    return {
      ...sourceSurfaceNotRun(error.message),
      checkedAt,
      status: 'blocked',
      errors: [error.message],
      warnings: []
    };
  }

  const context = liveHttpContext ?? createLiveHttpContext({
    attempted: true,
    concurrency: effectiveLimits.concurrency,
    deadlineMs: effectiveLimits.deadlineMs,
    maxRequests: effectiveLimits.maxRequests,
    maxTasks: effectiveLimits.maxTasks
  });
  const errors = [];
  const warnings = [];
  const routeQueue = [];
  const queuedRoutes = new Set();
  const routeProvenance = new Map();
  const sitemapQueue = [];
  const queuedSitemaps = new Set();
  const sitemapProvenance = new Map();
  const routes = new Map();
  const sitemaps = [];
  let droppedRouteCount = 0;
  let droppedSitemapCount = 0;
  let sitemapLocCount = 0;

  const addProvenance = (map, key, provenance) => {
    const records = map.get(key) ?? new Map();
    const normalized = {
      kind: String(provenance?.kind ?? 'unknown'),
      referrer: String(provenance?.referrer ?? '')
    };
    records.set(`${normalized.kind}\0${normalized.referrer}`, normalized);
    map.set(key, records);
  };
  const enqueueRoute = (value, provenance) => {
    const path = sourceDocumentPath(value, sourceBaseUrl);
    if (!path) return;
    addProvenance(routeProvenance, path, provenance);
    if (queuedRoutes.has(path)) return;
    if (queuedRoutes.size >= effectiveLimits.maxRoutes) {
      droppedRouteCount += 1;
      return;
    }
    queuedRoutes.add(path);
    routeQueue.push(path);
  };
  const enqueueSitemap = (value, provenance) => {
    let url;
    try {
      url = new URL(String(value ?? ''), sourceBaseUrl);
      url.hash = '';
    } catch {
      return;
    }
    if (url.origin !== sourceBaseUrl.origin || url.username || url.password || queuedSitemaps.has(url.href)) return;
    addProvenance(sitemapProvenance, url.href, provenance);
    if (queuedSitemaps.size >= effectiveLimits.maxSitemaps) {
      droppedSitemapCount += 1;
      return;
    }
    queuedSitemaps.add(url.href);
    sitemapQueue.push(url.href);
  };

  enqueueRoute('/', { kind: 'homepage', referrer: routeMatrix.sourceBaseUrl });
  for (const route of Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : []) {
    enqueueRoute(route?.sourcePath, { kind: 'declared-primary', referrer: 'route-matrix.json#primaryRoutes' });
  }

  let robots = null;
  try {
    robots = await context.runTask('source-robots', async () => {
      const url = new URL('/robots.txt', sourceBaseUrl);
      const response = await requestFollowingRedirects(url, {
        liveHttpContext: context,
        maxBodyBytes: effectiveLimits.maxBodyBytes
      });
      const directives = response.status >= 200 && response.status < 300
        ? sourceRobotsSitemapUrls(response.body, sourceBaseUrl)
        : [];
      for (const sitemapUrl of directives) {
        enqueueSitemap(sitemapUrl, { kind: 'robots-directive', referrer: url.href });
      }
      if (response.status >= 500 || response.status === 429) {
        errors.push(`Source robots.txt returned HTTP ${response.status}; source discovery is not complete.`);
      }
      return {
        bodySha256: `sha256:${sha256(response.body)}`,
        finalUrl: response.finalUrl,
        sitemapDirectives: directives,
        status: response.status
      };
    });
  } catch (error) {
    warnings.push(`Source robots.txt could not be inspected: ${error.message}`);
  }
  enqueueSitemap(new URL('/sitemap.xml', sourceBaseUrl).href, {
    kind: 'default-sitemap-probe',
    referrer: sourceBaseUrl.href
  });

  let sitemapCursor = 0;
  while (sitemapCursor < sitemapQueue.length) {
    const sitemapUrl = sitemapQueue[sitemapCursor];
    sitemapCursor += 1;
    try {
      const record = await context.runTask('source-sitemap', async () => {
        const response = await requestFollowingRedirects(new URL(sitemapUrl), {
          liveHttpContext: context,
          maxBodyBytes: effectiveLimits.maxBodyBytes
        });
        const locs = response.status >= 200 && response.status < 300
          ? sourceSitemapLocUrls(response.body, sourceBaseUrl)
          : [];
        const isIndex = /<sitemapindex\b/i.test(response.body);
        const isUrlset = /<urlset\b/i.test(response.body);
        sitemapLocCount += locs.length;
        if (sitemapLocCount > effectiveLimits.maxSitemapLocs) {
          errors.push(`Verifier-owned source sitemap discovery exceeded its ${effectiveLimits.maxSitemapLocs} URL limit.`);
        } else if (isIndex) {
          for (const location of locs) {
            enqueueSitemap(location, { kind: 'sitemap-index', referrer: sitemapUrl });
          }
        } else if (isUrlset) {
          for (const location of locs) {
            enqueueRoute(location, { kind: 'sitemap-url', referrer: sitemapUrl });
          }
        } else if (response.status >= 200 && response.status < 300 && sitemapProvenance.get(sitemapUrl)?.has(`robots-directive\0${new URL('/robots.txt', sourceBaseUrl).href}`)) {
          errors.push(`Robots-declared source sitemap ${redactedUrl(sitemapUrl)} is not a sitemap index or URL set.`);
        }
        if (response.status >= 500 || response.status === 429) {
          errors.push(`Source sitemap ${redactedUrl(sitemapUrl)} returned HTTP ${response.status}.`);
        }
        return {
          bodySha256: `sha256:${sha256(response.body)}`,
          finalUrl: response.finalUrl,
          kind: isIndex ? 'index' : isUrlset ? 'urlset' : 'unknown',
          locCount: locs.length,
          requestedUrl: sitemapUrl,
          status: response.status
        };
      });
      sitemaps.push(record);
    } catch (error) {
      const onlyDefaultProbe = [...(sitemapProvenance.get(sitemapUrl)?.values() ?? [])]
        .every((record) => record.kind === 'default-sitemap-probe');
      if (!onlyDefaultProbe) {
        errors.push(`Source sitemap ${redactedUrl(sitemapUrl)} could not be inspected: ${error.message}`);
      }
    }
  }

  let routeCursor = 0;
  while (routeCursor < routeQueue.length) {
    const batch = routeQueue.slice(routeCursor, routeCursor + effectiveLimits.concurrency);
    routeCursor += batch.length;
    let results;
    try {
      results = await context.runTasks('source-route', batch, async (path) => {
      const url = new URL(path, sourceBaseUrl);
      const routeErrors = [];
      try {
        const response = await requestFollowingRedirects(url, {
          liveHttpContext: context,
          maxBodyBytes: effectiveLimits.maxBodyBytes
        });
        const contentType = String(response.headers['content-type'] ?? '').toLowerCase();
        const isHtml = /(?:text\/html|application\/xhtml\+xml)/.test(contentType) ||
          (!contentType && /<(?:!doctype\s+html|html)\b/i.test(response.body));
        const metadata = isHtml ? renderedMetadata(response.body, response.finalUrl) : {};
        const extracted = isHtml
          ? sourceRenderedRouteLinks(response.body, response.finalUrl, sourceBaseUrl.origin)
          : { paths: [], warnings: [] };
        warnings.push(...extracted.warnings);
        const boundary = sourceBoundaryKind(response.status);
        let boundaryConfirmationStatus = 0;
        let boundaryConfirmed = false;
        if (boundary) {
          try {
            const confirmation = await requestFollowingRedirects(url, {
              captureBody: 'never',
              liveHttpContext: context,
              maxBodyBytes: effectiveLimits.maxBodyBytes
            });
            boundaryConfirmationStatus = confirmation.status;
            boundaryConfirmed = confirmation.status === response.status;
            if (!boundaryConfirmed) {
              routeErrors.push(`Source boundary ${path} changed from HTTP ${response.status} to ${confirmation.status} on immediate verifier recheck.`);
            }
          } catch (error) {
            routeErrors.push(`Source boundary ${path} could not be confirmed by a second verifier request: ${error.message}`);
          }
        }
        if (response.status >= 500 || response.status === 429) {
          routeErrors.push(`Source route ${path} returned HTTP ${response.status}; public reachability cannot be established.`);
        }
        return {
          bodySha256: `sha256:${sha256(response.body)}`,
          boundaryConfirmationStatus,
          boundaryConfirmed,
          canonical: metadata.canonicalUrl ?? '',
          discoveredLinks: extracted.paths,
          errors: routeErrors,
          finalUrl: response.finalUrl,
          h1: isHtml ? elementText(response.body, 'h1') : '',
          initialStatus: response.initialStatus,
          isHtml,
          path,
          status: response.status,
          title: isHtml ? elementText(response.body, 'title') : ''
        };
      } catch (error) {
        return {
          bodySha256: '', canonical: '', discoveredLinks: [],
          boundaryConfirmationStatus: 0, boundaryConfirmed: false,
          errors: [`Source route ${path} could not be inspected: ${error.message}`],
          finalUrl: '', h1: '', initialStatus: 0, isHtml: false, path, status: 0, title: ''
        };
      }
      });
    } catch (error) {
      errors.push(`Verifier-owned source route census could not complete within its HTTP budget: ${error.message}`);
      break;
    }
    for (const record of results) {
      routes.set(record.path, record);
      errors.push(...record.errors);
      for (const linkedPath of record.discoveredLinks) {
        enqueueRoute(linkedPath, { kind: 'rendered-link', referrer: record.path });
      }
      if (record.finalUrl) {
        const finalPath = sourceDocumentPath(record.finalUrl, sourceBaseUrl);
        if (finalPath && finalPath !== record.path) {
          enqueueRoute(finalPath, { kind: 'redirect-final', referrer: record.path });
        }
      }
    }
  }

  if (droppedRouteCount > 0) {
    errors.push(`Verifier-owned source route discovery exceeded its ${effectiveLimits.maxRoutes} route limit; ${droppedRouteCount} additional discoveries were not inspected.`);
  }
  if (droppedSitemapCount > 0) {
    errors.push(`Verifier-owned source sitemap discovery exceeded its ${effectiveLimits.maxSitemaps} sitemap limit; ${droppedSitemapCount} additional sitemaps were not inspected.`);
  }

  const declaredSourcePaths = new Set([
    ...(Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : [])
      .map((route) => normalizePath(route?.sourcePath)),
    ...(Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : [])
      .filter((route) => route?.accepted === true)
      .map((route) => normalizePath(route?.sourcePath))
  ].filter(Boolean));
  const discoveredPublicPaths = new Set();
  for (const record of routes.values()) {
    const publicHtml = record.status >= 200 && record.status < 300 && record.isHtml;
    const boundaryKind = sourceBoundaryKind(record.status);
    const boundaryDisposition = record.boundaryConfirmed
      ? sourceBoundaryDisposition(routeMatrix, independentVerification, record.path, record.status)
      : null;
    record.boundary = boundaryKind;
    record.boundaryDisposition = boundaryDisposition;
    if (publicHtml) {
      discoveredPublicPaths.add(record.path);
      if (!declaredSourcePaths.has(record.path)) {
        const provenance = [...(routeProvenance.get(record.path)?.values() ?? [])]
          .map((item) => item.kind)
          .join(', ') || 'source discovery';
        errors.push(`Verifier-owned source census discovered reachable public source route ${record.path} via ${provenance}, but route-matrix.json has no accepted source route. Reachable public routes cannot be excluded by builder-authored drift dispositions.`);
      }
    } else if (boundaryKind && !boundaryDisposition) {
      errors.push(`Verifier-owned source census found ${boundaryKind} source boundary ${record.path} with HTTP ${record.status}, but it was not persistently machine-confirmed and matched to an evidenced sourceRouteDriftClassification boundary.`);
    } else if (
      [...(routeProvenance.get(record.path)?.values() ?? [])].some((item) => item.kind === 'declared-primary') &&
      !publicHtml &&
      !boundaryKind
    ) {
      errors.push(`Declared primary source route ${record.path} did not resolve to a public HTML response.`);
    }
  }

  const declaredPrimaryByPath = new Map((Array.isArray(routeMatrix?.primaryRoutes) ? routeMatrix.primaryRoutes : [])
    .map((route) => [normalizePath(route?.sourcePath), route]));
  const sourceRowsByPath = new Map((Array.isArray(routeMatrix?.routes) ? routeMatrix.routes : [])
    .map((route) => [normalizePath(route?.sourcePath), route]));
  for (const [path] of declaredPrimaryByPath) {
    const record = routes.get(path);
    const declared = sourceRowsByPath.get(path);
    if (!record || !declared) continue;
    const sourceStatusDeclared = declared.sourceStatus !== null && declared.sourceStatus !== undefined && declared.sourceStatus !== '';
    const expectedStatus = Number(declared.sourceStatus);
    if (sourceStatusDeclared && Number.isFinite(expectedStatus) && expectedStatus !== record.initialStatus) {
      errors.push(`Primary source route ${path} returned HTTP ${record.initialStatus}; route-matrix.json records ${expectedStatus}.`);
    }
    const expectedFinalPath = normalizePath(declared.sourceFinalPath);
    if (expectedFinalPath && expectedFinalPath !== normalizePath(record.finalUrl)) {
      errors.push(`Primary source route ${path} ended at ${normalizePath(record.finalUrl)}; route-matrix.json records ${expectedFinalPath}.`);
    }
    if (String(declared.sourceTitle ?? '').trim() && declared.sourceTitle !== record.title) {
      errors.push(`Primary source route ${path} title does not match verifier-owned source readback.`);
    }
    if (String(declared.sourceH1 ?? '').trim() && declared.sourceH1 !== record.h1) {
      errors.push(`Primary source route ${path} H1 does not match verifier-owned source readback.`);
    }
  }

  const routeRecords = [...routes.values()].map(({ discoveredLinks: _discoveredLinks, ...record }) => ({
    ...record,
    provenance: [...(routeProvenance.get(record.path)?.values() ?? [])].sort((left, right) =>
      comparePortable(`${left.kind}\0${left.referrer}`, `${right.kind}\0${right.referrer}`)
    )
  })).sort((left, right) => comparePortable(left.path, right.path));
  const sitemapRecords = sitemaps.map((record) => ({
    ...record,
    provenance: [...(sitemapProvenance.get(record.requestedUrl)?.values() ?? [])].sort((left, right) =>
      comparePortable(`${left.kind}\0${left.referrer}`, `${right.kind}\0${right.referrer}`)
    )
  })).sort((left, right) => comparePortable(left.requestedUrl, right.requestedUrl));
  const fingerprintInput = {
    sourceOrigin: sourceBaseUrl.origin,
    routes: routeRecords.map(({ errors: _errors, ...record }) => record),
    sitemaps: sitemapRecords,
    robots
  };
  return {
    schemaVersion: 'public-kit.source-surface-census.1',
    checkedAt,
    status: errors.length === 0 ? 'passed' : 'blocked',
    authoritative: true,
    sourceOrigin: sourceBaseUrl.origin,
    routes: routeRecords,
    sitemaps: sitemapRecords,
    robots,
    discoveredPublicPaths: [...discoveredPublicPaths].sort(comparePortable),
    errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
    budget: {
      ...context.metrics(),
      droppedRouteCount,
      droppedSitemapCount,
      maxBodyBytes: effectiveLimits.maxBodyBytes,
      maxRoutes: effectiveLimits.maxRoutes,
      maxSitemapLocs: effectiveLimits.maxSitemapLocs,
      maxSitemaps: effectiveLimits.maxSitemaps,
      routeCount: routeRecords.length,
      sitemapCount: sitemapRecords.length,
      sitemapLocCount
    },
    fingerprint: stateSha256(fingerprintInput)
  };
}

function criticalAssetCandidates(html, finalUrl) {
  const base = new URL(finalUrl);
  const candidates = [];
  const add = (value, role, expectedType = '') => {
    const text = String(value ?? '').trim();
    if (!text) {
      return;
    }
    try {
      const url = new URL(text, base);
      url.hash = '';
      if (!['http:', 'https:'].includes(url.protocol) || url.origin !== base.origin) {
        return;
      }
      candidates.push({ expectedType, role, url });
    } catch {
      // Route semantics represent malformed URLs; only fetch valid same-origin assets.
    }
  };

  for (const attributes of matchingTags(html, 'link', (item) => Boolean(item.href))) {
    const relations = String(attributes.rel ?? '').toLowerCase().split(/\s+/).filter(Boolean);
    if (relations.includes('stylesheet')) {
      add(attributes.href, 'stylesheet', 'style');
    }
    if (relations.includes('preload')) {
      add(
        attributes.href,
        `preload:${String(attributes.as ?? 'unknown').toLowerCase()}`,
        String(attributes.as ?? '')
      );
    }
  }
  for (const attributes of matchingTags(html, 'script', (item) => Boolean(item.src))) {
    add(attributes.src, 'script', 'script');
  }
  for (const tagName of ['img', 'source']) {
    for (const attributes of matchingTags(html, tagName, () => true)) {
      if (tagName === 'img' || String(attributes.type ?? '').toLowerCase().startsWith('image/')) {
        add(attributes.src, `${tagName}:src`, 'image');
      }
      if (attributes.srcset) {
        for (const candidate of attributes.srcset.split(',')) {
          const [url, descriptor = ''] = candidate.trim().split(/\s+/, 2);
          add(url, `${tagName}:srcset:${descriptor}`, 'image');
        }
      }
    }
  }
  for (const tagName of ['video', 'audio']) {
    for (const attributes of matchingTags(html, tagName, () => true)) {
      add(attributes.poster, `${tagName}:poster`, 'image');
    }
  }

  const unique = new Map();
  for (const candidate of candidates) {
    const key = candidate.url.href;
    const current = unique.get(key);
    if (current) {
      current.roles.add(candidate.role);
      current.expectedTypes.add(candidate.expectedType);
    } else {
      unique.set(key, {
        expectedTypes: new Set([candidate.expectedType]),
        roles: new Set([candidate.role]),
        url: candidate.url
      });
    }
  }
  return [...unique.values()].sort((left, right) => comparePortable(left.url.href, right.url.href));
}

function assetContentTypeMatches(contentType, expectedTypes) {
  const normalized = String(contentType ?? '').split(';', 1)[0].trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  const matches = (expected) => {
    switch (String(expected).toLowerCase()) {
      case 'style':
        return normalized === 'text/css';
      case 'script':
      case 'worker':
        return /^(?:application|text)\/(?:javascript|ecmascript|x-javascript)$/.test(normalized);
      case 'image':
        return normalized.startsWith('image/');
      case 'font':
        return normalized.startsWith('font/') ||
          normalized === 'application/font-woff' ||
          normalized === 'application/font-woff2';
      case 'audio':
      case 'video':
        return normalized.startsWith(`${String(expected).toLowerCase()}/`);
      case 'document':
        return normalized === 'text/html' || normalized === 'application/xhtml+xml';
      case 'track':
        return normalized === 'text/vtt';
      case 'fetch':
      case '':
      case 'unknown':
        return normalized !== 'text/html';
      default:
        return normalized !== 'text/html';
    }
  };
  return [...expectedTypes].every(matches);
}

export function createCriticalAssetContext({
  concurrency = 8,
  liveHttpContext = null,
  maxAssetBytes = MAX_CRITICAL_ASSET_BYTES,
  maxRequests = MAX_CRITICAL_ASSET_REQUESTS,
  maxTotalBytes = MAX_CRITICAL_ASSET_TOTAL_BYTES,
  wallClockMs = 60_000
} = {}) {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > MAX_LIVE_ROUTE_CONCURRENCY) {
    throw new Error(`Critical asset concurrency must be between 1 and ${MAX_LIVE_ROUTE_CONCURRENCY}.`);
  }
  if (!Number.isSafeInteger(wallClockMs) || wallClockMs < 1 || wallClockMs > LIVE_ROUTE_DEADLINE_MS) {
    throw new Error(`Critical asset wall-clock budget must be between 1 and ${LIVE_ROUTE_DEADLINE_MS} ms.`);
  }
  const byteLimits = {
    maxAssetBytes: [maxAssetBytes, MAX_CRITICAL_ASSET_BYTES],
    maxTotalBytes: [maxTotalBytes, MAX_CRITICAL_ASSET_TOTAL_BYTES]
  };
  for (const [name, [value, maximum]] of Object.entries(byteLimits)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
      throw new Error(`Critical asset ${name} must be between 1 and ${maximum}.`);
    }
  }
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > MAX_CRITICAL_ASSET_REQUESTS) {
    throw new Error(`Critical asset maxRequests must be between 1 and ${MAX_CRITICAL_ASSET_REQUESTS}.`);
  }
  const sharedContext = liveHttpContext ?? createLiveHttpContext({
    concurrency,
    deadlineMs: wallClockMs,
    maxRequests,
    maxTasks: maxRequests
  });
  return {
    byteBudgetExhausted: false,
    byteWaiters: [],
    cache: new Map(),
    liveHttpContext: sharedContext,
    maxAssetBytes,
    maxRequests,
    maxTotalBytes,
    reservedBytes: 0,
    totalBytes: 0
  };
}

function dispatchCriticalAssetByteWaiters(context) {
  while (context.byteWaiters.length > 0) {
    if (context.byteBudgetExhausted || context.totalBytes >= context.maxTotalBytes) {
      context.byteBudgetExhausted = true;
      const error = new Error(`bytes exceed the ${context.maxTotalBytes} byte total limit`);
      for (const waiter of context.byteWaiters.splice(0)) {
        waiter.reject(error);
      }
      return;
    }
    const available = context.maxTotalBytes - context.totalBytes - context.reservedBytes;
    if (available <= 0) {
      return;
    }
    const waiter = context.byteWaiters.shift();
    const reservation = Math.min(context.maxAssetBytes, available);
    context.reservedBytes += reservation;
    waiter.resolve(reservation);
  }
}

function reserveCriticalAssetBytes(context) {
  if (context.byteBudgetExhausted || context.totalBytes >= context.maxTotalBytes) {
    context.byteBudgetExhausted = true;
    return Promise.reject(new Error(`bytes exceed the ${context.maxTotalBytes} byte total limit`));
  }
  const available = context.maxTotalBytes - context.totalBytes - context.reservedBytes;
  if (available > 0) {
    const reservation = Math.min(context.maxAssetBytes, available);
    context.reservedBytes += reservation;
    return Promise.resolve(reservation);
  }
  return new Promise((resolveReservation, rejectReservation) => {
    context.byteWaiters.push({ reject: rejectReservation, resolve: resolveReservation });
  });
}

function releaseCriticalAssetBytes(context, reservation) {
  context.reservedBytes = Math.max(0, context.reservedBytes - reservation);
  dispatchCriticalAssetByteWaiters(context);
}

function criticalAssetResponse(candidate, context) {
  if (!context.cache.has(candidate.url.href)) {
    if (context.cache.size >= context.maxRequests) {
      throw new Error(`inventory exceeds the ${context.maxRequests} request limit`);
    }
    context.cache.set(candidate.url.href, (async () => {
      const reservation = await reserveCriticalAssetBytes(context);
      try {
        const response = await context.liveHttpContext.runTask(
          'critical-asset',
          () => requestFollowingRedirects(candidate.url, {
            liveHttpContext: context.liveHttpContext,
            maxBodyBytes: reservation
          })
        );
        const bytes = response.bodyBytes ?? Buffer.from(response.body ?? '', 'utf8');
        context.totalBytes += bytes.length;
        if (context.totalBytes >= context.maxTotalBytes) {
          context.byteBudgetExhausted = true;
        }
        return response;
      } catch (error) {
        if (
          reservation < context.maxAssetBytes &&
          /response body exceeds the \d+ byte limit/i.test(String(error?.message ?? error))
        ) {
          context.byteBudgetExhausted = true;
        }
        throw error;
      } finally {
        releaseCriticalAssetBytes(context, reservation);
      }
    })());
  }
  return context.cache.get(candidate.url.href);
}

export async function inspectCriticalAssets(html, finalUrl, context) {
  if (!context?.liveHttpContext) {
    throw new Error('Critical asset inspection requires a bounded live HTTP context.');
  }
  const candidates = criticalAssetCandidates(html, finalUrl);
  const results = await Promise.all(candidates.map(async (candidate) => {
    try {
      const response = await criticalAssetResponse(candidate, context);
      const bytes = response.bodyBytes ?? Buffer.from(response.body ?? '', 'utf8');
      const errors = [];
      if (response.status < 200 || response.status >= 300) {
        errors.push(`${candidate.url.pathname} critical asset returned HTTP ${response.status}.`);
      }
      const contentType = response.headers['content-type'] ?? '';
      if (!assetContentTypeMatches(contentType, candidate.expectedTypes)) {
        errors.push(
          `${candidate.url.pathname} critical asset has content type ${JSON.stringify(String(contentType))}, incompatible with ${[...candidate.roles].join(', ')}.`
        );
      }
      return {
        errors,
        manifest: {
          contentType: String(contentType).split(';', 1)[0].trim().toLowerCase(),
          path: intrinsicUrl(response.finalUrl, finalUrl, { asset: true }),
          roles: [...candidate.roles].sort(comparePortable),
          sha256: `sha256:${sha256(bytes)}`,
          size: bytes.length
        }
      };
    } catch (error) {
      return {
        errors: [`${candidate.url.pathname} critical asset could not be fetched: ${error.message}`],
        manifest: null
      };
    }
  }));
  const manifest = results.map((result) => result.manifest).filter(Boolean);
  const errors = results.flatMap((result) => result.errors);
  manifest.sort((left, right) => comparePortable(
    `${left.path}\0${left.roles.join(',')}`,
    `${right.path}\0${right.roles.join(',')}`
  ));
  return {
    errors,
    fingerprint: stateSha256(manifest),
    manifest
  };
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

export function findDrupalDdevRoot(cwd) {
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

export function inspectDrupalLiveSurface(projectRoot, environment) {
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

const LIVE_NEXT_CYCLE_CENSUS_PHP = String.raw`
$signalKinds = static function ($value): array {
  $text = strtolower((string) $value);
  $text = preg_replace('/[_\\-.]+/', ' ', $text) ?: $text;
  $patterns = [
    'date' => '/\\b(date|dated|datetime|calendar|january|february|march|april|may|june|july|august|september|october|november|december)\\b/',
    'day' => '/\\b(day|daily|weekday|weekend|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\\b/',
    'year' => '/\\b(year|annual|annually|(?:19|20)\\d{2})\\b/',
    'season' => '/\\b(season|seasonal|spring|summer|autumn|fall|winter)\\b/',
    'period' => '/\\b(period|cycle|edition|quarter|quarterly|month|monthly|week|weekly|term|timeframe)\\b/',
    'schedule' => '/\\b(schedule|scheduled|timetable|agenda)\\b/',
    'time' => '/\\b(time|start|end|duration|interval)\\b/',
  ];
  $found = [];
  foreach ($patterns as $kind => $pattern) {
    if (preg_match($pattern, $text) === 1) {
      $found[] = $kind;
    }
  }
  return $found;
};

$entityTypeManager = \Drupal::entityTypeManager();
$vocabularyMetadata = [];
if ($entityTypeManager->hasDefinition('taxonomy_vocabulary')) {
  foreach ($entityTypeManager->getStorage('taxonomy_vocabulary')->loadMultiple() as $vocabulary) {
    $id = (string) $vocabulary->id();
    $kinds = $signalKinds($id . ' ' . (string) $vocabulary->label());
    $vocabularyMetadata[$id] = $kinds;
  }
}

$fields = [];
foreach ($entityTypeManager->getStorage('field_config')->loadMultiple() as $field) {
  $fieldName = (string) $field->getName();
  $fieldType = (string) $field->getType();
  $entityType = (string) $field->getTargetEntityTypeId();
  $bundle = (string) $field->getTargetBundle();
  if ($entityType === 'user') {
    continue;
  }

  // Machine names, labels, field types, and configured option labels are schema
  // metadata. Free-form descriptions are intentionally excluded because prose
  // such as "keep this up-to-date" creates noisy false positives.
  $kinds = $signalKinds($fieldName . ' ' . (string) $field->label());
  if (preg_match('/(?:date|time|timestamp|duration|interval|range)/i', $fieldType) === 1) {
    $kinds[] = 'date_type';
  }

  $optionCount = 0;
  $optionSignalKinds = [];
  if (preg_match('/^(?:list_|string$|integer$)/', $fieldType) === 1) {
    $allowedValues = $field->getFieldStorageDefinition()->getSetting('allowed_values');
    if (is_array($allowedValues)) {
      $optionCount = count($allowedValues);
      foreach ($allowedValues as $key => $option) {
        $optionText = is_array($option)
          ? implode(' ', array_map('strval', array_intersect_key($option, ['value' => TRUE, 'label' => TRUE])))
          : (string) $key . ' ' . (string) $option;
        $optionSignalKinds = array_merge($optionSignalKinds, $signalKinds($optionText));
      }
    }
  }

  $targetVocabularies = [];
  if ($fieldType === 'entity_reference' && $field->getSetting('handler') === 'default:taxonomy_term') {
    $configuredTargets = $field->getSetting('handler_settings')['target_bundles'] ?? [];
    if (is_array($configuredTargets)) {
      foreach ($configuredTargets as $key => $value) {
        $vocabularyId = is_string($key) ? $key : (string) $value;
        if ($vocabularyId !== '') {
          $targetVocabularies[] = $vocabularyId;
          if (!empty($vocabularyMetadata[$vocabularyId])) {
            $kinds[] = 'taxonomy';
            $kinds = array_merge($kinds, $vocabularyMetadata[$vocabularyId]);
          }
        }
      }
    }
  }

  $kinds = array_values(array_unique(array_merge($kinds, $optionSignalKinds)));
  sort($kinds);
  $targetVocabularies = array_values(array_unique($targetVocabularies));
  sort($targetVocabularies);
  if ($kinds === []) {
    continue;
  }
  $fields[] = [
    'key' => $entityType . '.' . $bundle . '.' . $fieldName,
    'entityType' => $entityType,
    'bundle' => $bundle,
    'machineName' => $fieldName,
    'fieldType' => $fieldType,
    'required' => $field->isRequired(),
    'cardinality' => (int) $field->getFieldStorageDefinition()->getCardinality(),
    'optionCount' => $optionCount,
    'signalKinds' => $kinds,
    'targetVocabularies' => $targetVocabularies,
  ];
}
usort($fields, static fn(array $a, array $b): int => $a['key'] <=> $b['key']);

$taxonomyDimensions = [];
foreach ($vocabularyMetadata as $id => $kinds) {
  if ($kinds === []) {
    continue;
  }
  sort($kinds);
  $taxonomyDimensions[] = [
    'key' => 'taxonomy.' . $id,
    'vocabulary' => $id,
    'signalKinds' => array_values(array_unique($kinds)),
  ];
}
usort($taxonomyDimensions, static fn(array $a, array $b): int => $a['key'] <=> $b['key']);

$workflows = [];
if ($entityTypeManager->hasDefinition('workflow')) {
  foreach ($entityTypeManager->getStorage('workflow')->loadMultiple() as $workflow) {
    try {
      $plugin = $workflow->getTypePlugin();
      $configuration = $plugin->getConfiguration();
      $bundleKeys = [];
      foreach (($configuration['entity_types'] ?? []) as $workflowEntityType => $bundles) {
        foreach ((array) $bundles as $workflowBundle) {
          $bundleKeys[] = (string) $workflowEntityType . '.' . (string) $workflowBundle;
        }
      }
      sort($bundleKeys);
      $workflows[] = [
        'id' => (string) $workflow->id(),
        'type' => (string) $workflow->getTypePlugin()->getPluginId(),
        'bundleKeys' => array_values(array_unique($bundleKeys)),
        'stateCount' => count($plugin->getStates()),
        'transitionCount' => count($plugin->getTransitions()),
      ];
    }
    catch (\Throwable) {
      // A broken workflow is reported by Drupal elsewhere; keep this census read-only.
    }
  }
}
usort($workflows, static fn(array $a, array $b): int => $a['id'] <=> $b['id']);

print json_encode([
  'schemaVersion' => 'public-kit.live-next-cycle-census.1',
  'metadataOnly' => TRUE,
  'privateContentRead' => FALSE,
  'candidateCount' => count($fields) + count($taxonomyDimensions),
  'fields' => $fields,
  'taxonomyDimensions' => $taxonomyDimensions,
  'workflows' => $workflows,
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
`;

function parseLiveNextCycleCensus(result) {
  if (result?.ok !== true) {
    return {
      candidateCount: 0,
      confirmed: false,
      fields: [],
      metadataOnly: true,
      privateContentRead: false,
      reason: 'The read-only Drush live model census did not run.',
      schemaVersion: 'public-kit.live-next-cycle-census.1',
      taxonomyDimensions: [],
      workflows: []
    };
  }
  try {
    const parsed = JSON.parse(result.output);
    const fields = Array.isArray(parsed?.fields) ? parsed.fields : [];
    const taxonomyDimensions = Array.isArray(parsed?.taxonomyDimensions) ? parsed.taxonomyDimensions : [];
    const workflows = Array.isArray(parsed?.workflows) ? parsed.workflows : [];
    if (
      parsed?.schemaVersion !== 'public-kit.live-next-cycle-census.1' ||
      parsed?.metadataOnly !== true ||
      parsed?.privateContentRead !== false ||
      Number(parsed?.candidateCount) !== fields.length + taxonomyDimensions.length
    ) {
      throw new Error('Unexpected census schema or count.');
    }
    return {
      candidateCount: fields.length + taxonomyDimensions.length,
      confirmed: true,
      fields,
      metadataOnly: true,
      privateContentRead: false,
      reason: '',
      schemaVersion: parsed.schemaVersion,
      taxonomyDimensions,
      workflows
    };
  } catch {
    return {
      candidateCount: 0,
      confirmed: false,
      fields: [],
      metadataOnly: true,
      privateContentRead: false,
      reason: 'The read-only Drush live model census returned invalid JSON or metadata.',
      schemaVersion: 'public-kit.live-next-cycle-census.1',
      taxonomyDimensions: [],
      workflows: []
    };
  }
}

const LIVE_EDITOR_SURFACE_SCHEMA = 'public-kit.live-editor-surface-census.1';
const FORMATTED_TEXT_FIELD_TYPES = new Set(['text', 'text_long', 'text_with_summary']);

function declaredLiveEditorSurface(fieldOutputMatrix, browserEvidence) {
  const errors = [];
  const roles = new Map();
  const addRole = (check, source, global = false) => {
    const declared = String(check?.editorRole ?? '').trim();
    if (!declared) {
      return;
    }
    const entityType = String(check?.entityType ?? '').trim();
    const bundle = String(check?.bundle ?? '').trim();
    if (!roles.has(declared)) {
      roles.set(declared, { declared, bindings: [] });
    }
    roles.get(declared).bindings.push({
      source,
      entityType,
      bundle,
      global
    });
  };
  for (const check of Array.isArray(browserEvidence?.editorWorkflowChecks)
    ? browserEvidence.editorWorkflowChecks
    : []) {
    addRole(check, 'editorWorkflowChecks', false);
  }
  for (const check of Array.isArray(browserEvidence?.canvasAuthoringChecks)
    ? browserEvidence.canvasAuthoringChecks
    : []) {
    addRole(check, 'canvasAuthoringChecks', true);
  }

  const fields = new Map();
  for (const bundleRow of Array.isArray(fieldOutputMatrix?.bundles) ? fieldOutputMatrix.bundles : []) {
    const entityType = String(bundleRow?.entityType ?? '').trim();
    const bundle = String(bundleRow?.bundle ?? '').trim();
    for (const field of Array.isArray(bundleRow?.fields) ? bundleRow.fields : []) {
      const publicRenderLocations = (Array.isArray(field?.publicRenderLocations)
        ? field.publicRenderLocations
        : [])
        .map((value) => String(value ?? '').trim())
        .filter(Boolean);
      if (field?.affectsAnonymousOutput !== true && publicRenderLocations.length === 0) {
        continue;
      }
      const machineName = String(field?.machineName ?? '').trim();
      const key = `${entityType}.${bundle}.${machineName}`;
      if (
        !/^[a-z][a-z0-9_]*$/.test(entityType) ||
        !/^[a-z][a-z0-9_]*$/.test(bundle) ||
        !/^[a-z][a-z0-9_]*$/.test(machineName)
      ) {
        errors.push(`field-output-matrix.json public field has an invalid live field identity: ${key}.`);
        continue;
      }
      if (fields.has(key)) {
        errors.push(`field-output-matrix.json repeats public field ${key}; live editor-surface metadata must be unique.`);
        continue;
      }
      const editorRoles = [...roles.values()]
        .filter((role) => role.bindings.some((binding) =>
          binding.global || (binding.entityType === entityType && binding.bundle === bundle)
        ))
        .map((role) => role.declared)
        .sort(comparePortable);
      fields.set(key, {
        key,
        entityType,
        bundle,
        machineName,
        packetRequired: field?.required,
        packetWidget: String(field?.widget ?? '').trim(),
        packetFieldType: String(field?.fieldType ?? '').trim(),
        publicRenderLocations,
        affectsAnonymousOutput: field?.affectsAnonymousOutput === true,
        editorRoles
      });
    }
  }

  return {
    errors,
    fields: [...fields.values()].sort((left, right) => comparePortable(left.key, right.key)),
    roles: [...roles.values()]
      .map((role) => ({
        ...role,
        bindings: role.bindings.sort((left, right) => comparePortable(
          `${left.source}\0${left.entityType}\0${left.bundle}`,
          `${right.source}\0${right.entityType}\0${right.bundle}`
        ))
      }))
      .sort((left, right) => comparePortable(left.declared, right.declared))
  };
}

export const DRUPAL_LIVE_EDITOR_SURFACE_EVAL = String.raw`
$entity_type_manager = \Drupal::entityTypeManager();
$entity_field_manager = \Drupal::service('entity_field.manager');
$field_config_storage = $entity_type_manager->getStorage('field_config');
$form_display_storage = $entity_type_manager->getStorage('entity_form_display');
$role_storage = $entity_type_manager->getStorage('user_role');
$role_entities = $role_storage->loadMultiple();
$declared_fields = is_array($declared_editor_surface['fields'] ?? NULL) ? $declared_editor_surface['fields'] : [];
$declared_roles = is_array($declared_editor_surface['roles'] ?? NULL) ? $declared_editor_surface['roles'] : [];
$errors = [];
$entity_limit = 5000;

$normalize_role = static function (string $value): string {
  $normalized = strtolower(trim($value));
  $normalized = preg_replace('/[^a-z0-9]+/', '_', $normalized) ?? '';
  return trim($normalized, '_');
};

$resolved_roles = [];
foreach ($declared_roles as $declared_role) {
  $declared = trim((string) ($declared_role['declared'] ?? ''));
  $matches = [];
  if ($declared !== '' && isset($role_entities[$declared])) {
    $matches[(string) $role_entities[$declared]->id()] = $role_entities[$declared];
  }
  if ($declared !== '') {
    $normalized_declared = $normalize_role($declared);
    foreach ($role_entities as $role) {
      $role_id = (string) $role->id();
      $role_label = (string) $role->label();
      if (
        strtolower($role_label) === strtolower($declared) ||
        $normalize_role($role_id) === $normalized_declared ||
        $normalize_role($role_label) === $normalized_declared
      ) {
        $matches[$role_id] = $role;
      }
    }
  }
  $resolved = count($matches) === 1;
  $role = $resolved ? reset($matches) : NULL;
  $resolved_roles[$declared] = [
    'declared' => $declared,
    'resolved' => $resolved,
    'ambiguous' => count($matches) > 1,
    'roleId' => $resolved ? (string) $role->id() : '',
    'roleLabel' => $resolved ? (string) $role->label() : '',
    'administrator' => $resolved && method_exists($role, 'isAdmin') && $role->isAdmin(),
  ];
}
ksort($resolved_roles, SORT_STRING);

$field_results = [];
foreach ($declared_fields as $declared_field) {
  $entity_type = trim((string) ($declared_field['entityType'] ?? ''));
  $bundle = trim((string) ($declared_field['bundle'] ?? ''));
  $field_name = trim((string) ($declared_field['machineName'] ?? ''));
  $key = $entity_type . '.' . $bundle . '.' . $field_name;
  $definitions = [];
  try {
    $definitions = $entity_field_manager->getFieldDefinitions($entity_type, $bundle);
  }
  catch (\Throwable $throwable) {
    $errors[] = $key . ': field definitions could not be loaded: ' . $throwable->getMessage();
  }
  $definition = $definitions[$field_name] ?? NULL;
  $definition_exists = $definition !== NULL;
  $config_entity_exists = $field_config_storage->load($key) !== NULL;
  $definition_source = $config_entity_exists ? 'configurable' : ($definition_exists ? 'base' : 'missing');
  $field_type = $definition_exists ? (string) $definition->getType() : '';
  $required = $definition_exists ? (bool) $definition->isRequired() : NULL;

  $display_id = $entity_type . '.' . $bundle . '.default';
  $display = $form_display_storage->load($display_id);
  $component = $display ? $display->getComponent($field_name) : NULL;
  $widget = is_array($component) ? trim((string) ($component['type'] ?? '')) : '';
  $widget_visible = $widget !== '';

  $formatted_text = in_array($field_type, ['text', 'text_long', 'text_with_summary'], TRUE);
  $format_ids = [];
  $format_inspection_error = '';
  $format_inspection_truncated = FALSE;
  if ($formatted_text && $definition_exists) {
    try {
      $entity_storage = $entity_type_manager->getStorage($entity_type);
      $entity_definition = $entity_type_manager->getDefinition($entity_type);
      $query = $entity_storage->getQuery()->accessCheck(FALSE)->exists($field_name);
      $bundle_key = (string) $entity_definition->getKey('bundle');
      if ($bundle_key !== '') {
        $query->condition($bundle_key, $bundle);
      }
      $query->range(0, $entity_limit + 1);
      $ids = array_values($query->execute());
      if (count($ids) > $entity_limit) {
        $format_inspection_truncated = TRUE;
        $errors[] = $key . ': formatted-text inspection exceeded the ' . $entity_limit . '-entity bound.';
        $ids = array_slice($ids, 0, $entity_limit);
      }
      foreach (array_chunk($ids, 100) as $id_batch) {
        foreach ($entity_storage->loadMultiple($id_batch) as $entity) {
          $translations = [$entity];
          foreach (array_keys($entity->getTranslationLanguages()) as $langcode) {
            if ($entity->hasTranslation($langcode)) {
              $translations[] = $entity->getTranslation($langcode);
            }
          }
          foreach ($translations as $translation) {
            if (!$translation->hasField($field_name)) {
              continue;
            }
            foreach ($translation->get($field_name) as $item) {
              $format = trim((string) ($item->getValue()['format'] ?? ''));
              if ($format !== '') {
                $format_ids[$format] = TRUE;
              }
            }
          }
        }
      }
    }
    catch (\Throwable $throwable) {
      $format_inspection_error = $throwable->getMessage();
      $errors[] = $key . ': formatted-text formats could not be inspected: ' . $format_inspection_error;
    }
  }
  $format_ids = array_keys($format_ids);
  sort($format_ids, SORT_STRING);

  $permission_checks = [];
  foreach ((array) ($declared_field['editorRoles'] ?? []) as $declared_role) {
    $declared_role = trim((string) $declared_role);
    $resolved_role = $resolved_roles[$declared_role] ?? [
      'declared' => $declared_role,
      'resolved' => FALSE,
      'ambiguous' => FALSE,
      'roleId' => '',
      'roleLabel' => '',
      'administrator' => FALSE,
    ];
    $missing_permissions = [];
    foreach ($format_ids as $format_id) {
      $permission = 'use text format ' . $format_id;
      $role = $resolved_role['resolved'] ? ($role_entities[$resolved_role['roleId']] ?? NULL) : NULL;
      $has_permission = $role && (
        $resolved_role['administrator'] || $role->hasPermission($permission)
      );
      if (!$has_permission) {
        $missing_permissions[] = $permission;
      }
    }
    $permission_checks[] = $resolved_role + [
      'requiredPermissions' => array_map(static fn(string $format_id): string => 'use text format ' . $format_id, $format_ids),
      'missingPermissions' => $missing_permissions,
    ];
  }
  usort($permission_checks, static fn(array $a, array $b): int => $a['declared'] <=> $b['declared']);

  $field_results[] = [
    'key' => $key,
    'entityType' => $entity_type,
    'bundle' => $bundle,
    'machineName' => $field_name,
    'fieldDefinitionExists' => $definition_exists,
    'configEntityExists' => $config_entity_exists,
    'definitionSource' => $definition_source,
    'fieldType' => $field_type,
    'required' => $required,
    'defaultFormDisplayId' => $display_id,
    'defaultFormDisplayExists' => $display !== NULL,
    'widgetVisible' => $widget_visible,
    'widget' => $widget,
    'formattedText' => $formatted_text,
    'existingFormatIds' => $format_ids,
    'formatInspectionTruncated' => $format_inspection_truncated,
    'formatInspectionError' => $format_inspection_error,
    'editorRolePermissionChecks' => $permission_checks,
  ];
}
usort($field_results, static fn(array $a, array $b): int => $a['key'] <=> $b['key']);
$role_results = array_values($resolved_roles);
usort($role_results, static fn(array $a, array $b): int => $a['declared'] <=> $b['declared']);

$payload = [
  'schemaVersion' => 'public-kit.live-editor-surface-census.1',
  'readOnly' => TRUE,
  'rawFieldValuesEmitted' => FALSE,
  'entityInspectionLimitPerField' => $entity_limit,
  'fieldCount' => count($field_results),
  'roleCount' => count($role_results),
  'fields' => $field_results,
  'roles' => $role_results,
  'errors' => $errors,
];
$encoded_payload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
print json_encode($payload + [
  'fingerprint' => 'sha256:' . hash('sha256', $encoded_payload),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
`;

function parseLiveEditorSurfaceCensus(result) {
  const unavailable = (reason) => ({
    schemaVersion: LIVE_EDITOR_SURFACE_SCHEMA,
    confirmed: false,
    readOnly: true,
    rawFieldValuesEmitted: false,
    entityInspectionLimitPerField: 5000,
    fieldCount: 0,
    roleCount: 0,
    fields: [],
    roles: [],
    errors: [],
    fingerprint: '',
    reason
  });
  if (result?.ok !== true) {
    return unavailable('The read-only Drush live editor-surface census did not run.');
  }
  try {
    const parsed = JSON.parse(result.output);
    const fields = Array.isArray(parsed?.fields) ? parsed.fields : [];
    const roles = Array.isArray(parsed?.roles) ? parsed.roles : [];
    const fieldKeys = fields.map((field) => String(field?.key ?? ''));
    const roleKeys = roles.map((role) => String(role?.declared ?? ''));
    const structurallyValid =
      parsed?.schemaVersion === LIVE_EDITOR_SURFACE_SCHEMA &&
      parsed?.readOnly === true &&
      parsed?.rawFieldValuesEmitted === false &&
      Number(parsed?.entityInspectionLimitPerField) === 5000 &&
      Number(parsed?.fieldCount) === fields.length &&
      Number(parsed?.roleCount) === roles.length &&
      new Set(fieldKeys).size === fieldKeys.length &&
      new Set(roleKeys).size === roleKeys.length &&
      fieldKeys.every((key) => /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(key)) &&
      Array.isArray(parsed?.errors) &&
      /^sha256:[a-f0-9]{64}$/.test(String(parsed?.fingerprint ?? ''));
    const complete = structurallyValid && parsed.errors.length === 0 && fields.every((field) =>
      field?.formatInspectionTruncated !== true && !String(field?.formatInspectionError ?? '').trim()
    );
    return {
      ...parsed,
      confirmed: complete,
      reason: complete
        ? ''
        : structurallyValid
          ? `The live editor-surface census was incomplete${parsed.errors.length ? `: ${parsed.errors.join(' ')}` : '.'}`
          : 'The live editor-surface census returned an invalid schema or count.'
    };
  } catch {
    return unavailable('The read-only Drush live editor-surface census returned malformed JSON.');
  }
}

function inspectLiveEditorSurface(
  projectRoot,
  environment,
  fieldOutputMatrix,
  browserEvidence,
  readDrush = null
) {
  const declared = declaredLiveEditorSurface(fieldOutputMatrix, browserEvidence);
  const encoded = Buffer.from(JSON.stringify({ fields: declared.fields, roles: declared.roles }), 'utf8').toString('base64');
  const evaluation = [
    `$declared_editor_surface = json_decode(base64_decode('${encoded}', TRUE), TRUE, 512, JSON_THROW_ON_ERROR);`,
    DRUPAL_LIVE_EDITOR_SURFACE_EVAL
  ].join('\n');
  return parseLiveEditorSurfaceCensus(
    readDrush
      ? readDrush(['php:eval', evaluation], 120_000)
      : runDrushResult(projectRoot, environment, ['php:eval', evaluation], 120_000)
  );
}

export function reconcileLiveEditorSurface(fieldOutputMatrix, browserEvidence, census, { required = false } = {}) {
  const declared = declaredLiveEditorSurface(fieldOutputMatrix, browserEvidence);
  const expectedFields = declared.fields;
  const expectedRoles = declared.roles;
  const errors = [...declared.errors];
  const censusTrusted =
    census?.confirmed === true &&
    census?.schemaVersion === LIVE_EDITOR_SURFACE_SCHEMA &&
    census?.readOnly === true &&
    census?.rawFieldValuesEmitted === false &&
    Number(census?.fieldCount) === (Array.isArray(census?.fields) ? census.fields.length : -1) &&
    Number(census?.roleCount) === (Array.isArray(census?.roles) ? census.roles.length : -1);
  if (required && expectedFields.length > 0 && !censusTrusted) {
    errors.push(
      `G-EDITOR-01 requires a successful verifier-owned read-only Drush live editor-surface census: ${String(census?.reason ?? 'census unavailable')}`
    );
  }

  const liveFields = new Map((Array.isArray(census?.fields) ? census.fields : []).map((field) => [field?.key, field]));
  const liveRoles = new Map((Array.isArray(census?.roles) ? census.roles : []).map((role) => [role?.declared, role]));
  if (censusTrusted) {
    for (const field of expectedFields) {
      const live = liveFields.get(field.key);
      if (!live) {
        errors.push(`Live editor-surface census omitted public field ${field.key}.`);
        continue;
      }
      if (live.fieldDefinitionExists !== true) {
        errors.push(`Public field ${field.key} has no live Drupal field config or base-field definition.`);
      }
      if (live.defaultFormDisplayExists !== true) {
        errors.push(`Public field ${field.key} has no live default form display ${field.entityType}.${field.bundle}.default.`);
      }
      if (live.widgetVisible !== true || !String(live.widget ?? '').trim()) {
        errors.push(`Public field ${field.key} is hidden or has no visible widget on the live default form display.`);
      }
      if (!field.packetWidget || field.packetWidget !== String(live.widget ?? '').trim()) {
        errors.push(
          `field-output-matrix.json widget for ${field.key} (${field.packetWidget || 'missing'}) does not match live default form widget ${String(live.widget ?? '').trim() || 'hidden'}.`
        );
      }
      if (typeof field.packetRequired !== 'boolean' || field.packetRequired !== live.required) {
        errors.push(
          `field-output-matrix.json required metadata for ${field.key} (${String(field.packetRequired)}) does not match live field config (${String(live.required)}).`
        );
      }
      const formats = Array.isArray(live.existingFormatIds) ? live.existingFormatIds.filter(Boolean) : [];
      if (FORMATTED_TEXT_FIELD_TYPES.has(String(live.fieldType ?? '')) && formats.length > 0) {
        if (field.editorRoles.length === 0) {
          errors.push(
            `Public formatted-text field ${field.key} has existing values using ${formats.join(', ')} but no matching editor role is declared in browser-evidence.json.`
          );
        }
        const checks = new Map((Array.isArray(live.editorRolePermissionChecks)
          ? live.editorRolePermissionChecks
          : []).map((check) => [check?.declared, check]));
        for (const declaredRole of field.editorRoles) {
          const check = checks.get(declaredRole);
          if (!check?.resolved) {
            errors.push(`browser-evidence.json editor role ${declaredRole} could not be resolved in live Drupal for ${field.key}.`);
            continue;
          }
          const missing = Array.isArray(check?.missingPermissions) ? check.missingPermissions.filter(Boolean) : [];
          if (missing.length > 0) {
            errors.push(
              `Live Drupal editor role ${declaredRole} cannot edit existing ${field.key} values; missing ${missing.join(', ')}.`
            );
          }
        }
      }
    }
    for (const role of expectedRoles) {
      const live = liveRoles.get(role.declared);
      if (!live?.resolved) {
        errors.push(`browser-evidence.json editor role ${role.declared} could not be resolved in live Drupal.`);
      }
    }
  }

  return {
    schemaVersion: 'public-kit.live-editor-surface-reconciliation.1',
    censusRequired: required && expectedFields.length > 0,
    censusTrusted,
    declaredFieldCount: expectedFields.length,
    declaredRoleCount: expectedRoles.length,
    inspectedFieldCount: Array.isArray(census?.fields) ? census.fields.length : 0,
    inspectedRoleCount: Array.isArray(census?.roles) ? census.roles.length : 0,
    fieldKeys: expectedFields.map((field) => field.key),
    roleDeclarations: expectedRoles.map((role) => role.declared),
    passed: errors.length === 0 && (!required || expectedFields.length === 0 || censusTrusted),
    errors
  };
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

function normalizedAgentBlocker(blocker, index) {
  const value = typeof blocker === 'string' ? { message: blocker } : (blocker ?? {});
  const message = String(value.message ?? '').trim();
  if (!message) {
    return null;
  }
  const requestedCode = String(value.code ?? '').trim();
  const requestedOrigin = String(value.origin ?? '').trim();
  const attemptedEvidence = [...new Set((Array.isArray(value.attemptedEvidence)
    ? value.attemptedEvidence
    : [])
    .map((reference) => String(reference ?? '').trim())
    .filter(Boolean))];
  const missingInput = String(value.missingInput ?? '').trim();
  const requestedNextAction = String(value.nextAction ?? '').trim();
  const verifierOwnedOrigin =
    requestedOrigin === 'live-verifier' ||
    requestedOrigin === 'lifecycle-verifier' ||
    requestedOrigin.startsWith('packet-verifier:') ||
    requestedOrigin.startsWith('source-census-verifier:');
  const verifierConfirmedExternal =
    value.resolutionClass === 'external' &&
    value.verifierConfirmedExternal === true &&
    Boolean(requestedCode) &&
    verifierOwnedOrigin &&
    attemptedEvidence.length > 0 &&
    Boolean(missingInput) &&
    Boolean(requestedNextAction);
  const resolutionClass = verifierConfirmedExternal ? 'external' : 'agent_resolvable';
  return {
    code: requestedCode || `unclassified.${index + 1}`,
    origin: requestedOrigin || 'live-verifier',
    resolutionClass,
    message,
    attemptedEvidence,
    missingInput,
    nextAction: requestedNextAction || (
      resolutionClass === 'external'
        ? 'Supply the missing external input, refresh affected evidence, and rerun the default live verifier.'
        : 'Repair the failing check, refresh affected evidence, and rerun the default live verifier.'
    )
  };
}

export function agentContinuation({
  complete = false,
  blockers = [],
  blockedReasons = [],
  claimLabel = 'complete-local-rebuild'
} = {}) {
  const normalized = [...(Array.isArray(blockers) ? blockers : []),
    ...(Array.isArray(blockedReasons) ? blockedReasons : [])]
    .map(normalizedAgentBlocker)
    .filter(Boolean);
  const unique = [];
  const seen = new Set();
  for (const blocker of normalized) {
    const key = `${blocker.code}\u0000${blocker.message}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(blocker);
    }
  }
  const externalOnly = !complete && unique.length > 0 &&
    unique.every((blocker) => blocker.resolutionClass === 'external');
  return {
    schemaVersion: 'public-kit.agent-continuation.2',
    status: complete ? 'complete' : externalOnly ? 'externally_blocked' : 'continue_required',
    requiredAction: complete ? 'handoff' : externalOnly ? 'pause-and-report' : 'repair-and-reverify',
    shouldContinue: !complete && !externalOnly,
    agentMayPause: externalOnly,
    agentMayStop: complete,
    stopConditionMet: complete,
    humanReviewRequiredBeforeContinuing: false,
    externalBlockerMayPauseOnlyWhenRecorded: true,
    blockers: complete ? [] : unique,
    blockedReasons: complete ? [] : unique.map((blocker) => blocker.message),
    instruction: complete
      ? `The lifecycle-verified ${claimLabel} machine bar passed; handoff may proceed.`
      : externalOnly
        ? 'Pause and report the verifier-confirmed external blockers and their next actions. Do not claim completion or handoff. Resume the repair-and-reverify loop when the missing external input is available.'
      : 'Continue autonomously: repair every agent-resolvable failure, refresh the evidence it affects, and rerun the default live verifier. Do not hand off or pause while any agent-resolvable blocker remains, even when other blockers are external. Do not wait for routine human review.'
  };
}

export function reconcileLifecycleContinuation(report, { baseCompletionAllowed = false } = {}) {
  const lifecycleBlockers = baseCompletionAllowed
    ? (Array.isArray(report?.currentStateBlockedReasons) ? report.currentStateBlockedReasons : [])
      .map((message) => ({
        code: 'lifecycle.current-state',
        message,
        nextAction: 'Classify, repair, or revert the current lifecycle state, then rerun the default live verifier.',
        origin: 'lifecycle-verifier',
        resolutionClass: 'agent_resolvable'
      }))
    : [];
  report.completionBlockers = [
    ...(Array.isArray(report?.completionBlockers) ? report.completionBlockers : []),
    ...lifecycleBlockers
  ];
  report.completionBlockedReasons = report.completionBlockers
    .map((blocker) => String(blocker?.message ?? '').trim())
    .filter(Boolean);
  report.agentContinuation = agentContinuation({
    complete: report.currentSiteClaimAllowed === true,
    claimLabel: report.claimScope,
    blockers: report.completionBlockers
  });
  return report;
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
    if (!safeExistingProjectDirectory(packetRoot, dirname(candidate)) || lstatSync(candidate).isSymbolicLink()) {
      return false;
    }
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

const CUSTOM_CODE_SCHEMA = 'public-kit.custom-code-inventory.2';
const CUSTOM_CODE_REVIEW_SCHEMA = 'public-kit.custom-code-review.2';
const CUSTOM_CODE_QUALITY_SCHEMA = 'public-kit.custom-code-quality.1';
const CUSTOM_CODE_TEST_EXECUTION_SCHEMA = 'public-kit.custom-code-test-execution.1';
const EXECUTABLE_CUSTOM_SURFACE_KINDS = new Set([
  'controller_class',
  'hook_or_callback',
  'plugin_class',
  'route',
  'service_registration'
]);
const CUSTOM_EXTENSION_DIRECTORY_LIMIT = 10_000;
const CUSTOM_EXTENSION_FILE_LIMIT = 10_000;
const CUSTOM_EXTENSION_SCAN_DEADLINE_MS = 5_000;
const CUSTOM_EXTENSION_FILE_BYTES_LIMIT = 5 * 1024 * 1024;
const CUSTOM_EXTENSION_TOTAL_BYTES_LIMIT = 100 * 1024 * 1024;
const CUSTOM_CODE_EXTENSION_LIMIT = 256;
const CUSTOM_CODE_DIRECTORY_LIMIT = 25_000;
const CUSTOM_CODE_FILE_LIMIT = 25_000;
const CUSTOM_CODE_SCAN_DEADLINE_MS = 30_000;
const CUSTOM_CODE_TOTAL_BYTES_LIMIT = 250 * 1024 * 1024;
const CUSTOM_CODE_SURFACES_PER_FILE_LIMIT = 5_000;
const CUSTOM_CODE_SURFACE_LIMIT = 50_000;
const CUSTOM_CODE_TEST_METHODS_PER_FILE_LIMIT = 5_000;
const CUSTOM_CODE_TEST_METHOD_LIMIT = 50_000;
const CUSTOM_CODE_PHP_INPUT_BYTES_LIMIT = 48 * 1024;
export const CUSTOM_CODE_EXECUTION_LIMITS = Object.freeze({
  aggregateDeadlineMs: 900_000,
  aggregateOutputBytes: 64 * 1024 * 1024,
  cleanupReserveMs: 30_000,
  commands: 384,
  composerMetadataBytes: 8 * 1024 * 1024,
  coverageRows: 128,
  dataCasesPerMethod: 256,
  dataCasesTotal: 2_048,
  discoveryOutputBytes: 2 * 1024 * 1024,
  discoveryTimeoutMs: 30_000,
  findingsPerCheck: 200,
  findingMessageCharacters: 500,
  junitBytesPerRun: 2 * 1024 * 1024,
  junitBytesTotal: 32 * 1024 * 1024,
  lintOutputBytes: 64 * 1024,
  lintTimeoutMs: 10_000,
  pathArgvBytes: 24 * 1024,
  phpcsChunkFiles: 32,
  phpcsOutputBytes: 8 * 1024 * 1024,
  phpcsTimeoutMs: 120_000,
  phpFiles: 256,
  phpstanOutputBytes: 8 * 1024 * 1024,
  phpstanTimeoutMs: 180_000,
  packageBytes: 256 * 1024 * 1024,
  packageFiles: 50_000,
  composerPackageBytesTotal: 512 * 1024 * 1024,
  composerPackageFilesTotal: 100_000,
  composerPackages: 512,
  testExecutionTimeoutMs: 90_000,
  testFiles: 32,
  testMethods: 32
});
const CUSTOM_CODE_DDEV_CONFIG_FILE_RE = /^config(?:\.[A-Za-z0-9_.-]+)?\.ya?ml$/i;
const CUSTOM_CODE_DDEV_COMPOSE_FILE_RE = /^(?:docker-compose|router-compose|ssh-auth-compose)(?:\.[A-Za-z0-9_.-]+)?\.ya?ml$/i;
const CUSTOM_CODE_DDEV_FILE_LIMIT = 10_000;
const CUSTOM_CODE_DDEV_TOTAL_BYTES_LIMIT = 32 * 1024 * 1024;
const CUSTOM_EXTENSION_WALK_EXCLUDED_DIRECTORIES = new Set(['.git', 'node_modules', 'vendor']);
const CUSTOM_SOURCE_EXCLUDED_SEGMENTS = new Set([
  '.cache', '.ddev', '.git', '.github', '.idea', '.vscode', 'bower_components', 'coverage',
  'docs', 'fixture', 'fixtures', 'node_modules', 'scripts', 'test', 'test-data',
  'test_data', 'testdata', 'tests', 'tmp', 'tooling', 'tools', 'translations', 'vendor'
]);
export const CUSTOM_SOLUTION_LADDER_STAGES = Object.freeze([
  'core',
  'installed_drupal_cms',
  'recipe',
  'maintained_contrib',
  'custom_exception'
]);

export function customExtensionFiles(root, label, options = {}) {
  const directoryLimit = options.directoryLimit ?? CUSTOM_EXTENSION_DIRECTORY_LIMIT;
  const fileLimit = options.fileLimit ?? CUSTOM_EXTENSION_FILE_LIMIT;
  const deadlineMs = options.deadlineMs ?? CUSTOM_EXTENSION_SCAN_DEADLINE_MS;
  const fileBytesLimit = options.fileBytesLimit ?? CUSTOM_EXTENSION_FILE_BYTES_LIMIT;
  const totalBytesLimit = options.totalBytesLimit ?? CUSTOM_EXTENSION_TOTAL_BYTES_LIMIT;
  const now = options.now ?? Date.now;
  const startedAt = now();
  const sharedBudget = options.sharedBudget ?? null;
  const errors = [];
  const files = [];
  let bytesScanned = 0;
  let filesVisited = 0;
  const deadlineError = () => {
    const currentTime = now();
    if (sharedBudget && currentTime - sharedBudget.startedAt > sharedBudget.deadlineMs) {
      return `Custom code inventory aggregate exceeded its ${sharedBudget.deadlineMs}ms deadline.`;
    }
    if (currentTime - startedAt > deadlineMs) {
      return `Custom extension inventory exceeded its ${deadlineMs}ms deadline under ${label}.`;
    }
    return '';
  };
  let rootRealPath = '';
  try {
    rootRealPath = realpathSync(root);
    if (!statSync(rootRealPath).isDirectory()) {
      return { bytesScanned, errors: [`${label} is not a directory and cannot be inventoried as a custom extension.`], files };
    }
  } catch (error) {
    return { bytesScanned, errors: [`${label} could not be resolved for custom extension inventory: ${error.message}`], files };
  }

  const pending = [{ logicalPath: root, realPath: rootRealPath }];
  const visitedRealDirectories = new Set();
  scan: while (pending.length > 0) {
    const deadline = deadlineError();
    if (deadline) {
      errors.push(deadline);
      break;
    }
    const directory = pending.pop();
    if (visitedRealDirectories.has(directory.realPath)) {
      continue;
    }
    visitedRealDirectories.add(directory.realPath);
    if (visitedRealDirectories.size > directoryLimit) {
      errors.push(`Custom extension inventory exceeded ${directoryLimit} directories under ${label}.`);
      break;
    }
    if (sharedBudget) {
      sharedBudget.directoriesVisited += 1;
      if (sharedBudget.directoriesVisited > sharedBudget.directoryLimit) {
        errors.push(`Custom code inventory aggregate exceeded ${sharedBudget.directoryLimit} directories.`);
        break;
      }
    }

    let entries = [];
    try {
      entries = readdirSync(directory.logicalPath, { withFileTypes: true });
    } catch (error) {
      errors.push(`${label} could not read ${directory.logicalPath}: ${error.message}`);
      continue;
    }
    for (const entry of entries.sort((left, right) => comparePortable(left.name, right.name))) {
      if (CUSTOM_EXTENSION_WALK_EXCLUDED_DIRECTORIES.has(entry.name)) {
        continue;
      }
      const entryDeadline = deadlineError();
      if (entryDeadline) {
        errors.push(entryDeadline);
        break scan;
      }
      const logicalPath = join(directory.logicalPath, entry.name);
      let realPath = '';
      let stats;
      try {
        realPath = realpathSync(logicalPath);
        if (!pathIsInside(rootRealPath, realPath)) {
          errors.push(`${logicalPath} resolves outside custom extension root ${label}.`);
          continue;
        }
        stats = statSync(realPath);
      } catch (error) {
        errors.push(`${logicalPath} could not be resolved for custom extension inventory: ${error.message}`);
        continue;
      }
      if (stats.isDirectory()) {
        pending.push({ logicalPath, realPath });
      } else if (stats.isFile()) {
        filesVisited += 1;
        if (filesVisited > fileLimit) {
          errors.push(`Custom extension inventory exceeded ${fileLimit} files under ${label}.`);
          break scan;
        }
        if (sharedBudget) {
          sharedBudget.filesVisited += 1;
          if (sharedBudget.filesVisited > sharedBudget.fileLimit) {
            errors.push(`Custom code inventory aggregate exceeded ${sharedBudget.fileLimit} files.`);
            break scan;
          }
        }
        if (customInventoryFileNeedsContent(root, logicalPath)) {
          if (stats.size > fileBytesLimit) {
            errors.push(`${logicalPath} exceeds the ${fileBytesLimit}-byte custom source file limit.`);
            continue;
          }
          if (bytesScanned + stats.size > totalBytesLimit) {
            errors.push(`Custom extension inventory exceeded ${totalBytesLimit} total source bytes under ${label}.`);
            break scan;
          }
          if (sharedBudget && sharedBudget.bytesScanned + stats.size > sharedBudget.totalBytesLimit) {
            errors.push(`Custom code inventory aggregate exceeded ${sharedBudget.totalBytesLimit} total source bytes.`);
            break scan;
          }
          bytesScanned += stats.size;
          if (sharedBudget) {
            sharedBudget.bytesScanned += stats.size;
          }
        }
        files.push(logicalPath);
      }
    }
  }
  const finalDeadline = deadlineError();
  if (finalDeadline && !errors.includes(finalDeadline)) {
    errors.push(finalDeadline);
  }
  return { bytesScanned, errors, files: files.sort(comparePortable) };
}

function customSourceKind(extensionRelativePath) {
  const normalized = extensionRelativePath.toLowerCase().replaceAll('\\', '/');
  const filename = basename(normalized);
  if (/(?:^|\/)config\/(?:install|optional)\//.test(normalized)) {
    return 'shipped_config';
  }
  if (/(?:^|\/)components?\/.*\.component\.ya?ml$/.test(normalized) || filename === 'component.yml') {
    return 'sdc_component';
  }
  if (/\.info\.ya?ml$/.test(filename)) {
    return 'extension_metadata';
  }
  if (/\.(?:module|theme|install|inc|test|profile)$/.test(filename)) {
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
  if (segments.some((segment) => CUSTOM_SOURCE_EXCLUDED_SEGMENTS.has(segment)) || filename.startsWith('.')) {
    return false;
  }
  if (/\.map$/.test(filename) || /^(?:readme|changelog|license)(?:\.|$)/.test(filename)) {
    return false;
  }
  return Boolean(customSourceKind(normalized));
}

function customInventoryFileNeedsContent(extensionRoot, file) {
  const extensionRelativePath = relative(extensionRoot, file);
  const normalized = extensionRelativePath.split(sep).join('/');
  return customSourceFileEligible(extensionRelativePath) || (
    /(?:^|\/)tests?(?:\/|$)/i.test(normalized) &&
    /\.(?:php|js|mjs|ts)$/i.test(normalized)
  );
}

function sourceLineLocator(text) {
  let line = 1;
  let offset = 0;
  let previousTarget = 0;
  return (index) => {
    const target = Math.max(0, index);
    if (target < previousTarget) {
      line = 1;
      offset = 0;
    }
    let newline = text.indexOf('\n', offset);
    while (newline !== -1 && newline < target) {
      line += 1;
      offset = newline + 1;
      newline = text.indexOf('\n', offset);
    }
    previousTarget = target;
    return line;
  };
}

function customSourceSurface(extension, path, kind, name, locateLine, index = 0) {
  const identity = `${extension}\u0000${path}\u0000${kind}\u0000${name}`;
  return {
    id: `SURFACE-${sha256(identity).slice(0, 16)}`,
    kind,
    name,
    line: locateLine(index)
  };
}

function yamlMappingChildren(text, rootKey, limit = CUSTOM_CODE_SURFACES_PER_FILE_LIMIT + 1) {
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
        if (children.length >= limit) {
          break;
        }
      }
    }
    offset += line.length + 1;
  }
  return children;
}

function customSourceSurfaces(extension, sharedPath, extensionRelativePath, kind, text) {
  const surfaces = [];
  const locateLine = sourceLineLocator(text);
  let truncated = false;
  const add = (surfaceKind, name, index = 0) => {
    if (surfaces.length >= CUSTOM_CODE_SURFACES_PER_FILE_LIMIT) {
      truncated = true;
      return false;
    }
    surfaces.push(customSourceSurface(extension, sharedPath, surfaceKind, name, locateLine, index));
    return true;
  };
  const normalized = extensionRelativePath.split(sep).join('/');
  if (kind === 'procedural_php') {
    for (const match of text.matchAll(/^[ \t]*function\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/gm)) {
      const surfaceKind = match[1].startsWith(`${extension}_`) ? 'hook_or_callback' : 'function';
      if (!add(surfaceKind, match[1], match.index)) break;
    }
  } else if (kind === 'php_class') {
    for (const match of text.matchAll(/^[ \t]*(?:(?:abstract|final|readonly)\s+)*(class|interface|trait|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b/gm)) {
      const surfaceKind = /(?:^|\/)src\/Controller\//i.test(normalized)
        ? 'controller_class'
        : /(?:^|\/)src\/Plugin\//i.test(normalized)
          ? 'plugin_class'
          : match[1];
      if (!add(surfaceKind, match[2], match.index)) break;
    }
  } else if (kind === 'javascript') {
    for (const match of text.matchAll(/^[ \t]*Drupal\.behaviors\.([A-Za-z_][A-Za-z0-9_]*)\s*=/gm)) {
      if (!add('drupal_behavior', match[1], match.index)) break;
    }
  } else if (kind === 'drupal_registration') {
    if (/\.services\.ya?ml$/i.test(sharedPath)) {
      for (const registration of yamlMappingChildren(text, 'services')) {
        if (!add('service_registration', registration.name, registration.index)) break;
      }
    } else if (/\.routing\.ya?ml$/i.test(sharedPath)) {
      for (const match of text.matchAll(/^([A-Za-z0-9_.\\-]+):\s*(?:#.*)?$/gm)) {
        if (!add('route', match[1], match.index)) break;
      }
    } else {
      for (const match of text.matchAll(/^([A-Za-z0-9_.\\-]+):\s*(?:#.*)?$/gm)) {
        if (!match[1].startsWith('_')) {
          if (!add('registration', match[1], match.index)) break;
        }
      }
    }
  } else if (kind === 'shipped_config') {
    add('shipped_config', basename(sharedPath).replace(/\.ya?ml$/i, ''));
  } else if (kind === 'sdc_component') {
    add('sdc_component', basename(dirname(sharedPath)));
  } else if (kind === 'twig_template') {
    add('twig_template', basename(sharedPath));
  } else if (kind === 'stylesheet') {
    add('stylesheet', basename(sharedPath));
  }
  if (surfaces.length === 0) {
    add(`${kind}_file`, basename(sharedPath));
  }
  return {
    surfaces: [...new Map(surfaces.map((surface) => [surface.id, surface])).values()]
      .sort((left, right) => comparePortable(left.id, right.id)),
    truncated
  };
}

function routingRecords(text, file, extension) {
  return text
    .split(/\n(?=[A-Za-z0-9_.-]+:\s*(?:#.*)?\n)/)
    .map((block) => {
      const name = block.match(/^([A-Za-z0-9_.-]+):\s*(?:#.*)?$/m)?.[1] ?? '';
      const path = block.match(/^\s+path:\s*['"]?([^'"\n#]+)['"]?\s*(?:#.*)?$/m)?.[1]?.trim() ?? '';
      const controller = block.match(/^\s+_controller:\s*['"]?([^'"\n#]+)['"]?\s*(?:#.*)?$/m)?.[1]?.trim() ?? '';
      return { controller, extension, file, name, path, discovery: 'routing_yaml' };
    })
    .filter((route) => route.name && route.path);
}

function phpCodeMask(text) {
  const characters = [...text];
  let state = 'code';
  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index];
    const next = characters[index + 1] ?? '';
    if (state === 'code') {
      if (character === '/' && next === '/') {
        characters[index] = characters[index + 1] = ' ';
        index += 1;
        state = 'line_comment';
      } else if (character === '#' && next !== '[') {
        characters[index] = ' ';
        state = 'line_comment';
      } else if (character === '/' && next === '*') {
        characters[index] = characters[index + 1] = ' ';
        index += 1;
        state = 'block_comment';
      } else if (character === "'") {
        characters[index] = ' ';
        state = 'single_quote';
      } else if (character === '"') {
        characters[index] = ' ';
        state = 'double_quote';
      }
      continue;
    }
    if (character === '\n' || character === '\r') {
      if (state === 'line_comment') {
        state = 'code';
      }
      continue;
    }
    characters[index] = ' ';
    if (state === 'block_comment' && character === '*' && next === '/') {
      characters[index + 1] = ' ';
      index += 1;
      state = 'code';
    } else if ((state === 'single_quote' || state === 'double_quote') && character === '\\') {
      if (index + 1 < characters.length) {
        characters[index + 1] = ' ';
        index += 1;
      }
    } else if (state === 'single_quote' && character === "'") {
      state = 'code';
    } else if (state === 'double_quote' && character === '"') {
      state = 'code';
    }
  }
  return characters.join('');
}

export function customTestMethodId(extension, path, className, methodName) {
  return `TESTMETHOD-${sha256(`${extension}\u0000${path}\u0000${className}\u0000${methodName}`).slice(0, 16)}`;
}

function phpTestMethods(extension, path, text) {
  const masked = phpCodeMask(text);
  const namespace = masked.match(/^[ \t]*namespace\s+([A-Za-z_][A-Za-z0-9_\\]*)\s*[;{]/m)?.[1] ?? '';
  const methods = [];
  const classPattern = /(?:^|\n)[ \t]*(?:(?:abstract|final|readonly)\s+)*class\s+([A-Za-z_][A-Za-z0-9_]*)\b/g;
  for (const classMatch of masked.matchAll(classPattern)) {
    const className = namespace ? `${namespace}\\${classMatch[1]}` : classMatch[1];
    const openingBrace = masked.indexOf('{', (classMatch.index ?? 0) + classMatch[0].length);
    if (openingBrace === -1) {
      continue;
    }
    const tokenPattern = /[{}]|(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*(test[A-Za-z0-9_]+)\s*\(/g;
    tokenPattern.lastIndex = openingBrace;
    let depth = 0;
    for (let token = tokenPattern.exec(masked); token; token = tokenPattern.exec(masked)) {
      if (token[0] === '{') {
        depth += 1;
      } else if (token[0] === '}') {
        depth -= 1;
        if (depth === 0) {
          break;
        }
      } else if (depth === 1 && token[1]) {
        const methodName = token[1];
        methods.push({
          id: customTestMethodId(extension, path, className, methodName),
          className,
          methodName
        });
        if (methods.length > CUSTOM_CODE_TEST_METHODS_PER_FILE_LIMIT) {
          break;
        }
      }
    }
    if (methods.length > CUSTOM_CODE_TEST_METHODS_PER_FILE_LIMIT) {
      break;
    }
  }
  return methods;
}

function inspectCustomTestFile(extension, projectRoot, file) {
  const sharedPath = relative(projectRoot, file).split(sep).join('/');
  if (!/(?:^|\/)tests?(?:\/|$)/i.test(sharedPath) || !/\.(?:php|js|mjs|ts)$/i.test(sharedPath)) {
    return null;
  }
  const bytes = readFileSync(file);
  const text = bytes.toString('utf8');
  const testMethods = /\.php$/i.test(sharedPath) ? phpTestMethods(extension, sharedPath, text) : [];
  const truncated = testMethods.length > CUSTOM_CODE_TEST_METHODS_PER_FILE_LIMIT;
  return {
    id: `TEST-${sha256(`${extension}\u0000${sharedPath}`).slice(0, 16)}`,
    extension,
    path: sharedPath,
    sha256: `sha256:${sha256(bytes)}`,
    testMethods: [...new Map(testMethods.map((method) => [method.id, method])).values()]
      .sort((left, right) => comparePortable(left.id, right.id)),
    truncated
  };
}

function topLevelYamlScalar(text, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return text.match(new RegExp(`^${escaped}:\\s*["']?([^\\s#"']+)["']?\\s*(?:#.*)?$`, 'mi'))?.[1]?.trim() ?? '';
}

export function customCapabilityId(extension, capabilityKey) {
  return `CAP-${sha256(`${extension}\u0000${capabilityKey}`).slice(0, 16)}`;
}

export function inspectCustomCodeFilesystem(projectRoot, options = {}) {
  let projectRealPath = '';
  try {
    projectRealPath = realpathSync(projectRoot);
  } catch (error) {
    return {
      schemaVersion: CUSTOM_CODE_SCHEMA,
      bounded: true,
      completed: false,
      errors: [`Project root could not be resolved for custom extension inventory: ${error.message}`],
      extensions: [], sourceFiles: [], controllers: [], routes: [], tests: [], fingerprint: ''
    };
  }
  const docroot = ddevDocroot(projectRoot);
  const extensions = [];
  const sourceFiles = [];
  const controllers = [];
  const routes = [];
  const tests = [];
  const errors = [];
  const now = options.now ?? Date.now;
  const extensionLimit = options.extensionLimit ?? CUSTOM_CODE_EXTENSION_LIMIT;
  const aggregateBudget = {
    startedAt: now(),
    deadlineMs: options.deadlineMs ?? CUSTOM_CODE_SCAN_DEADLINE_MS,
    directoryLimit: options.directoryLimit ?? CUSTOM_CODE_DIRECTORY_LIMIT,
    directoriesVisited: 0,
    fileLimit: options.fileLimit ?? CUSTOM_CODE_FILE_LIMIT,
    filesVisited: 0,
    totalBytesLimit: options.totalBytesLimit ?? CUSTOM_CODE_TOTAL_BYTES_LIMIT,
    bytesScanned: 0
  };
  let extensionCount = 0;
  let surfaceCount = 0;
  let testMethodCount = 0;
  extensionRoots: for (const [type, relativeRoot] of [
    ['module', join(docroot, 'modules', 'custom')],
    ['theme', join(docroot, 'themes', 'custom')]
  ]) {
    const root = join(projectRoot, relativeRoot);
    if (!existsSync(root)) {
      continue;
    }
    let entries = [];
    try {
      entries = readdirSync(root, { withFileTypes: true });
    } catch (error) {
      errors.push(`${relativeRoot.split(sep).join('/')} could not be read: ${error.message}`);
      continue;
    }
    for (const entry of entries.sort((left, right) => comparePortable(left.name, right.name))) {
      const extensionRoot = join(root, entry.name);
      let extensionRealPath = '';
      try {
        extensionRealPath = realpathSync(extensionRoot);
        if (!statSync(extensionRealPath).isDirectory()) {
          continue;
        }
      } catch (error) {
        if (entry.isDirectory() || entry.isSymbolicLink()) {
          errors.push(`${relative(projectRoot, extensionRoot).split(sep).join('/')} could not be resolved: ${error.message}`);
        }
        continue;
      }
      const extensionPath = relative(projectRoot, extensionRoot).split(sep).join('/');
      if (!pathIsInside(projectRealPath, extensionRealPath)) {
        errors.push(`${extensionPath} resolves outside the project root and cannot be inventoried as custom code.`);
        continue;
      }
      extensionCount += 1;
      if (extensionCount > extensionLimit) {
        errors.push(`Custom code inventory aggregate exceeded ${extensionLimit} custom extensions.`);
        break extensionRoots;
      }
      const walked = customExtensionFiles(extensionRoot, extensionPath, { now, sharedBudget: aggregateBudget });
      errors.push(...walked.errors.map((error) => error.replaceAll(extensionRoot, extensionPath)));
      if (walked.errors.some((error) => error.startsWith('Custom code inventory aggregate exceeded'))) {
        break extensionRoots;
      }
      const nestedInfoFiles = walked.files.filter((file) =>
        dirname(file) !== extensionRoot &&
        /\.info\.yml$/i.test(basename(file)) &&
        customSourceFileEligible(relative(extensionRoot, file))
      );
      if (nestedInfoFiles.length > 0) {
        errors.push(`${extensionPath} contains ${nestedInfoFiles.length} nested custom extension(s); nested production extension layouts are rejected instead of being attributed to the parent extension.`);
        continue;
      }
      const infoFiles = walked.files.filter((file) =>
        dirname(file) === extensionRoot && /\.info\.yml$/i.test(basename(file))
      );
      if (infoFiles.length !== 1) {
        errors.push(`${extensionPath} must contain exactly one top-level *.info.yml file; found ${infoFiles.length}.`);
        continue;
      }
      const infoFile = infoFiles[0];
      const machineName = basename(infoFile).replace(/\.info\.yml$/i, '');
      let declaredType = '';
      try {
        declaredType = topLevelYamlScalar(readFileSync(infoFile, 'utf8'), 'type');
      } catch (error) {
        errors.push(`${relative(projectRoot, infoFile).split(sep).join('/')} could not be read: ${error.message}`);
      }
      if (machineName !== entry.name) {
        errors.push(`${extensionPath} directory name does not match derived extension machine name ${machineName}.`);
      }
      if (!/^[a-z][a-z0-9_]*$/.test(machineName)) {
        errors.push(`${extensionPath} does not derive a valid Drupal extension machine name.`);
      }
      if (declaredType !== type) {
        errors.push(`${extensionPath} must declare type: ${type}; found ${declaredType || '(missing)'}.`);
      }

      const extensionSourceIds = [];
      const extensionTestIds = [];
      const extensionRouteNames = [];
      const extensionSchemaFiles = [];
      const extensionShippedConfigNames = [];
      for (const file of walked.files) {
        if (now() - aggregateBudget.startedAt > aggregateBudget.deadlineMs) {
          errors.push(`Custom code inventory aggregate exceeded its ${aggregateBudget.deadlineMs}ms deadline.`);
          break extensionRoots;
        }
        const sharedPath = relative(projectRoot, file).split(sep).join('/');
        const extensionRelativePath = relative(extensionRoot, file);
        try {
          const test = inspectCustomTestFile(machineName, projectRoot, file);
          if (test) {
            if (test.truncated) {
              errors.push(`${sharedPath} exceeded ${CUSTOM_CODE_TEST_METHODS_PER_FILE_LIMIT} discovered test methods.`);
              break extensionRoots;
            }
            testMethodCount += test.testMethods.length;
            if (testMethodCount > CUSTOM_CODE_TEST_METHOD_LIMIT) {
              errors.push(`Custom code inventory aggregate exceeded ${CUSTOM_CODE_TEST_METHOD_LIMIT} discovered test methods.`);
              break extensionRoots;
            }
            delete test.truncated;
            tests.push(test);
            extensionTestIds.push(test.id);
          }
          if (customSourceFileEligible(extensionRelativePath)) {
            const bytes = readFileSync(file);
            const text = bytes.toString('utf8');
            const kind = customSourceKind(extensionRelativePath);
            const surfaceInventory = customSourceSurfaces(machineName, sharedPath, extensionRelativePath, kind, text);
            if (surfaceInventory.truncated) {
              errors.push(`${sharedPath} exceeded ${CUSTOM_CODE_SURFACES_PER_FILE_LIMIT} lexical/registration custom-code surfaces.`);
              break extensionRoots;
            }
            surfaceCount += surfaceInventory.surfaces.length;
            if (surfaceCount > CUSTOM_CODE_SURFACE_LIMIT) {
              errors.push(`Custom code inventory aggregate exceeded ${CUSTOM_CODE_SURFACE_LIMIT} lexical/registration surfaces.`);
              break extensionRoots;
            }
            const source = {
              id: `SOURCE-${sha256(`${machineName}\u0000${sharedPath}`).slice(0, 16)}`,
              extension: machineName,
              path: sharedPath,
              kind,
              sha256: `sha256:${sha256(bytes)}`,
              surfaces: surfaceInventory.surfaces
            };
            sourceFiles.push(source);
            extensionSourceIds.push(source.id);
            if (source.surfaces.some((surface) => surface.kind === 'controller_class')) {
              controllers.push({
                extension: machineName,
                path: sharedPath,
                sourceFileId: source.id,
                surfaceIds: source.surfaces.filter((surface) => surface.kind === 'controller_class').map((surface) => surface.id)
              });
            }
            if (kind === 'shipped_config') {
              extensionShippedConfigNames.push(basename(sharedPath).replace(/\.ya?ml$/i, ''));
            }
          }
          if (/(?:^|\/)config\/schema\/.*\.schema\.ya?ml$/i.test(extensionRelativePath.split(sep).join('/'))) {
            extensionSchemaFiles.push(sharedPath);
          }
          if (/\.routing\.ya?ml$/i.test(sharedPath)) {
            const discovered = routingRecords(readFileSync(file, 'utf8'), sharedPath, machineName);
            routes.push(...discovered);
            extensionRouteNames.push(...discovered.map((route) => route.name));
          }
        } catch (error) {
          errors.push(`Custom code inventory could not read ${sharedPath}: ${error.message}`);
        }
      }
      extensions.push({
        id: `EXTENSION-${sha256(`${type}\u0000${machineName}`).slice(0, 16)}`,
        machineName,
        type,
        path: extensionPath,
        drupalPath: relative(join(projectRoot, docroot), extensionRoot).split(sep).join('/'),
        infoFile: relative(projectRoot, infoFile).split(sep).join('/'),
        sourceFileIds: [...new Set(extensionSourceIds)].sort(comparePortable),
        testFileIds: [...new Set(extensionTestIds)].sort(comparePortable),
        routeNames: [...new Set(extensionRouteNames)].sort(comparePortable),
        schemaFiles: [...new Set(extensionSchemaFiles)].sort(comparePortable),
        shippedConfigNames: [...new Set(extensionShippedConfigNames)].sort(comparePortable)
      });
    }
  }
  const routeNames = new Set();
  for (const route of routes) {
    if (routeNames.has(route.name)) {
      errors.push(`Custom route name ${route.name} is declared more than once.`);
    }
    routeNames.add(route.name);
  }
  const extensionNames = new Set();
  for (const extension of extensions) {
    if (extensionNames.has(extension.machineName)) {
      errors.push(`Custom extension machine name ${extension.machineName} is declared more than once across modules and themes.`);
    }
    extensionNames.add(extension.machineName);
  }
  if (
    now() - aggregateBudget.startedAt > aggregateBudget.deadlineMs &&
    !errors.some((error) => error === `Custom code inventory aggregate exceeded its ${aggregateBudget.deadlineMs}ms deadline.`)
  ) {
    errors.push(`Custom code inventory aggregate exceeded its ${aggregateBudget.deadlineMs}ms deadline.`);
  }
  extensions.sort((left, right) => comparePortable(left.path, right.path));
  sourceFiles.sort((left, right) => comparePortable(left.path, right.path));
  controllers.sort((left, right) => comparePortable(left.path, right.path));
  routes.sort((left, right) => comparePortable(`${left.file}\u0000${left.name}`, `${right.file}\u0000${right.name}`));
  tests.sort((left, right) => comparePortable(left.path, right.path));
  const fingerprintInput = { extensions, sourceFiles, controllers, routes, tests };
  return {
    schemaVersion: CUSTOM_CODE_SCHEMA,
    bounded: true,
    limits: {
      directoriesPerExtension: CUSTOM_EXTENSION_DIRECTORY_LIMIT,
      filesPerExtension: CUSTOM_EXTENSION_FILE_LIMIT,
      sourceBytesPerFile: CUSTOM_EXTENSION_FILE_BYTES_LIMIT,
      sourceBytesPerExtension: CUSTOM_EXTENSION_TOTAL_BYTES_LIMIT,
      millisecondsPerExtension: CUSTOM_EXTENSION_SCAN_DEADLINE_MS,
      extensionsTotal: extensionLimit,
      directoriesTotal: aggregateBudget.directoryLimit,
      filesTotal: aggregateBudget.fileLimit,
      sourceBytesTotal: aggregateBudget.totalBytesLimit,
      millisecondsTotal: aggregateBudget.deadlineMs,
      surfacesPerFile: CUSTOM_CODE_SURFACES_PER_FILE_LIMIT,
      surfacesTotal: CUSTOM_CODE_SURFACE_LIMIT,
      testMethodsPerFile: CUSTOM_CODE_TEST_METHODS_PER_FILE_LIMIT,
      testMethodsTotal: CUSTOM_CODE_TEST_METHOD_LIMIT,
      phpInputBytes: CUSTOM_CODE_PHP_INPUT_BYTES_LIMIT
    },
    completed: errors.length === 0,
    applies: extensions.length > 0,
    errors,
    extensions,
    sourceFiles,
    controllers,
    routes,
    tests,
    fingerprint: `sha256:${sha256(JSON.stringify(fingerprintInput))}`
  };
}

export const CUSTOM_ROUTE_AUDIT_PHP = String.raw`
$output = ['completed' => FALSE, 'routes' => [], 'violations' => []];
$route_provider = \Drupal::service('router.route_provider');
$url_generator = \Drupal::service('url_generator');
$access_manager = \Drupal::service('access_manager');
$router = \Drupal::service('router.no_access_checks');
$request_stack = \Drupal::service('request_stack');
$container = \Drupal::getContainer();
$anonymous = new \Drupal\Core\Session\AnonymousUserSession();
$route_inputs = is_array($audit_input['routes'] ?? NULL) ? $audit_input['routes'] : [];
$route_bindings = is_array($audit_input['bindings'] ?? NULL) ? $audit_input['bindings'] : [];
$custom_extensions = is_array($audit_input['extensions'] ?? NULL) ? $audit_input['extensions'] : [];
$base_url = rtrim((string) ($audit_input['baseUrl'] ?? 'http://localhost'), '/');
$route_scan_limit = 5000;
$core_extensions = \Drupal::service('config.storage')->read('core.extension') ?: [];
$active_custom_extensions = [];
foreach ($custom_extensions as $extension) {
  $machine_name = (string) ($extension['machineName'] ?? '');
  $type = (string) ($extension['type'] ?? '');
  $expected_path = trim((string) ($extension['drupalPath'] ?? ''), '/');
  if ($machine_name === '' || !in_array($type, ['module', 'theme'], TRUE) || $expected_path === '') {
    $output['violations'][] = ['name' => '', 'extension' => $machine_name, 'reason' => 'invalid_custom_extension_identity'];
    continue;
  }
  try {
    $list = \Drupal::service($type === 'module' ? 'extension.list.module' : 'extension.list.theme');
    $runtime_path = trim((string) $list->getPath($machine_name), '/');
    if ($runtime_path !== $expected_path) {
      $output['violations'][] = [
        'name' => '',
        'extension' => $machine_name,
        'reason' => 'custom_extension_runtime_path_mismatch',
        'expectedPath' => $expected_path,
        'runtimePath' => $runtime_path,
      ];
      continue;
    }
    if (array_key_exists($machine_name, is_array($core_extensions[$type] ?? NULL) ? $core_extensions[$type] : [])) {
      $active_custom_extensions[] = $extension;
    }
  }
  catch (\Throwable $error) {
    $output['violations'][] = [
      'name' => '',
      'extension' => $machine_name,
      'reason' => 'custom_extension_runtime_path_unavailable',
      'errorType' => get_class($error),
      'errorSha256' => hash('sha256', $error->getMessage()),
    ];
  }
}
$active_custom_extension_names = array_fill_keys(array_column($active_custom_extensions, 'machineName'), TRUE);

$bindings_by_name = [];
foreach ($route_bindings as $binding) {
  if (is_array($binding) && !empty($binding['name'])) {
    $bindings_by_name[(string) $binding['name']] = $binding;
  }
}
$inputs_by_name = [];
foreach ($route_inputs as $input) {
  if (!is_array($input) || empty($input['name'])) {
    continue;
  }
  if (!isset($active_custom_extension_names[(string) ($input['extension'] ?? '')])) {
    continue;
  }
  $name = (string) $input['name'];
  if (isset($inputs_by_name[$name])) {
    $output['violations'][] = ['name' => $name, 'reason' => 'duplicate_custom_route_name'];
    continue;
  }
  $inputs_by_name[$name] = $input;
}

$custom_route_callback_class = static function (string $definition, string $kind, $container): string {
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
};

$custom_route_extension_for_class = static function (string $class, array $extensions): string {
  $normalized = ltrim($class, '\\');
  $class_file = '';
  try {
    $class_file = (new \ReflectionClass($normalized))->getFileName() ?: '';
    $class_file = $class_file ? str_replace('\\', '/', realpath($class_file) ?: $class_file) : '';
  }
  catch (\Throwable) {
    // Namespace ownership can still identify an unreflectable class.
  }
  foreach ($extensions as $extension) {
    $machine_name = (string) ($extension['machineName'] ?? '');
    $type = (string) ($extension['type'] ?? '');
    if ($machine_name === '' || !in_array($type, ['module', 'theme'], TRUE)) {
      continue;
    }
    if (str_starts_with($normalized, 'Drupal\\' . $machine_name . '\\')) {
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
      // Try the remaining custom extensions.
    }
  }
  return '';
};

// Include attribute/callback routes whose executable callback resolves to a
// custom extension even when no routing YAML record exists.
$routes_scanned = 0;
foreach ($route_provider->getAllRoutes() as $live_name => $live_route) {
  $routes_scanned++;
  if ($routes_scanned > $route_scan_limit) {
    $output['violations'][] = ['name' => '', 'reason' => 'live_route_scan_limit_exceeded'];
    break;
  }
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
    $class = $custom_route_callback_class($definition, $kind, $container);
    $extension = $class ? $custom_route_extension_for_class($class, $active_custom_extensions) : '';
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
      'requestContentType' => (string) ($binding['requestContentType'] ?? ''),
      'discovery' => 'live_callback',
    ];
    break;
  }
}

ksort($inputs_by_name);
foreach (array_values($inputs_by_name) as $input) {
  $binding = $bindings_by_name[(string) ($input['name'] ?? '')] ?? [];
  $request_body = (string) ($binding['requestBody'] ?? '');
  $record = [
    'name' => (string) ($input['name'] ?? ''),
    'extension' => (string) ($input['extension'] ?? ''),
    'file' => (string) ($input['file'] ?? ''),
    'filesystemPath' => (string) ($input['path'] ?? ''),
    'filesystemController' => (string) ($input['controller'] ?? ''),
    'routeParameters' => is_array($binding['routeParameters'] ?? NULL) ? $binding['routeParameters'] : [],
    'requestMethod' => strtoupper((string) ($binding['requestMethod'] ?? '')),
    'requestContentType' => (string) ($binding['requestContentType'] ?? ''),
    'requestBodyPresent' => $request_body !== '',
    'requestBodySha256' => $request_body !== '' ? hash('sha256', $request_body) : '',
    'expectedAnonymousAccess' => (string) ($binding['expectedAnonymousAccess'] ?? ''),
    'discovery' => (string) ($input['discovery'] ?? 'routing_yaml'),
    'accessCheckCompleted' => FALSE,
    'parameterConversionCompleted' => FALSE,
    'requestMatched' => FALSE,
    'anonymousAccess' => '',
    'representativePath' => '',
    'convertedParameterTypes' => [],
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
      $server = $record['requestContentType'] !== ''
        ? ['CONTENT_TYPE' => $record['requestContentType'], 'HTTP_ACCEPT' => $record['requestContentType']]
        : [];
      $request = \Symfony\Component\HttpFoundation\Request::create(
        ($base_url ?: 'http://localhost') . $record['representativePath'],
        $record['requestMethod'],
        [], [], [], $server, $request_body
      );
      $request_stack->push($request);
      try {
        $matched = $router->matchRequest($request);
        $record['matchedRouteName'] = (string) ($matched[\Drupal\Core\Routing\RouteObjectInterface::ROUTE_NAME] ?? '');
        if ($record['matchedRouteName'] !== $record['name']) {
          $record['reason'] = 'representative_request_route_mismatch';
          $output['violations'][] = $record;
          $output['routes'][] = $record;
          continue;
        }
        $record['requestMatched'] = TRUE;
        // router.no_access_checks applies routing enhancers, including parameter
        // conversion, before the access manager evaluates the same request.
        $request->attributes->add($matched);
        foreach ($record['parameterNames'] as $parameter_name) {
          if ($request->attributes->has($parameter_name)) {
            $record['convertedParameterTypes'][$parameter_name] = get_debug_type($request->attributes->get($parameter_name));
          }
        }
        $record['parameterConversionCompleted'] = TRUE;
        $access = $access_manager->checkRequest($request, $anonymous, TRUE);
        $record['anonymousAccess'] = $access->isAllowed()
          ? 'allowed'
          : ($access->isForbidden() ? 'denied' : 'neutral');
        $record['accessCheckCompleted'] = TRUE;
        if (!in_array($record['expectedAnonymousAccess'], ['allowed', 'denied'], TRUE)) {
          $record['reason'] = 'missing_expected_anonymous_access';
          $output['violations'][] = $record;
        }
        elseif ($record['anonymousAccess'] === 'neutral') {
          $record['reason'] = 'neutral_access_result';
          $output['violations'][] = $record;
        }
        elseif ($record['anonymousAccess'] !== $record['expectedAnonymousAccess']) {
          $record['reason'] = 'anonymous_access_mismatch';
          $output['violations'][] = $record;
        }
      }
      finally {
        $request_stack->pop();
      }
    }
    if ($record['filesystemPath'] !== $record['path']) {
      $output['violations'][] = $record + ['reason' => 'route_path_mismatch'];
    }
    if ($record['filesystemController'] !== '' && $record['filesystemController'] !== $record['controller']) {
      $output['violations'][] = $record + ['reason' => 'route_controller_mismatch'];
    }
  }
  catch (\Throwable $error) {
    $record['reason'] = 'live_route_audit_failed';
    $record['errorType'] = get_class($error);
    $record['errorSha256'] = hash('sha256', $error->getMessage());
    $output['violations'][] = $record;
  }
  $output['routes'][] = $record;
}
usort($output['routes'], static fn (array $left, array $right) => strcmp((string) ($left['name'] ?? ''), (string) ($right['name'] ?? '')));
usort($output['violations'], static fn (array $left, array $right) => strcmp(
  json_encode($left, JSON_UNESCAPED_SLASHES),
  json_encode($right, JSON_UNESCAPED_SLASHES)
));
$output['completed'] = TRUE;
print json_encode($output, JSON_UNESCAPED_SLASHES);
`;

export function inspectCustomRouteRuntime(projectRoot, environment, routes, extensions = [], routeBindings = []) {
  if (routes.length === 0 && extensions.length === 0) {
    return { completed: true, routes: [], violations: [] };
  }
  const baseUrl = environmentTargetUrl(environment) || ddevTargetUrl(projectRoot) || 'http://localhost';
  const auditInput = JSON.stringify({
    baseUrl,
    bindings: routeBindings.map((binding) => ({
      name: binding?.name,
      routeParameters: binding?.routeParameters,
      requestMethod: binding?.requestMethod,
      requestContentType: binding?.requestContentType,
      requestBody: binding?.requestBody,
      expectedAnonymousAccess: binding?.expectedAnonymousAccess
    })),
    extensions: extensions.map((extension) => ({
      machineName: extension?.machineName,
      type: extension?.type,
      drupalPath: extension?.drupalPath
    })),
    routes: routes.map((route) => ({
      name: route?.name,
      extension: route?.extension,
      file: route?.file,
      path: route?.path,
      controller: route?.controller,
      discovery: route?.discovery
    }))
  });
  if (Buffer.byteLength(auditInput, 'utf8') > CUSTOM_CODE_PHP_INPUT_BYTES_LIMIT) {
    return {
      completed: false,
      error: `Live Drupal custom-route audit input exceeded ${CUSTOM_CODE_PHP_INPUT_BYTES_LIMIT} bytes.`,
      routes: [],
      violations: []
    };
  }
  const encodedInput = Buffer.from(auditInput, 'utf8').toString('base64');
  const php = `$audit_input = json_decode(base64_decode('${encodedInput}'), TRUE);\n${CUSTOM_ROUTE_AUDIT_PHP}`;
  const result = runDrushResult(projectRoot, environment, ['php:eval', php], 30_000);
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

export const CUSTOM_CONFIG_SCHEMA_AUDIT_PHP = String.raw`
$output = ['completed' => FALSE, 'extensions' => [], 'violations' => []];
$extensions = is_array($audit_input['extensions'] ?? NULL) ? $audit_input['extensions'] : [];
$active_storage = \Drupal::service('config.storage');
$typed_config = \Drupal::service('config.typed');
$core_extensions = $active_storage->read('core.extension') ?: [];
$active_names = $active_storage->listAll();
$schema_files_seen = 0;
$shipped_files_seen = 0;
$ownership_names_scanned = 0;
$ownership_nodes_scanned = 0;
$schema_datasets_checked = 0;
$checker = new class {
  use \Drupal\Core\Config\Schema\SchemaCheckTrait;
};

$custom_schema_pattern_matches = static function (string $pattern, string $config_name): bool {
  $quoted = preg_quote($pattern, '/');
  return preg_match('/^' . str_replace('\\*', '[^.]+', $quoted) . '$/', $config_name) === 1;
};

$custom_schema_data_contains = static function (mixed $value, array $tokens) use (&$ownership_nodes_scanned): ?bool {
  $pending = [$value];
  $visited = 0;
  while ($pending) {
    $current = array_pop($pending);
    $visited++;
    $ownership_nodes_scanned++;
    if ($visited > 10000 || $ownership_nodes_scanned > 1000000) {
      return NULL;
    }
    if (is_string($current) && in_array($current, $tokens, TRUE)) {
      return TRUE;
    }
    if (is_array($current)) {
      foreach ($current as $key => $child) {
        if (is_string($key) && in_array($key, $tokens, TRUE)) {
          return TRUE;
        }
        $pending[] = $child;
      }
    }
  }
  return FALSE;
};

foreach ($extensions as $extension) {
  $machine_name = (string) ($extension['machineName'] ?? '');
  $type = (string) ($extension['type'] ?? '');
  $record = [
    'machineName' => $machine_name,
    'schemaFiles' => [],
    'schemaTypes' => [],
    'candidateConfigNames' => [],
    'checkedConfigNames' => [],
    'checkedShippedConfigNames' => [],
    'skippedInactiveOptionalConfigNames' => [],
    'active' => FALSE,
    'notApplicable' => FALSE,
    'status' => 'fail',
    'violations' => [],
  ];
  try {
    if ($machine_name === '' || !in_array($type, ['module', 'theme'], TRUE)) {
      throw new \InvalidArgumentException('invalid_extension_identity');
    }
    $list = \Drupal::service($type === 'module' ? 'extension.list.module' : 'extension.list.theme');
    $extension_path = (string) $list->getPath($machine_name);
    if ($extension_path === '') {
      throw new \RuntimeException('extension_path_unavailable');
    }
    $expected_path = trim((string) ($extension['drupalPath'] ?? ''), '/');
    if ($expected_path === '' || trim($extension_path, '/') !== $expected_path) {
      throw new \RuntimeException('custom_extension_runtime_path_mismatch');
    }
    $record['active'] = array_key_exists(
      $machine_name,
      is_array($core_extensions[$type] ?? NULL) ? $core_extensions[$type] : []
    );
    if (!$record['active']) {
      $record['notApplicable'] = TRUE;
      $record['status'] = 'not_applicable';
      $output['extensions'][] = $record;
      continue;
    }
    $absolute_root = DRUPAL_ROOT . '/' . trim($extension_path, '/');
    $schema_files = array_merge(
      glob($absolute_root . '/config/schema/*.schema.yml') ?: [],
      glob($absolute_root . '/config/schema/*.schema.yaml') ?: []
    );
    if (count($schema_files) > 1000) {
      throw new \RuntimeException('custom_schema_file_limit_exceeded');
    }
    $schema_files_seen += count($schema_files);
    if ($schema_files_seen > 5000) {
      throw new \RuntimeException('aggregate_custom_schema_file_limit_exceeded');
    }
    foreach ($schema_files as $schema_file) {
      $parsed = \Symfony\Component\Yaml\Yaml::parseFile($schema_file);
      if (!is_array($parsed)) {
        throw new \RuntimeException('schema_file_not_mapping:' . basename($schema_file));
      }
      $record['schemaFiles'][] = str_replace('\\', '/', substr($schema_file, strlen(DRUPAL_ROOT) + 1));
      foreach (array_keys($parsed) as $schema_type) {
        if (is_string($schema_type) && $schema_type !== '') {
          $record['schemaTypes'][] = $schema_type;
        }
      }
    }
    $record['schemaFiles'] = array_values(array_unique($record['schemaFiles']));
    sort($record['schemaFiles']);
    $record['schemaTypes'] = array_values(array_unique($record['schemaTypes']));
    sort($record['schemaTypes']);
    $schema_value_tokens = [];
    foreach ($record['schemaTypes'] as $schema_type) {
      $segments = explode('.', $schema_type);
      $token = end($segments);
      $extension_owned_top_level = $schema_type === $machine_name || str_starts_with($schema_type, $machine_name . '.');
      $extension_prefixed_token = is_string($token) && (
        $token === $machine_name ||
        str_starts_with($token, $machine_name . '_') ||
        str_starts_with($token, $machine_name . '-') ||
        str_starts_with($token, $machine_name . ':')
      );
      if (
        !$extension_owned_top_level &&
        $extension_prefixed_token &&
        preg_match('/^[a-z][a-z0-9_:-]{2,}$/', $token)
      ) {
        $schema_value_tokens[$token] = TRUE;
      }
    }

    $shipped_data = [];
    $shipped_file_count = 0;
    foreach (['install', 'optional'] as $directory) {
      $files = array_merge(
        glob($absolute_root . '/config/' . $directory . '/*.yml') ?: [],
        glob($absolute_root . '/config/' . $directory . '/*.yaml') ?: []
      );
      $shipped_file_count += count($files);
      if ($shipped_file_count > 1000) {
        throw new \RuntimeException('shipped_config_file_limit_exceeded');
      }
      $shipped_files_seen += count($files);
      if ($shipped_files_seen > 5000) {
        throw new \RuntimeException('aggregate_shipped_config_file_limit_exceeded');
      }
      foreach ($files as $config_file) {
        $config_name = preg_replace('/\.ya?ml$/', '', basename($config_file));
        $parsed = \Symfony\Component\Yaml\Yaml::parseFile($config_file);
        if (!is_array($parsed)) {
          throw new \RuntimeException('shipped_config_not_mapping:' . basename($config_file));
        }
        if (isset($shipped_data[$config_name])) {
          throw new \RuntimeException('duplicate_shipped_config_name:' . $config_name);
        }
        $shipped_data[$config_name] = ['data' => $parsed, 'directory' => $directory];
      }
    }

    $candidate_names = array_fill_keys(array_keys($shipped_data), TRUE);
    if (count($active_names) > 10000) {
      throw new \RuntimeException('active_config_name_limit_exceeded');
    }
    foreach ($active_names as $config_name) {
      $ownership_names_scanned++;
      if ($ownership_names_scanned > 100000) {
        throw new \RuntimeException('aggregate_config_ownership_name_limit_exceeded');
      }
      $owned = $config_name === $machine_name || str_starts_with($config_name, $machine_name . '.');
      foreach ($record['schemaTypes'] as $schema_type) {
        if ($custom_schema_pattern_matches($schema_type, $config_name)) {
          $owned = TRUE;
          break;
        }
      }
      if (!$owned && $schema_value_tokens) {
        $active_data = $active_storage->read($config_name);
        $contains_token = is_array($active_data)
          ? $custom_schema_data_contains($active_data, array_keys($schema_value_tokens))
          : FALSE;
        if ($contains_token === NULL) {
          throw new \RuntimeException('config_ownership_scan_limit_exceeded:' . $config_name);
        }
        $owned = $contains_token;
      }
      if ($owned) {
        $candidate_names[$config_name] = TRUE;
      }
    }
    $record['candidateConfigNames'] = array_keys($candidate_names);
    sort($record['candidateConfigNames']);
    if (count($record['candidateConfigNames']) > 10000) {
      throw new \RuntimeException('candidate_config_name_limit_exceeded');
    }
    foreach ($record['candidateConfigNames'] as $config_name) {
      $datasets = [];
      $skipped_inactive_optional = FALSE;
      $active_data = $active_storage->read($config_name);
      if (is_array($active_data)) {
        $datasets[] = ['source' => 'active', 'data' => $active_data];
      }
      if (isset($shipped_data[$config_name])) {
        $shipped = $shipped_data[$config_name];
        if ($shipped['directory'] === 'install' || is_array($active_data)) {
          $datasets[] = ['source' => 'shipped', 'data' => $shipped['data']];
        }
        else {
          $record['skippedInactiveOptionalConfigNames'][] = $config_name;
          $skipped_inactive_optional = TRUE;
        }
      }
      if (!$datasets) {
        if ($skipped_inactive_optional) {
          continue;
        }
        $record['violations'][] = ['configName' => $config_name, 'reason' => 'config_unreadable'];
        continue;
      }
      foreach ($datasets as $dataset) {
        $schema_datasets_checked++;
        if ($schema_datasets_checked > 10000) {
          throw new \RuntimeException('aggregate_config_schema_dataset_limit_exceeded');
        }
        try {
          $result = $checker->checkConfigSchema($typed_config, $config_name, $dataset['data'], TRUE);
        }
        catch (\Throwable $error) {
          $record['violations'][] = [
            'configName' => $config_name,
            'source' => $dataset['source'],
            'reason' => 'schema_validation_exception',
            'errorType' => get_class($error),
            'errorSha256' => hash('sha256', $error->getMessage()),
          ];
          continue;
        }
        if ($result === FALSE) {
          $record['violations'][] = [
            'configName' => $config_name,
            'source' => $dataset['source'],
            'reason' => 'missing_schema',
          ];
        }
        elseif (is_array($result)) {
          $error_strings = array_values(array_map('strval', $result));
          $record['violations'][] = [
            'configName' => $config_name,
            'source' => $dataset['source'],
            'reason' => 'invalid_config_schema',
            'errorCount' => count($error_strings),
            'errorsSha256' => hash('sha256', implode("\0", $error_strings)),
          ];
        }
        else {
          $record['checkedConfigNames'][] = $config_name;
          if ($dataset['source'] === 'shipped') {
            $record['checkedShippedConfigNames'][] = $config_name;
          }
        }
      }
    }
    $record['checkedConfigNames'] = array_values(array_unique($record['checkedConfigNames']));
    sort($record['checkedConfigNames']);
    $record['checkedShippedConfigNames'] = array_values(array_unique($record['checkedShippedConfigNames']));
    sort($record['checkedShippedConfigNames']);
    $record['skippedInactiveOptionalConfigNames'] = array_values(array_unique($record['skippedInactiveOptionalConfigNames']));
    sort($record['skippedInactiveOptionalConfigNames']);
    $record['notApplicable'] = count($record['checkedConfigNames']) === 0 && count($record['violations']) === 0;
    $record['status'] = count($record['violations']) === 0 ? 'pass' : 'fail';
  }
  catch (\Throwable $error) {
    $record['violations'][] = [
      'configName' => '',
      'reason' => 'config_schema_audit_failed',
      'errorType' => get_class($error),
      'errorSha256' => hash('sha256', $error->getMessage()),
    ];
  }
  foreach ($record['violations'] as $violation) {
    $output['violations'][] = ['extension' => $machine_name] + $violation;
  }
  $output['extensions'][] = $record;
}
usort($output['extensions'], static fn (array $left, array $right) => strcmp((string) ($left['machineName'] ?? ''), (string) ($right['machineName'] ?? '')));
usort($output['violations'], static fn (array $left, array $right) => strcmp(
  json_encode($left, JSON_UNESCAPED_SLASHES),
  json_encode($right, JSON_UNESCAPED_SLASHES)
));
$output['completed'] = TRUE;
print json_encode($output, JSON_UNESCAPED_SLASHES);
`;

export function inspectCustomConfigSchema(projectRoot, environment, extensions) {
  if (extensions.length === 0) {
    return { completed: true, extensions: [], violations: [] };
  }
  const auditInput = JSON.stringify({
    extensions: extensions.map((extension) => ({
      machineName: extension?.machineName,
      type: extension?.type,
      drupalPath: extension?.drupalPath
    }))
  });
  if (Buffer.byteLength(auditInput, 'utf8') > CUSTOM_CODE_PHP_INPUT_BYTES_LIMIT) {
    return {
      completed: false,
      error: `Live Drupal custom config-schema audit input exceeded ${CUSTOM_CODE_PHP_INPUT_BYTES_LIMIT} bytes.`,
      extensions: [],
      violations: []
    };
  }
  const encodedInput = Buffer.from(auditInput, 'utf8').toString('base64');
  const php = `$audit_input = json_decode(base64_decode('${encodedInput}'), TRUE);\n${CUSTOM_CONFIG_SCHEMA_AUDIT_PHP}`;
  const result = runDrushResult(projectRoot, environment, ['php:eval', php], 30_000);
  if (!result.ok) {
    return {
      completed: false,
      error: 'Live Drupal custom config-schema audit could not run.',
      extensions: [],
      violations: []
    };
  }
  try {
    const audit = JSON.parse(result.output);
    return {
      completed: audit?.completed === true,
      extensions: Array.isArray(audit?.extensions) ? audit.extensions : [],
      violations: Array.isArray(audit?.violations) ? audit.violations : []
    };
  } catch {
    return {
      completed: false,
      error: 'Live Drupal custom config-schema audit returned invalid JSON.',
      extensions: [],
      violations: []
    };
  }
}

const CUSTOM_CODE_FAILURE_CODES = new Set([
  'input_limit_exceeded',
  'aggregate_deadline_exceeded',
  'tool_missing',
  'required_standard_missing',
  'config_missing',
  'spawn_failed',
  'timed_out',
  'invalid_output',
  'violations_found',
  'no_tests_executed',
  'unexpected_test_executed',
  'no_assertions_executed',
  'test_failed',
  'test_skipped',
  'stale_test_binding',
  'unknown_test_method',
  'uncovered_acceptance_criterion',
  'unsupported_runner'
]);

function boundedFindingMessage(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, CUSTOM_CODE_EXECUTION_LIMITS.findingMessageCharacters);
}

function customCodeFailure(code, check, subjectId = '', message = '') {
  return {
    code: CUSTOM_CODE_FAILURE_CODES.has(code) ? code : 'invalid_output',
    check,
    subjectId: String(subjectId ?? '').slice(0, 200),
    message: boundedFindingMessage(message)
  };
}

function boundedCustomCodeFailures(failures) {
  if (!Array.isArray(failures) || failures.length <= CUSTOM_CODE_EXECUTION_LIMITS.findingsPerCheck) {
    return Array.isArray(failures) ? failures : [];
  }
  return [
    ...failures.slice(0, CUSTOM_CODE_EXECUTION_LIMITS.findingsPerCheck - 1),
    customCodeFailure('input_limit_exceeded', 'report', '', 'Additional custom-code failures were bounded from the verifier report.')
  ];
}

function appendBounded(list, value, limit = CUSTOM_CODE_EXECUTION_LIMITS.findingsPerCheck) {
  if (list.length < limit) {
    list.push(value);
  }
}

export function customCodeResultFingerprint(record) {
  const fingerprintInput = { ...record };
  delete fingerprintInput.resultFingerprint;
  return `sha256:${sha256(JSON.stringify(fingerprintInput))}`;
}

function finalizedCustomCodeRecord(record) {
  const normalized = {
    ...record,
    ...(Array.isArray(record?.failures) ? { failures: boundedCustomCodeFailures(record.failures) } : {})
  };
  return { ...normalized, resultFingerprint: customCodeResultFingerprint(normalized) };
}

function safeCommandArg(value) {
  const text = String(value ?? '');
  if (/[/\\]agent-ready-custom-code-[^/\\]+/.test(text)) {
    return text.replace(/^.*[/\\]agent-ready-custom-code-[^/\\]+(?:[/\\]project)?/, '<disposable-workspace>');
  }
  return /(?:^|\/)\.ddev\/\.agent-ready-custom-code-[^/]+\//.test(text)
    ? text.replace(/^.*(?:^|\/)\.ddev\/\.agent-ready-custom-code-[^/]+\//, '.ddev/<custom-code-audit>/')
    : text;
}

function sanitizedDdevHostEnvironment(environment = process.env) {
  return Object.fromEntries(Object.entries(environment).filter(([key, value]) =>
    !/^(?:DDEV(?:_|$)|IS_DDEV_PROJECT$|COMPOSE_(?:FILE|PATH_SEPARATOR|PROJECT_NAME)$)/.test(key) &&
    !String(value ?? '').includes('\u0000')
  ));
}

function activeDdevConfigText(value) {
  return String(value ?? '')
    .split(/\r?\n/)
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n')
    .replace(/\\u([a-f0-9]{4})/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/\\U([a-f0-9]{8})/g, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/\\x([a-f0-9]{2})/gi, (_, code) => String.fromCodePoint(Number.parseInt(code, 16)));
}

function collectCustomCodeDdevTree(projectRoot) {
  const root = realpathSync(projectRoot);
  const ddevRoot = join(root, '.ddev');
  const ddevMetadata = lstatSync(ddevRoot);
  if (ddevMetadata.isSymbolicLink() || !ddevMetadata.isDirectory()) {
    throw new Error('Disposable custom-code verification requires a regular .ddev directory.');
  }
  const pending = [ddevRoot];
  const records = [];
  let totalBytes = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => comparePortable(left.name, right.name))) {
      const absolute = join(directory, entry.name);
      const metadata = lstatSync(absolute);
      const relativePath = relative(ddevRoot, absolute).split(sep).join('/');
      if (entry.isSymbolicLink() || metadata.isSymbolicLink()) {
        throw new Error(`Disposable custom-code verification rejects .ddev symlinks: .ddev/${relativePath}.`);
      }
      if (metadata.isDirectory()) {
        records.push({
          absolute,
          kind: 'directory',
          mode: metadata.mode & 0o777,
          relativePath: `${relativePath}/`,
          size: 0,
          sha256: ''
        });
        pending.push(absolute);
      } else if (metadata.isFile()) {
        const bytes = readFileSync(absolute);
        totalBytes += bytes.length;
        records.push({
          absolute,
          kind: 'file',
          mode: metadata.mode & 0o777,
          relativePath,
          size: bytes.length,
          sha256: `sha256:${sha256(bytes)}`
        });
      } else {
        throw new Error(`Disposable custom-code verification rejects unsupported .ddev entries: .ddev/${relativePath}.`);
      }
      if (records.length > CUSTOM_CODE_DDEV_FILE_LIMIT || totalBytes > CUSTOM_CODE_DDEV_TOTAL_BYTES_LIMIT) {
        throw new Error('Disposable custom-code verification rejects an oversized .ddev configuration tree.');
      }
    }
  }
  records.sort((left, right) => comparePortable(left.relativePath, right.relativePath));
  const fingerprintRecords = records.map(({ kind, mode, relativePath, sha256: recordSha256, size }) => ({
    kind,
    mode,
    path: relativePath,
    sha256: recordSha256,
    size
  }));
  return {
    ddevRoot,
    records,
    snapshot: {
      checkedDirectoryCount: records.filter((record) => record.kind === 'directory').length,
      checkedFileCount: records.filter((record) => record.kind === 'file').length,
      totalBytes,
      fingerprint: `sha256:${sha256(JSON.stringify(fingerprintRecords))}`
    }
  };
}

export function customCodeDdevTreeSnapshot(projectRoot) {
  return collectCustomCodeDdevTree(projectRoot).snapshot;
}

/** Refuse every project-controlled DDEV surface that can execute or mount host capabilities. */
export function assertSafeCustomCodeDdevConfig(projectRoot) {
  const { records, snapshot } = collectCustomCodeDdevTree(projectRoot);
  for (const record of records) {
    if (record.kind !== 'file') continue;
    if (['web-build/', 'db-build/', 'web-entrypoint.d/', 'db-entrypoint.d/'].some((prefix) => record.relativePath.startsWith(prefix))) {
      throw new Error(`Disposable custom-code verification rejects project image/entrypoint customization: .ddev/${record.relativePath}.`);
    }
    if (record.relativePath === 'commands' || record.relativePath.startsWith('commands/')) {
      throw new Error(`Disposable custom-code verification rejects project custom commands: .ddev/${record.relativePath}.`);
    }
    const name = record.relativePath.split('/').at(-1) ?? '';
    if (CUSTOM_CODE_DDEV_COMPOSE_FILE_RE.test(name)) {
      throw new Error(`Disposable custom-code verification rejects project compose overrides: .ddev/${record.relativePath}.`);
    }
    if (!CUSTOM_CODE_DDEV_CONFIG_FILE_RE.test(name)) continue;
    const raw = readFileSync(record.absolute, 'utf8');
    if (/\\(?:u[0-9a-f]{4}|U[0-9a-f]{8}|x[0-9a-f]{2})/i.test(raw)) {
      throw new Error(`Disposable custom-code verification rejects escaped YAML key material: .ddev/${record.relativePath}.`);
    }
    const text = activeDdevConfigText(raw);
    if (/(?:^|[\s,{])["']?hooks["']?\s*:/im.test(text)) {
      throw new Error(`Disposable custom-code verification rejects project hooks: .ddev/${record.relativePath}.`);
    }
    if (/(?:^|[\s,{])["']?remote_config["']?\s*:/im.test(text)) {
      throw new Error(`Disposable custom-code verification rejects remote_config: .ddev/${record.relativePath}.`);
    }
    if (/(?:^|[\s,[{])(?:&|\*)[A-Za-z0-9_.-]+/m.test(text)) {
      throw new Error(`Disposable custom-code verification rejects YAML anchors or aliases: .ddev/${record.relativePath}.`);
    }
  }
  return snapshot;
}

function verifierDdevRuntimeSpec(projectRoot) {
  const configPath = join(projectRoot, '.ddev', 'config.yaml');
  const metadata = lstatSync(configPath);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 1024 * 1024) {
    throw new Error('Disposable custom-code verification requires a bounded regular .ddev/config.yaml.');
  }
  const text = readFileSync(configPath, 'utf8');
  const scalar = (key) => {
    const match = text.match(new RegExp(`^${key}:\\s*(?:["']([^"']*)["']|([^#\\r\\n]*?))\\s*(?:#.*)?$`, 'mi'));
    return String(match?.[1] ?? match?.[2] ?? '').trim();
  };
  const type = scalar('type');
  const docroot = scalar('docroot').replace(/^\.\//, '').replace(/\/+$/, '');
  const phpVersion = scalar('php_version');
  const webserverType = scalar('webserver_type');
  if (!/^drupal(?:9|10|11)?$/.test(type)) throw new Error('Disposable custom-code verification requires a Drupal DDEV project type.');
  if (!docroot || isAbsolute(docroot) || docroot.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error('Disposable custom-code verification requires a safe project-relative DDEV docroot.');
  }
  const docrootPath = join(projectRoot, docroot);
  const docrootMetadata = lstatSync(docrootPath);
  if (docrootMetadata.isSymbolicLink() || !docrootMetadata.isDirectory() || !pathIsInside(realpathSync(projectRoot), realpathSync(docrootPath))) {
    throw new Error('Disposable custom-code verification requires a regular in-project DDEV docroot.');
  }
  if (phpVersion && !/^8\.[1-5]$/.test(phpVersion)) throw new Error('Disposable custom-code verification rejects an unsupported PHP runtime selection.');
  if (webserverType && !['nginx-fpm', 'apache-fpm'].includes(webserverType)) {
    throw new Error('Disposable custom-code verification rejects a custom DDEV webserver runtime.');
  }
  const databaseBlock = text.match(/^database:\s*(?:#.*)?\r?\n((?:[ \t]+[^\r\n]*(?:\r?\n|$))*)/mi)?.[1] ?? '';
  const databaseScalar = (key) => {
    const match = databaseBlock.match(new RegExp(`^[ \\t]+${key}:\\s*(?:["']([^"']*)["']|([^#\\r\\n]*?))\\s*(?:#.*)?$`, 'mi'));
    return String(match?.[1] ?? match?.[2] ?? '').trim();
  };
  const databaseType = databaseScalar('type');
  const databaseVersion = databaseScalar('version');
  if (databaseType && !['mariadb', 'mysql', 'postgres'].includes(databaseType)) {
    throw new Error('Disposable custom-code verification rejects a custom DDEV database runtime.');
  }
  if (databaseVersion && !/^\d+(?:\.\d+){0,2}$/.test(databaseVersion)) {
    throw new Error('Disposable custom-code verification rejects an unsupported DDEV database version.');
  }
  return { databaseType, databaseVersion, docroot, phpVersion, type, webserverType };
}

function establishVerifierOwnedDdevRuntime(projectRoot, projectName) {
  const spec = verifierDdevRuntimeSpec(projectRoot);
  const ddevRoot = join(projectRoot, '.ddev');
  rmSync(ddevRoot, { force: false, recursive: true });
  mkdirSync(ddevRoot, { mode: 0o700 });
  const lines = [
    `name: ${JSON.stringify(projectName)}`,
    `type: ${JSON.stringify(spec.type)}`,
    `docroot: ${JSON.stringify(spec.docroot)}`,
    'project_tld: "ddev.site"',
    'xdebug_enabled: false'
  ];
  if (spec.phpVersion) lines.push(`php_version: ${JSON.stringify(spec.phpVersion)}`);
  if (spec.webserverType) lines.push(`webserver_type: ${JSON.stringify(spec.webserverType)}`);
  if (spec.databaseType || spec.databaseVersion) {
    lines.push('database:');
    if (spec.databaseType) lines.push(`  type: ${JSON.stringify(spec.databaseType)}`);
    if (spec.databaseVersion) lines.push(`  version: ${JSON.stringify(spec.databaseVersion)}`);
  }
  const config = `${lines.join('\n')}\n`;
  writeFileSync(join(ddevRoot, 'config.yaml'), config, { flag: 'wx', mode: 0o600 });
  assertSafeCustomCodeDdevConfig(projectRoot);
  return {
    configSha256: `sha256:${sha256(config)}`,
    databaseFamily: spec.databaseType === 'postgres' ? 'postgres' : 'mysql',
    specSha256: `sha256:${sha256(JSON.stringify(spec))}`
  };
}

export function createCustomCodeDdevExecutor(projectRoot, environment = process.env, options = {}) {
  const spawn = options.spawnSync ?? spawnSync;
  let realProjectRoot = '';
  try {
    realProjectRoot = realpathSync(projectRoot);
  } catch {
    return () => ({ ok: false, exitCode: null, stdout: '', stderr: '', spawnError: true, timedOut: false });
  }
  if (findDrupalDdevRoot(realProjectRoot) !== realProjectRoot) {
    return () => ({ ok: false, exitCode: null, stdout: '', stderr: '', spawnError: true, timedOut: false });
  }
  const containerMarker = options.containerMarker === undefined
    ? existsSync('/.dockerenv')
    : typeof options.containerMarker === 'function'
      ? options.containerMarker()
      : options.containerMarker === true;
  const inContainer = containerMarker && ddevContainerContext(realProjectRoot, environment);
  return ({ argv, env = {}, timeoutMs, outputLimitBytes }) => {
    if (
      !Array.isArray(argv) || argv.length === 0 ||
      argv.some((argument) => typeof argument !== 'string' || argument.includes('\u0000')) ||
      Object.entries(env).some(([key, value]) => !/^[A-Z][A-Z0-9_]*$/.test(key) || String(value).includes('\u0000'))
    ) {
      return { ok: false, exitCode: null, stdout: '', stderr: '', spawnError: true, timedOut: false };
    }
    const envArgv = Object.keys(env).sort(comparePortable).map((key) => `${key}=${String(env[key])}`);
    let command;
    let args;
    if (inContainer) {
      if (envArgv.length > 0) {
        command = 'env';
        args = [...envArgv, ...argv];
      } else {
        [command, ...args] = argv;
      }
    } else {
      command = 'ddev';
      args = ['exec', '--raw', '--dir', '/var/www/html', '--'];
      if (envArgv.length > 0) {
        args.push('env', ...envArgv);
      }
      args.push(...argv);
    }
    const result = spawn(command, args, {
      cwd: realProjectRoot,
      encoding: 'utf8',
      env: inContainer ? environment : sanitizedDdevHostEnvironment(environment),
      maxBuffer: outputLimitBytes + 1,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs
    });
    const stdout = String(result?.stdout ?? '');
    const stderr = String(result?.stderr ?? '');
    const timedOut = result?.error?.code === 'ETIMEDOUT' || result?.signal === 'SIGTERM';
    return {
      ok: !result?.error && result?.status === 0,
      exitCode: Number.isInteger(result?.status) ? result.status : null,
      stdout,
      stderr,
      spawnError: Boolean(result?.error) && !timedOut,
      timedOut
    };
  };
}

function directHostExecutor(cwd, environment = process.env, options = {}) {
  const spawn = options.hostSpawnSync ?? spawnSync;
  const hostEnvironment = sanitizedDdevHostEnvironment(environment);
  return ({ argv, env = {}, timeoutMs, outputLimitBytes }) => {
    if (!Array.isArray(argv) || argv.length < 1 || argv.some((value) => typeof value !== 'string' || value.includes('\u0000'))) {
      return { ok: false, exitCode: null, stdout: '', stderr: '', spawnError: true, timedOut: false };
    }
    const [command, ...args] = argv;
    const result = spawn(command, args, {
      cwd,
      encoding: 'utf8',
      env: { ...hostEnvironment, ...env },
      maxBuffer: outputLimitBytes + 1,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs
    });
    const timedOut = result?.error?.code === 'ETIMEDOUT' || result?.signal === 'SIGTERM';
    return {
      ok: !result?.error && result?.status === 0,
      exitCode: Number.isInteger(result?.status) ? result.status : null,
      stdout: String(result?.stdout ?? ''),
      stderr: String(result?.stderr ?? ''),
      spawnError: Boolean(result?.error) && !timedOut,
      timedOut
    };
  };
}

function disposableDescriptionOrigin(description, workspace) {
  const raw = plainJsonObject(description?.raw) ? description.raw : description;
  const name = String(raw?.name ?? '');
  const appRoot = String(raw?.approot ?? raw?.appRoot ?? '');
  const primaryUrl = String(raw?.primary_url ?? raw?.primaryUrl ?? '');
  try {
    const parsed = parseHttpUrl(primaryUrl, 'Disposable DDEV primary URL');
    const expectedHostname = `${workspace.identity.projectName}.ddev.site`;
    if (
      name !== workspace.identity.projectName ||
      realpathSync(appRoot) !== realpathSync(workspace.projectRoot) ||
      parsed.hostname !== expectedHostname ||
      parsed.pathname !== '/' ||
      parsed.search
    ) {
      return '';
    }
    return parsed.origin;
  } catch {
    return '';
  }
}

function disposableDescriptionIdentity(description, workspace) {
  return Boolean(disposableDescriptionOrigin(description, workspace));
}

function disposableMarkerMatches(workspace) {
  try {
    const ownerReal = realpathSync(workspace.ownerRoot);
    const parentReal = realpathSync(workspace.tempParent);
    const markerMetadata = lstatSync(workspace.markerPath);
    const projectReal = realpathSync(workspace.projectRoot);
    return dirname(ownerReal) === parentReal && basename(ownerReal).startsWith('agent-ready-custom-code-') &&
      pathIsInside(ownerReal, projectReal) && markerMetadata.isFile() && !markerMetadata.isSymbolicLink() &&
      JSON.stringify(JSON.parse(readFileSync(workspace.markerPath, 'utf8'))) === JSON.stringify(workspace.identity);
  } catch {
    return false;
  }
}

function disposableVerifierConfigMatches(workspace) {
  try {
    const expectedHash = String(workspace?.runtimeProvenance?.configSha256 ?? '');
    const expectedName = `name: ${JSON.stringify(workspace.identity.projectName)}`;
    const ddevRoot = join(workspace.projectRoot, '.ddev');
    const configPath = join(ddevRoot, 'config.yaml');
    const metadata = lstatSync(configPath);
    const config = readFileSync(configPath, 'utf8');
    const hasAdditionalConfig = readdirSync(ddevRoot, { withFileTypes: true }).some((entry) =>
      entry.name !== 'config.yaml' && CUSTOM_CODE_DDEV_CONFIG_FILE_RE.test(entry.name)
    );
    return /^sha256:[a-f0-9]{64}$/.test(expectedHash) && !metadata.isSymbolicLink() && metadata.isFile() &&
      !hasAdditionalConfig && config.split(/\r?\n/).includes(expectedName) &&
      `sha256:${sha256(config)}` === expectedHash;
  } catch {
    return false;
  }
}

function captureDisposableRuntimeDdevTree(workspace) {
  const snapshot = customCodeDdevTreeSnapshot(workspace.projectRoot);
  workspace.runtimeProvenance = {
    ...workspace.runtimeProvenance,
    ddevTreeDirectoryCount: snapshot.checkedDirectoryCount,
    ddevTreeFileCount: snapshot.checkedFileCount,
    ddevTreeFingerprint: snapshot.fingerprint,
    ddevTreeTotalBytes: snapshot.totalBytes
  };
  return snapshot;
}

function disposableRuntimeDdevTreeMatches(workspace) {
  const expected = String(workspace?.runtimeProvenance?.ddevTreeFingerprint ?? '');
  if (!/^sha256:[a-f0-9]{64}$/.test(expected)) return false;
  try {
    return customCodeDdevTreeSnapshot(workspace.projectRoot).fingerprint === expected;
  } catch {
    return false;
  }
}

export function cleanupDisposableCustomCodeWorkspace(workspace, runner) {
  const failures = [];
  const commandResultHashes = [];
  if (!disposableMarkerMatches(workspace)) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace?.identity?.workspaceId ?? '', 'Disposable workspace ownership changed before cleanup; no delete was attempted.'));
    return { completed: false, commandResultHashes, failures };
  }
  if (!disposableVerifierConfigMatches(workspace)) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Verifier-owned DDEV configuration changed before cleanup; no delete was attempted.'));
    return { completed: false, commandResultHashes, failures };
  }
  if (workspace?.runtimeProvenance?.ddevTreeFingerprint) {
    if (!disposableRuntimeDdevTreeMatches(workspace)) {
      failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Verifier-owned DDEV runtime tree changed before cleanup; no delete was attempted.'));
      return { completed: false, commandResultHashes, failures };
    }
  } else {
    try {
      assertSafeCustomCodeDdevConfig(workspace.projectRoot);
      captureDisposableRuntimeDdevTree(workspace);
    } catch {
      failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Disposable DDEV configuration became unsafe before cleanup; no delete was attempted.'));
      return { completed: false, commandResultHashes, failures };
    }
  }
  const describe = runner.run({
    argv: ['ddev', 'describe', '-j', '--skip-hooks'],
    cleanup: true,
    executorOverride: workspace.hostExecutor,
    timeoutMs: 10_000,
    outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes
  });
  if (describe.record) commandResultHashes.push(describe.record.resultSha256);
  let description = null;
  try {
    description = describe.ok ? JSON.parse(describe.stdout) : null;
  } catch {
    description = null;
  }
  if (describe.ok && (!description || !disposableDescriptionIdentity(description, workspace))) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Disposable DDEV identity did not match immediately before cleanup; no delete was attempted.'));
    return { completed: false, commandResultHashes, failures };
  }
  if (!describe.ok && !disposableVerifierConfigMatches(workspace)) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Disposable DDEV identity was unavailable and the verifier-owned configuration no longer matched; no delete was attempted.'));
    return { completed: false, commandResultHashes, failures };
  }
  if (!disposableVerifierConfigMatches(workspace) || !disposableRuntimeDdevTreeMatches(workspace)) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Verifier-owned DDEV configuration or runtime tree changed immediately before deletion; no delete was attempted.'));
    return { completed: false, commandResultHashes, failures };
  }
  if (!disposableMarkerMatches(workspace) || (!describe.ok && !disposableVerifierConfigMatches(workspace))) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Disposable workspace ownership changed immediately before deletion; no delete was attempted.'));
    return { completed: false, commandResultHashes, failures };
  }
  const deletion = runner.run({
    argv: ['ddev', 'delete', '-Oy', '--skip-hooks'],
    cleanup: true,
    executorOverride: workspace.hostExecutor,
    timeoutMs: CUSTOM_CODE_EXECUTION_LIMITS.cleanupReserveMs,
    outputLimitBytes: 2 * 1024 * 1024
  });
  if (deletion.record) commandResultHashes.push(deletion.record.resultSha256);
  if (!deletion.ok || !disposableMarkerMatches(workspace)) {
    failures.push(commandFailure(deletion, 'phpunit-isolation-cleanup', workspace.identity.workspaceId));
    return { completed: false, commandResultHashes, failures };
  }
  try {
    rmSync(workspace.ownerRoot, { force: false, recursive: true });
  } catch {
    failures.push(customCodeFailure('spawn_failed', 'phpunit-isolation-cleanup', workspace.identity.workspaceId, 'Owned disposable workspace files could not be removed after DDEV deletion.'));
  }
  return { completed: failures.length === 0, commandResultHashes, failures };
}

function auditComposerProject(requirements) {
  return {
    name: 'agent-ready/verifier-audit',
    description: 'Ephemeral verifier-owned analyzer and test toolchain.',
    type: 'project',
    require: Object.fromEntries([...requirements.closure]
      .sort((left, right) => comparePortable(left.name, right.name))
      .map((record) => [record.name, record.version])),
    config: {
      'allow-plugins': false,
      'sort-packages': true
    },
    'minimum-stability': 'stable',
    'prefer-stable': true
  };
}

function exactToolRequirementsMatch(projectRoot, needs, expected) {
  const current = customCodeToolRequirements(projectRoot, needs);
  return current.failures.length === 0 &&
    current.snapshot.composerJsonSha256 === expected.snapshot.composerJsonSha256 &&
    current.snapshot.composerLockSha256 === expected.snapshot.composerLockSha256 &&
    sameLockedToolPackages(current, expected);
}

export function createDisposableCustomCodeWorkspace(projectRoot, inventory, runner, environment = process.env, options = {}) {
  const failures = [];
  const setupCommandResultHashes = [];
  const needs = options.toolNeeds ?? { phpcs: true, phpstan: true, phpunit: true };
  let sourceRoot = '';
  try {
    sourceRoot = realpathSync(projectRoot);
  } catch {
    failures.push(customCodeFailure('spawn_failed', 'phpunit-isolation', '', 'The working project root could not be resolved for disposable verification.'));
    return { failures, workspace: null };
  }
  const requirements = options.toolRequirements ?? customCodeToolRequirements(sourceRoot, needs);
  if (requirements.failures.length > 0 || !requirements.snapshot) {
    return { failures: [...requirements.failures], workspace: null };
  }
  const containerMarker = options.containerMarker === undefined ? existsSync('/.dockerenv') : options.containerMarker === true;
  if (containerMarker && ddevContainerContext(sourceRoot, environment)) {
    failures.push(customCodeFailure('spawn_failed', 'phpunit-isolation', '', 'Focused tests require host-side DDEV orchestration for a distinct disposable project and database.'));
    return { failures, workspace: null };
  }
  const tempParent = realpathSync(options.tempParent ?? tmpdir());
  const ownerRoot = mkdtempSync(join(tempParent, 'agent-ready-custom-code-'));
  const cloneRoot = join(ownerRoot, 'project');
  const markerPath = join(ownerRoot, 'identity.json');
  let workspace = null;
  let startAttempted = false;
  const runHost = (cwd, argv, timeoutMs, outputLimitBytes = 2 * 1024 * 1024) => {
    const result = runner.run({
      argv,
      executorOverride: directHostExecutor(cwd, environment, options),
      timeoutMs,
      outputLimitBytes
    });
    if (result.record) setupCommandResultHashes.push(result.record.resultSha256);
    return result;
  };
  try {
    const root = sourceRoot;
    const topLevel = runHost(root, ['git', 'rev-parse', '--show-toplevel'], 10_000);
    const headResult = runHost(root, ['git', 'rev-parse', 'HEAD'], 10_000);
    const head = headResult.stdout.trim();
    if (!topLevel.ok || realpathSync(topLevel.stdout.trim()) !== root || !headResult.ok || !/^[a-f0-9]{40,64}$/i.test(head)) {
      throw new Error('source is not an exact Git worktree');
    }
    const clone = runHost(root, [
      'git', '-c', 'core.hooksPath=/dev/null', 'clone', '--local', '--no-hardlinks', '--no-checkout',
      '--no-recurse-submodules', '--quiet', '.', cloneRoot
    ], 120_000, 8 * 1024 * 1024);
    if (!clone.ok) throw new Error('exact-HEAD clone failed');
    const checkout = runHost(cloneRoot, ['git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--detach', '--quiet', head], 120_000, 8 * 1024 * 1024);
    const clonedHead = runHost(cloneRoot, ['git', 'rev-parse', 'HEAD'], 10_000);
    if (!checkout.ok || !clonedHead.ok || clonedHead.stdout.trim().toLowerCase() !== head.toLowerCase()) throw new Error('clone HEAD mismatch');
    if (!exactToolRequirementsMatch(cloneRoot, needs, requirements)) throw new Error('clone tool lock mismatch');
    const cloneInventory = exactInventoryPhpFiles(cloneRoot, inventory);
    if (cloneInventory.failures.length > 0) throw new Error('inventoried PHP is not exact HEAD');
    // A committed or otherwise present vendor directory is target-controlled. Remove it
    // before provisioning the disposable project from the exact lock.
    rmSync(join(cloneRoot, 'vendor'), { force: true, recursive: true });
    const token = randomBytes(16).toString('hex');
    const projectName = `agent-ready-${sha256(`${head}\u0000${token}`).slice(0, 16)}`;
    const identity = {
      head,
      projectName,
      schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
      tokenSha256: `sha256:${sha256(token)}`,
      workspaceId: `DISPOSABLE-${sha256(`${head}\u0000${projectName}`).slice(0, 16)}`
    };
    assertSafeCustomCodeDdevConfig(cloneRoot);
    const runtimeProvenance = establishVerifierOwnedDdevRuntime(cloneRoot, projectName);
    writeFileSync(markerPath, `${JSON.stringify(identity)}\n`, { flag: 'wx', mode: 0o600 });
    workspace = {
      baseUrl: '',
      exactHead: true,
      freshDatabase: true,
      hostExecutor: directHostExecutor(cloneRoot, environment, options),
      identity,
      markerPath,
      ownerRoot,
      projectRoot: cloneRoot,
      runtimeProvenance,
      setupCommandResultHashes,
      tempParent
    };
    startAttempted = true;
    const start = runHost(cloneRoot, ['ddev', 'start', '--skip-hooks'], 180_000, 8 * 1024 * 1024);
    if (!start.ok) throw new Error('disposable DDEV start failed');
    const describe = runHost(cloneRoot, ['ddev', 'describe', '-j', '--skip-hooks'], 10_000, CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes);
    let description;
    try {
      description = describe.ok ? JSON.parse(describe.stdout) : null;
    } catch {
      description = null;
    }
    const disposableOrigin = description ? disposableDescriptionOrigin(description, workspace) : '';
    if (!disposableOrigin) throw new Error('disposable DDEV identity mismatch');
    workspace.baseUrl = disposableOrigin;
    captureDisposableRuntimeDdevTree(workspace);
    workspace.executor = createCustomCodeDdevExecutor(cloneRoot, environment, {
      ...options,
      containerMarker: false,
      spawnSync: options.spawnSync ?? options.hostSpawnSync
    });
    const runDisposable = (argv, timeoutMs = 600_000, env = {}) => {
      const result = runner.run({
        argv,
        env,
        executorOverride: workspace.executor,
        timeoutMs,
        outputLimitBytes: 8 * 1024 * 1024
      });
      if (result.record) setupCommandResultHashes.push(result.record.resultSha256);
      return result;
    };
    const projectLockValidation = runDisposable([
      'composer', 'validate', '--check-lock', '--no-check-publish', '--no-interaction',
      '--no-plugins', '--no-scripts'
    ]);
    if (!projectLockValidation.ok || !exactToolRequirementsMatch(cloneRoot, needs, requirements)) {
      throw new Error('project Composer lock is stale or changed during validation');
    }
    // Drupal Composer plugins and scripts are needed to materialize the committed
    // project lock correctly. They run only inside this exact-HEAD disposable DDEV
    // clone; the verifier-owned audit install below remains plugin- and script-free.
    const projectInstall = runDisposable([
      'composer', 'install', '--no-interaction', '--no-progress', '--prefer-dist'
    ]);
    if (!projectInstall.ok || !exactToolRequirementsMatch(cloneRoot, needs, requirements)) {
      throw new Error('fresh project Composer install failed or changed its lock');
    }
    if (exactInventoryPhpFiles(cloneRoot, inventory).failures.length > 0) {
      throw new Error('project dependency installation mutated inventoried PHP');
    }

    const auditRelative = `.agent-ready-audit-${token.slice(0, 16)}`;
    const auditRoot = join(cloneRoot, auditRelative);
    mkdirSync(auditRoot, { recursive: false, mode: 0o700 });
    writeFileSync(join(auditRoot, 'composer.json'), `${JSON.stringify(auditComposerProject(requirements), null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    const auditUpdate = runDisposable([
      'composer', `--working-dir=${auditRelative}`, 'update', '--no-install', '--no-interaction',
      '--no-plugins', '--no-scripts', '--prefer-dist', '--no-progress'
    ]);
    const auditRequirements = auditUpdate.ok ? customCodeToolRequirements(auditRoot, needs) : { failures: [true], packages: {} };
    let auditLockExact = false;
    try {
      auditLockExact = auditUpdate.ok && composerLockIsExactClosure(boundedLocalJson(auditRoot, 'composer.lock').value, requirements.closure);
    } catch {
      auditLockExact = false;
    }
    if (auditRequirements.failures.length > 0 || !sameLockedToolPackages(auditRequirements, requirements) || !auditLockExact) {
      throw new Error('fresh audit lock did not match canonical project tool packages');
    }
    const auditInstall = runDisposable([
      'composer', `--working-dir=${auditRelative}`, 'install', '--no-interaction', '--no-plugins',
      '--no-scripts', '--prefer-dist', '--no-progress'
    ]);
    if (!auditInstall.ok) throw new Error('fresh verifier audit Composer install failed');
    const auditProvenance = customCodeToolchainProvenance(auditRoot, needs, requirements);
    if (auditProvenance.failures.length > 0) throw new Error('fresh verifier audit package provenance failed');
    workspace.auditRoot = auditRoot;
    workspace.provenance = auditProvenance;
    workspace.requirements = requirements;
    workspace.toolNeeds = needs;
    return { failures, workspace };
  } catch {
    failures.push(customCodeFailure('spawn_failed', 'phpunit-isolation', '', 'An exact-HEAD disposable DDEV project and database could not be established.'));
    if (startAttempted && workspace) {
      if (!workspace?.runtimeProvenance?.ddevTreeFingerprint) {
        try {
          captureDisposableRuntimeDdevTree(workspace);
        } catch {
          // Cleanup retains strict pre-start safety when the generated tree cannot be bounded and captured.
        }
      }
      const cleanup = cleanupDisposableCustomCodeWorkspace(workspace, runner);
      failures.push(...cleanup.failures);
    } else {
      try {
        if (workspace ? disposableMarkerMatches(workspace) : dirname(realpathSync(ownerRoot)) === tempParent) {
          rmSync(ownerRoot, { force: false, recursive: true });
        }
      } catch {
        // Fail closed and leave ambiguous residue rather than deleting an unconfirmed path.
      }
    }
    return { failures, workspace: null };
  }
}

export function createCustomCodeExecutionRunner(executor, options = {}) {
  const now = options.now ?? Date.now;
  const budget = {
    startedAt: now(),
    now,
    commandCount: 0,
    outputBytes: 0,
    commandLimit: options.commandLimit ?? CUSTOM_CODE_EXECUTION_LIMITS.commands,
    outputLimit: options.outputLimit ?? CUSTOM_CODE_EXECUTION_LIMITS.aggregateOutputBytes,
    deadlineMs: options.deadlineMs ?? CUSTOM_CODE_EXECUTION_LIMITS.aggregateDeadlineMs
  };
  budget.cleanupReserveMs = Math.min(
    options.cleanupReserveMs ?? CUSTOM_CODE_EXECUTION_LIMITS.cleanupReserveMs,
    Math.floor(budget.deadlineMs / 2)
  );
  budget.cleanupCommandReserve = Math.min(2, Math.max(0, budget.commandLimit - 1));
  const run = ({ argv, env = {}, timeoutMs, outputLimitBytes, executorOverride = null, cleanup = false }) => {
    if (now() - budget.startedAt > budget.deadlineMs) {
      return { ok: false, failureCode: 'aggregate_deadline_exceeded', record: null, stdout: '', stderr: '' };
    }
    if (budget.commandCount >= budget.commandLimit - (cleanup ? 0 : budget.cleanupCommandReserve)) {
      return { ok: false, failureCode: 'input_limit_exceeded', record: null, stdout: '', stderr: '' };
    }
    const remainingMs = budget.deadlineMs - (now() - budget.startedAt) - (cleanup ? 0 : budget.cleanupReserveMs);
    if (remainingMs <= 0) {
      return { ok: false, failureCode: 'aggregate_deadline_exceeded', record: null, stdout: '', stderr: '' };
    }
    const boundedTimeoutMs = Math.max(1, Math.min(timeoutMs, remainingMs));
    budget.commandCount += 1;
    let raw;
    try {
      raw = (executorOverride ?? executor)({ argv, env, timeoutMs: boundedTimeoutMs, outputLimitBytes });
    } catch {
      raw = { ok: false, exitCode: null, stdout: '', stderr: '', spawnError: true, timedOut: false };
    }
    const stdout = String(raw?.stdout ?? '');
    const stderr = String(raw?.stderr ?? '');
    const outputBytes = Buffer.byteLength(stdout) + Buffer.byteLength(stderr);
    budget.outputBytes += outputBytes;
    let failureCode = '';
    if (now() - budget.startedAt > budget.deadlineMs) {
      failureCode = 'aggregate_deadline_exceeded';
    } else if (budget.outputBytes > budget.outputLimit || outputBytes > outputLimitBytes) {
      failureCode = 'invalid_output';
    } else if (raw?.timedOut) {
      failureCode = 'timed_out';
    } else if (raw?.spawnError) {
      failureCode = 'spawn_failed';
    }
    const envKeys = Object.keys(env).sort(comparePortable);
    const publicArgv = argv.map(safeCommandArg);
    const commandResult = {
      argv: publicArgv,
      envKeys,
      exitCode: Number.isInteger(raw?.exitCode) ? raw.exitCode : null,
      outputBytes,
      stdoutSha256: `sha256:${sha256(stdout)}`,
      stderrSha256: `sha256:${sha256(stderr)}`
    };
    const commandResultSha256 = sha256(JSON.stringify(commandResult));
    const record = {
      id: `COMMAND-${commandResultSha256.slice(0, 16)}`,
      resultSha256: `sha256:${commandResultSha256}`,
      ...commandResult
    };
    return {
      ok: failureCode === '' && raw?.ok === true,
      failureCode,
      record,
      stdout,
      stderr
    };
  };
  return { budget, run };
}

function reserveCustomCodeGeneratedOutput(runner, byteLength) {
  if (runner.budget.now() - runner.budget.startedAt > runner.budget.deadlineMs) {
    return 'aggregate_deadline_exceeded';
  }
  runner.budget.outputBytes += byteLength;
  return runner.budget.outputBytes > runner.budget.outputLimit ? 'invalid_output' : '';
}

function exactInventoryPhpFiles(projectRoot, inventory) {
  let realProjectRoot = projectRoot;
  try {
    realProjectRoot = realpathSync(projectRoot);
  } catch {
    // Individual file checks below fail closed.
  }
  const failures = [];
  const files = [];
  for (const source of Array.isArray(inventory?.sourceFiles) ? inventory.sourceFiles : []) {
    if (!['procedural_php', 'php_class'].includes(source?.kind)) {
      continue;
    }
    files.push({
      extension: String(source.extension ?? ''),
      id: String(source.id ?? ''),
      isTest: false,
      path: String(source.path ?? ''),
      sha256: String(source.sha256 ?? '')
    });
  }
  for (const test of Array.isArray(inventory?.tests) ? inventory.tests : []) {
    if (!/\.php$/i.test(String(test?.path ?? ''))) {
      continue;
    }
    files.push({
      extension: String(test.extension ?? ''),
      id: String(test.id ?? ''),
      isTest: true,
      path: String(test.path ?? ''),
      sha256: String(test.sha256 ?? '')
    });
  }
  const unique = [...new Map(files.map((file) => [file.path, file])).values()]
    .sort((left, right) => comparePortable(left.path, right.path));
  if (unique.length > CUSTOM_CODE_EXECUTION_LIMITS.phpFiles) {
    failures.push(customCodeFailure(
      'input_limit_exceeded', 'preflight', '',
      `Custom PHP inventory exceeds ${CUSTOM_CODE_EXECUTION_LIMITS.phpFiles} files.`
    ));
  }
  const argvBytes = unique.reduce((total, file) => total + Buffer.byteLength(file.path) + 1, 0);
  if (argvBytes > CUSTOM_CODE_EXECUTION_LIMITS.pathArgvBytes) {
    failures.push(customCodeFailure(
      'input_limit_exceeded', 'preflight', '',
      `Custom PHP paths exceed the ${CUSTOM_CODE_EXECUTION_LIMITS.pathArgvBytes}-byte aggregate argv limit.`
    ));
  }
  for (const file of unique) {
    if (!file.path || isAbsolute(file.path) || file.path.includes('\u0000')) {
      failures.push(customCodeFailure('input_limit_exceeded', 'preflight', file.id, 'Inventoried PHP path is not a safe project-relative argv value.'));
      continue;
    }
    const absolute = resolve(projectRoot, file.path);
    try {
      const metadata = lstatSync(absolute);
      const real = realpathSync(absolute);
      if (metadata.isSymbolicLink() || !metadata.isFile() || !pathIsInside(realProjectRoot, real)) {
        throw new Error('unsafe path');
      }
      const currentSha256 = `sha256:${sha256(readFileSync(real))}`;
      if (currentSha256 !== file.sha256) {
        failures.push(customCodeFailure('stale_test_binding', 'preflight', file.id, 'Inventoried PHP bytes changed before quality execution.'));
      }
    } catch {
      failures.push(customCodeFailure('stale_test_binding', 'preflight', file.id, 'Inventoried PHP file is missing or unsafe at execution time.'));
    }
  }
  return { argvBytes, failures, files: unique };
}

function executableCustomSurfaceIds(inventory) {
  return new Set(
    (Array.isArray(inventory?.sourceFiles) ? inventory.sourceFiles : [])
      .flatMap((source) => Array.isArray(source?.surfaces) ? source.surfaces : [])
      .filter((surface) => EXECUTABLE_CUSTOM_SURFACE_KINDS.has(surface?.kind))
      .map((surface) => String(surface?.id ?? ''))
      .filter(Boolean)
  );
}

function capabilityRequiresFocusedTests(capability, executableSurfaceIds) {
  return capability?.loadBearing === true ||
    (Array.isArray(capability?.sourceSurfaceIds) ? capability.sourceSurfaceIds : [])
      .some((surfaceId) => executableSurfaceIds.has(String(surfaceId)));
}

function coveragePreflight(inventory, review) {
  const failures = [];
  const rows = Array.isArray(review?.testCoverage) ? review.testCoverage : [];
  const capabilities = Array.isArray(review?.capabilities) ? review.capabilities : [];
  const executableSurfaceIds = executableCustomSurfaceIds(inventory);
  const criterionExtensions = new Map();
  const requiredCriteria = new Set();
  for (const capability of capabilities) {
    const extension = String(capability?.extension ?? '');
    const requiresFocusedTests = capabilityRequiresFocusedTests(capability, executableSurfaceIds);
    for (const criterion of Array.isArray(capability?.acceptanceCriteria) ? capability.acceptanceCriteria : []) {
      const id = String(criterion?.id ?? '');
      if (id) {
        criterionExtensions.set(id, extension);
        if (requiresFocusedTests) {
          requiredCriteria.add(id);
        }
      }
    }
  }
  if (rows.length > CUSTOM_CODE_EXECUTION_LIMITS.coverageRows) {
    failures.push(customCodeFailure('input_limit_exceeded', 'coverage', '', `Focused coverage exceeds ${CUSTOM_CODE_EXECUTION_LIMITS.coverageRows} rows.`));
  }
  const tests = new Map((Array.isArray(inventory?.tests) ? inventory.tests : []).map((test) => [String(test?.id ?? ''), test]));
  const methods = new Map();
  for (const test of tests.values()) {
    for (const method of Array.isArray(test?.testMethods) ? test.testMethods : []) {
      methods.set(String(method?.id ?? ''), { ...method, extension: test.extension, path: test.path, testFileId: test.id });
    }
  }
  const covered = new Set();
  const coverageRowBindings = new Set();
  const normalizedRows = [];
  for (const [index, row] of rows.entries()) {
    const acceptanceCriterionId = String(row?.acceptanceCriterionId ?? '').trim();
    const testFileId = String(row?.testFileId ?? '').trim();
    const className = String(row?.className ?? '').trim().replace(/^\\+/, '');
    const methodName = String(row?.methodName ?? '').trim();
    const testMethodId = String(row?.testMethodId ?? '').trim();
    const subject = testMethodId || `coverage-row-${index}`;
    if (row?.runner !== 'phpunit') {
      failures.push(customCodeFailure('unsupported_runner', 'coverage', subject, 'Only the verifier-owned phpunit runner is supported.'));
      continue;
    }
    if (className.length > 512 || methodName.length > 200) {
      failures.push(customCodeFailure('input_limit_exceeded', 'coverage', subject, 'Coverage class or method identity exceeds the verifier argv limit.'));
      continue;
    }
    const test = tests.get(testFileId);
    const method = methods.get(testMethodId);
    if (!test || !method) {
      failures.push(customCodeFailure('unknown_test_method', 'coverage', subject, 'Coverage references a test file or method absent from the verifier inventory.'));
      continue;
    }
    const expectedId = customTestMethodId(test.extension, test.path, className, methodName);
    if (
      expectedId !== testMethodId || method.testFileId !== testFileId ||
      method.className !== className || method.methodName !== methodName
    ) {
      failures.push(customCodeFailure('stale_test_binding', 'coverage', subject, 'Coverage class, method, file, or stable ID does not match the verifier inventory.'));
      continue;
    }
    const criterionExtension = criterionExtensions.get(acceptanceCriterionId);
    if (!criterionExtension || criterionExtension !== test.extension) {
      failures.push(customCodeFailure('stale_test_binding', 'coverage', subject, 'Coverage acceptance criterion is unknown or belongs to another extension.'));
      continue;
    }
    const exactKey = `${acceptanceCriterionId}\u0000${testFileId}\u0000${className}\u0000${methodName}`;
    if (coverageRowBindings.has(exactKey)) {
      failures.push(customCodeFailure('stale_test_binding', 'coverage', subject, 'Coverage repeats the same acceptance criterion and exact test method binding.'));
      continue;
    }
    coverageRowBindings.add(exactKey);
    covered.add(acceptanceCriterionId);
    normalizedRows.push({ acceptanceCriterionId, className, methodName, testFileId, testMethodId, path: test.path, extension: test.extension });
  }
  for (const criterionId of requiredCriteria) {
    if (!covered.has(criterionId)) {
      failures.push(customCodeFailure('uncovered_acceptance_criterion', 'coverage', criterionId, 'Required load-bearing or executable-surface acceptance criterion has no exact PHPUnit method binding.'));
    }
  }
  const testFileCount = new Set(normalizedRows.map((row) => row.testFileId)).size;
  const testMethodCount = new Set(normalizedRows.map((row) => row.testMethodId)).size;
  if (testFileCount > CUSTOM_CODE_EXECUTION_LIMITS.testFiles || testMethodCount > CUSTOM_CODE_EXECUTION_LIMITS.testMethods) {
    failures.push(customCodeFailure('input_limit_exceeded', 'coverage', '', 'Focused PHPUnit file or method count exceeds the verifier limit.'));
  }
  return {
    applies: requiredCriteria.size > 0,
    failures,
    rows: normalizedRows.sort((left, right) => comparePortable(left.testMethodId, right.testMethodId)),
    testFileCount,
    testMethodCount
  };
}

function commandFailure(result, check, subjectId, fallbackCode = 'spawn_failed') {
  const code = result?.failureCode || (result?.record?.exitCode === 127 ? 'tool_missing' : fallbackCode);
  return customCodeFailure(code, check, subjectId, `Verifier-owned ${check} command did not complete successfully.`);
}

function normalizedToolVersion(value, pattern) {
  const line = String(value ?? '').split(/\r?\n/).find((candidate) => candidate.trim())?.trim() ?? '';
  return line.match(pattern)?.[1] ?? '';
}

function recognizedProjectFile(projectRoot, candidates) {
  let realProjectRoot = projectRoot;
  try {
    realProjectRoot = realpathSync(projectRoot);
  } catch {
    return '';
  }
  for (const candidate of candidates) {
    const absolute = join(projectRoot, candidate);
    if (!existsSync(absolute)) {
      continue;
    }
    try {
      const metadata = lstatSync(absolute);
      const real = realpathSync(absolute);
      const target = statSync(real);
      if ((metadata.isFile() || metadata.isSymbolicLink()) && target.isFile() && pathIsInside(realProjectRoot, real)) {
        return candidate;
      }
    } catch {
      return '';
    }
    return '';
  }
  return '';
}

function projectFileSha256(projectRoot, path) {
  try {
    const realProjectRoot = realpathSync(projectRoot);
    const real = realpathSync(join(projectRoot, path));
    if (!pathIsInside(realProjectRoot, real) || !statSync(real).isFile()) {
      return '';
    }
    return `sha256:${sha256(readFileSync(real))}`;
  } catch {
    return '';
  }
}

const CUSTOM_CODE_COMPOSER_PACKAGES = Object.freeze({
  coder: {
    binary: '', name: 'drupal/coder',
    distPrefixes: ['https://api.github.com/repos/pfrenssen/coder/zipball/'],
    sourceUrls: ['https://github.com/pfrenssen/coder.git']
  },
  slevomat: {
    binary: '', name: 'slevomat/coding-standard',
    distPrefixes: ['https://api.github.com/repos/slevomat/coding-standard/zipball/'],
    sourceUrls: ['https://github.com/slevomat/coding-standard.git']
  },
  variableAnalysis: {
    binary: '', name: 'sirbrillig/phpcs-variable-analysis',
    distPrefixes: ['https://api.github.com/repos/sirbrillig/phpcs-variable-analysis/zipball/'],
    sourceUrls: ['https://github.com/sirbrillig/phpcs-variable-analysis.git']
  },
  phpcs: {
    binary: 'bin/phpcs', name: 'squizlabs/php_codesniffer',
    distPrefixes: [
      'https://api.github.com/repos/PHPCSStandards/PHP_CodeSniffer/zipball/',
      'https://api.github.com/repos/squizlabs/PHP_CodeSniffer/zipball/'
    ],
    sourceUrls: [
      'https://github.com/PHPCSStandards/PHP_CodeSniffer.git',
      'https://github.com/squizlabs/PHP_CodeSniffer.git'
    ]
  },
  phpstan: {
    binary: 'phpstan', name: 'phpstan/phpstan', sourceOptional: true,
    distPrefixes: ['https://api.github.com/repos/phpstan/phpstan/zipball/'],
    sourceUrls: ['https://github.com/phpstan/phpstan.git']
  },
  phpunit: {
    binary: 'phpunit', name: 'phpunit/phpunit',
    distPrefixes: ['https://api.github.com/repos/sebastianbergmann/phpunit/zipball/'],
    sourceUrls: ['https://github.com/sebastianbergmann/phpunit.git']
  }
});

function boundedLocalJson(projectRoot, relativePath) {
  const absolute = join(projectRoot, relativePath);
  const metadata = lstatSync(absolute);
  const real = realpathSync(absolute);
  const root = realpathSync(projectRoot);
  if (metadata.isSymbolicLink() || !metadata.isFile() || !pathIsInside(root, real) || metadata.size > CUSTOM_CODE_EXECUTION_LIMITS.composerMetadataBytes) {
    throw new Error('unsafe composer metadata');
  }
  const bytes = readFileSync(real);
  return { sha256: `sha256:${sha256(bytes)}`, value: parseBoundedJsonText(bytes.toString('utf8'), relativePath) };
}

function verifiedHttpsUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'https:' && !url.username && !url.password ? url.href : '';
  } catch {
    return '';
  }
}

function packageDirectoryFingerprint(projectRoot, packageName) {
  const logicalRoot = join(projectRoot, 'vendor', ...packageName.split('/'));
  const projectReal = realpathSync(projectRoot);
  const rootReal = realpathSync(logicalRoot);
  if (!pathIsInside(projectReal, rootReal) || !statSync(rootReal).isDirectory()) throw new Error('unsafe package directory');
  const pending = [{ logical: '', real: rootReal }];
  const visited = new Set();
  const entries = [];
  let bytes = 0;
  let files = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    if (visited.has(directory.real)) throw new Error('package directory cycle');
    visited.add(directory.real);
    for (const entry of readdirSync(directory.real, { withFileTypes: true }).sort((left, right) => comparePortable(left.name, right.name))) {
      const logical = directory.logical ? `${directory.logical}/${entry.name}` : entry.name;
      const absolute = join(directory.real, entry.name);
      const metadata = lstatSync(absolute);
      if (entry.isSymbolicLink() || metadata.isSymbolicLink()) throw new Error('package symlink');
      if (entry.isDirectory()) {
        const real = realpathSync(absolute);
        if (!pathIsInside(rootReal, real)) throw new Error('package escape');
        entries.push(`d\u0000${logical}\u0000${metadata.mode & 0o777}`);
        pending.push({ logical, real });
      } else if (entry.isFile()) {
        files += 1;
        bytes += metadata.size;
        if (files > CUSTOM_CODE_EXECUTION_LIMITS.packageFiles || bytes > CUSTOM_CODE_EXECUTION_LIMITS.packageBytes) throw new Error('package limit');
        entries.push(`f\u0000${logical}\u0000${metadata.mode & 0o777}\u0000${metadata.size}\u0000${sha256(readFileSync(absolute))}`);
      } else {
        throw new Error('unsupported package entry');
      }
    }
  }
  entries.sort(comparePortable);
  return { bytes, files, sha256: `sha256:${sha256(entries.join('\n'))}` };
}

function composerRootAutoloadFingerprint(projectRoot) {
  const projectReal = realpathSync(projectRoot);
  const vendorPath = join(projectReal, 'vendor');
  const vendorMetadata = lstatSync(vendorPath);
  const vendorReal = realpathSync(vendorPath);
  const autoloadPath = join(vendorPath, 'autoload.php');
  const metadata = lstatSync(autoloadPath);
  const autoloadReal = realpathSync(autoloadPath);
  if (
    vendorMetadata.isSymbolicLink() || !vendorMetadata.isDirectory() || vendorReal !== vendorPath ||
    metadata.isSymbolicLink() || !metadata.isFile() || autoloadReal !== join(vendorReal, 'autoload.php') ||
    metadata.size < 1 || metadata.size > CUSTOM_CODE_EXECUTION_LIMITS.composerMetadataBytes
  ) throw new Error('unsafe Composer root autoloader');
  const bytes = readFileSync(autoloadReal);
  if (bytes.length !== metadata.size || bytes.length > CUSTOM_CODE_EXECUTION_LIMITS.composerMetadataBytes) {
    throw new Error('Composer root autoloader changed or exceeded its bound while reading');
  }
  return { bytes: bytes.length, sha256: `sha256:${sha256(bytes)}` };
}

function requiredComposerPackageKeys(needs) {
  return [
    ...(needs.phpcs ? ['phpcs', 'coder', 'slevomat', 'variableAnalysis'] : []),
    ...(needs.phpstan ? ['phpstan'] : []),
    ...(needs.phpunit ? ['phpunit'] : [])
  ];
}

function canonicalComposerValue(value, depth = 0) {
  if (depth > 16) throw new Error('composer package metadata is too deeply nested');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.includes('\u0000') || Buffer.byteLength(value) > 16 * 1024) throw new Error('invalid composer metadata string');
    return value;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (Array.isArray(value)) {
    if (value.length > 10_000) throw new Error('composer metadata array is too large');
    return value.map((entry) => canonicalComposerValue(entry, depth + 1));
  }
  if (plainJsonObject(value)) {
    const keys = Object.keys(value).sort(comparePortable);
    if (keys.length > 10_000) throw new Error('composer metadata object is too large');
    return Object.fromEntries(keys.map((key) => {
      if (key.includes('\u0000') || Buffer.byteLength(key) > 1_024) throw new Error('invalid composer metadata key');
      return [key, canonicalComposerValue(value[key], depth + 1)];
    }));
  }
  throw new Error('unsupported composer metadata value');
}

function canonicalComposerStringMap(value) {
  if (value === undefined) return {};
  if (!plainJsonObject(value)) throw new Error('invalid composer dependency map');
  const entries = Object.keys(value).sort(comparePortable).map((name) => {
    const constraint = value[name];
    if (
      !/^[a-z0-9](?:[a-z0-9_.-]*\/[a-z0-9_.-]+|[a-z0-9_.-]*)$/i.test(name) ||
      typeof constraint !== 'string' || !constraint || constraint.includes('\u0000') || Buffer.byteLength(constraint) > 1_024
    ) throw new Error('invalid composer dependency');
    return [name.toLowerCase(), constraint];
  });
  if (new Set(entries.map(([name]) => name)).size !== entries.length) throw new Error('duplicate composer dependency');
  return Object.fromEntries(entries);
}

function canonicalComposerBin(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 100) throw new Error('invalid composer binary list');
  const binaries = value.map((entry) => String(entry ?? '')).sort(comparePortable);
  if (
    new Set(binaries).size !== binaries.length ||
    binaries.some((entry) => !entry || isAbsolute(entry) || entry.includes('\u0000') || entry.split('/').some((part) => !part || part === '.' || part === '..'))
  ) throw new Error('unsafe composer binary path');
  return binaries;
}

function exactComposerPackageIdentity(record) {
  if (!plainJsonObject(record)) throw new Error('invalid composer package');
  const name = String(record.name ?? '').toLowerCase();
  const version = String(record.version ?? '');
  const type = String(record.type ?? '');
  const distUrl = verifiedHttpsUrl(record?.dist?.url);
  const distReference = String(record?.dist?.reference ?? '');
  const sourceUrl = verifiedHttpsUrl(record?.source?.url);
  const sourceReference = String(record?.source?.reference ?? '');
  if (
    !/^[a-z0-9][a-z0-9_.-]*\/[a-z0-9][a-z0-9_.-]*$/.test(name) ||
    !version || version.length > 200 || /\s|\u0000/.test(version) ||
    !type || type.length > 200 || /[\r\n\u0000]/.test(type) ||
    record?.dist?.type !== 'zip' || !distUrl || !/^[a-f0-9]{7,64}$/i.test(distReference) ||
    (record.source !== undefined && (
      !plainJsonObject(record.source) || record.source.type !== 'git' || !sourceUrl ||
      !/^[a-f0-9]{7,64}$/i.test(sourceReference)
    ))
  ) throw new Error('untrusted composer package identity');
  return {
    autoload: canonicalComposerValue(record.autoload ?? {}),
    bin: canonicalComposerBin(record.bin),
    conflict: canonicalComposerStringMap(record.conflict),
    distReference,
    distUrlSha256: `sha256:${sha256(distUrl)}`,
    name,
    provide: canonicalComposerStringMap(record.provide),
    replace: canonicalComposerStringMap(record.replace),
    require: canonicalComposerStringMap(record.require),
    sourceReference: sourceUrl ? sourceReference : '',
    sourceUrlSha256: sourceUrl ? `sha256:${sha256(sourceUrl)}` : '',
    type,
    version
  };
}

function composerPackageRecords(lock) {
  const records = [...(Array.isArray(lock.packages) ? lock.packages : []), ...(Array.isArray(lock['packages-dev']) ? lock['packages-dev'] : [])];
  if (records.length > CUSTOM_CODE_EXECUTION_LIMITS.composerPackages) throw new Error('composer package limit exceeded');
  const byName = new Map();
  for (const record of records) {
    const name = String(record?.name ?? '').toLowerCase();
    if (!plainJsonObject(record) || !/^[a-z0-9][a-z0-9_.-]*\/[a-z0-9][a-z0-9_.-]*$/.test(name)) {
      throw new Error('invalid composer package name');
    }
    if (byName.has(name)) throw new Error('duplicate composer package');
    byName.set(name, record);
  }
  return byName;
}

function composerPlatformDependency(name) {
  return name === 'php' || name === 'php-64bit' || name === 'hhvm' ||
    name === 'composer-plugin-api' || name === 'composer-runtime-api' ||
    name.startsWith('ext-') || name.startsWith('lib-');
}

function lockedComposerClosure(lock, directNames) {
  const byName = composerPackageRecords(lock);
  const providers = new Map();
  for (const record of byName.values()) {
    const name = String(record.name).toLowerCase();
    const provide = canonicalComposerStringMap(record.provide);
    const replace = canonicalComposerStringMap(record.replace);
    for (const virtualName of [...Object.keys(provide), ...Object.keys(replace)]) {
      if (!providers.has(virtualName)) providers.set(virtualName, []);
      providers.get(virtualName).push(name);
    }
  }
  const pending = [...new Set(directNames.map((name) => String(name).toLowerCase()))];
  const selected = new Map();
  while (pending.length > 0) {
    const name = pending.shift();
    if (selected.has(name)) continue;
    const current = byName.get(name);
    if (!current) throw new Error('composer closure package is absent from lock');
    const identity = exactComposerPackageIdentity(current);
    selected.set(name, identity);
    if (selected.size > CUSTOM_CODE_EXECUTION_LIMITS.composerPackages) throw new Error('composer closure limit exceeded');
    for (const dependency of Object.keys(identity.require)) {
      if (composerPlatformDependency(dependency)) continue;
      if (byName.has(dependency)) {
        pending.push(dependency);
        continue;
      }
      const candidates = [...new Set(providers.get(dependency) ?? [])].sort(comparePortable);
      if (candidates.length === 0) throw new Error('composer dependency has no locked provider');
      pending.push(...candidates);
    }
  }
  return [...selected.values()].sort((left, right) => comparePortable(left.name, right.name));
}

function composerLockIsExactClosure(lock, expectedClosure) {
  try {
    const actual = [...composerPackageRecords(lock).values()]
      .map((record) => exactComposerPackageIdentity(record))
      .sort((left, right) => comparePortable(left.name, right.name));
    return JSON.stringify(actual) === JSON.stringify(expectedClosure);
  } catch {
    return false;
  }
}

function exactLockedComposerPackage(lock, key) {
  const specification = CUSTOM_CODE_COMPOSER_PACKAGES[key];
  const lockedPackages = [...(Array.isArray(lock.packages) ? lock.packages : []), ...(Array.isArray(lock['packages-dev']) ? lock['packages-dev'] : [])]
    .filter((candidate) => candidate?.name === specification.name);
  if (lockedPackages.length !== 1) throw new Error('missing or duplicate composer package');
  const locked = lockedPackages[0];
  const identity = exactComposerPackageIdentity(locked);
  const sourceUrl = verifiedHttpsUrl(locked?.source?.url);
  const distUrl = verifiedHttpsUrl(locked?.dist?.url);
  const reference = String(locked?.dist?.reference ?? '');
  const canonicalDist = specification.distPrefixes.some((prefix) => distUrl.startsWith(prefix));
  const canonicalSource = sourceUrl ? specification.sourceUrls.includes(sourceUrl) : specification.sourceOptional === true;
  if (
    !plainJsonObject(locked) || typeof locked.version !== 'string' ||
    !/^v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$/.test(locked.version) ||
    typeof locked.type !== 'string' || !locked.type || !canonicalSource || !canonicalDist ||
    locked?.dist?.type !== 'zip' || !/^[a-f0-9]{7,64}$/i.test(reference) ||
    (sourceUrl && (locked?.source?.type !== 'git' || locked?.source?.reference !== reference))
  ) throw new Error('untrusted composer package provenance');
  if (specification.binary && !identity.bin.includes(specification.binary)) throw new Error('locked package binary missing');
  return {
    constraint: locked.version,
    distUrlSha256: `sha256:${sha256(distUrl)}`,
    name: specification.name,
    reference,
    sourceUrlSha256: sourceUrl ? `sha256:${sha256(sourceUrl)}` : '',
    type: locked.type,
    version: locked.version
  };
}

function exactInstalledComposerPackage(lock, installed, key, projectRoot, packageTree = null) {
  const specification = CUSTOM_CODE_COMPOSER_PACKAGES[key];
  const lockedRecord = exactLockedComposerPackage(lock, key);
  const installedPackages = (Array.isArray(installed?.packages) ? installed.packages : [])
    .filter((candidate) => candidate?.name === specification.name);
  if (installedPackages.length !== 1) throw new Error('missing or duplicate installed composer package');
  const current = installedPackages[0];
  const lockedIdentity = exactComposerPackageIdentity(composerPackageRecords(lock).get(specification.name));
  const installedIdentity = exactComposerPackageIdentity(current);
  const currentSourceUrl = verifiedHttpsUrl(current?.source?.url);
  const currentDistUrl = verifiedHttpsUrl(current?.dist?.url);
  if (
    !plainJsonObject(current) || JSON.stringify(installedIdentity) !== JSON.stringify(lockedIdentity) ||
    current.version !== lockedRecord.version || current.type !== lockedRecord.type ||
    current['installation-source'] !== 'dist' || current['install-path'] !== `../${specification.name}` ||
    current?.dist?.type !== 'zip' || current?.dist?.reference !== lockedRecord.reference ||
    `sha256:${sha256(currentDistUrl)}` !== lockedRecord.distUrlSha256 ||
    (lockedRecord.sourceUrlSha256
      ? current?.source?.type !== 'git' || current?.source?.reference !== lockedRecord.reference ||
        `sha256:${sha256(currentSourceUrl)}` !== lockedRecord.sourceUrlSha256
      : currentSourceUrl !== '')
  ) throw new Error('untrusted installed composer package provenance');
  const packageRelative = `vendor/${specification.name}`;
  const packageReal = realpathSync(join(projectRoot, packageRelative));
  if (packageReal !== realpathSync(join(projectRoot, 'vendor', ...specification.name.split('/')))) throw new Error('noncanonical package path');
  const binary = specification.binary ? `${packageRelative}/${specification.binary}` : '';
  if (binary) {
    const binaryMetadata = lstatSync(join(projectRoot, binary));
    if (binaryMetadata.isSymbolicLink() || !binaryMetadata.isFile() || (binaryMetadata.mode & 0o111) === 0) throw new Error('unsafe direct package binary');
  }
  return {
    binary,
    distUrlSha256: lockedRecord.distUrlSha256,
    name: specification.name,
    packagePath: packageRelative,
    packageTree: packageTree ?? packageDirectoryFingerprint(projectRoot, specification.name),
    reference: lockedRecord.reference,
    sourceUrlSha256: lockedRecord.sourceUrlSha256,
    version: lockedRecord.version
  };
}

function exactInstalledComposerClosure(installed, expectedClosure, projectRoot) {
  if (!plainJsonObject(installed) || !Array.isArray(installed.packages)) throw new Error('invalid installed composer metadata');
  const expectedNames = expectedClosure.map((entry) => entry.name).sort(comparePortable);
  const installedByName = new Map();
  for (const current of installed.packages) {
    const identity = exactComposerPackageIdentity(current);
    if (installedByName.has(identity.name)) throw new Error('duplicate installed composer package');
    installedByName.set(identity.name, { current, identity });
  }
  if (JSON.stringify([...installedByName.keys()].sort(comparePortable)) !== JSON.stringify(expectedNames)) {
    throw new Error('installed composer closure differs from locked closure');
  }
  const trees = {};
  let bytes = 0;
  let files = 0;
  for (const expected of expectedClosure) {
    const installedPackage = installedByName.get(expected.name);
    const current = installedPackage?.current;
    if (
      !current || JSON.stringify(installedPackage.identity) !== JSON.stringify(expected) ||
      current['installation-source'] !== 'dist' || current['install-path'] !== `../${expected.name}`
    ) throw new Error('installed composer closure package differs from lock');
    const packageRelative = `vendor/${expected.name}`;
    const packageReal = realpathSync(join(projectRoot, packageRelative));
    if (packageReal !== realpathSync(join(projectRoot, 'vendor', ...expected.name.split('/')))) {
      throw new Error('noncanonical closure package path');
    }
    const tree = packageDirectoryFingerprint(projectRoot, expected.name);
    bytes += tree.bytes;
    files += tree.files;
    if (
      bytes > CUSTOM_CODE_EXECUTION_LIMITS.composerPackageBytesTotal ||
      files > CUSTOM_CODE_EXECUTION_LIMITS.composerPackageFilesTotal
    ) throw new Error('composer closure package tree limit exceeded');
    trees[expected.name] = tree;
  }
  const autoloadTree = packageDirectoryFingerprint(projectRoot, 'composer');
  return { autoloadTree, bytes, files, trees };
}

function customCodeToolRequirements(projectRoot, needs) {
  const failures = [];
  const packages = {};
  let closure = [];
  let composerRecord;
  let lockRecord;
  if (!needs.phpcs && !needs.phpstan && !needs.phpunit) return { closure, failures, packages, snapshot: null };
  try {
    composerRecord = boundedLocalJson(projectRoot, 'composer.json');
    lockRecord = boundedLocalJson(projectRoot, 'composer.lock');
    if (!plainJsonObject(composerRecord.value) || !plainJsonObject(lockRecord.value) || !/^[a-f0-9]{32}$/i.test(String(lockRecord.value['content-hash'] ?? ''))) {
      throw new Error('invalid composer metadata');
    }
    for (const key of requiredComposerPackageKeys(needs)) packages[key] = exactLockedComposerPackage(lockRecord.value, key);
    closure = lockedComposerClosure(lockRecord.value, Object.values(packages).map((entry) => entry.name));
  } catch {
    failures.push(customCodeFailure('tool_missing', 'tool-provenance', '', 'Required analyzer/test packages and their complete executable/autoload dependency closure must have bounded HTTPS dist/source metadata in the exact project lock.'));
  }
  const snapshot = failures.length === 0 ? {
    composerJsonSha256: composerRecord.sha256,
    composerLockSha256: lockRecord.sha256,
    closureIdentitySha256: `sha256:${sha256(JSON.stringify(closure))}`,
    closurePackageCount: closure.length,
    lockedPackageIdentitySha256: Object.fromEntries(Object.entries(packages).map(([key, value]) => [key, `sha256:${sha256(JSON.stringify(value))}`]))
  } : null;
  return { closure, failures, packages, snapshot };
}

function sameLockedToolPackages(actual, expected) {
  return Object.keys(expected.packages).length === Object.keys(actual.packages).length &&
    Object.keys(expected.packages).every((key) => JSON.stringify(actual.packages[key]) === JSON.stringify(expected.packages[key])) &&
    JSON.stringify(actual.closure) === JSON.stringify(expected.closure);
}

function customCodeToolchainProvenance(auditRoot, needs, requirements) {
  const failures = [];
  const packages = {};
  let closureInstall = null;
  let composerRecord;
  let lockRecord;
  let installedRecord;
  let rootAutoload;
  try {
    composerRecord = boundedLocalJson(auditRoot, 'composer.json');
    lockRecord = boundedLocalJson(auditRoot, 'composer.lock');
    installedRecord = boundedLocalJson(auditRoot, 'vendor/composer/installed.json');
    rootAutoload = composerRootAutoloadFingerprint(auditRoot);
    if (!plainJsonObject(composerRecord.value) || !plainJsonObject(lockRecord.value) || !plainJsonObject(installedRecord.value)) throw new Error('invalid audit composer metadata');
    if (!composerLockIsExactClosure(lockRecord.value, requirements.closure)) throw new Error('audit lock contains packages outside the exact closure');
    const locked = { closure: [], failures: [], packages: {}, snapshot: null };
    for (const key of requiredComposerPackageKeys(needs)) locked.packages[key] = exactLockedComposerPackage(lockRecord.value, key);
    locked.closure = lockedComposerClosure(lockRecord.value, Object.values(locked.packages).map((entry) => entry.name));
    if (!sameLockedToolPackages(locked, requirements)) throw new Error('audit lock differs from source lock');
    closureInstall = exactInstalledComposerClosure(installedRecord.value, locked.closure, auditRoot);
    for (const key of requiredComposerPackageKeys(needs)) {
      const name = CUSTOM_CODE_COMPOSER_PACKAGES[key].name;
      packages[key] = exactInstalledComposerPackage(lockRecord.value, installedRecord.value, key, auditRoot, closureInstall.trees[name]);
    }
  } catch {
    failures.push(customCodeFailure('tool_missing', 'tool-provenance', '', 'Fresh verifier audit dependencies, autoload metadata, and complete package closure did not match the exact independently resolved project lock closure.'));
  }
  const snapshot = failures.length === 0 ? {
    sourceComposerLockSha256: requirements.snapshot.composerLockSha256,
    composerJsonSha256: composerRecord.sha256,
    composerLockSha256: lockRecord.sha256,
    installedMetadataSha256: installedRecord.sha256,
    closureIdentitySha256: requirements.snapshot.closureIdentitySha256,
    closurePackageCount: requirements.snapshot.closurePackageCount,
    closurePackageTreeSha256: `sha256:${sha256(JSON.stringify(closureInstall.trees))}`,
    closurePackageBytes: closureInstall.bytes,
    closurePackageFiles: closureInstall.files,
    autoloadTreeSha256: closureInstall.autoloadTree.sha256,
    autoloadTreeBytes: closureInstall.autoloadTree.bytes,
    autoloadTreeFiles: closureInstall.autoloadTree.files,
    rootAutoloadSha256: rootAutoload.sha256,
    rootAutoloadBytes: rootAutoload.bytes,
    packageTreeSha256: Object.fromEntries(Object.entries(packages).map(([key, value]) => [key, value.packageTree.sha256]))
  } : null;
  return { failures, packages, snapshot };
}

function customCodeToolchainChanged(auditRoot, provenance, needs, requirements) {
  if (!provenance?.snapshot) return true;
  try {
    const current = customCodeToolchainProvenance(auditRoot, needs, requirements);
    return current.failures.length > 0 || JSON.stringify(current.snapshot) !== JSON.stringify(provenance.snapshot);
  } catch {
    return true;
  }
}

function auditToolBinary(projectRoot, auditRoot, packageRecord) {
  if (!packageRecord?.binary) return '';
  const projectReal = realpathSync(projectRoot);
  const auditReal = realpathSync(auditRoot);
  const binaryReal = realpathSync(join(auditReal, packageRecord.binary));
  if (!pathIsInside(projectReal, auditReal) || auditReal === projectReal || !pathIsInside(auditReal, binaryReal)) {
    return '';
  }
  return relative(projectReal, binaryReal).split(sep).join('/');
}

function auditPhpcsStandardsPath(projectRoot, auditRoot, packages) {
  try {
    const projectReal = realpathSync(projectRoot);
    const auditReal = realpathSync(auditRoot);
    if (!pathIsInside(projectReal, auditReal) || auditReal === projectReal) return '';
    const standards = [
      [packages?.coder, 'coder_sniffer'],
      [packages?.slevomat, ''],
      [packages?.variableAnalysis, '']
    ].map(([record, suffix]) => {
      const expectedPackagePath = `vendor/${record?.name ?? ''}`;
      if (!record || record.packagePath !== expectedPackagePath) throw new Error('noncanonical PHPCS standard package path');
      const packageReal = realpathSync(join(auditReal, ...expectedPackagePath.split('/')));
      const standardReal = suffix ? realpathSync(join(packageReal, suffix)) : packageReal;
      if (
        packageReal !== realpathSync(join(auditReal, 'vendor', ...record.name.split('/'))) ||
        !pathIsInside(auditReal, packageReal) || !pathIsInside(packageReal, standardReal) ||
        !statSync(standardReal).isDirectory()
      ) throw new Error('unsafe PHPCS standard package path');
      const projectRelative = relative(projectReal, standardReal).split(sep).join('/');
      if (!projectRelative || projectRelative.startsWith('../') || projectRelative.includes('/../')) {
        throw new Error('PHPCS standard path escaped the project');
      }
      return `/var/www/html/${projectRelative}`;
    });
    return standards.join(',');
  } catch {
    return '';
  }
}

function parseJsonOutput(result) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    return null;
  }
}

function plainJsonObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function finiteNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function analyzerFileLookup(files) {
  return new Map(files.map((file) => [file.path, file]));
}

function normalizedAnalyzerPath(value) {
  const path = String(value ?? '').replace(/^\/var\/www\/html\//, '');
  if (!path || path.includes('\u0000') || path.includes('\\') || path.startsWith('/') || path.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    return '';
  }
  return path;
}

function diagnosticDigest(value) {
  return `sha256:${sha256(String(value ?? ''))}`;
}

function strictPhpcsReport(parsed, expectedFiles) {
  if (!plainJsonObject(parsed) || !plainJsonObject(parsed.totals) || !plainJsonObject(parsed.files)) {
    return null;
  }
  for (const key of ['errors', 'warnings']) {
    if (!finiteNonnegativeInteger(parsed.totals[key])) return null;
  }
  if (parsed.totals.fixable !== undefined && !finiteNonnegativeInteger(parsed.totals.fixable)) return null;
  const expected = analyzerFileLookup(expectedFiles);
  const observed = new Map();
  const findings = [];
  let errors = 0;
  let warnings = 0;
  let fixable = 0;
  let messageCount = 0;
  for (const rawPath of Object.keys(parsed.files).sort(comparePortable)) {
    const path = normalizedAnalyzerPath(rawPath);
    const file = expected.get(path);
    const report = parsed.files[rawPath];
    if (!file || observed.has(path) || !plainJsonObject(report) || !Array.isArray(report.messages)) return null;
    if (!finiteNonnegativeInteger(report.errors) || !finiteNonnegativeInteger(report.warnings)) return null;
    observed.set(path, file);
    let fileErrors = 0;
    let fileWarnings = 0;
    for (const message of report.messages) {
      messageCount += 1;
      if (messageCount > 20_000 || !plainJsonObject(message)) return null;
      if (
        !finiteNonnegativeInteger(message.line) || !finiteNonnegativeInteger(message.column) ||
        !finiteNonnegativeInteger(message.severity) || !['ERROR', 'WARNING'].includes(message.type) ||
        typeof message.source !== 'string' || !message.source || message.source.length > 200 ||
        typeof message.message !== 'string' || Buffer.byteLength(message.message) > 16 * 1024 ||
        (message.fixable !== undefined && typeof message.fixable !== 'boolean')
      ) return null;
      if (message.type === 'ERROR') fileErrors += 1;
      else fileWarnings += 1;
      if (message.fixable === true) fixable += 1;
      appendBounded(findings, {
        fileId: file.id,
        line: message.line,
        column: message.column,
        severity: message.severity,
        type: message.type.toLowerCase(),
        ruleId: message.source,
        messageSha256: diagnosticDigest(message.message)
      });
    }
    if (report.errors !== fileErrors || report.warnings !== fileWarnings) return null;
    errors += fileErrors;
    warnings += fileWarnings;
  }
  if (parsed.totals.errors !== errors || parsed.totals.warnings !== warnings) return null;
  if (parsed.totals.fixable !== undefined && parsed.totals.fixable !== fixable) return null;
  return { findings, totals: { errors, warnings, fixable } };
}

function strictPhpstanReport(parsed, expectedFiles) {
  if (!plainJsonObject(parsed) || !plainJsonObject(parsed.totals) || !plainJsonObject(parsed.files) || !Array.isArray(parsed.errors)) {
    return null;
  }
  if (!finiteNonnegativeInteger(parsed.totals.errors) || !finiteNonnegativeInteger(parsed.totals.file_errors)) return null;
  const expected = analyzerFileLookup(expectedFiles);
  const observed = new Set();
  const findings = [];
  let fileErrors = 0;
  let messageCount = 0;
  for (const rawPath of Object.keys(parsed.files).sort(comparePortable)) {
    const path = normalizedAnalyzerPath(rawPath);
    const file = expected.get(path);
    const report = parsed.files[rawPath];
    if (!file || observed.has(path) || !plainJsonObject(report) || !Array.isArray(report.messages) || !finiteNonnegativeInteger(report.errors) || report.errors === 0) return null;
    observed.add(path);
    if (report.errors !== report.messages.length) return null;
    fileErrors += report.errors;
    for (const message of report.messages) {
      messageCount += 1;
      if (messageCount > 20_000 || !plainJsonObject(message)) return null;
      if (
        !(message.line === null || finiteNonnegativeInteger(message.line)) || typeof message.message !== 'string' ||
        Buffer.byteLength(message.message) > 16 * 1024 ||
        (message.identifier !== undefined && (typeof message.identifier !== 'string' || message.identifier.length > 200)) ||
        (message.tip !== undefined && (typeof message.tip !== 'string' || Buffer.byteLength(message.tip) > 16 * 1024)) ||
        (message.ignorable !== undefined && typeof message.ignorable !== 'boolean')
      ) return null;
      appendBounded(findings, {
        fileId: file.id,
        line: message.line ?? 0,
        ruleId: String(message.identifier ?? ''),
        messageSha256: diagnosticDigest(message.message)
      });
    }
  }
  if (parsed.errors.length > 20_000 || parsed.errors.some((message) => typeof message !== 'string' || Buffer.byteLength(message) > 16 * 1024)) return null;
  for (const message of parsed.errors) {
    appendBounded(findings, { fileId: '', line: 0, ruleId: 'phpstan.global', messageSha256: diagnosticDigest(message) });
  }
  if (parsed.totals.file_errors !== fileErrors || parsed.totals.errors !== parsed.errors.length) return null;
  return { findings, reportedFileIds: [...observed].map((path) => expected.get(path).id).sort(comparePortable), totals: { errors: parsed.totals.errors, fileErrors } };
}

function reportedComposerProvenance(provenance, packageRecords) {
  return {
    ...provenance.snapshot,
    rootAutoloadBytes: provenance.snapshot.rootAutoloadBytes,
    rootAutoloadSha256: provenance.snapshot.rootAutoloadSha256,
    packages: packageRecords
  };
}

function blockedQualityAudit(inventory, failures, phpFiles = []) {
  return finalizedCustomCodeRecord({
    schemaVersion: CUSTOM_CODE_QUALITY_SCHEMA,
    applies: phpFiles.length > 0,
    completed: false,
    status: 'blocked',
    inputInventoryFingerprint: String(inventory?.fingerprint ?? ''),
    limits: CUSTOM_CODE_EXECUTION_LIMITS,
    tools: {
      php: { status: 'blocked', version: '' },
      phpcs: { status: 'blocked', version: '', requiredStandards: ['Drupal', 'DrupalPractice'], installedStandards: [] },
      phpstan: { status: 'blocked', version: '', config: '', configSha256: '' }
    },
    checks: {
      phpSyntax: { status: 'blocked', expectedFileIds: phpFiles.map((file) => file.id), completedFileIds: [], findings: [], commandResultHashes: [] },
      phpcs: { status: 'blocked', expectedFileIds: phpFiles.map((file) => file.id), completedFileIds: [], findings: [], commandResultHashes: [] },
      phpstan: { status: 'blocked', expectedFileIds: phpFiles.map((file) => file.id), requestedFileIds: [], reportedFileIds: [], findings: [], commandResultHashes: [] }
    },
    failures
  });
}

function notApplicableQualityAudit(inventory) {
  return finalizedCustomCodeRecord({
    schemaVersion: CUSTOM_CODE_QUALITY_SCHEMA,
    applies: false,
    completed: true,
    status: 'not_applicable',
    inputInventoryFingerprint: String(inventory?.fingerprint ?? ''),
    limits: CUSTOM_CODE_EXECUTION_LIMITS,
    tools: {
      php: { status: 'not_applicable', version: '' },
      phpcs: { status: 'not_applicable', version: '', requiredStandards: ['Drupal', 'DrupalPractice'], installedStandards: [] },
      phpstan: { status: 'not_applicable', version: '', config: '', configSha256: '' }
    },
    checks: {
      phpSyntax: { status: 'not_applicable', expectedFileIds: [], completedFileIds: [], findings: [], commandResultHashes: [] },
      phpcs: { status: 'not_applicable', expectedFileIds: [], completedFileIds: [], findings: [], commandResultHashes: [] },
      phpstan: { status: 'not_applicable', expectedFileIds: [], requestedFileIds: [], reportedFileIds: [], findings: [], commandResultHashes: [] }
    },
    failures: []
  });
}

function runCustomCodeQualityAudit(projectRoot, inventory, phpFiles, runner, provenance, auditRoot) {
  if (phpFiles.length === 0) {
    return notApplicableQualityAudit(inventory);
  }
  const failures = [];
  const expectedFileIds = phpFiles.map((file) => file.id);
  const commandHashes = (records) => records.filter(Boolean).map((record) => record.resultSha256);
  const phpSyntax = {
    status: 'pass', expectedFileIds, completedFileIds: [], findings: [], commandResultHashes: []
  };
  const phpcs = {
    status: 'pass', expectedFileIds, completedFileIds: [], findings: [], commandResultHashes: []
  };
  const phpstan = {
    status: 'not_supported', expectedFileIds, requestedFileIds: [], reportedFileIds: [], findings: [], commandResultHashes: []
  };
  const tools = {
    php: { status: 'blocked', version: '' },
    phpcs: { status: 'blocked', version: '', requiredStandards: ['Drupal', 'DrupalPractice'], installedStandards: [] },
    phpstan: { status: 'not_supported', version: '', config: '', configSha256: '' }
  };

  const phpcsBinary = auditToolBinary(projectRoot, auditRoot, provenance?.packages?.phpcs);
  const phpcsStandardsPath = auditPhpcsStandardsPath(projectRoot, auditRoot, provenance?.packages);
  const phpstanConfigCandidates = ['phpstan.neon', 'phpstan.neon.dist', 'phpstan.dist.neon'];
  const phpstanConfig = recognizedProjectFile(projectRoot, phpstanConfigCandidates);
  const phpstanConfigDeclared = phpstanConfigCandidates.some((candidate) => existsSync(join(projectRoot, candidate)));
  const phpstanBinary = auditToolBinary(projectRoot, auditRoot, provenance?.packages?.phpstan);
  if (!phpcsBinary || !phpcsStandardsPath) {
    failures.push(customCodeFailure('tool_missing', 'phpcs', CUSTOM_CODE_COMPOSER_PACKAGES.phpcs.name, 'Custom PHP requires provenance-bound PHPCS, Drupal Coder, Slevomat, and VariableAnalysis package paths.'));
  }
  if (phpstanConfig && !phpstanBinary) {
    failures.push(customCodeFailure('tool_missing', 'phpstan', phpstanConfig, 'Recognized PHPStan config exists but its provenance-bound direct package binary is missing.'));
  }
  if (phpstanConfigDeclared && !phpstanConfig) {
    failures.push(customCodeFailure('config_missing', 'phpstan', '', 'The recognized PHPStan config path is unsafe or unreadable.'));
  }
  if (failures.length > 0) {
    return blockedQualityAudit(inventory, failures, phpFiles);
  }

  const phpVersion = runner.run({ argv: ['php', '--version'], timeoutMs: 10_000, outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes });
  phpSyntax.commandResultHashes.push(...commandHashes([phpVersion.record]));
  if (!phpVersion.ok) {
    failures.push(commandFailure(phpVersion, 'php-syntax', 'php', 'tool_missing'));
    return blockedQualityAudit(inventory, failures, phpFiles);
  }
  const normalizedPhpVersion = normalizedToolVersion(phpVersion.stdout, /^PHP\s+(\d+\.\d+\.\d+)(?:\s|$)/);
  if (!normalizedPhpVersion) {
    failures.push(customCodeFailure('invalid_output', 'php-syntax', 'php', 'PHP returned an unrecognized version record.'));
    return blockedQualityAudit(inventory, failures, phpFiles);
  }
  tools.php = { status: 'pass', version: normalizedPhpVersion, commandResultHash: phpVersion.record.resultSha256 };

  for (const file of phpFiles) {
    const result = runner.run({
      argv: ['php', '-l', file.path],
      timeoutMs: CUSTOM_CODE_EXECUTION_LIMITS.lintTimeoutMs,
      outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes
    });
    phpSyntax.commandResultHashes.push(...commandHashes([result.record]));
    if (result.failureCode) {
      failures.push(commandFailure(result, 'php-syntax', file.id));
      phpSyntax.status = 'blocked';
      break;
    }
    phpSyntax.completedFileIds.push(file.id);
    if (!result.ok) {
      phpSyntax.status = 'fail';
      appendBounded(phpSyntax.findings, {
        fileId: file.id,
        line: 0,
        ruleId: 'php.syntax'
      });
      failures.push(customCodeFailure('violations_found', 'php-syntax', file.id, 'PHP syntax validation reported a violation.'));
    }
  }
  if (phpSyntax.status === 'blocked') {
    return finalizedCustomCodeRecord({
      ...blockedQualityAudit(inventory, failures, phpFiles),
      checks: { ...blockedQualityAudit(inventory, failures, phpFiles).checks, phpSyntax },
      tools
    });
  }

  const phpcsVersion = runner.run({ argv: [phpcsBinary, '--version'], timeoutMs: 10_000, outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes });
  phpcs.commandResultHashes.push(...commandHashes([phpcsVersion.record]));
  if (!phpcsVersion.ok) {
    failures.push(commandFailure(phpcsVersion, 'phpcs', phpcsBinary, 'tool_missing'));
    return blockedQualityAudit(inventory, failures, phpFiles);
  }
  const normalizedPhpcsVersion = normalizedToolVersion(phpcsVersion.stdout, /^PHP_CodeSniffer\s+version\s+(\d+\.\d+(?:\.\d+)?)(?:\s|$)/i);
  if (!normalizedPhpcsVersion) {
    failures.push(customCodeFailure('invalid_output', 'phpcs', phpcsBinary, 'PHPCS returned an unrecognized version record.'));
    return blockedQualityAudit(inventory, failures, phpFiles);
  }
  const phpcsStandards = runner.run({
    argv: [phpcsBinary, '--runtime-set', 'installed_paths', phpcsStandardsPath, '-i'],
    timeoutMs: 10_000,
    outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes
  });
  phpcs.commandResultHashes.push(...commandHashes([phpcsStandards.record]));
  if (!phpcsStandards.ok) {
    failures.push(commandFailure(phpcsStandards, 'phpcs', phpcsBinary, 'invalid_output'));
    return blockedQualityAudit(inventory, failures, phpFiles);
  }
  const installedStandards = ['Drupal', 'DrupalPractice'].filter((standard) => new RegExp(`(?:^|[^A-Za-z])${standard}(?:$|[^A-Za-z])`).test(phpcsStandards.stdout));
  tools.phpcs = {
    status: installedStandards.length === 2 ? 'pass' : 'blocked',
    version: normalizedPhpcsVersion,
    requiredStandards: ['Drupal', 'DrupalPractice'],
    installedStandards,
    provenance: reportedComposerProvenance(provenance, [
      provenance.packages.phpcs,
      provenance.packages.coder,
      provenance.packages.slevomat,
      provenance.packages.variableAnalysis
    ]),
    versionCommandResultHash: phpcsVersion.record.resultSha256,
    standardsCommandResultHash: phpcsStandards.record.resultSha256
  };
  if (installedStandards.length !== 2) {
    failures.push(customCodeFailure('required_standard_missing', 'phpcs', phpcsBinary, 'PHPCS must expose both Drupal and DrupalPractice standards.'));
    return blockedQualityAudit(inventory, failures, phpFiles);
  }
  for (let offset = 0; offset < phpFiles.length; offset += CUSTOM_CODE_EXECUTION_LIMITS.phpcsChunkFiles) {
    const chunk = phpFiles.slice(offset, offset + CUSTOM_CODE_EXECUTION_LIMITS.phpcsChunkFiles);
    const result = runner.run({
      argv: [
        phpcsBinary,
        '--runtime-set', 'installed_paths', phpcsStandardsPath,
        '--standard=Drupal,DrupalPractice',
        '--extensions=php,module,inc,install,test,profile,theme',
        '--no-cache',
        '--report=json',
        ...chunk.map((file) => file.path)
      ],
      timeoutMs: CUSTOM_CODE_EXECUTION_LIMITS.phpcsTimeoutMs,
      outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.phpcsOutputBytes
    });
    phpcs.commandResultHashes.push(...commandHashes([result.record]));
    if (result.failureCode) {
      failures.push(commandFailure(result, 'phpcs', chunk[0]?.id ?? ''));
      phpcs.status = 'blocked';
      break;
    }
    const report = strictPhpcsReport(parseJsonOutput(result), chunk);
    if (!report) {
      failures.push(customCodeFailure('invalid_output', 'phpcs', chunk[0]?.id ?? '', 'PHPCS did not return a strict, file-reconciled bounded JSON report.'));
      phpcs.status = 'blocked';
      break;
    }
    phpcs.completedFileIds.push(...chunk.map((file) => file.id));
    for (const finding of report.findings) appendBounded(phpcs.findings, finding);
    if (report.totals.errors > 0 || report.totals.warnings > 0 || !result.ok) {
      phpcs.status = 'fail';
    }
  }
  if (phpcs.status === 'fail') {
    failures.push(customCodeFailure('violations_found', 'phpcs', '', `PHPCS reported ${phpcs.findings.length} bounded finding(s).`));
  }

  if (!phpstanConfig) {
    tools.phpstan = { status: 'not_supported', version: '', config: '', configSha256: '' };
    phpstan.status = 'not_supported';
  } else if (phpcs.status !== 'blocked') {
    const phpstanConfigSha256 = projectFileSha256(projectRoot, phpstanConfig);
    tools.phpstan = { status: 'blocked', version: '', config: phpstanConfig, configSha256: phpstanConfigSha256 };
    const version = runner.run({ argv: [phpstanBinary, '--version'], timeoutMs: 10_000, outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes });
    phpstan.commandResultHashes.push(...commandHashes([version.record]));
    if (!version.ok) {
      failures.push(commandFailure(version, 'phpstan', phpstanBinary, 'tool_missing'));
      phpstan.status = 'blocked';
    } else {
      const normalizedPhpstanVersion = normalizedToolVersion(version.stdout, /^(?:PHPStan(?:\s+-\s+PHP Static Analysis Tool)?\s+)(\d+\.\d+(?:\.\d+)?)(?:\s|$)/i);
      if (!normalizedPhpstanVersion) {
        failures.push(customCodeFailure('invalid_output', 'phpstan', phpstanBinary, 'PHPStan returned an unrecognized version record.'));
        phpstan.status = 'blocked';
      }
      if (phpstan.status === 'blocked') {
        // Do not execute an analyzer whose bounded version record is unrecognized.
      } else {
      tools.phpstan = {
        status: 'pass', version: normalizedPhpstanVersion, config: phpstanConfig, configSha256: phpstanConfigSha256,
        provenance: reportedComposerProvenance(provenance, [provenance.packages.phpstan]),
        versionCommandResultHash: version.record.resultSha256
      };
      phpstan.requestedFileIds = [...expectedFileIds];
      const result = runner.run({
        argv: [
          phpstanBinary,
          'analyse',
          `--configuration=${phpstanConfig}`,
          '--memory-limit=512M',
          '--no-result-cache',
          '--error-format=json',
          '--no-progress',
          ...phpFiles.map((file) => file.path)
        ],
        timeoutMs: CUSTOM_CODE_EXECUTION_LIMITS.phpstanTimeoutMs,
        outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.phpstanOutputBytes
      });
      phpstan.commandResultHashes.push(...commandHashes([result.record]));
      if (result.failureCode) {
        failures.push(commandFailure(result, 'phpstan', phpstanConfig));
        phpstan.status = 'blocked';
      } else {
        if (projectFileSha256(projectRoot, phpstanConfig) !== phpstanConfigSha256) {
          failures.push(customCodeFailure('stale_test_binding', 'phpstan', phpstanConfig, 'PHPStan config changed during verifier execution.'));
          phpstan.status = 'blocked';
        }
        const report = strictPhpstanReport(parseJsonOutput(result), phpFiles);
        if (phpstan.status !== 'blocked' && !report) {
          failures.push(customCodeFailure('invalid_output', 'phpstan', phpstanConfig, 'PHPStan did not return a strict, file-reconciled bounded JSON report.'));
          phpstan.status = 'blocked';
        } else if (phpstan.status !== 'blocked') {
          phpstan.reportedFileIds = report.reportedFileIds;
          phpstan.findings = report.findings;
          if (report.totals.fileErrors > 0 || report.totals.errors > 0 || !result.ok) {
            phpstan.status = 'fail';
            failures.push(customCodeFailure('violations_found', 'phpstan', phpstanConfig, `PHPStan reported ${phpstan.findings.length} bounded finding(s).`));
          } else {
            phpstan.status = 'pass';
          }
        }
      }
      }
    }
  }

  const blocked = [phpSyntax.status, phpcs.status, phpstan.status].includes('blocked');
  const failed = [phpSyntax.status, phpcs.status, phpstan.status].includes('fail');
  return finalizedCustomCodeRecord({
    schemaVersion: CUSTOM_CODE_QUALITY_SCHEMA,
    applies: true,
    completed: !blocked,
    status: blocked ? 'blocked' : failed ? 'fail' : 'pass',
    inputInventoryFingerprint: String(inventory?.fingerprint ?? ''),
    limits: CUSTOM_CODE_EXECUTION_LIMITS,
    tools,
    checks: { phpSyntax, phpcs, phpstan },
    failures
  });
}

function xmlDecodeStrict(value) {
  const text = String(value ?? '');
  let output = '';
  let offset = 0;
  for (const match of text.matchAll(/&([^;]*);/g)) {
    if (match.index > offset && text.slice(offset, match.index).includes('&')) throw new Error('malformed XML entity');
    output += text.slice(offset, match.index);
    const entity = match[1];
    if ({ amp: true, apos: true, gt: true, lt: true, quot: true }[entity]) {
      output += { amp: '&', apos: "'", gt: '>', lt: '<', quot: '"' }[entity];
    } else if (/^#(?:[1-9][0-9]*|0)$/.test(entity) || /^#x[0-9a-f]+$/i.test(entity)) {
      const codePoint = entity[1].toLowerCase() === 'x' ? Number.parseInt(entity.slice(2), 16) : Number.parseInt(entity.slice(1), 10);
      if (
        !Number.isSafeInteger(codePoint) || codePoint <= 0 || codePoint > 0x10ffff ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
        (codePoint < 0x20 && ![0x09, 0x0a, 0x0d].includes(codePoint))
      ) throw new Error('invalid XML character reference');
      output += String.fromCodePoint(codePoint);
    } else {
      throw new Error('unsupported XML entity');
    }
    offset = match.index + match[0].length;
  }
  if (text.slice(offset).includes('&')) throw new Error('malformed XML entity');
  return output + text.slice(offset);
}

function xmlAttributesStrict(value) {
  const text = String(value ?? '');
  const attributes = {};
  let offset = 0;
  while (offset < text.length) {
    if (!/\s/.test(text[offset])) throw new Error('XML attributes must be whitespace separated');
    while (offset < text.length && /\s/.test(text[offset])) offset += 1;
    if (offset === text.length) break;
    const nameMatch = text.slice(offset).match(/^([A-Za-z_:][A-Za-z0-9_.:-]*)/);
    if (!nameMatch) throw new Error('invalid XML attribute name');
    const name = nameMatch[1];
    offset += name.length;
    while (offset < text.length && /\s/.test(text[offset])) offset += 1;
    if (text[offset] !== '=') throw new Error('XML attribute is missing equals');
    offset += 1;
    while (offset < text.length && /\s/.test(text[offset])) offset += 1;
    const quote = text[offset];
    if (quote !== '"' && quote !== "'") throw new Error('XML attribute must be quoted');
    offset += 1;
    const end = text.indexOf(quote, offset);
    if (end < 0) throw new Error('unterminated XML attribute');
    const raw = text.slice(offset, end);
    if (raw.includes('<')) throw new Error('invalid XML attribute value');
    if (Object.hasOwn(attributes, name)) throw new Error('duplicate XML attribute');
    attributes[name] = xmlDecodeStrict(raw);
    if (Object.keys(attributes).length > 200) throw new Error('too many XML attributes');
    offset = end + 1;
  }
  return attributes;
}

function strictXmlDocument(value) {
  let xml = String(value ?? '');
  if (xml.charCodeAt(0) === 0xfeff) xml = xml.slice(1);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(xml)) throw new Error('XML contains forbidden control characters');
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('XML document types and entities are not accepted');
  let offset = 0;
  let declarationSeen = false;
  let root = null;
  let nodes = 0;
  const stack = [];
  const skipWhitespace = () => {
    while (offset < xml.length && /\s/.test(xml[offset])) offset += 1;
  };
  skipWhitespace();
  if (xml.startsWith('<?xml', offset)) {
    const end = xml.indexOf('?>', offset + 5);
    if (end < 0) throw new Error('unterminated XML declaration');
    const attributes = xmlAttributesStrict(xml.slice(offset + 5, end));
    if (!['1.0', '1.1'].includes(attributes.version) || Object.keys(attributes).some((name) => !['version', 'encoding', 'standalone'].includes(name))) {
      throw new Error('invalid XML declaration');
    }
    if (attributes.encoding && !/^utf-8$/i.test(attributes.encoding)) throw new Error('unsupported XML encoding');
    if (attributes.standalone && !['yes', 'no'].includes(attributes.standalone)) throw new Error('invalid XML standalone value');
    declarationSeen = true;
    offset = end + 2;
  }
  while (offset < xml.length) {
    if (xml[offset] !== '<') {
      const end = xml.indexOf('<', offset);
      const text = xml.slice(offset, end < 0 ? xml.length : end);
      if (text.includes(']]>')) throw new Error('invalid XML text terminator');
      xmlDecodeStrict(text);
      if (stack.length === 0 && text.trim()) throw new Error('XML text exists outside the root element');
      offset = end < 0 ? xml.length : end;
      continue;
    }
    if (xml.startsWith('<!--', offset)) {
      const end = xml.indexOf('-->', offset + 4);
      if (end < 0 || xml.slice(offset + 4, end).includes('--')) throw new Error('malformed XML comment');
      offset = end + 3;
      continue;
    }
    if (xml.startsWith('<![CDATA[', offset)) {
      if (stack.length === 0) throw new Error('XML CDATA exists outside the root element');
      const end = xml.indexOf(']]>', offset + 9);
      if (end < 0) throw new Error('unterminated XML CDATA');
      offset = end + 3;
      continue;
    }
    if (xml.startsWith('<?', offset) || xml.startsWith('<!', offset)) {
      throw new Error(declarationSeen ? 'XML processing instructions are not accepted' : 'unsupported XML markup');
    }
    let end = offset + 1;
    let quote = '';
    for (; end < xml.length; end += 1) {
      const character = xml[end];
      if (quote) {
        if (character === quote) quote = '';
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === '>') {
        break;
      } else if (character === '<') {
        throw new Error('nested XML tag opener');
      }
    }
    if (end >= xml.length || quote) throw new Error('unterminated XML tag');
    let content = xml.slice(offset + 1, end);
    if (content.startsWith('/')) {
      const name = content.slice(1).trim();
      if (!/^[A-Za-z_:][A-Za-z0-9_.:-]*$/.test(name) || stack.length === 0 || stack.at(-1).name !== name) {
        throw new Error('mismatched XML closing tag');
      }
      stack.pop();
      offset = end + 1;
      continue;
    }
    const selfClosing = /\/\s*$/.test(content);
    if (selfClosing) content = content.replace(/\/\s*$/, '');
    const nameMatch = content.match(/^([A-Za-z_:][A-Za-z0-9_.:-]*)/);
    if (!nameMatch) throw new Error('invalid XML element name');
    const name = nameMatch[1];
    const node = { attributes: xmlAttributesStrict(content.slice(name.length)), children: [], name };
    nodes += 1;
    if (nodes > 50_000) throw new Error('XML node limit exceeded');
    if (stack.length > 0) {
      stack.at(-1).children.push(node);
    } else if (root) {
      throw new Error('multiple XML root elements');
    } else {
      root = node;
    }
    if (!selfClosing) {
      stack.push(node);
      if (stack.length > 64) throw new Error('XML depth limit exceeded');
    }
    offset = end + 1;
  }
  if (!root || stack.length > 0) throw new Error('incomplete XML document');
  return root;
}

function xmlLocalName(node) {
  return String(node?.name ?? '').split(':').at(-1).toLowerCase();
}

function walkXml(node, visit) {
  visit(node);
  for (const child of node.children) walkXml(child, visit);
}

function parsePhpunitListTestsXml(xml) {
  const root = strictXmlDocument(xml);
  if (!['tests', 'testsuites'].includes(xmlLocalName(root))) throw new Error('unexpected PHPUnit list-tests root');
  const tests = [];
  walkXml(root, (node) => {
    const localName = xmlLocalName(node);
    if (localName === 'testcaseclass') {
      const className = String(node.attributes.name ?? '').replace(/^\\+/, '');
      for (const child of node.children) {
        if (xmlLocalName(child) !== 'testcasemethod') continue;
        const methodName = String(child.attributes.name ?? '').replace(/\s+with data set[\s\S]*$/i, '');
        if (className && methodName) tests.push({ className, methodName });
      }
    } else if (localName === 'testcase') {
      const className = String(node.attributes.classname ?? node.attributes.class ?? '').replace(/^\\+/, '');
      const methodName = String(node.attributes.name ?? '').replace(/\s+with data set[\s\S]*$/i, '');
      if (className && methodName) tests.push({ className, methodName });
    } else if (localName === 'test') {
      const name = String(node.attributes.name ?? '');
      const separator = name.lastIndexOf('::');
      if (separator > 0) {
        tests.push({
          className: name.slice(0, separator).replace(/^\\+/, ''),
          methodName: name.slice(separator + 2).replace(/\s+with data set[\s\S]*$/i, '')
        });
      }
    }
  });
  return [...new Map(tests.map((entry) => [`${entry.className}\u0000${entry.methodName}`, entry])).values()]
    .sort((left, right) => comparePortable(`${left.className}\u0000${left.methodName}`, `${right.className}\u0000${right.methodName}`));
}

function xmlNonnegativeInteger(attributes, name, required = true) {
  if (!Object.hasOwn(attributes, name)) {
    if (required) throw new Error(`JUnit suite is missing ${name}`);
    return 0;
  }
  const value = String(attributes[name]);
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`JUnit suite has invalid ${name}`);
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new Error(`JUnit suite ${name} exceeds integer bounds`);
  return number;
}

function parsePhpunitJunit(xml) {
  const root = strictXmlDocument(xml);
  if (!['testsuite', 'testsuites'].includes(xmlLocalName(root))) throw new Error('unexpected JUnit root');
  const cases = [];
  const metricKeys = ['tests', 'assertions', 'failures', 'errors', 'skipped', 'warnings', 'risky', 'incomplete'];
  const testcaseMetrics = (node) => {
    let className = String(node.attributes.classname ?? node.attributes.class ?? '').replace(/^\\+/, '');
    let name = String(node.attributes.name ?? '');
    const qualifiedSeparator = name.lastIndexOf('::');
    if (qualifiedSeparator > 0) {
      if (!className) className = name.slice(0, qualifiedSeparator).replace(/^\\+/, '');
      name = name.slice(qualifiedSeparator + 2);
    }
    if (!name) throw new Error('JUnit testcase is missing a name');
    const directNames = node.children.map(xmlLocalName);
    const record = {
      className,
      name,
      assertions: xmlNonnegativeInteger(node.attributes, 'assertions'),
      errors: directNames.filter((entry) => entry === 'error').length,
      failures: directNames.filter((entry) => entry === 'failure').length,
      skipped: directNames.filter((entry) => entry === 'skipped').length,
      warnings: directNames.filter((entry) => ['warning', 'risky', 'incomplete'].includes(entry)).length
    };
    cases.push(record);
    return {
      tests: 1,
      assertions: record.assertions,
      failures: record.failures,
      errors: record.errors,
      skipped: record.skipped,
      warnings: directNames.filter((entry) => entry === 'warning').length,
      risky: directNames.filter((entry) => entry === 'risky').length,
      incomplete: directNames.filter((entry) => entry === 'incomplete').length
    };
  };
  const addMetrics = (left, right) => Object.fromEntries(metricKeys.map((key) => [key, left[key] + right[key]]));
  const suiteMetrics = (node) => {
    let actual = Object.fromEntries(metricKeys.map((key) => [key, 0]));
    for (const child of node.children) {
      const localName = xmlLocalName(child);
      if (localName === 'testcase') actual = addMetrics(actual, testcaseMetrics(child));
      else if (localName === 'testsuite') actual = addMetrics(actual, suiteMetrics(child));
      else {
        let nestedTestNode = false;
        walkXml(child, (descendant) => {
          if (['testcase', 'testsuite'].includes(xmlLocalName(descendant))) nestedTestNode = true;
        });
        if (nestedTestNode) throw new Error('JUnit testcase or suite is nested under an unsupported element');
      }
    }
    const declared = Object.fromEntries(metricKeys.map((key) => [key, xmlNonnegativeInteger(
      node.attributes,
      key,
      ['tests', 'assertions', 'failures', 'errors', 'skipped'].includes(key)
    )]));
    for (const key of metricKeys) {
      if (declared[key] !== actual[key]) throw new Error(`JUnit suite ${key} total is inconsistent`);
    }
    return actual;
  };
  let totals;
  if (xmlLocalName(root) === 'testsuite') {
    totals = suiteMetrics(root);
  } else {
    totals = Object.fromEntries(metricKeys.map((key) => [key, 0]));
    for (const child of root.children) {
      if (xmlLocalName(child) !== 'testsuite') throw new Error('JUnit testsuites root contains an unsupported child');
      totals = addMetrics(totals, suiteMetrics(child));
    }
    const declaredKeys = metricKeys.filter((key) => Object.hasOwn(root.attributes, key));
    if (declaredKeys.length > 0) {
      if (['tests', 'assertions', 'failures', 'errors', 'skipped'].some((key) => !declaredKeys.includes(key))) {
        throw new Error('JUnit testsuites root has partial totals');
      }
      for (const key of metricKeys) {
        const declared = xmlNonnegativeInteger(root.attributes, key, false);
        if (declared !== totals[key]) throw new Error(`JUnit testsuites ${key} total is inconsistent`);
      }
    }
  }
  return {
    cases,
    assertions: totals.assertions,
    errors: totals.errors,
    failures: totals.failures,
    skipped: totals.skipped,
    warnings: totals.warnings + totals.risky + totals.incomplete
  };
}

function boundedGeneratedFile(projectRoot, path, limit) {
  const absolute = resolve(projectRoot, path);
  const metadata = lstatSync(absolute);
  const real = realpathSync(absolute);
  const realProjectRoot = realpathSync(projectRoot);
  if (metadata.isSymbolicLink() || !metadata.isFile() || !pathIsInside(realProjectRoot, real) || metadata.size > limit) {
    throw new Error('Generated verifier file is missing, unsafe, or oversized.');
  }
  return readFileSync(real);
}

function blockedFocusedTestExecution(inventory, applies, rows, failures) {
  return finalizedCustomCodeRecord({
    schemaVersion: CUSTOM_CODE_TEST_EXECUTION_SCHEMA,
    applies,
    completed: false,
    status: 'blocked',
    inputInventoryFingerprint: String(inventory?.fingerprint ?? ''),
    limits: CUSTOM_CODE_EXECUTION_LIMITS,
    tools: { phpunit: { status: 'blocked', version: '', config: '', configSha256: '' }, ddevDatabaseFamily: { status: 'blocked', family: '' } },
    expectedTestMethodIds: [...new Set(rows.map((row) => row.testMethodId))].sort(comparePortable),
    completedTestMethodIds: [],
    discovery: [],
    runs: [],
    failures
  });
}

function notApplicableFocusedTestExecution(inventory) {
  return finalizedCustomCodeRecord({
    schemaVersion: CUSTOM_CODE_TEST_EXECUTION_SCHEMA,
    applies: false,
    completed: true,
    status: 'not_applicable',
    inputInventoryFingerprint: String(inventory?.fingerprint ?? ''),
    limits: CUSTOM_CODE_EXECUTION_LIMITS,
    tools: { phpunit: { status: 'not_applicable', version: '', config: '', configSha256: '' }, ddevDatabaseFamily: { status: 'not_applicable', family: '' } },
    expectedTestMethodIds: [],
    completedTestMethodIds: [],
    discovery: [],
    runs: [],
    failures: []
  });
}

function pcreLiteral(value) {
  return String(value).replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
}

function runFocusedCustomCodeTests(projectRoot, inventory, coverage, runner, baseUrl, provenance, auditRoot, executorOverride = null, isolation = null) {
  if (!coverage.applies) {
    return notApplicableFocusedTestExecution(inventory);
  }
  if (coverage.failures.length > 0) {
    return blockedFocusedTestExecution(inventory, true, coverage.rows, coverage.failures);
  }
  const failures = [];
  const phpunitConfig = recognizedProjectFile(projectRoot, [
    'phpunit.xml',
    'phpunit.xml.dist',
    'phpunit.dist.xml',
    `${ddevDocroot(projectRoot)}/core/phpunit.xml`,
    `${ddevDocroot(projectRoot)}/core/phpunit.xml.dist`
  ]);
  const phpunitBinary = auditToolBinary(projectRoot, auditRoot, provenance?.packages?.phpunit);
  if (!phpunitConfig) {
    failures.push(customCodeFailure('config_missing', 'phpunit', '', 'Focused PHPUnit execution requires a recognized project or Drupal core PHPUnit config.'));
  }
  if (!phpunitBinary) {
    failures.push(customCodeFailure('tool_missing', 'phpunit', CUSTOM_CODE_COMPOSER_PACKAGES.phpunit.name, 'Focused PHPUnit execution requires a provenance-bound direct PHPUnit package binary.'));
  }
  let simpletestBaseUrl = '';
  try {
    simpletestBaseUrl = baseUrl ? parseHttpUrl(baseUrl, 'Verified DDEV base URL').origin : '';
  } catch {
    simpletestBaseUrl = '';
  }
  if (!simpletestBaseUrl) {
    failures.push(customCodeFailure('config_missing', 'phpunit', 'SIMPLETEST_BASE_URL', 'Verified DDEV base URL is unavailable.'));
  }
  if (failures.length > 0) {
    return blockedFocusedTestExecution(inventory, true, coverage.rows, failures);
  }

  const run = (specification) => runner.run({ ...specification, executorOverride });
  const version = run({ argv: [phpunitBinary, '--version'], timeoutMs: 10_000, outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes });
  if (!version.ok) {
    failures.push(commandFailure(version, 'phpunit', phpunitBinary, 'tool_missing'));
    return blockedFocusedTestExecution(inventory, true, coverage.rows, failures);
  }
  const normalizedPhpunitVersion = normalizedToolVersion(version.stdout, /^PHPUnit\s+(\d+\.\d+(?:\.\d+)?)(?:\s|$)/i);
  if (!normalizedPhpunitVersion) {
    failures.push(customCodeFailure('invalid_output', 'phpunit', phpunitBinary, 'PHPUnit returned an unrecognized version record.'));
    return blockedFocusedTestExecution(inventory, true, coverage.rows, failures);
  }
  const databaseFamilyResult = run({
    argv: ['printenv', 'DDEV_DATABASE_FAMILY'],
    timeoutMs: 10_000,
    outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.lintOutputBytes
  });
  if (!databaseFamilyResult.ok) {
    failures.push(commandFailure(databaseFamilyResult, 'phpunit', 'DDEV_DATABASE_FAMILY', 'invalid_output'));
    return blockedFocusedTestExecution(inventory, true, coverage.rows, failures);
  }
  const databaseFamily = databaseFamilyResult.ok ? databaseFamilyResult.stdout.trim() : '';
  if (!['mysql', 'postgres'].includes(databaseFamily)) {
    failures.push(customCodeFailure('invalid_output', 'phpunit', 'DDEV_DATABASE_FAMILY', 'Verified DDEV database family must be mysql or postgres.'));
    return blockedFocusedTestExecution(inventory, true, coverage.rows, failures);
  }
  const tools = {
    phpunit: {
      status: 'pass',
      version: normalizedPhpunitVersion,
      config: phpunitConfig,
      configSha256: projectFileSha256(projectRoot, phpunitConfig),
      provenance: reportedComposerProvenance(provenance, [provenance.packages.phpunit]),
      versionCommandResultHash: version.record.resultSha256
    },
    ddevDatabaseFamily: { status: 'pass', family: databaseFamily, commandResultHash: databaseFamilyResult.record.resultSha256 }
  };
  const simpletestDb = databaseFamily === 'mysql' ? 'mysql://db:db@db/db' : 'pgsql://db:db@db/db';
  const env = { SIMPLETEST_BASE_URL: simpletestBaseUrl, SIMPLETEST_DB: simpletestDb };
  const discovery = [];
  const runs = [];
  const expectedTestMethodIds = [...new Set(coverage.rows.map((row) => row.testMethodId))].sort(comparePortable);
  const completedTestMethodIds = [];
  let junitBytes = 0;
  let dataCases = 0;
  let tempDirectory = '';
  try {
    const ddevDirectory = join(projectRoot, '.ddev');
    const ddevMetadata = lstatSync(ddevDirectory);
    if (ddevMetadata.isSymbolicLink() || !ddevMetadata.isDirectory()) {
      throw new Error('Unsafe DDEV directory.');
    }
    tempDirectory = mkdtempSync(join(ddevDirectory, '.agent-ready-custom-code-'));
    const tempRelative = relative(projectRoot, tempDirectory).split(sep).join('/');
    const rowsByFile = new Map();
    for (const row of coverage.rows) {
      if (!rowsByFile.has(row.testFileId)) rowsByFile.set(row.testFileId, []);
      rowsByFile.get(row.testFileId).push(row);
    }
    for (const [testFileId, rows] of [...rowsByFile].sort(([left], [right]) => comparePortable(left, right))) {
      const outputPath = `${tempRelative}/list-${testFileId}.xml`;
      const result = run({
        argv: [
          phpunitBinary,
          '--configuration', phpunitConfig,
          '--colors=never',
          '--do-not-cache-result',
          '--list-tests-xml', outputPath,
          rows[0].path
        ],
        env,
        timeoutMs: CUSTOM_CODE_EXECUTION_LIMITS.discoveryTimeoutMs,
        outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.discoveryOutputBytes
      });
      if (!result.ok) {
        failures.push(commandFailure(result, 'phpunit-discovery', testFileId, result.failureCode || 'invalid_output'));
        break;
      }
      let bytes;
      try {
        bytes = boundedGeneratedFile(projectRoot, outputPath, CUSTOM_CODE_EXECUTION_LIMITS.discoveryOutputBytes);
      } catch {
        failures.push(customCodeFailure('invalid_output', 'phpunit-discovery', testFileId, 'PHPUnit list-tests XML is missing, unsafe, or oversized.'));
        break;
      }
      const discoveryBudgetFailure = reserveCustomCodeGeneratedOutput(runner, bytes.length);
      if (discoveryBudgetFailure) {
        failures.push(customCodeFailure(discoveryBudgetFailure, 'phpunit-discovery', testFileId, 'Generated PHPUnit discovery evidence exceeded the shared execution budget.'));
        break;
      }
      let discovered;
      try {
        discovered = parsePhpunitListTestsXml(bytes.toString('utf8'));
      } catch {
        failures.push(customCodeFailure('invalid_output', 'phpunit-discovery', testFileId, 'PHPUnit list-tests XML is not a strict well-formed bounded document.'));
        break;
      }
      const discoveredKeys = new Set(discovered.map((test) => `${test.className}\u0000${test.methodName}`));
      const missing = rows.filter((row) => !discoveredKeys.has(`${row.className}\u0000${row.methodName}`));
      discovery.push({
        testFileId,
        path: rows[0].path,
        expectedTestMethodIds: [...new Set(rows.map((row) => row.testMethodId))].sort(comparePortable),
        discoveredMethodCount: discovered.length,
        xmlSha256: `sha256:${sha256(bytes)}`,
        commandResultHash: result.record.resultSha256,
        status: missing.length === 0 ? 'pass' : 'blocked'
      });
      for (const row of missing) {
        failures.push(customCodeFailure('unknown_test_method', 'phpunit-discovery', row.testMethodId, 'Inventoried test method was not present in PHPUnit list-tests XML.'));
      }
      if (missing.length > 0) break;
    }
    if (failures.length === 0) {
      const executionRows = [...new Map(coverage.rows.map((row) => [row.testMethodId, row])).values()]
        .sort((left, right) => comparePortable(left.testMethodId, right.testMethodId));
      for (const row of executionRows) {
        const junitPath = `${tempRelative}/junit-${row.testMethodId}.xml`;
        const filter = `/^${pcreLiteral(row.className)}::${pcreLiteral(row.methodName)}(?: .*)?$/`;
        const result = run({
          argv: [
            phpunitBinary,
            '--configuration', phpunitConfig,
            '--colors=never',
            '--do-not-cache-result',
            '--filter', filter,
            '--log-junit', junitPath,
            '--fail-on-warning',
            '--fail-on-risky',
            '--fail-on-incomplete',
            '--fail-on-skipped',
            row.path
          ],
          env,
          timeoutMs: CUSTOM_CODE_EXECUTION_LIMITS.testExecutionTimeoutMs,
          outputLimitBytes: CUSTOM_CODE_EXECUTION_LIMITS.junitBytesPerRun
        });
        if (result.failureCode) {
          failures.push(commandFailure(result, 'phpunit-execution', row.testMethodId));
          break;
        }
        let bytes;
        try {
          bytes = boundedGeneratedFile(projectRoot, junitPath, CUSTOM_CODE_EXECUTION_LIMITS.junitBytesPerRun);
        } catch {
          failures.push(customCodeFailure('invalid_output', 'phpunit-execution', row.testMethodId, 'PHPUnit JUnit XML is missing, unsafe, or oversized.'));
          break;
        }
        const junitBudgetFailure = reserveCustomCodeGeneratedOutput(runner, bytes.length);
        if (junitBudgetFailure) {
          failures.push(customCodeFailure(junitBudgetFailure, 'phpunit-execution', row.testMethodId, 'Generated JUnit evidence exceeded the shared execution budget.'));
          break;
        }
        junitBytes += bytes.length;
        if (junitBytes > CUSTOM_CODE_EXECUTION_LIMITS.junitBytesTotal) {
          failures.push(customCodeFailure('input_limit_exceeded', 'phpunit-execution', row.testMethodId, 'Aggregate JUnit XML exceeded its verifier limit.'));
          break;
        }
        let parsed;
        try {
          parsed = parsePhpunitJunit(bytes.toString('utf8'));
        } catch {
          failures.push(customCodeFailure('invalid_output', 'phpunit-execution', row.testMethodId, 'PHPUnit JUnit XML is malformed or has missing, negative, or inconsistent suite totals.'));
          break;
        }
        const exactCases = parsed.cases.filter((testcase) =>
          testcase.className === row.className &&
          (testcase.name === row.methodName || testcase.name.startsWith(`${row.methodName} with data set`))
        );
        const unexpectedCases = parsed.cases.length - exactCases.length;
        const assertionCount = exactCases.reduce((total, testcase) => total + testcase.assertions, 0);
        dataCases += exactCases.length;
        let status = 'pass';
        let failureCode = '';
        if (exactCases.length === 0) {
          status = 'blocked';
          failureCode = 'no_tests_executed';
        } else if (unexpectedCases > 0) {
          status = 'blocked';
          failureCode = 'unexpected_test_executed';
        } else if (exactCases.length > CUSTOM_CODE_EXECUTION_LIMITS.dataCasesPerMethod || dataCases > CUSTOM_CODE_EXECUTION_LIMITS.dataCasesTotal) {
          status = 'blocked';
          failureCode = 'input_limit_exceeded';
        } else if (parsed.skipped > 0 || exactCases.some((testcase) => testcase.skipped > 0)) {
          status = 'fail';
          failureCode = 'test_skipped';
        } else if (assertionCount < 1 || parsed.assertions < 1) {
          status = 'fail';
          failureCode = 'no_assertions_executed';
        } else if (
          !result.ok || parsed.failures > 0 || parsed.errors > 0 || parsed.warnings > 0 ||
          exactCases.some((testcase) => testcase.failures > 0 || testcase.errors > 0 || testcase.warnings > 0)
        ) {
          status = 'fail';
          failureCode = 'test_failed';
        }
        runs.push({
          testMethodId: row.testMethodId,
          testFileId: row.testFileId,
          className: row.className,
          methodName: row.methodName,
          status,
          testcaseCount: exactCases.length,
          assertionCount,
          junitSha256: `sha256:${sha256(bytes)}`,
          commandResultHash: result.record.resultSha256
        });
        if (failureCode) {
          failures.push(customCodeFailure(failureCode, 'phpunit-execution', row.testMethodId, 'Focused PHPUnit method did not produce an exact clean passing JUnit result.'));
          if (status === 'blocked') break;
        } else {
          completedTestMethodIds.push(row.testMethodId);
        }
      }
    }
  } catch {
    failures.push(customCodeFailure('spawn_failed', 'phpunit', '', 'Verifier-owned temporary PHPUnit evidence directory could not be created or inspected.'));
  } finally {
    if (tempDirectory) {
      rmSync(tempDirectory, { recursive: true, force: true });
    }
  }
  if (projectFileSha256(projectRoot, phpunitConfig) !== tools.phpunit.configSha256) {
    failures.push(customCodeFailure('stale_test_binding', 'phpunit', phpunitConfig, 'PHPUnit config changed during verifier execution.'));
  }
  const testFailureCodes = new Set(['no_assertions_executed', 'test_failed', 'test_skipped']);
  const blocked = failures.some((failure) => !testFailureCodes.has(failure.code));
  const failed = failures.some((failure) => testFailureCodes.has(failure.code));
  return finalizedCustomCodeRecord({
    schemaVersion: CUSTOM_CODE_TEST_EXECUTION_SCHEMA,
    applies: true,
    completed: !blocked,
    status: blocked ? 'blocked' : failed ? 'fail' : 'pass',
    inputInventoryFingerprint: String(inventory?.fingerprint ?? ''),
    limits: CUSTOM_CODE_EXECUTION_LIMITS,
    tools,
    expectedTestMethodIds,
    completedTestMethodIds: [...new Set(completedTestMethodIds)].sort(comparePortable),
    discovery,
    runs,
    isolation,
    failures
  });
}

function workingCustomCodeSnapshot(projectRoot, inventory) {
  const php = exactInventoryPhpFiles(projectRoot, inventory);
  if (php.failures.length > 0) throw new Error('working custom PHP changed');
  const runtime = collectRuntimeCodeManifest(projectRoot);
  return stateSha256({
    inventoriedPhp: php.files.map((file) => ({ id: file.id, path: file.path, sha256: file.sha256 })),
    runtime
  });
}

export function inspectCustomCodeQuality(projectRoot, environment, inventory, review, options = {}) {
  const phpInventory = exactInventoryPhpFiles(projectRoot, inventory);
  const coverage = coveragePreflight(inventory, review);
  const phpstanConfig = recognizedProjectFile(projectRoot, ['phpstan.neon', 'phpstan.neon.dist', 'phpstan.dist.neon']);
  const needs = {
    phpcs: phpInventory.files.length > 0,
    phpstan: phpInventory.files.length > 0 && Boolean(phpstanConfig),
    phpunit: coverage.applies && coverage.failures.length === 0
  };
  const requirements = phpInventory.files.length > 0
    ? customCodeToolRequirements(projectRoot, needs)
    : { failures: [], packages: {}, snapshot: null };
  const estimatedCommands = phpInventory.files.length === 0 ? 0 : (
    12 + 2 + phpInventory.files.length + 2 + Math.ceil(phpInventory.files.length / CUSTOM_CODE_EXECUTION_LIMITS.phpcsChunkFiles) +
    (phpstanConfig ? 2 : 0)
  ) + (coverage.applies && coverage.failures.length === 0
    ? 1 + coverage.testFileCount + coverage.testMethodCount
    : 0);
  const preflightFailures = [...phpInventory.failures, ...requirements.failures];
  if (estimatedCommands > CUSTOM_CODE_EXECUTION_LIMITS.commands) {
    preflightFailures.push(customCodeFailure('input_limit_exceeded', 'preflight', '', 'Planned custom-code quality commands exceed the shared command limit.'));
  }
  let workingSnapshotBefore = '';
  if (phpInventory.files.length > 0 && preflightFailures.length === 0) {
    try {
      workingSnapshotBefore = workingCustomCodeSnapshot(projectRoot, inventory);
    } catch {
      preflightFailures.push(customCodeFailure('stale_test_binding', 'working-target-snapshot', '', 'The exact working source/runtime snapshot could not be established before custom-code execution.'));
    }
  }

  let activeExecutor = () => ({ ok: false, exitCode: null, stdout: '', stderr: '', spawnError: true, timedOut: false });
  const runner = createCustomCodeExecutionRunner((specification) => activeExecutor(specification), options);
  let qualityAudit = phpInventory.files.length === 0
    ? notApplicableQualityAudit(inventory)
    : blockedQualityAudit(inventory, preflightFailures, phpInventory.files);
  let focusedTestExecution = coverage.applies
    ? blockedFocusedTestExecution(inventory, true, coverage.rows, [...preflightFailures, ...coverage.failures])
    : notApplicableFocusedTestExecution(inventory);
  let isolation = null;

  if (phpInventory.files.length > 0 && preflightFailures.length === 0) {
    const disposableWorkspaceFactory = options.disposableWorkspaceFactory ?? options.executor?.disposableWorkspaceFactory;
    const workspaceResult = disposableWorkspaceFactory
      ? disposableWorkspaceFactory({ environment, inventory, needs, options, projectRoot, requirements, runner })
      : createDisposableCustomCodeWorkspace(projectRoot, inventory, runner, environment, {
          ...options,
          toolNeeds: needs,
          toolRequirements: requirements
        });
    const workspace = workspaceResult?.workspace;
    const workspaceFailures = Array.isArray(workspaceResult?.failures) ? workspaceResult.failures : [];
    let isolationValid = false;
    let provenance = null;
    try {
      try {
        const projectReal = realpathSync(projectRoot);
        const workspaceReal = realpathSync(workspace.projectRoot);
        const auditReal = realpathSync(workspace.auditRoot);
        const runtimeConfigSha256 = projectFileSha256(workspaceReal, '.ddev/config.yaml');
        provenance = customCodeToolchainProvenance(auditReal, needs, requirements);
        isolationValid = Boolean(
          workspace && workspaceReal !== projectReal && pathIsInside(workspaceReal, auditReal) && auditReal !== workspaceReal &&
          workspace.exactHead === true && workspace.freshDatabase === true &&
          typeof workspace.executor === 'function' &&
          /^sha256:[a-f0-9]{64}$/.test(String(workspace?.runtimeProvenance?.specSha256 ?? '')) &&
          /^sha256:[a-f0-9]{64}$/.test(String(workspace?.runtimeProvenance?.ddevTreeFingerprint ?? '')) &&
          runtimeConfigSha256 === workspace?.runtimeProvenance?.configSha256 &&
          provenance.failures.length === 0 && exactInventoryPhpFiles(workspaceReal, inventory).failures.length === 0 &&
          (!coverage.applies || parseHttpUrl(workspace.baseUrl, 'Disposable PHPUnit base URL').origin !== parseHttpUrl(options.baseUrl ?? '', 'Working target base URL').origin)
        );
      } catch {
        isolationValid = false;
      }
      if (!isolationValid || workspaceFailures.length > 0) {
        const failures = [
          ...workspaceFailures,
          ...(!isolationValid ? [customCodeFailure('stale_test_binding', 'custom-code-isolation', '', 'Custom-code commands require an exact-HEAD disposable DDEV project, fresh dependency installs, fresh database, and verifier audit vendor.')] : [])
        ];
        qualityAudit = blockedQualityAudit(inventory, failures, phpInventory.files);
        if (coverage.applies) focusedTestExecution = blockedFocusedTestExecution(inventory, true, coverage.rows, [...failures, ...coverage.failures]);
      } else {
        activeExecutor = workspace.executor;
        isolation = {
          schemaVersion: 'public-kit.disposable-custom-code-workspace.1',
          status: 'active',
          workspaceId: String(workspace.identity?.workspaceId ?? ''),
          head: String(workspace.identity?.head ?? ''),
          projectNameSha256: `sha256:${sha256(String(workspace.identity?.projectName ?? ''))}`,
          exactHead: true,
          freshDatabase: true,
          executionBoundary: 'exact-head-disposable-ddev',
          auditVendor: 'fresh-composer-install',
          runtimeOwner: 'verifier-generated-minimal-ddev-config',
          runtimeConfigSha256: workspace.runtimeProvenance.configSha256,
          runtimeDdevTreeSha256: workspace.runtimeProvenance.ddevTreeFingerprint,
          runtimeSpecSha256: workspace.runtimeProvenance.specSha256,
          workingTargetSnapshotBeforeSha256: workingSnapshotBefore,
          workingTargetSnapshotAfterSha256: '',
          setupCommandResultHashes: [...(workspace.setupCommandResultHashes ?? [])]
        };
        qualityAudit = runCustomCodeQualityAudit(
          workspace.projectRoot, inventory, phpInventory.files, runner, provenance, workspace.auditRoot
        );
        focusedTestExecution = coverage.failures.length > 0
          ? blockedFocusedTestExecution(inventory, true, coverage.rows, coverage.failures)
          : coverage.applies
            ? runFocusedCustomCodeTests(
                workspace.projectRoot,
                inventory,
                coverage,
                runner,
                workspace.baseUrl,
                provenance,
                workspace.auditRoot,
                workspace.executor,
                isolation
              )
            : notApplicableFocusedTestExecution(inventory);
        const disposablePostflightFailures = exactInventoryPhpFiles(workspace.projectRoot, inventory).failures;
        if (!exactToolRequirementsMatch(workspace.projectRoot, needs, requirements)) {
          disposablePostflightFailures.push(customCodeFailure('stale_test_binding', 'custom-code-isolation', isolation.workspaceId, 'Disposable project Composer inputs changed during custom-code execution.'));
        }
        if (projectFileSha256(workspace.projectRoot, '.ddev/config.yaml') !== isolation.runtimeConfigSha256) {
          disposablePostflightFailures.push(customCodeFailure('stale_test_binding', 'custom-code-isolation', isolation.workspaceId, 'Verifier-owned disposable DDEV runtime configuration changed during custom-code execution.'));
        }
        if (customCodeToolchainChanged(workspace.auditRoot, provenance, needs, requirements)) {
          disposablePostflightFailures.push(customCodeFailure('stale_test_binding', 'tool-provenance', isolation.workspaceId, 'Fresh verifier audit package metadata or package trees changed during custom-code execution.'));
        }
        if (disposablePostflightFailures.length > 0) {
          qualityAudit = finalizedCustomCodeRecord({
            ...qualityAudit,
            completed: false,
            status: 'blocked',
            failures: [...(qualityAudit.failures ?? []), ...disposablePostflightFailures]
          });
          if (coverage.applies) {
            focusedTestExecution = finalizedCustomCodeRecord({
              ...focusedTestExecution,
              completed: false,
              status: 'blocked',
              failures: [
                ...(focusedTestExecution.failures ?? []),
                ...disposablePostflightFailures
              ]
            });
          }
        }
      }
    } catch {
      const executionFailure = customCodeFailure(
        'spawn_failed',
        'custom-code-isolation',
        workspace?.identity?.workspaceId ?? '',
        'Disposable custom-code verification failed safely.'
      );
      qualityAudit = finalizedCustomCodeRecord({
        ...qualityAudit,
        completed: false,
        status: 'blocked',
        failures: [...(qualityAudit.failures ?? []), executionFailure]
      });
      if (coverage.applies) focusedTestExecution = finalizedCustomCodeRecord({
        ...focusedTestExecution,
        completed: false,
        status: 'blocked',
        failures: [...(focusedTestExecution.failures ?? []), executionFailure]
      });
    } finally {
      // A factory may return a workspace whose identity or provenance fails closed.
      // It is still verifier-owned state and must be cleaned exactly once.
      if (workspace !== null && workspace !== undefined) {
        let cleanup;
        try {
          cleanup = typeof workspace.cleanup === 'function'
            ? workspace.cleanup(runner)
            : cleanupDisposableCustomCodeWorkspace(workspace, runner);
        } catch {
          cleanup = { completed: false, commandResultHashes: [], failures: [] };
        }
        const cleanupFailures = Array.isArray(cleanup?.failures) ? cleanup.failures : [];
        const workspaceId = String(isolation?.workspaceId ?? workspace?.identity?.workspaceId ?? '');
        if (isolation) {
          isolation = {
            ...isolation,
            status: cleanup?.completed === true ? 'cleaned' : 'cleanup_blocked',
            cleanupCommandResultHashes: [...(cleanup?.commandResultHashes ?? [])]
          };
        }
        if (cleanupFailures.length > 0 || cleanup?.completed !== true) {
          const failures = [
            ...cleanupFailures,
            ...(cleanupFailures.length === 0
              ? [customCodeFailure('spawn_failed', 'phpunit-isolation-cleanup', workspaceId, 'Disposable DDEV cleanup did not complete.')]
              : [])
          ];
          qualityAudit = finalizedCustomCodeRecord({
            ...qualityAudit,
            completed: false,
            status: 'blocked',
            failures: [...(qualityAudit.failures ?? []), ...failures]
          });
          if (coverage.applies) focusedTestExecution = finalizedCustomCodeRecord({
            ...focusedTestExecution,
            completed: false,
            status: 'blocked',
            failures: [...(focusedTestExecution.failures ?? []), ...failures]
          });
        }
      }
    }
  }

  if (phpInventory.files.length > 0 && workingSnapshotBefore) {
    const postflightFailures = [];
    let workingSnapshotAfter = '';
    try {
      workingSnapshotAfter = workingCustomCodeSnapshot(projectRoot, inventory);
    } catch {
      // The generic measured-snapshot failure below is sufficient and does not expose a changed path.
    }
    if (!workingSnapshotAfter || workingSnapshotAfter !== workingSnapshotBefore) {
      postflightFailures.push(customCodeFailure('stale_test_binding', 'working-target-snapshot', '', 'The exact working source/runtime snapshot changed during disposable custom-code execution.'));
    }
    if (runner.budget.now() - runner.budget.startedAt > runner.budget.deadlineMs) {
      postflightFailures.push(customCodeFailure('aggregate_deadline_exceeded', 'postflight', '', 'Custom-code execution exceeded the shared wall-clock deadline.'));
    }
    if (postflightFailures.length > 0) {
      qualityAudit = finalizedCustomCodeRecord({
        ...qualityAudit,
        completed: false,
        status: 'blocked',
        failures: [...(qualityAudit.failures ?? []), ...postflightFailures]
      });
      if (coverage.applies) focusedTestExecution = finalizedCustomCodeRecord({
        ...focusedTestExecution,
        completed: false,
        status: 'blocked',
        failures: [...(focusedTestExecution.failures ?? []), ...postflightFailures]
      });
    }
    if (isolation) isolation = {
      ...isolation,
      workingTargetSnapshotAfterSha256: workingSnapshotAfter
    };
  }
  const executionBudget = {
    commandsExecuted: runner.budget.commandCount,
    outputBytes: runner.budget.outputBytes,
    commandLimit: runner.budget.commandLimit,
    outputLimit: runner.budget.outputLimit,
    deadlineMs: runner.budget.deadlineMs,
    cleanupReserveMs: runner.budget.cleanupReserveMs,
    cleanupCommandReserve: runner.budget.cleanupCommandReserve
  };
  qualityAudit = finalizedCustomCodeRecord({ ...qualityAudit, ...(isolation ? { isolation } : {}), executionBudget });
  focusedTestExecution = finalizedCustomCodeRecord({
    ...focusedTestExecution,
    ...(coverage.applies && isolation ? { isolation } : {}),
    executionBudget
  });
  return { qualityAudit, focusedTestExecution, executionBudget };
}

export function inspectCustomCode(projectRoot, environment, review = {}, options = {}) {
  const filesystem = inspectCustomCodeFilesystem(projectRoot);
  const reviewRecord = Array.isArray(review) ? { routeBindings: review, capabilities: [], testCoverage: [] } : (review ?? {});
  const routeBindings = Array.isArray(reviewRecord?.routeBindings) ? reviewRecord.routeBindings : [];
  const routeAudit = filesystem.completed
    ? inspectCustomRouteRuntime(projectRoot, environment, filesystem.routes, filesystem.extensions, routeBindings)
    : { completed: false, error: 'Filesystem custom-code inventory did not complete.', routes: [], violations: [] };
  const configSchema = filesystem.completed
    ? inspectCustomConfigSchema(projectRoot, environment, filesystem.extensions)
    : { completed: false, error: 'Filesystem custom-code inventory did not complete.', extensions: [], violations: [] };
  const errors = [...filesystem.errors];
  if (!routeAudit.completed) {
    errors.push(routeAudit.error || 'Live custom-route audit did not complete.');
  }
  if (routeAudit.violations.length > 0) {
    errors.push(`Live custom-route audit found ${routeAudit.violations.length} violation(s).`);
  }
  if (!configSchema.completed) {
    errors.push(configSchema.error || 'Live custom config-schema audit did not complete.');
  }
  if (configSchema.violations.length > 0) {
    errors.push(`Live custom config-schema audit found ${configSchema.violations.length} violation(s).`);
  }
  const fingerprintInput = {
    extensions: filesystem.extensions,
    sourceFiles: filesystem.sourceFiles,
    controllers: filesystem.controllers,
    routes: filesystem.routes,
    tests: filesystem.tests,
    routeAudit,
    configSchema
  };
  const phaseAFingerprint = `sha256:${sha256(JSON.stringify(fingerprintInput))}`;
  const phaseAInventory = { ...filesystem, routeAudit, configSchema, fingerprint: phaseAFingerprint };
  const { qualityAudit, focusedTestExecution, executionBudget } = filesystem.completed
    ? inspectCustomCodeQuality(projectRoot, environment, phaseAInventory, reviewRecord, options)
    : {
        qualityAudit: blockedQualityAudit(phaseAInventory, [customCodeFailure('stale_test_binding', 'preflight', '', 'Filesystem custom-code inventory did not complete.')]),
        focusedTestExecution: blockedFocusedTestExecution(phaseAInventory, false, [], [customCodeFailure('stale_test_binding', 'preflight', '', 'Filesystem custom-code inventory did not complete.')]),
        executionBudget: {
          commandsExecuted: 0,
          outputBytes: 0,
          commandLimit: CUSTOM_CODE_EXECUTION_LIMITS.commands,
          outputLimit: CUSTOM_CODE_EXECUTION_LIMITS.aggregateOutputBytes,
          deadlineMs: CUSTOM_CODE_EXECUTION_LIMITS.aggregateDeadlineMs,
          cleanupReserveMs: CUSTOM_CODE_EXECUTION_LIMITS.cleanupReserveMs,
          cleanupCommandReserve: 2
        }
      };
  if (!['pass', 'not_applicable'].includes(qualityAudit.status)) {
    errors.push(`Verifier-owned custom-code quality audit status is ${qualityAudit.status}.`);
  }
  if (!['pass', 'not_applicable'].includes(focusedTestExecution.status)) {
    errors.push(`Verifier-owned focused custom-code test execution status is ${focusedTestExecution.status}.`);
  }
  return {
    ...filesystem,
    completed: filesystem.completed && routeAudit.completed && configSchema.completed &&
      ['pass', 'not_applicable'].includes(qualityAudit.status) &&
      ['pass', 'not_applicable'].includes(focusedTestExecution.status) && errors.length === 0,
    errors,
    routeAudit,
    configSchema,
    qualityAudit,
    focusedTestExecution,
    executionBudget,
    fingerprint: phaseAFingerprint
  };
}

function redactedCustomCodeFindings(findings, knownFileIds) {
  if (!Array.isArray(findings) || findings.length > CUSTOM_CODE_EXECUTION_LIMITS.findingsPerCheck) return false;
  return findings.every((finding) =>
    plainJsonObject(finding) && !Object.hasOwn(finding, 'message') && !Object.hasOwn(finding, 'path') &&
    (String(finding.fileId ?? '') === '' || knownFileIds.has(String(finding.fileId))) &&
    finiteNonnegativeInteger(finding.line ?? 0) &&
    (!Object.hasOwn(finding, 'column') || finiteNonnegativeInteger(finding.column)) &&
    (!Object.hasOwn(finding, 'severity') || finiteNonnegativeInteger(finding.severity)) &&
    typeof finding.ruleId === 'string' && finding.ruleId.length <= 200 &&
    (!Object.hasOwn(finding, 'messageSha256') || /^sha256:[a-f0-9]{64}$/.test(String(finding.messageSha256)))
  );
}

function trustedComposerProvenance(value, expectedPackages) {
  if (
    !plainJsonObject(value) || !/^sha256:[a-f0-9]{64}$/.test(String(value.composerJsonSha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.composerLockSha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.sourceComposerLockSha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.installedMetadataSha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.closureIdentitySha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.closurePackageTreeSha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.autoloadTreeSha256 ?? '')) ||
    !/^sha256:[a-f0-9]{64}$/.test(String(value.rootAutoloadSha256 ?? '')) ||
    !finiteNonnegativeInteger(value.closurePackageCount) || value.closurePackageCount < expectedPackages.length ||
    value.closurePackageCount > CUSTOM_CODE_EXECUTION_LIMITS.composerPackages ||
    !finiteNonnegativeInteger(value.closurePackageBytes) || value.closurePackageBytes > CUSTOM_CODE_EXECUTION_LIMITS.composerPackageBytesTotal ||
    !finiteNonnegativeInteger(value.closurePackageFiles) || value.closurePackageFiles > CUSTOM_CODE_EXECUTION_LIMITS.composerPackageFilesTotal ||
    !finiteNonnegativeInteger(value.autoloadTreeBytes) || value.autoloadTreeBytes > CUSTOM_CODE_EXECUTION_LIMITS.packageBytes ||
    !finiteNonnegativeInteger(value.autoloadTreeFiles) || value.autoloadTreeFiles > CUSTOM_CODE_EXECUTION_LIMITS.packageFiles ||
    !finiteNonnegativeInteger(value.rootAutoloadBytes) || value.rootAutoloadBytes < 1 ||
    value.rootAutoloadBytes > CUSTOM_CODE_EXECUTION_LIMITS.composerMetadataBytes ||
    !Array.isArray(value.packages) || value.packages.length !== expectedPackages.length
  ) return false;
  const byName = new Map(value.packages.map((entry) => [String(entry?.name ?? ''), entry]));
  return expectedPackages.every((name) => {
    const entry = byName.get(name);
    const expectedPath = `vendor/${name}`;
    return plainJsonObject(entry) && entry.packagePath === expectedPath &&
      typeof entry.version === 'string' && entry.version.length > 0 && entry.version.length <= 200 &&
      /^[a-f0-9]{7,64}$/i.test(String(entry.reference ?? '')) &&
      /^sha256:[a-f0-9]{64}$/.test(String(entry.distUrlSha256 ?? '')) &&
      (name === CUSTOM_CODE_COMPOSER_PACKAGES.phpstan.name
        ? String(entry.sourceUrlSha256 ?? '') === '' || /^sha256:[a-f0-9]{64}$/.test(String(entry.sourceUrlSha256))
        : /^sha256:[a-f0-9]{64}$/.test(String(entry.sourceUrlSha256 ?? ''))) &&
      /^sha256:[a-f0-9]{64}$/.test(String(entry?.packageTree?.sha256 ?? '')) &&
      finiteNonnegativeInteger(entry?.packageTree?.files) && finiteNonnegativeInteger(entry?.packageTree?.bytes) &&
      (!entry.binary || (entry.binary.startsWith(`${expectedPath}/`) && !entry.binary.includes('/vendor/bin/')));
  });
}

function trustedCustomCodeIsolation(isolation) {
  return plainJsonObject(isolation) &&
    isolation.schemaVersion === 'public-kit.disposable-custom-code-workspace.1' && isolation.status === 'cleaned' &&
    isolation.exactHead === true && isolation.freshDatabase === true &&
    isolation.executionBoundary === 'exact-head-disposable-ddev' && isolation.auditVendor === 'fresh-composer-install' &&
    isolation.runtimeOwner === 'verifier-generated-minimal-ddev-config' &&
    /^sha256:[a-f0-9]{64}$/.test(String(isolation.runtimeConfigSha256 ?? '')) &&
    /^sha256:[a-f0-9]{64}$/.test(String(isolation.runtimeDdevTreeSha256 ?? '')) &&
    /^sha256:[a-f0-9]{64}$/.test(String(isolation.runtimeSpecSha256 ?? '')) &&
    /^DISPOSABLE-[A-Za-z0-9._-]+$/.test(String(isolation.workspaceId ?? '')) &&
    /^[a-f0-9]{40,64}$/i.test(String(isolation.head ?? '')) &&
    /^sha256:[a-f0-9]{64}$/.test(String(isolation.projectNameSha256 ?? '')) &&
    /^sha256:[a-f0-9]{64}$/.test(String(isolation.workingTargetSnapshotBeforeSha256 ?? '')) &&
    isolation.workingTargetSnapshotAfterSha256 === isolation.workingTargetSnapshotBeforeSha256 &&
    Array.isArray(isolation.setupCommandResultHashes) && isolation.setupCommandResultHashes.length > 0 &&
    isolation.setupCommandResultHashes.every((hash) => /^sha256:[a-f0-9]{64}$/.test(String(hash))) &&
    Array.isArray(isolation.cleanupCommandResultHashes) && isolation.cleanupCommandResultHashes.length >= 2 &&
    isolation.cleanupCommandResultHashes.every((hash) => /^sha256:[a-f0-9]{64}$/.test(String(hash)));
}

export function customCodeReconciliationErrors(runtimeInventory, review, packetDir = '') {
  const errors = [];
  const push = (message) => {
    if (errors.length < 200) {
      errors.push(message);
    } else if (errors.length === 200) {
      errors.push('Custom-code reconciliation produced more than 200 errors; remaining errors were bounded.');
    }
  };
  if (runtimeInventory?.completed !== true) {
    push(runtimeInventory?.errors?.[0] || 'Verifier-owned custom-code inventory did not complete.');
    return errors;
  }
  if (runtimeInventory.schemaVersion !== CUSTOM_CODE_SCHEMA) {
    push(`Verifier-owned custom-code inventory must use schemaVersion ${CUSTOM_CODE_SCHEMA}.`);
  }
  if (!review || typeof review !== 'object' || Array.isArray(review)) {
    push('drupal-readback.json implementationQuality.customCodeInventory must be an object.');
    return errors;
  }
  if (review.schemaVersion !== CUSTOM_CODE_REVIEW_SCHEMA) {
    push(`Custom-code review must use schemaVersion ${CUSTOM_CODE_REVIEW_SCHEMA}.`);
  }
  if (review.inventoryComplete !== true || !Array.isArray(review.blockers) || review.blockers.length > 0) {
    push('Custom-code review must be complete with an explicit empty blockers array.');
  }
  if (!Array.isArray(review.capabilities) || !Array.isArray(review.routeBindings) || !Array.isArray(review.testCoverage)) {
    push('Custom-code review capabilities, routeBindings, and testCoverage must be explicit arrays.');
  }
  if (review.applies !== (runtimeInventory.extensions.length > 0)) {
    push('Custom-code review applicability does not match the current custom extension inventory.');
  }
  if (
    (runtimeInventory.extensions.length > 0 || String(review.runtimeFingerprint ?? '')) &&
    String(review.runtimeFingerprint ?? '') !== String(runtimeInventory.fingerprint ?? '')
  ) {
    push('Custom-code review runtimeFingerprint does not match the current verifier-owned inventory.');
  }
  if (runtimeInventory.configSchema?.completed !== true) {
    push('Verifier-owned custom config-schema validation did not complete.');
  }
  for (const violation of Array.isArray(runtimeInventory.configSchema?.violations)
    ? runtimeInventory.configSchema.violations
    : []) {
    push(`Custom config schema violation for ${violation?.extension || '(unknown extension)'} ${violation?.configName || '(unknown config)'}: ${violation?.reason || 'invalid schema'}.`);
  }
  if (runtimeInventory.routeAudit?.completed !== true) {
    push('Verifier-owned custom-route runtime audit did not complete.');
  }
  for (const violation of Array.isArray(runtimeInventory.routeAudit?.violations)
    ? runtimeInventory.routeAudit.violations
    : []) {
    push(`Custom route ${violation?.name || '(unknown route)'} failed runtime audit: ${violation?.reason || 'unknown violation'}.`);
  }

  const runtimePhpFileIds = [
    ...runtimeInventory.sourceFiles
      .filter((source) => ['procedural_php', 'php_class'].includes(source?.kind))
      .map((source) => String(source?.id ?? '')),
    ...(Array.isArray(runtimeInventory.tests) ? runtimeInventory.tests : [])
      .filter((test) => /\.php$/i.test(String(test?.path ?? '')))
      .map((test) => String(test?.id ?? ''))
  ].filter(Boolean).sort(comparePortable);
  const qualityAudit = runtimeInventory?.qualityAudit;
  const runtimePhpFileIdSet = new Set(runtimePhpFileIds);
  if (!qualityAudit || qualityAudit.schemaVersion !== CUSTOM_CODE_QUALITY_SCHEMA) {
    push(`Verifier-owned custom-code quality audit must use schemaVersion ${CUSTOM_CODE_QUALITY_SCHEMA}.`);
  } else {
    if (qualityAudit.inputInventoryFingerprint !== runtimeInventory.fingerprint) {
      push('Verifier-owned custom-code quality audit is not bound to the current phase-A inventory fingerprint.');
    }
    if (qualityAudit.resultFingerprint !== customCodeResultFingerprint(qualityAudit)) {
      push('Verifier-owned custom-code quality audit result fingerprint is invalid.');
    }
    if (
      Number(qualityAudit?.executionBudget?.commandsExecuted) > CUSTOM_CODE_EXECUTION_LIMITS.commands ||
      Number(qualityAudit?.executionBudget?.outputBytes) > CUSTOM_CODE_EXECUTION_LIMITS.aggregateOutputBytes ||
      Number(qualityAudit?.executionBudget?.deadlineMs) !== CUSTOM_CODE_EXECUTION_LIMITS.aggregateDeadlineMs ||
      Number(qualityAudit?.executionBudget?.cleanupReserveMs) !== CUSTOM_CODE_EXECUTION_LIMITS.cleanupReserveMs ||
      Number(qualityAudit?.executionBudget?.cleanupCommandReserve) !== 2
    ) {
      push('Verifier-owned custom-code quality audit exceeded or misstated the shared execution budget.');
    }
    const expectedStatus = runtimePhpFileIds.length > 0 ? 'pass' : 'not_applicable';
    if (qualityAudit.applies !== (runtimePhpFileIds.length > 0) || qualityAudit.completed !== true || qualityAudit.status !== expectedStatus) {
      push(`Verifier-owned custom-code quality audit must complete with status ${expectedStatus}.`);
    }
    for (const checkName of ['phpSyntax', 'phpcs']) {
      const check = qualityAudit?.checks?.[checkName];
      if (runtimePhpFileIds.length > 0 && (
        check?.status !== 'pass' ||
        JSON.stringify([...(check?.expectedFileIds ?? [])].sort(comparePortable)) !== JSON.stringify(runtimePhpFileIds) ||
        JSON.stringify([...(check?.completedFileIds ?? [])].sort(comparePortable)) !== JSON.stringify(runtimePhpFileIds)
      )) {
        push(`Verifier-owned ${checkName} quality check did not pass every exact inventoried PHP file.`);
      }
      if (!redactedCustomCodeFindings(check?.findings, runtimePhpFileIdSet)) {
        push(`Verifier-owned ${checkName} findings must contain only bounded redacted rule/location/digest data.`);
      }
    }
    if (runtimePhpFileIds.length > 0 && !trustedComposerProvenance(
      qualityAudit?.tools?.phpcs?.provenance,
      [
        CUSTOM_CODE_COMPOSER_PACKAGES.phpcs.name,
        CUSTOM_CODE_COMPOSER_PACKAGES.coder.name,
        CUSTOM_CODE_COMPOSER_PACKAGES.slevomat.name,
        CUSTOM_CODE_COMPOSER_PACKAGES.variableAnalysis.name
      ]
    )) {
      push('Verifier-owned PHPCS result lacks exact canonical Composer package provenance.');
    }
    if (runtimePhpFileIds.length > 0) {
      if (!trustedCustomCodeIsolation(qualityAudit?.isolation)) {
        push('Verifier-owned custom-code analyzers lack measured working-target snapshots and cleaned exact-HEAD disposable DDEV/audit-vendor isolation evidence.');
      }
      const phpstanCheck = qualityAudit?.checks?.phpstan;
      const phpstanTool = qualityAudit?.tools?.phpstan;
      if (!['pass', 'not_supported'].includes(phpstanCheck?.status)) {
        push('Verifier-owned PHPStan check must pass or explicitly report not_supported when no recognized config exists.');
      } else if (phpstanCheck.status === 'pass' && (
        phpstanTool?.status !== 'pass' ||
        !trustedComposerProvenance(phpstanTool?.provenance, [CUSTOM_CODE_COMPOSER_PACKAGES.phpstan.name]) ||
        !String(phpstanTool?.config ?? '') ||
        !/^sha256:[a-f0-9]{64}$/.test(String(phpstanTool?.configSha256 ?? '')) ||
        JSON.stringify([...(phpstanCheck?.expectedFileIds ?? [])].sort(comparePortable)) !== JSON.stringify(runtimePhpFileIds) ||
        JSON.stringify([...(phpstanCheck?.requestedFileIds ?? [])].sort(comparePortable)) !== JSON.stringify(runtimePhpFileIds) ||
        !Array.isArray(phpstanCheck?.reportedFileIds) ||
        new Set(phpstanCheck.reportedFileIds).size !== phpstanCheck.reportedFileIds.length ||
        phpstanCheck.reportedFileIds.some((id) => !runtimePhpFileIdSet.has(String(id)))
      )) {
        push('Verifier-owned PHPStan pass did not bind its recognized config, exact requested PHP-file argv, and bounded error-bearing file report.');
      } else if (phpstanCheck.status === 'not_supported' && (
        phpstanTool?.status !== 'not_supported' ||
        String(phpstanTool?.config ?? '') !== '' ||
        String(phpstanTool?.configSha256 ?? '') !== '' ||
        (phpstanCheck?.requestedFileIds ?? []).length !== 0 ||
        (phpstanCheck?.reportedFileIds ?? []).length !== 0
      )) {
        push('Verifier-owned PHPStan not_supported status contradicts a recognized config/tool record.');
      }
      if (!redactedCustomCodeFindings(phpstanCheck?.findings, runtimePhpFileIdSet)) {
        push('Verifier-owned PHPStan findings must contain only bounded redacted rule/location/digest data.');
      }
    }
  }

  const runtimeExtensions = new Set(runtimeInventory.extensions.map((extension) => extension.machineName));
  const runtimeSurfaces = new Map(
    runtimeInventory.sourceFiles.flatMap((source) => source.surfaces.map((surface) => [surface.id, {
      ...surface,
      extension: source.extension,
      path: source.path,
      sourceFileId: source.id
    }]))
  );
  const executableSurfaceIds = new Set(
    [...runtimeSurfaces]
      .filter(([, surface]) => EXECUTABLE_CUSTOM_SURFACE_KINDS.has(surface.kind))
      .map(([surfaceId]) => surfaceId)
  );
  const capabilities = Array.isArray(review.capabilities) ? review.capabilities : [];
  const capabilityIds = new Set();
  const acceptanceCriterionIds = new Set();
  const focusedTestAcceptanceCriterionIds = new Set();
  const boundSurfaces = new Map();
  const capabilityExtensions = new Set();
  for (const [index, capability] of capabilities.entries()) {
    const extension = String(capability?.extension ?? '').trim();
    const capabilityKey = String(capability?.capabilityKey ?? '').trim();
    const capabilityId = String(capability?.capabilityId ?? '').trim();
    const surfaceIds = Array.isArray(capability?.sourceSurfaceIds) ? capability.sourceSurfaceIds : [];
    const requiresFocusedTests = capabilityRequiresFocusedTests(capability, executableSurfaceIds);
    if (!runtimeExtensions.has(extension)) {
      push(`Custom capability ${capabilityId || `(row ${index})`} names unknown extension ${extension || '(missing)'}.`);
    } else {
      capabilityExtensions.add(extension);
    }
    if (!/^[a-z][a-z0-9_]*$/.test(capabilityKey) || capabilityId !== customCapabilityId(extension, capabilityKey)) {
      push(`Custom capability ${capabilityId || `(row ${index})`} must use the stable verifier-derived ID for its extension and capabilityKey.`);
    }
    if (!capabilityId || capabilityIds.has(capabilityId)) {
      push(`Custom capability row ${index} has a missing or duplicate capabilityId.`);
    }
    capabilityIds.add(capabilityId);
    if (
      !String(capability?.need ?? '').trim() ||
      !String(capability?.responsibility ?? '').trim() ||
      typeof capability?.loadBearing !== 'boolean'
    ) {
      push(`Custom capability ${capabilityId || `(row ${index})`} needs a bounded need, responsibility, and loadBearing boolean.`);
    }
    const acceptanceCriteria = Array.isArray(capability?.acceptanceCriteria) ? capability.acceptanceCriteria : [];
    const criterionIds = acceptanceCriteria.map((criterion) => String(criterion?.id ?? '').trim());
    if (
      acceptanceCriteria.length === 0 ||
      criterionIds.some((id) => !/^AC-[A-Z0-9][A-Z0-9._-]*$/.test(id)) ||
      new Set(criterionIds).size !== criterionIds.length ||
      criterionIds.some((id) => acceptanceCriterionIds.has(id)) ||
      acceptanceCriteria.some((criterion) => !String(criterion?.criterion ?? '').trim())
    ) {
      push(`Custom capability ${capabilityId || `(row ${index})`} needs unique stable AC- acceptance criteria.`);
    }
    for (const id of criterionIds) {
      acceptanceCriterionIds.add(id);
      if (requiresFocusedTests) {
        focusedTestAcceptanceCriterionIds.add(id);
      }
    }
    const ladder = Array.isArray(capability?.solutionLadder) ? capability.solutionLadder : [];
    if (
      ladder.length !== CUSTOM_SOLUTION_LADDER_STAGES.length ||
      ladder.some((stage, stageIndex) => stage?.stage !== CUSTOM_SOLUTION_LADDER_STAGES[stageIndex])
    ) {
      push(`Custom capability ${capabilityId || `(row ${index})`} must record the five native-first solution-ladder stages in order.`);
    } else {
      for (const stage of ladder) {
        const evidence = Array.isArray(stage?.evidence) ? stage.evidence : [];
        const allowedDecisions = stage.stage === 'custom_exception'
          ? new Set(['accepted'])
          : new Set(['rejected', 'no_candidate']);
        if (
          stage.checked !== true ||
          !allowedDecisions.has(stage.decision) ||
          !String(stage.rationale ?? '').trim() ||
          evidence.length === 0 ||
          evidence.some((reference) => !String(reference ?? '').trim()) ||
          (packetDir && evidence.some((reference) => !nonEmptyPacketFile(packetDir, reference, { requireFragment: true })))
        ) {
          push(`Custom capability ${capabilityId || `(row ${index})`} has an incomplete ${stage.stage} solution-ladder record or a missing packet-local file#fragment reference.`);
        }
      }
    }
    if (surfaceIds.length === 0 || new Set(surfaceIds).size !== surfaceIds.length) {
      push(`Custom capability ${capabilityId || `(row ${index})`} must bind one or more unique sourceSurfaceIds.`);
    }
    for (const surfaceId of surfaceIds) {
      const runtimeSurface = runtimeSurfaces.get(String(surfaceId));
      if (!runtimeSurface) {
        push(`Custom capability ${capabilityId || `(row ${index})`} binds unknown source surface ${surfaceId}.`);
        continue;
      }
      if (runtimeSurface.extension !== extension) {
        push(`Custom capability ${capabilityId || `(row ${index})`} binds ${surfaceId} from extension ${runtimeSurface.extension}.`);
      }
      if (boundSurfaces.has(surfaceId)) {
        push(`Custom source surface ${surfaceId} is bound by more than one capability.`);
      }
      boundSurfaces.set(surfaceId, capabilityId);
    }
  }
  for (const [surfaceId, surface] of runtimeSurfaces) {
    if (!boundSurfaces.has(surfaceId)) {
      push(`Custom source surface ${surfaceId} (${surface.path}) is not bound to a capability.`);
    }
  }
  for (const extension of runtimeExtensions) {
    if (!capabilityExtensions.has(extension)) {
      push(`Custom extension ${extension} has no capability record.`);
    }
  }

  const coverage = coveragePreflight(runtimeInventory, review);
  for (const failure of coverage.failures) {
    push(`Custom-code focused test coverage ${failure.code}: ${failure.subjectId || '(unbound)'} ${failure.message}`.trim());
  }
  if (coverage.applies !== (focusedTestAcceptanceCriterionIds.size > 0)) {
    push('Custom-code focused test coverage applicability does not match the load-bearing or executable-surface capability AC inventory.');
  }
  const focusedTestExecution = runtimeInventory?.focusedTestExecution;
  if (!focusedTestExecution || focusedTestExecution.schemaVersion !== CUSTOM_CODE_TEST_EXECUTION_SCHEMA) {
    push(`Verifier-owned focused test execution must use schemaVersion ${CUSTOM_CODE_TEST_EXECUTION_SCHEMA}.`);
  } else {
    if (focusedTestExecution.inputInventoryFingerprint !== runtimeInventory.fingerprint) {
      push('Verifier-owned focused test execution is not bound to the current phase-A inventory fingerprint.');
    }
    if (focusedTestExecution.resultFingerprint !== customCodeResultFingerprint(focusedTestExecution)) {
      push('Verifier-owned focused test execution result fingerprint is invalid.');
    }
    if (JSON.stringify(focusedTestExecution.executionBudget ?? null) !== JSON.stringify(qualityAudit?.executionBudget ?? null)) {
      push('Verifier-owned quality and focused-test records do not share one execution-budget result.');
    }
    const expectedStatus = coverage.applies ? 'pass' : 'not_applicable';
    if (focusedTestExecution.applies !== coverage.applies || focusedTestExecution.completed !== true || focusedTestExecution.status !== expectedStatus) {
      push(`Verifier-owned focused test execution must complete with status ${expectedStatus}.`);
    }
    if (coverage.applies && (
      focusedTestExecution?.tools?.phpunit?.status !== 'pass' ||
      !trustedComposerProvenance(focusedTestExecution?.tools?.phpunit?.provenance, [CUSTOM_CODE_COMPOSER_PACKAGES.phpunit.name]) ||
      !String(focusedTestExecution?.tools?.phpunit?.config ?? '') ||
      !/^sha256:[a-f0-9]{64}$/.test(String(focusedTestExecution?.tools?.phpunit?.configSha256 ?? '')) ||
      !['mysql', 'postgres'].includes(focusedTestExecution?.tools?.ddevDatabaseFamily?.family)
    )) {
      push('Verifier-owned focused test execution lacks a recognized PHPUnit config/tool or verified DDEV database family.');
    }
    const isolation = focusedTestExecution?.isolation;
    if (coverage.applies && !trustedCustomCodeIsolation(isolation)) {
      push('Verifier-owned focused tests lack cleaned exact-HEAD disposable DDEV project/database isolation evidence.');
    }
    const expectedMethodIds = [...new Set(coverage.rows.map((row) => row.testMethodId))].sort(comparePortable);
    const recordedExpected = [...(Array.isArray(focusedTestExecution.expectedTestMethodIds) ? focusedTestExecution.expectedTestMethodIds : [])].sort(comparePortable);
    const recordedCompleted = [...(Array.isArray(focusedTestExecution.completedTestMethodIds) ? focusedTestExecution.completedTestMethodIds : [])].sort(comparePortable);
    if (
      JSON.stringify(recordedExpected) !== JSON.stringify(expectedMethodIds) ||
      (coverage.applies && JSON.stringify(recordedCompleted) !== JSON.stringify(expectedMethodIds))
    ) {
      push('Verifier-owned focused test execution did not bind and complete the exact expected TESTMETHOD IDs.');
    }
    if (coverage.applies) {
      const passingRuns = (Array.isArray(focusedTestExecution.runs) ? focusedTestExecution.runs : [])
        .filter((run) =>
          run?.status === 'pass' &&
          Number.isSafeInteger(run?.testcaseCount) && run.testcaseCount > 0 &&
          Number.isSafeInteger(run?.assertionCount) && run.assertionCount > 0
        )
        .map((run) => String(run.testMethodId ?? ''))
        .filter(Boolean)
        .sort(comparePortable);
      if (
        new Set(passingRuns).size !== passingRuns.length ||
        JSON.stringify(passingRuns) !== JSON.stringify(expectedMethodIds)
      ) {
        push('Verifier-owned focused test execution must record one exact passing JUnit run with a positive assertion count for every expected TESTMETHOD ID.');
      }
    }
  }

  const routeBindings = Array.isArray(review.routeBindings) ? review.routeBindings : [];
  const bindingsByName = new Map();
  for (const [index, binding] of routeBindings.entries()) {
    const name = String(binding?.name ?? '').trim();
    if (!name || bindingsByName.has(name)) {
      push(`Custom route binding row ${index} has a missing or duplicate name.`);
      continue;
    }
    bindingsByName.set(name, binding);
    if (
      !/^[A-Z]+$/.test(String(binding?.requestMethod ?? '')) ||
      !binding?.routeParameters ||
      typeof binding.routeParameters !== 'object' ||
      Array.isArray(binding.routeParameters) ||
      !['allowed', 'denied'].includes(binding?.expectedAnonymousAccess)
    ) {
      push(`Custom route binding ${name} needs an uppercase requestMethod, routeParameters object, and expectedAnonymousAccess of allowed or denied.`);
    }
  }
  const auditedRoutes = Array.isArray(runtimeInventory.routeAudit?.routes) ? runtimeInventory.routeAudit.routes : [];
  const auditedNames = new Set(auditedRoutes.map((route) => String(route?.name ?? '')).filter(Boolean));
  for (const route of auditedRoutes) {
    const binding = bindingsByName.get(route.name);
    if (!binding) {
      push(`Custom route ${route.name} has no representative request binding.`);
    }
    if (
      route.requestMatched !== true ||
      route.parameterConversionCompleted !== true ||
      route.accessCheckCompleted !== true ||
      !['allowed', 'denied'].includes(route.anonymousAccess)
    ) {
      push(`Custom route ${route.name} lacks a completed representative match, parameter-conversion, and anonymous access-manager result.`);
    }
    if (
      binding &&
      ['allowed', 'denied'].includes(binding.expectedAnonymousAccess) &&
      route.anonymousAccess !== binding.expectedAnonymousAccess
    ) {
      push(`Custom route ${route.name} anonymous access ${route.anonymousAccess || '(missing)'} does not match expected ${binding.expectedAnonymousAccess}.`);
    }
  }
  for (const name of bindingsByName.keys()) {
    if (!auditedNames.has(name)) {
      push(`Packet-only custom route binding ${name} is not present in the live custom-route audit.`);
    }
  }
  return errors;
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

const REGULAR_GIT_FILE_MODES = new Set(['100644', '100755']);

function gitBlobObjectId(bytes, objectFormat) {
  const context = createHash(objectFormat);
  context.update(`blob ${bytes.length}\0`);
  context.update(bytes);
  return context.digest('hex');
}

export function yamlTreeMatchesHead(projectRoot, yamlFiles, relativeDirectories) {
  if (!Array.isArray(yamlFiles) || !Array.isArray(relativeDirectories)) {
    throw new TypeError('YAML files and config directories must be arrays.');
  }
  const normalizedYamlFiles = yamlFiles.map((path) => String(path).replaceAll('\\', '/'));
  if (new Set(normalizedYamlFiles).size !== normalizedYamlFiles.length) {
    return false;
  }

  const headOutput = execFileSync(
    'git',
    ['ls-tree', '-r', '-z', '--full-tree', 'HEAD', '--', ...relativeDirectories],
    {
      cwd: projectRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000
    }
  );
  const headYamlEntries = headOutput
    .split('\0')
    .filter(Boolean)
    .map((record) => {
      const separator = record.indexOf('\t');
      if (separator === -1) {
        throw new Error('HEAD config tree returned malformed Git metadata.');
      }
      const [mode, type, objectId] = record.slice(0, separator).split(' ');
      return {
        mode,
        objectId,
        path: record.slice(separator + 1).replaceAll('\\', '/'),
        type
      };
    })
    .filter((entry) => /\.ya?ml$/i.test(entry.path))
    .sort((left, right) => comparePortable(left.path, right.path));

  const sortedYamlFiles = [...normalizedYamlFiles].sort(comparePortable);
  if (
    headYamlEntries.length !== sortedYamlFiles.length ||
    headYamlEntries.some((entry, index) =>
      entry.path !== sortedYamlFiles[index] ||
      entry.type !== 'blob' ||
      !REGULAR_GIT_FILE_MODES.has(entry.mode)
    )
  ) {
    return false;
  }

  const objectFormat = execFileSync('git', ['rev-parse', '--show-object-format=storage'], {
    cwd: projectRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 10_000
  }).trim();
  if (!['sha1', 'sha256'].includes(objectFormat)) {
    throw new Error(`Unsupported Git object format: ${objectFormat || '(missing)'}.`);
  }

  return headYamlEntries.every((entry) => {
    const bytes = readFileSync(join(projectRoot, entry.path));
    return gitBlobObjectId(bytes, objectFormat) === entry.objectId;
  });
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
          yamlTreeMatchesHead(projectRoot, allYamlFiles, relativeDirectories);
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

function inspectDrupalRuntime(cwd, environment, fieldOutputMatrix, browserEvidence, routeMatrix, patternMap, drupalReadback) {
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
      configSyncMatchesHead: false,
      configSyncTracked: false,
      configSyncDirectory: '',
      configManifest: null,
      configSplitDirectories: [],
      customCodeInventory: {
        schemaVersion: CUSTOM_CODE_SCHEMA,
        bounded: true,
        completed: false,
        applies: false,
        errors: ['Drupal runtime is unavailable.'],
        extensions: [], sourceFiles: [], controllers: [], routes: [], tests: [],
        routeAudit: { completed: false, routes: [], violations: [] },
        configSchema: { completed: false, extensions: [], violations: [] },
        qualityAudit: blockedQualityAudit({ fingerprint: '' }, [customCodeFailure('spawn_failed', 'preflight', '', 'Drupal runtime is unavailable.')]),
        focusedTestExecution: blockedFocusedTestExecution({ fingerprint: '' }, false, [], [customCodeFailure('spawn_failed', 'preflight', '', 'Drupal runtime is unavailable.')]),
        fingerprint: ''
      },
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
      liveEditorSurfaceCensus: parseLiveEditorSurfaceCensus({ ok: false, output: '' }),
      liveNextCycleCensus: parseLiveNextCycleCensus({ ok: false, output: '' }),
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
  const readDrush = (args, timeout = 15_000) => {
    const result = runDrushResult(projectRoot, environment, args, timeout);
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
  const consentInventory = inspectConsentInventory(projectRoot, environment);
  const describedTarget = inContainer
    ? { primaryUrl: environmentTargetUrl(environment), webOrigins: environmentWebOrigins(environment) }
    : ddevTargetDescription(projectRoot, environment);
  const baseUrl = describedTarget.primaryUrl;
  const customCodeInventory = inspectCustomCode(
    projectRoot,
    environment,
    drupalReadback?.implementationQuality?.customCodeInventory ?? {},
    { baseUrl }
  );
  const siteUuid = uuidResult.output.match(UUID_RE)?.[0]?.toLowerCase() ?? '';
  const confirmed = /successful/i.test(bootstrapResult.output) && Boolean(siteUuid);
  const identityReadbackFailed = !bootstrapResult.ok || !uuidResult.ok;
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
  const liveNextCycleCensus = parseLiveNextCycleCensus(
    readDrush(['php:eval', LIVE_NEXT_CYCLE_CENSUS_PHP])
  );
  const liveEditorSurfaceCensus = inspectLiveEditorSurface(
    projectRoot,
    environment,
    fieldOutputMatrix,
    browserEvidence,
    readDrush
  );
  return {
    baseUrl,
    confirmed,
    configStatusClean: configStatusIsClean(configStatus),
    consentInventory,
    configSyncMatchesHead: trackedConfig.matchesHead,
    configSyncTracked: trackedConfig.confirmed,
    configSyncDirectory,
    configManifest: trackedConfig.configManifest,
    configSplitDirectories: trackedConfig.configSplitDirectories,
    customCodeInventory,
    drupalRoot,
    entityInventory,
    liveSurfaceInventory,
    runtimeFacts,
    drushCommandFailures,
    frontPage,
    identityReadbackFailed,
    liveEditorSurfaceCensus,
    liveNextCycleCensus,
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

function expectedRoute(routeMatrix, primaryRoute, browserEvidence, { briefMode = false } = {}) {
  const requestTarget = requestPathAndSearch(primaryRoute?.targetPath || primaryRoute?.sourcePath);
  const targetPath = normalizePath(requestTarget);
  const record = matchingRouteRecord(routeMatrix, targetPath, requestTarget) ?? {};
  const homepage = targetPath === '/'
    ? briefMode
      ? routeMatrix.homepageTargetAcceptance ?? {}
      : routeMatrix.homepageParity ?? {}
    : {};
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
    matchesBrowserRenderedSource: briefMode || primaryRoute?.matchesBrowserRenderedSource === true,
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
  negativeRouteConsent,
  nextCycleVerification,
  parityReport,
  patternMap,
  sourceAudit,
  sourceUrl,
  targetUrl
}) {
  const errors = [];
  const targetOrigin = targetUrl.origin;
  const sourceOrigin = sourceUrl?.origin ?? '';
  if (sourceOrigin) {
    requiredOriginMatch(errors, 'source-audit.json site.baseUrl', sourceAudit?.site?.baseUrl, sourceOrigin);
    requiredOriginMatch(errors, 'pattern-map.json sourceSite', patternMap?.sourceSite, sourceOrigin);
  }
  requiredOriginMatch(errors, 'field-output-matrix.json site', fieldOutputMatrix?.site, targetOrigin);
  const briefParityNotApplicable = !sourceOrigin &&
    parityReport?.schemaVersion === 'public-kit.mode-disposition.1' &&
    parityReport?.artifact === 'parity-report.json' &&
    parityReport?.buildMode === 'brief' &&
    parityReport?.status === 'not_applicable';
  if (!briefParityNotApplicable) {
    requiredOriginMatch(errors, 'parity-report.json targetUrl', parityReport?.targetUrl, targetOrigin);
  }
  requiredOriginMatch(errors, 'browser-evidence.json site', browserEvidence?.site, targetOrigin);
  requiredOriginMatch(errors, 'drupal-readback.json site', drupalReadback?.site, targetOrigin);
  requiredOriginMatch(errors, 'negative-route-consent.json site', negativeRouteConsent?.site, targetOrigin);
  requiredOriginMatch(errors, 'next-cycle-verification.json site', nextCycleVerification?.site, targetOrigin);
  requiredOriginMatch(
    errors,
    'independent-verification.json target.baseUrl',
    independentVerification?.target?.baseUrl,
    targetOrigin
  );
  if (nextCycleVerification?.applicability?.applies === true) {
    requiredOriginMatch(
      errors,
      'next-cycle-verification.json futureContentProbe.publicUrl',
      nextCycleVerification?.futureContentProbe?.publicUrl,
      targetOrigin
    );
  }
  requiredOriginMatch(
    errors,
    'independent-verification.json target.adminUrl',
    independentVerification?.target?.adminUrl,
    targetOrigin
  );

  for (const [index, check] of (Array.isArray(browserEvidence?.publicRouteChecks)
    ? browserEvidence.publicRouteChecks
    : []).entries()) {
    if (sourceOrigin) {
      requiredOriginMatch(errors, `browser-evidence.json publicRouteChecks[${index}].sourceUrl`, check?.sourceUrl, sourceOrigin);
      requiredOriginMatch(
        errors,
        `browser-evidence.json publicRouteChecks[${index}].sourceFinalUrl`,
        check?.sourceFinalUrl,
        sourceOrigin
      );
    }
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

async function verifyRoute(baseUrl, expected, liveHttpContext, criticalAssetContext) {
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
    const criticalAssets = await inspectCriticalAssets(
      response.body,
      response.finalUrl,
      criticalAssetContext
    );
    errors.push(...criticalAssets.errors.map((error) => `${expected.targetPath}: ${error}`));
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
      criticalAssets,
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
      renderedLegalLinks: renderedLegalLinks(response.body, response.finalUrl),
      renderedResourceUrls: renderedResourceUrls(response.body, response.finalUrl),
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

async function verifyGeneratedMissingRoute(baseUrl, policy, liveHttpContext) {
  const path = `/.well-known/agent-ready-missing-${randomBytes(16).toString('hex')}`;
  const requestedUrl = new URL(path, baseUrl);
  const errors = [];
  try {
    const response = await liveHttpContext.request(requestedUrl);
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

async function verifyAccessWallRoute(baseUrl, declaration, liveHttpContext) {
  const path = normalizePath(declaration?.path);
  const requestedUrl = new URL(path.replace(/^\//, ''), new URL('/', baseUrl));
  const errors = [];
  try {
    if (declaration?.expectedBehavior === 'external_auth') {
      const response = await liveHttpContext.request(requestedUrl);
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
    const response = await requestFollowingRedirects(requestedUrl, { liveHttpContext });
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

async function verifyRenderedLegalLinks(baseUrl, routeChecks, declaration, liveHttpContext) {
  const rendered = [...routeChecks.flatMap((route) => route.renderedLegalLinks ?? [])];
  const activeRequirements = (Array.isArray(declaration?.requirements) ? declaration.requirements : [])
    .filter((requirement) => requirement?.status === 'active')
    .map((requirement) => ({ sourceUrl: 'negative-route-consent.json', text: '', url: new URL(normalizePath(requirement.path).replace(/^\//, ''), new URL('/', baseUrl)).href }));
  const candidates = [...rendered, ...activeRequirements];
  const unique = [...new Map(candidates.map((link) => [link.url, link])).values()];
  return liveHttpContext.runTasks('legal-privacy-link', unique, async (link) => {
    const errors = [];
    try {
      const response = await requestFollowingRedirects(new URL(link.url), { liveHttpContext });
      if (new URL(response.finalUrl).origin !== baseUrl.origin || response.status < 200 || response.status >= 300) {
        errors.push(`Rendered or active legal/privacy link ${link.url} ended at ${response.finalUrl} with HTTP ${response.status}; it cannot be treated as not applicable.`);
      }
      return { ...link, errors, finalUrl: response.finalUrl, passed: errors.length === 0, status: response.status };
    } catch (error) {
      errors.push(`Rendered or active legal/privacy link ${link.url} could not be fetched: ${error.message}`);
      return { ...link, errors, passed: false };
    }
  });
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
    (Array.isArray(application?.controlledResources) ? application.controlledResources : []).some((resource) =>
      String(resource?.pattern ?? '').trim()
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
      errors.push(`G-PRIVACY-01 requires verifier-owned fresh browser/network capture for every declared application with controlled resources: ${error.message}`);
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
    const essentialWithoutConsent = application.required === true &&
      application.essentialWithoutConsent === true &&
      String(application.essentialServiceRationale ?? '').trim() &&
      Array.isArray(application.essentialServiceEvidence) &&
      application.essentialServiceEvidence.length > 0;
    if (application.required === true && !essentialWithoutConsent) {
      errors.push(`Required consent application ${application.id} lacks an explicit evidence-backed essential-without-consent classification; required=true cannot disable observation or authorize loading.`);
    }
    if (violating.length > 0 && !essentialWithoutConsent) {
      const state = application.enabled !== true
        ? 'while its consent application is disabled'
        : application.required === true
          ? 'before consent while its required application lacks an evidence-backed essential-service classification'
          : 'before consent';
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

export async function scheduleLiveRouteChecks({
  baseUrl,
  tasks = [],
  allowRuntimeBoundLocalCertificate = false,
  maxRoutes = MAX_LIVE_ROUTE_CHECKS,
  concurrency = MAX_LIVE_ROUTE_CONCURRENCY,
  deadlineMs = LIVE_ROUTE_DEADLINE_MS,
  maxRequests = MAX_LIVE_HTTP_REQUESTS,
  liveHttpContext = null,
  criticalAssetContext = null
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
  const assetContext = criticalAssetContext ?? createCriticalAssetContext({
    liveHttpContext: context
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
        check: await context.runTask(
          kind,
          () => verifyRoute(baseUrl, task.expected, context, assetContext)
        )
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

function authoredNextCycleDimensionKeys(nextCycleVerification) {
  const keys = new Set();
  const models = Array.isArray(nextCycleVerification?.discovery?.recurringPublicModels)
    ? nextCycleVerification.discovery.recurringPublicModels
    : [];
  for (const model of models) {
    for (const dimension of (Array.isArray(model?.dimensions) ? model.dimensions : [])) {
      const entityType = String(model?.entityType ?? '').trim();
      const bundle = String(model?.bundle ?? '').trim();
      const machineName = String(dimension?.machineName ?? '').trim();
      if (entityType && bundle && machineName) {
        keys.add(`${entityType}.${bundle}.${machineName}`);
      }
      const configName = String(dimension?.configName ?? '').trim();
      const fieldConfig = configName.match(/^field\.field\.([^.]+)\.([^.]+)\.(.+)$/);
      if (fieldConfig) {
        keys.add(`${fieldConfig[1]}.${fieldConfig[2]}.${fieldConfig[3]}`);
      }
      const vocabulary = String(dimension?.vocabulary ?? dimension?.vocabularyId ?? '').trim();
      if (vocabulary) {
        keys.add(`taxonomy.${vocabulary}`);
      }
      const vocabularyConfig = configName.match(/^taxonomy\.vocabulary\.(.+)$/);
      if (vocabularyConfig) {
        keys.add(`taxonomy.${vocabularyConfig[1]}`);
      }
    }
  }
  return [...keys].sort();
}

function reconcileLiveNextCycleCensus(nextCycleVerification, census, { required = false } = {}) {
  const authoredApplies = nextCycleVerification?.applicability?.applies === true;
  const fields = Array.isArray(census?.fields) ? census.fields : [];
  const taxonomyDimensions = Array.isArray(census?.taxonomyDimensions) ? census.taxonomyDimensions : [];
  const liveCandidateKeys = [...new Set([...fields, ...taxonomyDimensions]
    .map((record) => String(record?.key ?? '').trim())
    .filter(Boolean))].sort();
  const censusTrusted =
    census?.confirmed === true &&
    census?.schemaVersion === 'public-kit.live-next-cycle-census.1' &&
    census?.metadataOnly === true &&
    census?.privateContentRead === false &&
    Number(census?.candidateCount) === fields.length + taxonomyDimensions.length &&
    liveCandidateKeys.length === fields.length + taxonomyDimensions.length;
  const authoredDimensionKeys = authoredNextCycleDimensionKeys(nextCycleVerification);
  const authoredSet = new Set(authoredDimensionKeys);
  const unreviewedLiveCandidateKeys = liveCandidateKeys.filter((key) => !authoredSet.has(key));
  const errors = [];

  if (required && !censusTrusted) {
    errors.push(
      'G-EDITOR-02 requires a successful read-only Drush live model census before authored next-cycle applicability can support completion.'
    );
  }
  if (!authoredApplies && censusTrusted && liveCandidateKeys.length > 0) {
    errors.push(
      `G-EDITOR-02 cannot use N/A because the live Drupal model has temporal/cycle candidates omitted from the packet: ${liveCandidateKeys.join(', ')}.`
    );
  }
  if (authoredApplies && censusTrusted && unreviewedLiveCandidateKeys.length > 0) {
    errors.push(
      `G-EDITOR-02 authored applicability omits live Drupal temporal/cycle candidates: ${unreviewedLiveCandidateKeys.join(', ')}.`
    );
  }

  return {
    authoredApplies,
    authoredDimensionKeys,
    censusRequired: required,
    censusTrusted,
    errors,
    liveApplies: censusTrusted && liveCandidateKeys.length > 0,
    liveCandidateKeys,
    passed: errors.length === 0,
    unreviewedLiveCandidateKeys
  };
}

async function verifyNextCycleCleanup(
  baseUrl,
  nextCycleVerification,
  liveReconciliation = null,
  liveHttpContext = null
) {
  if (nextCycleVerification?.applicability?.applies !== true) {
    if (liveReconciliation?.liveApplies === true) {
      return {
        applicable: true,
        authoredApplicable: false,
        errors: [],
        passed: false,
        reason: 'Live model census requires next-cycle evidence, but the packet declared N/A.'
      };
    }
    return { applicable: false, errors: [], passed: true };
  }
  const errors = [];
  const declaredUrl = String(nextCycleVerification?.futureContentProbe?.publicUrl ?? '').trim();
  const expectedStatus = Number(nextCycleVerification?.cleanup?.publicUrlStatusAfterCleanup);
  let requestedUrl;
  try {
    requestedUrl = parseHttpUrl(declaredUrl, 'next-cycle-verification.json futureContentProbe.publicUrl');
  } catch (error) {
    errors.push(error.message);
    return { applicable: true, errors, passed: false, requestedUrl: declaredUrl };
  }
  if (requestedUrl.origin !== baseUrl.origin) {
    errors.push(`Next-cycle cleanup URL origin ${requestedUrl.origin} does not match ${baseUrl.origin}.`);
  }
  if (![404, 410].includes(expectedStatus)) {
    errors.push('Next-cycle cleanup must declare publicUrlStatusAfterCleanup as 404 or 410.');
  }
  try {
    const response = await requestFollowingRedirects(requestedUrl, { liveHttpContext });
    if (response.redirects.length > 0) {
      errors.push('Next-cycle cleanup URL still redirects; alias or redirect residue remains.');
    }
    if (new URL(response.finalUrl).origin !== baseUrl.origin) {
      errors.push(`Next-cycle cleanup URL left the target origin and resolved to ${new URL(response.finalUrl).origin}.`);
    }
    if (response.status !== expectedStatus) {
      errors.push(`Next-cycle cleanup URL returned ${response.status}; expected ${expectedStatus}.`);
    }
    return {
      actualStatus: response.status,
      applicable: true,
      bodySha256: `sha256:${sha256(response.body)}`,
      errors,
      finalUrl: response.finalUrl,
      passed: errors.length === 0,
      redirects: response.redirects,
      requestedUrl: requestedUrl.href
    };
  } catch (error) {
    errors.push(`Next-cycle cleanup URL could not be fetched: ${error.message}`);
    return { applicable: true, errors, passed: false, requestedUrl: requestedUrl.href };
  }
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
  const gates = JSON.parse(readFileSync(join(KIT_ROOT, 'gates.json'), 'utf8'));
  const briefMode = packetReport.buildMode === 'brief';
  const claimScope = briefMode ? 'complete-local-build-from-brief' : 'complete-local-rebuild';
  let routeMatrixText = '';
  let routeMatrix = {};
  let routeMatrixError = '';
  const runtimeJsonBudget = { bytes: 0 };
  try {
    const boundedRouteMatrix = await readBoundedJsonFile(routeMatrixPath, { budget: runtimeJsonBudget });
    routeMatrixText = boundedRouteMatrix.text;
    routeMatrix = boundedRouteMatrix.value;
  } catch (error) {
    routeMatrixError = `route-matrix.json cannot be used for live verification: ${error.message}`;
  }
  let independentVerification = null;
  let blindReview = null;
  let drupalReadback = null;
  let browserEvidence = null;
  let fieldOutputMatrix = null;
  let nextCycleVerification = null;
  let parityReport = null;
  let patternMap = null;
  let sourceAudit = null;
  let negativeRouteConsent = null;
  let reviewHandoff = null;
  try {
    independentVerification = (await readBoundedJsonFile(join(absolutePacketDir, 'independent-verification.json'), { budget: runtimeJsonBudget })).value;
    blindReview = (await readBoundedJsonFile(join(absolutePacketDir, 'blind-adversarial-review.json'), { budget: runtimeJsonBudget })).value;
    drupalReadback = (await readBoundedJsonFile(join(absolutePacketDir, 'drupal-readback.json'), { budget: runtimeJsonBudget })).value;
    browserEvidence = (await readBoundedJsonFile(join(absolutePacketDir, 'browser-evidence.json'), { budget: runtimeJsonBudget })).value;
    fieldOutputMatrix = (await readBoundedJsonFile(join(absolutePacketDir, 'field-output-matrix.json'), { budget: runtimeJsonBudget })).value;
    nextCycleVerification = (await readBoundedJsonFile(join(absolutePacketDir, 'next-cycle-verification.json'), { budget: runtimeJsonBudget })).value;
    parityReport = (await readBoundedJsonFile(join(absolutePacketDir, 'parity-report.json'), { budget: runtimeJsonBudget })).value;
    patternMap = (await readBoundedJsonFile(join(absolutePacketDir, 'pattern-map.json'), { budget: runtimeJsonBudget })).value;
    sourceAudit = (await readBoundedJsonFile(join(absolutePacketDir, 'source-audit.json'), { budget: runtimeJsonBudget })).value;
    negativeRouteConsent = (await readBoundedJsonFile(join(absolutePacketDir, 'negative-route-consent.json'), { budget: runtimeJsonBudget })).value;
    try {
      reviewHandoff = (
        await readBoundedJsonFile(
          join(absolutePacketDir, 'evidence', 'review-handoff.json'),
          { budget: runtimeJsonBudget }
        )
      ).value;
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        // Packet validation records malformed, non-regular, or oversized optional handoff JSON.
      }
      reviewHandoff = null;
    }
  } catch {
    // Packet validation already records malformed or missing required JSON.
  }
  const liveErrors = boundedReportMessages(routeMatrixError ? [routeMatrixError] : []);
  const declaredSource = String(routeMatrix.sourceBaseUrl ?? '').trim();
  const declaredTarget = String(routeMatrix.targetBaseUrl ?? '').trim();
  if (!briefMode && !declaredSource) {
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
    browserEvidence,
    routeMatrix,
    patternMap,
    drupalReadback
  );
  const runtimeAuthoritativeForCompletion = !runtimeWasInjected;
  const packetSupportsCompletion = packetReport.completionEvidence?.packetSupportsCompletion === true;
  const packetClaimsQualifyingReview =
    independentVerification?.summary?.verdict === 'pass' ||
    ['good', 'good_enough'].includes(blindReview?.summary?.verdict);
  const liveNextCycleCensusRequired =
    (runtimeAuthoritativeForCompletion && (packetSupportsCompletion || packetClaimsQualifyingReview)) ||
    (runtimeWasInjected && Object.prototype.hasOwnProperty.call(inspectedDrupalRuntime, 'liveNextCycleCensus'));
  const liveNextCycleReconciliation = reconcileLiveNextCycleCensus(
    nextCycleVerification,
    inspectedDrupalRuntime.liveNextCycleCensus,
    { required: liveNextCycleCensusRequired }
  );
  liveErrors.push(...liveNextCycleReconciliation.errors);
  const liveEditorSurfaceCensusRequired =
    (runtimeAuthoritativeForCompletion && (packetSupportsCompletion || packetClaimsQualifyingReview)) ||
    (runtimeWasInjected && Object.prototype.hasOwnProperty.call(inspectedDrupalRuntime, 'liveEditorSurfaceCensus'));
  const liveEditorSurfaceReconciliation = reconcileLiveEditorSurface(
    fieldOutputMatrix,
    browserEvidence,
    inspectedDrupalRuntime.liveEditorSurfaceCensus,
    { required: liveEditorSurfaceCensusRequired }
  );
  liveErrors.push(...liveEditorSurfaceReconciliation.errors);
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

  let chromeContext = { lifecyclePresent: false, latestVerifiedAnchor: null, contract: null };
  try {
    chromeContext = globalChromeCaptureContext({ packetDir: absolutePacketDir });
  } catch (error) {
    liveErrors.push(`Global chrome lifecycle context could not be read: ${error.message}`);
  }
  const browserBackend = inspectedDrupalRuntime.mode === 'ddev-container' ? 'remote' : 'local';
  const browserCaptureAttempted = Boolean(
    target &&
    explicitTargetFetchAllowed &&
    runtimeAuthoritativeForCompletion
  );
  const rawGlobalChromeCapture = browserCaptureAttempted
    ? await captureGlobalChrome({
        browserBackend,
        baseUrl: target.url,
        primaryRoutes,
        contract: chromeContext.contract ?? browserEvidence?.globalChromeRegression ?? {},
        environment
      })
    : globalChromeCaptureWithoutArtifacts({
        schemaVersion: 'public-kit.global-chrome-capture.1',
        checkedAt: new Date().toISOString(),
        status: 'unavailable',
        authoritative: false,
        captureMode: 'verifier-owned-browser',
        targetOrigin: target?.url?.origin ?? '',
        contract: chromeContext.contract ?? browserEvidence?.globalChromeRegression ?? {},
        browser: { executable: '', product: '' },
        runtime: {
          backend: browserBackend === 'remote' ? 'selenium-grid-cdp' : 'local-executable-cdp-pipe',
          executionBoundary: browserBackend === 'remote' ? 'ddev-add-on-sidecar' : 'maintainer-local-process',
          service: browserBackend === 'remote' ? 'selenium-chrome' : '',
          addOnRelease: '',
          image: '',
          executable: '',
          product: '',
          protocolVersion: '',
          ready: false
        },
        primaryRoutes: [],
        routes: [],
        budget: null,
        warnings: [],
        errors: ['Verifier-owned browser capture is disabled for an injected or unavailable runtime.']
      });
  const browserRuntimeUnavailable = browserRuntimePreflightUnavailable(rawGlobalChromeCapture, {
    attempted: browserCaptureAttempted
  });
  if (browserRuntimeUnavailable) {
    liveErrors.push(browserBackend === 'remote'
      ? 'Verifier-owned browser preflight failed before source or target HTTP verification. From the DDEV host run: bash .agents/skills/agent-ready-drupal-build-kit/scripts/repair-browser-runtime.sh, then rerun verification.'
      : 'Verifier-owned browser preflight failed before source or target HTTP verification. Use the canonical DDEV agent workflow, or set CHROME_PATH for an explicit host-side maintainer run.');
  }

  const sourceSurfaceCensusPromise = briefMode
    ? Promise.resolve(sourceSurfaceNotRun(
        'Source-site discovery does not apply to a brief-based build.',
        { status: 'not_applicable', authoritative: true }
      ))
    : browserRuntimeUnavailable
    ? Promise.resolve(sourceSurfaceNotRun(
        'Browser runtime preflight failed; expensive verification was not started.'
      ))
    : runtimeAuthoritativeForCompletion && declaredSource
    ? inspectSourceSurface({ independentVerification, routeMatrix })
    : Promise.resolve(sourceSurfaceNotRun(
        runtimeWasInjected
          ? 'Verifier-owned source census is disabled for an injected Drupal runtime.'
          : 'Verifier-owned source census could not start without sourceBaseUrl.'
      ));
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
      expected: expectedRoute(routeMatrix, route, browserEvidence, { briefMode })
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
  const fetchChecksEnabled = Boolean(
    target &&
    explicitTargetFetchAllowed &&
    (!runtimeAuthoritativeForCompletion || !browserRuntimeUnavailable)
  );
  const liveHttpContext = createLiveHttpContext({
    allowRuntimeBoundLocalCertificate: runtimeAuthoritativeForCompletion && runtimeTargetOriginMatches,
    attempted: fetchChecksEnabled,
    concurrency: liveHttpLimits.concurrency ?? MAX_LIVE_ROUTE_CONCURRENCY,
    deadlineMs: liveHttpLimits.deadlineMs ?? LIVE_ROUTE_DEADLINE_MS,
    maxRequests: liveHttpLimits.maxRequests ?? MAX_LIVE_HTTP_REQUESTS,
    maxTasks: liveHttpLimits.maxTasks ?? MAX_LIVE_HTTP_TASKS
  });
  const criticalAssetContext = createCriticalAssetContext({ liveHttpContext });
  const liveRouteSchedule = fetchChecksEnabled
    ? await scheduleLiveRouteChecks({
        allowRuntimeBoundLocalCertificate: runtimeAuthoritativeForCompletion && runtimeTargetOriginMatches,
        baseUrl: target.url,
        criticalAssetContext,
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
  let nextCycleCleanupCheck;
  if (fetchChecksEnabled) {
    try {
      nextCycleCleanupCheck = nextCycleVerification?.applicability?.applies === true
        ? await liveHttpContext.runTask(
            'next-cycle-cleanup',
            () => verifyNextCycleCleanup(
              target.url,
              nextCycleVerification,
              liveNextCycleReconciliation,
              liveHttpContext
            )
          )
        : await verifyNextCycleCleanup(
            target.url,
            nextCycleVerification,
            liveNextCycleReconciliation,
            liveHttpContext
          );
    } catch (error) {
      nextCycleCleanupCheck = {
        applicable: true,
        errors: [`Next-cycle cleanup verification could not be scheduled: ${error.message}`],
        passed: false
      };
    }
  } else {
    nextCycleCleanupCheck = {
      applicable:
        nextCycleVerification?.applicability?.applies === true ||
        liveNextCycleReconciliation.liveApplies === true,
      errors: [],
      passed: false
    };
  }
  liveErrors.push(...nextCycleCleanupCheck.errors);
  for (const error of liveHttpContext.errors) {
    if (!liveErrors.includes(error)) {
      liveErrors.push(error);
    }
  }
  let negativeRouteCheck = null;
  if (fetchChecksEnabled) {
    try {
      negativeRouteCheck = await liveHttpContext.runTask(
        'generated-missing-route',
        () => verifyGeneratedMissingRoute(target.url, negativeRouteConsent?.missingRoute, liveHttpContext)
      );
    } catch (error) {
      liveErrors.push(`Generated missing-route verification could not complete: ${error.message}`);
    }
  }
  if (negativeRouteCheck) {
    liveErrors.push(...negativeRouteCheck.errors);
  }
  let accessWallChecks = [];
  if (fetchChecksEnabled) {
    try {
      accessWallChecks = await liveHttpContext.runTasks(
        'access-wall-route',
        Array.isArray(negativeRouteConsent?.accessWallRoutes) ? negativeRouteConsent.accessWallRoutes : [],
        (route) => verifyAccessWallRoute(target.url, route, liveHttpContext)
      );
    } catch (error) {
      liveErrors.push(`Access-wall verification could not complete: ${error.message}`);
    }
  }
  for (const check of accessWallChecks) {
    liveErrors.push(...check.errors);
  }
  let legalPrivacyLinkChecks = [];
  if (fetchChecksEnabled) {
    try {
      legalPrivacyLinkChecks = await verifyRenderedLegalLinks(
        target.url,
        [...routeChecks, ...targetRequiredRouteChecks, ...browserRepresentativeRouteChecks],
        negativeRouteConsent?.legalPrivacyScope,
        liveHttpContext
      );
    } catch (error) {
      liveErrors.push(`Legal/privacy-link verification could not complete: ${error.message}`);
    }
  }
  for (const check of legalPrivacyLinkChecks) {
    liveErrors.push(...check.errors);
  }
  // Await the verifier-owned source census only AFTER every target-side
  // liveHttpContext check has completed. The census is started concurrently
  // above (sourceSurfaceCensusPromise) but crawls a slow / large / CDN-gated
  // SOURCE origin; awaiting it earlier let it consume the target context's
  // fixed wall-clock deadline (deadlineAt = startedAt + deadlineMs), which then
  // failed unrelated target-side checks (server-rendered surface, redirect
  // materialization, next-cycle cleanup, generated missing-route, access-wall,
  // legal/privacy) with false "exceeded its total wall-clock deadline" errors.
  // The census result is only consumed by completion logic below, so deferring
  // the await keeps the target-side verdict independent of source-census cost
  // without changing any source-census behavior or enforcement.
  const sourceSurfaceCensus = await sourceSurfaceCensusPromise;
  liveErrors.push(...sourceSurfaceCensus.errors);
  for (const error of liveHttpContext.errors) {
    if (!liveErrors.includes(error)) {
      liveErrors.push(error);
    }
  }
  const liveHttpBudget = liveHttpContext.metrics();
  const consentInventory = inspectedDrupalRuntime.consentInventory ?? {
    applications: [],
    configNames: [],
    confirmed: runtimeWasInjected,
    detected: false,
    managerModules: [],
    reason: runtimeWasInjected ? '' : 'Consent inventory is unavailable.'
  };
  const consentNetworkApplicable = consentNetworkCaptureRequired(negativeRouteConsent?.consent);
  const rawBeforeConsentNetworkCapture = consentNetworkApplicable && fetchChecksEnabled && runtimeAuthoritativeForCompletion
    ? await captureBeforeConsentNetwork({
        browserBackend,
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
        budget: null,
        warnings: [],
        errors: consentNetworkApplicable
          ? ['Verifier-owned before-consent capture is disabled for an injected or unavailable Drupal runtime.']
          : []
      };

  if (target && (packetSupportsCompletion || packetClaimsQualifyingReview) && (briefMode || declaredSource)) {
    try {
      const sourceUrl = briefMode
        ? null
        : parseHttpUrl(declaredSource, 'route-matrix.json sourceBaseUrl');
      liveErrors.push(
        ...completionEvidenceTargetErrors({
          blindReview,
          browserEvidence,
          drupalReadback,
          fieldOutputMatrix,
          independentVerification,
          negativeRouteConsent,
          nextCycleVerification,
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
  const customCodeErrors = !runtimeWasInjected || Object.hasOwn(inspectedDrupalRuntime, 'customCodeInventory')
    ? customCodeReconciliationErrors(
      inspectedDrupalRuntime.customCodeInventory,
      drupalReadback?.implementationQuality?.customCodeInventory,
      absolutePacketDir
    )
    : [];
  liveErrors.push(...customCodeErrors);
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
      canonicalPath: normalizeRouteKey(publicRedactedValue(route.actualMetadata?.canonicalUrl)),
      criticalAssetManifest: route.criticalAssets?.manifest ?? [],
      criticalAssetManifestSha256: route.criticalAssets?.fingerprint ?? '',
      finalPath: normalizeRouteKey(publicRedactedValue(route.finalUrl)),
      h1: route.actualH1 ?? '',
      initialStatus: route.initialStatus ?? 0,
      intrinsicSemanticsSha256: route.intrinsicSemantics?.fingerprint ?? '',
      metaDescriptionSha256: stateSha256(route.actualMetadata?.metaDescription ?? ''),
      noindex: route.actualMetadata?.noindex === true,
      openGraphImagePath: normalizePath(publicRedactedValue(route.actualMetadata?.openGraphImage)),
      path: normalizeRouteKey(publicRedactedValue(route.requestTarget || route.targetPath)),
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
  if (customCodeErrors.length > 0) {
    stateBlockers.push('The current verifier-owned custom-code inventory is not exactly capability/test-bound or its quality, focused-test, representative-route, or config-schema checks failed.');
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
  let globalChromeCapture = globalChromeCaptureWithoutArtifacts(rawGlobalChromeCapture, {
    status: rawGlobalChromeCapture.status === 'captured'
      ? 'blocked'
      : rawGlobalChromeCapture.status,
    error: rawGlobalChromeCapture.status === 'captured'
      ? 'Global chrome capture could not be bound to a complete Drupal build state.'
      : ''
  });
  if (
    buildStateReady &&
    rawGlobalChromeCapture.status === 'captured' &&
    rawGlobalChromeCapture.authoritative === true
  ) {
    try {
      globalChromeCapture = finalizeGlobalChromeCapture({
        capture: rawGlobalChromeCapture,
        packetDir: absolutePacketDir,
        stateFingerprint: buildState.fingerprint
      });
    } catch (error) {
      globalChromeCapture = globalChromeCaptureWithoutArtifacts(rawGlobalChromeCapture, {
        status: 'blocked',
        resultStateFingerprint: buildState.fingerprint,
        error: `Global chrome capture finalization failed: ${error.message}`
      });
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
        budget: rawBeforeConsentNetworkCapture.budget ?? null,
        warnings: rawBeforeConsentNetworkCapture.warnings ?? [],
        errors: [`Before-consent capture finalization failed: ${error.message}`]
      };
    }
  }
  const consentReconciliation = verifyConsentReconciliation(
    negativeRouteConsent?.consent,
    consentInventory,
    [...routeChecks, ...targetRequiredRouteChecks, ...browserRepresentativeRouteChecks],
    beforeConsentNetworkCapture,
    {
      targetOrigin: target?.url?.origin ?? '',
      primaryRoutes,
      stateFingerprint: buildStateReady ? buildState.fingerprint : ''
    }
  );
  liveErrors.push(...consentReconciliation.errors);
  const verifierOwnedAxeErrors = verifierAxeCompletionErrors(globalChromeCapture);
  const verifierOwnedAxeSupportsCompletion = verifierOwnedAxeErrors.length === 0;
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
    drupalRuntimeConfigSyncMatchesHead &&
    drupalRuntimeTrackedConfigReadbackMatches &&
    drupalRuntimeSeoUrlsPortable &&
    buildStateReady;
  const reviewHandoffRequired =
    independentVerification?.summary?.verdict === 'pass' ||
    ['good', 'good_enough'].includes(blindReview?.summary?.verdict);
  const reviewHandoffBindingErrors = reviewHandoffRequired
    ? reviewHandoffStateErrors({
        manifest: reviewHandoff,
        buildMode: briefMode ? 'brief' : 'source_site',
        buildState,
        targetOrigin: target?.url?.origin ?? ''
      })
    : [];
  const reviewHandoffStateValid = reviewHandoffRequired && reviewHandoffBindingErrors.length === 0;
  const completionClaimAllowed =
    packetReport.valid &&
    liveTargetValid &&
    packetSupportsCompletion &&
    verifierOwnedAxeSupportsCompletion &&
    drupalRuntimeSupportsCompletion &&
    reviewHandoffStateValid;
  const completeLocalRebuildClaimAllowed = !briefMode && completionClaimAllowed;
  const completeLocalBuildFromBriefClaimAllowed = briefMode && completionClaimAllowed;
  const completionBlockers = [];
  const addCompletionBlocker = (code, message, options = {}) => {
    completionBlockers.push({
      attemptedEvidence: [],
      missingInput: '',
      nextAction: 'Repair the failing check, refresh affected evidence, and rerun the default live verifier.',
      origin: 'live-verifier',
      resolutionClass: 'agent_resolvable',
      ...options,
      code,
      message
    });
  };
  if (!packetReport.valid) {
    addCompletionBlocker('packet.validation', 'Packet validation failed.');
  }
  if (!liveTargetValid) {
    addCompletionBlocker('target.validation', 'Live target identity or route verification failed.');
  }
  if (!briefMode && runtimeAuthoritativeForCompletion && sourceSurfaceCensus.status !== 'passed') {
    addCompletionBlocker(
      'source.census',
      'Verifier-owned source route discovery is incomplete or does not reconcile with route-matrix.json.'
    );
  }
  if (!packetReport.completionEvidence?.independentVerificationSupportsCompletion) {
    addCompletionBlocker(
      'packet.independent-verification',
      'Independent verification evidence does not support completion.'
    );
  }
  if (!packetReport.completionEvidence?.blindAdversarialReviewSupportsCompletion) {
    const externalBlockers = Array.isArray(packetReport.completionEvidence?.externalBlockers)
      ? packetReport.completionEvidence.externalBlockers
      : [];
    if (packetReport.completionEvidence?.externalBlockersOnly === true && externalBlockers.length > 0) {
      completionBlockers.push(...externalBlockers);
    } else {
      addCompletionBlocker(
        'packet.blind-adversarial-review',
        'Blind adversarial review evidence does not support completion.'
      );
      completionBlockers.push(...externalBlockers);
    }
  }
  if (!packetReport.completionEvidence?.packetCompletionReady) {
    addCompletionBlocker(
      'packet.completion-evidence',
      'Required machine-checkable packet evidence is still template-like, unresolved, or incomplete.'
    );
  }
  for (const error of verifierOwnedAxeErrors) {
    addCompletionBlocker('accessibility.axe', error);
  }
  if (!reviewHandoffStateValid) {
    const handoffBlockers = reviewHandoffBindingErrors.length > 0
      ? reviewHandoffBindingErrors
      : ['A state-bound review handoff has not been completed.'];
    for (const error of handoffBlockers) {
      addCompletionBlocker('review-handoff.state', error);
    }
  }
  const runtimeDrushCommandFailures = Array.isArray(inspectedDrupalRuntime.drushCommandFailures)
    ? inspectedDrupalRuntime.drushCommandFailures.filter(Boolean)
    : [];
  for (const failure of runtimeDrushCommandFailures) {
    addCompletionBlocker('runtime.drush', `Drush runtime inspection command failed: ${failure}`);
  }
  if (inspectedDrupalRuntime.confirmed !== true || !drupalRuntimeSiteUuidMatches) {
    // A failed identity readback command must never be reported as an identity mismatch.
    if (inspectedDrupalRuntime.identityReadbackFailed !== true) {
      addCompletionBlocker(
        'runtime.site-uuid',
        'Current DDEV Drupal runtime identity does not match drupal-readback.json siteUuid.'
      );
    }
  }
  if (!drupalRuntimeTargetMatches) {
    addCompletionBlocker(
      'runtime.target-origin',
      'Current DDEV runtime base URL does not match the live target origin.'
    );
  }
  if (!drupalRuntimeFrontPageMatches) {
    addCompletionBlocker(
      'runtime.front-page',
      'Current DDEV front-page setting does not match drupal-readback.json.'
    );
  }
  if (!drupalRuntimeConfigSyncMatches) {
    addCompletionBlocker(
      'runtime.config-sync-directory',
      'Current DDEV config-sync directory does not match drupal-readback.json.'
    );
  }
  if (!drupalRuntimeConfigStatusClean) {
    addCompletionBlocker(
      'runtime.config-status',
      'Current DDEV config status is not clean or could not be verified.'
    );
  }
  if (!drupalRuntimeConfigSyncTracked) {
    addCompletionBlocker(
      'runtime.config-tracking',
      'Current DDEV config-sync and configured Config Split directories do not contain complete Git-tracked YAML evidence.'
    );
  }
  if (!drupalRuntimeConfigSyncMatchesHead) {
    addCompletionBlocker(
      'runtime.config-head',
      'Current DDEV config-sync YAML does not match HEAD; commit or remove staged, modified, deleted, untracked, or ignored sync YAML before completion.'
    );
  }
  if (!drupalRuntimeTrackedConfigReadbackMatches) {
    addCompletionBlocker(
      'runtime.config-readback',
      'Current Git-tracked config evidence does not match drupal-readback.json.'
    );
  }
  if (!buildStateReady) {
    for (const blocker of stateBlockers) {
      addCompletionBlocker('state.fingerprint', blocker);
    }
  }
  if (!drupalRuntimeSeoUrlsPortable) {
    addCompletionBlocker(
      'runtime.seo-portability',
      'Exported SEO configuration contains literal local-environment URLs; use request-aware Drupal tokens or managed media tokens.'
    );
  }
  if (!runtimeAuthoritativeForCompletion) {
    addCompletionBlocker(
      'runtime.non-authoritative',
      'Injected Drupal runtime evidence is non-authoritative and cannot authorize completion.'
    );
  }
  const completionBlockedReasons = completionBlockers.map((blocker) => blocker.message);

  const targetFingerprintInput = JSON.stringify({
    origin: target?.url.origin ?? '',
    sourceSurfaceFingerprint: sourceSurfaceCensus.fingerprint ?? '',
    globalChromeCaptureFingerprint: globalChromeCapture?.captureFingerprint ?? '',
    beforeConsentNetworkCaptureFingerprint: beforeConsentNetworkCapture?.captureFingerprint ?? '',
    negativeRouteCheck: negativeRouteCheck
      ? { bodySha256: negativeRouteCheck.bodySha256 ?? '', path: negativeRouteCheck.path, status: negativeRouteCheck.status ?? 0 }
      : null,
    accessWallChecks: accessWallChecks.map((check) => ({ finalUrl: check.finalUrl ?? '', path: check.path, status: check.status ?? 0 })),
    legalPrivacyLinkChecks: legalPrivacyLinkChecks.map((check) => ({ finalUrl: check.finalUrl ?? '', status: check.status ?? 0, url: check.url })),
    consentRuntime: consentInventory,
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
    routeChecks: routeEvidenceManifest,
    nextCycleCleanup: {
      bodySha256: nextCycleCleanupCheck.bodySha256 ?? '',
      finalUrl: nextCycleCleanupCheck.finalUrl ?? '',
      status: nextCycleCleanupCheck.actualStatus ?? 0
    },
    liveNextCycleCensus: {
      candidateKeys: liveNextCycleReconciliation.liveCandidateKeys,
      confirmed: liveNextCycleReconciliation.censusTrusted
    },
    liveEditorSurfaceCensus: {
      fieldKeys: liveEditorSurfaceReconciliation.fieldKeys,
      roleDeclarations: liveEditorSurfaceReconciliation.roleDeclarations,
      confirmed: liveEditorSurfaceReconciliation.censusTrusted,
      passed: liveEditorSurfaceReconciliation.passed
    },
    customCodeInventoryFingerprint: inspectedDrupalRuntime.customCodeInventory?.fingerprint ?? '',
    customCodeQualityResultFingerprint: inspectedDrupalRuntime.customCodeInventory?.qualityAudit?.resultFingerprint ?? '',
    customCodeTestExecutionResultFingerprint: inspectedDrupalRuntime.customCodeInventory?.focusedTestExecution?.resultFingerprint ?? ''
  });
  const sharedPacketReport = {
    ...sharedValue(packetReport, absolutePacketDir),
    packetDir: sharedPacketDirName(absolutePacketDir)
  };
  const sharedBeforeConsentCapture = sharedBeforeConsentNetworkCapture(
    beforeConsentNetworkCapture,
    absolutePacketDir
  );
  const sharedGlobalChrome = sharedGlobalChromeCapture(globalChromeCapture, absolutePacketDir);
  const globalChromeCaptureSummary = captureSummary(sharedGlobalChrome);
  const sharedConsentReconciliation = sharedValue(consentReconciliation, absolutePacketDir);
  if (sharedConsentReconciliation.authoritativeBeforeConsentCapture === true) {
    sharedConsentReconciliation.beforeConsentCaptureFingerprint = sharedBeforeConsentCapture.captureFingerprint;
  }
  const liveGateFindings = [
    ...sharedPacketReport.errors,
    ...(sharedPacketReport.completionEvidence?.packetCompletionBlockedReasons ?? []),
    ...liveErrors.map((error) => `G-VERIFY-02 ${sharedMessage(error, absolutePacketDir)}`),
    ...completionBlockedReasons.map((reason) => `G-VERIFY-02 ${sharedMessage(reason, absolutePacketDir)}`)
  ];

  return publicRedactedValue({
    schemaVersion: 'public-kit.live-verification.2',
    checkedAt: new Date().toISOString(),
    buildMode: briefMode ? 'brief' : 'source_site',
    claimScope,
    productionReadinessEvaluated: false,
    launchReady: false,
    verificationMode: 'live-target-and-packet',
    gateResults: perGateResults(gates, liveGateFindings, { mode: 'live' }),
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
      customCodeInventorySha256: inspectedDrupalRuntime.customCodeInventory?.fingerprint ?? '',
      customCodeQualityResultSha256: inspectedDrupalRuntime.customCodeInventory?.qualityAudit?.resultFingerprint ?? '',
      customCodeTestExecutionResultSha256: inspectedDrupalRuntime.customCodeInventory?.focusedTestExecution?.resultFingerprint ?? '',
      liveEditorSurfaceCensusSha256: `sha256:${sha256(JSON.stringify(inspectedDrupalRuntime.liveEditorSurfaceCensus ?? null))}`,
      liveNextCycleCensusSha256: `sha256:${sha256(JSON.stringify(inspectedDrupalRuntime.liveNextCycleCensus ?? null))}`,
      sourceSurfaceSha256: sourceSurfaceCensus.fingerprint ?? '',
      routeMatrixSha256: `sha256:${sha256(routeMatrixText)}`,
      packetEvidenceSha256: buildState?.evidenceBindings?.packetFingerprint ?? '',
      targetFingerprintInputVersion: 7
    },
    criticalAssetInspection: {
      distinctRequestCount: criticalAssetContext.cache.size,
      totalBytes: criticalAssetContext.totalBytes,
      limits: {
        requestCount: criticalAssetContext.maxRequests,
        perAssetBytes: criticalAssetContext.maxAssetBytes,
        totalBytes: criticalAssetContext.maxTotalBytes,
        concurrency: liveHttpBudget.maxConcurrency,
        wallClockMs: liveHttpBudget.deadlineMs
      },
      sharesLiveHttpBudget: true
    },
    routeChecks: routeChecks.map((route) => sharedRouteCheck(route, absolutePacketDir)),
    sourceSurfaceCensus: sharedValue(sourceSurfaceCensus, absolutePacketDir),
    targetRequiredRouteChecks: targetRequiredRouteChecks.map((route) => sharedRouteCheck(route, absolutePacketDir)),
    globalChromeCapture: sharedGlobalChrome,
    globalChromeCaptureSummary,
    verifierOwnedAccessibility: {
      authority: 'verifier-owned-global-chrome',
      ...globalChromeCaptureSummary.verifierAxe,
      passed: verifierOwnedAxeSupportsCompletion,
      errors: verifierOwnedAxeErrors
    },
    beforeConsentNetworkCapture: sharedBeforeConsentCapture,
    negativeRouteCheck: sharedValue(negativeRouteCheck, absolutePacketDir),
    accessWallChecks: sharedValue(accessWallChecks, absolutePacketDir),
    legalPrivacyLinkChecks: sharedValue(legalPrivacyLinkChecks, absolutePacketDir),
    consentReconciliation: sharedConsentReconciliation,
    browserRepresentativeRouteChecks: browserRepresentativeRouteChecks.map((route) => sharedRouteCheck(route, absolutePacketDir)),
    serverRenderedResponseSurface: sharedValue(serverRenderedResponseSurface, absolutePacketDir),
    redirectMappingConflicts: redirectMaterialization.conflicts,
    redirectMaterializationChecks: sharedValue(redirectMaterializationChecks, absolutePacketDir),
    liveHttpBudget,
    liveRouteBudget: liveRouteSchedule.budget,
    nextCycleCleanupCheck,
    liveEditorSurfaceReconciliation,
    liveNextCycleReconciliation,
    liveTargetValid,
    buildState,
    reviewHandoffBinding: {
      attribution: 'builder-writable-self-attested-non-authoritative',
      digest: reviewHandoff?.handoffDigest ?? '',
      errors: reviewHandoffBindingErrors,
      required: reviewHandoffRequired,
      valid: reviewHandoffStateValid
    },
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
    completeLocalBuildFromBriefClaimAllowed,
    verdict: completionClaimAllowed
      ? claimScope
      : packetReport.valid && liveTargetValid
        ? 'machine-incomplete'
        : 'blocked',
    agentContinuation: agentContinuation({
      complete: completionClaimAllowed,
      claimLabel: claimScope,
      blockers: completionBlockers
    }),
    completionBlockers,
    completionBlockedReasons,
    valid: packetReport.valid && liveTargetValid,
    errors: [...sharedPacketReport.errors, ...liveErrors.map((error) => sharedMessage(error, absolutePacketDir))],
    warnings: sharedPacketReport.warnings
  });
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
    const completionClaimAllowed =
      report.completeLocalRebuildClaimAllowed === true ||
      report.completeLocalBuildFromBriefClaimAllowed === true;
    const operationCanRun = !args.changeId || completionClaimAllowed;
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
      completionClaimAllowed &&
      report.lifecycle.currentStateVerified === true;
    report.currentStateBlockedReasons = report.lifecycle.currentStateVerified
      ? []
      : report.lifecycle.relation === 'changed-since-latest-anchor' &&
          report.lifecycle.currentStateClassification?.kind === 'unclassified'
        ? ['Current state differs from the latest lifecycle anchor and has no classified repair or extension; revert it or begin with explicit --adopt-current classification.']
        : ['Current derived state is not yet verified against its lifecycle baseline or checkpoint.'];
    reconcileLifecycleContinuation(report, { baseCompletionAllowed: completionClaimAllowed });
  }
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, `${JSON.stringify(report, null, 2)}\n`);

  if (!report.valid) {
    process.stderr.write(`${args.packetOnly ? 'Packet' : 'Live target'} verification failed. Report: ${args.out}\n`);
    for (const error of report.errors) {
      process.stderr.write(`- ${error}\n`);
    }
    if (!args.packetOnly) {
      process.stderr.write(`Agent action: ${report.agentContinuation.instruction}\n`);
    }
    process.exitCode = 1;
    return;
  }
  if (args.packetOnly) {
    process.stdout.write(`Packet structure valid; packet-only verification never authorizes completion. Report: ${args.out}\n`);
  } else if (
    (report.completeLocalRebuildClaimAllowed || report.completeLocalBuildFromBriefClaimAllowed) &&
    report.currentSiteClaimAllowed
  ) {
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
    const claimDescription = report.claimScope === 'complete-local-build-from-brief'
      ? 'complete local build-from-brief'
      : 'complete local rebuild';
    const recordedStatusLabel = report.claimScope === 'complete-local-build-from-brief'
      ? 'local-build'
      : 'local-rebuild';
    process.stdout.write(`Live target and packet verification passed; ${claimDescription} machine claim authorized for the lifecycle-verified current state (independence evidence: ${independenceSummary}; recorded ${recordedStatusLabel} operator/maintainer status: ${recordedHumanStatus}, self-attested record only).${lifecycleNote} Report: ${args.out}\n`);
  } else {
    const baselineNote = report.lifecycle?.initialBaseline?.status === 'passed'
      ? ' The create-once, integrity-checked initial baseline remains passed; the current derived state is not yet verified.'
      : '';
    const completionClaimAllowed =
      report.completeLocalRebuildClaimAllowed || report.completeLocalBuildFromBriefClaimAllowed;
    const claimDescription = report.claimScope === 'complete-local-build-from-brief'
      ? 'complete local build-from-brief'
      : 'complete local rebuild';
    const reason = completionClaimAllowed && !report.currentSiteClaimAllowed
      ? `Full ${claimDescription} checks passed, but the changed current state is not classified and lifecycle-verified.`
      : `Live target checks passed, but ${claimDescription} machine authorization remains blocked by required machine evidence.`;
    process.stderr.write(`${reason}${baselineNote} Report: ${args.out}\n`);
    process.stderr.write(`Agent action: ${report.agentContinuation.instruction}\n`);
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
