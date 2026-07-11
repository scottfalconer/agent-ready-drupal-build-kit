#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validatePacket } from './verify-packet.mjs';

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
const MAX_LIVE_ROUTE_CHECKS = 1_000;
const MAX_LIVE_ROUTE_CONCURRENCY = 12;
const MAX_LIVE_HTTP_REQUESTS = 2_000;
const MAX_LIVE_HTTP_TASKS = 20_000;
const LIVE_ROUTE_DEADLINE_MS = 90_000;
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

function ddevTargetDescription(cwd) {
  try {
    const output = execFileSync('ddev', ['describe', '-j'], {
      cwd,
      encoding: 'utf8',
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

function ddevTargetUrl(cwd) {
  return ddevTargetDescription(cwd).primaryUrl;
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

function inspectDrupalRuntime(cwd, environment) {
  const projectRoot = findDrupalDdevRoot(cwd);
  if (!projectRoot) {
    return {
      baseUrl: '',
      confirmed: false,
      configStatusClean: false,
      configSyncTracked: false,
      configSyncDirectory: '',
      frontPage: '',
      mode: 'unavailable',
      reason: 'Current working directory is not inside a DDEV Drupal project.',
      siteUuid: '',
      trackedConfigDirectory: '',
      trackedConfigYamlFiles: [],
      exportedSeoUrlPortabilityFindings: [],
      webOrigins: []
    };
  }
  const inContainer = Boolean(environment.DDEV_PRIMARY_URL || environment.DDEV_PROJECT || environment.DDEV_SITENAME);
  const bootstrap = runDrush(projectRoot, environment, ['status', '--field=bootstrap']);
  const uuidOutput = runDrush(projectRoot, environment, ['config:get', 'system.site', '--field=uuid']);
  const frontPage = cleanScalar(
    runDrush(projectRoot, environment, ['config:get', 'system.site', 'page.front', '--format=string'])
  );
  const configSyncDirectory = cleanScalar(
    runDrush(projectRoot, environment, ['status', '--field=config-sync'])
  );
  const drupalRoot = cleanScalar(runDrush(projectRoot, environment, ['status', '--field=root']));
  const configStatus = runDrushResult(projectRoot, environment, ['config:status', '--format=json']);
  const trackedConfig = trackedConfigEvidence(projectRoot, configSyncDirectory, drupalRoot);
  const siteUuid = uuidOutput.match(UUID_RE)?.[0]?.toLowerCase() ?? '';
  const confirmed = /successful/i.test(bootstrap) && Boolean(siteUuid);
  const describedTarget = inContainer
    ? { primaryUrl: environmentTargetUrl(environment), webOrigins: environmentWebOrigins(environment) }
    : ddevTargetDescription(projectRoot);
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
    configSyncTracked: trackedConfig.confirmed,
    configSyncDirectory,
    drupalRoot,
    frontPage,
    mode: inContainer ? 'ddev-container' : 'ddev-host',
    project: basename(projectRoot),
    reason: confirmed ? '' : 'Drupal did not bootstrap or expose a valid system.site UUID through Drush.',
    siteUuid,
    trackedConfigDirectory: trackedConfig.directory,
    trackedConfigYamlFiles: trackedConfig.yamlFiles,
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
  cwd = process.cwd(),
  environment = process.env,
  drupalRuntime = null,
  liveHttpLimits = {}
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
  const inspectedDrupalRuntime = drupalRuntime ?? inspectDrupalRuntime(cwd, environment);
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
  const drupalRuntimeTrackedConfigReadbackMatches =
    Boolean(packetTrackedConfigDirectory) &&
    packetTrackedConfigDirectory === runtimeTrackedConfigDirectory &&
    packetTrackedConfigYamlFiles.length > 0 &&
    packetTrackedConfigYamlFiles.every((path) => runtimeTrackedConfigSet.has(path));
  const runtimeSeoUrlPortabilityFindings = Array.isArray(inspectedDrupalRuntime.exportedSeoUrlPortabilityFindings)
    ? inspectedDrupalRuntime.exportedSeoUrlPortabilityFindings
    : [];
  const drupalRuntimeSeoUrlsPortable = runtimeSeoUrlPortabilityFindings.length === 0;
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
    drupalRuntimeSeoUrlsPortable;
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
    completionBlockedReasons.push('Current DDEV config-sync directory does not contain real Git-tracked YAML files.');
  }
  if (!drupalRuntimeTrackedConfigReadbackMatches) {
    completionBlockedReasons.push('Current Git-tracked config evidence does not match drupal-readback.json.');
  }
  if (!drupalRuntimeSeoUrlsPortable) {
    completionBlockedReasons.push('Exported SEO configuration contains literal local-environment URLs; use request-aware Drupal tokens or managed media tokens.');
  }
  if (!runtimeAuthoritativeForCompletion) {
    completionBlockedReasons.push('Injected Drupal runtime evidence is non-authoritative and cannot authorize completion.');
  }

  const targetFingerprintInput = JSON.stringify({
    origin: target?.url.origin ?? '',
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
    routeChecks: [...routeChecks, ...targetRequiredRouteChecks, ...browserRepresentativeRouteChecks].map((route) => ({
      bodySha256: route.bodySha256 ?? '',
      finalUrl: route.finalUrl ?? '',
      h1: route.actualH1 ?? '',
      path: route.targetPath,
      status: route.finalStatus ?? 0,
      title: route.actualTitle ?? ''
    }))
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
      targetFingerprintInputVersion: 3
    },
    routeChecks,
    targetRequiredRouteChecks,
    browserRepresentativeRouteChecks,
    serverRenderedResponseSurface,
    redirectMappingConflicts: redirectMaterialization.conflicts,
    redirectMaterializationChecks,
    liveHttpBudget,
    liveRouteBudget: liveRouteSchedule.budget,
    liveTargetValid,
    drupalRuntime: {
      ...inspectedDrupalRuntime,
      authoritativeForCompletion: runtimeAuthoritativeForCompletion,
      baseUrl: inspectedDrupalRuntime.baseUrl ? redactedUrl(inspectedDrupalRuntime.baseUrl) : '',
      configStatusClean: drupalRuntimeConfigStatusClean,
      configSyncTracked: drupalRuntimeConfigSyncTracked,
      configSyncDirectory: sharedConfigSyncDirectory(inspectedDrupalRuntime.configSyncDirectory),
      configSyncDirectoryMatchesPacket: drupalRuntimeConfigSyncMatches,
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
