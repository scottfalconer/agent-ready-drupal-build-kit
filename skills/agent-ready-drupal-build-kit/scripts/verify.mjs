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
  --packet <path>           Review packet directory (default: review-packet)
  --target-url <url>        Explicit target URL (otherwise detect current DDEV target)
  --out <path>              Report path (default: review-packet/evidence/live-verification.json)
  --route-sample-seed <s>   Seed for the full-route-matrix sample (default: random, recorded in the report)
  --packet-only             Run structural packet lint only; never authorizes completion
  --help                    Show this help`;
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 15_000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i;
// Sampling the full routes array on every run (fresh seed, recorded for reproducibility)
// defeats teaching-to-the-test against the fixed primaryRoutes list.
const ROUTE_SAMPLE_RATE = 0.15;
const ROUTE_SAMPLE_MIN = 3;
const LINK_CRAWL_CONTENT_PAGE_COUNT = 5;
const LIVE_FETCH_CONCURRENCY = 8;
const PER_LINK_RECORD_FIELDS = ['menuAndFooterLinksChecked', 'renderedLinksChecked'];
const NON_ROUTE_LINK_EXTENSION_RE =
  /\.(?:7z|avif|bmp|css|docx?|eot|gif|gz|ico|jpe?g|js|json|m4[av]|mjs|mov|mp[34]|ogg|otf|pdf|png|pptx?|rar|svg|tar|tiff?|ttf|txt|wav|webm|webp|woff2?|xlsx?|xml|zip)$/i;

class UsageError extends Error {}

function parseArgs(argv) {
  const args = { packet: 'review-packet', out: '', packetOnly: false, routeSampleSeed: '', targetUrl: '' };
  const valueOptions = new Map([
    ['--packet', 'packet'],
    ['--out', 'out'],
    ['--route-sample-seed', 'routeSampleSeed'],
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

async function requestFollowingRedirects(startUrl, { allowCrossOriginRedirect = false } = {}) {
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
        if (allowCrossOriginRedirect) {
          // Stop at the boundary: report the redirect response itself and the
          // off-origin destination without fetching the other origin.
          return {
            ...response,
            crossOriginLocation: next.href,
            finalUrl: current.href,
            initialStatus: redirects[0]?.status ?? response.status,
            localTlsVerificationBypassed,
            redirects
          };
        }
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
      trackedConfigYamlFiles: []
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
  const baseUrl = inContainer ? environmentTargetUrl(environment) : ddevTargetUrl(projectRoot);
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

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function requestUrlForPath(baseUrl, path) {
  return new URL(String(path ?? '').replace(/^\//, ''), new URL('/', baseUrl));
}

// Like normalizePath but preserves the query string, so query-differentiated
// legacy routes (`/CivicAlerts.aspx?AID=1` vs `?AID=2`) stay distinct.
function pathWithQuery(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  let url;
  try {
    url = new URL(text, 'https://relative-path.invalid');
  } catch {
    return '';
  }
  return `${normalizePath(url.pathname)}${url.search}`;
}

function seededRandom(seed) {
  let state = Number.parseInt(sha256(String(seed)).slice(0, 8), 16) >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 0x1_0000_0000;
  };
}

function seededSample(items, sampleSize, random) {
  const pool = [...items];
  for (let index = pool.length - 1; index > 0; index -= 1) {
    const swap = Math.floor(random() * (index + 1));
    [pool[index], pool[swap]] = [pool[swap], pool[index]];
  }
  return pool.slice(0, Math.max(0, sampleSize));
}

async function mapWithConcurrency(items, limit, task) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await task(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

function expectedSampledRoute(record) {
  const targetPath = normalizePath(record?.targetPath);
  const declaredStatus = record?.targetStatus;
  const expectedStatus = declaredStatus !== null && declaredStatus !== '' && Number.isFinite(Number(declaredStatus))
    ? Number(declaredStatus)
    : 200;
  return {
    accepted: record?.accepted === true,
    expectedBehavior: record?.expectedRedirect === true ? 'redirect' : 'public_200',
    expectedFinalPath: normalizePath(record?.targetFinalPath || targetPath),
    expectedH1: normalizeText(record?.targetH1),
    expectedStatus,
    expectedTitle: normalizeText(record?.targetTitle),
    identityRequired: false,
    matchesBrowserRenderedSource: true,
    renderedSeo: null,
    routeKind: 'sampled',
    statusUsesInitialResponse: record?.expectedRedirect === true,
    targetPath
  };
}

function anchorHrefs(html) {
  return matchingTags(html, 'a', () => true)
    .map((attributes) => String(attributes.href ?? '').trim())
    .filter(Boolean);
}

function sameOriginLinkPath(href, pageUrl, targetOrigin) {
  let url;
  try {
    url = new URL(href, pageUrl);
  } catch {
    return '';
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.origin !== targetOrigin ||
    NON_ROUTE_LINK_EXTENSION_RE.test(url.pathname)
  ) {
    return '';
  }
  return `${normalizePath(url.pathname)}${url.search}`;
}

function acceptedBrokenLinkDisposition(record) {
  return record?.disposition === 'owner_accepted_broken' &&
    Boolean(String(record?.acceptedBy ?? '').trim()) &&
    Boolean(String(record?.rationale ?? '').trim());
}

function acceptedBrokenLinkDispositions(routeMatrix) {
  const dispositions = new Map();
  for (const field of PER_LINK_RECORD_FIELDS) {
    for (const record of arrayOrEmpty(routeMatrix?.[field])) {
      if (record && typeof record === 'object' && !Array.isArray(record) && acceptedBrokenLinkDisposition(record)) {
        // Key by path plus query string so a disposition excuses exactly one
        // link, not every query variant of the same path.
        const path = pathWithQuery(record.href);
        if (path) {
          dispositions.set(path, {
            acceptedBy: String(record.acceptedBy).trim(),
            field,
            rationale: String(record.rationale).trim()
          });
        }
      }
    }
  }
  return dispositions;
}

function declaredPerLinkEntries(routeMatrix) {
  const entries = [];
  for (const field of PER_LINK_RECORD_FIELDS) {
    for (const entry of arrayOrEmpty(routeMatrix?.[field])) {
      const isRecord = Boolean(entry) && typeof entry === 'object' && !Array.isArray(entry);
      const isUntouchedTemplateRow = isRecord && !Object.values(entry).some((value) =>
        (typeof value === 'string' && value.trim()) ||
        (typeof value === 'number' && Number.isFinite(value)) ||
        value === true
      );
      if (!isUntouchedTemplateRow) {
        entries.push({ entry, field });
      }
    }
  }
  return entries;
}

async function verifyDeclaredLink(baseUrl, field, record) {
  const label = `route-matrix.json ${field}`;
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    return {
      errors: [`${label} entry ${JSON.stringify(record)} is a bare label; per-link records with href, observed status, and finalPath are required.`],
      field,
      href: typeof record === 'string' ? record : '',
      passed: false
    };
  }
  const errors = [];
  const href = String(record.href ?? '').trim();
  if (record.disposition === 'external') {
    // Cross-origin links are recorded, not fetched: the live verifier never
    // leaves the target origin, so it only validates that the record names an
    // absolute off-origin destination.
    let externalUrl = null;
    try {
      externalUrl = new URL(href);
    } catch {
      externalUrl = null;
    }
    if (!externalUrl || !['http:', 'https:'].includes(externalUrl.protocol)) {
      errors.push(`${label} external link record ${JSON.stringify(href || record)} must record the absolute http(s) URL of the external destination.`);
    } else if (externalUrl.origin === baseUrl.origin) {
      errors.push(`${label} href ${JSON.stringify(href)} resolves to the live target origin; record it with observed status and finalPath instead of an external disposition.`);
    }
    return { disposition: 'external', errors, field, href, passed: errors.length === 0 };
  }
  const declaredStatus = record.status === null || record.status === '' ? Number.NaN : Number(record.status);
  const declaredFinalPath = normalizePath(record.finalPath);
  let requestPath = '';
  if (href) {
    try {
      const url = new URL(href, new URL('/', baseUrl));
      if (['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && url.origin === baseUrl.origin) {
        requestPath = `${url.pathname}${url.search}`;
      }
    } catch {
      // An unparsable href cannot be re-fetched and fails below.
    }
  }
  if (!href || !Number.isFinite(declaredStatus) || !declaredFinalPath) {
    errors.push(`${label} entry ${JSON.stringify(href || record)} must declare href, the observed HTTP status, and finalPath.`);
  } else if (!requestPath) {
    errors.push(`${label} href ${JSON.stringify(href)} does not resolve to a fetchable same-origin route on the live target; record off-origin links with disposition "external" and the absolute href.`);
  }
  if (Number.isFinite(declaredStatus) && declaredStatus >= 400 && !acceptedBrokenLinkDisposition(record)) {
    errors.push(`${label} href ${JSON.stringify(href)} declares HTTP ${declaredStatus} without an owner_accepted_broken disposition naming acceptedBy and a rationale.`);
  }
  if (errors.length > 0) {
    return { errors, field, href, passed: false };
  }
  try {
    const response = await requestFollowingRedirects(requestUrlForPath(baseUrl, requestPath), {
      allowCrossOriginRedirect: true
    });
    const actualStatus = REDIRECT_STATUSES.has(declaredStatus) ? response.initialStatus : response.status;
    if (actualStatus !== declaredStatus) {
      errors.push(`${label} href ${JSON.stringify(href)} returned status ${actualStatus}; the packet record declares ${declaredStatus}.`);
    }
    if (response.crossOriginLocation) {
      // A same-origin link that redirects off-origin (vanity /go/* links) must
      // declare the absolute external destination as finalPath.
      if (String(record.finalPath ?? '').trim() !== response.crossOriginLocation) {
        errors.push(`${label} href ${JSON.stringify(href)} redirects off-origin to ${response.crossOriginLocation}; the packet record must declare that absolute URL as finalPath.`);
      }
    } else if (normalizePath(response.finalUrl) !== declaredFinalPath) {
      errors.push(`${label} href ${JSON.stringify(href)} resolved to ${normalizePath(response.finalUrl)}; the packet record declares ${declaredFinalPath}.`);
    }
    return { actualStatus, errors, field, finalUrl: response.finalUrl, href, passed: errors.length === 0 };
  } catch (error) {
    errors.push(`${label} href ${JSON.stringify(href)} could not be fetched: ${error.message}`);
    return { errors, field, href, passed: false };
  }
}

async function fetchCrawlPage(baseUrl, path) {
  try {
    const response = await requestFollowingRedirects(requestUrlForPath(baseUrl, path));
    return response.status >= 200 && response.status < 300
      ? { finalUrl: response.finalUrl, html: response.body }
      : null;
  } catch {
    return null;
  }
}

async function verifyCrawledLink(baseUrl, link, dispositions) {
  const errors = [];
  const disposition = dispositions.get(link.path) ?? null;
  const foundOn = [...link.foundOn].sort();
  const record = {
    dispositionAccepted: Boolean(disposition),
    dispositionAcceptedBy: disposition?.acceptedBy ?? '',
    foundOn,
    path: link.path
  };
  try {
    const response = await requestFollowingRedirects(requestUrlForPath(baseUrl, link.path), {
      allowCrossOriginRedirect: true
    });
    if (response.crossOriginLocation) {
      // A same-origin link that intentionally redirects off-origin (vanity
      // /go/* links) is not a broken route; record where it went and move on.
      return {
        ...record,
        crossOriginLocation: response.crossOriginLocation,
        errors,
        finalPath: '',
        passed: true,
        status: response.status
      };
    }
    if ((response.status < 200 || response.status >= 400) && !disposition) {
      errors.push(`Rendered link ${link.path} (found on ${foundOn.join(', ')}) returned HTTP ${response.status}; rewrite the link or record an owner_accepted_broken disposition in route-matrix.json.`);
    }
    return { ...record, errors, finalPath: normalizePath(response.finalUrl), passed: errors.length === 0, status: response.status };
  } catch (error) {
    if (!disposition) {
      errors.push(`Rendered link ${link.path} (found on ${foundOn.join(', ')}) could not be fetched: ${error.message}`);
    }
    return { ...record, errors, finalPath: '', passed: errors.length === 0, status: 0 };
  }
}

function redirectMaterializationExpectations(routeMatrix) {
  // Source paths keep their query strings: `/CivicAlerts.aspx?AID=1` and
  // `?AID=2` are distinct mappings that are each verified, and two rows that
  // declare the same source path with different targets conflict loudly
  // instead of silently collapsing to whichever row happens to come first.
  const conflicts = [];
  const expectations = new Map();
  const addExpectation = (candidate) => {
    const existing = expectations.get(candidate.sourcePath);
    if (existing) {
      if (existing.expectedFinalPath !== candidate.expectedFinalPath) {
        conflicts.push(`route-matrix.json maps ${candidate.sourcePath} to both ${existing.expectedFinalPath} (${existing.declaredIn}) and ${candidate.expectedFinalPath} (${candidate.declaredIn}); reconcile the duplicate mapping before verification.`);
      }
      return;
    }
    expectations.set(candidate.sourcePath, candidate);
  };
  for (const row of arrayOrEmpty(routeMatrix?.routes)) {
    const sourcePath = pathWithQuery(row?.sourcePath);
    const targetPath = normalizePath(row?.targetPath);
    if (!sourcePath || !targetPath || sourcePath === pathWithQuery(row?.targetPath)) {
      continue;
    }
    const disposition = row?.noRedirectDisposition;
    const dispositionAccepted =
      Boolean(String(disposition?.acceptedBy ?? '').trim()) &&
      Boolean(String(disposition?.rationale ?? '').trim());
    addExpectation({
      declaredIn: 'routes',
      expectedFinalPath: normalizePath(row?.targetFinalPath || row?.targetPath),
      noRedirectDisposition: dispositionAccepted
        ? { acceptedBy: String(disposition.acceptedBy).trim(), rationale: String(disposition.rationale).trim() }
        : null,
      sourcePath
    });
  }
  for (const record of arrayOrEmpty(routeMatrix?.sourceRouteDriftClassification)) {
    const sourcePath = pathWithQuery(record?.sourcePath);
    const targetPath = normalizePath(record?.targetPath);
    if (
      record?.targetDisposition !== 'redirect' ||
      !sourcePath ||
      !targetPath ||
      sourcePath === pathWithQuery(record?.targetPath)
    ) {
      continue;
    }
    addExpectation({
      declaredIn: 'sourceRouteDriftClassification',
      expectedFinalPath: targetPath,
      noRedirectDisposition: null,
      sourcePath
    });
  }
  return { conflicts, expectations: [...expectations.values()] };
}

async function verifyRedirectMaterialization(baseUrl, expectation) {
  if (expectation.noRedirectDisposition) {
    return { ...expectation, checked: false, errors: [], passed: true };
  }
  const errors = [];
  try {
    const response = await requestFollowingRedirects(requestUrlForPath(baseUrl, expectation.sourcePath));
    if (response.initialStatus !== 301 && response.initialStatus !== 308) {
      errors.push(`${expectation.sourcePath} is mapped to ${expectation.expectedFinalPath} in ${expectation.declaredIn} but returned initial status ${response.initialStatus} on the target; materialize a permanent HTTP 301 (or 308) redirect or record a noRedirectDisposition with acceptedBy and a rationale.`);
    }
    if (normalizePath(response.finalUrl) !== expectation.expectedFinalPath) {
      errors.push(`${expectation.sourcePath} resolved to ${normalizePath(response.finalUrl)}; the declared mapping expects ${expectation.expectedFinalPath}.`);
    }
    return {
      ...expectation,
      checked: true,
      errors,
      finalPath: normalizePath(response.finalUrl),
      initialStatus: response.initialStatus,
      passed: errors.length === 0
    };
  } catch (error) {
    errors.push(`${expectation.sourcePath} is mapped to ${expectation.expectedFinalPath} but could not be verified on the target: ${error.message}`);
    return { ...expectation, checked: true, errors, passed: false };
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
  const requestedUrl = requestUrlForPath(baseUrl, expected.targetPath);
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
      passed: errors.length === 0,
      redirects: response.redirects,
      requestedUrl: requestedUrl.href
    };
  } catch (error) {
    errors.push(`${expected.targetPath} could not be fetched: ${error.message}`);
    return { ...expected, errors, passed: false, requestedUrl: requestedUrl.href };
  }
}

export async function verifyLive({
  packetDir = 'review-packet',
  targetUrl = '',
  cwd = process.cwd(),
  environment = process.env,
  drupalRuntime = null,
  routeSampleSeed = ''
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

  const fetchChecksEnabled = Boolean(target) && explicitTargetFetchAllowed;
  const routeRows = arrayOrEmpty(routeMatrix.routes);
  const verifiedTargetPaths = new Set(
    [
      ...primaryRoutes.map((route) => normalizePath(route?.targetPath || route?.sourcePath)),
      ...targetRequiredRoutes.map((route) => normalizePath(route?.targetPath))
    ].filter(Boolean)
  );
  const sampleSeed = String(routeSampleSeed ?? '').trim() ||
    `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  const random = seededRandom(sampleSeed);
  const samplePopulation = [];
  const samplePopulationPaths = new Set();
  for (const row of routeRows) {
    const rowTargetPath = normalizePath(row?.targetPath);
    if (!rowTargetPath) {
      // A blank targetPath would silently shrink the sample population and
      // skip redirect materialization, so it is a hard live failure, not a
      // skip: the packet verifier rejects the same shape.
      const rowLabel = normalizePath(row?.sourcePath) || JSON.stringify(row?.sourcePath ?? row ?? null);
      liveErrors.push(`route-matrix.json routes row for ${rowLabel} has no targetPath; every route row must declare a non-empty target path so it stays in the verifiable sample population.`);
      continue;
    }
    if (verifiedTargetPaths.has(rowTargetPath) || samplePopulationPaths.has(rowTargetPath)) {
      continue;
    }
    samplePopulationPaths.add(rowTargetPath);
    samplePopulation.push(row);
  }
  const sampleSize = Math.min(
    samplePopulation.length,
    Math.max(ROUTE_SAMPLE_MIN, Math.ceil(samplePopulation.length * ROUTE_SAMPLE_RATE))
  );
  const sampledRows = seededSample(samplePopulation, sampleSize, random);
  const sampledTargetPaths = sampledRows.map((row) => normalizePath(row?.targetPath));
  const sampledRouteChecks = fetchChecksEnabled
    ? await mapWithConcurrency(sampledRows, LIVE_FETCH_CONCURRENCY, (row) =>
        verifyRoute(target.url, expectedSampledRoute(row)))
    : [];
  for (const route of sampledRouteChecks) {
    liveErrors.push(...route.errors);
  }
  for (const path of sampledTargetPaths) {
    verifiedTargetPaths.add(path);
  }

  const brokenLinkDispositions = acceptedBrokenLinkDispositions(routeMatrix);
  const renderedLinkCrawl = { checks: [], crawledPages: [], discoveredSameOriginLinkCount: 0 };
  if (fetchChecksEnabled) {
    const crawlSeedPaths = [
      '/',
      ...sampledTargetPaths.filter((path) => path && path !== '/').slice(0, LINK_CRAWL_CONTENT_PAGE_COUNT)
    ];
    const discoveredLinks = new Map();
    for (const seedPath of crawlSeedPaths) {
      const page = await fetchCrawlPage(target.url, seedPath);
      if (!page) {
        if (seedPath === '/') {
          liveErrors.push('The front page could not be crawled for rendered same-origin links.');
        }
        continue;
      }
      renderedLinkCrawl.crawledPages.push(seedPath);
      for (const href of anchorHrefs(page.html)) {
        const linkPath = sameOriginLinkPath(href, page.finalUrl, target.url.origin);
        if (!linkPath) {
          continue;
        }
        const existing = discoveredLinks.get(linkPath);
        if (existing) {
          existing.foundOn.add(seedPath);
        } else {
          discoveredLinks.set(linkPath, { foundOn: new Set([seedPath]), path: linkPath });
        }
      }
    }
    renderedLinkCrawl.discoveredSameOriginLinkCount = discoveredLinks.size;
    // Match on the full path including any query string: `/foo?page=2` must
    // still be fetched even when `/foo` was already verified as a route.
    const crawlTargets = [...discoveredLinks.values()].filter(
      (link) => !verifiedTargetPaths.has(link.path)
    );
    renderedLinkCrawl.checks = await mapWithConcurrency(crawlTargets, LIVE_FETCH_CONCURRENCY, (link) =>
      verifyCrawledLink(target.url, link, brokenLinkDispositions));
    for (const check of renderedLinkCrawl.checks) {
      liveErrors.push(...check.errors);
    }
  }

  const declaredLinkChecks = fetchChecksEnabled
    ? await mapWithConcurrency(declaredPerLinkEntries(routeMatrix), LIVE_FETCH_CONCURRENCY, ({ entry, field }) =>
        verifyDeclaredLink(target.url, field, entry))
    : [];
  for (const check of declaredLinkChecks) {
    liveErrors.push(...check.errors);
  }

  const redirectMaterialization = redirectMaterializationExpectations(routeMatrix);
  liveErrors.push(...redirectMaterialization.conflicts);
  const redirectMaterializationChecks = fetchChecksEnabled
    ? await mapWithConcurrency(
        redirectMaterialization.expectations,
        LIVE_FETCH_CONCURRENCY,
        (expectation) => verifyRedirectMaterialization(target.url, expectation)
      )
    : [];
  for (const check of redirectMaterializationChecks) {
    liveErrors.push(...check.errors);
  }

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
  const drupalRuntimeSupportsCompletion =
    runtimeAuthoritativeForCompletion &&
    inspectedDrupalRuntime.confirmed === true &&
    drupalRuntimeTargetMatches &&
    drupalRuntimeSiteUuidMatches &&
    drupalRuntimeFrontPageMatches &&
    drupalRuntimeConfigSyncMatches &&
    drupalRuntimeConfigStatusClean &&
    drupalRuntimeConfigSyncTracked &&
    drupalRuntimeTrackedConfigReadbackMatches;
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
    routeSample: {
      seed: sampleSeed,
      sampleRate: ROUTE_SAMPLE_RATE,
      minimumSampleSize: ROUTE_SAMPLE_MIN,
      // Reviewers can spot population shrinkage (rows blanked or moved into
      // drift classification) by comparing these counts against the packet.
      routeRowCount: routeRows.length,
      driftClassifiedRouteCount: arrayOrEmpty(routeMatrix.sourceRouteDriftClassification).length,
      populationSize: samplePopulation.length,
      sampleSize: sampledRows.length,
      sampledTargetPaths,
      checks: sampledRouteChecks
    },
    renderedLinkCrawl,
    declaredLinkChecks,
    redirectMappingConflicts: redirectMaterialization.conflicts,
    redirectMaterializationChecks,
    liveTargetValid,
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
        routeSampleSeed: args.routeSampleSeed,
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
