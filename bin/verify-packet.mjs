#!/usr/bin/env node
import { existsSync, realpathSync } from 'node:fs';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const KIT_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const USAGE = 'Usage: node bin/verify-packet.mjs --packet review-packet --out review-packet/evidence/packet-verification.json';
const HASH_RE = /^sha256:[a-f0-9]{64}$/;
const BLIND_COMPLETE_VERDICTS = new Set(['good', 'good_enough']);
const GATE_CHECKED_BY = new Set(['human', 'verify-script', 'verifier', 'blind-verifier']);
const BLIND_DEFECT_SEVERITIES = new Set(['blocker', 'critical', 'high', 'medium', 'low']);
const BLIND_DEFECT_STATUSES = new Set(['open', 'fixed', 'accepted_out_of_scope', 'external_blocker']);

class UsageError extends Error {}

function parseArgs(argv) {
  const args = {
    packet: 'review-packet',
    out: ''
  };

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--packet' || arg === '--out') {
      const next = argv[index + 1];
      if (!next || next.startsWith('--')) {
        throw new UsageError(`${arg} requires a value.`);
      }
      if (arg === '--packet') {
        args.packet = next;
      } else {
        args.out = next;
      }
      index += 1;
    } else if (arg.startsWith('--packet=')) {
      const value = arg.slice('--packet='.length);
      if (!value) {
        throw new UsageError('--packet requires a value.');
      }
      args.packet = value;
    } else if (arg.startsWith('--out=')) {
      const value = arg.slice('--out='.length);
      if (!value) {
        throw new UsageError('--out requires a value.');
      }
      args.out = value;
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg.startsWith('-')) {
      throw new UsageError(`Unknown option: ${arg}.`);
    } else {
      throw new UsageError(`Unexpected positional argument: ${arg}.`);
    }
  }

  if (!args.out) {
    args.out = join(args.packet, 'evidence', 'packet-verification.json');
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

async function readJson(path, errors) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    errors.push(`${path} must be valid JSON: ${error.message}`);
    return null;
  }
}

async function hasFiles(path) {
  try {
    return (await readdir(path)).length > 0;
  } catch {
    return false;
  }
}

function isJsonObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function completionAllowed(record) {
  return isJsonObject(record?.summary) && record.summary.completeLocalRebuildClaimAllowed === true;
}

function normalizeRouteKey(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }

  try {
    return new URL(text).pathname || '/';
  } catch {
    return text.split(/[?#]/)[0] || '/';
  }
}

function fileExistsForReviewEvidence(packetDir, evidenceDir, value) {
  const path = String(value ?? '').trim();
  if (!path) {
    return false;
  }

  const candidates = [
    isAbsolute(path) ? path : '',
    join(evidenceDir, path),
    join(packetDir, path),
    join(dirname(packetDir), path)
  ].filter(Boolean);

  return candidates.some((candidate) => existsSync(candidate));
}

function validateGateVocabulary(gates, errors) {
  if (gates?.schemaVersion !== 'public-kit.gates.1') {
    errors.push('gates.json must use schemaVersion public-kit.gates.1.');
  }

  const ids = new Set();
  for (const gate of gates?.gates ?? []) {
    if (!gate.id || ids.has(gate.id)) {
      errors.push(`gates.json has missing or duplicate gate id: ${gate.id || '(missing)'}.`);
    }
    ids.add(gate.id);

    for (const field of ['title', 'phase', 'evidenceFile', 'checkedBy', 'blocking']) {
      if (gate[field] === undefined || gate[field] === '') {
        errors.push(`gate ${gate.id || '(missing)'} is missing ${field}.`);
      }
    }

    if (!gates.reviewPacketFiles.includes(gate.evidenceFile)) {
      errors.push(`gate ${gate.id} evidenceFile ${gate.evidenceFile} is not listed in reviewPacketFiles.`);
    }

    if (!GATE_CHECKED_BY.has(gate.checkedBy)) {
      errors.push(`gate ${gate.id} checkedBy ${gate.checkedBy} is not an allowed gate checker.`);
    }
  }
}

async function validateRequiredFiles(packetDir, gates, errors) {
  for (const file of gates.reviewPacketFiles ?? []) {
    const path = join(packetDir, file);
    if (!existsSync(path)) {
      errors.push(`review packet is missing required file: ${file}.`);
      continue;
    }

    if (file.endsWith('.json')) {
      await readJson(path, errors);
    }
  }
}

function validateIndependentVerification(packetDir, independentVerification, errors) {
  if (!isJsonObject(independentVerification)) {
    errors.push('independent-verification.json must be a JSON object (blocked stub at minimum).');
    return;
  }

  const verifier = independentVerification.verifier ?? {};
  const summary = independentVerification.summary ?? {};
  const degraded =
    verifier.sameContextAsBuilder === true ||
    Boolean(verifier.independenceDegradedReason) ||
    verifier.freshContextUsed === false;

  if (degraded && summary.completeLocalRebuildClaimAllowed !== false) {
    errors.push(
      'independent-verification.json must set summary.completeLocalRebuildClaimAllowed=false when verifier independence is degraded.'
    );
  }

  if (
    summary.completeLocalRebuildClaimAllowed === true &&
    (summary.verdict !== 'pass' || Number(summary.failedClaimCount) > 0 || Number(summary.blockedClaimCount) > 0)
  ) {
    errors.push('independent-verification.json cannot allow a complete rebuild claim with failed or blocked verifier claims.');
  }

  if (summary.completeLocalRebuildClaimAllowed === true) {
    const evidenceDir = join(packetDir, 'evidence', 'independent-verification');
    if (!existsSync(evidenceDir)) {
      errors.push('complete rebuild claims require raw verifier evidence under review-packet/evidence/independent-verification/.');
    }
  }
}

function validateCompletionAgreement(independentVerification, blindReview, errors) {
  const independentAllowsComplete = completionAllowed(independentVerification);
  const blindAllowsComplete = completionAllowed(blindReview);

  if (independentAllowsComplete && !blindAllowsComplete) {
    errors.push(
      'complete local rebuild claims require blind-adversarial-review.json to set summary.completeLocalRebuildClaimAllowed=true.'
    );
  }

  if (blindAllowsComplete && !independentAllowsComplete) {
    errors.push(
      'blind-adversarial-review.json cannot allow a complete rebuild claim unless independent-verification.json also allows it.'
    );
  }
}

async function validateBlindAdversarialReview(packetDir, blindReview, routeMatrix, errors) {
  if (!isJsonObject(blindReview)) {
    errors.push('blind-adversarial-review.json must be a JSON object (blocked stub at minimum).');
    return;
  }

  if (blindReview.schemaVersion !== 'public-kit.blind-adversarial-review.1') {
    errors.push('blind-adversarial-review.json must use schemaVersion public-kit.blind-adversarial-review.1.');
  }

  const reviewer = blindReview.reviewer ?? {};
  const summary = blindReview.summary ?? {};
  const defects = arrayOrEmpty(blindReview.productDefects);
  const routeReviews = arrayOrEmpty(blindReview.routeViewportReviews);
  const reviewPasses = arrayOrEmpty(blindReview.reviewPasses);
  const reviewInputs = blindReview.reviewInputs ?? {};
  const blindAllowsComplete = completionAllowed(blindReview);

  if (!blindAllowsComplete) {
    return;
  }

  const degraded =
    reviewer.freshContextUsed !== true ||
    reviewer.sameContextAsBuilder === true ||
    reviewer.didNotBuildTarget !== true ||
    reviewer.inputsRestrictedToBriefTargetAndSourceTruth !== true ||
    reviewer.implementationFilesReadBeforePublicReview === true ||
    reviewer.reviewPacketReadBeforePublicReview === true ||
    reviewer.priorBuildConversationRead === true ||
    reviewer.builderSummaryExcluded !== true;

  if (degraded) {
    errors.push(
      'blind-adversarial-review.json cannot allow a complete rebuild claim unless the reviewer is fresh, did not build the target, used only brief/target/source-truth inputs before public review, and excluded builder claims.'
    );
  }

  if (!BLIND_COMPLETE_VERDICTS.has(summary.verdict)) {
    errors.push('blind-adversarial-review.json can allow completion only with summary.verdict good or good_enough.');
  }

  const requiredCountFields = ['openBlockerIssueCount', 'openCriticalIssueCount', 'openHighIssueCount'];
  for (const field of requiredCountFields) {
    if (summary[field] === undefined || !Number.isFinite(Number(summary[field]))) {
      errors.push(`blind-adversarial-review.json complete claims require numeric summary.${field}.`);
    }
  }

  const reviewPassIds = new Set();
  for (const [index, pass] of reviewPasses.entries()) {
    if (!isJsonObject(pass)) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] must be an object.`);
      continue;
    }
    if (!String(pass.id ?? '').trim()) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] is missing id.`);
    } else {
      reviewPassIds.add(pass.id);
    }
    if (!String(pass.checkedAt ?? '').trim()) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] is missing checkedAt.`);
    }
    if (!BLIND_COMPLETE_VERDICTS.has(pass.verdict)) {
      errors.push(`blind-adversarial-review.json reviewPasses[${index}] must record a good or good_enough verdict for completion.`);
    }
  }

  if (reviewPasses.length === 0) {
    errors.push('blind-adversarial-review.json complete claims require at least one reviewPasses entry.');
  }

  for (const [index, defect] of defects.entries()) {
    if (!isJsonObject(defect)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] must be an object.`);
      continue;
    }

    if (!BLIND_DEFECT_SEVERITIES.has(defect.severity)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] must have severity blocker, critical, high, medium, or low.`);
    }

    if (defect.status === undefined) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] is missing status; missing status is treated as open.`);
    } else if (!BLIND_DEFECT_STATUSES.has(defect.status)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] has invalid status ${defect.status}.`);
    }

    if (defect.status === 'fixed' && !reviewPassIds.has(defect.resolvedByReviewPassId)) {
      errors.push(`blind-adversarial-review.json productDefects[${index}] marked fixed must name resolvedByReviewPassId from reviewPasses.`);
    }
  }

  const openSevereDefects = defects.filter((defect) =>
    ['blocker', 'critical', 'high'].includes(defect.severity) && (defect.status ?? 'open') === 'open'
  );
  const openBlockerCount = defects.filter((defect) => defect.severity === 'blocker' && (defect.status ?? 'open') === 'open').length;
  const openCriticalCount = defects.filter((defect) => defect.severity === 'critical' && (defect.status ?? 'open') === 'open').length;
  const openHighCount = defects.filter((defect) => defect.severity === 'high' && (defect.status ?? 'open') === 'open').length;

  if (Number(summary.openBlockerIssueCount) !== openBlockerCount) {
    errors.push('blind-adversarial-review.json summary.openBlockerIssueCount must match open blocker defects.');
  }
  if (Number(summary.openCriticalIssueCount) !== openCriticalCount) {
    errors.push('blind-adversarial-review.json summary.openCriticalIssueCount must match open critical defects.');
  }
  if (Number(summary.openHighIssueCount) !== openHighCount) {
    errors.push('blind-adversarial-review.json summary.openHighIssueCount must match open high defects.');
  }

  if (
    openSevereDefects.length > 0 ||
    Number(summary.openBlockerIssueCount) > 0 ||
    Number(summary.openCriticalIssueCount) > 0 ||
    Number(summary.openHighIssueCount) > 0
  ) {
    errors.push('blind-adversarial-review.json cannot allow completion with open blocker, critical, or high product defects.');
  }

  const hasDesktop = routeReviews.some((review) => review.viewport === 'desktop');
  const hasMobile = routeReviews.some((review) => review.viewport === 'mobile');
  const hasRouteNotes = routeReviews.some((review) => String(review.routeNotes ?? '').trim().length > 0);
  const evidenceDir = join(packetDir, 'evidence', 'blind-adversarial-review');

  if (summary.desktopMobileReviewed !== true || !hasDesktop || !hasMobile) {
    errors.push('blind-adversarial-review.json complete claims require desktop and mobile route reviews.');
  }

  if (summary.routeNotesPresent !== true || !hasRouteNotes) {
    errors.push('blind-adversarial-review.json complete claims require route notes from the blind review.');
  }

  if (summary.rawEvidencePresent !== true || !(await hasFiles(evidenceDir))) {
    errors.push('complete rebuild claims require raw blind review evidence under review-packet/evidence/blind-adversarial-review/.');
  }

  for (const [index, review] of routeReviews.entries()) {
    for (const screenshotField of ['sourceScreenshot', 'targetScreenshot']) {
      if (!fileExistsForReviewEvidence(packetDir, evidenceDir, review[screenshotField])) {
        errors.push(`blind-adversarial-review.json routeViewportReviews[${index}].${screenshotField} must reference an existing evidence file.`);
      }
    }
  }

  const primaryRoutes = arrayOrEmpty(routeMatrix?.primaryRoutes)
    .map((route) => normalizeRouteKey(route.targetPath || route.sourcePath || route.route || route.path))
    .filter(Boolean);
  const omittedPrimaryRoutes = arrayOrEmpty(blindReview.routeCoverage?.omittedPrimaryRoutes);
  const acceptedOmissions = new Map(
    omittedPrimaryRoutes
      .filter((route) =>
        String(route.rationale ?? '').trim() &&
        ['accepted_out_of_scope', 'external_blocker'].includes(route.disposition)
      )
      .map((route) => [normalizeRouteKey(route.route || route.targetPath || route.sourcePath || route.path), route])
  );

  for (const primaryRoute of primaryRoutes) {
    const matchingReviews = routeReviews.filter((review) => {
      const routeKey = normalizeRouteKey(review.route);
      const targetKey = normalizeRouteKey(review.targetUrlOrArtifact);
      const sourceKey = normalizeRouteKey(review.sourceTruthReference);
      return [routeKey, targetKey, sourceKey].includes(primaryRoute);
    });
    const coveredDesktop = matchingReviews.some((review) => review.viewport === 'desktop');
    const coveredMobile = matchingReviews.some((review) => review.viewport === 'mobile');

    if ((!coveredDesktop || !coveredMobile) && !acceptedOmissions.has(primaryRoute)) {
      errors.push(`blind-adversarial-review.json complete claims require desktop and mobile blind review coverage for primary route ${primaryRoute}.`);
    }
  }

  if (!String(reviewInputs.originalBrief ?? '').trim() && (reviewInputs.acceptanceCriteria ?? []).length === 0) {
    errors.push('blind-adversarial-review.json complete claims require the original brief or acceptance criteria.');
  }

  if ((reviewInputs.targetUrlsOrArtifacts ?? []).length === 0) {
    errors.push('blind-adversarial-review.json complete claims require target URLs or artifacts.');
  }

  if ((reviewInputs.sourceOfTruthMaterials ?? []).length === 0) {
    errors.push('blind-adversarial-review.json complete claims require source-of-truth materials from the brief.');
  }
}

async function validateDurableIntent(packetDir, errors) {
  const path = join(packetDir, 'durable-intent.yml');
  if (!existsSync(path)) {
    return;
  }

  const text = await readFile(path, 'utf8');
  const statusBlocks = text.split(/\n(?=\s*-\s+id:)/);

  for (const block of statusBlocks) {
    const id = block.match(/\bid:\s*"?([^"\n]+)"?/)?.[1] ?? '(unknown intent)';
    const status = block.match(/\bstatus:\s*"?([^"\n]+)"?/)?.[1] ?? '';
    const configHash = block.match(/\bconfig_hash:\s*"?([^"\n]*)"?/)?.[1] ?? '';

    if ((status === 'hash-valid' || status === 'accepted') && !HASH_RE.test(configHash) && configHash !== 'not-applicable') {
      errors.push(`${id} has status ${status} but config_hash is not sha256:<64 hex chars> or not-applicable.`);
    }

    if ((status === 'hash-valid' || status === 'accepted') && (configHash === 'UNKNOWN' || configHash === '')) {
      errors.push(`${id} has status ${status} but config_hash is blank or UNKNOWN.`);
    }
  }
}

async function validateRecipeStartPoint(packetDir, errors) {
  const path = join(packetDir, 'recipe-start-point.md');
  if (!existsSync(path)) {
    return;
  }

  const text = await readFile(path, 'utf8');
  if (!/ddev exec dr list recipe/.test(text)) {
    errors.push('recipe-start-point.md must record recipe discovery with ddev exec dr list recipe.');
  }
  if (!/default owner|default-owner|recipe.*default/i.test(text)) {
    errors.push('recipe-start-point.md must record the recipe default-owner decision before custom content-type overlays.');
  }
}

export async function validatePacket({ packetDir = 'review-packet' } = {}) {
  const errors = [];
  const warnings = [];
  const gates = await readJson(join(KIT_ROOT, 'gates.json'), errors);

  if (gates) {
    validateGateVocabulary(gates, errors);
    await validateRequiredFiles(packetDir, gates, errors);
  }

  const independentVerification = await readJson(join(packetDir, 'independent-verification.json'), []);
  const blindAdversarialReview = await readJson(join(packetDir, 'blind-adversarial-review.json'), []);
  const routeMatrix = await readJson(join(packetDir, 'route-matrix.json'), []);
  const completeLocalRebuildClaimAllowed =
    completionAllowed(independentVerification) && completionAllowed(blindAdversarialReview);
  validateCompletionAgreement(independentVerification, blindAdversarialReview, errors);
  validateIndependentVerification(packetDir, independentVerification, errors);
  await validateBlindAdversarialReview(packetDir, blindAdversarialReview, routeMatrix, errors);
  await validateDurableIntent(packetDir, errors);
  await validateRecipeStartPoint(packetDir, errors);

  return {
    schemaVersion: 'public-kit.packet-verification.1',
    checkedAt: new Date().toISOString(),
    packetDir,
    gatesSchemaVersion: gates?.schemaVersion ?? '',
    gateCount: gates?.gates?.length ?? 0,
    requiredFileCount: gates?.reviewPacketFiles?.length ?? 0,
    completeLocalRebuildClaimAllowed,
    valid: errors.length === 0,
    errors,
    warnings
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

  const report = await validatePacket({ packetDir: args.packet });
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, `${JSON.stringify(report, null, 2)}\n`);

  if (!report.valid) {
    process.stderr.write(`Packet verification failed. Report: ${args.out}\n`);
    for (const error of report.errors) {
      process.stderr.write(`- ${error}\n`);
    }
    process.exit(1);
  }

  if (report.completeLocalRebuildClaimAllowed) {
    process.stdout.write(`Packet verification passed for complete local rebuild claim. Report: ${args.out}\n`);
  } else {
    process.stdout.write(
      `Packet structure valid; no complete local rebuild claim allowed by verifier/blind-review evidence. Report: ${args.out}\n`
    );
  }
}

if (isDirectRun()) {
  main().catch((error) => {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n${USAGE}\n`);
    } else {
      process.stderr.write(`${error.stack || error.message}\n`);
    }
    process.exit(1);
  });
}
