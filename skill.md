# Send Your AI Agent To Drupal

Build a complete local Drupal CMS site, not a static lookalike, Drupal-shaped foundation, or partial representative build.

## Human Input

Ask the human for only one required value:

- Source site URL

If the source URL is missing, ask for it before continuing.

## Agent Instructions

1. Make sure you are working in a local coding environment with filesystem and shell access.
2. If this repository is not already available locally, clone it beside the target Drupal workspace:

   ```bash
   git clone https://github.com/scottfalconer/agent-ready-drupal-build-kit.git
   ```

3. Read `agent-ready-drupal-build-kit/USAGE.md` for the canonical run instructions.
4. Use `agent-ready-drupal-build-kit/AGENTS.md.template` as the operating guide for the target Drupal CMS workspace.
5. If Agent Skills are supported, read `agent-ready-drupal-build-kit/docs/recommended-agent-skills.md`; install only skills that fit the run and record them in `review-packet/operator-run.md`.
6. Create a clean Drupal CMS project workspace alongside the kit folder.
7. Create the review packet at `review-packet/`.
8. Build with DDEV and `drupal/cms`; include public content, media, visual design, routes, functionality, and editor experience.
9. Use nodes/content types for reusable information and Canvas pages / Experience Builder for one-off composed experiences; record the reason for each major ownership decision.
10. Before building flexible landing-like pages, declare the composition model in `review-packet/pattern-map.json`: selected Drupal authoring owner, route rationale, sections, data sources, expected editor actions, Canvas component model when Canvas is used, and deviation records when implementation changes.
11. When Canvas/Experience Builder is the selected owner for a homepage, landing page, or composed marketing route, prove the actual public route opens in that editor and is not a disconnected starter placeholder or theme-only composition. Any public or rebuild-owned Canvas page must have a usable component model, not one monolithic component, JSON/newline URL/string blobs, or repeatable content detached from Drupal-owned data.
12. Run browser-first route expansion, browser-evidence checks for visitor-facing routes, composition model fidelity, Canvas authoring ownership, Canvas component model fidelity, and non-admin editor tasks, Starter route cleanup, front-page/alias decision checks, tracked config export/import checks, rendered SEO checks, Drupal readback, field-output checks, off-road inventory, and non-admin editor-form checks before handoff.
13. Run an independent mechanical verifier pass in a separate subagent, fresh context, review-only task, or clearly separated skeptic checklist that did not build the site. Its job is to try to falsify packet and live-site completion claims. Produce `review-packet/independent-verification.json`; fix or item-block failures for per-route item counts, collection ownership, rendered embeds/media, raw embed/markup scans, footer/legal/target-required routes, route drift, Canvas placeholders, composition model fidelity, Canvas component model fidelity, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness. If same-context fallback is unavoidable, record degraded independence.
14. Run a blind adversarial product review in a fresh agent/context. Give the reviewer only the original brief, target URL or artifact, source-of-truth materials named in the brief, and credentials needed for editor checks. Do not show implementation files, review-packet files, builder notes, config/scripts, prior build conversation, or self-authored claims before public/artifact review. Produce `review-packet/blind-adversarial-review.json` with every primary route from `route-matrix.json` covered at desktop/mobile widths unless an accepted omission is recorded, real screenshot evidence under `review-packet/evidence/blind-adversarial-review/`, and defect review passes; fix or item-block failures until the blind reviewer verdict is `good` or `good_enough`.
15. Copy needed files from `agent-ready-drupal-build-kit/templates/` into `review-packet/`, fill them with evidence or blocked stubs, then run `node agent-ready-drupal-build-kit/bin/verify-packet.mjs --packet review-packet` before any complete rebuild claim.
16. Work in review loops: build, verify, self-review against `AGENTS.md`, fix the highest-impact gaps, update the review packet, and repeat until the complete local rebuild bar is met or a real blocker is recorded.
17. Do not substitute static HTML, screenshots, a local file preview, a CMS-shaped packet, a stock-theme placeholder, a partial/sample catalog, or a separate frontend.

Partial or incomplete sites are failed runs, not deliverables. Keep working unless a blocker is outside the local agent's control and is recorded with the missing input and next action.

## Build Assumption

Assume the human's source URL is authorized for a public-facing local rebuild. Do not turn the build into placeholders because permission is not separately recorded.

Mark uncertain facts, missing evidence, and assumptions clearly in the review packet instead of inventing details.
