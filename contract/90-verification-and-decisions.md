## Required Verification

Before calling the local build successful, record:

- DDEV project URL;
- `ddev drush status`;
- enabled modules/profile;
- exported config;
- active config sync directory, non-empty Git-tracked YAML in that exact current directory, representative YAML, and clean active-to-sync status independently read from the live DDEV target; record clean-import reproduction separately only if it was run;
- optional Agent Skills used, including repo, selected skill, version or commit SHA, and any conflict with this `AGENTS.md`;
- unfiltered Drupal readback, including `system.site` UUID, front-page setting, config sync directory, all nodes including unpublished/default/demo content, all aliases including duplicates, menu links, media counts, Canvas pages when available, themes, config status, and unexpected public routes;
- content inventory, media inventory, and import/recreation counts;
- design-system capture and target theme evidence;
- browser evidence for visitor-facing visual/functional claims and authenticated non-admin editor tasks;
- `next-cycle-verification.json` plus structured evidence under `review-packet/evidence/next-cycle/`, covering live-model discovery, the actual least-privilege role, taxonomy/cycle permissions, publish workflow transition, future public output, and residue-free cleanup. The default live verifier must confirm the cleaned probe URL still returns the recorded `404` or `410`;
- node-vs-Canvas ownership evidence: for each homepage, landing, campaign, marketing, reusable information item, listing, and editor-arranged page, record whether the canonical owner is a node/content type, Canvas page / Experience Builder page, View, entity display, block/Layout Builder region, or another Drupal-native primitive, plus the reason and editor-maintenance evidence. The actual target owner must match, or a target-bound accepted deviation must name its accepter, rationale, and evidence.
- Canvas authoring ownership evidence: when Canvas/Experience Builder is the selected owner, the rebuilt public route must open in the Canvas editor for a non-admin editor, not a disconnected starter placeholder, and a representative edit must affect the anonymous public route.
- Utility Page exception evidence: every Utility Page used for a public source route must record why Canvas/Experience Builder or a structured content type was not the better owner.
- content type, field, form display, view display, View, menu, alias, media, taxonomy, workflow, and role/permission evidence;
- content type label evidence showing editor-facing bundle labels are generic, portable nouns and site-specific names are limited to machine names where needed;
- field-to-output evidence: every load-bearing or required editorial field must identify its editor label, widget, formatter/public rendering location, and whether changing it affects anonymous output. Independently change every load-bearing field and every field claimed to affect anonymous output, then record the observed public result. If a field is editor-only metadata, record an evidence-backed rationale.
- presentation-boundary evidence: no editor field stores raw CSS, style attributes, class names, HTML snippets, JavaScript, or theme implementation strings. Any editor-owned visual variation is constrained to semantic tokens or validated color/palette choices. Also record hardcoded public strings in Twig/templates, raw field-value rendering that bypasses Drupal formatters, invalid alt/ARIA attributes, and any public navigation, footer links, CTA labels, or source-owned public copy that only exists in theme code.
- raw embed and source-markup scan evidence: editorial field scans for raw iframe/script/inline-handler/style/source HTML findings, with every remaining raw embed listed in `off-road-inventory.md`.
- independent verification evidence: a fresh verifier context attempted to falsify completion claims against the live site, including per-route item counts, collection ownership, rendered embed/media presence, raw embed/markup scans, footer/legal/target-required route resolution, route drift dispositions, placeholder/starter scans, Canvas placeholder leaks, first-fold brand assets, editor add-a-row tasks, cold-reader labels, field-output behavior, direct database cleanup/off-road records, and packet freshness.
- blind adversarial review evidence: a reviewer that did not build the target compared the original brief and source-of-truth materials to the live target on desktop and mobile, excluded builder rationale before public review, produced `review-packet/blind-adversarial-review.json`, and stored raw evidence under `review-packet/evidence/blind-adversarial-review/`.
- open decisions evidence: `review-packet/open-decisions.md` lists only decisions a human owner, operator, legal/privacy reviewer, maintainer, or launch authority must make, with options, current evidence, impact, and affected gate. It must not hide work the agent can still fix.
- live verifier evidence: `review-packet/evidence/live-verification.json` from `node [KIT_LOCAL_PATH]/scripts/verify.mjs --packet review-packet`, with a zero exit code, the correct typed claim, live DDEV identity, exact live-first surface reconciliation, fetched accepted routes, actual rendered primary-route SEO, and independently confirmed Git-tracked config YAML before any completion claim. Structural packet data and injected test runtimes are supporting diagnostics only and cannot certify the site.
- composition model evidence: every flexible landing-like route has a declared authoring owner, section ownership model, editor mental-model rationale, expected editor actions, acceptance proof, and deviation records when the implementation differs.
- Canvas component fidelity evidence: every public or rebuild-owned Canvas page has a rational component model that rejects one giant components, JSON/newline URL/string blobs for repeatable content, hardcoded source-owned Twig literals, and repeatable sections not backed by Drupal-owned data.
- primary-route evidence: browser-rendered source `/` compared with target `/` for final URL, status, title, H1, key body intent, canonical link, screenshot, and Drupal route ownership. A correct page at a different alias does not satisfy this gate unless the source also redirects there.
- SEO/social metadata, moderation/workflow, accessibility-tooling, privacy/legal, backup/update, email, and site-settings evidence or explicit blocked notes;
- rendered SEO evidence for every primary route, including exactly one usable canonical, non-empty meta description, and `og:image` where applicable. Every `not_applicable` disposition needs reviewed rationale and evidence;
- exported SEO defaults contain no literal local-environment URLs;
- raw in-browser axe-core results with accepted rule scope, structured exact-route incomplete dispositions, and manual keyboard/focus/name checks for every browser-evidence route;
- anonymous public-form invalid/valid submission checks joined by stable `formKey`, with structured mode-specific outcome and vendor-neutral abuse-protection evidence independently matched to the same form and target;
- representative detail-route evidence for each collection that declares a separate public detail route, including its required and anonymous-output fields, concrete Drupal owner config ID, selector-bound computed visibility, and an independent matching check;
- anonymous public route checks;
- bounded same-origin critical-asset checks for rendered stylesheets, scripts, images/srcset candidates, posters, and declared preloads. Hash served bytes, reject failed or content-type-incompatible responses, and keep third-party provider bytes outside the intrinsic state digest;
- visual parity checks for homepage, listing, detail, navigation, footer, and major responsive states;
- functional parity checks for source-like behaviors;
- browser-rendered homepage, listing, detail, search, contact, legal, and other representative route evidence;
- authenticated editor add/edit form checks with clean labels and visible load-bearing fields.
- non-admin editor role/user evidence proving custom content types can be created and edited without uid=1.

## Scoped Gap List

Create `review-packet/scoped-gap-list.md`. It should name the remaining work by role and gate, not bury gaps in prose.

At minimum cover:

- target schema review;
- recipe/template/start-point decisions;
- source routes and redirect/alias gaps;
- content completeness and editorial workflow gaps;
- media, video, file, and alt-text gaps;
- visual design and responsive behavior gaps;
- functional behavior gaps;
- SEO/search/discovery gaps;
- legal/privacy/consent gaps;
- forms, analytics, email, commerce, donation, CRM, map, API, and third-party integration gaps;
- accessibility, performance, security, and privacy review gaps;
- production target, backup/update, deployment, rollback, and launch evidence gaps;
- maintainer review blockers and final QA blockers.

Each gap needs responsible role, current evidence, blocked reason, next action, and status.

## Open Decisions

Create `review-packet/open-decisions.md` at final handoff. This is the short list for decisions only a human can make. It should include current evidence, options, recommended default when evidence supports one, impact if deferred, owner role, affected gate, and status.

This is not a permission slip to stop early. Before adding a decision here, ask whether the agent can resolve it with more build work, browser checks, Drupal readback, packet updates, route cleanup, imports, theme work, or editor-form fixes. If yes, fix it or record it as an implementation gap in `scoped-gap-list.md`, not as a human decision.

Valid human-only decisions include production target selection, credentials and provider accounts, legal/privacy policy approval, content/business acceptance, accepted route/content dispositions, accessibility/performance/security exceptions, maintainer signoff, launch go/no-go, and owner acceptance of documented out-of-scope items. Every `accepted_out_of_scope` item needs recorded attribution, a specific reason, and evidence; the local verifier treats that attribution as self-attested, while authenticated approval belongs in the external human workflow. External blockers are not accepted completion; they keep the result blocked.

Builder-accepted consequential calls are ratification decisions, not resolved history. When `off-road-inventory.md` contains `OR-` rows or the parity/blind reviews record accepted exclusions or `accepted_out_of_scope` items, present them here as ratification decisions; the verifier rejects the packet contradiction created by a `Decisions still open: None` declaration while such records exist. It does not authenticate a recorded approver.

Use the four-layer truth model:

1. command success;
2. CMS readback;
3. public route status;
4. browser-rendered truth.

A higher layer cannot be inferred from a lower layer.

## Route Smoke Checks

Run route and alias checks for the representative top-level, listing, search, and detail routes implied by the source:

- homepage;
- landing pages;
- product/service/event/location/person detail pages;
- product/article/advice/event/location listing pages;
- category/topic/condition/audience taxonomy pages;
- where-to-buy, directory, contact, form, search, privacy, legal, and footer routes;
- important source-intent aliases and redirects.

Detail pages must render expected title/H1 and load-bearing fields, not only HTTP 200. A route that works only through a controller template but has no editable Drupal content/config ownership is an architecture risk.

The homepage is a primary route, not a representative sample. Target `/` must match the browser-rendered source homepage intent unless the source itself redirects. Do not satisfy homepage parity by placing the correct page at `/artist`, `/home`, `/landing`, or another alias while `/` renders different content.

If the source or target has both `/` and another route for the same public concept, record the front-page alias decision: canonical redirect, distinct Drupal display route, View/route composition, or duplication with synchronization warning. Check no-follow redirects so route-normalizer behavior is visible instead of hidden by `curl -L` or browser navigation.

Also check target-required routes introduced by the rebuild even when they were not explicit source routes: privacy/legal/footer links, sitemap and robots behavior when enabled, login/admin expectations, canonical front page behavior, and any locally introduced menu or footer links. The default live verifier must fetch these routes from the real DDEV target. A broken target-owned footer link or any target-required `5xx` fails the route gate even when packet records report the same status.

Starter and route drift cleanup is part of route parity. Check `/home`, `/page/1`, `/privacy-policy`, raw `/node/*`, starter Canvas pages, stale menu/footer links, duplicate aliases, and unexpected public 200 routes before handoff.

The route matrix must reconcile source-rendered routes against target routes. It must fail the review loop when a source route is missing, a target route renders the wrong H1/body pattern, homepage/front-page behavior is wrong, a legal/footer route is broken, or an unexpected public 200 exists because of duplicate aliases, duplicate content, stale menu links, default demo content, or route-normalization shortcuts. Expected redirects are acceptable only when recorded with source evidence and rationale. A legacy source path+query mapped to a different target must materialize on the target as a first-hop `301` or `308` ending at the exact same-origin target path+query. Otherwise record `noRedirectDisposition` with `accepted: true`, `acceptedBy`, rationale, and non-empty packet-local evidence. Duplicate mapping declarations must fully agree.

Direct SQL cleanup, table purges, alias resets, and destructive import cleanup are off-road operations. They may be acceptable only in a clean local rebuild when recorded as local-only in `off-road-inventory.md` with what changed, why Drupal APIs/config were insufficient, why the operation is safe in this workspace, and what a production-safe alternative would be.
