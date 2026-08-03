## Browser Evidence Gate

Claims about what a visitor sees or what an editor can do require browser evidence. The tool is not prescribed. The evidence is prescribed.

Use any available real browser method: an automated browser runner, browser DevTools protocol, Selenium-style driver, local browser with screenshots, or another tool that renders CSS, JavaScript, fonts, media, redirects, and authenticated Drupal pages as a user would see them. Do not prescribe one tool. Do record the tool or method used, and label the visual comparison honestly: agent-performed structural comparison is `agent_review`; `human_review` requires a reviewer label in the record, which the local verifier reports as self-attested rather than authenticated.

Do not claim visual parity, functional parity, homepage parity, source-like behavior, or editor experience from curl, HTTP status, Drush, config export, Drupal readback, DOM snapshots without rendered layout, target-only screenshots, or prose review alone.

Create `review-packet/browser-evidence.json` and store supporting files under:

```text
review-packet/evidence/browser/
```

At minimum, browser evidence must cover:

- target homepage at desktop and mobile widths, plus the source homepage in `source_site` mode;
- target examples for every major public page pattern, plus matching source examples in `source_site` mode: landing, listing, detail, taxonomy/category, search/discovery, form/contact, legal/footer, and media/embed routes where present;
- every primary route identified in `route-matrix.json`;
- any route whose design, behavior, or source intent differs from the dominant template;
- non-admin editor create/edit workflows for every custom content type and load-bearing workflow.

For each public route check, record target URL/final URL, viewport, target screenshot, title, H1, key visible body intent, section order, header/footer treatment, typography and spacing notes, media placement, functional behavior notes, accepted exceptions, brief requirement IDs when applicable, and pass/fail status. Keep capture-state declarations on that same record: every normalized target request + viewport name + stable state ID tuple is unique, every state row is accepted and passing without blockers, every primary route has a `default` desktop and mobile state, and every state binds one fixture revision plus the exact screenshot and axe-report bytes. State records use the fixed `self_attested_capture_evidence` authority. The packet verifier checks their shape, artifact hashes, dimensions, origin, and cross-state consistency, but does not replay their interactions; they cannot replace live verification or independent/blind review. A default state is non-mutating. If its structured mobile menu state declares a visible toggle, record the exact toggle and controlled-region selectors closed, then add an accepted, passing `mobile-menu-open` record that clicks the toggle or presses it with `Enter`/`Space` and observes the same region open with distinct screenshots and axe evidence. Do not infer the requirement from prose or create a second state manifest. Each state may have at most 12 interaction steps, 16 unique-selector exact-count assertions, and 8 masks using only an element-specific `#id`, `.class`, or `[data-*]` compound selector; universal/functional selectors and common page/global-chrome tokens are rejected, and the observed rectangle union may cover no more than 25% of the viewport. Counts and masks remain self-attested diagnostics tied to the state evidence; masks do not authorize or replace verifier-owned global-chrome anchor masks. In `source_site` mode, also record source URL/final URL, source screenshot, and optional diff image or score when the tool supports it; brief mode remains target-only. Legacy schema v1 remains valid as implicit `default`-only evidence but cannot declare interacted states.

The default source/target managed-browser floor also extracts visible native controls associated with public forms on every primary route and every distinct accepted form/search route from the route matrix, including exact accepted source/target routes bound by the audited and modeled form records. A form/search route cannot escape this verifier-owned comparison merely because it was not chosen as a primary representative or its accepted route row was mislabeled. Exact path-and-query identities are retained inside the verifier and query values are redacted from shared evidence. This expanded route union still uses the fixed 64-route browser ceiling and aggregate deadline; it is never truncated, and exceeding either bound fails closed without running partial browser checks. Controls associated through the HTML `form` attribute outside their form element participate. The verifier binds each control to privacy-safe one-based form and control ordinals, then compares Unicode-NFKC-normalized accessible identity plus occurrence when the source has one, native kind, normalized visible label text, required and disabled state, checkbox/radio selected and default state, and the ordered normalized labels plus selected, default, and disabled state of every `<select>` option. Markup mechanisms are implementation-neutral: equal public identity and visible text may move between an associated `<label>`, visible `aria-labelledby` text, or native button text. Accessibility repairs are deliberately narrow. A source identity with no durable visible label may gain matching durable visible text; an inaccessible source with existing visible text may gain only that exact normalized identity while preserving the text; and a source with neither may gain an identity only together with matching durable visible text. Hidden `aria-label` invention, changed public wording, a placeholder-only replacement, and a missing, extra, reordered, or still-inaccessible target control fail. Controls hidden directly or by a hidden, inert, `aria-hidden`, opacity, visibility, or display ancestor do not participate. Internal field names, visitor-entered/current input values, and option values are never retained (an input submit/reset/button value may contribute only its rendered public label). Evidence is capped at 64 controls per route state, 64 options per control, and 180 normalized characters per public label; malformed evidence is bounded before reporting, and an inaccessible target or any truncation fails closed. A select must expose a complete non-empty observed option state. If options load dynamically, make the populated state deterministic at the exact captured route/query state; an empty source or target list is not a wildcard and authored prose cannot replace the verifier-owned DOM observation.

The exact audited/modelled source/target pair list is also capped at 64 before CDP starts, independently of the 64 unique-route ceiling on each capture side; neither list is sliced. Structural, navigation, and composition findings remain scoped to authored primaries, while dedicated `publicFormControlFindings` cover additional non-primary form/search routes. An audited form/search route with no visible native source controls is insufficient even when target evidence is also empty.

The verifier-owned managed-browser capture also records a bounded, privacy-safe computed-style sample for semantic body, H1, H2, primary-navigation-link, primary-action, first-form-control, and representative card/listing anchors. Samples contain only the semantic role, fixed selection method, allowlisted computed typography/color/border values, and loaded font-family names; they contain no element text or URLs. Source/target comparisons report font replacement, a source web font that is computed but no longer loaded, extreme font-size ratios, and obvious control-token drift as `computedStyleShadow` diagnostics. Missing anchors are `insufficient_evidence`, never a pass. This record has `authority: none` and `completionEffect: none`: it guides review but cannot change the visual-floor status, live-verifier exit, or completion claim.

For each editor workflow check, record editor user/role, Drupal route, task performed, screenshots or captured evidence for the form and result, fields/widgets verified, public output affected, failures, accepted exceptions, and pass/fail status.

If browser evidence is missing or failing, return to the review loop. A target that is only source-inspired is not visually complete.

## Completion Contract

The initial handoff must be binary: `complete-local-rebuild` in source-site mode, `complete-local-build-from-brief` in brief mode, or blocked. A partial local site is worse than no handoff because it hides the work still required. After that milestone passes, later lifecycle reporting must preserve the initial result and separately report whether the last inspected cached state is unchanged, under repair or extension, evidence-recorded, fully verified by a later original-gate run, or unclassified.

The following are not acceptable final states:

- a sample catalog when the public source exposes a fuller catalog;
- partially imported reachable public content, shows, products, articles, events, episodes, locations, or legal/footer pages;
- partially imported reachable public media, posters, documents, videos, thumbnails, logos, or alt text without item-level blockers;
- placeholder copy/media where source material was reachable;
- a stock theme, generic theme, or base-theme look that does not match the source's public visual language;
- a front page that renders the wrong source pattern, wrong canonical content, or an unrelated default page;
- a browser-rendered source route, likely public slug, or source-bundle route hint that is not preserved, redirected, or item-blocked;
- per-route item-count mismatches that are not item-blocked or owner-dispositioned;
- collection routes without a Drupal owner plus View/collection config and editor add-a-row evidence;
- homepage-only visual parity with weak listing, detail, taxonomy/category, search, form, legal/footer, or navigation routes;
- first-fold homepage or primary-route output missing reachable brand-defining hero artwork, logo/lockup, campaign graphics, signature imagery, or primary CTA treatment without an explicit exception;
- public pages that render but do not expose Drupal-owned content, fields, Media, Views, menus, aliases, and blocks behind them;
- editor add/edit forms that omit load-bearing fields or expose raw machine names, missing labels, or broken widgets;
- stale review-packet files that still describe placeholders, old route checks, old screenshots, or earlier architecture decisions.

These are work items, not blockers: large catalogs, many media files, CSS/theme bugs, cache issues, route alias bugs, field/display mistakes, failed imports that can be retried, and time spent reconciling counts.

Valid blockers are external or environmental: source routes are unreachable, content is private or authenticated, provider credentials are missing, assets remain technically inaccessible after retries, DDEV/Drupal cannot run locally, or the human changes scope. Each blocker must name the affected item, attempted evidence, missing input, and next action. Private or unreachable claims need evidence of that boundary. These records make the handoff honest, but completion remains blocked and omitted routes remain uncovered.

Before final handoff, answer this completion gate:

- Public content inventory reconciled: every reachable source item is imported/recreated or item-blocked.
- Per-route item reconciliation complete: repeated items on each load-bearing route match source counts, or a recorded owner label, reason, and evidence disposition a specific exclusion; local attribution is self-attested.
- Collection ownership ledger complete: every declared row includes source/target count reconciliation, Drupal content/entity plus View/collection ownership, and non-admin editor add-a-row evidence.
- Collection pagination complete: every accepted collection declares source/target mode, continuation mechanism, and positive observed page/batch sizes when continuing; the live View pager matches the target declaration with zero offset; and every continuing collection has either verifier-owned distinct final requests plus semantic distinctness or an exact, explicitly self-attested interaction-bearing JS-only capture-state binding.
- Public media inventory reconciled: every reachable asset is managed in Drupal Media or item-blocked.
- Source-like visual design is implemented across homepage, listing, detail, taxonomy/category, navigation, footer, and responsive states.
- First-fold and brand-defining assets are present or explicitly dispositioned for primary routes.
- Source-like public behavior is implemented or blocked for search, filters, pagination, forms, embeds, provider links, redirects, and canonical routes.
- Drupal editor experience is verified for every custom public bundle, every repeating public bundle, and every load-bearing workflow; every load-bearing or anonymous-output field has a falsification check.
- Non-admin editor add-a-row tasks prove new representative collection items appear publicly without code changes.
- Target-required routes such as privacy/legal/footer links, sitemap/robots when enabled, login/admin expectations, canonical front page behavior, and locally introduced menu/footer links resolve as intended.
- Review packet evidence is current and matches the live Drupal site.
- Independent verification has tried to falsify the completion claims and every failure is fixed. Evidence-backed accepted exclusions may narrow agreed scope; external blockers leave completion blocked.
- Human-only open decisions are listed in `review-packet/open-decisions.md`, and agent-resolvable work has not been hidden there.

If any answer is no, continue the review loop. Do not present the site as finished.
