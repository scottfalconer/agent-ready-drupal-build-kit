### Phase 3: Durable Intent

- For every major architectural decision, content type, View, workflow, integration boundary, custom controller, or recipe/overlay decision, append a durable intent record.
- Include purpose, source evidence, rationale, asserted by, last reviewed date, config hash, status, and stale behavior. For config objects, compute `config_hash` as `sha256:<64 lowercase hex chars>` from the exported config YAML after deleting `uuid:` and `_core:` lines and trimming trailing whitespace. Use `config_hash: "not-applicable"` only for behavior or external decisions with no Drupal config object.
- A solo-agent run may set durable intent status to `hash-valid` when the hash matches exported config. Only human maintainer review should set status to `accepted`. Blank or `UNKNOWN` hashes are advisory only and fail the packet verifier when paired with `hash-valid` or `accepted`.
- An empty `intent_records` list is not self-justifying. Record `empty_intent_acceptance` with disposition `accepted_no_durable_intent`, a named accepter, rationale, and non-empty packet-local evidence; otherwise the completion claim remains blocked.
- Produce `review-packet/durable-intent.yml`.

### Phase 4: Gap List

- Produce `review-packet/scoped-gap-list.md`.
- Produce `review-packet/open-decisions.md`.
- Name what remains for operator, maintainer, private or inaccessible content, provider credentials, legal/privacy, integration, accessibility, performance, security, SEO, production target, launch, and final QA.
- Separate human-only decisions from agent-resolvable work. Human-only decisions include owner approval of source/content/legal choices, production target selection, provider credentials, route/content disposition calls, accepted exceptions, maintainer signoff, and launch go/no-go. Missing reachable content, broken routes, visual defects, editor-form gaps, import retries, and incomplete packet evidence are work items; keep building instead of listing them as decisions.
- Do not stop early because a human-only decision exists. Build as far as the local agent can, item-block only the affected facts, and present the remaining decisions during final handoff.
- Create blocked stubs for gate records that are not earned yet.

### Phase 5: Stake-My-Name Self-Eval

- Fill the evidence, checklist, and rationale sections of `review-packet/maintainer-review.md`, including the builder identity, and answer the canonical signoff questions as self-eval.
- If any answer is no, say the result is useful but not something to stand behind yet.
- Leave the binary stake-my-name acceptance pending unless an authorized person records it. Gates marked `checkedBy: human` in `gates.json` (operator run, production target, launch checklist, maintainer review) are a separate human-facing status plane. Their Markdown fields are builder-writable, so the local verifier reports typed names, string comparisons, and choices as self-attested records only. It never treats a different name as proof of a person or uses these records to determine machine completion, verdict, or exit code. `G-HANDOFF-01` is instead a `verify-script` check that decisions declared human-only are presented consistently; it does not prove that classification or approve those decisions.
