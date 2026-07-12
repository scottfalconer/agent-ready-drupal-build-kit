# Open Decisions

## Site

- Source URL:
- Target site name:
- Target workspace:
- Date:

## Rule

This file is for decisions only a human owner, operator, legal/privacy reviewer, maintainer, or launch authority can make.

Do not use this file as a reason to stop early. Build, verify, fix, and item-block everything the agent can reasonably resolve first. Then present the remaining human-owned decisions in the final handoff.

Do not list normal implementation work here. Missing reachable content, broken routes, CSS defects, import retries, field/display mistakes, route alias bugs, editor-form defects, and incomplete packet evidence are work items, not human decisions.

Builder-accepted deviations require a presented ratification decision. If `off-road-inventory.md` contains `OR-` rows, the parity/blind reviews record accepted exclusions or `accepted_out_of_scope` items, route count reconciliation uses `owner_approved_exclusion`, or composition verification accepts an owner fallback, list each decision here; the verifier rejects an unrelated decision row or a contradictory `Decisions still open: None` declaration. It reports any recorded human choice as self-attested and does not authenticate the approver.

Put each stable deviation reference in the decision row's **Current evidence** cell so the verifier can bind the decision to the exact item:

- off-road row: `OR-001`;
- blind defect: its required ID, such as `DEF-001`;
- omitted primary route: `omitted-route:/source-path`;
- parity exclusion: `parity-exclusion:<token-safe-id-or-route>` (add an ID when the description contains spaces);
- repeated-item count exclusion: `count-exclusion:/source-path->/target-path:item-type-slug` (for example, `gallery image` becomes `gallery-image`).
- accepted composition-owner fallback: `composition-deviation:/target-path`.

References are exact tokens: `OR-0010` does not satisfy `OR-001`.

## Decisions

| ID | Decision needed | Human owner | Current evidence | Options | Recommended default | Impact if deferred | Needed by gate | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DEC-001 | Confirm production target and hosting assumptions | Operator/Owner | UNKNOWN | DDEV only / staging target / production-equivalent target | UNKNOWN | Launch and performance evidence remain blocked | production-target.md | open |
| DEC-002 | Approve legal/privacy/footer content and policies | Legal/Owner | UNKNOWN | Use existing policy / draft replacement / block publication | UNKNOWN | Privacy/legal routes cannot be launch-cleared | launch-checklist.md | open |
| DEC-003 | Provide provider credentials or accept integration stubs | Operator/Owner | UNKNOWN | Provide credentials / keep local stub / remove integration | UNKNOWN | Forms, maps, search, analytics, commerce, CRM, email, or media providers remain blocked | scoped-gap-list.md | open |
| DEC-004 | Accept, reject, or revise out-of-scope route/content dispositions | Owner/Maintainer | UNKNOWN | Keep / redirect / drop / unpublished import / owner decision required | UNKNOWN | Route and content parity cannot be finally accepted | route-matrix.json | open |
| DEC-005 | Accept final go/no-go for maintainer and launch review | Owner/Maintainer | UNKNOWN | Accept local rebuild / request changes / block launch | UNKNOWN | Handoff cannot become launch approval | maintainer-review.md | open |

## Handoff Summary

- Decisions still open:
- Decisions accepted:
- Decisions blocked by missing external input:
- Agent-resolvable work deliberately excluded from this file:

## Notes

- Use `UNKNOWN` only as a value placeholder for evidence that is genuinely not available.
- Every open decision should name a human owner, current evidence, options, and the gate it affects.
- Use one of these Status values: `open`, `pending`, `blocked`, `deferred`, `accepted`, `rejected`, `resolved`, or `not_applicable`.
- If no human-only decisions remain, say so explicitly and explain what evidence supports that.
