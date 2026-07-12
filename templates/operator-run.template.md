# Independent Operator Run Record

## Operator

- Name:
- Role:
- Environment:
- Environment provisioning (manual, One Line Installer, other):
- Builder identity:
- Date:

`Builder identity` names the agent/runtime that produced the build. `Name` and `Reviewer` are recorded labels, not authenticated identities. The local verifier reports whether the strings match but does not infer that a different string proves an independent human.

## Run Evidence

- DDEV project URL:
- `ddev describe`:
- Drupal core version from `ddev drush status` or Composer:
- Recipe discovery command and result:
- Drupal core Recipe runner availability:
- `ddev drush status`:
- Config export location:
- Anonymous route checks:
- Browser-rendered evidence:
- Timed task log:
- Command transcript:
- Manual corrections:
- Product gaps:
- Handoff notes:
- Reviewer:

## Decision

This is the human-facing `G-OPERATOR-01` record. An authorized operator should record the decision. Because this file is builder-writable, the local verifier reports the choice as self-attested status only; pending or recorded acceptance does not change the machine completion verdict or exit code.

- [ ] Repeatability not reviewed
- [ ] Repeatability blocked
- [ ] Repeatability accepted
- [ ] Repeatability accepted with restrictions

## How This Record Is Used

Use this record as operator evidence in the review packet alongside the architecture, content/design/function parity, target, QA, and maintainer records.
