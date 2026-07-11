# Independent Operator Run Record

## Operator

- Name:
- Role:
- Environment:
- Environment provisioning (manual, One Line Installer, other):
- Builder identity:
- Date:

`Builder identity` names the agent/runtime that produced the build. The operator `Name` and `Reviewer` are human identities and must differ from it.

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

This is the `G-OPERATOR-01` human acceptance. The builder agent fills the run evidence but leaves these boxes unchecked; only the named human operator records the decision. Until then the verifier caps the run at exit `2`: mechanically verified, awaiting human signoff.

- [ ] Repeatability not reviewed
- [ ] Repeatability blocked
- [ ] Repeatability accepted
- [ ] Repeatability accepted with restrictions

## How This Record Is Used

Use this record as operator evidence in the review packet alongside the architecture, content/design/function parity, target, QA, and maintainer records.
