# Independent Operator Run Record

## Operator

- Name:
- Role:
- Environment:
- Environment provisioning (manual, One Line Installer, other):
- Date:

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

## Restore Path

A maintainer must be able to restore this exact build state without asking the builder. Record the restore method, then list every restore artifact (database snapshot, ordered rebuild scripts, or the tracked config directory) as its own list line with the path in backticks, relative to the review packet or the project root. The packet verifier existence-checks every listed artifact; a referenced-but-missing restore file fails verification, absolute machine paths are rejected, symlinks that point outside the packet or project are rejected, and the packet itself or its primary artifacts do not count as restore artifacts.

- Restore method (database snapshot, rebuild scripts, config import):
- Restore artifacts:
  - (one artifact path in backticks per line)

## Decision

- [ ] Repeatability not reviewed
- [ ] Repeatability blocked
- [ ] Repeatability accepted
- [ ] Repeatability accepted with restrictions

## How This Record Is Used

Use this record as operator evidence in the review packet alongside the architecture, content/design/function parity, target, QA, and maintainer records.
