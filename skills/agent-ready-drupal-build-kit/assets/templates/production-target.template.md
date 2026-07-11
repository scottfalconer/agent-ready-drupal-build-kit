# Production Target Record

## Run Identity

- Site:
- Target workspace:
- Date:
- Declared by:

## Local Claim Scope

Check exactly one. A complete-local-rebuild claim never certifies this record, but the record must still identify its run instead of shipping as an untouched template copy.

- [ ] Production target not selected: this record is not applicable to the local completion claim.
- [ ] Production target selected: launch evidence is tracked here and stays outside the local completion claim.

## Target

- URL:
- Environment:
- Runtime evidence:
- Build identifier:
- Deployment owner:
- Rollback owner:

## Required Evidence

- Recipe or configuration application transcript:
- Target config export:
- Target config drift report:
- Content/media import or recreation record:
- Rendered smoke record:
- Browser QA report:
- Accessibility evidence:
- Performance evidence:
- Security and privacy evidence:
- Rollback record:

## Boundary

This is a `checkedBy: human` gate record: the builder agent fills the evidence fields, but only a named human distinct from the builder identity accepts the target.

Disposable lab evidence is not production target evidence.

Local DDEV evidence can support a local review build. It is not production target evidence unless the project explicitly defines that DDEV environment as the accepted target for the current review phase.
