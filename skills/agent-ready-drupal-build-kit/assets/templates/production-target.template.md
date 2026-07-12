# Production Target Record

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

This is a human-facing `checkedBy: human` gate record. An authorized production owner should record the decision below. Because this file is builder-writable, the local verifier reports the choice and attribution as self-attested status only; it does not authenticate the approver, and this production decision does not affect the complete-local-rebuild machine verdict.

## Recorded Human Status

- Approver:
- Builder identity:
- Reviewed at:

- [ ] Production target accepted
- [ ] Production target not accepted

Disposable lab evidence is not production target evidence.

Local DDEV evidence can support a local review build. It is not production target evidence unless the project explicitly defines that DDEV environment as the accepted target for the current review phase.
