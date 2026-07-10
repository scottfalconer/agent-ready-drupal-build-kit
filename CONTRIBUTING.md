# Contributing

Contributions should preserve the kit's evidence discipline.

For a bug, confusing first run, or focused proposal, [open an issue](https://github.com/scottfalconer/agent-ready-drupal-build-kit/issues) with the affected command or document, what you expected, and what happened. Do not attach private source content, credentials, or a generated customer review packet.

## Requirements

- Keep examples fictional or explicitly permissioned.
- Do not add copied source-site content without permission.
- Do not add local paths, credentials, private notes, or run-specific evidence.
- Keep generated implementation code out of this public package.
- Add or update evidence requirements when adding a new workflow, template, or evidence type.
- Record unresolved evidence clearly; use `UNKNOWN` only where a structured field needs a placeholder value.
- Separate generated packets from accepted launch evidence.

## Make A Change

Canonical gates, templates, references, and verifier entrypoints live at the repository root. After changing one of them, refresh the self-contained installed skill and run the checks:

```bash
node scripts/sync-skill-package.mjs --write
npm test
node scripts/sync-skill-package.mjs --check
npm pack --dry-run --json
```

Do not hand-edit a mirrored file under `skills/agent-ready-drupal-build-kit/`; change its canonical root source and run the synchronization command.

A pull request should explain the user or agent failure it addresses, keep the diff scoped, update tests when behavior changes, and name any claim the available evidence still cannot support.

## Review Bar

A contribution should make the kit easier for agents to use without making it easier for agents to skip evidence. CI must pass before the change is ready for review.
