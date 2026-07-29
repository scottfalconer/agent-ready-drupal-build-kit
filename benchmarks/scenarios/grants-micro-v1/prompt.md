You are the sole builder in a fresh, pilot-only Agent-Ready Drupal Build Kit benchmark run.

Work only in the current Drupal/DDEV project. Read the installed
`.agents/skills/agent-ready-drupal-build-kit/SKILL.md` and use progressive
disclosure, but keep this run to the bounded brief in `benchmark-brief.md`.
This benchmark is diagnostic evidence, not a general build-completion claim.
You are already inside the DDEV web container, so run Drush, Composer, PHP, and
other project commands directly.
Do not inspect authentication files, credential-like environment variables,
SSH-agent paths, host mounts, or unrelated filesystem locations. Do not use
external network access.

Implement every requirement below as real Drupal configuration and content:

1. Create the `grant` node type.
2. Add `field_grant_amount` as a decimal field and
   `field_application_deadline` as a datetime field. Both fields must be
   required, single-value fields. Put visible widgets on the default Grant
   form display and visible formatters on the default Grant view display.
3. Create exactly these three Grant nodes, all published, with these field
   values:
   - Community Garden Starter Grant — amount `2500.00`, deadline `2026-09-30`
   - Neighborhood Resilience Grant — amount `7500.00`, deadline `2026-10-15`
   - Youth Arts Access Grant — amount `5000.00`, deadline `2026-11-01`
4. Create a Drupal View with machine name `grants` and a page at `/grants`.
   Filter it to published Grant nodes only. Configure visible View fields for
   title, amount, and deadline, rendering the decimal with two fraction digits
   and the date as `Y-m-d`. Use only the default display and this one page
   display. Do not add other fields, filters, sorts, arguments, relationships,
   headers, footers, or empty-text handlers. The rendered page must visibly
   contain every exact title, amount, and deadline listed above.
5. Add Grant to the existing `basic_editorial` workflow. On the existing
   `content_editor` role, add only the permissions needed to create Grant
   content and edit its own Grant content; retain its existing draft/publish
   transition permissions. Do not add administer-node, administer-content-type,
   bypass-node-access, delete, edit-any, or other Grant permissions.
6. Export all resulting Drupal configuration to the configured sync directory.
7. Update the initialized review packet so the arm kit's packet-only verifier
   exits successfully. Record truthful evidence only.
8. Clear caches, verify the focused requirements, and commit all build changes
   so the Git worktree is clean.

Do not replace Drupal entities or the View with static HTML. Do not fetch or
update the installed kit, switch projects, run the authoritative live verifier,
perform a blind review, add a custom module or theme, persist helper/source
code, create aliases or unrelated durable content, alter pre-existing entities,
add unrelated configuration or features, or wait for human input. Do not create
temporary users, nodes, aliases, or other durable entities as access or editor
probes. Pathauto may create aliases automatically when Grant nodes are saved:
before the final verification, query `path_alias` for only the three Grant
node paths, remove any aliases for those exact paths, leave every pre-existing
alias untouched, and verify that no Grant alias remains. Keep the implementation
configuration-and-content-only. If a
requirement cannot be met, leave precise evidence in the packet and explain it
in your final response. Otherwise finish the complete bounded slice in this one
fresh turn.
