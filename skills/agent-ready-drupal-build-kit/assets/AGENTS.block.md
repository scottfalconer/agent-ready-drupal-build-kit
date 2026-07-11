## Agent-Ready Drupal Build Kit

Source site: `{{SOURCE_URL}}`

This repository is the existing Drupal rebuild target. Work in place. Do not create a sibling Drupal project, clone another copy of the kit, substitute a static frontend, or overwrite this `AGENTS.md` file.

Canonical workflow: [`{{SKILL_PATH}}/SKILL.md`]({{SKILL_PATH}}/SKILL.md)

Review packet: `{{PACKET_PATH}}/`

Non-negotiable gates:

- Model repeatable information as Drupal-owned structured content. Every declared collection needs count, ownership, and non-admin add-a-row evidence; accepted exclusions need a named owner and evidence.
- Declare composition ownership before implementing landing-like routes and prove the target's actual owner matches it or has a target-bound accepted deviation. Canvas/Experience Builder owns editor composition, not canonical repeatable data.
- Keep configuration in a non-empty tracked sync directory and prove active configuration has no drift from it. Record clean-install/import reproduction separately only when it was actually run.
- Test actual anonymous routes and realistic non-admin editor tasks against the running Drupal site. Every custom or repeating public bundle needs an editor workflow, and load-bearing/anonymous-output fields need falsification checks.
- Complete negative-route and consent evidence: generated 404 quality, access-wall canonicals, rendered legal/privacy links, active consent configuration, and fresh before-consent resource behavior.
- Preserve real packet-local evidence and separate builder work from independent and blind review.
- Treat packet-only validation and injected test runtimes as diagnostic only. The default live-target verifier must independently inspect the current DDEV origin and Git-tracked config YAML before it may derive local completion authorization.
- After the first successful full verification, preserve its create-once, integrity-checked historical baseline under kit tooling. The initial rebuild remains done. For later work, begin a repair or extension before editing, allow detected impact to widen required checks, and report targeted authored evidence separately as `evidence_recorded` without calling it independent verification or a new completion certificate.

Default verification:

```bash
node {{SHELL_SKILL_PATH}}/scripts/verify.mjs --packet {{SHELL_PACKET_PATH}}
```

For later work, `status` reads the last inspected cached state. Refresh with the default verifier before `begin` when `currentStateFresh` is false. Begin one `repair` or `extension` before editing and declare every affected anonymous `--route`, or explicit `--no-public-route` when there is no anonymous route effect; use `--adopt-current` only for existing edits, which always adds conservative `unknown` impact. Every concrete route must be in the packet route matrix and pass the fresh fetch. Copy the base fingerprint from `begin` and the result fingerprint from the fresh report into the targeted JSON. Then complete with evidence for every criterion and non-machine check; `complete` performs its own fresh inspection and snapshots evidence bytes. Use `abandon --reason "..."` when the active record will not be completed. Only after targeted evidence is recorded may `verify --change` re-evaluate the current packet/live state against the full original verifier gates and optionally create a checkpoint; it validates existing review artifacts rather than recreating them.

Commands below use host `node`; use `ddev exec node` instead when Node is available only inside DDEV.

```bash
node {{SHELL_SKILL_PATH}}/scripts/lifecycle.mjs status --packet {{SHELL_PACKET_PATH}}
node {{SHELL_SKILL_PATH}}/scripts/lifecycle.mjs begin --packet {{SHELL_PACKET_PATH}} --id <change-id> --kind <repair-or-extension> --summary "..." --acceptance "..." --route </affected-path>
node {{SHELL_SKILL_PATH}}/scripts/lifecycle.mjs complete --packet {{SHELL_PACKET_PATH}} --id <change-id> --verification <path>
node {{SHELL_SKILL_PATH}}/scripts/lifecycle.mjs abandon --packet {{SHELL_PACKET_PATH}} --id <change-id> --reason "..."
node {{SHELL_SKILL_PATH}}/scripts/verify.mjs --packet {{SHELL_PACKET_PATH}} --change <change-id> --checkpoint <checkpoint-id>
```

Targeted semantic evidence is integrity-bound but not independently evaluated. The optional full path does not synthesize semantic passes and never overwrites the historical initial baseline.

The kit initializer may replace only the content between its own start/end markers. Preserve all One Line Installer, Drupal AI best-practices, project, and user instructions outside those markers.
