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
- Preserve real packet-local evidence and separate builder work from independent and blind review.
- Before relying on assembly again, exercise reruns in disposable state, never the working target, and optionally record builder-observed evidence. The packet linter does not execute assembly commands; `E-ASSEMBLY-01: evidence_recorded` is non-authoritative and does not affect completion.
- Treat packet-only validation and injected test runtimes as diagnostic only. The default live-target verifier must independently inspect the current DDEV origin and Git-tracked config YAML before it may derive local completion authorization.

Default verification:

```bash
node {{SHELL_SKILL_PATH}}/scripts/verify.mjs --packet {{SHELL_PACKET_PATH}}
```

The kit initializer may replace only the content between its own start/end markers. Preserve all One Line Installer, Drupal AI best-practices, project, and user instructions outside those markers.
