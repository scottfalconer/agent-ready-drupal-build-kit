You are the sole diagnostician in a disposable Agent-Ready Drupal Build Kit
benchmark. This is diagnosis-only. Do not repair, reformat, or edit the review
packet or any other input.

Work only in the current opaque workspace. Do not inspect parent directories,
Git history or metadata, benchmark scheduling, authentication, environment
credentials, host paths, or external network resources.
Do not run `pwd`, resolve the absolute workspace path, or inspect the current
directory's parent path; relative paths below are sufficient.

1. Read the installed
   `.agents/skills/agent-ready-drupal-build-kit/SKILL.md` and only the local
   verifier-output guidance it directly requires for this diagnosis.
2. Invoke the installed arm verifier exactly once with this exact packet-only
   contract, capturing both streams:

   `node .agents/skills/agent-ready-drupal-build-kit/scripts/verify.mjs --packet review-packet --packet-only --out .benchmark-runtime/arm/live-verification.json > .benchmark-runtime/arm/verifier.stdout 2> .benchmark-runtime/arm/verifier.stderr`

   Failure is expected because the packet is intentionally invalid.
3. Read all of `.benchmark-runtime/arm/verifier.stderr`. It is the only
   terminal diagnosis input. Follow the verifier's announced artifact order.
   For every announced JSON diagnostic artifact you inspect, use only:

   `node .benchmark-runtime/read-diagnostic.mjs <announced-relative-path>`

   If a bounded diagnostic summary is announced, inspect it before deciding
   whether the authoritative report is needed. If no summary is announced,
   inspect the authoritative report. Do not open either JSON file any other
   way.
4. Write `diagnosis.json` with exactly this shape and no extra keys:

   ```json
   {
     "schemaVersion": "public-kit.high-error-diagnosis.1",
     "authority": "diagnostic_only",
     "valid": false,
     "verdict": "<authoritative verifier verdict, including an empty string if the report has none>",
     "errorCount": 0,
     "failingGateCount": 0,
     "dominantEvidenceFile": "<packet filename responsible for the most errors>",
     "firstDiagnosticArtifact": "<first announced JSON path you inspected>",
     "recommendedAction": "repair-packet-and-reverify"
   }
   ```

   Replace the counts and bracketed values with evidence-backed values. The
   diagnosis must remain diagnostic-only and smaller than 4 KiB.

Do not change `AGENTS.md`, `benchmark-brief.md`, `composer.json`, the installed
skill, `.benchmark-runtime/read-diagnostic.mjs`, or anything in
`review-packet`. Do not run a second verifier or a different verifier command.
Finish after `diagnosis.json` is complete.
