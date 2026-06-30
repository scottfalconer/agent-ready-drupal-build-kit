# Send Your AI Agent To Drupal

Build a real local Drupal CMS site, not a static lookalike.

## Human Input

Ask the human for only one required value:

- Source site URL

If the source URL is missing, ask for it before continuing. If the human supplied a preferred target site name, use it; otherwise derive a human-readable target site name from the source site title or domain.

## Agent Instructions

1. Make sure you are working in a local coding environment with filesystem and shell access.
2. If this repository is not already available locally, clone it:

   ```bash
   git clone https://github.com/scottfalconer/agent-ready-drupal-build-kit.git
   cd agent-ready-drupal-build-kit
   ```

3. Read `USAGE.md` for the canonical run instructions.
4. Use `AGENTS.md.template` as the operating guide for the target Drupal CMS workspace.
5. Create the Drupal CMS project as a sibling folder.
6. Create the review packet at `review-packet/`.
7. Build with DDEV and `drupal/cms`; do not substitute static HTML, screenshots, a local file preview, a CMS-shaped packet, or a separate frontend.

## Source Use

Use this kit only with source sites the human is allowed to inspect and rebuild. Do not copy source content, images, files, videos, private data, credentials, tracking IDs, or third-party integrations unless the human has the right to use them.

Mark uncertain facts, missing evidence, and assumptions clearly in the review packet instead of inventing details.
