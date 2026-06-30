# Send Your AI Agent To Drupal

Build a complete local Drupal CMS site, not a static lookalike or Drupal-shaped foundation.

## Human Input

Ask the human for only one required value:

- Source site URL

If the source URL is missing, ask for it before continuing.

## Agent Instructions

1. Make sure you are working in a local coding environment with filesystem and shell access.
2. If this repository is not already available locally, clone it:

   ```bash
   git clone https://github.com/scottfalconer/agent-ready-drupal-build-kit.git
   cd agent-ready-drupal-build-kit
   ```

3. Read `USAGE.md` for the canonical run instructions.
4. Use `AGENTS.md.template` as the operating guide for the target Drupal CMS workspace.
5. Create a clean Drupal CMS project workspace outside the kit folder.
6. Create the review packet at `review-packet/`.
7. Build with DDEV and `drupal/cms`; include public content, media, visual design, routes, functionality, and editor experience.
8. Do not substitute static HTML, screenshots, a local file preview, a CMS-shaped packet, a stock-theme placeholder, or a separate frontend.

## Build Assumption

Assume the human's source URL is authorized for a public-facing local rebuild. Do not turn the build into placeholders because permission is not separately recorded.

Mark uncertain facts, missing evidence, and assumptions clearly in the review packet instead of inventing details.
