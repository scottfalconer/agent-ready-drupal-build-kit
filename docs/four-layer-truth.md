# Four-Layer Truth Model

This model tells agents which evidence layer they have and which layer comes next.

## Layer 1: API or Command Success

The command returned success.

Examples:

- recipe apply completed;
- migration import command finished;
- `ddev drush status` reports a successful Drupal bootstrap;
- entity write returned an ID.

Next evidence layer: CMS readback.

## Layer 2: CMS Readback

Drupal stores and returns expected configuration or content.

Examples:

- config export contains expected config;
- entity query returns expected node;
- field values read back correctly.

Next evidence layer: public route status.

## Layer 3: Public Route Status

The target route returns the expected public status for the intended visitor state.

Examples:

- strict 200 for public pages;
- expected 301 for approved redirects;
- expected 403 for private routes.

Next evidence layer: browser-rendered truth.

## Layer 4: Browser-Rendered Truth

A browser renders the expected target page state and behavior.

Examples:

- visible content and metadata match approved target expectations;
- navigation and interactions work;
- console, accessibility, performance, and security evidence are attached.

Launch decisions use the gate records in `docs/output-inventory.md`.

For local builds, DDEV is the default environment for collecting these layers. Static previews and non-Drupal servers sit outside the Drupal CMS evidence model.
