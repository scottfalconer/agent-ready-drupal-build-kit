# Four-Layer Truth Model

This model prevents agents from turning one kind of success into a stronger claim.

## Layer 1: API or Command Success

The command returned success.

Examples:

- recipe apply completed;
- migration import command finished;
- `ddev drush status` reports a successful Drupal bootstrap;
- entity write returned an ID.

This does not prove the CMS stores the right thing or that visitors can see it.

## Layer 2: CMS Readback

Drupal stores and returns expected configuration or content.

Examples:

- config export contains expected config;
- entity query returns expected node;
- field values read back correctly.

This does not prove public route behavior.

## Layer 3: Public Route Status

The target route returns the expected public status for the intended visitor state.

Examples:

- strict 200 for public pages;
- expected 301 for approved redirects;
- expected 403 for private routes.

This does not prove browser-rendered functional parity.

## Layer 4: Browser-Rendered Truth

A browser renders the expected target page state and behavior.

Examples:

- visible content and metadata match approved target expectations;
- navigation and interactions work;
- console, accessibility, performance, and security evidence are attached.

This still does not approve launch unless all launch gates are accepted.

For local builds, DDEV is the default environment for collecting these layers. Static previews and non-Drupal servers sit outside the model and cannot prove Drupal CMS behavior.
