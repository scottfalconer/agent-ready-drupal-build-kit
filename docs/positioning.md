# Why Use This Kit

This kit is for developers and teams who want to try Drupal CMS with an AI coding agent, without already knowing how to build Drupal well.

It is especially for Drupal-curious developers, designers, agencies, and site builders who know an existing site could use a stronger CMS but do not want a blank Drupal install, a pile of unfamiliar terms, or an AI-generated static mimic.

The promise is simple: bring a source site and a local coding agent. The kit tells the agent how to build a real Drupal CMS site, show its work, and leave evidence a Drupal expert can inspect.

It is not trying to make every website a Drupal project. It is for sites that already need a serious CMS: structured content, editorial ownership, search and SEO, accessibility, privacy, integrations, governance, and a path a Drupal maintainer can stand behind.

## The Problem

Generic agents can make something that looks like the old site. That is not enough.

A useful Drupal CMS rebuild needs to answer harder questions:

- What are the real content patterns?
- Which parts should be content types, fields, taxonomy, media, menus, Views, workflows, or integrations?
- Which source claims, forms, legal pages, redirects, and third-party services need human review, provider access, or integration decisions?
- Can an editor maintain the result?
- Can a Drupal maintainer review the architecture and say it is a credible starting point?

This kit makes the agent produce that evidence instead of hiding the important decisions inside a static mimic.

## Why Drupal

Drupal is a strong target when the site needs more than pages:

- structured content that can be reused across listings, landing pages, search, related content, feeds, and future channels;
- editorial workflows, roles, permissions, moderation, and accountability;
- flexible information architecture through content types, fields, taxonomy, entity references, Views, menus, blocks, and aliases;
- integration capacity for forms, search, analytics, CRM, commerce, maps, authentication, APIs, and external services;
- open source ownership with no single-vendor lock-in;
- a large ecosystem and maintainer culture around security, accessibility, performance, and long-lived sites.

The tradeoff is that Drupal rewards good architecture. That is part of why new developers can bounce off it: Drupal gives you powerful primitives, but it expects you to use them coherently. A rushed build can still be bad Drupal. This kit exists to let an agent do the Drupal assembly while forcing the architectural decisions into the open.

## Why Drupal CMS

Drupal CMS makes the Drupal starting point more approachable for marketing teams, content teams, designers, site builders, and agencies.

Use Drupal CMS when you want:

- smart defaults instead of a blank Drupal install;
- recipe-backed features and templates where they fit;
- a marketer-friendly admin and editing path;
- built-in or available support for media, SEO, search, forms, privacy, accessibility tooling, analytics, AI-assisted setup, and updates;
- a path that keeps Drupal's flexibility, security posture, scalability, and open source ownership while reducing the initial setup burden.

In plain terms: Drupal CMS is the friendlier launchpad. The kit is the governed rebuild method that keeps an agent from turning that launchpad into an unreviewable one-off.

## Why This Kit Instead Of Just Prompting An Agent

Use this kit when you need a governed head start, not just a demo.

Without the kit, an agent may:

- produce static HTML that looks plausible but has no Drupal editing experience;
- create controller-rendered pages instead of Drupal-owned content, Views, menus, and aliases;
- bury filterable or governed information in body text;
- hotlink assets, hard-code the final site, or invent missing content;
- skip SEO, accessibility, privacy, redirect, workflow, and integration gaps;
- leave no durable record of why decisions were made.

With the kit, the agent is instructed to:

- build an actual Drupal CMS site with DDEV and `drupal/cms`;
- start from source audit and pattern map before import;
- use Drupal-native primitives first;
- evaluate Drupal CMS recipes and templates before custom overlays;
- record durable intent for load-bearing decisions;
- verify public routes and editor forms;
- create blocked stubs for launch-gate evidence that does not exist yet;
- produce a maintainer review packet with a binary stake-my-name verdict.

That is the marketing value: the agent does not just make something Drupal-shaped. It builds on Drupal CMS, uses Drupal-native primitives, and gives you the records needed to decide what is trustworthy.

## What You Get

A good run gives you:

- a local Drupal CMS build that can be inspected;
- a source audit that says what was observed and what is `UNKNOWN`;
- a pattern map that turns source patterns into Drupal decisions;
- a recipe start-point decision that explains what Drupal CMS gives you by construction;
- durable intent so later agents and maintainers can see why the model exists;
- a scoped gap list that names the work humans still own;
- a complete review packet, including blocked gate records instead of missing evidence;
- a clear answer to whether the result is a complete local rebuild another developer can stand behind.

The most valuable output is often not the local site by itself. It is the combination of local site plus evidence that lets a senior team decide what to trust, what to revise, and what to do next.

## When To Use It

Use this kit when:

- an existing public site needs to be rebuilt or replatformed onto Drupal CMS;
- the team wants an agent to create a strong first pass but still expects human review;
- content structure, editorial workflow, SEO, accessibility, privacy, integrations, redirects, or governance matter;
- you need to compare a potential rebuild approach before committing a full team;
- you want a partner, maintainer, or stakeholder to review concrete evidence instead of a vague prototype.

## When Not To Use It

Do not use this kit when:

- you need a same-day production launch without maintainer review;
- the target should not be Drupal CMS;
- the site is intentionally static and has no meaningful editorial workflow;
- you are not allowed to inspect or rebuild the source site;
- no one will review the Drupal architecture before using it.

## The Human Value

This kit moves the human from manual Drupal assembly to judgment:

- Is this the right content model?
- Which gaps matter commercially or legally?
- Which integrations are real blockers?
- What needs human approval, provider access, or business review?
- Would a Drupal maintainer put their name on the result?

That is the point: not replacing expertise, but making the agent produce work that expertise can evaluate.

## Source Notes

The positioning above follows the public Drupal CMS direction: Drupal CMS is presented as a launchpad for marketers, designers, and content creators, with smart defaults, recipes/templates, marketer-friendly editing, SEO, accessibility, privacy, integrations, AI-assisted tools, and Drupal's open source foundation. For exact current product claims, verify against:

- https://new.drupal.org/drupal-cms
- https://www.drupal.org/association/blog/drupal-launches-game-changing-cms-platform
- https://www.drupal.org/blog/drupal-cms-20-is-here-visual-building-ai-and-site-templates-transform-drupal
