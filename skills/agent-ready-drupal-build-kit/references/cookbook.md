# Drupal Build Cookbook

This cookbook turns the kit's requirements into copy-paste Drupal moves. The contract and playbook say what must be true; these are the worked commands, config shapes, and code snippets that make it true without inventing syntax.

Commands use Drush 13 syntax in the host-side `ddev drush` form. Inside a `ddev codex`, `ddev claude`, or `ddev opencode` session, run `drush` directly. Replace `example-city.ddev.site`, `example.gov`, the `event` bundle, the `example_theme` theme, and the `news_listing` view with the target's real names. Machine names for workflows, text formats, and bundles vary per target: discover them from the running site before granting or importing, and never assume the ids in these examples exist.

Commands that change Composer dependencies are not pre-authorized by this cookbook. Discover the installed capability and compatible package constraint first, record the decision, and get the human owner's approval before running `composer require` or enabling a new module. Do not use a broad dependency-update flag as a copy-paste default.

Stance-type dispositions (multilingual scope, caching/performance budget, update strategy, 404-page quality) are not cookbook material: record each as a row in `review-packet/scoped-gap-list.md`.

## Seed the Non-Admin Editor Role and User

Every custom public bundle needs a non-admin editor who can create and edit it. Drupal CMS ships `content_editor`; when the target has no suitable role, seed one instead of testing as uid 1.

Discover the real workflow and permission names first. Drush 13 rejects unknown permission names, so a failed grant means a wrong name, not a soft warning:

```bash
ddev drush php:eval "echo implode(PHP_EOL, \Drupal::configFactory()->listAll('workflows.workflow.'));"
ddev drush php:eval "echo implode(PHP_EOL, array_keys(\Drupal::service('user.permissions')->getPermissions()));" | grep -i event
```

Create the role and grant site-wide editor basics once (adjust the workflow id and text format id to what discovery returned):

```bash
ddev drush role:create site_editor 'Site editor'
ddev drush role:perm:add site_editor 'access content overview,access media overview,view own unpublished content,view own unpublished media,use text format basic_html,use editorial transition create_new_draft,use editorial transition publish'
```

Then grant the per-bundle set. Repeat this block for every custom public bundle and every bundle that owns repeating public content — this is the ~12-permission checklist per bundle:

```bash
# Bundle: event — content permissions
ddev drush role:perm:add site_editor 'create event content,edit own event content,edit any event content,delete own event content,view event revisions'
# Media types the bundle's fields reference
ddev drush role:perm:add site_editor 'create image media,edit own image media,create document media,edit own document media'
```

Seed the editor user, assign the role, and get a login link for browser evidence:

```bash
ddev drush user:create editor --mail='editor@example.gov' --password='local-only-change-me'
ddev drush user:role:add site_editor editor
ddev drush uli --name=editor --uri=https://example-city.ddev.site
```

Verify the seed before recording editor evidence:

```bash
ddev drush user:information editor
ddev drush role:list --format=yaml
```

`user:information` must show the editor active with exactly the intended role; `role:list` must show the granted permissions on `site_editor`, not on `authenticated`. The role is config: export it (`ddev drush config:export -y`) so `user.role.site_editor.yml` lands in the tracked sync directory. The seeded credentials are local verification fixtures, not production accounts.

## Text Formats for Imported HTML

Imported source HTML goes into a filtered text format, never `full_html`. Granting an editor role `use text format full_html` or importing body values as `full_html` hands every editor raw script/iframe injection and is an off-road move that must be inventoried.

Discover the target's formats and what a candidate format actually allows:

```bash
ddev drush php:eval "echo implode(PHP_EOL, \Drupal::configFactory()->listAll('filter.format.'));"
ddev drush config:get filter.format.basic_html filters.filter_html.settings.allowed_html
```

When importing, set both value and format explicitly:

```php
$node = \Drupal\node\Entity\Node::create([
  'type' => 'event',
  'title' => $sourceTitle,
  'body' => ['value' => $sanitizedHtml, 'format' => 'basic_html'],
]);
```

If the source markup needs tags the filtered format strips (tables, figure/figcaption), extend the filtered format's allowed-HTML list or create a new filtered format with `filter_html` enabled; do not switch to `full_html`. For every imported formatted-text field, record the target field, chosen format, and the sanitizer or transform that produced the stored value, as the build contract's content-field-format record requires.

## Content Import Hygiene

Imported entities need a named, non-anonymous author. Content created by import scripts defaults to the executing user; anonymous-owned content breaks "edit own" permissions and revision attribution. Load the seeded editor (or a dedicated import user) and set `uid` explicitly:

```php
$users = \Drupal::entityTypeManager()
  ->getStorage('user')
  ->loadByProperties(['name' => 'editor']);
$author = reset($users);
if (!$author) {
  throw new \RuntimeException('The editor import account does not exist.');
}
$node = \Drupal\node\Entity\Node::create([
  'type' => 'event',
  'title' => $sourceTitle,
  'uid' => $author->id(),
]);
```

Verify no anonymous-owned content shipped:

```bash
ddev drush sqlq "SELECT COUNT(*) FROM node_field_data WHERE uid = 0"
ddev drush sqlq "SELECT COUNT(*) FROM media_field_data WHERE uid = 0"
```

Derive media entity names from the source alt text or title, not from content-addressed or hashed filenames. `a3f9c2… .jpg` in the media library is unusable for editors; `Summer concert at the amphitheater` is findable:

```php
$media = \Drupal\media\Entity\Media::create([
  'bundle' => 'image',
  'name' => $altText ?: $sourceCaption ?: $sourceTitle,
  'uid' => $author->id(),
  'field_media_image' => ['target_id' => $file->id(), 'alt' => $altText],
]);
```

Give every addressable public-detail bundle a Pathauto pattern (or another explicit editor-owned alias policy) so editor-created content gets readable routes instead of `/node/{id}`. Row-only, embedded, internal, and no-public-detail bundles do not need invented canonical aliases. One Pathauto pattern per addressable bundle, exported as config:

```yaml
# config/sync/pathauto.pattern.event_content.yml
langcode: en
status: true
dependencies:
  config:
    - node.type.event
  module:
    - node
id: event_content
label: 'Event content'
type: 'canonical_entities:node'
pattern: '/events/[node:title]'
selection_criteria:
  5b1e35c2-6a80-4b93-8f0e-0d8a1a2b3c4d:
    id: 'entity_bundle:node'
    negate: false
    context_mapping:
      node: node
    bundles:
      event: event
selection_logic: and
weight: -5
relationships: {  }
```

After patterns exist, generate aliases for already-imported content and spot-check:

```bash
ddev drush pathauto:aliases-generate create all
ddev drush php:eval "echo \Drupal::service('path_alias.manager')->getAliasByPath('/node/12');"
```

## Custom Theme Checklist

A custom default theme opts out of everything the starter theme placed for free. When the public theme is custom, place each of these blocks in the theme's regions — or record a per-block deviation with an owner and rationale in `off-road-inventory.md`:

| Block | Plugin id |
| --- | --- |
| Status messages | `system_messages_block` |
| Page title | `page_title_block` |
| Breadcrumbs | `system_breadcrumb_block` |
| Primary local tasks | `local_tasks_block` |

Without status messages, editors save content and see nothing. Without local tasks, editors lose the View/Edit tabs. Place blocks at `/admin/structure/block` for the custom theme, then export. A placed block is one config file:

```yaml
# config/sync/block.block.example_theme_messages.yml
langcode: en
status: true
dependencies:
  theme:
    - example_theme
id: example_theme_messages
theme: example_theme
region: highlighted
weight: -10
provider: null
plugin: system_messages_block
settings:
  id: system_messages_block
  label: 'Status messages'
  label_display: '0'
  provider: system
visibility: {  }
```

Verify all four exist in exported config for the public theme:

```bash
for plugin in system_messages_block page_title_block system_breadcrumb_block local_tasks_block; do
  grep -l "plugin: $plugin" config/sync/block.block.*.yml || echo "MISSING: $plugin"
done
```

Template rules for the custom theme:

- Every page template variant renders the content region. A `page--front.html.twig` without `{{ page.content }}` silently hides blocks, messages, and the title on that route. Check: `grep -rL 'page.content' web/themes/custom/example_theme/templates --include='page*.html.twig'` must return nothing.
- Node templates keep `{{ title_prefix }}` and `{{ title_suffix }}`; removing them breaks contextual links and metadata that editors and modules rely on.
- Pipe UI strings through translation: `{{ 'Read more'|t }}`, not a bare literal. Source-owned public copy belongs in fields, menus, or blocks, not in Twig at all.
- Override Views output with per-view template suggestions (`views-view--news-listing.html.twig`, `views-view-unformatted--news-listing.html.twig`), not by editing the global `views-view.html.twig`, which silently restyles every present and future view including admin listings.
- Record the base-theme decision (`base theme: false` versus extending a core/contrib base) in the theme's `.info.yml` and note the rationale in the packet; it determines which template and library defaults the theme inherits or forfeits.

Verify breadcrumb presence in the browser on at least one route per public bundle; block config proves placement, not rendering.

## Cache Correctness Snippets

Custom routes must carry cache metadata. A controller that lists entities without list cache tags serves stale content until a full cache clear. For render arrays:

```php
use Drupal\Core\Cache\CacheableMetadata;

$build = ['#theme' => 'item_list', '#items' => $items];
$cache = new CacheableMetadata();
$cache->addCacheTags(['node_list:event']);
$cache->applyTo($build);
return $build;
```

For non-render responses, return a `CacheableResponse` and attach the same tags:

```php
use Drupal\Core\Cache\CacheableResponse;

$response = new CacheableResponse($payload, 200, ['Content-Type' => 'application/json']);
$response->getCacheableMetadata()->addCacheTags(['node_list:event']);
return $response;
```

Preprocess variables derived from the current route must bubble the matching cache context, or the first cached page can win for later routes. Prefer structural route, entity, menu, or taxonomy state over alias parsing:

```php
function example_theme_preprocess_page(array &$variables): void {
  $route_name = \Drupal::routeMatch()->getRouteName();
  $variables['is_news_listing'] = $route_name === 'view.news_listing.page_1';
  $variables['#cache']['contexts'][] = 'route';
}
```

Any View filtering on relative time (an offset date filter such as "now" for upcoming events) needs time-based cache max-age, not tag-only caching. Tag-only caching invalidates when content changes; a past event stays listed as upcoming until someone edits a node. In the View: Advanced → Caching → Time-based, which exports as:

```yaml
cache:
  type: time
  options:
    results_lifespan: 3600
    output_lifespan: 3600
```

## API Warnings

Two APIs that read as if they do what the build needs, and do not:

- `\Drupal::service('path.current')->getPath()` returns the internal path (`/node/42`), not the alias (`/events/summer-concert`). Logic that string-matches it against alias patterns never fires. Use `\Drupal::service('path_alias.manager')->getAliasByPath($path)` when the alias is genuinely needed — and prefer structural signals (route name, bundle, menu placement) over any path string matching.
- On the node preview route (`entity.node.preview`), the route parameter is named `node_preview`, and `\Drupal::routeMatch()->getParameter('node')` returns nothing. Route parameters are not guaranteed to be upcast entity objects on every route; guard with `$node instanceof \Drupal\node\NodeInterface` before calling entity methods, or previews crash while saved pages work.

## Prefer Config-Owned Route SEO

When the project uses Metatag, prefer its exported configuration for route-specific descriptions, titles, and `og:image`. SEO copy hardcoded in `hook_preprocess_html()` is usually invisible to editors and harder to review. Other cache-correct render-metadata implementations can be valid when the target deliberately chooses and documents them.

Discover whether Metatag and its Views integration are already installed before proposing a dependency change:

```bash
ddev composer show drupal/metatag 2>/dev/null || true
ddev drush pm:list --type=module --format=list | grep -E '^(metatag|metatag_views)$' || true
```

If the capability is missing and the audited routes need it, record the package choice in `review-packet/open-decisions.md`, inspect compatible releases with `ddev composer show drupal/metatag --all`, and ask the human owner to approve the dependency change. Only after approval, replace the placeholder with a target-compatible constraint and run the narrow install:

```bash
ddev composer require 'drupal/metatag:<TARGET_COMPATIBLE_CONSTRAINT>'
ddev drush en metatag metatag_views -y
```

If Composer reports that locked transitive dependencies must change, stop and present that expanded update for approval rather than adding a broad update flag automatically.

Set per-bundle defaults at `/admin/config/search/metatag` using tokens (`[node:summary]`, `[node:field_image:entity:url]`); each exports as `metatag.metatag_defaults.node__event.yml`. For Views routes (listings, search pages), `metatag_views` adds a metatag section to the view itself, so the listing's description is config too. Verify by fetching the rendered route, as the playbook's SEO section requires — enabled modules are not evidence.

## Sub-Site and Section Branding

When source sections carry their own branding (a parks sub-site header, a library section logo), model the section explicitly. Avoid deriving it in theme code by string-matching the current alias — aliases change, and `path.current` does not return them anyway.

A common implementation is a section menu, a branding block referencing a media entity, and exported block visibility. A hierarchical shared menu or taxonomy-backed section model can be cleaner when it matches the source and editor workflow; choose one explicit owner instead of mandating one menu per section.

1. If separate menus are the chosen model, create one config entity per section:

```yaml
# config/sync/system.menu.parks.yml
langcode: en
status: true
dependencies: {  }
id: parks
label: 'Parks section'
description: 'Navigation and section identity for the parks sub-site.'
locked: false
```

2. Import the section logo as a media entity (named from its alt text, per import hygiene) and reference it from a custom block type with a media reference field, so editors can swap the artwork without a deploy.

3. Place the branding block and the section's menu block in the theme with visibility conditions in the exported block config (`visibility:` keyed to content types, or to the section vocabulary via a term reference condition when membership is a node field). Visibility lives in reviewable config; membership lives in Drupal data (menu placement, a `field_section` term), not in URL strings parsed at render time.

Verify as the seeded editor: move a node into the section (menu placement or term change) and confirm the section branding follows it on the anonymous route without any code change.
