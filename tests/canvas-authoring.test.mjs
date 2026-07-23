import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const discoverPath = join(repoRoot, 'scripts', 'canvas-discover.php');
const authorPath = join(repoRoot, 'scripts', 'canvas-author-page.php');
const discover = readFileSync(discoverPath, 'utf8');
const author = readFileSync(authorPath, 'utf8');
const cookbook = readFileSync(join(repoRoot, 'docs', 'cookbook.md'), 'utf8');

test('headless Canvas discovery derives live component versions, slots, and page-tree digests', () => {
  assert.match(discover, /Component::loadMultiple\(\)/);
  assert.match(discover, /getActiveVersion\(\)/);
  assert.match(discover, /getSlotDefinitions\(\)/);
  assert.match(discover, /getDefaultExplicitInput\(\)/);
  assert.match(discover, /PropSource::parse\(/);
  assert.doesNotMatch(discover, /getClientSideInfo\(/);
  assert.match(discover, /getComponentTree\(\)->getValue\(\)/);
  assert.match(discover, /componentTreeSha256/);
  assert.match(discover, /authoringStateSha256/);
  assert.match(discover, /defaultTheme/);
  assert.match(discover, /'mercury'/);
  assert.match(discover, /\^1\\\.8\\\./);
  assert.match(discover, /'description' =>/);
  assert.match(discover, /disabledComponentIds/);
});

test('headless Canvas authoring never trusts manifest versions or silently upserts', () => {
  assert.match(author, /\['create', 'replace'\]/);
  assert.match(author, /implicit upserts are not allowed/);
  assert.match(author, /expectedExistingAuthoringStateSha256/);
  assert.match(author, /hash_equals\(\$expected_digest, \$actual_digest\)/);
  assert.match(author, /->forUpdate\(\)/);
  assert.match(author, /Component::load\(\$component_id\)/);
  assert.match(author, /!\$component->status\(\)/);
  assert.match(author, /'component_version' => \$component->getActiveVersion\(\)/);
  assert.doesNotMatch(author, /\$spec\[['"]componentVersion['"]\]/);
  assert.doesNotMatch(author, /service\(['"]uuid['"]\)->generate/);
  assert.match(author, /uuid is required so dry-run and apply address the same instance/);
});

test('headless Canvas authoring validates source inputs, parent slots, and persisted entity state', () => {
  assert.match(author, /clientModelToInput\(/);
  assert.match(author, /validateComponentInput\(/);
  assert.match(author, /array_keys\(\$component_entities\[\$parent_key\]->getSlotDefinitions\(\)\)/);
  assert.match(author, /setComponentTree\(\$tree\)/);
  assert.match(author, /\$page->validate\(\)/);
  assert.match(author, /\$page->save\(\)/);
  assert.match(author, /\$normalized_tree = \$page->getComponentTree\(\)->getValue\(\)/);
  assert.match(author, /persisted component tree does not match/);
  assert.match(author, /saveComponentInstanceFormViolations\(\$instance_uuids\[\$key\]\)/);
});

test('headless Canvas authoring makes writes explicit and preserves foreign/editor state', () => {
  assert.match(author, /\['--dry-run', '--apply'\]/);
  assert.match(author, /count\(\$extra\) !== 2/);
  assert.match(author, /manifest\.published must be a JSON boolean/);
  assert.match(author, /'status' => \$manifest\['published'\] \?\? FALSE/);
  assert.match(author, /array_key_exists\('description', \$manifest\) \|\| \$page->isNew\(\)/);
  assert.match(author, /getStorage\('path_alias'\)->loadByProperties/);
  assert.match(author, /already owned by the non-Canvas route/);
  assert.match(author, /array_intersect_key\(\$existing_path_value, array_flip\(\['pid', 'langcode'\]\)\)/);
});

test('Canvas cookbook names the real authoring model and preserves structured-content ownership', () => {
  assert.match(cookbook, /`canvas_page` content entity whose `components` field is a `component_tree`/);
  assert.match(cookbook, /Mercury is installed, enabled, and the default theme/);
  assert.match(cookbook, /Views block component/);
  assert.match(cookbook, /Recurring case studies, posts, events, or products stay canonical Drupal entities/);
  assert.match(cookbook, /There is deliberately no implicit upsert/);
  assert.match(cookbook, /explicit write flag/);
  assert.match(cookbook, /defaults to unpublished/);
  assert.match(cookbook, /`drush config:export` does not turn a `canvas_page` into configuration/);
});

const php = spawnSync('php', ['--version'], { encoding: 'utf8' });
test('Canvas PHP helper scripts parse when PHP is available', { skip: php.status !== 0 }, () => {
  for (const script of [discoverPath, authorPath]) {
    const result = spawnSync('php', ['-l', script], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  }
});
