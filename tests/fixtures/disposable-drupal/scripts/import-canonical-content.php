<?php

declare(strict_types=1);

use Drupal\file\Entity\File;
use Drupal\node\Entity\Node;
use Drupal\path_alias\Entity\PathAlias;

$file_uri = 'public://proof.txt';
$timestamp = 1704067200;
if (!is_file($file_uri)) {
  throw new RuntimeException('The digest-bound public file was not imported.');
}

$file = File::create([
  'uuid' => '303c7d48-7a90-4fc3-bb50-789da1baedc1',
  'filename' => 'proof.txt',
  'uri' => $file_uri,
  'status' => 1,
  'created' => $timestamp,
]);
$file->save();

$node = Node::create([
  'uuid' => '74cc8780-79e8-4eda-8e75-b9f6f4b2fac7',
  'type' => 'proof',
  'title' => 'Disposable reproduction proof',
  'status' => 1,
  'uid' => 1,
  'created' => $timestamp,
  'changed' => $timestamp,
  'revision_timestamp' => $timestamp,
]);
$node->save();

$alias = PathAlias::create([
  'uuid' => 'b5496955-cf0f-4d2c-8e12-bb51e4e2f856',
  'path' => '/node/' . $node->id(),
  'alias' => '/reproduction-proof',
  'langcode' => 'en',
]);
$alias->save();
