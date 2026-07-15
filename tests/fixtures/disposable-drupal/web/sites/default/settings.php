<?php

declare(strict_types=1);

$databases['default']['default'] = [
  'database' => 'db',
  'username' => 'db',
  'password' => 'db',
  'host' => 'db',
  'port' => '3306',
  'driver' => 'mysql',
];

$settings['hash_salt'] = 'YvCFrLk5TVBtgC1kttesLKj2ph_qQGsQP4XXYkzYooC2Ku9PSW2sMCzADjTWWIDZXRizvod72Q';
$settings['trusted_host_patterns'] = ['.*'];
$settings['skip_permissions_hardening'] = TRUE;
$settings['config_sync_directory'] = dirname(__DIR__, 3) . '/config/sync';


// Automatically generated include for settings managed by ddev.
$ddev_settings = __DIR__ . '/settings.ddev.php';
if (getenv('IS_DDEV_PROJECT') == 'true' && is_readable($ddev_settings)) {
  require $ddev_settings;
}
$databases['default']['default'] = array (
  'database' => 'db',
  'username' => 'db',
  'password' => 'db',
  'prefix' => '',
  'host' => 'db',
  'port' => 3306,
  'isolation_level' => 'READ COMMITTED',
  'driver' => 'mysql',
  'namespace' => 'Drupal\\mysql\\Driver\\Database\\mysql',
  'autoload' => 'core/modules/mysql/src/Driver/Database/mysql/',
);
