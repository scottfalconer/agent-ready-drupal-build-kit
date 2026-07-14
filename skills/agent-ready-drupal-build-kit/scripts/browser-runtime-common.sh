#!/usr/bin/env bash

# Shared Bash 3.2-compatible helpers for the host-only browser runtime scripts.

BROWSER_RUNTIME_OVERRIDE_BASENAME="docker-compose.zz-agent-ready-verifier.yaml"
BROWSER_RUNTIME_OVERRIDE_START="# agent-ready-drupal-build-kit:browser-runtime:start"
BROWSER_RUNTIME_OVERRIDE_END="# agent-ready-drupal-build-kit:browser-runtime:end"

browser_runtime_error() {
  printf 'Browser runtime error: %s\n' "$*" >&2
  return 1
}

browser_runtime_refuse_container() {
  if [ -e /.dockerenv ] || [ "${IS_DDEV_PROJECT:-}" = "true" ] || [ -n "${DDEV_APPROOT:-}" ]; then
    browser_runtime_error "this is a host-only command. Exit the DDEV container and run it from the DDEV project root."
    return 1
  fi
}

browser_runtime_find_project_root() {
  local directory parent
  directory=$(pwd -P)
  while :; do
    if [ -f "$directory/.ddev/config.yaml" ]; then
      printf '%s\n' "$directory"
      return 0
    fi
    parent=$(dirname "$directory")
    if [ "$parent" = "$directory" ]; then
      break
    fi
    directory=$parent
  done
  browser_runtime_error "no active DDEV project root was found above $(pwd -P). Run this command from inside the intended project."
}

browser_runtime_init_paths() {
  local script_directory=$1
  BROWSER_RUNTIME_ASSET_DIRECTORY=$(cd "$script_directory/../assets/browser-runtime" 2>/dev/null && pwd -P) || {
    browser_runtime_error "browser runtime assets are missing beside the installed script. Reinstall the build-kit skill."
    return 1
  }
  BROWSER_RUNTIME_MANIFEST="$BROWSER_RUNTIME_ASSET_DIRECTORY/runtime.json"
  BROWSER_RUNTIME_OVERRIDE_TEMPLATE="$BROWSER_RUNTIME_ASSET_DIRECTORY/$BROWSER_RUNTIME_OVERRIDE_BASENAME"
  BROWSER_RUNTIME_SMOKE_SCRIPT="$script_directory/browser-runtime-smoke.mjs"
  for browser_runtime_path in "$BROWSER_RUNTIME_MANIFEST" "$BROWSER_RUNTIME_OVERRIDE_TEMPLATE" "$BROWSER_RUNTIME_SMOKE_SCRIPT"; do
    if [ ! -f "$browser_runtime_path" ] || [ -L "$browser_runtime_path" ]; then
      browser_runtime_error "required managed asset is missing or unsafe: $browser_runtime_path"
      return 1
    fi
  done
}

browser_runtime_manifest_string() {
  local key=$1 file=$2 matches count
  matches=$(sed -n 's/^[[:space:]]*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)"[[:space:]]*,\{0,1\}[[:space:]]*$/\1/p' "$file")
  count=$(printf '%s\n' "$matches" | awk 'NF { count += 1 } END { print count + 0 }')
  if [ "$count" -ne 1 ]; then
    browser_runtime_error "runtime manifest key $key must occur exactly once as a string."
    return 1
  fi
  printf '%s\n' "$matches"
}

browser_runtime_load_manifest() {
  local manifest=$1
  BROWSER_RUNTIME_SCHEMA_VERSION=$(browser_runtime_manifest_string schemaVersion "$manifest") || return 1
  BROWSER_RUNTIME_DDEV_MINIMUM=$(browser_runtime_manifest_string ddevMinimumVersion "$manifest") || return 1
  BROWSER_RUNTIME_ADDON=$(browser_runtime_manifest_string addOnRepository "$manifest") || return 1
  BROWSER_RUNTIME_ADDON_RELEASE=$(browser_runtime_manifest_string addOnRelease "$manifest") || return 1
  BROWSER_RUNTIME_ADDON_METADATA_DIRECTORY=$(browser_runtime_manifest_string addOnMetadataDirectory "$manifest") || return 1
  BROWSER_RUNTIME_ADDON_COMPOSE_SHA256=$(browser_runtime_manifest_string addOnComposeSha256 "$manifest") || return 1
  BROWSER_RUNTIME_ADDON_CONFIG_SHA256=$(browser_runtime_manifest_string addOnConfigSha256 "$manifest") || return 1
  BROWSER_RUNTIME_SERVICE=$(browser_runtime_manifest_string serviceName "$manifest") || return 1
  BROWSER_RUNTIME_GRID_URL=$(browser_runtime_manifest_string gridUrl "$manifest") || return 1
  BROWSER_RUNTIME_IMAGE=$(browser_runtime_manifest_string browserImage "$manifest") || return 1
  BROWSER_RUNTIME_MAX_SESSIONS=$(browser_runtime_manifest_string maxSessions "$manifest") || return 1
  BROWSER_RUNTIME_OVERRIDE_MAX_SESSIONS=$(browser_runtime_manifest_string overrideMaxSessions "$manifest") || return 1
  BROWSER_RUNTIME_SHARED_MEMORY=$(browser_runtime_manifest_string sharedMemory "$manifest") || return 1
  BROWSER_RUNTIME_SHARED_MEMORY_BYTES=$(browser_runtime_manifest_string sharedMemoryBytes "$manifest") || return 1
  BROWSER_RUNTIME_HEALTHCHECK_URL=$(browser_runtime_manifest_string healthcheckUrl "$manifest") || return 1
  BROWSER_RUNTIME_HEALTHCHECK_INTERVAL=$(browser_runtime_manifest_string healthcheckInterval "$manifest") || return 1
  BROWSER_RUNTIME_HEALTHCHECK_TIMEOUT=$(browser_runtime_manifest_string healthcheckTimeout "$manifest") || return 1
  BROWSER_RUNTIME_HEALTHCHECK_RETRIES=$(browser_runtime_manifest_string healthcheckRetries "$manifest") || return 1
  BROWSER_RUNTIME_HEALTHCHECK_START_PERIOD=$(browser_runtime_manifest_string healthcheckStartPeriod "$manifest") || return 1
  BROWSER_RUNTIME_SMOKE_TIMEOUT_MS=$(browser_runtime_manifest_string smokeTimeoutMs "$manifest") || return 1

  case "$BROWSER_RUNTIME_IMAGE" in
    selenium/standalone-chromium:*@sha256:????????????????????????????????????????????????????????????????) ;;
    *) browser_runtime_error "browserImage must be an exact Selenium Chromium tag and sha256 manifest-list digest."; return 1 ;;
  esac
  if [ "$BROWSER_RUNTIME_GRID_URL" != "http://$BROWSER_RUNTIME_SERVICE:4444" ]; then
    browser_runtime_error "gridUrl must use the selected DDEV service DNS name on port 4444."
    return 1
  fi
  if [ "$BROWSER_RUNTIME_MAX_SESSIONS" != "1" ] || [ "$BROWSER_RUNTIME_OVERRIDE_MAX_SESSIONS" != "false" ]; then
    browser_runtime_error "the supported verifier runtime must expose exactly one non-overridable session."
    return 1
  fi
  if [ "$BROWSER_RUNTIME_SHARED_MEMORY_BYTES" != "2147483648" ]; then
    browser_runtime_error "the supported verifier runtime must allocate exactly 2 GiB of shared memory."
    return 1
  fi
}

browser_runtime_sha256() {
  local file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{ print $1 }'
  else
    browser_runtime_error "sha256sum or shasum is required to verify managed add-on assets."
    return 1
  fi
}

browser_runtime_validate_override_ownership() {
  local override=$1
  if [ ! -e "$override" ] && [ ! -L "$override" ]; then
    return 0
  fi
  if [ -L "$override" ] || [ ! -f "$override" ]; then
    browser_runtime_error "$override must be a regular non-symlink file."
    return 1
  fi
  if [ "$(grep -Fxc "$BROWSER_RUNTIME_OVERRIDE_START" "$override" || true)" -ne 1 ] ||
     [ "$(grep -Fxc "$BROWSER_RUNTIME_OVERRIDE_END" "$override" || true)" -ne 1 ]; then
    browser_runtime_error "$override already exists but is not marker-owned by the build kit; it was not changed."
    return 1
  fi
}

browser_runtime_render_override() {
  local template=$1 rendered
  rendered=$(cat "$template")
  rendered=${rendered//@@SCHEMA_VERSION@@/$BROWSER_RUNTIME_SCHEMA_VERSION}
  rendered=${rendered//@@BROWSER_IMAGE@@/$BROWSER_RUNTIME_IMAGE}
  rendered=${rendered//@@SHARED_MEMORY@@/$BROWSER_RUNTIME_SHARED_MEMORY}
  rendered=${rendered//@@GRID_URL@@/$BROWSER_RUNTIME_GRID_URL}
  rendered=${rendered//@@MAX_SESSIONS@@/$BROWSER_RUNTIME_MAX_SESSIONS}
  rendered=${rendered//@@OVERRIDE_MAX_SESSIONS@@/$BROWSER_RUNTIME_OVERRIDE_MAX_SESSIONS}
  rendered=${rendered//@@HEALTHCHECK_URL@@/$BROWSER_RUNTIME_HEALTHCHECK_URL}
  rendered=${rendered//@@HEALTHCHECK_INTERVAL@@/$BROWSER_RUNTIME_HEALTHCHECK_INTERVAL}
  rendered=${rendered//@@HEALTHCHECK_TIMEOUT@@/$BROWSER_RUNTIME_HEALTHCHECK_TIMEOUT}
  rendered=${rendered//@@HEALTHCHECK_RETRIES@@/$BROWSER_RUNTIME_HEALTHCHECK_RETRIES}
  rendered=${rendered//@@HEALTHCHECK_START_PERIOD@@/$BROWSER_RUNTIME_HEALTHCHECK_START_PERIOD}
  if printf '%s\n' "$rendered" | grep -Fq '@@'; then
    browser_runtime_error "the browser runtime override template contains an unresolved token."
    return 1
  fi
  printf '%s\n' "$rendered"
}

browser_runtime_override_matches() {
  local override=$1 rendered=$2 existing
  [ -f "$override" ] || return 1
  existing=$(cat "$override")
  [ "$existing" = "$rendered" ]
}

browser_runtime_write_override() {
  local override=$1 rendered=$2 temporary
  BROWSER_RUNTIME_OVERRIDE_CHANGED=false
  if browser_runtime_override_matches "$override" "$rendered"; then
    return 0
  fi
  temporary=$(mktemp "$(dirname "$override")/.agent-ready-browser-runtime.XXXXXX") || return 1
  if ! printf '%s\n' "$rendered" > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  chmod 0644 "$temporary"
  if ! mv -f "$temporary" "$override"; then
    rm -f "$temporary"
    return 1
  fi
  BROWSER_RUNTIME_OVERRIDE_CHANGED=true
}

browser_runtime_validate_addon_file_ownership() {
  local file
  for file in "$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/docker-compose.selenium-chrome.yaml" \
              "$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/config.selenium-standalone-chrome.yaml"; do
    if [ -L "$file" ]; then
      browser_runtime_error "refusing to replace symbolic-link add-on asset: $file"
      return 1
    fi
    if [ -e "$file" ] && ! grep -Fqx '#ddev-generated' "$file"; then
      browser_runtime_error "$file is not marked as DDEV-generated; move it aside or reconcile it before setup."
      return 1
    fi
  done
}

browser_runtime_addon_matches() {
  local metadata compose config repository version
  metadata="$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/addon-metadata/$BROWSER_RUNTIME_ADDON_METADATA_DIRECTORY/manifest.yaml"
  compose="$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/docker-compose.selenium-chrome.yaml"
  config="$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/config.selenium-standalone-chrome.yaml"
  [ -f "$metadata" ] && [ ! -L "$metadata" ] && [ -f "$compose" ] && [ ! -L "$compose" ] && [ -f "$config" ] && [ ! -L "$config" ] || return 1
  repository=$(awk -F ': *' '$1 == "repository" { print $2 }' "$metadata")
  version=$(awk -F ': *' '$1 == "version" { print $2 }' "$metadata")
  [ "$repository" = "$BROWSER_RUNTIME_ADDON" ] || return 1
  [ "$version" = "$BROWSER_RUNTIME_ADDON_RELEASE" ] || return 1
  [ "$(browser_runtime_sha256 "$compose")" = "$BROWSER_RUNTIME_ADDON_COMPOSE_SHA256" ] || return 1
  [ "$(browser_runtime_sha256 "$config")" = "$BROWSER_RUNTIME_ADDON_CONFIG_SHA256" ] || return 1
}

browser_runtime_require_addon() {
  if ! browser_runtime_addon_matches; then
    browser_runtime_error "the installed DDEV browser add-on does not match release $BROWSER_RUNTIME_ADDON_RELEASE and its recorded checksums. Run the host setup command before launching an agent."
    return 1
  fi
}

browser_runtime_validate_lexical_order() {
  local generated override last
  generated="$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/docker-compose.selenium-chrome.yaml"
  override="$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/$BROWSER_RUNTIME_OVERRIDE_BASENAME"
  [ -f "$generated" ] || { browser_runtime_error "the pinned add-on Compose file is missing."; return 1; }
  [ -f "$override" ] || { browser_runtime_error "the verifier override is missing."; return 1; }
  last=$(printf '%s\n%s\n' "$(basename "$generated")" "$(basename "$override")" | LC_ALL=C sort | tail -n 1)
  if [ "$last" != "$BROWSER_RUNTIME_OVERRIDE_BASENAME" ]; then
    browser_runtime_error "$BROWSER_RUNTIME_OVERRIDE_BASENAME must sort after the add-on Compose file."
    return 1
  fi
}

browser_runtime_ddev() {
  "$BROWSER_RUNTIME_DDEV_BIN" "$@"
}

browser_runtime_docker() {
  "$BROWSER_RUNTIME_DOCKER_BIN" "$@"
}

browser_runtime_compose_service_block() {
  local compose=$1 service=$2
  printf '%s\n' "$compose" | awk -v service="$service" '
    $0 == "  " service ":" { capture = 1; print; next }
    capture && $0 ~ /^  [^[:space:]][^:]*:/ { exit }
    capture { print }
  '
}

browser_runtime_validate_effective_compose() {
  local compose service_block expected
  compose=$(browser_runtime_ddev utility compose-config) || {
    browser_runtime_error "DDEV could not resolve the effective Compose configuration."
    return 1
  }
  service_block=$(browser_runtime_compose_service_block "$compose" "$BROWSER_RUNTIME_SERVICE")
  [ -n "$service_block" ] || { browser_runtime_error "effective Compose does not contain $BROWSER_RUNTIME_SERVICE."; return 1; }

  for expected in \
    "    image: $BROWSER_RUNTIME_IMAGE" \
    "      SE_NODE_GRID_URL: $BROWSER_RUNTIME_GRID_URL" \
    "      SE_NODE_MAX_SESSIONS: \"$BROWSER_RUNTIME_MAX_SESSIONS\"" \
    "      SE_NODE_OVERRIDE_MAX_SESSIONS: \"$BROWSER_RUNTIME_OVERRIDE_MAX_SESSIONS\"" \
    "    shm_size: \"$BROWSER_RUNTIME_SHARED_MEMORY_BYTES\"" \
    "      interval: $BROWSER_RUNTIME_HEALTHCHECK_INTERVAL" \
    "      timeout: $BROWSER_RUNTIME_HEALTHCHECK_TIMEOUT" \
    "      retries: $BROWSER_RUNTIME_HEALTHCHECK_RETRIES" \
    "      start_period: $BROWSER_RUNTIME_HEALTHCHECK_START_PERIOD"; do
    if ! printf '%s\n' "$service_block" | grep -Fqx "$expected"; then
      browser_runtime_error "effective Compose drifted from the runtime manifest: missing '$expected'."
      return 1
    fi
  done
  if ! printf '%s\n' "$service_block" | grep -Fq "curl -fsS $BROWSER_RUNTIME_HEALTHCHECK_URL" ||
     ! printf '%s\n' "$service_block" | grep -Fq '"ready"'; then
    browser_runtime_error "effective Compose healthcheck must require Grid value.ready=true."
    return 1
  fi
  BROWSER_RUNTIME_EFFECTIVE_COMPOSE=$compose
  BROWSER_RUNTIME_EFFECTIVE_SERVICE=$service_block
}

browser_runtime_container_name() {
  local service=$1 block
  block=$(browser_runtime_compose_service_block "$BROWSER_RUNTIME_EFFECTIVE_COMPOSE" "$service")
  printf '%s\n' "$block" | awk '$1 == "container_name:" { print $2; exit }'
}

browser_runtime_running_service_matches() {
  local container inspect image status health shm environment health_test
  container=$(browser_runtime_container_name "$BROWSER_RUNTIME_SERVICE")
  [ -n "$container" ] || return 1
  inspect=$(browser_runtime_docker inspect --format '{{.Config.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.HostConfig.ShmSize}}|{{json .Config.Env}}|{{json .Config.Healthcheck.Test}}' "$container" 2>/dev/null) || return 1
  IFS='|' read -r image status health shm environment health_test <<EOF
$inspect
EOF
  [ "$image" = "$BROWSER_RUNTIME_IMAGE" ] || return 1
  [ "$status" = "running" ] || return 1
  [ "$health" = "healthy" ] || return 1
  [ "$shm" = "$BROWSER_RUNTIME_SHARED_MEMORY_BYTES" ] || return 1
  case "$environment" in *"SE_NODE_GRID_URL=$BROWSER_RUNTIME_GRID_URL"*) ;; *) return 1 ;; esac
  case "$environment" in *"SE_NODE_MAX_SESSIONS=$BROWSER_RUNTIME_MAX_SESSIONS"*) ;; *) return 1 ;; esac
  case "$environment" in *"SE_NODE_OVERRIDE_MAX_SESSIONS=$BROWSER_RUNTIME_OVERRIDE_MAX_SESSIONS"*) ;; *) return 1 ;; esac
  case "$health_test" in *"$BROWSER_RUNTIME_HEALTHCHECK_URL"*'ready'*) ;; *) return 1 ;; esac
}

browser_runtime_require_running_service() {
  if ! browser_runtime_running_service_matches; then
    browser_runtime_error "$BROWSER_RUNTIME_SERVICE is not running with the manifest-selected image, capacity, shared memory, and healthy Grid check."
    return 1
  fi
}

browser_runtime_web_container_id() {
  local container
  container=$(browser_runtime_container_name web)
  [ -n "$container" ] || { browser_runtime_error "effective Compose does not expose the DDEV web container name."; return 1; }
  browser_runtime_docker inspect --format '{{.Id}}' "$container" 2>/dev/null
}

browser_runtime_smoke_relative_path() {
  case "$BROWSER_RUNTIME_SMOKE_SCRIPT" in
    "$BROWSER_RUNTIME_PROJECT_ROOT"/*) printf '%s\n' "${BROWSER_RUNTIME_SMOKE_SCRIPT#"$BROWSER_RUNTIME_PROJECT_ROOT"/}" ;;
    *) browser_runtime_error "the smoke helper must be installed inside the active DDEV project."; return 1 ;;
  esac
}

browser_runtime_run_smoke() {
  local relative
  relative=$(browser_runtime_smoke_relative_path) || return 1
  browser_runtime_ddev exec --service web --dir /var/www/html env \
    "AGENT_READY_BROWSER_GRID_URL=$BROWSER_RUNTIME_GRID_URL" \
    "AGENT_READY_BROWSER_SMOKE_TIMEOUT_MS=$BROWSER_RUNTIME_SMOKE_TIMEOUT_MS" \
    node "$relative"
}
