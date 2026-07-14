#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=browser-runtime-common.sh
source "$SCRIPT_DIRECTORY/browser-runtime-common.sh"

main() {
  local override rendered web_before web_after
  if [ "$#" -ne 0 ]; then
    browser_runtime_error "this command takes no arguments; run it from the intended DDEV project."
    return 1
  fi

  browser_runtime_refuse_container
  browser_runtime_init_paths "$SCRIPT_DIRECTORY"
  browser_runtime_load_manifest "$BROWSER_RUNTIME_MANIFEST"
  BROWSER_RUNTIME_PROJECT_ROOT=$(browser_runtime_find_project_root)
  override="$BROWSER_RUNTIME_PROJECT_ROOT/.ddev/$BROWSER_RUNTIME_OVERRIDE_BASENAME"
  browser_runtime_validate_override_ownership "$override"
  browser_runtime_validate_addon_file_ownership

  BROWSER_RUNTIME_DDEV_BIN=$(command -v ddev) || { browser_runtime_error "DDEV is required on the host."; return 1; }
  BROWSER_RUNTIME_DOCKER_BIN=$(command -v docker) || { browser_runtime_error "Docker is required on the host."; return 1; }

  cd "$BROWSER_RUNTIME_PROJECT_ROOT"
  browser_runtime_ddev utility match-constraint ">= $BROWSER_RUNTIME_DDEV_MINIMUM" >/dev/null || {
    browser_runtime_error "DDEV $BROWSER_RUNTIME_DDEV_MINIMUM or newer is required."
    return 1
  }
  browser_runtime_ddev utility dockercheck >/dev/null

  web_before=$(browser_runtime_web_container_id) || {
    browser_runtime_error "the DDEV web container is not running; repair cannot preserve the active agent. Run setup-browser-runtime.sh from the host."
    return 1
  }

  if ! browser_runtime_addon_matches; then
    printf 'Restoring pinned browser add-on %s release %s at commit %s...\n' \
      "$BROWSER_RUNTIME_ADDON" "$BROWSER_RUNTIME_ADDON_RELEASE" "$BROWSER_RUNTIME_ADDON_COMMIT"
    browser_runtime_ddev add-on get "$BROWSER_RUNTIME_ADDON" --version "$BROWSER_RUNTIME_ADDON_COMMIT"
  fi
  browser_runtime_require_addon
  rendered=$(browser_runtime_render_override "$BROWSER_RUNTIME_OVERRIDE_TEMPLATE")
  browser_runtime_write_override "$override" "$rendered"
  browser_runtime_validate_lexical_order
  browser_runtime_validate_effective_compose

  printf 'Converging only the %s service...\n' "$BROWSER_RUNTIME_SERVICE"
  browser_runtime_ddev utility rebuild --service "$BROWSER_RUNTIME_SERVICE" --cache

  browser_runtime_validate_effective_compose
  browser_runtime_require_running_service
  web_after=$(browser_runtime_web_container_id) || return 1
  if [ "$web_before" != "$web_after" ]; then
    browser_runtime_error "DDEV unexpectedly replaced the web container during service-only repair. Stop and inspect the project before continuing."
    return 1
  fi
  browser_runtime_run_smoke
  printf 'Browser runtime repaired without replacing the DDEV web container.\n'
}

main "$@"
