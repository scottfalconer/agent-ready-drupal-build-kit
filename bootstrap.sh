#!/usr/bin/env bash
set -euo pipefail

repo_url="${AGENT_READY_DRUPAL_REPO_URL:-https://github.com/scottfalconer/agent-ready-drupal-build-kit.git}"
target_dir="${AGENT_READY_DRUPAL_DIR:-agent-ready-drupal-build-kit}"

say() {
  printf '%s\n' "$*"
}

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    say "Missing required command: $1"
    say "Install it, then rerun this bootstrap."
    exit 1
  fi
}

say "Agent-Ready Drupal Build Kit bootstrap"
say

need_command git
need_command curl

if ! command -v docker >/dev/null 2>&1; then
  say "Docker is not installed or not on PATH."
  say "Install a Docker provider first: https://docs.ddev.com/en/stable/users/install/docker-installation/"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  say "Docker is installed but not running or not reachable."
  say "Start your Docker provider, then rerun this bootstrap."
  say "DDEV Docker setup reference: https://docs.ddev.com/en/stable/users/install/docker-installation/"
  exit 1
fi

if ! command -v ddev >/dev/null 2>&1; then
  say "DDEV is not installed. Installing with the official DDEV installer..."
  curl -fsSL https://ddev.com/install.sh | bash
  hash -r 2>/dev/null || true
fi

if ! command -v ddev >/dev/null 2>&1; then
  say "DDEV still was not found after install."
  say "Open a new terminal or follow DDEV install docs: https://docs.ddev.com/en/stable/users/install/ddev-installation/"
  exit 1
fi

say "DDEV:"
ddev version
say

if [ -d "$target_dir/.git" ]; then
  say "Updating existing $target_dir checkout..."
  git -C "$target_dir" pull --ff-only
else
  say "Cloning $repo_url into $target_dir..."
  git clone "$repo_url" "$target_dir"
fi

say
say "Ready."
say
say "Give your AI coding agent this:"
cat <<'PROMPT'
Read skill.md and follow the instructions to build a real local Drupal CMS site.

Source site: [SOURCE_URL]

If I provided a preferred target site name, use it. Otherwise derive a human-readable target site name from the source site title or domain.
PROMPT

say
say "From the kit folder:"
say "  cd $target_dir"
