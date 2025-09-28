#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "[ui-build] node not found; skipping UI build (not required for Python-only changes)."
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "[ui-build] npm not found; skipping UI build."
  exit 0
fi

build_ui() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    echo "[ui-build] skip: $dir does not exist"
    return 0
  fi
  echo "[ui-build] building $dir"
  pushd "$dir" >/dev/null
  # Prefer ci if lockfile present
  if [ -f package-lock.json ]; then
    npm ci || npm i
  else
    npm i
  fi
  CI=true npm run build
  popd >/dev/null
}

build_ui "$ROOT_DIR/core/ui"
build_ui "$ROOT_DIR/core/admin_ui"

echo "[ui-build] done."

