#!/usr/bin/env bash
# One-command dev start: UI package (watch) + main/preload (watch) +
# Vite dev server + Electron pointed at it.
set -euo pipefail
cd "$(dirname "$0")/.."

export REDJOHN_RENDERER_URL="${REDJOHN_RENDERER_URL:-http://127.0.0.1:5173}"

echo "[dev] building @redjohn/ui once…"
pnpm --filter @redjohn/ui build
echo "[dev] building main + preload once…"
pnpm --filter @redjohn/app run build:main
pnpm --filter @redjohn/app run build:preload

echo "[dev] starting watchers + electron (renderer: $REDJOHN_RENDERER_URL)"
exec pnpm exec concurrently -n ui,main,preload,vite,electron -k \
  "pnpm --filter @redjohn/ui exec tsc -p tsconfig.json --watch --preserveWatchOutput" \
  "pnpm --filter @redjohn/app run dev:main" \
  "pnpm --filter @redjohn/app run dev:preload" \
  "pnpm --filter @redjohn/app run dev:renderer" \
  "pnpm exec wait-on tcp:127.0.0.1:5173 && pnpm --filter @redjohn/app exec electron ."
