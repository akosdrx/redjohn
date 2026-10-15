#!/usr/bin/env bash
set -euo pipefail
RJ_LINUX_ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
[ "$(uname -s)" = Linux ] || { echo "Build the Linux desktop on Linux for its target architecture." >&2; exit 1; }
cd "$RJ_LINUX_ROOT"
if [ -f rj-linux-desktop/.build/environment.sh ]; then source rj-linux-desktop/.build/environment.sh; fi
: "${REDJOHN_BUILD_PYTHON:?Use a Linux build environment containing redjohn-core and PyInstaller}"
pnpm install --frozen-lockfile
pnpm build
bash scripts/build-engine.sh
cd app
node node_modules/electron-builder/cli.js --config ../rj-linux-desktop/packaging/electron-builder.yml --linux "--${RJ_LINUX_ARCH:-x64}"
