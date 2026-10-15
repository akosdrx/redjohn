#!/usr/bin/env bash
set -euo pipefail
# Build host dependencies, not runtime installation on app launch.
# Covers the core build only: Electron, the engine (PyInstaller) and the
# relocatable OpenViking Python (libssl/libffi/zlib headers). Assessment tools
# are NOT bundled — they download on demand at first run or are installed from
# the system — so the former tool-build deps (golang-go, libyaml-dev,
# libreadline-dev, libpcap-dev, libpq-dev) are omitted here; install them only
# if you build the optional manual tool bundle (scripts/build-native-tools.py).
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git curl build-essential \
  pkg-config libssl-dev libffi-dev zlib1g-dev libseccomp-dev libgtk-3-0 libnss3 libxss1 libgbm1 \
  libasound2t64 libxkbcommon0 libatk-bridge2.0-0 zstd || \
sudo apt-get install -y python3 python3-venv python3-pip git curl build-essential \
  pkg-config libssl-dev libffi-dev zlib1g-dev libseccomp-dev libgtk-3-0 libnss3 libxss1 libgbm1 \
  libasound2 libxkbcommon0 libatk-bridge2.0-0 zstd
python3 -m venv "$(dirname "$0")/../.bootstrap"
"$(dirname "$0")/../.bootstrap/bin/python" -m pip install 'httpx>=0.28'
"$(dirname "$0")/../.bootstrap/bin/python" "$(dirname "$0")/bootstrap.py"
