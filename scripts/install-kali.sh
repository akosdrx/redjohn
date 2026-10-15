#!/usr/bin/env bash
# ==============================================================================
# RedJohn / Strix — Native Kali Linux Installer & Desktop Builder
# ==============================================================================
# Usage:
#   ./scripts/install-kali.sh              # Install CLI + Go TUI + Web Viewer + Kali shims
#   ./scripts/install-kali.sh --desktop    # Also build & install the Kali .deb Desktop app
#   ./scripts/install-kali.sh --no-apt     # Skip APT package installation
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUILD_DESKTOP=0
SKIP_APT=0

for arg in "$@"; do
  case "$arg" in
    --desktop)
      BUILD_DESKTOP=1
      ;;
    --no-apt)
      SKIP_APT=1
      ;;
    -h|--help)
      echo "Usage: ./scripts/install-kali.sh [--desktop] [--no-apt]"
      echo "  --desktop   Build and install the native Kali Linux .deb Electron Desktop app"
      echo "  --no-apt    Skip APT system package checks/installations"
      exit 0
      ;;
  esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

echo "==> [1/6] Checking Kali Linux / Debian environment..."
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "    Detected OS: ${PRETTY_NAME:-Linux}"
fi

if [ "$SKIP_APT" -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
  echo "==> [2/6] Installing Kali Linux system & assessment dependencies via APT..."
  $SUDO apt-get update -qq || true
  CORE_PKGS=(
    python3
    python3-venv
    python3-pip
    python3-dev
    libseccomp2
    libseccomp-dev
    build-essential
    ca-certificates
    curl
    git
    jq
    ripgrep
  )
  $SUDO apt-get install -y "${CORE_PKGS[@]}"

  KALI_TOOLS=(
    nmap
    sqlmap
    ffuf
    nuclei
    httpx-toolkit
    subfinder
    gobuster
    nikto
    wpscan
    seclists
    wordlists
  )
  for pkg in "${KALI_TOOLS[@]}"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
      $SUDO apt-get install -y "$pkg" || true
    fi
  done

  if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "    Decompressing /usr/share/wordlists/rockyou.txt.gz..."
    $SUDO gzip -dk /usr/share/wordlists/rockyou.txt.gz || true
  fi
else
  echo "==> [2/6] Skipping APT package installation."
fi

echo "==> [3/6] Setting up Python virtual environment (.venv)..."
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x "$ROOT_DIR/.venv/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$ROOT_DIR/.venv"
fi

VENV_PY="$ROOT_DIR/.venv/bin/python"
VENV_PIP="$ROOT_DIR/.venv/bin/pip"

"$VENV_PIP" install --upgrade pip wheel setuptools >/dev/null
echo "    Installing Strix engine (Docker-free local runtime + 170 skills) and RedJohn Core..."
"$VENV_PIP" install -e "$ROOT_DIR" -e "$ROOT_DIR/packages/core[anthropic]"

echo "==> [4/6] Configuring native Go Bubble Tea TUI binary for Linux..."
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *) GO_ARCH="$ARCH_RAW" ;;
esac

mkdir -p "$ROOT_DIR/strix/bin"
PREBUILT_TUI="$ROOT_DIR/strix/bin/strix-tui-linux-${GO_ARCH}"
if command -v go >/dev/null 2>&1 && [ -f "$ROOT_DIR/strix/interface/tui/go.mod" ]; then
  echo "    Building strix-tui from Go source for linux/${GO_ARCH}..."
  (
    cd "$ROOT_DIR/strix/interface/tui"
    CGO_ENABLED=0 GOOS=linux GOARCH="$GO_ARCH" go build -ldflags="-s -w" -o "$PREBUILT_TUI" ./cmd/strix-tui
  )
fi

if [ -f "$PREBUILT_TUI" ]; then
  cp -f "$PREBUILT_TUI" "$ROOT_DIR/strix/bin/strix-tui"
  chmod +x "$PREBUILT_TUI" "$ROOT_DIR/strix/bin/strix-tui"
  echo "    Active TUI binary: $PREBUILT_TUI"
else
  echo "    WARNING: Prebuilt TUI binary not found for linux/${GO_ARCH}. Install 'golang-go' and re-run." >&2
fi

echo "==> [5/6] Configuring Kali tool shims & CLI entrypoints (strix, redjohn, rj)..."
SHIM_DIR="$HOME/.strix/kali-shims"
mkdir -p "$SHIM_DIR" "$HOME/.local/bin"

if command -v httpx-toolkit >/dev/null 2>&1; then
  ln -sf "$(command -v httpx-toolkit)" "$SHIM_DIR/httpx"
  echo "    Linked Kali httpx shim -> $(command -v httpx-toolkit)"
fi
if command -v zaproxy >/dev/null 2>&1 && ! command -v zap.sh >/dev/null 2>&1; then
  ln -sf "$(command -v zaproxy)" "$SHIM_DIR/zap.sh"
fi

for cmd_name in strix redjohn rj; do
  WRAPPER="$HOME/.local/bin/$cmd_name"
  cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
export PATH="$SHIM_DIR:\$PATH"
exec "$ROOT_DIR/.venv/bin/$cmd_name" "\$@"
EOF
  chmod +x "$WRAPPER"
  if [ -n "$SUDO" ] || [ -w /usr/local/bin ]; then
    $SUDO ln -sf "$WRAPPER" "/usr/local/bin/$cmd_name" 2>/dev/null || true
  fi
done

echo "    Installing Playwright Chromium browser for headless DOM/XSS verification..."
"$ROOT_DIR/.venv/bin/playwright" install chromium || true

if [ "$BUILD_DESKTOP" -eq 1 ]; then
  echo "==> [6/6] Building native Kali Linux Desktop (.deb & AppImage)..."
  "$VENV_PIP" install pyinstaller
  SKIP_NATIVE_MEMORY=1 REDJOHN_BUILD_PYTHON="$VENV_PY" ./scripts/build-engine.sh
  if command -v pnpm >/dev/null 2>&1; then
    pnpm install
    pnpm --filter @redjohn/app run build
    SKIP_NATIVE_MEMORY=1 pnpm --filter @redjohn/app run package:linux
    DEB_PKG="$(find "$ROOT_DIR/release" -maxdepth 1 -name "*.deb" | head -n 1 || true)"
    if [ -n "$DEB_PKG" ] && command -v dpkg >/dev/null 2>&1; then
      echo "    Installing Kali Linux package: $DEB_PKG"
      $SUDO dpkg -i "$DEB_PKG" || $SUDO apt-get install -f -y
    fi
  else
    echo "    WARNING: pnpm not found. Install Node.js + pnpm to build the Electron .deb package." >&2
  fi
else
  echo "==> [6/6] CLI + TUI + Web Viewer ready! (Pass --desktop to also build the Electron .deb app)"
fi

echo ""
echo "=============================================================================="
echo " RedJohn / Strix is ready on Kali Linux!"
echo "   - Launch interactive TUI : rj   (or: redjohn / strix)"
echo "   - Launch Web Viewer      : strix view"
echo "   - Headless scan          : strix -n -t <target>"
echo "=============================================================================="
