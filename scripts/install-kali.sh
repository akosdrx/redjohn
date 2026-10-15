#!/usr/bin/env bash
# ==============================================================================
# RedJohn / Strix — Native Kali Linux Installer & Desktop Builder (x64 & ARM64)
# ==============================================================================
# Usage:
#   ./scripts/install-kali.sh              # Install CLI + Go TUI + Web Viewer + agent-browser
#   ./scripts/install-kali.sh --desktop    # Also build & install the Kali .deb Desktop app
#   ./scripts/install-kali.sh --no-apt     # Skip full APT scan-tool check (still ensures chromium/npm if missing)
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
      echo "  --no-apt    Skip full APT tool suite check"
      exit 0
      ;;
  esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

echo "==> [1/6] Checking Kali Linux / Debian environment ($(uname -m))..."
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "    Detected OS: ${PRETTY_NAME:-Linux}"
fi

if command -v apt-get >/dev/null 2>&1; then
  if [ "$SKIP_APT" -eq 0 ]; then
    echo "==> [2/6] Installing Kali Linux system, Chromium & assessment dependencies via APT..."
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
      chromium
      fonts-liberation
      nodejs
      npm
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
    # Even with --no-apt, ensure native ARM64/x64 Chromium and npm are present for agent-browser
    MISSING_BROWSER_PKGS=()
    command -v chromium >/dev/null 2>&1 || MISSING_BROWSER_PKGS+=(chromium fonts-liberation)
    command -v npm >/dev/null 2>&1 || MISSING_BROWSER_PKGS+=(nodejs npm)
    if [ "${#MISSING_BROWSER_PKGS[@]}" -gt 0 ]; then
      echo "==> [2/6] Installing native Kali Chromium & Node/NPM (${MISSING_BROWSER_PKGS[*]})..."
      $SUDO apt-get update -qq || true
      $SUDO apt-get install -y "${MISSING_BROWSER_PKGS[@]}"
    else
      echo "==> [2/6] Native Kali Chromium & NPM already installed."
    fi
  fi
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
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
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

echo "==> [5/6] Installing agent-browser & configuring Kali native Chromium (${ARCH_RAW})..."
NPM_GLOBAL="$HOME/.npm-global"
SHIM_DIR="$HOME/.strix/kali-shims"
mkdir -p "$NPM_GLOBAL" "$SHIM_DIR" "$HOME/.local/bin"

if command -v npm >/dev/null 2>&1; then
  NPM_CONFIG_PREFIX="$NPM_GLOBAL" npm install -g agent-browser@0.26.0 @ast-grep/cli@latest js-beautify@latest retire@latest
  if [ -x "$NPM_GLOBAL/bin/agent-browser" ]; then
    ln -sf "$NPM_GLOBAL/bin/agent-browser" "$HOME/.local/bin/agent-browser"
    if [ -n "$SUDO" ] || [ -w /usr/local/bin ]; then
      $SUDO ln -sf "$NPM_GLOBAL/bin/agent-browser" "/usr/local/bin/agent-browser" 2>/dev/null || true
    fi
    echo "    Installed agent-browser -> $NPM_GLOBAL/bin/agent-browser"
  fi
fi

CHROMIUM_BIN="$(command -v chromium || command -v chromium-browser || command -v google-chrome || echo /usr/bin/chromium)"
echo "    Using native system Chromium (${ARCH_RAW}): $CHROMIUM_BIN"

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
export PATH="$SHIM_DIR:$NPM_GLOBAL/bin:$HOME/.local/bin:\$PATH"
export AGENT_BROWSER_EXECUTABLE_PATH="${CHROMIUM_BIN}"
export CHROME_PATH="${CHROMIUM_BIN}"
export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="${CHROMIUM_BIN}"
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
export AGENT_BROWSER_ARGS="--no-sandbox,--disable-dev-shm-usage,--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
exec "$ROOT_DIR/.venv/bin/$cmd_name" "\$@"
EOF
  chmod +x "$WRAPPER"
  if [ -n "$SUDO" ] || [ -w /usr/local/bin ]; then
    $SUDO ln -sf "$WRAPPER" "/usr/local/bin/$cmd_name" 2>/dev/null || true
  fi
done

if [ -x "$NPM_GLOBAL/bin/agent-browser" ]; then
  AGENT_BROWSER_EXECUTABLE_PATH="$CHROMIUM_BIN" "$NPM_GLOBAL/bin/agent-browser" doctor --offline --quick || true
fi

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
  echo "==> [6/6] CLI + TUI + Web Viewer + agent-browser ready! (Pass --desktop to also build the Electron .deb app)"
fi

echo ""
echo "=============================================================================="
echo " RedJohn / Strix is ready on Kali Linux (${ARCH_RAW})!"
echo "   - Launch interactive TUI : rj   (or: redjohn / strix)"
echo "   - Launch Web Viewer      : strix view"
echo "   - Verify agent-browser   : agent-browser doctor --offline --quick"
echo "   - Headless scan          : strix -n -t <target>"
echo "=============================================================================="
