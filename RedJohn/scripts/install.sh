#!/usr/bin/env bash
# RedJohn installation script
set -euo pipefail

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64|amd64) TARGET="linux-x64" ;;
      aarch64|arm64) TARGET="linux-arm64" ;;
      *)
        echo "Unsupported OS/Arch: $OS/$ARCH"
        exit 1
        ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64|amd64) TARGET="darwin-x64" ;;
      arm64) TARGET="darwin-arm64" ;;
      *)
        echo "Unsupported OS/Arch: $OS/$ARCH"
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported OS/Arch: $OS/$ARCH"
    exit 1
    ;;
esac

VERSION="${VERSION:-latest}"
INSTALL_DIR="${HOME}/.redjohn/bin"
mkdir -p "$INSTALL_DIR"

FILENAME="redjohn-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/redjohn-ai/redjohn/releases/download/${VERSION}/${FILENAME}"

TMP_DIR="${TMPDIR:-/tmp}"
ARCHIVE="${TMP_DIR}/${FILENAME}"

curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE"
curl -fsSL "${DOWNLOAD_URL}.sha256" -o "${ARCHIVE}.sha256"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && sha256sum -c "${ARCHIVE}.sha256")
else
  (cd "$TMP_DIR" && shasum -a 256 -c "${ARCHIVE}.sha256")
fi
tar -xzf "$ARCHIVE" -C "$INSTALL_DIR"

BINARY_NAME="redjohn-${VERSION}-${TARGET}"
if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
  mv "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/redjohn"
fi
chmod +x "${INSTALL_DIR}/redjohn"

echo "RedJohn installed successfully to ${INSTALL_DIR}/redjohn"
