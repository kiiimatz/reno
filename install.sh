#!/usr/bin/env bash
set -e

REPO="kiiimatz/reno"
INSTALL_DIR="/usr/local/bin"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

# detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*)  OS=linux ;;
  Darwin*) OS=darwin ;;
  *)       echo "Unsupported OS: $OS"; exit 1 ;;
esac

# detect arch
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)             echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

BINARY="reno-${OS}-${ARCH}"
DEST="${INSTALL_DIR}/reno"

echo "Downloading reno (${OS}/${ARCH})..."

if command -v curl &>/dev/null; then
  curl -fsSL "${BASE_URL}/${BINARY}" -o "$DEST"
elif command -v wget &>/dev/null; then
  wget -q "${BASE_URL}/${BINARY}" -O "$DEST"
else
  echo "curl or wget is required"; exit 1
fi

chmod +x "$DEST"

echo "Installed: $DEST"
echo ""
echo "Usage:"
echo "  reno config    # set up config (~/.config/reno/config.json)"
echo "  reno station   # start Station server (background, auto-start on boot)"
echo "  reno edge      # start Edge client (background, auto-start on boot)"
echo "  reno down      # stop Station and Edge"
echo "  reno remove    # uninstall reno (stops services, removes binary)"
echo "  reno version   # show version"
