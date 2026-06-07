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
TMP="$(mktemp)"
DEST="${INSTALL_DIR}/reno"

echo "Downloading reno (${OS}/${ARCH})..."

if command -v curl &>/dev/null; then
  curl -fsSL "${BASE_URL}/${BINARY}" -o "$TMP"
elif command -v wget &>/dev/null; then
  wget -q "${BASE_URL}/${BINARY}" -O "$TMP"
else
  echo "curl or wget is required"; exit 1
fi

chmod +x "$TMP"

# Install to /usr/local/bin, using sudo if needed
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP" "$DEST"
elif command -v sudo &>/dev/null; then
  sudo mv "$TMP" "$DEST"
else
  # Fallback: install to ~/.local/bin
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  DEST="${INSTALL_DIR}/reno"
  mv "$TMP" "$DEST"
  echo "Note: installed to $DEST (not in PATH by default, add ~/.local/bin to PATH)"
fi

echo "Installed: $DEST"

# Optional: start services based on argument
# Usage: install.sh [station|edge|both]
case "${1:-}" in
  station)
    echo ""
    reno station
    ;;
  edge)
    echo ""
    reno edge
    ;;
  both)
    echo ""
    reno station
    reno edge
    ;;
  *)
    echo ""
    echo "Usage:"
    echo "  reno config    # set up config (~/.config/reno/config.json)"
    echo "  reno station   # start Station (background, auto-start on boot)"
    echo "  reno edge      # start Edge (background, auto-start on boot)"
    echo "  reno down      # stop both"
    echo "  reno remove    # uninstall"
    echo "  reno update    # update to latest"
    echo "  reno version   # show version"
    ;;
esac
