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

# which component to install
COMPONENT="${1:-}"
if [ -z "$COMPONENT" ]; then
  echo "Usage: install.sh [station|edge|both]"
  echo "  station  - install reno-station"
  echo "  edge     - install reno-edge"
  echo "  both     - install both"
  exit 1
fi

install_binary() {
  local name="$1"
  local url="${BASE_URL}/${name}-${OS}-${ARCH}"
  local dest="${INSTALL_DIR}/${name}"

  echo "Downloading ${name} (${OS}/${ARCH})..."
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -q "$url" -O "$dest"
  else
    echo "curl or wget is required"; exit 1
  fi
  chmod +x "$dest"
  echo "Installed: $dest"
}

if [ "$COMPONENT" = "station" ] || [ "$COMPONENT" = "both" ]; then
  install_binary reno-station
fi
if [ "$COMPONENT" = "edge" ] || [ "$COMPONENT" = "both" ]; then
  install_binary reno-edge
fi

echo ""
echo "Done! Run 'reno-station --help' or 'reno-edge --help' to get started."
