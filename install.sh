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

# On Linux/macOS, service install needs root. Use sudo when available.
# When piped (curl|bash), stdin is not a tty so sudo can't prompt — fall back to instructions.
maybe_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif sudo -n true 2>/dev/null; then
    # sudo credentials are cached or NOPASSWD — no prompt needed
    sudo "$@"
  elif [ -t 0 ] && [ -t 1 ]; then
    # stdin/stdout are both ttys — interactive, can prompt
    sudo "$@"
  else
    echo ""
    echo "  Root is required to install the service."
    echo "  Run this manually to finish setup:"
    echo ""
    echo "    sudo $*"
    echo ""
  fi
}

# Optional: start services based on argument
# Usage: install.sh [station|edge|both]
case "${1:-}" in
  station)
    echo ""
    maybe_sudo reno station
    ;;
  edge)
    echo ""
    maybe_sudo reno edge
    ;;
  both)
    echo ""
    maybe_sudo reno station
    maybe_sudo reno edge
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
