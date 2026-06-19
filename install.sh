#!/bin/sh
# Reno installer for Linux/macOS (no sudo required)
# Run:
#   curl -fsSL https://raw.githubusercontent.com/kiiimatz/reno/main/install.sh | sh

set -e

REPO="kiiimatz/reno"
BASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR="$HOME/.local/bin"

# Detect OS and arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

BINARY="reno-${OS}-${ARCH}"
URL="$BASE_URL/$BINARY"
DEST="$INSTALL_DIR/reno"

echo "Downloading reno (${OS}/${ARCH})..."
mkdir -p "$INSTALL_DIR"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$DEST"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEST" "$URL"
else
    echo "Error: curl or wget is required"; exit 1
fi

chmod +x "$DEST"
echo "Installed: $DEST"

# Add to PATH in shell profile if needed
add_to_path() {
    PROFILE="$1"
    if [ -f "$PROFILE" ] && ! grep -q "$INSTALL_DIR" "$PROFILE" 2>/dev/null; then
        echo "" >> "$PROFILE"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$PROFILE"
        echo "Added $INSTALL_DIR to PATH in $PROFILE"
    fi
}

case "$SHELL" in
  */zsh)  add_to_path "$HOME/.zshrc" ;;
  */bash) add_to_path "$HOME/.bashrc"; add_to_path "$HOME/.bash_profile" ;;
  *)      add_to_path "$HOME/.profile" ;;
esac

export PATH="$INSTALL_DIR:$PATH"

echo "Starting reno..."
"$DEST" station
"$DEST" edge

echo "Done. Run 'reno version' to verify."
