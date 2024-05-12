#!/usr/bin/env bash
set -euo pipefail

# Configuration
REPO="and-rose/jwtox"
RELEASE="latest"

# Determine OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

# Convert Arch names to more common identifiers
case "$ARCH" in
  x86_64) ARCH="x86_64" ;;
  arm64) ARCH="arm" ;;
  aarch64) ARCH="aarch64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Find the correct URL for the binary
BINARY_URL=$(curl -sSL "https://api.github.com/repos/$REPO/releases/$RELEASE" |
  grep "browser_download_url" |
  grep -i "$OS" |
  grep -i "$ARCH" |
  cut -d '"' -f 4)

if [ -z "$BINARY_URL" ]; then
  echo "Failed to find a suitable binary for your system."
  exit 1
fi

# Define install directory and binary name
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="jwtox"
TARBALL_NAME="jwtox-$RELEASE-$OS-$ARCH.tar.gz"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

echo "Downloading $BINARY_NAME from $BINARY_URL"

# Download the binary
curl -sSL -o "/tmp/$TARBALL_NAME" "$BINARY_URL"

if [ $? -ne 0 ]; then
  echo "Download failed!"
  exit 1
fi

echo "Download complete."

# Extract the binary
tar -xvzf "/tmp/$TARBALL_NAME" $BINARY_NAME

# Give execute permissions
chmod +x $BINARY_NAME

# Move the binary to the install directory
mv $BINARY_NAME $INSTALL_DIR

if [ $? -ne 0 ]; then
  echo "Failed to move the binary to $INSTALL_DIR."
  exit 1
fi

echo "$BINARY_NAME installed successfully to $INSTALL_DIR."
