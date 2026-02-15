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
  arm64) ARCH="aarch64" ;;
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
DIR_NAME="jwtox"
DOWNLOAD_PATH="/tmp/$DIR_NAME"
TARBALL_NAME="jwtox-$RELEASE-$OS-$ARCH.tar.gz"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

# Clean up anything with jwtox in the tmp directory
rm -rf /tmp/jwtox*

echo "Downloading $BINARY_NAME from $BINARY_URL"

# Download the binary
if ! curl -fsSL -o "/tmp/$TARBALL_NAME" "$BINARY_URL"; then
  echo "Download failed!"
  exit 1
fi

echo "Download complete."

# Extract the contents
mkdir -p $DOWNLOAD_PATH
echo "Extracting $TARBALL_NAME to $DOWNLOAD_PATH"
tar -xzf "/tmp/$TARBALL_NAME" -C $DOWNLOAD_PATH

# Expect a directory with the binary and completion files
# Should be jwtox/jwtox and jwtox/contrib/completion

# Give execute permissions
chmod +x "$DOWNLOAD_PATH/$BINARY_NAME"

# Move the binary to the install directory
echo "Moving $BINARY_NAME to $INSTALL_DIR"

if [ ! -d "$INSTALL_DIR" ]; then
  echo "Creating install directory at $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
fi

if ! mv "$DOWNLOAD_PATH/$BINARY_NAME" "$BINARY_PATH"; then
  echo "Failed to move the binary to $INSTALL_DIR."
  exit 1
fi

echo "$BINARY_NAME installed successfully to $INSTALL_DIR."

# Install shell completions to the appropriate directory
# If the user has the required directories, install the completions

# Fish
FISH_COMPLETION_DIR="$HOME/.config/fish/completions"
if [ -d "$HOME/.config/fish/completions" ]; then
  cp $DOWNLOAD_PATH/completions/jwtox.fish "$FISH_COMPLETION_DIR"
  echo "Fish completions installed successfully to $FISH_COMPLETION_DIR."
fi

# Bash
BASH_COMPLETION_DIR="$HOME/.bash_completion.d"
if [ -d "$HOME/share/bash-completion/completions" ]; then
  cp $DOWNLOAD_PATH/completions/jwtox.bash "$BASH_COMPLETION_DIR"
  echo "Bash completions installed successfully to $BASH_COMPLETION_DIR."
fi

# Zsh
ZSH_COMPLETION_DIR="$HOME/.zsh/completions"
if [ -d "$HOME/.zsh/completions" ]; then
  cp $DOWNLOAD_PATH/completions/_jwtox "$HOME"/.zsh/completions
  echo "Zsh completions installed successfully to $ZSH_COMPLETION_DIR."
fi
