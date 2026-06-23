#!/bin/bash
# Aegis Alias Setup Script

# Resolve the absolute path to the local bin/aegis script
AEGIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
AEGIS_BIN="$AEGIS_DIR/bin/aegis"

# Detect user shell config file
SHELL_NAME=$(basename "$SHELL")
CONFIG_FILE=""

if [ "$SHELL_NAME" = "zsh" ]; then
  CONFIG_FILE="$HOME/.zshrc"
elif [ "$SHELL_NAME" = "bash" ]; then
  if [ "$(uname)" = "Darwin" ]; then
    CONFIG_FILE="$HOME/.bash_profile"
  else
    CONFIG_FILE="$HOME/.bashrc"
  fi
else
  # Default fallback
  CONFIG_FILE="$HOME/.zshrc"
fi

echo "🛡️  Setting up Aegis shell shortcuts..."
echo "Detected shell: $SHELL_NAME"
echo "Target configuration file: $CONFIG_FILE"

# Define the alias lines we want to add
ALIAS_MARKER="# >>> aegis shell configuration >>>"
ALIAS_END_MARKER="# <<< aegis shell configuration <<<"

ALIAS_BLOCK="
$ALIAS_MARKER
alias aegis='$AEGIS_BIN'
alias aegis-scan='aegis scan'
alias aegis-hook='aegis install-hook'
$ALIAS_END_MARKER"

# Check if aegis config already exists in the file
if [ -f "$CONFIG_FILE" ] && grep -q "$ALIAS_MARKER" "$CONFIG_FILE"; then
  echo "ℹ️  Aegis configuration already exists in $CONFIG_FILE. Overwriting with latest path."
  # Remove existing block
  sed -i.bak "/$ALIAS_MARKER/,/$ALIAS_END_MARKER/d" "$CONFIG_FILE" 2>/dev/null || \
  sed -i "" "/$ALIAS_MARKER/,/$ALIAS_END_MARKER/d" "$CONFIG_FILE"
fi

# Append the new alias block
echo "$ALIAS_BLOCK" >> "$CONFIG_FILE"

echo "✅ Shell aliases added successfully to $CONFIG_FILE!"
echo "Please reload your shell to start using them:"
echo "  source $CONFIG_FILE"
echo ""
echo "Try running these simplified shortcuts:"
echo "  aegis             (starts web app)"
echo "  aegis-scan        (runs CLI scan)"
echo "  aegis-hook        (installs git pre-push hook)"
