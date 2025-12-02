#!/bin/bash

# Exit on error
set -e

echo "Updating system..."
sudo apt update && sudo apt upgrade -y

echo "Installing Python3 and pip..."
sudo apt install -y python3 python3-pip

echo "Installing required Python modules..."
pip3 install cryptography

# If not working, it’s possible to try following alternatives:
#  - Alternative 1: pipx install cryptography
#  - Alternative 2: sudo apt install python3-cryptography

# PATH to the script (adjust, if required)
SCRIPT_SOURCE="webswak.py"
SCRIPT_TARGET="/usr/local/bin/webswak"

if [ ! -f "$SCRIPT_SOURCE" ]; then
    echo "Error: $SCRIPT_SOURCE not found in current directory."
    exit 1
fi

echo "Copying script to /usr/local/bin..."
sudo cp "$SCRIPT_SOURCE" "$SCRIPT_TARGET"

echo "Making script executable..."
sudo chmod +x "$SCRIPT_TARGET"

echo "Installation complete!"
echo "You can now run the server with:"
echo "  webswak   (Default => https on port 443)"
echo "or"
echo "  webswak --mode http (Default => port 80)"
