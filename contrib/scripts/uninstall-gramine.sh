#!/usr/bin/env bash
# Uninstall Gramine support for Passless

set -e

GRAMINE_DIR="/opt/passless/gramine"
BIN_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"

echo "Uninstalling Gramine support for Passless..."

# Stop and disable service
if [ -f "$SERVICE_DIR/passless-sgx.service" ]; then
    echo "Stopping systemd service..."
    sudo systemctl stop passless-sgx 2>/dev/null || true
    sudo systemctl disable passless-sgx 2>/dev/null || true
    sudo rm -f "$SERVICE_DIR/passless-sgx.service"
    sudo systemctl daemon-reload
fi

# Remove binary wrapper
echo "Removing binary wrapper..."
sudo rm -f "$BIN_DIR/passless-sgx"

# Remove Gramine directory
echo "Removing Gramine files..."
sudo rm -rf "$GRAMINE_DIR"

echo ""
echo "Uninstallation complete!"
echo ""
echo "Note: Credential data in /var/lib/passless is preserved."