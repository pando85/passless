#!/usr/bin/env bash
# Install Gramine support for Passless

set -e

GRAMINE_DIR="/opt/passless/gramine"
BIN_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"

echo "Installing Gramine support for Passless..."

# Create directories
echo "Creating directories..."
sudo mkdir -p "$GRAMINE_DIR"
sudo mkdir -p /var/lib/passless

# Copy Gramine files
echo "Copying Gramine files..."
sudo cp -r gramine/* "$GRAMINE_DIR/"

# Make scripts executable
sudo chmod +x "$GRAMINE_DIR/build.sh"
sudo chmod +x "$GRAMINE_DIR/run.sh"

# Copy systemd wrapper
sudo install -m 755 contrib/systemd/passless-sgx-wrapper.sh "$BIN_DIR/passless-sgx"

# Build manifest if not exists
if [ ! -f "$GRAMINE_DIR/passless-sealed.manifest.sgx" ]; then
    echo "Building Gramine manifest..."
    cd "$GRAMINE_DIR"
    ./build.sh
fi

# Install systemd service
if command -v systemctl &> /dev/null; then
    echo "Installing systemd service..."
    sudo cp contrib/systemd/passless-sgx.service "$SERVICE_DIR/"
    sudo systemctl daemon-reload
    echo ""
    echo "To enable the service:"
    echo "  sudo systemctl enable passless-sgx"
    echo "  sudo systemctl start passless-sgx"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Run with:"
echo "  passless-sgx"
echo ""
echo "Or with systemd:"
echo "  sudo systemctl start passless-sgx"