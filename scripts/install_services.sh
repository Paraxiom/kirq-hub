#!/bin/bash
# Install KIRQ systemd services

echo "Installing KIRQ systemd services..."

# Check if services are already installed
if systemctl list-unit-files | grep -q "kirq-hub.service"; then
    echo "Services appear to be already installed. Stopping them first..."
    sudo systemctl stop kirq-hub.service kirq-pusher.service 2>/dev/null
fi

# Copy service files
echo "Copying service files..."
sudo cp kirq-hub.service /etc/systemd/system/
sudo cp kirq-pusher.service /etc/systemd/system/

# Reload systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable services
echo "Enabling services..."
sudo systemctl enable kirq-hub.service
sudo systemctl enable kirq-pusher.service

# Kill any existing processes
echo "Stopping any existing KIRQ processes..."
pkill -f quantum_rng_kirq_hub
pkill -f kirq_to_droplet_pusher.py

sleep 2

# Start services
echo "Starting services..."
sudo systemctl start kirq-hub.service
sleep 5  # Give hub time to start
sudo systemctl start kirq-pusher.service

# Check status
echo ""
echo "=== Service Status ==="
sudo systemctl status kirq-hub.service --no-pager | head -15
echo ""
sudo systemctl status kirq-pusher.service --no-pager | head -15

echo ""
echo "Services installed and started!"
echo "To view logs: sudo journalctl -u kirq-hub -u kirq-pusher -f"
echo "To check entropy push: tail -f /home/paraxiom/kirq_services.log"