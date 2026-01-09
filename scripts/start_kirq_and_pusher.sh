#!/bin/bash
# Start both Kirq Hub and the pusher to droplet

echo "Starting Kirq Hub and Droplet Pusher..."

# Start Kirq Hub in background
echo "Starting Kirq Hub..."
cd /home/paraxiom/quantum-rng-kirq-hub
./target/release/quantum_rng_kirq_hub > kirk_hub.log 2>&1 &
KIRK_PID=$!
echo "Kirq Hub started with PID: $KIRK_PID"

# Wait for Kirq Hub to be ready
echo "Waiting for Kirq Hub to be ready..."
for i in {1..10}; do
    if curl -s http://localhost:8001/api/health > /dev/null 2>&1; then
        echo "✓ Kirq Hub is ready"
        break
    fi
    echo "  Waiting... ($i/10)"
    sleep 2
done

# Start the pusher
echo ""
echo "Starting pusher to api.paraxiom.org..."
cd /home/paraxiom
python3 kirk_to_droplet_pusher.py