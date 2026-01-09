#!/bin/bash
# Start only Kirq Hub

echo "Starting Kirq Hub..."
cd /home/paraxiom/quantum-rng-kirq-hub

# Kill any existing Kirq Hub
pkill -f quantum_rng_kirq_hub

# Start fresh
./target/release/quantum_rng_kirq_hub