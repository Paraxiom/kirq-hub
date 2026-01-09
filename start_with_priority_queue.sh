#!/bin/bash
# Start KIRQ hub configured to push entropy to priority queue

echo "Starting KIRQ hub with priority queue integration..."
echo "Priority queue should be running on port 5555"
echo ""

# Run with config file that points to priority queue
RUST_LOG=info ./target/release/quantum_rng_kirk_hub