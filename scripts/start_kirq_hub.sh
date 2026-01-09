#!/bin/bash
# Start quantum-rng-kirq-hub with environment variables for push

cd /home/paraxiom/quantum-rng-kirq-hub

# Export environment variables
export RUST_LOG=info
# Option 1: Push to local Quantum Harmony
# export QUANTUM_HARMONY_RPC=http://localhost:9944

# Option 2: Push directly to api.paraxiom.org (if it has the endpoint)
export QUANTUM_HARMONY_RPC=https://api.paraxiom.org
export PUSH_INTERVAL_SECS=30
export ENTROPY_BYTES_PER_PUSH=32

# Run the service
exec ./target/release/quantum_rng_kirq_hub