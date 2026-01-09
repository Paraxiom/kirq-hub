#!/bin/bash

echo "Building Quantum RNG Bridge (Rust)"
echo "================================="
echo "No async, no cloning - quantum-like entropy consumption"
echo ""

# Build in release mode
cargo build --release

echo ""
echo "Build complete. Run with:"
echo "  ./target/release/quantum_rng_bridge"
echo ""
echo "API will be available at http://localhost:8001"
echo ""
echo "Endpoints:"
echo "  GET  /api/rng/health"
echo "  POST /api/rng/random"