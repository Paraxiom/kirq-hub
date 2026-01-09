# Kirq Entropy Hub

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18200118.svg)](https://doi.org/10.5281/zenodo.18200118)

Quantum-secure random number generation hub for the Kirq Network, aggregating entropy from multiple quantum and hardware sources.

## Research Paper

This implementation is based on the research paper:

> **A Robust, Decentralized Architecture for Quantum Randomness Generation**
> Sylvain Cormier (Paraxiom), December 2024
> DOI: [10.5281/zenodo.18200118](https://doi.org/10.5281/zenodo.18200118)

## Overview

The Kirq Hub acts as a secure aggregation point for multiple entropy sources:
- **QRNG/QKD**: Quantum Key Distribution keys used as true quantum random numbers
- **Crypto4A HSM**: Hardware Security Module RNG (FIPS compliant)
- **Decentralized QRNG**: Network of distributed quantum sources

## Features

- **Quantum-Safe Mixing**: Combines entropy using cryptographically secure algorithms
- **STARK Proofs**: Verifiable proof of proper entropy mixing
- **High Performance**: Rust-based implementation for minimal latency
- **Multiple Sources**: Failover and redundancy through diverse entropy sources
- **No-Cloning**: Quantum properties preserved through single-use consumption
- **Post-Quantum Signatures**: Falcon-512 for authentication

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   QRNG      │────▶│              │────▶│   Client    │
│   Source    │     │              │     │  (TAO API)  │
└─────────────┘     │              │     └─────────────┘
                    │  Kirq Hub    │
┌─────────────┐     │              │     ┌─────────────┐
│  Crypto4A   │────▶│  - Mix      │────▶│   Client    │
│    HSM      │     │  - Prove    │     │  (Other)    │
└─────────────┘     │  - Deliver  │     └─────────────┘
                    │              │
┌─────────────┐     │              │
│Decentralized│────▶│              │
│    QRNG     │     └──────────────┘
└─────────────┘
```

## Quick Start

### Build

```bash
cargo build --release
```

### Configure

```bash
cp config.example.toml config.toml
# Edit config.toml with your entropy sources
```

### Run

```bash
./target/release/kirq-hub
```

## API Endpoints

### Get Mixed Entropy
```bash
POST /api/entropy/mixed
{
  "num_bytes": 32,
  "sources": ["qrng", "hsm", "decentralized"],
  "proof_required": true
}
```

### Get Single Source
```bash
POST /api/entropy/source/{source_name}
{
  "num_bytes": 32
}
```

### Health Check
```bash
GET /api/health
```

## Configuration

### Entropy Sources

Configure in `config.toml`:

```toml
[sources.qrng]
# Uses QKD keys as quantum random numbers
enabled = true
endpoint = "https://qkd.network/api/v1/keys"
api_key = "your-qkd-api-key"
timeout_ms = 5000

[sources.crypto4a]
enabled = true
endpoint = "http://localhost:8106/v1/random"
timeout_ms = 1000

[sources.decentralized]
enabled = true
nodes = [
  "https://node1.kirq.network/entropy",
  "https://node2.kirq.network/entropy"
]
```

### Mixing Algorithm

```toml
[mixing]
algorithm = "hybrid_xor_hkdf"
salt = "kirq-hub-v1"
info = "quantum-entropy-mix"
```

## Security

- All entropy is consumed on read (no caching)
- Time-bounded delivery (60 second expiration)
- Post-quantum signatures (Falcon-512)
- STARK proofs for verifiable mixing
- TLS 1.3 for all connections

## Documentation

See the `docs/` folder for detailed documentation:
- [Decentralized QRNG Architecture (PDF)](docs/decentralized_QRNG_kirq.pdf)
- [Threshold QRNG Architecture](docs/THRESHOLD_QRNG_ARCHITECTURE.md)
- [Quantum RNG Delivery Architecture](docs/QUANTUM_RNG_DELIVERY_ARCHITECTURE.md)
- [Quantum Safe Transmission](docs/quantum_safe_transmission.md)

## Development

### Testing

```bash
cargo test
```

### Benchmarks

```bash
cargo bench
```

## Related Projects

- [QuantumHarmony](https://github.com/Paraxiom/quantumharmony) - Post-quantum Layer 1 blockchain
- [Topological Coherence](https://huggingface.co/spaces/paraxiom-research/topological-coherence) - LLM hallucination reduction

## License

MIT License - see LICENSE file

## Citation

If you use this work, please cite:

```bibtex
@misc{cormier2024decentralized,
  author = {Cormier, Sylvain},
  title = {A Robust, Decentralized Architecture for Quantum Randomness Generation},
  year = {2024},
  publisher = {Zenodo},
  doi = {10.5281/zenodo.18200118},
  url = {https://doi.org/10.5281/zenodo.18200118}
}
```
