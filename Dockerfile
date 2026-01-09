# Quantum RNG Kirk Hub - Docker Build
# Multi-stage build for minimal production image

FROM rust:1.75-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY benches ./benches

# Build the application in release mode
RUN cargo build --release

# ===========================================================================
# Runtime stage
# ===========================================================================

FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/quantum-rng-kirk-hub /usr/local/bin/

# Copy configuration template
COPY config.example.toml /app/config.example.toml

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash kirkuser && \
    chown -R kirkuser:kirkuser /app

USER kirkuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/api/health || exit 1

# Expose ports
EXPOSE 8001 9090

# Default environment variables
ENV RUST_LOG=info
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8001

# Entry point
ENTRYPOINT ["/usr/local/bin/quantum-rng-kirk-hub"]
