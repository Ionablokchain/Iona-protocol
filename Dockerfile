# IONA Node Dockerfile
# Multi-stage build for optimized image size and layer caching

# ---- Builder stage ----
FROM rust:1-bookworm AS builder
WORKDIR /app

# Create a dummy project to cache dependencies
# This ensures that dependencies are built only when Cargo.toml/Cargo.lock change
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --bin iona-node || true && \
    rm -rf src

# Now copy the actual source code
COPY src ./src
COPY tests ./tests   # Only if needed for build? Usually not required for release binary
COPY docs ./docs     # Not needed for build, remove from builder stage if not used

# Build the real binary (cargo will reuse cached dependencies)
RUN cargo build --release --bin iona-node && \
    # Strip the binary to reduce size
    strip /app/target/release/iona-node

# ---- Runtime stage ----
FROM debian:bookworm-slim

# Install CA certificates and create a non-root user
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 10001 iona

WORKDIR /home/iona

# Copy the compiled binary from builder
COPY --from=builder /app/target/release/iona-node /usr/local/bin/iona-node

# Use non-root user
USER iona

# Expose ports (adjust if needed)
# 7001: P2P peer-to-peer communication
# 9001: RPC HTTP endpoint
EXPOSE 7001 9001

# Add a healthcheck (adjust the command to your node's health endpoint)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl --fail http://localhost:9001/health || exit 1

# Metadata labels
LABEL maintainer="Iona Blockchain Contributors" \
      version="v28.0.0" \
      description="IONA node image"

ENTRYPOINT ["/usr/local/bin/iona-node"]
# Default arguments can be added as CMD, e.g.:
# CMD ["--config", "/etc/iona/config.toml"]
