# Build stage
FROM rust:1-bookworm AS builder
WORKDIR /app

# 1. Copy only manifest files first to cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch --locked

# 2. Copy source code (no tests/docs, they are not needed for the binary)
COPY src ./src

# 3. Build release binary (locked to Cargo.lock)
RUN cargo build --release --locked --bin iona-node

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies, create unprivileged user
RUN useradd -m -u 10001 iona && \
    apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/iona

# Copy binary from builder, set ownership
COPY --from=builder --chown=iona:iona /app/target/release/iona-node /usr/local/bin/iona-node

USER iona

EXPOSE 7001 9001

# Healthcheck: query node's health endpoint every 30s, timeout 10s
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD /usr/local/bin/iona-node --health || exit 1

ENTRYPOINT ["/usr/local/bin/iona-node"]
