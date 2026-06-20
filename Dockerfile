# =============================================================================
# IONA Node — Production Dockerfile
# =============================================================================
# Multi-stage build with dependency caching, minimal runtime,
# non‑root user, healthchecks, and environment configuration.
# =============================================================================

# -----------------------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

# Build arguments for reproducibility
ARG CARGO_PROFILE=release
ARG GIT_COMMIT=unknown
ARG BUILD_TIMESTAMP=unknown
ARG VERSION=unknown

# Set environment variables for build
ENV CARGO_TERM_COLOR=always \
    RUST_BACKTRACE=1

WORKDIR /app

# 1. Copy manifest files to cache dependencies
COPY Cargo.toml Cargo.lock ./

# 2. Fetch dependencies (cached until Cargo.toml/Cargo.lock changes)
RUN cargo fetch --locked

# 3. Copy source code
COPY src ./src

# 4. Build binary with optimisations
RUN cargo build --profile ${CARGO_PROFILE} --locked --bin iona-node && \
    # Strip debug symbols in release mode to reduce binary size
    if [ "${CARGO_PROFILE}" = "release" ]; then \
        strip /app/target/release/iona-node; \
    fi

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

# Build arguments for labels
ARG GIT_COMMIT=unknown
ARG BUILD_TIMESTAMP=unknown
ARG VERSION=unknown

# Metadata labels
LABEL maintainer="IONA team <dev@iona.network>" \
      description="IONA blockchain node — production image" \
      version="${VERSION}" \
      git-commit="${GIT_COMMIT}" \
      build-timestamp="${BUILD_TIMESTAMP}"

# Install runtime dependencies (ca-certificates for TLS, tini for signal handling)
RUN apt-get update && \
    apt-get install -y \
        ca-certificates \
        tini \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged user and required directories
RUN groupadd -r -g 10001 iona && \
    useradd -r -u 10001 -g iona -m -d /home/iona -s /sbin/nologin iona && \
    mkdir -p /data /etc/iona && \
    chown -R iona:iona /data /etc/iona

# Set working directory
WORKDIR /home/iona

# Copy binary from builder
COPY --from=builder --chown=iona:iona /app/target/release/iona-node /usr/local/bin/iona-node

# Ensure binary is executable
RUN chmod +x /usr/local/bin/iona-node

# Set environment variable defaults
ENV RPC_PORT=9001 \
    P2P_PORT=7001 \
    DATA_DIR=/data \
    CONFIG_FILE=/etc/iona/config.toml

# Expose ports:
#   - 7001: P2P (gossip/consensus)
#   - 9001: RPC (JSON-RPC)
EXPOSE ${P2P_PORT} ${RPC_PORT}

# Healthcheck: query the node's health endpoint (requires --rpc-port to be set)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /usr/local/bin/iona-node --health --rpc-port ${RPC_PORT} || exit 1

# Switch to non-root user
USER iona

# Entrypoint with tini for proper signal handling (SIGTERM, SIGINT)
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/iona-node"]

# Default command (can be overridden)
CMD ["--config", "/etc/iona/config.toml"]
