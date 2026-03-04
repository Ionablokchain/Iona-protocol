# Build stage
FROM rust:1-bookworm AS builder
WORKDIR /app

# Better layer caching
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
COPY docs ./docs

RUN cargo build --release --bin iona-node

# Runtime stage
FROM debian:bookworm-slim
RUN useradd -m -u 10001 iona && apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /home/iona
COPY --from=builder /app/target/release/iona-node /usr/local/bin/iona-node
USER iona

EXPOSE 7001 9001
ENTRYPOINT ["/usr/local/bin/iona-node"]
