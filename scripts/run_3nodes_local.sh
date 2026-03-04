#!/usr/bin/env bash
set -euo pipefail

# Local 3-node quickstart (no Docker).
# Usage: ./scripts/run_3nodes_local.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export RUST_LOG=${RUST_LOG:-info}

mkdir -p "$ROOT_DIR/data/node1" "$ROOT_DIR/data/node2" "$ROOT_DIR/data/node3"

cat > "$ROOT_DIR/data/node1/config.toml" <<'TOML'
[node]
data_dir  = "./data/node1"
seed      = 1
chain_id  = 6126151
log_level = "info"

[consensus]
validator_seeds = [1, 2, 3]
simple_producer = true

[network]
listen = "/ip4/0.0.0.0/tcp/7001"
peers  = ["/ip4/127.0.0.1/tcp/7002", "/ip4/127.0.0.1/tcp/7003"]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[rpc]
listen = "127.0.0.1:9001"
TOML

cat > "$ROOT_DIR/data/node2/config.toml" <<'TOML'
[node]
data_dir  = "./data/node2"
seed      = 2
chain_id  = 6126151
log_level = "info"

[consensus]
validator_seeds = [1, 2, 3]
simple_producer = true

[network]
listen = "/ip4/0.0.0.0/tcp/7002"
peers  = ["/ip4/127.0.0.1/tcp/7001", "/ip4/127.0.0.1/tcp/7003"]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[rpc]
listen = "127.0.0.1:9002"
TOML

cat > "$ROOT_DIR/data/node3/config.toml" <<'TOML'
[node]
data_dir  = "./data/node3"
seed      = 3
chain_id  = 6126151
log_level = "info"

[consensus]
validator_seeds = [1, 2, 3]
simple_producer = true

[network]
listen = "/ip4/0.0.0.0/tcp/7003"
peers  = ["/ip4/127.0.0.1/tcp/7001", "/ip4/127.0.0.1/tcp/7002"]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[rpc]
listen = "127.0.0.1:9003"
TOML

( cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node )

# Run in 3 terminals (this script spawns background jobs and waits)
( cd "$ROOT_DIR" && ./target/release/iona-node --config ./data/node1/config.toml ) &
P1=$!
( cd "$ROOT_DIR" && ./target/release/iona-node --config ./data/node2/config.toml ) &
P2=$!
( cd "$ROOT_DIR" && ./target/release/iona-node --config ./data/node3/config.toml ) &
P3=$!

trap 'kill $P1 $P2 $P3 2>/dev/null || true' INT TERM EXIT

echo "\nNodes started:" 
echo " - RPC1: http://127.0.0.1:9001/health"
echo " - RPC2: http://127.0.0.1:9002/health"
echo " - RPC3: http://127.0.0.1:9003/health"
echo "Press Ctrl+C to stop."

wait
