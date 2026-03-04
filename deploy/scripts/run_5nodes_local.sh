#!/usr/bin/env bash
set -euo pipefail
#
# IONA Local 5-Node Network — for development and testing.
#
# Topology:
#   val2 (producer, seed=2, tcp/7002, rpc/9002)
#   val3 (producer, seed=3, tcp/7003, rpc/9003)
#   val4 (producer, seed=4, tcp/7004, rpc/9004)
#   val1 (follower, seed=1, tcp/7001, rpc/9001)
#   rpc  (public,   seed=100, tcp/7005, rpc/9000)
#
# Usage:
#   ./deploy/scripts/run_5nodes_local.sh
#   RUST_LOG=debug ./deploy/scripts/run_5nodes_local.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export RUST_LOG=${RUST_LOG:-info}

DATA_ROOT="$ROOT_DIR/data"
mkdir -p "$DATA_ROOT"/{val1,val2,val3,val4,rpc}

# ── Generate configs ──────────────────────────────────────────────────────
# Rules:
#   - Each node connects to ALL others except itself
#   - Producers have simple_producer = true
#   - Follower + RPC have simple_producer = false

gen_config() {
    local name="$1" seed="$2" p2p_port="$3" rpc_port="$4" producer="$5"
    shift 5
    local peers_toml=""
    for p in "$@"; do
        if [[ -n "$peers_toml" ]]; then peers_toml="${peers_toml}, "; fi
        peers_toml="${peers_toml}\"${p}\""
    done

    cat > "$DATA_ROOT/${name}/config.toml" <<EOF
[node]
data_dir  = "${DATA_ROOT}/${name}"
seed      = ${seed}
chain_id  = 6126151
log_level = "info"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = ${producer}
validator_seeds      = [2, 3, 4]

[network]
listen = "/ip4/127.0.0.1/tcp/${p2p_port}"
peers  = [${peers_toml}]
bootnodes  = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:${rpc_port}"
enable_faucet = true

[storage]
enable_snapshots        = true
snapshot_every_n_blocks = 500
snapshot_keep           = 5
snapshot_zstd_level     = 1
EOF
}

# val2 (producer): peers = val3, val4, val1, rpc
gen_config val2 2 7002 9002 true \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7001" \
    "/ip4/127.0.0.1/tcp/7005"

# val3 (producer): peers = val2, val4, val1, rpc
gen_config val3 3 7003 9003 true \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7001" \
    "/ip4/127.0.0.1/tcp/7005"

# val4 (producer): peers = val2, val3, val1, rpc
gen_config val4 4 7004 9004 true \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7001" \
    "/ip4/127.0.0.1/tcp/7005"

# val1 (follower): peers = val2, val3, val4, rpc
gen_config val1 1 7001 9001 false \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7005"

# rpc (public): peers = val2, val3, val4
gen_config rpc 100 7005 9000 false \
    "/ip4/127.0.0.1/tcp/7002" \
    "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004"

# ── Build ─────────────────────────────────────────────────────────────────
echo "Building iona-node..."
( cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node )
BIN="$ROOT_DIR/target/release/iona-node"

# ── Start nodes in correct order ──────────────────────────────────────────
PIDS=()
cleanup() {
    echo ""
    echo "Stopping all nodes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "All nodes stopped."
}
trap cleanup INT TERM EXIT

echo ""
echo "Starting producers (val2, val3, val4)..."
( cd "$ROOT_DIR" && "$BIN" --config "$DATA_ROOT/val2/config.toml" ) &
PIDS+=($!)
sleep 1
( cd "$ROOT_DIR" && "$BIN" --config "$DATA_ROOT/val3/config.toml" ) &
PIDS+=($!)
sleep 1
( cd "$ROOT_DIR" && "$BIN" --config "$DATA_ROOT/val4/config.toml" ) &
PIDS+=($!)
sleep 3

echo "Starting follower (val1)..."
( cd "$ROOT_DIR" && "$BIN" --config "$DATA_ROOT/val1/config.toml" ) &
PIDS+=($!)
sleep 1

echo "Starting RPC node..."
( cd "$ROOT_DIR" && "$BIN" --config "$DATA_ROOT/rpc/config.toml" ) &
PIDS+=($!)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  IONA 5-Node Local Network                                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  val2 (producer)  RPC: http://127.0.0.1:9002/health        ║"
echo "║  val3 (producer)  RPC: http://127.0.0.1:9003/health        ║"
echo "║  val4 (producer)  RPC: http://127.0.0.1:9004/health        ║"
echo "║  val1 (follower)  RPC: http://127.0.0.1:9001/health        ║"
echo "║  rpc  (public)    RPC: http://127.0.0.1:9000/health        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Press Ctrl+C to stop all nodes.                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

wait
