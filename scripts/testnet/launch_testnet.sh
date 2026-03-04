#!/usr/bin/env bash
# ============================================================================
# IONA Public Testnet Launcher
# ============================================================================
# Launches a configurable N-node public testnet on a single machine or across
# multiple machines. Designed for both local development and public testnet
# deployment.
#
# Usage:
#   ./scripts/testnet/launch_testnet.sh [OPTIONS]
#
# Options:
#   --nodes N          Number of validator nodes (default: 4)
#   --chain-id ID      Chain ID (default: 6126151)
#   --base-p2p PORT    Base P2P port (default: 17001)
#   --base-rpc PORT    Base RPC port (default: 19001)
#   --data-dir DIR     Base data directory (default: ./testnet_data)
#   --release          Build in release mode (default: debug)
#   --faucet           Enable faucet on all nodes
#   --log-level LVL    Log level: trace|debug|info|warn|error (default: info)
#   --clean            Remove existing testnet data before starting
#   --external-ip IP   External IP for remote peer connections
#   --help             Show this help
#
# Examples:
#   # Launch 4-node local testnet
#   ./scripts/testnet/launch_testnet.sh
#
#   # Launch 7-node testnet with faucet and debug logging
#   ./scripts/testnet/launch_testnet.sh --nodes 7 --faucet --log-level debug
#
#   # Launch public testnet with external IP
#   ./scripts/testnet/launch_testnet.sh --nodes 4 --external-ip 1.2.3.4 --release
# ============================================================================

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────

NUM_NODES=4
CHAIN_ID=6126151
BASE_P2P_PORT=17001
BASE_RPC_PORT=19001
DATA_DIR="./testnet_data"
BUILD_MODE="debug"
ENABLE_FAUCET=false
LOG_LEVEL="info"
CLEAN=false
EXTERNAL_IP="127.0.0.1"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── Parse Arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes)       NUM_NODES="$2"; shift 2 ;;
        --chain-id)    CHAIN_ID="$2"; shift 2 ;;
        --base-p2p)    BASE_P2P_PORT="$2"; shift 2 ;;
        --base-rpc)    BASE_RPC_PORT="$2"; shift 2 ;;
        --data-dir)    DATA_DIR="$2"; shift 2 ;;
        --release)     BUILD_MODE="release"; shift ;;
        --faucet)      ENABLE_FAUCET=true; shift ;;
        --log-level)   LOG_LEVEL="$2"; shift 2 ;;
        --clean)       CLEAN=true; shift ;;
        --external-ip) EXTERNAL_IP="$2"; shift 2 ;;
        --help)
            head -35 "$0" | tail -30
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Validation ──────────────────────────────────────────────────────────────

if [[ $NUM_NODES -lt 1 ]]; then
    echo "Error: Need at least 1 node"
    exit 1
fi

if [[ $NUM_NODES -lt 3 ]]; then
    echo "Warning: BFT consensus requires at least 3 nodes for fault tolerance"
fi

# ── Build ───────────────────────────────────────────────────────────────────

echo "============================================"
echo " IONA Public Testnet Launcher"
echo "============================================"
echo " Nodes:      $NUM_NODES"
echo " Chain ID:   $CHAIN_ID"
echo " P2P ports:  $BASE_P2P_PORT - $((BASE_P2P_PORT + NUM_NODES - 1))"
echo " RPC ports:  $BASE_RPC_PORT - $((BASE_RPC_PORT + NUM_NODES - 1))"
echo " Data dir:   $DATA_DIR"
echo " Build:      $BUILD_MODE"
echo " Faucet:     $ENABLE_FAUCET"
echo " Log level:  $LOG_LEVEL"
echo " External IP: $EXTERNAL_IP"
echo "============================================"

echo ""
echo "[1/4] Building iona-node ($BUILD_MODE)..."

if [[ "$BUILD_MODE" == "release" ]]; then
    ( cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node )
    BINARY="$ROOT_DIR/target/release/iona-node"
else
    ( cd "$ROOT_DIR" && cargo build --locked --bin iona-node )
    BINARY="$ROOT_DIR/target/debug/iona-node"
fi

if [[ ! -f "$BINARY" ]]; then
    echo "Error: Binary not found at $BINARY"
    exit 1
fi

echo "  Binary: $BINARY"

# ── Clean ───────────────────────────────────────────────────────────────────

if [[ "$CLEAN" == "true" ]]; then
    echo ""
    echo "[2/4] Cleaning existing testnet data..."
    rm -rf "$DATA_DIR"
fi

# ── Generate Configs ────────────────────────────────────────────────────────

echo ""
echo "[2/4] Generating node configurations..."

# Build peer list
build_peers() {
    local node_idx=$1
    local peers=""
    for i in $(seq 1 "$NUM_NODES"); do
        if [[ $i -ne $node_idx ]]; then
            local p2p_port=$((BASE_P2P_PORT + i - 1))
            if [[ -n "$peers" ]]; then
                peers="$peers, "
            fi
            peers="$peers\"/ip4/$EXTERNAL_IP/tcp/$p2p_port\""
        fi
    done
    echo "[$peers]"
}

for i in $(seq 1 "$NUM_NODES"); do
    NODE_DIR="$DATA_DIR/node$i"
    mkdir -p "$NODE_DIR"

    P2P_PORT=$((BASE_P2P_PORT + i - 1))
    RPC_PORT=$((BASE_RPC_PORT + i - 1))
    PEERS=$(build_peers "$i")

    cat > "$NODE_DIR/config.toml" <<TOML
# IONA Testnet Node $i Configuration
# Generated by launch_testnet.sh

[node]
data_dir  = "$NODE_DIR"
seed      = $i
chain_id  = $CHAIN_ID
log_level = "$LOG_LEVEL"
keystore  = "plain"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = true

[network]
listen = "/ip4/0.0.0.0/tcp/$P2P_PORT"
peers  = $PEERS
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10
enable_p2p_state_sync = true

[mempool]
capacity = 200000

[rpc]
listen        = "0.0.0.0:$RPC_PORT"
enable_faucet = $ENABLE_FAUCET

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 100
snapshot_keep = 5
snapshot_zstd_level = 3

[observability]
enable_otel = false
TOML

    echo "  Node $i: P2P=$P2P_PORT, RPC=$RPC_PORT, Seed=$i"
done

# ── Launch Nodes ────────────────────────────────────────────────────────────

echo ""
echo "[3/4] Launching $NUM_NODES nodes..."

PIDS=()
export RUST_LOG="${LOG_LEVEL}"

for i in $(seq 1 "$NUM_NODES"); do
    NODE_DIR="$DATA_DIR/node$i"
    LOG_FILE="$NODE_DIR/node.log"

    "$BINARY" --config "$NODE_DIR/config.toml" > "$LOG_FILE" 2>&1 &
    PID=$!
    PIDS+=("$PID")
    echo "  Node $i started (PID=$PID, log=$LOG_FILE)"
done

# ── Cleanup Trap ────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "Shutting down testnet..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    echo "All nodes stopped."
}

trap cleanup INT TERM EXIT

# ── Status ──────────────────────────────────────────────────────────────────

echo ""
echo "[4/4] Testnet is running!"
echo ""
echo "============================================"
echo " IONA Testnet Status"
echo "============================================"
echo ""
echo " RPC Endpoints:"
for i in $(seq 1 "$NUM_NODES"); do
    RPC_PORT=$((BASE_RPC_PORT + i - 1))
    echo "   Node $i: http://$EXTERNAL_IP:$RPC_PORT"
    echo "     Health: http://$EXTERNAL_IP:$RPC_PORT/health"
    echo "     Status: http://$EXTERNAL_IP:$RPC_PORT/status"
    echo "     Metrics: http://$EXTERNAL_IP:$RPC_PORT/metrics"
done
echo ""
echo " P2P Endpoints:"
for i in $(seq 1 "$NUM_NODES"); do
    P2P_PORT=$((BASE_P2P_PORT + i - 1))
    echo "   Node $i: /ip4/$EXTERNAL_IP/tcp/$P2P_PORT"
done
echo ""
echo " Logs:"
for i in $(seq 1 "$NUM_NODES"); do
    echo "   Node $i: $DATA_DIR/node$i/node.log"
done
echo ""
echo " Quick Test:"
echo "   curl http://$EXTERNAL_IP:$BASE_RPC_PORT/health"
echo "   curl http://$EXTERNAL_IP:$BASE_RPC_PORT/status"
echo ""
if [[ "$ENABLE_FAUCET" == "true" ]]; then
    echo " Faucet:"
    echo "   curl -X POST http://$EXTERNAL_IP:$BASE_RPC_PORT/faucet -H 'Content-Type: application/json' -d '{\"address\":\"YOUR_ADDRESS\"}'"
    echo ""
fi
echo " Press Ctrl+C to stop all nodes."
echo "============================================"

# Wait for all nodes
wait
