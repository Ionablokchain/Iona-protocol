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
#   --health-timeout S Timeout in seconds waiting for nodes to become healthy (default: 30)
#   --verbose          Enable verbose output
#   --json             Output node information in JSON format
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

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Helper Functions ────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo -e "\n${BLUE}${BOLD}============================================${NC}"; echo -e "${BLUE}${BOLD} $* ${NC}"; echo -e "${BLUE}${BOLD}============================================${NC}"; }
log_verbose() { if [[ "$VERBOSE" == true ]]; then echo -e "${CYAN}[DEBUG]${NC} $*"; fi; }

die() {
    log_error "$*"
    exit 1
}

command_exists() {
    command -v "$1" &>/dev/null
}

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
HEALTH_TIMEOUT=30
VERBOSE=false
JSON_OUTPUT=false

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
START_TIME=$(date +%s)

# ── Parse Arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes)           NUM_NODES="$2"; shift 2 ;;
        --chain-id)        CHAIN_ID="$2"; shift 2 ;;
        --base-p2p)        BASE_P2P_PORT="$2"; shift 2 ;;
        --base-rpc)        BASE_RPC_PORT="$2"; shift 2 ;;
        --data-dir)        DATA_DIR="$2"; shift 2 ;;
        --release)         BUILD_MODE="release"; shift ;;
        --faucet)          ENABLE_FAUCET=true; shift ;;
        --log-level)       LOG_LEVEL="$2"; shift 2 ;;
        --clean)           CLEAN=true; shift ;;
        --external-ip)     EXTERNAL_IP="$2"; shift 2 ;;
        --health-timeout)  HEALTH_TIMEOUT="$2"; shift 2 ;;
        --verbose)         VERBOSE=true; shift ;;
        --json)            JSON_OUTPUT=true; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# =/p' "$0" | sed 's/^# \{0,1\}//'
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
    die "Need at least 1 node"
fi

if [[ $NUM_NODES -lt 3 ]]; then
    log_warn "BFT consensus requires at least 3 nodes for fault tolerance"
fi

if ! [[ "$LOG_LEVEL" =~ ^(trace|debug|info|warn|error)$ ]]; then
    die "Invalid log level: $LOG_LEVEL (must be trace, debug, info, warn, error)"
fi

# ── Build ───────────────────────────────────────────────────────────────────
log_section "IONA Public Testnet Launcher"
echo "  Nodes:        $NUM_NODES"
echo "  Chain ID:     $CHAIN_ID"
echo "  P2P ports:    $BASE_P2P_PORT - $((BASE_P2P_PORT + NUM_NODES - 1))"
echo "  RPC ports:    $BASE_RPC_PORT - $((BASE_RPC_PORT + NUM_NODES - 1))"
echo "  Data dir:     $DATA_DIR"
echo "  Build:        $BUILD_MODE"
echo "  Faucet:       $ENABLE_FAUCET"
echo "  Log level:    $LOG_LEVEL"
echo "  External IP:  $EXTERNAL_IP"
echo "  Health timeout: ${HEALTH_TIMEOUT}s"
echo ""

log_info "Building iona-node ($BUILD_MODE)..."

if [[ "$BUILD_MODE" == "release" ]]; then
    ( cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node 2>&1 | tail -5 ) || die "Release build failed"
    BINARY="$ROOT_DIR/target/release/iona-node"
else
    ( cd "$ROOT_DIR" && cargo build --locked --bin iona-node 2>&1 | tail -5 ) || die "Debug build failed"
    BINARY="$ROOT_DIR/target/debug/iona-node"
fi

if [[ ! -f "$BINARY" ]]; then
    die "Binary not found at $BINARY"
fi

log_info "Binary: $BINARY"

# ── Clean ───────────────────────────────────────────────────────────────────
if [[ "$CLEAN" == "true" ]]; then
    log_info "Cleaning existing testnet data..."
    rm -rf "$DATA_DIR"
fi

# ── Generate Configs ────────────────────────────────────────────────────────
log_info "Generating node configurations..."

# Function to build peer list for a node
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

    log_verbose "Node $i: P2P=$P2P_PORT, RPC=$RPC_PORT, Seed=$i"
done
log_info "Configuration generated for $NUM_NODES nodes"

# ── Launch Nodes ────────────────────────────────────────────────────────────
log_info "Launching $NUM_NODES nodes..."

PIDS=()
NODE_INFO=()
export RUST_LOG="${LOG_LEVEL}"

for i in $(seq 1 "$NUM_NODES"); do
    NODE_DIR="$DATA_DIR/node$i"
    LOG_FILE="$NODE_DIR/node.log"
    RPC_PORT=$((BASE_RPC_PORT + i - 1))

    "$BINARY" --config "$NODE_DIR/config.toml" > "$LOG_FILE" 2>&1 &
    PID=$!
    PIDS+=("$PID")
    NODE_INFO+=("{\"index\":$i,\"pid\":$PID,\"rpc_port\":$RPC_PORT,\"p2p_port\":$((BASE_P2P_PORT + i - 1)),\"log\":\"$LOG_FILE\"}")
    log_verbose "Node $i started (PID=$PID)"
done
log_info "All nodes launched"

# ── Wait for health ─────────────────────────────────────────────────────────
log_info "Waiting for nodes to become healthy (timeout: ${HEALTH_TIMEOUT}s)..."

HEALTHY_COUNT=0
for i in $(seq 1 "$NUM_NODES"); do
    RPC_PORT=$((BASE_RPC_PORT + i - 1))
    HEALTH_URL="http://127.0.0.1:$RPC_PORT/health"
    echo -n "  Node $i (port $RPC_PORT) ... "

    for ((t=1; t<=HEALTH_TIMEOUT; t++)); do
        if curl -s -f -o /dev/null "$HEALTH_URL" 2>/dev/null; then
            echo -e "${GREEN}healthy (${t}s)${NC}"
            ((HEALTHY_COUNT++))
            break
        fi
        sleep 1
    done
    if [[ $t -gt $HEALTH_TIMEOUT ]]; then
        echo -e "${RED}FAILED (timeout)${NC}"
        log_warn "Node $i failed to become healthy; check log: $DATA_DIR/node$i/node.log"
    fi
done

# ── Cleanup Trap ───────────────────────────────────────────────────────────
cleanup() {
    echo ""
    log_info "Shutting down testnet..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    log_info "All nodes stopped."
}

trap cleanup INT TERM EXIT

# ── Output ──────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [[ "$JSON_OUTPUT" == "true" ]]; then
    JSON_NODES=$(printf '%s\n' "${NODE_INFO[@]}" | jq -s '.')
    cat <<EOF
{
  "status": "running",
  "nodes": $JSON_NODES,
  "healthy_count": $HEALTHY_COUNT,
  "total_nodes": $NUM_NODES,
  "chain_id": $CHAIN_ID,
  "external_ip": "$EXTERNAL_IP",
  "base_p2p_port": $BASE_P2P_PORT,
  "base_rpc_port": $BASE_RPC_PORT,
  "data_dir": "$DATA_DIR",
  "duration_seconds": $DURATION
}
EOF
else
    echo ""
    echo "============================================"
    echo " IONA Testnet Status"
    echo "============================================"
    echo ""
    echo " Healthy nodes: $HEALTHY_COUNT/$NUM_NODES"
    echo " Duration: ${DURATION}s"
    echo ""
    echo " RPC Endpoints:"
    for i in $(seq 1 "$NUM_NODES"); do
        RPC_PORT=$((BASE_RPC_PORT + i - 1))
        echo "   Node $i: http://$EXTERNAL_IP:$RPC_PORT"
        echo "     Health: http://$EXTERNAL_IP:$RPC_PORT/health"
        echo "     Status: http://$EXTERNAL_IP:$RPC_PORT/status"
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
    if [[ "$ENABLE_FAUCET" == "true" ]]; then
        echo " Faucet:"
        echo "   curl -X POST http://$EXTERNAL_IP:$BASE_RPC_PORT/faucet -H 'Content-Type: application/json' -d '{\"address\":\"YOUR_ADDRESS\"}'"
        echo ""
    fi
    echo " Press Ctrl+C to stop all nodes."
    echo "============================================"
fi

# Wait for nodes (keeps script running)
wait
