#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Local 5-Node Network — Production‑Grade Development Environment
# =============================================================================
#
# Spawns a complete 5‑node IONA network on localhost for development/testing.
#
# Topology:
#   val2 (producer, seed=2, tcp/7002, rpc/9002)
#   val3 (producer, seed=3, tcp/7003, rpc/9003)
#   val4 (producer, seed=4, tcp/7004, rpc/9004)
#   val1 (follower, seed=1, tcp/7001, rpc/9001)
#   rpc  (public,   seed=100, tcp/7005, rpc/9000)
#
# Usage:
#   ./run_5nodes_local.sh [OPTIONS]
#
# Options:
#   --binary PATH         Path to iona-node binary (default: build from source)
#   --data-root DIR       Root directory for node data (default: ./data)
#   --build               Force rebuild before starting
#   --keep-data           Do not delete existing data directories
#   --log-dir DIR         Directory for log files (default: ./logs)
#   --verbose             Enable detailed output
#   --help                Show this help
#
# Environment:
#   RUST_LOG              Log level for all nodes (default: info)

# ── Configuration ────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export RUST_LOG="${RUST_LOG:-info}"
DATA_ROOT="${DATA_ROOT:-$ROOT_DIR/data}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
BINARY="${BINARY:-}"
FORCE_BUILD=false
KEEP_DATA=false
VERBOSE=0
START_TIME=$(date +%s)

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Helpers ─────────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }
die()     { error "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)     BINARY="$2"; shift 2 ;;
        --data-root)  DATA_ROOT="$2"; shift 2 ;;
        --build)      FORCE_BUILD=true; shift ;;
        --keep-data)  KEEP_DATA=true; shift ;;
        --log-dir)    LOG_DIR="$2"; shift 2 ;;
        --verbose)    VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Resolve binary ──────────────────────────────────────────────────────────
if [[ -z "$BINARY" ]]; then
    BINARY="$ROOT_DIR/target/release/iona-node"
fi

if [[ ! -f "$BINARY" ]] || [[ "$FORCE_BUILD" == true ]]; then
    info "Building iona-node..."
    (cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node) || die "Build failed"
    BINARY="$ROOT_DIR/target/release/iona-node"
fi

if [[ ! -x "$BINARY" ]]; then
    die "Binary not executable: $BINARY"
fi

info "Using binary: $BINARY"
info "Data root:    $DATA_ROOT"
info "Log dir:      $LOG_DIR"

# ── Prepare directories ─────────────────────────────────────────────────────
if [[ "$KEEP_DATA" == false ]]; then
    info "Removing old data..."
    rm -rf "$DATA_ROOT"/{val1,val2,val3,val4,rpc}
fi
mkdir -p "$DATA_ROOT"/{val1,val2,val3,val4,rpc}
mkdir -p "$LOG_DIR"

# ── Generate configs ────────────────────────────────────────────────────────
gen_config() {
    local name="$1" seed="$2" p2p_port="$3" rpc_port="$4" producer="$5"
    shift 5
    local peers_toml=""
    for p in "$@"; do
        [[ -n "$peers_toml" ]] && peers_toml="${peers_toml}, "
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

info "Generating configuration files..."

gen_config val2 2 7002 9002 true \
    "/ip4/127.0.0.1/tcp/7003" "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7001" "/ip4/127.0.0.1/tcp/7005"

gen_config val3 3 7003 9003 true \
    "/ip4/127.0.0.1/tcp/7002" "/ip4/127.0.0.1/tcp/7004" \
    "/ip4/127.0.0.1/tcp/7001" "/ip4/127.0.0.1/tcp/7005"

gen_config val4 4 7004 9004 true \
    "/ip4/127.0.0.1/tcp/7002" "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7001" "/ip4/127.0.0.1/tcp/7005"

gen_config val1 1 7001 9001 false \
    "/ip4/127.0.0.1/tcp/7002" "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004" "/ip4/127.0.0.1/tcp/7005"

gen_config rpc 100 7005 9000 false \
    "/ip4/127.0.0.1/tcp/7002" "/ip4/127.0.0.1/tcp/7003" \
    "/ip4/127.0.0.1/tcp/7004"

# ── Start nodes ─────────────────────────────────────────────────────────────
PIDS=()
cleanup() {
    echo ""
    info "Stopping all nodes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    info "All nodes stopped."
}
trap cleanup EXIT INT TERM

start_node() {
    local name="$1" delay="$2"
    local log_file="$LOG_DIR/${name}.log"
    info "Starting $name (log: $log_file)..."
    "$BINARY" --config "$DATA_ROOT/$name/config.toml" >> "$log_file" 2>&1 &
    PIDS+=($!)
    sleep "$delay"
}

info "Starting IONA 5-node local network..."
echo ""

start_node val2 1
start_node val3 1
start_node val4 3

start_node val1 1
start_node rpc  1

# ── Health check ────────────────────────────────────────────────────────────
info "Waiting for nodes to become healthy..."
for port in 9002 9003 9004 9001 9000; do
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
            verbose "  Port $port healthy after ${i}s"
            break
        fi
        sleep 1
    done
done

# ── Summary ─────────────────────────────────────────────────────────────────
DURATION=$(($(date +%s) - START_TIME))

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
echo "║  Logs: $LOG_DIR/node-*.log"
echo "║  Started in ${DURATION}s                                     "
echo "║  Press Ctrl+C to stop all nodes.                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

wait
