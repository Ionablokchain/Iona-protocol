#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Local Multi-Node Testnet — Production‑Grade                          ║
# ║                                                                             ║
# ║  Starts an N‑node IONA network locally (default: 3).                        ║
# ║  Each node gets its own data directory, config, and RPC port.              ║
# ║                                                                             ║
# ║  Usage:                                                                     ║
# ║    ./scripts/run_nodes_local.sh [OPTIONS]                                   ║
# ║                                                                             ║
# ║  Options:                                                                   ║
# ║    --nodes N         Number of nodes to start (default: 3, min: 1)         ║
# ║    --binary PATH     Path to iona-node binary (default: build if missing)  ║
# ║    --build           Force rebuild before starting                         ║
# ║    --keep-data       Keep data directories after exit (default: remove)    ║
# ║    --keep-logs       Keep log files after exit (default: remove)           ║
# ║    --base-port P2P   Base P2P port (default: 7000)                         ║
# ║    --base-rpc-port   Base RPC port (default: 9000)                         ║
# ║    --verbose         Show detailed output                                  ║
# ║    --help            Show this help                                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── Configuration ────────────────────────────────────────────────────────────

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY=""
FORCE_BUILD=false
KEEP_DATA=false
KEEP_LOGS=false
VERBOSE=false
NODES=3
BASE_P2P_PORT=7000
BASE_RPC_PORT=9000

# Colors for better readability (if terminal supports)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

# ── Helper functions ─────────────────────────────────────────────────────────

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
section() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "[DEBUG] $*"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes)        NODES="$2"; shift 2 ;;
        --nodes=*)      NODES="${1#*=}"; shift ;;
        --binary)       BINARY="$2"; shift 2 ;;
        --binary=*)     BINARY="${1#*=}"; shift ;;
        --build)        FORCE_BUILD=true; shift ;;
        --keep-data)    KEEP_DATA=true; shift ;;
        --keep-logs)    KEEP_LOGS=true; shift ;;
        --base-port)    BASE_P2P_PORT="$2"; shift 2 ;;
        --base-port=*)  BASE_P2P_PORT="${1#*=}"; shift ;;
        --base-rpc-port) BASE_RPC_PORT="$2"; shift 2 ;;
        --base-rpc-port=*) BASE_RPC_PORT="${1#*=}"; shift ;;
        --verbose)      VERBOSE=true; shift ;;
        --help|-h)
            sed -n '/^# Usage:/,/^# ╚══/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)              warn "Unknown option: $1"; shift ;;
    esac
done

# ── Validate inputs ─────────────────────────────────────────────────────────

if [[ "$NODES" -lt 1 ]]; then
    die "Number of nodes must be at least 1 (got $NODES)"
fi

if [[ "$BASE_P2P_PORT" -lt 1024 ]] || [[ "$BASE_P2P_PORT" -gt 65535 ]]; then
    die "Base P2P port must be between 1024 and 65535"
fi

if [[ "$BASE_RPC_PORT" -lt 1024 ]] || [[ "$BASE_RPC_PORT" -gt 65535 ]]; then
    die "Base RPC port must be between 1024 and 65535"
fi

# Check port overlap
if [[ $((BASE_RPC_PORT - BASE_P2P_PORT)) -lt $NODES ]] && [[ $((BASE_RPC_PORT - BASE_P2P_PORT)) -gt -$NODES ]]; then
    warn "P2P and RPC port ranges overlap. This may cause conflicts."
fi

# ── Dependency checks ────────────────────────────────────────────────────────

section "Checking dependencies"

if ! command_exists cargo; then
    die "cargo not found. Please install Rust: https://rustup.rs/"
fi
ok "cargo available"

if ! command_exists curl; then
    die "curl is required for health checks"
fi
ok "curl available"

# ── Ensure binary exists / build ─────────────────────────────────────────────

if [[ -z "$BINARY" ]]; then
    BINARY="$ROOT_DIR/target/release/iona-node"
fi

if [[ ! -f "$BINARY" ]] || [[ "$FORCE_BUILD" == true ]]; then
    info "Building iona-node release binary..."
    (cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node) || die "Build failed"
    ok "Binary built at $BINARY"
else
    ok "Binary found at $BINARY"
fi

if [[ ! -x "$BINARY" ]]; then
    die "Binary $BINARY is not executable"
fi

# ── Clean old data (optional) ───────────────────────────────────────────────

section "Preparing data directories"

DATA_BASE="$ROOT_DIR/data/nodes"
LOG_DIR="$ROOT_DIR/logs"

# Remove old data if not keeping
if [[ "$KEEP_DATA" != true ]]; then
    log_verbose "Removing old data directories"
    rm -rf "$DATA_BASE"*
fi

# Create directories
for i in $(seq 1 $NODES); do
    DATA_DIR="$DATA_BASE$i"
    mkdir -p "$DATA_DIR"
    ok "Data directory: $DATA_DIR"
done

if [[ "$KEEP_LOGS" == true ]]; then
    mkdir -p "$LOG_DIR"
    ok "Log directory: $LOG_DIR"
fi

# ── Generate configuration files ────────────────────────────────────────────

section "Generating configuration files"

# Build peer list for each node
for i in $(seq 1 $NODES); do
    PEERS=""
    for j in $(seq 1 $NODES); do
        if [[ $i -ne $j ]]; then
            PEER="/ip4/127.0.0.1/tcp$((BASE_P2P_PORT + j))"
            if [[ -n "$PEERS" ]]; then
                PEERS="$PEERS, \"$PEER\""
            else
                PEERS="\"$PEER\""
            fi
        fi
    done

    VALIDATOR_LIST=""
    for s in $(seq 1 $NODES); do
        if [[ -n "$VALIDATOR_LIST" ]]; then
            VALIDATOR_LIST="$VALIDATOR_LIST, $s"
        else
            VALIDATOR_LIST="$s"
        fi
    done

    cat > "$DATA_BASE$i/config.toml" << TOML
# IONA node configuration — node $i (local testnet)
[node]
data_dir  = "$DATA_BASE$i"
seed      = $i
chain_id  = 6126151
log_level = "info"
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
validator_seeds      = [$VALIDATOR_LIST]

[network]
listen = "/ip4/0.0.0.0/tcp$((BASE_P2P_PORT + i))"
peers  = [$PEERS]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:$((BASE_RPC_PORT + i))"
enable_faucet = false
cors_allow_all = false

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
TOML

    ok "Config for node $i created"
done

# ── Start nodes ──────────────────────────────────────────────────────────────

section "Starting nodes"

PIDS=()
cleanup() {
    echo ""
    info "Shutting down all nodes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    
    if [[ "$KEEP_LOGS" != true ]]; then
        rm -rf "$LOG_DIR" 2>/dev/null || true
    fi
    if [[ "$KEEP_DATA" != true ]]; then
        for i in $(seq 1 $NODES); do
            rm -rf "$DATA_BASE$i" 2>/dev/null || true
        done
    fi
    ok "Cleanup completed"
}
trap cleanup EXIT INT TERM

start_node() {
    local i=$1
    local data_dir="$DATA_BASE$i"
    local rpc_port=$((BASE_RPC_PORT + i))
    local cmd="$BINARY --config $data_dir/config.toml"

    if [[ "$KEEP_LOGS" == true ]]; then
        local log_file="$LOG_DIR/node$i.log"
        mkdir -p "$(dirname "$log_file")"
        $cmd >> "$log_file" 2>&1 &
    else
        $cmd > /dev/null 2>&1 &
    fi
    local pid=$!
    PIDS+=($pid)
    echo -n "  Node $i (PID $pid, RPC $rpc_port)"

    # Wait for health endpoint
    local health_url="http://127.0.0.1:$rpc_port/health"
    local max_attempts=30
    for attempt in $(seq 1 $max_attempts); do
        if curl -s -f -o /dev/null "$health_url" 2>/dev/null; then
            echo -e " ${GREEN}✓ healthy${NC} (${attempt}s)"
            return 0
        fi
        sleep 1
    done
    echo -e " ${RED}✗ failed to become healthy after ${max_attempts}s${NC}"
    return 1
}

FAILED=0
for i in $(seq 1 $NODES); do
    if ! start_node $i; then
        FAILED=1
        warn "Node $i may not be fully functional"
    fi
done

if [[ $FAILED -eq 1 ]]; then
    warn "Some nodes failed to become healthy. Check logs."
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
section "Testnet running"
echo -e "  ${BOLD}Nodes:${NC} $NODES"
echo -e "  ${BOLD}RPC endpoints:${NC}"
for i in $(seq 1 $NODES); do
    echo "    http://127.0.0.1:$((BASE_RPC_PORT + i))/health"
done
echo ""
echo "  ${BOLD}Data directories:${NC} $DATA_BASE*"
if [[ "$KEEP_LOGS" == true ]]; then
    echo "  ${BOLD}Logs:${NC} $LOG_DIR/node*.log"
fi
echo ""
echo "  Press ${BOLD}Ctrl+C${NC} to stop all nodes."

# ── Wait for all background processes ────────────────────────────────────────

wait
