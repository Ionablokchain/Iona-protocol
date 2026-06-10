#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Startup Order — Production‑Grade Node Sequencer
# =============================================================================
#
# Starts all IONA nodes in the correct sequence for BFT consensus.
#
# Usage:
#   ./startup_order.sh [OPTIONS]
#
# Options:
#   --dry-run             Show what would happen without starting
#   --service-prefix NAME Systemd service prefix (default: iona)
#   --health-timeout SEC  Max seconds to wait for health check (default: 60)
#   --quorum-wait SEC     Seconds to wait for height to advance (default: 30)
#   --producers LIST      Comma‑separated producer nodes (default: val2,val3,val4)
#   --followers LIST      Comma‑separated follower nodes (default: val1)
#   --rpc-nodes LIST      Comma‑separated RPC nodes (default: rpc)
#   --verbose             Enable detailed output
#   --help                Show this help
#
# Environment variables (fallback):
#   IONA_SERVICE_PREFIX, IONA_HEALTH_TIMEOUT, IONA_QUORUM_WAIT,
#   IONA_PRODUCERS, IONA_FOLLOWERS, IONA_RPC_NODES, IONA_VERBOSE
#
# Order (critical for BFT):
#   1. Start ALL producers first — need quorum (2/3+) for consensus
#   2. Wait for height to advance (consensus active)
#   3. Start followers
#   4. Start RPC nodes
#
# Why this order matters:
#   - Producers must form quorum before blocks can be produced
#   - Starting followers first causes them to timeout waiting for blocks
#   - RPC depends on synced state from producers

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=false
SERVICE_PREFIX="${IONA_SERVICE_PREFIX:-iona}"
HEALTH_TIMEOUT="${IONA_HEALTH_TIMEOUT:-60}"
QUORUM_WAIT="${IONA_QUORUM_WAIT:-30}"
PRODUCERS="${IONA_PRODUCERS:-val2,val3,val4}"
FOLLOWERS="${IONA_FOLLOWERS:-val1}"
RPC_NODES="${IONA_RPC_NODES:-rpc}"
VERBOSE="${IONA_VERBOSE:-0}"
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
        --dry-run)        DRY_RUN=true; shift ;;
        --service-prefix) SERVICE_PREFIX="$2"; shift 2 ;;
        --health-timeout) HEALTH_TIMEOUT="$2"; shift 2 ;;
        --quorum-wait)    QUORUM_WAIT="$2"; shift 2 ;;
        --producers)      PRODUCERS="$2"; shift 2 ;;
        --followers)      FOLLOWERS="$2"; shift 2 ;;
        --rpc-nodes)      RPC_NODES="$2"; shift 2 ;;
        --verbose)        VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Parse node lists ────────────────────────────────────────────────────────
IFS=',' read -ra PRODUCER_ARRAY <<< "$PRODUCERS"
IFS=',' read -ra FOLLOWER_ARRAY <<< "$FOLLOWERS"
IFS=',' read -ra RPC_ARRAY <<< "$RPC_NODES"

# ── Node port mapping ───────────────────────────────────────────────────────
declare -A NODE_PORTS=(
    [val1]=9001 [val2]=9002 [val3]=9003 [val4]=9004 [rpc]=9000
)

# ── Functions ───────────────────────────────────────────────────────────────
start_node() {
    local node="$1"
    local service="${SERVICE_PREFIX}-${node}"
    info "Starting $service..."
    if $DRY_RUN; then
        info "  [DRY RUN] sudo systemctl start $service"
    else
        sudo systemctl start "$service" || warn "Failed to start $service"
    fi
}

wait_health() {
    local node="$1"
    local port="$2"
    local timeout="$3"

    if $DRY_RUN; then
        info "  [DRY RUN] Wait for http://127.0.0.1:${port}/health (${timeout}s)"
        return 0
    fi

    for i in $(seq 1 "$timeout"); do
        if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
            info "  Health OK ($node, port $port)"
            return 0
        fi
        sleep 1
    done
    warn "  Health timeout for $node (port $port)"
    return 1
}

wait_height_advancing() {
    local port="$1"
    local wait_s="$2"

    if $DRY_RUN; then
        info "  [DRY RUN] Wait ${wait_s}s for height to advance on port ${port}"
        return 0
    fi

    local h1 h2
    h1=$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('height',0))" 2>/dev/null || echo "0")

    info "  Current height: $h1. Waiting ${wait_s}s for advancement..."
    sleep "$wait_s"

    h2=$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('height',0))" 2>/dev/null || echo "0")

    info "  Height after wait: $h2"
    if [[ "$h2" -gt "$h1" ]]; then
        info "  Consensus ACTIVE (height advancing)"
        return 0
    else
        warn "  Height not advancing — check producer logs"
        return 1
    fi
}

# ── Main sequence ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  IONA Startup Sequence                                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
info "Producers: ${PRODUCER_ARRAY[*]}"
info "Followers: ${FOLLOWER_ARRAY[*]}"
info "RPC nodes: ${RPC_ARRAY[*]}"
info "Health timeout: ${HEALTH_TIMEOUT}s"
info "Quorum wait: ${QUORUM_WAIT}s"
echo ""

# Phase 1: Start all producers
echo "──────────────────────────────────────────────────────────────────────"
info "[Phase 1] Starting producers (need quorum for consensus)"
echo ""

for node in "${PRODUCER_ARRAY[@]}"; do
    start_node "$node"
    sleep 2
done

echo ""
info "[Phase 1] Waiting for producers to become healthy..."
for node in "${PRODUCER_ARRAY[@]}"; do
    port="${NODE_PORTS[$node]:-9000}"
    wait_health "$node" "$port" "$HEALTH_TIMEOUT" || true
done

echo ""
info "[Phase 1] Checking consensus is active..."
FIRST_PRODUCER_PORT="${NODE_PORTS[${PRODUCER_ARRAY[0]}]:-9002}"
wait_height_advancing "$FIRST_PRODUCER_PORT" "$QUORUM_WAIT" || true

# Phase 2: Start followers
echo ""
echo "──────────────────────────────────────────────────────────────────────"
info "[Phase 2] Starting followers..."
echo ""

for node in "${FOLLOWER_ARRAY[@]}"; do
    start_node "$node"
    port="${NODE_PORTS[$node]:-9001}"
    wait_health "$node" "$port" "$HEALTH_TIMEOUT" || true
done

# Phase 3: Start RPC nodes
echo ""
echo "──────────────────────────────────────────────────────────────────────"
info "[Phase 3] Starting RPC nodes..."
echo ""

for node in "${RPC_ARRAY[@]}"; do
    start_node "$node"
    port="${NODE_PORTS[$node]:-9000}"
    wait_health "$node" "$port" "$HEALTH_TIMEOUT" || true
done

# ── Summary ─────────────────────────────────────────────────────────────────
DURATION=$(($(date +%s) - START_TIME))

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Startup Complete (${DURATION}s)                                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Quick verification:"
for node in "${PRODUCER_ARRAY[@]}" "${FOLLOWER_ARRAY[@]}" "${RPC_ARRAY[@]}"; do
    port="${NODE_PORTS[$node]:-9000}"
    echo "  curl http://127.0.0.1:${port}/health   # $node"
done
echo ""
echo "Dashboard: ./deploy/scripts/healthcheck.sh --watch"
