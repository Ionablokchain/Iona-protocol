#!/usr/bin/env bash
set -euo pipefail
#
# IONA Startup Order — start all nodes in the correct sequence.
#
# Usage:
#   ./deploy/scripts/startup_order.sh              # start all in order
#   ./deploy/scripts/startup_order.sh --dry-run     # show what would happen
#
# Order (critical for BFT):
#   1. Start ALL producers first (val2, val3, val4) — need quorum for consensus
#   2. Wait for height to advance (consensus active)
#   3. Start follower (val1)
#   4. Start RPC node (rpc)
#
# Why this order matters:
#   - Producers must form quorum (2/3+) before blocks can be produced
#   - If you start followers first, they'll time out waiting for blocks
#   - RPC depends on synced state from producers

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=false
SERVICE_PREFIX="${IONA_SERVICE_PREFIX:-iona}"
HEALTH_TIMEOUT=60
QUORUM_WAIT=30

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--dry-run]"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

start_node() {
    local node="$1"
    local service="${SERVICE_PREFIX}-${node}"
    echo "  Starting $service..."
    if $DRY_RUN; then
        echo "    [DRY RUN] sudo systemctl start $service"
    else
        sudo systemctl start "$service"
    fi
}

wait_health() {
    local node="$1"
    local port="$2"
    local timeout="$3"

    if $DRY_RUN; then
        echo "    [DRY RUN] Wait for http://127.0.0.1:${port}/health (${timeout}s)"
        return 0
    fi

    for i in $(seq 1 "$timeout"); do
        if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
            echo "    Health OK ($node, port $port)"
            return 0
        fi
        sleep 1
    done
    echo "    WARN: Health timeout for $node (port $port)"
    return 1
}

wait_height_advancing() {
    local port="$1"
    local wait_s="$2"

    if $DRY_RUN; then
        echo "    [DRY RUN] Wait ${wait_s}s for height to advance on port ${port}"
        return 0
    fi

    local h1
    h1=$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('height',0))" 2>/dev/null || echo "0")

    echo "    Current height: $h1. Waiting ${wait_s}s..."
    sleep "$wait_s"

    local h2
    h2=$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('height',0))" 2>/dev/null || echo "0")

    echo "    Height after wait: $h2"
    if [[ "$h2" -gt "$h1" ]]; then
        echo "    Consensus ACTIVE (height advancing)"
        return 0
    else
        echo "    WARN: Height not advancing — check producer logs"
        return 1
    fi
}

echo "=== IONA Startup Sequence ==="
echo ""

# Phase 1: Start all producers (need quorum)
echo "[Phase 1] Starting producers (val2, val3, val4)..."
start_node "val2"
sleep 2
start_node "val3"
sleep 2
start_node "val4"

echo ""
echo "[Phase 1] Waiting for producers to be healthy..."
wait_health "val2" 9002 "$HEALTH_TIMEOUT" || true
wait_health "val3" 9003 "$HEALTH_TIMEOUT" || true
wait_health "val4" 9004 "$HEALTH_TIMEOUT" || true

echo ""
echo "[Phase 1] Checking consensus is active..."
wait_height_advancing 9002 "$QUORUM_WAIT" || true

# Phase 2: Start follower
echo ""
echo "[Phase 2] Starting follower (val1)..."
start_node "val1"
wait_health "val1" 9001 "$HEALTH_TIMEOUT" || true

# Phase 3: Start RPC
echo ""
echo "[Phase 3] Starting RPC node..."
start_node "rpc"
wait_health "rpc" 9000 "$HEALTH_TIMEOUT" || true

echo ""
echo "=== Startup Complete ==="
echo ""
echo "Quick verification:"
echo "  curl http://127.0.0.1:9002/health   # val2 (producer)"
echo "  curl http://127.0.0.1:9003/health   # val3 (producer)"
echo "  curl http://127.0.0.1:9004/health   # val4 (producer)"
echo "  curl http://127.0.0.1:9001/health   # val1 (follower)"
echo "  curl http://127.0.0.1:9000/health   # rpc  (public)"
echo ""
echo "Dashboard: ./deploy/scripts/healthcheck.sh --watch"
