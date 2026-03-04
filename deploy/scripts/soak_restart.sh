#!/usr/bin/env bash
# IONA Soak Test: Random Node Restarts
# Usage: ./deploy/scripts/soak_restart.sh [--duration DURATION] [--interval SECONDS]
#
# Randomly restarts nodes and verifies the chain continues producing blocks.
# Default: 24h duration, 300s between restarts.

set -euo pipefail

DURATION="24h"
INTERVAL=300
BINARY="./target/release/iona-node"
NODES=("val2" "val3" "val4")
CONFIG_DIR="./deploy/configs"
DATA_BASE="/tmp/iona_soak"
LOG_FILE="${DATA_BASE}/soak_restart.log"
RPC_PORT=9000

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p "$DATA_BASE"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }

get_height() {
    curl -sf "http://127.0.0.1:${RPC_PORT}/status" 2>/dev/null \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('height',0))" 2>/dev/null \
      || echo "0"
}

duration_to_seconds() {
    local d="$1"
    case "$d" in
        *h) echo $(( ${d%h} * 3600 )) ;;
        *m) echo $(( ${d%m} * 60 )) ;;
        *s) echo "${d%s}" ;;
        *) echo "$d" ;;
    esac
}

DURATION_S=$(duration_to_seconds "$DURATION")
END_TIME=$(( $(date +%s) + DURATION_S ))

log "=== IONA Soak Test: Restart Resilience ==="
log "Duration: $DURATION ($DURATION_S seconds)"
log "Interval: ${INTERVAL}s between restarts"
log "Nodes: ${NODES[*]}"
log ""

RESTARTS=0
FAILURES=0

while [ $(date +%s) -lt $END_TIME ]; do
    NODE=${NODES[$RANDOM % ${#NODES[@]}]}
    log "--- Restarting $NODE ---"

    HEIGHT_BEFORE=$(get_height)
    log "Height before: $HEIGHT_BEFORE"

    PID=$(pgrep -f "config.*${NODE}" 2>/dev/null || true)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        sleep 2
    fi

    $BINARY --config "${CONFIG_DIR}/${NODE}.toml" >> "${DATA_BASE}/${NODE}.log" 2>&1 &
    RESTARTS=$((RESTARTS + 1))
    log "Restarted $NODE (attempt #$RESTARTS)"

    sleep 10

    HEIGHT_AFTER=$(get_height)
    log "Height after: $HEIGHT_AFTER"

    if [ "$HEIGHT_AFTER" -le "$HEIGHT_BEFORE" ]; then
        log "WARNING: Height did not increase! ($HEIGHT_BEFORE -> $HEIGHT_AFTER)"
        FAILURES=$((FAILURES + 1))
    else
        log "OK: Height increased ($HEIGHT_BEFORE -> $HEIGHT_AFTER)"
    fi

    log ""
    sleep "$INTERVAL"
done

log "=== Soak Test Complete ==="
log "Total restarts: $RESTARTS"
log "Failures: $FAILURES"

if [ "$FAILURES" -gt 0 ]; then
    log "RESULT: FAIL ($FAILURES height stalls detected)"
    exit 1
else
    log "RESULT: PASS (all restarts recovered successfully)"
    exit 0
fi
