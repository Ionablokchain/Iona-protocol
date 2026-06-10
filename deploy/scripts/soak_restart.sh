#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Soak Test: Random Node Restarts — Production‑Grade
# =============================================================================
#
# Randomly restarts validator nodes and verifies the chain continues
# producing blocks after each restart.
#
# Usage:
#   ./soak_restart.sh [OPTIONS]
#
# Options:
#   --duration DURATION   Test duration (e.g. 24h, 30m, 3600s) (default: 24h)
#   --interval SECONDS    Seconds between restart attempts (default: 300)
#   --binary PATH         Path to iona-node binary (default: ./target/release/iona-node)
#   --config-dir DIR      Directory containing node configs (default: ./deploy/configs)
#   --data-base DIR       Base directory for data/logs (default: /tmp/iona_soak)
#   --log-dir DIR         Directory for log files (default: same as data-base)
#   --rpc-port PORT       RPC port for health/status queries (default: 9000)
#   --nodes LIST          Comma‑separated node names (default: val2,val3,val4)
#   --json                Output final summary as JSON (for CI/CD)
#   --verbose             Enable detailed output
#   --help                Show this help
#
# Environment variables (fallback):
#   IONA_SOAK_DURATION, IONA_SOAK_INTERVAL, IONA_SOAK_BINARY,
#   IONA_SOAK_CONFIG_DIR, IONA_SOAK_DATA_BASE, IONA_SOAK_RPC_PORT,
#   IONA_SOAK_NODES, IONA_VERBOSE

# ── Configuration ────────────────────────────────────────────────────────────
DURATION="${IONA_SOAK_DURATION:-24h}"
INTERVAL="${IONA_SOAK_INTERVAL:-300}"
BINARY="${IONA_SOAK_BINARY:-./target/release/iona-node}"
CONFIG_DIR="${IONA_SOAK_CONFIG_DIR:-./deploy/configs}"
DATA_BASE="${IONA_SOAK_DATA_BASE:-/tmp/iona_soak}"
LOG_DIR="${IONA_SOAK_LOG_DIR:-$DATA_BASE}"
RPC_PORT="${IONA_SOAK_RPC_PORT:-9000}"
NODES="${IONA_SOAK_NODES:-val2,val3,val4}"
VERBOSE="${IONA_VERBOSE:-0}"
JSON_OUTPUT=0
START_TIME=$(date +%s)

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

# ── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE=""
log_init() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/soak_restart_$(date +%Y%m%d-%H%M%S).log"
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOG_FILE") 2>&1
}

log_info()    { echo -e "${GREEN}[INFO]${NC}  $(date -u +%H:%M:%S) $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date -u +%H:%M:%S) $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date -u +%H:%M:%S) $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $(date -u +%H:%M:%S) $*"; }
die()         { log_error "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)   DURATION="$2"; shift 2 ;;
        --interval)   INTERVAL="$2"; shift 2 ;;
        --binary)     BINARY="$2"; shift 2 ;;
        --config-dir) CONFIG_DIR="$2"; shift 2 ;;
        --data-base)  DATA_BASE="$2"; shift 2 ;;
        --log-dir)    LOG_DIR="$2"; shift 2 ;;
        --rpc-port)   RPC_PORT="$2"; shift 2 ;;
        --nodes)      NODES="$2"; shift 2 ;;
        --json)       JSON_OUTPUT=1; shift ;;
        --verbose)    VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Pre-flight checks ──────────────────────────────────────────────────────
log_init
mkdir -p "$DATA_BASE"

if ! command -v curl &>/dev/null; then
    die "curl is required but not installed"
fi

# Parse nodes
IFS=',' read -ra NODE_ARRAY <<< "$NODES"
if [[ ${#NODE_ARRAY[@]} -eq 0 ]]; then
    die "Need at least 1 node (got 0)"
fi
log_info "Nodes: ${NODE_ARRAY[*]}"

# Validate binary
if [[ ! -x "$BINARY" ]]; then
    die "Binary not found or not executable: $BINARY"
fi
BIN_VER=$("$BINARY" --version 2>/dev/null | head -1 || echo "unknown")
log_info "Binary: $BINARY ($BIN_VER)"

# Validate configs
for node in "${NODE_ARRAY[@]}"; do
    cfg="${CONFIG_DIR}/${node}.toml"
    if [[ ! -f "$cfg" ]]; then
        die "Config not found: $cfg"
    fi
done
log_info "Configs validated"

# Parse duration to seconds
duration_to_seconds() {
    local d="$1"
    case "$d" in
        *h) echo $(( ${d%h} * 3600 )) ;;
        *m) echo $(( ${d%m} * 60 )) ;;
        *s) echo "${d%s}" ;;
        *)   echo "$d" ;;
    esac
}
DURATION_S=$(duration_to_seconds "$DURATION")
INTERVAL_S=$(duration_to_seconds "${INTERVAL}s")
if [[ ! "$DURATION_S" =~ ^[0-9]+$ ]] || [[ "$DURATION_S" -lt 60 ]]; then
    die "Invalid duration: $DURATION (minimum 60s)"
fi
if [[ ! "$INTERVAL_S" =~ ^[0-9]+$ ]] || [[ "$INTERVAL_S" -lt 10 ]]; then
    die "Invalid interval: $INTERVAL (minimum 10s)"
fi

log_info "Duration: $DURATION (${DURATION_S}s)"
log_info "Interval: ${INTERVAL}s"
log_info "RPC port: $RPC_PORT"
log_info "Log dir: $LOG_DIR"
echo ""

# ── Helper functions ────────────────────────────────────────────────────────
get_height() {
    local height
    height=$(curl -sf --max-time 5 "http://127.0.0.1:${RPC_PORT}/status" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('height',0))" 2>/dev/null \
        || echo "0")
    echo "$height"
}

restart_node() {
    local node="$1"
    local cfg="${CONFIG_DIR}/${node}.toml"
    local log_file="${LOG_DIR}/${node}.log"

    log_verbose "  Stopping $node..."
    local pid
    pid=$(pgrep -f "config.*${node}" 2>/dev/null || true)
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        sleep 2
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
            sleep 1
        fi
    fi

    log_verbose "  Starting $node..."
    "$BINARY" --config "$cfg" >> "$log_file" 2>&1 &

    # Wait for health
    local node_rpc_port=$(( RPC_PORT + ${node#val} - 1 ))
    for i in $(seq 1 30); do
        if curl -sf --max-time 2 "http://127.0.0.1:${node_rpc_port}/health" >/dev/null 2>&1; then
            log_verbose "  $node healthy after ${i}s"
            return 0
        fi
        sleep 1
    done
    log_warn "  $node did not become healthy within 30s"
    return 1
}

# ── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    log_info "Cleaning up..."
    # Don't kill nodes — they may be needed for analysis
    log_info "Log saved to: $LOG_FILE"
}
trap cleanup EXIT

# ── Main test loop ──────────────────────────────────────────────────────────
END_TIME=$(( $(date +%s) + DURATION_S ))
RESTARTS=0
FAILURES=0
HEIGHTS_BEFORE=()
HEIGHTS_AFTER=()

log_info "=== IONA Soak Test: Restart Resilience ==="

while [[ $(date +%s) -lt $END_TIME ]]; do
    NODE=${NODE_ARRAY[$RANDOM % ${#NODE_ARRAY[@]}]}

    HEIGHT_BEFORE=$(get_height)
    HEIGHTS_BEFORE+=("$HEIGHT_BEFORE")

    log_info "─── Restarting $NODE (attempt #$((RESTARTS + 1))) ───"
    log_info "  Height before: $HEIGHT_BEFORE"

    if restart_node "$NODE"; then
        RESTARTS=$((RESTARTS + 1))
    else
        FAILURES=$((FAILURES + 1))
        log_error "  Failed to restart $NODE"
    fi

    sleep 10

    HEIGHT_AFTER=$(get_height)
    HEIGHTS_AFTER+=("$HEIGHT_AFTER")
    log_info "  Height after:  $HEIGHT_AFTER"

    if [[ "$HEIGHT_AFTER" -le "$HEIGHT_BEFORE" ]]; then
        log_warn "  Height did NOT increase ($HEIGHT_BEFORE → $HEIGHT_AFTER)"
        FAILURES=$((FAILURES + 1))
    else
        log_info "  Height increased ($HEIGHT_BEFORE → $HEIGHT_AFTER) ✓"
    fi

    echo ""
    sleep "$INTERVAL_S"
done

# ── Summary ─────────────────────────────────────────────────────────────────
DURATION_ACTUAL=$(($(date +%s) - START_TIME))

echo ""
log_info "=== Soak Test Complete ==="
log_info "Duration: ${DURATION_ACTUAL}s"
log_info "Restarts: $RESTARTS"
log_info "Failures: $FAILURES"

# Compute statistics
if [[ ${#HEIGHTS_BEFORE[@]} -gt 0 ]]; then
    AVG_BEFORE=$(printf '%s\n' "${HEIGHTS_BEFORE[@]}" | awk '{sum+=$1} END {printf "%.0f", sum/NR}')
    AVG_AFTER=$(printf '%s\n' "${HEIGHTS_AFTER[@]}" | awk '{sum+=$1} END {printf "%.0f", sum/NR}')
    log_info "Avg height before: $AVG_BEFORE"
    log_info "Avg height after:  $AVG_AFTER"
    if [[ "$AVG_AFTER" -gt "$AVG_BEFORE" ]]; then
        BLOCKS_GAINED=$(( AVG_AFTER - AVG_BEFORE ))
        log_info "Avg blocks gained: $BLOCKS_GAINED"
    fi
fi

if [[ "$FAILURES" -gt 0 ]]; then
    log_error "RESULT: FAIL ($FAILURES failure(s))"
    STATUS="FAIL"
else
    log_info "RESULT: PASS (all restarts recovered successfully)"
    STATUS="PASS"
fi

# ── JSON output (for CI/CD) ─────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    jq -n \
        --arg status "$STATUS" \
        --argjson restarts "$RESTARTS" \
        --argjson failures "$FAILURES" \
        --argjson duration "$DURATION_ACTUAL" \
        --arg log_file "$LOG_FILE" \
        --arg binary_version "$BIN_VER" \
        --arg timestamp "$(date -Iseconds)" \
        '{
            status: $status,
            restarts: $restarts,
            failures: $failures,
            duration_s: $duration,
            log_file: $log_file,
            binary_version: $binary_version,
            timestamp: $timestamp
        }'
fi

[[ "$FAILURES" -eq 0 ]] && exit 0 || exit 1
