#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# IONA Healthcheck — Production‑Grade Node Diagnostic
# =============================================================================
#
# Quick diagnostic for all IONA validator nodes.
# Checks service status, RPC health, block height, peer count, and commit recency.
#
# Usage:
#   ./healthcheck.sh [OPTIONS]
#
# Options:
#   --node NAME          Check only the specified node (val1|val2|val3|val4|rpc)
#   --watch              Continuously monitor every N seconds
#   --interval SEC       Watch interval in seconds (default: 30)
#   --json               Output machine‑readable JSON
#   --timeout SEC        Curl timeout per node (default: 5)
#   --min-peers N        Minimum expected peers (default: 2)
#   --max-commit-age SEC Alert if last commit older than this (default: 120)
#   --data-root DIR      Override data root directory (default: /var/lib/iona)
#   --verbose            Enable detailed output
#   --help               Show this help
#
# Environment variables (fallback):
#   IONA_HEALTH_INTERVAL, IONA_HEALTH_TIMEOUT, IONA_MIN_PEERS,
#   IONA_MAX_COMMIT_AGE, IONA_DATA_ROOT, IONA_VERBOSE

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_NODE=""
WATCH=false
JSON_OUTPUT=false
INTERVAL="${IONA_HEALTH_INTERVAL:-30}"
TIMEOUT="${IONA_HEALTH_TIMEOUT:-5}"
MIN_PEERS="${IONA_MIN_PEERS:-2}"
MAX_COMMIT_AGE_S="${IONA_MAX_COMMIT_AGE:-120}"
DATA_ROOT="${IONA_DATA_ROOT:-/var/lib/iona}"
VERBOSE="${IONA_VERBOSE:-0}"

# Colours for output (safe for non‑TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_verbose() { [[ "$VERBOSE" -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*"; }
die()         { log_error "$*"; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)           TARGET_NODE="$2"; shift 2 ;;
        --watch)          WATCH=true; shift ;;
        --json)           JSON_OUTPUT=true; shift ;;
        --interval)       INTERVAL="$2"; shift 2 ;;
        --timeout)        TIMEOUT="$2"; shift 2 ;;
        --min-peers)      MIN_PEERS="$2"; shift 2 ;;
        --max-commit-age) MAX_COMMIT_AGE_S="$2"; shift 2 ;;
        --data-root)      DATA_ROOT="$2"; shift 2 ;;
        --verbose)        VERBOSE=1; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# ======/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Validate inputs ─────────────────────────────────────────────────────────
if [[ ! "$INTERVAL" =~ ^[0-9]+$ ]] || [[ "$INTERVAL" -lt 1 ]]; then
    die "Invalid interval: $INTERVAL (must be positive integer)"
fi
if [[ ! "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 ]]; then
    die "Invalid timeout: $TIMEOUT (must be positive integer)"
fi

# ── Node definitions ────────────────────────────────────────────────────────
declare -A NODE_PORTS=(
    [val1]=9001
    [val2]=9002
    [val3]=9003
    [val4]=9004
    [rpc]=9000
)

declare -A NODE_ROLES=(
    [val1]="follower"
    [val2]="producer"
    [val3]="producer"
    [val4]="producer"
    [rpc]="rpc"
)

# Determine which nodes to check
if [[ -n "$TARGET_NODE" ]]; then
    if [[ ! " ${!NODE_PORTS[*]} " =~ " ${TARGET_NODE} " ]]; then
        die "Unknown node: $TARGET_NODE (valid: ${!NODE_PORTS[*]})"
    fi
    NODES=("$TARGET_NODE")
else
    NODES=("val2" "val3" "val4" "val1" "rpc")
fi

# ── Check dependencies ──────────────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    die "curl is required but not installed"
fi

# ── Health check functions ──────────────────────────────────────────────────
check_node() {
    local node="$1"
    local port="${NODE_PORTS[$node]}"
    local role="${NODE_ROLES[$node]}"
    local service="iona-${node}"

    local status="OK"
    local issues=()

    # 1. Service status (systemd)
    local svc_active="unknown"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        svc_active="active"
    elif systemctl list-units --type=service --all 2>/dev/null | grep -q "$service"; then
        svc_active="inactive"
        status="WARN"
        issues+=("service not running")
    else
        svc_active="not-installed"
        status="WARN"
        issues+=("service not installed")
    fi

    # 2. RPC health endpoint
    local height="-"
    local peers="-"
    local commit_age="-"
    local rpc_ok=false

    local health_json
    health_json=$(curl -sf --max-time "$TIMEOUT" "http://127.0.0.1:${port}/health" 2>/dev/null || echo "")

    if [[ -n "$health_json" ]]; then
        rpc_ok=true
        # Try jq first, fall back to python3, then grep
        if command -v jq &>/dev/null; then
            height=$(echo "$health_json" | jq -r '.height // "-"' 2>/dev/null || echo "-")
            peers=$(echo "$health_json" | jq -r '.peers // "-"' 2>/dev/null || echo "-")
            commit_age=$(echo "$health_json" | jq -r '.commit_age_s // "-"' 2>/dev/null || echo "-")
        elif command -v python3 &>/dev/null; then
            height=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('height', '-'))" 2>/dev/null || echo "-")
            peers=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('peers', '-'))" 2>/dev/null || echo "-")
        else
            height=$(echo "$health_json" | grep -oP '"height"\s*:\s*\K[0-9]+' 2>/dev/null || echo "-")
            peers=$(echo "$health_json" | grep -oP '"peers"\s*:\s*\K[0-9]+' 2>/dev/null || echo "-")
        fi
    else
        status="FAIL"
        issues+=("RPC unreachable")
    fi

    # 3. Peer count check
    if [[ "$peers" != "-" ]] && [[ "$peers" -lt "$MIN_PEERS" ]]; then
        if [[ "$status" == "OK" ]]; then status="WARN"; fi
        issues+=("low peers: ${peers}/${MIN_PEERS}")
    fi

    # 4. Commit age check
    if [[ "$commit_age" != "-" ]] && [[ "$commit_age" -gt "$MAX_COMMIT_AGE_S" ]]; then
        if [[ "$status" == "OK" ]]; then status="WARN"; fi
        issues+=("stale commit: ${commit_age}s")
    fi

    # 5. Block count (filesystem)
    local block_count="-"
    if [[ -d "${DATA_ROOT}/${node}/blocks" ]]; then
        block_count=$(find "${DATA_ROOT}/${node}/blocks/" -type f 2>/dev/null | wc -l || echo "-")
    fi

    # ── Output ──────────────────────────────────────────────────────────
    if $JSON_OUTPUT; then
        local issues_str=""
        if [[ ${#issues[@]} -gt 0 ]]; then
            issues_str=$(printf '"%s",' "${issues[@]}")
            issues_str="[${issues_str%,}]"
        else
            issues_str="[]"
        fi
        echo "{\"node\":\"${node}\",\"role\":\"${role}\",\"status\":\"${status}\",\"service\":\"${svc_active}\",\"height\":${height:-null},\"peers\":${peers:-null},\"commit_age_s\":${commit_age:-null},\"blocks\":${block_count:-null},\"issues\":${issues_str}}"
    else
        # Coloured output
        local status_colour=""
        case "$status" in
            OK)   status_colour="${GREEN}" ;;
            WARN) status_colour="${YELLOW}" ;;
            FAIL) status_colour="${RED}" ;;
        esac

        printf "  %-6s %-10s ${status_colour}%-6s${NC} svc=%-12s height=%-8s peers=%-4s blocks=%-6s" \
            "$node" "$role" "$status" "$svc_active" "$height" "$peers" "$block_count"
        if [[ ${#issues[@]} -gt 0 ]]; then
            printf " [%s]" "$(IFS=', '; echo "${issues[*]}")"
        fi
        echo ""
    fi
}

# ── Run health check ────────────────────────────────────────────────────────
run_check() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    if $JSON_OUTPUT; then
        echo "{\"timestamp\":\"${ts}\",\"nodes\":["
        local first=true
        for node in "${NODES[@]}"; do
            if $first; then first=false; else echo ","; fi
            check_node "$node"
        done
        echo "]}"
    else
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║  IONA Health Check ($ts)                                 ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        for node in "${NODES[@]}"; do
            check_node "$node"
        done
        echo ""
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
if $WATCH; then
    log_info "Watching every ${INTERVAL}s (Ctrl+C to stop)..."
    while true; do
        run_check
        sleep "$INTERVAL"
    done
else
    run_check
fi
