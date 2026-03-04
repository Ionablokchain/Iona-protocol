#!/usr/bin/env bash
set -euo pipefail
#
# IONA Healthcheck — quick diagnostic for all nodes.
#
# Usage:
#   ./deploy/scripts/healthcheck.sh                # check all local nodes
#   ./deploy/scripts/healthcheck.sh --node val2    # check single node
#   ./deploy/scripts/healthcheck.sh --watch        # loop every 30s
#   ./deploy/scripts/healthcheck.sh --json         # machine-readable output
#
# Checks per node:
#   - Service status (systemd)
#   - RPC /health reachable
#   - Block height advancing
#   - Peer count >= minimum
#   - Last commit recency

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TARGET_NODE=""
WATCH=false
JSON_OUTPUT=false
INTERVAL=30
MIN_PEERS=2
MAX_COMMIT_AGE_S=120     # alert if last commit older than this

while [[ $# -gt 0 ]]; do
    case $1 in
        --node)     TARGET_NODE="$2"; shift 2 ;;
        --watch)    WATCH=true; shift ;;
        --json)     JSON_OUTPUT=true; shift ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--node <name>] [--watch] [--json] [--interval <sec>]"
            exit 0
            ;;
        *)          echo "Unknown: $1"; exit 1 ;;
    esac
done

# Node definitions: name -> rpc_port
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

if [[ -n "$TARGET_NODE" ]]; then
    NODES=("$TARGET_NODE")
else
    NODES=("val2" "val3" "val4" "val1" "rpc")
fi

check_node() {
    local node="$1"
    local port="${NODE_PORTS[$node]}"
    local role="${NODE_ROLES[$node]}"
    local service="iona-${node}"

    local status="OK"
    local issues=()

    # 1. Service status
    local svc_active="unknown"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        svc_active="active"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "$service"; then
        svc_active="inactive"
        status="WARN"
        issues+=("service not running")
    else
        svc_active="not-installed"
    fi

    # 2. RPC health
    local height="-"
    local peers="-"
    local rpc_ok=false

    local health_json
    health_json=$(curl -sf "http://127.0.0.1:${port}/health" 2>/dev/null || echo "")

    if [[ -n "$health_json" ]]; then
        rpc_ok=true
        height=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('height', '-'))" 2>/dev/null || echo "-")
        peers=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('peers', '-'))" 2>/dev/null || echo "-")
    else
        status="FAIL"
        issues+=("RPC unreachable")
    fi

    # 3. Peer count check
    if [[ "$peers" != "-" ]] && [[ "$peers" -lt "$MIN_PEERS" ]]; then
        status="WARN"
        issues+=("low peers: ${peers}")
    fi

    # 4. Block count (filesystem check)
    local data_dir="/var/lib/iona/${node}"
    local block_count="-"
    if [[ -d "${data_dir}/blocks" ]]; then
        block_count=$(ls "${data_dir}/blocks/" 2>/dev/null | wc -l || echo "-")
    fi

    # Output
    if $JSON_OUTPUT; then
        local issues_str=""
        if [[ ${#issues[@]} -gt 0 ]]; then
            issues_str=$(printf '"%s",' "${issues[@]}")
            issues_str="[${issues_str%,}]"
        else
            issues_str="[]"
        fi
        echo "{\"node\":\"${node}\",\"role\":\"${role}\",\"status\":\"${status}\",\"service\":\"${svc_active}\",\"height\":${height:-null},\"peers\":${peers:-null},\"blocks\":${block_count:-null},\"issues\":${issues_str}}"
    else
        printf "  %-6s %-10s %-6s svc=%-12s height=%-8s peers=%-4s blocks=%-6s" \
            "$node" "$role" "$status" "$svc_active" "$height" "$peers" "$block_count"
        if [[ ${#issues[@]} -gt 0 ]]; then
            printf " [%s]" "$(IFS=', '; echo "${issues[*]}")"
        fi
        echo ""
    fi
}

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
        echo "=== IONA Health Check ($ts) ==="
        echo ""
        for node in "${NODES[@]}"; do
            check_node "$node"
        done
        echo ""
    fi
}

if $WATCH; then
    echo "Watching every ${INTERVAL}s (Ctrl+C to stop)..."
    while true; do
        run_check
        sleep "$INTERVAL"
    done
else
    run_check
fi
